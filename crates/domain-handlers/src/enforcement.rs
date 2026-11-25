use crate::handler::{
    GroupBackendHandler, GroupListerBackendHandler, GroupRequestFilter, PolicyBackendHandler,
    UserBackendHandler, UserListerBackendHandler,
};
use crate::inactivity::{
    ActivityBook, InactivityCheck, Recorded, active_since, cached_active_since, fill_activity,
    idle_past_limit, read_user_activity,
};
use crate::instant::{Timestamp, from_naive};
use crate::kdc_proof::{ProofSettings, ProofWindow, Reread, WindowReader};
use crate::kdc_proof::{fill_windows, proofs_live, take_user_windows};
use crate::kerberos::{CommitError, HostRow};
use crate::lockout::{self, LockRow, Lockout, LockoutCheck, lockout};
use crate::logging::{self, LogKind, Protocol, RequestMeta};
use crate::login_hours::{self, LoginHoursCheck};
use crate::mfa::{
    ENABLE_MFA, EnableMfa, MFA_DISABLED_GROUP, MfaEnrollmentStatus, MfaPolicy, MfaRequirement,
    mfa_requirement,
};
use crate::networks::{NetworksBook, NetworksCheck};
use crate::policies::{
    EffectiveItem, POLICY_ITEM_CATALOG, POLICY_READ_WAIT, Policy, PolicyValueType,
    canonical_ou_key, catalog_item, resolve, resolve_effective_items,
};
use async_trait::async_trait;
use jiff::tz::TimeZone;
use lldap_domain::requests::{CreateGroupRequest, UpdateUserRequest};
use lldap_domain::types::{Attribute, GroupDetails, MFA_TYPE_TOTP, User, UserId, Uuid, user_ou};
use lldap_domain_model::error::{DomainError, Result};
use std::collections::{BTreeSet, HashMap};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex, PoisonError, RwLock};
use std::time::Duration;
use tokio::sync::Notify;
use tracing::warn;

pub const POLICY_REFILL: Duration = Duration::from_secs(30);
pub const FILL_GAP: Duration = Duration::from_millis(250);
pub const FILL_BACKOFF_LIMIT: Duration = Duration::from_secs(30);
pub const OVERLAY_FOLD: usize = 1024;
const MARK_PASSES: usize = 4;
const FLAG_OFF: u8 = 0;
const FLAG_ON: u8 = 1;
const FLAG_UNKNOWN: u8 = 2;
pub const UNREADABLE: &str = "unreadable";
pub const NOT_LOADED: &str = "not loaded yet";
pub const POLICY_UNANSWERED: &str = "the policy read did not answer within its bound";
pub const LOGIN_HOURS: &str = "login-hours";
pub const ALLOWED_NETWORKS: &str = "allowed-networks";
pub const INACTIVITY_DAYS: &str = "inactivity-days";
const GATED: [&str; 3] = [LOGIN_HOURS, ALLOWED_NETWORKS, INACTIVITY_DAYS];
pub const ZONE_FILES: &str = "/usr/share/zoneinfo";
pub const BUILT_IN: &str = "built in";

/// A read that gave up within its bound, by the client's timer or the database's own.
pub fn gave_up(e: &DomainError) -> bool {
    matches!(e, DomainError::InternalError(detail) if detail == POLICY_UNANSWERED)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Door {
    WebLogin,
    SimpleLogin,
    Refresh,
    TokenUse,
    LdapBind,
    KerberosAs,
    KerberosTgs,
    KerberosS4u,
}

impl Door {
    pub fn log_kind(self) -> LogKind {
        match self {
            Self::WebLogin | Self::KerberosAs => LogKind::Login,
            Self::SimpleLogin | Self::LdapBind => LogKind::Bind,
            Self::Refresh => LogKind::TokenRefresh,
            Self::TokenUse | Self::KerberosTgs | Self::KerberosS4u => LogKind::AccessDenied,
        }
    }

    /// `LoginHandler::bind` serves both binds; the request's protocol names the door.
    pub fn of_bind() -> Self {
        match logging::current_request().protocol {
            Protocol::Ldap => Self::LdapBind,
            _ => Self::SimpleLogin,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::WebLogin => "web login",
            Self::SimpleLogin => "simple login",
            Self::Refresh => "token refresh",
            Self::TokenUse => "token use",
            Self::LdapBind => "ldap bind",
            Self::KerberosAs => "kerberos",
            Self::KerberosTgs => "kerberos service ticket",
            Self::KerberosS4u => "kerberos S4U",
        }
    }

    /// A login counts toward a lock; a renewal, a service ticket or an S4U request does not.
    pub fn is_login(self) -> bool {
        matches!(
            self,
            Self::WebLogin | Self::SimpleLogin | Self::LdapBind | Self::KerberosAs
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Attempt<'a> {
    pub user: &'a UserId,
    pub door: Door,
    pub peer: Option<IpAddr>,
    pub now: Timestamp,
    pub second_factor: bool,
}

#[cfg(any(test, feature = "test-backend-scope"))]
static TEST_CLOCK: RwLock<Option<Timestamp>> = RwLock::new(None);

/// For tests only, through test-utils' `EnforcementGuard`: the doors' clock until it is reset.
#[cfg(any(test, feature = "test-backend-scope"))]
pub fn set_test_clock(now: Option<Timestamp>) {
    *TEST_CLOCK.write().unwrap_or_else(PoisonError::into_inner) = now;
}

#[cfg(any(test, feature = "test-backend-scope"))]
fn pinned_clock() -> Option<Timestamp> {
    *TEST_CLOCK.read().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(not(any(test, feature = "test-backend-scope")))]
fn pinned_clock() -> Option<Timestamp> {
    None
}

pub fn door_clock() -> Timestamp {
    pinned_clock().unwrap_or_else(Timestamp::now)
}

impl<'a> Attempt<'a> {
    pub fn new(user: &'a UserId, door: Door) -> Self {
        Self {
            user,
            door,
            peer: logging::current_request().peer,
            now: door_clock(),
            second_factor: false,
        }
    }

    /// The KDC's clock and peer: its thread has no request of its own.
    pub fn at_kdc(user: &'a UserId, door: Door, peer: Option<IpAddr>, now: u32) -> Self {
        Self {
            user,
            door,
            peer,
            now: Timestamp::from_second(i64::from(now)).unwrap_or_else(|_| Timestamp::now()),
            second_factor: false,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Refusal {
    pub item: &'static str,
    pub door: Door,
    pub reason: Option<&'static str>,
}

impl Refusal {
    pub fn detail(&self) -> String {
        if self.item == lockout::THRESHOLD {
            return lockout::LOCKED_OUT.to_owned();
        }
        match self.reason {
            Some(reason) => format!("policy: {} ({reason})", self.item),
            None => format!("policy: {}", self.item),
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UserState {
    pub lock: Option<LockRow>,
    /// The latest of inactivity's starting points; `None` while one is not read.
    pub active_since: Option<Timestamp>,
}

pub trait ItemCheck: Send + Sync {
    fn key(&self) -> &'static str;
    /// Read with the key, and enforced with it.
    fn also_enforces(&self) -> &'static [&'static str] {
        &[]
    }
    /// A check that is not live costs nothing: no read, no fill.
    fn live(&self, _cache: &PolicyCache) -> bool {
        true
    }
    /// A user no check judges is admitted before any read.
    fn judges(&self, _user: &UserId) -> bool {
        true
    }
    fn may_refuse(&self, _state: &UserState) -> bool {
        true
    }
    /// Said after the key in the refusal's row: `policy: <key> (<reason>)`.
    fn reason(&self) -> Option<&'static str> {
        None
    }
    /// Whether it judges a user a service asks for (S4U2Self, S4U2Proxy).
    fn judges_at_s4u(&self) -> bool {
        true
    }
    /// A value or a state the check cannot read refuses as `unreadable`.
    fn readable(&self, _value: &str, _state: &UserState) -> bool {
        true
    }
    /// Until what it judges with is held, a live check refuses as an unread item.
    fn loaded(&self) -> bool {
        true
    }
    fn allows(&self, attempt: &Attempt<'_>, value: &str, state: &UserState) -> bool;
    fn allows_among(
        &self,
        attempt: &Attempt<'_>,
        value: &str,
        _items: &[EffectiveItem],
        state: &UserState,
    ) -> bool {
        self.allows(attempt, value, state)
    }
}

pub type ItemChecks = Arc<[Arc<dyn ItemCheck>]>;

pub fn decide(
    attempt: &Attempt<'_>,
    items: &[EffectiveItem],
    state: &UserState,
    checks: &[Arc<dyn ItemCheck>],
) -> std::result::Result<(), Refusal> {
    for check in checks.iter().filter(|check| judges_attempt(check, attempt)) {
        let Some(item) = items.iter().find(|item| item.key == check.key()) else {
            continue;
        };
        if !check.readable(&item.value, state) {
            return Err(Refusal {
                item: UNREADABLE,
                door: attempt.door,
                reason: None,
            });
        }
        if !check.allows_among(attempt, &item.value, items, state) {
            return Err(Refusal {
                item: check.key(),
                door: attempt.door,
                reason: check.reason(),
            });
        }
    }
    Ok(())
}

fn judges_attempt(check: &Arc<dyn ItemCheck>, attempt: &Attempt<'_>) -> bool {
    let at_s4u = attempt.door == Door::KerberosS4u;
    check.judges(attempt.user) && (!at_s4u || check.judges_at_s4u())
}

pub fn judged(checks: &[Arc<dyn ItemCheck>], user: &UserId) -> bool {
    checks.iter().any(|check| check.judges(user))
}

fn live(cache: &PolicyCache) -> bool {
    item_checks().iter().any(|check| check.live(cache))
}

pub fn live_checks(checks: &[Arc<dyn ItemCheck>], cache: &PolicyCache) -> Vec<Arc<dyn ItemCheck>> {
    let live = |check: &&Arc<dyn ItemCheck>| check.live(cache);
    checks.iter().filter(live).cloned().collect()
}

fn refusing(
    checks: &[Arc<dyn ItemCheck>],
    cache: &PolicyCache,
    lockout: &Lockout,
    user: &UserId,
) -> (UserState, Vec<Arc<dyn ItemCheck>>) {
    let judging = |check: &&Arc<dyn ItemCheck>| check.live(cache) && check.judges(user);
    let checks: Vec<_> = checks.iter().filter(judging).cloned().collect();
    if checks.is_empty() {
        return (UserState::default(), checks);
    }
    let state = lockout.user_state(user);
    let can = |check: &Arc<dyn ItemCheck>| check.may_refuse(&state);
    let checks = checks.into_iter().filter(can).collect();
    (state, checks)
}

/// Each enforcing cell adds its item's check here and turns the item's `enforced` flag on.
pub fn default_item_checks() -> ItemChecks {
    let checks: Vec<Arc<dyn ItemCheck>> = vec![
        Arc::new(LockoutCheck),
        Arc::new(InactivityCheck),
        Arc::new(NetworksCheck),
        Arc::new(MfaItemCheck),
        Arc::new(LoginHoursCheck::on(policy_cache())),
    ];
    checks.into()
}

static CHECKS: LazyLock<RwLock<ItemChecks>> = LazyLock::new(|| RwLock::new(default_item_checks()));

pub fn item_checks() -> ItemChecks {
    CHECKS
        .read()
        .unwrap_or_else(PoisonError::into_inner)
        .clone()
}

/// For tests only, through test-utils' `EnforcementGuard`.
#[cfg(any(test, feature = "test-backend-scope"))]
pub fn set_item_checks(checks: ItemChecks) {
    *CHECKS.write().unwrap_or_else(PoisonError::into_inner) = checks;
}

/// What the doors need of a user that only the directory knows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserFacts {
    pub uuid: Uuid,
    pub enrolled: bool,
    pub exempt: bool,
    pub created: Timestamp,
    /// inactivity-days' row; `None` until read.
    pub recorded: Option<Recorded>,
}

impl UserFacts {
    pub fn of<'a>(user: &User, mut groups: impl Iterator<Item = &'a GroupDetails>) -> Self {
        Self {
            uuid: user.uuid.clone(),
            enrolled: user.mfa_type.as_deref() == Some(MFA_TYPE_TOTP),
            exempt: groups.any(|group| group.display_name.as_str() == MFA_DISABLED_GROUP),
            created: from_naive(user.creation_date),
            recorded: None,
        }
    }

    /// The bind's own test: enrolled, the second factor on, and not exempt.
    pub fn second_factor_required(&self, policy: MfaPolicy) -> bool {
        let status = MfaEnrollmentStatus {
            enrolled: self.enrolled,
            exempt: self.exempt,
        };
        mfa_requirement(policy, Some(&status)) == MfaRequirement::Totp
    }
}

/// Keeps the cache filled while an OU sets `enable-mfa` or the KDC asks a proof.
pub struct MfaItemCheck;

impl ItemCheck for MfaItemCheck {
    fn key(&self) -> &'static str {
        ENABLE_MFA
    }

    fn live(&self, cache: &PolicyCache) -> bool {
        (cache.mfa_policy().is_none() && !cache.mfa_item_off()) || proofs_live(cache)
    }

    fn may_refuse(&self, _: &UserState) -> bool {
        false
    }

    fn allows(&self, _: &Attempt<'_>, _: &str, _: &UserState) -> bool {
        true
    }
}

/// `Some(false)` when no OU's value is needed: an explicit server-wide value, or no OU sets
/// one; `None` until the policies are read.
pub fn mfa_item_matters(cache: &PolicyCache, server: Option<MfaPolicy>) -> Option<bool> {
    if server.is_some() || cache.mfa_item_off() {
        return Some(false);
    }
    (!cache.mfa_item_unknown()).then_some(true)
}

/// The user's resolved value from memory alone.
pub fn cached_mfa_policy(
    cache: &PolicyCache,
    entries: &Snapshot,
    user: &UserId,
) -> Option<MfaPolicy> {
    mfa_policy_from(cache, entries.items_of(user))
}

pub(crate) fn mfa_policy_from(
    cache: &PolicyCache,
    items: Option<&[EffectiveItem]>,
) -> Option<MfaPolicy> {
    let server = cache.mfa_policy();
    let resolved = |items: &[EffectiveItem]| resolve::<EnableMfa>(server, items).0;
    match mfa_item_matters(cache, server)? {
        false => Some(resolved(&[])),
        true => items.map(resolved),
    }
}

/// Whether the resolution can turn the factor on for anyone; while unknown, it can.
pub fn mfa_can_be_on(server: Option<MfaPolicy>, cache: &PolicyCache) -> bool {
    match server {
        Some(policy) => policy != MfaPolicy::Disabled,
        None => !cache.mfa_item_off(),
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Entries {
    pub ous_of_users: HashMap<UserId, String>,
    pub items_of_ous: HashMap<String, Arc<[EffectiveItem]>>,
    pub facts: HashMap<UserId, UserFacts>,
    pub windows: HashMap<UserId, Arc<[ProofWindow]>>,
    pub built_at: Timestamp,
}

impl Entries {
    pub fn items_of(&self, user: &UserId) -> Option<&[EffectiveItem]> {
        let ou_key = self.ous_of_users.get(user)?;
        self.items_of_ous.get(ou_key).map(|items| &items[..])
    }

    pub fn facts_of(&self, user: &UserId) -> Option<&UserFacts> {
        self.facts.get(user)
    }

    pub fn windows_of(&self, user: &UserId) -> &[ProofWindow] {
        self.windows
            .get(user)
            .map(|windows| &windows[..])
            .unwrap_or_default()
    }

    fn of(&self, user: &UserId) -> Over {
        let ou = self.ous_of_users.get(user);
        Over {
            items: ou.and_then(|ou_key| self.items_of_ous.get(ou_key)).cloned(),
            ou: ou.cloned(),
            facts: self.facts.get(user).cloned(),
            windows: self.windows.get(user).cloned().unwrap_or_default(),
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Over {
    pub(crate) ou: Option<String>,
    pub(crate) items: Option<Arc<[EffectiveItem]>>,
    pub(crate) facts: Option<UserFacts>,
    pub(crate) windows: Arc<[ProofWindow]>,
}

/// A fill's entries and, over them, the users edited since; never changed once made.
#[derive(Clone, Debug, Default)]
pub struct Snapshot {
    base: Arc<Entries>,
    over: HashMap<UserId, Arc<Over>>,
}

impl Snapshot {
    pub fn items_of(&self, user: &UserId) -> Option<&[EffectiveItem]> {
        match self.over.get(user) {
            Some(over) => over.items.as_deref(),
            None => self.base.items_of(user),
        }
    }

    pub fn facts_of(&self, user: &UserId) -> Option<&UserFacts> {
        match self.over.get(user) {
            Some(over) => over.facts.as_ref(),
            None => self.base.facts_of(user),
        }
    }

    pub fn windows_of(&self, user: &UserId) -> &[ProofWindow] {
        match self.over.get(user) {
            Some(over) => &over.windows,
            None => self.base.windows_of(user),
        }
    }

    pub fn ou_of(&self, user: &UserId) -> Option<&str> {
        match self.over.get(user) {
            Some(over) => over.ou.as_deref(),
            None => self.base.ous_of_users.get(user).map(String::as_str),
        }
    }

    /// For tests only: every user's OU, the edited users' over the fill's.
    #[cfg(any(test, feature = "test-backend-scope"))]
    pub fn ous_of_users(&self) -> HashMap<UserId, String> {
        let mut ous = self.base.ous_of_users.clone();
        for (user, over) in &self.over {
            match &over.ou {
                Some(ou) => ous.insert(user.clone(), ou.clone()),
                None => ous.remove(user),
            };
        }
        ous
    }

    fn shared_items_of(&self, user: &UserId) -> Option<Arc<[EffectiveItem]>> {
        match self.over.get(user) {
            Some(over) => over.items.clone(),
            None => {
                let ou_key = self.base.ous_of_users.get(user)?;
                self.base.items_of_ous.get(ou_key).cloned()
            }
        }
    }

    fn of(&self, user: &UserId) -> Over {
        match self.over.get(user) {
            Some(over) => Over::clone(over),
            None => self.base.of(user),
        }
    }

    fn with(&self, user: &UserId, over: Over) -> Self {
        let mut next = self.clone();
        match over == self.base.of(user) {
            true => next.over.remove(user),
            false => next.over.insert(user.clone(), Arc::new(over)),
        };
        next
    }
}

/// Swapped whole: a reader holds the old snapshot or the new one, never none.
pub struct PolicyCache {
    current: RwLock<Arc<Snapshot>>,
    generation: AtomicU64,
    reads: AtomicU64,
    fill: Notify,
    refill: AtomicBool,
    writers: tokio::sync::Mutex<()>,
    marked: Mutex<Marks>,
    read_failed: AtomicBool,
    lockout: AtomicU8,
    mfa: RwLock<Option<MfaPolicy>>,
    mfa_item: AtomicU8,
    items: [AtomicU8; 3],
    zone: RwLock<Option<TimeZone>>,
    pub(crate) activity: ActivityBook,
    pub(crate) networks: NetworksBook,
    pub(crate) proofs: RwLock<Option<ProofSettings>>,
    pub(crate) reader: RwLock<Option<WindowReader>>,
    pub(crate) rereads: Mutex<HashMap<UserId, Reread>>,
}

#[derive(Default)]
struct Marks {
    made: u64,
    users: HashMap<UserId, u64>,
}

/// Holds the writers' lock; once it is let go, marks still in the set go to the filler.
pub(crate) struct Taking<'a> {
    cache: &'a PolicyCache,
    writers: Option<tokio::sync::MutexGuard<'a, ()>>,
}

impl Drop for Taking<'_> {
    fn drop(&mut self) {
        drop(self.writers.take());
        if !self.cache.marks().users.is_empty() {
            self.cache.fill.notify_one();
        }
    }
}

impl Default for PolicyCache {
    fn default() -> Self {
        Self::new()
    }
}

impl PolicyCache {
    pub fn new() -> Self {
        Self {
            current: RwLock::default(),
            generation: AtomicU64::new(0),
            reads: AtomicU64::new(0),
            fill: Notify::new(),
            refill: AtomicBool::new(false),
            writers: tokio::sync::Mutex::new(()),
            marked: Mutex::default(),
            read_failed: AtomicBool::new(false),
            lockout: AtomicU8::new(FLAG_OFF),
            mfa: RwLock::new(None),
            mfa_item: AtomicU8::new(FLAG_OFF),
            items: std::array::from_fn(|_| AtomicU8::new(FLAG_OFF)),
            zone: RwLock::new(None),
            activity: ActivityBook::default(),
            networks: NetworksBook::default(),
            proofs: RwLock::new(None),
            reader: RwLock::new(None),
            rereads: Mutex::default(),
        }
    }

    /// Whether an OU policy sets a lockout threshold: one atomic read.
    pub fn lockout_live(&self) -> bool {
        self.lockout.load(Ordering::Acquire) == FLAG_ON
    }

    pub fn lockout_off(&self) -> bool {
        self.lockout.load(Ordering::Acquire) == FLAG_OFF
    }

    /// Before the first read of the policies: the doors the lockout judges refuse.
    pub fn lockout_unknown(&self) -> bool {
        self.lockout.load(Ordering::Acquire) == FLAG_UNKNOWN
    }

    pub fn set_lockout_live(&self, live: bool) {
        let state = if live { FLAG_ON } else { FLAG_OFF };
        self.lockout.store(state, Ordering::Release);
    }

    /// The explicit server-wide `enable_mfa`; `None` lets the OUs decide.
    pub fn mfa_policy(&self) -> Option<MfaPolicy> {
        *self.mfa.read().unwrap_or_else(PoisonError::into_inner)
    }

    pub fn set_mfa_policy(&self, policy: Option<MfaPolicy>) {
        *self.mfa.write().unwrap_or_else(PoisonError::into_inner) = policy;
    }

    /// The zone `login-hours` windows are read in, loaded once at start; `None` until then.
    pub fn login_hours_zone(&self) -> Option<TimeZone> {
        self.zone
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    pub fn set_login_hours_zone(&self, zone: TimeZone) {
        *self.zone.write().unwrap_or_else(PoisonError::into_inner) = Some(zone);
    }

    pub fn set_lockout_unknown(&self) {
        self.lockout.store(FLAG_UNKNOWN, Ordering::Release);
    }

    /// Whether an OU policy sets `enable-mfa`: one atomic read.
    pub fn mfa_item_live(&self) -> bool {
        self.mfa_item.load(Ordering::Acquire) == FLAG_ON
    }

    pub fn mfa_item_off(&self) -> bool {
        self.mfa_item.load(Ordering::Acquire) == FLAG_OFF
    }

    pub fn mfa_item_unknown(&self) -> bool {
        self.mfa_item.load(Ordering::Acquire) == FLAG_UNKNOWN
    }

    pub fn set_mfa_item_live(&self, live: bool) {
        let state = if live { FLAG_ON } else { FLAG_OFF };
        self.mfa_item.store(state, Ordering::Release);
    }

    pub fn set_mfa_item_unknown(&self) {
        self.mfa_item.store(FLAG_UNKNOWN, Ordering::Release);
    }

    fn item_state(&self, key: &str) -> u8 {
        let at = GATED.iter().position(|gated| *gated == key);
        let flag = at.and_then(|at| self.items.get(at));
        flag.map_or(FLAG_OFF, |flag| flag.load(Ordering::Acquire))
    }

    fn set_item(&self, key: &str, state: u8) {
        let at = GATED.iter().position(|gated| *gated == key);
        if let Some(flag) = at.and_then(|at| self.items.get(at)) {
            flag.store(state, Ordering::Release);
        }
    }

    /// Whether no OU's linked policy sets the item off its default: one atomic read.
    pub fn item_off(&self, key: &str) -> bool {
        self.item_state(key) == FLAG_OFF
    }

    /// The lockout before its first follow, or an item whose fill failed as it turned on.
    pub fn item_unread(&self, key: &str) -> bool {
        match key {
            lockout::THRESHOLD => self.lockout_unknown(),
            _ => self.item_state(key) == FLAG_UNKNOWN,
        }
    }

    #[cfg(any(test, feature = "test-backend-scope"))]
    pub fn items_unread(&self) -> bool {
        GATED.iter().any(|key| self.item_state(key) == FLAG_UNKNOWN)
    }

    pub fn items_unread_besides(&self, key: &str) -> bool {
        let unread = |gated: &&str| *gated != key && self.item_state(gated) == FLAG_UNKNOWN;
        GATED.iter().any(unread)
    }

    #[cfg(any(test, feature = "test-backend-scope"))]
    pub fn set_item_flags(&self, flags: ItemFlags) {
        for (key, on) in flags.keyed() {
            self.set_item(key, flag(on));
        }
    }

    pub(crate) fn current(&self) -> Arc<Snapshot> {
        self.current
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    pub fn get(&self) -> Arc<Snapshot> {
        self.reads.fetch_add(1, Ordering::Relaxed);
        self.current()
    }

    pub fn reads(&self) -> u64 {
        self.reads.load(Ordering::Relaxed)
    }

    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    pub fn replace(&self, next: Entries) {
        self.swap(Snapshot {
            base: Arc::new(next),
            over: HashMap::new(),
        });
    }

    fn swap(&self, next: Snapshot) {
        let next = Arc::new(next);
        *self.current.write().unwrap_or_else(PoisonError::into_inner) = next;
        self.generation.fetch_add(1, Ordering::AcqRel);
    }

    /// Under the writers' lock; a change that leaves the user as held swaps nothing.
    pub(crate) fn edit(&self, user: &UserId, change: impl FnOnce(&mut Over)) {
        let held = self.current();
        let was = held.of(user);
        let mut now = was.clone();
        change(&mut now);
        if now == was {
            return;
        }
        let next = held.with(user, now);
        let large = next.over.len() > OVERLAY_FOLD;
        self.swap(next);
        if large {
            self.poke_fill();
        }
    }

    pub fn put_user(&self, user: &UserId, ou_key: &str, items: Arc<[EffectiveItem]>) {
        self.edit(user, |over| {
            over.ou = Some(ou_key.to_owned());
            over.items = Some(items);
        });
    }

    pub fn put_facts(&self, user: &UserId, facts: UserFacts) {
        self.edit(user, |over| over.facts = Some(facts));
    }

    pub fn remove_user(&self, user: &UserId) {
        self.edit(user, |over| *over = Over::default());
    }

    pub(crate) fn note_read_failed(&self) {
        self.read_failed.store(true, Ordering::Release);
    }

    pub fn failed_read(&self) -> bool {
        self.read_failed.load(Ordering::Acquire)
    }

    pub fn marked(&self, user: &UserId) -> bool {
        self.marks().users.contains_key(user)
    }

    fn marks(&self) -> std::sync::MutexGuard<'_, Marks> {
        self.marked.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub(crate) fn mark(&self, user: &UserId) {
        let mut marks = self.marks();
        marks.made += 1;
        let made = marks.made;
        marks.users.insert(user.clone(), made);
    }

    fn marked_since(&self, seen: u64) -> Vec<(UserId, u64)> {
        let marks = self.marks();
        let later = marks.users.iter().filter(|(_, made)| **made > seen);
        later.map(|(user, made)| (user.clone(), *made)).collect()
    }

    fn unmark(&self, user: &UserId, made: u64) {
        let mut marks = self.marks();
        if marks.users.get(user) == Some(&made) {
            marks.users.remove(user);
        }
    }

    pub(crate) fn try_take(&self) -> Option<Taking<'_>> {
        let writers = self.writers.try_lock().ok();
        writers.map(|writers| Taking {
            cache: self,
            writers: Some(writers),
        })
    }

    async fn take(&self) -> Taking<'_> {
        let writers = Some(self.writers.lock().await);
        Taking {
            cache: self,
            writers,
        }
    }

    /// Asks the filler for a whole fill; a mark left at a release wakes it for the marks alone.
    pub fn poke_fill(&self) {
        self.refill.store(true, Ordering::Release);
        self.fill.notify_one();
    }

    pub async fn poked(&self) {
        self.fill.notified().await;
    }
}

#[cfg(any(test, feature = "test-backend-scope"))]
fn flag(live: bool) -> u8 {
    if live { FLAG_ON } else { FLAG_OFF }
}

static CACHE: LazyLock<PolicyCache> = LazyLock::new(PolicyCache::new);

pub fn policy_cache() -> &'static PolicyCache {
    &CACHE
}

async fn ou_items<H>(handler: &H, ou_key: &str) -> Result<Arc<[EffectiveItem]>>
where
    H: PolicyBackendHandler + ?Sized,
{
    let levels = handler.get_policy_levels(ou_key).await?;
    Ok(resolve_effective_items(POLICY_ITEM_CATALOG, &levels).into())
}

type UserEntry = (String, Arc<[EffectiveItem]>, User);

async fn user_entry<H>(handler: &H, user: &UserId) -> Result<UserEntry>
where
    H: UserBackendHandler + PolicyBackendHandler + ?Sized,
{
    let read = tokio::time::timeout(POLICY_READ_WAIT, handler.bounded_policy_entry(user));
    let unanswered = DomainError::InternalError(POLICY_UNANSWERED.to_owned());
    let (details, levels) = read.await.map_err(|_| unanswered)??;
    let ou_key = canonical_ou_key(&user_ou(&details.attributes));
    let items = resolve_effective_items(POLICY_ITEM_CATALOG, &levels).into();
    Ok((ou_key, items, details))
}

async fn user_facts<H>(handler: &H, user: &User) -> Result<UserFacts>
where
    H: UserBackendHandler + ?Sized,
{
    let groups = handler.get_user_groups(&user.user_id).await?;
    Ok(UserFacts::of(user, groups.iter()))
}

pub async fn build_entries<H>(handler: &H) -> Result<Entries>
where
    H: UserListerBackendHandler + PolicyBackendHandler + ?Sized,
{
    let mut entries = Entries {
        built_at: Timestamp::now(),
        ..Entries::default()
    };
    let mut ou_keys = BTreeSet::new();
    for entry in handler.list_users(None, true).await? {
        let ou_key = canonical_ou_key(&user_ou(&entry.user.attributes));
        ou_keys.insert(ou_key.clone());
        let facts = UserFacts::of(&entry.user, entry.groups.iter().flatten());
        entries.facts.insert(entry.user.user_id.clone(), facts);
        entries.ous_of_users.insert(entry.user.user_id, ou_key);
    }
    for ou_key in ou_keys {
        let items = ou_items(handler, &ou_key).await?;
        entries.items_of_ous.insert(ou_key, items);
    }
    Ok(entries)
}

pub async fn fill_policy_cache<H>(handler: &H, cache: &PolicyCache) -> Result<()>
where
    H: UserListerBackendHandler + UserBackendHandler + PolicyBackendHandler + ?Sized,
{
    let _taking = cache.take().await;
    let mut entries = build_entries(handler).await?;
    fill_activity(handler, cache, &mut entries).await;
    fill_windows(handler, cache, &mut entries).await;
    cache.replace(entries);
    take_marks(handler, cache).await;
    Ok(())
}

pub fn start_policy_filler<H>(
    handler: H,
    cache: &'static PolicyCache,
) -> tokio::task::JoinHandle<()>
where
    H: UserListerBackendHandler + UserBackendHandler + PolicyBackendHandler + Send + Sync + 'static,
{
    tokio::spawn(async move {
        let mut gap = FILL_GAP;
        let mut refill_at = tokio::time::Instant::now() + POLICY_REFILL;
        loop {
            let due = tokio::select! {
                () = cache.poked() => false,
                () = tokio::time::sleep_until(refill_at) => true,
            };
            let whole = due | cache.refill.swap(false, Ordering::AcqRel);
            if live(cache) {
                let failed = fill_round(&handler, cache, whole).await;
                gap = next_gap(gap, failed);
                tokio::time::sleep(gap).await;
            }
            if whole {
                refill_at = tokio::time::Instant::now() + POLICY_REFILL;
            }
        }
    })
}

/// A whole fill when one is asked or due, else the marks alone; a read that failed asks a whole
/// fill of the next round. True when a read failed.
async fn fill_round<H>(handler: &H, cache: &PolicyCache, whole: bool) -> bool
where
    H: UserListerBackendHandler + UserBackendHandler + PolicyBackendHandler + ?Sized,
{
    let filled = match whole {
        true => fill_policy_cache(handler, cache).await,
        false => {
            let _taking = cache.take().await;
            take_marks(handler, cache).await;
            Ok(())
        }
    };
    if let Err(e) = &filled {
        warn!("The policy cache was not refilled: {e}");
    }
    let failed = filled.is_err() | cache.read_failed.swap(false, Ordering::AcqRel);
    if failed {
        cache.refill.store(true, Ordering::Release);
    }
    failed
}

/// A fill whose reads keep failing waits twice as long each time, up to `FILL_BACKOFF_LIMIT`.
pub fn next_gap(gap: Duration, failed: bool) -> Duration {
    match failed {
        true => (gap * 2).min(FILL_BACKOFF_LIMIT),
        false => FILL_GAP,
    }
}

/// Before the KDC serves; nothing is read while no item is enforced.
pub async fn start_policy_cache<H>(handler: &H) -> Option<tokio::task::JoinHandle<()>>
where
    H: UserListerBackendHandler
        + UserBackendHandler
        + PolicyBackendHandler
        + Clone
        + Send
        + Sync
        + 'static,
{
    if item_checks().is_empty() {
        return None;
    }
    if live(policy_cache())
        && let Err(e) = fill_policy_cache(handler, policy_cache()).await
    {
        warn!("The policy cache was not filled at start: {e}");
        policy_cache().poke_fill();
    }
    Some(start_policy_filler(handler.clone(), policy_cache()))
}

/// When a linked policy first asks a second factor, the cache is filled before the flag lets a
/// door use it; a fill that fails leaves the flag unknown, and the doors it concerns refuse.
pub async fn follow_mfa_item<H>(
    handler: &H,
    cache: &PolicyCache,
    policies: &[Policy],
) -> Result<bool>
where
    H: UserListerBackendHandler + UserBackendHandler + PolicyBackendHandler + ?Sized,
{
    let live = cache.mfa_policy().is_none() && policies.iter().any(asks_mfa);
    if !live || cache.mfa_item_live() {
        cache.set_mfa_item_live(live);
        return Ok(false);
    }
    if let Err(e) = fill_policy_cache(handler, cache).await {
        cache.set_mfa_item_unknown();
        return Err(e);
    }
    cache.set_mfa_item_live(true);
    if let Err(e) = fill_policy_cache(handler, cache).await {
        cache.set_mfa_item_unknown();
        return Err(e);
    }
    Ok(true)
}

fn asks_mfa(policy: &Policy) -> bool {
    let value = policy.items.get(ENABLE_MFA);
    !policy.linked_ous.is_empty() && value.is_some_and(|value| value != "off")
}

/// Whether an OU's linked policy sets the item at a value other than the catalog's default.
pub fn item_set(policies: &[Policy], key: &str) -> bool {
    let Some(spec) = catalog_item(key) else {
        return false;
    };
    let off_default = |value: &String| match spec.value_type {
        PolicyValueType::Int { .. } => value.parse::<i64>().ok() != spec.default_value.parse().ok(),
        _ => value != spec.default_value,
    };
    let linked = policies
        .iter()
        .filter(|policy| !policy.linked_ous.is_empty());
    linked
        .filter_map(|policy| policy.items.get(key))
        .any(off_default)
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ItemFlags {
    pub login_hours: bool,
    pub networks: bool,
    pub inactivity: bool,
}

impl ItemFlags {
    pub fn of(policies: &[Policy]) -> Self {
        Self {
            login_hours: item_set(policies, LOGIN_HOURS),
            networks: item_set(policies, ALLOWED_NETWORKS),
            inactivity: item_set(policies, INACTIVITY_DAYS),
        }
    }

    #[cfg(any(test, feature = "test-backend-scope"))]
    pub fn held(cache: &PolicyCache) -> Self {
        Self {
            login_hours: !cache.item_off(LOGIN_HOURS),
            networks: !cache.item_off(ALLOWED_NETWORKS),
            inactivity: !cache.item_off(INACTIVITY_DAYS),
        }
    }

    fn keyed(self) -> [(&'static str, bool); 3] {
        let on = [self.login_hours, self.networks, self.inactivity];
        [0, 1, 2].map(|at| (GATED[at], on[at]))
    }
}

/// An item turning on fills the cache first and stays unread while that fails. A live
/// inactivity's missed read is filled again.
pub async fn follow_items<H>(handler: &H, cache: &PolicyCache, policies: &[Policy]) -> Result<bool>
where
    H: UserListerBackendHandler + UserBackendHandler + PolicyBackendHandler + ?Sized,
{
    for said in login_hours::UNPARSED.take(policies) {
        warn!("{said}");
    }
    let mut rising = Vec::new();
    for (key, on) in ItemFlags::of(policies).keyed() {
        match (on, cache.item_state(key)) {
            (false, _) => cache.set_item(key, FLAG_OFF),
            (true, FLAG_ON) => {}
            (true, _) => rising.push(key),
        }
    }
    if rising.is_empty() {
        if cache.activity_due() {
            fill_policy_cache(handler, cache).await?;
        }
        return Ok(false);
    }
    let mark = |state| rising.iter().for_each(|key| cache.set_item(key, state));
    let flipped = async {
        fill_policy_cache(handler, cache).await?;
        mark(FLAG_ON);
        fill_policy_cache(handler, cache).await
    };
    if let Err(e) = flipped.await {
        mark(FLAG_UNKNOWN);
        return Err(e);
    }
    Ok(true)
}

/// The OUs whose policy turns the factor on with no explicit server-wide value over them.
pub fn ous_asking_mfa(server: Option<MfaPolicy>, policies: &[Policy]) -> usize {
    let asking = policies.iter().filter(|policy| asks_mfa(policy));
    let ous = asking.map(|policy| policy.linked_ous.len()).sum();
    if server.is_some() { 0 } else { ous }
}

/// The start's one warning that stored OU items now ask a factor: a count, never a name.
#[derive(Default)]
pub struct StartWarning(AtomicBool);

impl StartWarning {
    pub const fn new() -> Self {
        Self(AtomicBool::new(false))
    }

    pub fn take(&self, server: Option<MfaPolicy>, policies: &[Policy]) -> Option<String> {
        let ous = ous_asking_mfa(server, policies);
        if ous == 0 || self.0.swap(true, Ordering::AcqRel) {
            return None;
        }
        Some(format!(
            "{ous} OU(s) set enable-mfa to enabled or always, and no server-wide enable_mfa \
             overrides them: under always, a user without a factor is refused at the LDAP bind \
             and the simple login, administrators and service accounts too, until enrolled or \
             in {MFA_DISABLED_GROUP}"
        ))
    }
}

/// Made by whichever server first sees the item apply; a name held in any case is kept.
pub async fn ensure_exempt_group<H>(handler: &H) -> Result<()>
where
    H: GroupListerBackendHandler + GroupBackendHandler + ?Sized,
{
    let filter = GroupRequestFilter::DisplayName(MFA_DISABLED_GROUP.into());
    let named = handler.list_groups(Some(filter)).await?;
    let holds = |name: &str| name.to_lowercase() == MFA_DISABLED_GROUP;
    if named.iter().any(|group| holds(group.display_name.as_str())) {
        return Ok(());
    }
    let ou = Attribute {
        name: "ou".into(),
        value: "groups".to_owned().into(),
    };
    let request = CreateGroupRequest {
        display_name: MFA_DISABLED_GROUP.into(),
        attributes: vec![ou],
    };
    handler.create_group(request).await.map(drop)
}

pub async fn exempt_group_twin<H>(handler: &H) -> Result<Option<String>>
where
    H: GroupListerBackendHandler + ?Sized,
{
    let filter = GroupRequestFilter::DisplayName(MFA_DISABLED_GROUP.into());
    let named = handler.list_groups(Some(filter)).await?;
    let twin = named.into_iter().find_map(|group| {
        let name = group.display_name.into_string();
        let twin = name != MFA_DISABLED_GROUP && name.to_lowercase() == MFA_DISABLED_GROUP;
        twin.then_some(name)
    });
    Ok(twin.map(|name| {
        format!(
            "The group {name} is not the exempt group {MFA_DISABLED_GROUP}, whose name it takes \
             in another case: while it exists, nobody is exempt"
        )
    }))
}

#[derive(Clone, Debug)]
pub struct LoadedZone {
    pub zone: TimeZone,
    pub source: String,
}

/// The system's zone files only, under `TZDIR` when set; the process's own zone is never read.
pub fn load_zone(name: &str) -> std::result::Result<LoadedZone, String> {
    let dir = std::env::var_os("TZDIR").filter(|dir| !dir.is_empty());
    load_zone_from(
        &dir.map_or_else(|| PathBuf::from(ZONE_FILES), PathBuf::from),
        name,
    )
}

pub fn load_zone_from(dir: &Path, name: &str) -> std::result::Result<LoadedZone, String> {
    if name.eq_ignore_ascii_case("UTC") {
        let source = BUILT_IN.to_owned();
        return Ok(LoadedZone {
            zone: TimeZone::UTC,
            source,
        });
    }
    let refused = |cause: &str| format!("login_hours_timezone \"{name}\" is refused: {cause}");
    let part = |part: &str| {
        let named = |c: char| c.is_ascii_alphanumeric() || "_+-".contains(c);
        !part.is_empty() && part != "." && part != ".." && part.chars().all(named)
    };
    let first = name.split('/').next().unwrap_or_default();
    let tree = ["right", "posix"]
        .iter()
        .any(|tree| first.eq_ignore_ascii_case(tree));
    let host = ["localtime", "posixrules"]
        .iter()
        .any(|own| name.eq_ignore_ascii_case(own));
    if tree || host || !name.split('/').all(part) {
        return Err(refused("not an IANA time zone name"));
    }
    let path = dir.join(name);
    let unread = |e: &dyn std::fmt::Display| refused(&format!("{}: {e}", path.display()));
    let data = std::fs::read(&path).map_err(|e| unread(&e))?;
    let zone = TimeZone::tzif(name, &data).map_err(|e| unread(&e))?;
    let source = path.display().to_string();
    Ok(LoadedZone { zone, source })
}

pub async fn policy_changed<H>(handler: &H, cache: &PolicyCache)
where
    H: UserListerBackendHandler + UserBackendHandler + PolicyBackendHandler + ?Sized,
{
    if !live(cache) {
        return;
    }
    if let Err(e) = fill_policy_cache(handler, cache).await {
        warn!("The policy cache was not refilled after a policy change: {e}");
        cache.poke_fill();
    }
}

/// Passes over the marks until one finds none made since the pass before, `MARK_PASSES` at most,
/// ending at the first read that gave up; a mark leaves the set only once its entry is stored.
async fn take_marks<H>(handler: &H, cache: &PolicyCache)
where
    H: UserBackendHandler + PolicyBackendHandler + ?Sized,
{
    let mut seen = 0;
    for _ in 0..MARK_PASSES {
        let marks = cache.marked_since(seen);
        let Some(last) = marks.iter().map(|(_, made)| *made).max() else {
            return;
        };
        if !take_pass(handler, cache, marks).await {
            return;
        }
        seen = last;
    }
}

async fn take_pass<H>(handler: &H, cache: &PolicyCache, marks: Vec<(UserId, u64)>) -> bool
where
    H: UserBackendHandler + PolicyBackendHandler + ?Sized,
{
    for (user, made) in marks {
        let entry = match user_entry(handler, &user).await {
            Ok((ou_key, items, details)) => user_facts(handler, &details)
                .await
                .map(|facts| (ou_key, items, facts)),
            Err(e) => Err(e),
        };
        match entry {
            Ok((ou_key, items, mut facts)) => {
                let read = read_user_activity(handler, &user, &items, &mut facts).await;
                if !read {
                    facts.recorded = cache.current().facts_of(&user).and_then(|was| was.recorded);
                }
                cache.put_user(&user, &ou_key, items);
                cache.put_facts(&user, facts);
                if !read || !take_user_windows(handler, cache, &user).await {
                    cache.note_read_failed();
                    continue;
                }
            }
            Err(DomainError::EntityNotFound(_)) => cache.remove_user(&user),
            Err(e) if gave_up(&e) => {
                warn!("The policy cache did not take {user}'s change within its bound: {e}");
                return false;
            }
            Err(e) => {
                warn!("The policy cache did not take {user}'s change: {e}");
                cache.read_failed.store(true, Ordering::Release);
                continue;
            }
        }
        cache.unmark(&user, made);
    }
    true
}

/// Marks the user before trying the lock: a taker of the lock always sees the mark after it.
pub async fn user_written<H>(handler: &H, cache: &PolicyCache, user: &UserId)
where
    H: UserBackendHandler + PolicyBackendHandler + ?Sized,
{
    if !judged(&live_checks(&item_checks(), cache), user) {
        return;
    }
    cache.mark(user);
    let Some(_taking) = cache.try_take() else {
        return;
    };
    take_marks(handler, cache).await;
}

pub fn moves_ou(request: &UpdateUserRequest) -> bool {
    let inserted = request.insert_attributes.iter().map(|a| &a.name);
    let mut named = inserted.chain(&request.delete_attributes);
    named.any(|name| name.as_str().eq_ignore_ascii_case("ou"))
}

/// The users a change committed with the realm wrote as the cache holds them.
pub fn touched_users(rows: &[HostRow]) -> Vec<UserId> {
    let touched = |row: &HostRow| match row {
        HostRow::CreateUser(request) => Some(request.user_id.clone()),
        HostRow::UpdateUser(request) if moves_ou(request) => Some(request.user_id.clone()),
        HostRow::DeleteUser(user) => Some(user.clone()),
        _ => None,
    };
    rows.iter().filter_map(touched).collect()
}

/// An answer that may stand for a commit pokes a fill; a commit re-reads each user it touched.
pub async fn follow_commit<H>(
    handler: &H,
    cache: &PolicyCache,
    users: &[UserId],
    answer: &std::result::Result<(), CommitError>,
) where
    H: UserBackendHandler + PolicyBackendHandler + ?Sized,
{
    let checks = live_checks(&item_checks(), cache);
    let ours: Vec<&UserId> = users.iter().filter(|user| judged(&checks, user)).collect();
    if ours.is_empty() {
        return;
    }
    match answer {
        Ok(()) => {
            for user in ours {
                user_written(handler, cache, user).await;
            }
        }
        Err(CommitError::Unknown(_) | CommitError::Unsettled(_)) => cache.poke_fill(),
        Err(_) => {}
    }
}

#[async_trait]
pub trait CommitFollower: Send + Sync {
    async fn committed(&self, users: &[UserId], answer: &std::result::Result<(), CommitError>);
}

pub struct CacheFollower<H> {
    handler: H,
    cache: &'static PolicyCache,
}

impl<H> CacheFollower<H> {
    pub fn new(handler: H, cache: &'static PolicyCache) -> Self {
        Self { handler, cache }
    }
}

#[async_trait]
impl<H> CommitFollower for CacheFollower<H>
where
    H: UserBackendHandler + PolicyBackendHandler + Send + Sync,
{
    async fn committed(&self, users: &[UserId], answer: &std::result::Result<(), CommitError>) {
        follow_commit(&self.handler, self.cache, users, answer).await;
    }
}

pub async fn resolve_items<H>(
    handler: &H,
    cache: &PolicyCache,
    user: &UserId,
) -> Result<Arc<[EffectiveItem]>>
where
    H: UserBackendHandler + PolicyBackendHandler + ?Sized,
{
    if let Some(items) = cache.get().shared_items_of(user) {
        return Ok(items);
    }
    Ok(user_entry(handler, user).await?.1)
}

/// The items and inactivity's start; a user the cache lacks costs one bounded read for both.
async fn resolve_entry<H>(
    handler: &H,
    cache: &PolicyCache,
    user: &UserId,
    activity: bool,
) -> Result<(Arc<[EffectiveItem]>, Option<Timestamp>)>
where
    H: UserBackendHandler + PolicyBackendHandler + ?Sized,
{
    if !activity {
        return Ok((resolve_items(handler, cache, user).await?, None));
    }
    let entries = cache.get();
    if let Some(items) = entries.shared_items_of(user) {
        return Ok((items, cached_active_since(cache, entries.facts_of(user))));
    }
    let read = tokio::time::timeout(POLICY_READ_WAIT, handler.bounded_activity_entry(user));
    let unanswered = DomainError::InternalError(POLICY_UNANSWERED.to_owned());
    let (details, levels, recorded) = read.await.map_err(|_| unanswered)??;
    let items = resolve_effective_items(POLICY_ITEM_CATALOG, &levels).into();
    let created = from_naive(details.creation_date);
    Ok((
        items,
        active_since(created, Some(recorded), cache.recording()),
    ))
}

/// When the user's idle time passed their limit, judged as at the doors; `None` while admitted.
pub async fn inactive_since<H>(
    handler: &H,
    cache: &PolicyCache,
    user: &UserId,
    now: Timestamp,
) -> Result<Option<Timestamp>>
where
    H: UserBackendHandler + PolicyBackendHandler + ?Sized,
{
    if cache.item_off(INACTIVITY_DAYS) {
        return Ok(None);
    }
    let unread = || DomainError::InternalError(format!("{INACTIVITY_DAYS}: {UNREADABLE}"));
    if cache.item_unread(INACTIVITY_DAYS) {
        return Err(unread());
    }
    let (items, since) = resolve_entry(handler, cache, user, true).await?;
    let value = items
        .iter()
        .find(|item| item.key == INACTIVITY_DAYS)
        .map_or("0", |item| item.value.as_str());
    idle_past_limit(value, since, now).ok_or_else(unread)
}

fn unread_item(
    cache: &PolicyCache,
    attempt: &Attempt<'_>,
    checks: &[Arc<dyn ItemCheck>],
) -> Option<&'static str> {
    let unread = |check: &&Arc<dyn ItemCheck>| {
        cache.item_unread(check.key()) || (!check.loaded() && check.live(cache))
    };
    let judging = checks.iter().filter(|check| judges_attempt(check, attempt));
    judging.filter(unread).map(|check| check.key()).next()
}

/// Until an item it judges is read, a user is refused as when a policy is unreadable.
fn not_read_yet(
    cache: &PolicyCache,
    attempt: &Attempt<'_>,
    checks: &[Arc<dyn ItemCheck>],
) -> Option<Refusal> {
    unread_item(cache, attempt, checks).map(|_| Refusal {
        item: UNREADABLE,
        door: attempt.door,
        reason: None,
    })
}

/// The door's one row for a value that could not be read.
pub fn refuse_unreadable(user: &UserId, door: Door) -> Refusal {
    let refusal = Refusal {
        item: UNREADABLE,
        door,
        reason: None,
    };
    record_refusal(user, &refusal);
    refusal
}

fn record_refusal(user: &UserId, refusal: &Refusal) {
    logging::record_as(
        Some(user),
        refusal.door.log_kind(),
        Some(user.as_str()),
        false,
        Some(&refusal.detail()),
    );
}

pub async fn admit<H>(handler: &H, attempt: &Attempt<'_>) -> std::result::Result<(), Refusal>
where
    H: UserBackendHandler + PolicyBackendHandler + ?Sized,
{
    let cache = policy_cache();
    let checks = item_checks();
    if let Some(refusal) = not_read_yet(cache, attempt, &checks) {
        record_refusal(attempt.user, &refusal);
        return Err(refusal);
    }
    let (state, checks) = refusing(&checks, cache, lockout(), attempt.user);
    if checks.is_empty() {
        return Ok(());
    }
    let activity = checks.iter().any(|check| check.key() == INACTIVITY_DAYS);
    let decision = match resolve_entry(handler, cache, attempt.user, activity).await {
        Ok((items, active_since)) => {
            let state = UserState {
                active_since,
                ..state
            };
            let decided = decide(attempt, &items, &state, &checks);
            let locked = matches!(&decided, Err(refusal) if refusal.item == lockout::THRESHOLD);
            if locked && lockout().confirm(attempt.user).await {
                let state = UserState {
                    active_since,
                    ..lockout().user_state(attempt.user)
                };
                decide(attempt, &items, &state, &checks)
            } else {
                decided
            }
        }
        Err(e) => {
            warn!(
                "The policy of {} could not be read at {:?}: {e}",
                attempt.user, attempt.door
            );
            Err(Refusal {
                item: UNREADABLE,
                door: attempt.door,
                reason: None,
            })
        }
    };
    decision.inspect_err(|refusal| record_refusal(attempt.user, refusal))
}

/// The KDC's verdict: from memory, without a wait. A user the cache lacks is refused.
pub fn admit_at_kdc(
    cache: &PolicyCache,
    attempt: &Attempt<'_>,
    checks: &[Arc<dyn ItemCheck>],
) -> std::result::Result<(), Refusal> {
    admit_at_kdc_with(cache, lockout(), attempt, checks)
}

pub fn admit_at_kdc_with(
    cache: &PolicyCache,
    lockout: &Lockout,
    attempt: &Attempt<'_>,
    checks: &[Arc<dyn ItemCheck>],
) -> std::result::Result<(), Refusal> {
    let refused = |item| Refusal {
        item,
        door: attempt.door,
        reason: None,
    };
    match unread_item(cache, attempt, checks) {
        Some(lockout::THRESHOLD) => return Err(refused(UNREADABLE)),
        Some(_) => {
            cache.poke_fill();
            return Err(refused(NOT_LOADED));
        }
        None => {}
    }
    let at_door = checks.iter().filter(|check| judges_attempt(check, attempt));
    let at_door: Vec<_> = at_door.cloned().collect();
    let (state, checks) = refusing(&at_door, cache, lockout, attempt.user);
    if checks.is_empty() {
        return Ok(());
    }
    let entries = cache.get();
    let Some(items) = entries.items_of(attempt.user) else {
        cache.poke_fill();
        return Err(refused(NOT_LOADED));
    };
    let state = UserState {
        active_since: cached_active_since(cache, entries.facts_of(attempt.user)),
        ..state
    };
    decide(attempt, items, &state, &checks)
}

pub fn record_kdc_row(
    user: Option<&UserId>,
    target: &str,
    kind: LogKind,
    success: bool,
    peer: Option<IpAddr>,
    detail: &str,
    proved: bool,
) {
    let meta = RequestMeta {
        protocol: Protocol::Kerberos,
        peer,
        client_address: peer,
        ..RequestMeta::default()
    };
    let row = || logging::record_as(user, kind, Some(target), success, Some(detail));
    logging::with_request_sync(meta, || match proved {
        true => logging::proved_sync(row),
        false => row(),
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handler::{ReadSchemaBackendHandler, UserRequestFilter};
    use crate::inactivity::Recording;
    use crate::inactivity::tests::turn;
    use crate::instant::SignedDuration;
    use crate::lockout::{LockStore, LockWrite, SplitMark, StoredLock, Written, first_follow};
    use crate::policies::{
        AttachedPolicy, CreatePolicyRequest, ItemSource, OuPolicyState, Policy, PolicyId,
        PolicyLevel, PolicyScope, UpdatePolicyRequest, catalog_item,
    };
    use chrono::DateTime;
    use lldap_domain::requests::{CreateUserRequest, UpdateGroupRequest};
    use lldap_domain::types::{Attribute, Group, GroupDetails, GroupId, User, UserAndGroups, Uuid};
    use lldap_schema::PublicSchema;
    use pretty_assertions::assert_eq;
    use std::collections::{BTreeMap, HashSet};
    use std::sync::atomic::AtomicBool;

    struct Check(&'static str, fn(&Attempt<'_>, &str) -> bool);

    impl ItemCheck for Check {
        fn key(&self) -> &'static str {
            self.0
        }
        fn allows(&self, attempt: &Attempt<'_>, value: &str, _: &UserState) -> bool {
            (self.1)(attempt, value)
        }
    }

    fn check(key: &'static str, allows: fn(&Attempt<'_>, &str) -> bool) -> Arc<dyn ItemCheck> {
        Arc::new(Check(key, allows))
    }

    struct Only(&'static str, &'static str);

    impl ItemCheck for Only {
        fn key(&self) -> &'static str {
            self.1
        }
        fn judges(&self, user: &UserId) -> bool {
            user.as_str() == self.0
        }
        fn allows(&self, _: &Attempt<'_>, _: &str, _: &UserState) -> bool {
            false
        }
    }

    fn only(user: &'static str, key: &'static str) -> Arc<dyn ItemCheck> {
        Arc::new(Only(user, key))
    }

    fn item(key: &str, value: &str) -> EffectiveItem {
        EffectiveItem {
            key: key.to_owned(),
            scope: PolicyScope::User,
            value: value.to_owned(),
            enforced: false,
            source: None,
        }
    }

    fn at(seconds: i64) -> Timestamp {
        Timestamp::from_second(1_700_000_000 + seconds).unwrap()
    }

    fn entries(users: &[(&str, &str)], ous: &[(&str, &[EffectiveItem])]) -> Entries {
        Entries {
            ous_of_users: users
                .iter()
                .map(|(user, ou)| (UserId::new(user), (*ou).to_owned()))
                .collect(),
            items_of_ous: ous
                .iter()
                .map(|(ou, items)| ((*ou).to_owned(), items.to_vec().into()))
                .collect(),
            facts: HashMap::new(),
            windows: HashMap::new(),
            built_at: at(0),
        }
    }

    #[test]
    fn test_decide_table() {
        let bob = UserId::new("bob");
        let attempt = Attempt {
            user: &bob,
            door: Door::LdapBind,
            peer: None,
            now: at(0),
            second_factor: true,
        };
        let refuse = |key| check(key, |_, _| false);
        let allow = |key| check(key, |_, _| true);
        let items = [
            item("login-hours", "mon 08:00-09:00"),
            item("enable-mfa", "always"),
        ];
        let refused = |item| {
            Err(Refusal {
                item,
                door: Door::LdapBind,
                reason: None,
            })
        };
        let rows = [
            ("no checks", vec![], Ok(())),
            (
                "one refusing",
                vec![refuse("login-hours")],
                refused("login-hours"),
            ),
            (
                "not in the effective set",
                vec![refuse("inactivity-days")],
                Ok(()),
            ),
            (
                "the first refusing is named",
                vec![
                    allow("login-hours"),
                    refuse("enable-mfa"),
                    refuse("login-hours"),
                ],
                refused("enable-mfa"),
            ),
            (
                "the check sees the value",
                vec![check("enable-mfa", |_, value| value == "off")],
                refused("enable-mfa"),
            ),
            (
                "the check sees the attempt",
                vec![check("enable-mfa", |attempt, _| attempt.second_factor)],
                Ok(()),
            ),
            (
                "a check that judges another user",
                vec![only("alice", "login-hours")],
                Ok(()),
            ),
            (
                "a check that judges this user",
                vec![only("bob", "login-hours")],
                refused("login-hours"),
            ),
        ];
        for (row, checks, expected) in rows {
            assert_eq!(
                decide(&attempt, &items, &UserState::default(), &checks),
                expected,
                "{row}"
            );
        }
    }

    #[test]
    fn test_enforced_flags_match_the_checks() {
        let checks = default_item_checks();
        let keys = checks.iter().map(|c| c.key());
        let read = checks
            .iter()
            .flat_map(|c| c.also_enforces().iter().copied());
        let checked: HashSet<&str> = keys.chain(read).collect();
        assert_eq!(
            checked,
            HashSet::from([
                "lockout-threshold",
                "lockout-duration-seconds",
                "enable-mfa",
                "inactivity-days",
                "login-hours",
                "allowed-networks"
            ]),
            "the lockout, enable-mfa, inactivity-days, allowed-networks and login-hours are enforced \
             at sign-in"
        );
        let at_password_doors = crate::password::PASSWORD_MIN_LENGTH_ITEM;
        for spec in POLICY_ITEM_CATALOG {
            let enforced = checked.contains(spec.key) || spec.key == at_password_doors;
            let why = if spec.key == at_password_doors {
                "enforced without an ItemCheck: judged at a password change, read from the \
                 database, never at sign-in"
            } else {
                "enforced exactly when an ItemCheck reads it"
            };
            assert_eq!(spec.enforced, enforced, "{}: {why}", spec.key);
        }
        for key in checked {
            assert!(catalog_item(key).is_some(), "{key} is not a catalog item");
        }
    }

    fn set_by_ou(key: &str, value: &str) -> EffectiveItem {
        let source = ItemSource {
            policy_id: PolicyId(1),
            policy_name: "p".to_owned(),
            ou_key: "e2ou".to_owned(),
        };
        EffectiveItem {
            source: Some(source),
            ..item(key, value)
        }
    }

    #[test]
    fn test_the_mfa_item_costs_one_atomic_read_until_an_ou_sets_it() {
        use MfaPolicy::{Always, Disabled, Enrolled};
        let cache = PolicyCache::new();
        let strict = [set_by_ou("enable-mfa", "always")];
        let loose = [set_by_ou("enable-mfa", "enabled")];
        cache.replace(entries(
            &[("e2strict", "e2s"), ("e2loose", "e2l")],
            &[("e2s", &strict[..]), ("e2l", &loose[..])],
        ));
        let (strict, loose, missing) = (
            UserId::new("e2strict"),
            UserId::new("e2loose"),
            UserId::new("e2missing"),
        );
        let flag = |live: Option<bool>| match live {
            Some(live) => cache.set_mfa_item_live(live),
            None => cache.set_mfa_item_unknown(),
        };
        let (off, on, unknown) = (Some(false), Some(true), None);
        let rows = [
            (
                "nothing set anywhere",
                off,
                None,
                Some(false),
                [Some(Disabled); 3],
                false,
            ),
            (
                "an OU sets it",
                on,
                None,
                Some(true),
                [Some(Always), Some(Enrolled), None],
                true,
            ),
            (
                "an explicit always overrides",
                on,
                Some(Always),
                Some(false),
                [Some(Always); 3],
                true,
            ),
            (
                "an explicit enabled overrides",
                on,
                Some(Enrolled),
                Some(false),
                [Some(Enrolled); 3],
                true,
            ),
            (
                "an explicit off overrides",
                on,
                Some(Disabled),
                Some(false),
                [Some(Disabled); 3],
                false,
            ),
            ("not read yet", unknown, None, None, [None; 3], true),
            (
                "not read yet, an explicit off",
                unknown,
                Some(Disabled),
                Some(false),
                [Some(Disabled); 3],
                false,
            ),
        ];
        for (label, live, server, matters, policies, can_be_on) in rows {
            flag(live);
            cache.set_mfa_policy(server);
            let reads = cache.reads();
            assert_eq!(mfa_item_matters(&cache, server), matters, "{label}");
            assert_eq!(mfa_can_be_on(server, &cache), can_be_on, "{label}");
            assert_eq!(cache.reads(), reads, "{label}: no read of the entries");
            let held = cache.get();
            let got =
                [&strict, &loose, &missing].map(|user| cached_mfa_policy(&cache, &held, user));
            assert_eq!(got, policies, "{label}");
        }
        for live in [unknown, on] {
            flag(live);
            cache.set_mfa_policy(Some(Enrolled));
            assert!(
                !MfaItemCheck.live(&cache),
                "an explicit value: the OUs' item is not live ({live:?})"
            );
        }
        cache.set_mfa_policy(None);
        flag(unknown);
        assert!(
            MfaItemCheck.live(&cache),
            "not read yet: the cache is kept filled"
        );
        flag(off);
        assert!(!MfaItemCheck.live(&cache), "no OU sets it: no fill");
    }

    #[test]
    fn test_an_attempt_at_the_kdc_is_made_at_the_second_the_kdc_gives() {
        let bob = UserId::new("bob");
        for now in [0, 1_700_000_000, 2_147_483_648, u32::MAX] {
            let attempt = Attempt::at_kdc(&bob, Door::KerberosAs, None, now);
            assert_eq!(attempt.now, at(i64::from(now) - 1_700_000_000), "{now}");
        }
    }

    #[test]
    fn test_the_mfa_item_check_refuses_nothing_at_any_door() {
        let bob = UserId::new("bob");
        let items = [item("enable-mfa", "always")];
        let checks: Vec<Arc<dyn ItemCheck>> = vec![Arc::new(MfaItemCheck)];
        let (cache, counter) = (PolicyCache::new(), Lockout::default());
        cache.replace(entries(&[("bob", "e2s")], &[("e2s", &items[..])]));
        cache.set_mfa_item_live(true);
        for door in [
            Door::LdapBind,
            Door::WebLogin,
            Door::KerberosAs,
            Door::KerberosTgs,
        ] {
            let attempt = Attempt::at_kdc(&bob, door, None, 1_700_000_000);
            assert_eq!(
                decide(&attempt, &items, &UserState::default(), &checks),
                Ok(()),
                "{door:?}"
            );
            let reads = cache.reads();
            assert_eq!(
                (
                    admit_at_kdc_with(&cache, &counter, &attempt, &checks),
                    cache.reads() - reads
                ),
                (Ok(()), 0),
                "{door:?}: the KDC's verdict is as it was"
            );
        }
        assert!(!MfaItemCheck.may_refuse(&UserState::default()));
    }

    #[test]
    fn test_each_door_has_its_row_kind_and_only_logins_count() {
        let rows = [
            (Door::WebLogin, LogKind::Login, true, "web login"),
            (Door::SimpleLogin, LogKind::Bind, true, "simple login"),
            (Door::Refresh, LogKind::TokenRefresh, false, "token refresh"),
            (Door::TokenUse, LogKind::AccessDenied, false, "token use"),
            (Door::LdapBind, LogKind::Bind, true, "ldap bind"),
            (Door::KerberosAs, LogKind::Login, true, "kerberos"),
            (
                Door::KerberosTgs,
                LogKind::AccessDenied,
                false,
                "kerberos service ticket",
            ),
            (
                Door::KerberosS4u,
                LogKind::AccessDenied,
                false,
                "kerberos S4U",
            ),
        ];
        for (door, kind, login, name) in rows {
            assert_eq!(
                (door.log_kind(), door.is_login(), door.name()),
                (kind, login, name),
                "{door:?}"
            );
        }
    }

    #[test]
    fn test_the_lockout_costs_one_atomic_read_until_a_threshold_is_set_somewhere() {
        let (clean, counted) = (UserId::new("e1clean"), UserId::new("e1counted"));
        let (cache, counter) = (PolicyCache::new(), Lockout::default());
        let three = [
            item("lockout-threshold", "3"),
            item("lockout-duration-seconds", "0"),
        ];
        cache.replace(entries(
            &[("e1clean", "e1ou"), ("e1counted", "e1ou")],
            &[("e1ou", &three[..])],
        ));
        let failed = Some(at(-5));
        let locked = LockRow {
            fail_count: 3,
            last_failed: failed,
            ..LockRow::default()
        };
        counter.seed(&counted, locked);
        let checks = default_item_checks();
        let refused = Err(Refusal {
            item: "lockout-threshold",
            door: Door::KerberosAs,
            reason: None,
        });
        let rows = [
            ("no threshold anywhere", false, &counted, Ok(()), 0),
            ("a user with no count", true, &clean, Ok(()), 0),
            ("a locked user", true, &counted, refused, 1),
        ];
        for (label, live, user, expected, reads) in rows {
            cache.set_lockout_live(live);
            let attempt = Attempt::at_kdc(user, Door::KerberosAs, None, 1_700_000_000);
            let before = cache.reads();
            let got = admit_at_kdc_with(&cache, &counter, &attempt, &checks);
            assert_eq!((got, cache.reads() - before), (expected, reads), "{label}");
        }
        cache.set_lockout_unknown();
        let attempt = Attempt::at_kdc(&clean, Door::KerberosAs, None, 1_700_000_000);
        assert_eq!(
            admit_at_kdc_with(&cache, &counter, &attempt, &checks),
            Err(Refusal {
                item: UNREADABLE,
                door: Door::KerberosAs,
                reason: None,
            }),
            "until the policies are read, every user the lockout judges is refused"
        );
        let refusal = Refusal {
            item: "lockout-threshold",
            door: Door::LdapBind,
            reason: None,
        };
        assert_eq!(refusal.detail(), "locked out");
    }

    #[test]
    fn test_a_fill_whose_reads_keep_failing_backs_off_to_the_limit() {
        let mut gap = FILL_GAP;
        let mut gaps = Vec::new();
        for _ in 0..9 {
            gap = next_gap(gap, true);
            gaps.push(gap.as_millis());
        }
        assert_eq!(
            gaps,
            vec![
                500, 1_000, 2_000, 4_000, 8_000, 16_000, 30_000, 30_000, 30_000
            ]
        );
        assert_eq!(
            next_gap(gap, false),
            FILL_GAP,
            "a fill that reads everything"
        );
    }

    #[test]
    fn test_the_users_a_committed_change_touched() {
        use lldap_domain::requests::CreateUserRequest;
        use lldap_domain::types::Attribute;
        let update = |name: &str, attribute: Option<&str>| {
            let set = attribute.map(|name| Attribute {
                name: name.into(),
                value: "x".to_owned().into(),
            });
            HostRow::UpdateUser(UpdateUserRequest {
                user_id: UserId::new(name),
                insert_attributes: set.into_iter().collect(),
                ..Default::default()
            })
        };
        let created = CreateUserRequest {
            user_id: UserId::new("ann"),
            ..Default::default()
        };
        let rows = vec![
            HostRow::CreateUser(created),
            update("bea", Some("OU")),
            update("cal", Some("displayname")),
            update("dan", None),
            HostRow::DeleteUser(UserId::new("eve")),
            HostRow::SyncIs(UserId::new("fay"), true),
        ];
        let got: Vec<_> = touched_users(&rows)
            .iter()
            .map(|u| u.as_str().to_owned())
            .collect();
        assert_eq!(got, ["ann", "bea", "eve"]);
        let removed = UpdateUserRequest {
            delete_attributes: vec!["Ou".into()],
            ..Default::default()
        };
        assert!(moves_ou(&removed), "an OU removed is a move to the default");
    }

    #[tokio::test]
    async fn test_the_bind_door_is_named_by_the_requests_protocol() {
        let rows = [
            (RequestMeta::ldap(None, None), Door::LdapBind),
            (RequestMeta::http(None, None), Door::SimpleLogin),
        ];
        for (meta, door) in rows {
            let named = logging::with_request(meta, async { Door::of_bind() }).await;
            assert_eq!(named, door);
        }
    }

    #[test]
    fn test_an_attempt_at_the_kdc_takes_its_clock_and_peer() {
        let bob = UserId::new("bob");
        let peer: IpAddr = "192.0.2.7".parse().unwrap();
        let attempt = Attempt::at_kdc(&bob, Door::KerberosTgs, Some(peer), 1_700_000_000);
        assert_eq!(
            attempt,
            Attempt {
                user: &bob,
                door: Door::KerberosTgs,
                peer: Some(peer),
                now: at(0),
                second_factor: false,
            }
        );
    }

    #[tokio::test]
    async fn test_the_kdc_reads_the_cache_and_refuses_a_miss_with_a_poke() {
        let cache = PolicyCache::new();
        let labs = [item("login-hours", "mon 08:00-09:00")];
        let none: &[EffectiveItem] = &[];
        cache.replace(entries(
            &[("alice", "people\\labs"), ("bob", "people")],
            &[("people\\labs", &labs[..]), ("people", none)],
        ));
        let all = vec![check("login-hours", |_, value| value.is_empty())];
        let narrow = vec![only("alice", "login-hours")];
        let refused = |item| {
            Err(Refusal {
                item,
                door: Door::KerberosAs,
                reason: None,
            })
        };
        let rows = [
            ("alice", &all, refused("login-hours"), 1_u64, false),
            ("bob", &all, Ok(()), 1, false),
            ("carol", &all, refused(NOT_LOADED), 1, true),
            ("carol", &narrow, Ok(()), 0, false),
        ];
        for (user, checks, expected, read, poked) in rows {
            let user = UserId::new(user);
            let attempt = Attempt::at_kdc(&user, Door::KerberosAs, None, 1_700_000_000);
            let reads = cache.reads();
            assert_eq!(admit_at_kdc(&cache, &attempt, checks), expected, "{user}");
            let got_poke = tokio::time::timeout(Duration::from_millis(20), cache.poked())
                .await
                .is_ok();
            assert_eq!((cache.reads() - reads, got_poke), (read, poked), "{user}");
        }
    }

    #[test]
    fn test_an_edit_swaps_the_overlay_alone_and_a_held_reader_keeps_its_entries() {
        let (bob, amy) = (UserId::new("bob"), UserId::new("amy"));
        let hours = [item("login-hours", "")];
        type Edit = fn(&PolicyCache, &UserId);
        let rows: [(&str, Edit); 4] = [
            ("put_user", |cache, bob| {
                cache.put_user(bob, LABS, Vec::new().into())
            }),
            ("put_facts", |cache, bob| {
                cache.put_facts(bob, UserFacts::of(&user("bob"), std::iter::empty()))
            }),
            ("put_window", |cache, bob| cache.put_window(bob, opened())),
            ("remove_user", |cache, bob| cache.remove_user(bob)),
        ];
        for (label, edit) in rows {
            let cache = PolicyCache::new();
            cache.replace(entries(
                &[("bob", "people"), ("amy", "people")],
                &[("people", &hours[..])],
            ));
            let (held, generation) = (cache.get(), cache.generation());
            let was = held.of(&bob);
            edit(&cache, &bob);
            let now = cache.get();
            assert_eq!(
                (
                    Arc::ptr_eq(&held.base, &now.base),
                    held.of(&bob) == was,
                    now.of(&bob) != was,
                    now.of(&amy) == held.of(&amy),
                    now.over.len(),
                    cache.generation() - generation,
                ),
                (true, true, true, true, 1, 1),
                "{label}: one swap that shares the fill's entries; the held reader's user and the \
                 other user are as they were"
            );
        }
    }

    #[test]
    fn test_an_edit_of_one_user_leaves_its_ous_items_to_the_others_as_filled() {
        let cache = PolicyCache::new();
        let (bob, amy) = (UserId::new("bob"), UserId::new("amy"));
        let filled = [item("login-hours", "")];
        let read = [item("login-hours", "mon 08:00-09:00")];
        cache.replace(entries(
            &[("bob", "people"), ("amy", "people")],
            &[("people", &filled[..])],
        ));
        cache.put_user(&bob, "people", read.to_vec().into());
        let held = cache.get();
        assert_eq!(
            (held.items_of(&bob), held.items_of(&amy)),
            (Some(&read[..]), Some(&filled[..])),
            "the edited user's items alone: the OU's other users keep the fill's until the next"
        );
    }

    #[tokio::test]
    async fn test_the_overlay_asks_a_whole_fill_once_it_is_large_and_a_fill_folds_it() {
        let cache = PolicyCache::new();
        let items: Arc<[EffectiveItem]> = Vec::new().into();
        let name = |n: usize| UserId::new(&format!("r1fold{n}"));
        let edit = |n: usize| cache.put_user(&name(n), "people", items.clone());
        for n in 0..OVERLAY_FOLD {
            edit(n);
        }
        let at_the_limit = (cache.get().over.len(), poked(&cache).await);
        edit(OVERLAY_FOLD);
        let asked = cache.refill.load(Ordering::Acquire);
        let past_it = (cache.get().over.len(), asked, poked(&cache).await);
        cache.remove_user(&name(0));
        let undone = cache.get().over.len();
        fill_policy_cache(&Directory::default(), &cache)
            .await
            .unwrap();
        assert_eq!(
            (at_the_limit, past_it, undone, cache.get().over.len()),
            (
                (OVERLAY_FOLD, false),
                (OVERLAY_FOLD + 1, true, true),
                OVERLAY_FOLD,
                0
            ),
            "past the fold size an edit asks a whole fill; an edit back to what the fill holds \
             leaves the overlay; the fill empties it"
        );
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn test_a_reread_that_changes_nothing_swaps_nothing() {
        let _judging = Judging::only(&[LATE, OTHER]);
        let cache = PolicyCache::new();
        let directory = Directory::knowing(&[LATE, OTHER]).listing(&[LATE, OTHER]);
        fill_policy_cache(&directory, &cache).await.unwrap();
        let generation = cache.generation();
        for n in 0..2_000 {
            let user = UserId::new([LATE, OTHER][n % 2]);
            user_written(&directory, &cache, &user).await;
        }
        assert_eq!(
            (cache.generation() - generation, poked(&cache).await),
            (0, false),
            "2,000 re-reads of users as the cache holds them: no swap, and no fill asked"
        );
    }

    struct Names(&'static [&'static str]);

    impl ItemCheck for Names {
        fn key(&self) -> &'static str {
            "login-hours"
        }
        fn judges(&self, user: &UserId) -> bool {
            self.0.contains(&user.as_str())
        }
        fn allows(&self, _: &Attempt<'_>, _: &str, _: &UserState) -> bool {
            true
        }
    }

    struct Judging;

    impl Judging {
        fn only(users: &'static [&'static str]) -> Self {
            let check: Arc<dyn ItemCheck> = Arc::new(Names(users));
            set_item_checks(vec![check].into());
            Self
        }
    }

    impl Drop for Judging {
        fn drop(&mut self) {
            set_item_checks(default_item_checks());
        }
    }

    const LATE: &str = "e0late";
    const OTHER: &str = "e0other";
    const SLOW: &str = "e0slow";
    const LABS: &str = "people\\labs";
    const STALLED: &str = "k2stalled";
    const HELD: &str = "k2held";
    const NO_ANSWER: u8 = 1;
    const LOCK_ERROR: u8 = 2;
    const DOWN: u8 = 3;
    const WITHIN: Duration = Duration::from_secs(4);

    fn user(name: &str) -> User {
        user_in(name, LABS)
    }

    fn user_in(name: &str, ou: &str) -> User {
        let epoch = DateTime::from_timestamp(0, 0).unwrap().naive_utc();
        User {
            user_id: UserId::new(name),
            email: format!("{name}@example.com").into(),
            display_name: None,
            creation_date: epoch,
            uuid: Uuid::from_name_and_date(name, &epoch),
            attributes: vec![Attribute {
                name: "ou".into(),
                value: ou.to_owned().into(),
            }],
            modified_date: epoch,
            password_modified_date: epoch,
            krb_principal_name: None,
            mfa_type: None,
        }
    }

    /// Its listing is the fill's snapshot, taken before the writes the hooks report.
    #[derive(Default)]
    struct Directory {
        listed: Vec<User>,
        users: Mutex<HashMap<UserId, User>>,
        stalled: AtomicBool,
        moves: Mutex<Option<(UserId, &'static str)>>,
        meanwhile: Mutex<Option<(&'static PolicyCache, UserId)>>,
        policies_down: AtomicBool,
        policy_reads: AtomicU64,
        policies: Vec<Policy>,
        users_down: AtomicBool,
        user_lists: AtomicU64,
        groups: Mutex<Vec<CreateGroupRequest>>,
        proof_rows: Vec<(UserId, ProofWindow)>,
        proofs_down: AtomicBool,
        proof_reads: AtomicU64,
        policy_read: AtomicU8,
        entry_reads: AtomicU64,
        watching: Mutex<Option<(&'static PolicyCache, &'static Lockout)>>,
        verdicts: Mutex<Vec<(bool, std::result::Result<(), Refusal>)>>,
        watching_idle: Mutex<Option<(&'static PolicyCache, &'static Lockout)>>,
        levels: Vec<PolicyLevel>,
        activity_rows: Mutex<Vec<(UserId, Recorded)>>,
        activity_down: AtomicBool,
        activity_reads: AtomicU64,
        activity_entry_reads: AtomicU64,
        recording_down: AtomicBool,
        successes: Mutex<Vec<(UserId, Timestamp)>>,
        restless: Mutex<Option<&'static PolicyCache>>,
    }

    impl Directory {
        fn knowing(names: &[&str]) -> Self {
            let users = names.iter().map(|name| (UserId::new(name), user(name)));
            Self {
                users: Mutex::new(users.collect()),
                ..Self::default()
            }
        }

        fn listing(mut self, names: &[&str]) -> Self {
            self.listed = names.iter().map(|name| user(name)).collect();
            self
        }

        fn asking(mut self, value: &str) -> Self {
            self.policies = vec![Policy {
                id: PolicyId(1),
                name: "labs".to_owned(),
                description: String::new(),
                items: BTreeMap::from([(ENABLE_MFA.to_owned(), value.to_owned())]),
                linked_ous: vec![LABS.to_owned()],
            }];
            self
        }

        fn enrolling(mut self, names: &[&str]) -> Self {
            let named = |user: &&mut User| names.contains(&user.user_id.as_str());
            let enrol = |user: &mut User| user.mfa_type = Some(MFA_TYPE_TOTP.to_owned());
            self.listed.iter_mut().filter(named).for_each(enrol);
            let users = self.users.get_mut().unwrap().values_mut();
            users.filter(named).for_each(enrol);
            self
        }

        fn group_names(&self) -> Vec<String> {
            let made = self.groups.lock().unwrap();
            made.iter().map(|g| g.display_name.to_string()).collect()
        }
    }

    #[async_trait]
    impl ReadSchemaBackendHandler for Directory {
        async fn get_schema(&self) -> Result<PublicSchema> {
            unimplemented!()
        }
    }

    #[async_trait]
    impl UserListerBackendHandler for Directory {
        async fn list_users(
            &self,
            _: Option<UserRequestFilter>,
            _: bool,
        ) -> Result<Vec<UserAndGroups>> {
            self.user_lists.fetch_add(1, Ordering::Relaxed);
            if let Some((cache, counter)) = *self.watching.lock().unwrap() {
                let late = UserId::new(LATE);
                let attempt = Attempt::at_kdc(&late, Door::KerberosAs, None, 1_700_000_000);
                let checks: Vec<Arc<dyn ItemCheck>> = vec![Arc::new(HoursLive)];
                let verdict = admit_at_kdc_with(cache, counter, &attempt, &checks);
                let flag = !cache.item_off(LOGIN_HOURS);
                self.verdicts.lock().unwrap().push((flag, verdict));
            }
            if let Some((cache, counter)) = *self.watching_idle.lock().unwrap() {
                let late = UserId::new(LATE);
                let attempt = Attempt::at_kdc(&late, Door::KerberosAs, None, 1_700_000_000);
                let checks: Vec<Arc<dyn ItemCheck>> = vec![Arc::new(InactivityCheck)];
                let verdict = admit_at_kdc_with(cache, counter, &attempt, &checks);
                let flag = !cache.item_off(INACTIVITY_DAYS);
                self.verdicts.lock().unwrap().push((flag, verdict));
            }
            if self.users_down.load(Ordering::Relaxed) {
                return Err(DomainError::InternalError("down".to_owned()));
            }
            let listed = self.listed.iter().cloned();
            Ok(listed
                .map(|user| UserAndGroups { user, groups: None })
                .collect())
        }
    }

    #[async_trait]
    impl UserBackendHandler for Directory {
        async fn get_user_details(&self, user_id: &UserId) -> Result<User> {
            if user_id.as_str() == SLOW && self.stalled.load(Ordering::Relaxed) {
                std::future::pending::<()>().await;
            }
            let found = self.users.lock().unwrap().get(user_id).cloned();
            let moved = self.moves.lock().unwrap().take();
            if let Some((name, ou)) = moved {
                let later = user_in(name.as_str(), ou);
                self.users.lock().unwrap().insert(name, later);
            }
            let meanwhile = self.meanwhile.lock().unwrap().take();
            if let Some((cache, other)) = meanwhile {
                cache.mark(&other);
            }
            if let Some(cache) = *self.restless.lock().unwrap() {
                cache.mark(user_id);
            }
            found.ok_or_else(|| DomainError::EntityNotFound(user_id.to_string()))
        }
        async fn create_user(&self, _: CreateUserRequest) -> Result<()> {
            unimplemented!()
        }
        async fn update_user(&self, _: UpdateUserRequest) -> Result<()> {
            unimplemented!()
        }
        async fn delete_user(&self, _: &UserId) -> Result<()> {
            unimplemented!()
        }
        async fn add_user_to_group(&self, _: &UserId, _: GroupId) -> Result<()> {
            unimplemented!()
        }
        async fn remove_user_from_group(&self, _: &UserId, _: GroupId) -> Result<()> {
            unimplemented!()
        }
        async fn get_user_groups(&self, _: &UserId) -> Result<HashSet<GroupDetails>> {
            Ok(HashSet::new())
        }
        async fn ensure_kerberos_principal_consistency(&self, _: &UserId, _: bool) -> Result<()> {
            unimplemented!()
        }
    }

    #[async_trait]
    impl PolicyBackendHandler for Directory {
        async fn list_policies(&self) -> Result<Vec<Policy>> {
            self.policy_reads.fetch_add(1, Ordering::Relaxed);
            match self.policies_down.load(Ordering::Relaxed) {
                true => Err(DomainError::InternalError("down".to_owned())),
                false => Ok(self.policies.clone()),
            }
        }
        async fn get_policy(&self, _: PolicyId) -> Result<Policy> {
            unimplemented!()
        }
        async fn create_policy(&self, _: CreatePolicyRequest) -> Result<PolicyId> {
            unimplemented!()
        }
        async fn update_policy(&self, _: UpdatePolicyRequest) -> Result<()> {
            unimplemented!()
        }
        async fn delete_policy(&self, _: PolicyId) -> Result<()> {
            unimplemented!()
        }
        async fn set_ou_policy(&self, _: &str, _: PolicyId) -> Result<()> {
            unimplemented!()
        }
        async fn clear_ou_policy(&self, _: &str) -> Result<()> {
            unimplemented!()
        }
        async fn set_ou_policy_inheritance(&self, _: &str, _: bool) -> Result<()> {
            unimplemented!()
        }
        async fn list_ou_policy_states(&self) -> Result<Vec<OuPolicyState>> {
            unimplemented!()
        }
        async fn get_policy_levels(&self, _: &str) -> Result<Vec<PolicyLevel>> {
            Ok(self.levels.clone())
        }
        async fn delete_ou_policy_state(&self, _: &str) -> Result<()> {
            unimplemented!()
        }
        async fn bounded_policy_entry(&self, user: &UserId) -> Result<(User, Vec<PolicyLevel>)> {
            self.entry_reads.fetch_add(1, Ordering::Relaxed);
            match self.policy_read.load(Ordering::Relaxed) {
                NO_ANSWER => std::future::pending().await,
                LOCK_ERROR => Err(DomainError::InternalError(POLICY_UNANSWERED.to_owned())),
                DOWN => Err(DomainError::InternalError("down".to_owned())),
                _ => {
                    let details = self.get_user_details(user).await?;
                    let ou_key = canonical_ou_key(&user_ou(&details.attributes));
                    Ok((details, self.get_policy_levels(&ou_key).await?))
                }
            }
        }
        async fn bounded_policy_levels(&self, _: &str) -> Result<Vec<PolicyLevel>> {
            unimplemented!()
        }
        async fn read_proof_windows(
            &self,
            user: Option<&UserId>,
        ) -> Result<Vec<(UserId, ProofWindow)>> {
            self.proof_reads.fetch_add(1, Ordering::Relaxed);
            if self.proofs_down.load(Ordering::Relaxed) {
                return Err(DomainError::InternalError("down".to_owned()));
            }
            let rows = self.proof_rows.iter();
            let theirs = rows.filter(|(owner, _)| user.is_none_or(|user| owner == user));
            Ok(theirs.cloned().collect())
        }
        async fn read_activity(&self, user: Option<&UserId>) -> Result<Vec<(UserId, Recorded)>> {
            self.activity_reads.fetch_add(1, Ordering::Relaxed);
            if self.activity_down.load(Ordering::Relaxed) {
                return Err(DomainError::InternalError("down".to_owned()));
            }
            let rows = self.activity_rows.lock().unwrap().clone().into_iter();
            Ok(rows
                .filter(|(owner, _)| user.is_none_or(|user| owner == user))
                .collect())
        }
        async fn bounded_activity_entry(
            &self,
            user: &UserId,
        ) -> Result<(User, Vec<PolicyLevel>, Recorded)> {
            self.activity_entry_reads.fetch_add(1, Ordering::Relaxed);
            let details = self.get_user_details(user).await?;
            let rows = self.activity_rows.lock().unwrap().clone().into_iter();
            let theirs = rows.into_iter().find(|(owner, _)| owner == user);
            let recorded = theirs.map(|(_, recorded)| recorded).unwrap_or_default();
            Ok((details, self.levels.clone(), recorded))
        }
    }

    #[async_trait]
    impl GroupListerBackendHandler for Directory {
        async fn list_groups(&self, _: Option<GroupRequestFilter>) -> Result<Vec<Group>> {
            let epoch = DateTime::from_timestamp(0, 0).unwrap().naive_utc();
            let made = self.groups.lock().unwrap().clone();
            let group = |(n, made): (usize, CreateGroupRequest)| Group {
                id: GroupId(n as i32 + 1),
                uuid: Uuid::from_name_and_date(made.display_name.as_str(), &epoch),
                display_name: made.display_name,
                creation_date: epoch,
                users: Vec::new(),
                attributes: made.attributes,
                modified_date: epoch,
            };
            Ok(made.into_iter().enumerate().map(group).collect())
        }
    }

    #[async_trait]
    impl GroupBackendHandler for Directory {
        async fn get_group_details(&self, _: GroupId) -> Result<GroupDetails> {
            unimplemented!()
        }
        async fn update_group(&self, _: UpdateGroupRequest) -> Result<()> {
            unimplemented!()
        }
        async fn create_group(&self, request: CreateGroupRequest) -> Result<GroupId> {
            let mut made = self.groups.lock().unwrap();
            made.push(request);
            Ok(GroupId(made.len() as i32))
        }
        async fn delete_group(&self, _: GroupId) -> Result<()> {
            unimplemented!()
        }
    }

    #[async_trait]
    impl LockStore for Directory {
        async fn read_lock(&self, _: &UserId) -> Result<Option<LockRow>> {
            Ok(None)
        }
        async fn read_locks(&self, _: Option<Timestamp>) -> Result<Vec<StoredLock>> {
            Ok(Vec::new())
        }
        async fn read_lock_users(&self) -> Result<Vec<UserId>> {
            Ok(Vec::new())
        }
        async fn read_split(&self, _: &UserId) -> Result<Option<SplitMark>> {
            Ok(None)
        }
        async fn read_period(&self) -> Result<String> {
            Ok("0".to_owned())
        }
        async fn write_locks(&self, period: &str, _: &[LockWrite]) -> Result<Written> {
            let period = period.to_owned();
            Ok(Written {
                period,
                ..Written::default()
            })
        }
        async fn read_recording(&self) -> Result<Option<Timestamp>> {
            match self.recording_down.load(Ordering::Relaxed) {
                true => Err(DomainError::InternalError("down".to_owned())),
                false => Ok(None),
            }
        }
        async fn write_success(&self, user: &UserId, at: Timestamp) -> Result<()> {
            self.successes.lock().unwrap().push((user.clone(), at));
            Ok(())
        }
    }

    #[tokio::test(start_paused = true)]
    async fn test_while_the_mfa_item_is_unknown_the_policies_are_read_again_every_second() {
        let cache: &'static PolicyCache = Box::leak(Box::new(PolicyCache::new()));
        let counter: &'static Lockout = Box::leak(Box::default());
        let directory = Arc::new(Directory::default());
        directory.policies_down.store(true, Ordering::Relaxed);
        cache.set_mfa_item_unknown();
        let running = counter.run(directory.clone(), cache);
        let reads = || directory.policy_reads.load(Ordering::Relaxed);
        let doors = || mfa_item_matters(cache, None);
        tokio::time::sleep(Duration::from_millis(3_900)).await;
        assert_eq!(
            (reads(), doors()),
            (3, None),
            "unreadable: read again each second, and the doors it concerns refuse"
        );
        directory.policies_down.store(false, Ordering::Relaxed);
        tokio::time::sleep(Duration::from_millis(1_250)).await;
        assert_eq!(
            (reads(), doors()),
            (4, Some(false)),
            "the next second's read takes it, and the doors serve"
        );
        tokio::time::sleep(Duration::from_secs(10)).await;
        assert_eq!(reads(), 4, "once read, no read until the next tick");
        counter.follow_policies(&*directory, cache).await.unwrap();
        assert_eq!(
            reads(),
            5,
            "a follow reads the policies once for both flags"
        );
        running.abort();
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn test_at_start_an_unreadable_mfa_item_leaves_the_lockout_known_and_the_kdc_admitting() {
        let (cache, counter) = (PolicyCache::new(), Lockout::default());
        let directory = Directory::knowing(&[LATE]).listing(&[LATE]);
        let directory = directory.asking("always");
        directory.users_down.store(true, Ordering::Relaxed);
        let started = first_follow(&counter, &directory, &cache).await;
        let flags = (cache.lockout_unknown(), mfa_item_matters(&cache, None));
        assert_eq!(
            (started.is_err(), flags),
            (true, (false, None)),
            "the item's fill failed; the lockout's flag left unknown all the same"
        );
        let (late, checks) = (UserId::new(LATE), default_item_checks());
        for door in [Door::KerberosAs, Door::KerberosTgs, Door::KerberosS4u] {
            let attempt = Attempt::new(&late, door);
            let verdict = admit_at_kdc(&cache, &attempt, &checks);
            assert_eq!(verdict, Ok(()), "{door:?}: no `policy: unreadable`");
        }
        assert_eq!(
            directory.group_names(),
            Vec::<String>::new(),
            "none while unknown"
        );
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn test_the_follow_makes_the_exempt_group_only_once_the_item_is_read_applying() {
        let always = Some(MfaPolicy::Always);
        let rows = [
            ("unreadable: unknown", "always", None, true, false),
            ("off", "off", None, false, false),
            (
                "an explicit value: the item is not read",
                "always",
                always,
                false,
                false,
            ),
            ("enabled, read", "enabled", None, false, true),
            ("always, read", "always", None, false, true),
        ];
        for (label, value, server, down, made) in rows {
            let (cache, counter) = (PolicyCache::new(), Lockout::default());
            cache.set_mfa_policy(server);
            let directory = Directory::knowing(&[LATE]).listing(&[LATE]);
            let directory = directory.asking(value);
            directory.users_down.store(down, Ordering::Relaxed);
            let _ = first_follow(&counter, &directory, &cache).await;
            let expected = match made {
                true => vec![MFA_DISABLED_GROUP.to_owned()],
                false => vec![],
            };
            assert_eq!(directory.group_names(), expected, "{label}");
        }
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn test_whichever_server_first_reads_the_item_applying_makes_the_one_exempt_group() {
        let directory = Directory::knowing(&[LATE]).listing(&[LATE]);
        let directory = directory.asking("always");
        let (here, there) = (PolicyCache::new(), PolicyCache::new());
        let (counter_here, counter_there) = (Lockout::default(), Lockout::default());
        directory.users_down.store(true, Ordering::Relaxed);
        let _ = first_follow(&counter_here, &directory, &here).await;
        assert_eq!(directory.group_names().len(), 0, "unreadable at this start");
        directory.users_down.store(false, Ordering::Relaxed);
        let tick = counter_there.follow_policies(&directory, &there).await;
        assert_eq!(
            (tick.is_ok(), directory.group_names()),
            (true, vec![MFA_DISABLED_GROUP.to_owned()]),
            "the other server's refill tick reads it applying and makes it"
        );
        let next = counter_here.follow_policies(&directory, &here).await;
        assert_eq!(
            (next.is_ok(), directory.group_names().len()),
            (true, 1),
            "this server's next follow keeps the one"
        );
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn test_under_an_explicit_value_the_ou_item_is_never_read() {
        let late = UserId::new(LATE);
        for server in [MfaPolicy::Disabled, MfaPolicy::Enrolled, MfaPolicy::Always] {
            let (cache, counter) = (PolicyCache::new(), Lockout::default());
            cache.set_mfa_policy(Some(server));
            let directory = Directory::knowing(&[LATE]).listing(&[LATE]);
            let directory = directory.asking("always");
            first_follow(&counter, &directory, &cache).await.unwrap();
            user_written(&directory, &cache, &late).await;
            policy_changed(&directory, &cache).await;
            let live = live_checks(&default_item_checks(), &cache).len();
            let lists = directory.user_lists.load(Ordering::Relaxed);
            assert_eq!(
                (live, lists, ou_of(&cache, &late)),
                (0, 0, None),
                "{server:?}: no fill at the follow, no re-read at a write"
            );
        }
    }

    #[test]
    fn test_the_start_warns_once_with_the_ou_count_when_stored_items_now_ask_a_factor() {
        let warning = StartWarning::new();
        let policy = |value: &str, ous: &[&str]| Policy {
            id: PolicyId(1),
            name: "p".to_owned(),
            description: String::new(),
            items: BTreeMap::from([(ENABLE_MFA.to_owned(), value.to_owned())]),
            linked_ous: ous.iter().map(|ou| ou.to_string()).collect(),
        };
        let (off, stored) = (
            [policy("off", &["people"])],
            [policy("always", &["a", "b"])],
        );
        let said = [
            warning.take(None, &off),
            warning.take(Some(MfaPolicy::Enrolled), &stored),
            warning.take(None, &stored),
            warning.take(None, &stored),
        ];
        let counted = said.map(|text| text.map(|t| t.starts_with("2 OU(s) set enable-mfa ")));
        assert_eq!(
            counted,
            [None, None, Some(true), None],
            "nothing stored, or an explicit value: no warning; stored items now enforced: one \
             warning with the count; a second call: none"
        );
    }

    #[test]
    fn test_the_start_counts_the_ous_that_turn_the_factor_on() {
        let policy = |id, value: &str, ous: &[&str]| Policy {
            id: PolicyId(id),
            name: format!("p{id}"),
            description: String::new(),
            items: BTreeMap::from([(ENABLE_MFA.to_owned(), value.to_owned())]),
            linked_ous: ous.iter().map(|ou| ou.to_string()).collect(),
        };
        let policies = [
            policy(1, "enabled", &["people", "people\\labs"]),
            policy(2, "always", &["staff"]),
            policy(3, "off", &["guests"]),
            policy(4, "always", &[]),
        ];
        let rows = [
            (None, 3),
            (Some(MfaPolicy::Disabled), 0),
            (Some(MfaPolicy::Enrolled), 0),
            (Some(MfaPolicy::Always), 0),
        ];
        for (server, ous) in rows {
            assert_eq!(ous_asking_mfa(server, &policies), ous, "{server:?}");
        }
    }

    fn opened() -> ProofWindow {
        let peer = String::new();
        ProofWindow {
            opened_at: 1_700_000_000,
            until_at: 1_700_000_600,
            peer,
        }
    }

    #[tokio::test]
    async fn test_the_fill_reads_the_windows_once_for_the_users_who_need_a_proof() {
        type Row = (&'static str, MfaPolicy, bool, u64, usize);
        let rows: [Row; 4] = [
            (
                "enabled: the enrolled user's",
                MfaPolicy::Enrolled,
                false,
                1,
                1,
            ),
            (
                "off: nobody's, nothing read",
                MfaPolicy::Disabled,
                false,
                0,
                0,
            ),
            ("always: both users'", MfaPolicy::Always, false, 1, 2),
            (
                "a failed read: none, the fill stands",
                MfaPolicy::Enrolled,
                true,
                1,
                0,
            ),
        ];
        for (label, server, down, reads, held) in rows {
            let cache = PolicyCache::new();
            cache.set_proofs(Some(ProofSettings::new(600, false, 3600)));
            cache.set_mfa_policy(Some(server));
            let directory = Directory::knowing(&[LATE, OTHER]).listing(&[LATE, OTHER]);
            let mut directory = directory.enrolling(&[LATE]);
            let both = [LATE, OTHER].map(|name| (UserId::new(name), opened()));
            directory.proof_rows = both.to_vec();
            directory.proofs_down.store(down, Ordering::Relaxed);
            let filled = fill_policy_cache(&directory, &cache).await;
            let entries = cache.get();
            let kept = [LATE, OTHER].map(|name| entries.windows_of(&UserId::new(name)).len());
            let failed = cache.read_failed.load(Ordering::Acquire);
            let read = directory.proof_reads.load(Ordering::Relaxed);
            assert_eq!(
                (filled.is_ok(), read, kept.iter().sum::<usize>(), failed),
                (true, reads, held, down),
                "{label}"
            );
        }
    }

    #[tokio::test]
    async fn test_a_proof_put_while_a_fill_holds_the_lock_is_read_by_the_taker() {
        let cache = PolicyCache::new();
        cache.set_proofs(Some(ProofSettings::new(600, false, 3600)));
        cache.set_mfa_policy(Some(MfaPolicy::Enrolled));
        let directory = Directory::knowing(&[LATE]).listing(&[LATE]);
        let mut directory = directory.enrolling(&[LATE]);
        directory.proof_rows = vec![(UserId::new(LATE), opened())];
        let late = UserId::new(LATE);
        let held = cache.writers.lock().await;
        cache.put_window(&late, opened());
        let entries = cache.get();
        let while_held = (entries.windows_of(&late).len(), cache.marks().users.len());
        drop(held);
        fill_policy_cache(&directory, &cache).await.unwrap();
        let entries = cache.get();
        let taken = (
            entries.windows_of(&late).to_vec(),
            cache.marks().users.len(),
        );
        assert_eq!(
            (while_held, taken),
            ((0, 1), (vec![opened()], 0)),
            "under a held lock the proof marks its user instead of editing; the taker reads it"
        );
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn test_a_written_user_who_needs_a_proof_reads_their_own_windows_again() {
        let cache = PolicyCache::new();
        cache.set_proofs(Some(ProofSettings::new(600, false, 3600)));
        cache.set_mfa_policy(Some(MfaPolicy::Enrolled));
        let mut directory = Directory::knowing(&[LATE, OTHER]).enrolling(&[LATE]);
        let both = [LATE, OTHER].map(|name| (UserId::new(name), opened()));
        directory.proof_rows = both.to_vec();
        let (late, other) = (UserId::new(LATE), UserId::new(OTHER));
        user_written(&directory, &cache, &late).await;
        user_written(&directory, &cache, &other).await;
        let entries = cache.get();
        let held = (entries.windows_of(&late), entries.windows_of(&other).len());
        assert_eq!(
            (directory.proof_reads.load(Ordering::Relaxed), held),
            (1, (&[opened()][..], 0)),
            "the enrolled user's own rows, read once; a user who needs no proof reads nothing"
        );
    }

    fn ou_of(cache: &PolicyCache, user: &UserId) -> Option<String> {
        cache.get().ou_of(user).map(str::to_owned)
    }

    async fn returns(hook: impl Future<Output = ()>) -> bool {
        tokio::time::timeout(Duration::from_millis(500), hook)
            .await
            .is_ok()
    }

    async fn poked(cache: &PolicyCache) -> bool {
        tokio::time::timeout(Duration::from_millis(20), cache.poked())
            .await
            .is_ok()
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn test_a_hook_under_a_held_lock_returns_and_the_fills_own_pass_stores_its_user() {
        let _judging = Judging::only(&[LATE]);
        let (cache, directory) = (PolicyCache::new(), Directory::knowing(&[LATE]));
        let late = UserId::new(LATE);
        let held = cache.writers.lock().await;
        assert!(
            returns(user_written(&directory, &cache, &late)).await,
            "the hook waited"
        );
        assert_eq!(
            ou_of(&cache, &late),
            None,
            "the hook stored nothing while the lock was held"
        );
        drop(held);
        fill_policy_cache(&directory, &cache).await.unwrap();
        assert_eq!(
            (ou_of(&cache, &late), cache.marks().users.len()),
            (Some(LABS.to_owned()), 0),
            "the fill's listing lacks the user: only its pass over the marks stores it"
        );
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn test_a_mark_left_under_a_held_lock_is_stored_by_the_next_taker() {
        let _judging = Judging::only(&[LATE, OTHER]);
        let (cache, directory) = (PolicyCache::new(), Directory::knowing(&[LATE, OTHER]));
        let (late, other) = (UserId::new(LATE), UserId::new(OTHER));
        let held = cache.writers.lock().await;
        assert!(
            returns(user_written(&directory, &cache, &late)).await,
            "the hook waited"
        );
        drop(held);
        assert_eq!(
            ou_of(&cache, &late),
            None,
            "letting the lock go stores nothing"
        );
        user_written(&directory, &cache, &other).await;
        assert_eq!(
            (
                ou_of(&cache, &late),
                ou_of(&cache, &other),
                cache.marks().users.len()
            ),
            (Some(LABS.to_owned()), Some(LABS.to_owned()), 0),
            "the next taker's pass stores every mark present when it took the lock"
        );
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn test_a_cancelled_pass_loses_no_mark_and_the_next_fill_stores_them() {
        let _judging = Judging::only(&[OTHER, SLOW]);
        let cache = PolicyCache::new();
        let directory = Directory::knowing(&[OTHER, SLOW]).listing(&[OTHER]);
        let (other, slow) = (UserId::new(OTHER), UserId::new(SLOW));
        let held = cache.writers.lock().await;
        user_written(&directory, &cache, &other).await;
        drop(held);
        directory.stalled.store(true, Ordering::Relaxed);
        assert!(
            !returns(user_written(&directory, &cache, &slow)).await,
            "the pass is dropped while it reads"
        );
        let marked = |user: &UserId| cache.marks().users.contains_key(user);
        assert!(
            marked(&slow),
            "the dropped pass keeps the mark it did not store"
        );
        assert_ne!(
            ou_of(&cache, &other).is_some(),
            marked(&other),
            "the other user is stored or still marked, never lost"
        );
        assert!(
            poked(&cache).await,
            "the dropped pass hands what is left to the filler"
        );
        directory.stalled.store(false, Ordering::Relaxed);
        fill_policy_cache(&directory, &cache).await.unwrap();
        assert_eq!(
            (ou_of(&cache, &slow), cache.marks().users.len()),
            (Some(LABS.to_owned()), 0),
            "the next fill stores the user its listing lacks"
        );
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn test_a_mark_made_during_a_holders_walk_is_taken_by_that_holder() {
        let _judging = Judging::only(&[LATE, OTHER]);
        let cache: &'static PolicyCache = Box::leak(Box::new(PolicyCache::new()));
        let directory = Directory::knowing(&[LATE, OTHER]);
        let (late, other) = (UserId::new(LATE), UserId::new(OTHER));
        *directory.meanwhile.lock().unwrap() = Some((cache, other.clone()));
        user_written(&directory, cache, &late).await;
        let left = (cache.marked(&other), poked(cache).await);
        assert_eq!(
            (ou_of(cache, &late), ou_of(cache, &other), left),
            (Some(LABS.to_owned()), Some(LABS.to_owned()), (false, false)),
            "the holder walks again for the mark made during its walk: none goes to the filler"
        );
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn test_a_user_marked_again_during_its_own_read_is_read_again_by_the_same_holder() {
        let _judging = Judging::only(&[LATE]);
        let cache: &'static PolicyCache = Box::leak(Box::new(PolicyCache::new()));
        let directory = Directory::knowing(&[LATE]);
        let late = UserId::new(LATE);
        *directory.moves.lock().unwrap() = Some((late.clone(), "people"));
        *directory.meanwhile.lock().unwrap() = Some((cache, late.clone()));
        user_written(&directory, cache, &late).await;
        let left = (cache.marked(&late), poked(cache).await);
        assert_eq!(
            (ou_of(cache, &late), left),
            (Some("people".to_owned()), (false, false)),
            "the mark made during the read outlives that read: the next pass stores the newer state"
        );
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn test_a_user_marked_at_every_read_is_left_to_the_filler_after_four_passes() {
        let _judging = Judging::only(&[LATE]);
        let cache: &'static PolicyCache = Box::leak(Box::new(PolicyCache::new()));
        let directory = Directory::knowing(&[LATE]);
        let late = UserId::new(LATE);
        *directory.restless.lock().unwrap() = Some(cache);
        user_written(&directory, cache, &late).await;
        let reads = directory.entry_reads.load(Ordering::Relaxed);
        assert_eq!(
            (reads, cache.marked(&late), poked(cache).await),
            (4, true, true),
            "a stream of writes holds the lock for four passes; the mark left goes to the filler"
        );
    }

    #[tokio::test(start_paused = true)]
    #[serial_test::serial]
    async fn test_a_mark_left_as_a_holder_lets_go_is_taken_by_the_filler_without_a_fill() {
        let _judging = Judging::only(&[LATE]);
        let cache: &'static PolicyCache = Box::leak(Box::new(PolicyCache::new()));
        let directory = Directory::knowing(&[LATE]).listing(&[OTHER]);
        let (late, other) = (UserId::new(LATE), UserId::new(OTHER));
        let filler = start_policy_filler(directory, cache);
        let held = cache.writers.lock().await;
        cache.mark(&late);
        drop(Taking {
            cache,
            writers: Some(held),
        });
        for _ in 0..100 {
            if !cache.marked(&late) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let alone = (ou_of(cache, &late), ou_of(cache, &other));
        cache.poke_fill();
        for _ in 0..100 {
            if ou_of(cache, &other).is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        filler.abort();
        assert_eq!(
            (alone, ou_of(cache, &other)),
            ((Some(LABS.to_owned()), None), Some(LABS.to_owned())),
            "the filler reads the marked user alone, not the listing, which holds another; a \
             poke still asks the whole fill"
        );
    }

    #[tokio::test]
    async fn test_a_mark_present_as_a_short_hold_ends_is_handed_to_the_filler() {
        let (late, other) = (UserId::new(LATE), UserId::new(OTHER));
        for (label, proof) in [("a proof put", true), ("a success held", false)] {
            let (cache, directory) = (PolicyCache::new(), Directory::default());
            turn(&cache, true);
            cache.mark(&late);
            match proof {
                true => cache.put_window(&other, opened()),
                false => cache.note_success(&directory, &other, at(0)).await,
            }
            assert!(poked(&cache).await, "{label}: letting go hands the mark on");
        }
    }

    struct Rows(Mutex<Vec<logging::LogEvent>>);

    impl logging::LogSink for Rows {
        fn record(&self, event: logging::LogEvent) {
            if matches!(event.actor.as_deref(), Some(STALLED | HELD)) {
                self.0.lock().unwrap().push(event);
            }
        }
    }

    impl Rows {
        fn take(&self) -> Vec<(LogKind, bool, Option<String>)> {
            let rows = std::mem::take(&mut *self.0.lock().unwrap());
            let row = |e: logging::LogEvent| (e.kind, e.success, e.detail);
            rows.into_iter().map(row).collect()
        }
    }

    #[tokio::test(start_paused = true)]
    #[serial_test::serial]
    async fn test_a_policy_read_past_its_bound_refuses_each_sign_in_door_with_its_one_row() {
        type Row = (Door, u8, LogKind, bool);
        let rows: [Row; 10] = [
            (Door::LdapBind, NO_ANSWER, LogKind::Bind, true),
            (Door::LdapBind, LOCK_ERROR, LogKind::Bind, false),
            (Door::SimpleLogin, NO_ANSWER, LogKind::Bind, true),
            (Door::SimpleLogin, LOCK_ERROR, LogKind::Bind, false),
            (Door::WebLogin, NO_ANSWER, LogKind::Login, true),
            (Door::WebLogin, LOCK_ERROR, LogKind::Login, false),
            (Door::Refresh, NO_ANSWER, LogKind::TokenRefresh, true),
            (Door::Refresh, LOCK_ERROR, LogKind::TokenRefresh, false),
            (Door::TokenUse, NO_ANSWER, LogKind::AccessDenied, true),
            (Door::TokenUse, LOCK_ERROR, LogKind::AccessDenied, false),
        ];
        let _judging = Judging::only(&[STALLED, HELD]);
        let sink = Arc::new(Rows(Mutex::default()));
        logging::set_log_sink(sink.clone());
        let directory = Directory::knowing(&[STALLED, HELD]);
        let (stalled, held) = (UserId::new(STALLED), UserId::new(HELD));
        let reads = || directory.entry_reads.load(Ordering::Relaxed);
        let (mut got, mut want) = (Vec::new(), Vec::new());
        for (door, answer, kind, waits) in rows {
            directory.policy_read.store(answer, Ordering::Relaxed);
            let (before, started) = (reads(), tokio::time::Instant::now());
            let answered = admit(&directory, &Attempt::new(&stalled, door)).await;
            let took = started.elapsed();
            let bound = (took >= POLICY_READ_WAIT, took < WITHIN);
            got.push((door, answer, answered, sink.take(), reads() - before, bound));
            let refusal = Refusal {
                item: UNREADABLE,
                door,
                reason: None,
            };
            let row = (kind, false, Some("policy: unreadable".to_owned()));
            want.push((door, answer, Err(refusal), vec![row], 1, (waits, true)));
        }
        policy_cache().put_user(&held, LABS, Vec::new().into());
        for (door, answer, _, _) in rows {
            directory.policy_read.store(answer, Ordering::Relaxed);
            let (before, started) = (reads(), tokio::time::Instant::now());
            let answered = admit(&directory, &Attempt::new(&held, door)).await;
            let took = started.elapsed();
            let bound = (took >= POLICY_READ_WAIT, took < WITHIN);
            got.push((door, answer, answered, sink.take(), reads() - before, bound));
            want.push((door, answer, Ok(()), vec![], 0, (false, true)));
        }
        policy_cache().remove_user(&held);
        logging::set_log_sink(Arc::new(logging::NoopLogSink));
        assert_eq!(got, want);
    }

    #[tokio::test(start_paused = true)]
    #[serial_test::serial]
    async fn test_the_lockouts_read_past_its_bound_is_its_existing_error() {
        let (cache, counter) = (PolicyCache::new(), Lockout::default());
        cache.set_lockout_live(true);
        let directory = Directory::knowing(&[STALLED]);
        let stalled = UserId::new(STALLED);
        let rows = [
            (NO_ANSWER, POLICY_UNANSWERED, true),
            (LOCK_ERROR, POLICY_UNANSWERED, false),
            (DOWN, "down", false),
        ];
        for (answer, error, waits) in rows {
            directory.policy_read.store(answer, Ordering::Relaxed);
            let started = tokio::time::Instant::now();
            let state = counter.state(&directory, &cache, &stalled).await;
            let took = started.elapsed();
            assert_eq!(
                (
                    state.map(drop).map_err(|e| e.to_string()),
                    took >= POLICY_READ_WAIT,
                    took < WITHIN
                ),
                (Err(format!("Internal error: `{error}`")), waits, true),
                "{answer}"
            );
        }
    }

    #[tokio::test(start_paused = true)]
    #[serial_test::serial]
    async fn test_a_mark_pass_that_gives_up_within_the_bound_keeps_the_mark_and_flags_no_failure() {
        let _judging = Judging::only(&[STALLED]);
        let cache: &'static PolicyCache = Box::leak(Box::new(PolicyCache::new()));
        let (counter, checks) = (Lockout::default(), item_checks());
        let directory = Directory::knowing(&[STALLED]);
        let stalled = UserId::new(STALLED);
        let kdc = || {
            let attempt = Attempt::at_kdc(&stalled, Door::KerberosAs, None, 1_700_000_000);
            admit_at_kdc_with(cache, &counter, &attempt, &checks)
        };
        let not_loaded = Err(Refusal {
            item: NOT_LOADED,
            door: Door::KerberosAs,
            reason: None,
        });
        type Row = (&'static str, u8, bool, bool);
        let rows: [Row; 3] = [
            ("a read that never answers", NO_ANSWER, true, false),
            ("the database's own bound", LOCK_ERROR, false, false),
            ("another error", DOWN, false, true),
        ];
        for (label, answer, waits, failed) in rows {
            directory.policy_read.store(answer, Ordering::Relaxed);
            cache.read_failed.store(false, Ordering::Release);
            poked(cache).await;
            let started = tokio::time::Instant::now();
            user_written(&directory, cache, &stalled).await;
            let took = started.elapsed();
            let handed = poked(cache).await;
            let left = (cache.marked(&stalled), cache.failed_read(), handed);
            assert_eq!(
                (left, kdc(), took >= POLICY_READ_WAIT, took < WITHIN),
                ((true, failed, true), not_loaded, waits, true),
                "{label}: the mark stays and goes to the filler"
            );
        }
        directory.policy_read.store(0, Ordering::Relaxed);
        let filler = start_policy_filler(directory, cache);
        let mut verdict = kdc();
        for _ in 0..100 {
            if verdict.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
            verdict = kdc();
        }
        filler.abort();
        assert_eq!(
            (verdict, cache.marked(&stalled)),
            (Ok(()), false),
            "the filler's next pass loads the user, with no other write"
        );
    }

    #[tokio::test(start_paused = true)]
    #[serial_test::serial]
    async fn test_a_mark_pass_leaves_at_the_first_read_that_gave_up_and_keeps_every_mark() {
        const MARKED: [&str; 3] = [STALLED, "k2stalled2", "k2stalled3"];
        let _judging = Judging::only(&MARKED);
        let cache: &'static PolicyCache = Box::leak(Box::new(PolicyCache::new()));
        let directory = Directory::knowing(&MARKED);
        let users = MARKED.map(UserId::new);
        let reads = || directory.entry_reads.load(Ordering::Relaxed);
        let marks = || users.iter().filter(|user| cache.marked(user)).count();
        let rows: [(&str, u8, bool); 2] = [
            ("a read that never answers", NO_ANSWER, true),
            ("the database's own bound", LOCK_ERROR, false),
        ];
        for (label, answer, waits) in rows {
            directory.policy_read.store(answer, Ordering::Relaxed);
            users.iter().for_each(|user| cache.mark(user));
            let (before, started) = (reads(), tokio::time::Instant::now());
            user_written(&directory, cache, &users[0]).await;
            let took = started.elapsed();
            assert_eq!(
                (
                    reads() - before,
                    marks(),
                    cache.failed_read(),
                    took >= POLICY_READ_WAIT,
                    took < POLICY_READ_WAIT * 2,
                ),
                (1, 3, false, waits, true),
                "{label}: one bounded read for the pass, every mark kept"
            );
        }
        directory.policy_read.store(0, Ordering::Relaxed);
        let before = reads();
        user_written(&directory, cache, &users[0]).await;
        assert_eq!(
            (reads() - before, marks()),
            (3, 0),
            "with the table free, the next pass takes every mark"
        );
    }

    struct HoursLive;

    impl ItemCheck for HoursLive {
        fn key(&self) -> &'static str {
            LOGIN_HOURS
        }
        fn live(&self, cache: &PolicyCache) -> bool {
            !cache.item_off(LOGIN_HOURS)
        }
        fn allows(&self, _: &Attempt<'_>, _: &str, _: &UserState) -> bool {
            true
        }
    }

    struct Outside;

    impl ItemCheck for Outside {
        fn key(&self) -> &'static str {
            LOGIN_HOURS
        }
        fn reason(&self) -> Option<&'static str> {
            Some("outside login hours")
        }
        fn judges_at_s4u(&self) -> bool {
            false
        }
        fn allows(&self, _: &Attempt<'_>, _: &str, _: &UserState) -> bool {
            false
        }
    }

    #[test]
    fn test_a_refusal_names_the_checks_reason_after_the_key() {
        let bob = UserId::new("bob");
        let items = [item(LOGIN_HOURS, "mon 08:00-09:00")];
        let reasoned: Vec<Arc<dyn ItemCheck>> = vec![Arc::new(Outside)];
        let scripted = vec![check(LOGIN_HOURS, |_, _| false)];
        let attempt = Attempt::at_kdc(&bob, Door::LdapBind, None, 1_700_000_000);
        let rows = [
            (
                &reasoned,
                Some("outside login hours"),
                "policy: login-hours (outside login hours)",
            ),
            (&scripted, None, "policy: login-hours"),
        ];
        for (checks, reason, detail) in rows {
            let refused = decide(&attempt, &items, &UserState::default(), checks).unwrap_err();
            assert_eq!(
                (refused.reason, refused.detail()),
                (reason, detail.to_owned())
            );
        }
        assert_eq!((LockoutCheck.reason(), MfaItemCheck.reason()), (None, None));
    }

    #[test]
    fn test_a_check_that_does_not_judge_at_s4u_is_left_out_there_only() {
        let bob = UserId::new("bob");
        let items = [item(LOGIN_HOURS, "mon 08:00-09:00")];
        let present: Vec<Arc<dyn ItemCheck>> = vec![Arc::new(Outside)];
        let everywhere = vec![check(LOGIN_HOURS, |_, _| false)];
        let outside = Some("outside login hours");
        let refused = |door, reason| {
            Err(Refusal {
                item: LOGIN_HOURS,
                door,
                reason,
            })
        };
        let rows = [
            (&present, Door::KerberosS4u, Ok(())),
            (
                &present,
                Door::KerberosTgs,
                refused(Door::KerberosTgs, outside),
            ),
            (
                &present,
                Door::KerberosAs,
                refused(Door::KerberosAs, outside),
            ),
            (&present, Door::LdapBind, refused(Door::LdapBind, outside)),
            (
                &everywhere,
                Door::KerberosS4u,
                refused(Door::KerberosS4u, None),
            ),
        ];
        for (checks, door, expected) in rows {
            let attempt = Attempt::at_kdc(&bob, door, None, 1_700_000_000);
            let got = decide(&attempt, &items, &UserState::default(), checks);
            assert_eq!(got, expected, "{door:?}");
        }
        assert!(
            LockoutCheck.judges_at_s4u() && MfaItemCheck.judges_at_s4u(),
            "the lockout and enable-mfa judge there"
        );
    }

    fn linked(key: &str, value: &str, ous: &[&str]) -> Policy {
        Policy {
            id: PolicyId(1),
            name: "p".to_owned(),
            description: String::new(),
            items: BTreeMap::from([(key.to_owned(), value.to_owned())]),
            linked_ous: ous.iter().map(|ou| ou.to_string()).collect(),
        }
    }

    #[tokio::test]
    async fn test_each_gated_item_is_live_only_while_a_linked_policy_sets_it_off_its_default() {
        let flags = |login_hours, networks, inactivity| ItemFlags {
            login_hours,
            networks,
            inactivity,
        };
        let off = flags(false, false, false);
        let hours = "mon-fri 08:00-18:00";
        let nets = "10.0.0.0/8";
        type Row = (&'static str, Vec<Policy>, ItemFlags);
        let rows: [Row; 10] = [
            ("nothing set", vec![], off),
            (
                "set but not linked",
                vec![linked(LOGIN_HOURS, hours, &[])],
                off,
            ),
            (
                "linked at the default value",
                vec![
                    linked(LOGIN_HOURS, "", &["people"]),
                    linked(ALLOWED_NETWORKS, "", &["people"]),
                    linked(INACTIVITY_DAYS, "0", &["people"]),
                ],
                off,
            ),
            (
                "the default written another way",
                vec![linked(INACTIVITY_DAYS, "00", &["people"])],
                off,
            ),
            (
                "another item only",
                vec![linked("lockout-duration-seconds", "60", &["people"])],
                off,
            ),
            (
                "login-hours linked",
                vec![linked(LOGIN_HOURS, hours, &["people"])],
                flags(true, false, false),
            ),
            (
                "allowed-networks linked",
                vec![linked(ALLOWED_NETWORKS, nets, &["people"])],
                flags(false, true, false),
            ),
            (
                "inactivity-days linked",
                vec![linked(INACTIVITY_DAYS, "90", &["people"])],
                flags(false, false, true),
            ),
            (
                "linked to the root",
                vec![linked(LOGIN_HOURS, hours, &[""])],
                flags(true, false, false),
            ),
            (
                "all three linked",
                vec![
                    linked(LOGIN_HOURS, hours, &["a"]),
                    linked(ALLOWED_NETWORKS, nets, &["b"]),
                    linked(INACTIVITY_DAYS, "90", &[""]),
                ],
                flags(true, true, true),
            ),
        ];
        for (label, policies, expected) in rows {
            let (cache, counter) = (PolicyCache::new(), Lockout::default());
            let directory = Directory {
                policies,
                ..Directory::default()
            };
            counter.follow_policies(&directory, &cache).await.unwrap();
            let filled = directory.user_lists.load(Ordering::Relaxed) > 0;
            assert_eq!(
                (ItemFlags::held(&cache), filled),
                (expected, expected != off),
                "{label}: a flag that turns on fills the cache first"
            );
            if expected == off {
                assert_eq!(cache.reads(), 0, "{label}: no fill and no read");
            }
        }
        let (cache, counter) = (PolicyCache::new(), Lockout::default());
        let set = Directory {
            policies: vec![linked(INACTIVITY_DAYS, "90", &["people"])],
            ..Directory::default()
        };
        counter.follow_policies(&set, &cache).await.unwrap();
        counter
            .follow_policies(&Directory::default(), &cache)
            .await
            .unwrap();
        assert_eq!(
            ItemFlags::held(&cache),
            off,
            "an item unset turns off at the next follow"
        );
    }

    #[tokio::test]
    async fn test_a_gated_item_fills_the_cache_before_its_flag_lets_the_kdc_judge() {
        let cache: &'static PolicyCache = Box::leak(Box::new(PolicyCache::new()));
        let counter: &'static Lockout = Box::leak(Box::default());
        let mut directory = Directory::knowing(&[LATE]).listing(&[LATE]);
        directory.policies = vec![linked(LOGIN_HOURS, "mon-fri 08:00-18:00", &[LABS])];
        *directory.watching.lock().unwrap() = Some((cache, counter));
        counter.follow_policies(&directory, cache).await.unwrap();
        let at_each_fill = directory.verdicts.lock().unwrap().clone();
        assert_eq!(
            at_each_fill,
            vec![(false, Ok(())), (true, Ok(()))],
            "the flag turns on only after a fill: the KDC never answers `not loaded yet` for a \
             user it knows"
        );
        let late = UserId::new(LATE);
        let attempt = Attempt::at_kdc(&late, Door::KerberosAs, None, 1_700_000_000);
        let checks: Vec<Arc<dyn ItemCheck>> = vec![Arc::new(HoursLive)];
        let reads = cache.reads();
        assert_eq!(
            (
                admit_at_kdc_with(cache, counter, &attempt, &checks),
                cache.reads() - reads
            ),
            (Ok(()), 1),
            "after the flip the KDC judges the user from memory"
        );
    }

    #[test]
    fn test_without_a_pinned_clock_an_attempt_takes_the_time_of_the_moment() {
        let bob = UserId::new("bob");
        let before = Timestamp::now();
        let now = Attempt::new(&bob, Door::LdapBind).now;
        let took = (now - before).as_millis();
        assert!((0..1_000).contains(&took), "{took} ms");
        let lock = lockout::lock_clock();
        let apart = (lock - now).as_millis();
        assert!(apart.abs() < 1_000, "the lockout's clock: {apart} ms");
    }

    #[test]
    fn test_only_the_exact_name_makes_a_member_exempt_in_the_cache() {
        let epoch = DateTime::from_timestamp(0, 0).unwrap().naive_utc();
        let group = |name: &str| GroupDetails {
            group_id: GroupId(1),
            display_name: name.into(),
            creation_date: epoch,
            uuid: Uuid::from_name_and_date(name, &epoch),
            attributes: vec![],
            modified_date: epoch,
        };
        let rows = [
            (MFA_DISABLED_GROUP, true),
            ("LLDAP_MFA_DISABLED", false),
            ("Lldap_Mfa_Disabled", false),
            ("lldap_disabled", false),
        ];
        for (name, exempt) in rows {
            let groups = [group(name)];
            let facts = UserFacts::of(&user(LATE), groups.iter());
            assert_eq!(facts.exempt, exempt, "{name}");
        }
    }

    #[tokio::test]
    async fn test_the_start_names_a_group_that_differs_from_the_exempt_group_only_by_case() {
        const TWIN: &str = "LLDAP_MFA_DISABLED";
        let warning = format!(
            "The group {TWIN} is not the exempt group {MFA_DISABLED_GROUP}, whose name it takes \
             in another case: while it exists, nobody is exempt"
        );
        type Row = (
            &'static str,
            &'static [&'static str],
            Option<String>,
            &'static [&'static str],
        );
        let rows: [Row; 4] = [
            ("no group", &[], None, &[MFA_DISABLED_GROUP]),
            (
                "the group itself",
                &[MFA_DISABLED_GROUP],
                None,
                &[MFA_DISABLED_GROUP],
            ),
            ("a case twin", &[TWIN], Some(warning), &[TWIN]),
            (
                "another group",
                &["staff"],
                None,
                &["staff", MFA_DISABLED_GROUP],
            ),
        ];
        for (label, present, warned, after) in rows {
            let directory = Directory::default();
            for name in present {
                let request = CreateGroupRequest {
                    display_name: (*name).into(),
                    attributes: vec![],
                };
                directory.create_group(request).await.unwrap();
            }
            let mut said = None;
            for _start in 0..2 {
                said = exempt_group_twin(&directory).await.unwrap();
                ensure_exempt_group(&directory).await.unwrap();
                assert_eq!(said, warned, "{label}: every start says the same");
            }
            assert_eq!(
                (said, directory.group_names()),
                (
                    warned,
                    after
                        .iter()
                        .map(|name| name.to_string())
                        .collect::<Vec<_>>()
                ),
                "{label}: the start's warning, then what creation leaves"
            );
        }
    }

    #[test]
    fn test_the_login_hours_zone_is_utc_built_in_or_one_zone_file_of_the_system() {
        let dir = Path::new(ZONE_FILES);
        let chicago = format!("{ZONE_FILES}/America/Chicago");
        let loaded = |name: &str| {
            let loaded = load_zone_from(dir, name)?;
            let zone = loaded.zone.iana_name().map(str::to_owned);
            Ok::<_, String>((zone, loaded.source))
        };
        let rows = [
            ("UTC", Some(("UTC", BUILT_IN))),
            ("utc", Some(("UTC", BUILT_IN))),
            (
                "America/Chicago",
                Some(("America/Chicago", chicago.as_str())),
            ),
            ("America/Nowhere", None),
            ("right/America/Chicago", None),
            ("posix/America/Chicago", None),
            ("../../etc/passwd", None),
            ("/etc/localtime", None),
            ("", None),
        ];
        for (name, expected) in rows {
            match (loaded(name), expected) {
                (Ok(got), Some((zone, source))) => {
                    let want = (Some(zone.to_owned()), source.to_owned());
                    assert_eq!(got, want, "{name}");
                }
                (Err(text), None) => {
                    let named = format!("login_hours_timezone \"{name}\"");
                    assert!(text.starts_with(&named), "{name}: {text}");
                }
                (got, _) => panic!("{name}: {got:?}"),
            }
        }
        let utc = load_zone_from(dir, "UTC").map(|loaded| loaded.zone);
        assert_eq!(utc, Ok(TimeZone::UTC));
    }

    #[test]
    fn test_the_hosts_own_zone_files_are_refused_as_zone_names_where_they_exist() {
        let dir = std::env::temp_dir().join(format!("klldap-zones-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let chicago = std::fs::read(format!("{ZONE_FILES}/America/Chicago")).unwrap();
        let names = ["localtime", "posixrules", "Localtime", "Copied"];
        let loaded = names.map(|name| {
            std::fs::write(dir.join(name), &chicago).unwrap();
            load_zone_from(&dir, name).map(|loaded| loaded.source)
        });
        let copied = dir.join("Copied").display().to_string();
        std::fs::remove_dir_all(&dir).unwrap();
        let refused = |name: &str| {
            let text = "is refused: not an IANA time zone name";
            Err(format!("login_hours_timezone \"{name}\" {text}"))
        };
        assert_eq!(
            loaded,
            [
                refused("localtime"),
                refused("posixrules"),
                refused("Localtime"),
                Ok(copied)
            ],
            "the same zone file is refused under the host's own names, before it is read, and \
             loads under a zone's name"
        );
    }

    #[test]
    fn test_the_registered_checks_refuse_in_the_ruled_order() {
        const RULED: [&str; 4] = [
            "lockout-threshold",
            "inactivity-days",
            "allowed-networks",
            "login-hours",
        ];
        let checks = default_item_checks();
        let keys = checks.iter().map(|check| check.key());
        let registered: Vec<&str> = keys.filter(|key| RULED.contains(key)).collect();
        let ruled: Vec<&str> = RULED
            .into_iter()
            .filter(|key| registered.contains(key))
            .collect();
        assert_eq!(registered, ruled);
        assert!(registered.contains(&INACTIVITY_DAYS));
        let bob = UserId::new("bob");
        let attempt = Attempt {
            user: &bob,
            door: Door::LdapBind,
            peer: None,
            now: at(2 * 86_400),
            second_factor: false,
        };
        let items = [
            item("lockout-threshold", "1"),
            item("lockout-duration-seconds", "0"),
            item(INACTIVITY_DAYS, "1"),
        ];
        let locked = LockRow {
            fail_count: 1,
            last_failed: Some(at(0)),
            ..LockRow::default()
        };
        let both = UserState {
            lock: Some(locked),
            active_since: Some(at(0)),
        };
        let idle = UserState {
            lock: None,
            ..both.clone()
        };
        let named =
            |state: &UserState| decide(&attempt, &items, state, &checks).map_err(|r| r.item);
        assert_eq!(
            (named(&both), named(&idle)),
            (Err("lockout-threshold"), Err(INACTIVITY_DAYS)),
            "a locked user who is also inactive is named locked"
        );
    }

    #[test]
    fn test_a_check_that_cannot_read_its_value_refuses_as_unreadable() {
        struct Picky;
        impl ItemCheck for Picky {
            fn key(&self) -> &'static str {
                "login-hours"
            }
            fn readable(&self, value: &str, _: &UserState) -> bool {
                value != "garbled"
            }
            fn allows(&self, _: &Attempt<'_>, _: &str, _: &UserState) -> bool {
                false
            }
        }
        let bob = UserId::new("bob");
        let attempt = Attempt::at_kdc(&bob, Door::KerberosTgs, None, 1_700_000_000);
        let checks: Vec<Arc<dyn ItemCheck>> = vec![Arc::new(Picky)];
        let rows = [("garbled", UNREADABLE), ("mon 08:00-09:00", "login-hours")];
        for (value, refused) in rows {
            let items = [item("login-hours", value)];
            let got = decide(&attempt, &items, &UserState::default(), &checks);
            let refusal = Refusal {
                item: refused,
                door: Door::KerberosTgs,
                reason: None,
            };
            assert_eq!(got, Err(refusal), "{value}");
        }
    }

    fn idle_level(value: &str) -> Vec<PolicyLevel> {
        let policy = AttachedPolicy {
            id: PolicyId(6),
            name: "idle".to_owned(),
            items: BTreeMap::from([(INACTIVITY_DAYS.to_owned(), value.to_owned())]),
        };
        let level = PolicyLevel {
            ou_key: String::new(),
            blocked: false,
            policy: Some(policy),
        };
        vec![level]
    }

    #[tokio::test]
    async fn test_the_fill_reads_the_activity_once_and_only_while_an_ou_sets_the_item() {
        let (late, other) = (UserId::new(LATE), UserId::new(OTHER));
        let seen = Recorded {
            last_success: Some(at(0)),
            reenabled_at: None,
        };
        let epoch = Timestamp::UNIX_EPOCH;
        for (label, value, reads, read) in [("not set", "0", 0, false), ("set", "30", 1, true)] {
            let cache = PolicyCache::new();
            let mut directory = Directory::knowing(&[LATE]).listing(&[LATE, OTHER]);
            directory.levels = idle_level(value);
            *directory.activity_rows.lock().unwrap() = vec![(late.clone(), seen)];
            fill_policy_cache(&directory, &cache).await.unwrap();
            let held = cache.get();
            let facts = |user: &UserId| held.facts_of(user).map(|f| (f.created, f.recorded));
            let recorded = |row: Recorded| read.then_some(row);
            assert_eq!(
                (
                    directory.activity_reads.load(Ordering::Relaxed),
                    facts(&late),
                    facts(&other)
                ),
                (
                    reads,
                    Some((epoch, recorded(seen))),
                    Some((epoch, recorded(Recorded::default())))
                ),
                "{label}: the creation from the fill's own rows; one read for every user's row"
            );
        }
        let cache = PolicyCache::new();
        let mut directory = Directory::knowing(&[LATE, OTHER]).listing(&[LATE]);
        directory.levels = idle_level("30");
        fill_policy_cache(&directory, &cache).await.unwrap();
        *directory.activity_rows.lock().unwrap() = vec![(late.clone(), seen)];
        cache.mark(&late);
        take_marks(&directory, &cache).await;
        let taken = |cache: &PolicyCache| cache.get().facts_of(&late).and_then(|f| f.recorded);
        assert_eq!(
            (
                directory.activity_reads.load(Ordering::Relaxed),
                taken(&cache),
                cache.marked(&late)
            ),
            (2, Some(seen), false),
            "a marked user reads their own row again"
        );
        directory.activity_down.store(true, Ordering::Relaxed);
        cache.mark(&late);
        take_marks(&directory, &cache).await;
        assert_eq!(
            (taken(&cache), cache.marked(&late), cache.failed_read()),
            (Some(seen), true, true),
            "a read that failed keeps what was read, and the user stays marked"
        );
        cache.mark(&other);
        take_marks(&directory, &cache).await;
        let first = cache.get().facts_of(&other).map(|f| f.recorded);
        assert_eq!(
            (first, cache.marked(&other)),
            (Some(None), true),
            "a user the cache did not hold has nothing to keep: unread, never as never signed in"
        );
    }

    #[tokio::test]
    async fn test_the_activity_is_read_before_the_inactivity_flag_lets_the_kdc_judge() {
        let cache: &'static PolicyCache = Box::leak(Box::new(PolicyCache::new()));
        let counter: &'static Lockout = Box::leak(Box::default());
        let mut directory = Directory::knowing(&[LATE]).listing(&[LATE]);
        directory.policies = vec![linked(INACTIVITY_DAYS, "30", &[LABS])];
        directory.levels = idle_level("30");
        *directory.watching_idle.lock().unwrap() = Some((cache, counter));
        counter.follow_policies(&directory, cache).await.unwrap();
        let at_each_fill = directory.verdicts.lock().unwrap().clone();
        let read = cache.get().facts_of(&UserId::new(LATE)).map(|f| f.recorded);
        assert_eq!(
            (
                at_each_fill,
                read,
                directory.activity_reads.load(Ordering::Relaxed)
            ),
            (
                vec![(false, Ok(())), (true, Ok(()))],
                Some(Some(Recorded::default())),
                2
            ),
            "each fill reads the activity, the first one with the flag still off: the KDC never \
             answers `unreadable` for a user it knows"
        );
        let late = UserId::new(LATE);
        let attempt = Attempt::at_kdc(&late, Door::KerberosAs, None, 1_700_000_000);
        let checks: Vec<Arc<dyn ItemCheck>> = vec![Arc::new(InactivityCheck)];
        let reads = cache.reads();
        assert_eq!(
            (
                admit_at_kdc_with(cache, counter, &attempt, &checks),
                cache.reads() - reads
            ),
            (Ok(()), 1),
            "after the flip the KDC judges the user from memory"
        );
    }

    /// The real inactivity check alone, live on the process's cache; put back on drop.
    struct Idle;

    impl Idle {
        fn since(recording: Timestamp) -> Self {
            let checks: Vec<Arc<dyn ItemCheck>> = vec![Arc::new(InactivityCheck)];
            set_item_checks(checks.into());
            turn(policy_cache(), true);
            policy_cache().set_recording(Recording::Since(recording));
            policy_cache().replace(Entries::default());
            Self
        }
    }

    impl Drop for Idle {
        fn drop(&mut self) {
            set_item_checks(default_item_checks());
            turn(policy_cache(), false);
            policy_cache().reset_activity_reads();
            policy_cache().replace(Entries::default());
        }
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn test_a_door_reads_a_missing_users_activity_in_its_one_bounded_read() {
        let late = UserId::new(LATE);
        let mut directory = Directory::knowing(&[LATE]).listing(&[LATE]);
        directory.levels = idle_level("1");
        let reads = |d: &Directory| {
            let count = |n: &AtomicU64| n.load(Ordering::Relaxed);
            let (joined, alone) = (&d.activity_entry_reads, &d.entry_reads);
            [count(joined), count(alone), count(&d.activity_reads)]
        };
        let now = Timestamp::now();
        let ago = |seconds: i64| now - SignedDuration::from_secs(seconds);
        let inactive = Err("policy: inactivity-days (inactive)".to_owned());
        let rows = [
            ("active since the recording began", 3_600, None, Ok(())),
            ("idle past one day", 2 * 86_400, None, inactive),
            ("a success an hour ago", 2 * 86_400, Some(3_600), Ok(())),
        ];
        for (label, since, success, expected) in rows {
            let _idle = Idle::since(ago(since));
            let row = Recorded {
                last_success: success.map(ago),
                reenabled_at: None,
            };
            *directory.activity_rows.lock().unwrap() = vec![(late.clone(), row)];
            let before = reads(&directory);
            let attempt = Attempt::new(&late, Door::LdapBind);
            let got = admit(&directory, &attempt).await.map_err(|r| r.detail());
            let after = reads(&directory);
            let read = [0_usize, 1, 2].map(|n| after[n] - before[n]);
            assert_eq!(
                (got, read),
                (expected, [1, 0, 0]),
                "{label}: the cache lacks the user; one bounded read, the activity joined"
            );
        }
        let _idle = Idle::since(ago(3_600));
        fill_policy_cache(&directory, policy_cache()).await.unwrap();
        let before = reads(&directory);
        let attempt = Attempt::new(&late, Door::LdapBind);
        let got = admit(&directory, &attempt).await;
        assert_eq!(
            (got, reads(&directory)),
            (Ok(()), before),
            "the cache holds the user: no read at the door"
        );
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn test_an_item_whose_fill_fails_at_its_flip_refuses_as_unread_until_a_fill_succeeds() {
        let _judging = Judging::only(&[LATE]);
        let (cache, counter) = (policy_cache(), Lockout::default());
        let mut directory = Directory::knowing(&[LATE]).listing(&[LATE]);
        directory.policies = vec![linked(LOGIN_HOURS, "mon-fri 08:00-18:00", &[LABS])];
        let late = UserId::new(LATE);
        let verdicts = async || {
            let door = admit(&directory, &Attempt::new(&late, Door::LdapBind)).await;
            let attempt = Attempt::at_kdc(&late, Door::KerberosAs, None, 1_700_000_000);
            let kdc = admit_at_kdc_with(cache, &counter, &attempt, &item_checks());
            (
                cache.item_off(LOGIN_HOURS),
                cache.item_unread(LOGIN_HOURS),
                door,
                kdc,
            )
        };
        let refused = |item, door| {
            Err(Refusal {
                item,
                door,
                reason: None,
            })
        };
        directory.users_down.store(true, Ordering::Relaxed);
        let failed = counter.follow_policies(&directory, cache).await.is_err();
        let during = verdicts().await;
        let due = cache.items_unread();
        directory.users_down.store(false, Ordering::Relaxed);
        let filled = counter.follow_policies(&directory, cache).await.is_ok();
        let after = verdicts().await;
        cache.set_item_flags(ItemFlags::default());
        cache.replace(Entries::default());
        assert_eq!(
            (failed, during, due),
            (
                true,
                (
                    false,
                    true,
                    refused(UNREADABLE, Door::LdapBind),
                    refused(NOT_LOADED, Door::KerberosAs)
                ),
                true
            ),
            "the fill failed at the flip: the item is on and unread, the doors refuse it"
        );
        assert_eq!(
            (filled, after),
            (true, (false, false, Ok(()), Ok(()))),
            "the next good fill: judged as usual"
        );
    }

    #[tokio::test]
    async fn test_a_lockout_whose_fill_fails_at_its_flip_refuses_as_unread_until_a_fill_succeeds() {
        let (cache, counter) = (PolicyCache::new(), Lockout::default());
        let mut directory = Directory::knowing(&[LATE]).listing(&[LATE]);
        directory.policies = vec![linked(lockout::THRESHOLD, "3", &[LABS])];
        let (late, checks) = (UserId::new(LATE), default_item_checks());
        let kdc = |cache: &PolicyCache| {
            let attempt = Attempt::at_kdc(&late, Door::KerberosAs, None, 1_700_000_000);
            admit_at_kdc_with(cache, &counter, &attempt, &checks)
        };
        directory.users_down.store(true, Ordering::Relaxed);
        let failed = counter.follow_policies(&directory, &cache).await.is_err();
        let during = (cache.lockout_unknown(), kdc(&cache));
        directory.users_down.store(false, Ordering::Relaxed);
        let filled = counter.follow_policies(&directory, &cache).await.is_ok();
        let after = (cache.lockout_live(), kdc(&cache));
        let unread = Err(Refusal {
            item: UNREADABLE,
            door: Door::KerberosAs,
            reason: None,
        });
        assert_eq!(
            (failed, during, filled, after),
            (true, (true, unread), true, (true, Ok(()))),
            "a failed fill as counting turns on: unread until the next good fill"
        );
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn test_inactivity_turning_on_with_a_read_unanswered_refuses_its_users_until_both_read() {
        let now = Timestamp::now();
        let _idle = Idle::since(now);
        let (cache, counter) = (policy_cache(), Lockout::default());
        let mut directory = Directory::knowing(&[LATE]).listing(&[LATE]);
        directory.policies = vec![linked(INACTIVITY_DAYS, "30", &[LABS])];
        directory.levels = idle_level("30");
        let late = UserId::new(LATE);
        let checks: Vec<Arc<dyn ItemCheck>> = vec![Arc::new(InactivityCheck)];
        let seconds = u32::try_from(now.as_second()).unwrap();
        let detail = |verdict: std::result::Result<(), Refusal>| verdict.map_err(|r| r.detail());
        let verdicts = async || {
            let door = admit(&directory, &Attempt::new(&late, Door::LdapBind)).await;
            let _ = poked(cache).await;
            let attempt = Attempt::at_kdc(&late, Door::KerberosAs, None, seconds);
            let kdc = admit_at_kdc_with(cache, &counter, &attempt, &checks);
            let unread = cache.item_unread(INACTIVITY_DAYS);
            (unread, detail(door), detail(kdc), poked(cache).await)
        };
        let rows = [
            (
                "a start, the users' rows",
                Recording::Unknown,
                &directory.activity_down,
            ),
            (
                "a start, recording_since",
                Recording::Unknown,
                &directory.recording_down,
            ),
            (
                "linked later, the users' rows",
                Recording::Off,
                &directory.activity_down,
            ),
            (
                "linked later, recording_since",
                Recording::Off,
                &directory.recording_down,
            ),
        ];
        let unreadable = Err("policy: unreadable".to_owned());
        for (label, recording, down) in rows {
            turn(cache, false);
            cache.set_recording(recording);
            cache.replace(Entries::default());
            down.store(true, Ordering::Relaxed);
            let _ = counter.follow_policies(&directory, cache).await;
            let during = verdicts().await;
            down.store(false, Ordering::Relaxed);
            counter.follow_policies(&directory, cache).await.unwrap();
            let after = verdicts().await;
            assert_eq!(
                (during, after),
                (
                    (false, unreadable.clone(), unreadable.clone(), false),
                    (false, Ok(()), Ok(()), false)
                ),
                "{label}: the policies read, its own data not: on, and a user under its limit is \
                 refused at the door and at the KDC; the next follow that reads both judges them"
            );
        }
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn test_while_inactivitys_own_data_is_unread_a_user_under_0_or_no_limit_is_admitted() {
        let now = Timestamp::now();
        let _idle = Idle::since(now);
        let (cache, counter) = (policy_cache(), Lockout::default());
        let late = UserId::new(LATE);
        let checks: Vec<Arc<dyn ItemCheck>> = vec![Arc::new(InactivityCheck)];
        let seconds = u32::try_from(now.as_second()).unwrap();
        let detail = |verdict: std::result::Result<(), Refusal>| verdict.map_err(|r| r.detail());
        let unreadable = Err("policy: unreadable".to_owned());
        let rows = [
            ("a limit of 30", idle_level("30"), unreadable),
            ("a limit of 0", idle_level("0"), Ok(())),
            ("no value", Vec::new(), Ok(())),
        ];
        for (label, levels, expected) in rows {
            let mut directory = Directory::knowing(&[LATE]).listing(&[LATE]);
            directory.policies = vec![linked(INACTIVITY_DAYS, "30", &[LABS])];
            directory.levels = levels;
            turn(cache, false);
            cache.set_recording(Recording::Unknown);
            cache.replace(Entries::default());
            directory.recording_down.store(true, Ordering::Relaxed);
            let _ = counter.follow_policies(&directory, cache).await;
            let door = admit(&directory, &Attempt::new(&late, Door::LdapBind)).await;
            let attempt = Attempt::at_kdc(&late, Door::KerberosAs, None, seconds);
            let kdc = admit_at_kdc_with(cache, &counter, &attempt, &checks);
            assert_eq!(
                (cache.activity_due(), detail(door), detail(kdc)),
                (true, expected.clone(), expected),
                "{label}: the policies read, recording_since not: only a user the item judges is \
                 refused, at the door and at the KDC"
            );
        }
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn test_a_relink_whose_recording_since_read_fails_judges_no_one_on_an_older_time() {
        let (cache, counter) = (PolicyCache::new(), Lockout::default());
        let mut directory = Directory::knowing(&[LATE]).listing(&[LATE]);
        directory.policies = vec![linked(INACTIVITY_DAYS, "30", &[LABS])];
        directory.levels = idle_level("30");
        let late = UserId::new(LATE);
        let checks: Vec<Arc<dyn ItemCheck>> = vec![Arc::new(InactivityCheck)];
        let kdc = |cache: &PolicyCache| {
            let attempt = Attempt::at_kdc(&late, Door::KerberosAs, None, 1_700_000_000);
            let verdict = admit_at_kdc_with(cache, &counter, &attempt, &checks);
            verdict.map_err(|r| r.detail())
        };
        cache.set_recording(Recording::Since(at(-40 * 86_400)));
        directory.recording_down.store(true, Ordering::Relaxed);
        let failed = counter.follow_policies(&directory, &cache).await.is_err();
        let during = (cache.recording(), cache.activity_due(), kdc(&cache));
        directory.recording_down.store(false, Ordering::Relaxed);
        counter.follow_policies(&directory, &cache).await.unwrap();
        let older = at(-40 * 86_400);
        let read = matches!(cache.recording(), Recording::Since(since) if since != older);
        assert_eq!(
            (failed, during, (read, kdc(&cache))),
            (
                true,
                (
                    Recording::Unknown,
                    true,
                    Err("policy: unreadable".to_owned())
                ),
                (true, Ok(()))
            ),
            "off with an older time still held, linked again while recording_since is unread: \
             the older time is dropped and the user refused as unread, never judged inactive on \
             it; the next read takes the stored time"
        );
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn test_a_refill_that_misses_the_activity_keeps_what_was_read_and_refuses_no_one() {
        let now = Timestamp::now();
        let _idle = Idle::since(now - SignedDuration::from_hours(40 * 24));
        let (cache, counter) = (policy_cache(), Lockout::default());
        let mut directory = Directory::knowing(&[LATE, OTHER]).listing(&[LATE, OTHER]);
        directory.policies = vec![linked(INACTIVITY_DAYS, "30", &[LABS])];
        directory.levels = idle_level("30");
        let (late, other) = (UserId::new(LATE), UserId::new(OTHER));
        let seen = Recorded {
            last_success: Some(now - SignedDuration::from_hours(1)),
            reenabled_at: None,
        };
        *directory.activity_rows.lock().unwrap() = vec![(late.clone(), seen)];
        let checks: Vec<Arc<dyn ItemCheck>> = vec![Arc::new(InactivityCheck)];
        let seconds = u32::try_from(now.as_second()).unwrap();
        let verdicts = async || {
            let mut got = Vec::new();
            for user in [&late, &other] {
                let door = admit(&directory, &Attempt::new(user, Door::LdapBind)).await;
                let attempt = Attempt::at_kdc(user, Door::KerberosAs, None, seconds);
                let kdc = admit_at_kdc_with(cache, &counter, &attempt, &checks);
                got.push((door.map_err(|r| r.detail()), kdc.map_err(|r| r.detail())));
            }
            got
        };
        fill_policy_cache(&directory, cache).await.unwrap();
        let read = verdicts().await;
        directory.activity_down.store(true, Ordering::Relaxed);
        fill_policy_cache(&directory, cache).await.unwrap();
        let kept = (
            verdicts().await,
            cache.item_unread(INACTIVITY_DAYS),
            cache.activity_due(),
        );
        directory.activity_down.store(false, Ordering::Relaxed);
        let reads = directory.activity_reads.load(Ordering::Relaxed);
        counter.follow_policies(&directory, cache).await.unwrap();
        let again = (
            directory.activity_reads.load(Ordering::Relaxed) - reads,
            cache.activity_due(),
        );
        let inactive = Err("policy: inactivity-days (inactive)".to_owned());
        let judged = vec![(Ok(()), Ok(())), (inactive.clone(), inactive)];
        assert_eq!(
            read, judged,
            "read: Late signed in an hour ago, Other never in 40 days under 30"
        );
        assert_eq!(
            (kept, again),
            ((judged, false, true), (1, false)),
            "a refill that cannot read the users' rows keeps what was read: each judged as before \
             at the door and at the KDC, the item on; the next follow reads them again"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_while_inactivity_has_a_read_unanswered_the_run_loop_follows_every_second() {
        let rows = [
            ("the flip, the users' rows", true, false, false),
            ("the flip, recording_since", false, true, false),
            ("a refill, the users' rows", true, false, true),
        ];
        for (label, rows_down, recording_down, refill) in rows {
            let cache: &'static PolicyCache = Box::leak(Box::new(PolicyCache::new()));
            let counter: &'static Lockout = Box::leak(Box::default());
            let mut directory = Directory::knowing(&[LATE]).listing(&[LATE]);
            directory.policies = vec![linked(INACTIVITY_DAYS, "30", &[LABS])];
            directory.levels = idle_level("30");
            let directory = Arc::new(directory);
            let fail = |on: bool| {
                directory
                    .activity_down
                    .store(on && rows_down, Ordering::Relaxed);
                directory
                    .recording_down
                    .store(on && recording_down, Ordering::Relaxed);
            };
            if refill {
                counter.follow_policies(&*directory, cache).await.unwrap();
                fail(true);
                fill_policy_cache(&*directory, cache).await.unwrap();
            } else {
                fail(true);
                let _ = counter.follow_policies(&*directory, cache).await;
            }
            let state = || {
                let follows = directory.policy_reads.load(Ordering::Relaxed);
                (
                    follows,
                    cache.item_unread(INACTIVITY_DAYS),
                    cache.activity_due(),
                )
            };
            let before = state();
            let running = counter.run(directory.clone(), cache);
            tokio::time::sleep(Duration::from_millis(3_900)).await;
            let during = state();
            fail(false);
            tokio::time::sleep(Duration::from_millis(1_250)).await;
            let healed = state();
            tokio::time::sleep(Duration::from_secs(10)).await;
            let later = state();
            running.abort();
            assert_eq!(
                [before, during, healed, later],
                [
                    (1, false, true),
                    (4, false, true),
                    (5, false, false),
                    (5, false, false)
                ],
                "{label}: a follow each second while a read is unanswered; the next one reads it, \
                 then none until the next tick"
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn test_inactivitys_unread_follow_waits_five_seconds_after_ten_tries_until_one_reads() {
        let rows = [
            ("the flip, the users' rows", true, false, false),
            ("the flip, recording_since", false, true, false),
            ("a refill, the users' rows", true, false, true),
        ];
        for (label, rows_down, recording_down, refill) in rows {
            let cache: &'static PolicyCache = Box::leak(Box::new(PolicyCache::new()));
            let counter: &'static Lockout = Box::leak(Box::default());
            let mut directory = Directory::knowing(&[LATE]).listing(&[LATE]);
            directory.policies = vec![linked(INACTIVITY_DAYS, "30", &[LABS])];
            directory.levels = idle_level("30");
            let directory = Arc::new(directory);
            let fail = |users: bool, recording: bool| {
                directory.activity_down.store(users, Ordering::Relaxed);
                directory.recording_down.store(recording, Ordering::Relaxed);
            };
            if refill {
                counter.follow_policies(&*directory, cache).await.unwrap();
                fail(rows_down, recording_down);
                fill_policy_cache(&*directory, cache).await.unwrap();
            } else {
                fail(rows_down, recording_down);
                let _ = counter.follow_policies(&*directory, cache).await;
            }
            let follows = || directory.policy_reads.load(Ordering::Relaxed);
            let (start, mut seen, mut at) = (tokio::time::Instant::now(), follows(), Vec::new());
            let running = counter.run(directory.clone(), cache);
            for step in 0..120 {
                let sample = Duration::from_millis(100 + 250 * step);
                tokio::time::sleep_until(start + sample).await;
                if follows() == seen {
                    continue;
                }
                seen = follows();
                at.push(sample.as_millis() - 100);
                match at.len() {
                    11 | 13 => fail(false, false),
                    12 => {
                        fail(true, false);
                        fill_policy_cache(&*directory, cache).await.unwrap();
                    }
                    _ => {}
                }
            }
            running.abort();
            let state = (cache.item_unread(INACTIVITY_DAYS), cache.activity_due());
            assert_eq!(
                (at, state),
                (
                    vec![
                        1_250, 2_500, 3_750, 5_000, 6_250, 7_500, 8_750, 10_000, 11_250, 12_500,
                        17_500, 22_500, 23_750, 25_000
                    ],
                    (false, false)
                ),
                "{label}: tries 1 to 10 a tick apart, the 11th and 12th five seconds apart; the \
                 12th reads it; a refill then misses the users' rows, and the next try comes a \
                 tick later"
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn test_the_run_loop_writes_at_most_one_batch_of_owed_successes_a_tick() {
        let cache: &'static PolicyCache = Box::leak(Box::new(PolicyCache::new()));
        let counter: &'static Lockout = Box::leak(Box::default());
        let directory = Arc::new(Directory::default());
        turn(cache, true);
        for n in 0..300 {
            let user = UserId::new(&format!("e6owed{n}"));
            cache.carry_success_from_kdc(&user, at(0));
        }
        let owed = cache.owed_successes();
        let running = counter.run(directory.clone(), cache);
        let mut ticks = Vec::new();
        for wait in [1_900, 1_250] {
            tokio::time::sleep(Duration::from_millis(wait)).await;
            let written = directory.successes.lock().unwrap().len();
            ticks.push((written, cache.owed_successes()));
        }
        running.abort();
        assert_eq!(
            (owed, ticks),
            (300, vec![(256, 44), (300, 0)]),
            "256 a tick, the rest at the next"
        );
    }

    #[tokio::test]
    async fn test_an_unread_item_goes_off_once_no_linked_policy_sets_it() {
        let rows = [
            (LOGIN_HOURS, "mon-fri 08:00-18:00"),
            (ALLOWED_NETWORKS, "10.0.0.0/8"),
            (INACTIVITY_DAYS, "30"),
        ];
        let (late, checks) = (UserId::new(LATE), default_item_checks());
        for (key, value) in rows {
            let (cache, counter) = (PolicyCache::new(), Lockout::default());
            let mut set = Directory::knowing(&[LATE]).listing(&[LATE]);
            set.policies = vec![linked(key, value, &[LABS])];
            set.users_down.store(true, Ordering::Relaxed);
            let kdc = |cache: &PolicyCache| {
                let attempt = Attempt::at_kdc(&late, Door::KerberosAs, None, 1_700_000_000);
                let verdict = admit_at_kdc_with(cache, &counter, &attempt, &checks);
                let flags = (cache.item_off(key), cache.item_unread(key));
                (flags, verdict.map_err(|r| r.detail()))
            };
            let failed = counter.follow_policies(&set, &cache).await.is_err();
            let unread = kdc(&cache);
            let unlinked = Directory::knowing(&[LATE]).listing(&[LATE]);
            counter.follow_policies(&unlinked, &cache).await.unwrap();
            let off = kdc(&cache);
            assert_eq!(
                (failed, unread, off),
                (
                    true,
                    ((false, true), Err("policy: not loaded yet".to_owned())),
                    ((true, false), Ok(()))
                ),
                "{key}: on but unread, then unlinked: off, and the KDC admits"
            );
        }
    }

    #[tokio::test]
    async fn test_a_fill_forgets_the_hourly_write_of_a_user_it_no_longer_lists() {
        let cache = PolicyCache::new();
        turn(&cache, true);
        let directory = Directory::knowing(&[LATE]).listing(&[LATE]);
        let (late, other) = (UserId::new(LATE), UserId::new(OTHER));
        let success = at;
        for user in [&late, &other] {
            cache.note_success(&directory, user, success(0)).await;
        }
        fill_policy_cache(&directory, &cache).await.unwrap();
        for user in [&late, &other] {
            cache.note_success(&directory, user, success(60)).await;
        }
        let written = directory.successes.lock().unwrap().clone();
        assert_eq!(
            written,
            vec![
                (late, success(0)),
                (other.clone(), success(0)),
                (other, success(60))
            ],
            "the fill lists Late alone: Other's last write is forgotten, so the next one writes"
        );
    }
}
