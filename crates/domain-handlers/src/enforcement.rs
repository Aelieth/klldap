use crate::handler::{
    GroupBackendHandler, GroupListerBackendHandler, GroupRequestFilter, PolicyBackendHandler,
    UserBackendHandler, UserListerBackendHandler,
};
use crate::kdc_proof::{ProofSettings, ProofWindow, Reread, WindowReader};
use crate::kdc_proof::{fill_windows, proofs_live, take_user_windows};
use crate::kerberos::{CommitError, HostRow};
use crate::lockout::{self, LockRow, Lockout, LockoutCheck, lockout};
use crate::logging::{self, LogKind, Protocol, RequestMeta};
use crate::mfa::{
    ENABLE_MFA, EnableMfa, MFA_DISABLED_GROUP, MfaEnrollmentStatus, MfaPolicy, MfaRequirement,
    mfa_requirement,
};
use crate::policies::{
    EffectiveItem, POLICY_ITEM_CATALOG, POLICY_READ_WAIT, Policy, canonical_ou_key, resolve,
    resolve_effective_items,
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use lldap_domain::requests::{CreateGroupRequest, UpdateUserRequest};
use lldap_domain::types::{Attribute, GroupDetails, MFA_TYPE_TOTP, User, UserId, Uuid, user_ou};
use lldap_domain_model::error::{DomainError, Result};
use std::collections::{BTreeSet, HashMap};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex, PoisonError, RwLock};
use std::time::Duration;
use tokio::sync::Notify;
use tracing::warn;

pub const POLICY_REFILL: Duration = Duration::from_secs(30);
pub const FILL_GAP: Duration = Duration::from_millis(250);
pub const FILL_BACKOFF_LIMIT: Duration = Duration::from_secs(30);
const FLAG_OFF: u8 = 0;
const FLAG_ON: u8 = 1;
const FLAG_UNKNOWN: u8 = 2;
pub const UNREADABLE: &str = "unreadable";
pub const NOT_LOADED: &str = "not loaded yet";
pub const POLICY_UNANSWERED: &str = "the policy read did not answer within its bound";

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
            Self::KerberosS4u => "kerberos S4U2Self",
        }
    }

    /// A login counts toward a lock; a renewal, a service ticket or an S4U2Self does not.
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
    pub now: DateTime<Utc>,
    pub second_factor: bool,
}

impl<'a> Attempt<'a> {
    pub fn new(user: &'a UserId, door: Door) -> Self {
        Self {
            user,
            door,
            peer: logging::current_request().peer,
            now: Utc::now(),
            second_factor: false,
        }
    }

    /// The KDC's clock and peer: its thread has no request of its own.
    pub fn at_kdc(user: &'a UserId, door: Door, peer: Option<IpAddr>, now: u32) -> Self {
        Self {
            user,
            door,
            peer,
            now: DateTime::from_timestamp(i64::from(now), 0).unwrap_or_else(Utc::now),
            second_factor: false,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Refusal {
    pub item: &'static str,
    pub door: Door,
}

impl Refusal {
    pub fn detail(&self) -> String {
        if self.item == lockout::THRESHOLD {
            return lockout::LOCKED_OUT.to_owned();
        }
        format!("policy: {}", self.item)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UserState {
    pub lock: Option<LockRow>,
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
    for check in checks.iter().filter(|check| check.judges(attempt.user)) {
        let Some(item) = items.iter().find(|item| item.key == check.key()) else {
            continue;
        };
        if !check.allows_among(attempt, &item.value, items, state) {
            return Err(Refusal {
                item: check.key(),
                door: attempt.door,
            });
        }
    }
    Ok(())
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
    let checks: Vec<Arc<dyn ItemCheck>> = vec![Arc::new(LockoutCheck), Arc::new(MfaItemCheck)];
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
pub fn set_item_checks(checks: ItemChecks) {
    *CHECKS.write().unwrap_or_else(PoisonError::into_inner) = checks;
}

/// What the doors need of a user that only the directory knows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserFacts {
    pub uuid: Uuid,
    pub enrolled: bool,
    pub exempt: bool,
}

impl UserFacts {
    pub fn of<'a>(user: &User, mut groups: impl Iterator<Item = &'a GroupDetails>) -> Self {
        Self {
            uuid: user.uuid.clone(),
            enrolled: user.mfa_type.as_deref() == Some(MFA_TYPE_TOTP),
            exempt: groups.any(|group| group.display_name.as_str() == MFA_DISABLED_GROUP),
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
    entries: &Entries,
    user: &UserId,
) -> Option<MfaPolicy> {
    let server = cache.mfa_policy();
    let resolved = |items: &[EffectiveItem]| resolve::<EnableMfa>(server, items).0;
    match mfa_item_matters(cache, server)? {
        false => Some(resolved(&[])),
        true => entries.items_of(user).map(resolved),
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
    pub built_at: DateTime<Utc>,
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
}

/// Swapped whole: a reader holds the old entries or the new ones, never none.
pub struct PolicyCache {
    current: RwLock<Arc<Entries>>,
    generation: AtomicU64,
    reads: AtomicU64,
    fill: Notify,
    pub(crate) writers: tokio::sync::Mutex<()>,
    marked: Mutex<Marks>,
    read_failed: AtomicBool,
    lockout: AtomicU8,
    mfa: RwLock<Option<MfaPolicy>>,
    mfa_item: AtomicU8,
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
struct Taking<'a> {
    cache: &'a PolicyCache,
    writers: Option<tokio::sync::MutexGuard<'a, ()>>,
}

impl Drop for Taking<'_> {
    fn drop(&mut self) {
        drop(self.writers.take());
        if !self.cache.marks().users.is_empty() {
            self.cache.poke_fill();
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
            writers: tokio::sync::Mutex::new(()),
            marked: Mutex::default(),
            read_failed: AtomicBool::new(false),
            lockout: AtomicU8::new(FLAG_OFF),
            mfa: RwLock::new(None),
            mfa_item: AtomicU8::new(FLAG_OFF),
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

    fn current(&self) -> Arc<Entries> {
        self.current
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    pub fn get(&self) -> Arc<Entries> {
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
        let next = Arc::new(next);
        *self.current.write().unwrap_or_else(PoisonError::into_inner) = next;
        self.generation.fetch_add(1, Ordering::AcqRel);
    }

    pub(crate) fn edit(&self, change: impl FnOnce(&mut Entries)) {
        let mut next = Entries::clone(&self.current());
        change(&mut next);
        self.replace(next);
    }

    pub fn put_user(&self, user: &UserId, ou_key: &str, items: Arc<[EffectiveItem]>) {
        self.edit(|entries| {
            entries.ous_of_users.insert(user.clone(), ou_key.to_owned());
            entries.items_of_ous.insert(ou_key.to_owned(), items);
        });
    }

    pub fn put_facts(&self, user: &UserId, facts: UserFacts) {
        self.edit(|entries| {
            entries.facts.insert(user.clone(), facts);
        });
    }

    pub fn remove_user(&self, user: &UserId) {
        self.edit(|entries| {
            entries.ous_of_users.remove(user);
            entries.facts.remove(user);
            entries.windows.remove(user);
        });
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

    fn marked_now(&self) -> Vec<(UserId, u64)> {
        let marks = self.marks();
        marks
            .users
            .iter()
            .map(|(user, made)| (user.clone(), *made))
            .collect()
    }

    fn unmark(&self, user: &UserId, made: u64) {
        let mut marks = self.marks();
        if marks.users.get(user) == Some(&made) {
            marks.users.remove(user);
        }
    }

    pub fn poke_fill(&self) {
        self.fill.notify_one();
    }

    pub async fn poked(&self) {
        self.fill.notified().await;
    }
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
        built_at: Utc::now(),
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
    let writers = cache.writers.lock().await;
    let _taking = Taking {
        cache,
        writers: Some(writers),
    };
    let mut entries = build_entries(handler).await?;
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
        loop {
            tokio::select! {
                () = cache.poked() => {}
                () = tokio::time::sleep(POLICY_REFILL) => {}
            }
            if !live(cache) {
                continue;
            }
            let filled = fill_policy_cache(&handler, cache).await;
            if let Err(e) = &filled {
                warn!("The policy cache was not refilled: {e}");
            }
            let failed = filled.is_err() | cache.read_failed.swap(false, Ordering::AcqRel);
            gap = next_gap(gap, failed);
            tokio::time::sleep(gap).await;
        }
    })
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

/// Made by whichever server first sees the item apply; one of that name is kept.
pub async fn ensure_exempt_group<H>(handler: &H) -> Result<()>
where
    H: GroupListerBackendHandler + GroupBackendHandler + ?Sized,
{
    let filter = GroupRequestFilter::DisplayName(MFA_DISABLED_GROUP.into());
    if !handler.list_groups(Some(filter)).await?.is_empty() {
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

/// One pass over the marks present now, ending at the first read that gave up; a mark leaves the
/// set only once its entry is stored.
async fn take_marks<H>(handler: &H, cache: &PolicyCache)
where
    H: UserBackendHandler + PolicyBackendHandler + ?Sized,
{
    for (user, made) in cache.marked_now() {
        let entry = match user_entry(handler, &user).await {
            Ok((ou_key, items, details)) => user_facts(handler, &details)
                .await
                .map(|facts| (ou_key, items, facts)),
            Err(e) => Err(e),
        };
        match entry {
            Ok((ou_key, items, facts)) => {
                cache.put_user(&user, &ou_key, items);
                cache.put_facts(&user, facts);
                if !take_user_windows(handler, cache, &user).await {
                    cache.note_read_failed();
                    continue;
                }
            }
            Err(DomainError::EntityNotFound(_)) => cache.remove_user(&user),
            Err(e) if gave_up(&e) => {
                warn!("The policy cache did not take {user}'s change within its bound: {e}");
                break;
            }
            Err(e) => {
                warn!("The policy cache did not take {user}'s change: {e}");
                cache.read_failed.store(true, Ordering::Release);
                continue;
            }
        }
        cache.unmark(&user, made);
    }
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
    let Ok(writers) = cache.writers.try_lock() else {
        return;
    };
    let _taking = Taking {
        cache,
        writers: Some(writers),
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
    let entries = cache.get();
    let held = entries.ous_of_users.get(user);
    if let Some(items) = held.and_then(|ou_key| entries.items_of_ous.get(ou_key)) {
        return Ok(items.clone());
    }
    Ok(user_entry(handler, user).await?.1)
}

/// Until the lockout's state is read, a user it judges is refused as when a policy is unreadable.
fn not_read_yet(
    cache: &PolicyCache,
    attempt: &Attempt<'_>,
    checks: &[Arc<dyn ItemCheck>],
) -> Option<Refusal> {
    let judges = |check: &Arc<dyn ItemCheck>| {
        check.key() == lockout::THRESHOLD && check.judges(attempt.user)
    };
    (cache.lockout_unknown() && checks.iter().any(judges)).then_some(Refusal {
        item: UNREADABLE,
        door: attempt.door,
    })
}

/// The door's one row for a value that could not be read.
pub fn refuse_unreadable(user: &UserId, door: Door) -> Refusal {
    let refusal = Refusal {
        item: UNREADABLE,
        door,
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
    let decision = match resolve_items(handler, cache, attempt.user).await {
        Ok(items) => {
            let decided = decide(attempt, &items, &state, &checks);
            let locked = matches!(&decided, Err(refusal) if refusal.item == lockout::THRESHOLD);
            if locked && lockout().confirm(attempt.user).await {
                let state = lockout().user_state(attempt.user);
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
    if let Some(refusal) = not_read_yet(cache, attempt, checks) {
        return Err(refusal);
    }
    let (state, checks) = refusing(checks, cache, lockout, attempt.user);
    if checks.is_empty() {
        return Ok(());
    }
    let entries = cache.get();
    let Some(items) = entries.items_of(attempt.user) else {
        cache.poke_fill();
        return Err(Refusal {
            item: NOT_LOADED,
            door: attempt.door,
        });
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
) {
    let meta = RequestMeta {
        protocol: Protocol::Kerberos,
        peer,
        ..RequestMeta::default()
    };
    logging::with_request_sync(meta, || {
        logging::record_as(user, kind, Some(target), success, Some(detail));
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handler::{ReadSchemaBackendHandler, UserRequestFilter};
    use crate::lockout::{LockStore, LockWrite, SplitMark, StoredLock, Written, first_follow};
    use crate::policies::{
        CreatePolicyRequest, ItemSource, OuPolicyState, Policy, PolicyId, PolicyLevel, PolicyScope,
        UpdatePolicyRequest, catalog_item,
    };
    use chrono::NaiveDateTime;
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

    fn at(seconds: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(1_700_000_000 + seconds, 0).unwrap()
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
                "enable-mfa"
            ]),
            "the lockout and enable-mfa are enforced at sign-in; the other items are not yet"
        );
        let at_password_doors = crate::password::PASSWORD_MIN_LENGTH_ITEM;
        for spec in POLICY_ITEM_CATALOG {
            let enforced = checked.contains(spec.key) || spec.key == at_password_doors;
            assert_eq!(spec.enforced, enforced, "{}", spec.key);
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
                "kerberos S4U2Self",
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
        let failed = Some(at(-5).naive_utc());
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
            }),
            "until the policies are read, every user the lockout judges is refused"
        );
        let refusal = Refusal {
            item: "lockout-threshold",
            door: Door::LdapBind,
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
    fn test_an_edit_swaps_a_copy_and_a_held_reader_keeps_its_entries() {
        let cache = PolicyCache::new();
        let hours: Arc<[EffectiveItem]> = vec![item("login-hours", "")].into();
        cache.put_user(&UserId::new("bob"), "people", hours.clone());
        let held = cache.get();
        let generation = cache.generation();
        cache.put_user(&UserId::new("bob"), "people\\labs", hours.clone());
        cache.remove_user(&UserId::new("bob"));
        let now = cache.get();
        assert_eq!(
            (
                held.ous_of_users.get(&UserId::new("bob")).cloned(),
                now.ous_of_users.get(&UserId::new("bob")).cloned(),
                cache.generation() - generation,
            ),
            (Some("people".to_owned()), None, 2)
        );
        assert_eq!(now.items_of_ous.len(), 2, "the OUs' items stay");
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
            Ok(Vec::new())
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
        async fn password_min_length(&self, _: &UserId) -> Result<usize> {
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
        async fn read_locks(&self, _: Option<NaiveDateTime>) -> Result<Vec<StoredLock>> {
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
        cache.get().ous_of_users.get(user).cloned()
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
    async fn test_a_hook_takes_one_pass_and_hands_later_marks_to_the_filler() {
        let _judging = Judging::only(&[LATE, OTHER]);
        let cache: &'static PolicyCache = Box::leak(Box::new(PolicyCache::new()));
        let directory = Directory::knowing(&[LATE, OTHER]);
        let (late, other) = (UserId::new(LATE), UserId::new(OTHER));
        *directory.meanwhile.lock().unwrap() = Some((cache, other.clone()));
        user_written(&directory, cache, &late).await;
        assert_eq!(
            (ou_of(cache, &late), ou_of(cache, &other)),
            (Some(LABS.to_owned()), None),
            "one pass over the marks present at the take"
        );
        assert!(
            cache.marks().users.contains_key(&other),
            "the later mark stays"
        );
        assert!(poked(cache).await, "the later mark goes to the filler");
        fill_policy_cache(&directory, cache).await.unwrap();
        assert_eq!(ou_of(cache, &other), Some(LABS.to_owned()));
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn test_a_user_marked_again_during_its_own_read_keeps_the_newer_mark() {
        let _judging = Judging::only(&[LATE]);
        let cache: &'static PolicyCache = Box::leak(Box::new(PolicyCache::new()));
        let directory = Directory::knowing(&[LATE]);
        let late = UserId::new(LATE);
        *directory.moves.lock().unwrap() = Some((late.clone(), "people"));
        *directory.meanwhile.lock().unwrap() = Some((cache, late.clone()));
        user_written(&directory, cache, &late).await;
        assert_eq!(
            (ou_of(cache, &late), cache.marks().users.contains_key(&late)),
            (Some(LABS.to_owned()), true),
            "the read stored the state it saw; the mark made during the read stays"
        );
        assert!(
            poked(cache).await,
            "the mark left after the pass goes to the filler"
        );
        fill_policy_cache(&directory, cache).await.unwrap();
        assert_eq!(
            (ou_of(cache, &late), cache.marks().users.len()),
            (Some("people".to_owned()), 0),
            "the next pass stores the newer state"
        );
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
}
