use crate::enforcement::{
    Attempt, Door, ItemCheck, POLICY_REFILL, PolicyCache, UserState, cached_mfa_policy, door_clock,
    ensure_exempt_group, fill_policy_cache, follow_items, follow_mfa_item, item_checks,
    resolve_items,
};
use crate::handler::{
    GroupBackendHandler, GroupListerBackendHandler, PolicyBackendHandler, UserBackendHandler,
    UserListerBackendHandler,
};
use crate::logging::{self, LogKind};
use crate::policies::{EffectiveItem, Policy, catalog_item};
use async_trait::async_trait;
use chrono::NaiveDateTime;
use lldap_domain::types::{UserId, Uuid};
use lldap_domain_model::error::{DomainError, Result};
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock, Mutex, MutexGuard, PoisonError, RwLock};
use std::time::{Duration, Instant};
use tokio::sync::Notify;
use tracing::{info, warn};

pub const THRESHOLD: &str = "lockout-threshold";
pub const DURATION: &str = "lockout-duration-seconds";
pub const LOCKED_OUT: &str = "locked out";
pub const UNLOCKED_BY_ADMIN: &str = "unlockUser";
pub const UNLOCKED_BY_TOOL: &str = "lldap unlock";
pub const UNLOCKED_BY_KADMIN: &str = "kadmin modprinc -unlock";
/// The whole write, connection and statement, at a door and on the KDC's thread.
pub const WRITE_BOUND: Duration = Duration::from_millis(250);
/// A web start counts beside the row at once, and joins the row only if no finish removes it.
pub const START_HOLD: Duration = Duration::from_secs(10);
pub const OVERLAY_CAP: usize = 32;
pub const UNWRITTEN_CAP: usize = 100;
pub const CONFIRM_EVERY: Duration = Duration::from_secs(1);
pub const RETRY_AFTER: Duration = Duration::from_secs(1);
pub const DRAIN_EVERY: Duration = Duration::from_secs(1);
pub const DRAIN_GAP: Duration = Duration::from_millis(250);
pub const STOP_BOUND: Duration = Duration::from_secs(1);
pub const QUEUE_LIMIT: usize = 65_536;
pub const BATCH_LIMIT: usize = 256;
pub const NOT_READ_YET: &str = "the lockout's state is not read yet";
const REREAD_MARGIN_SECS: i64 = 60;

pub fn lock_clock() -> NaiveDateTime {
    let now = door_clock();
    chrono::DateTime::from_timestamp_micros(now.timestamp_micros())
        .unwrap_or(now)
        .naive_utc()
}

pub fn micros_of(at: NaiveDateTime) -> i64 {
    at.and_utc().timestamp_micros()
}

pub fn time_of_micros(micros: i64) -> Option<NaiveDateTime> {
    chrono::DateTime::from_timestamp_micros(micros).map(|at| at.naive_utc())
}

fn after(a: Option<NaiveDateTime>, b: Option<NaiveDateTime>) -> bool {
    match (a, b) {
        (Some(a), Some(b)) => a > b,
        (Some(_), None) => true,
        (None, _) => false,
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LockoutPolicy {
    pub threshold: u32,
    pub duration_seconds: u32,
}

fn number(items: &[EffectiveItem], key: &str) -> u32 {
    items
        .iter()
        .find(|item| item.key == key)
        .map(|item| item.value.as_str())
        .or_else(|| catalog_item(key).map(|spec| spec.default_value))
        .and_then(|value| value.parse().ok())
        .unwrap_or(0)
}

impl LockoutPolicy {
    pub fn of(items: &[EffectiveItem]) -> Self {
        Self {
            threshold: number(items, THRESHOLD),
            duration_seconds: number(items, DURATION),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LockRow {
    pub fail_count: u32,
    pub last_failed: Option<NaiveDateTime>,
    pub last_success: Option<NaiveDateTime>,
    pub last_admin_unlock: Option<NaiveDateTime>,
    pub lock_logged: Option<NaiveDateTime>,
}

impl LockRow {
    pub fn locked(&self, policy: LockoutPolicy, now: NaiveDateTime) -> bool {
        if !after(self.last_failed, self.last_admin_unlock) {
            return false;
        }
        if policy.threshold == 0 || self.fail_count < policy.threshold {
            return false;
        }
        if policy.duration_seconds == 0 {
            return true;
        }
        let duration = chrono::Duration::seconds(i64::from(policy.duration_seconds));
        self.last_failed
            .is_some_and(|failed| failed + duration > now)
    }

    pub fn failed(self, at: NaiveDateTime) -> Self {
        let base = if after(self.last_failed, self.last_admin_unlock) {
            self.fail_count
        } else {
            0
        };
        Self {
            fail_count: base.saturating_add(1),
            last_failed: self.last_failed.max(Some(at)),
            ..self
        }
    }

    pub fn cleared(self, at: NaiveDateTime) -> Self {
        Self {
            fail_count: 0,
            last_success: self.last_success.max(Some(at)),
            ..self
        }
    }

    pub fn unlocked(self, at: NaiveDateTime) -> Self {
        Self {
            fail_count: 0,
            last_admin_unlock: Some(at),
            ..self
        }
    }

    pub fn zeroed(self) -> Self {
        Self {
            fail_count: 0,
            lock_logged: None,
            ..self
        }
    }

    pub fn with_overlays(self, overlays: &[Overlay]) -> Self {
        let counted = overlays
            .iter()
            .filter(|overlay| after(Some(overlay.at), self.last_admin_unlock));
        counted.fold(self, |row, overlay| row.failed(overlay.at))
    }

    pub fn lock_logged_this_cycle(&self) -> bool {
        after(self.lock_logged, self.last_admin_unlock)
            && after(self.lock_logged, self.last_success)
    }
}

/// A stored start id; its lowest bit says whether that finish completed the sign-in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SplitMark {
    pub id: u64,
    pub completed: bool,
}

impl SplitMark {
    pub fn of(id: u64, completed: bool) -> Self {
        Self {
            id: id & !1,
            completed,
        }
    }

    pub fn bits(self) -> u64 {
        self.id | u64::from(self.completed)
    }

    pub fn from_bits(bits: u64) -> Self {
        Self::of(bits, bits & 1 == 1)
    }

    fn names(self, overlay: &Overlay) -> bool {
        overlay.id & !1 == self.id
    }
}

/// A web start's +1, kept beside the user's row until its finish removes it or it expires.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Overlay {
    pub id: u64,
    pub at: NaiveDateTime,
    pub policy: LockoutPolicy,
    pub expires: Instant,
    pub peer: Option<IpAddr>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LockWrite {
    pub user: UserId,
    pub uuid: Option<Uuid>,
    pub row: Option<LockRow>,
    pub split: Option<SplitMark>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Written {
    /// The rows the table did not take, each with the row it holds instead.
    pub kept: Vec<(UserId, Option<LockRow>)>,
    pub split_kept: Vec<UserId>,
    pub period: String,
}

/// A stored row with its account's uuid, `None` only where the store does not know it.
pub type StoredLock = (UserId, Option<Uuid>, LockRow);

#[async_trait]
pub trait LockStore: Send + Sync {
    async fn read_lock(&self, user: &UserId) -> Result<Option<LockRow>>;
    /// The rows with a stamp at or after `since`; every row for `None`.
    async fn read_locks(&self, since: Option<NaiveDateTime>) -> Result<Vec<StoredLock>>;
    async fn read_lock_users(&self) -> Result<Vec<UserId>>;
    async fn read_split(&self, user: &UserId) -> Result<Option<SplitMark>>;
    async fn read_period(&self) -> Result<String>;
    /// One transaction: nothing is stored unless the period, read under a lock, is `period`.
    async fn write_locks(&self, period: &str, writes: &[LockWrite]) -> Result<Written>;
    /// The second factor's spent steps and used enrollment proofs, pruned on this tick.
    async fn prune_codes(&self) -> Result<u64> {
        Ok(0)
    }
}

/// Whether any OU's policy sets a lockout threshold above 0.
pub fn threshold_set(policies: &[Policy]) -> bool {
    policies
        .iter()
        .any(|policy| !policy.linked_ous.is_empty() && sets_threshold(&policy.items))
}

pub fn sets_threshold(items: &std::collections::BTreeMap<String, String>) -> bool {
    let value = items.get(THRESHOLD).and_then(|v| v.parse::<u32>().ok());
    value.is_some_and(|threshold| threshold > 0)
}

pub fn lockout_judges(user: &UserId) -> bool {
    item_checks()
        .iter()
        .any(|check| check.key() == THRESHOLD && check.judges(user))
}

pub fn lock_detail(door: Door) -> String {
    format!("locked: {}", door.name())
}

pub fn record_account_lock(user: &UserId, door: Door) {
    let detail = lock_detail(door);
    logging::record_as(
        None,
        LogKind::AccountLock,
        Some(user.as_str()),
        true,
        Some(&detail),
    );
}

pub struct LockoutCheck;

impl ItemCheck for LockoutCheck {
    fn key(&self) -> &'static str {
        THRESHOLD
    }

    fn also_enforces(&self) -> &'static [&'static str] {
        &[DURATION]
    }

    fn live(&self, cache: &PolicyCache) -> bool {
        !cache.lockout_off()
    }

    fn may_refuse(&self, state: &UserState) -> bool {
        state.lock.is_some_and(|row| row.fail_count > 0)
    }

    fn allows(&self, attempt: &Attempt<'_>, value: &str, state: &UserState) -> bool {
        self.allows_among(attempt, value, &[], state)
    }

    fn allows_among(
        &self,
        attempt: &Attempt<'_>,
        value: &str,
        items: &[EffectiveItem],
        state: &UserState,
    ) -> bool {
        let Some(row) = state.lock else {
            return true;
        };
        let policy = LockoutPolicy {
            threshold: value.parse().unwrap_or(0),
            duration_seconds: number(items, DURATION),
        };
        !row.locked(policy, attempt.now.naive_utc())
    }
}

/// The user's row with its live starts, as a door judges it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LockState {
    pub user: UserId,
    pub policy: LockoutPolicy,
    pub row: LockRow,
    pub uuid: Option<Uuid>,
}

impl LockState {
    pub fn locked(&self, now: NaiveDateTime) -> bool {
        self.row.locked(self.policy, now)
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Write {
    #[default]
    None,
    Now,
    Later,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[must_use]
pub struct Step {
    pub write: Write,
    pub lock_logged: bool,
}

#[derive(Clone, Debug, Default)]
struct Entry {
    row: LockRow,
    overlays: Vec<Overlay>,
    seeded: bool,
    version: u64,
    stored: u64,
    touched: u64,
    uuid: Option<Uuid>,
    split: Option<SplitMark>,
    confirmed: Option<Instant>,
    confirming: bool,
    unwritten: VecDeque<(u64, i64)>,
}

impl Entry {
    fn effective(&self) -> LockRow {
        self.row.with_overlays(&self.overlays)
    }

    fn change(&mut self, row: LockRow) {
        self.row = row;
        self.version += 1;
    }

    fn take_stored(&mut self, row: LockRow) {
        self.change(row);
        self.stored = self.version;
        self.seeded = true;
        self.unwritten.clear();
    }

    fn count(&mut self, row: LockRow, times: &[NaiveDateTime]) {
        self.change(row);
        for at in times {
            if self.unwritten.len() == UNWRITTEN_CAP {
                self.unwritten.pop_front();
            }
            self.unwritten.push_back((self.version, micros_of(*at)));
        }
    }

    fn carried(&mut self, version: u64) {
        self.unwritten.retain(|(counted, _)| *counted > version);
    }

    /// A newer unlock in the table: the table's row, plus this server's unwritten failures later
    /// than the unlock.
    fn take_unlock(&mut self, table: LockRow) -> bool {
        let unlock = table.last_admin_unlock;
        if !after(unlock, self.row.last_admin_unlock) {
            return false;
        }
        let since = unlock.map_or(i64::MIN, micros_of);
        self.unwritten.retain(|(_, at)| *at > since);
        let mut later: Vec<i64> = self.unwritten.iter().map(|(_, at)| *at).collect();
        later.sort_unstable();
        let start = LockRow {
            last_success: self.row.last_success.max(table.last_success),
            ..table
        };
        let failures = later.into_iter().filter_map(time_of_micros);
        self.change(failures.fold(start, LockRow::failed));
        if self.row == table {
            self.stored = self.version;
        }
        true
    }

    fn owes_row(&self) -> bool {
        self.version != self.stored
    }

    fn owes_write(&self) -> bool {
        self.owes_row() || self.split.is_some()
    }

    fn next_expiry(&self) -> Option<Instant> {
        self.overlays.iter().map(|overlay| overlay.expires).min()
    }

    fn fold_all(&mut self, at: NaiveDateTime) -> Option<Option<IpAddr>> {
        let (mut row, mut logged, mut times) = (self.row, None, Vec::new());
        for overlay in self.overlays.drain(..) {
            let mut step = Step::default();
            row = Lockout::log_once(overlay.policy, row.failed(overlay.at), at, &mut step);
            if step.lock_logged {
                logged = Some(overlay.peer);
            }
            times.push(overlay.at);
        }
        if !times.is_empty() {
            self.count(row, &times);
        }
        logged
    }
}

struct Owed {
    ready_at: Instant,
    seq: u64,
    taken: bool,
}

/// What a full queue let go: the owed writes dropped so far, and a user whose folded starts
/// reached the threshold.
type Evicted = Option<(u64, Option<(UserId, Option<IpAddr>)>)>;

/// The rows every door judges with, and the users the table still owes, in insertion order.
#[derive(Default)]
struct Book {
    entries: HashMap<UserId, Entry>,
    owed: HashMap<UserId, Owed>,
    order: VecDeque<(UserId, u64)>,
    seq: u64,
    dropped: u64,
    read_at: Option<NaiveDateTime>,
    changes: u64,
    forgotten: HashMap<UserId, u64>,
    cleared_at: u64,
    refreshed_at: u64,
}

impl Book {
    fn tick(&mut self) -> u64 {
        self.changes += 1;
        self.changes
    }

    fn unchanged_since(&self, user: &UserId, since: u64) -> bool {
        self.cleared_at <= since
            && self.forgotten.get(user).is_none_or(|at| *at <= since)
            && self
                .entries
                .get(user)
                .is_none_or(|entry| entry.touched <= since)
    }

    /// An entry is the account it was made for: a known uuid it does not hold starts it anew.
    fn ensure(&mut self, user: &UserId, uuid: Option<&Uuid>) {
        let other = self
            .entries
            .get(user)
            .is_some_and(|entry| uuid.is_some_and(|uuid| entry.uuid.as_ref() != Some(uuid)));
        if other {
            self.forget(user);
        }
        let tick = self.tick();
        self.entries.entry(user.clone()).or_insert_with(|| Entry {
            touched: tick,
            uuid: uuid.cloned(),
            ..Entry::default()
        });
    }

    fn forget(&mut self, user: &UserId) {
        self.entries.remove(user);
        self.owed.remove(user);
        let tick = self.tick();
        self.forgotten.insert(user.clone(), tick);
    }

    fn owe(&mut self, user: &UserId, ready_at: Instant) -> Evicted {
        if let Some(owed) = self.owed.get_mut(user) {
            owed.ready_at = owed.ready_at.min(ready_at);
            return None;
        }
        self.seq += 1;
        let seq = self.seq;
        let owed = Owed {
            ready_at,
            seq,
            taken: false,
        };
        self.owed.insert(user.clone(), owed);
        self.order.push_back((user.clone(), seq));
        let evicted = (self.owed.len() > QUEUE_LIMIT)
            .then(|| self.evict_oldest(user))
            .flatten();
        if self.order.len() > 2 * self.owed.len() + 64 {
            let owed = &self.owed;
            self.order
                .retain(|(user, seq)| owed.get(user).is_some_and(|o| o.seq == *seq));
        }
        evicted
    }

    /// The oldest owed user not being written nor `kept`: its starts join its row; its write goes.
    fn evict_oldest(&mut self, kept: &UserId) -> Evicted {
        for _ in 0..self.order.len() {
            let Some((user, seq)) = self.order.pop_front() else {
                break;
            };
            let Some(owed) = self.owed.get(&user).filter(|owed| owed.seq == seq) else {
                continue;
            };
            if owed.taken || user == *kept {
                self.order.push_back((user, seq));
                continue;
            }
            self.owed.remove(&user);
            let tick = self.tick();
            let logged = self.entries.get_mut(&user).and_then(|entry| {
                entry.touched = tick;
                let logged = entry.fold_all(lock_clock());
                entry.unwritten.clear();
                logged
            });
            self.dropped += 1;
            return Some((self.dropped, logged.map(|peer| (user, peer))));
        }
        None
    }

    fn needs_read(&self, user: &UserId) -> bool {
        !self.owed.contains_key(user) && self.entries.get(user).is_none_or(|entry| !entry.seeded)
    }

    fn take(&mut self, ready_by: Option<Instant>, limit: usize) -> Vec<UserId> {
        let ready = |owed: &&Owed| ready_by.is_none_or(|by| owed.ready_at <= by);
        let taken: Vec<UserId> = self
            .owed
            .iter()
            .filter(|(_, owed)| !owed.taken && ready(owed))
            .map(|(user, _)| user.clone())
            .take(limit)
            .collect();
        self.mark_taken(&taken);
        taken
    }

    fn take_users(&mut self, users: &[UserId]) -> Vec<UserId> {
        let free = |user: &&UserId| self.owed.get(*user).is_some_and(|owed| !owed.taken);
        let taken: Vec<UserId> = users.iter().filter(free).cloned().collect();
        self.mark_taken(&taken);
        taken
    }

    fn mark_taken(&mut self, users: &[UserId]) {
        for user in users {
            if let Some(owed) = self.owed.get_mut(user) {
                owed.taken = true;
            }
        }
    }

    fn release(&mut self, user: &UserId, after: Option<Duration>) {
        let next = match (self.entries.get(user), after) {
            (None, _) => None,
            (Some(_), Some(after)) => Some(Instant::now() + after),
            (Some(entry), None) if entry.owes_write() => Some(Instant::now()),
            (Some(entry), None) => entry.next_expiry(),
        };
        if !self.owed.get(user).is_some_and(|owed| owed.taken) {
            return;
        }
        match next {
            Some(ready_at) => {
                if let Some(owed) = self.owed.get_mut(user) {
                    owed.taken = false;
                    owed.ready_at = ready_at;
                }
            }
            None => {
                self.owed.remove(user);
            }
        }
    }
}

fn note_evicted(evicted: Evicted) {
    let Some((n, locked)) = evicted else {
        return;
    };
    if n.is_power_of_two() {
        warn!("The lockout queue is full: {n} users' rows left to memory");
    }
    if let Some((user, peer)) = locked {
        record_start_lock(&user, peer);
    }
}

/// A lock that a web start's fold reached is logged as that start's: over HTTP, from its peer.
fn record_start_lock(user: &UserId, peer: Option<IpAddr>) {
    logging::as_start(peer, || record_account_lock(user, Door::WebLogin));
}

struct Confirming<'a> {
    lockout: &'a Lockout,
    user: &'a UserId,
}

impl Drop for Confirming<'_> {
    fn drop(&mut self) {
        if let Some(entry) = self.lockout.book().entries.get_mut(self.user) {
            entry.confirming = false;
        }
    }
}

/// Lets a taken entry go again when its write ends without settling it.
struct Again<'a> {
    lockout: &'a Lockout,
    users: Vec<UserId>,
    after: Duration,
}

impl Drop for Again<'_> {
    fn drop(&mut self) {
        let mut book = self.lockout.book();
        for user in &self.users {
            book.release(user, Some(self.after));
        }
    }
}

#[derive(Clone)]
struct KdcWriter {
    store: Arc<dyn LockStore>,
    runtime: tokio::runtime::Handle,
}

pub struct Lockout {
    book: Mutex<Book>,
    ready: Notify,
    writing: tokio::sync::Mutex<()>,
    following: tokio::sync::Mutex<()>,
    period: Mutex<String>,
    stale: AtomicBool,
    outage: Mutex<Option<(Instant, HashSet<UserId>)>>,
    kdc: RwLock<Option<KdcWriter>>,
}

impl Default for Lockout {
    fn default() -> Self {
        Self {
            book: Mutex::default(),
            ready: Notify::new(),
            writing: tokio::sync::Mutex::new(()),
            following: tokio::sync::Mutex::new(()),
            period: Mutex::new("0".to_owned()),
            stale: AtomicBool::new(false),
            outage: Mutex::new(None),
            kdc: RwLock::new(None),
        }
    }
}

static LOCKOUT: LazyLock<Lockout> = LazyLock::new(Lockout::default);

pub fn lockout() -> &'static Lockout {
    &LOCKOUT
}

impl Lockout {
    fn book(&self) -> MutexGuard<'_, Book> {
        self.book.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub fn row(&self, user: &UserId) -> Option<LockRow> {
        self.book().entries.get(user).map(|entry| entry.row)
    }

    pub fn effective(&self, user: &UserId) -> Option<LockRow> {
        self.book().entries.get(user).map(Entry::effective)
    }

    pub fn overlays(&self, user: &UserId) -> usize {
        let book = self.book();
        book.entries
            .get(user)
            .map_or(0, |entry| entry.overlays.len())
    }

    pub fn pending(&self, user: &UserId) -> bool {
        self.book().owed.contains_key(user)
    }

    pub fn owed(&self) -> usize {
        self.book().owed.len()
    }

    pub fn dropped(&self) -> u64 {
        self.book().dropped
    }

    pub fn is_empty(&self) -> bool {
        let book = self.book();
        book.entries.is_empty() && book.owed.is_empty()
    }

    pub fn period(&self) -> String {
        self.period
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn set_period(&self, period: String) {
        *self.period.lock().unwrap_or_else(PoisonError::into_inner) = period;
    }

    /// The row as the table holds it, as a read would take it.
    pub fn seed(&self, user: &UserId, row: LockRow) {
        let mut book = self.book();
        book.ensure(user, None);
        let tick = book.tick();
        if let Some(entry) = book.entries.get_mut(user) {
            entry.take_stored(row);
            entry.touched = tick;
        }
    }

    pub fn user_state(&self, user: &UserId) -> UserState {
        UserState {
            lock: self.effective(user),
        }
    }

    pub fn outage(&self) -> Option<(Instant, usize)> {
        let outage = self.outage.lock().unwrap_or_else(PoisonError::into_inner);
        outage.as_ref().map(|(since, users)| (*since, users.len()))
    }

    fn lock_state(&self, user: &UserId, policy: LockoutPolicy) -> LockState {
        let book = self.book();
        let entry = book.entries.get(user);
        LockState {
            user: user.clone(),
            policy,
            row: entry.map(Entry::effective).unwrap_or_default(),
            uuid: entry.and_then(|entry| entry.uuid.clone()),
        }
    }

    /// One atomic read while no OU sets a threshold; the table is read only for a row this
    /// server does not hold and owes nothing for, or to confirm a lock.
    pub async fn state<H>(
        &self,
        handler: &H,
        cache: &PolicyCache,
        user: &UserId,
    ) -> Result<Option<LockState>>
    where
        H: UserBackendHandler + PolicyBackendHandler + LockStore + ?Sized,
    {
        if cache.lockout_off() || !lockout_judges(user) {
            return Ok(None);
        }
        if cache.lockout_unknown() {
            return Err(DomainError::InternalError(NOT_READ_YET.to_owned()));
        }
        let policy = LockoutPolicy::of(&resolve_items(handler, cache, user).await?);
        let uuid = cache.get().facts_of(user).map(|facts| facts.uuid.clone());
        let since = {
            let mut book = self.book();
            book.ensure(user, uuid.as_ref());
            book.changes
        };
        if policy.threshold > 0 && self.book().needs_read(user) {
            let stored = handler.read_lock(user).await?;
            let mut book = self.book();
            let fresh = book.needs_read(user) && book.unchanged_since(user, since);
            let tick = book.tick();
            if let Some(entry) = book.entries.get_mut(user).filter(|_| fresh) {
                entry.take_stored(stored.unwrap_or_default());
                entry.touched = tick;
            }
        }
        let state = self.lock_state(user, policy);
        if policy.threshold == 0 || !state.locked(lock_clock()) || !self.confirm_due(user) {
            return Ok(Some(state));
        }
        if let Err(e) = self.confirm_with(handler, user).await {
            warn!("The lock of {user} was not confirmed against the table: {e}");
        }
        Ok(Some(self.lock_state(user, policy)))
    }

    pub fn kdc_state(&self, cache: &PolicyCache, user: &UserId) -> Option<LockState> {
        if !cache.lockout_live() || !lockout_judges(user) {
            return None;
        }
        let entries = cache.get();
        let policy = entries.items_of(user).map(LockoutPolicy::of);
        let uuid = entries.facts_of(user).map(|facts| &facts.uuid);
        self.book().ensure(user, uuid);
        Some(self.lock_state(user, policy.unwrap_or_default()))
    }

    fn confirm_due(&self, user: &UserId) -> bool {
        let mut book = self.book();
        let Some(entry) = book.entries.get_mut(user) else {
            return false;
        };
        let recent = entry
            .confirmed
            .is_some_and(|at| at.elapsed() < CONFIRM_EVERY);
        if recent || entry.confirming {
            return false;
        }
        entry.confirmed = Some(Instant::now());
        entry.confirming = true;
        true
    }

    /// Takes over a newer unlock the table holds; nothing else.
    async fn confirm_with<S: LockStore + ?Sized>(&self, store: &S, user: &UserId) -> Result<bool> {
        let _confirming = Confirming {
            lockout: self,
            user,
        };
        let stored = store.read_lock(user).await?;
        let mut book = self.book();
        let tick = book.tick();
        let Some((entry, table)) = book.entries.get_mut(user).zip(stored) else {
            return Ok(false);
        };
        if !entry.take_unlock(table) {
            return Ok(false);
        }
        entry.touched = tick;
        if entry.owes_row() {
            self.owe(book, user, Instant::now());
        }
        Ok(true)
    }

    /// Whether a lock about to refuse gave way to a newer unlock, for a door with no store.
    pub async fn confirm(&self, user: &UserId) -> bool {
        let writer = self
            .kdc
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        let Some(writer) = writer.filter(|_| self.confirm_due(user)) else {
            return false;
        };
        self.confirm_with(&*writer.store, user)
            .await
            .unwrap_or(false)
    }

    /// From the KDC's thread: the read runs on the server's runtime, for the next request.
    pub fn confirm_soon(&'static self, user: &UserId) {
        let writer = self
            .kdc
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        let Some(KdcWriter { store, runtime }) = writer.filter(|_| self.confirm_due(user)) else {
            return;
        };
        let user = user.clone();
        runtime.spawn(async move {
            let _ = self.confirm_with(&*store, &user).await;
        });
    }

    fn timing(state: &LockState) -> Write {
        if state.policy.threshold > 0 {
            Write::Now
        } else {
            Write::Later
        }
    }

    fn log_once(
        policy: LockoutPolicy,
        row: LockRow,
        at: NaiveDateTime,
        step: &mut Step,
    ) -> LockRow {
        if !row.locked(policy, at) || row.lock_logged_this_cycle() {
            return row;
        }
        step.lock_logged = true;
        LockRow {
            lock_logged: Some(at),
            ..row
        }
    }

    fn owe(&self, mut book: MutexGuard<'_, Book>, user: &UserId, ready_at: Instant) {
        let evicted = book.owe(user, ready_at);
        drop(book);
        note_evicted(evicted);
        self.ready.notify_one();
    }

    /// Counted on the user's current row, never on the row the door read before its work.
    pub fn failure(&self, state: &LockState, at: NaiveDateTime) -> Step {
        let mut book = self.book();
        let tick = book.tick();
        let Some(entry) = book
            .entries
            .get_mut(&state.user)
            .filter(|e| e.uuid == state.uuid)
        else {
            return Step::default();
        };
        if entry.effective().locked(state.policy, at) {
            return Step::default();
        }
        let mut step = Step {
            write: Self::timing(state),
            ..Step::default()
        };
        let row = Self::log_once(state.policy, entry.row.failed(at), at, &mut step);
        entry.count(row, &[at]);
        entry.touched = tick;
        self.owe(book, &state.user, Instant::now());
        step
    }

    /// False when the user is locked by now, the start's own +1 not counted, or when the entry
    /// the door read is gone, so no start is accepted unrecorded.
    pub fn start(&self, state: &LockState, id: u64, at: NaiveDateTime) -> bool {
        let expires = Instant::now() + START_HOLD;
        let mut book = self.book();
        let tick = book.tick();
        let Some(entry) = book
            .entries
            .get_mut(&state.user)
            .filter(|e| e.uuid == state.uuid)
        else {
            return false;
        };
        if entry.effective().locked(state.policy, at) {
            return false;
        }
        entry.touched = tick;
        if entry.overlays.len() >= OVERLAY_CAP {
            let mut step = Step::default();
            let row = Self::log_once(state.policy, entry.row.failed(at), at, &mut step);
            entry.count(row, &[at]);
            self.owe(book, &state.user, Instant::now());
            if step.lock_logged {
                record_account_lock(&state.user, Door::WebLogin);
            }
            return true;
        }
        entry.overlays.push(Overlay {
            id,
            at,
            policy: state.policy,
            expires,
            peer: logging::current_request().peer,
        });
        self.owe(book, &state.user, expires);
        true
    }

    /// A verified finish removes its own start, once; it changes nothing else.
    pub fn finish(&self, user: &UserId, id: u64) -> bool {
        let mut book = self.book();
        let tick = book.tick();
        let Some(entry) = book.entries.get_mut(user) else {
            return false;
        };
        let before = entry.overlays.len();
        entry.overlays.retain(|overlay| overlay.id != id);
        let found = entry.overlays.len() != before;
        if found {
            entry.touched = tick;
        }
        found
    }

    /// A verified finish whose start another server holds: its id goes to the table.
    pub fn split(&self, user: &UserId, id: u64, completed: bool) -> Step {
        let mut book = self.book();
        let tick = book.tick();
        let Some(entry) = book.entries.get_mut(user) else {
            return Step::default();
        };
        entry.split = Some(SplitMark::of(id, completed));
        entry.touched = tick;
        self.owe(book, user, Instant::now());
        Step {
            write: Write::Now,
            ..Step::default()
        }
    }

    /// A completed sign-in drops the user's starts made before it, here and with no write.
    pub fn success(&self, state: &LockState, at: NaiveDateTime) -> Step {
        let mut book = self.book();
        let tick = book.tick();
        let Some(entry) = book
            .entries
            .get_mut(&state.user)
            .filter(|e| e.uuid == state.uuid)
        else {
            return Step::default();
        };
        entry.overlays.retain(|overlay| overlay.at >= at);
        entry.unwritten.clear();
        entry.touched = tick;
        if entry.row.fail_count == 0 {
            return Step::default();
        }
        entry.change(entry.row.cleared(at));
        self.owe(book, &state.user, Instant::now());
        Step {
            write: Self::timing(state),
            ..Step::default()
        }
    }

    /// A ticket on the password alone is a sign-in only for a user known to have no second factor.
    pub fn ticket_issued(&self, cache: &PolicyCache, state: &LockState, at: NaiveDateTime) -> Step {
        let entries = cache.get();
        let policy = cached_mfa_policy(cache, &entries, &state.user);
        let one_factor = entries
            .facts_of(&state.user)
            .zip(policy)
            .is_some_and(|(facts, policy)| !facts.second_factor_required(policy));
        if !one_factor {
            return Step::default();
        }
        self.success(state, at)
    }

    pub fn unlocked(&self, user: &UserId, at: NaiveDateTime) {
        let mut book = self.book();
        let owed = book.owed.contains_key(user);
        let tick = book.tick();
        if let Some(entry) = book.entries.get_mut(user) {
            entry.change(entry.row.unlocked(at));
            entry.unwritten.clear();
            if !owed {
                entry.stored = entry.version;
            }
            entry.touched = tick;
        }
    }

    /// The user's row, starts and owed write, at once: the account is gone or new.
    pub fn forget(&self, user: &UserId) {
        self.book().forget(user);
    }

    pub async fn carry<S: LockStore + ?Sized>(&self, store: &S, user: &UserId, step: Step) {
        if step.write == Write::Now {
            let users = std::slice::from_ref(user);
            let _ = tokio::time::timeout(WRITE_BOUND, self.flush(store, users)).await;
        }
    }

    async fn flush<S: LockStore + ?Sized>(&self, store: &S, users: &[UserId]) {
        let _writing = self.writing.lock().await;
        let taken = self.book().take_users(users);
        self.write_taken(store, taken).await;
    }

    pub async fn drain<S: LockStore + ?Sized>(&self, store: &S) -> usize {
        let _writing = self.writing.lock().await;
        let taken = self.book().take(Some(Instant::now()), BATCH_LIMIT);
        let n = taken.len();
        self.write_taken(store, taken).await;
        n
    }

    async fn write_taken<S: LockStore + ?Sized>(&self, store: &S, users: Vec<UserId>) {
        if users.is_empty() {
            return;
        }
        let mut again = Again {
            lockout: self,
            users,
            after: Duration::ZERO,
        };
        let unread = self.fold_expired(store, &again.users).await;
        if !unread.is_empty() {
            let users = std::mem::take(&mut again.users);
            let (users, unread): (Vec<UserId>, Vec<UserId>) =
                users.into_iter().partition(|user| !unread.contains(user));
            again.users = users;
            drop(Again {
                lockout: self,
                users: unread,
                after: RETRY_AFTER,
            });
        }
        let writes: Vec<(LockWrite, u64)> = {
            let book = self.book();
            let owing = again.users.iter().filter_map(|user| {
                let entry = book.entries.get(user).filter(|entry| entry.owes_write())?;
                let write = LockWrite {
                    user: user.clone(),
                    uuid: entry.uuid.clone(),
                    row: entry.owes_row().then_some(entry.row),
                    split: entry.split,
                };
                Some((write, entry.version))
            });
            owing.collect()
        };
        if !writes.is_empty() {
            let period = self.period();
            let batch: Vec<LockWrite> = writes.iter().map(|(write, _)| write.clone()).collect();
            let written = store.write_locks(&period, &batch).await;
            self.note(&written, &again.users);
            let Ok(written) = written else {
                again.after = RETRY_AFTER;
                return;
            };
            if written.period != period {
                self.stale.store(true, Ordering::Release);
            }
            self.settle(&writes, &written);
        }
        let users = std::mem::take(&mut again.users);
        let mut book = self.book();
        for user in &users {
            book.release(user, None);
        }
    }

    fn settle(&self, writes: &[(LockWrite, u64)], written: &Written) {
        let kept: HashMap<&UserId, Option<LockRow>> = written
            .kept
            .iter()
            .map(|(user, row)| (user, *row))
            .collect();
        let mut book = self.book();
        for (write, version) in writes {
            let user = &write.user;
            if let Some(None) = kept.get(user) {
                book.forget(user);
                continue;
            }
            let tick = book.tick();
            let Some(entry) = book.entries.get_mut(user) else {
                continue;
            };
            entry.touched = tick;
            match (write.row, kept.get(user)) {
                (Some(_), Some(Some(table))) => {
                    let unlocked = entry.take_unlock(*table);
                    if !unlocked && entry.version == *version {
                        entry.take_stored(*table);
                    }
                }
                (Some(_), _) => {
                    entry.carried(*version);
                    if entry.version == *version {
                        entry.stored = *version;
                        entry.seeded = true;
                    }
                }
                _ => {}
            }
            if write.split.is_some()
                && entry.split == write.split
                && !written.split_kept.contains(user)
            {
                entry.split = None;
            }
        }
    }

    /// Each expired start joins the row as a failure at its own time, unless the table holds its
    /// id, or that of a later start held here whose sign-in completed.
    async fn fold_expired<S: LockStore + ?Sized>(
        &self,
        store: &S,
        users: &[UserId],
    ) -> Vec<UserId> {
        let now = Instant::now();
        let expiring: Vec<UserId> = {
            let book = self.book();
            let expired = |user: &&UserId| {
                book.entries
                    .get(*user)
                    .is_some_and(|entry| entry.overlays.iter().any(|o| o.expires <= now))
            };
            users.iter().filter(expired).cloned().collect()
        };
        let mut unread = Vec::new();
        for user in expiring {
            let split = match store.read_split(&user).await {
                Ok(split) => split,
                Err(e) => {
                    warn!("The starts of {user} were not folded: {e}");
                    unread.push(user);
                    continue;
                }
            };
            let at = lock_clock();
            let mut logged = None;
            {
                let mut book = self.book();
                let tick = book.tick();
                let Some(entry) = book.entries.get_mut(&user) else {
                    continue;
                };
                let (mut row, mut times) = (entry.row, Vec::new());
                let completed = split.filter(|mark| mark.completed);
                let later = completed.and_then(|mark| {
                    entry
                        .overlays
                        .iter()
                        .position(|overlay| mark.names(overlay))
                });
                let mut index = 0;
                entry.overlays.retain(|overlay| {
                    let here = index;
                    index += 1;
                    if overlay.expires > now {
                        return true;
                    }
                    let own = split.is_some_and(|mark| mark.names(overlay));
                    let before = later.is_some_and(|later| here < later);
                    if !own && !before {
                        let mut step = Step::default();
                        row = Self::log_once(overlay.policy, row.failed(overlay.at), at, &mut step);
                        if step.lock_logged {
                            logged = Some(overlay.peer);
                        }
                        times.push(overlay.at);
                    }
                    false
                });
                if !times.is_empty() {
                    entry.count(row, &times);
                }
                entry.touched = tick;
            }
            if let Some(peer) = logged {
                record_start_lock(&user, peer);
            }
        }
        unread
    }

    fn note<T>(&self, written: &Result<T>, users: &[UserId]) {
        let mut outage = self.outage.lock().unwrap_or_else(PoisonError::into_inner);
        match written {
            Err(e) => {
                if let Some((_, waiting)) = outage.as_mut() {
                    waiting.extend(users.iter().cloned());
                } else {
                    warn!("Lockout counts are not being stored ({e}); they are kept and retried");
                    *outage = Some((Instant::now(), users.iter().cloned().collect()));
                }
            }
            Ok(_) => {
                if let Some((since, waiting)) = outage.take() {
                    let (took, n) = (since.elapsed(), waiting.len());
                    info!("Lockout counts are stored again after {took:?}; {n} users' rows waited");
                }
            }
        }
    }

    pub fn serve_kdc(&self, store: Arc<dyn LockStore>, runtime: tokio::runtime::Handle) {
        *self.kdc.write().unwrap_or_else(PoisonError::into_inner) =
            Some(KdcWriter { store, runtime });
    }

    fn stop_serving_kdc(&self) -> Option<Arc<dyn LockStore>> {
        let writer = self
            .kdc
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        writer.map(|writer| writer.store)
    }

    pub fn kdc_counts(&self) -> bool {
        self.kdc
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .is_some()
    }

    /// On the KDC's thread: a queued count is marked here; a count due now is written on the
    /// server's runtime, and the thread waits at most `WRITE_BOUND` for it.
    pub fn carry_from_kdc(&'static self, user: &UserId, step: Step) {
        if step.write != Write::Now {
            return;
        }
        let writer = self
            .kdc
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        let Some(KdcWriter { store, runtime }) = writer else {
            return;
        };
        let (done, wait) = std::sync::mpsc::channel();
        let user = user.clone();
        runtime.spawn(async move {
            self.carry(&*store, &user, step).await;
            let _ = done.send(());
        });
        let _ = wait.recv_timeout(WRITE_BOUND);
    }

    /// A row read here is taken only for an entry nothing touched since the read began.
    async fn reread<S: LockStore + ?Sized>(&self, store: &S, all: bool) -> Result<usize> {
        let read_at = lock_clock();
        let margin = chrono::Duration::seconds(REREAD_MARGIN_SECS);
        let (since, since_at) = {
            let book = self.book();
            let since_at = match all {
                true => None,
                false => book.read_at.map(|at| at - margin),
            };
            (book.changes, since_at)
        };
        let rows = store.read_locks(since_at).await?;
        let present: HashSet<UserId> = match all {
            true => rows.iter().map(|(user, _, _)| user.clone()).collect(),
            false => store.read_lock_users().await?.into_iter().collect(),
        };
        let mut book = self.book();
        let mut taken = 0;
        for (user, uuid, row) in rows {
            let owes = book.entries.get(&user).is_some_and(Entry::owes_row);
            if owes || book.owed.contains_key(&user) || !book.unchanged_since(&user, since) {
                continue;
            }
            book.ensure(&user, uuid.as_ref());
            let tick = book.tick();
            if let Some(entry) = book.entries.get_mut(&user) {
                entry.take_stored(row);
                entry.touched = tick;
                taken += 1;
            }
        }
        let previous = book.refreshed_at;
        let Book {
            entries,
            owed,
            forgotten,
            ..
        } = &mut *book;
        entries.retain(|user, entry| {
            present.contains(user)
                || owed.contains_key(user)
                || !entry.overlays.is_empty()
                || entry.touched > previous
        });
        forgotten.retain(|_, at| *at > previous);
        book.refreshed_at = since;
        book.read_at = Some(read_at);
        Ok(taken)
    }

    pub async fn refresh<S: LockStore + ?Sized>(&self, store: &S) -> Result<usize> {
        let _following = self.following.lock().await;
        self.reread(store, false).await
    }

    /// One at a time, one read for every flag, no part stopping another; true when filled.
    pub async fn follow_policies<H>(&self, handler: &H, cache: &PolicyCache) -> Result<bool>
    where
        H: UserListerBackendHandler
            + UserBackendHandler
            + PolicyBackendHandler
            + GroupListerBackendHandler
            + GroupBackendHandler
            + LockStore
            + ?Sized,
    {
        let _following = self.following.lock().await;
        let policies = handler.list_policies().await?;
        let mfa = follow_mfa_item(handler, cache, &policies).await;
        let lockout = self.follow_threshold(handler, cache, &policies).await;
        let items = follow_items(handler, cache, &policies).await;
        if cache.mfa_item_live()
            && let Err(e) = ensure_exempt_group(handler).await
        {
            warn!("The exempt group was not made: {e}");
        }
        Ok(mfa? | lockout? | items?)
    }

    /// A threshold that first takes effect, or a counting period that moved on, drops all in
    /// memory and reads it again before the flag lets a verdict use it.
    async fn follow_threshold<H>(
        &self,
        handler: &H,
        cache: &PolicyCache,
        policies: &[Policy],
    ) -> Result<bool>
    where
        H: UserListerBackendHandler
            + UserBackendHandler
            + PolicyBackendHandler
            + LockStore
            + ?Sized,
    {
        let live = threshold_set(policies);
        let period = handler.read_period().await?;
        let stale = self.stale.swap(false, Ordering::AcqRel);
        let moved = stale || period != self.period();
        if live && (moved || !cache.lockout_live()) {
            let flipped = async {
                fill_policy_cache(handler, cache).await?;
                self.forget_all().await;
                self.reread(handler, true).await?;
                self.set_period(period);
                cache.set_lockout_live(true);
                fill_policy_cache(handler, cache).await
            };
            if let Err(e) = flipped.await {
                cache.set_lockout_unknown();
                return Err(e);
            }
            return Ok(true);
        }
        if !live && !cache.lockout_off() {
            cache.set_lockout_live(false);
            self.forget_all().await;
        }
        self.set_period(period);
        Ok(false)
    }

    async fn forget_all(&self) {
        let _writing = self.writing.lock().await;
        let mut book = self.book();
        book.entries.clear();
        book.owed.clear();
        book.order.clear();
        book.cleared_at = book.tick();
    }

    pub fn run<S>(&'static self, store: Arc<S>, cache: &'static PolicyCache) -> Running
    where
        S: LockStore
            + UserListerBackendHandler
            + UserBackendHandler
            + PolicyBackendHandler
            + GroupListerBackendHandler
            + GroupBackendHandler
            + 'static,
    {
        tokio::spawn(async move {
            let mut followed = Instant::now();
            loop {
                tokio::select! {
                    () = self.ready.notified() => {}
                    () = tokio::time::sleep(DRAIN_EVERY) => {}
                }
                tokio::time::sleep(DRAIN_GAP).await;
                while self.drain(&*store).await == BATCH_LIMIT {}
                let due = followed.elapsed() >= POLICY_REFILL
                    || cache.lockout_unknown()
                    || cache.mfa_item_unknown()
                    || cache.items_unread()
                    || self.stale.load(Ordering::Acquire);
                if !due {
                    continue;
                }
                followed = Instant::now();
                let refreshed = match self.follow_policies(&*store, cache).await {
                    Ok(false) if cache.lockout_live() => self.refresh(&*store).await.map(drop),
                    other => other.map(drop),
                };
                if let Err(e) = refreshed {
                    warn!("The lockout view was not refreshed: {e}");
                }
                prune_spent_steps(&*store).await;
            }
        })
    }

    /// A clean stop writes, once and for at most `STOP_BOUND`, what is owed, every start that
    /// has not finished included.
    pub async fn stop(&self) {
        let Some(store) = self.stop_serving_kdc() else {
            return;
        };
        let _ = tokio::time::timeout(STOP_BOUND, self.write_all_now(&*store)).await;
    }

    /// Every owed row and every start still held, written now.
    pub async fn write_all_now<S: LockStore + ?Sized>(&self, store: &S) {
        let _writing = self.writing.lock().await;
        let now = Instant::now();
        let taken = {
            let mut book = self.book();
            for entry in book.entries.values_mut() {
                entry
                    .overlays
                    .iter_mut()
                    .for_each(|overlay| overlay.expires = now);
            }
            book.take(None, usize::MAX)
        };
        for batch in taken.chunks(BATCH_LIMIT) {
            self.write_taken(store, batch.to_vec()).await;
        }
    }
}

pub type Running = tokio::task::JoinHandle<()>;

/// Before the KDC serves: until the first follow reads the policies, every door the lockout
/// or enable-mfa judges refuses, and the follow is tried again every second.
pub async fn start_lockout<S>(store: &S, cache: &'static PolicyCache) -> Running
where
    S: LockStore
        + UserListerBackendHandler
        + UserBackendHandler
        + PolicyBackendHandler
        + GroupListerBackendHandler
        + GroupBackendHandler
        + Clone
        + 'static,
{
    let lockout = lockout();
    if let Err(e) = first_follow(lockout, store, cache).await {
        warn!("The policies were not read at start; the doors needing them refuse until read: {e}");
    }
    prune_spent_steps(store).await;
    let store = Arc::new(store.clone());
    lockout.serve_kdc(store.clone(), tokio::runtime::Handle::current());
    cache.serve_windows(store.clone(), tokio::runtime::Handle::current());
    lockout.run(store, cache)
}

/// Both flags unknown until read; the lockout's leaves that state whatever the MFA part answers.
pub async fn first_follow<S>(lockout: &Lockout, store: &S, cache: &PolicyCache) -> Result<bool>
where
    S: LockStore
        + UserListerBackendHandler
        + UserBackendHandler
        + PolicyBackendHandler
        + GroupListerBackendHandler
        + GroupBackendHandler
        + ?Sized,
{
    cache.set_lockout_unknown();
    cache.set_mfa_item_unknown();
    lockout.follow_policies(store, cache).await
}

async fn prune_spent_steps<S: LockStore + ?Sized>(store: &S) {
    if let Err(e) = store.prune_codes().await {
        warn!("The second factor's past steps were not pruned: {e}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policies::PolicyScope;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_a_kdc_door_waits_at_most_a_quarter_second_for_its_count_to_be_written() {
        assert_eq!(WRITE_BOUND, Duration::from_millis(250));
    }

    fn at(seconds: i64) -> NaiveDateTime {
        chrono::DateTime::from_timestamp(1_700_000_000 + seconds, 0)
            .unwrap()
            .naive_utc()
    }

    fn row(fail_count: u32, failed: Option<i64>, unlocked: Option<i64>) -> LockRow {
        LockRow {
            fail_count,
            last_failed: failed.map(at),
            last_admin_unlock: unlocked.map(at),
            ..LockRow::default()
        }
    }

    fn policy(threshold: u32, duration_seconds: u32) -> LockoutPolicy {
        LockoutPolicy {
            threshold,
            duration_seconds,
        }
    }

    fn bob() -> UserId {
        UserId::new("bob")
    }

    fn state_of(user: &UserId, policy: LockoutPolicy, row: LockRow) -> LockState {
        LockState {
            user: user.clone(),
            policy,
            row,
            uuid: None,
        }
    }

    fn account(n: u8) -> Uuid {
        Uuid::from_name_and_date(&format!("bob{n}"), &at(0))
    }

    fn state(policy: LockoutPolicy, row: LockRow) -> LockState {
        state_of(&bob(), policy, row)
    }

    fn overlay(id: u64, seconds: i64) -> Overlay {
        Overlay {
            id,
            at: at(seconds),
            policy: policy(3, 0),
            expires: Instant::now() + START_HOLD,
            peer: None,
        }
    }

    /// As if `START_HOLD` had passed for every start of the user.
    fn expire(lockout: &Lockout, user: &UserId) {
        let now = Instant::now();
        let mut book = lockout.book();
        if let Some(entry) = book.entries.get_mut(user) {
            entry.overlays.iter_mut().for_each(|o| o.expires = now);
        }
        if let Some(owed) = book.owed.get_mut(user) {
            owed.ready_at = now;
        }
    }

    #[test]
    fn test_the_lock_rules_table() {
        let rows = [
            ("threshold 0", policy(0, 0), row(9, Some(0), None), 1, false),
            ("below", policy(3, 60), row(2, Some(0), None), 1, false),
            ("at", policy(3, 60), row(3, Some(0), None), 1, true),
            ("past", policy(3, 60), row(7, Some(0), None), 1, true),
            (
                "the duration runs out",
                policy(3, 60),
                row(3, Some(0), None),
                60,
                false,
            ),
            (
                "one second before",
                policy(3, 60),
                row(3, Some(0), None),
                59,
                true,
            ),
            (
                "duration 0 holds",
                policy(3, 0),
                row(3, Some(0), None),
                999_999,
                true,
            ),
            ("never failed", policy(1, 0), row(3, None, None), 1, false),
            (
                "unlocked since",
                policy(3, 0),
                row(3, Some(0), Some(0)),
                1,
                false,
            ),
            (
                "failed after the unlock",
                policy(3, 0),
                row(3, Some(5), Some(0)),
                6,
                true,
            ),
            (
                "a lowered threshold applies",
                policy(2, 60),
                row(2, Some(0), None),
                1,
                true,
            ),
            (
                "a raised threshold applies",
                policy(4, 60),
                row(3, Some(0), None),
                1,
                false,
            ),
            (
                "cleared by a success",
                policy(3, 60),
                row(0, Some(0), None),
                1,
                false,
            ),
        ];
        for (label, policy, row, now, locked) in rows {
            assert_eq!(row.locked(policy, at(now)), locked, "{label}");
        }
    }

    #[test]
    fn test_each_change_of_a_row() {
        let rows = [
            (
                "first failure",
                row(0, None, None).failed(at(1)),
                row(1, Some(1), None),
            ),
            (
                "counts on",
                row(2, Some(0), None).failed(at(1)),
                row(3, Some(1), None),
            ),
            (
                "an earlier start keeps the later failure's time",
                row(2, Some(9), None).failed(at(4)),
                row(3, Some(9), None),
            ),
            (
                "restarts after an unlock",
                row(5, Some(0), Some(3)).failed(at(4)),
                row(1, Some(4), Some(3)),
            ),
            (
                "an unlock",
                row(4, Some(1), None).unlocked(at(2)),
                row(0, Some(1), Some(2)),
            ),
            (
                "two live starts on the row",
                row(1, Some(0), None).with_overlays(&[overlay(1, 5), overlay(2, 6)]),
                row(3, Some(6), None),
            ),
            (
                "a start before the unlock counts nothing",
                row(0, Some(0), Some(7)).with_overlays(&[overlay(1, 5)]),
                row(0, Some(0), Some(7)),
            ),
        ];
        for (label, got, expected) in rows {
            assert_eq!(got, expected, "{label}");
        }
        let cleared = row(4, Some(1), None).cleared(at(2));
        assert_eq!((cleared.fail_count, cleared.last_success), (0, Some(at(2))));
        let logged = LockRow {
            lock_logged: Some(at(3)),
            ..row(4, Some(1), None)
        };
        assert_eq!(
            logged.zeroed(),
            row(0, Some(1), None),
            "counting from zero clears the logged lock too"
        );
        let logged = |logged: i64, unlock: Option<i64>, success: Option<i64>| LockRow {
            lock_logged: Some(at(logged)),
            last_admin_unlock: unlock.map(at),
            last_success: success.map(at),
            ..LockRow::default()
        };
        let cycles = [
            ("never logged", LockRow::default(), false),
            ("logged in this cycle", logged(5, Some(1), Some(2)), true),
            ("an unlock since", logged(5, Some(6), None), false),
            ("a success since", logged(5, None, Some(6)), false),
        ];
        for (label, row, this_cycle) in cycles {
            assert_eq!(row.lock_logged_this_cycle(), this_cycle, "{label}");
        }
    }

    fn item(key: &str, value: &str) -> EffectiveItem {
        EffectiveItem {
            key: key.to_owned(),
            scope: PolicyScope::User,
            value: value.to_owned(),
            enforced: true,
            source: None,
        }
    }

    #[test]
    fn test_the_check_reads_the_threshold_and_the_duration_and_is_live_unless_off() {
        assert_eq!(
            LockoutPolicy::of(&[]),
            policy(0, 900),
            "the catalog defaults"
        );
        let items = [item(THRESHOLD, "3"), item(DURATION, "0")];
        assert_eq!(LockoutPolicy::of(&items), policy(3, 0));
        let user = bob();
        let attempt = |seconds| Attempt {
            user: &user,
            door: Door::TokenUse,
            peer: None,
            now: at(seconds).and_utc(),
            second_factor: false,
        };
        let locked = UserState {
            lock: Some(row(3, Some(0), None)),
        };
        let rows = [
            ("no row", UserState::default(), &items[..], 1, true),
            (
                "locked, duration 0",
                locked.clone(),
                &items[..],
                999_999,
                false,
            ),
            (
                "the default duration runs out",
                locked.clone(),
                &items[..1],
                900,
                true,
            ),
            (
                "the default duration holds",
                locked.clone(),
                &items[..1],
                899,
                false,
            ),
        ];
        for (label, state, items, now, allowed) in rows {
            assert_eq!(
                LockoutCheck.allows_among(&attempt(now), "3", items, &state),
                allowed,
                "{label}"
            );
        }
        let may = |lock| LockoutCheck.may_refuse(&UserState { lock });
        assert_eq!(
            (
                may(None),
                may(Some(row(0, Some(0), None))),
                may(locked.lock)
            ),
            (false, false, true),
            "only a count can lock, so a count of 0 reads nothing"
        );
        let cache = PolicyCache::new();
        let off = LockoutCheck.live(&cache);
        cache.set_lockout_unknown();
        let unknown = LockoutCheck.live(&cache);
        cache.set_lockout_live(true);
        assert_eq!(
            (off, unknown, LockoutCheck.live(&cache)),
            (false, true, true)
        );
    }

    #[test]
    fn test_each_step_writes_what_the_rules_say() {
        let lockout = Lockout::default();
        let user = bob();
        let step = |write, lock_logged| Step { write, lock_logged };
        let three = policy(3, 0);
        let rows = [
            (
                "under a threshold, at once",
                state(three, row(0, None, None)),
                step(Write::Now, false),
            ),
            (
                "the third locks, logged once",
                state(three, row(2, Some(0), None)),
                step(Write::Now, true),
            ),
            (
                "no threshold, queued",
                state(policy(0, 0), row(7, Some(0), None)),
                step(Write::Later, false),
            ),
            (
                "locked: not counted",
                state(three, row(3, Some(0), None)),
                Step::default(),
            ),
        ];
        for (label, before, expected) in rows {
            lockout.seed(&user, before.row);
            assert_eq!(lockout.failure(&before, at(1)), expected, "{label}");
        }
        lockout.seed(&user, row(0, None, None));
        let clean = state(three, row(0, None, None));
        assert_eq!(
            lockout.success(&clean, at(3)),
            Step::default(),
            "a count of 0 writes nothing"
        );
        assert_eq!(
            lockout.split(&user, 9, false),
            step(Write::Now, false),
            "a verified finish whose start another server holds writes that start's id at once"
        );
        lockout.seed(&user, row(2, Some(0), None));
        let counted = state(three, row(2, Some(0), None));
        assert_eq!(lockout.success(&counted, at(3)), step(Write::Now, false));
        lockout.forget(&user);
        assert_eq!(
            (
                lockout.failure(&counted, at(4)),
                lockout.row(&user),
                lockout.pending(&user)
            ),
            (Step::default(), None, false),
            "a failure in flight for a user forgotten meanwhile creates nothing"
        );
    }

    #[test]
    fn test_every_change_is_made_on_the_current_row_not_on_the_one_a_door_read() {
        let lockout = Lockout::default();
        let user = bob();
        lockout.seed(&user, LockRow::default());
        let read_before_the_work = state(policy(9, 0), LockRow::default());
        for i in 0..5 {
            let _ = lockout.failure(&read_before_the_work, at(i));
        }
        assert_eq!(
            lockout.row(&user).map(|row| row.fail_count),
            Some(5),
            "five attempts that each read 0 count five"
        );
        let unlocked = row(0, Some(4), Some(9));
        lockout.unlocked(&user, at(9));
        let _ = lockout.failure(&read_before_the_work, at(10));
        assert_eq!(
            lockout
                .row(&user)
                .map(|row| (row.fail_count, row.last_admin_unlock)),
            Some((1, unlocked.last_admin_unlock)),
            "a failure after an unlock counts from the unlock"
        );
    }

    #[test]
    fn test_a_burst_of_starts_locks_at_once_and_a_finish_removes_only_its_own_start_once() {
        let lockout = Lockout::default();
        let user = bob();
        let three = policy(3, 0);
        let stored = row(1, Some(0), None);
        lockout.seed(&user, stored);
        let judged = || state(three, lockout.effective(&user).unwrap());
        assert!(lockout.start(&judged(), 1, at(5)));
        assert!(lockout.start(&judged(), 2, at(6)));
        assert!(
            judged().locked(at(7)),
            "the row's 1 and two starts lock at once"
        );
        assert!(
            !lockout.start(&judged(), 3, at(7)),
            "a start while locked is not counted"
        );
        assert_eq!(
            (lockout.overlays(&user), lockout.row(&user)),
            (2, Some(stored)),
            "a start is never part of the row"
        );
        assert!(
            lockout.finish(&user, 2),
            "a verified finish removes its own"
        );
        assert!(
            !lockout.finish(&user, 2),
            "once: the same finish sent again finds none and changes nothing"
        );
        assert_eq!(lockout.row(&user), Some(stored), "no decrement, ever");
        assert!(!judged().locked(at(8)));
        let step = lockout.success(&judged(), at(8));
        assert_eq!(
            (step.write, lockout.row(&user).unwrap().fail_count),
            (Write::Now, 0),
            "the sign-in clears the count as every success does"
        );
        assert_eq!(
            lockout.overlays(&user),
            0,
            "a completed sign-in drops the starts made before it"
        );
    }

    #[tokio::test]
    async fn test_a_completed_sign_in_drops_the_starts_made_before_it_and_nothing_else_does() {
        let three = policy(3, 0);
        for (label, signed_in, count) in [
            ("a sign-in that completes", true, 0),
            ("a finish that stops at code required", false, 2),
        ] {
            let lockout = Lockout::default();
            let store = Memory::default();
            let user = bob();
            lockout.seed(&user, LockRow::default());
            let judged = || state(three, lockout.effective(&user).unwrap());
            for (id, seconds) in [(1, 5), (2, 6), (3, 7)] {
                assert!(
                    lockout.start(&judged(), id, at(seconds)),
                    "{label}: start {id}"
                );
            }
            assert!(lockout.finish(&user, 3), "{label}: its own start");
            if signed_in {
                let _ = lockout.success(&judged(), at(8));
            }
            assert!(lockout.start(&judged(), 4, at(9)), "{label}");
            assert_eq!(
                lockout.overlays(&user),
                if signed_in { 1 } else { 3 },
                "{label}: a start made after the sign-in stays"
            );
            assert!(lockout.finish(&user, 4));
            expire(&lockout, &user);
            lockout.drain(&store).await;
            assert_eq!(
                (
                    lockout.row(&user).unwrap().fail_count,
                    lockout.overlays(&user)
                ),
                (count, 0),
                "{label}: what is left once the starts expire"
            );
        }
    }

    type Meanwhile = Box<dyn FnOnce() + Send>;

    #[derive(Default)]
    struct Memory {
        rows: Mutex<HashMap<UserId, LockRow>>,
        splits: Mutex<HashMap<UserId, SplitMark>>,
        users: Mutex<Option<HashSet<UserId>>>,
        unreadable: Mutex<HashSet<UserId>>,
        calls: Mutex<Vec<String>>,
        fails: AtomicBool,
        delay: Mutex<Duration>,
        period: Mutex<String>,
        meanwhile: Mutex<Option<Meanwhile>>,
        uuids: Mutex<HashMap<UserId, Uuid>>,
        read_delay: Mutex<Duration>,
    }

    impl Memory {
        fn calls(&self) -> Vec<String> {
            std::mem::take(&mut *self.calls.lock().unwrap())
        }

        fn stored(&self, user: &UserId) -> Option<LockRow> {
            self.rows.lock().unwrap().get(user).copied()
        }

        fn count(&self, user: &UserId) -> Option<u32> {
            self.stored(user).map(|row| row.fail_count)
        }

        fn put(&self, user: &UserId, row: LockRow) {
            self.rows.lock().unwrap().insert(user.clone(), row);
        }

        fn current_period(&self) -> String {
            let period = self.period.lock().unwrap().clone();
            if period.is_empty() {
                "0".to_owned()
            } else {
                period
            }
        }
    }

    #[async_trait]
    impl LockStore for Memory {
        async fn read_lock(&self, user: &UserId) -> Result<Option<LockRow>> {
            self.calls.lock().unwrap().push(format!("read {user}"));
            let delay = *self.read_delay.lock().unwrap();
            tokio::time::sleep(delay).await;
            Ok(self.stored(user))
        }

        async fn read_locks(&self, since: Option<NaiveDateTime>) -> Result<Vec<StoredLock>> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("read since {since:?}"));
            let rows: Vec<StoredLock> = {
                let rows = self.rows.lock().unwrap();
                let uuids = self.uuids.lock().unwrap();
                rows.iter()
                    .map(|(user, row)| (user.clone(), uuids.get(user).cloned(), *row))
                    .collect()
            };
            if let Some(meanwhile) = self.meanwhile.lock().unwrap().take() {
                meanwhile();
            }
            Ok(rows)
        }

        async fn read_lock_users(&self) -> Result<Vec<UserId>> {
            Ok(self.rows.lock().unwrap().keys().cloned().collect())
        }

        async fn read_split(&self, user: &UserId) -> Result<Option<SplitMark>> {
            if self.unreadable.lock().unwrap().contains(user) {
                return Err(DomainError::InternalError("unreadable".to_owned()));
            }
            Ok(self.splits.lock().unwrap().get(user).copied())
        }

        async fn read_period(&self) -> Result<String> {
            Ok(self.current_period())
        }

        async fn write_locks(&self, period: &str, writes: &[LockWrite]) -> Result<Written> {
            let delay = *self.delay.lock().unwrap();
            tokio::time::sleep(delay).await;
            self.calls
                .lock()
                .unwrap()
                .push(format!("write {}", writes.len()));
            if self.fails.load(Ordering::Relaxed) {
                let down = DomainError::InternalError("down".to_owned());
                return Err(down);
            }
            let now = self.current_period();
            let users = self.users.lock().unwrap().clone();
            let mut stored = self.rows.lock().unwrap();
            let mut splits = self.splits.lock().unwrap();
            let mut written = Written {
                period: now.clone(),
                ..Written::default()
            };
            for write in writes {
                let user = &write.user;
                if users.as_ref().is_some_and(|users| !users.contains(user)) {
                    written.kept.push((user.clone(), None));
                    continue;
                }
                if period != now {
                    written.kept.push((user.clone(), stored.get(user).copied()));
                    written.split_kept.push(user.clone());
                    continue;
                }
                if let Some(mark) = write.split {
                    splits.insert(user.clone(), mark);
                }
                let Some(row) = write.row else {
                    continue;
                };
                let unlock = stored.get(user).and_then(|stored| stored.last_admin_unlock);
                if after(unlock, row.last_admin_unlock) {
                    written.kept.push((user.clone(), stored.get(user).copied()));
                } else {
                    stored.insert(user.clone(), row);
                }
            }
            Ok(written)
        }
    }

    #[tokio::test]
    async fn test_an_expired_start_joins_the_row_unless_the_table_holds_its_id() {
        let three = policy(3, 0);
        for (label, stored, folded) in [
            ("no finish anywhere", None, true),
            ("another start's id", Some(SplitMark::of(8, true)), true),
            (
                "its own id, written by a finish elsewhere",
                Some(SplitMark::of(7, false)),
                false,
            ),
        ] {
            let lockout = Lockout::default();
            let store = Memory::default();
            let user = bob();
            let before = row(2, Some(0), None);
            store.put(&user, before);
            if let Some(mark) = stored {
                store.splits.lock().unwrap().insert(user.clone(), mark);
            }
            lockout.seed(&user, before);
            assert!(lockout.start(&state(three, before), 7, at(10)));
            expire(&lockout, &user);
            assert_eq!(lockout.drain(&store).await, 1, "{label}");
            let after = lockout.row(&user).unwrap();
            assert_eq!(
                (
                    after.fail_count,
                    lockout.overlays(&user),
                    lockout.pending(&user)
                ),
                (if folded { 3 } else { 2 }, 0, false),
                "{label}"
            );
            if folded {
                assert_eq!(
                    (
                        after.last_failed,
                        after.lock_logged.is_some(),
                        store.count(&user)
                    ),
                    (Some(at(10)), true, Some(3)),
                    "{label}: +1 at the start's own time, written, and the stored row's lock logged"
                );
            }
        }
    }

    #[tokio::test]
    async fn test_a_completed_sign_in_elsewhere_drops_the_starts_held_here_before_its_own() {
        let none = policy(0, 0);
        for (label, mark, count) in [
            (
                "the second start's sign-in completed",
                SplitMark::of(2, true),
                0,
            ),
            ("it stopped at code required", SplitMark::of(2, false), 1),
        ] {
            let lockout = Lockout::default();
            let store = Memory::default();
            let user = bob();
            lockout.seed(&user, LockRow::default());
            for (id, seconds) in [(4, 1), (2, 3)] {
                assert!(lockout.start(&state(none, LockRow::default()), id, at(seconds)));
            }
            store.splits.lock().unwrap().insert(user.clone(), mark);
            expire(&lockout, &user);
            lockout.drain(&store).await;
            assert_eq!(
                (
                    lockout.row(&user).map(|row| row.fail_count),
                    lockout.overlays(&user)
                ),
                (Some(count), 0),
                "{label}: the earlier start drops only by a completed later one; the later one by \
                 its own id"
            );
        }
        let (bits, back) = (SplitMark::of(7, true).bits(), SplitMark::from_bits(7));
        assert_eq!(
            (bits, back, SplitMark::of(6, false).names(&overlay(7, 0))),
            (7, SplitMark::of(6, true), true),
            "the flag rides in the lowest bit; ids compare without it"
        );
    }

    #[tokio::test]
    async fn test_a_finish_elsewhere_writes_its_start_id_and_one_unreadable_user_holds_no_one_up() {
        let lockout = Lockout::default();
        let store = Memory::default();
        let (bob, ann) = (bob(), UserId::new("ann"));
        lockout.seed(&bob, LockRow::default());
        let step = lockout.split(&bob, 41, true);
        lockout.carry(&store, &bob, step).await;
        assert_eq!(
            (
                store.splits.lock().unwrap().get(&bob).copied(),
                lockout.pending(&bob)
            ),
            (Some(SplitMark::of(41, true)), false),
            "the id is in the table, and nothing more is owed"
        );
        let three = policy(3, 0);
        for user in [&bob, &ann] {
            lockout.seed(user, LockRow::default());
            assert!(lockout.start(&state_of(user, three, LockRow::default()), 1, at(10)));
            expire(&lockout, user);
        }
        store.unreadable.lock().unwrap().insert(ann.clone());
        lockout.drain(&store).await;
        assert_eq!(
            (
                store.count(&bob),
                lockout.overlays(&ann),
                lockout.pending(&ann)
            ),
            (Some(1), 1, true),
            "bob's start folded and written; ann's waits for a read that works"
        );
    }

    #[tokio::test]
    async fn test_a_change_made_while_a_write_is_in_flight_is_neither_lost_nor_read_over() {
        let lockout: &'static Lockout = Box::leak(Box::default());
        let store = Arc::new(Memory::default());
        *store.delay.lock().unwrap() = Duration::from_millis(200);
        let user = bob();
        let three = policy(3, 0);
        lockout.seed(&user, LockRow::default());
        let read_before = state(three, LockRow::default());
        let _ = lockout.failure(&read_before, at(1));
        let writing = {
            let (store, user) = (store.clone(), user.clone());
            tokio::spawn(async move { lockout.flush(&*store, &[user]).await })
        };
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            !lockout.book().needs_read(&user),
            "no door reads the table over a write in flight"
        );
        let _ = lockout.failure(&read_before, at(2));
        writing.await.unwrap();
        assert_eq!(
            (store.count(&user), lockout.pending(&user)),
            (Some(1), true),
            "the newer row is still owed after the older write"
        );
        lockout.drain(&*store).await;
        assert_eq!(
            (store.count(&user), lockout.row(&user).unwrap().fail_count),
            (Some(2), 2)
        );
    }

    #[tokio::test]
    async fn test_an_entry_is_the_account_it_was_made_for_and_counts_only_for_it() {
        let lockout = Lockout::default();
        let store = Memory::default();
        let (user, five) = (bob(), policy(5, 0));
        let (old, new) = (account(1), account(2));
        store.put(&user, row(4, Some(1), None));
        store
            .uuids
            .lock()
            .unwrap()
            .insert(user.clone(), old.clone());
        lockout.reread(&store, true).await.unwrap();
        let read = lockout.lock_state(&user, five);
        assert_eq!(
            (read.uuid.clone(), read.row.fail_count),
            (Some(old.clone()), 4),
            "the refresh reads the row's account with it"
        );
        lockout.book().ensure(&user, Some(&new));
        let counted = (
            lockout.failure(&read, at(2)),
            lockout.start(&read, 7, at(2)),
            lockout.success(&read, at(2)),
            lockout.row(&user).map(|row| row.fail_count),
        );
        assert_eq!(
            counted,
            (Step::default(), false, Step::default(), Some(0)),
            "the name made again starts at 0, and a door that read the old account counts nothing"
        );
        let ann = UserId::new("ann");
        lockout.seed(&ann, row(2, Some(1), None));
        lockout.book().ensure(&ann, Some(&old));
        let made = lockout.lock_state(&ann, five);
        assert_eq!(
            (made.uuid.clone(), made.row.fail_count),
            (Some(old.clone()), 0),
            "an entry with no account known goes at the first account a door knows"
        );
        let _ = lockout.failure(&made, at(3));
        lockout.book().ensure(&ann, Some(&old));
        assert_eq!(
            lockout.row(&ann).map(|row| row.fail_count),
            Some(1),
            "an entry a door made under that account stays"
        );
    }

    #[test]
    fn test_no_start_is_accepted_on_an_entry_gone_since_the_door_read_it() {
        let lockout = Lockout::default();
        let user = bob();
        lockout.seed(&user, LockRow::default());
        let read = lockout.lock_state(&user, policy(3, 0));
        lockout.forget(&user);
        assert_eq!(
            (lockout.start(&read, 7, at(1)), lockout.overlays(&user)),
            (false, 0),
            "refused, not accepted and counted nowhere"
        );
    }

    #[tokio::test]
    async fn test_a_start_folded_at_eviction_is_never_overwritten_by_a_refresh() {
        let lockout = Lockout::default();
        let store = Memory::default();
        let none = policy(0, 0);
        let users: Vec<UserId> = (0..=QUEUE_LIMIT)
            .map(|n| UserId::new(&format!("u{n}")))
            .collect();
        let first = &users[0];
        store.put(first, row(1, Some(0), None));
        lockout.seed(first, row(1, Some(0), None));
        for id in 1..=3 {
            assert!(lockout.start(&state_of(first, none, row(1, Some(0), None)), id, at(1)));
        }
        for user in &users[1..] {
            lockout.seed(user, LockRow::default());
            let _ = lockout.failure(&state_of(user, none, LockRow::default()), at(1));
        }
        let folded = lockout.row(first).map(|row| row.fail_count);
        assert_eq!(
            (lockout.pending(first), folded),
            (false, Some(4)),
            "evicted, its three starts folded into its row"
        );
        lockout.refresh(&store).await.unwrap();
        assert_eq!(
            lockout.row(first).map(|row| row.fail_count),
            Some(4),
            "a refresh that reads the older row leaves the fold alone"
        );
    }

    #[tokio::test]
    async fn test_a_newer_unlock_keeps_only_the_failures_here_after_it() {
        let five = policy(5, 0);
        for (label, first, meanwhile, count) in [
            (
                "two wrong tries after the unlock, one write in flight",
                11,
                Some(12),
                2,
            ),
            ("one after it, its write kept", 11, None, 1),
            ("one before it, written after it", 9, None, 0),
        ] {
            let lockout = Lockout::default();
            let store = Memory::default();
            let user = bob();
            lockout.seed(&user, row(2, Some(1), None));
            store.put(&user, row(2, Some(1), None).unlocked(at(10)));
            let _ = lockout.failure(&state(five, LockRow::default()), at(first));
            *store.delay.lock().unwrap() = Duration::from_millis(50);
            let late = async {
                tokio::time::sleep(Duration::from_millis(10)).await;
                if let Some(seconds) = meanwhile {
                    let _ = lockout.failure(&state(five, LockRow::default()), at(seconds));
                }
            };
            tokio::join!(lockout.drain(&store), late);
            *store.delay.lock().unwrap() = Duration::ZERO;
            expire(&lockout, &user);
            lockout.drain(&store).await;
            assert_eq!(
                (
                    lockout.row(&user).map(|row| row.fail_count),
                    store.count(&user)
                ),
                (Some(count), Some(count)),
                "{label}"
            );
        }
    }

    #[tokio::test]
    async fn test_a_failure_the_table_took_is_never_counted_again() {
        let five = policy(5, 0);
        for (label, kept, count) in [
            ("its write retried after an error, then taken", false, 0),
            ("its write kept twice", true, 1),
        ] {
            let lockout = Lockout::default();
            let store = Memory::default();
            let user = bob();
            lockout.seed(&user, row(2, Some(1), None));
            store.put(&user, row(2, Some(1), None));
            if kept {
                store.put(&user, row(2, Some(1), None).unlocked(at(25)));
            }
            store.fails.store(!kept, Ordering::Relaxed);
            let _ = lockout.failure(&state(five, LockRow::default()), at(30));
            lockout.drain(&store).await;
            store.fails.store(false, Ordering::Relaxed);
            let second = match kept {
                true => row(0, Some(1), None).unlocked(at(28)),
                false => {
                    expire(&lockout, &user);
                    lockout.drain(&store).await;
                    row(3, Some(30), None).unlocked(at(20))
                }
            };
            store.put(&user, second);
            if !kept {
                lockout.confirm_with(&store, &user).await.unwrap();
            }
            for _ in 0..2 {
                expire(&lockout, &user);
                lockout.drain(&store).await;
            }
            assert_eq!(
                (
                    lockout.row(&user).map(|row| row.fail_count),
                    store.count(&user)
                ),
                (Some(count), Some(count)),
                "{label}"
            );
        }
    }

    #[tokio::test]
    async fn test_the_unwritten_failures_keep_the_newest_hundred_and_the_count_still_rises() {
        let lockout = Lockout::default();
        let store = Memory::default();
        let user = bob();
        let none = policy(0, 0);
        lockout.seed(&user, LockRow::default());
        for seconds in 1..=105 {
            let _ = lockout.failure(&state(none, LockRow::default()), at(seconds));
        }
        let before = lockout.row(&user).map(|row| row.fail_count);
        store.put(&user, LockRow::default().unlocked(at(0)));
        lockout.confirm_with(&store, &user).await.unwrap();
        assert_eq!(
            (before, lockout.row(&user).map(|row| row.fail_count)),
            (Some(105), Some(100)),
            "the five oldest times are forgotten and taken as earlier than the unlock"
        );
    }

    #[tokio::test]
    async fn test_a_confirm_that_leaves_the_entry_owing_its_row_queues_the_write() {
        let lockout = Lockout::default();
        let store = Memory::default();
        let user = bob();
        let succeeded = |seconds| LockRow {
            last_success: Some(at(seconds)),
            ..LockRow::default()
        };
        lockout.seed(&user, succeeded(5));
        store.put(&user, succeeded(3).unlocked(at(6)));
        assert!(lockout.confirm_with(&store, &user).await.unwrap());
        let queued = lockout.pending(&user);
        lockout.drain(&store).await;
        assert_eq!(
            (queued, store.stored(&user).and_then(|row| row.last_success)),
            (true, Some(at(5))),
            "the unlock is taken, and the row it leaves owed is written"
        );
    }

    #[tokio::test]
    async fn test_a_confirm_dropped_with_its_request_leaves_none_in_flight() {
        let lockout = Lockout::default();
        let store = Arc::new(Memory::default());
        let user = bob();
        lockout.seed(&user, row(3, Some(0), None));
        *store.read_delay.lock().unwrap() = Duration::from_secs(5);
        lockout.serve_kdc(store.clone(), tokio::runtime::Handle::current());
        let confirm = lockout.confirm(&user);
        let dropped = tokio::time::timeout(Duration::from_millis(20), confirm).await;
        let in_flight = lockout.book().entries[&user].confirming;
        assert_eq!(
            (dropped.is_err(), in_flight),
            (true, false),
            "the request went, and its read with it"
        );
    }

    #[test]
    fn test_the_queue_keeps_one_entry_per_user_and_lets_the_oldest_go_when_full() {
        let lockout = Lockout::default();
        let none = policy(0, 0);
        let users: Vec<UserId> = (0..QUEUE_LIMIT + 3)
            .map(|n| UserId::new(&format!("u{n}")))
            .collect();
        for user in &users {
            lockout.seed(user, LockRow::default());
            if user == &users[0] {
                assert!(lockout.start(&state_of(user, none, LockRow::default()), 1, at(1)));
            }
            let _ = lockout.failure(&state_of(user, none, LockRow::default()), at(1));
            let _ = lockout.failure(&state_of(user, none, LockRow::default()), at(2));
        }
        assert_eq!((lockout.owed(), lockout.dropped()), (QUEUE_LIMIT, 3));
        assert!(
            !lockout.pending(&users[0])
                && !lockout.pending(&users[2])
                && lockout.pending(&users[3]),
            "the oldest owed rows go first"
        );
        assert_eq!(
            (
                lockout.row(&users[0]).map(|row| row.fail_count),
                lockout.overlays(&users[0])
            ),
            (Some(3), 0),
            "a row left to memory still counts here, its live start folded in, never dropped"
        );
    }

    #[tokio::test]
    async fn test_a_write_carries_the_row_as_it_stands_and_a_later_unlock_is_kept() {
        let lockout = Lockout::default();
        let store = Memory::default();
        let user = bob();
        let three = policy(3, 0);
        lockout.seed(&user, LockRow::default());
        let step = lockout.failure(&state(three, LockRow::default()), at(1));
        lockout.carry(&store, &user, step).await;
        let step = lockout.failure(&state(three, LockRow::default()), at(2));
        lockout.carry(&store, &user, step).await;
        assert_eq!(
            (
                store.count(&user),
                store.calls().len(),
                lockout.pending(&user)
            ),
            (Some(2), 2, false),
            "each write stores the row as it stands, never one more"
        );
        let unlocked = row(0, Some(2), Some(9));
        store.put(&user, unlocked);
        let step = lockout.failure(&state(three, LockRow::default()), at(3));
        lockout.carry(&store, &user, step).await;
        assert_eq!(
            (store.stored(&user), lockout.row(&user)),
            (Some(unlocked), Some(unlocked)),
            "an unlock stored by another writer is kept, and taken into the view"
        );
    }

    #[tokio::test]
    async fn test_a_row_the_table_cannot_take_is_forgotten_and_never_holds_up_the_others() {
        let lockout = Lockout::default();
        let store = Memory::default();
        let (bob, ann) = (bob(), UserId::new("ann"));
        *store.users.lock().unwrap() = Some(HashSet::from([ann.clone()]));
        let none = policy(0, 0);
        for user in [&bob, &ann] {
            lockout.seed(user, LockRow::default());
            let _ = lockout.failure(&state_of(user, none, LockRow::default()), at(1));
        }
        assert_eq!(lockout.drain(&store).await, 2);
        assert_eq!(
            (
                store.count(&ann),
                store.count(&bob),
                lockout.row(&bob),
                lockout.pending(&bob),
                lockout.outage()
            ),
            (Some(1), None, None, false, None),
            "a user who is gone: no row, nothing owed, no outage; the other one stored"
        );
        assert_eq!(lockout.drain(&store).await, 0, "and it is not retried");
    }

    #[tokio::test]
    async fn test_a_failed_write_is_retried_until_the_table_takes_it_with_one_line_per_outage() {
        let lockout = Lockout::default();
        let store = Memory::default();
        let user = bob();
        store.fails.store(true, Ordering::Relaxed);
        let three = policy(3, 0);
        lockout.seed(&user, LockRow::default());
        let step = lockout.failure(&state(three, LockRow::default()), at(1));
        lockout.carry(&store, &user, step).await;
        let down = lockout.outage();
        assert!(down.is_some() && lockout.pending(&user), "kept and owed");
        tokio::time::sleep(RETRY_AFTER).await;
        assert_eq!(lockout.drain(&store).await, 1);
        assert_eq!((lockout.outage(), lockout.pending(&user)), (down, true));
        store.fails.store(false, Ordering::Relaxed);
        tokio::time::sleep(RETRY_AFTER).await;
        assert_eq!(lockout.drain(&store).await, 1);
        assert_eq!(
            (store.count(&user), lockout.outage(), lockout.pending(&user)),
            (Some(1), None, false)
        );
    }

    #[tokio::test]
    async fn test_a_write_from_an_older_period_stores_nothing_and_the_period_is_read_again() {
        let lockout = Lockout::default();
        let store = Memory::default();
        let user = bob();
        store.put(&user, row(0, Some(0), None));
        *store.period.lock().unwrap() = "1".to_owned();
        lockout.seed(&user, row(6, Some(0), None));
        let step = lockout.failure(&state(policy(9, 0), row(6, Some(0), None)), at(1));
        lockout.carry(&store, &user, step).await;
        assert_eq!(
            (
                store.count(&user),
                lockout.row(&user),
                lockout.stale.load(Ordering::Acquire)
            ),
            (Some(0), Some(row(0, Some(0), None)), true),
            "the old count is not written back: the table's row is taken and the follow is due"
        );
    }

    #[tokio::test]
    async fn test_the_view_takes_other_writers_rows_and_drops_the_ones_the_table_lost() {
        let lockout = Lockout::default();
        let store = Memory::default();
        let (bob, ann, gone, kept) = (
            bob(),
            UserId::new("ann"),
            UserId::new("gone"),
            UserId::new("kept"),
        );
        store.put(&bob, row(2, Some(0), None));
        store.put(&ann, row(1, Some(0), None));
        lockout.seed(&gone, row(4, Some(0), None));
        lockout.seed(&kept, row(4, Some(0), None));
        lockout.seed(&ann, LockRow::default());
        let none = policy(0, 0);
        let _ = lockout.failure(&state_of(&ann, none, LockRow::default()), at(1));
        let _ = lockout.failure(&state_of(&kept, none, LockRow::default()), at(1));
        assert_eq!(lockout.refresh(&store).await.unwrap(), 1);
        assert_eq!(
            (
                lockout.row(&bob),
                lockout.row(&ann).map(|row| row.fail_count),
                lockout.row(&gone).map(|row| row.fail_count),
                lockout.row(&kept).map(|row| row.fail_count)
            ),
            (Some(row(2, Some(0), None)), Some(1), Some(4), Some(5)),
            "another writer's row is taken; an owed one is not read over; a row touched within \
             the last refresh stays"
        );
        lockout.refresh(&store).await.unwrap();
        assert_eq!(
            (
                lockout.row(&gone),
                lockout.row(&kept).map(|row| row.fail_count)
            ),
            (None, Some(5)),
            "untouched for a whole refresh, with no stored row and nothing owed: dropped"
        );
        let calls = store.calls();
        assert!(
            calls[0] == "read since None" && calls[1].starts_with("read since Some"),
            "{calls:?}"
        );
    }

    #[tokio::test]
    async fn test_a_refresh_never_puts_back_what_changed_or_was_forgotten_during_its_read() {
        let lockout: &'static Lockout = Box::leak(Box::default());
        let store = Memory::default();
        let (bob, gone, fresh) = (bob(), UserId::new("gone"), UserId::new("fresh"));
        store.put(&bob, row(2, Some(0), None));
        store.put(&gone, row(4, Some(0), None));
        lockout.seed(&bob, row(2, Some(0), None));
        lockout.seed(&gone, row(4, Some(0), None));
        let meanwhile = {
            let (bob, gone) = (bob.clone(), gone.clone());
            move || {
                lockout.unlocked(&bob, at(9));
                lockout.forget(&gone);
            }
        };
        *store.meanwhile.lock().unwrap() = Some(Box::new(meanwhile));
        lockout.refresh(&store).await.unwrap();
        assert_eq!(
            (
                lockout.row(&bob).map(|row| row.fail_count),
                lockout.row(&gone)
            ),
            (Some(0), None),
            "an unlock made during the read is not undone, a forgotten user does not come back"
        );
        lockout.seed(&fresh, LockRow::default());
        lockout.refresh(&store).await.unwrap();
        let counted = lockout.failure(&state_of(&fresh, policy(0, 0), LockRow::default()), at(10));
        assert_eq!(
            (counted.write, lockout.row(&fresh).map(|row| row.fail_count)),
            (Write::Later, Some(1)),
            "a door that read before a refresh, for a user with no stored row, still counts"
        );
    }

    #[test]
    fn test_live_starts_are_capped_and_the_ones_beyond_count_at_once() {
        let lockout = Lockout::default();
        let user = bob();
        lockout.seed(&user, LockRow::default());
        let none = policy(0, 0);
        for id in 0..40 {
            let judged = state(none, lockout.effective(&user).unwrap());
            assert!(lockout.start(&judged, id, at(1)));
        }
        assert_eq!(
            (
                lockout.overlays(&user),
                lockout.row(&user).map(|row| row.fail_count)
            ),
            (OVERLAY_CAP, Some(40 - OVERLAY_CAP as u32)),
            "past the cap a start is counted in the row, beyond any finish"
        );
    }

    #[tokio::test]
    async fn test_a_lock_is_confirmed_against_the_table_at_most_once_a_second() {
        let lockout = Lockout::default();
        let store = Arc::new(Memory::default());
        let user = bob();
        lockout.seed(&user, row(3, Some(0), None));
        store.put(&user, row(0, Some(0), Some(5)));
        lockout.serve_kdc(store.clone(), tokio::runtime::Handle::current());
        assert!(
            lockout.confirm(&user).await,
            "a newer unlock in the table is taken over"
        );
        let after = lockout.row(&user).unwrap();
        assert!(!after.locked(policy(3, 0), at(6)));
        lockout.seed(&user, row(3, Some(6), Some(5)));
        store.calls();
        assert!(!lockout.confirm(&user).await, "within the second: no read");
        assert_eq!(store.calls(), Vec::<String>::new());
    }

    #[tokio::test]
    async fn test_a_clean_stop_writes_what_is_owed_once_and_every_start_still_held() {
        let lockout = Lockout::default();
        let store = Arc::new(Memory::default());
        let (bob, ann) = (bob(), UserId::new("ann"));
        lockout.seed(&bob, LockRow::default());
        lockout.seed(&ann, LockRow::default());
        let _ = lockout.failure(&state_of(&bob, policy(0, 0), LockRow::default()), at(1));
        assert!(lockout.start(&state_of(&ann, policy(3, 0), LockRow::default()), 1, at(2)));
        lockout.serve_kdc(store.clone(), tokio::runtime::Handle::current());
        let started = Instant::now();
        lockout.stop().await;
        assert!(started.elapsed() <= STOP_BOUND);
        assert_eq!(
            (
                store.count(&bob),
                store.count(&ann),
                lockout.owed(),
                lockout.kdc_counts()
            ),
            (Some(1), Some(1), 0, false)
        );
    }

    #[test]
    fn test_the_kdc_thread_waits_at_most_the_bound_and_marks_a_queued_count_itself() {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        let lockout: &'static Lockout = Box::leak(Box::default());
        let store = Arc::new(Memory::default());
        *store.delay.lock().unwrap() = Duration::from_millis(600);
        let user = bob();
        let three = policy(3, 0);
        lockout.seed(&user, LockRow::default());
        let started = Instant::now();
        let queued = lockout.failure(&state(policy(0, 0), LockRow::default()), at(1));
        lockout.carry_from_kdc(&user, queued);
        assert!(
            started.elapsed() < Duration::from_millis(50) && lockout.pending(&user),
            "a queued count is marked inline, with no task to wait for"
        );
        lockout.serve_kdc(store.clone(), runtime.handle().clone());
        let counted = state(three, LockRow::default());
        let started = Instant::now();
        let asked = user.clone();
        std::thread::spawn(move || {
            lockout.carry_from_kdc(&asked, lockout.failure(&counted, at(2)))
        })
        .join()
        .unwrap();
        let waited = started.elapsed();
        assert!(waited < Duration::from_millis(300), "{waited:?}");
        std::thread::sleep(Duration::from_millis(500));
        runtime.block_on(lockout.drain(&*store));
        assert_eq!(
            store.count(&user),
            Some(2),
            "the count is right once the write lands"
        );
    }
}
