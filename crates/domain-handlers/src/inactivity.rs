use crate::enforcement::{
    Attempt, Entries, FILL_CHUNK, INACTIVITY_DAYS, ItemCheck, POLICY_UNANSWERED, PolicyCache,
    Snapshot, UserFacts, UserState, bounded, item_set,
};
use crate::handler::PolicyBackendHandler;
use crate::instant::{self, SignedDuration, Timestamp};
use crate::lockout::{LockStore, QUEUE_LIMIT, STOP_BOUND, WRITE_BOUND};
use crate::policies::{EffectiveItem, POLICY_READ_WAIT, Policy};
use lldap_domain::types::UserId;
use lldap_domain_model::error::Result;
use std::collections::{BTreeSet, HashMap};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, RwLock};
use std::time::Duration;
use tracing::warn;

pub const INACTIVE: &str = "inactive";
pub const REENABLED_BY_ADMIN: &str = "reenableUser";
pub const REENABLED_BY_TOOL: &str = "lldap reenable";
/// The `system_config` row: when the item last went live, or `off`.
pub const RECORDING_KEY: &str = "inactivity_recording_since";
pub const RECORDING_OFF: &str = "off";
pub const WRITE_EVERY_SECS: i64 = 3600;

/// A user's row: no success and no re-enable for a user it does not hold.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Recorded {
    pub last_success: Option<Timestamp>,
    pub reenabled_at: Option<Timestamp>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Recording {
    #[default]
    Unknown,
    Off,
    Since(Timestamp),
}

/// The latest of the four starting points; `None` while one of them is not read.
pub fn active_since(
    created: Timestamp,
    recorded: Option<Recorded>,
    recording: Recording,
) -> Option<Timestamp> {
    let (Recording::Since(since), Some(recorded)) = (recording, recorded) else {
        return None;
    };
    let points = [recorded.last_success, recorded.reenabled_at];
    Some(
        points
            .into_iter()
            .flatten()
            .fold(created.max(since), Ord::max),
    )
}

pub fn cached_active_since(cache: &PolicyCache, facts: Option<&UserFacts>) -> Option<Timestamp> {
    let facts = facts?;
    active_since(facts.created, facts.recorded, cache.recording())
}

pub fn days(value: &str) -> Option<i64> {
    value.parse::<u16>().ok().map(i64::from)
}

/// `Some(None)` while the check admits; `None` when the value or the start cannot be read.
pub fn idle_past_limit(
    value: &str,
    active_since: Option<Timestamp>,
    now: Timestamp,
) -> Option<Option<Timestamp>> {
    match (days(value)?, active_since) {
        (0, _) => Some(None),
        (days, Some(since)) => {
            let end = instant::later(since, instant::days(days));
            Some((now > end).then_some(end))
        }
        (_, None) => None,
    }
}

/// Whether these items judge a user: a value other than 0.
pub fn judged_by(items: &[EffectiveItem]) -> bool {
    let set = |item: &EffectiveItem| item.key == INACTIVITY_DAYS && days(&item.value) != Some(0);
    items.iter().any(set)
}

pub fn live(cache: &PolicyCache) -> bool {
    !cache.item_off(INACTIVITY_DAYS)
}

pub struct InactivityCheck;

impl ItemCheck for InactivityCheck {
    fn key(&self) -> &'static str {
        INACTIVITY_DAYS
    }

    fn live(&self, cache: &PolicyCache) -> bool {
        live(cache)
    }

    fn reason(&self) -> Option<&'static str> {
        Some(INACTIVE)
    }

    fn judges_at_s4u(&self) -> bool {
        true
    }

    fn readable(&self, value: &str, state: &UserState) -> bool {
        match days(value) {
            Some(0) => true,
            Some(_) => state.active_since.is_some(),
            None => false,
        }
    }

    fn allows(&self, attempt: &Attempt<'_>, value: &str, state: &UserState) -> bool {
        match (days(value), state.active_since) {
            (Some(0), _) => true,
            (Some(days), Some(since)) => attempt.now - since <= instant::days(days),
            _ => false,
        }
    }
}

#[derive(Clone)]
struct Writer {
    store: Arc<dyn LockStore>,
    runtime: tokio::runtime::Handle,
}

#[derive(Default)]
pub(crate) struct ActivityBook {
    written: Mutex<HashMap<UserId, Timestamp>>,
    owed: Mutex<HashMap<UserId, Timestamp>>,
    writer: RwLock<Option<Writer>>,
    recording: RwLock<Recording>,
    rows_failed: AtomicBool,
    warned: Mutex<BTreeSet<(String, String)>>,
}

fn held<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

impl PolicyCache {
    pub fn recording(&self) -> Recording {
        let recording = self.activity.recording.read();
        *recording.unwrap_or_else(PoisonError::into_inner)
    }

    pub fn set_recording(&self, recording: Recording) {
        *self
            .activity
            .recording
            .write()
            .unwrap_or_else(PoisonError::into_inner) = recording;
    }

    /// Both of the item's reads answered at their last try: `recording_since` and the users' rows.
    pub fn activity_read(&self) -> bool {
        let rows = !self.activity.rows_failed.load(Ordering::Acquire);
        rows && matches!(self.recording(), Recording::Since(_))
    }

    /// While the item is set and one of its reads has not answered, the follow tries it again.
    pub fn activity_due(&self) -> bool {
        live(self) && !self.activity_read()
    }

    pub fn activity_pending(&self) -> bool {
        self.item_unread(INACTIVITY_DAYS) || self.activity_due()
    }

    /// For tests only: the item's reads as before a start.
    #[cfg(any(test, feature = "test-backend-scope"))]
    pub fn reset_activity_reads(&self) {
        self.set_recording(Recording::Unknown);
        self.activity.rows_failed.store(false, Ordering::Release);
    }

    #[cfg(any(test, feature = "test-backend-scope"))]
    pub fn owed_successes(&self) -> usize {
        held(&self.activity.owed).len()
    }

    pub fn serve_successes(&self, store: Arc<dyn LockStore>, runtime: tokio::runtime::Handle) {
        let writer = Some(Writer { store, runtime });
        *self
            .activity
            .writer
            .write()
            .unwrap_or_else(PoisonError::into_inner) = writer;
    }

    fn writer(&self) -> Option<Writer> {
        let writer = self.activity.writer.read();
        writer.unwrap_or_else(PoisonError::into_inner).clone()
    }

    /// While the item is live: the first success after a start, then one an hour, per user.
    fn success_due(&self, user: &UserId, at: Timestamp) -> bool {
        if !live(self) {
            return false;
        }
        let mut written = held(&self.activity.written);
        let every = SignedDuration::from_secs(WRITE_EVERY_SECS);
        if written.get(user).is_some_and(|last| at - *last < every) {
            return false;
        }
        written.insert(user.clone(), at);
        true
    }

    /// A door's success, after the last check that can still refuse.
    pub async fn note_success<S>(&self, store: &S, user: &UserId, at: Timestamp)
    where
        S: LockStore + ?Sized,
    {
        if self.success_due(user, at) {
            self.write_success(store, user, at).await;
        }
    }

    async fn write_success<S>(&self, store: &S, user: &UserId, at: Timestamp)
    where
        S: LockStore + ?Sized,
    {
        let written = tokio::time::timeout(WRITE_BOUND, store.write_success(user, at)).await;
        if !matches!(written, Ok(Ok(()))) {
            self.owe_success(user, at);
        }
        self.hold_success(user, at);
    }

    /// On the KDC's thread: written on the server's runtime; the thread waits at most
    /// `WRITE_BOUND`, and a write that does not land is owed.
    pub fn carry_success_from_kdc(&'static self, user: &UserId, at: Timestamp) {
        if !self.success_due(user, at) {
            return;
        }
        let Some(Writer { store, runtime }) = self.writer() else {
            self.owe_success(user, at);
            self.hold_success(user, at);
            return;
        };
        let (done, wait) = std::sync::mpsc::channel();
        let user = user.clone();
        runtime.spawn(async move {
            self.write_success(&*store, &user, at).await;
            let _ = done.send(());
        });
        let _ = wait.recv_timeout(WRITE_BOUND);
    }

    fn hold_success(&self, user: &UserId, at: Timestamp) {
        let Some(_taking) = self.try_take() else {
            self.mark(user);
            return;
        };
        self.edit(user, |over| {
            if let Some(facts) = over.facts.as_mut() {
                let recorded = facts.recorded.unwrap_or_default();
                facts.recorded = Some(Recorded {
                    last_success: recorded.last_success.max(Some(at)),
                    ..recorded
                });
            }
        });
    }

    fn owe_success(&self, user: &UserId, at: Timestamp) {
        let mut owed = held(&self.activity.owed);
        if owed.len() >= QUEUE_LIMIT && !owed.contains_key(user) {
            warn!("The sign-in of {user} was not kept for inactivity-days: {QUEUE_LIMIT} are owed");
            return;
        }
        let kept = owed.entry(user.clone()).or_insert(at);
        *kept = (*kept).max(at);
    }

    /// Every owed success once more, as a clean stop writes them.
    pub async fn drain_successes<S: LockStore + ?Sized>(&self, store: &S) -> usize {
        self.drain_successes_up_to(store, usize::MAX, Duration::MAX)
            .await
    }

    /// At most `limit` owed successes within `budget`, stopping at the first write that fails.
    pub async fn drain_successes_up_to<S>(&self, store: &S, limit: usize, budget: Duration) -> usize
    where
        S: LockStore + ?Sized,
    {
        let taken: Vec<(UserId, Timestamp)> = {
            let mut owed = held(&self.activity.owed);
            let users: Vec<UserId> = owed.keys().take(limit).cloned().collect();
            let taken = users.iter().filter_map(|user| owed.remove_entry(user));
            taken.collect()
        };
        let started = tokio::time::Instant::now();
        let (mut owed, mut written) = (taken.into_iter(), 0);
        while let Some((user, at)) = owed.next() {
            let stored = if started.elapsed() < budget {
                let write = store.write_success(&user, at);
                tokio::time::timeout(WRITE_BOUND, write).await.ok()
            } else {
                None
            };
            if matches!(stored, Some(Ok(()))) {
                written += 1;
                continue;
            }
            self.owe_success(&user, at);
            for (user, at) in owed.by_ref() {
                self.owe_success(&user, at);
            }
        }
        written
    }

    pub async fn stop_successes(&self) {
        if let Some(Writer { store, .. }) = self.writer() {
            let _ = tokio::time::timeout(STOP_BOUND, self.drain_successes(&*store)).await;
        }
    }

    /// One warning for each linked policy whose value does not parse, until that value changes.
    pub fn unreadable_warnings(&self, policies: &[Policy]) -> Vec<String> {
        let linked = policies
            .iter()
            .filter(|policy| !policy.linked_ous.is_empty());
        let unread = linked.filter_map(|policy| {
            let value = policy.items.get(INACTIVITY_DAYS)?;
            days(value)
                .is_none()
                .then(|| (policy.name.clone(), value.clone()))
        });
        let now: BTreeSet<(String, String)> = unread.collect();
        let mut warned = held(&self.activity.warned);
        let new = now.difference(&warned).map(|(name, _)| {
            format!(
                "The policy \"{name}\" sets {INACTIVITY_DAYS} to a value that does not parse: \
                 the users it applies to are refused as unreadable until it is set again"
            )
        });
        let new = new.collect();
        *warned = now;
        new
    }
}

/// `recording_since` from the stored row, moved by a conditional write only when the item
/// turns: two servers agree, and a restart keeps the stored time.
pub async fn follow_recording<S: LockStore + ?Sized>(
    store: &S,
    cache: &PolicyCache,
    policies: &[Policy],
    at: Timestamp,
) -> Result<()> {
    for warning in cache.unreadable_warnings(policies) {
        warn!("{warning}");
    }
    let next = match (item_set(policies, INACTIVITY_DAYS), cache.recording()) {
        (false, Recording::Off) => return Ok(()),
        (false, _) => {
            store.write_recording(false, at).await?;
            Recording::Off
        }
        (true, _) => {
            let turning = !live(cache) || cache.item_unread(INACTIVITY_DAYS);
            let stored = match bounded(POLICY_READ_WAIT, store.read_recording()).await {
                Ok(None) => store.write_recording(true, at).await,
                read => read,
            };
            if turning && stored.is_err() {
                cache.set_recording(Recording::Unknown);
            }
            stored?.map_or(Recording::Unknown, Recording::Since)
        }
    };
    cache.set_recording(next);
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ActivityRead {
    NotAsked,
    Read,
    Failed,
}

/// Every user's row, a chunk at a time in user-id order, each chunk under its own bound.
async fn activity_rows<H>(handler: &H) -> Result<Vec<(UserId, Recorded)>>
where
    H: PolicyBackendHandler + ?Sized,
{
    let mut rows: Vec<(UserId, Recorded)> = Vec::new();
    loop {
        let after = rows.last().map(|(user, _)| user);
        let chunk = handler.read_activity_after(after, FILL_CHUNK);
        let chunk = bounded(POLICY_READ_WAIT, chunk).await?;
        let last = chunk.len() < FILL_CHUNK;
        rows.extend(chunk);
        if last {
            return Ok(rows);
        }
        tokio::task::yield_now().await;
    }
}

/// Every user's row while an OU's items set the item, in the fill before the flag.
pub(crate) async fn read_activity_rows<H>(handler: &H, entries: &mut Entries) -> ActivityRead
where
    H: PolicyBackendHandler + ?Sized,
{
    if !entries.items_of_ous.values().any(|items| judged_by(items)) {
        return ActivityRead::NotAsked;
    }
    let rows = match activity_rows(handler).await {
        Ok(rows) => rows,
        Err(e) => {
            warn!("The users' activity was not read: {e}");
            return ActivityRead::Failed;
        }
    };
    let rows: HashMap<UserId, Recorded> = rows.into_iter().collect();
    for (user, facts) in entries.facts.iter_mut() {
        facts.recorded = Some(rows.get(user).copied().unwrap_or_default());
    }
    ActivityRead::Read
}

/// At the fill's swap: a read that failed keeps what this server holds then, for the follow.
pub(crate) fn settle_activity(
    cache: &PolicyCache,
    in_use: &Snapshot,
    entries: &mut Entries,
    read: ActivityRead,
) {
    let failed = read == ActivityRead::Failed;
    cache.activity.rows_failed.store(failed, Ordering::Release);
    if !failed {
        return;
    }
    cache.note_read_failed();
    for (user, facts) in entries.facts.iter_mut() {
        facts.recorded = in_use.facts_of(user).and_then(|was| was.recorded);
    }
}

pub(crate) fn forget_writes(cache: &PolicyCache, next: &Snapshot) {
    held(&cache.activity.written).retain(|user, _| next.facts_of(user).is_some());
}

/// One user's row again, as a write asks; false when the read failed.
pub(crate) async fn read_user_activity<H>(
    handler: &H,
    user: &UserId,
    items: &[EffectiveItem],
    facts: &mut UserFacts,
) -> bool
where
    H: PolicyBackendHandler + ?Sized,
{
    if !judged_by(items) {
        return true;
    }
    let read = tokio::time::timeout(POLICY_READ_WAIT, handler.read_activity(Some(user))).await;
    match read {
        Ok(Ok(rows)) => {
            let theirs = rows.into_iter().find(|(owner, _)| owner == user);
            facts.recorded = Some(theirs.map(|(_, recorded)| recorded).unwrap_or_default());
            true
        }
        Ok(Err(e)) => {
            warn!("The activity of {user} was not read: {e}");
            false
        }
        Err(_) => {
            warn!("The activity of {user} was not read: {POLICY_UNANSWERED}");
            false
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::enforcement::{Door, ItemFlags, Refusal, UNREADABLE, decide};
    use crate::lockout::{
        BATCH_LIMIT, LockRow, LockWrite, SUCCESS_BUDGET, SplitMark, StoredLock, Written,
    };
    use crate::policies::{PolicyId, PolicyScope};
    use async_trait::async_trait;
    use lldap_domain::types::Uuid;
    use lldap_domain_model::error::DomainError;
    use pretty_assertions::assert_eq;
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

    const DAY: i64 = 86_400;

    /// The one place a row turns the item's flag.
    pub(crate) fn turn(cache: &PolicyCache, live: bool) {
        let flags = ItemFlags {
            inactivity: live,
            ..ItemFlags::default()
        };
        cache.set_item_flags(flags);
    }

    fn exact(seconds: i64, nanos: u32) -> Timestamp {
        Timestamp::new(seconds, nanos as i32).unwrap()
    }

    fn at(seconds: i64) -> Timestamp {
        exact(1_700_000_000 + seconds, 0)
    }

    fn naive(seconds: i64) -> Timestamp {
        at(seconds)
    }

    fn item(value: &str) -> EffectiveItem {
        EffectiveItem {
            key: INACTIVITY_DAYS.to_owned(),
            scope: PolicyScope::User,
            value: value.to_owned(),
            enforced: true,
            source: None,
        }
    }

    fn attempt(user: &UserId, seconds: i64) -> Attempt<'_> {
        Attempt {
            user,
            door: Door::LdapBind,
            peer: None,
            now: at(seconds),
            second_factor: false,
        }
    }

    fn state(active_since: Option<Timestamp>) -> UserState {
        UserState {
            active_since,
            ..UserState::default()
        }
    }

    fn linked(name: &str, value: &str, ous: &[&str]) -> Policy {
        Policy {
            id: PolicyId(6),
            name: name.to_owned(),
            description: String::new(),
            items: BTreeMap::from([(INACTIVITY_DAYS.to_owned(), value.to_owned())]),
            linked_ous: ous.iter().map(|ou| ou.to_string()).collect(),
        }
    }

    /// The row's `recording_since` as a conditional store keeps it: `None` is off.
    #[derive(Default)]
    struct Memory {
        successes: Mutex<Vec<(UserId, Timestamp)>>,
        down: AtomicBool,
        slow: AtomicBool,
        since: Mutex<Option<Timestamp>>,
        recording_writes: Mutex<Vec<bool>>,
        recording_reads: AtomicU64,
    }

    impl Memory {
        fn written(&self) -> Vec<(UserId, Timestamp)> {
            self.successes.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl LockStore for Memory {
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
            self.recording_reads.fetch_add(1, Ordering::Relaxed);
            Ok(*self.since.lock().unwrap())
        }
        async fn write_recording(&self, live: bool, at: Timestamp) -> Result<Option<Timestamp>> {
            self.recording_writes.lock().unwrap().push(live);
            let mut since = self.since.lock().unwrap();
            match live {
                true => *since = Some((*since).unwrap_or(at)),
                false => *since = None,
            }
            Ok(*since)
        }
        async fn write_success(&self, user: &UserId, at: Timestamp) -> Result<()> {
            if self.slow.load(Ordering::Relaxed) {
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
            if self.down.load(Ordering::Relaxed) {
                return Err(DomainError::InternalError("down".to_owned()));
            }
            self.successes.lock().unwrap().push((user.clone(), at));
            Ok(())
        }
    }

    #[test]
    fn test_the_idle_time_counts_from_the_latest_of_the_four_starting_points() {
        let recorded = |success: Option<i64>, reenabled: Option<i64>| Recorded {
            last_success: success.map(at),
            reenabled_at: reenabled.map(at),
        };
        let rows = [
            ("the creation", 40, recorded(Some(10), Some(20)), 30, 40),
            ("the last success", 10, recorded(Some(40), Some(20)), 30, 40),
            ("recording since", 10, recorded(Some(20), None), 40, 40),
            (
                "the last re-enable",
                10,
                recorded(Some(20), Some(40)),
                30,
                40,
            ),
            ("never signed in", 10, recorded(None, None), 30, 30),
        ];
        for (label, created, recorded, since, latest) in rows {
            let recording = Recording::Since(at(since));
            let got = active_since(at(created), Some(recorded), recording);
            assert_eq!(got, Some(at(latest)), "{label}");
        }
        let unknown = [
            ("the user's row not read", None, Recording::Since(at(30))),
            (
                "recording since not read",
                Some(Recorded::default()),
                Recording::Unknown,
            ),
            (
                "recording since off",
                Some(Recorded::default()),
                Recording::Off,
            ),
        ];
        for (label, recorded, recording) in unknown {
            let got = active_since(at(10), recorded, recording);
            assert_eq!(got, None, "{label}: never read as never signed in");
        }
    }

    #[test]
    fn test_the_idle_end_agrees_with_the_check_at_each_edge() {
        let bob = UserId::new("e7bob");
        let rows = [
            ("exactly the limit", "1", Some(at(0)), DAY, Some(None)),
            (
                "one second more",
                "1",
                Some(at(0)),
                DAY + 1,
                Some(Some(at(DAY))),
            ),
            ("0 never", "0", Some(at(0)), 3650 * DAY, Some(None)),
            ("0 with no start", "0", None, DAY, Some(None)),
            ("a value that does not parse", "x", Some(at(0)), DAY, None),
            ("no start", "1", None, DAY, None),
        ];
        for (label, value, since, now, expected) in rows {
            let state = state(since);
            let check = (
                InactivityCheck.readable(value, &state),
                InactivityCheck.allows(&attempt(&bob, now), value, &state),
            );
            assert_eq!(
                (idle_past_limit(value, since, at(now)), check),
                (expected, (expected.is_some(), expected == Some(None))),
                "{label}"
            );
        }
    }

    type IdleRow = (
        &'static str,
        &'static str,
        (i64, u32),
        (i64, u32),
        Option<(i64, u32)>,
    );

    #[test]
    fn test_a_day_of_the_limit_is_86400_seconds_to_the_nanosecond() {
        let bob = UserId::new("g1bob");
        let rows: [IdleRow; 6] = [
            (
                "exactly one day",
                "1",
                (1_700_000_000, 123_456_789),
                (1_700_086_400, 123_456_789),
                None,
            ),
            (
                "one day and one nanosecond",
                "1",
                (1_700_000_000, 123_456_789),
                (1_700_086_400, 123_456_790),
                Some((1_700_086_400, 123_456_789)),
            ),
            (
                "two days over 2028-02-29",
                "2",
                (1_835_352_000, 0),
                (1_835_524_800, 1),
                Some((1_835_524_800, 0)),
            ),
            (
                "a day that ends at 2038-01-19T03:14:08Z",
                "1",
                (2_147_397_248, 0),
                (2_147_483_648, 0),
                None,
            ),
            (
                "the longest limit",
                "65535",
                (1_700_000_000, 0),
                (7_362_224_000, 1),
                Some((7_362_224_000, 0)),
            ),
            (
                "a day that ends before 1970",
                "1",
                (-86_401, 500_000_000),
                (0, 0),
                Some((-1, 500_000_000)),
            ),
        ];
        for (label, value, since, now, end) in rows {
            let since = Some(exact(since.0, since.1));
            let attempt = Attempt {
                now: exact(now.0, now.1),
                ..attempt(&bob, 0)
            };
            let end = end.map(|(seconds, nanos)| exact(seconds, nanos));
            assert_eq!(
                (
                    idle_past_limit(value, since, attempt.now),
                    InactivityCheck.allows(&attempt, value, &state(since)),
                ),
                (Some(end), end.is_none()),
                "{label}"
            );
        }
    }

    #[test]
    fn test_exactly_the_limit_admits_and_one_second_more_refuses() {
        let bob = UserId::new("e6bob");
        let since = state(Some(at(0)));
        let rows = [
            ("a day before the limit", "30", 29 * DAY, true),
            ("exactly 30 days", "30", 30 * DAY, true),
            ("30 days and one second", "30", 30 * DAY + 1, false),
            ("exactly one day", "1", DAY, true),
            ("one day and one second", "1", DAY + 1, false),
            ("0 never refuses", "0", 3650 * DAY, true),
            ("00 is 0", "00", 3650 * DAY, true),
        ];
        for (label, value, now, admitted) in rows {
            let allowed = InactivityCheck.allows(&attempt(&bob, now), value, &since);
            assert_eq!(allowed, admitted, "{label}");
        }
    }

    #[test]
    fn test_an_unknown_start_or_a_value_that_does_not_parse_is_unreadable() {
        let bob = UserId::new("e6bob");
        let checks: Vec<Arc<dyn ItemCheck>> = vec![Arc::new(InactivityCheck)];
        let unreadable = Err(Refusal {
            item: UNREADABLE,
            door: Door::LdapBind,
            reason: None,
        });
        let inactive = Err(Refusal {
            item: INACTIVITY_DAYS,
            door: Door::LdapBind,
            reason: Some(INACTIVE),
        });
        let rows = [
            ("a start not read", "30", None, unreadable),
            (
                "a value that does not parse",
                "thirty",
                Some(at(0)),
                unreadable,
            ),
            ("a negative value", "-1", Some(at(0)), unreadable),
            ("0 needs no start", "0", None, Ok(())),
            ("inside the limit", "30", Some(at(0)), Ok(())),
            ("past the limit", "1", Some(at(-2 * DAY)), inactive),
        ];
        for (label, value, since, expected) in rows {
            let got = decide(&attempt(&bob, 0), &[item(value)], &state(since), &checks);
            assert_eq!(got, expected, "{label}");
        }
        let detail = inactive.map_err(|refusal| refusal.detail());
        assert_eq!(detail, Err("policy: inactivity-days (inactive)".to_owned()));
    }

    #[test]
    fn test_the_check_is_live_with_its_flag_names_inactive_and_judges_at_s4u() {
        let cache = PolicyCache::new();
        let off = (InactivityCheck.live(&cache), cache.reads());
        turn(&cache, true);
        let on = (InactivityCheck.live(&cache), cache.reads());
        assert_eq!(
            (off, on),
            ((false, 0), (true, 0)),
            "one atomic read, and no read of the entries"
        );
        assert_eq!(
            (InactivityCheck.reason(), InactivityCheck.judges_at_s4u()),
            (Some(INACTIVE), true)
        );
        let bob = UserId::new("e6bob");
        let asked = Attempt {
            door: Door::KerberosS4u,
            ..attempt(&bob, 2 * DAY)
        };
        let checks: Vec<Arc<dyn ItemCheck>> = vec![Arc::new(InactivityCheck)];
        let got = decide(&asked, &[item("1")], &state(Some(at(0))), &checks);
        let refused = Refusal {
            item: INACTIVITY_DAYS,
            door: Door::KerberosS4u,
            reason: Some(INACTIVE),
        };
        assert_eq!(got, Err(refused), "the user a service asks for is judged");
    }

    #[tokio::test]
    async fn test_the_first_success_after_a_start_writes_and_then_one_an_hour_per_user() {
        let (cache, store) = (PolicyCache::new(), Memory::default());
        turn(&cache, true);
        let (bob, ann) = (UserId::new("e6bob"), UserId::new("e6ann"));
        let rows = [
            ("bob's first after the start", &bob, 0, true),
            ("bob within the hour", &bob, 3_599, false),
            ("ann's first, inside bob's hour", &ann, 1, true),
            ("bob an hour after his write", &bob, 3_600, true),
            ("bob inside the next hour", &bob, 7_199, false),
        ];
        for (label, user, seconds, writes) in rows {
            let before = store.written().len();
            cache.note_success(&store, user, naive(seconds)).await;
            assert_eq!(store.written().len() > before, writes, "{label}");
        }
        assert_eq!(
            store.written(),
            vec![
                (bob.clone(), naive(0)),
                (ann, naive(1)),
                (bob.clone(), naive(3_600))
            ]
        );
        let restarted = PolicyCache::new();
        turn(&restarted, true);
        restarted.note_success(&store, &bob, naive(3_601)).await;
        assert_eq!(
            store.written().len(),
            4,
            "a new start's first success writes"
        );
    }

    #[tokio::test]
    async fn test_nothing_is_written_while_the_item_is_off() {
        let (cache, store) = (PolicyCache::new(), Memory::default());
        let bob = UserId::new("e6bob");
        cache.note_success(&store, &bob, naive(0)).await;
        turn(&cache, true);
        cache.note_success(&store, &bob, naive(1)).await;
        assert_eq!(
            store.written(),
            vec![(bob, naive(1))],
            "off: nothing written and nothing remembered; live: the first one writes"
        );
    }

    #[tokio::test]
    async fn test_a_success_that_does_not_land_is_owed_and_written_by_the_drain() {
        let (cache, store) = (PolicyCache::new(), Memory::default());
        turn(&cache, true);
        let bob = UserId::new("e6bob");
        store.down.store(true, Ordering::Relaxed);
        cache.note_success(&store, &bob, naive(0)).await;
        cache.note_success(&store, &bob, naive(3_600)).await;
        let owed = cache.owed_successes();
        let drained = (cache.drain_successes(&store).await, cache.owed_successes());
        assert_eq!(
            (owed, drained),
            (1, (0, 1)),
            "one owed entry per user, kept while the store fails"
        );
        store.down.store(false, Ordering::Relaxed);
        let drained = (cache.drain_successes(&store).await, cache.owed_successes());
        assert_eq!(
            (drained, store.written()),
            ((1, 0), vec![(bob, naive(3_600))]),
            "the later time lands once the store answers"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_a_drain_stops_at_its_time_budget_and_leaves_the_rest_owed() {
        let (cache, store) = (PolicyCache::new(), Memory::default());
        turn(&cache, true);
        store.down.store(true, Ordering::Relaxed);
        for n in 0..20 {
            let user = UserId::new(&format!("e6owed{n}"));
            cache.note_success(&store, &user, naive(0)).await;
        }
        store.down.store(false, Ordering::Relaxed);
        store.slow.store(true, Ordering::Relaxed);
        let mut ticks = Vec::new();
        for _ in 0..2 {
            let written = cache
                .drain_successes_up_to(&store, BATCH_LIMIT, SUCCESS_BUDGET)
                .await;
            ticks.push((written, cache.owed_successes()));
        }
        assert_eq!(
            (SUCCESS_BUDGET, ticks),
            (Duration::from_secs(2), vec![(10, 10), (10, 0)]),
            "200 ms a write: ten fit in the two seconds, the other ten wait for the next tick"
        );
    }

    #[tokio::test]
    async fn test_a_ticket_issued_with_no_writer_served_is_owed_and_held_here() {
        let cache: &'static PolicyCache = Box::leak(Box::new(PolicyCache::new()));
        let store = Memory::default();
        turn(cache, true);
        let bob = UserId::new("e6bob");
        let facts = UserFacts {
            uuid: Uuid::from_name_and_date("e6bob", &chrono::NaiveDateTime::default()),
            enrolled: false,
            exempt: false,
            created: at(-DAY),
            recorded: Some(Recorded::default()),
        };
        cache.put_facts(&bob, facts);
        cache.carry_success_from_kdc(&bob, naive(0));
        let held = cache.get().facts_of(&bob).and_then(|facts| facts.recorded);
        let owed = (
            cache.owed_successes(),
            held.and_then(|row| row.last_success),
        );
        let drained = (cache.drain_successes(&store).await, cache.owed_successes());
        assert_eq!(
            (owed, drained, store.written()),
            ((1, Some(at(0))), (1, 0), vec![(bob, naive(0))]),
            "no writer served yet: owed, and held here at once; the drain writes it"
        );
    }

    #[tokio::test]
    async fn test_a_success_written_here_reaches_the_cache_at_once() {
        let (cache, store) = (PolicyCache::new(), Memory::default());
        turn(&cache, true);
        let bob = UserId::new("e6bob");
        let reenabled = Recorded {
            reenabled_at: Some(at(-10)),
            ..Recorded::default()
        };
        let facts = UserFacts {
            uuid: Uuid::from_name_and_date("e6bob", &chrono::NaiveDateTime::default()),
            enrolled: false,
            exempt: false,
            created: at(-DAY),
            recorded: Some(reenabled),
        };
        cache.put_facts(&bob, facts);
        cache.note_success(&store, &bob, naive(0)).await;
        let held = cache.get().facts_of(&bob).and_then(|facts| facts.recorded);
        let expected = Recorded {
            last_success: Some(at(0)),
            reenabled_at: Some(at(-10)),
        };
        assert_eq!(held, Some(expected));
    }

    #[tokio::test]
    async fn test_recording_since_moves_only_when_the_item_turns() {
        let (cache, store) = (PolicyCache::new(), Memory::default());
        let (live, off) = (
            [linked("idle", "30", &["people"])],
            [linked("idle", "0", &["people"])],
        );
        type Row<'a> = (&'static str, &'a [Policy], i64, Recording, Vec<bool>, u64);
        let rows: [Row<'_>; 6] = [
            (
                "the start, not set: one write to off",
                &off,
                0,
                Recording::Off,
                vec![false],
                0,
            ),
            (
                "not set again: nothing",
                &off,
                100,
                Recording::Off,
                vec![],
                0,
            ),
            (
                "off to live: the time",
                &live,
                200,
                Recording::Since(at(200)),
                vec![true],
                1,
            ),
            (
                "live to live: a read, no write",
                &live,
                300,
                Recording::Since(at(200)),
                vec![],
                1,
            ),
            (
                "live to off: off",
                &off,
                400,
                Recording::Off,
                vec![false],
                0,
            ),
            (
                "off to live again: the new time",
                &live,
                500,
                Recording::Since(at(500)),
                vec![true],
                1,
            ),
        ];
        for (label, policies, seconds, recording, writes, reads) in rows {
            let before = store.recording_reads.load(Ordering::Relaxed);
            follow_recording(&store, &cache, policies, naive(seconds))
                .await
                .unwrap();
            let written = std::mem::take(&mut *store.recording_writes.lock().unwrap());
            let read = store.recording_reads.load(Ordering::Relaxed) - before;
            assert_eq!(
                (cache.recording(), written, read),
                (recording, writes, reads),
                "{label}"
            );
        }
    }

    #[tokio::test]
    async fn test_a_restart_while_live_keeps_the_stored_recording_time() {
        let store = Memory::default();
        let live = [linked("idle", "30", &["people"])];
        let first = PolicyCache::new();
        follow_recording(&store, &first, &live, naive(100))
            .await
            .unwrap();
        let (restarted, other) = (PolicyCache::new(), PolicyCache::new());
        follow_recording(&store, &restarted, &live, naive(9_000))
            .await
            .unwrap();
        follow_recording(&store, &other, &live, naive(9_001))
            .await
            .unwrap();
        let since = Recording::Since(at(100));
        assert_eq!(
            [first.recording(), restarted.recording(), other.recording()],
            [since; 3],
            "a restart and a second server take the stored time"
        );
        assert_eq!(*store.recording_writes.lock().unwrap(), vec![true]);
    }

    #[test]
    fn test_one_warning_for_a_value_that_does_not_parse_until_it_changes() {
        let cache = PolicyCache::new();
        let bad = linked("idle", "thirty", &["people"]);
        let unlinked = linked("spare", "x", &[]);
        let good = linked("idle", "30", &["people"]);
        let said = [
            cache.unreadable_warnings(&[bad.clone(), unlinked]),
            cache.unreadable_warnings(std::slice::from_ref(&bad)),
            cache.unreadable_warnings(&[good]),
            cache.unreadable_warnings(&[bad]),
        ];
        let text = "The policy \"idle\" sets inactivity-days to a value that does not parse: the \
                    users it applies to are refused as unreadable until it is set again"
            .to_owned();
        assert_eq!(said, [vec![text.clone()], vec![], vec![], vec![text]]);
    }
}
