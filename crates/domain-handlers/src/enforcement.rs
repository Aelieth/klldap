use crate::handler::{PolicyBackendHandler, UserBackendHandler, UserListerBackendHandler};
use crate::kerberos::{CommitError, HostRow};
use crate::logging::{self, LogKind, Protocol, RequestMeta};
use crate::policies::{
    EffectiveItem, POLICY_ITEM_CATALOG, canonical_ou_key, resolve_effective_items,
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use lldap_domain::requests::UpdateUserRequest;
use lldap_domain::types::{UserId, user_ou};
use lldap_domain_model::error::{DomainError, Result};
use std::collections::{BTreeSet, HashMap};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex, PoisonError, RwLock};
use std::time::Duration;
use tokio::sync::Notify;
use tracing::warn;

pub const POLICY_REFILL: Duration = Duration::from_secs(30);
pub const FILL_GAP: Duration = Duration::from_millis(250);
pub const UNREADABLE: &str = "unreadable";
pub const NOT_LOADED: &str = "not loaded yet";

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
        format!("policy: {}", self.item)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UserState {}

pub trait ItemCheck: Send + Sync {
    fn key(&self) -> &'static str;
    /// A user no check judges is admitted before any read.
    fn judges(&self, _user: &UserId) -> bool {
        true
    }
    fn allows(&self, attempt: &Attempt<'_>, value: &str, state: &UserState) -> bool;
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
        if !check.allows(attempt, &item.value, state) {
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

/// Each enforcing cell adds its item's check here and turns the item's `enforced` flag on.
pub fn default_item_checks() -> ItemChecks {
    let checks: Vec<Arc<dyn ItemCheck>> = Vec::new();
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

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Entries {
    pub ous_of_users: HashMap<UserId, String>,
    pub items_of_ous: HashMap<String, Arc<[EffectiveItem]>>,
    pub built_at: DateTime<Utc>,
}

impl Entries {
    pub fn items_of(&self, user: &UserId) -> Option<&[EffectiveItem]> {
        let ou_key = self.ous_of_users.get(user)?;
        self.items_of_ous.get(ou_key).map(|items| &items[..])
    }
}

/// Swapped whole: a reader holds the old entries or the new ones, never none.
pub struct PolicyCache {
    current: RwLock<Arc<Entries>>,
    generation: AtomicU64,
    reads: AtomicU64,
    fill: Notify,
    writers: tokio::sync::Mutex<()>,
    marked: Mutex<Marks>,
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
        }
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

    fn edit(&self, change: impl FnOnce(&mut Entries)) {
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

    pub fn remove_user(&self, user: &UserId) {
        self.edit(|entries| {
            entries.ous_of_users.remove(user);
        });
    }

    fn marks(&self) -> std::sync::MutexGuard<'_, Marks> {
        self.marked.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn mark(&self, user: &UserId) {
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

async fn user_entry<H>(handler: &H, user: &UserId) -> Result<(String, Arc<[EffectiveItem]>)>
where
    H: UserBackendHandler + PolicyBackendHandler + ?Sized,
{
    let details = handler.get_user_details(user).await?;
    let ou_key = canonical_ou_key(&user_ou(&details.attributes));
    let items = ou_items(handler, &ou_key).await?;
    Ok((ou_key, items))
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
    for entry in handler.list_users(None, false).await? {
        let ou_key = canonical_ou_key(&user_ou(&entry.user.attributes));
        ou_keys.insert(ou_key.clone());
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
    let entries = build_entries(handler).await?;
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
        loop {
            tokio::select! {
                () = cache.poked() => {}
                () = tokio::time::sleep(POLICY_REFILL) => {}
            }
            if let Err(e) = fill_policy_cache(&handler, cache).await {
                warn!("The policy cache was not refilled: {e}");
            }
            tokio::time::sleep(FILL_GAP).await;
        }
    })
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
    if let Err(e) = fill_policy_cache(handler, policy_cache()).await {
        warn!("The policy cache was not filled at start: {e}");
        policy_cache().poke_fill();
    }
    Some(start_policy_filler(handler.clone(), policy_cache()))
}

pub async fn policy_changed<H>(handler: &H, cache: &PolicyCache)
where
    H: UserListerBackendHandler + UserBackendHandler + PolicyBackendHandler + ?Sized,
{
    if item_checks().is_empty() {
        return;
    }
    if let Err(e) = fill_policy_cache(handler, cache).await {
        warn!("The policy cache was not refilled after a policy change: {e}");
        cache.poke_fill();
    }
}

/// One pass over the marks present now; a mark leaves the set only once its entry is stored.
async fn take_marks<H>(handler: &H, cache: &PolicyCache)
where
    H: UserBackendHandler + PolicyBackendHandler + ?Sized,
{
    for (user, made) in cache.marked_now() {
        match user_entry(handler, &user).await {
            Ok((ou_key, items)) => cache.put_user(&user, &ou_key, items),
            Err(DomainError::EntityNotFound(_)) => cache.remove_user(&user),
            Err(e) => {
                warn!("The policy cache did not take {user}'s change: {e}");
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
    if !judged(&item_checks(), user) {
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
    let checks = item_checks();
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
    let checks = item_checks();
    if !judged(&checks, attempt.user) {
        return Ok(());
    }
    let decision = match resolve_items(handler, policy_cache(), attempt.user).await {
        Ok(items) => decide(attempt, &items, &UserState::default(), &checks),
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
    if !judged(checks, attempt.user) {
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
    decide(attempt, items, &UserState::default(), checks)
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
    use crate::policies::{
        CreatePolicyRequest, OuPolicyState, Policy, PolicyId, PolicyLevel, PolicyScope,
        UpdatePolicyRequest, catalog_item,
    };
    use lldap_domain::requests::CreateUserRequest;
    use lldap_domain::types::{Attribute, GroupDetails, GroupId, User, UserAndGroups, Uuid};
    use lldap_schema::PublicSchema;
    use pretty_assertions::assert_eq;
    use std::collections::HashSet;
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
            item("require-mfa", "always"),
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
                    refuse("require-mfa"),
                    refuse("login-hours"),
                ],
                refused("require-mfa"),
            ),
            (
                "the check sees the value",
                vec![check("require-mfa", |_, value| value == "off")],
                refused("require-mfa"),
            ),
            (
                "the check sees the attempt",
                vec![check("require-mfa", |attempt, _| attempt.second_factor)],
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
        let checked: HashSet<&str> = default_item_checks().iter().map(|c| c.key()).collect();
        for spec in POLICY_ITEM_CATALOG {
            assert_eq!(spec.enforced, checked.contains(spec.key), "{}", spec.key);
        }
        for key in checked {
            assert!(catalog_item(key).is_some(), "{key} is not a catalog item");
        }
    }

    #[test]
    fn test_each_door_has_its_row_kind_and_only_logins_count() {
        let rows = [
            (Door::WebLogin, LogKind::Login, true),
            (Door::SimpleLogin, LogKind::Bind, true),
            (Door::Refresh, LogKind::TokenRefresh, false),
            (Door::TokenUse, LogKind::AccessDenied, false),
            (Door::LdapBind, LogKind::Bind, true),
            (Door::KerberosAs, LogKind::Login, true),
            (Door::KerberosTgs, LogKind::AccessDenied, false),
            (Door::KerberosS4u, LogKind::AccessDenied, false),
        ];
        for (door, kind, login) in rows {
            assert_eq!(
                (door.log_kind(), door.is_login()),
                (kind, login),
                "{door:?}"
            );
        }
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
            unimplemented!()
        }
        async fn ensure_kerberos_principal_consistency(&self, _: &UserId, _: bool) -> Result<()> {
            unimplemented!()
        }
    }

    #[async_trait]
    impl PolicyBackendHandler for Directory {
        async fn list_policies(&self) -> Result<Vec<Policy>> {
            unimplemented!()
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
}
