use crate::logging::{LogEvent, LogKind};
use async_trait::async_trait;
use lldap_domain::requests::{CreateUserRequest, UpdateUserRequest};
use lldap_domain::types::{GroupId, UserId};
use lldap_domain_model::error::DomainError;
use std::sync::{Arc, LazyLock, RwLock};

pub fn domain_from_base_dn(base_dn: &str) -> String {
    base_dn
        .split(',')
        .filter_map(|part| {
            let part = part.trim();
            part.get(..3)
                .filter(|p| p.eq_ignore_ascii_case("dc="))
                .map(|_| part[3..].to_owned())
        })
        .collect::<Vec<_>>()
        .join(".")
        .to_lowercase()
}

pub fn realm_from(realm_override: Option<&str>, base_dn: &str) -> String {
    realm_override
        .filter(|realm| !realm.is_empty())
        .map(str::to_owned)
        .unwrap_or_else(|| domain_from_base_dn(base_dn))
        .to_uppercase()
}

const RESERVED_PRINCIPALS: &[&str] = &["krbtgt", "kadmin", "kiprop", "wellknown"];

/// One principal component (`/` or `@` would start another), no whitespace, no KDC-reserved name.
pub fn validate_kerberos_username(username: &str) -> Result<(), String> {
    if username.is_empty() || username.len() > 128 {
        return Err("Kerberos username is empty or longer than 128 characters".to_owned());
    }
    let mut chars = username.chars();
    let Some(first) = chars.next() else {
        return Err("Kerberos username is empty".to_owned());
    };
    if !first.is_ascii_alphanumeric()
        || !chars.all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-')
    {
        return Err("Kerberos username must be ASCII alphanumeric plus '.', '_' or '-'".to_owned());
    }
    if RESERVED_PRINCIPALS
        .iter()
        .any(|reserved| username.eq_ignore_ascii_case(reserved))
    {
        return Err(format!(
            "Kerberos username '{username}' is reserved by the KDC"
        ));
    }
    Ok(())
}

/// Looser than `validate_kerberos_username`: refuses only `/`, `@` and reserved KDC names, so
/// existing IDs with quotes or non-ASCII, and the SQL-injection fixture, still insert.
pub fn validate_directory_username(username: &str) -> Result<(), String> {
    if username.is_empty() || username.len() > 128 {
        return Err("Username is empty or longer than 128 characters".to_owned());
    }
    if username.contains('/')
        || username.contains('@')
        || username
            .chars()
            .any(|c| c.is_whitespace() || c.is_control())
    {
        return Err(
            "Username must not contain '/', '@', whitespace or control characters".to_owned(),
        );
    }
    if RESERVED_PRINCIPALS
        .iter()
        .any(|reserved| username.eq_ignore_ascii_case(reserved))
    {
        return Err(format!(
            "Kerberos username '{username}' is reserved by the KDC"
        ));
    }
    Ok(())
}

/// Goes into `HTTP/{host}@{realm}`: a DNS name or IPv4 address, so no space, `/` or newline.
pub fn validate_keytab_hostname(hostname: &str) -> Result<(), String> {
    if hostname.is_empty() || hostname.len() > 253 {
        return Err("Keytab hostname is empty or longer than 253 characters".to_owned());
    }
    if hostname.starts_with('.') || hostname.ends_with('.') {
        return Err("Keytab hostname must be a DNS name or IPv4 address".to_owned());
    }
    for label in hostname.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err("Keytab hostname has an empty or oversized label".to_owned());
        }
        let bytes = label.as_bytes();
        if !bytes[0].is_ascii_alphanumeric() || !bytes[label.len() - 1].is_ascii_alphanumeric() {
            return Err(
                "Keytab hostname labels must start and end with an alphanumeric character"
                    .to_owned(),
            );
        }
        if !bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || *b == b'-')
        {
            return Err("Keytab hostname contains invalid characters".to_owned());
        }
    }
    Ok(())
}

#[async_trait]
pub trait KerberosSync: Send + Sync {
    /// Whether the KDC has been reachable at least once since the process started.
    fn ready(&self) -> bool {
        true
    }
    fn unavailable(&self) -> Option<String> {
        None
    }
    /// Why a held realm still refuses a change to both stores: its last write is unsettled.
    fn unsettled(&self) -> Option<String> {
        None
    }
    /// False when the configuration disables Kerberos: no realm runs, and none will.
    fn enabled(&self) -> bool {
        true
    }
    fn realm(&self) -> &str;
    fn principal_name(&self, user: &UserId) -> String {
        format!("{}@{}", user.as_str(), self.realm())
    }
    /// Kerberos's own check of a new password, before anything is locked or written.
    async fn check_password(&self, _user: &UserId, _password: &str) -> Result<(), String> {
        Ok(())
    }
    /// A synced user's new keys and `change.rows`, in one transaction.
    async fn commit_password(
        &self,
        change: PasswordCommit,
        _password: &str,
    ) -> Result<(), CommitError> {
        let failed = CommitError::Failed(NO_COMMIT.to_owned());
        crate::password::record_commit_failure(change.kind, &change.user, &failed);
        Err(failed)
    }
    /// A user's delete or sync change and its principal's, in one transaction; None: no realm.
    async fn commit_user(&self, _change: UserChange) -> Option<Result<(), CommitError>> {
        None
    }
    /// Why the realm refuses sync on for `user`, if it does: its name is an alias.
    async fn sync_on_refused(&self, _user: &UserId) -> Result<(), String> {
        Ok(())
    }
    /// Held around a plain password write while the switch stays off; None: no realm.
    async fn hold_plain(&self, _user: &UserId) -> Result<Option<Held>, CommitError> {
        Ok(None)
    }
    async fn delete_principal(&self, user: &UserId) -> Result<(), String>;
    async fn set_principal_enabled(&self, user: &UserId, enabled: bool) -> Result<(), String>;
    async fn export_keytab_for_keycloak(&self, hostname: &str) -> Result<String, String>;
}

const NOT_REGISTERED: &str = "Kerberos backend not registered";
const NO_COMMIT: &str = "this Kerberos backend cannot commit a password";
const NO_HOST_ROWS: &str = "this Kerberos store writes no directory rows";

pub const USER_GONE: &str = "the user is gone";
pub const KERBEROS_DISABLED: &str =
    "Kerberos is disabled on this server (kerberos_options.enabled is false)";
pub const SYNC_CHANGED: &str = "the user's Kerberos sync changed; try again";
pub const CREATE_WITHOUT_SYNC: &str = "Kerberos is disabled; create the user without Kerberos sync";
pub const SYNC_ON_NEEDS_KERBEROS: &str = "Kerberos sync is turned on only with Kerberos enabled";
pub const SYNC_OFF_FIRST: &str = "enable Kerberos, or turn the user's Kerberos sync off first";
pub const LEFT_FOR_THE_START_PASS: &str = "Kerberos is disabled: a principal, if there is one, is \
     left for the start pass, which removes it at the next start with Kerberos enabled";
pub const STATUS_LEFT_DISABLED: &str = "Kerberos is disabled: the status of a principal, if there \
     is one, is left for the start pass, which sets it from lldap_disabled at the next start with \
     Kerberos enabled";
pub const STATUS_LEFT_NOT_READY: &str = "the Kerberos realm is not ready: the status of a \
     principal, if there is one, is left for the server that holds the realm, which sets it from \
     lldap_disabled at its next status pass, within a minute, or when the realm opens";
pub const CREATED_FIRST: &str = "another server created the realm first";
/// A new principal name is a directory user's, or a case twin of one.
pub const DIRECTORY_USER: &str = "the name belongs to a directory user";
pub const DIRECTORY_TARGET: &str = "the alias's target belongs to a directory user";
/// Starts the Failed answer of a commit whose outcome could not be read back.
pub const UNREAD_AFTER_COMMIT: &str = "the result is unknown: the commit could not be read back";
pub const ANSWER_UNSETTLED: &str =
    "the answer to this server's last Kerberos write was lost and is not yet settled";

/// A directory row that commits in the transaction of a Kerberos change.
#[derive(Clone)]
pub enum HostRow {
    /// Exactly one user row must change, or the transaction rolls back.
    SetPassword {
        user: UserId,
        record: Vec<u8>,
        now: chrono::NaiveDateTime,
    },
    CreateUser(CreateUserRequest),
    Log(LogEvent),
    /// None of these users may exist, or the transaction rolls back with `DIRECTORY_USER`.
    NoUser(Vec<UserId>),
    /// No name on these targets' chains may be a user's, or it rolls back with `DIRECTORY_TARGET`.
    NoAliasOnto(AliasOnto),
    /// Exactly one user row must go, with its memberships and attributes, or it rolls back.
    DeleteUser(UserId),
    UpdateUser(UpdateUserRequest),
    /// The user's sync must still be as the door read it, or it rolls back (`SYNC_CHANGED`).
    SyncIs(UserId, bool),
    /// The user and the group must exist and one membership row must change, or it rolls back.
    Membership {
        user: UserId,
        group: GroupId,
        add: bool,
    },
    Unlock {
        user: UserId,
        at: chrono::NaiveDateTime,
    },
}

pub type UserOf = Arc<dyn Fn(&str) -> Option<UserId> + Send + Sync>;
pub type Held = Box<dyn std::any::Any + Send>;

/// The targets of new alias rows, followed through the principals' `alias_target` column.
#[derive(Clone)]
pub struct AliasOnto {
    pub targets: Vec<String>,
    pub hops: usize,
    pub user_of: UserOf,
}

impl HostRow {
    pub fn is_password(&self) -> bool {
        matches!(self, Self::SetPassword { .. })
    }

    pub fn has_kill_points(&self) -> bool {
        matches!(
            self,
            Self::SetPassword { .. } | Self::DeleteUser(_) | Self::UpdateUser(_)
        )
    }

    pub fn label(&self) -> String {
        match self {
            Self::SetPassword { user, .. } => format!("password {user}"),
            Self::CreateUser(request) => format!("create {}", request.user_id),
            Self::Log(event) => format!("log {}", event.kind),
            Self::NoUser(users) => format!("no user {}", names(users)),
            Self::NoAliasOnto(onto) => format!("no alias onto {}", onto.targets.join(", ")),
            Self::DeleteUser(user) => format!("delete {user}"),
            Self::UpdateUser(request) => format!("update {}", request.user_id),
            Self::SyncIs(user, true) => format!("synced {user}"),
            Self::SyncIs(user, false) => format!("unsynced {user}"),
            Self::Membership {
                user,
                group,
                add: true,
            } => format!("add {user} to group {}", group.0),
            Self::Membership { user, group, .. } => format!("remove {user} from group {}", group.0),
            Self::Unlock { user, .. } => format!("unlock {user}"),
        }
    }
}

fn names(users: &[UserId]) -> String {
    let users: Vec<_> = users.iter().map(UserId::as_str).collect();
    users.join(", ")
}

impl std::fmt::Debug for HostRow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.label())
    }
}

/// The rows that carry the prepared OPAQUE record; the password goes beside them.
pub struct PasswordCommit {
    pub user: UserId,
    pub rows: Vec<HostRow>,
    pub kind: LogKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UserStep {
    Delete,
    SyncOff,
    SyncOn,
    DeleteWithoutSync,
    SyncUnchanged,
    Create,
    Disable,
    Enable,
}

impl UserStep {
    pub fn op(self) -> &'static str {
        match self {
            Self::Delete | Self::DeleteWithoutSync => "delete",
            Self::SyncOff => "sync off",
            Self::SyncOn => "sync on",
            Self::SyncUnchanged => "update",
            Self::Create => "create",
            Self::Disable => "disable",
            Self::Enable => "enable",
        }
    }

    pub fn touches_principal(self) -> bool {
        matches!(
            self,
            Self::Delete
                | Self::SyncOff
                | Self::SyncOn
                | Self::Create
                | Self::Disable
                | Self::Enable
        )
    }

    pub fn turns_sync_on(self) -> bool {
        matches!(self, Self::SyncOn | Self::Create)
    }
}

/// Delete and sync off remove the principal of the user's name; sync on adopts any principal of
/// it (random keys, disabled until its status is next set); disable and enable set its status.
pub struct UserChange {
    pub user: UserId,
    pub step: UserStep,
    pub rows: Vec<HostRow>,
}

pub fn sync_refused(user: &UserId, why: &str) -> String {
    format!("Kerberos sync cannot be turned on for user {user}: {why}")
}

pub fn while_disabled(way_on: &str) -> String {
    format!("{KERBEROS_DISABLED}: {way_on}")
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CommitError {
    Busy,
    Refused(String),
    UserGone,
    Failed(String),
    Unknown(String),
    Unsettled(String),
}

// Stands in when no realm is registered: idempotent cleanups succeed, operations that
// need the realm fail, so a missing registration stays visible.
#[derive(Default)]
pub struct NoopKerberos {
    realm: String,
}

impl NoopKerberos {
    pub fn new(realm: String) -> Self {
        Self { realm }
    }
}

#[async_trait]
impl KerberosSync for NoopKerberos {
    fn ready(&self) -> bool {
        false
    }
    fn enabled(&self) -> bool {
        false
    }
    fn realm(&self) -> &str {
        &self.realm
    }
    async fn delete_principal(&self, _: &UserId) -> Result<(), String> {
        Ok(())
    }
    async fn set_principal_enabled(&self, _: &UserId, _: bool) -> Result<(), String> {
        Ok(())
    }
    async fn export_keytab_for_keycloak(&self, _: &str) -> Result<String, String> {
        Err(NOT_REGISTERED.to_owned())
    }
}

pub struct DegradedKerberos {
    realm: String,
    cause: String,
}

impl DegradedKerberos {
    pub fn new(realm: String, cause: String) -> Self {
        Self { realm, cause }
    }
}

#[async_trait]
impl KerberosSync for DegradedKerberos {
    fn ready(&self) -> bool {
        false
    }
    fn unavailable(&self) -> Option<String> {
        Some(self.cause.clone())
    }
    fn realm(&self) -> &str {
        &self.realm
    }
    async fn delete_principal(&self, _: &UserId) -> Result<(), String> {
        Err(self.cause.clone())
    }
    async fn set_principal_enabled(&self, _: &UserId, _: bool) -> Result<(), String> {
        Err(self.cause.clone())
    }
    async fn export_keytab_for_keycloak(&self, _: &str) -> Result<String, String> {
        Err(self.cause.clone())
    }
}

// Process-global so ldap/sql call sites stay one-liners; tests that install a
// recorder must be #[serial] and restore the default on drop.
static BACKEND: LazyLock<RwLock<Arc<dyn KerberosSync>>> =
    LazyLock::new(|| RwLock::new(Arc::new(NoopKerberos::default())));

pub const ADMINS_ONLY: &str = "only admins may sign in while Kerberos is unavailable";
pub const LDAP_ADMINS_ONLY: &str = "only admins may bind while Kerberos is unavailable";

/// While the realm is unavailable only admins get in; a refusal writes its row and gives the cause.
pub fn refusal_while_degraded(
    user: &UserId,
    is_admin: bool,
    unavailable: Option<String>,
) -> Option<String> {
    let cause = unavailable.filter(|_| !is_admin)?;
    crate::logging::record_as(
        Some(user),
        LogKind::AccessDenied,
        None,
        false,
        Some(ADMINS_ONLY),
    );
    Some(cause)
}

pub fn kerberos_backend() -> Arc<dyn KerberosSync> {
    #[cfg(feature = "test-backend-scope")]
    if let Some(backend) = THREAD_BACKEND.with(|scoped| scoped.borrow().clone()) {
        return backend;
    }
    BACKEND.read().expect("kerberos backend").clone()
}

#[cfg(feature = "test-backend-scope")]
thread_local! {
    static THREAD_BACKEND: std::cell::RefCell<Option<Arc<dyn KerberosSync>>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(feature = "test-backend-scope")]
pub fn set_thread_kerberos_backend(backend: Option<Arc<dyn KerberosSync>>) {
    THREAD_BACKEND.with(|scoped| *scoped.borrow_mut() = backend);
}

pub fn set_kerberos_backend(backend: Arc<dyn KerberosSync>) {
    *BACKEND.write().expect("kerberos backend") = backend;
}

pub fn user_id_for_principal_name(name: &str) -> Option<&str> {
    if name.is_empty() || name.contains('/') || name.contains('@') {
        None
    } else {
        Some(name)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrincipalRow {
    pub name: String,
    pub record: Vec<u8>,
    pub has_keys: bool,
    pub disabled: bool,
    pub kvno: i32,
    pub expiration: Option<chrono::NaiveDateTime>,
    pub password_expiration: Option<chrono::NaiveDateTime>,
    pub policy: Option<String>,
    pub modified_date: chrono::NaiveDateTime,
    pub alias_target: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoadedPrincipal {
    pub name: String,
    pub record: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyRow {
    pub name: String,
    pub record: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RealmState {
    pub realm: String,
    pub state: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoadedRealm {
    pub principals: Vec<LoadedPrincipal>,
    pub policies: Vec<PolicyRow>,
    pub realm: Option<RealmState>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RealmBatch {
    pub upsert_principals: Vec<PrincipalRow>,
    pub delete_principals: Vec<String>,
    pub put_policies: Vec<PolicyRow>,
    pub delete_policies: Vec<String>,
    pub realm: Option<RealmState>,
}

#[derive(Clone, Debug)]
pub enum KerberosStoreError {
    NotReady(String),
    Failed(String),
    Refused(String),
}

impl std::fmt::Display for KerberosStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotReady(reason) => write!(f, "Kerberos store not ready: {reason}"),
            Self::Failed(reason) => write!(f, "Kerberos store failed: {reason}"),
            Self::Refused(reason) => write!(f, "Kerberos store refused the change: {reason}"),
        }
    }
}

impl std::error::Error for KerberosStoreError {}

pub trait KerberosStore: Send + Sync {
    fn load(&self) -> Result<LoadedRealm, KerberosStoreError>;
    fn commit(&self, batch: RealmBatch) -> Result<(), KerberosStoreError>;
    /// `host` first, then the batch, in one transaction.
    fn commit_with(&self, host: Vec<HostRow>, batch: RealmBatch) -> Result<(), KerberosStoreError> {
        if host.is_empty() {
            self.commit(batch)
        } else {
            Err(KerberosStoreError::Refused(NO_HOST_ROWS.to_owned()))
        }
    }
    /// Which of `users` exist, read outside any transaction.
    fn directory_users(&self, _users: &[UserId]) -> Result<Vec<UserId>, KerberosStoreError> {
        Err(KerberosStoreError::NotReady(NO_HOST_ROWS.to_owned()))
    }
    /// Whether `user` is in `lldap_disabled`, read outside any transaction; false for no user.
    fn user_disabled(&self, _user: &UserId) -> Result<bool, KerberosStoreError> {
        Err(KerberosStoreError::NotReady(NO_HOST_ROWS.to_owned()))
    }
    /// Whether `user` has Kerberos sync, read outside any transaction; false for no user.
    fn user_synced(&self, _user: &UserId) -> Result<bool, KerberosStoreError> {
        Err(KerberosStoreError::NotReady(NO_HOST_ROWS.to_owned()))
    }
    /// Each user with Kerberos sync and whether it is in `lldap_disabled`, in one read.
    fn synced_statuses(&self) -> Result<Vec<(UserId, bool)>, KerberosStoreError> {
        Err(KerberosStoreError::NotReady(NO_HOST_ROWS.to_owned()))
    }
    /// `start`, then each row name its alias rows lead to, at most `hops` further.
    fn alias_chain(&self, _start: &str, _hops: usize) -> Result<Vec<String>, KerberosStoreError> {
        Err(KerberosStoreError::NotReady(NO_HOST_ROWS.to_owned()))
    }
    /// Sets `alias_target` where it is empty, by (row name, target); the records stay as they are.
    fn fill_alias_targets(&self, _rows: &[(String, String)]) -> Result<u64, KerberosStoreError> {
        Err(KerberosStoreError::NotReady(NO_HOST_ROWS.to_owned()))
    }
    /// Why this server does not hold the realm now: it lost it.
    fn realm_not_held(&self) -> Option<String> {
        None
    }
    /// Why this server's last write is unknown while it still holds the realm.
    fn realm_unsettled(&self) -> Option<String> {
        None
    }
}

const STORE_NOT_REGISTERED: &str = "Kerberos store not registered";

pub struct NoopKerberosStore;

impl KerberosStore for NoopKerberosStore {
    fn load(&self) -> Result<LoadedRealm, KerberosStoreError> {
        Err(KerberosStoreError::NotReady(
            STORE_NOT_REGISTERED.to_owned(),
        ))
    }

    fn commit(&self, _: RealmBatch) -> Result<(), KerberosStoreError> {
        Err(KerberosStoreError::NotReady(
            STORE_NOT_REGISTERED.to_owned(),
        ))
    }
}

static STORE: LazyLock<RwLock<Arc<dyn KerberosStore>>> =
    LazyLock::new(|| RwLock::new(Arc::new(NoopKerberosStore)));

pub fn kerberos_store() -> Arc<dyn KerberosStore> {
    STORE.read().expect("kerberos store").clone()
}

pub fn set_kerberos_store(store: Arc<dyn KerberosStore>) {
    *STORE.write().expect("kerberos store") = store;
}

/// Directory writes are refused until the KDC has come up, so nothing changes that the
/// KDC could not follow.
pub fn require_kdc_ready() -> Result<(), DomainError> {
    match kerberos_state() {
        KerberosState::NotReady(cause) => Err(DomainError::KdcUnavailable(cause)),
        KerberosState::Disabled | KerberosState::Ready => Ok(()),
    }
}

/// Disabled by the configuration is never "not ready": the directory goes on as plain LLDAP.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KerberosState {
    Disabled,
    NotReady(String),
    Ready,
}

pub fn state_of(backend: &dyn KerberosSync) -> KerberosState {
    if !backend.enabled() {
        return KerberosState::Disabled;
    }
    if backend.ready() {
        return KerberosState::Ready;
    }
    KerberosState::NotReady(
        backend
            .unavailable()
            .unwrap_or_else(|| "the Kerberos KDC is still starting; retry shortly".to_owned()),
    )
}

pub fn kerberos_state() -> KerberosState {
    state_of(&*kerberos_backend())
}

/// What a password, or a change to both stores, needs: `state_of`, and the last write settled.
pub fn settled_state_of(backend: &dyn KerberosSync) -> KerberosState {
    match state_of(backend) {
        KerberosState::Ready => backend
            .unsettled()
            .map_or(KerberosState::Ready, KerberosState::NotReady),
        state => state,
    }
}

pub fn settled_state() -> KerberosState {
    settled_state_of(&*kerberos_backend())
}

/// A user change that writes both stores: refused with one row until the realm is settled.
pub fn require_settled(kind: LogKind, user: &UserId) -> Result<(), DomainError> {
    let KerberosState::NotReady(cause) = settled_state() else {
        return Ok(());
    };
    let refused = unsettled_answer(&cause);
    crate::logging::record_failure(kind, Some(user.as_str()), &refused.to_string());
    Err(refused)
}

pub fn unsettled_answer(cause: &str) -> DomainError {
    DomainError::KdcUnavailable(format!("{cause}; try again"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
    use serial_test::serial;
    use std::sync::Mutex;

    struct RestoreStore;
    impl Drop for RestoreStore {
        fn drop(&mut self) {
            set_kerberos_store(Arc::new(NoopKerberosStore));
        }
    }

    struct MockStore {
        loaded: LoadedRealm,
        committed: Mutex<Option<RealmBatch>>,
    }

    impl KerberosStore for MockStore {
        fn load(&self) -> Result<LoadedRealm, KerberosStoreError> {
            Ok(self.loaded.clone())
        }

        fn commit(&self, batch: RealmBatch) -> Result<(), KerberosStoreError> {
            *self.committed.lock().expect("mock batch") = Some(batch);
            Ok(())
        }
    }

    fn sample_batch() -> RealmBatch {
        RealmBatch {
            upsert_principals: vec![PrincipalRow {
                name: "alice".to_owned(),
                record: vec![1],
                has_keys: true,
                disabled: false,
                kvno: 1,
                expiration: None,
                password_expiration: None,
                policy: None,
                modified_date: chrono::NaiveDateTime::parse_from_str(
                    "1970-01-01 00:00:00",
                    "%Y-%m-%d %H:%M:%S",
                )
                .unwrap(),
                alias_target: None,
            }],
            delete_principals: vec!["bob".to_owned()],
            put_policies: vec![PolicyRow {
                name: "default".to_owned(),
                record: vec![2],
            }],
            delete_policies: vec!["old".to_owned()],
            realm: Some(RealmState {
                realm: "EXAMPLE.COM".to_owned(),
                state: vec![3],
            }),
        }
    }

    #[test]
    #[serial]
    fn test_kerberos_store_registration() {
        let restore = RestoreStore;
        let loaded = LoadedRealm {
            principals: vec![LoadedPrincipal {
                name: "alice".to_owned(),
                record: vec![1],
            }],
            policies: vec![],
            realm: Some(RealmState {
                realm: "EXAMPLE.COM".to_owned(),
                state: vec![3],
            }),
        };
        let mock = Arc::new(MockStore {
            loaded: loaded.clone(),
            committed: Mutex::new(None),
        });
        set_kerberos_store(mock.clone());
        assert_eq!(kerberos_store().load().unwrap(), loaded);
        let batch = sample_batch();
        kerberos_store().commit(batch.clone()).unwrap();
        assert_eq!(mock.committed.lock().unwrap().clone().unwrap(), batch);
        drop(restore);
        assert!(kerberos_store().load().is_err());
    }

    #[test]
    fn test_host_rows_print_their_label_and_no_record() {
        use crate::logging::{LogKind, event};
        let now = chrono::DateTime::from_timestamp(0, 0).unwrap().naive_utc();
        let bob = UserId::new("bob");
        let rows: [(HostRow, &str, bool, bool); 12] = [
            (
                HostRow::Unlock {
                    user: bob.clone(),
                    at: now,
                },
                "unlock bob",
                false,
                false,
            ),
            (
                HostRow::SetPassword {
                    user: bob.clone(),
                    record: vec![0xAB; 8],
                    now,
                },
                "password bob",
                true,
                true,
            ),
            (
                HostRow::CreateUser(CreateUserRequest {
                    user_id: bob.clone(),
                    ..Default::default()
                }),
                "create bob",
                false,
                false,
            ),
            (
                HostRow::Log(event(LogKind::PasswordChange, Some("bob"), true, None)),
                "log password_change",
                false,
                false,
            ),
            (
                HostRow::NoUser(vec![UserId::new("Alice"), UserId::new("carol")]),
                "no user alice, carol",
                false,
                false,
            ),
            (
                HostRow::NoAliasOnto(AliasOnto {
                    targets: vec!["Bob".to_owned(), "svc/a".to_owned()],
                    hops: 10,
                    user_of: Arc::new(|_: &str| None),
                }),
                "no alias onto Bob, svc/a",
                false,
                false,
            ),
            (HostRow::DeleteUser(bob.clone()), "delete bob", false, true),
            (
                HostRow::SyncIs(UserId::new("Bob"), true),
                "synced bob",
                false,
                false,
            ),
            (
                HostRow::SyncIs(UserId::new("bob"), false),
                "unsynced bob",
                false,
                false,
            ),
            (
                HostRow::Membership {
                    user: bob.clone(),
                    group: GroupId(7),
                    add: true,
                },
                "add bob to group 7",
                false,
                false,
            ),
            (
                HostRow::Membership {
                    user: bob.clone(),
                    group: GroupId(7),
                    add: false,
                },
                "remove bob from group 7",
                false,
                false,
            ),
            (
                HostRow::UpdateUser(UpdateUserRequest {
                    user_id: bob,
                    ..Default::default()
                }),
                "update bob",
                false,
                true,
            ),
        ];
        for (row, label, password, points) in rows {
            assert_eq!(
                (format!("{row:?}"), row.is_password(), row.has_kill_points()),
                (label.to_owned(), password, points)
            );
        }
        let refused = MockStore {
            loaded: LoadedRealm {
                principals: vec![],
                policies: vec![],
                realm: None,
            },
            committed: Mutex::new(None),
        }
        .commit_with(
            vec![HostRow::Log(event(
                LogKind::PasswordChange,
                None,
                true,
                None,
            ))],
            sample_batch(),
        );
        assert!(matches!(refused, Err(KerberosStoreError::Refused(_))));
    }

    /// The sink is process-wide: keep only rows from the thread that installed it.
    struct Rows(Mutex<Vec<crate::logging::LogEvent>>, std::thread::ThreadId);

    impl Default for Rows {
        fn default() -> Self {
            Self(Mutex::default(), std::thread::current().id())
        }
    }

    impl crate::logging::LogSink for Rows {
        fn record(&self, event: crate::logging::LogEvent) {
            if std::thread::current().id() == self.1 {
                self.0.lock().unwrap().push(event);
            }
        }
    }

    #[tokio::test]
    #[serial]
    async fn test_without_a_realm_a_synced_change_fails_with_one_row() {
        let rows = Arc::new(Rows::default());
        crate::logging::set_log_sink(rows.clone());
        let change = PasswordCommit {
            user: UserId::new("bob"),
            rows: Vec::new(),
            kind: LogKind::PasswordChange,
        };
        let answered = NoopKerberos::new("EXAMPLE.COM".to_owned())
            .commit_password(change, "Bob-Pass-1")
            .await;
        crate::logging::set_log_sink(Arc::new(crate::logging::NoopLogSink));
        let logged: Vec<_> = rows
            .0
            .lock()
            .unwrap()
            .iter()
            .map(|e| (e.kind, e.target.clone(), e.success, e.detail.clone()))
            .collect();
        assert_eq!(
            (answered, logged),
            (
                Err(CommitError::Failed(NO_COMMIT.to_owned())),
                vec![(
                    LogKind::PasswordChange,
                    Some("bob".to_owned()),
                    false,
                    Some(format!("password change failed: {NO_COMMIT}"))
                )]
            )
        );
    }

    #[tokio::test]
    async fn test_without_a_realm_a_user_change_is_the_directory_write_alone() {
        let change = || UserChange {
            user: UserId::new("bob"),
            step: UserStep::Delete,
            rows: vec![HostRow::DeleteUser(UserId::new("bob"))],
        };
        let realm = "EXAMPLE.COM".to_owned();
        let answers = [
            NoopKerberos::new(realm.clone()).commit_user(change()).await,
            DegradedKerberos::new(realm, "down".to_owned())
                .commit_user(change())
                .await,
        ];
        assert_eq!(answers, [None, None]);
        let enabled = [
            NoopKerberos::new("EXAMPLE.COM".to_owned()).enabled(),
            DegradedKerberos::new("EXAMPLE.COM".to_owned(), "down".to_owned()).enabled(),
        ];
        assert_eq!(
            enabled,
            [false, true],
            "only a disabled Kerberos is not enabled"
        );
        let steps = [
            UserStep::Delete,
            UserStep::SyncOff,
            UserStep::SyncOn,
            UserStep::DeleteWithoutSync,
            UserStep::SyncUnchanged,
            UserStep::Create,
            UserStep::Disable,
            UserStep::Enable,
        ];
        let ops: Vec<_> = steps
            .iter()
            .map(|step| (step.op(), step.touches_principal(), step.turns_sync_on()))
            .collect();
        assert_eq!(
            ops,
            [
                ("delete", true, false),
                ("sync off", true, false),
                ("sync on", true, true),
                ("delete", false, false),
                ("update", false, false),
                ("create", true, true),
                ("disable", true, false),
                ("enable", true, false)
            ]
        );
    }

    struct Up(bool);

    #[async_trait]
    impl KerberosSync for Up {
        fn ready(&self) -> bool {
            self.0
        }
        fn realm(&self) -> &str {
            "EXAMPLE.COM"
        }
        async fn delete_principal(&self, _: &UserId) -> Result<(), String> {
            unreachable!()
        }
        async fn set_principal_enabled(&self, _: &UserId, _: bool) -> Result<(), String> {
            unreachable!()
        }
        async fn export_keytab_for_keycloak(&self, _: &str) -> Result<String, String> {
            unreachable!()
        }
    }

    #[test]
    #[serial]
    fn test_disabled_is_its_own_state_and_never_not_ready() {
        let starting = "the Kerberos KDC is still starting; retry shortly";
        let rows: [(Arc<dyn KerberosSync>, KerberosState, bool); 4] = [
            (
                Arc::new(NoopKerberos::new("EXAMPLE.COM".to_owned())),
                KerberosState::Disabled,
                true,
            ),
            (
                Arc::new(DegradedKerberos::new(
                    "EXAMPLE.COM".to_owned(),
                    "down".to_owned(),
                )),
                KerberosState::NotReady("down".to_owned()),
                false,
            ),
            (
                Arc::new(Up(false)),
                KerberosState::NotReady(starting.to_owned()),
                false,
            ),
            (Arc::new(Up(true)), KerberosState::Ready, true),
        ];
        let mut got = Vec::new();
        for (backend, _, _) in &rows {
            set_kerberos_backend(backend.clone());
            got.push((kerberos_state(), require_kdc_ready().is_ok()));
        }
        set_kerberos_backend(Arc::new(NoopKerberos::default()));
        let want: Vec<_> = rows.into_iter().map(|(_, state, ok)| (state, ok)).collect();
        assert_eq!(got, want);
        assert_eq!(
            (
                NoopKerberos::default().ready(),
                while_disabled(SYNC_OFF_FIRST)
            ),
            (
                false,
                "Kerberos is disabled on this server (kerberos_options.enabled is false): enable \
                 Kerberos, or turn the user's Kerberos sync off first"
                    .to_owned()
            )
        );
    }

    struct Unsettled;

    #[async_trait]
    impl KerberosSync for Unsettled {
        fn unsettled(&self) -> Option<String> {
            Some(ANSWER_UNSETTLED.to_owned())
        }
        fn realm(&self) -> &str {
            "EXAMPLE.COM"
        }
        async fn delete_principal(&self, _: &UserId) -> Result<(), String> {
            unreachable!()
        }
        async fn set_principal_enabled(&self, _: &UserId, _: bool) -> Result<(), String> {
            unreachable!()
        }
        async fn export_keytab_for_keycloak(&self, _: &str) -> Result<String, String> {
            unreachable!()
        }
    }

    #[test]
    #[serial]
    fn test_an_unsettled_realm_is_held_and_refuses_only_a_change_to_both_stores() {
        let down = || KerberosState::NotReady("down".to_owned());
        let rows: [(Arc<dyn KerberosSync>, KerberosState, KerberosState, bool); 4] = [
            (
                Arc::new(NoopKerberos::new("EXAMPLE.COM".to_owned())),
                KerberosState::Disabled,
                KerberosState::Disabled,
                true,
            ),
            (
                Arc::new(DegradedKerberos::new(
                    "EXAMPLE.COM".to_owned(),
                    "down".to_owned(),
                )),
                down(),
                down(),
                false,
            ),
            (
                Arc::new(Up(true)),
                KerberosState::Ready,
                KerberosState::Ready,
                true,
            ),
            (
                Arc::new(Unsettled),
                KerberosState::Ready,
                KerberosState::NotReady(ANSWER_UNSETTLED.to_owned()),
                true,
            ),
        ];
        let mut got = Vec::new();
        for (backend, _, _, _) in &rows {
            set_kerberos_backend(backend.clone());
            got.push((
                kerberos_state(),
                settled_state(),
                require_kdc_ready().is_ok(),
            ));
        }
        let bob = UserId::new("bob");
        let refused = require_settled(LogKind::UserCreate, &bob).map_err(|e| e.to_string());
        set_kerberos_backend(Arc::new(NoopKerberos::default()));
        let want: Vec<_> = rows
            .into_iter()
            .map(|(_, held, settled, plain)| (held, settled, plain))
            .collect();
        assert_eq!(
            (got, refused),
            (
                want,
                Err(format!(
                    "Kerberos KDC unavailable: {ANSWER_UNSETTLED}; try again"
                ))
            ),
            "unsettled: held for directory writes, not settled for a change to both stores"
        );
    }

    #[test]
    fn test_turning_sync_on_names_the_rule() {
        let why = validate_kerberos_username("jürgen").unwrap_err();
        assert_eq!(
            sync_refused(&UserId::new("jürgen"), &why),
            "Kerberos sync cannot be turned on for user jürgen: Kerberos username must be \
             ASCII alphanumeric plus '.', '_' or '-'"
        );
    }

    #[test]
    fn test_user_id_for_principal_name() {
        assert_eq!(user_id_for_principal_name("alice"), Some("alice"));
        assert_eq!(user_id_for_principal_name("HTTP/kc.example.com"), None);
        assert_eq!(user_id_for_principal_name("krbtgt/REALM"), None);
    }

    #[test]
    fn test_domain_and_realm_from_base_dn() {
        assert_eq!(domain_from_base_dn("dc=gate,dc=test"), "gate.test");
        assert_eq!(domain_from_base_dn("dc=Example,dc=COM"), "example.com");
        assert_eq!(domain_from_base_dn("DC=Example, dc=COM"), "example.com");
        assert_eq!(
            domain_from_base_dn("ou=people,dc=example,dc=com"),
            "example.com"
        );
        assert_eq!(realm_from(None, "dc=gate,dc=test"), "GATE.TEST");
        assert_eq!(realm_from(Some(""), "dc=gate,dc=test"), "GATE.TEST");
        assert_eq!(
            realm_from(Some("custom.realm"), "dc=gate,dc=test"),
            "CUSTOM.REALM"
        );
    }

    #[test]
    fn test_username_validators() {
        for name in [
            "bob",
            "admin",
            "bob.smith",
            "bob_smith",
            "bob-1",
            &format!("user-{}", "a".repeat(60)),
        ] {
            assert_eq!(validate_kerberos_username(name), Ok(()), "{name}");
        }
        for name in [
            "",
            "bob/admin",
            "bob@realm",
            "bob principal",
            "bob\ndelprinc",
            "krbtgt",
            "KAdmin",
            "kiprop",
            "WELLKNOWN",
            "-leading",
            "has space",
        ] {
            assert!(
                validate_kerberos_username(name).is_err(),
                "expected {name:?} to be rejected"
            );
        }
        assert_eq!(
            validate_directory_username(r#"bob"e"i'o;aü"#),
            Ok(()),
            "SQL-injection fixture ids must still insert"
        );
        for name in ["krbtgt", "bob/admin", "bob@realm", "bob principal"] {
            assert!(
                validate_directory_username(name).is_err(),
                "expected {name:?} to be rejected"
            );
        }
    }

    #[test]
    fn test_validate_keytab_hostname() {
        for host in ["keycloak", "keycloak.example.com", "192.168.1.10"] {
            assert_eq!(validate_keytab_hostname(host), Ok(()), "{host}");
        }
        for host in [
            "",
            "foo\ndelprinc admin/admin",
            "foo; delprinc",
            "foo bar",
            "../etc",
            "foo/bar",
            "-leading",
            ".example.com",
            "example.com.",
        ] {
            assert!(
                validate_keytab_hostname(host).is_err(),
                "expected {host:?} to be rejected"
            );
        }
    }
}
