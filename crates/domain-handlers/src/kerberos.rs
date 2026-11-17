use crate::logging::{LogEvent, LogKind};
use async_trait::async_trait;
use lldap_domain::requests::CreateUserRequest;
use lldap_domain::types::UserId;
use lldap_domain_model::error::DomainError;
use std::sync::{Arc, LazyLock, RwLock};
use tracing::warn;

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
    fn realm(&self) -> &str;
    fn principal_name(&self, user: &UserId) -> String {
        format!("{}@{}", user.as_str(), self.realm())
    }
    async fn sync_principal(&self, user: &UserId, password: &str) -> Result<(), String>;
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
    async fn delete_principal(&self, user: &UserId) -> Result<(), String>;
    async fn set_principal_enabled(&self, user: &UserId, enabled: bool) -> Result<(), String>;
    async fn reassert_disabled(&self, user: &UserId) {
        if let Err(e) = self.set_principal_enabled(user, false).await {
            warn!("Failed to re-assert Kerberos disable for {user} after password set: {e}");
        }
    }
    async fn export_keytab_for_keycloak(&self, hostname: &str) -> Result<String, String>;
}

const NOT_REGISTERED: &str = "Kerberos backend not registered";
const NO_COMMIT: &str = "this Kerberos backend cannot commit a password";
const NO_HOST_ROWS: &str = "this Kerberos store writes no directory rows";

pub const USER_GONE: &str = "the user is gone";
/// A new principal name is a directory user's, or a case twin of one.
pub const DIRECTORY_USER: &str = "the name belongs to a directory user";
pub const DIRECTORY_TARGET: &str = "the alias's target belongs to a directory user";
/// Starts the Failed answer of a commit whose outcome could not be read back.
pub const UNREAD_AFTER_COMMIT: &str = "the result is unknown: the commit could not be read back";

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
}

pub type UserOf = Arc<dyn Fn(&str) -> Option<UserId> + Send + Sync>;

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

    pub fn label(&self) -> String {
        match self {
            Self::SetPassword { user, .. } => format!("password {user}"),
            Self::CreateUser(request) => format!("create {}", request.user_id),
            Self::Log(event) => format!("log {}", event.kind),
            Self::NoUser(users) => format!("no user {}", names(users)),
            Self::NoAliasOnto(onto) => format!("no alias onto {}", onto.targets.join(", ")),
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CommitError {
    Busy,
    Refused(String),
    UserGone,
    Failed(String),
    Unknown(String),
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
    fn realm(&self) -> &str {
        &self.realm
    }
    async fn sync_principal(&self, _: &UserId, _: &str) -> Result<(), String> {
        Err(NOT_REGISTERED.to_owned())
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
    async fn sync_principal(&self, _: &UserId, _: &str) -> Result<(), String> {
        Err(self.cause.clone())
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

pub fn kerberos_backend() -> Arc<dyn KerberosSync> {
    BACKEND.read().expect("kerberos backend").clone()
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
    /// `start`, then each row name its alias rows lead to, at most `hops` further.
    fn alias_chain(&self, _start: &str, _hops: usize) -> Result<Vec<String>, KerberosStoreError> {
        Err(KerberosStoreError::NotReady(NO_HOST_ROWS.to_owned()))
    }
    /// Sets `alias_target` where it is empty, by (row name, target); the records stay as they are.
    fn fill_alias_targets(&self, _rows: &[(String, String)]) -> Result<u64, KerberosStoreError> {
        Err(KerberosStoreError::NotReady(NO_HOST_ROWS.to_owned()))
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
    let backend = kerberos_backend();
    if backend.ready() {
        return Ok(());
    }
    Err(DomainError::KdcUnavailable(
        backend
            .unavailable()
            .unwrap_or_else(|| "the Kerberos KDC is still starting; retry shortly".to_owned()),
    ))
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
        let rows: [(HostRow, &str, bool); 5] = [
            (
                HostRow::SetPassword {
                    user: bob.clone(),
                    record: vec![0xAB; 8],
                    now,
                },
                "password bob",
                true,
            ),
            (
                HostRow::CreateUser(CreateUserRequest {
                    user_id: bob,
                    ..Default::default()
                }),
                "create bob",
                false,
            ),
            (
                HostRow::Log(event(LogKind::PasswordChange, Some("bob"), true, None)),
                "log password_change",
                false,
            ),
            (
                HostRow::NoUser(vec![UserId::new("Alice"), UserId::new("carol")]),
                "no user alice, carol",
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
            ),
        ];
        for (row, label, password) in rows {
            assert_eq!(
                (format!("{row:?}"), row.is_password()),
                (label.to_owned(), password)
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

    #[derive(Default)]
    struct Rows(Mutex<Vec<crate::logging::LogEvent>>);

    impl crate::logging::LogSink for Rows {
        fn record(&self, event: crate::logging::LogEvent) {
            self.0.lock().unwrap().push(event);
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
