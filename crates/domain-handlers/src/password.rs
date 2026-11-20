use crate::kerberos::{
    CREATE_WITHOUT_SYNC, CommitError, Held, HostRow, KerberosState, KerberosSync, PasswordCommit,
    SYNC_CHANGED, SYNC_OFF_FIRST, kerberos_backend, settled_state, settled_state_of,
    while_disabled,
};
use crate::logging::{self, LogKind};
use lldap_domain::requests::CreateUserRequest;
use lldap_domain::types::UserId;
use lldap_domain_model::error::DomainError;
use lldap_opaque_handler::registration::ClientRegistrationFinishRequest;
use lldap_opaque_handler::{OpaqueHandler, prepare_registration};
use tracing::warn;

pub const PASSWORD_CHANGE_IN_PROGRESS: &str = "a password change is in progress, try again";
pub const RESULT_UNKNOWN: &str = "the result is unknown: try the new password";
pub const ANSWER_LOST: &str = "the answer was lost; the change had committed";
pub const UNKNOWN_ROW: &str = "result unknown: the database did not answer";
pub const UNREPORTED_ROW: &str = "result unknown: the change did not report";
pub const PASSWORD_MIN_LENGTH: usize = 8;
pub const PASSWORD_TOO_SHORT: &str = "the password must be at least 8 characters";
pub const PASSWORD_HAS_NUL: &str = "the password must not contain a NUL character (U+0000)";
pub const PASSWORD_NEEDS_THE_REALM: &str =
    "a password is changed only by the server that holds the Kerberos realm; try again";

/// The directory's floor, in characters (Unicode scalar values), at every door.
pub fn long_enough(password: &str) -> bool {
    password.chars().count() >= PASSWORD_MIN_LENGTH
}

/// What every door asks of a new password: no NUL character, and the floor.
pub fn password_rules(password: &str) -> Result<(), PasswordChangeError> {
    if password.contains('\0') {
        return Err(PasswordChangeError::HasNul);
    }
    if !long_enough(password) {
        return Err(PasswordChangeError::TooShort);
    }
    Ok(())
}

#[cfg(feature = "kill-points")]
pub fn kill_point(name: &str) {
    if std::env::var("LLDAP_TEST_KILL_POINT").is_ok_and(|point| point == name) {
        std::process::abort();
    }
}

#[cfg(not(feature = "kill-points"))]
#[inline(always)]
pub fn kill_point(_: &str) {}

/// For tests: a password change of the armed user waits after its door's read of the switch.
#[cfg(feature = "test-hooks")]
pub mod pause {
    use lldap_domain::types::UserId;
    use std::sync::Mutex;
    use tokio::sync::oneshot;

    type Armed = (UserId, oneshot::Sender<()>, oneshot::Receiver<()>);
    static ARMED: Mutex<Option<Armed>> = Mutex::new(None);

    pub struct Paused {
        pub reached: oneshot::Receiver<()>,
        pub resume: oneshot::Sender<()>,
    }

    pub fn arm(user: &UserId) -> Paused {
        let (reached_tx, reached) = oneshot::channel();
        let (resume, resume_rx) = oneshot::channel();
        *ARMED.lock().unwrap_or_else(|e| e.into_inner()) =
            Some((user.clone(), reached_tx, resume_rx));
        Paused { reached, resume }
    }

    pub(crate) async fn here(user: &UserId) {
        let armed = {
            let mut armed = ARMED.lock().unwrap_or_else(|e| e.into_inner());
            match armed.as_ref() {
                Some((armed_for, _, _)) if armed_for == user => armed.take(),
                _ => None,
            }
        };
        if let Some((_, reached, resume)) = armed {
            let _ = reached.send(());
            let _ = resume.await;
        }
    }
}

#[cfg(not(feature = "test-hooks"))]
mod pause {
    pub(crate) async fn here(_: &lldap_domain::types::UserId) {}
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PasswordSync {
    Off,
    On,
}

impl PasswordSync {
    pub fn of(enabled: bool) -> Self {
        if enabled { Self::On } else { Self::Off }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PasswordChangeError {
    TooShort,
    HasNul,
    /// Kerberos refused the password or the name; nothing was written.
    Refused(String),
    InProgress,
    Unavailable(String),
    NoSuchUser,
    Failed(String),
    Unknown,
    SyncChanged,
    KerberosDisabled(String),
}

impl std::fmt::Display for PasswordChangeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooShort => f.write_str(PASSWORD_TOO_SHORT),
            Self::HasNul => f.write_str(PASSWORD_HAS_NUL),
            Self::Refused(reason) => write!(f, "refused by Kerberos: {reason}"),
            Self::InProgress => f.write_str(PASSWORD_CHANGE_IN_PROGRESS),
            Self::Unavailable(cause) => write!(f, "Kerberos KDC unavailable: {cause}"),
            Self::NoSuchUser => f.write_str("password change failed: no such user"),
            Self::Failed(cause) => write!(f, "password change failed: {cause}"),
            Self::Unknown => f.write_str(RESULT_UNKNOWN),
            Self::SyncChanged => f.write_str(SYNC_CHANGED),
            Self::KerberosDisabled(why) => f.write_str(why),
        }
    }
}

impl std::error::Error for PasswordChangeError {}

fn change_error(e: DomainError) -> PasswordChangeError {
    match e {
        DomainError::KdcUnavailable(cause) => PasswordChangeError::Unavailable(cause),
        e => PasswordChangeError::Failed(e.to_string()),
    }
}

fn commit_error(e: CommitError) -> PasswordChangeError {
    match e {
        CommitError::Busy => PasswordChangeError::InProgress,
        CommitError::Refused(reason) if reason == SYNC_CHANGED => PasswordChangeError::SyncChanged,
        CommitError::Refused(reason) => PasswordChangeError::Refused(reason),
        CommitError::UserGone => PasswordChangeError::NoSuchUser,
        CommitError::Failed(cause) => PasswordChangeError::Failed(cause),
        CommitError::Unknown(_) => PasswordChangeError::Unknown,
        CommitError::Unsettled(cause) => realm_not_ready(&cause),
    }
}

/// Written by the task that did the work, so a dropped caller still has its row.
pub fn record_commit_failure(kind: LogKind, user: &UserId, error: &CommitError) {
    if let CommitError::Unknown(cause) = error {
        warn!("A password change's result is unknown: {cause}");
    }
    record_failed(kind, user, &commit_error(error.clone()));
}

/// The row of a change whose task panicked or did not run.
pub fn record_unreported(kind: LogKind, user: &UserId, cause: &str) {
    warn!("A password change's result is unknown: {cause}");
    logging::record_failure(kind, Some(user.as_str()), UNREPORTED_ROW);
}

/// The one failure row of a refused change that named `user`.
pub fn record_failed(kind: LogKind, user: &UserId, error: &PasswordChangeError) {
    let detail = match error {
        PasswordChangeError::Unknown => UNKNOWN_ROW.to_owned(),
        e => e.to_string(),
    };
    logging::record_failure(kind, Some(user.as_str()), &detail);
}

pub fn realm_not_ready(cause: &str) -> PasswordChangeError {
    PasswordChangeError::Unavailable(format!("{cause}; {PASSWORD_NEEDS_THE_REALM}"))
}

fn realm_ready(kind: LogKind, user: &UserId) -> Result<(), PasswordChangeError> {
    let KerberosState::NotReady(cause) = settled_state() else {
        return Ok(());
    };
    Err(refused_with_row(kind, user, realm_not_ready(&cause)))
}

fn refused_with_row(kind: LogKind, user: &UserId, e: PasswordChangeError) -> PasswordChangeError {
    record_failed(kind, user, &e);
    e
}

/// With kerberossync on, the directory record and the KDC keys change in one transaction, or
/// neither does. With it off, this is the directory write alone.
pub async fn change_password_everywhere(
    handler: &(impl OpaqueHandler + ?Sized),
    user: &UserId,
    password: &str,
    sync: PasswordSync,
) -> Result<(), PasswordChangeError> {
    if sync == PasswordSync::Off {
        let kind = LogKind::PasswordChange;
        realm_ready(kind, user)?;
        password_rules(password).map_err(|e| refused_with_row(kind, user, e))?;
        let (_, request) = prepare_registration(handler, user.clone(), password.as_bytes())
            .await
            .map_err(|e| refused_with_row(kind, user, change_error(e)))?;
        return finish_plain(handler, user, request).await.map(drop);
    }
    commit_synced(handler, user, password, None).await
}

/// The one write of a password the switch keeps plain: upstream's `registration_finish`, held.
pub async fn finish_plain(
    handler: &(impl OpaqueHandler + ?Sized),
    user: &UserId,
    request: ClientRegistrationFinishRequest,
) -> Result<UserId, PasswordChangeError> {
    let kind = LogKind::PasswordChange;
    realm_ready(kind, user)?;
    let _held = hold_plain(user).await?;
    handler
        .registration_finish(request)
        .await
        .map_err(|e| refused_with_row(kind, user, change_error(e)))
}

/// After a door read the switch off: refused with `SyncChanged` if it is on under the realm's lock.
pub async fn hold_plain(user: &UserId) -> Result<Option<Held>, PasswordChangeError> {
    pause::here(user).await;
    kerberos_backend().hold_plain(user).await.map_err(|e| {
        let refused = commit_error(e);
        record_failed(LogKind::PasswordChange, user, &refused);
        refused
    })
}

/// The web and tool finish of a synced user: the server registers the opened password itself.
pub async fn finish_synced_registration(
    handler: &(impl OpaqueHandler + ?Sized),
    user: &UserId,
    password: &str,
) -> Result<(), PasswordChangeError> {
    change_password_everywhere(handler, user, password, PasswordSync::On).await
}

/// An LDAP Add with a password for a synced user: the user, its record and its principal in one
/// transaction, or nothing.
pub async fn create_synced_user(
    handler: &(impl OpaqueHandler + ?Sized),
    request: CreateUserRequest,
    password: &str,
) -> Result<(), PasswordChangeError> {
    let user = request.user_id.clone();
    commit_synced(handler, &user, password, Some(request)).await
}

async fn commit_synced(
    handler: &(impl OpaqueHandler + ?Sized),
    user: &UserId,
    password: &str,
    create: Option<CreateUserRequest>,
) -> Result<(), PasswordChangeError> {
    pause::here(user).await;
    let kind = match create {
        Some(_) => LogKind::UserCreate,
        None => LogKind::PasswordChange,
    };
    let kerberos = kerberos_backend();
    let answer = match prepare_change(handler, &*kerberos, user, password, create).await {
        Ok(rows) => {
            let change = PasswordCommit {
                user: user.clone(),
                rows,
                kind,
            };
            kerberos.commit_password(change, password).await
        }
        Err(e) => {
            record_failed(kind, user, &e);
            return Err(e);
        }
    };
    match answer {
        Ok(()) => Ok(()),
        Err(CommitError::Busy) => {
            record_failed(kind, user, &PasswordChangeError::InProgress);
            Err(PasswordChangeError::InProgress)
        }
        Err(e) => Err(commit_error(e)),
    }
}

async fn prepare_change(
    handler: &(impl OpaqueHandler + ?Sized),
    kerberos: &dyn KerberosSync,
    user: &UserId,
    password: &str,
    create: Option<CreateUserRequest>,
) -> Result<Vec<HostRow>, PasswordChangeError> {
    match settled_state_of(kerberos) {
        KerberosState::Disabled => return Err(disabled_answer(create.is_some())),
        KerberosState::NotReady(cause) => return Err(realm_not_ready(&cause)),
        KerberosState::Ready => {}
    }
    password_rules(password)?;
    kerberos
        .check_password(user, password)
        .await
        .map_err(PasswordChangeError::Refused)?;
    let (record, _) = prepare_registration(handler, user.clone(), password.as_bytes())
        .await
        .map_err(change_error)?;
    kill_point("opaque-prepared");
    Ok(host_rows(user, &record, create))
}

fn disabled_answer(create: bool) -> PasswordChangeError {
    PasswordChangeError::KerberosDisabled(match create {
        true => CREATE_WITHOUT_SYNC.to_owned(),
        false => while_disabled(SYNC_OFF_FIRST),
    })
}

fn host_rows(user: &UserId, record: &[u8], create: Option<CreateUserRequest>) -> Vec<HostRow> {
    let target = Some(user.as_str());
    let mut rows = Vec::new();
    let mut logged = Vec::new();
    if let Some(request) = create {
        rows.push(HostRow::CreateUser(request));
        logged.push(logging::event(LogKind::UserCreate, target, true, None));
    }
    rows.push(HostRow::SetPassword {
        user: user.clone(),
        record: record.to_vec(),
        now: chrono::Utc::now().naive_utc(),
    });
    rows.push(HostRow::SyncIs(user.clone(), true));
    logged.push(logging::event(LogKind::PasswordChange, target, true, None));
    rows.extend(logged.into_iter().map(HostRow::Log));
    rows
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_each_commit_answer_and_its_text() {
        type Row = (CommitError, PasswordChangeError, &'static str);
        let rows: [Row; 6] = [
            (
                CommitError::Busy,
                PasswordChangeError::InProgress,
                PASSWORD_CHANGE_IN_PROGRESS,
            ),
            (
                CommitError::Refused("password policy: min_length 40".to_owned()),
                PasswordChangeError::Refused("password policy: min_length 40".to_owned()),
                "refused by Kerberos: password policy: min_length 40",
            ),
            (
                CommitError::Refused(SYNC_CHANGED.to_owned()),
                PasswordChangeError::SyncChanged,
                "the user's Kerberos sync changed; try again",
            ),
            (
                CommitError::UserGone,
                PasswordChangeError::NoSuchUser,
                "password change failed: no such user",
            ),
            (
                CommitError::Failed("the generation moved".to_owned()),
                PasswordChangeError::Failed("the generation moved".to_owned()),
                "password change failed: the generation moved",
            ),
            (
                CommitError::Unknown("the database did not answer".to_owned()),
                PasswordChangeError::Unknown,
                RESULT_UNKNOWN,
            ),
        ];
        for (answer, error, text) in rows {
            let got = commit_error(answer);
            assert_eq!((got.to_string(), got), (text.to_owned(), error));
        }
        assert_eq!(
            change_error(DomainError::KdcUnavailable("starting".to_owned())),
            PasswordChangeError::Unavailable("starting".to_owned())
        );
    }

    #[test]
    fn test_the_rows_of_a_change_and_of_an_add() {
        let bob = UserId::new("bob");
        let request = CreateUserRequest {
            user_id: bob.clone(),
            ..Default::default()
        };
        type Row = (Option<CreateUserRequest>, Vec<&'static str>);
        let rows: [Row; 2] = [
            (
                None,
                vec!["password bob", "synced bob", "log password_change"],
            ),
            (
                Some(request),
                vec![
                    "create bob",
                    "password bob",
                    "synced bob",
                    "log user_create",
                    "log password_change",
                ],
            ),
        ];
        for (create, expected) in rows {
            let rows = host_rows(&bob, b"record", create);
            let labels: Vec<_> = rows.iter().map(HostRow::label).collect();
            assert_eq!(labels, expected);
            assert!(rows.iter().all(|row| match row {
                HostRow::Log(event) => event.success && event.detail.is_none(),
                _ => true,
            }));
        }
    }

    struct Untouched;

    #[async_trait::async_trait]
    impl OpaqueHandler for Untouched {
        async fn login_start(
            &self,
            _: lldap_opaque_handler::login::ClientLoginStartRequest,
        ) -> lldap_domain_model::error::Result<lldap_opaque_handler::login::ServerLoginStartResponse>
        {
            unreachable!("a short password reached the directory")
        }
        async fn login_finish(
            &self,
            _: lldap_opaque_handler::login::ClientLoginFinishRequest,
        ) -> lldap_domain_model::error::Result<lldap_domain::types::LoginOutcome> {
            unreachable!("a short password reached the directory")
        }
        async fn registration_start(
            &self,
            _: lldap_opaque_handler::registration::ClientRegistrationStartRequest,
        ) -> lldap_domain_model::error::Result<
            lldap_opaque_handler::registration::ServerRegistrationStartResponse,
        > {
            unreachable!("a short password reached the directory")
        }
        async fn registration_finish(
            &self,
            _: lldap_opaque_handler::registration::ClientRegistrationFinishRequest,
        ) -> lldap_domain_model::error::Result<UserId> {
            unreachable!("a short password reached the directory")
        }
        async fn registration_user(
            &self,
            _: &lldap_opaque_handler::registration::ClientRegistrationFinishRequest,
        ) -> lldap_domain_model::error::Result<UserId> {
            unreachable!("a short password reached the directory")
        }
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn test_a_password_the_rules_refuse_is_refused_before_anything_at_each_door() {
        use crate::kerberos::{NoopKerberos, set_kerberos_backend};
        set_kerberos_backend(std::sync::Arc::new(Starting(true)));
        let bob = UserId::new("bob");
        let refusals = [
            ("pässwör", PasswordChangeError::TooShort),
            ("a\0aaaaaaa", PasswordChangeError::HasNul),
        ];
        for (password, refused) in refusals {
            let rows = std::sync::Arc::new(Rows::default());
            logging::set_log_sink(rows.clone());
            let off =
                change_password_everywhere(&Untouched, &bob, password, PasswordSync::Off).await;
            let on = change_password_everywhere(&Untouched, &bob, password, PasswordSync::On).await;
            let web = finish_synced_registration(&Untouched, &bob, password).await;
            let request = CreateUserRequest {
                user_id: bob.clone(),
                ..Default::default()
            };
            let add = create_synced_user(&Untouched, request, password).await;
            logging::set_log_sink(std::sync::Arc::new(logging::NoopLogSink));
            let logged: Vec<_> = rows
                .0
                .lock()
                .unwrap()
                .iter()
                .map(|e| (e.kind, e.target.clone(), e.success, e.detail.clone()))
                .collect();
            let row = |kind| {
                (
                    kind,
                    Some("bob".to_owned()),
                    false,
                    Some(refused.to_string()),
                )
            };
            let answer = || Err(refused.clone());
            assert_eq!(
                (off, on, web, add),
                (answer(), answer(), answer(), answer()),
                "{password:?}"
            );
            assert_eq!(
                logged,
                vec![
                    row(LogKind::PasswordChange),
                    row(LogKind::PasswordChange),
                    row(LogKind::PasswordChange),
                    row(LogKind::UserCreate),
                ],
                "{password:?}"
            );
        }
        set_kerberos_backend(std::sync::Arc::new(NoopKerberos::default()));
        assert_eq!(
            (
                PasswordChangeError::TooShort.to_string(),
                PasswordChangeError::HasNul.to_string()
            ),
            (
                "the password must be at least 8 characters".to_owned(),
                "the password must not contain a NUL character (U+0000)".to_owned()
            )
        );
    }

    struct Unstarted;

    #[async_trait::async_trait]
    impl OpaqueHandler for Unstarted {
        async fn login_start(
            &self,
            _: lldap_opaque_handler::login::ClientLoginStartRequest,
        ) -> lldap_domain_model::error::Result<lldap_opaque_handler::login::ServerLoginStartResponse>
        {
            unreachable!()
        }
        async fn login_finish(
            &self,
            _: lldap_opaque_handler::login::ClientLoginFinishRequest,
        ) -> lldap_domain_model::error::Result<lldap_domain::types::LoginOutcome> {
            unreachable!()
        }
        async fn registration_start(
            &self,
            _: lldap_opaque_handler::registration::ClientRegistrationStartRequest,
        ) -> lldap_domain_model::error::Result<
            lldap_opaque_handler::registration::ServerRegistrationStartResponse,
        > {
            Err(DomainError::InternalError("no start".to_owned()))
        }
        async fn registration_finish(
            &self,
            _: lldap_opaque_handler::registration::ClientRegistrationFinishRequest,
        ) -> lldap_domain_model::error::Result<UserId> {
            unreachable!("nothing was derived")
        }
        async fn registration_user(
            &self,
            _: &lldap_opaque_handler::registration::ClientRegistrationFinishRequest,
        ) -> lldap_domain_model::error::Result<UserId> {
            unreachable!()
        }
    }

    struct Starting(bool);

    #[async_trait::async_trait]
    impl KerberosSync for Starting {
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

    #[tokio::test]
    #[serial_test::serial]
    async fn test_a_synced_finish_asks_for_the_kdc_before_the_rules() {
        use crate::kerberos::{NoopKerberos, set_kerberos_backend};
        set_kerberos_backend(std::sync::Arc::new(Starting(false)));
        let bob = UserId::new("bob");
        let short = finish_synced_registration(&Untouched, &bob, "Short-7").await;
        let nul = finish_synced_registration(&Untouched, &bob, "a\0aaaaaaa").await;
        set_kerberos_backend(std::sync::Arc::new(NoopKerberos::default()));
        let starting = || {
            Err(realm_not_ready(
                "the Kerberos KDC is still starting; retry shortly",
            ))
        };
        assert_eq!((short, nul), (starting(), starting()));
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn test_with_kerberos_enabled_a_plain_change_needs_a_ready_realm() {
        use crate::kerberos::{DegradedKerberos, NoopKerberos, set_kerberos_backend};
        use std::sync::Arc;
        let bob = UserId::new("bob");
        let web = Deriving(
            lldap_auth::opaque::server::generate_random_private_key(),
            None,
        );
        let (_, upload) = prepare_registration(&web, bob.clone(), b"Eight-88")
            .await
            .unwrap();
        let rows = Arc::new(Rows::default());
        logging::set_log_sink(rows.clone());
        let starting = "the Kerberos KDC is still starting; retry shortly";
        let backends: [(Arc<dyn KerberosSync>, &str); 2] = [
            (Arc::new(Starting(false)), starting),
            (
                Arc::new(DegradedKerberos::new(
                    "EXAMPLE.COM".to_owned(),
                    "down".to_owned(),
                )),
                "down",
            ),
        ];
        let mut got = Vec::new();
        let mut want = Vec::new();
        for (backend, cause) in backends {
            set_kerberos_backend(backend);
            let door =
                change_password_everywhere(&Untouched, &bob, "Short-7", PasswordSync::Off).await;
            let finish = finish_plain(&web, &bob, upload.clone()).await;
            got.push((door, finish.map(drop)));
            want.push((Err(realm_not_ready(cause)), Err(realm_not_ready(cause))));
        }
        set_kerberos_backend(Arc::new(NoopKerberos::default()));
        logging::set_log_sink(Arc::new(logging::NoopLogSink));
        let logged: Vec<_> = rows
            .0
            .lock()
            .unwrap()
            .iter()
            .map(|e| (e.kind, e.success, e.detail.clone().unwrap_or_default()))
            .collect();
        let row = |cause| {
            (
                LogKind::PasswordChange,
                false,
                realm_not_ready(cause).to_string(),
            )
        };
        assert_eq!(
            (got, logged),
            (
                want,
                vec![row(starting), row(starting), row("down"), row("down")]
            ),
            "refused before the rules, the derive and the store, one row each"
        );
        assert_eq!(
            realm_not_ready("down").to_string(),
            "Kerberos KDC unavailable: down; a password is changed only by the server that holds \
             the Kerberos realm; try again"
        );
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn test_a_plain_change_whose_derive_or_store_fails_writes_one_row() {
        use crate::kerberos::{NoopKerberos, set_kerberos_backend};
        use std::sync::Arc;
        let bob = UserId::new("bob");
        let rows = Arc::new(Rows::default());
        logging::set_log_sink(rows.clone());
        set_kerberos_backend(Arc::new(Holding(None)));
        let key = lldap_auth::opaque::server::generate_random_private_key;
        let stored = Deriving(key(), Some("the disk is full"));
        let store = change_password_everywhere(&stored, &bob, "Eight-88", PasswordSync::Off).await;
        let derive =
            change_password_everywhere(&Unstarted, &bob, "Eight-88", PasswordSync::Off).await;
        set_kerberos_backend(Arc::new(NoopKerberos::default()));
        logging::set_log_sink(Arc::new(logging::NoopLogSink));
        let logged: Vec<_> = rows
            .0
            .lock()
            .unwrap()
            .iter()
            .map(|e| (e.kind, e.success, e.detail.clone().unwrap_or_default()))
            .collect();
        let failed = |why: &str| PasswordChangeError::Failed(format!("Internal error: `{why}`"));
        let row = |why: &str| (LogKind::PasswordChange, false, failed(why).to_string());
        assert_eq!(
            ((store, derive), logged),
            (
                (Err(failed("the disk is full")), Err(failed("no start"))),
                vec![row("the disk is full"), row("no start")]
            )
        );
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn test_with_kerberos_disabled_a_synced_change_names_the_way_on() {
        let bob = UserId::new("bob");
        let rows = std::sync::Arc::new(Rows::default());
        logging::set_log_sink(rows.clone());
        let request = || CreateUserRequest {
            user_id: bob.clone(),
            ..Default::default()
        };
        let answers = [
            finish_synced_registration(&Untouched, &bob, "Eight-88").await,
            change_password_everywhere(&Untouched, &bob, "Short-7", PasswordSync::On).await,
            create_synced_user(&Untouched, request(), "Eight-88").await,
            create_synced_user(&Untouched, request(), "a\0aaaaaaa").await,
        ];
        logging::set_log_sink(std::sync::Arc::new(logging::NoopLogSink));
        let both_ways = "Kerberos is disabled on this server (kerberos_options.enabled is false): \
                         enable Kerberos, or turn the user's Kerberos sync off first";
        let create = "Kerberos is disabled; create the user without Kerberos sync";
        let refused = |text: &str| Err(PasswordChangeError::KerberosDisabled(text.to_owned()));
        assert_eq!(
            answers,
            [
                refused(both_ways),
                refused(both_ways),
                refused(create),
                refused(create)
            ]
        );
        let logged: Vec<_> = rows
            .0
            .lock()
            .unwrap()
            .iter()
            .map(|e| (e.kind, e.success, e.detail.clone().unwrap_or_default()))
            .collect();
        let row = |kind, text: &str| (kind, false, text.to_owned());
        assert_eq!(
            logged,
            vec![
                row(LogKind::PasswordChange, both_ways),
                row(LogKind::PasswordChange, both_ways),
                row(LogKind::UserCreate, create),
                row(LogKind::UserCreate, create),
            ]
        );
    }

    struct Deriving(
        lldap_auth::opaque::server::ServerSetup,
        Option<&'static str>,
    );

    #[async_trait::async_trait]
    impl OpaqueHandler for Deriving {
        async fn login_start(
            &self,
            _: lldap_opaque_handler::login::ClientLoginStartRequest,
        ) -> lldap_domain_model::error::Result<lldap_opaque_handler::login::ServerLoginStartResponse>
        {
            unreachable!()
        }
        async fn login_finish(
            &self,
            _: lldap_opaque_handler::login::ClientLoginFinishRequest,
        ) -> lldap_domain_model::error::Result<lldap_domain::types::LoginOutcome> {
            unreachable!()
        }
        async fn registration_start(
            &self,
            request: lldap_opaque_handler::registration::ClientRegistrationStartRequest,
        ) -> lldap_domain_model::error::Result<
            lldap_opaque_handler::registration::ServerRegistrationStartResponse,
        > {
            let start = lldap_auth::opaque::server::registration::start_registration(
                &self.0,
                request.registration_start_request,
                &request.username,
            )?;
            Ok(
                lldap_opaque_handler::registration::ServerRegistrationStartResponse {
                    server_data: String::new(),
                    registration_response: start.message,
                },
            )
        }
        async fn registration_finish(
            &self,
            _: lldap_opaque_handler::registration::ClientRegistrationFinishRequest,
        ) -> lldap_domain_model::error::Result<UserId> {
            match self.1 {
                Some(why) => Err(DomainError::InternalError(why.to_owned())),
                None => unreachable!("the record was stored although the switch is on"),
            }
        }
        async fn registration_user(
            &self,
            _: &lldap_opaque_handler::registration::ClientRegistrationFinishRequest,
        ) -> lldap_domain_model::error::Result<UserId> {
            unreachable!()
        }
    }

    struct Holding(Option<CommitError>);

    #[async_trait::async_trait]
    impl KerberosSync for Holding {
        fn realm(&self) -> &str {
            "EXAMPLE.COM"
        }
        async fn hold_plain(&self, _: &UserId) -> Result<Option<Held>, CommitError> {
            self.0.clone().map_or(Ok(None), Err)
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

    #[tokio::test]
    #[serial_test::serial]
    async fn test_a_plain_change_is_refused_when_the_switch_turned_on() {
        use crate::kerberos::{NoopKerberos, set_kerberos_backend};
        let bob = UserId::new("bob");
        let rows = std::sync::Arc::new(Rows::default());
        logging::set_log_sink(rows.clone());
        let mut answers = Vec::new();
        for held in [
            CommitError::Refused(SYNC_CHANGED.to_owned()),
            CommitError::Busy,
        ] {
            set_kerberos_backend(std::sync::Arc::new(Holding(Some(held))));
            let handler = Deriving(
                lldap_auth::opaque::server::generate_random_private_key(),
                None,
            );
            let off = change_password_everywhere(&handler, &bob, "Eight-88", PasswordSync::Off);
            answers.push(off.await);
        }
        set_kerberos_backend(std::sync::Arc::new(NoopKerberos::default()));
        logging::set_log_sink(std::sync::Arc::new(logging::NoopLogSink));
        let logged: Vec<_> = rows
            .0
            .lock()
            .unwrap()
            .iter()
            .map(|e| (e.kind, e.success, e.detail.clone().unwrap_or_default()))
            .collect();
        assert_eq!(
            (answers, logged),
            (
                vec![
                    Err(PasswordChangeError::SyncChanged),
                    Err(PasswordChangeError::InProgress)
                ],
                vec![
                    (LogKind::PasswordChange, false, SYNC_CHANGED.to_owned()),
                    (
                        LogKind::PasswordChange,
                        false,
                        PASSWORD_CHANGE_IN_PROGRESS.to_owned()
                    ),
                ]
            )
        );
    }

    #[test]
    fn test_the_rules_refuse_a_nul_anywhere_and_then_count_characters() {
        let rows = [
            ("Eight-88", Ok(())),
            ("pässwörd", Ok(())),
            ("pässwör", Err(PasswordChangeError::TooShort)),
            ("a\0aaaaaaa", Err(PasswordChangeError::HasNul)),
            ("Eight-88\0", Err(PasswordChangeError::HasNul)),
            ("\0", Err(PasswordChangeError::HasNul)),
        ];
        let got: Vec<_> = rows
            .iter()
            .map(|(text, _)| (*text, password_rules(text)))
            .collect();
        assert_eq!(got, rows.to_vec());
        assert_eq!(
            "a\0aaaaaaa".chars().count(),
            9,
            "the NUL row passes the floor alone"
        );
    }

    #[test]
    fn test_the_floor_counts_characters() {
        let rows = [
            ("", false),
            ("Short-7", false),
            ("pässwör", false),
            ("Eight-88", true),
            ("pässwörd", true),
            ("ÄÖÜäöüßé", true),
        ];
        let got: Vec<_> = rows
            .iter()
            .map(|(text, _)| (*text, long_enough(text)))
            .collect();
        assert_eq!(got, rows.to_vec());
        assert_eq!(("pässwör".len(), PASSWORD_MIN_LENGTH), (9, 8));
    }

    #[test]
    fn test_sync_off_and_on() {
        assert_eq!(
            (PasswordSync::of(false), PasswordSync::of(true)),
            (PasswordSync::Off, PasswordSync::On)
        );
    }

    struct Rows(
        std::sync::Mutex<Vec<logging::LogEvent>>,
        std::thread::ThreadId,
    );

    impl Default for Rows {
        fn default() -> Self {
            Self(Default::default(), std::thread::current().id())
        }
    }

    impl logging::LogSink for Rows {
        fn record(&self, event: logging::LogEvent) {
            if std::thread::current().id() == self.1 {
                self.0.lock().unwrap().push(event);
            }
        }
    }

    #[test]
    #[serial_test::serial]
    fn test_an_unknown_result_is_logged_as_unknown_never_as_failed() {
        let rows = std::sync::Arc::new(Rows::default());
        logging::set_log_sink(rows.clone());
        let bob = UserId::new("bob");
        let unknown = CommitError::Unknown("the database did not answer".to_owned());
        record_commit_failure(LogKind::PasswordChange, &bob, &unknown);
        let failed = CommitError::Failed("the generation moved".to_owned());
        record_commit_failure(LogKind::PasswordChange, &bob, &failed);
        logging::set_log_sink(std::sync::Arc::new(logging::NoopLogSink));
        assert_eq!(commit_error(unknown).to_string(), RESULT_UNKNOWN);
        let details: Vec<_> = rows
            .0
            .lock()
            .unwrap()
            .iter()
            .map(|e| (e.success, e.detail.clone().unwrap_or_default()))
            .collect();
        assert_eq!(
            details,
            vec![
                (false, UNKNOWN_ROW.to_owned()),
                (
                    false,
                    "password change failed: the generation moved".to_owned()
                ),
            ]
        );
        assert!(!UNKNOWN_ROW.contains("failed"));
    }
}
