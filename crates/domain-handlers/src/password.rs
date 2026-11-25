use crate::enforcement::POLICY_UNANSWERED;
use crate::handler::PolicyBackendHandler;
use crate::instant::Timestamp;
use crate::kerberos::{
    CREATE_WITHOUT_SYNC, CommitError, Held, HostRow, KerberosState, KerberosSync, PasswordCommit,
    SYNC_CHANGED, SYNC_OFF_FIRST, kerberos_backend, plain_password_refused, refusal_row,
    refusal_text, settled_state_of, while_disabled,
};
use crate::logging::{self, LogKind};
use crate::policies::{
    EffectiveItem, POLICY_ITEM_CATALOG, POLICY_READ_WAIT, Setting, canonical_ou_key, resolve,
    resolve_effective_items,
};
pub use lldap_auth::{
    PASSWORD_HAS_NUL, PASSWORD_LENGTH_UNIT, PASSWORD_MIN_LENGTH, PasswordShapeError,
    password_length, password_shape,
};
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
pub const PASSWORD_MIN_LENGTH_CAP: usize = 128;
pub const PASSWORD_MIN_LENGTH_ITEM: &str = "password-min-length";
pub const PASSWORD_POLICY_UNREADABLE: &str = "the password policy could not be read; try again";
pub const PASSWORD_NEEDS_THE_REALM: &str =
    "a password is changed only by the server that holds the Kerberos realm; try again";
pub const REGISTRATION_UNFINISHABLE: &str = "this registration cannot be finished; start again";

const MIN_LENGTH_NOT_A_NUMBER: &str = "the stored password-min-length is not a number";

pub struct PasswordMinLength;

impl Setting for PasswordMinLength {
    type Value = Option<usize>;
    const KEY: &'static str = PASSWORD_MIN_LENGTH_ITEM;
    fn parse(value: &str) -> Option<usize> {
        let (floor, cap) = (PASSWORD_MIN_LENGTH as i64, PASSWORD_MIN_LENGTH_CAP as i64);
        let value = value.trim();
        let (beyond, digits) = match value.strip_prefix('-') {
            Some(digits) => (floor, digits),
            None => (cap, value.strip_prefix('+').unwrap_or(value)),
        };
        let whole = !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit());
        let min = value.parse::<i64>().ok().or(whole.then_some(beyond))?;
        Some(min.clamp(floor, cap) as usize)
    }
}

/// What every door asks of a new password: no NUL character, and the floor.
pub fn password_rules(password: &str, min: usize) -> Result<(), PasswordChangeError> {
    let min = min.max(PASSWORD_MIN_LENGTH);
    password_shape(password, min).map_err(|e| match e {
        PasswordShapeError::HasNul => PasswordChangeError::HasNul,
        PasswordShapeError::Empty | PasswordShapeError::TooShort(_) => {
            PasswordChangeError::TooShort(min)
        }
    })
}

pub async fn min_length_of(
    handler: &(impl PolicyBackendHandler + ?Sized),
    user: &UserId,
) -> Result<usize, PasswordChangeError> {
    min_length_for_user(handler, user).await.map_err(|e| {
        warn!("The password policy of {user} could not be read: {e}");
        let refused = PasswordChangeError::PolicyUnreadable;
        refused_with_row(LogKind::PasswordChange, user, refused)
    })
}

pub async fn min_length_in_ou(
    handler: &(impl PolicyBackendHandler + ?Sized),
    ou: &str,
    user: &UserId,
    kind: LogKind,
) -> Result<usize, PasswordChangeError> {
    let ou_key = canonical_ou_key(ou);
    min_length_for_ou_key(handler, &ou_key).await.map_err(|e| {
        warn!("The password policy of OU {ou} for {user} could not be read: {e}");
        refused_with_row(kind, user, PasswordChangeError::PolicyUnreadable)
    })
}

/// The user's minimum, 8 for a user the directory does not have.
pub async fn min_length_for_user(
    handler: &(impl PolicyBackendHandler + ?Sized),
    user: &UserId,
) -> Result<usize, DomainError> {
    let levels = match within_the_bound(handler.bounded_policy_entry(user)).await {
        Err(DomainError::EntityNotFound(_)) => Vec::new(),
        entry => entry?.1,
    };
    min_length_in(&resolve_effective_items(POLICY_ITEM_CATALOG, &levels))
}

pub async fn min_length_for_ou_key(
    handler: &(impl PolicyBackendHandler + ?Sized),
    ou_key: &str,
) -> Result<usize, DomainError> {
    let levels = within_the_bound(handler.bounded_policy_levels(ou_key)).await?;
    min_length_in(&resolve_effective_items(POLICY_ITEM_CATALOG, &levels))
}

async fn within_the_bound<T>(
    read: impl std::future::Future<Output = Result<T, DomainError>>,
) -> Result<T, DomainError> {
    let unanswered = || DomainError::InternalError(POLICY_UNANSWERED.to_owned());
    tokio::time::timeout(POLICY_READ_WAIT, read)
        .await
        .map_err(|_| unanswered())?
}

pub fn min_length_in(items: &[EffectiveItem]) -> Result<usize, DomainError> {
    let min = resolve::<PasswordMinLength>(None, items).0;
    min.ok_or_else(|| DomainError::InternalError(MIN_LENGTH_NOT_A_NUMBER.to_owned()))
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
    TooShort(usize),
    HasNul,
    PolicyUnreadable,
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
            Self::TooShort(min) => write!(f, "{}", PasswordShapeError::TooShort(*min)),
            Self::HasNul => f.write_str(PASSWORD_HAS_NUL),
            Self::PolicyUnreadable => f.write_str(PASSWORD_POLICY_UNREADABLE),
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
        DomainError::InternalError(why) if why == SYNC_CHANGED => PasswordChangeError::SyncChanged,
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
        e => refusal_row(e.to_string()),
    };
    logging::record_failure(kind, Some(user.as_str()), &detail);
}

/// The one answer and row of a web or tool finish refused before its envelope is opened.
pub fn refuse_unfinishable(user: &UserId) -> DomainError {
    let target = Some(user.as_str());
    logging::record_failure(LogKind::PasswordChange, target, REGISTRATION_UNFINISHABLE);
    DomainError::AuthenticationError(REGISTRATION_UNFINISHABLE.to_owned())
}

pub fn realm_not_ready(cause: &str) -> PasswordChangeError {
    PasswordChangeError::Unavailable(refusal_text(cause, PASSWORD_NEEDS_THE_REALM))
}

fn realm_ready(kind: LogKind, user: &UserId) -> Result<(), PasswordChangeError> {
    let Some(cause) = plain_password_refused() else {
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
    min: usize,
) -> Result<(), PasswordChangeError> {
    if sync == PasswordSync::Off {
        let kind = LogKind::PasswordChange;
        realm_ready(kind, user)?;
        password_rules(password, min).map_err(|e| refused_with_row(kind, user, e))?;
        let (_, request) = prepare_registration(handler, user.clone(), password.as_bytes())
            .await
            .map_err(|e| refused_with_row(kind, user, change_error(e)))?;
        return finish_plain(handler, user, request).await.map(drop);
    }
    commit_synced(handler, user, password, None, min).await
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
    min: usize,
) -> Result<(), PasswordChangeError> {
    change_password_everywhere(handler, user, password, PasswordSync::On, min).await
}

/// An LDAP Add with a password for a synced user: the user, its record and its principal in one
/// transaction, or nothing.
pub async fn create_synced_user(
    handler: &(impl OpaqueHandler + ?Sized),
    request: CreateUserRequest,
    password: &str,
    min: usize,
) -> Result<(), PasswordChangeError> {
    let user = request.user_id.clone();
    commit_synced(handler, &user, password, Some(request), min).await
}

async fn commit_synced(
    handler: &(impl OpaqueHandler + ?Sized),
    user: &UserId,
    password: &str,
    create: Option<CreateUserRequest>,
    min: usize,
) -> Result<(), PasswordChangeError> {
    pause::here(user).await;
    let kind = match create {
        Some(_) => LogKind::UserCreate,
        None => LogKind::PasswordChange,
    };
    let kerberos = kerberos_backend();
    let answer = match prepare_change(handler, &*kerberos, user, password, create, min).await {
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
    min: usize,
) -> Result<Vec<HostRow>, PasswordChangeError> {
    match settled_state_of(kerberos) {
        KerberosState::Disabled => return Err(disabled_answer(create.is_some())),
        KerberosState::NotReady(cause) => return Err(realm_not_ready(&cause)),
        KerberosState::Ready => {}
    }
    password_rules(password, min)?;
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
        now: Timestamp::now(),
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
        async fn registration_start_by(
            &self,
            _: lldap_opaque_handler::registration::ClientRegistrationStartRequest,
            _: lldap_opaque_handler::registration::Presenter,
            _: Option<[u8; 32]>,
        ) -> lldap_domain_model::error::Result<
            lldap_opaque_handler::registration::ServerRegistrationStartResponse,
        > {
            unreachable!("a short password reached the directory")
        }
        async fn registration_claim(
            &self,
            _: &lldap_opaque_handler::registration::ClientRegistrationFinishRequest,
            _: &lldap_opaque_handler::registration::Presenter,
        ) -> lldap_domain_model::error::Result<lldap_opaque_handler::registration::Claim> {
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
            ("pässwör", 8, PasswordChangeError::TooShort(8)),
            ("a\0aaaaaaa", 8, PasswordChangeError::HasNul),
            ("Eleven-11ch", 12, PasswordChangeError::TooShort(12)),
            ("", 8, PasswordChangeError::TooShort(8)),
        ];
        for (password, min, refused) in refusals {
            let rows = std::sync::Arc::new(Rows::default());
            logging::set_log_sink(rows.clone());
            let off = PasswordSync::Off;
            let off = change_password_everywhere(&Untouched, &bob, password, off, min).await;
            let on = PasswordSync::On;
            let on = change_password_everywhere(&Untouched, &bob, password, on, min).await;
            let web = finish_synced_registration(&Untouched, &bob, password, min).await;
            let request = CreateUserRequest {
                user_id: bob.clone(),
                ..Default::default()
            };
            let add = create_synced_user(&Untouched, request, password, min).await;
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
                PasswordChangeError::TooShort(8).to_string(),
                PasswordChangeError::HasNul.to_string(),
                PasswordChangeError::TooShort(12).to_string(),
                PasswordChangeError::PolicyUnreadable.to_string()
            ),
            (
                "the password must be at least 8 characters".to_owned(),
                "the password must not contain a NUL character (U+0000)".to_owned(),
                "the password must be at least 12 characters".to_owned(),
                "the password policy could not be read; try again".to_owned()
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
        async fn registration_start_by(
            &self,
            _: lldap_opaque_handler::registration::ClientRegistrationStartRequest,
            _: lldap_opaque_handler::registration::Presenter,
            _: Option<[u8; 32]>,
        ) -> lldap_domain_model::error::Result<
            lldap_opaque_handler::registration::ServerRegistrationStartResponse,
        > {
            unreachable!()
        }
        async fn registration_claim(
            &self,
            _: &lldap_opaque_handler::registration::ClientRegistrationFinishRequest,
            _: &lldap_opaque_handler::registration::Presenter,
        ) -> lldap_domain_model::error::Result<lldap_opaque_handler::registration::Claim> {
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
        let short =
            finish_synced_registration(&Untouched, &bob, "Short-7", PASSWORD_MIN_LENGTH).await;
        let nul =
            finish_synced_registration(&Untouched, &bob, "a\0aaaaaaa", PASSWORD_MIN_LENGTH).await;
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
            let door = change_password_everywhere(
                &Untouched,
                &bob,
                "Short-7",
                PasswordSync::Off,
                PASSWORD_MIN_LENGTH,
            )
            .await;
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
    async fn test_in_directory_only_a_plain_change_goes_on_and_a_synced_one_is_refused_first() {
        use crate::kerberos::{
            DegradedKerberos, DegradedMode, NoopKerberos, closed_to_writes, set_kerberos_backend,
        };
        use std::sync::Arc;
        let bob = UserId::new("bob");
        let turned_on = Deriving(
            lldap_auth::opaque::server::generate_random_private_key(),
            Some(SYNC_CHANGED),
        );
        let (realm, cause) = ("EXAMPLE.COM".to_owned(), "down".to_owned());
        let closed = DegradedKerberos::with_mode(realm, cause, DegradedMode::DirectoryOnly);
        set_kerberos_backend(Arc::new(closed));
        let (off, on, min) = (PasswordSync::Off, PasswordSync::On, PASSWORD_MIN_LENGTH);
        let plain = (
            change_password_everywhere(&Untouched, &bob, "Short-7", off, min).await,
            change_password_everywhere(&turned_on, &bob, "Eight-88", off, min).await,
        );
        let rows = Arc::new(Rows::default());
        logging::set_log_sink(rows.clone());
        let synced = change_password_everywhere(&Untouched, &bob, "Eight-88", on, min).await;
        set_kerberos_backend(Arc::new(NoopKerberos::default()));
        logging::set_log_sink(Arc::new(logging::NoopLogSink));
        assert_eq!(
            plain,
            (
                Err(PasswordChangeError::TooShort(8)),
                Err(PasswordChangeError::SyncChanged),
            ),
            "a plain change passes to the rules, and the store's SYNC_CHANGED keeps its answer"
        );
        let logged: Vec<_> = rows
            .0
            .lock()
            .unwrap()
            .iter()
            .map(|e| (e.kind, e.success, e.detail.clone().unwrap_or_default()))
            .collect();
        let told = closed_to_writes("down");
        assert_eq!(
            (synced, logged, told.contains("down")),
            (
                Err(PasswordChangeError::Unavailable(told)),
                vec![(
                    LogKind::PasswordChange,
                    false,
                    "Kerberos KDC unavailable: down".to_owned()
                )],
                false,
            ),
            "a synced one is refused before anything is derived: the public cause to the user, \
             the full one in its row"
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
        let store = change_password_everywhere(
            &stored,
            &bob,
            "Eight-88",
            PasswordSync::Off,
            PASSWORD_MIN_LENGTH,
        )
        .await;
        let derive = change_password_everywhere(
            &Unstarted,
            &bob,
            "Eight-88",
            PasswordSync::Off,
            PASSWORD_MIN_LENGTH,
        )
        .await;
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
            finish_synced_registration(&Untouched, &bob, "Eight-88", PASSWORD_MIN_LENGTH).await,
            change_password_everywhere(
                &Untouched,
                &bob,
                "Short-7",
                PasswordSync::On,
                PASSWORD_MIN_LENGTH,
            )
            .await,
            create_synced_user(&Untouched, request(), "Eight-88", PASSWORD_MIN_LENGTH).await,
            create_synced_user(&Untouched, request(), "a\0aaaaaaa", PASSWORD_MIN_LENGTH).await,
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
        async fn registration_start_by(
            &self,
            _: lldap_opaque_handler::registration::ClientRegistrationStartRequest,
            _: lldap_opaque_handler::registration::Presenter,
            _: Option<[u8; 32]>,
        ) -> lldap_domain_model::error::Result<
            lldap_opaque_handler::registration::ServerRegistrationStartResponse,
        > {
            unreachable!()
        }
        async fn registration_claim(
            &self,
            _: &lldap_opaque_handler::registration::ClientRegistrationFinishRequest,
            _: &lldap_opaque_handler::registration::Presenter,
        ) -> lldap_domain_model::error::Result<lldap_opaque_handler::registration::Claim> {
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
            let off = change_password_everywhere(
                &handler,
                &bob,
                "Eight-88",
                PasswordSync::Off,
                PASSWORD_MIN_LENGTH,
            );
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
        use PasswordChangeError::{HasNul, TooShort};
        let rows = [
            ("Eight-88", 8, Ok(())),
            ("pässwörd", 8, Ok(())),
            ("pässwör", 8, Err(TooShort(8))),
            ("a\0aaaaaaa", 8, Err(HasNul)),
            ("Eight-88\0", 8, Err(HasNul)),
            ("\0", 8, Err(HasNul)),
            ("Eleven-11ch", 12, Err(TooShort(12))),
            ("Twelve-12chr", 12, Ok(())),
            ("pässwörd-äöü", 12, Ok(())),
            ("\0", 12, Err(HasNul)),
            ("Short-7", 5, Err(TooShort(8))),
            ("Eight-88", 5, Ok(())),
        ];
        let got: Vec<_> = rows
            .iter()
            .map(|(text, min, _)| (*text, *min, password_rules(text, *min)))
            .collect();
        assert_eq!(got, rows.to_vec());
        assert_eq!(
            ["a\0aaaaaaa", "Eleven-11ch", "Twelve-12chr", "pässwörd-äöü"]
                .map(|text| (text.chars().count(), text.len())),
            [(9, 9), (11, 11), (12, 12), (12, 17)],
            "the NUL row passes the floor alone; the rows count characters, not bytes"
        );
        assert_eq!(
            [TooShort(8), TooShort(12), HasNul].map(|e| e.to_string()),
            [
                "the password must be at least 8 characters".to_owned(),
                "the password must be at least 12 characters".to_owned(),
                "the password must not contain a NUL character (U+0000)".to_owned()
            ]
        );
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn test_each_door_here_counts_a_new_password_as_password_length() {
        use crate::kerberos::{NoopKerberos, set_kerberos_backend};
        use PasswordChangeError::{Failed, TooShort};
        use std::sync::Arc;
        type Row = (&'static str, usize, (usize, usize), Option<usize>);
        let rows: [Row; 3] = [
            ("ääääääää", 12, (8, 16), Some(12)),
            ("ääää", 8, (4, 8), Some(8)),
            ("e\u{301}e\u{301}e\u{301}e\u{301}", 8, (8, 12), None),
        ];
        set_kerberos_backend(Arc::new(Holding(None)));
        let bob = UserId::new("bob");
        let key = lldap_auth::opaque::server::generate_random_private_key;
        let handler = Deriving(key(), Some("stored"));
        let request = || CreateUserRequest {
            user_id: bob.clone(),
            ..Default::default()
        };
        let (mut got, mut want) = (Vec::new(), Vec::new());
        for (text, min, counts, short) in rows {
            let off = change_password_everywhere(&handler, &bob, text, PasswordSync::Off, min);
            let on = change_password_everywhere(&handler, &bob, text, PasswordSync::On, min);
            let doors = (
                password_rules(text, min),
                off.await,
                on.await,
                finish_synced_registration(&handler, &bob, text, min).await,
                create_synced_user(&handler, request(), text, min).await,
            );
            let counted = (password_length(text), text.len());
            let judged = (password_length(text) < min).then_some(min);
            got.push((text, counted, judged, doors));
            let past = |failed: &str| -> Result<(), PasswordChangeError> {
                Err(short.map_or_else(|| Failed(failed.to_owned()), TooShort))
            };
            let committed = "this Kerberos backend cannot commit a password";
            let doors = (
                short.map_or(Ok(()), |m| Err(TooShort(m))),
                past("Internal error: `stored`"),
                past(committed),
                past(committed),
                past(committed),
            );
            want.push((text, counts, short, doors));
        }
        set_kerberos_backend(Arc::new(NoopKerberos::default()));
        assert_eq!(
            got, want,
            "fewer characters than the minimum, though not fewer bytes, is refused at each door; \
             a combining mark is a character: past the rules, to the store or the commit"
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
            .map(|(text, _)| (*text, password_rules(text, PASSWORD_MIN_LENGTH).is_ok()))
            .collect();
        assert_eq!(got, rows.to_vec());
        assert_eq!(("pässwör".len(), PASSWORD_MIN_LENGTH), (9, 8));
        let empty = [0, 12].map(|min| password_rules("", min).map_err(|e| e.to_string()));
        assert_eq!(
            empty,
            [
                Err("the password must be at least 8 characters".to_owned()),
                Err("the password must be at least 12 characters".to_owned()),
            ],
            "the server's doors answer an empty password with the minimum's text"
        );
    }

    #[test]
    fn test_the_minimum_is_read_trimmed_and_held_between_8_and_128() {
        let rows: [(&str, Option<usize>); 15] = [
            ("12", Some(12)),
            ("7", Some(8)),
            ("129", Some(128)),
            ("x", None),
            (" 20 ", Some(20)),
            ("8", Some(8)),
            ("128", Some(128)),
            ("", None),
            ("-1", Some(8)),
            ("12.5", None),
            ("12x", None),
            ("99999999999999999999", Some(128)),
            ("-99999999999999999999", Some(8)),
            ("99999999999999999999x", None),
            ("-", None),
        ];
        let got = rows.map(|(value, _)| (value, PasswordMinLength::parse(value)));
        assert_eq!(got, rows);
        assert_eq!(PasswordMinLength::KEY, "password-min-length");
        assert_eq!(
            [
                min_length_in(&[]).map_err(|e| e.to_string()),
                min_length_in(&[item_of("x")]).map_err(|e| e.to_string()),
                min_length_in(&[item_of("500")]).map_err(|e| e.to_string()),
            ],
            [
                Ok(8),
                Err("Internal error: `the stored password-min-length is not a number`".to_owned()),
                Ok(128),
            ],
            "no item is the default 8; a stored value that is not a number is unreadable"
        );
    }

    fn item_of(value: &str) -> crate::policies::EffectiveItem {
        use crate::policies::{EffectiveItem, ItemSource, PolicyId, PolicyScope};
        EffectiveItem {
            key: PASSWORD_MIN_LENGTH_ITEM.to_owned(),
            scope: PolicyScope::User,
            value: value.to_owned(),
            enforced: true,
            source: Some(ItemSource {
                policy_id: PolicyId(1),
                policy_name: "p".to_owned(),
                ou_key: "labs".to_owned(),
            }),
        }
    }

    #[test]
    fn test_the_minimum_comes_from_the_users_ou_else_eight() {
        use crate::policies::{
            AttachedPolicy, POLICY_ITEM_CATALOG, PolicyId, PolicyLevel, SettingSource, resolve,
            resolve_effective_items,
        };
        let level = |ou: &str, blocked: bool, value: Option<&str>| PolicyLevel {
            ou_key: ou.to_owned(),
            blocked,
            policy: value.map(|value| AttachedPolicy {
                id: PolicyId(1),
                name: format!("on {ou}"),
                items: [("password-min-length".to_owned(), value.to_owned())].into(),
            }),
        };
        type Row = (
            &'static str,
            Vec<PolicyLevel>,
            (Option<usize>, SettingSource),
        );
        let rows: Vec<Row> = vec![
            ("no policy", vec![], (Some(8), SettingSource::Default)),
            (
                "the OU sets 12",
                vec![level("", false, None), level("labs", false, Some("12"))],
                (Some(12), SettingSource::Ou),
            ),
            (
                "the parent sets 20, the child inherits",
                vec![
                    level("", false, None),
                    level("labs", false, Some("20")),
                    level("labs\\east", false, None),
                ],
                (Some(20), SettingSource::Ou),
            ),
            (
                "the child blocks the parent's 20",
                vec![
                    level("", false, None),
                    level("labs", false, Some("20")),
                    level("labs\\east", true, None),
                ],
                (Some(8), SettingSource::Default),
            ),
            (
                "the child's 12 over the parent's 20",
                vec![
                    level("", false, None),
                    level("labs", false, Some("20")),
                    level("labs\\east", false, Some("12")),
                ],
                (Some(12), SettingSource::Ou),
            ),
            (
                "a stored 500 is held to 128",
                vec![level("", false, Some("500"))],
                (Some(128), SettingSource::Ou),
            ),
            (
                "a stored x is not a number",
                vec![level("", false, Some("x"))],
                (None, SettingSource::Ou),
            ),
        ];
        for (row, levels, expected) in rows {
            let items = resolve_effective_items(POLICY_ITEM_CATALOG, &levels);
            assert_eq!(
                resolve::<PasswordMinLength>(None, &items),
                expected,
                "{row}"
            );
        }
        assert_eq!(
            resolve::<PasswordMinLength>(None, &[]),
            (Some(8), SettingSource::Default),
            "no items at all, as for a user the directory does not have"
        );
    }

    mod stalled {
        use crate::enforcement::POLICY_UNANSWERED;
        use crate::handler::PolicyBackendHandler;
        use crate::policies::{
            CreatePolicyRequest, OuPolicyState, Policy, PolicyId, PolicyLevel, UpdatePolicyRequest,
        };
        use async_trait::async_trait;
        use lldap_domain::types::{User, UserId};
        use lldap_domain_model::error::{DomainError, Result};

        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub(super) enum Answer {
            Never,
            ItsOwnBound,
            Down,
        }

        /// A policy store whose bounded reads never answer, or answer an error at once.
        pub(super) struct Stalled(pub(super) Answer);

        impl Stalled {
            async fn answer(&self) -> DomainError {
                let detail = match self.0 {
                    Answer::Never => std::future::pending().await,
                    Answer::ItsOwnBound => POLICY_UNANSWERED,
                    Answer::Down => "down",
                };
                DomainError::InternalError(detail.to_owned())
            }
        }

        #[async_trait]
        impl PolicyBackendHandler for Stalled {
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
                unimplemented!()
            }
            async fn delete_ou_policy_state(&self, _: &str) -> Result<()> {
                unimplemented!()
            }
            async fn bounded_policy_entry(&self, _: &UserId) -> Result<(User, Vec<PolicyLevel>)> {
                Err(self.answer().await)
            }
            async fn bounded_policy_levels(&self, _: &str) -> Result<Vec<PolicyLevel>> {
                Err(self.answer().await)
            }
        }
    }

    #[derive(Clone, Copy)]
    enum Caller {
        Change,
        AddByOu,
        Read,
    }

    async fn ask(caller: Caller, store: &stalled::Stalled) -> Result<usize, String> {
        let user = UserId::new("e3slow");
        match caller {
            Caller::Change => min_length_of(store, &user).await.map_err(|e| e.to_string()),
            Caller::AddByOu => {
                let min = min_length_in_ou(store, "people", &user, LogKind::UserCreate).await;
                min.map_err(|e| e.to_string())
            }
            Caller::Read => {
                let min = min_length_for_user(store, &user).await;
                min.map_err(|e| e.to_string())
            }
        }
    }

    #[tokio::test(start_paused = true)]
    #[serial_test::serial]
    async fn test_a_minimum_read_past_its_bound_refuses_each_door_with_its_one_row() {
        use stalled::Answer::{Down, ItsOwnBound, Never};
        const UNREADABLE: &str = "the password policy could not be read; try again";
        const UNANSWERED: &str =
            "Internal error: `the policy read did not answer within its bound`";
        const DOWN: &str = "Internal error: `down`";
        const WITHIN: std::time::Duration = std::time::Duration::from_secs(4);
        type Door = (&'static str, Caller, Option<LogKind>);
        let doors: [Door; 7] = [
            ("A", Caller::Change, Some(LogKind::PasswordChange)),
            ("B/C", Caller::Change, Some(LogKind::PasswordChange)),
            ("G", Caller::Change, Some(LogKind::PasswordChange)),
            ("F/H/I", Caller::Change, Some(LogKind::PasswordChange)),
            ("D/E", Caller::AddByOu, Some(LogKind::UserCreate)),
            ("J/K", Caller::Read, None),
            ("L", Caller::Read, None),
        ];
        let rows = std::sync::Arc::new(Rows::default());
        logging::set_log_sink(rows.clone());
        let (mut got, mut want) = (Vec::new(), Vec::new());
        for (door, caller, kind) in doors {
            for answer in [Never, ItsOwnBound, Down] {
                let started = tokio::time::Instant::now();
                let answered = ask(caller, &stalled::Stalled(answer)).await;
                let took = started.elapsed();
                let events = std::mem::take(&mut *rows.0.lock().unwrap());
                let row = |e: logging::LogEvent| (e.kind, e.success, e.detail);
                let written: Vec<_> = events.into_iter().map(row).collect();
                let bound = (took >= POLICY_READ_WAIT, took < WITHIN);
                got.push((door, answer, answered, written, bound));
                let (text, written) = match (kind, answer) {
                    (Some(kind), _) => (UNREADABLE, vec![(kind, false, Some(UNREADABLE.into()))]),
                    (None, Down) => (DOWN, vec![]),
                    (None, _) => (UNANSWERED, vec![]),
                };
                let waited = (answer == Never, true);
                want.push((door, answer, Err(text.to_owned()), written, waited));
            }
        }
        logging::set_log_sink(std::sync::Arc::new(logging::NoopLogSink));
        assert_eq!(got, want);
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
