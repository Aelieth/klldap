use crate::kerberos::{
    CommitError, HostRow, KerberosSync, PasswordCommit, kerberos_backend, require_kdc_ready,
};
use crate::logging::{self, LogKind};
use lldap_domain::requests::CreateUserRequest;
use lldap_domain::types::UserId;
use lldap_domain_model::error::DomainError;
use lldap_opaque_handler::{OpaqueHandler, prepare_registration, register_password};
use tracing::warn;

pub const PASSWORD_CHANGE_IN_PROGRESS: &str = "a password change is in progress, try again";
pub const RESULT_UNKNOWN: &str = "the result is unknown: try the new password";
pub const ANSWER_LOST: &str = "the answer was lost; the change had committed";
pub const UNKNOWN_ROW: &str = "result unknown: the database did not answer";
pub const PASSWORD_MIN_LENGTH: usize = 8;

/// The directory's floor, in characters (Unicode scalar values), at every door.
pub fn long_enough(password: &str) -> bool {
    password.chars().count() >= PASSWORD_MIN_LENGTH
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
    /// Kerberos refused the password or the name; nothing was written.
    Refused(String),
    InProgress,
    Unavailable(String),
    NoSuchUser,
    Failed(String),
    Unknown,
}

impl std::fmt::Display for PasswordChangeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Refused(reason) => write!(f, "refused by Kerberos: {reason}"),
            Self::InProgress => f.write_str(PASSWORD_CHANGE_IN_PROGRESS),
            Self::Unavailable(cause) => write!(f, "Kerberos KDC unavailable: {cause}"),
            Self::NoSuchUser => f.write_str("password change failed: no such user"),
            Self::Failed(cause) => write!(f, "password change failed: {cause}"),
            Self::Unknown => f.write_str(RESULT_UNKNOWN),
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
        CommitError::Refused(reason) => PasswordChangeError::Refused(reason),
        CommitError::UserGone => PasswordChangeError::NoSuchUser,
        CommitError::Failed(cause) => PasswordChangeError::Failed(cause),
        CommitError::Unknown(_) => PasswordChangeError::Unknown,
    }
}

/// Written by the task that did the work, so a dropped caller still has its row.
pub fn record_commit_failure(kind: LogKind, user: &UserId, error: &CommitError) {
    if let CommitError::Unknown(cause) = error {
        warn!("A password change's result is unknown: {cause}");
    }
    record_failed(kind, user, &commit_error(error.clone()));
}

fn record_failed(kind: LogKind, user: &UserId, error: &PasswordChangeError) {
    let detail = match error {
        PasswordChangeError::Unknown => UNKNOWN_ROW.to_owned(),
        e => e.to_string(),
    };
    logging::record_failure(kind, Some(user.as_str()), &detail);
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
        return register_password(handler, user.clone(), password.as_bytes())
            .await
            .map_err(change_error);
    }
    commit_synced(handler, user, password, None).await
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
    require_kdc_ready().map_err(change_error)?;
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
        let rows: [Row; 5] = [
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
            (None, vec!["password bob", "log password_change"]),
            (
                Some(request),
                vec![
                    "create bob",
                    "password bob",
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

    #[derive(Default)]
    struct Rows(std::sync::Mutex<Vec<logging::LogEvent>>);

    impl logging::LogSink for Rows {
        fn record(&self, event: logging::LogEvent) {
            self.0.lock().unwrap().push(event);
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
