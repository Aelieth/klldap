use async_trait::async_trait;
use lldap_domain::types::UserId;
use lldap_domain_handlers::kerberos::{
    CauseClass, CommitError, DegradedKerberos, DegradedMode, Held, HostRow, KerberosSync,
    PasswordCommit, UserChange, set_thread_kerberos_backend,
};
use lldap_domain_handlers::password::record_commit_failure;
use std::sync::{Arc, Mutex};

pub const RECORDER_REALM: &str = "RECORDER.TEST";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KerberosOp {
    CommitPassword {
        username: String,
        password: String,
        rows: Vec<String>,
    },
    CommitUser {
        username: String,
        step: &'static str,
        rows: Vec<String>,
    },
    DeletePrincipal {
        username: String,
    },
    SetEnabled {
        username: String,
        enabled: bool,
    },
    ExportKeytab {
        hostname: String,
    },
}

pub struct RecordingKerberos {
    ops: Mutex<Vec<KerberosOp>>,
    check_error: Option<String>,
    alias_error: Option<String>,
    commit: Result<(), CommitError>,
    hold: Result<(), CommitError>,
    unsettled: Option<String>,
}

impl Default for RecordingKerberos {
    fn default() -> Self {
        Self {
            ops: Mutex::new(Vec::new()),
            check_error: None,
            alias_error: None,
            commit: Ok(()),
            hold: Ok(()),
            unsettled: None,
        }
    }
}

impl RecordingKerberos {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    // Records each commit and fails it with `cause`.
    pub fn failing(cause: &str) -> Arc<Self> {
        Arc::new(Self {
            commit: Err(CommitError::Failed(cause.to_owned())),
            ..Self::default()
        })
    }

    // The password check before any write refuses with `cause`, as a bound policy would.
    pub fn refusing(cause: &str) -> Arc<Self> {
        Arc::new(Self {
            check_error: Some(cause.to_owned()),
            ..Self::default()
        })
    }

    pub fn aliased(why: &str) -> Arc<Self> {
        Arc::new(Self {
            alias_error: Some(why.to_owned()),
            ..Self::default()
        })
    }

    pub fn answering(commit: Result<(), CommitError>) -> Arc<Self> {
        Arc::new(Self {
            commit,
            ..Self::default()
        })
    }

    pub fn holding(hold: Result<(), CommitError>) -> Arc<Self> {
        Arc::new(Self {
            hold,
            ..Self::default()
        })
    }

    pub fn unsettled(cause: &str) -> Arc<Self> {
        Arc::new(Self {
            unsettled: Some(cause.to_owned()),
            ..Self::default()
        })
    }

    pub fn take_ops(&self) -> Vec<KerberosOp> {
        self.ops.lock().expect("ops").drain(..).collect()
    }
}

#[async_trait]
impl KerberosSync for RecordingKerberos {
    fn unsettled(&self) -> Option<String> {
        self.unsettled.clone()
    }
    fn realm(&self) -> &str {
        RECORDER_REALM
    }
    async fn check_password(&self, _: &UserId, _: &str) -> Result<(), String> {
        self.check_error.clone().map_or(Ok(()), Err)
    }
    async fn sync_on_refused(&self, _: &UserId) -> Result<(), String> {
        self.alias_error.clone().map_or(Ok(()), Err)
    }
    async fn hold_plain(&self, _: &UserId) -> Result<Option<Held>, CommitError> {
        self.hold.clone().map(|()| None)
    }
    async fn commit_password(
        &self,
        change: PasswordCommit,
        password: &str,
    ) -> Result<(), CommitError> {
        self.ops
            .lock()
            .expect("ops")
            .push(KerberosOp::CommitPassword {
                username: change.user.as_str().to_owned(),
                password: password.to_owned(),
                rows: change.rows.iter().map(HostRow::label).collect(),
            });
        if let Err(e) = &self.commit
            && *e != CommitError::Busy
        {
            record_commit_failure(change.kind, &change.user, e);
        }
        self.commit.clone()
    }
    // An accepted change leaves the directory write to its caller, as no realm would.
    async fn commit_user(&self, change: UserChange) -> Option<Result<(), CommitError>> {
        self.ops.lock().expect("ops").push(KerberosOp::CommitUser {
            username: change.user.as_str().to_owned(),
            step: change.step.op(),
            rows: change.rows.iter().map(HostRow::label).collect(),
        });
        self.commit.clone().err().map(Err)
    }
    async fn delete_principal(&self, user: &UserId) -> Result<(), String> {
        self.ops
            .lock()
            .expect("ops")
            .push(KerberosOp::DeletePrincipal {
                username: user.as_str().to_owned(),
            });
        Ok(())
    }
    async fn set_principal_enabled(&self, user: &UserId, enabled: bool) -> Result<(), String> {
        self.ops.lock().expect("ops").push(KerberosOp::SetEnabled {
            username: user.as_str().to_owned(),
            enabled,
        });
        Ok(())
    }
    async fn export_keytab_for_keycloak(&self, hostname: &str) -> Result<String, String> {
        self.ops
            .lock()
            .expect("ops")
            .push(KerberosOp::ExportKeytab {
                hostname: hostname.to_owned(),
            });
        Ok("/tmp/recording.keytab".into())
    }
}

pub struct RecordingGuard {
    rec: Arc<RecordingKerberos>,
}

impl RecordingGuard {
    pub fn install() -> Self {
        let rec = RecordingKerberos::new();
        set_thread_kerberos_backend(Some(rec.clone()));
        Self { rec }
    }

    pub fn install_failing(cause: &str) -> Self {
        Self::installed(RecordingKerberos::failing(cause))
    }

    pub fn install_refusing(cause: &str) -> Self {
        Self::installed(RecordingKerberos::refusing(cause))
    }

    pub fn install_aliased(why: &str) -> Self {
        Self::installed(RecordingKerberos::aliased(why))
    }

    pub fn install_answering(commit: Result<(), CommitError>) -> Self {
        Self::installed(RecordingKerberos::answering(commit))
    }

    pub fn install_holding(hold: Result<(), CommitError>) -> Self {
        Self::installed(RecordingKerberos::holding(hold))
    }

    pub fn install_unsettled(cause: &str) -> Self {
        Self::installed(RecordingKerberos::unsettled(cause))
    }

    fn installed(rec: Arc<RecordingKerberos>) -> Self {
        set_thread_kerberos_backend(Some(rec.clone()));
        Self { rec }
    }

    pub fn recorder(&self) -> &RecordingKerberos {
        &self.rec
    }
}

impl Drop for RecordingGuard {
    fn drop(&mut self) {
        set_thread_kerberos_backend(None);
    }
}

// The KDC has not come up yet: directory writes must be refused.
pub struct NotReadyKerberos;

#[async_trait]
impl KerberosSync for NotReadyKerberos {
    fn ready(&self) -> bool {
        false
    }
    fn realm(&self) -> &str {
        RECORDER_REALM
    }
    async fn delete_principal(&self, _: &UserId) -> Result<(), String> {
        Err("KDC not ready".to_owned())
    }
    async fn set_principal_enabled(&self, _: &UserId, _: bool) -> Result<(), String> {
        Err("KDC not ready".to_owned())
    }
    async fn export_keytab_for_keycloak(&self, _: &str) -> Result<String, String> {
        Err("KDC not ready".to_owned())
    }
}

pub struct NotReadyGuard;

impl NotReadyGuard {
    pub fn install() -> Self {
        set_thread_kerberos_backend(Some(Arc::new(NotReadyKerberos)));
        Self
    }
}

impl Drop for NotReadyGuard {
    fn drop(&mut self) {
        set_thread_kerberos_backend(None);
    }
}

pub const DEGRADED_CAUSE: &str = "the Kerberos realm did not open: test";
pub const DEGRADED_CLASS: CauseClass = CauseClass::Records;

pub struct DegradedGuard;

impl DegradedGuard {
    pub fn install() -> Self {
        Self::installed(DegradedMode::AdminOnly)
    }

    pub fn install_directory_only() -> Self {
        Self::installed(DegradedMode::DirectoryOnly)
    }

    fn installed(mode: DegradedMode) -> Self {
        let degraded =
            DegradedKerberos::with_mode(RECORDER_REALM.to_owned(), DEGRADED_CAUSE.to_owned(), mode);
        set_thread_kerberos_backend(Some(Arc::new(degraded.closed_by(DEGRADED_CLASS))));
        Self
    }
}

impl Drop for DegradedGuard {
    fn drop(&mut self) {
        set_thread_kerberos_backend(None);
    }
}
