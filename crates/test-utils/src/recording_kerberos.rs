use async_trait::async_trait;
use lldap_domain::types::UserId;
use lldap_domain_handlers::kerberos::{
    CommitError, DegradedKerberos, HostRow, KerberosSync, NoopKerberos, PasswordCommit,
    set_kerberos_backend,
};
use lldap_domain_handlers::password::record_commit_failure;
use std::sync::{Arc, Mutex};

pub const RECORDER_REALM: &str = "RECORDER.TEST";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KerberosOp {
    SyncPrincipal {
        username: String,
        password: String,
    },
    CommitPassword {
        username: String,
        password: String,
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
    sync_error: Option<String>,
    check_error: Option<String>,
    commit: Result<(), CommitError>,
}

impl Default for RecordingKerberos {
    fn default() -> Self {
        Self {
            ops: Mutex::new(Vec::new()),
            sync_error: None,
            check_error: None,
            commit: Ok(()),
        }
    }
}

impl RecordingKerberos {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    // Records each sync and refuses it with `cause`, as a KDC refusal would.
    pub fn failing(cause: &str) -> Arc<Self> {
        Arc::new(Self {
            sync_error: Some(cause.to_owned()),
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

    pub fn answering(commit: Result<(), CommitError>) -> Arc<Self> {
        Arc::new(Self {
            commit,
            ..Self::default()
        })
    }

    pub fn take_ops(&self) -> Vec<KerberosOp> {
        self.ops.lock().expect("ops").drain(..).collect()
    }
}

#[async_trait]
impl KerberosSync for RecordingKerberos {
    fn realm(&self) -> &str {
        RECORDER_REALM
    }
    async fn sync_principal(&self, user: &UserId, password: &str) -> Result<(), String> {
        self.ops
            .lock()
            .expect("ops")
            .push(KerberosOp::SyncPrincipal {
                username: user.as_str().to_owned(),
                password: password.to_owned(),
            });
        self.sync_error.clone().map_or(Ok(()), Err)
    }
    async fn check_password(&self, _: &UserId, _: &str) -> Result<(), String> {
        self.check_error.clone().map_or(Ok(()), Err)
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
        set_kerberos_backend(rec.clone());
        Self { rec }
    }

    pub fn install_failing(cause: &str) -> Self {
        Self::installed(RecordingKerberos::failing(cause))
    }

    pub fn install_refusing(cause: &str) -> Self {
        Self::installed(RecordingKerberos::refusing(cause))
    }

    pub fn install_answering(commit: Result<(), CommitError>) -> Self {
        Self::installed(RecordingKerberos::answering(commit))
    }

    fn installed(rec: Arc<RecordingKerberos>) -> Self {
        set_kerberos_backend(rec.clone());
        Self { rec }
    }

    pub fn recorder(&self) -> &RecordingKerberos {
        &self.rec
    }
}

impl Drop for RecordingGuard {
    fn drop(&mut self) {
        set_kerberos_backend(Arc::new(NoopKerberos::default()));
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
    async fn sync_principal(&self, _: &UserId, _: &str) -> Result<(), String> {
        Err("KDC not ready".to_owned())
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
        set_kerberos_backend(Arc::new(NotReadyKerberos));
        Self
    }
}

impl Drop for NotReadyGuard {
    fn drop(&mut self) {
        set_kerberos_backend(Arc::new(NoopKerberos::default()));
    }
}

pub const DEGRADED_CAUSE: &str = "the Kerberos realm did not open: test";

pub struct DegradedGuard;

impl DegradedGuard {
    pub fn install() -> Self {
        set_kerberos_backend(Arc::new(DegradedKerberos::new(
            RECORDER_REALM.to_owned(),
            DEGRADED_CAUSE.to_owned(),
        )));
        Self
    }
}

impl Drop for DegradedGuard {
    fn drop(&mut self) {
        set_kerberos_backend(Arc::new(NoopKerberos::default()));
    }
}
