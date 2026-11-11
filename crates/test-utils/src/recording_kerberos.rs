use async_trait::async_trait;
use lldap_domain::types::UserId;
use lldap_domain_handlers::kerberos::{
    DegradedKerberos, KerberosSync, NoopKerberos, set_kerberos_backend,
};
use std::sync::{Arc, Mutex};

pub const RECORDER_REALM: &str = "RECORDER.TEST";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KerberosOp {
    SyncPrincipal { username: String, password: String },
    DeletePrincipal { username: String },
    SetEnabled { username: String, enabled: bool },
    ExportKeytab { hostname: String },
}

pub struct RecordingKerberos {
    ops: Mutex<Vec<KerberosOp>>,
}

impl RecordingKerberos {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            ops: Mutex::new(Vec::new()),
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
        Ok(())
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
