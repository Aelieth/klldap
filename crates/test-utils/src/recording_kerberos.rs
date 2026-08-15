use lldap_domain_handlers::kerberos::{KerberosSync, NoopKerberos, set_kerberos_backend};
use std::sync::{Arc, Mutex};

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

impl KerberosSync for RecordingKerberos {
    fn sync_principal(&self, username: &str, password: &str) -> Result<(), String> {
        self.ops
            .lock()
            .expect("ops")
            .push(KerberosOp::SyncPrincipal {
                username: username.to_owned(),
                password: password.to_owned(),
            });
        Ok(())
    }
    fn delete_principal(&self, username: &str) -> Result<(), String> {
        self.ops
            .lock()
            .expect("ops")
            .push(KerberosOp::DeletePrincipal {
                username: username.to_owned(),
            });
        Ok(())
    }
    fn set_principal_enabled(&self, username: &str, enabled: bool) -> Result<(), String> {
        self.ops.lock().expect("ops").push(KerberosOp::SetEnabled {
            username: username.to_owned(),
            enabled,
        });
        Ok(())
    }
    fn export_keytab_for_keycloak(&self, hostname: &str) -> Result<String, String> {
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
        set_kerberos_backend(Arc::new(NoopKerberos));
    }
}

// The KDC has not come up yet: directory writes must be refused.
pub struct NotReadyKerberos;

impl KerberosSync for NotReadyKerberos {
    fn ready(&self) -> bool {
        false
    }
    fn sync_principal(&self, _: &str, _: &str) -> Result<(), String> {
        Err("KDC not ready".to_owned())
    }
    fn delete_principal(&self, _: &str) -> Result<(), String> {
        Err("KDC not ready".to_owned())
    }
    fn set_principal_enabled(&self, _: &str, _: bool) -> Result<(), String> {
        Err("KDC not ready".to_owned())
    }
    fn export_keytab_for_keycloak(&self, _: &str) -> Result<String, String> {
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
        set_kerberos_backend(Arc::new(NoopKerberos));
    }
}
