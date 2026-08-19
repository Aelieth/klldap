use crate::{
    delete_kerberos_principal, export_keytab_for_keycloak, paths::KerberosPaths,
    set_kerberos_principal_enabled, sync_kerberos_principal,
};
use lldap_domain_handlers::kerberos::KerberosSync;
use lldap_domain_handlers::logging::{LogKind, record_outcome};
use std::{
    net::{SocketAddr, TcpStream},
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

pub struct LiveKerberos {
    kdc_port: u16,
    wait_for_kdc: bool,
    seen_kdc: AtomicBool,
}

impl LiveKerberos {
    /// `wait_for_kdc` is the deployment saying a KDC is part of it (the image sets
    /// `healthcheck_options.kerberos`); without it, directory writes never wait.
    pub fn new(wait_for_kdc: bool) -> Self {
        Self::on_port(KerberosPaths::from_env().kdc_port, wait_for_kdc)
    }

    pub fn on_port(kdc_port: u16, wait_for_kdc: bool) -> Self {
        Self {
            kdc_port,
            wait_for_kdc,
            seen_kdc: AtomicBool::new(false),
        }
    }
}

impl KerberosSync for LiveKerberos {
    // Latch: wait once after boot; a later KDC death is the healthcheck's job.
    fn ready(&self) -> bool {
        if !self.wait_for_kdc || self.seen_kdc.load(Ordering::Relaxed) {
            return true;
        }
        let addr = SocketAddr::from(([127, 0, 0, 1], self.kdc_port));
        let up = TcpStream::connect_timeout(&addr, Duration::from_millis(200)).is_ok();
        if up {
            self.seen_kdc.store(true, Ordering::Relaxed);
        }
        up
    }
    fn sync_principal(&self, username: &str, password: &str) -> Result<(), String> {
        logged(LogKind::KerberosSync, username, "sync", || {
            sync_kerberos_principal(username, password)
        })
    }
    fn delete_principal(&self, username: &str) -> Result<(), String> {
        logged(LogKind::KerberosSync, username, "delete", || {
            delete_kerberos_principal(username)
        })
    }
    fn set_principal_enabled(&self, username: &str, enabled: bool) -> Result<(), String> {
        let op = if enabled { "enable" } else { "disable" };
        logged(LogKind::KerberosSync, username, op, || {
            set_kerberos_principal_enabled(username, enabled)
        })
    }
    fn export_keytab_for_keycloak(&self, hostname: &str) -> Result<String, String> {
        logged(LogKind::KeytabExport, hostname, "keycloak", || {
            export_keytab_for_keycloak(hostname)
        })
    }
}

fn logged<T>(
    kind: LogKind,
    target: &str,
    op: &str,
    f: impl FnOnce() -> anyhow::Result<T>,
) -> Result<T, String> {
    let result = f().map_err(|e| format!("{e:#}"));
    record_outcome(kind, Some(target), result.is_ok(), Some(op));
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn test_ready_latches_once_the_kdc_port_answers() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let live = LiveKerberos::on_port(port, true);
        assert!(!live.ready(), "nothing listens yet");
        assert!(
            LiveKerberos::on_port(port, false).ready(),
            "no KDC expected: never waits"
        );
        let listener = TcpListener::bind(("127.0.0.1", port)).unwrap();
        assert!(live.ready(), "the KDC port answers");
        drop(listener);
        assert!(live.ready(), "latched: a KDC seen once counts as up");
    }
}

#[cfg(test)]
mod log_tests {
    use super::*;
    use lldap_domain_handlers::logging::{LogKind, Protocol};
    use lldap_test_utils::recording_log::LogGuard;
    use serial_test::serial;

    #[test]
    #[serial]
    fn test_principal_operations_record_kerberos_sync_events() {
        let guard = LogGuard::install();
        let live = LiveKerberos::on_port(1, false);

        // No KDC: the delete is a no-op success, the sync a failure; both are recorded.
        assert!(live.delete_principal("bob").is_ok());
        assert!(live.sync_principal("bob", "pw").is_err());
        assert!(live.export_keytab_for_keycloak("host.example.com").is_err());

        let events = guard.recorder().take_events();
        let summary: Vec<_> = events
            .iter()
            .map(|e| (e.kind, e.target.as_deref(), e.detail.as_deref(), e.success))
            .collect();
        assert_eq!(
            summary,
            vec![
                (LogKind::KerberosSync, Some("bob"), Some("delete"), true),
                (LogKind::KerberosSync, Some("bob"), Some("sync"), false),
                (
                    LogKind::KeytabExport,
                    Some("host.example.com"),
                    Some("keycloak"),
                    false
                ),
            ]
        );
        assert!(events.iter().all(|e| e.protocol == Protocol::System));
    }
}
