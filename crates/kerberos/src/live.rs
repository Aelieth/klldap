use crate::{
    delete_kerberos_principal, export_keytab_for_keycloak, paths::KerberosPaths,
    set_kerberos_principal_enabled, sync_kerberos_principal,
};
use async_trait::async_trait;
use lldap_domain_handlers::kerberos::KerberosSync;
use lldap_domain_handlers::logging::{LogKind, current_request, record_outcome, with_request_sync};
use std::{
    net::{SocketAddr, TcpStream},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::sync::Mutex;
use tracing::Span;

pub struct LiveKerberos {
    kdc_port: u16,
    wait_for_kdc: bool,
    seen_kdc: AtomicBool,
    kadm5: Arc<Mutex<()>>,
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
            kadm5: Arc::new(Mutex::new(())),
        }
    }

    // One kadm5 call at a time; lock and log row go with the call, so a dropped caller keeps both.
    async fn logged<T: Send + 'static>(
        &self,
        kind: LogKind,
        target: &str,
        op: &'static str,
        f: impl FnOnce() -> anyhow::Result<T> + Send + 'static,
    ) -> Result<T, String> {
        let meta = current_request();
        let span = Span::current();
        let target = target.to_owned();
        let serial = self.kadm5.clone().lock_owned().await;
        tokio::task::spawn_blocking(move || {
            let _serial = serial;
            span.in_scope(|| {
                with_request_sync(meta, || {
                    let result = f().map_err(|e| format!("{e:#}"));
                    record_outcome(kind, Some(&target), result.is_ok(), Some(op));
                    result
                })
            })
        })
        .await
        .unwrap_or_else(|e| Err(format!("Kerberos call did not complete: {e}")))
    }
}

#[async_trait]
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
    async fn sync_principal(&self, username: &str, password: &str) -> Result<(), String> {
        let (user, password) = (username.to_owned(), password.to_owned());
        self.logged(LogKind::KerberosSync, username, "sync", move || {
            sync_kerberos_principal(&user, &password)
        })
        .await
    }
    async fn delete_principal(&self, username: &str) -> Result<(), String> {
        let user = username.to_owned();
        self.logged(LogKind::KerberosSync, username, "delete", move || {
            delete_kerberos_principal(&user)
        })
        .await
    }
    async fn set_principal_enabled(&self, username: &str, enabled: bool) -> Result<(), String> {
        let op = if enabled { "enable" } else { "disable" };
        let user = username.to_owned();
        self.logged(LogKind::KerberosSync, username, op, move || {
            set_kerberos_principal_enabled(&user, enabled)
        })
        .await
    }
    async fn export_keytab_for_keycloak(&self, hostname: &str) -> Result<String, String> {
        let host = hostname.to_owned();
        self.logged(LogKind::KeytabExport, hostname, "keycloak", move || {
            export_keytab_for_keycloak(&host)
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lldap_domain::types::UserId;
    use lldap_domain_handlers::logging::{Protocol, RequestMeta, with_request};
    use lldap_test_utils::recording_log::LogGuard;
    use serial_test::serial;
    use std::{net::TcpListener, sync::mpsc};

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

    #[tokio::test]
    #[serial]
    async fn test_principal_operations_record_kerberos_sync_events() {
        let guard = LogGuard::install();
        let live = LiveKerberos::on_port(1, false);

        // No KDC: the delete is a no-op success, the sync a failure; both are recorded.
        assert!(live.delete_principal("bob").await.is_ok());
        assert!(live.sync_principal("bob", "pw").await.is_err());
        assert!(
            live.export_keytab_for_keycloak("host.example.com")
                .await
                .is_err()
        );

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

    #[tokio::test]
    #[serial]
    async fn test_a_dropped_caller_keeps_the_kadm5_lock_and_its_log_row() {
        let guard = LogGuard::install();
        let live = LiveKerberos::on_port(1, false);
        let (release, held) = mpsc::channel::<()>();
        let alice = RequestMeta::ldap(Some(UserId::new("alice")), None);
        let call = live.logged(LogKind::KerberosSync, "bob", "sync", move || {
            Ok(held.recv()?)
        });
        let waited =
            tokio::time::timeout(Duration::from_millis(50), with_request(alice, call)).await;
        assert!(
            waited.is_err(),
            "the caller gives up while the call is blocked"
        );
        assert!(
            live.kadm5.try_lock().is_err(),
            "a dropped caller freed the lock mid-call"
        );

        release.send(()).unwrap();
        drop(live.kadm5.lock().await);
        let rows: Vec<_> = guard
            .recorder()
            .take_events()
            .into_iter()
            .map(|e| (e.target, e.actor))
            .collect();
        assert_eq!(
            rows,
            vec![(Some("bob".to_owned()), Some("alice".to_owned()))],
            "the dropped call's row keeps its request's actor"
        );
    }
}
