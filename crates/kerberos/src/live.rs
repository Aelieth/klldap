use crate::{
    delete_kerberos_principal, export_keytab_for_keycloak, paths::KerberosPaths,
    set_kerberos_principal_enabled, sync_kerberos_principal,
};
use lldap_domain_handlers::kerberos::KerberosSync;
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
        sync_kerberos_principal(username, password).map_err(|e| format!("{e:#}"))
    }
    fn delete_principal(&self, username: &str) -> Result<(), String> {
        delete_kerberos_principal(username).map_err(|e| format!("{e:#}"))
    }
    fn set_principal_enabled(&self, username: &str, enabled: bool) -> Result<(), String> {
        set_kerberos_principal_enabled(username, enabled).map_err(|e| format!("{e:#}"))
    }
    fn export_keytab_for_keycloak(&self, hostname: &str) -> Result<String, String> {
        export_keytab_for_keycloak(hostname).map_err(|e| format!("{e:#}"))
    }
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
