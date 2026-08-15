use crate::{
    delete_kerberos_principal, export_keytab_for_keycloak, set_kerberos_principal_enabled,
    sync_kerberos_principal,
};
use lldap_domain_handlers::kerberos::KerberosSync;

pub struct LiveKerberos;

impl KerberosSync for LiveKerberos {
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
