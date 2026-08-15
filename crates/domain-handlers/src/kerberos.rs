use std::env;
use std::sync::{Arc, LazyLock, RwLock};
use tracing::warn;

const DEFAULT_BASE_DN: &str = "dc=example,dc=com";

pub fn base_dn_from_env() -> String {
    env::var("LLDAP_LDAP_BASE_DN").unwrap_or_else(|_| DEFAULT_BASE_DN.to_owned())
}

pub fn domain_from_base_dn(base_dn: &str) -> String {
    base_dn
        .split(',')
        .filter_map(|part| part.strip_prefix("dc="))
        .collect::<Vec<_>>()
        .join(".")
        .to_lowercase()
}

pub fn derive_domain_from_base_dn() -> String {
    domain_from_base_dn(&base_dn_from_env())
}

fn realm_from(realm_override: Option<&str>, base_dn: &str) -> String {
    realm_override
        .filter(|realm| !realm.is_empty())
        .map(str::to_owned)
        .unwrap_or_else(|| domain_from_base_dn(base_dn))
        .to_uppercase()
}

pub fn derive_realm_from_base_dn() -> String {
    realm_from(
        env::var("LLDAP_KERB_REALM_NAME").ok().as_deref(),
        &base_dn_from_env(),
    )
}

pub fn principal_name(username: &str) -> String {
    format!("{username}@{}", derive_realm_from_base_dn())
}

pub trait KerberosSync: Send + Sync {
    fn sync_principal(&self, username: &str, password: &str) -> Result<(), String>;
    fn sync_if_enabled(
        &self,
        sync_enabled: bool,
        username: &str,
        password: &str,
    ) -> Result<(), String> {
        if sync_enabled {
            self.sync_principal(username, password)
        } else {
            Ok(())
        }
    }
    fn delete_principal(&self, username: &str) -> Result<(), String>;
    fn set_principal_enabled(&self, username: &str, enabled: bool) -> Result<(), String>;
    fn reassert_disabled(&self, username: &str) {
        if let Err(e) = self.set_principal_enabled(username, false) {
            warn!("Failed to re-assert Kerberos disable for {username} after password set: {e}");
        }
    }
    fn export_keytab_for_keycloak(&self, hostname: &str) -> Result<String, String>;
}

const NOT_REGISTERED: &str = "Kerberos backend not registered";

// Mirrors the FFI functions without a reachable KDC: idempotent cleanups succeed,
// operations that must reach the KDC fail, so a missing registration stays visible.
pub struct NoopKerberos;

impl KerberosSync for NoopKerberos {
    fn sync_principal(&self, _: &str, _: &str) -> Result<(), String> {
        Err(NOT_REGISTERED.to_owned())
    }
    fn delete_principal(&self, _: &str) -> Result<(), String> {
        Ok(())
    }
    fn set_principal_enabled(&self, _: &str, _: bool) -> Result<(), String> {
        Ok(())
    }
    fn export_keytab_for_keycloak(&self, _: &str) -> Result<String, String> {
        Err(NOT_REGISTERED.to_owned())
    }
}

// Process-global so ldap/sql call sites stay one-liners; tests that install a
// recorder must be #[serial] and restore the default on drop.
static BACKEND: LazyLock<RwLock<Arc<dyn KerberosSync>>> =
    LazyLock::new(|| RwLock::new(Arc::new(NoopKerberos)));

pub fn kerberos_backend() -> Arc<dyn KerberosSync> {
    BACKEND.read().expect("kerberos backend").clone()
}

pub fn set_kerberos_backend(backend: Arc<dyn KerberosSync>) {
    *BACKEND.write().expect("kerberos backend") = backend;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_from_base_dn_joins_dc_components() {
        assert_eq!(domain_from_base_dn("dc=gate,dc=test"), "gate.test");
        assert_eq!(domain_from_base_dn("dc=Example,dc=COM"), "example.com");
        assert_eq!(
            domain_from_base_dn("ou=people,dc=example,dc=com"),
            "example.com"
        );
    }

    #[test]
    fn realm_prefers_non_empty_override_and_uppercases() {
        assert_eq!(realm_from(None, "dc=gate,dc=test"), "GATE.TEST");
        assert_eq!(realm_from(Some(""), "dc=gate,dc=test"), "GATE.TEST");
        assert_eq!(
            realm_from(Some("custom.realm"), "dc=gate,dc=test"),
            "CUSTOM.REALM"
        );
    }

    #[test]
    fn principal_name_is_user_at_realm() {
        assert_eq!(
            format!("bob@{}", realm_from(Some("gate.test"), "dc=unused,dc=com")),
            "bob@GATE.TEST"
        );
    }
}
