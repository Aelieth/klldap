use lldap_domain_model::error::DomainError;
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

const RESERVED_PRINCIPALS: &[&str] = &["krbtgt", "kadmin", "kiprop", "wellknown"];

/// Usernames that become `{user}@{realm}` must be a single principal component:
/// no `/` `@` whitespace (those would parse as another principal or feed
/// `kadmin.local -q`), and never the KDC's own reserved names.
pub fn validate_kerberos_username(username: &str) -> Result<(), String> {
    if username.is_empty() || username.len() > 128 {
        return Err("Kerberos username is empty or longer than 128 characters".to_owned());
    }
    let mut chars = username.chars();
    let Some(first) = chars.next() else {
        return Err("Kerberos username is empty".to_owned());
    };
    if !first.is_ascii_alphanumeric()
        || !chars.all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-')
    {
        return Err("Kerberos username must be ASCII alphanumeric plus '.', '_' or '-'".to_owned());
    }
    if RESERVED_PRINCIPALS
        .iter()
        .any(|reserved| username.eq_ignore_ascii_case(reserved))
    {
        return Err(format!(
            "Kerberos username '{username}' is reserved by the KDC"
        ));
    }
    Ok(())
}

/// Hostnames interpolated into `HTTP/{host}@{realm}` and then into
/// `kadmin.local -q` must be a DNS name or IPv4 address: no spaces, slashes
/// or newlines that would split the query.
pub fn validate_keytab_hostname(hostname: &str) -> Result<(), String> {
    if hostname.is_empty() || hostname.len() > 253 {
        return Err("Keytab hostname is empty or longer than 253 characters".to_owned());
    }
    if hostname.starts_with('.') || hostname.ends_with('.') {
        return Err("Keytab hostname must be a DNS name or IPv4 address".to_owned());
    }
    for label in hostname.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err("Keytab hostname has an empty or oversized label".to_owned());
        }
        let bytes = label.as_bytes();
        if !bytes[0].is_ascii_alphanumeric() || !bytes[label.len() - 1].is_ascii_alphanumeric() {
            return Err(
                "Keytab hostname labels must start and end with an alphanumeric character"
                    .to_owned(),
            );
        }
        if !bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || *b == b'-')
        {
            return Err("Keytab hostname contains invalid characters".to_owned());
        }
    }
    Ok(())
}

pub trait KerberosSync: Send + Sync {
    /// Whether the KDC has been reachable at least once since the process started.
    fn ready(&self) -> bool {
        true
    }
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

/// Directory writes are refused until the KDC has come up, so nothing changes that the
/// KDC could not follow.
pub fn require_kdc_ready() -> Result<(), DomainError> {
    if kerberos_backend().ready() {
        Ok(())
    } else {
        Err(DomainError::KdcUnavailable(
            "the Kerberos KDC is still starting; retry shortly".to_owned(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_domain_from_base_dn_joins_dc_components() {
        assert_eq!(domain_from_base_dn("dc=gate,dc=test"), "gate.test");
        assert_eq!(domain_from_base_dn("dc=Example,dc=COM"), "example.com");
        assert_eq!(
            domain_from_base_dn("ou=people,dc=example,dc=com"),
            "example.com"
        );
    }

    #[test]
    fn test_realm_prefers_non_empty_override_and_uppercases() {
        assert_eq!(realm_from(None, "dc=gate,dc=test"), "GATE.TEST");
        assert_eq!(realm_from(Some(""), "dc=gate,dc=test"), "GATE.TEST");
        assert_eq!(
            realm_from(Some("custom.realm"), "dc=gate,dc=test"),
            "CUSTOM.REALM"
        );
    }

    #[test]
    fn test_principal_name_is_user_at_realm() {
        assert_eq!(
            format!("bob@{}", realm_from(Some("gate.test"), "dc=unused,dc=com")),
            "bob@GATE.TEST"
        );
    }

    #[test]
    fn test_validate_kerberos_username_accepts_directory_ids() {
        for name in [
            "bob",
            "admin",
            "bob.smith",
            "bob_smith",
            "bob-1",
            &format!("user-{}", "a".repeat(60)),
        ] {
            assert_eq!(validate_kerberos_username(name), Ok(()), "{name}");
        }
    }

    #[test]
    fn test_validate_kerberos_username_rejects_injection_and_reserved() {
        for name in [
            "",
            "bob/admin",
            "bob@realm",
            "bob principal",
            "bob\ndelprinc",
            "krbtgt",
            "KAdmin",
            "kiprop",
            "WELLKNOWN",
            "-leading",
            "has space",
        ] {
            assert!(
                validate_kerberos_username(name).is_err(),
                "expected {name:?} to be rejected"
            );
        }
    }

    #[test]
    fn test_validate_keytab_hostname_accepts_dns_and_ipv4() {
        for host in ["keycloak", "keycloak.example.com", "192.168.1.10"] {
            assert_eq!(validate_keytab_hostname(host), Ok(()), "{host}");
        }
    }

    #[test]
    fn test_validate_keytab_hostname_rejects_kadmin_injection() {
        for host in [
            "",
            "foo\ndelprinc admin/admin",
            "foo; delprinc",
            "foo bar",
            "../etc",
            "foo/bar",
            "-leading",
            ".example.com",
            "example.com.",
        ] {
            assert!(
                validate_keytab_hostname(host).is_err(),
                "expected {host:?} to be rejected"
            );
        }
    }
}
