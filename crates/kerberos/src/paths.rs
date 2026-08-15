use std::env;
use std::path::PathBuf;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KerberosPaths {
    pub admin_keytab: PathBuf,
    pub kerberos_config: PathBuf,
    pub kerberos_config_template: PathBuf,
    pub krb5_conf: PathBuf,
    pub krb5_template: PathBuf,
    pub kdc_conf: PathBuf,
    pub kdc_template: PathBuf,
    pub kadm5_acl: PathBuf,
    pub kadm5_acl_template: PathBuf,
    pub kdc_dir: PathBuf,
    pub keycloak_keytab: PathBuf,
    pub kdc_port: u16,
}

impl Default for KerberosPaths {
    fn default() -> Self {
        Self {
            admin_keytab: PathBuf::from("/data/kadm5.keytab"),
            kerberos_config: PathBuf::from("/data/kerberos_config.toml"),
            kerberos_config_template: PathBuf::from("/app/kerberos_config.template.toml"),
            krb5_conf: PathBuf::from("/etc/krb5.conf"),
            krb5_template: PathBuf::from("/app/krb5.template.conf"),
            kdc_conf: PathBuf::from("/var/kerberos/krb5kdc/kdc.conf"),
            kdc_template: PathBuf::from("/app/kdc.template.conf"),
            kadm5_acl: PathBuf::from("/var/kerberos/krb5kdc/kadm5.acl"),
            kadm5_acl_template: PathBuf::from("/app/kadm5.template.acl"),
            kdc_dir: PathBuf::from("/var/kerberos/krb5kdc"),
            keycloak_keytab: PathBuf::from("/data/keytab/keycloak-http.keytab"),
            kdc_port: 88,
        }
    }
}

impl KerberosPaths {
    pub fn from_env() -> Self {
        Self::from_lookup(|key| env::var(key).ok())
    }

    fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Self {
        let defaults = Self::default();
        let path = |key: &str, default: PathBuf| {
            get(key)
                .filter(|value| !value.is_empty())
                .map(PathBuf::from)
                .unwrap_or(default)
        };
        Self {
            admin_keytab: path("LLDAP_KERB_ADMIN_KEYTAB", defaults.admin_keytab),
            kerberos_config: path("LLDAP_KERB_CONFIG", defaults.kerberos_config),
            kerberos_config_template: path(
                "LLDAP_KERB_CONFIG_TEMPLATE",
                defaults.kerberos_config_template,
            ),
            krb5_conf: path("LLDAP_KERB_KRB5_CONF", defaults.krb5_conf),
            krb5_template: path("LLDAP_KERB_KRB5_TEMPLATE", defaults.krb5_template),
            kdc_conf: path("LLDAP_KERB_KDC_CONF", defaults.kdc_conf),
            kdc_template: path("LLDAP_KERB_KDC_TEMPLATE", defaults.kdc_template),
            kadm5_acl: path("LLDAP_KERB_KADM5_ACL", defaults.kadm5_acl),
            kadm5_acl_template: path("LLDAP_KERB_KADM5_ACL_TEMPLATE", defaults.kadm5_acl_template),
            kdc_dir: path("LLDAP_KERB_KDC_DIR", defaults.kdc_dir),
            keycloak_keytab: path("LLDAP_KERB_KEYCLOAK_KEYTAB", defaults.keycloak_keytab),
            kdc_port: get("LLDAP_KERB_KDC_PORT")
                .and_then(|value| value.parse().ok())
                .unwrap_or(defaults.kdc_port),
        }
    }

    pub fn kdc_principal(&self) -> PathBuf {
        self.kdc_dir.join("principal")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_matches_container_layout() {
        let paths = KerberosPaths::default();
        assert_eq!(paths.admin_keytab, PathBuf::from("/data/kadm5.keytab"));
        assert_eq!(
            paths.kdc_principal(),
            PathBuf::from("/var/kerberos/krb5kdc/principal")
        );
        assert_eq!(paths.kdc_port, 88);
    }

    #[test]
    fn lookup_overrides_non_empty_values_only() {
        let paths = KerberosPaths::from_lookup(|key| match key {
            "LLDAP_KERB_ADMIN_KEYTAB" => Some("/tmp/sandbox/kadm5.keytab".to_owned()),
            "LLDAP_KERB_KDC_DIR" => Some(String::new()),
            "LLDAP_KERB_KDC_PORT" => Some("18888".to_owned()),
            _ => None,
        });
        assert_eq!(
            paths.admin_keytab,
            PathBuf::from("/tmp/sandbox/kadm5.keytab")
        );
        assert_eq!(paths.kdc_dir, PathBuf::from("/var/kerberos/krb5kdc"));
        assert_eq!(paths.kdc_port, 18888);
    }

    #[test]
    fn unparsable_port_falls_back_to_default() {
        let paths = KerberosPaths::from_lookup(|key| {
            (key == "LLDAP_KERB_KDC_PORT").then(|| "kdc".to_owned())
        });
        assert_eq!(paths.kdc_port, 88);
    }
}
