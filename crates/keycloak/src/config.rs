use anyhow::{Context, Result};
use lldap_domain_handlers::kerberos::domain_from_base_dn;
use secstr::SecUtf8;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

pub const SUGGESTED_HOSTNAME: &str = "keycloak";

pub struct KeycloakSettings {
    pub base_dn: String,
    pub config_file: PathBuf,
    pub admin_pass: Option<SecUtf8>,
}

impl KeycloakSettings {
    pub fn admin_pass_str(&self) -> Option<&str> {
        self.admin_pass.as_ref().map(SecUtf8::unsecure)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct KeycloakConfig {
    pub url: String,
    pub realm: String,
    pub admin_user: String,
}

impl KeycloakConfig {
    pub fn suggested(base_dn: &str, realm: &str) -> Self {
        Self {
            url: format!(
                "http://{SUGGESTED_HOSTNAME}.{}",
                domain_from_base_dn(base_dn)
            ),
            realm: realm.to_lowercase(),
            admin_user: "admin".to_owned(),
        }
    }

    pub fn load(base_dn: &str, realm: &str, path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::suggested(base_dn, realm));
        }
        let contents = std::fs::read_to_string(path)
            .with_context(|| format!("while reading {}", path.display()))?;
        toml::from_str(&contents).with_context(|| format!("while parsing {}", path.display()))
    }

    pub fn save(&self, path: &Path) -> Result<PathBuf> {
        let header = "# KLLDAP Keycloak federation settings, written from the Federation tab.\n\
                      # The admin password is not stored here. Set keycloak_options.admin_pass\n\
                      # (LLDAP_KEYCLOAK_OPTIONS__ADMIN_PASS).\n\n";
        let body = toml::to_string_pretty(self).context("while serializing the Keycloak config")?;
        std::fs::write(path, format!("{header}{body}"))
            .with_context(|| format!("while writing {}", path.display()))?;
        Ok(path.to_path_buf())
    }
}

pub fn admin_password(value: Option<&str>) -> Result<String> {
    value
        .map(str::trim)
        .filter(|pass| !pass.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| anyhow::anyhow!("admin password is not set"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_admin_password_has_no_default() {
        let err = super::admin_password(None).unwrap_err();
        assert!(
            err.to_string().contains("admin password is not set"),
            "{err}"
        );
        assert!(super::admin_password(Some("")).is_err());
        assert!(super::admin_password(Some("   ")).is_err());
        assert_eq!(super::admin_password(Some("s3cret")).unwrap(), "s3cret");
    }

    #[test]
    fn save_then_load_round_trips_through_a_temporary_path() {
        let path = std::env::temp_dir().join(format!("kco-save-load-{}.toml", std::process::id()));
        let cfg = KeycloakConfig {
            url: "http://keycloak.gate.test".into(),
            realm: "gate.test".into(),
            admin_user: "admin".into(),
        };
        cfg.save(&path).unwrap();
        let loaded = KeycloakConfig::load("dc=other,dc=com", "OTHER.COM", &path).unwrap();
        let _ = std::fs::remove_file(&path);
        assert_eq!(loaded, cfg);
    }

    #[test]
    fn suggested_uses_the_base_dn_and_lowercases_the_realm() {
        let rows = [
            (
                "dc=Example,dc=Com",
                "Example.COM",
                "example.com",
                "example.com",
            ),
            ("dc=gate,dc=test", "GATE.TEST", "gate.test", "gate.test"),
        ];
        for (base_dn, realm, domain, lowered) in rows {
            let cfg = super::KeycloakConfig::suggested(base_dn, realm);
            assert_eq!(cfg.url, format!("http://keycloak.{domain}"));
            assert_eq!(cfg.realm, lowered);
        }
    }
}
