use anyhow::{Context, Result};
use lldap_domain_handlers::kerberos::{derive_domain_from_base_dn, derive_realm_from_base_dn};
use serde::{Deserialize, Serialize};
use std::env;
use std::path::PathBuf;

pub const SUGGESTED_HOSTNAME: &str = "keycloak";

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct KeycloakConfig {
    pub url: String,
    pub realm: String,
    pub admin_user: String,
}

impl KeycloakConfig {
    pub fn path() -> PathBuf {
        env::var("LLDAP_KEYCLOAK_CONFIG")
            .ok()
            .filter(|path| !path.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/data/keycloak_config.toml"))
    }

    pub fn suggested() -> Self {
        Self {
            url: format!(
                "http://{SUGGESTED_HOSTNAME}.{}",
                derive_domain_from_base_dn()
            ),
            realm: derive_realm_from_base_dn().to_lowercase(),
            admin_user: "admin".to_owned(),
        }
    }

    pub fn load() -> Result<Self> {
        let path = Self::path();
        if !path.exists() {
            return Ok(Self::suggested());
        }
        let contents = std::fs::read_to_string(&path)
            .with_context(|| format!("while reading {}", path.display()))?;
        toml::from_str(&contents).with_context(|| format!("while parsing {}", path.display()))
    }

    pub fn save(&self) -> Result<PathBuf> {
        let path = Self::path();
        let header = "# KLLDAP Keycloak federation settings, written from the Federation tab.\n\
                      # The admin password is not stored here: set LLDAP_KEYCLOAK_ADMIN_PASS.\n\n";
        let body = toml::to_string_pretty(self).context("while serializing the Keycloak config")?;
        std::fs::write(&path, format!("{header}{body}"))
            .with_context(|| format!("while writing {}", path.display()))?;
        Ok(path)
    }
}

pub fn admin_password() -> Result<String> {
    admin_password_from(env::var("LLDAP_KEYCLOAK_ADMIN_PASS").ok().as_deref())
}

fn admin_password_from(value: Option<&str>) -> Result<String> {
    value
        .map(str::trim)
        .filter(|pass| !pass.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| anyhow::anyhow!("LLDAP_KEYCLOAK_ADMIN_PASS is not set"))
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_admin_password_has_no_default() {
        assert!(super::admin_password_from(None).is_err());
        assert!(super::admin_password_from(Some("")).is_err());
        assert!(super::admin_password_from(Some("   ")).is_err());
        assert_eq!(
            super::admin_password_from(Some("s3cret")).unwrap(),
            "s3cret"
        );
    }
}
