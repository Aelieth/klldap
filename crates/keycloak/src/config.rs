use anyhow::{Context, Result};
use lldap_domain_handlers::kerberos::domain_from_base_dn;
use secstr::SecUtf8;
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use tracing::warn;

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
        write_synced(path, format!("{header}{body}").as_bytes())
            .with_context(|| format!("while writing {}", path.display()))?;
        Ok(path.to_path_buf())
    }
}

fn write_synced(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let parent = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    let name = path.file_name().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "path has no file name")
    })?;
    let tmp = parent.join(format!(
        ".{}.{}.{}.tmp",
        name.to_string_lossy(),
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    let mut created = false;
    let result = (|| {
        let mut file = OpenOptions::new().write(true).create_new(true).open(&tmp)?;
        created = true;
        file.write_all(bytes)?;
        if let Ok(meta) = fs::metadata(path) {
            fs::set_permissions(&tmp, meta.permissions())?;
        }
        file.sync_all()?;
        Ok(())
    })();
    if let Err(err) = result {
        if created {
            let _ = fs::remove_file(&tmp);
        }
        return Err(err);
    }
    if let Err(err) = fs::rename(&tmp, path) {
        let _ = fs::remove_file(&tmp);
        return Err(err);
    }
    match File::open(parent) {
        Ok(dir) => {
            if let Err(err) = dir.sync_all() {
                warn!("could not sync {}: {err}", parent.display());
            }
        }
        Err(err) => warn!("could not sync {}: {err}", parent.display()),
    }
    Ok(())
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
    use std::os::unix::fs::PermissionsExt;

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

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("klldap-kco-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn sample() -> KeycloakConfig {
        KeycloakConfig {
            url: "http://keycloak.gate.test".into(),
            realm: "gate.test".into(),
            admin_user: "admin".into(),
        }
    }

    fn no_temp_left(dir: &Path) -> bool {
        fs::read_dir(dir).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .contains(".tmp")
        })
    }

    #[test]
    fn save_replaces_the_file_and_leaves_no_temp() {
        let dir = scratch("save");
        let path = dir.join("keycloak_config.toml");
        let cfg = sample();
        cfg.save(&path).unwrap();
        let text = fs::read_to_string(&path).unwrap();
        assert!(
            text.starts_with("# KLLDAP Keycloak federation settings"),
            "{text}"
        );
        assert_eq!(
            KeycloakConfig::load("dc=other,dc=com", "OTHER.COM", &path).unwrap(),
            cfg
        );
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        let next = KeycloakConfig {
            admin_user: "kcadmin".into(),
            ..cfg
        };
        next.save(&path).unwrap();
        let text = fs::read_to_string(&path).unwrap();
        assert!(text.contains("kcadmin"), "{text}");
        assert_eq!(
            KeycloakConfig::load("dc=other,dc=com", "OTHER.COM", &path).unwrap(),
            next
        );
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o640
        );
        assert!(no_temp_left(&dir));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_failed_save_leaves_the_previous_file() {
        let dir = scratch("fail");
        let path = dir.join("keycloak_config.toml");
        sample().save(&path).unwrap();
        let before = fs::read(&path).unwrap();
        let mode = fs::metadata(&dir).unwrap().permissions().mode();
        struct Restore(PathBuf, u32);
        impl Drop for Restore {
            fn drop(&mut self) {
                let _ = fs::set_permissions(&self.0, fs::Permissions::from_mode(self.1));
                let _ = fs::remove_dir_all(&self.0);
            }
        }
        let _restore = Restore(dir.clone(), mode);
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o555)).unwrap();
        if File::create(dir.join(".probe")).is_ok() {
            let _ = fs::remove_file(dir.join(".probe"));
            eprintln!("a_failed_save_leaves_the_previous_file: directory stayed writable");
            return;
        }
        let err = KeycloakConfig {
            admin_user: "other".into(),
            ..sample()
        }
        .save(&path)
        .unwrap_err();
        assert!(err.to_string().contains("while writing"), "{err}");
        assert_eq!(fs::read(&path).unwrap(), before);
        fs::set_permissions(&dir, fs::Permissions::from_mode(mode)).unwrap();
        assert!(no_temp_left(&dir));
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
