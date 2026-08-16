#![deny(unsafe_code)]
#![deny(unsafe_op_in_unsafe_fn)]
#![warn(clippy::undocumented_unsafe_blocks)]
use anyhow::{Context, Result};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;
use tracing::{info, warn};

pub mod live;
pub mod manager;
pub mod paths;

pub use lldap_domain_handlers::kerberos::{
    derive_domain_from_base_dn, derive_realm_from_base_dn, domain_from_base_dn, principal_name,
    validate_kerberos_username, validate_keytab_hostname,
};
use paths::KerberosPaths;

mod ffi;
pub(crate) use ffi::Kadm5Handle;

fn admin_handle(realm: &str) -> Result<Kadm5Handle> {
    let keytab = KerberosPaths::from_env().admin_keytab;
    Kadm5Handle::init_with_keytab(
        &keytab.to_string_lossy(),
        &format!("admin/admin@{realm}"),
        realm,
    )
    .with_context(|| {
        format!(
            "while initializing the Kerberos admin handle from {}",
            keytab.display()
        )
    })
}

pub fn delete_kerberos_principal(username: &str) -> Result<()> {
    validate_kerberos_username(username).map_err(anyhow::Error::msg)?;
    let realm = derive_realm_from_base_dn();
    let full_principal = format!("{username}@{realm}");
    info!(
        "Attempting to delete Kerberos principal via FFI: {}",
        full_principal
    );

    // No admin handle: Kerberos is off or not bootstrapped; delete is a no-op.
    let handle = match admin_handle(&realm) {
        Ok(handle) => handle,
        Err(e) => {
            info!(
                "Kerberos admin handle unavailable for principal delete ({:#}). \
                 Treating as success (principal either never existed or Kerberos sync disabled).",
                e
            );
            return Ok(());
        }
    };
    handle.delete_principal(&full_principal)
}

/// `enabled == false` sets DISALLOW_ALL_TIX; a missing admin handle is a no-op.
pub fn set_kerberos_principal_enabled(username: &str, enabled: bool) -> Result<()> {
    validate_kerberos_username(username).map_err(anyhow::Error::msg)?;
    let realm = derive_realm_from_base_dn();
    let handle = match admin_handle(&realm) {
        Ok(handle) => handle,
        Err(e) => {
            info!(
                "Kerberos admin handle unavailable to {} principal for user {} ({:#}). \
                 Treating as no-op (Kerberos disabled or not yet bootstrapped).",
                if enabled { "enable" } else { "disable" },
                username,
                e
            );
            return Ok(());
        }
    };
    handle.set_principal_allow_tickets(username, &realm, enabled)
}

pub fn sync_kerberos_principal(username: &str, plain_password: &str) -> Result<()> {
    validate_kerberos_username(username).map_err(anyhow::Error::msg)?;
    let realm = derive_realm_from_base_dn();
    let full_principal = format!("{username}@{realm}");
    info!("Kerberos sync started for principal: {}", full_principal);
    let handle = admin_handle(&realm)?;

    if handle
        .chpass_principal(username, plain_password, &realm)
        .is_ok()
    {
        info!(
            "✅ Kerberos password updated successfully for {}",
            full_principal
        );
        return Ok(());
    }

    warn!("Change password failed (likely principal does not exist), creating new principal...");
    handle
        .create_principal(username, plain_password, &realm)
        .context("while creating the Kerberos principal")?;
    info!(
        "✅ Kerberos principal created and password set for {}",
        full_principal
    );
    Ok(())
}

pub fn export_keytab_for_keycloak(hostname_input: &str) -> Result<String> {
    let realm = derive_realm_from_base_dn();
    let hostname = match hostname_input.trim() {
        "" | "keycloak" => format!("keycloak.{}", derive_domain_from_base_dn()),
        hostname => hostname.to_owned(),
    };
    validate_keytab_hostname(&hostname).map_err(anyhow::Error::msg)?;
    let principal = format!("HTTP/{hostname}@{realm}");
    info!("Generating Keycloak keytab for principal: {}", principal);
    let paths = KerberosPaths::from_env();
    let handle = admin_handle(&realm)?;
    let keytab_path = &paths.keycloak_keytab;
    if let Some(dir) = keytab_path.parent() {
        fs::create_dir_all(dir).with_context(|| format!("while creating {}", dir.display()))?;
    }
    let _ = fs::remove_file(keytab_path);

    handle.set_random_key_for_service(&principal)?;
    let query = format!(
        "ktadd -k {} -e aes256-cts-hmac-sha1-96:normal,aes128-cts-hmac-sha1-96:normal {}",
        keytab_path.display(),
        principal
    );
    // -p: this uid may have no passwd entry for kadmin.local to derive a name from.
    let output = Command::new("/usr/sbin/kadmin.local")
        .env("KRB5_CONFIG", &paths.krb5_conf)
        .arg("-p")
        .arg(format!("admin/admin@{realm}"))
        .arg("-q")
        .arg(&query)
        .output()
        .context("while running kadmin.local")?;
    if !output.status.success() {
        anyhow::bail!(
            "kadmin.local ktadd failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    lock_down_keytab(keytab_path)?;

    info!("Keytab successfully exported to {}", keytab_path.display());
    Ok(keytab_path.display().to_string())
}

fn lock_down_keytab(path: &Path) -> Result<()> {
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .with_context(|| format!("while chmodding {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sync_principal_rejects_krbtgt_before_touching_the_kdc() {
        let err = sync_kerberos_principal("krbtgt", "secret")
            .expect_err("krbtgt must never be synced")
            .to_string();
        assert!(
            err.contains("reserved"),
            "expected reserved-name error, got {err}"
        );
    }

    #[test]
    fn test_lock_down_keytab_is_owner_read_write_only() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("kll-keytab-mode-{}", std::process::id()));
        std::fs::write(&path, b"keytab").unwrap();
        lock_down_keytab(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        let _ = std::fs::remove_file(&path);
        assert_eq!(mode, 0o600, "exported keytab must not be world-readable");
    }

    #[test]
    fn test_export_keytab_rejects_injected_hostname_before_kadmin() {
        let err = export_keytab_for_keycloak("foo\ndelprinc admin/admin")
            .expect_err("newline hostname must be rejected")
            .to_string();
        assert!(
            err.contains("hostname") || err.contains("invalid"),
            "expected hostname validation error, got {err}"
        );
    }
}
