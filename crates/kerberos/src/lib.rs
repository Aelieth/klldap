#![recursion_limit = "256"]
use anyhow::{Context, Result};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use rand::rngs::OsRng;
use rsa::pkcs1::EncodeRsaPublicKey;
use rsa::{Oaep, RsaPrivateKey, RsaPublicKey};
use sha2::Sha256;
use std::process::Command;
use std::{env, fs};
use tracing::{info, warn};

pub mod keycloak_client;
pub mod keycloak_config;

pub use keycloak_client::KeycloakClient;
pub use keycloak_config::{
    KeycloakConfig, KeycloakSuggestedConfig, get_keycloak_admin_password,
    get_keycloak_suggested_config, load_keycloak_config, save_keycloak_config,
};

mod ffi;
pub(crate) use ffi::Kadm5Handle;

pub fn domain_from_base_dn(base_dn: &str) -> String {
    base_dn
        .split(',')
        .filter_map(|part| part.strip_prefix("dc="))
        .collect::<Vec<_>>()
        .join(".")
        .to_lowercase()
}

pub fn derive_domain_from_base_dn() -> String {
    domain_from_base_dn(
        &env::var("LLDAP_LDAP_BASE_DN").unwrap_or_else(|_| "dc=example,dc=com".to_string()),
    )
}

pub fn derive_realm_from_base_dn() -> String {
    env::var("LLDAP_KERB_REALM_NAME")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(derive_domain_from_base_dn)
        .to_uppercase()
}

static KEYPAIR: std::sync::LazyLock<(RsaPrivateKey, RsaPublicKey)> =
    std::sync::LazyLock::new(|| {
        generate_keypair().expect("Failed to generate RSA keypair for Kerberos password sync")
    });

fn generate_keypair() -> Result<(RsaPrivateKey, RsaPublicKey)> {
    let mut rng = OsRng;
    let bits = 2048;
    let priv_key = RsaPrivateKey::new(&mut rng, bits).context("Failed to generate private key")?;
    let pub_key = RsaPublicKey::from(&priv_key);
    Ok((priv_key, pub_key))
}

pub fn decrypt_password(encrypted: &str) -> Result<String> {
    let priv_key = &KEYPAIR.0;
    let dec_data = STANDARD.decode(encrypted).context("Base64 decode failed")?;
    let padding = Oaep::new::<Sha256>();
    let plain_data = priv_key
        .decrypt(padding, &dec_data)
        .context("Decryption failed")?;
    String::from_utf8(plain_data).context("UTF-8 decode failed")
}

pub fn delete_kerberos_principal(username: &str) -> Result<()> {
    let realm_upper = derive_realm_from_base_dn();
    let full_principal = format!("{}@{}", username, realm_upper);
    info!(
        "Attempting to delete Kerberos principal via FFI: {}",
        full_principal
    );

    let admin_principal = format!("admin/admin@{}", realm_upper);
    let keytab_path = "/data/kadm5.keytab";

    // An unavailable admin handle means Kerberos is disabled or not yet bootstrapped;
    // deleting a principal that cannot exist is treated as idempotent success.
    let handle = match Kadm5Handle::init_with_keytab(keytab_path, &admin_principal, &realm_upper) {
        Ok(h) => h,
        Err(e) => {
            info!(
                "Kerberos admin handle unavailable for principal delete ({}). \
                 Treating as success (principal either never existed or Kerberos sync disabled).",
                e
            );
            return Ok(());
        }
    };

    handle.delete_principal(&full_principal)
}

/// Enable or disable Kerberos ticket issuance for a user's principal:
/// `enabled == false` sets DISALLOW_ALL_TIX (`kadmin modprinc -allow_tix`), `true` clears it
/// (`+allow_tix`). Mirrors `delete_kerberos_principal`'s graceful degradation — if the admin handle
/// can't init (Kerberos disabled or not yet bootstrapped) it's an idempotent no-op.
pub fn set_kerberos_principal_enabled(username: &str, enabled: bool) -> Result<()> {
    let realm_upper = derive_realm_from_base_dn();
    let admin_principal = format!("admin/admin@{}", realm_upper);
    let keytab_path = "/data/kadm5.keytab";

    let handle = match Kadm5Handle::init_with_keytab(keytab_path, &admin_principal, &realm_upper) {
        Ok(h) => h,
        Err(e) => {
            info!(
                "Kerberos admin handle unavailable to {} principal for user {} ({}). \
                 Treating as no-op (Kerberos disabled or not yet bootstrapped).",
                if enabled { "enable" } else { "disable" },
                username,
                e
            );
            return Ok(());
        }
    };

    handle.set_principal_allow_tickets(username, &realm_upper, enabled)
}

pub fn sync_kerberos_principal(username: &str, plain_password: &str) -> Result<()> {
    let full_principal = get_kerberos_principal_name(username);
    info!("Kerberos sync started for principal: {}", full_principal);

    let realm_upper = derive_realm_from_base_dn();

    let admin_principal = format!("admin/admin@{}", realm_upper);
    let keytab_path = "/data/kadm5.keytab";

    info!(
        "Using direct keytab auth for admin: {} (keytab: {})",
        admin_principal, keytab_path
    );

    let handle = Kadm5Handle::init_with_keytab(keytab_path, &admin_principal, &realm_upper)
    .context("Failed to initialize Kerberos admin handle with keytab (check keytab exists/permissions)")?;

    // Try change password first (most common case after user already exists)
    if handle
        .chpass_principal(username, plain_password, &realm_upper)
        .is_ok()
    {
        info!(
            "✅ Kerberos password updated successfully for {}",
            full_principal
        );
        return Ok(());
    }

    warn!("Change password failed (likely principal does not exist)—creating new principal...");

    handle
        .create_principal(username, plain_password, &realm_upper)
        .context("Failed to create new Kerberos principal")?;

    info!(
        "✅ Kerberos principal created and password set for {}",
        full_principal
    );
    Ok(())
}

pub fn get_public_key_der_base64() -> String {
    let der = KEYPAIR
        .1
        .to_pkcs1_der()
        .expect("Failed to encode Kerberos RSA public key as PKCS1 DER");
    STANDARD.encode(der.as_bytes())
}

pub fn export_keytab_for_keycloak(hostname_input: &str) -> Result<String> {
    let realm = derive_realm_from_base_dn();
    let domain = derive_domain_from_base_dn();

    let hostname = if hostname_input.trim().is_empty() || hostname_input.trim() == "keycloak" {
        format!("keycloak.{}", domain)
    } else {
        hostname_input.trim().to_string()
    };

    let principal = format!("HTTP/{}@{}", hostname, realm);
    info!("Generating Keycloak keytab for principal: {}", principal);

    let admin_principal = format!("admin/admin@{}", realm);

    let handle = Kadm5Handle::init_with_keytab("/data/kadm5.keytab", &admin_principal, &realm)
        .context("Failed to initialize Kerberos admin handle")?;

    let keytab_path = "/data/keytab/keycloak-http.keytab";
    let _ = fs::remove_file(keytab_path);

    // Step 1: Ensure principal exists and has a fresh key (via FFI)
    handle.set_random_key_for_service(&principal)?;

    // Step 2: Export the keytab using kadmin.local (no sudo)
    // Force strong encryption types so Keycloak/Java can decrypt SPNEGO tickets
    let query = format!(
        "ktadd -k {} -e aes256-cts-hmac-sha1-96:normal,aes128-cts-hmac-sha1-96:normal {}",
        keytab_path, principal
    );

    let output = Command::new("/usr/sbin/kadmin.local")
        .env("KRB5_CONFIG", "/etc/krb5.conf")
        .arg("-q")
        .arg(&query)
        .output()
        .context("Failed to execute kadmin.local")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow::anyhow!("kadmin.local ktadd failed: {}", stderr));
    }

    info!("Keytab successfully exported to {}", keytab_path);
    Ok(keytab_path.to_string())
}

// Returns the full Kerberos principal name for any user (e.g. "testuser1@TESTLABBY.LOCAL") Used by Keycloak LDAP provider
pub fn get_kerberos_principal_name(username: &str) -> String {
    let realm_upper = derive_realm_from_base_dn();
    format!("{}@{}", username, realm_upper)
}

// Central call for Kerberos sync—callers pass if sync is enabled (from attr check).
pub fn sync_kerberos_if_enabled(
    sync_enabled: bool,
    user_id: &str,
    plain_password: &str,
) -> Result<()> {
    if sync_enabled {
        info!(
            "Kerberos sync enabled for user {}; triggering principal sync",
            user_id
        );
        sync_kerberos_principal(user_id, plain_password)
    } else {
        info!("Kerberos sync disabled for user {}; skipping", user_id);
        Ok(())
    }
}

/// After a password sync that may have minted a live principal, re-assert DISALLOW_ALL_TIX
/// for a user already in `lldap_disabled`. Best-effort.
pub fn reassert_kerberos_disabled(username: &str) {
    if let Err(e) = set_kerberos_principal_enabled(username, false) {
        warn!(
            "Failed to re-assert Kerberos disable for {} after password set: {}",
            username, e
        );
    }
}
