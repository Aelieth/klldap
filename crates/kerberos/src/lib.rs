#![recursion_limit = "256"]
use anyhow::{Context, Result};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use rand::rngs::OsRng;
use rsa::pkcs1::EncodeRsaPublicKey;
use rsa::{Oaep, RsaPrivateKey, RsaPublicKey};
use sha2::Sha256;
use std::fs;
use std::process::Command;
use tracing::{info, warn};

pub mod keycloak_client;
pub mod keycloak_config;
pub mod live;
pub mod manager;
pub mod paths;

pub use keycloak_client::KeycloakClient;
pub use keycloak_config::{
    KeycloakConfig, KeycloakSuggestedConfig, get_keycloak_admin_password,
    get_keycloak_suggested_config, load_keycloak_config, save_keycloak_config,
};
pub use lldap_domain_handlers::kerberos::{
    derive_domain_from_base_dn, derive_realm_from_base_dn, domain_from_base_dn, principal_name,
};
use paths::KerberosPaths;

mod ffi;
pub(crate) use ffi::Kadm5Handle;

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
    let realm = derive_realm_from_base_dn();
    let full_principal = format!("{username}@{realm}");
    info!(
        "Attempting to delete Kerberos principal via FFI: {}",
        full_principal
    );

    // An unavailable admin handle means Kerberos is disabled or not yet bootstrapped;
    // deleting a principal that cannot exist is treated as idempotent success.
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

/// `enabled == false` sets DISALLOW_ALL_TIX (`modprinc -allow_tix`), `true` clears it.
/// Like `delete_kerberos_principal`, an unavailable admin handle is an idempotent no-op.
pub fn set_kerberos_principal_enabled(username: &str, enabled: bool) -> Result<()> {
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
    let realm = derive_realm_from_base_dn();
    let full_principal = format!("{username}@{realm}");
    info!("Kerberos sync started for principal: {}", full_principal);

    let handle = admin_handle(&realm)?;

    // Try change password first (most common case after user already exists)
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

    warn!("Change password failed (likely principal does not exist)—creating new principal...");

    handle
        .create_principal(username, plain_password, &realm)
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
    let hostname = match hostname_input.trim() {
        "" | "keycloak" => format!("keycloak.{}", derive_domain_from_base_dn()),
        hostname => hostname.to_owned(),
    };
    let principal = format!("HTTP/{hostname}@{realm}");
    info!("Generating Keycloak keytab for principal: {}", principal);

    let paths = KerberosPaths::from_env();
    let handle = admin_handle(&realm)?;
    let keytab_path = &paths.keycloak_keytab;
    if let Some(dir) = keytab_path.parent() {
        fs::create_dir_all(dir).with_context(|| format!("while creating {}", dir.display()))?;
    }
    let _ = fs::remove_file(keytab_path);

    // Fresh random key via FFI, then ktadd with the enctypes Keycloak/Java can decrypt.
    handle.set_random_key_for_service(&principal)?;
    let query = format!(
        "ktadd -k {} -e aes256-cts-hmac-sha1-96:normal,aes128-cts-hmac-sha1-96:normal {}",
        keytab_path.display(),
        principal
    );
    let output = Command::new("/usr/sbin/kadmin.local")
        .env("KRB5_CONFIG", &paths.krb5_conf)
        .arg("-q")
        .arg(&query)
        .output()
        .context("Failed to execute kadmin.local")?;
    if !output.status.success() {
        anyhow::bail!(
            "kadmin.local ktadd failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    info!("Keytab successfully exported to {}", keytab_path.display());
    Ok(keytab_path.display().to_string())
}
