use anyhow::{Context, Result};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use rsa::pkcs1::DecodeRsaPublicKey;
use rsa::{Oaep, RsaPublicKey};
use sha2::Sha256;

pub fn encrypt_password(pub_key_der_base64: &str, plain: &str) -> Result<String> {
    let der_bytes = STANDARD
        .decode(pub_key_der_base64)
        .context("Base64 decode of public key failed")?;
    let pub_key =
        RsaPublicKey::from_pkcs1_der(&der_bytes).context("Failed to load public key from DER")?;

    // Match backend exactly: OAEP + SHA-256 (modern, secure padding)
    let padding = Oaep::new::<Sha256>();
    let encrypted_data = pub_key
        .encrypt(&mut rand::thread_rng(), padding, plain.as_bytes())
        .context("Encryption failed")?;

    Ok(STANDARD.encode(encrypted_data))
}
