use anyhow::{Context, Result};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use rsa::PublicKey;
use rsa::pkcs1::DecodeRsaPublicKey;
use rsa::sha2::Sha256;

pub(crate) fn encrypt_password(pub_key_der_base64: &str, plain: &str) -> Result<String> {
    let der_bytes = STANDARD
        .decode(pub_key_der_base64)
        .context("Base64 decode of public key failed")?;
    let pub_key =
        PublicKey::from_pkcs1_der(&der_bytes).context("Failed to load public key from DER")?;

    let encrypted_data = pub_key
        .oaep_encrypt::<Sha256>(plain.as_bytes())
        .context("Encryption failed")?;

    Ok(STANDARD.encode(encrypted_data))
}

/// Encrypts `password` with the Kerberos public key. Errors if the key is missing.
pub fn encrypt_kerberos_password(
    public_key_der_base64: Option<&str>,
    password: &str,
) -> Result<String> {
    let key = public_key_der_base64
        .filter(|k| !k.is_empty())
        .context("Kerberos enabled but no public key available—check backend startup/logs")?;
    encrypt_password(key, password).context("Failed to encrypt password for Kerberos sync")
}
#[cfg(test)]
mod tests {
    use super::*;
    use getrandom::SysRng;
    use rsa::PrivateKey;
    use rsa::pkcs1::EncodeRsaPublicKey;

    #[test]
    fn encrypt_round_trips_with_backend_padding() {
        // Mirrors the backend: OAEP + SHA-256, PKCS1 DER public key, base64 wire form.
        let private = PrivateKey::new(&mut SysRng, 2048).unwrap();
        let public = private.to_public_key();
        let pub_der_b64 = STANDARD.encode(public.to_pkcs1_der().unwrap().as_bytes());

        let plaintext = "correct horse battery staple";
        let wire = encrypt_password(&pub_der_b64, plaintext).unwrap();

        let ciphertext = STANDARD.decode(&wire).unwrap();
        let decrypted = private.oaep_decrypt::<Sha256>(&ciphertext).unwrap();
        assert_eq!(decrypted, plaintext.as_bytes());
    }
}
