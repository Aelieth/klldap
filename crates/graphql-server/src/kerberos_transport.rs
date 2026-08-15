//! RSA envelope for Kerberos passwords sent by the frontend: `kerberosInfo` publishes the
//! public key, `syncKerberosPassword` decrypts with the matching private key.

use anyhow::{Context, Result};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use rand::rngs::OsRng;
use rsa::pkcs1::EncodeRsaPublicKey;
use rsa::{Oaep, RsaPrivateKey, RsaPublicKey};
use sha2::Sha256;
use std::sync::LazyLock;

static KEYPAIR: LazyLock<(RsaPrivateKey, RsaPublicKey)> = LazyLock::new(|| {
    let private_key = RsaPrivateKey::new(&mut OsRng, 2048)
        .expect("Failed to generate the RSA keypair for Kerberos password transport");
    let public_key = RsaPublicKey::from(&private_key);
    (private_key, public_key)
});

pub fn public_key_der_base64() -> String {
    let der = KEYPAIR
        .1
        .to_pkcs1_der()
        .expect("Failed to encode the Kerberos RSA public key as PKCS1 DER");
    STANDARD.encode(der.as_bytes())
}

pub fn decrypt_password(encrypted: &str) -> Result<String> {
    let ciphertext = STANDARD.decode(encrypted).context("Base64 decode failed")?;
    let plaintext = KEYPAIR
        .0
        .decrypt(Oaep::new::<Sha256>(), &ciphertext)
        .context("Decryption failed")?;
    String::from_utf8(plaintext).context("UTF-8 decode failed")
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::pkcs1::DecodeRsaPublicKey;

    #[test]
    fn frontend_envelope_round_trips() {
        let der = STANDARD.decode(public_key_der_base64()).unwrap();
        let public_key = RsaPublicKey::from_pkcs1_der(&der).unwrap();
        let wire = STANDARD.encode(
            public_key
                .encrypt(
                    &mut OsRng,
                    Oaep::new::<Sha256>(),
                    b"correct horse battery staple",
                )
                .unwrap(),
        );
        assert_eq!(
            decrypt_password(&wire).unwrap(),
            "correct horse battery staple"
        );
    }
}
