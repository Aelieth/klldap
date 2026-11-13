//! RSA envelope for Kerberos passwords sent by the frontend: `kerberosInfo` publishes the
//! public key, `syncKerberosPassword` decrypts with the matching private key.

use anyhow::{Context, Result};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use getrandom::SysRng;
use rsa::pkcs1::EncodeRsaPublicKey;
use rsa::sha2::Sha256;
use rsa::{PrivateKey, PublicKey};
use std::sync::LazyLock;

static KEYPAIR: LazyLock<(PrivateKey, PublicKey)> = LazyLock::new(|| {
    let private_key = PrivateKey::new(&mut SysRng, 2048)
        .expect("Failed to generate the RSA keypair for Kerberos password transport");
    let public_key = private_key.to_public_key();
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
        .oaep_decrypt::<Sha256>(&ciphertext)
        .context("Decryption failed")?;
    String::from_utf8(plaintext).context("UTF-8 decode failed")
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
    use rsa::pkcs1::DecodeRsaPublicKey;

    #[test]
    fn test_frontend_envelope_round_trips_and_refuses_damage() {
        let der = STANDARD.decode(public_key_der_base64()).unwrap();
        let public_key = PublicKey::from_pkcs1_der(&der).unwrap();
        let sealed = public_key
            .oaep_encrypt::<Sha256>(b"correct horse battery staple")
            .unwrap();
        let mut flipped = sealed.clone();
        *flipped.last_mut().unwrap() ^= 1;
        let rows = [
            (
                "sealed",
                STANDARD.encode(&sealed),
                Ok("correct horse battery staple"),
            ),
            (
                "one byte flipped",
                STANDARD.encode(&flipped),
                Err("Decryption failed"),
            ),
            (
                "not base64",
                "not base64!".to_owned(),
                Err("Base64 decode failed"),
            ),
        ];
        for (case, wire, expected) in rows {
            let got = decrypt_password(&wire).map_err(|e| e.to_string());
            let expected = expected.map(str::to_owned).map_err(str::to_owned);
            assert_eq!(got, expected, "{case}");
        }
    }
}
