//! RSA envelope for a synced user's new password, under an OAEP label naming that user.

use anyhow::Result;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use lldap_auth::kerberos_envelope::open_kerberos_envelope;
use lldap_auth::types::UserId;
use rsa::pkcs1::EncodeRsaPublicKey;
use rsa::{Generate, PrivateKey, PublicKey};
use std::sync::LazyLock;
use std::time::Instant;
use tracing::info;
use zeroize::Zeroizing;

static KEYPAIR: LazyLock<(PrivateKey, PublicKey)> = LazyLock::new(|| {
    let started = Instant::now();
    let private_key = PrivateKey::try_generate()
        .expect("Failed to generate the RSA keypair for Kerberos password transport");
    info!(
        "Made the {}-bit RSA key in {} ms",
        PrivateKey::DEFAULT_BITS,
        started.elapsed().as_millis()
    );
    let public_key = private_key.to_public_key();
    (private_key, public_key)
});

/// Makes the key now; a request that comes first waits for the same one.
pub fn warm_transport_key() {
    LazyLock::force(&KEYPAIR);
}

pub fn public_key_der_base64() -> String {
    let der = KEYPAIR
        .1
        .to_pkcs1_der()
        .expect("Failed to encode the Kerberos RSA public key as PKCS1 DER");
    STANDARD.encode(der.as_bytes())
}

/// Opens an envelope sealed for `user`; one sealed for anyone else does not open.
pub fn open_password_envelope(envelope: &str, user: &UserId) -> Result<Zeroizing<String>> {
    open_kerberos_envelope(&KEYPAIR.0, envelope, user)
}

#[cfg(test)]
mod tests {
    use super::*;
    use getrandom::SysRng;
    use lldap_auth::kerberos_envelope::seal_kerberos_envelope;
    use lldap_auth::registration::{KERBEROS_ENVELOPE_MAX_BYTES, kerberos_envelope_label};
    use pretty_assertions::assert_eq;
    use rsa::Oaep;
    use rsa::pkcs1::DecodeRsaPublicKey;
    use rsa::sha2::Sha256;

    fn transport_key() -> PublicKey {
        let der = STANDARD.decode(public_key_der_base64()).unwrap();
        PublicKey::from_pkcs1_der(&der).unwrap()
    }

    fn seal(label: Option<&str>, plain: &[u8]) -> rsa::Result<Vec<u8>> {
        let padding = match label {
            Some(user) => Oaep::<Sha256>::new_with_label(
                kerberos_envelope_label(&UserId::new(user)).into_bytes(),
            ),
            None => Oaep::<Sha256>::new(),
        };
        transport_key().encrypt(&mut SysRng, padding, plain)
    }

    #[test]
    fn test_an_envelope_opens_only_for_the_user_it_was_sealed_for() {
        let staple = b"correct horse battery staple";
        let sealed = seal(Some("alice"), staple).unwrap();
        let mut flipped = sealed.clone();
        *flipped.last_mut().unwrap() ^= 1;
        let typed = |username| {
            seal_kerberos_envelope(
                &public_key_der_base64(),
                username,
                "correct horse battery staple",
            )
            .unwrap()
        };
        let rows = [
            (
                "sealed by the pages' seal for the id as typed, Alice",
                typed("Alice"),
                Ok("correct horse battery staple"),
            ),
            (
                "sealed by the pages' seal for bob",
                typed("bob"),
                Err("Decryption failed"),
            ),
            (
                "sealed for bob",
                STANDARD.encode(seal(Some("bob"), staple).unwrap()),
                Err("Decryption failed"),
            ),
            (
                "sealed without a label",
                STANDARD.encode(seal(None, staple).unwrap()),
                Err("Decryption failed"),
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
            (
                "not UTF-8",
                STANDARD.encode(seal(Some("alice"), b"\xff\xfeA").unwrap()),
                Err("UTF-8 decode failed"),
            ),
        ];
        for (case, wire, expected) in rows {
            let opened: Result<Zeroizing<String>> =
                open_password_envelope(&wire, &UserId::new("alice"));
            let got = opened
                .map(|password| password.as_str().to_owned())
                .map_err(|e| e.to_string());
            let expected = expected.map(str::to_owned).map_err(str::to_owned);
            assert_eq!(got, expected, "{case}");
        }
    }

    #[test]
    fn test_the_envelope_holds_the_bytes_the_pages_allow() {
        let fits = vec![b'a'; KERBEROS_ENVELOPE_MAX_BYTES];
        let sealed = STANDARD.encode(seal(Some("alice"), &fits).unwrap());
        let opened = open_password_envelope(&sealed, &UserId::new("alice")).unwrap();
        assert_eq!(opened.len(), KERBEROS_ENVELOPE_MAX_BYTES);
        let over = vec![b'a'; KERBEROS_ENVELOPE_MAX_BYTES + 1];
        assert!(seal(Some("alice"), &over).is_err());
        assert_eq!(
            PrivateKey::DEFAULT_BITS / 8 - 2 * 32 - 2,
            KERBEROS_ENVELOPE_MAX_BYTES
        );
    }
}
