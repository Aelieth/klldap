//! RSA envelope for a synced user's new password, under an OAEP label naming that user and the
//! registration start it finishes.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use lldap_auth::kerberos_envelope::{EnvelopeUnopened, open_kerberos_envelope};
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

/// Opens an envelope sealed for `user` and the start that answered `server_data`.
pub fn open_password_envelope(
    envelope: &str,
    user: &UserId,
    server_data: &str,
) -> Result<Zeroizing<String>, EnvelopeUnopened> {
    open_kerberos_envelope(&KEYPAIR.0, envelope, user, server_data)
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

    const START: &str = "c3RhcnQgb25l";

    fn transport_key() -> PublicKey {
        let der = STANDARD.decode(public_key_der_base64()).unwrap();
        PublicKey::from_pkcs1_der(&der).unwrap()
    }

    fn seal(user: &str, plain: &[u8]) -> rsa::Result<Vec<u8>> {
        let label = kerberos_envelope_label(&UserId::new(user), START).into_bytes();
        transport_key().encrypt(&mut SysRng, Oaep::<Sha256>::new_with_label(label), plain)
    }

    #[test]
    fn test_an_envelope_opens_only_for_the_user_and_the_start_it_was_sealed_for() {
        const STAPLE: &str = "correct horse battery staple";
        let mut flipped = seal("alice", STAPLE.as_bytes()).unwrap();
        *flipped.last_mut().unwrap() ^= 1;
        let typed = |username, start| {
            seal_kerberos_envelope(&public_key_der_base64(), username, start, STAPLE).unwrap()
        };
        let rows = [
            (
                "sealed by the pages' seal for the id as typed, Alice",
                typed("Alice", START),
                Ok(STAPLE),
            ),
            (
                "sealed by the pages' seal for bob",
                typed("bob", START),
                Err(EnvelopeUnopened),
            ),
            (
                "sealed by the pages' seal for alice's other start",
                typed("alice", "c3RhcnQgdHdv"),
                Err(EnvelopeUnopened),
            ),
            (
                "one byte flipped",
                STANDARD.encode(&flipped),
                Err(EnvelopeUnopened),
            ),
        ];
        for (case, wire, expected) in rows {
            let got = open_password_envelope(&wire, &UserId::new("alice"), START)
                .map(|password| password.as_str().to_owned());
            assert_eq!(got, expected.map(str::to_owned), "{case}");
        }
    }

    #[test]
    fn test_the_envelope_holds_the_bytes_the_pages_allow() {
        let fits = vec![b'a'; KERBEROS_ENVELOPE_MAX_BYTES];
        let sealed = STANDARD.encode(seal("alice", &fits).unwrap());
        let opened = open_password_envelope(&sealed, &UserId::new("alice"), START).unwrap();
        assert_eq!(opened.len(), KERBEROS_ENVELOPE_MAX_BYTES);
        let over = vec![b'a'; KERBEROS_ENVELOPE_MAX_BYTES + 1];
        assert!(seal("alice", &over).is_err());
        assert_eq!(
            PrivateKey::DEFAULT_BITS / 8 - 2 * 32 - 2,
            KERBEROS_ENVELOPE_MAX_BYTES
        );
    }
}
