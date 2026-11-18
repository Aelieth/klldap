use crate::registration::{
    KERBEROS_ENVELOPE_MAX_BYTES, fits_kerberos_envelope, kerberos_envelope_label,
};
use crate::types::UserId;
use anyhow::{Context, Result, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use getrandom04::SysRng;
use rsa::pkcs1::DecodeRsaPublicKey;
use rsa::sha2::Sha256;
use rsa::{Oaep, PrivateKey, PublicKey};
use zeroize::Zeroizing;

pub fn check_kerberos_envelope(password: &str) -> Result<()> {
    if !fits_kerberos_envelope(password) {
        bail!(
            "A password with Kerberos sync can be at most {KERBEROS_ENVELOPE_MAX_BYTES} bytes long"
        );
    }
    Ok(())
}

/// Seals `password` to the register/start answer's key, for `username` as it was typed.
pub fn seal_kerberos_envelope(
    public_key_der_base64: &str,
    username: &str,
    password: &str,
) -> Result<String> {
    check_kerberos_envelope(password)?;
    let der = STANDARD
        .decode(public_key_der_base64)
        .context("Base64 decode of the Kerberos envelope key failed")?;
    let key =
        PublicKey::from_pkcs1_der(&der).context("Could not read the Kerberos envelope key")?;
    let label = kerberos_envelope_label(&UserId::new(username));
    let sealed = key
        .encrypt(
            &mut SysRng,
            Oaep::<Sha256>::new_with_label(label.into_bytes()),
            password.as_bytes(),
        )
        .context("Could not seal the password for Kerberos")?;
    Ok(STANDARD.encode(sealed))
}

/// Opens an envelope sealed for `user`; one sealed for anyone else does not open.
pub fn open_kerberos_envelope(
    key: &PrivateKey,
    envelope: &str,
    user: &UserId,
) -> Result<Zeroizing<String>> {
    let ciphertext = STANDARD.decode(envelope).context("Base64 decode failed")?;
    let padding = Oaep::<Sha256>::new_with_label(kerberos_envelope_label(user).into_bytes());
    let plaintext = key
        .decrypt(padding, &ciphertext)
        .context("Decryption failed")?;
    String::from_utf8(plaintext)
        .map(Zeroizing::new)
        .map_err(|e| {
            let cause = e.utf8_error();
            drop(Zeroizing::new(e.into_bytes()));
            anyhow::Error::new(cause).context("UTF-8 decode failed")
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registration::KERBEROS_ENVELOPE_LABEL_PREFIX;
    use rsa::pkcs1::EncodeRsaPublicKey;

    const STAPLE: &str = "correct horse battery staple";

    fn raw_seal(key: &PrivateKey, label: &str, plain: &[u8]) -> String {
        let padding = Oaep::<Sha256>::new_with_label(label.as_bytes().to_vec());
        let sealed = key
            .to_public_key()
            .encrypt(&mut SysRng, padding, plain)
            .unwrap();
        STANDARD.encode(sealed)
    }

    #[test]
    fn test_the_seal_opens_only_for_its_user_through_the_servers_open() {
        let private = PrivateKey::new(&mut SysRng, 2048).unwrap();
        let key = STANDARD.encode(private.to_public_key().to_pkcs1_der().unwrap().as_bytes());
        let alice = UserId::new("alice");
        let label_of = |typed: &str| format!("{KERBEROS_ENVELOPE_LABEL_PREFIX}{typed}");
        let rows = [
            (
                "sealed for the id as typed, Alice",
                seal_kerberos_envelope(&key, "Alice", STAPLE).unwrap(),
                Ok(STAPLE),
            ),
            (
                "sealed for alice",
                seal_kerberos_envelope(&key, "alice", STAPLE).unwrap(),
                Ok(STAPLE),
            ),
            (
                "sealed for bob",
                seal_kerberos_envelope(&key, "bob", STAPLE).unwrap(),
                Err("Decryption failed"),
            ),
            (
                "a label in the case as typed, not the user id's",
                raw_seal(&private, &label_of("Alice"), STAPLE.as_bytes()),
                Err("Decryption failed"),
            ),
            (
                "no label",
                raw_seal(&private, "", STAPLE.as_bytes()),
                Err("Decryption failed"),
            ),
            (
                "not UTF-8",
                raw_seal(&private, &label_of("alice"), b"\xff\xfeA"),
                Err("UTF-8 decode failed"),
            ),
            (
                "not base64",
                "not base64!".to_owned(),
                Err("Base64 decode failed"),
            ),
        ];
        for (row, wire, expected) in rows {
            let opened = open_kerberos_envelope(&private, &wire, &alice)
                .map(|password| password.as_str().to_owned())
                .map_err(|e| e.to_string());
            let expected = expected.map(str::to_owned).map_err(str::to_owned);
            assert_eq!(opened, expected, "{row}");
        }
        let longest = "a".repeat(KERBEROS_ENVELOPE_MAX_BYTES);
        let over = "ä".repeat(KERBEROS_ENVELOPE_MAX_BYTES / 2 + 1);
        assert!(check_kerberos_envelope(&longest).is_ok());
        assert!(check_kerberos_envelope(&over).is_err());
        assert!(seal_kerberos_envelope(&key, "alice", &over).is_err());
        assert!(seal_kerberos_envelope("not base64!", "alice", "Eight-88").is_err());
    }
}
