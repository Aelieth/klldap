use crate::registration::{
    ClientRegistrationFinish, ClientRegistrationFinishRequest, KERBEROS_ENVELOPE_MAX_BYTES,
    fits_kerberos_envelope, kerberos_envelope_label,
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

/// Seals `password` to the register/start answer's key, for `username` as it was typed and for
/// that answer's `server_data`.
pub fn seal_kerberos_envelope(
    public_key_der_base64: &str,
    username: &str,
    server_data: &str,
    password: &str,
) -> Result<String> {
    check_kerberos_envelope(password)?;
    let der = STANDARD
        .decode(public_key_der_base64)
        .context("Base64 decode of the Kerberos envelope key failed")?;
    let key =
        PublicKey::from_pkcs1_der(&der).context("Could not read the Kerberos envelope key")?;
    let label = kerberos_envelope_label(&UserId::new(username), server_data);
    let sealed = key
        .encrypt(
            &mut SysRng,
            Oaep::<Sha256>::new_with_label(label.into_bytes()),
            password.as_bytes(),
        )
        .context("Could not seal the password for Kerberos")?;
    Ok(STANDARD.encode(sealed))
}

/// Which key a client seals a synced user's password to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SealTo<'a> {
    /// Only the key a login of this client bound; `None` when it holds none.
    Bound(Option<&'a str>),
    /// The key as the start answered it: the e-mail reset page, and the tool given a token.
    Answered,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("the server's Kerberos envelope key is not one this sign-in bound; sign in again")]
pub struct KeyNotBound;

pub fn sealing_key<'k>(
    answered: Option<&'k str>,
    seal_to: SealTo<'_>,
) -> Result<Option<&'k str>, KeyNotBound> {
    match (answered, seal_to) {
        (None, _) => Ok(None),
        (Some(key), SealTo::Answered) => Ok(Some(key)),
        (Some(key), SealTo::Bound(Some(bound))) if bound == key => Ok(Some(key)),
        (Some(_), SealTo::Bound(_)) => Err(KeyNotBound),
    }
}

/// The finish a client sends: when its start answered a key it may seal to, with `password`
/// sealed to that key for the server data this finish carries.
pub fn finish_with_envelope(
    request: ClientRegistrationFinishRequest,
    key: Option<&str>,
    seal_to: SealTo<'_>,
    username: &str,
    password: &str,
) -> Result<ClientRegistrationFinish> {
    let kerberos_password_envelope = sealing_key(key, seal_to)?
        .map(|key| seal_kerberos_envelope(key, username, &request.server_data, password))
        .transpose()?;
    Ok(ClientRegistrationFinish {
        request,
        kerberos_password_envelope,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("the Kerberos password envelope did not open")]
pub struct EnvelopeUnopened;

/// Opens an envelope sealed for `user` and for the start that answered `server_data`.
pub fn open_kerberos_envelope(
    key: &PrivateKey,
    envelope: &str,
    user: &UserId,
    server_data: &str,
) -> Result<Zeroizing<String>, EnvelopeUnopened> {
    let ciphertext = STANDARD.decode(envelope).map_err(|_| EnvelopeUnopened)?;
    let label = kerberos_envelope_label(user, server_data).into_bytes();
    let plaintext = key
        .decrypt(Oaep::<Sha256>::new_with_label(label), &ciphertext)
        .map_err(|_| EnvelopeUnopened)?;
    String::from_utf8(plaintext)
        .map(Zeroizing::new)
        .map_err(|e| {
            drop(Zeroizing::new(e.into_bytes()));
            EnvelopeUnopened
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registration::KERBEROS_ENVELOPE_LABEL_PREFIX;
    use rsa::pkcs1::EncodeRsaPublicKey;
    use std::sync::LazyLock;

    const STAPLE: &str = "correct horse battery staple";
    const SPACED: &str = "  Cafe\u{301}-Pass-12  ";
    const START: &str = "c3RhcnQgb25l";
    const OTHER_START: &str = "c3RhcnQgdHdv";

    static PRIVATE: LazyLock<PrivateKey> =
        LazyLock::new(|| PrivateKey::new(&mut SysRng, 2048).unwrap());

    fn public() -> String {
        STANDARD.encode(PRIVATE.to_public_key().to_pkcs1_der().unwrap().as_bytes())
    }

    fn raw_seal(label: &str, plain: &[u8]) -> String {
        let padding = Oaep::<Sha256>::new_with_label(label.as_bytes().to_vec());
        let sealed = PRIVATE
            .to_public_key()
            .encrypt(&mut SysRng, padding, plain)
            .unwrap();
        STANDARD.encode(sealed)
    }

    fn opened(wire: &str, user: &str, start: &str) -> Result<String, EnvelopeUnopened> {
        open_kerberos_envelope(&PRIVATE, wire, &UserId::new(user), start)
            .map(|password| password.as_str().to_owned())
    }

    #[test]
    fn test_the_seal_opens_only_for_its_user_and_its_start() {
        let key = public();
        let seal = |typed: &str, start: &str, password: &str| {
            seal_kerberos_envelope(&key, typed, start, password).unwrap()
        };
        let rows = [
            (
                "sealed for the id as typed, Alice",
                seal("Alice", START, STAPLE),
                Ok(STAPLE),
            ),
            ("sealed for alice", seal("alice", START, STAPLE), Ok(STAPLE)),
            (
                "spaces and a combining mark, opened byte for byte: not trimmed, not composed",
                seal("alice", START, SPACED),
                Ok("  Cafe\u{301}-Pass-12  "),
            ),
            (
                "sealed for bob",
                seal("bob", START, STAPLE),
                Err(EnvelopeUnopened),
            ),
            (
                "sealed for alice's other start",
                seal("alice", OTHER_START, STAPLE),
                Err(EnvelopeUnopened),
            ),
        ];
        for (row, wire, expected) in rows {
            let expected = expected.map(str::to_owned);
            assert_eq!(opened(&wire, "alice", START), expected, "{row}");
        }
        assert_eq!(
            kerberos_envelope_label(&UserId::new("Alice"), START),
            "klldap-kerberos-envelope-v2:alice:c3RhcnQgb25l"
        );
        let longest = "a".repeat(KERBEROS_ENVELOPE_MAX_BYTES);
        let over = "ä".repeat(KERBEROS_ENVELOPE_MAX_BYTES / 2 + 1);
        assert!(check_kerberos_envelope(&longest).is_ok());
        assert!(check_kerberos_envelope(&over).is_err());
        assert!(seal_kerberos_envelope(&key, "alice", START, &over).is_err());
        assert!(seal_kerberos_envelope("not base64!", "alice", START, "Eight-88").is_err());
    }

    #[test]
    fn test_a_clients_finish_carries_an_envelope_for_its_own_server_data() {
        use crate::opaque::{client, server};
        let mut rng = rand::rngs::OsRng;
        let start = client::registration::start_registration(STAPLE.as_bytes(), &mut rng).unwrap();
        let setup = server::ServerSetup::new(&mut rng);
        let alice = UserId::new("alice");
        let answer = server::registration::start_registration(&setup, start.message, &alice)
            .unwrap()
            .message;
        let upload = client::registration::finish_registration(
            start.state,
            STAPLE.as_bytes(),
            answer,
            &mut rng,
        )
        .unwrap()
        .message;
        let request = || ClientRegistrationFinishRequest {
            server_data: START.to_owned(),
            registration_upload: upload.clone(),
        };
        let public_key = public();
        let key = public_key.as_str();
        let finish = |answered: Option<&str>, seal_to| {
            finish_with_envelope(request(), answered, seal_to, "Alice", STAPLE)
        };
        let plain = finish(None, SealTo::Bound(None)).unwrap();
        assert_eq!(plain.kerberos_password_envelope, None);
        for seal_to in [SealTo::Answered, SealTo::Bound(Some(key))] {
            let sealed = finish(Some(key), seal_to).unwrap();
            let envelope = sealed.kerberos_password_envelope.unwrap();
            assert_eq!(
                (
                    sealed.request.server_data.as_str(),
                    opened(&envelope, "alice", START),
                    opened(&envelope, "alice", OTHER_START)
                ),
                (START, Ok(STAPLE.to_owned()), Err(EnvelopeUnopened)),
                "{seal_to:?}"
            );
        }
        for seal_to in [SealTo::Bound(None), SealTo::Bound(Some("another key"))] {
            let refused = finish(Some(key), seal_to).map(drop);
            let said = refused.map_err(|e| e.to_string());
            assert_eq!(said, Err(KeyNotBound.to_string()), "{seal_to:?}");
        }
    }

    #[test]
    fn test_a_client_seals_only_to_a_key_its_sign_in_bound() {
        use SealTo::{Answered, Bound};
        type Row = (
            Option<&'static str>,
            SealTo<'static>,
            Result<Option<&'static str>, KeyNotBound>,
        );
        let rows: [Row; 7] = [
            (None, Bound(None), Ok(None)),
            (None, Bound(Some("key")), Ok(None)),
            (None, Answered, Ok(None)),
            (Some("key"), Bound(Some("key")), Ok(Some("key"))),
            (Some("key"), Bound(Some("another key")), Err(KeyNotBound)),
            (Some("key"), Bound(None), Err(KeyNotBound)),
            (Some("key"), Answered, Ok(Some("key"))),
        ];
        let got =
            rows.map(|(answered, seal_to, _)| (answered, seal_to, sealing_key(answered, seal_to)));
        assert_eq!(got, rows);
        assert_eq!(
            KeyNotBound.to_string(),
            "the server's Kerberos envelope key is not one this sign-in bound; sign in again"
        );
    }

    #[test]
    fn test_every_envelope_that_does_not_open_gives_one_error() {
        let label = kerberos_envelope_label(&UserId::new("alice"), START);
        let typed_case = format!("{KERBEROS_ENVELOPE_LABEL_PREFIX}Alice:{START}");
        let mut flipped = STANDARD
            .decode(raw_seal(&label, STAPLE.as_bytes()))
            .unwrap();
        *flipped.last_mut().unwrap() ^= 1;
        let rows = [
            (
                "a label in the case as typed, not the user id's",
                raw_seal(&typed_case, STAPLE.as_bytes()),
            ),
            ("no label", raw_seal("", STAPLE.as_bytes())),
            (
                "the label without a start",
                raw_seal("klldap-kerberos-envelope-v1:alice", STAPLE.as_bytes()),
            ),
            ("one byte flipped", STANDARD.encode(&flipped)),
            ("not UTF-8", raw_seal(&label, b"\xff\xfeA")),
            ("not base64", "not base64!".to_owned()),
            ("empty", String::new()),
        ];
        for (row, wire) in rows {
            assert_eq!(
                opened(&wire, "alice", START),
                Err(EnvelopeUnopened),
                "{row}"
            );
        }
        assert_eq!(
            EnvelopeUnopened.to_string(),
            "the Kerberos password envelope did not open"
        );
    }
}
