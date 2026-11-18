use base64::{Engine, engine::general_purpose::STANDARD};
use orion::aead;
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::error::{MfaError, Result};
use crate::sealing::{decode_exact, derive_sealing_key};
use crate::types::ENROLLMENT_PROOF_KEY_INFO;

pub const ENROLLMENT_PROOF_PURPOSE: &str = "mfa-enroll";
pub const ENROLLMENT_PROOF_TTL_SECS: i64 = 5 * 60;
/// Servers that share a database may disagree on the time by this much.
pub const ENROLLMENT_PROOF_CLOCK_TOLERANCE_SECS: i64 = 60;
const PROOF_KIND: u8 = 2;

#[derive(Serialize, Deserialize)]
pub struct EnrollmentProof {
    kind: u8,
    pub user_id: String,
    purpose: String,
    pub expiry_unix: i64,
    pub id: [u8; 16],
}

fn latest_expiry(now_unix: i64) -> i64 {
    now_unix + ENROLLMENT_PROOF_TTL_SECS + ENROLLMENT_PROOF_CLOCK_TOLERANCE_SECS
}

pub fn seal_enrollment_proof(ikm: &[u8], user_id: &str, now_unix: i64) -> Result<String> {
    let mut id = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut id);
    let proof = EnrollmentProof {
        kind: PROOF_KIND,
        user_id: user_id.to_owned(),
        purpose: ENROLLMENT_PROOF_PURPOSE.to_owned(),
        expiry_unix: now_unix + ENROLLMENT_PROOF_TTL_SECS,
        id,
    };
    let key = derive_sealing_key(ikm, ENROLLMENT_PROOF_KEY_INFO)?;
    let sealed = aead::seal(&key, &bincode::serialize(&proof)?)?;
    Ok(STANDARD.encode(sealed))
}

pub fn open_enrollment_proof(ikm: &[u8], sealed: &str, now_unix: i64) -> Result<EnrollmentProof> {
    let key = derive_sealing_key(ikm, ENROLLMENT_PROOF_KEY_INFO)?;
    let blob = STANDARD
        .decode(sealed.as_bytes())
        .map_err(|_| MfaError::InvalidSealedFormat)?;
    let proof: EnrollmentProof = decode_exact(&aead::open(&key, &blob)?)?;
    if proof.kind != PROOF_KIND || proof.purpose != ENROLLMENT_PROOF_PURPOSE {
        return Err(MfaError::InvalidSealedFormat);
    }
    if proof.expiry_unix <= now_unix {
        return Err(MfaError::EnrollmentExpired);
    }
    if proof.expiry_unix > latest_expiry(now_unix) {
        return Err(MfaError::InvalidSealedFormat);
    }
    Ok(proof)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generate_seed;
    use crate::types::ENROLLMENT_KEY_INFO;
    use crate::{open_enrollment, seal_enrollment};
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    const IKM: &[u8] = b"server key";
    const LOGIN_INFO: &[u8] = b"lldap-opaque-login-state-v1";
    const REGISTRATION_INFO: &[u8] = b"lldap-opaque-registration-state-v1";
    const LATEST: i64 = ENROLLMENT_PROOF_TTL_SECS + ENROLLMENT_PROOF_CLOCK_TOLERANCE_SECS;

    fn proof_plain(expiry_unix: i64) -> EnrollmentProof {
        EnrollmentProof {
            kind: PROOF_KIND,
            user_id: "bob".to_owned(),
            purpose: ENROLLMENT_PROOF_PURPOSE.to_owned(),
            expiry_unix,
            id: [7u8; 16],
        }
    }

    fn seal_under(info: &[u8], plain: &[u8]) -> String {
        let key = derive_sealing_key(IKM, info).unwrap();
        STANDARD.encode(aead::seal(&key, plain).unwrap())
    }

    #[test]
    fn test_proof_opens_only_under_its_own_key() {
        let now = 1_700_000_000;
        let sealed = seal_enrollment_proof(IKM, "bob", now).unwrap();
        let opened = open_enrollment_proof(IKM, &sealed, now).unwrap();
        assert_eq!(opened.user_id, "bob");
        assert_eq!(opened.expiry_unix, now + ENROLLMENT_PROOF_TTL_SECS);

        let plain = bincode::serialize(&proof_plain(now + 60)).unwrap();
        for (info, label) in [
            (LOGIN_INFO, "login"),
            (REGISTRATION_INFO, "registration"),
            (ENROLLMENT_KEY_INFO, "enrollment"),
        ] {
            assert!(
                open_enrollment_proof(IKM, &seal_under(info, &plain), now).is_err(),
                "{label} seal must not open as a proof"
            );
        }

        let raw = STANDARD.decode(sealed.as_bytes()).unwrap();
        for (info, label) in [
            (LOGIN_INFO, "login"),
            (REGISTRATION_INFO, "registration"),
            (ENROLLMENT_KEY_INFO, "enrollment"),
        ] {
            let key = derive_sealing_key(IKM, info).unwrap();
            assert!(
                aead::open(&key, &raw).is_err(),
                "a proof must not open as a {label} seal"
            );
        }

        // Each value is re-encoded in the opener's alphabet, so only the key can refuse it.
        let seed = generate_seed();
        let state = seal_enrollment(IKM, "bob", &seed, None, now).unwrap();
        let state_as_proof = STANDARD.encode(URL_SAFE_NO_PAD.decode(&state).unwrap());
        let refused = open_enrollment_proof(IKM, &state_as_proof, now);
        assert!(
            matches!(refused, Err(MfaError::Crypto(_))),
            "{:?}",
            refused.err()
        );
        let proof_as_state = URL_SAFE_NO_PAD.encode(&raw);
        let refused = open_enrollment(IKM, &proof_as_state, now);
        assert!(
            matches!(refused, Err(MfaError::Crypto(_))),
            "{:?}",
            refused.err()
        );
    }

    #[test]
    fn test_proof_decoder_refuses_trailing_bytes_and_a_far_expiry() {
        let now = 1_700_000_000;
        let mut plain = bincode::serialize(&proof_plain(now + 60)).unwrap();
        plain.push(1);
        assert!(
            open_enrollment_proof(IKM, &seal_under(ENROLLMENT_PROOF_KEY_INFO, &plain), now)
                .is_err()
        );

        let opens = |expiry: i64| {
            let plain = bincode::serialize(&proof_plain(expiry)).unwrap();
            open_enrollment_proof(IKM, &seal_under(ENROLLMENT_PROOF_KEY_INFO, &plain), now).is_ok()
        };
        let rows = [
            ("the full lifetime", now + ENROLLMENT_PROOF_TTL_SECS, true),
            (
                "a minting clock one second ahead",
                now + ENROLLMENT_PROOF_TTL_SECS + 1,
                true,
            ),
            ("the clock tolerance", now + LATEST, true),
            ("past the tolerance", now + LATEST + 1, false),
            ("expired", now, false),
        ];
        for (label, expiry, expected) in rows {
            assert_eq!(opens(expiry), expected, "{label}");
        }
    }
}
