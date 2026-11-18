#![forbid(unsafe_code)]
#![forbid(non_ascii_idents)]

mod encoding;
mod error;
#[cfg(feature = "seal")]
mod proof;
#[cfg(feature = "seal")]
mod sealing;
#[cfg(feature = "seal")]
mod secret;
mod totp;
mod types;

pub use encoding::{otpauth_uri, seed_base32, seed_from_base32};
pub use error::{MfaError, Result};
#[cfg(feature = "seal")]
pub use proof::{
    ENROLLMENT_PROOF_CLOCK_TOLERANCE_SECS, ENROLLMENT_PROOF_PURPOSE, ENROLLMENT_PROOF_TTL_SECS,
    ProofUse, UsedProofs, open_enrollment_proof, seal_enrollment_proof,
};
#[cfg(feature = "seal")]
pub use sealing::{decode_exact, derive_sealing_key};
#[cfg(feature = "seal")]
pub use secret::{
    EnrollmentState, FACTOR_DIGEST_LEN, factor_digest, generate_seed, open_enrollment,
    open_totp_secret, seal_enrollment, seal_totp_secret,
};
pub use totp::{format_code, split_totp_suffix, totp_code, totp_matched_step, totp_verify};
pub use types::{
    ENROLLMENT_PROOF_BUSY, MFA_ENROLLMENT_REQUIRED, PASSWORD_PROOF_REQUIRED,
    TOTP_CODE_ALREADY_USED, TOTP_CODE_REQUIRED, TOTP_CURRENT_CODE_REQUIRED, TOTP_DIGITS,
    TOTP_ENROLLMENT_EXPIRED, TOTP_ENROLLMENT_TTL_SECS, TOTP_SEED_LEN, TOTP_SEPARATOR,
    TOTP_STEP_SECS, TOTP_TOO_MANY_ATTEMPTS, TotpFailure, totp_failure,
};
#[cfg(feature = "seal")]
pub use types::{SEALED_BLOB_LEN, SEALED_PREFIX, TOTP_MAX_ATTEMPTS_PER_STEP};
