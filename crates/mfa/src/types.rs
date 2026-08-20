pub const TOTP_SEED_LEN: usize = 20;
pub const TOTP_DIGITS: u32 = 6;
pub const TOTP_STEP_SECS: u64 = 30;
pub const TOTP_SKEW_STEPS: i64 = 1;
pub const TOTP_SEPARATOR: char = ':';
pub const TOTP_ENROLLMENT_TTL_SECS: u64 = 5 * 60;
#[cfg(feature = "seal")]
pub const TOTP_ACCEPTANCE_WINDOW_SECS: i64 = TOTP_STEP_SECS as i64 * (2 * TOTP_SKEW_STEPS + 1);
#[cfg(feature = "seal")]
pub const TOTP_MAX_ATTEMPTS_PER_STEP: u8 = 5;

#[cfg(feature = "seal")]
pub const SEAL_SALT_LEN: usize = 4;
#[cfg(feature = "seal")]
pub const SEAL_TAG_LEN: usize = 16;
#[cfg(feature = "seal")]
pub const SEALED_PREFIX: &str = "v1.";
#[cfg(feature = "seal")]
pub const SEALED_BLOB_LEN: usize =
    SEALED_PREFIX.len() + ((SEAL_SALT_LEN + TOTP_SEED_LEN + SEAL_TAG_LEN) * 4).div_ceil(3);

// Error markers: the doors and the web client classify failures by these, through the
// GraphQL and anyhow layers, so they are matched anywhere in the message.
pub const TOTP_CODE_ALREADY_USED: &str = "TOTP code already used";
pub const TOTP_ENROLLMENT_EXPIRED: &str = "Expired TOTP enrollment";
pub const TOTP_TOO_MANY_ATTEMPTS: &str = "Too many TOTP attempts";
pub const TOTP_CURRENT_CODE_REQUIRED: &str = "Current TOTP code required";
pub const TOTP_CODE_REQUIRED: &str = "TOTP code required";
pub const MFA_ENROLLMENT_REQUIRED: &str =
    "MFA enrollment required: enroll through the web interface or contact an administrator";

/// Why a login failed, for doors that name some failures and hide the rest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TotpFailure {
    Replayed,
    TooManyAttempts,
    CodeRequired,
    EnrollmentRequired,
    Other,
}

pub fn totp_failure(message: &str) -> TotpFailure {
    if message.contains(TOTP_CODE_ALREADY_USED) {
        TotpFailure::Replayed
    } else if message.contains(TOTP_TOO_MANY_ATTEMPTS) {
        TotpFailure::TooManyAttempts
    } else if message.contains(TOTP_CURRENT_CODE_REQUIRED) {
        // CURRENT contains CODE ("Current TOTP code required"); enrollment is not a door failure.
        TotpFailure::Other
    } else if message.contains(TOTP_CODE_REQUIRED) {
        TotpFailure::CodeRequired
    } else if message.contains(MFA_ENROLLMENT_REQUIRED) {
        TotpFailure::EnrollmentRequired
    } else {
        TotpFailure::Other
    }
}

#[cfg(feature = "seal")]
pub(crate) const STORAGE_KEY_INFO: &[u8] = b"lldap-totp-storage-key-v1";
#[cfg(feature = "seal")]
pub(crate) const ENROLLMENT_KEY_INFO: &[u8] = b"lldap-totp-enrollment-key-v1";
#[cfg(feature = "seal")]
const NONCE_INFO_PREFIX: &[u8] = b"lldap-totp-nonce-v1";

#[cfg(feature = "seal")]
pub(crate) fn build_nonce_info(user_uuid: &str, salt: &[u8]) -> Vec<u8> {
    let mut info =
        Vec::with_capacity(NONCE_INFO_PREFIX.len() + 1 + user_uuid.len() + 1 + salt.len());
    info.extend_from_slice(NONCE_INFO_PREFIX);
    info.push(0);
    info.extend_from_slice(user_uuid.as_bytes());
    info.push(0);
    info.extend_from_slice(salt);
    info
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_failures_are_named_only_when_recognised() {
        for (message, expected) in [
            (
                format!("{TOTP_CODE_ALREADY_USED} for bob"),
                TotpFailure::Replayed,
            ),
            (
                format!("Authentication error {TOTP_TOO_MANY_ATTEMPTS} for bob"),
                TotpFailure::TooManyAttempts,
            ),
            (
                format!("Authentication error {TOTP_CODE_REQUIRED} for \"bob\""),
                TotpFailure::CodeRequired,
            ),
            (
                format!("{TOTP_CURRENT_CODE_REQUIRED} for bob"),
                TotpFailure::Other,
            ),
            (
                format!("{MFA_ENROLLMENT_REQUIRED} for bob"),
                TotpFailure::EnrollmentRequired,
            ),
            ("Invalid TOTP code for bob".to_owned(), TotpFailure::Other),
            (String::new(), TotpFailure::Other),
        ] {
            assert_eq!(totp_failure(&message), expected, "{message}");
        }
    }
}
