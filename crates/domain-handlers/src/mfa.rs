pub const MFA_DISABLED_GROUP: &str = "lldap_mfa_disabled";

/// `enable_mfa`: false, true (only enrolled users present a code), "always".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MfaPolicy {
    #[default]
    Disabled,
    Enrolled,
    Always,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MfaRequirement {
    None,
    Totp,
    Enrollment,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MfaEnrollmentStatus {
    pub enrolled: bool,
    pub exempt: bool,
}

// Exemption beats enrollment: an exempt member logs in with the password alone.
pub fn mfa_requirement(policy: MfaPolicy, status: Option<&MfaEnrollmentStatus>) -> MfaRequirement {
    match (policy, status) {
        (MfaPolicy::Disabled, _) | (_, None) => MfaRequirement::None,
        (_, Some(status)) if status.exempt => MfaRequirement::None,
        (_, Some(status)) if status.enrolled => MfaRequirement::Totp,
        (MfaPolicy::Enrolled, Some(_)) => MfaRequirement::None,
        (MfaPolicy::Always, Some(_)) => MfaRequirement::Enrollment,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MfaResetReason {
    Administrative,
    PasswordReset,
    ForcedAdminReset,
}

impl MfaResetReason {
    pub fn detail(self) -> Option<&'static str> {
        match self {
            Self::Administrative => None,
            Self::PasswordReset => Some("password reset"),
            Self::ForcedAdminReset => Some("forced admin reset"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_requirement_table() {
        let status = |enrolled, exempt| MfaEnrollmentStatus { enrolled, exempt };
        for (policy, status, expected) in [
            (
                MfaPolicy::Disabled,
                Some(status(true, false)),
                MfaRequirement::None,
            ),
            (MfaPolicy::Always, None, MfaRequirement::None),
            (
                MfaPolicy::Enrolled,
                Some(status(true, true)),
                MfaRequirement::None,
            ),
            (
                MfaPolicy::Always,
                Some(status(true, true)),
                MfaRequirement::None,
            ),
            (
                MfaPolicy::Always,
                Some(status(false, true)),
                MfaRequirement::None,
            ),
            (
                MfaPolicy::Enrolled,
                Some(status(true, false)),
                MfaRequirement::Totp,
            ),
            (
                MfaPolicy::Always,
                Some(status(true, false)),
                MfaRequirement::Totp,
            ),
            (
                MfaPolicy::Enrolled,
                Some(status(false, false)),
                MfaRequirement::None,
            ),
            (
                MfaPolicy::Always,
                Some(status(false, false)),
                MfaRequirement::Enrollment,
            ),
        ] {
            assert_eq!(
                mfa_requirement(policy, status.as_ref()),
                expected,
                "{policy:?} {status:?}"
            );
        }
    }
}
