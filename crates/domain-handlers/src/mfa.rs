use crate::policies::Setting;
use lldap_domain::is_builtin_group;

pub const MFA_DISABLED_GROUP: &str = "lldap_mfa_disabled";

/// `enable_mfa`: off, enabled (only enrolled users present a code), always.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MfaPolicy {
    #[default]
    Disabled,
    Enrolled,
    Always,
}

pub const ENABLE_MFA: &str = "enable-mfa";

impl MfaPolicy {
    /// An OU's `enable-mfa`; a value outside the catalog asks the most.
    pub fn of_item(value: &str) -> Self {
        match value {
            "off" => Self::Disabled,
            "enabled" => Self::Enrolled,
            _ => Self::Always,
        }
    }

    pub fn item(self) -> &'static str {
        match self {
            Self::Disabled => "off",
            Self::Enrolled => "enabled",
            Self::Always => "always",
        }
    }
}

pub struct EnableMfa;

impl Setting for EnableMfa {
    type Value = MfaPolicy;
    const KEY: &'static str = ENABLE_MFA;
    fn parse(value: &str) -> MfaPolicy {
        MfaPolicy::of_item(value)
    }
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

// The exempt group is load-bearing only while a factor can be on; else the name is ordinary.
pub fn is_protected_group(name: &str, mfa_can_be_on: bool) -> bool {
    is_builtin_group(name) || (mfa_can_be_on && name.eq_ignore_ascii_case(MFA_DISABLED_GROUP))
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
    use crate::policies::{
        AttachedPolicy, POLICY_ITEM_CATALOG, PolicyId, PolicyLevel, resolve,
        resolve_effective_items,
    };
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

    #[test]
    fn test_the_resolved_value_meets_the_user() {
        use MfaPolicy::{Always, Disabled, Enrolled};
        use MfaRequirement::{Enrollment, Totp};
        let free = MfaRequirement::None;
        let status = |enrolled, exempt| MfaEnrollmentStatus { enrolled, exempt };
        let users = [
            ("enrolled", status(true, false)),
            ("not enrolled", status(false, false)),
            ("exempt and enrolled", status(true, true)),
        ];
        let ou = |value: Option<&str>| {
            let policy = value.map(|value| AttachedPolicy {
                id: PolicyId(1),
                name: "p".to_owned(),
                items: [(ENABLE_MFA.to_owned(), value.to_owned())].into(),
            });
            let levels = [PolicyLevel {
                ou_key: String::new(),
                blocked: false,
                policy,
            }];
            resolve_effective_items(POLICY_ITEM_CATALOG, &levels)
        };
        let rows = [
            (None, None, Disabled),
            (None, Some("off"), Disabled),
            (None, Some("enabled"), Enrolled),
            (None, Some("always"), Always),
            (Some(Disabled), None, Disabled),
            (Some(Disabled), Some("off"), Disabled),
            (Some(Disabled), Some("enabled"), Disabled),
            (Some(Disabled), Some("always"), Disabled),
            (Some(Enrolled), None, Enrolled),
            (Some(Enrolled), Some("off"), Enrolled),
            (Some(Enrolled), Some("enabled"), Enrolled),
            (Some(Enrolled), Some("always"), Enrolled),
            (Some(Always), None, Always),
            (Some(Always), Some("off"), Always),
            (Some(Always), Some("enabled"), Always),
            (Some(Always), Some("always"), Always),
        ];
        assert_eq!(rows.len() * users.len(), 48);
        for (server, item, resolved) in rows {
            let expected = match resolved {
                Disabled => [free, free, free],
                Enrolled => [Totp, free, free],
                Always => [Totp, Enrollment, free],
            };
            let (policy, _) = resolve::<EnableMfa>(server, &ou(item));
            assert_eq!(policy, resolved, "server {server:?}, OU {item:?}");
            for ((user, facts), want) in users.iter().zip(expected) {
                assert_eq!(
                    mfa_requirement(policy, Some(facts)),
                    want,
                    "server {server:?}, OU {item:?}, {user}"
                );
            }
        }
    }

    #[test]
    fn test_the_items_values_both_ways() {
        let values = [
            ("off", MfaPolicy::Disabled),
            ("enabled", MfaPolicy::Enrolled),
            ("always", MfaPolicy::Always),
        ];
        for (value, policy) in values {
            assert_eq!(
                (MfaPolicy::of_item(value), policy.item()),
                (policy, value),
                "{value}"
            );
        }
        for value in ["enrolled", "Always", ""] {
            assert_eq!(MfaPolicy::of_item(value), MfaPolicy::Always, "{value:?}");
        }
    }

    #[test]
    fn test_protected_group_table() {
        for on in [false, true] {
            for name in lldap_domain::BUILTIN_GROUPS {
                assert!(is_protected_group(name, on), "{name} {on}");
            }
            assert!(!is_protected_group("family", on), "{on}");
            for name in ["lldap_mfa_disabled", "LLDAP_MFA_DISABLED"] {
                assert_eq!(is_protected_group(name, on), on, "{name} {on}");
            }
        }
    }
}
