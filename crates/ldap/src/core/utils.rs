use crate::core::error::LdapResult;
use itertools::join;
use lldap_domain::types::AttributeName;

/// LdapInfo — shared configuration for the LDAP layer (base DN + ignored attributes).
pub struct LdapInfo {
    pub base_dn: Vec<(String, String)>,
    pub base_dn_str: String,
    pub ignored_user_attributes: Vec<AttributeName>,
    pub ignored_group_attributes: Vec<AttributeName>,
}

impl LdapInfo {
    pub fn new(
        base_dn: &str,
        ignored_user_attributes: Vec<AttributeName>,
        ignored_group_attributes: Vec<AttributeName>,
    ) -> LdapResult<Self> {
        let base_dn = crate::dn::parse_distinguished_name(&base_dn.to_ascii_lowercase())?;
        let base_dn_str = join(base_dn.iter().map(|(k, v)| format!("{k}={v}")), ",");
        Ok(Self {
            base_dn,
            base_dn_str,
            ignored_user_attributes,
            ignored_group_attributes,
        })
    }
}

/// Attributes SSSD (rfc2307) and similar clients routinely request but KLLDAP will never model.
/// Recognized as silent no-ops so they don't produce "unknown attribute" debug noise — operators
/// need not list them in `ignored_user_attributes` / `ignored_group_attributes`.
pub const BUILTIN_IGNORED_ATTRIBUTES: &[&str] = &[
    "shadowlastchange",
    "shadowmin",
    "shadowmax",
    "shadowwarning",
    "shadowinactive",
    "shadowexpire",
    "authorizedservice",
    "host",
    "rhost",
    "userpassword",
];

/// True if `name` is a configured-ignored attribute or one of the built-in expected-absent names.
pub fn is_ignored_attribute(name: &AttributeName, configured: &[AttributeName]) -> bool {
    configured.contains(name)
        || BUILTIN_IGNORED_ATTRIBUTES
            .iter()
            .any(|a| name.as_str().eq_ignore_ascii_case(a))
}

/// True when a NoMatch name should emit the "unknown attribute" debug line.
/// Known names used on the wrong object class (e.g. `uid` on a group) stay silent.
pub fn is_unrecognized_attribute(name: &AttributeName, configured: &[AttributeName]) -> bool {
    !is_ignored_attribute(name, configured)
        && crate::schema::get_schema_manager()
            .resolve_attribute(name.as_str())
            .is_none()
}

#[cfg(test)]
mod utils_tests {
    use super::super::utils::LdapInfo;
    use lldap_domain::types::AttributeName;

    #[test]
    fn builtin_ignored_attributes_recognized() {
        use super::is_ignored_attribute;
        let none: Vec<AttributeName> = vec![];
        assert!(is_ignored_attribute(
            &AttributeName::from("shadowLastChange"),
            &none
        ));
        assert!(is_ignored_attribute(
            &AttributeName::from("userPassword"),
            &none
        ));
        assert!(!is_ignored_attribute(&AttributeName::from("uid"), &none));
        use super::is_unrecognized_attribute;
        // uid is a known user attr — group-side NoMatch must not log.
        assert!(!is_unrecognized_attribute(
            &AttributeName::from("uid"),
            &none
        ));
        assert!(!is_unrecognized_attribute(
            &AttributeName::from("shadowLastChange"),
            &none
        ));
        assert!(is_unrecognized_attribute(
            &AttributeName::from("definitelyNotAnAttribute"),
            &none
        ));
        // configured names still work (and AttributeName matching is case-insensitive).
        let cfg = vec![AttributeName::from("sAMAccountName")];
        assert!(is_ignored_attribute(
            &AttributeName::from("samaccountname"),
            &cfg
        ));
    }

    #[test]
    fn ldap_info_new_valid_base_dn() {
        let info = LdapInfo::new(
            "dc=example,dc=com",
            vec![AttributeName::from("mail")],
            vec![],
        )
        .expect("valid DN should parse");

        assert_eq!(
            info.base_dn,
            vec![
                ("dc".to_string(), "example".to_string()),
                ("dc".to_string(), "com".to_string())
            ]
        );
        assert_eq!(info.base_dn_str, "dc=example,dc=com");
        assert_eq!(info.ignored_user_attributes.len(), 1);
        assert!(info.ignored_group_attributes.is_empty());
    }

    #[test]
    fn ldap_info_new_lowercases_and_trims() {
        let info = LdapInfo::new("DC=Example, DC=COM", vec![], vec![]).unwrap();
        assert_eq!(info.base_dn_str, "dc=example,dc=com");
    }

    #[test]
    fn ldap_info_new_rejects_malformed_dn() {
        // Missing value
        assert!(LdapInfo::new("dc=example,dc", vec![], vec![]).is_err());
        // Empty element
        assert!(LdapInfo::new("dc=example,,dc=com", vec![], vec![]).is_err());
        // Too many =
        assert!(LdapInfo::new("dc=example=foo,dc=com", vec![], vec![]).is_err());
    }
}
