use crate::core::error::{LdapError, LdapResult};
use itertools::join;
use ldap3_proto::LdapResultCode;
use lldap_domain::{
    deserialize::deserialize_attribute_value,
    types::{Attribute, AttributeName, AttributeType},
};

pub(crate) fn typed_attribute(
    name: &str,
    values: &[String],
    attribute_type: AttributeType,
    is_list: bool,
) -> LdapResult<Attribute> {
    Ok(Attribute {
        name: name.into(),
        value: deserialize_attribute_value(values, attribute_type, is_list).map_err(|e| {
            LdapError {
                code: LdapResultCode::ConstraintViolation,
                message: format!("Invalid {name} value: {e}"),
            }
        })?,
    })
}

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

/// Attributes SSSD (rfc2307) and similar clients request but KLLDAP never models; silent
/// no-ops, so operators need not list them in `ignored_*_attributes`.
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
mod tests {
    use super::*;
    use lldap_domain::types::AttributeName;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_builtin_ignored_attributes_recognized() {
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
        // uid is a known user attribute: a group-side NoMatch must not log.
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
        let cfg = vec![AttributeName::from("sAMAccountName")];
        assert!(is_ignored_attribute(
            &AttributeName::from("samaccountname"),
            &cfg
        ));
    }

    #[test]
    fn test_ldap_info_new_valid_base_dn() {
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
    fn test_ldap_info_new_lowercases_and_trims() {
        let info = LdapInfo::new("DC=Example, DC=COM", vec![], vec![]).unwrap();
        assert_eq!(info.base_dn_str, "dc=example,dc=com");
    }

    #[test]
    fn test_ldap_info_new_rejects_malformed_dn() {
        assert!(LdapInfo::new("dc=example,dc", vec![], vec![]).is_err());
        assert!(LdapInfo::new("dc=example,,dc=com", vec![], vec![]).is_err());
        assert!(LdapInfo::new("dc=example=foo,dc=com", vec![], vec![]).is_err());
    }
}
