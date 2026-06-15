use crate::core::error::LdapResult;
use itertools::join;
use lldap_domain::types::AttributeName;

// Re-export the constants and DN helpers that are still widely used
pub use crate::dn::{
    DEFAULT_PRIMARY_GROUP_OU, DEFAULT_PRIMARY_USER_OU, get_user_id_from_distinguished_name,
    internal_ou_to_ldap_rdn_chain,
};

// Re-export FieldType enums from schema (single source of truth)
pub use crate::schema::definitions::{ExpandedAttributes, GroupFieldType, UserFieldType};

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

#[cfg(test)]
mod utils_tests {
    use super::super::utils::LdapInfo;
    use lldap_domain::types::AttributeName;

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

    #[test]
    fn ldap_info_reexports_are_available() {
        // Just ensure the pub use doesn't break compilation / visibility
        let _ = crate::core::utils::DEFAULT_PRIMARY_USER_OU;
        let _ = crate::core::utils::DEFAULT_PRIMARY_GROUP_OU;
    }
}
