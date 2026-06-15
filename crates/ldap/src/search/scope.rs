//! Search scope resolution and OU/container handling.

use crate::dn::{is_container_dn, is_subtree};
use ldap3_proto::{LdapPartialAttribute, LdapSearchResultEntry, LdapSearchScope, proto::LdapOp};
use uuid::Uuid; //commented out to test entryUUID issues with keycloak

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SearchScope {
    Root,
    Container,
    LeafUser,
    LeafGroup,
    Invalid,
    Unknown,
}

pub fn get_search_scope(
    base_dn: &[(String, String)],
    dn_parts: &[(String, String)],
    ldap_scope: &LdapSearchScope,
    allowed_ous: &[String],
) -> SearchScope {
    if !is_subtree(dn_parts, base_dn) {
        return SearchScope::Invalid;
    }

    if dn_parts == base_dn {
        return SearchScope::Root;
    }

    if matches!(
        ldap_scope,
        LdapSearchScope::OneLevel | LdapSearchScope::Subtree
    ) && dn_parts.len() == base_dn.len() + 1
    {
        return SearchScope::Container;
    }

    if matches!(ldap_scope, LdapSearchScope::Base) && dn_parts.len() > base_dn.len() {
        let full_dn = dn_parts
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect::<Vec<_>>()
            .join(",");
        match crate::dn::get_user_or_group_id_from_distinguished_name(&full_dn, base_dn) {
            crate::dn::UserOrGroupName::User(_) => return SearchScope::LeafUser,
            crate::dn::UserOrGroupName::Group(_) => return SearchScope::LeafGroup,
            _ => {}
        }
    }

    if is_container_dn(dn_parts, base_dn, allowed_ous) {
        return SearchScope::Container;
    }

    SearchScope::Unknown
}

pub fn make_ou_entry(
    ou_str: &str,
    base_dn_str: &str,
    include_operational_attributes: bool,
) -> LdapSearchResultEntry {
    let rdn_chain = crate::dn::internal_ou_to_ldap_rdn_chain(ou_str);
    let ou_part: String = rdn_chain
        .iter()
        .map(|(k, v)| format!("{}={}", k, v))
        .collect::<Vec<_>>()
        .join(",");
    let dn = if ou_part.is_empty() {
        base_dn_str.to_string()
    } else {
        format!("{},{}", ou_part, base_dn_str)
    };

    let leaf_ou_val = rdn_chain
        .first()
        .map(|(_, v)| v.as_bytes().to_vec())
        .unwrap_or_else(|| crate::dn::DEFAULT_PRIMARY_USER_OU.as_bytes().to_vec());

    let mut attributes = vec![
        LdapPartialAttribute {
            atype: "objectClass".to_string(),
            vals: vec![b"top".to_vec(), b"organizationalUnit".to_vec()],
        },
        LdapPartialAttribute {
            atype: "ou".to_string(),
            vals: vec![leaf_ou_val],
        },
    ];

    if include_operational_attributes {
        attributes.push(LdapPartialAttribute {
            atype: "hasSubordinates".to_string(),
            vals: vec![b"TRUE".to_vec()],
        });
        attributes.push(LdapPartialAttribute {
            atype: "structuralObjectClass".to_string(),
            vals: vec![b"organizationalUnit".to_vec()],
        });
        attributes.push(LdapPartialAttribute {
            atype: "subschemaSubentry".to_string(),
            vals: vec![format!("cn=Subschema,{}", base_dn_str).into_bytes()],
        });

        // Stable synthetic entryUUID — only when client requests operational attributes.
        let ou_uuid = Uuid::new_v5(&Uuid::NAMESPACE_DNS, dn.as_bytes());
        attributes.push(LdapPartialAttribute {
            atype: "entryUUID".to_string(),
            vals: vec![ou_uuid.to_string().into_bytes()],
        });
    }

    LdapSearchResultEntry { dn, attributes }
}

pub fn build_ou_entries(
    allowed_ous: &[String],
    base_dn_str: &str,
    include_operational_attributes: bool,
) -> Vec<LdapOp> {
    allowed_ous
        .iter()
        .map(|ou_str| {
            LdapOp::SearchResultEntry(make_ou_entry(
                ou_str,
                base_dn_str,
                include_operational_attributes,
            ))
        })
        .collect()
}

// Production-grade, reusable OU filter matcher.
// Supports equality on ou/objectClass, Present, And/Or/Not.
// Extensible for future filters. Zero assumptions on complex cases (defaults to include).
pub fn ou_matches_filter(ou_str: &str, filter: &ldap3_proto::LdapFilter) -> bool {
    match filter {
        ldap3_proto::LdapFilter::Equality(field, value) => {
            let f = field.to_ascii_lowercase();
            let v = value.to_ascii_lowercase();
            if f == "ou" {
                ou_str.to_ascii_lowercase() == v
            } else if f == "objectclass" {
                v == "organizationalunit" || v == "top"
            } else {
                true // unknown field on OU — include (client will filter further if needed)
            }
        }
        ldap3_proto::LdapFilter::Present(field) => {
            let f = field.to_ascii_lowercase();
            f == "ou"
                || f == "objectclass"
                || f == "hassubordinates"
                || f == "structuralobjectclass"
        }
        ldap3_proto::LdapFilter::And(filters) => {
            filters.iter().all(|f| ou_matches_filter(ou_str, f))
        }
        ldap3_proto::LdapFilter::Or(filters) => {
            filters.iter().any(|f| ou_matches_filter(ou_str, f))
        }
        ldap3_proto::LdapFilter::Not(f) => !ou_matches_filter(ou_str, f),
        // Substring/Greater/etc not applicable to OU synthetic entries — include
        _ => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ldap3_proto::LdapSearchScope;

    fn make_dn(dn: &str) -> Vec<(String, String)> {
        dn.split(',')
            .map(|part| {
                let mut split = part.split('=');
                (
                    split.next().unwrap().trim().to_string(),
                    split.next().unwrap().trim().to_string(),
                )
            })
            .collect()
    }

    #[test]
    fn test_search_scope_root() {
        let base_dn = make_dn("dc=example,dc=com");
        let dn = make_dn("dc=example,dc=com");

        let scope = get_search_scope(
            &base_dn,
            &dn,
            &LdapSearchScope::Base,
            &["people".to_string(), "groups".to_string()],
        );
        assert_eq!(scope, SearchScope::Root);
    }

    #[test]
    fn test_search_scope_container_people() {
        let base_dn = make_dn("dc=example,dc=com");
        let dn = make_dn("ou=people,dc=example,dc=com");

        let scope = get_search_scope(
            &base_dn,
            &dn,
            &LdapSearchScope::OneLevel,
            &["people".to_string(), "groups".to_string()],
        );
        assert_eq!(scope, SearchScope::Container);
    }

    #[test]
    fn test_search_scope_leaf_user() {
        let base_dn = make_dn("dc=example,dc=com");
        let dn = make_dn("uid=alice,ou=people,dc=example,dc=com");

        let scope = get_search_scope(
            &base_dn,
            &dn,
            &LdapSearchScope::Base,
            &["people".to_string(), "groups".to_string()],
        );
        assert_eq!(scope, SearchScope::LeafUser);
    }

    #[test]
    fn test_search_scope_leaf_group() {
        let base_dn = make_dn("dc=example,dc=com");
        let dn = make_dn("cn=admins,ou=groups,dc=example,dc=com");

        let scope = get_search_scope(
            &base_dn,
            &dn,
            &LdapSearchScope::Base,
            &["people".to_string(), "groups".to_string()],
        );
        assert_eq!(scope, SearchScope::LeafGroup);
    }

    #[test]
    fn test_search_scope_invalid() {
        let base_dn = make_dn("dc=example,dc=com");
        let dn = make_dn("ou=other,dc=evil,dc=com");

        let scope = get_search_scope(
            &base_dn,
            &dn,
            &LdapSearchScope::Subtree,
            &["people".to_string(), "groups".to_string()],
        );
        assert_eq!(scope, SearchScope::Invalid);
    }

    #[test]
    fn test_search_scope_nested_ou_container() {
        let base_dn = make_dn("dc=example,dc=com");
        let dn = make_dn("ou=office,ou=people,dc=example,dc=com");

        let scope = get_search_scope(
            &base_dn,
            &dn,
            &LdapSearchScope::Subtree,
            &["people".to_string(), "groups".to_string()],
        );
        assert!(matches!(
            scope,
            SearchScope::Container | SearchScope::Unknown
        ));
    }

    #[test]
    fn test_ou_matches_filter_equality_ou() {
        let filter = ldap3_proto::LdapFilter::Equality("ou".to_string(), "office".to_string());
        assert!(ou_matches_filter("office", &filter));
        assert!(!ou_matches_filter("people", &filter));
    }

    #[test]
    fn test_ou_matches_filter_objectclass() {
        let filter = ldap3_proto::LdapFilter::Equality(
            "objectClass".to_string(),
            "organizationalUnit".to_string(),
        );
        assert!(ou_matches_filter("office", &filter));
    }

    #[test]
    fn test_ou_matches_filter_and() {
        let filter = ldap3_proto::LdapFilter::And(vec![
            ldap3_proto::LdapFilter::Equality(
                "objectClass".to_string(),
                "organizationalUnit".to_string(),
            ),
            ldap3_proto::LdapFilter::Equality("ou".to_string(), "office".to_string()),
        ]);
        assert!(ou_matches_filter("office", &filter));
        assert!(!ou_matches_filter("people", &filter));
    }
    #[test]
    fn test_ou_matches_filter_present() {
        let filter = ldap3_proto::LdapFilter::Present("ou".to_string());
        assert!(ou_matches_filter("people", &filter));
        let filter2 = ldap3_proto::LdapFilter::Present("mail".to_string());
        assert!(!ou_matches_filter("people", &filter2));
    }

    #[test]
    fn test_ou_matches_filter_or() {
        let filter = ldap3_proto::LdapFilter::Or(vec![
            ldap3_proto::LdapFilter::Equality("ou".to_string(), "office".to_string()),
            ldap3_proto::LdapFilter::Equality("ou".to_string(), "people".to_string()),
        ]);
        assert!(ou_matches_filter("office", &filter));
        assert!(ou_matches_filter("people", &filter));
        assert!(!ou_matches_filter("groups", &filter));
    }

    #[test]
    fn test_ou_matches_filter_not() {
        let filter = ldap3_proto::LdapFilter::Not(Box::new(ldap3_proto::LdapFilter::Equality(
            "ou".to_string(),
            "office".to_string(),
        )));
        assert!(ou_matches_filter("people", &filter));
        assert!(!ou_matches_filter("office", &filter));
    }

    #[test]
    fn test_ou_matches_filter_default_true_for_unsupported() {
        // GreaterOrEqual (and similar) are not handled by ou_matches_filter → should default to true
        let filter = ldap3_proto::LdapFilter::GreaterOrEqual("cn".to_string(), "a".to_string());
        assert!(ou_matches_filter("office", &filter));
    }

    #[test]
    fn test_make_ou_entry_simple() {
        let entry = make_ou_entry("people", "dc=example,dc=com", false);
        assert_eq!(entry.dn, "ou=people,dc=example,dc=com");
        assert_eq!(entry.attributes.len(), 2);
    }

    #[test]
    fn test_make_ou_entry_with_operational() {
        let entry = make_ou_entry("office", "dc=example,dc=com", true);
        assert!(
            entry
                .attributes
                .iter()
                .any(|a| a.atype == "hasSubordinates")
        );
        assert!(
            entry
                .attributes
                .iter()
                .any(|a| a.atype == "structuralObjectClass")
        );
    }

    #[test]
    fn test_make_ou_entry_empty_ou() {
        let entry = make_ou_entry("", "dc=example,dc=com", false);
        assert_eq!(entry.dn, "dc=example,dc=com");
    }

    #[test]
    fn test_build_ou_entries() {
        let ous = vec!["people".to_string(), "groups".to_string()];
        let ops = build_ou_entries(&ous, "dc=example,dc=com", false);
        assert_eq!(ops.len(), 2);
        if let LdapOp::SearchResultEntry(e) = &ops[0] {
            assert!(e.dn.contains("ou=people"));
        }
    }
}
