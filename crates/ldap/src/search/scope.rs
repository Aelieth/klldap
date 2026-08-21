use crate::dn::{is_container_dn, is_subtree};
use ldap3_proto::{LdapPartialAttribute, LdapSearchResultEntry, LdapSearchScope, proto::LdapOp};
use uuid::Uuid;

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

    // Base/Subtree at a leaf DN is the entry itself (RFC 4511 §4.5.1.2). OneLevel is not.
    if matches!(ldap_scope, LdapSearchScope::Base | LdapSearchScope::Subtree)
        && dn_parts.len() > base_dn.len()
    {
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

        // A stable synthetic entryUUID, only under operational requests.
        let ou_uuid = Uuid::new_v5(&Uuid::NAMESPACE_DNS, dn.as_bytes());
        attributes.push(LdapPartialAttribute {
            atype: "entryUUID".to_string(),
            vals: vec![ou_uuid.to_string().into_bytes()],
        });

        // entryDN is the OU's own DN; creators/modifiers use the admin DN like inject.
        attributes.push(LdapPartialAttribute {
            atype: "entryDN".to_string(),
            vals: vec![dn.as_bytes().to_vec()],
        });
        attributes.push(LdapPartialAttribute {
            atype: "creatorsName".to_string(),
            vals: vec![format!("cn=admin,ou=people,{}", base_dn_str).into_bytes()],
        });
        attributes.push(LdapPartialAttribute {
            atype: "modifiersName".to_string(),
            vals: vec![format!("cn=admin,ou=people,{}", base_dn_str).into_bytes()],
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

// Filter a synthetic OU against the attributes it actually carries (`ou` leaf, objectClass).
pub fn ou_matches_filter(ou_str: &str, filter: &ldap3_proto::LdapFilter) -> bool {
    match filter {
        ldap3_proto::LdapFilter::Equality(field, value) => {
            let f = field.to_ascii_lowercase();
            let v = value.to_ascii_lowercase();
            if f == "ou" {
                ou_leaf(ou_str).eq_ignore_ascii_case(&v)
            } else if f == "objectclass" {
                v == "organizationalunit" || v == "top"
            } else {
                false
            }
        }
        ldap3_proto::LdapFilter::Substring(field, sub) => {
            field.eq_ignore_ascii_case("ou")
                && substring_matches(&ou_leaf(ou_str).to_ascii_lowercase(), sub)
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
        _ => false,
    }
}

fn ou_leaf(ou_str: &str) -> &str {
    ou_str.rsplit('\\').next().unwrap_or(ou_str)
}

fn substring_matches(haystack: &str, sub: &ldap3_proto::proto::LdapSubstringFilter) -> bool {
    let mut pos = 0;
    if let Some(initial) = &sub.initial {
        let initial = initial.to_ascii_lowercase();
        if !haystack[pos..].starts_with(&initial) {
            return false;
        }
        pos += initial.len();
    }
    for any in &sub.any {
        let any = any.to_ascii_lowercase();
        match haystack[pos..].find(&any) {
            Some(i) => pos += i + any.len(),
            None => return false,
        }
    }
    match &sub.final_ {
        Some(final_) => haystack[pos..].ends_with(&final_.to_ascii_lowercase()),
        None => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ldap3_proto::LdapFilter;
    use ldap3_proto::proto::LdapSubstringFilter;
    use pretty_assertions::assert_eq;

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

    fn scope_of(dn: &str, scope: LdapSearchScope) -> SearchScope {
        get_search_scope(
            &make_dn("dc=example,dc=com"),
            &make_dn(dn),
            &scope,
            &["people".to_string(), "groups".to_string()],
        )
    }

    #[test]
    fn test_search_scope_resolution() {
        use LdapSearchScope::{Base, OneLevel, Subtree};
        let cases = [
            (
                "the base itself",
                "dc=example,dc=com",
                Base,
                SearchScope::Root,
            ),
            (
                "a top-level OU",
                "ou=people,dc=example,dc=com",
                OneLevel,
                SearchScope::Container,
            ),
            (
                "a user at base scope",
                "uid=alice,ou=people,dc=example,dc=com",
                Base,
                SearchScope::LeafUser,
            ),
            (
                "a group at base scope",
                "cn=admins,ou=groups,dc=example,dc=com",
                Base,
                SearchScope::LeafGroup,
            ),
            (
                "a user at subtree scope (RFC 4511 4.5.1.2)",
                "uid=alice,ou=people,dc=example,dc=com",
                Subtree,
                SearchScope::LeafUser,
            ),
            (
                "a group at subtree scope",
                "cn=admins,ou=groups,dc=example,dc=com",
                Subtree,
                SearchScope::LeafGroup,
            ),
            (
                "a foreign base",
                "ou=other,dc=evil,dc=com",
                Subtree,
                SearchScope::Invalid,
            ),
            (
                "an unknown top-level OU resolves as a container",
                "ou=users,dc=example,dc=com",
                Subtree,
                SearchScope::Container,
            ),
        ];
        for (label, dn, scope, expected) in cases {
            assert_eq!(scope_of(dn, scope), expected, "{label}");
        }
        assert_ne!(
            scope_of("uid=alice,ou=people,dc=example,dc=com", OneLevel),
            SearchScope::LeafUser,
            "one-level at a leaf is not the entry itself"
        );
        assert!(
            matches!(
                scope_of("ou=office,ou=people,dc=example,dc=com", Subtree),
                SearchScope::Container | SearchScope::Unknown
            ),
            "a nested OU"
        );
    }

    #[test]
    fn test_ou_matches_filter_cases() {
        let eq =
            |field: &str, value: &str| LdapFilter::Equality(field.to_string(), value.to_string());
        let sub = |field: &str, any: &str| {
            LdapFilter::Substring(
                field.to_string(),
                LdapSubstringFilter {
                    initial: None,
                    any: vec![any.to_string()],
                    final_: None,
                },
            )
        };
        let both = || {
            LdapFilter::And(vec![
                eq("objectClass", "organizationalUnit"),
                eq("ou", "office"),
            ])
        };
        let either = || LdapFilter::Or(vec![eq("ou", "office"), eq("ou", "people")]);
        let negated = || LdapFilter::Not(Box::new(eq("ou", "office")));
        let cases = [
            (
                "(ou=office) matches office",
                "office",
                eq("ou", "office"),
                true,
            ),
            (
                "(ou=office) does not match people",
                "people",
                eq("ou", "office"),
                false,
            ),
            (
                "(objectClass=organizationalUnit) matches",
                "office",
                eq("objectClass", "organizationalUnit"),
                true,
            ),
            (
                "And(objectClass, ou=office) matches office",
                "office",
                both(),
                true,
            ),
            (
                "And(objectClass, ou=office) does not match people",
                "people",
                both(),
                false,
            ),
            (
                "Present(ou) matches: deliberate, Present is not expanded to every attribute",
                "people",
                LdapFilter::Present("ou".to_string()),
                true,
            ),
            (
                "Present(mail) does not match: deliberate",
                "people",
                LdapFilter::Present("mail".to_string()),
                false,
            ),
            (
                "Or(ou=office, ou=people) matches office",
                "office",
                either(),
                true,
            ),
            (
                "Or(ou=office, ou=people) matches people",
                "people",
                either(),
                true,
            ),
            (
                "Or(ou=office, ou=people) does not match groups",
                "groups",
                either(),
                false,
            ),
            ("Not(ou=office) matches people", "people", negated(), true),
            (
                "Not(ou=office) does not match office",
                "office",
                negated(),
                false,
            ),
            (
                "GreaterOrEqual is unsupported",
                "office",
                LdapFilter::GreaterOrEqual("cn".to_string(), "a".to_string()),
                false,
            ),
            (
                "(cn=*aelieth*) never matches an OU",
                "family",
                sub("cn", "aelieth"),
                false,
            ),
            (
                "(ou=*fam*) matches family",
                "family",
                sub("ou", "fam"),
                true,
            ),
            (
                "(ou=*fam*) matches the nested leaf people\\family",
                "people\\family",
                sub("ou", "fam"),
                true,
            ),
            (
                "(ou=*fam*) does not match groups",
                "groups",
                sub("ou", "fam"),
                false,
            ),
            (
                "(cn=aelieth) never matches an OU",
                "family",
                eq("cn", "aelieth"),
                false,
            ),
            (
                "(ou=family) matches the nested leaf people\\family",
                "people\\family",
                eq("ou", "family"),
                true,
            ),
            (
                "(ou=people) does not match the nested leaf people\\family",
                "people\\family",
                eq("ou", "people"),
                false,
            ),
        ];
        for (label, ou, filter, expected) in cases {
            assert_eq!(ou_matches_filter(ou, &filter), expected, "{label}");
        }
    }

    #[test]
    fn test_make_ou_entry_shapes() {
        let entry = make_ou_entry("people", "dc=example,dc=com", false);
        assert_eq!(entry.dn, "ou=people,dc=example,dc=com");
        assert_eq!(entry.attributes.len(), 2);
        assert_eq!(
            make_ou_entry("", "dc=example,dc=com", false).dn,
            "dc=example,dc=com"
        );
        let ous = vec!["people".to_string(), "groups".to_string()];
        let ops = build_ou_entries(&ous, "dc=example,dc=com", false);
        assert_eq!(ops.len(), 2);
        let LdapOp::SearchResultEntry(first) = &ops[0] else {
            panic!("expected an entry");
        };
        assert!(first.dn.contains("ou=people"));
    }

    #[test]
    fn test_make_ou_entry_with_operational() {
        let entry = make_ou_entry("office", "dc=example,dc=com", true);
        let names: Vec<&str> = entry.attributes.iter().map(|a| a.atype.as_str()).collect();
        assert!(names.contains(&"hasSubordinates"));
        assert!(names.contains(&"structuralObjectClass"));
        assert!(names.contains(&"subschemaSubentry"));
        assert!(names.contains(&"entryUUID"));
        // OU `+` emits entryDN and creators/modifiers like users and groups.
        assert!(names.contains(&"entryDN"));
        assert!(names.contains(&"creatorsName"));
        assert!(names.contains(&"modifiersName"));
        assert!(!names.contains(&"memberOf"));
        let entry_dn = entry
            .attributes
            .iter()
            .find(|a| a.atype == "entryDN")
            .unwrap();
        assert_eq!(entry_dn.vals, vec![entry.dn.clone().into_bytes()]);
    }
}
