//! Attribute handling — Single canonical source of truth
//!
//! All user/group attribute resolution, EntryDn construction, memberOf,
//! operational attributes, and search result entry building lives here.

use crate::core::utils::{DEFAULT_PRIMARY_GROUP_OU, DEFAULT_PRIMARY_USER_OU};
use crate::dn::{build_group_dn, build_user_dn};
use chrono::{NaiveDateTime, TimeZone};
use ldap3_proto::LdapPartialAttribute;
use ldap3_proto::LdapSearchResultEntry;
use lldap_domain::{
    public_schema::PublicSchema,
    types::{Attribute, AttributeName, AttributeValue, Cardinality, Group, GroupDetails, User},
};
use std::collections::HashSet;
use std::sync::LazyLock;

static USER_SCHEMA_ATTRIBUTE_NAMES: LazyLock<HashSet<String>> = LazyLock::new(|| {
    PublicSchema::shared()
        .user_attributes()
        .all_names_and_aliases()
        .map(str::to_owned)
        .collect()
});

static GROUP_SCHEMA_ATTRIBUTE_NAMES: LazyLock<HashSet<String>> = LazyLock::new(|| {
    PublicSchema::shared()
        .group_attributes()
        .all_names_and_aliases()
        .map(str::to_owned)
        .collect()
});

// ============================================================================
// LOW-LEVEL HELPERS MOVED HERE (single source of truth for attribute handling)
// ============================================================================

/// Convert a NaiveDateTime to LDAP GeneralizedTime format (e.g. 20260101120000.000000Z)
pub fn to_generalized_time(dt: &NaiveDateTime) -> Vec<u8> {
    chrono::Utc
        .from_utc_datetime(dt)
        .format("%Y%m%d%H%M%S.%fZ")
        .to_string()
        .into_bytes()
}

/// Extracts a custom attribute value from a list of attributes.
pub fn get_custom_attribute(
    attributes: &[Attribute],
    attribute_name: &AttributeName,
) -> Option<Vec<Vec<u8>>> {
    attributes
        .iter()
        .find(|a| &a.name == attribute_name)
        .map(|attribute| match &attribute.value {
            AttributeValue::String(Cardinality::Singleton(s)) => {
                // Always return the full stored OU value (e.g. "people" or "people\testou").
                // Returning only the leaf via get_leaf_ou broke Keycloak sync when child OUs
                // were created under a parent OU. Users must continue advertising their
                // actual stored ou value.
                vec![s.clone().into_bytes()]
            }
            AttributeValue::String(Cardinality::Unbounded(l)) => {
                l.iter().map(|s| s.clone().into_bytes()).collect()
            }
            AttributeValue::Integer(Cardinality::Singleton(i)) => vec![i.to_string().into_bytes()],
            AttributeValue::Integer(Cardinality::Unbounded(l)) => {
                l.iter().map(|i| i.to_string().into_bytes()).collect()
            }
            AttributeValue::Avatar(Cardinality::Singleton(p)) => vec![p.as_bytes().to_vec()],
            AttributeValue::Avatar(Cardinality::Unbounded(l)) => {
                l.iter().map(|p| p.as_bytes().to_vec()).collect()
            }

            AttributeValue::DateTime(Cardinality::Singleton(dt)) => vec![to_generalized_time(dt)],
            AttributeValue::DateTime(Cardinality::Unbounded(l)) => {
                l.iter().map(to_generalized_time).collect()
            }
        })
}

/// Common OU extractor from entity attributes (used by users and groups).
/// Falls back to the provided default (e.g. "people" or "groups").
pub fn get_ou_from_attributes(attributes: &[Attribute], default: &str) -> String {
    attributes
        .iter()
        .find(|a| a.name.as_str().eq_ignore_ascii_case("ou"))
        .and_then(|a| match &a.value {
            AttributeValue::String(Cardinality::Singleton(s)) => Some(s.clone()),
            AttributeValue::String(Cardinality::Unbounded(list)) if !list.is_empty() => {
                Some(list[0].clone())
            }
            _ => None,
        })
        .unwrap_or_else(|| default.to_string())
}

/// Injects the standard operational attributes we always add to every LDAP search result.
/// Only adds if not already present (prevents leaking operational attrs into "*").
pub(crate) fn inject_operational_attributes(
    attrs: &mut Vec<LdapPartialAttribute>,
    structural_class: &str,
    base_dn_str: &str,
) {
    let existing: std::collections::HashSet<String> =
        attrs.iter().map(|a| a.atype.to_ascii_lowercase()).collect();

    if !existing.contains("hassubordinates") {
        attrs.push(LdapPartialAttribute {
            atype: "hasSubordinates".to_string(),
            vals: vec![b"FALSE".to_vec()],
        });
    }
    if !existing.contains("structuralobjectclass") {
        attrs.push(LdapPartialAttribute {
            atype: "structuralObjectClass".to_string(),
            vals: vec![structural_class.as_bytes().to_vec()],
        });
    }
    if !existing.contains("subschemasubentry") {
        attrs.push(LdapPartialAttribute {
            atype: "subschemaSubentry".to_string(),
            vals: vec![format!("cn=Subschema,{}", base_dn_str).into_bytes()],
        });
    }
    // RFC 4512 creatorsName and modifiersName — injected with default admin DN
    // (lldap doesn't track per-entry creators/modifiers, so we use a sensible default)
    if !existing.contains("creatorsname") {
        attrs.push(LdapPartialAttribute {
            atype: "creatorsName".to_string(),
            vals: vec![format!("cn=admin,ou=people,{}", base_dn_str).into_bytes()],
        });
    }
    if !existing.contains("modifiersname") {
        attrs.push(LdapPartialAttribute {
            atype: "modifiersName".to_string(),
            vals: vec![format!("cn=admin,ou=people,{}", base_dn_str).into_bytes()],
        });
    }
}

/// Returns the default object classes for a user as raw bytes (for LDAP internal use).
pub fn get_default_user_object_classes_bytes(schema: &PublicSchema) -> Vec<Vec<u8>> {
    let mut classes: Vec<Vec<u8>> = vec![
        b"top".to_vec(),
        b"person".to_vec(),
        // mailAccount removed - non-standard lldap-specific objectClass
        // Use extra_user_object_classes in schema config if legacy compatibility needed
    ];
    classes.extend(
        schema
            .get_schema()
            .extra_user_object_classes
            .iter()
            .map(|c| c.as_str().as_bytes().to_vec()),
    );
    classes
}

/// Returns the default object classes for a group as raw bytes (for LDAP internal use).
pub fn get_default_group_object_classes_bytes(schema: &PublicSchema) -> Vec<Vec<u8>> {
    let mut classes: Vec<Vec<u8>> = vec![b"groupOfUniqueNames".to_vec(), b"groupOfNames".to_vec()];
    classes.extend(
        schema
            .get_schema()
            .extra_group_object_classes
            .iter()
            .map(|c| c.as_str().as_bytes().to_vec()),
    );
    classes
}

/// 0-argument versions for GraphQL + public API (returns LdapObjectClass).
pub fn get_default_user_object_classes() -> Vec<lldap_domain::types::LdapObjectClass> {
    let schema = PublicSchema::shared();
    get_default_user_object_classes_bytes(schema)
        .into_iter()
        .map(|b| {
            lldap_domain::types::LdapObjectClass::from(String::from_utf8_lossy(&b).to_string())
        })
        .collect()
}

pub fn get_default_group_object_classes() -> Vec<lldap_domain::types::LdapObjectClass> {
    let schema = PublicSchema::shared();
    get_default_group_object_classes_bytes(schema)
        .into_iter()
        .map(|b| {
            lldap_domain::types::LdapObjectClass::from(String::from_utf8_lossy(&b).to_string())
        })
        .collect()
}

pub fn get_user_ou(user: &User) -> String {
    get_ou_from_attributes(&user.attributes, DEFAULT_PRIMARY_USER_OU)
}

pub fn get_group_ou(group: &Group) -> String {
    get_ou_from_attributes(&group.attributes, DEFAULT_PRIMARY_GROUP_OU)
}

// ============================================================================
// USER ATTRIBUTE RESOLUTION (canonical implementation)
// ============================================================================

pub fn get_user_attribute(
    user: &User,
    attribute: &AttributeName,
    base_dn_str: &str,
    groups: Option<&[GroupDetails]>,
    ignored_user_attributes: &[AttributeName],
    schema: &PublicSchema,
) -> Option<Vec<Vec<u8>>> {
    let attribute = AttributeName::from(attribute.as_str());
    let attribute_values = match crate::schema::get_schema_manager()
        .map_user_field(&attribute, schema)
    {
        crate::core::utils::UserFieldType::ObjectClass => {
            get_default_user_object_classes_bytes(schema)
        }
        crate::core::utils::UserFieldType::Dn => return None,
        crate::core::utils::UserFieldType::EntryDn => {
            let internal_ou = get_user_ou(user);
            vec![build_user_dn(&user.user_id, &internal_ou, base_dn_str).into_bytes()]
        }
        crate::core::utils::UserFieldType::EntryUuid => {
            vec![user.uuid.to_string().into_bytes()]
        }
        crate::core::utils::UserFieldType::MemberOf => groups
            .into_iter()
            .flatten()
            .map(|group| {
                let group_ou = group
                    .attributes
                    .iter()
                    .find(|a| a.name.as_str().eq_ignore_ascii_case("ou"))
                    .and_then(|a| {
                        if let lldap_domain::types::AttributeValue::String(
                            lldap_domain::types::Cardinality::Singleton(s),
                        ) = &a.value
                        {
                            Some(s.clone())
                        } else {
                            None
                        }
                    })
                    .unwrap_or_else(|| DEFAULT_PRIMARY_GROUP_OU.to_string());
                build_group_dn(&group.display_name, &group_ou, base_dn_str).into_bytes()
            })
            .collect(),
        crate::core::utils::UserFieldType::PrimaryField(
            lldap_domain_model::model::UserColumn::UserId,
        ) => {
            vec![user.user_id.to_string().into_bytes()]
        }
        crate::core::utils::UserFieldType::PrimaryField(
            lldap_domain_model::model::UserColumn::Email,
        ) => {
            vec![user.email.to_string().into_bytes()]
        }
        crate::core::utils::UserFieldType::PrimaryField(
            lldap_domain_model::model::UserColumn::LowercaseEmail
            | lldap_domain_model::model::UserColumn::PasswordHash
            | lldap_domain_model::model::UserColumn::TotpSecret
            | lldap_domain_model::model::UserColumn::MfaType,
        ) => panic!("Should not get here"),
        crate::core::utils::UserFieldType::PrimaryField(
            lldap_domain_model::model::UserColumn::Uuid,
        ) => {
            vec![user.uuid.to_string().into_bytes()]
        }
        crate::core::utils::UserFieldType::PrimaryField(
            lldap_domain_model::model::UserColumn::DisplayName,
        ) => {
            vec![user.display_name.clone()?.into_bytes()]
        }
        crate::core::utils::UserFieldType::PrimaryField(
            lldap_domain_model::model::UserColumn::CreationDate,
        ) => {
            vec![to_generalized_time(&user.creation_date)]
        }
        crate::core::utils::UserFieldType::PrimaryField(
            lldap_domain_model::model::UserColumn::ModifiedDate,
        ) => {
            vec![to_generalized_time(&user.modified_date)]
        }
        crate::core::utils::UserFieldType::PrimaryField(
            lldap_domain_model::model::UserColumn::PasswordModifiedDate,
        ) => {
            vec![to_generalized_time(&user.password_modified_date)]
        }
        crate::core::utils::UserFieldType::PrimaryField(
            lldap_domain_model::model::UserColumn::KrbPrincipalName,
        ) => {
            vec![user.krb_principal_name.clone()?.into_bytes()]
        }
        crate::core::utils::UserFieldType::Attribute(attr, _, _) => {
            get_custom_attribute(&user.attributes, &attr)?
        }
        crate::core::utils::UserFieldType::NoMatch => match attribute.as_str() {
            "1.1" => return None,
            "+" => return None,
            "*" => panic!("Matched {attribute}, * should have been expanded"),
            // Virtual attributes driven purely by built-in group membership
            s if s.eq_ignore_ascii_case("logindisabled") => {
                if groups.is_some_and(|gs| {
                    gs.iter()
                        .any(|g| g.display_name.as_str() == "lldap_disabled")
                }) {
                    vec![b"TRUE".to_vec()]
                } else {
                    return None;
                }
            }
            s if s.eq_ignore_ascii_case("sudohost") => {
                if groups.is_some_and(|gs| {
                    gs.iter()
                        .any(|g| g.display_name.as_str() == "lldap_sudohost")
                }) {
                    vec![b"ALL".to_vec()]
                } else {
                    return None;
                }
            }
            _ => {
                if ignored_user_attributes.contains(&attribute) {
                    return None;
                }
                let is_unknown = crate::schema::get_schema_manager()
                    .resolve_attribute(attribute.as_str())
                    .is_none();
                get_custom_attribute(&user.attributes, &attribute).or_else(|| {
                    if is_unknown {
                        tracing::debug!(r#"Ignoring unrecognized user attribute: {}. Add to "ignored_user_attributes"."#, attribute);
                    }
                    None
                })?
            }
        },
    };
    if attribute_values.len() == 1 && attribute_values[0].is_empty() {
        None
    } else {
        Some(attribute_values)
    }
}

// ============================================================================
// GROUP ATTRIBUTE RESOLUTION (canonical implementation)
// ============================================================================

pub fn get_group_attribute(
    group: &Group,
    base_dn_str: &str,
    attribute: &AttributeName,
    user_filter: &Option<lldap_domain::types::UserId>,
    ignored_group_attributes: &[AttributeName],
    schema: &PublicSchema,
) -> Option<Vec<Vec<u8>>> {
    let attribute_values = match crate::schema::get_schema_manager()
        .map_group_field(attribute, schema)
    {
        crate::core::utils::GroupFieldType::ObjectClass => {
            get_default_group_object_classes_bytes(schema)
        }
        crate::core::utils::GroupFieldType::Dn => return None,
        crate::core::utils::GroupFieldType::EntryDn => {
            let internal_ou = get_group_ou(group);
            vec![build_group_dn(&group.display_name, &internal_ou, base_dn_str).into_bytes()]
        }
        crate::core::utils::GroupFieldType::EntryUuid => {
            vec![group.uuid.to_string().into_bytes()]
        }
        crate::core::utils::GroupFieldType::GroupId => vec![group.id.0.to_string().into_bytes()],
        crate::core::utils::GroupFieldType::DisplayName => {
            vec![group.display_name.to_string().into_bytes()]
        }
        crate::core::utils::GroupFieldType::CreationDate => {
            vec![to_generalized_time(&group.creation_date)]
        }
        crate::core::utils::GroupFieldType::ModifiedDate => {
            vec![to_generalized_time(&group.modified_date)]
        }
        crate::core::utils::GroupFieldType::Member => {
            let members: std::collections::BTreeSet<_> = group
                .users
                .iter()
                .filter(|u| {
                    user_filter
                        .as_ref()
                        .map(|f| u.user_id == *f)
                        .unwrap_or(true)
                })
                .map(|u| build_user_dn(&u.user_id, &u.ou, base_dn_str))
                .collect();
            members.into_iter().map(|s| s.into_bytes()).collect()
        }
        crate::core::utils::GroupFieldType::UniqueMember => {
            // uniqueMember is the standard attribute for groupOfUniqueNames (RFC 4519)
            // Use the exact same logic as Member
            let members: std::collections::BTreeSet<_> = group
                .users
                .iter()
                .filter(|u| {
                    user_filter
                        .as_ref()
                        .map(|f| u.user_id == *f)
                        .unwrap_or(true)
                })
                .map(|u| build_user_dn(&u.user_id, &u.ou, base_dn_str))
                .collect();
            members.into_iter().map(|s| s.into_bytes()).collect()
        }
        crate::core::utils::GroupFieldType::MemberOf => {
            // memberOf is a user operational/virtual attribute (groups a user belongs to).
            // For group entries we never emit it; use "member" / "uniqueMember" instead.
            // (This prevents the filter alias from leaking into result attributes.)
            return None;
        }
        crate::core::utils::GroupFieldType::Uuid => vec![group.uuid.to_string().into_bytes()],
        crate::core::utils::GroupFieldType::Attribute(attr, _, _) => {
            get_custom_attribute(&group.attributes, &attr)?
        }
        crate::core::utils::GroupFieldType::NoMatch => match attribute.as_str() {
            "1.1" => return None,
            "+" => return None,
            "*" => panic!("Matched {attribute}, * should have been expanded"),
            _ => {
                if ignored_group_attributes.contains(attribute) {
                    return None;
                }
                let is_unknown = crate::schema::get_schema_manager()
                    .resolve_attribute(attribute.as_str())
                    .is_none();
                get_custom_attribute(&group.attributes, attribute).or_else(|| {
                    if is_unknown {
                        tracing::debug!(r#"Ignoring unrecognized group attribute: {}. Add to "ignored_group_attributes"."#, attribute);
                    }
                    None
                })?
            }
        },
    };
    if attribute_values.len() == 1 && attribute_values[0].is_empty() {
        None
    } else {
        Some(attribute_values)
    }
}

// ============================================================================
// SEARCH RESULT ENTRY BUILDERS (canonical implementation)
// ============================================================================

pub fn make_ldap_search_user_result_entry(
    user: User,
    base_dn_str: &str,
    mut expanded_attributes: crate::core::utils::ExpandedAttributes,
    groups: Option<&[GroupDetails]>,
    ignored_user_attributes: &[AttributeName],
    schema: &PublicSchema,
) -> LdapSearchResultEntry {
    if expanded_attributes.include_custom_attributes {
        let custom_to_add: Vec<_> = user
            .attributes
            .iter()
            .filter(|a| !USER_SCHEMA_ATTRIBUTE_NAMES.contains(a.name.as_str()))
            .map(|a| (a.name.clone(), a.name.to_string()))
            .collect();
        expanded_attributes.attribute_keys.extend(custom_to_add);
    }

    LdapSearchResultEntry {
        dn: build_user_dn(&user.user_id, &get_user_ou(&user), base_dn_str),
        attributes: {
            let mut attrs: Vec<ldap3_proto::LdapPartialAttribute> = expanded_attributes
                .attribute_keys
                .into_iter()
                .filter(|(attribute, _)| {
                    let is_op =
                        crate::schema::get_schema_manager().is_operational(attribute.as_str());
                    !is_op || expanded_attributes.include_operational_attributes
                })
                .filter_map(|(attribute, name)| {
                    let values = get_user_attribute(
                        &user,
                        &attribute,
                        base_dn_str,
                        groups,
                        ignored_user_attributes,
                        schema,
                    )?;
                    Some(ldap3_proto::LdapPartialAttribute {
                        atype: name,
                        vals: values,
                    })
                })
                .collect();
            if expanded_attributes.include_operational_attributes {
                inject_operational_attributes(&mut attrs, "inetOrgPerson", base_dn_str);
            }
            let mut seen = std::collections::HashSet::new();
            attrs.retain(|attr| seen.insert(attr.atype.clone()));
            attrs
        },
    }
}

pub fn make_ldap_search_group_result_entry(
    group: Group,
    base_dn_str: &str,
    mut expanded_attributes: crate::core::utils::ExpandedAttributes,
    user_filter: &Option<lldap_domain::types::UserId>,
    ignored_group_attributes: &[AttributeName],
    schema: &PublicSchema,
) -> LdapSearchResultEntry {
    if expanded_attributes.include_custom_attributes {
        let custom_to_add: Vec<_> = group
            .attributes
            .iter()
            .filter(|a| !GROUP_SCHEMA_ATTRIBUTE_NAMES.contains(a.name.as_str()))
            .map(|a| (a.name.clone(), a.name.to_string()))
            .collect();
        expanded_attributes.attribute_keys.extend(custom_to_add);
    }

    LdapSearchResultEntry {
        dn: build_group_dn(&group.display_name, &get_group_ou(&group), base_dn_str),
        attributes: {
            let mut attrs: Vec<ldap3_proto::LdapPartialAttribute> = expanded_attributes
                .attribute_keys
                .into_iter()
                .filter(|(attribute, _)| {
                    let is_op =
                        crate::schema::get_schema_manager().is_operational(attribute.as_str());
                    !is_op || expanded_attributes.include_operational_attributes
                })
                .filter_map(|(attribute, name)| {
                    let values = get_group_attribute(
                        &group,
                        base_dn_str,
                        &attribute,
                        user_filter,
                        ignored_group_attributes,
                        schema,
                    )?;
                    Some(ldap3_proto::LdapPartialAttribute {
                        atype: name,
                        vals: values,
                    })
                })
                .collect();
            if expanded_attributes.include_operational_attributes {
                inject_operational_attributes(&mut attrs, "groupOfUniqueNames", base_dn_str);
            }
            let mut seen = std::collections::HashSet::new();
            attrs.retain(|attr| seen.insert(attr.atype.clone()));
            attrs
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::utils::ExpandedAttributes;
    use lldap_domain::types::UserId;
    use std::collections::{BTreeMap, HashSet};

    #[test]
    fn cached_schema_names_include_canonical_names_and_aliases() {
        assert!(USER_SCHEMA_ATTRIBUTE_NAMES.contains("mail"));
        assert!(USER_SCHEMA_ATTRIBUTE_NAMES.contains("email"));
        assert!(!USER_SCHEMA_ATTRIBUTE_NAMES.contains("mycustomattr"));
        assert!(GROUP_SCHEMA_ATTRIBUTE_NAMES.contains("displayname"));
        assert!(GROUP_SCHEMA_ATTRIBUTE_NAMES.contains("cn"));
        assert!(!GROUP_SCHEMA_ATTRIBUTE_NAMES.contains("mycustomattr"));
    }

    #[test]
    fn result_entry_emits_custom_attribute_and_hides_schema_named_one() {
        let user = User {
            user_id: UserId::new("bob"),
            email: "bob@example.com".into(),
            attributes: vec![
                Attribute {
                    name: AttributeName::from("mycustomattr"),
                    value: vec!["hello".to_string()].into(),
                },
                Attribute {
                    name: AttributeName::from("mail"),
                    value: vec!["skip".to_string()].into(),
                },
            ],
            ..Default::default()
        };
        let expanded = ExpandedAttributes {
            attribute_keys: BTreeMap::new(),
            include_custom_attributes: true,
            include_operational_attributes: false,
        };
        let entry = make_ldap_search_user_result_entry(
            user,
            "dc=example,dc=com",
            expanded,
            None,
            &[],
            PublicSchema::shared(),
        );
        assert!(entry.attributes.iter().any(|a| a.atype == "mycustomattr"));
        assert!(!entry.attributes.iter().any(|a| a.atype == "mail"));
    }

    fn sample_user() -> User {
        let epoch = chrono::Utc.timestamp_opt(0, 0).unwrap().naive_utc();
        User {
            user_id: UserId::new("bob"),
            email: "bob@example.com".into(),
            display_name: Some("Bob".to_string()),
            creation_date: epoch,
            modified_date: epoch,
            password_modified_date: epoch,
            uuid: lldap_domain::types::Uuid::from_name_and_date("bob", &epoch),
            attributes: vec![],
            krb_principal_name: None,
        }
    }

    fn sample_group() -> Group {
        let epoch = chrono::Utc.timestamp_opt(0, 0).unwrap().naive_utc();
        Group {
            id: lldap_domain::types::GroupId(1),
            display_name: "admins".into(),
            creation_date: epoch,
            uuid: lldap_domain::types::Uuid::from_name_and_date("admins", &epoch),
            users: vec![],
            attributes: vec![],
            modified_date: epoch,
        }
    }

    fn emitted(entry: &LdapSearchResultEntry) -> HashSet<String> {
        entry
            .attributes
            .iter()
            .map(|a| a.atype.to_ascii_lowercase())
            .collect()
    }

    fn expand_and_user(attrs: &[&str]) -> HashSet<String> {
        let schema = PublicSchema::shared();
        let expanded = crate::schema::SchemaManager::default().expand_attribute_wildcards(
            &attrs.iter().map(|s| (*s).to_string()).collect::<Vec<_>>(),
            schema,
        );
        emitted(&make_ldap_search_user_result_entry(
            sample_user(),
            "dc=example,dc=com",
            expanded,
            None,
            &[],
            schema,
        ))
    }

    fn expand_and_group(attrs: &[&str]) -> HashSet<String> {
        let schema = PublicSchema::shared();
        let expanded = crate::schema::SchemaManager::default().expand_attribute_wildcards(
            &attrs.iter().map(|s| (*s).to_string()).collect::<Vec<_>>(),
            schema,
        );
        emitted(&make_ldap_search_group_result_entry(
            sample_group(),
            "dc=example,dc=com",
            expanded,
            &None,
            &[],
            schema,
        ))
    }

    #[test]
    fn user_result_star_excludes_operational_and_plus_injects() {
        let star = expand_and_user(&["*"]);
        assert!(star.contains("uid"));
        assert!(star.contains("mail"));
        assert!(star.contains("objectclass"));
        for op in [
            "createtimestamp",
            "hassubordinates",
            "creatorsname",
            "entryuuid",
            "entrydn",
        ] {
            assert!(!star.contains(op), "* {op}");
        }

        let plus = expand_and_user(&["+"]);
        assert!(plus.contains("uid"));
        assert!(plus.contains("createtimestamp"));
        assert!(plus.contains("modifytimestamp"));
        assert!(plus.contains("pwdchangedtime"));
        assert!(plus.contains("entryuuid"));
        assert!(plus.contains("entrydn"));
        assert!(plus.contains("hassubordinates"));
        assert!(plus.contains("structuralobjectclass"));
        assert!(plus.contains("subschemasubentry"));
        assert!(plus.contains("creatorsname"));
        assert!(plus.contains("modifiersname"));
        assert!(!plus.contains("logindisabled"));
    }

    #[test]
    fn user_result_explicit_login_disabled_omits_injected_ops() {
        // Explicit loginDisabled/sudoHost must NOT trigger the 5 injected operational attrs
        // (include_operational stays off — the Stage-2 correction; guards the Stage-4c flip).
        for virt in ["loginDisabled", "sudoHost"] {
            let e = expand_and_user(&[virt]);
            for op in [
                "hassubordinates",
                "structuralobjectclass",
                "subschemasubentry",
                "creatorsname",
                "modifiersname",
            ] {
                assert!(!e.contains(op), "{virt}: {op}");
            }
        }
    }

    #[test]
    fn group_result_star_excludes_operational_and_plus_injects() {
        let star = expand_and_group(&["*"]);
        assert!(star.contains("cn"));
        assert!(!star.contains("createtimestamp"));
        assert!(!star.contains("hassubordinates"));

        let plus = expand_and_group(&["+"]);
        assert!(plus.contains("cn"));
        assert!(plus.contains("createtimestamp"));
        assert!(plus.contains("hassubordinates"));
        assert!(plus.contains("creatorsname"));
        assert!(plus.contains("entryuuid"));
    }

    fn user_entry(attrs: &[&str]) -> LdapSearchResultEntry {
        let schema = PublicSchema::shared();
        let expanded = crate::schema::SchemaManager::default().expand_attribute_wildcards(
            &attrs.iter().map(|s| (*s).to_string()).collect::<Vec<_>>(),
            schema,
        );
        make_ldap_search_user_result_entry(
            sample_user(),
            "dc=example,dc=com",
            expanded,
            None,
            &[],
            schema,
        )
    }

    fn group_entry(attrs: &[&str]) -> LdapSearchResultEntry {
        let schema = PublicSchema::shared();
        let expanded = crate::schema::SchemaManager::default().expand_attribute_wildcards(
            &attrs.iter().map(|s| (*s).to_string()).collect::<Vec<_>>(),
            schema,
        );
        make_ldap_search_group_result_entry(
            sample_group(),
            "dc=example,dc=com",
            expanded,
            &None,
            &[],
            schema,
        )
    }

    fn atype_vals<'a>(entry: &'a LdapSearchResultEntry, atype: &str) -> Option<&'a Vec<Vec<u8>>> {
        entry
            .attributes
            .iter()
            .find(|a| a.atype == atype)
            .map(|a| &a.vals)
    }

    #[test]
    fn display_name_hybrid_emission() {
        // * emits both cn and displayName (same value); explicit displayName → displayName only;
        // explicit cn → cn only; for users and groups.
        let star = user_entry(&["*"]);
        assert_eq!(atype_vals(&star, "cn"), Some(&vec![b"Bob".to_vec()]));
        assert_eq!(
            atype_vals(&star, "displayName"),
            Some(&vec![b"Bob".to_vec()])
        );

        let dn = user_entry(&["displayName"]);
        assert_eq!(atype_vals(&dn, "displayName"), Some(&vec![b"Bob".to_vec()]));
        assert!(
            atype_vals(&dn, "cn").is_none(),
            "explicit displayName must not emit cn"
        );

        let cn = user_entry(&["cn"]);
        assert_eq!(atype_vals(&cn, "cn"), Some(&vec![b"Bob".to_vec()]));
        assert!(
            atype_vals(&cn, "displayName").is_none(),
            "explicit cn must not emit displayName"
        );

        let gstar = group_entry(&["*"]);
        assert_eq!(atype_vals(&gstar, "cn"), Some(&vec![b"admins".to_vec()]));
        assert_eq!(
            atype_vals(&gstar, "displayName"),
            Some(&vec![b"admins".to_vec()])
        );
    }
}
