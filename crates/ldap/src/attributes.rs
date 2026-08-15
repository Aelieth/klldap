//! Attribute handling — Single canonical source of truth
//!
//! All user/group attribute resolution, EntryDn construction, memberOf,
//! operational attributes, and search result entry building lives here.

use crate::core::utils::is_ignored_attribute;
use crate::dn::{DEFAULT_PRIMARY_GROUP_OU, DEFAULT_PRIMARY_USER_OU, build_group_dn, build_user_dn};
use crate::schema::{ExpandedAttributes, GroupFieldType, UserFieldType};
use chrono::{NaiveDateTime, TimeZone};
use ldap3_proto::LdapPartialAttribute;
use ldap3_proto::LdapSearchResultEntry;
use lldap_domain::types::{
    Attribute, AttributeName, AttributeValue, Cardinality, Group, GroupDetails, GroupMember,
    LdapObjectClass, User, UserId,
};
use lldap_schema::{AttributeList, PublicSchema};
use std::collections::HashSet;
use std::sync::LazyLock;

static USER_SCHEMA_ATTRIBUTE_NAMES: LazyLock<HashSet<String>> =
    LazyLock::new(|| schema_names(PublicSchema::shared().user_attributes()));

static GROUP_SCHEMA_ATTRIBUTE_NAMES: LazyLock<HashSet<String>> =
    LazyLock::new(|| schema_names(PublicSchema::shared().group_attributes()));

fn schema_names(attributes: &AttributeList) -> HashSet<String> {
    attributes
        .all_names_and_aliases()
        .map(str::to_owned)
        .collect()
}

fn member_values(
    group: &Group,
    user_filter: &Option<UserId>,
    render: impl Fn(&GroupMember) -> String,
) -> Vec<Vec<u8>> {
    let members: std::collections::BTreeSet<String> = group
        .users
        .iter()
        .filter(|member| user_filter.as_ref().is_none_or(|f| member.user_id == *f))
        .map(render)
        .collect();
    members.into_iter().map(String::into_bytes).collect()
}

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

pub fn get_default_user_object_classes() -> Vec<LdapObjectClass> {
    object_classes(get_default_user_object_classes_bytes(PublicSchema::shared()))
}

pub fn get_default_group_object_classes() -> Vec<LdapObjectClass> {
    object_classes(get_default_group_object_classes_bytes(
        PublicSchema::shared(),
    ))
}

fn object_classes(classes: Vec<Vec<u8>>) -> Vec<LdapObjectClass> {
    classes
        .into_iter()
        .map(|class| LdapObjectClass::from(String::from_utf8_lossy(&class).to_string()))
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
        UserFieldType::ObjectClass => get_default_user_object_classes_bytes(schema),
        UserFieldType::Dn => return None,
        UserFieldType::EntryDn => {
            let internal_ou = get_user_ou(user);
            vec![build_user_dn(&user.user_id, &internal_ou, base_dn_str).into_bytes()]
        }
        UserFieldType::EntryUuid => {
            vec![user.uuid.to_string().into_bytes()]
        }
        UserFieldType::MemberOf => groups
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
        UserFieldType::PrimaryField(lldap_domain_model::model::UserColumn::UserId) => {
            vec![user.user_id.to_string().into_bytes()]
        }
        UserFieldType::PrimaryField(lldap_domain_model::model::UserColumn::Email) => {
            vec![user.email.to_string().into_bytes()]
        }
        UserFieldType::PrimaryField(
            lldap_domain_model::model::UserColumn::LowercaseEmail
            | lldap_domain_model::model::UserColumn::PasswordHash
            | lldap_domain_model::model::UserColumn::TotpSecret
            | lldap_domain_model::model::UserColumn::MfaType,
        ) => panic!("Should not get here"),
        UserFieldType::PrimaryField(lldap_domain_model::model::UserColumn::Uuid) => {
            vec![user.uuid.to_string().into_bytes()]
        }
        UserFieldType::PrimaryField(lldap_domain_model::model::UserColumn::DisplayName) => {
            vec![user.display_name.clone()?.into_bytes()]
        }
        UserFieldType::PrimaryField(lldap_domain_model::model::UserColumn::CreationDate) => {
            vec![to_generalized_time(&user.creation_date)]
        }
        UserFieldType::PrimaryField(lldap_domain_model::model::UserColumn::ModifiedDate) => {
            vec![to_generalized_time(&user.modified_date)]
        }
        UserFieldType::PrimaryField(
            lldap_domain_model::model::UserColumn::PasswordModifiedDate,
        ) => {
            vec![to_generalized_time(&user.password_modified_date)]
        }
        UserFieldType::PrimaryField(lldap_domain_model::model::UserColumn::KrbPrincipalName) => {
            vec![user.krb_principal_name.clone()?.into_bytes()]
        }
        UserFieldType::Attribute(attr, _, _) => get_custom_attribute(&user.attributes, &attr)?,
        UserFieldType::NoMatch => match attribute.as_str() {
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
                if is_ignored_attribute(&attribute, ignored_user_attributes) {
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
    // Omit an attribute with no values (e.g. member/uniqueMember/memberUid on a memberless group, or
    // memberOf for a user in no groups) — an attribute with zero values is malformed LDAP.
    if attribute_values.is_empty()
        || (attribute_values.len() == 1 && attribute_values[0].is_empty())
    {
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
        GroupFieldType::ObjectClass => get_default_group_object_classes_bytes(schema),
        GroupFieldType::Dn => return None,
        GroupFieldType::EntryDn => {
            let internal_ou = get_group_ou(group);
            vec![build_group_dn(&group.display_name, &internal_ou, base_dn_str).into_bytes()]
        }
        GroupFieldType::EntryUuid => {
            vec![group.uuid.to_string().into_bytes()]
        }
        GroupFieldType::GroupId => vec![group.id.0.to_string().into_bytes()],
        GroupFieldType::DisplayName => {
            vec![group.display_name.to_string().into_bytes()]
        }
        GroupFieldType::CreationDate => {
            vec![to_generalized_time(&group.creation_date)]
        }
        GroupFieldType::ModifiedDate => {
            vec![to_generalized_time(&group.modified_date)]
        }
        // groupOf(Unique)Names carry member DNs; RFC 2307 posixGroup carries bare login names.
        GroupFieldType::Member | GroupFieldType::UniqueMember => {
            member_values(group, user_filter, |member| {
                build_user_dn(&member.user_id, &member.ou, base_dn_str)
            })
        }
        GroupFieldType::MemberUid => {
            member_values(group, user_filter, |member| member.user_id.to_string())
        }
        GroupFieldType::MemberOf => {
            // memberOf is a user operational/virtual attribute (groups a user belongs to).
            // For group entries we never emit it; use "member" / "uniqueMember" instead.
            // (This prevents the filter alias from leaking into result attributes.)
            return None;
        }
        GroupFieldType::Uuid => vec![group.uuid.to_string().into_bytes()],
        GroupFieldType::Attribute(attr, _, _) => get_custom_attribute(&group.attributes, &attr)?,
        GroupFieldType::NoMatch => match attribute.as_str() {
            "1.1" => return None,
            "+" => return None,
            "*" => panic!("Matched {attribute}, * should have been expanded"),
            _ => {
                if is_ignored_attribute(attribute, ignored_group_attributes) {
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
    // Omit an attribute with no values (e.g. member/uniqueMember/memberUid on a memberless group, or
    // memberOf for a user in no groups) — an attribute with zero values is malformed LDAP.
    if attribute_values.is_empty()
        || (attribute_values.len() == 1 && attribute_values[0].is_empty())
    {
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
    expanded_attributes: ExpandedAttributes,
    groups: Option<&[GroupDetails]>,
    ignored_user_attributes: &[AttributeName],
    schema: &PublicSchema,
) -> LdapSearchResultEntry {
    let dn = build_user_dn(&user.user_id, &get_user_ou(&user), base_dn_str);
    // posixAccount MAY: gecos is the POSIX full name (same value as displayName / cn).
    build_entry(
        dn,
        expanded_attributes,
        EntryShape {
            custom_attributes: &user.attributes,
            schema_names: &USER_SCHEMA_ATTRIBUTE_NAMES,
            extra_wires: &["gecos"],
            structural_class: "inetOrgPerson",
            base_dn_str,
        },
        |attribute| {
            get_user_attribute(
                &user,
                attribute,
                base_dn_str,
                groups,
                ignored_user_attributes,
                schema,
            )
        },
    )
}

pub fn make_ldap_search_group_result_entry(
    group: Group,
    base_dn_str: &str,
    expanded_attributes: ExpandedAttributes,
    user_filter: &Option<UserId>,
    ignored_group_attributes: &[AttributeName],
    schema: &PublicSchema,
) -> LdapSearchResultEntry {
    let dn = build_group_dn(&group.display_name, &get_group_ou(&group), base_dn_str);
    // posixGroup / groupOf(Unique)Names membership — group entries only.
    build_entry(
        dn,
        expanded_attributes,
        EntryShape {
            custom_attributes: &group.attributes,
            schema_names: &GROUP_SCHEMA_ATTRIBUTE_NAMES,
            extra_wires: &["member", "uniqueMember", "memberUid"],
            structural_class: "groupOfUniqueNames",
            base_dn_str,
        },
        |attribute| {
            get_group_attribute(
                &group,
                base_dn_str,
                attribute,
                user_filter,
                ignored_group_attributes,
                schema,
            )
        },
    )
}

struct EntryShape<'a> {
    custom_attributes: &'a [Attribute],
    schema_names: &'a HashSet<String>,
    extra_wires: &'a [&'a str],
    structural_class: &'a str,
    base_dn_str: &'a str,
}

fn build_entry(
    dn: String,
    mut expanded_attributes: ExpandedAttributes,
    shape: EntryShape<'_>,
    value_of: impl Fn(&AttributeName) -> Option<Vec<Vec<u8>>>,
) -> LdapSearchResultEntry {
    if expanded_attributes.include_custom_attributes {
        expanded_attributes.attribute_keys.extend(
            shape
                .custom_attributes
                .iter()
                .filter(|a| !shape.schema_names.contains(a.name.as_str()))
                .map(|a| (a.name.clone(), a.name.to_string())),
        );
        for wire in shape.extra_wires {
            expanded_attributes
                .attribute_keys
                .insert(AttributeName::from(*wire), wire.to_string());
        }
    }
    let include_operational = expanded_attributes.include_operational_attributes;
    let mut attributes: Vec<LdapPartialAttribute> = expanded_attributes
        .attribute_keys
        .into_iter()
        .filter(|(attribute, _)| {
            include_operational
                || !crate::schema::get_schema_manager().is_operational(attribute.as_str())
        })
        .filter_map(|(attribute, name)| {
            Some(LdapPartialAttribute {
                atype: name,
                vals: value_of(&attribute)?,
            })
        })
        .collect();
    if include_operational {
        inject_operational_attributes(&mut attributes, shape.structural_class, shape.base_dn_str);
    }
    let mut seen = HashSet::new();
    attributes.retain(|attr| seen.insert(attr.atype.clone()));
    LdapSearchResultEntry { dn, attributes }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lldap_domain::types::UserId;
    use std::collections::{BTreeMap, HashSet};

    #[test]
    fn default_object_classes_include_the_hub_extras() {
        let users: Vec<String> = get_default_user_object_classes()
            .into_iter()
            .map(|c| c.to_string())
            .collect();
        for class in [
            "top",
            "person",
            "inetOrgPerson",
            "posixAccount",
            "ldapPublicKey",
        ] {
            assert!(users.contains(&class.to_string()), "{class}");
        }
        let groups: Vec<String> = get_default_group_object_classes()
            .into_iter()
            .map(|c| c.to_string())
            .collect();
        for class in ["groupOfUniqueNames", "groupOfNames", "posixGroup"] {
            assert!(groups.contains(&class.to_string()), "{class}");
        }
    }

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

    #[test]
    fn group_entry_emits_the_primary_id_as_groupid() {
        let entry = group_entry(&["groupid"]);
        assert_eq!(atype_vals(&entry, "groupid"), Some(&vec![b"1".to_vec()]));
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

    #[test]
    fn membership_attributes_agree_and_honor_the_user_filter() {
        let mut group = sample_group();
        group.users = vec![
            lldap_domain::types::GroupMember {
                user_id: UserId::new("bob"),
                ou: "people".into(),
            },
            lldap_domain::types::GroupMember {
                user_id: UserId::new("alice"),
                ou: "people\\lab".into(),
            },
        ];
        let schema = PublicSchema::shared();
        let values = |attribute: &str, user_filter: Option<&str>| {
            get_group_attribute(
                &group,
                "dc=example,dc=com",
                &AttributeName::from(attribute),
                &user_filter.map(UserId::new),
                &[],
                schema,
            )
            .unwrap()
        };
        let dns = vec![
            b"uid=alice,ou=lab,ou=people,dc=example,dc=com".to_vec(),
            b"uid=bob,ou=people,dc=example,dc=com".to_vec(),
        ];
        assert_eq!(values("member", None), dns);
        assert_eq!(values("uniqueMember", None), dns);
        assert_eq!(
            values("memberUid", None),
            vec![b"alice".to_vec(), b"bob".to_vec()]
        );
        assert_eq!(values("member", Some("bob")), vec![dns[1].clone()]);
        assert_eq!(values("uniqueMember", Some("bob")), vec![dns[1].clone()]);
        assert_eq!(values("memberUid", Some("bob")), vec![b"bob".to_vec()]);
    }

    #[test]
    fn member_uid_emits_login_names() {
        // RFC 2307 posixGroup: memberUid = bare login names (sorted/deduped), on explicit and `*`.
        let mut group = sample_group();
        group.users = vec![
            lldap_domain::types::GroupMember {
                user_id: UserId::new("bob"),
                ou: "people".into(),
            },
            lldap_domain::types::GroupMember {
                user_id: UserId::new("alice"),
                ou: "people".into(),
            },
        ];
        let schema = PublicSchema::shared();
        let entry = |attrs: &[&str]| {
            let expanded = crate::schema::SchemaManager::default().expand_attribute_wildcards(
                &attrs.iter().map(|s| (*s).to_string()).collect::<Vec<_>>(),
                schema,
            );
            make_ldap_search_group_result_entry(
                group.clone(),
                "dc=example,dc=com",
                expanded,
                &None,
                &[],
                schema,
            )
        };

        let expected = vec![b"alice".to_vec(), b"bob".to_vec()];
        assert_eq!(
            atype_vals(&entry(&["memberUid"]), "memberUid"),
            Some(&expected)
        );
        assert_eq!(atype_vals(&entry(&["*"]), "memberUid"), Some(&expected));

        // member still emits DNs, not bare uids.
        let member_entry = entry(&["member"]);
        let dns = atype_vals(&member_entry, "member").unwrap();
        assert!(dns.iter().all(|v| v.starts_with(b"uid=")));

        // On `*`, member and uniqueMember (DNs) ride along too (groupOf(Unique)Names MUST).
        let star = entry(&["*"]);
        for atype in ["member", "uniqueMember"] {
            let vals = atype_vals(&star, atype).unwrap_or_else(|| panic!("* missing {atype}"));
            assert!(
                vals.iter().all(|v| v.starts_with(b"uid=")),
                "{atype} not DNs"
            );
        }
    }

    #[test]
    fn empty_group_omits_membership_on_star() {
        // A memberless group must not emit empty member/uniqueMember/memberUid on `*`.
        let star = group_entry(&["*"]);
        assert!(atype_vals(&star, "member").is_none());
        assert!(atype_vals(&star, "uniqueMember").is_none());
        assert!(atype_vals(&star, "memberUid").is_none());
    }

    #[test]
    fn star_does_not_cross_object_class_wires() {
        // Membership is group-only; gecos is user-only. Shared expand must not
        // leak them onto the other class (that logged as unknown on every `*`).
        let ustar = user_entry(&["*"]);
        assert!(atype_vals(&ustar, "member").is_none());
        assert!(atype_vals(&ustar, "uniqueMember").is_none());
        assert!(atype_vals(&ustar, "memberUid").is_none());
        assert!(atype_vals(&ustar, "gecos").is_some());

        let gstar = group_entry(&["*"]);
        assert!(atype_vals(&gstar, "gecos").is_none());
    }

    #[test]
    fn gecos_emits_display_name() {
        // gecos = display_name (POSIX GECOS), on explicit + `*`; a null display_name omits it.
        let expected = vec![b"Bob".to_vec()];
        assert_eq!(
            atype_vals(&user_entry(&["gecos"]), "gecos"),
            Some(&expected)
        );
        assert_eq!(atype_vals(&user_entry(&["*"]), "gecos"), Some(&expected));

        let mut u = sample_user();
        u.display_name = None;
        let schema = PublicSchema::shared();
        let exp = crate::schema::SchemaManager::default()
            .expand_attribute_wildcards(&["gecos".to_string()], schema);
        let entry =
            make_ldap_search_user_result_entry(u, "dc=example,dc=com", exp, None, &[], schema);
        assert!(atype_vals(&entry, "gecos").is_none());
    }
}
