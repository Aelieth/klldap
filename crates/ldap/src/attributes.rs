use crate::{
    core::utils::is_ignored_attribute,
    dn::{DEFAULT_PRIMARY_GROUP_OU, DEFAULT_PRIMARY_USER_OU, build_group_dn, build_user_dn},
    schema::{ExpandedAttributes, GroupFieldType, UserFieldType},
};
use chrono::{NaiveDateTime, TimeZone};
use ldap3_proto::{LdapPartialAttribute, LdapSearchResultEntry};
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

pub fn to_generalized_time(dt: &NaiveDateTime) -> Vec<u8> {
    chrono::Utc
        .from_utc_datetime(dt)
        .format("%Y%m%d%H%M%S.%fZ")
        .to_string()
        .into_bytes()
}

pub fn get_custom_attribute(
    attributes: &[Attribute],
    attribute_name: &AttributeName,
) -> Option<Vec<Vec<u8>>> {
    attributes
        .iter()
        .find(|a| &a.name == attribute_name)
        .map(|attribute| match &attribute.value {
            AttributeValue::String(Cardinality::Singleton(s)) => {
                // The full stored OU (e.g. "people\\testou"): emitting only the leaf broke
                // Keycloak sync for users under child OUs.
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
    // lldap tracks no per-entry creators/modifiers, so the admin DN stands in.
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

pub fn get_default_user_object_classes_bytes(schema: &PublicSchema) -> Vec<Vec<u8>> {
    let mut classes: Vec<Vec<u8>> = vec![b"top".to_vec(), b"person".to_vec()];
    classes.extend(
        schema
            .get_schema()
            .extra_user_object_classes
            .iter()
            .map(|c| c.as_str().as_bytes().to_vec()),
    );
    classes
}

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
                        if let AttributeValue::String(Cardinality::Singleton(s)) = &a.value {
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
            // Virtual attributes driven by built-in group membership.
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
    // An attribute with zero values is malformed LDAP (memberless group, user in no groups).
    if attribute_values.is_empty()
        || (attribute_values.len() == 1 && attribute_values[0].is_empty())
    {
        None
    } else {
        Some(attribute_values)
    }
}

pub fn get_group_attribute(
    group: &Group,
    base_dn_str: &str,
    attribute: &AttributeName,
    user_filter: &Option<UserId>,
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
            // memberOf is a user attribute; groups emit member/uniqueMember instead.
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
    if attribute_values.is_empty()
        || (attribute_values.len() == 1 && attribute_values[0].is_empty())
    {
        None
    } else {
        Some(attribute_values)
    }
}

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
    // posixGroup / groupOf(Unique)Names membership, group entries only.
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
    use pretty_assertions::assert_eq;
    use std::collections::{BTreeMap, HashSet};

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
            mfa_type: None,
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

    fn expanded(attrs: &[&str]) -> ExpandedAttributes {
        crate::schema::SchemaManager::default().expand_attribute_wildcards(
            &attrs.iter().map(|s| (*s).to_string()).collect::<Vec<_>>(),
            PublicSchema::shared(),
        )
    }

    fn user_entry(attrs: &[&str]) -> LdapSearchResultEntry {
        make_ldap_search_user_result_entry(
            sample_user(),
            "dc=example,dc=com",
            expanded(attrs),
            None,
            &[],
            PublicSchema::shared(),
        )
    }

    fn group_entry(attrs: &[&str]) -> LdapSearchResultEntry {
        make_ldap_search_group_result_entry(
            sample_group(),
            "dc=example,dc=com",
            expanded(attrs),
            &None,
            &[],
            PublicSchema::shared(),
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
    fn test_schema_statics_are_pinned() {
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
        assert!(USER_SCHEMA_ATTRIBUTE_NAMES.contains("mail"));
        assert!(USER_SCHEMA_ATTRIBUTE_NAMES.contains("email"));
        assert!(!USER_SCHEMA_ATTRIBUTE_NAMES.contains("mycustomattr"));
        assert!(GROUP_SCHEMA_ATTRIBUTE_NAMES.contains("displayname"));
        assert!(GROUP_SCHEMA_ATTRIBUTE_NAMES.contains("cn"));
        assert!(!GROUP_SCHEMA_ATTRIBUTE_NAMES.contains("mycustomattr"));
    }

    #[test]
    fn test_result_entry_emits_custom_attribute_and_hides_schema_named_one() {
        let custom_only = || ExpandedAttributes {
            attribute_keys: BTreeMap::new(),
            include_custom_attributes: true,
            include_operational_attributes: false,
        };
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
        let entry = make_ldap_search_user_result_entry(
            user,
            "dc=example,dc=com",
            custom_only(),
            None,
            &[],
            PublicSchema::shared(),
        );
        assert!(entry.attributes.iter().any(|a| a.atype == "mycustomattr"));
        assert!(!entry.attributes.iter().any(|a| a.atype == "mail"));

        let mut group = sample_group();
        group.attributes = vec![
            Attribute {
                name: AttributeName::from("mycustomattr"),
                value: vec!["hello".to_string()].into(),
            },
            Attribute {
                name: AttributeName::from("displayname"),
                value: vec!["skip".to_string()].into(),
            },
        ];
        let entry = make_ldap_search_group_result_entry(
            group,
            "dc=example,dc=com",
            custom_only(),
            &None,
            &[],
            PublicSchema::shared(),
        );
        assert!(entry.attributes.iter().any(|a| a.atype == "mycustomattr"));
        assert!(!entry.attributes.iter().any(|a| a.atype == "displayname"));
    }

    #[test]
    fn test_entry_star_plus_and_explicit_virtuals() {
        const INJECTED: [&str; 5] = [
            "hassubordinates",
            "structuralobjectclass",
            "subschemasubentry",
            "creatorsname",
            "modifiersname",
        ];
        type Case<'a> = (&'a str, bool, &'a [&'a str], Vec<&'a str>, Vec<&'a str>);
        let cases: Vec<Case> = vec![
            (
                "user *",
                false,
                &["*"],
                vec!["uid", "mail", "objectclass"],
                vec![
                    "createtimestamp",
                    "hassubordinates",
                    "creatorsname",
                    "entryuuid",
                    "entrydn",
                ],
            ),
            (
                "user +",
                false,
                &["+"],
                vec![
                    "uid",
                    "createtimestamp",
                    "modifytimestamp",
                    "pwdchangedtime",
                    "entryuuid",
                    "entrydn",
                    "hassubordinates",
                    "structuralobjectclass",
                    "subschemasubentry",
                    "creatorsname",
                    "modifiersname",
                ],
                vec!["logindisabled"],
            ),
            (
                "user loginDisabled: deliberate, an explicit virtual injects no operational attributes",
                false,
                &["loginDisabled"],
                vec![],
                INJECTED.to_vec(),
            ),
            (
                "user sudoHost: deliberate, same rule",
                false,
                &["sudoHost"],
                vec![],
                INJECTED.to_vec(),
            ),
            (
                "group *",
                true,
                &["*"],
                vec!["cn"],
                vec!["createtimestamp", "hassubordinates"],
            ),
            (
                "group +",
                true,
                &["+"],
                vec![
                    "cn",
                    "createtimestamp",
                    "hassubordinates",
                    "creatorsname",
                    "entryuuid",
                ],
                vec![],
            ),
        ];
        for (label, group, attrs, present, absent) in cases {
            let names = if group {
                emitted(&group_entry(attrs))
            } else {
                emitted(&user_entry(attrs))
            };
            for name in present {
                assert!(names.contains(name), "{label}: missing {name}");
            }
            for name in absent {
                assert!(!names.contains(name), "{label}: unexpected {name}");
            }
        }
        assert_eq!(
            atype_vals(&user_entry(&["+"]), "createTimestamp"),
            Some(&vec![b"19700101000000.000000000Z".to_vec()]),
            "generalized time"
        );
    }

    #[test]
    fn test_display_name_hybrid_emission() {
        // `*` emits both cn and displayName; explicit requests get only what they asked.
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
    fn test_group_membership_wires_and_group_id() {
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

        // RFC 2307 posixGroup: memberUid is bare login names, sorted and deduped; on `*`,
        // member and uniqueMember ride along (groupOf(Unique)Names MUST).
        let entry = |attrs: &[&str]| {
            make_ldap_search_group_result_entry(
                group.clone(),
                "dc=example,dc=com",
                expanded(attrs),
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
        let member_entry = entry(&["member"]);
        let member_dns = atype_vals(&member_entry, "member").unwrap();
        assert!(member_dns.iter().all(|v| v.starts_with(b"uid=")));
        let star = entry(&["*"]);
        for atype in ["member", "uniqueMember"] {
            let vals = atype_vals(&star, atype).unwrap_or_else(|| panic!("* missing {atype}"));
            assert!(
                vals.iter().all(|v| v.starts_with(b"uid=")),
                "{atype} not DNs"
            );
        }

        // A memberless group must not emit empty member/uniqueMember/memberUid on `*`.
        let empty = group_entry(&["*"]);
        assert!(atype_vals(&empty, "member").is_none());
        assert!(atype_vals(&empty, "uniqueMember").is_none());
        assert!(atype_vals(&empty, "memberUid").is_none());

        assert_eq!(
            atype_vals(&group_entry(&["groupid"]), "groupid"),
            Some(&vec![b"1".to_vec()])
        );
    }

    #[test]
    fn test_star_does_not_cross_object_class_wires() {
        // Membership is group-only and gecos user-only; shared expand must not leak
        // them onto the other class.
        let ustar = user_entry(&["*"]);
        assert!(atype_vals(&ustar, "member").is_none());
        assert!(atype_vals(&ustar, "uniqueMember").is_none());
        assert!(atype_vals(&ustar, "memberUid").is_none());
        let expected = vec![b"Bob".to_vec()];
        assert_eq!(atype_vals(&ustar, "gecos"), Some(&expected));
        assert_eq!(
            atype_vals(&user_entry(&["gecos"]), "gecos"),
            Some(&expected)
        );
        assert!(atype_vals(&group_entry(&["*"]), "gecos").is_none());

        // gecos mirrors display_name; a null display_name omits it.
        let mut u = sample_user();
        u.display_name = None;
        let entry = make_ldap_search_user_result_entry(
            u,
            "dc=example,dc=com",
            expanded(&["gecos"]),
            None,
            &[],
            PublicSchema::shared(),
        );
        assert!(atype_vals(&entry, "gecos").is_none());
    }
}
