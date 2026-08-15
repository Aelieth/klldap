//! Filter conversion logic
//!
//! This module handles conversion of LDAP filters to domain-specific request filters.
//! Kept here so search/handler.rs can orchestrate cleanly while core/ stays slim.

use crate::core::error::{LdapError, LdapResult};
use crate::dn::{
    get_group_id_from_distinguished_name_or_plain_name,
    get_user_id_from_distinguished_name_or_plain_name,
};
use ldap3_proto::LdapFilter;
use lldap_domain::deserialize::deserialize_attribute_value;
use lldap_domain::types::{AttributeName, AttributeType, UserId};
use lldap_domain_handlers::handler::{GroupRequestFilter, UserRequestFilter};
use lldap_schema::PublicSchema;
use tracing::{debug, warn};

use crate::attributes::{
    get_default_group_object_classes_bytes, get_default_user_object_classes_bytes,
};
use crate::core::utils::{LdapInfo, is_unrecognized_attribute};
use crate::schema::{GroupFieldType, UserFieldType};

fn is_object_class(value: &str, classes: &[Vec<u8>]) -> bool {
    classes
        .iter()
        .any(|class| class.eq_ignore_ascii_case(value.as_bytes()))
}

// USER FILTER CONVERSION

fn get_user_attribute_equality_filter(
    field: &AttributeName,
    typ: AttributeType,
    is_list: bool,
    value: &str,
) -> UserRequestFilter {
    let value_lc = value.to_ascii_lowercase();
    let attribute_value = deserialize_attribute_value(&[value.to_owned()], typ, is_list);
    let attribute_value_lc =
        deserialize_attribute_value(std::slice::from_ref(&value_lc), typ, is_list);
    match (attribute_value, attribute_value_lc) {
        (Ok(v), Ok(v_lc)) => UserRequestFilter::Or(vec![
            UserRequestFilter::AttributeEquality(field.clone(), v),
            UserRequestFilter::AttributeEquality(field.clone(), v_lc),
        ]),
        (Ok(_), Err(e)) => {
            warn!("Invalid value for attribute {} (lowercased): {}", field, e);
            UserRequestFilter::False
        }
        (Err(e), _) => {
            warn!("Invalid value for attribute {}: {}", field, e);
            UserRequestFilter::False
        }
    }
}

pub fn convert_user_filter(
    ldap_info: &LdapInfo,
    filter: &LdapFilter,
    schema: &PublicSchema,
) -> LdapResult<UserRequestFilter> {
    let rec = |f| convert_user_filter(ldap_info, f, schema);
    match filter {
        LdapFilter::Equality(field, value) if field.eq_ignore_ascii_case("objectclass") => Ok(
            if is_object_class(value, &get_default_user_object_classes_bytes(schema)) {
                UserRequestFilter::True
            } else {
                UserRequestFilter::False
            },
        ),

        LdapFilter::And(filters) => {
            let res = filters
                .iter()
                .map(rec)
                .filter(|c| !matches!(c, Ok(UserRequestFilter::True)))
                .flat_map(|f| match f {
                    Ok(UserRequestFilter::And(v)) => v.into_iter().map(Ok).collect(),
                    f => vec![f],
                })
                .collect::<LdapResult<Vec<_>>>()?;
            if res.is_empty() {
                Ok(UserRequestFilter::True)
            } else if res.len() == 1 {
                Ok(res.into_iter().next().unwrap())
            } else {
                Ok(UserRequestFilter::And(res))
            }
        }
        LdapFilter::Or(filters) => {
            let res = filters
                .iter()
                .map(rec)
                .filter(|c| !matches!(c, Ok(UserRequestFilter::False)))
                .flat_map(|f| match f {
                    Ok(UserRequestFilter::Or(v)) => v.into_iter().map(Ok).collect(),
                    f => vec![f],
                })
                .collect::<LdapResult<Vec<_>>>()?;
            if res.is_empty() {
                Ok(UserRequestFilter::False)
            } else if res.len() == 1 {
                Ok(res.into_iter().next().unwrap())
            } else {
                Ok(UserRequestFilter::Or(res))
            }
        }
        LdapFilter::Not(filter) => Ok(match rec(filter)? {
            UserRequestFilter::True => UserRequestFilter::False,
            UserRequestFilter::False => UserRequestFilter::True,
            f => UserRequestFilter::Not(Box::new(f)),
        }),
        LdapFilter::Equality(field, value) => {
            let field = AttributeName::from(field.as_str());
            let value_lc = value.to_ascii_lowercase();

            // RFC/standards-mapped virtual attributes (loginDisabled, sudoHost).
            // These are synthesized from lldap_* group membership (see attributes.rs + subschema.rs).
            // Translate filters on the standardized names into the equivalent MemberOf on the
            // source built-in group. This makes (loginDisabled=TRUE) etc. work for "proper search"
            // and avoids the generic "unknown attribute" warning + False for these now-published attrs.
            let fname = field.as_str();
            if fname.eq_ignore_ascii_case("logindisabled") {
                if value_lc == "true" || value_lc == "1" || value_lc == "yes" {
                    return Ok(UserRequestFilter::MemberOf("lldap_disabled".into()));
                } else {
                    return Ok(UserRequestFilter::False);
                }
            }
            if fname.eq_ignore_ascii_case("sudohost") {
                // Support common "has the flag" assertions (clients may send *, ALL, or true-ish).
                if value_lc == "*" || value_lc == "all" || value_lc == "true" || value_lc == "1" {
                    return Ok(UserRequestFilter::MemberOf("lldap_sudohost".into()));
                } else {
                    return Ok(UserRequestFilter::False);
                }
            }

            match crate::schema::get_schema_manager().map_user_field(&field, schema) {
                UserFieldType::PrimaryField(lldap_domain_model::model::UserColumn::UserId) => {
                    Ok(UserRequestFilter::UserId(UserId::new(&value_lc)))
                }
                UserFieldType::PrimaryField(lldap_domain_model::model::UserColumn::Email) => {
                    Ok(UserRequestFilter::Equality(
                        lldap_domain_model::model::UserColumn::LowercaseEmail,
                        value_lc,
                    ))
                }
                UserFieldType::PrimaryField(field) => {
                    Ok(UserRequestFilter::Equality(field, value_lc))
                }
                UserFieldType::Attribute(field, typ, is_list) => Ok(
                    get_user_attribute_equality_filter(&field, typ, is_list, value),
                ),
                UserFieldType::NoMatch => {
                    if is_unrecognized_attribute(&field, &ldap_info.ignored_user_attributes) {
                        debug!(
                            r#"Ignoring unknown user attribute "{}" in filter. Add to "ignored_user_attributes" to silence."#,
                            field
                        );
                    }
                    Ok(UserRequestFilter::False)
                }
                UserFieldType::ObjectClass => Ok(UserRequestFilter::And(vec![])),
                UserFieldType::MemberOf => Ok(get_group_id_from_distinguished_name_or_plain_name(
                    &value_lc,
                    &ldap_info.base_dn,
                    &ldap_info.base_dn_str,
                )
                .map(UserRequestFilter::MemberOf)
                .unwrap_or_else(|e| {
                    warn!("Invalid memberOf filter: {}", e);
                    UserRequestFilter::False
                })),
                UserFieldType::EntryDn | UserFieldType::Dn => {
                    Ok(get_user_id_from_distinguished_name_or_plain_name(
                        value_lc.as_str(),
                        &ldap_info.base_dn,
                        &ldap_info.base_dn_str,
                    )
                    .map(UserRequestFilter::UserId)
                    .unwrap_or_else(|_| {
                        warn!("Invalid dn filter on user: {}", value_lc);
                        UserRequestFilter::False
                    }))
                }
                UserFieldType::EntryUuid => {
                    // entryUUID maps to the internal user uuid column
                    match lldap_domain::types::Uuid::try_from(value.as_str()) {
                        Ok(_) => Ok(UserRequestFilter::Equality(
                            lldap_domain_model::model::UserColumn::Uuid,
                            value.to_string(),
                        )),
                        Err(e) => Err(LdapError {
                            code: ldap3_proto::LdapResultCode::Other,
                            message: format!("Invalid UUID in filter: {e:#}"),
                        }),
                    }
                }
            }
        }
        LdapFilter::GreaterOrEqual(field, value) => {
            let field = AttributeName::from(field.as_str());
            match crate::schema::get_schema_manager().map_user_field(&field, schema) {
                UserFieldType::PrimaryField(f)
                    if matches!(
                        f,
                        lldap_domain_model::model::UserColumn::CreationDate
                            | lldap_domain_model::model::UserColumn::ModifiedDate
                            | lldap_domain_model::model::UserColumn::PasswordModifiedDate
                    ) =>
                {
                    Ok(UserRequestFilter::GreaterOrEqual(f, value.to_string()))
                }
                UserFieldType::Attribute(name, AttributeType::DateTime, _) => Ok(
                    UserRequestFilter::AttributeGreaterOrEqual(name, value.to_string()),
                ),
                _ => Err(LdapError {
                    code: ldap3_proto::LdapResultCode::UnwillingToPerform,
                    message: format!("GreaterOrEqual not supported on this attribute: {}", field),
                }),
            }
        }
        LdapFilter::LessOrEqual(field, value) => {
            let field = AttributeName::from(field.as_str());
            match crate::schema::get_schema_manager().map_user_field(&field, schema) {
                UserFieldType::PrimaryField(f)
                    if matches!(
                        f,
                        lldap_domain_model::model::UserColumn::CreationDate
                            | lldap_domain_model::model::UserColumn::ModifiedDate
                            | lldap_domain_model::model::UserColumn::PasswordModifiedDate
                    ) =>
                {
                    Ok(UserRequestFilter::LessOrEqual(f, value.to_string()))
                }
                UserFieldType::Attribute(name, AttributeType::DateTime, _) => Ok(
                    UserRequestFilter::AttributeLessOrEqual(name, value.to_string()),
                ),
                _ => Err(LdapError {
                    code: ldap3_proto::LdapResultCode::UnwillingToPerform,
                    message: format!("LessOrEqual not supported on this attribute: {}", field),
                }),
            }
        }
        LdapFilter::Present(field) => {
            let field = AttributeName::from(field.as_str());

            // Same virtual attr translation as Equality: presence of loginDisabled/sudoHost
            // means "member of the corresponding lldap_* built-in group".
            let fname = field.as_str();
            if fname.eq_ignore_ascii_case("logindisabled") {
                return Ok(UserRequestFilter::MemberOf("lldap_disabled".into()));
            }
            if fname.eq_ignore_ascii_case("sudohost") {
                return Ok(UserRequestFilter::MemberOf("lldap_sudohost".into()));
            }

            Ok(
                match crate::schema::get_schema_manager().map_user_field(&field, schema) {
                    UserFieldType::Attribute(name, _, _) => {
                        UserRequestFilter::CustomAttributePresent(name)
                    }
                    UserFieldType::NoMatch => UserRequestFilter::False,
                    _ => UserRequestFilter::True,
                },
            )
        }
        LdapFilter::Substring(field, substring_filter) => {
            let field = AttributeName::from(field.as_str());
            match crate::schema::get_schema_manager().map_user_field(&field, schema) {
                UserFieldType::PrimaryField(lldap_domain_model::model::UserColumn::UserId) => Ok(
                    UserRequestFilter::UserIdSubString(substring_filter.clone().into()),
                ),
                UserFieldType::Attribute(name, lldap_schema::AttributeType::String, _) => Ok(
                    UserRequestFilter::AttributeSubString(name, substring_filter.clone().into()),
                ),
                // Non-string custom attributes still get rejected (makes sense)
                UserFieldType::Attribute(_, _, _) => Err(LdapError {
                    code: ldap3_proto::LdapResultCode::UnwillingToPerform,
                    message: format!("Unsupported user attribute for substring filter: {field:?}"),
                }),
                UserFieldType::ObjectClass
                | UserFieldType::MemberOf
                | UserFieldType::Dn
                | UserFieldType::EntryDn
                | UserFieldType::EntryUuid
                | UserFieldType::PrimaryField(
                    lldap_domain_model::model::UserColumn::CreationDate,
                )
                | UserFieldType::PrimaryField(lldap_domain_model::model::UserColumn::Uuid) => {
                    Err(LdapError {
                        code: ldap3_proto::LdapResultCode::UnwillingToPerform,
                        message: format!(
                            "Unsupported user attribute for substring filter: {field:?}"
                        ),
                    })
                }
                UserFieldType::NoMatch => Ok(UserRequestFilter::False),
                UserFieldType::PrimaryField(lldap_domain_model::model::UserColumn::Email) => {
                    Ok(UserRequestFilter::SubString(
                        lldap_domain_model::model::UserColumn::LowercaseEmail,
                        substring_filter.clone().into(),
                    ))
                }
                UserFieldType::PrimaryField(field) => Ok(UserRequestFilter::SubString(
                    field,
                    substring_filter.clone().into(),
                )),
            }
        }
        _ => Err(LdapError {
            code: ldap3_proto::LdapResultCode::UnwillingToPerform,
            message: format!("Unsupported user filter: {filter:?}"),
        }),
    }
}

// GROUP FILTER CONVERSION

fn get_group_attribute_equality_filter(
    field: &AttributeName,
    typ: AttributeType,
    is_list: bool,
    value: &str,
) -> GroupRequestFilter {
    let value_lc = value.to_ascii_lowercase();
    let serialized_value = deserialize_attribute_value(&[value.to_owned()], typ, is_list);
    let serialized_value_lc =
        deserialize_attribute_value(std::slice::from_ref(&value_lc), typ, is_list);
    match (serialized_value, serialized_value_lc) {
        (Ok(v), Ok(v_lc)) => GroupRequestFilter::Or(vec![
            GroupRequestFilter::AttributeEquality(field.clone(), v),
            GroupRequestFilter::AttributeEquality(field.clone(), v_lc),
        ]),
        (Ok(_), Err(e)) => {
            warn!("Invalid value for attribute {} (lowercased): {}", field, e);
            GroupRequestFilter::False
        }
        (Err(e), _) => {
            warn!("Invalid value for attribute {}: {}", field, e);
            GroupRequestFilter::False
        }
    }
}

pub fn convert_group_filter(
    ldap_info: &LdapInfo,
    filter: &LdapFilter,
    schema: &PublicSchema,
) -> LdapResult<GroupRequestFilter> {
    let rec = |f| convert_group_filter(ldap_info, f, schema);
    match filter {
        LdapFilter::Equality(field, value) if field.eq_ignore_ascii_case("objectclass") => Ok(
            if is_object_class(value, &get_default_group_object_classes_bytes(schema)) {
                GroupRequestFilter::True
            } else {
                GroupRequestFilter::False
            },
        ),

        LdapFilter::Equality(field, value) => {
            let field = AttributeName::from(field.as_str());
            let value_lc = value.to_ascii_lowercase();
            match crate::schema::get_schema_manager().map_group_field(&field, schema) {
                GroupFieldType::GroupId => Ok(value_lc
                    .parse::<i32>()
                    .map(|id| GroupRequestFilter::GroupId(lldap_domain::types::GroupId(id)))
                    .unwrap_or_else(|_| {
                        warn!("Given group id is not a valid integer: {}", value_lc);
                        GroupRequestFilter::False
                    })),
                GroupFieldType::DisplayName => Ok(GroupRequestFilter::DisplayName(value_lc.into())),
                GroupFieldType::Uuid => lldap_domain::types::Uuid::try_from(value_lc.as_str())
                    .map(GroupRequestFilter::Uuid)
                    .map_err(|e| LdapError {
                        code: ldap3_proto::LdapResultCode::Other,
                        message: format!("Invalid UUID: {e:#}"),
                    }),
                GroupFieldType::Member
                | GroupFieldType::UniqueMember
                | GroupFieldType::MemberUid
                | GroupFieldType::MemberOf => {
                    // "member" and "uniqueMember" are the standards; "memberof"/"ismemberof"
                    // are accepted as aliases pointing to the same membership filter semantics
                    // for groups (enables client compatibility + faster lookups).
                    Ok(get_user_id_from_distinguished_name_or_plain_name(
                        &value_lc,
                        &ldap_info.base_dn,
                        &ldap_info.base_dn_str,
                    )
                    .map(GroupRequestFilter::Member)
                    .unwrap_or_else(|e| {
                        warn!(
                            "Invalid member/uniqueMember/memberOf filter on group: {}",
                            e
                        );
                        GroupRequestFilter::False
                    }))
                }
                GroupFieldType::ObjectClass => Ok(GroupRequestFilter::And(vec![])),
                GroupFieldType::Dn | GroupFieldType::EntryDn => {
                    Ok(get_group_id_from_distinguished_name_or_plain_name(
                        value_lc.as_str(),
                        &ldap_info.base_dn,
                        &ldap_info.base_dn_str,
                    )
                    .map(GroupRequestFilter::DisplayName)
                    .unwrap_or_else(|_| {
                        warn!("Invalid dn filter on group: {}", value_lc);
                        GroupRequestFilter::False
                    }))
                }
                GroupFieldType::EntryUuid => lldap_domain::types::Uuid::try_from(value.as_str())
                    .map(GroupRequestFilter::Uuid)
                    .map_err(|e| LdapError {
                        code: ldap3_proto::LdapResultCode::Other,
                        message: format!("Invalid UUID in filter: {e:#}"),
                    }),
                GroupFieldType::NoMatch => {
                    if is_unrecognized_attribute(&field, &ldap_info.ignored_group_attributes) {
                        debug!(
                            r#"Ignoring unknown group attribute "{}" in filter. Add to "ignored_group_attributes" to silence."#,
                            field
                        );
                    }
                    Ok(GroupRequestFilter::False)
                }
                GroupFieldType::Attribute(field, typ, is_list) => Ok(
                    get_group_attribute_equality_filter(&field, typ, is_list, value),
                ),
                GroupFieldType::CreationDate => Err(LdapError {
                    code: ldap3_proto::LdapResultCode::UnwillingToPerform,
                    message: "Creation date filter for groups not supported".to_owned(),
                }),
                GroupFieldType::ModifiedDate => Err(LdapError {
                    code: ldap3_proto::LdapResultCode::UnwillingToPerform,
                    message: "Modified date filter for groups not supported".to_owned(),
                }),
            }
        }
        LdapFilter::GreaterOrEqual(field, value) => {
            let field = AttributeName::from(field.as_str());
            match crate::schema::get_schema_manager().map_group_field(&field, schema) {
                GroupFieldType::CreationDate | GroupFieldType::ModifiedDate => {
                    // Use the authoritative PublicSchema (passed in) + resolve_group_canonical_name
                    // so aliases ("createTimestamp", "modifyTimestamp", "creation_date", etc.)
                    // are properly translated to the internal canonical names ("creationdate"/"modifieddate").
                    let canonical = schema
                        .resolve_group_canonical_name(field.as_str())
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| field.as_str().to_string());
                    Ok(GroupRequestFilter::GreaterOrEqual(
                        canonical,
                        value.to_string(),
                    ))
                }
                GroupFieldType::Attribute(name, AttributeType::DateTime, _) => Ok(
                    GroupRequestFilter::AttributeGreaterOrEqual(name, value.to_string()),
                ),
                _ => Err(LdapError {
                    code: ldap3_proto::LdapResultCode::UnwillingToPerform,
                    message: format!(
                        "GreaterOrEqual is only supported on timestamp attributes for groups (got: {})",
                        field
                    ),
                }),
            }
        }
        LdapFilter::LessOrEqual(field, value) => {
            let field = AttributeName::from(field.as_str());
            match crate::schema::get_schema_manager().map_group_field(&field, schema) {
                GroupFieldType::CreationDate | GroupFieldType::ModifiedDate => {
                    // Use the authoritative PublicSchema (passed in) + resolve_group_canonical_name
                    // (see GreaterOrEqual comment for full rationale)
                    let canonical = schema
                        .resolve_group_canonical_name(field.as_str())
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| field.as_str().to_string());
                    Ok(GroupRequestFilter::LessOrEqual(
                        canonical,
                        value.to_string(),
                    ))
                }
                GroupFieldType::Attribute(name, AttributeType::DateTime, _) => Ok(
                    GroupRequestFilter::AttributeLessOrEqual(name, value.to_string()),
                ),
                _ => Err(LdapError {
                    code: ldap3_proto::LdapResultCode::UnwillingToPerform,
                    message: format!(
                        "LessOrEqual is only supported on timestamp attributes for groups (got: {})",
                        field
                    ),
                }),
            }
        }
        LdapFilter::And(filters) => {
            let res = filters
                .iter()
                .map(rec)
                .filter(|f| !matches!(f, Ok(GroupRequestFilter::True)))
                .flat_map(|f| match f {
                    Ok(GroupRequestFilter::And(v)) => v.into_iter().map(Ok).collect(),
                    f => vec![f],
                })
                .collect::<LdapResult<Vec<_>>>()?;
            if res.is_empty() {
                Ok(GroupRequestFilter::True)
            } else if res.len() == 1 {
                Ok(res.into_iter().next().unwrap())
            } else {
                Ok(GroupRequestFilter::And(res))
            }
        }
        LdapFilter::Or(filters) => {
            let res = filters
                .iter()
                .map(rec)
                .filter(|c| !matches!(c, Ok(GroupRequestFilter::False)))
                .flat_map(|f| match f {
                    Ok(GroupRequestFilter::Or(v)) => v.into_iter().map(Ok).collect(),
                    f => vec![f],
                })
                .collect::<LdapResult<Vec<_>>>()?;
            if res.is_empty() {
                Ok(GroupRequestFilter::False)
            } else if res.len() == 1 {
                Ok(res.into_iter().next().unwrap())
            } else {
                Ok(GroupRequestFilter::Or(res))
            }
        }
        LdapFilter::Not(filter) => Ok(match rec(filter)? {
            GroupRequestFilter::True => GroupRequestFilter::False,
            GroupRequestFilter::False => GroupRequestFilter::True,
            f => GroupRequestFilter::Not(Box::new(f)),
        }),
        LdapFilter::Present(field) => {
            let field = AttributeName::from(field.as_str());
            Ok(
                match crate::schema::get_schema_manager().map_group_field(&field, schema) {
                    GroupFieldType::Attribute(name, _, _) => {
                        GroupRequestFilter::CustomAttributePresent(name)
                    }
                    GroupFieldType::NoMatch => GroupRequestFilter::False,
                    _ => GroupRequestFilter::True,
                },
            )
        }
        LdapFilter::Substring(field, substring_filter) => {
            let field = AttributeName::from(field.as_str());
            match crate::schema::get_schema_manager().map_group_field(&field, schema) {
                GroupFieldType::DisplayName => Ok(GroupRequestFilter::DisplayNameSubString(
                    substring_filter.clone().into(),
                )),
                GroupFieldType::Attribute(name, AttributeType::String, _) => Ok(
                    GroupRequestFilter::AttributeSubString(name, substring_filter.clone().into()),
                ),
                GroupFieldType::NoMatch => Ok(GroupRequestFilter::False),
                _ => Err(LdapError {
                    code: ldap3_proto::LdapResultCode::UnwillingToPerform,
                    message: format!(
                        "Unsupported group attribute for substring filter: \"{field}\""
                    ),
                }),
            }
        }
        _ => Err(LdapError {
            code: ldap3_proto::LdapResultCode::UnwillingToPerform,
            message: format!("Unsupported group filter: {filter:?}"),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ldap3_proto::proto::LdapSubstringFilter;
    use lldap_schema::PublicSchema;

    #[test]
    fn test_convert_user_filter_substring_on_custom_string_attribute() {
        let schema = PublicSchema::get();
        let ldap_info = crate::core::utils::LdapInfo {
            base_dn: vec![],
            base_dn_str: "dc=example,dc=com".to_string(),
            ignored_user_attributes: vec![],
            ignored_group_attributes: vec![],
        };

        let filter = LdapFilter::Substring(
            "givenName".to_string(),
            LdapSubstringFilter {
                initial: Some("jo".to_string()),
                any: vec![],
                final_: None,
            },
        );

        let result = convert_user_filter(&ldap_info, &filter, &schema);
        assert!(result.is_ok());

        // Should produce AttributeSubString (not an error)
        match result.unwrap() {
            UserRequestFilter::AttributeSubString(name, _) => {
                assert_eq!(name.as_str(), "firstname"); // canonical name
            }
            other => panic!("Expected AttributeSubString, got {:?}", other),
        }
    }

    #[test]
    fn test_convert_group_filter_memberof_points_to_member() {
        let schema = PublicSchema::get();
        let ldap_info = crate::core::utils::LdapInfo {
            base_dn: vec![],
            base_dn_str: "dc=example,dc=com".to_string(),
            ignored_user_attributes: vec![],
            ignored_group_attributes: vec![],
        };

        // memberof (and ismemberof) on group filter should point to Member semantics
        let filter = LdapFilter::Equality("memberof".to_string(), "someuser".to_string());
        let result = convert_group_filter(&ldap_info, &filter, &schema);
        assert!(result.is_ok());
        match result.unwrap() {
            GroupRequestFilter::Member(uid) => {
                assert_eq!(uid.as_str(), "someuser");
            }
            other => panic!("Expected Member for memberof group filter, got {:?}", other),
        }

        // Also via the standard "member" name (plain value is accepted and lowercased)
        let filter2 = LdapFilter::Equality("member".to_string(), "bar".to_string());
        let result2 = convert_group_filter(&ldap_info, &filter2, &schema);
        assert!(result2.is_ok());
        match result2.unwrap() {
            GroupRequestFilter::Member(uid) => {
                assert_eq!(uid.as_str(), "bar");
            }
            other => panic!("Expected Member for member group filter, got {:?}", other),
        }
    }

    #[test]
    fn group_filter_member_uid_resolves_to_member() {
        // (memberUid=alice) finds groups containing alice (SSSD rfc2307 initgroups path).
        match group_eq("memberUid", "alice") {
            GroupRequestFilter::Member(uid) => assert_eq!(uid.as_str(), "alice"),
            other => panic!("expected Member for memberUid, got {other:?}"),
        }
    }

    #[test]
    fn user_filter_gecos_maps_to_display_name() {
        // gecos (POSIX GECOS = the full name) filters on display_name.
        match user_eq("gecos", "bob") {
            UserRequestFilter::Equality(lldap_domain_model::model::UserColumn::DisplayName, v) => {
                assert_eq!(v, "bob");
            }
            other => panic!("expected DisplayName equality for gecos, got {other:?}"),
        }
    }

    #[test]
    fn group_filter_uid_is_false_not_unknown() {
        // (uid=…) on a group search: uid is known (user-side); group NoMatch is
        // False without treating it as unrecognized.
        match group_eq("uid", "bob") {
            GroupRequestFilter::False => {}
            other => panic!("expected False for uid-on-group, got {other:?}"),
        }
        assert!(!is_unrecognized_attribute(&AttributeName::from("uid"), &[]));
    }

    fn info() -> LdapInfo {
        LdapInfo {
            base_dn: vec![],
            base_dn_str: "dc=example,dc=com".to_string(),
            ignored_user_attributes: vec![],
            ignored_group_attributes: vec![],
        }
    }

    fn user_eq(name: &str, value: &str) -> UserRequestFilter {
        let filter = LdapFilter::Equality(name.to_string(), value.to_string());
        convert_user_filter(&info(), &filter, &PublicSchema::get()).unwrap()
    }

    fn group_eq(name: &str, value: &str) -> GroupRequestFilter {
        let filter = LdapFilter::Equality(name.to_string(), value.to_string());
        convert_group_filter(&info(), &filter, &PublicSchema::get()).unwrap()
    }

    // After the SchemaManager fix, the schema canonical name resolves to its primary field just
    // like its aliases (issues #2/#5) — previously the canonical name fell to the custom path.
    #[test]
    fn user_filter_canonical_and_aliases_resolve_to_primary() {
        for name in ["userid", "user_id", "uid", "id"] {
            assert!(
                matches!(user_eq(name, "Bob"), UserRequestFilter::UserId(_)),
                "{name}"
            );
        }
        for name in ["mail", "email"] {
            assert!(
                matches!(user_eq(name, "a@b.co"), UserRequestFilter::Equality(_, _)),
                "{name}"
            );
        }
        for name in ["displayname", "display_name", "cn", "commonname"] {
            assert!(
                matches!(user_eq(name, "Bob"), UserRequestFilter::Equality(_, _)),
                "{name}"
            );
        }
        for name in ["creationdate", "createTimestamp", "modifieddate"] {
            assert!(
                matches!(
                    user_eq(name, "20200101000000Z"),
                    UserRequestFilter::Equality(_, _)
                ),
                "{name}"
            );
        }
    }

    #[test]
    fn user_filter_cn_substring_maps_to_display_name() {
        for name in ["cn", "displayname", "display_name"] {
            let filter = LdapFilter::Substring(
                name.to_string(),
                LdapSubstringFilter {
                    initial: None,
                    any: vec!["ae".to_string()],
                    final_: None,
                },
            );
            let got = convert_user_filter(&info(), &filter, &PublicSchema::get()).unwrap();
            assert!(
                matches!(
                    got,
                    UserRequestFilter::SubString(
                        lldap_domain_model::model::UserColumn::DisplayName,
                        _
                    )
                ),
                "{name}"
            );
        }
    }

    #[test]
    fn user_filter_virtuals_objectclass_and_unknown_are_pinned() {
        assert!(matches!(
            user_eq("loginDisabled", "TRUE"),
            UserRequestFilter::MemberOf(_)
        ));
        assert!(matches!(
            user_eq("loginDisabled", "nope"),
            UserRequestFilter::False
        ));
        assert!(matches!(
            user_eq("sudoHost", "ALL"),
            UserRequestFilter::MemberOf(_)
        ));
        assert!(matches!(
            user_eq("sudoHost", "nope"),
            UserRequestFilter::False
        ));
        assert!(matches!(
            user_eq("objectclass", "inetOrgPerson"),
            UserRequestFilter::True
        ));
        assert!(matches!(
            user_eq("objectclass", "bogusClass"),
            UserRequestFilter::False
        ));
        assert!(matches!(
            user_eq("no_such_attr", "x"),
            UserRequestFilter::False
        ));
    }

    #[test]
    fn group_filter_resolution_is_pinned() {
        for n in ["memberof", "member", "uniquemember", "ismemberof"] {
            assert!(
                matches!(group_eq(n, "bar"), GroupRequestFilter::Member(_)),
                "{n}"
            );
        }
        for name in ["displayname", "display_name", "cn", "commonname"] {
            assert!(
                matches!(group_eq(name, "admins"), GroupRequestFilter::DisplayName(_)),
                "{name}"
            );
        }
        assert!(matches!(
            group_eq("no_such_attr", "x"),
            GroupRequestFilter::False
        ));
    }

    #[test]
    fn group_filter_groupid_targets_the_primary_id() {
        for name in ["groupid", "group_id", "groupId"] {
            assert_eq!(
                group_eq(name, "7"),
                GroupRequestFilter::GroupId(lldap_domain::types::GroupId(7)),
                "{name}"
            );
        }
    }
}
