use crate::attributes::{make_ldap_search_group_result_entry, make_ldap_search_user_result_entry};
use crate::core::utils::LdapInfo;
use ldap3_proto::proto::LdapOp;
use lldap_domain::types::{Group, UserAndGroups, UserId};
use lldap_schema::PublicSchema;

pub fn convert_users_to_ldap_op<'a>(
    users: Vec<UserAndGroups>,
    attributes: &'a [String],
    ldap_info: &'a LdapInfo,
    schema: &'a PublicSchema,
) -> impl Iterator<Item = LdapOp> + 'a {
    let expanded_attributes = if users.is_empty() {
        None
    } else {
        Some(crate::schema::get_schema_manager().expand_attribute_wildcards(attributes, schema))
    };
    users.into_iter().map(move |u| {
        LdapOp::SearchResultEntry(make_ldap_search_user_result_entry(
            u.user,
            &ldap_info.base_dn_str,
            expanded_attributes.clone().unwrap(),
            u.groups.as_deref(),
            &ldap_info.ignored_user_attributes,
            schema,
        ))
    })
}

pub fn convert_groups_to_ldap_op<'a>(
    groups: Vec<Group>,
    attributes: &'a [String],
    ldap_info: &'a LdapInfo,
    user_filter: &'a Option<UserId>,
    schema: &'a PublicSchema,
) -> impl Iterator<Item = LdapOp> + 'a {
    let expanded_attributes = if groups.is_empty() {
        None
    } else {
        Some(crate::schema::get_schema_manager().expand_attribute_wildcards(attributes, schema))
    };
    groups.into_iter().map(move |g| {
        LdapOp::SearchResultEntry(make_ldap_search_group_result_entry(
            g,
            &ldap_info.base_dn_str,
            expanded_attributes.clone().unwrap(),
            user_filter,
            &ldap_info.ignored_group_attributes,
            schema,
        ))
    })
}
