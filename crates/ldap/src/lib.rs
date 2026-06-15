#![forbid(unsafe_code)]
pub(crate) mod attributes;
pub(crate) mod compare;
pub(crate) mod core;
pub(crate) mod create;
pub(crate) mod delete;
pub(crate) mod dn;
pub(crate) mod handler;
pub(crate) mod modify;
pub(crate) mod password;
pub(crate) mod schema;
pub(crate) mod search;

pub use core::utils::LdapInfo;
pub use handler::LdapHandler;

pub use core::group::get_default_group_object_classes;
pub use core::user::get_default_user_object_classes;

pub use schema::{
    ExpandedAttributes, GroupFieldType, LogicalAttr, SchemaManager, UserFieldType,
    get_schema_manager,
};

// Thin shims for graphql-server compatibility (will be removed once graphql-server is updated)
pub fn map_user_field(
    field: &lldap_domain::types::AttributeName,
    schema: &lldap_domain::public_schema::PublicSchema,
) -> UserFieldType {
    get_schema_manager().map_user_field(field, schema)
}

pub fn map_group_field(
    field: &lldap_domain::types::AttributeName,
    schema: &lldap_domain::public_schema::PublicSchema,
) -> GroupFieldType {
    get_schema_manager().map_group_field(field, schema)
}

pub use attributes::{
    get_default_group_object_classes_bytes, get_default_user_object_classes_bytes,
    get_group_attribute, get_group_ou, get_user_attribute, get_user_ou,
    make_ldap_search_group_result_entry, make_ldap_search_user_result_entry,
};
