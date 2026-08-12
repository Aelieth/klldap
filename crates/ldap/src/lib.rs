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

pub use attributes::{
    get_default_group_object_classes_bytes, get_default_user_object_classes_bytes,
    get_group_attribute, get_group_ou, get_user_attribute, get_user_ou,
    make_ldap_search_group_result_entry, make_ldap_search_user_result_entry,
};
