//! Schema-related type definitions.

use lldap_domain::types::{AttributeName, AttributeType};
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LogicalAttr {
    ObjectClass,
    MemberOf,
    Dn,
    EntryDn,
    Primary(lldap_domain_model::model::UserColumn),
    Custom(&'static str, AttributeType, bool),
    Operational,
}

#[derive(Clone, Debug)]
pub struct ExpandedAttributes {
    pub attribute_keys: BTreeMap<AttributeName, String>,
    pub include_custom_attributes: bool,
    pub include_operational_attributes: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UserFieldType {
    NoMatch,
    ObjectClass,
    MemberOf,
    Dn,
    EntryDn,
    EntryUuid,
    PrimaryField(lldap_domain_model::model::UserColumn),
    Attribute(AttributeName, AttributeType, bool),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GroupFieldType {
    NoMatch,
    GroupId,
    DisplayName,
    CreationDate,
    ModifiedDate,
    ObjectClass,
    Dn,
    EntryDn,
    EntryUuid,
    UniqueMember,
    Member,
    MemberOf,
    Uuid,
    Attribute(AttributeName, AttributeType, bool),
}

// UserFieldType and GroupFieldType are defined above (single source of truth — no Copy because AttributeName is not Copy)
