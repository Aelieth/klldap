use derive_more::Display;
use juniper::GraphQLEnum;
use serde::{Deserialize, Serialize};
use strum::{EnumIter, EnumString, IntoStaticStr};

// ==================== ATTRIBUTE TYPE (SINGLE SOURCE OF TRUTH) ====================
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    sea_orm::DeriveActiveEnum,
    EnumIter,
    EnumString,
    IntoStaticStr,
    GraphQLEnum,
    Display,
)]
#[sea_orm(rs_type = "String", db_type = "Text")]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[strum(serialize_all = "SCREAMING_SNAKE_CASE")]
pub enum AttributeType {
    #[sea_orm(string_value = "String")]
    String,
    #[sea_orm(string_value = "Integer")]
    Integer,
    #[sea_orm(string_value = "Avatar")]
    Avatar,
    #[sea_orm(string_value = "DateTime")]
    DateTime,
}

// ==================== SCHEMA STRUCTS ====================
#[derive(PartialEq, Eq, Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Schema {
    pub user_attributes: AttributeList,
    pub group_attributes: AttributeList,
    pub system_attributes: AttributeList,
    pub posix_settings: PosixSettings, // ← NEW: full POSIX settings
    pub extra_user_object_classes: Vec<String>,
    pub extra_group_object_classes: Vec<String>,
}

#[derive(PartialEq, Eq, Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct AttributeSchema {
    pub name: String,
    pub aliases: Vec<String>,
    pub attribute_type: AttributeType,
    pub is_list: bool,
    pub is_visible: bool,
    pub is_editable: bool,
    pub is_hardcoded: bool,
    pub is_readonly: bool,
}

#[derive(PartialEq, Eq, Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct AttributeList {
    pub attributes: Vec<AttributeSchema>,
}

#[derive(PartialEq, Eq, Debug, Serialize, Deserialize, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct PosixSettings {
    // === Users ===
    pub user_uidnumber_assign: bool,
    pub user_uidnumber_start: i64,
    pub user_uidnumber_max: i64,

    pub user_gidnumber_assign: bool,
    pub user_gidnumber_start: i64,

    pub user_loginshell_assign: bool,
    pub user_loginshell_default: String,

    pub user_homedirectory_assign: bool,
    pub user_homedirectory_prefix: String,

    // === Groups ===
    pub group_gidnumber_assign: bool,
    pub group_gidnumber_start: i64,
    pub group_gidnumber_max: i64,
}

impl AttributeList {
    pub fn get_by_name_or_alias(&self, name: &str) -> Option<&AttributeSchema> {
        // Case-insensitive match on both canonical name and aliases.
        // This fixes resolution when AttributeName::as_str() or loaded aliases
        // have subtle casing differences from CaseInsensitiveString.
        self.attributes.iter().find(|a| {
            a.name.eq_ignore_ascii_case(name)
                || a.aliases
                    .iter()
                    .any(|alias| alias.eq_ignore_ascii_case(name))
        })
    }

    pub fn get_attribute_schema(&self, name: &str) -> Option<&AttributeSchema> {
        self.get_by_name_or_alias(name)
    }

    pub fn get_attribute_type(&self, name: &str) -> Option<(AttributeType, bool)> {
        self.get_by_name_or_alias(name)
            .map(|a| (a.attribute_type, a.is_list))
    }

    pub fn format_for_ldap_schema_description(&self) -> String {
        self.attributes
            .iter()
            .map(|a| a.name.as_str())
            .collect::<Vec<_>>()
            .join(" $ ")
    }

    pub fn resolve_canonical_name(&self, name_or_alias: &str) -> Option<&str> {
        self.get_by_name_or_alias(name_or_alias)
            .map(|a| a.name.as_str())
    }
}
