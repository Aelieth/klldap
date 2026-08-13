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
    pub posix_settings: PosixSettings,
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

impl AttributeSchema {
    fn new(name: &str, attribute_type: AttributeType) -> Self {
        Self {
            name: name.to_owned(),
            aliases: Vec::new(),
            attribute_type,
            is_list: false,
            is_visible: true,
            is_editable: false,
            is_hardcoded: true,
            is_readonly: false,
        }
    }

    pub fn editable(name: &str, attribute_type: AttributeType) -> Self {
        Self {
            is_editable: true,
            ..Self::new(name, attribute_type)
        }
    }

    pub fn readonly(name: &str, attribute_type: AttributeType) -> Self {
        Self {
            is_readonly: true,
            ..Self::new(name, attribute_type)
        }
    }

    /// POSIX/Kerberos assigned: is_editable=false / is_readonly=false — do not normalize.
    pub fn generated(name: &str, attribute_type: AttributeType) -> Self {
        Self::new(name, attribute_type)
    }

    pub fn hidden(name: &str, attribute_type: AttributeType) -> Self {
        Self {
            is_visible: false,
            is_readonly: true,
            ..Self::new(name, attribute_type)
        }
    }

    pub fn aliases(mut self, aliases: &[&str]) -> Self {
        self.aliases = aliases.iter().map(|a| a.to_string()).collect();
        self
    }

    pub fn list(mut self) -> Self {
        self.is_list = true;
        self
    }

    /// The first alias that is a recognized standard LDAP name, else the canonical name.
    pub fn preferred_ldap_name(&self) -> &str {
        self.aliases
            .iter()
            .find(|alias| is_standard_ldap_name(&alias.to_ascii_lowercase()))
            .map(String::as_str)
            .unwrap_or(&self.name)
    }
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
        self.attributes.iter().find(|a| {
            a.name.eq_ignore_ascii_case(name)
                || a.aliases
                    .iter()
                    .any(|alias| alias.eq_ignore_ascii_case(name))
        })
    }

    pub fn contains_name_or_alias(&self, name: &str) -> bool {
        self.get_by_name_or_alias(name).is_some()
    }

    pub fn all_names_and_aliases(&self) -> impl Iterator<Item = &str> {
        self.attributes.iter().flat_map(|a| {
            std::iter::once(a.name.as_str()).chain(a.aliases.iter().map(String::as_str))
        })
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

    pub fn preferred_ldap_name(&self, name_or_alias: &str) -> Option<&str> {
        self.get_by_name_or_alias(name_or_alias)
            .map(AttributeSchema::preferred_ldap_name)
    }
}

// Standard LDAP attribute names. When an attribute carries one of these as an alias, it is
// advertised as the wire name (see AttributeSchema::preferred_ldap_name).
#[rustfmt::skip]
const STANDARD_LDAP_NAMES: &[&str] = &[
    "cn", "sn", "givenname", "uid", "mail", "ou", "dc", "o", "c", "l", "st",
    "title", "description", "member", "uniquemember", "memberof",
    "createtimestamp", "modifytimestamp", "pwdchangedtime", "entryuuid",
    "hassubordinates", "structuralobjectclass", "subschemasubentry",
    "uidnumber", "gidnumber", "homedirectory", "loginshell", "sshpublickey",
    "krbprincipalname", "jpegphoto", "avatar",
];

fn is_standard_ldap_name(name: &str) -> bool {
    STANDARD_LDAP_NAMES.contains(&name)
}
