//! SchemaManager - For all attribute handling.

use super::definitions::{ExpandedAttributes, LogicalAttr};
use crate::attributes::get_preferred_ldap_name;
use crate::core::utils::{GroupFieldType, UserFieldType};
use lldap_domain::public_schema::PublicSchema;
use lldap_domain::types::AttributeName;
use std::collections::{BTreeMap, HashSet};

#[derive(Clone)]
pub struct SchemaManager {
    /// name (lowercased) → (LogicalAttr, canonical LDAP name)
    /// Built dynamically from PublicSchema at construction time.
    attribute_map: std::collections::HashMap<String, (LogicalAttr, String)>,
}

impl SchemaManager {
    /// Creates a fully dynamic SchemaManager from the given PublicSchema.
    pub fn new(schema: &PublicSchema) -> Self {
        let mut attribute_map = std::collections::HashMap::new();

        // Helper to register an attribute + all its aliases
        let mut register =
            |_internal_name: &str, logical: LogicalAttr, canonical: &str, aliases: &[String]| {
                let lower_canonical = canonical.to_ascii_lowercase();
                attribute_map.insert(lower_canonical.clone(), (logical, canonical.to_string()));

                for alias in aliases {
                    let lower_alias = alias.to_ascii_lowercase();
                    if lower_alias != lower_canonical {
                        attribute_map.insert(lower_alias, (logical, canonical.to_string()));
                    }
                }
            };

        // Register core operational / structural attributes (these are not in PublicSchema)
        let core_attrs: Vec<(&str, LogicalAttr, &str, Vec<String>)> = vec![
            (
                "objectclass",
                LogicalAttr::ObjectClass,
                "objectClass",
                vec![],
            ),
            (
                "memberof",
                LogicalAttr::MemberOf,
                "memberOf",
                vec!["ismemberof".into()],
            ),
            (
                "dn",
                LogicalAttr::Dn,
                "dn",
                vec!["distinguishedname".into()],
            ),
            ("entrydn", LogicalAttr::EntryDn, "entryDN", vec![]),
            (
                "hassubordinates",
                LogicalAttr::Operational,
                "hasSubordinates",
                vec![],
            ),
            (
                "structuralobjectclass",
                LogicalAttr::Operational,
                "structuralObjectClass",
                vec![],
            ),
            (
                "subschemasubentry",
                LogicalAttr::Operational,
                "subschemaSubentry",
                vec![],
            ),
            (
                "createtimestamp",
                LogicalAttr::Operational,
                "createTimestamp",
                vec![
                    "creationdate".into(),
                    "creation_date".into(),
                    "creationtimestamp".into(),
                ],
            ),
            (
                "modifytimestamp",
                LogicalAttr::Operational,
                "modifyTimestamp",
                vec![
                    "modifieddate".into(),
                    "modified_date".into(),
                    "modifydate".into(),
                ],
            ),
            (
                "pwdchangedtime",
                LogicalAttr::Operational,
                "pwdChangedTime",
                vec![
                    "passwordmodifieddate".into(),
                    "password_modified_date".into(),
                ],
            ),
            (
                "creatorsname",
                LogicalAttr::Operational,
                "creatorsName",
                vec![],
            ),
            (
                "modifiersname",
                LogicalAttr::Operational,
                "modifiersName",
                vec![],
            ),
            (
                "entryuuid",
                LogicalAttr::Operational,
                "entryUUID",
                vec!["uuid".into()],
            ),
            (
                "logindisabled",
                LogicalAttr::Operational,
                "loginDisabled",
                vec!["loginDisabled".into()],
            ),
            (
                "sudohost",
                LogicalAttr::Operational,
                "sudoHost",
                vec!["sudoHost".into()],
            ),
        ];

        for (name, logical, canonical, aliases) in core_attrs {
            register(name, logical, canonical, &aliases);
        }

        // Register all user attributes from PublicSchema
        for attr in schema.user_attributes().attributes.iter() {
            let preferred = get_preferred_ldap_name(attr);
            let logical = Self::determine_logical_attr(attr, &preferred);

            register(
                &attr.name.as_str().to_lowercase(),
                logical,
                &preferred,
                &attr.aliases,
            );
        }

        // Register all group attributes from PublicSchema
        for attr in schema.group_attributes().attributes.iter() {
            let preferred = get_preferred_ldap_name(attr);
            let logical = Self::determine_logical_attr(attr, &preferred);

            register(
                &attr.name.as_str().to_lowercase(),
                logical,
                &preferred,
                &attr.aliases,
            );
        }

        Self { attribute_map }
    }

    /// Determines whether an attribute is a known Primary column, Operational, or a Custom attribute.
    fn determine_logical_attr(
        attr: &lldap_schema::AttributeSchema,
        preferred: &str,
    ) -> LogicalAttr {
        let lower = preferred.to_ascii_lowercase();

        // Operational attributes — must be hidden in "*" and only shown in "+"
        if matches!(
            lower.as_str(),
            "hassubordinates"
                | "structuralobjectclass"
                | "subschemasubentry"
                | "entryuuid"
                | "uuid"
                | "memberof"
                | "ismemberof"
        ) {
            return LogicalAttr::Operational;
        }

        match lower.as_str() {
            "uid" | "user_id" | "id" | "userid" => {
                LogicalAttr::Primary(lldap_domain_model::model::UserColumn::UserId)
            }
            "mail" | "email" => LogicalAttr::Primary(lldap_domain_model::model::UserColumn::Email),
            "cn" | "displayname" | "display_name" => {
                LogicalAttr::Primary(lldap_domain_model::model::UserColumn::DisplayName)
            }
            "krbprincipalname" | "krb_principal_name" => {
                LogicalAttr::Primary(lldap_domain_model::model::UserColumn::KrbPrincipalName)
            }
            "createtimestamp" | "creationdate" | "creation_date" | "creationtimestamp" => {
                LogicalAttr::Primary(lldap_domain_model::model::UserColumn::CreationDate)
            }
            "modifytimestamp" | "modifieddate" | "modified_date" | "modifydate" => {
                LogicalAttr::Primary(lldap_domain_model::model::UserColumn::ModifiedDate)
            }
            "pwdchangedtime" | "passwordmodifieddate" | "password_modified_date" => {
                LogicalAttr::Primary(lldap_domain_model::model::UserColumn::PasswordModifiedDate)
            }
            _ => LogicalAttr::Custom(
                Box::leak(attr.name.as_str().to_string().into_boxed_str()),
                attr.attribute_type,
                attr.is_list,
            ),
        }
    }

    // ========================================================================
    // RESOLVE & CANONICAL NAME
    // ========================================================================

    /// Resolves an attribute name (case-insensitive) to its LogicalAttr and canonical LDAP name.
    /// Now fully dynamic — powered by the maps built from PublicSchema.
    pub fn resolve_attribute(&self, name: &str) -> Option<(LogicalAttr, String)> {
        let lower = name.to_ascii_lowercase();
        self.attribute_map.get(&lower).cloned()
    }

    pub fn get_canonical_name(&self, name: &str) -> String {
        self.resolve_attribute(name)
            .map(|(_, canon)| canon)
            .unwrap_or_else(|| name.to_string())
    }

    pub fn is_operational(&self, name: &str) -> bool {
        matches!(
            self.resolve_attribute(name),
            Some((LogicalAttr::Operational, _))
        )
    }

    // ========================================================================
    // FIELD MAPPING
    // ========================================================================

    pub fn map_user_field(&self, field: &AttributeName, schema: &PublicSchema) -> UserFieldType {
        if let Some((logical, _)) = self.resolve_attribute(field.as_str()) {
            return match logical {
                LogicalAttr::ObjectClass => UserFieldType::ObjectClass,
                LogicalAttr::MemberOf => UserFieldType::MemberOf,
                LogicalAttr::Dn => UserFieldType::Dn,
                LogicalAttr::EntryDn => UserFieldType::EntryDn,
                LogicalAttr::Operational
                    if field.as_str().eq_ignore_ascii_case("entryuuid")
                        || field.as_str().eq_ignore_ascii_case("uuid") =>
                {
                    UserFieldType::EntryUuid
                }
                LogicalAttr::Primary(col) => UserFieldType::PrimaryField(col),
                LogicalAttr::Custom(internal, t, is_list) => {
                    UserFieldType::Attribute(AttributeName::from(internal), t, is_list)
                }
                LogicalAttr::Operational => UserFieldType::NoMatch,
            };
        }

        schema
            .get_schema()
            .user_attributes
            .get_attribute_type(field.as_str())
            .map(|(t, is_list)| UserFieldType::Attribute(field.clone(), t, is_list))
            .unwrap_or(UserFieldType::NoMatch)
    }

    pub fn map_group_field(&self, field: &AttributeName, schema: &PublicSchema) -> GroupFieldType {
        if let Some((logical, _)) = self.resolve_attribute(field.as_str()) {
            return match logical {
                LogicalAttr::ObjectClass => GroupFieldType::ObjectClass,
                LogicalAttr::MemberOf => GroupFieldType::MemberOf,
                LogicalAttr::Dn => GroupFieldType::Dn,
                LogicalAttr::EntryDn => GroupFieldType::EntryDn,
                LogicalAttr::Operational
                    if field.as_str().eq_ignore_ascii_case("entryuuid")
                        || field.as_str().eq_ignore_ascii_case("uuid") =>
                {
                    GroupFieldType::EntryUuid
                }
                LogicalAttr::Primary(col) => match col {
                    lldap_domain_model::model::UserColumn::CreationDate => {
                        GroupFieldType::CreationDate
                    }
                    lldap_domain_model::model::UserColumn::ModifiedDate => {
                        GroupFieldType::ModifiedDate
                    }
                    lldap_domain_model::model::UserColumn::Uuid => GroupFieldType::Uuid,
                    lldap_domain_model::model::UserColumn::UserId => GroupFieldType::DisplayName,
                    lldap_domain_model::model::UserColumn::DisplayName => {
                        GroupFieldType::DisplayName
                    }
                    _ => GroupFieldType::NoMatch,
                },
                LogicalAttr::Custom(internal, t, is_list) => {
                    GroupFieldType::Attribute(AttributeName::from(internal), t, is_list)
                }
                LogicalAttr::Operational => GroupFieldType::NoMatch,
            };
        }

        // Explicit handling for member (standard for groupOfNames) and uniqueMember
        // (standard for groupOfUniqueNames). "memberof"/"ismemberof" are handled via
        // LogicalAttr::MemberOf above (pointed to Member semantics for group *filters*).
        if field.as_str().eq_ignore_ascii_case("member") {
            return GroupFieldType::Member;
        }
        if field.as_str().eq_ignore_ascii_case("uniquemember") {
            return GroupFieldType::UniqueMember;
        }

        schema
            .get_schema()
            .group_attributes
            .get_attribute_type(field.as_str())
            .map(|(t, is_list)| GroupFieldType::Attribute(field.clone(), t, is_list))
            .unwrap_or(GroupFieldType::NoMatch)
    }

    // ========================================================================
    // EXPAND ATTRIBUTE WILDCARDS (FULL LOGIC - COMPLETED)
    // ========================================================================

    pub fn expand_attribute_wildcards(
        &self,
        ldap_attributes: &[String],
        schema: &PublicSchema,
    ) -> ExpandedAttributes {
        let mut include_custom_attributes = false;

        let mut standard_keys: Vec<String> = Vec::new();
        let mut operational_keys: Vec<String> = Vec::new();

        let always_operational: HashSet<&str> = [
            "hassubordinates",
            "structuralobjectclass",
            "subschemasubentry",
            "createtimestamp",
            "modifytimestamp",
            "pwdchangedtime",
            "entryuuid",
            "entrydn",
            "memberof",
            "creatorsname",
            "modifiersname",
        ]
        .iter()
        .cloned()
        .collect();

        let _ignore_on_plus: HashSet<&str> = [
            "attributetypes",
            "objectclasses",
            "matchingrules",
            "ldapsyntaxes",
            "matchingruleuse",
            "creatorsname",
            "modifiersname",
            "namingcontexts",
            "supportedcontrol",
            "supportedextension",
            "supportedfeatures",
            "supportedldapversion",
            "supportedsaslmechanisms",
            "vendorname",
            "vendorversion",
            "altserver",
            "ref",
            "queryid",
        ]
        .iter()
        .cloned()
        .collect();

        for attr in schema
            .user_attributes()
            .attributes
            .iter()
            .chain(schema.group_attributes().attributes.iter())
        {
            let preferred_name = get_preferred_ldap_name(attr);

            if let Some((logical, _)) = self.resolve_attribute(&preferred_name) {
                let is_always_op =
                    always_operational.contains(preferred_name.to_ascii_lowercase().as_str());
                let target = if matches!(logical, LogicalAttr::Operational) || is_always_op {
                    &mut operational_keys
                } else {
                    &mut standard_keys
                };
                if !target
                    .iter()
                    .any(|k| k.eq_ignore_ascii_case(&preferred_name))
                {
                    target.push(preferred_name);
                }
            } else {
                if !standard_keys
                    .iter()
                    .any(|k| k.eq_ignore_ascii_case(&preferred_name))
                {
                    standard_keys.push(preferred_name);
                }
            }
        }

        for name in &always_operational {
            if !operational_keys
                .iter()
                .any(|k| k.eq_ignore_ascii_case(name))
            {
                operational_keys.push(name.to_string());
            }
        }

        let always_operational_set: HashSet<&str> = always_operational.iter().cloned().collect();
        standard_keys.retain(|k| !always_operational_set.contains(k.to_ascii_lowercase().as_str()));

        // objectClass is always included for standard searches
        if !standard_keys
            .iter()
            .any(|k| k.eq_ignore_ascii_case("objectClass"))
        {
            standard_keys.push("objectClass".to_string());
        }

        let mut seen = HashSet::new();
        standard_keys.retain(|k| seen.insert(k.to_ascii_lowercase()));
        seen.clear();
        operational_keys.retain(|k| seen.insert(k.to_ascii_lowercase()));

        let ignore_set: HashSet<String> = _ignore_on_plus
            .iter()
            .map(|s| s.to_ascii_lowercase())
            .collect();

        let mut attributes_out: BTreeMap<AttributeName, String> = BTreeMap::new();

        for s in ldap_attributes.iter().filter(|&s| {
            let lower = s.to_ascii_lowercase();
            lower != "*" && lower != "+" && lower != "1.1" && !ignore_set.contains(&lower)
        }) {
            let canonical = self.get_canonical_name(s);
            attributes_out.insert(AttributeName::from(&canonical), canonical);
        }

        operational_keys.retain(|k| !_ignore_on_plus.contains(k.as_str()));

        let has_star = ldap_attributes.iter().any(|x| x == "*") || ldap_attributes.is_empty();
        let has_plus = ldap_attributes.iter().any(|x| x == "+");

        // Standard LDAP behavior: "+" returns both standard + operational attributes
        if has_star || has_plus {
            include_custom_attributes = true;
            for s in &standard_keys {
                attributes_out.insert(AttributeName::from(s), s.clone());
            }
        }

        if has_plus {
            for s in &operational_keys {
                attributes_out.insert(AttributeName::from(s), s.clone());
            }
        }

        // If any explicitly requested attribute is operational, include operational attrs
        // (per LDAP spec: explicitly requested operational attrs must be returned)
        let has_explicit_operational = attributes_out.keys().any(|k| {
            self.is_operational(k.as_str())
                || always_operational.contains(k.as_str().to_ascii_lowercase().as_str())
        });

        ExpandedAttributes {
            attribute_keys: attributes_out,
            include_custom_attributes,
            include_operational_attributes: has_plus || has_explicit_operational,
        }
    }

    // ========================================================================
    // SCHEMA ACCESS FOR SUBSCHEMA GENERATION
    // ========================================================================

    pub fn get_all_user_attributes(&self) -> Vec<lldap_schema::AttributeSchema> {
        PublicSchema::get().user_attributes().attributes.clone()
    }

    pub fn get_all_group_attributes(&self) -> Vec<lldap_schema::AttributeSchema> {
        PublicSchema::get().group_attributes().attributes.clone()
    }
}

impl Default for SchemaManager {
    fn default() -> Self {
        Self::new(&PublicSchema::get())
    }
}
