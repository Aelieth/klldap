//! SchemaManager - For all attribute handling.

use super::definitions::{ExpandedAttributes, LogicalAttr};
use super::operational;
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
            |internal_name: &str, logical: LogicalAttr, canonical: &str, aliases: &[String]| {
                let lower_canonical = canonical.to_ascii_lowercase();
                attribute_map.insert(lower_canonical.clone(), (logical, canonical.to_string()));

                // Also key on the schema canonical name (userid, displayname, creationdate, ...)
                // so filters on the internal name resolve like their aliases do.
                let lower_internal = internal_name.to_ascii_lowercase();
                if lower_internal != lower_canonical {
                    attribute_map.insert(lower_internal, (logical, canonical.to_string()));
                }

                for alias in aliases {
                    let lower_alias = alias.to_ascii_lowercase();
                    if lower_alias != lower_canonical {
                        attribute_map.insert(lower_alias, (logical, canonical.to_string()));
                    }
                }
            };

        // Register core operational / structural attributes from the single operational source.
        for op in operational::all() {
            let logical = match op.logical {
                operational::OpLogical::ObjectClass => LogicalAttr::ObjectClass,
                operational::OpLogical::Dn => LogicalAttr::Dn,
                operational::OpLogical::EntryDn => LogicalAttr::EntryDn,
                operational::OpLogical::MemberOf => LogicalAttr::MemberOf,
                operational::OpLogical::Operational => LogicalAttr::Operational,
            };
            let aliases: Vec<String> = op
                .aliases
                .iter()
                .chain(op.resolver_aliases.iter())
                .map(|s| s.to_string())
                .collect();
            register(&op.key(), logical, op.wire_name, &aliases);
        }

        // Register all user attributes from PublicSchema
        for attr in schema.user_attributes().attributes.iter() {
            let preferred = attr.preferred_ldap_name();
            let logical = Self::determine_logical_attr(attr, attr.name.as_str());

            register(
                &attr.name.as_str().to_lowercase(),
                logical,
                preferred,
                &attr.aliases,
            );
        }

        // Register all group attributes from PublicSchema
        for attr in schema.group_attributes().attributes.iter() {
            let preferred = attr.preferred_ldap_name();
            let logical = Self::determine_logical_attr(attr, attr.name.as_str());

            register(
                &attr.name.as_str().to_lowercase(),
                logical,
                preferred,
                &attr.aliases,
            );
        }

        Self { attribute_map }
    }

    /// Determines whether an attribute is a known Primary column, Operational, or a Custom attribute.
    fn determine_logical_attr(attr: &lldap_schema::AttributeSchema, name: &str) -> LogicalAttr {
        use lldap_domain_model::model::UserColumn;
        let lower = name.to_ascii_lowercase();

        // uuid is operational — hidden in "*", shown only in "+".
        if lower == "uuid" {
            return LogicalAttr::Operational;
        }

        // Keyed on the schema canonical name; aliases are folded in by `register`.
        match lower.as_str() {
            "userid" => LogicalAttr::Primary(UserColumn::UserId),
            "mail" => LogicalAttr::Primary(UserColumn::Email),
            "displayname" => LogicalAttr::Primary(UserColumn::DisplayName),
            "krbprincipalname" => LogicalAttr::Primary(UserColumn::KrbPrincipalName),
            "creationdate" => LogicalAttr::Primary(UserColumn::CreationDate),
            "modifieddate" => LogicalAttr::Primary(UserColumn::ModifiedDate),
            "passwordmodifieddate" => LogicalAttr::Primary(UserColumn::PasswordModifiedDate),
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
        // Single operational-gating predicate for the whole crate (RFC 4512: `+`/explicit, not `*`).
        operational::is_operational(name)
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

        // gecos (RFC 2307 posixAccount MAY) is the POSIX full-name field — back it with display_name,
        // so it filters and emits (under its own wire name) like the other display_name spellings.
        if field.as_str().eq_ignore_ascii_case("gecos") {
            return UserFieldType::PrimaryField(lldap_domain_model::model::UserColumn::DisplayName);
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
        // memberUid (RFC 2307 posixGroup) — SSSD's default rfc2307 group-member attribute.
        if field.as_str().eq_ignore_ascii_case("memberuid") {
            return GroupFieldType::MemberUid;
        }

        schema
            .get_schema()
            .group_attributes
            .get_attribute_type(field.as_str())
            .map(|(t, is_list)| GroupFieldType::Attribute(field.clone(), t, is_list))
            .unwrap_or(GroupFieldType::NoMatch)
    }

    // ========================================================================
    // EXPAND ATTRIBUTE WILDCARDS
    // ========================================================================

    pub fn expand_attribute_wildcards(
        &self,
        ldap_attributes: &[String],
        schema: &PublicSchema,
    ) -> ExpandedAttributes {
        let mut include_custom_attributes = false;

        let mut standard_keys: Vec<String> = Vec::new();
        let mut operational_keys: Vec<String> = Vec::new();

        let always_operational: HashSet<String> = operational::all()
            .iter()
            .filter(|o| o.always_operational)
            .map(|o| o.key())
            .collect();

        let ignore_set: HashSet<&str> = operational::SUBSCHEMA_PUBLISHED_NAMES
            .iter()
            .copied()
            .collect();

        for attr in schema
            .user_attributes()
            .attributes
            .iter()
            .chain(schema.group_attributes().attributes.iter())
        {
            let preferred_name = attr.preferred_ldap_name();

            if self.resolve_attribute(preferred_name).is_some() {
                let target = if operational::is_operational(preferred_name) {
                    &mut operational_keys
                } else {
                    &mut standard_keys
                };
                if !target
                    .iter()
                    .any(|k| k.eq_ignore_ascii_case(preferred_name))
                {
                    target.push(preferred_name.to_string());
                }
            } else if !standard_keys
                .iter()
                .any(|k| k.eq_ignore_ascii_case(preferred_name))
            {
                standard_keys.push(preferred_name.to_string());
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

        standard_keys.retain(|k| !always_operational.contains(k.to_ascii_lowercase().as_str()));

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

        let mut attributes_out: BTreeMap<AttributeName, String> = BTreeMap::new();

        // displayName is a distinct emitted wire name for the display_name value.
        const DISPLAY_NAME_WIRE: &str = "displayName";

        for s in ldap_attributes.iter().filter(|&s| {
            let lower = s.to_ascii_lowercase();
            lower != "*" && lower != "+" && lower != "1.1" && !ignore_set.contains(lower.as_str())
        }) {
            // Keep displayName apart from cn so an explicit displayName request returns displayName.
            if s.eq_ignore_ascii_case(DISPLAY_NAME_WIRE) {
                attributes_out.insert(
                    AttributeName::from(DISPLAY_NAME_WIRE),
                    DISPLAY_NAME_WIRE.to_string(),
                );
            } else {
                let canonical = self.get_canonical_name(s);
                attributes_out.insert(AttributeName::from(&canonical), canonical);
            }
        }

        let has_star = ldap_attributes.iter().any(|x| x == "*") || ldap_attributes.is_empty();
        let has_plus = ldap_attributes.iter().any(|x| x == "+");

        // Standard LDAP behavior: "+" returns both standard + operational attributes
        if has_star || has_plus {
            include_custom_attributes = true;
            for s in &standard_keys {
                attributes_out.insert(AttributeName::from(s), s.clone());
            }
            // Wildcard searches also emit displayName alongside cn (AD-compat).
            if standard_keys.iter().any(|k| k.eq_ignore_ascii_case("cn")) {
                attributes_out.insert(
                    AttributeName::from(DISPLAY_NAME_WIRE),
                    DISPLAY_NAME_WIRE.to_string(),
                );
            }
        }

        if has_plus {
            for s in &operational_keys {
                attributes_out.insert(AttributeName::from(s), s.clone());
            }
        }

        // If any explicitly requested attribute is operational, include operational attrs
        // (per LDAP spec: explicitly requested operational attrs must be returned)
        let has_explicit_operational = attributes_out
            .keys()
            .any(|k| self.is_operational(k.as_str()));

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
        PublicSchema::shared().user_attributes().attributes.clone()
    }

    pub fn get_all_group_attributes(&self) -> Vec<lldap_schema::AttributeSchema> {
        PublicSchema::shared().group_attributes().attributes.clone()
    }
}

impl Default for SchemaManager {
    fn default() -> Self {
        Self::new(PublicSchema::shared())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lldap_domain_model::model::UserColumn;
    use std::collections::HashSet;

    fn keys(exp: &ExpandedAttributes) -> HashSet<String> {
        exp.attribute_keys
            .values()
            .map(|s| s.to_ascii_lowercase())
            .collect()
    }

    fn expand(attrs: &[&str]) -> ExpandedAttributes {
        SchemaManager::default().expand_attribute_wildcards(
            &attrs.iter().map(|s| (*s).to_string()).collect::<Vec<_>>(),
            PublicSchema::shared(),
        )
    }

    #[test]
    fn expand_star_and_empty_are_user_attributes_only() {
        for attrs in [&["*"][..], &[][..]] {
            let exp = expand(attrs);
            assert!(exp.include_custom_attributes, "{attrs:?}");
            assert!(!exp.include_operational_attributes, "{attrs:?}");
            let k = keys(&exp);
            assert!(k.contains("uid"), "{attrs:?}");
            assert!(k.contains("mail"), "{attrs:?}");
            assert!(k.contains("objectclass"), "{attrs:?}");
            for op in [
                "createtimestamp",
                "modifytimestamp",
                "pwdchangedtime",
                "entryuuid",
                "hassubordinates",
                "entrydn",
                "memberof",
                "creatorsname",
                "modifiersname",
            ] {
                assert!(!k.contains(op), "{attrs:?} {op}");
            }
        }
    }

    #[test]
    fn expand_plus_adds_all_always_operational() {
        let exp = expand(&["+"]);
        assert!(exp.include_custom_attributes);
        assert!(exp.include_operational_attributes);
        let k = keys(&exp);
        assert!(k.contains("uid"));
        for op in [
            "createtimestamp",
            "modifytimestamp",
            "pwdchangedtime",
            "entryuuid",
            "hassubordinates",
            "structuralobjectclass",
            "subschemasubentry",
            "entrydn",
            "memberof",
            "creatorsname",
            "modifiersname",
        ] {
            assert!(k.contains(op), "{op}");
        }
        // loginDisabled/sudoHost stay explicit-only (not always_operational).
        assert!(!k.contains("logindisabled"));
        assert!(!k.contains("sudohost"));
    }

    #[test]
    fn expand_one_one_is_empty() {
        let exp = expand(&["1.1"]);
        assert!(!exp.include_custom_attributes);
        assert!(!exp.include_operational_attributes);
        assert!(exp.attribute_keys.is_empty());
    }

    #[test]
    fn expand_display_name_hybrid_emission() {
        // explicit displayName → displayName only; explicit cn → cn only; * → both.
        let dn = expand(&["displayName"]);
        let dn_vals: Vec<&str> = dn.attribute_keys.values().map(String::as_str).collect();
        assert!(dn_vals.contains(&"displayName"), "{dn_vals:?}");
        assert!(
            !keys(&dn).contains("cn"),
            "explicit displayName must not add cn"
        );

        let cn = expand(&["cn"]);
        assert!(keys(&cn).contains("cn"));
        assert!(
            !keys(&cn).contains("displayname"),
            "explicit cn must not add displayName"
        );

        let star = expand(&["*"]);
        let star_vals: Vec<&str> = star.attribute_keys.values().map(String::as_str).collect();
        assert!(star_vals.contains(&"cn"), "{star_vals:?}");
        assert!(star_vals.contains(&"displayName"), "{star_vals:?}");
    }

    #[test]
    fn expand_membership_explicit_only() {
        // Membership wires are group-builder inserts on `*`, not shared expand.
        for wire in ["member", "uniquemember", "memberuid"] {
            assert!(
                !keys(&expand(&["*"])).contains(wire),
                "* expand must not inject {wire} (user entries would log unknown)"
            );
        }
        assert!(keys(&expand(&["memberUid"])).contains("memberuid"));
        assert!(!keys(&expand(&["uid"])).contains("memberuid"));
    }

    #[test]
    fn gecos_backs_display_name() {
        // gecos resolves to the display_name column; explicit keeps the wire name.
        // `*` insert is user-builder only (posixAccount), not shared expand.
        let sm = SchemaManager::default();
        assert_eq!(
            sm.map_user_field(&AttributeName::from("gecos"), PublicSchema::shared()),
            UserFieldType::PrimaryField(UserColumn::DisplayName)
        );
        assert!(
            !keys(&expand(&["*"])).contains("gecos"),
            "* expand must not inject gecos (group entries would log unknown)"
        );
        assert!(keys(&expand(&["gecos"])).contains("gecos"));
    }

    #[test]
    fn expand_explicit_operational_requests_are_pinned() {
        let ts = expand(&["createTimestamp"]);
        assert!(ts.include_operational_attributes);
        assert!(!ts.include_custom_attributes);
        assert!(keys(&ts).contains("createtimestamp"));

        let uuid = expand(&["entryUUID"]);
        assert!(uuid.include_operational_attributes);
        assert!(keys(&uuid).contains("entryuuid"));

        let entry_dn = expand(&["entryDN"]);
        assert!(entry_dn.include_operational_attributes);
        assert!(keys(&entry_dn).contains("entrydn"));

        // creatorsName/modifiersName are now standard operational — explicit request works.
        let creators = expand(&["creatorsName"]);
        assert!(creators.include_operational_attributes);
        assert!(keys(&creators).contains("creatorsname"));

        // loginDisabled/sudoHost are explicit-only virtuals: requesting them must NOT set
        // include_operational (that would dump the 5 injected ops). The key is present (returned
        // via the per-attribute path), but the operational bucket stays off.
        let ld = expand(&["loginDisabled"]);
        assert!(!ld.include_operational_attributes);
        assert!(keys(&ld).contains("logindisabled"));
        let sh = expand(&["sudoHost"]);
        assert!(!sh.include_operational_attributes);
        assert!(keys(&sh).contains("sudohost"));
    }

    #[test]
    fn resolve_and_is_operational_normalized() {
        let sm = SchemaManager::default();
        let cases: &[(&str, bool, &str, Option<LogicalAttr>)] = &[
            (
                "objectclass",
                false,
                "objectClass",
                Some(LogicalAttr::ObjectClass),
            ),
            ("memberof", true, "memberOf", Some(LogicalAttr::MemberOf)),
            ("dn", false, "dn", Some(LogicalAttr::Dn)),
            ("entrydn", true, "entryDN", Some(LogicalAttr::EntryDn)),
            (
                "hassubordinates",
                true,
                "hasSubordinates",
                Some(LogicalAttr::Operational),
            ),
            (
                "createtimestamp",
                true,
                "createTimestamp",
                Some(LogicalAttr::Primary(UserColumn::CreationDate)),
            ),
            (
                "creationdate",
                true,
                "createTimestamp",
                Some(LogicalAttr::Primary(UserColumn::CreationDate)),
            ),
            (
                "creationtimestamp",
                true,
                "createTimestamp",
                Some(LogicalAttr::Operational),
            ),
            (
                "modifytimestamp",
                true,
                "modifyTimestamp",
                Some(LogicalAttr::Primary(UserColumn::ModifiedDate)),
            ),
            (
                "modifydate",
                true,
                "modifyTimestamp",
                Some(LogicalAttr::Operational),
            ),
            (
                "pwdchangedtime",
                true,
                "pwdChangedTime",
                Some(LogicalAttr::Primary(UserColumn::PasswordModifiedDate)),
            ),
            (
                "creatorsname",
                true,
                "creatorsName",
                Some(LogicalAttr::Operational),
            ),
            (
                "entryuuid",
                true,
                "entryUUID",
                Some(LogicalAttr::Operational),
            ),
            ("uuid", true, "entryUUID", Some(LogicalAttr::Operational)),
            (
                "logindisabled",
                false,
                "loginDisabled",
                Some(LogicalAttr::Operational),
            ),
            (
                "sudohost",
                false,
                "sudoHost",
                Some(LogicalAttr::Operational),
            ),
            (
                "userid",
                false,
                "uid",
                Some(LogicalAttr::Primary(UserColumn::UserId)),
            ),
        ];
        for &(name, operational, canon, ref logical) in cases {
            assert_eq!(
                sm.is_operational(name),
                operational,
                "is_operational({name})"
            );
            assert_eq!(sm.get_canonical_name(name), canon, "canonical({name})");
            let resolved = sm.resolve_attribute(name).map(|(l, _)| l);
            assert_eq!(resolved, *logical, "logical({name})");
        }
    }
}
