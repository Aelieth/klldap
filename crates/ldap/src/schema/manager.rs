use super::definitions::{ExpandedAttributes, GroupFieldType, LogicalAttr, UserFieldType};
use super::operational;
use lldap_domain::types::AttributeName;
use lldap_schema::PublicSchema;
use std::collections::{BTreeMap, HashSet};

#[derive(Clone)]
pub struct SchemaManager {
    attribute_map: std::collections::HashMap<String, (LogicalAttr, String)>,
}

impl SchemaManager {
    pub fn new(schema: &PublicSchema) -> Self {
        let mut attribute_map = std::collections::HashMap::new();

        let mut register =
            |internal_name: &str, logical: LogicalAttr, canonical: &str, aliases: &[String]| {
                let lower_canonical = canonical.to_ascii_lowercase();
                attribute_map.insert(lower_canonical.clone(), (logical, canonical.to_string()));

                // Keyed on the canonical name too, so filters on it resolve like the aliases.
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

    fn determine_logical_attr(attr: &lldap_schema::AttributeSchema, name: &str) -> LogicalAttr {
        use lldap_domain_model::model::UserColumn;
        let lower = name.to_ascii_lowercase();

        // uuid is operational: hidden in "*", shown only in "+".
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

        // gecos (RFC 2307 posixAccount MAY) is backed by display_name.
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
        // The primary key, not an EAV attribute: filter and emit it as the group id.
        if schema.resolve_group_canonical_name(field.as_str()) == Some("groupid") {
            return GroupFieldType::GroupId;
        }
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

        // memberof/ismemberof resolve to Member semantics for group filters above.
        if field.as_str().eq_ignore_ascii_case("member") {
            return GroupFieldType::Member;
        }
        if field.as_str().eq_ignore_ascii_case("uniquemember") {
            return GroupFieldType::UniqueMember;
        }
        // memberUid: RFC 2307 posixGroup, SSSD's default rfc2307 member attribute.
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

        // displayName is emitted apart from cn.
        const DISPLAY_NAME_WIRE: &str = "displayName";

        for s in ldap_attributes.iter().filter(|&s| {
            let lower = s.to_ascii_lowercase();
            lower != "*" && lower != "+" && lower != "1.1" && !ignore_set.contains(lower.as_str())
        }) {
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

        if has_star || has_plus {
            include_custom_attributes = true;
            for s in &standard_keys {
                attributes_out.insert(AttributeName::from(s), s.clone());
            }
            // Wildcards also emit displayName alongside cn (AD compatibility).
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

        // Explicitly requested operational attributes must be returned (RFC 4512).
        let has_explicit_operational = attributes_out
            .keys()
            .any(|k| self.is_operational(k.as_str()));

        ExpandedAttributes {
            attribute_keys: attributes_out,
            include_custom_attributes,
            include_operational_attributes: has_plus || has_explicit_operational,
        }
    }

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
    use pretty_assertions::assert_eq;
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
    fn test_expand_attribute_wildcards_is_pinned() {
        const OPERATIONAL: [&str; 9] = [
            "createtimestamp",
            "modifytimestamp",
            "pwdchangedtime",
            "entryuuid",
            "hassubordinates",
            "entrydn",
            "memberof",
            "creatorsname",
            "modifiersname",
        ];
        const ALWAYS_OPERATIONAL: [&str; 11] = [
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
        ];
        // Membership wires and gecos are builder inserts on `*`, not shared expand.
        type Case<'a> = (
            &'a str,
            &'a [&'a str],
            Option<bool>,
            Option<bool>,
            Vec<&'a str>,
            Vec<&'a str>,
        );
        let cases: Vec<Case> = vec![
            (
                "*",
                &["*"],
                Some(true),
                Some(false),
                vec!["uid", "mail", "objectclass", "cn", "displayname"],
                [
                    OPERATIONAL.as_slice(),
                    &["member", "uniquemember", "memberuid", "gecos"],
                ]
                .concat(),
            ),
            (
                "nothing requested",
                &[],
                Some(true),
                Some(false),
                vec!["uid", "mail", "objectclass"],
                OPERATIONAL.to_vec(),
            ),
            (
                "+",
                &["+"],
                Some(true),
                Some(true),
                [&["uid"], ALWAYS_OPERATIONAL.as_slice()].concat(),
                vec!["logindisabled", "sudohost"],
            ),
            (
                "1.1",
                &["1.1"],
                Some(false),
                Some(false),
                vec![],
                vec!["uid", "objectclass"],
            ),
            (
                "displayName",
                &["displayName"],
                None,
                None,
                vec!["displayname"],
                vec!["cn"],
            ),
            ("cn", &["cn"], None, None, vec!["cn"], vec!["displayname"]),
            (
                "memberUid",
                &["memberUid"],
                None,
                None,
                vec!["memberuid"],
                vec![],
            ),
            ("uid", &["uid"], None, None, vec!["uid"], vec!["memberuid"]),
            ("gecos", &["gecos"], None, None, vec!["gecos"], vec![]),
            (
                "createTimestamp",
                &["createTimestamp"],
                Some(false),
                Some(true),
                vec!["createtimestamp"],
                vec![],
            ),
            (
                "entryUUID",
                &["entryUUID"],
                None,
                Some(true),
                vec!["entryuuid"],
                vec![],
            ),
            (
                "entryDN",
                &["entryDN"],
                None,
                Some(true),
                vec!["entrydn"],
                vec![],
            ),
            (
                "creatorsName",
                &["creatorsName"],
                None,
                Some(true),
                vec!["creatorsname"],
                vec![],
            ),
            (
                "loginDisabled: deliberate, an explicit virtual does not switch the operational bucket on",
                &["loginDisabled"],
                None,
                Some(false),
                vec!["logindisabled"],
                vec![],
            ),
            (
                "sudoHost: deliberate, same rule",
                &["sudoHost"],
                None,
                Some(false),
                vec!["sudohost"],
                vec![],
            ),
        ];
        for (label, attrs, custom, operational, present, absent) in cases {
            let exp = expand(attrs);
            if let Some(custom) = custom {
                assert_eq!(
                    exp.include_custom_attributes, custom,
                    "{label}: include_custom_attributes"
                );
            }
            if let Some(operational) = operational {
                assert_eq!(
                    exp.include_operational_attributes, operational,
                    "{label}: include_operational_attributes"
                );
            }
            let k = keys(&exp);
            for name in present {
                assert!(k.contains(name), "{label}: missing {name}");
            }
            for name in absent {
                assert!(!k.contains(name), "{label}: unexpected {name}");
            }
        }
        assert!(expand(&["1.1"]).attribute_keys.is_empty());
        // The wire case survives expansion.
        let wire = |attrs: &[&str]| -> Vec<String> {
            expand(attrs).attribute_keys.values().cloned().collect()
        };
        assert!(wire(&["displayName"]).contains(&"displayName".to_string()));
        let star = wire(&["*"]);
        assert!(star.contains(&"cn".to_string()) && star.contains(&"displayName".to_string()));
    }

    #[test]
    fn test_resolve_and_is_operational_normalized() {
        let sm = SchemaManager::default();
        let cases: &[(&str, bool, &str, Option<LogicalAttr>)] = &[
            (
                "objectclass",
                false,
                "objectClass",
                Some(LogicalAttr::ObjectClass),
            ),
            ("memberof", true, "memberOf", Some(LogicalAttr::MemberOf)),
            ("ismemberof", true, "memberOf", Some(LogicalAttr::MemberOf)),
            ("dn", false, "dn", Some(LogicalAttr::Dn)),
            ("distinguishedname", false, "dn", Some(LogicalAttr::Dn)),
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
            ("nope", false, "nope", None),
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
        // gecos resolves to the display_name column.
        assert_eq!(
            sm.map_user_field(&AttributeName::from("gecos"), PublicSchema::shared()),
            UserFieldType::PrimaryField(UserColumn::DisplayName)
        );
    }
}
