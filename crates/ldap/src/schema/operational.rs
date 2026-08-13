//! Single source of truth for operational / structural LDAP attributes.
//!
//! These are the LDAP-protocol "plumbing" attributes that are NOT part of the identity schema
//! (`PublicSchema`). Every operational-name consumer — the `SchemaManager` resolver map, the
//! wildcard-expansion gating, the published subschema `attributeType`s, and the result/OU/root
//! emitters — derives from `OPERATIONAL_ATTRS` here, so the sets can no longer silently drift.
//!
//! Gating rule (RFC 4512): `is_operational == always_operational`. "Present in the table" does NOT
//! mean "operational" — `objectClass`/`dn`/`loginDisabled`/`sudoHost` are here with
//! `always_operational: false`.

// LDAP syntax OIDs (RFC 4517 + UUID draft).
const SYN_DIR_STRING: &str = "1.3.6.1.4.1.1466.115.121.1.15";
const SYN_DN: &str = "1.3.6.1.4.1.1466.115.121.1.12";
const SYN_GEN_TIME: &str = "1.3.6.1.4.1.1466.115.121.1.24";
const SYN_BOOLEAN: &str = "1.3.6.1.4.1.1466.115.121.1.7";
const SYN_OID: &str = "1.3.6.1.4.1.1466.115.121.1.38";
const SYN_IA5: &str = "1.3.6.1.4.1.1466.115.121.1.26";
const SYN_UUID: &str = "1.3.6.1.1.16.1";

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum OpUsage {
    DirectoryOperation,
    DsaOperation,
}

/// The logical role used by the LDAP resolver (`SchemaManager`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum OpLogical {
    ObjectClass,
    Dn,
    EntryDn,
    MemberOf,
    Operational,
}

/// The bits needed to regenerate a subschema `attributeType` definition.
pub struct AttributeTypeDef {
    pub oid: &'static str,
    pub syntax: &'static str,
    pub equality: &'static str,
    pub ordering: Option<&'static str>,
    pub substr: Option<&'static str>,
    pub desc: &'static str,
    pub single_value: bool,
    pub no_user_modification: bool,
    pub usage: OpUsage,
}

pub struct OperationalAttr {
    /// Primary advertised NAME + emitted atype (e.g. `entryUUID`, `createTimestamp`).
    pub wire_name: &'static str,
    /// Additional published NAMEs (subschema NAME list after `wire_name`), deduped.
    pub aliases: &'static [&'static str],
    /// Resolver-only keys that are NOT published (e.g. `ismemberof`, `distinguishedname`).
    pub resolver_aliases: &'static [&'static str],
    pub logical: OpLogical,
    /// The single `*`/`+` gating predicate. `is_operational(name)` returns this.
    pub always_operational: bool,
    /// `Some` for the attributes that publish an `attributeType` blob (the 12 op_entries).
    /// `objectClass` (in `core_entries`), `dn`, and `entryDN` are `None`.
    pub published: Option<AttributeTypeDef>,
}

impl OperationalAttr {
    /// Lowercase primary resolver key.
    pub fn key(&self) -> String {
        self.wire_name.to_ascii_lowercase()
    }

    /// The RFC-4512 `attributeType` definition, for rows that publish one.
    pub fn to_attribute_type_definition(&self) -> Option<Vec<u8>> {
        let d = self.published.as_ref()?;
        let name = if self.aliases.is_empty() {
            format!("'{}'", self.wire_name)
        } else {
            let names: Vec<String> = std::iter::once(self.wire_name)
                .chain(self.aliases.iter().copied())
                .map(|n| format!("'{n}'"))
                .collect();
            format!("( {} )", names.join(" "))
        };
        let ordering = d
            .ordering
            .map(|o| format!(" ORDERING {o}"))
            .unwrap_or_default();
        let substr = d.substr.map(|s| format!(" SUBSTR {s}")).unwrap_or_default();
        let single = if d.single_value { " SINGLE-VALUE" } else { "" };
        let nomod = if d.no_user_modification {
            " NO-USER-MODIFICATION"
        } else {
            ""
        };
        let usage = match d.usage {
            OpUsage::DirectoryOperation => "directoryOperation",
            OpUsage::DsaOperation => "dSAOperation",
        };
        Some(
            format!(
                "( {} NAME {} DESC '{}' EQUALITY {}{}{} SYNTAX {}{}{} USAGE {} )",
                d.oid, name, d.desc, d.equality, ordering, substr, d.syntax, single, nomod, usage
            )
            .into_bytes(),
        )
    }
}

/// Root-DSE / subschema published names that are not operational attributes.
/// Suppressed from `+` expansion (they are entry-level published data).
pub const SUBSCHEMA_PUBLISHED_NAMES: &[&str] = &[
    "attributetypes",
    "objectclasses",
    "matchingrules",
    "ldapsyntaxes",
    "matchingruleuse",
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
];

#[rustfmt::skip]
pub static OPERATIONAL_ATTRS: &[OperationalAttr] = &[
    // Resolver-only structural roles (no published attributeType here).
    OperationalAttr { wire_name: "objectClass", aliases: &[], resolver_aliases: &[], logical: OpLogical::ObjectClass, always_operational: false, published: None },
    OperationalAttr { wire_name: "dn", aliases: &[], resolver_aliases: &["distinguishedname"], logical: OpLogical::Dn, always_operational: false, published: None },
    OperationalAttr { wire_name: "entryDN", aliases: &[], resolver_aliases: &[], logical: OpLogical::EntryDn, always_operational: true, published: None },

    OperationalAttr {
        wire_name: "memberOf", aliases: &[], resolver_aliases: &["ismemberof"],
        logical: OpLogical::MemberOf, always_operational: true,
        published: Some(AttributeTypeDef { oid: "1.2.840.113556.1.2.102", syntax: SYN_DN, equality: "distinguishedNameMatch", ordering: None, substr: None, desc: "Group membership", single_value: false, no_user_modification: true, usage: OpUsage::DsaOperation }),
    },
    OperationalAttr {
        wire_name: "hasSubordinates", aliases: &[], resolver_aliases: &[],
        logical: OpLogical::Operational, always_operational: true,
        published: Some(AttributeTypeDef { oid: "1.3.6.1.4.1.1466.101.120.6", syntax: SYN_BOOLEAN, equality: "booleanMatch", ordering: None, substr: None, desc: "X.500 Has Subordinates", single_value: true, no_user_modification: true, usage: OpUsage::DirectoryOperation }),
    },
    OperationalAttr {
        wire_name: "structuralObjectClass", aliases: &[], resolver_aliases: &[],
        logical: OpLogical::Operational, always_operational: true,
        published: Some(AttributeTypeDef { oid: "2.5.21.1", syntax: SYN_OID, equality: "objectIdentifierMatch", ordering: None, substr: None, desc: "X.500 Structural Object Class", single_value: true, no_user_modification: true, usage: OpUsage::DirectoryOperation }),
    },
    OperationalAttr {
        wire_name: "subschemaSubentry", aliases: &[], resolver_aliases: &[],
        logical: OpLogical::Operational, always_operational: true,
        published: Some(AttributeTypeDef { oid: "2.5.21.2", syntax: SYN_DN, equality: "distinguishedNameMatch", ordering: None, substr: None, desc: "X.500 Subschema Subentry", single_value: true, no_user_modification: true, usage: OpUsage::DirectoryOperation }),
    },
    OperationalAttr {
        wire_name: "createTimestamp", aliases: &["creationdate", "creation_date", "creationTimestamp"], resolver_aliases: &[],
        logical: OpLogical::Operational, always_operational: true,
        published: Some(AttributeTypeDef { oid: "2.5.18.1", syntax: SYN_GEN_TIME, equality: "generalizedTimeMatch", ordering: Some("generalizedTimeOrderingMatch"), substr: None, desc: "RFC4512", single_value: true, no_user_modification: true, usage: OpUsage::DirectoryOperation }),
    },
    OperationalAttr {
        wire_name: "modifyTimestamp", aliases: &["modifieddate", "modified_date", "modifydate"], resolver_aliases: &[],
        logical: OpLogical::Operational, always_operational: true,
        published: Some(AttributeTypeDef { oid: "2.5.18.2", syntax: SYN_GEN_TIME, equality: "generalizedTimeMatch", ordering: Some("generalizedTimeOrderingMatch"), substr: None, desc: "RFC4512", single_value: true, no_user_modification: true, usage: OpUsage::DirectoryOperation }),
    },
    OperationalAttr {
        wire_name: "pwdChangedTime", aliases: &["passwordmodifieddate", "password_modified_date"], resolver_aliases: &[],
        logical: OpLogical::Operational, always_operational: true,
        published: Some(AttributeTypeDef { oid: "1.3.6.1.4.1.42.2.27.8.1.16", syntax: SYN_GEN_TIME, equality: "generalizedTimeMatch", ordering: None, substr: None, desc: "Password last changed time", single_value: true, no_user_modification: true, usage: OpUsage::DsaOperation }),
    },
    OperationalAttr {
        wire_name: "creatorsName", aliases: &[], resolver_aliases: &[],
        logical: OpLogical::Operational, always_operational: true,
        published: Some(AttributeTypeDef { oid: "2.5.18.3", syntax: SYN_DN, equality: "distinguishedNameMatch", ordering: None, substr: None, desc: "RFC4512", single_value: true, no_user_modification: true, usage: OpUsage::DirectoryOperation }),
    },
    OperationalAttr {
        wire_name: "modifiersName", aliases: &[], resolver_aliases: &[],
        logical: OpLogical::Operational, always_operational: true,
        published: Some(AttributeTypeDef { oid: "2.5.18.4", syntax: SYN_DN, equality: "distinguishedNameMatch", ordering: None, substr: None, desc: "RFC4512", single_value: true, no_user_modification: true, usage: OpUsage::DirectoryOperation }),
    },
    OperationalAttr {
        wire_name: "entryUUID", aliases: &["uuid"], resolver_aliases: &[],
        logical: OpLogical::Operational, always_operational: true,
        published: Some(AttributeTypeDef { oid: "1.3.6.1.1.16.4", syntax: SYN_UUID, equality: "UUIDMatch", ordering: Some("UUIDOrderingMatch"), substr: None, desc: "UUID", single_value: true, no_user_modification: true, usage: OpUsage::DirectoryOperation }),
    },
    // Virtuals (group-membership-derived). Operational NAME but explicit-only: always_operational = false.
    OperationalAttr {
        wire_name: "loginDisabled", aliases: &["logindisabled"], resolver_aliases: &[],
        logical: OpLogical::Operational, always_operational: false,
        published: Some(AttributeTypeDef { oid: "2.16.840.1.113719.1.1.4.1.7", syntax: SYN_DIR_STRING, equality: "caseIgnoreMatch", ordering: None, substr: None, desc: "NDS/eDirectory loginDisabled (SSSD nds policy / account disable; synthesized by lldap_disabled group membership)", single_value: true, no_user_modification: true, usage: OpUsage::DirectoryOperation }),
    },
    OperationalAttr {
        wire_name: "sudoHost", aliases: &["sudohost"], resolver_aliases: &[],
        logical: OpLogical::Operational, always_operational: false,
        published: Some(AttributeTypeDef { oid: "1.3.6.1.4.1.15953.9.1.2", syntax: SYN_IA5, equality: "caseExactIA5Match", ordering: None, substr: Some("caseExactIA5SubstringsMatch"), desc: "Host(s) who may run sudo (from sudoers LDAP schema; synthesized by lldap_sudohost group membership)", single_value: false, no_user_modification: true, usage: OpUsage::DirectoryOperation }),
    },
];

pub fn all() -> &'static [OperationalAttr] {
    OPERATIONAL_ATTRS
}

/// Resolve a name (case-insensitive) against wire names, published aliases, and resolver-only keys.
pub fn resolve(name: &str) -> Option<&'static OperationalAttr> {
    let lower = name.to_ascii_lowercase();
    OPERATIONAL_ATTRS.iter().find(|o| {
        o.wire_name.eq_ignore_ascii_case(&lower)
            || o.aliases.iter().any(|a| a.eq_ignore_ascii_case(&lower))
            || o.resolver_aliases
                .iter()
                .any(|a| a.eq_ignore_ascii_case(&lower))
    })
}

/// The single operational-gating predicate: `== always_operational`. NOT "present in the table".
pub fn is_operational(name: &str) -> bool {
    resolve(name).is_some_and(|o| o.always_operational)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn published_blobs_reproduce_current_subschema() {
        let expected: &[(&str, &str)] = &[
            (
                "entryUUID",
                "( 1.3.6.1.1.16.4 NAME ( 'entryUUID' 'uuid' ) DESC 'UUID' EQUALITY UUIDMatch ORDERING UUIDOrderingMatch SYNTAX 1.3.6.1.1.16.1 SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )",
            ),
            (
                "createTimestamp",
                "( 2.5.18.1 NAME ( 'createTimestamp' 'creationdate' 'creation_date' 'creationTimestamp' ) DESC 'RFC4512' EQUALITY generalizedTimeMatch ORDERING generalizedTimeOrderingMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.24 SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )",
            ),
            (
                "modifyTimestamp",
                "( 2.5.18.2 NAME ( 'modifyTimestamp' 'modifieddate' 'modified_date' 'modifydate' ) DESC 'RFC4512' EQUALITY generalizedTimeMatch ORDERING generalizedTimeOrderingMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.24 SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )",
            ),
            (
                "creatorsName",
                "( 2.5.18.3 NAME 'creatorsName' DESC 'RFC4512' EQUALITY distinguishedNameMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )",
            ),
            (
                "modifiersName",
                "( 2.5.18.4 NAME 'modifiersName' DESC 'RFC4512' EQUALITY distinguishedNameMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )",
            ),
            (
                "memberOf",
                "( 1.2.840.113556.1.2.102 NAME 'memberOf' DESC 'Group membership' EQUALITY distinguishedNameMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 NO-USER-MODIFICATION USAGE dSAOperation )",
            ),
            (
                "hasSubordinates",
                "( 1.3.6.1.4.1.1466.101.120.6 NAME 'hasSubordinates' DESC 'X.500 Has Subordinates' EQUALITY booleanMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.7 SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )",
            ),
            (
                "structuralObjectClass",
                "( 2.5.21.1 NAME 'structuralObjectClass' DESC 'X.500 Structural Object Class' EQUALITY objectIdentifierMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )",
            ),
            (
                "subschemaSubentry",
                "( 2.5.21.2 NAME 'subschemaSubentry' DESC 'X.500 Subschema Subentry' EQUALITY distinguishedNameMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )",
            ),
            (
                "pwdChangedTime",
                "( 1.3.6.1.4.1.42.2.27.8.1.16 NAME ( 'pwdChangedTime' 'passwordmodifieddate' 'password_modified_date' ) DESC 'Password last changed time' EQUALITY generalizedTimeMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.24 SINGLE-VALUE NO-USER-MODIFICATION USAGE dSAOperation )",
            ),
            (
                "sudoHost",
                "( 1.3.6.1.4.1.15953.9.1.2 NAME ( 'sudoHost' 'sudohost' ) DESC 'Host(s) who may run sudo (from sudoers LDAP schema; synthesized by lldap_sudohost group membership)' EQUALITY caseExactIA5Match SUBSTR caseExactIA5SubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 NO-USER-MODIFICATION USAGE directoryOperation )",
            ),
            (
                "loginDisabled",
                "( 2.16.840.1.113719.1.1.4.1.7 NAME ( 'loginDisabled' 'logindisabled' ) DESC 'NDS/eDirectory loginDisabled (SSSD nds policy / account disable; synthesized by lldap_disabled group membership)' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )",
            ),
        ];
        for (wire, blob) in expected {
            let op = resolve(wire).unwrap();
            let got = String::from_utf8(op.to_attribute_type_definition().unwrap()).unwrap();
            assert_eq!(&got, blob, "blob mismatch for {wire}");
        }
        // The three resolver-only roles publish nothing.
        for wire in ["objectClass", "dn", "entryDN"] {
            assert!(
                resolve(wire)
                    .unwrap()
                    .to_attribute_type_definition()
                    .is_none(),
                "{wire}"
            );
        }
        // Exactly 12 published attributeTypes.
        assert_eq!(
            OPERATIONAL_ATTRS
                .iter()
                .filter(|o| o.published.is_some())
                .count(),
            12
        );
    }

    #[test]
    fn always_operational_matches_current_set() {
        let mut got: Vec<String> = OPERATIONAL_ATTRS
            .iter()
            .filter(|o| o.always_operational)
            .map(|o| o.key())
            .collect();
        got.sort();
        let mut want = vec![
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
        ];
        want.sort();
        assert_eq!(got, want);
    }

    #[test]
    fn resolve_and_is_operational_semantics() {
        // Aliases + resolver-only keys fold to the entry.
        assert_eq!(resolve("ismemberof").unwrap().wire_name, "memberOf");
        assert_eq!(resolve("uuid").unwrap().wire_name, "entryUUID");
        assert_eq!(
            resolve("creationdate").unwrap().wire_name,
            "createTimestamp"
        );
        assert_eq!(resolve("distinguishedname").unwrap().wire_name, "dn");
        assert!(resolve("nope").is_none());

        // is_operational == always_operational, NOT "in table".
        assert!(is_operational("memberOf"));
        assert!(is_operational("createTimestamp"));
        assert!(is_operational("entryDN"));
        assert!(!is_operational("loginDisabled"));
        assert!(!is_operational("sudoHost"));
        assert!(!is_operational("objectClass"));
        assert!(!is_operational("dn"));
    }
}
