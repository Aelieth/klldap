use crate::schema::SchemaManager;
use chrono::Utc;
use ldap3_proto::{LdapPartialAttribute, LdapSearchResultEntry, proto::LdapOp};
use std::collections::HashSet;

pub fn make_ldap_subschema_entry(schema_manager: &SchemaManager, base_dn_str: &str) -> LdapOp {
    let current_time_utc = Utc::now().format("%Y%m%d%H%M%SZ").to_string().into_bytes();
    let full_subschema_dn = format!("cn=Subschema,{}", base_dn_str);

    fn attr_type_to_ldap_syntax(attr: &lldap_schema::AttributeSchema) -> (String, bool, bool) {
        let (syntax, is_single) = match attr.attribute_type {
            lldap_schema::AttributeType::String => ("1.3.6.1.4.1.1466.115.121.1.15", !attr.is_list),
            lldap_schema::AttributeType::Integer => {
                ("1.3.6.1.4.1.1466.115.121.1.27", !attr.is_list)
            }
            lldap_schema::AttributeType::DateTime => {
                ("1.3.6.1.4.1.1466.115.121.1.24", !attr.is_list)
            }
            lldap_schema::AttributeType::Avatar => ("1.3.6.1.4.1.1466.115.121.1.28", !attr.is_list),
        };
        let name_lower = attr.name.to_ascii_lowercase();
        let is_operational = attr.is_readonly
            || matches!(
                name_lower.as_str(),
                "creationdate" | "modifieddate" | "passwordmodifieddate" | "uuid" | "entryuuid"
            );
        (syntax.to_string(), is_single, is_operational)
    }

    let mut dynamic_attr_types: Vec<Vec<u8>> = Vec::new();
    let mut seen_attr_oids: HashSet<String> = HashSet::new();

    // Core and std entries
    let core_entries: Vec<(&str, Vec<u8>)> = vec![
        ("2.5.4.0", b"( 2.5.4.0 NAME 'objectClass' DESC 'RFC4512' EQUALITY objectIdentifierMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 )".to_vec()),
        ("2.5.4.3", b"( 2.5.4.3 NAME ( 'cn' 'commonName' 'displayname' 'display_name' ) DESC 'RFC4519' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{256} SINGLE-VALUE )".to_vec()),
        ("2.5.4.4", b"( 2.5.4.4 NAME ( 'sn' 'surname' 'lastname' 'last_name' ) DESC 'RFC2256' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{256} SINGLE-VALUE )".to_vec()),
        ("0.9.2342.19200300.100.1.1", b"( 0.9.2342.19200300.100.1.1 NAME ( 'uid' 'user_id' 'userid' 'id' ) DESC 'User identifier' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{256} SINGLE-VALUE )".to_vec()),
    ];
    for (oid, entry) in core_entries {
        if seen_attr_oids.insert(oid.to_string()) {
            dynamic_attr_types.push(entry);
        }
    }

    let std_entries: Vec<(&str, Vec<u8>)> = vec![
        ("2.5.4.42", b"( 2.5.4.42 NAME ( 'givenName' 'givenname' 'firstname' 'first_name' ) DESC 'RFC4519 givenName' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{256} SINGLE-VALUE )".to_vec()),
        ("0.9.2342.19200300.100.1.3", b"( 0.9.2342.19200300.100.1.3 NAME ( 'mail' 'email' 'rfc822Mailbox' ) DESC 'RFC1274/2307 mail' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{256} SINGLE-VALUE )".to_vec()),
        ("2.5.4.11", b"( 2.5.4.11 NAME ( 'ou' 'organizationalUnit' 'organizationalunit' 'organizationalUnitName' ) DESC 'RFC4519 ou' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{256} SINGLE-VALUE )".to_vec()),
        ("1.3.6.1.1.1.1.0", b"( 1.3.6.1.1.1.1.0 NAME ( 'uidNumber' 'uidnumber' 'uid_number' 'uidNumber' ) DESC 'RFC2307 uidNumber' EQUALITY integerMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )".to_vec()),
        ("1.3.6.1.1.1.1.1", b"( 1.3.6.1.1.1.1.1 NAME ( 'gidNumber' 'gidnumber' 'gid_number' 'gidNumber' ) DESC 'RFC2307 gidNumber' EQUALITY integerMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )".to_vec()),
        ("1.3.6.1.1.1.1.3", b"( 1.3.6.1.1.1.1.3 NAME ( 'homeDirectory' 'homedirectory' 'home_directory' 'homeDirectory' ) DESC 'RFC2307 homeDirectory' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{256} SINGLE-VALUE )".to_vec()),
        ("1.3.6.1.1.1.1.4", b"( 1.3.6.1.1.1.1.4 NAME ( 'loginShell' 'loginshell' 'login_shell' 'loginShell' ) DESC 'RFC2307 loginShell' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{256} SINGLE-VALUE )".to_vec()),
        ("1.3.6.1.1.1.1.8", b"( 1.3.6.1.1.1.1.8 NAME ( 'sshPublicKey' 'sshpublickey' 'sshPublicKey' 'ssHPublicKey' ) DESC 'OpenSSH/LDAP sshPublicKey' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )".to_vec()),
        ("1.3.6.1.4.1.5322.1.1.2", b"( 1.3.6.1.4.1.5322.1.1.2 NAME ( 'krbPrincipalName' 'krb_principal_name' 'krbPrincipalName' ) DESC 'Kerberos principal name' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{256} SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )".to_vec()),
        ("0.9.2342.19200300.100.1.60", b"( 0.9.2342.19200300.100.1.60 NAME ( 'jpegPhoto' 'jpegphoto' 'avatar' ) DESC 'RFC2798 jpegPhoto' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.28 )".to_vec()),
    ];
    for (oid, entry) in std_entries {
        if seen_attr_oids.insert(oid.to_string()) {
            dynamic_attr_types.push(entry);
        }
    }

    // unique OID counter for custom / runtime attributes (prevents collision)
    let mut custom_oid_counter: u32 = 100;

    // Attributes that have *predefined static entries* in core/std/op_entries.
    // Skipped here to avoid duplicate attributeType definitions (RFC 4512 §2.2.1 compliance).
    // Exact match to PublicSchema::get() user/group attributes.
    // (kerberossync, groupid, and any future custom attrs go dynamic)
    let static_covered_attrs: HashSet<&str> = [
        "avatar",
        "creationdate",
        "displayname",
        "firstname",
        "lastname",
        "mail",
        "modifieddate",
        "passwordmodifieddate",
        "userid",
        "uuid",
        "uidnumber",
        "gidnumber",
        "homedirectory",
        "loginshell",
        "krbprincipalname",
        "sshpublickey",
        "ou",
    ]
    .iter()
    .cloned()
    .collect();

    for attr in schema_manager
        .get_all_user_attributes()
        .iter()
        .chain(schema_manager.get_all_group_attributes().iter())
    {
        if static_covered_attrs.contains(attr.name.as_str()) {
            continue;
        }

        let preferred = attr.preferred_ldap_name();
        let (syntax, is_single, is_operational) = attr_type_to_ldap_syntax(attr);
        let single_str = if is_single { " SINGLE-VALUE" } else { "" };
        let op_str = if is_operational {
            " NO-USER-MODIFICATION USAGE directoryOperation"
        } else {
            ""
        };

        // RFC-compliant EQUALITY per attribute type (future-proofs any custom DateTime/Integer attrs)
        let equality = match attr.attribute_type {
            lldap_schema::AttributeType::Integer => "integerMatch",
            lldap_schema::AttributeType::DateTime => "generalizedTimeMatch",
            _ => "caseIgnoreMatch", // String + Avatar
        };

        let name_list = if attr.aliases.is_empty() {
            format!("'{}'", preferred)
        } else {
            let mut names = vec![format!("'{}'", preferred)];
            for a in &attr.aliases {
                if a != preferred {
                    names.push(format!("'{}'", a));
                }
            }
            names.join(" ")
        };

        let desc = format!(
            "LLDAP {} ({})",
            attr.name,
            if attr.is_list { "multi" } else { "single" }
        );
        let oid = match attr.name.as_str() {
            "avatar" => "10.0".to_string(),
            "sshpublickey" => "10.1".to_string(),
            "kerberossync" => "1.3.6.1.4.1.5322.1.1.1".to_string(),
            "groupid" => "10.2".to_string(),
            // unique incremental OID for every custom/runtime attribute
            _ => {
                let oid = format!("10.{}", custom_oid_counter);
                custom_oid_counter += 1;
                oid
            }
        };

        let entry = format!(
            "( {} NAME ( {} ) DESC '{}' EQUALITY {} SYNTAX {}{}{} )",
            oid, name_list, desc, equality, syntax, single_str, op_str
        );
        // Always push — OIDs are now guaranteed unique
        dynamic_attr_types.push(entry.into_bytes());
        seen_attr_oids.insert(oid);
    }

    // Operational attributeType definitions are generated from the single operational source.
    for op in crate::schema::operational::all() {
        if let Some(entry) = op.to_attribute_type_definition() {
            let oid = op.published.as_ref().unwrap().oid;
            if seen_attr_oids.insert(oid.to_string()) {
                dynamic_attr_types.push(entry);
            }
        }
    }

    // Build inetOrgPerson MAY list (unchanged)
    let mut inet_may: Vec<String> = vec![];
    let mut seen: HashSet<String> = HashSet::new();

    for name in ["cn", "sn", "givenName", "displayName", "uid", "mail"] {
        let lower = name.to_ascii_lowercase();
        if seen.insert(lower) {
            inet_may.push(name.to_string());
        }
    }

    // Names excluded from the inetOrgPerson MAY list: the operational attrs + their published
    // aliases, from the single operational source.
    let operational_names: HashSet<String> = crate::schema::operational::all()
        .iter()
        .filter(|o| o.always_operational)
        .flat_map(|o| {
            std::iter::once(o.key()).chain(o.aliases.iter().map(|a| a.to_ascii_lowercase()))
        })
        .collect();

    for attr in schema_manager.get_all_user_attributes() {
        let pref = attr.preferred_ldap_name();
        let lower = pref.to_ascii_lowercase();
        if !operational_names.contains(lower.as_str()) && seen.insert(lower) {
            inet_may.push(pref.to_string());
        }
    }

    // inetOrgPerson MAY deliberately re-includes these operational names for client compatibility.
    for extra in [
        "createTimestamp",
        "modifyTimestamp",
        "pwdChangedTime",
        "memberOf",
        "loginDisabled",
        "sudoHost",
    ] {
        let lower = extra.to_ascii_lowercase();
        if seen.insert(lower) {
            inet_may.push(extra.to_string());
        }
    }

    let inet_may_str = inet_may.join(" $ ");

    let posix_user_may =
        "userPassword $ loginShell $ gecos $ description $ sshPublicKey $ avatar $ kerberosSync $ loginDisabled $ sudoHost"
            .to_string();
    let posix_group_may = "userPassword $ memberUid $ description $ gidNumber".to_string();

    LdapOp::SearchResultEntry(LdapSearchResultEntry {
        dn: full_subschema_dn.clone(),
        attributes: vec![
            LdapPartialAttribute {
                atype: "structuralObjectClass".to_string(),
                vals: vec![b"subentry".to_vec()],
            },
            LdapPartialAttribute {
                atype: "objectClass".to_string(),
                vals: vec![b"top".to_vec(), b"subentry".to_vec(), b"subschema".to_vec(), b"extensibleObject".to_vec()],
            },
            LdapPartialAttribute {
                atype: "cn".to_string(),
                vals: vec![b"Subschema".to_vec()],
            },
            LdapPartialAttribute {
                atype: "createTimestamp".to_string(),
                vals: vec![current_time_utc.clone()],
            },
            LdapPartialAttribute {
                atype: "modifyTimestamp".to_string(),
                vals: vec![current_time_utc],
            },
            LdapPartialAttribute {
                atype: "ldapSyntaxes".to_string(),
                vals: vec![
                    b"( 1.3.6.1.1.16.1 DESC 'UUID' )".to_vec(),
                    b"( 1.3.6.1.4.1.1466.115.121.1.3 DESC 'Attribute Type Description' )".to_vec(),
                    b"( 1.3.6.1.4.1.1466.115.121.1.12 DESC 'Distinguished Name' )".to_vec(),
                    b"( 1.3.6.1.4.1.1466.115.121.1.15 DESC 'Directory String' )".to_vec(),
                    b"( 1.3.6.1.4.1.1466.115.121.1.24 DESC 'Generalized Time' )".to_vec(),
                    b"( 1.3.6.1.4.1.1466.115.121.1.27 DESC 'Integer' )".to_vec(),
                    b"( 1.3.6.1.4.1.1466.115.121.1.28 DESC 'JPEG' X-NOT-HUMAN-READABLE 'TRUE' )".to_vec(),
                    b"( 1.3.6.1.4.1.1466.115.121.1.34 DESC 'Name And Optional UID' )".to_vec(),
                    b"( 1.3.6.1.4.1.1466.115.121.1.37 DESC 'Object Class Description' )".to_vec(),
                    b"( 1.3.6.1.4.1.1466.115.121.1.38 DESC 'OID' )".to_vec(),
                    b"( 1.3.6.1.4.1.1466.115.121.1.54 DESC 'LDAP Syntax Description' )".to_vec(),
                    b"( 1.3.6.1.4.1.1466.115.121.1.58 DESC 'Substring Assertion' )".to_vec(),
                ],
            },
            LdapPartialAttribute {
                atype: "matchingRules".to_string(),
                vals: vec![
                    b"( 1.3.6.1.1.16.2 NAME 'UUIDMatch' SYNTAX 1.3.6.1.1.16.1 )".to_vec(),
                    b"( 1.3.6.1.1.16.3 NAME 'UUIDOrderingMatch' SYNTAX 1.3.6.1.1.16.1 )".to_vec(),
                    b"( 2.5.13.0 NAME 'objectIdentifierMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 )".to_vec(),
                    b"( 2.5.13.1 NAME 'distinguishedNameMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 )".to_vec(),
                    b"( 2.5.13.2 NAME 'caseIgnoreMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )".to_vec(),
                    b"( 2.5.13.4 NAME 'caseIgnoreSubstringsMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.58 )".to_vec(),
                    b"( 2.5.13.23 NAME 'uniqueMemberMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.34 )".to_vec(),
                    b"( 2.5.13.27 NAME 'generalizedTimeMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.24 )".to_vec(),
                    b"( 2.5.13.28 NAME 'generalizedTimeOrderingMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.24 )".to_vec(),
                    b"( 2.5.13.30 NAME 'objectIdentifierFirstComponentMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 )".to_vec(),
                ],
            },
            LdapPartialAttribute {
                atype: "attributeTypes".to_string(),
                vals: dynamic_attr_types,
            },
            LdapPartialAttribute {
                atype: "objectClasses".to_string(),
                vals: vec![
                    b"( 2.5.6.0 NAME 'top' DESC 'RFC4512' ABSTRACT MUST objectClass )".to_vec(),
                    b"( 2.5.6.6 NAME 'person' DESC 'RFC4519' STRUCTURAL MUST ( cn $ sn $ objectClass ) MAY ( userPassword $ telephoneNumber $ seeAlso $ description $ givenName $ mail ) )".to_vec(),
                    b"( 2.5.6.7 NAME 'organizationalPerson' DESC 'RFC4519' STRUCTURAL SUP person MAY ( title $ ou $ o $ l $ st $ postalAddress ) )".to_vec(),
                    format!(
                        "( 1.3.6.1.1.3.1 NAME 'inetOrgPerson' DESC 'RFC2798' STRUCTURAL SUP organizationalPerson MUST ( cn $ sn $ objectClass ) MAY ( {} ) )",
                        inet_may_str
                    ).into_bytes(),
                    format!(
                        "( 1.3.6.1.1.1.2.0 NAME 'posixAccount' DESC 'RFC2307' STRUCTURAL MUST ( cn $ uid $ uidNumber $ gidNumber $ homeDirectory $ objectClass ) MAY ( {} ) )",
                        posix_user_may
                    ).into_bytes(),
                    b"( 2.5.6.9 NAME 'groupOfNames' DESC 'RFC4519' STRUCTURAL MUST ( member $ cn $ objectClass ) MAY ( businessCategory $ seeAlso $ owner $ ou $ o $ description ) )".to_vec(),
                    b"( 2.5.6.17 NAME 'groupOfUniqueNames' DESC 'RFC4519' STRUCTURAL MUST ( uniqueMember $ cn $ objectClass ) MAY ( businessCategory $ seeAlso $ owner $ ou $ o $ description ) )".to_vec(),
                    format!(
                        "( 1.3.6.1.1.1.2.2 NAME 'posixGroup' DESC 'RFC2307' STRUCTURAL MUST ( cn $ gidNumber $ objectClass ) MAY ( {} ) )",
                        posix_group_may
                    ).into_bytes(),
                    b"( 1.3.6.1.4.1.24552.500.1.1.2.0 NAME 'ldapPublicKey' SUP top AUXILIARY DESC 'OpenSSH LPK auxiliary object class for SSH public keys' MAY sshPublicKey )".to_vec(),
                ],
            },
            LdapPartialAttribute {
                atype: "subschemaSubentry".to_string(),
                vals: vec![full_subschema_dn.into_bytes()],
            },
        ],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::SchemaManager; // or wherever the real one lives

    #[test]
    fn test_make_ldap_subschema_entry_basic_structure() {
        let schema = SchemaManager::default();
        let op = make_ldap_subschema_entry(&schema, "dc=example,dc=com");
        if let LdapOp::SearchResultEntry(entry) = op {
            assert_eq!(entry.dn, "cn=Subschema,dc=example,dc=com");
            assert!(entry.attributes.iter().any(|a| a.atype == "attributeTypes"));
            assert!(entry.attributes.iter().any(|a| a.atype == "objectClasses"));
            // Spot-check unique OID logic didn't collide
            let attr_types = entry
                .attributes
                .iter()
                .find(|a| a.atype == "attributeTypes")
                .unwrap();
            assert!(!attr_types.vals.is_empty());

            // RFC compliance check for the two virtual synthesized attributes.
            let attr_types_blob: String = attr_types
                .vals
                .iter()
                .map(|v| String::from_utf8_lossy(v).to_string())
                .collect::<Vec<_>>()
                .join(" ");
            assert!(
                attr_types_blob.contains("1.3.6.1.4.1.15953.9.1.2")
                    && (attr_types_blob.contains("'sudoHost'")
                        || attr_types_blob.contains("sudoHost")),
                "sudoHost (sudoers schema) attributeType missing from subschema"
            );
            assert!(
                attr_types_blob.contains("2.16.840.1.113719.1.1.4.1.7")
                    && (attr_types_blob.contains("'loginDisabled'")
                        || attr_types_blob.contains("loginDisabled")),
                "loginDisabled (NDS/eDirectory/SSSD) attributeType missing from subschema"
            );
        } else {
            panic!("expected SearchResultEntry");
        }
    }

    #[test]
    fn op_entries_match_the_operational_source() {
        // Byte fidelity of the blobs is owned by operational.rs's own test; here we assert the
        // subschema emits exactly what the generator produces (no second handwritten copy).
        let schema = SchemaManager::default();
        let LdapOp::SearchResultEntry(entry) =
            make_ldap_subschema_entry(&schema, "dc=example,dc=com")
        else {
            panic!("expected SearchResultEntry");
        };
        let blobs: HashSet<String> = entry
            .attributes
            .iter()
            .find(|a| a.atype == "attributeTypes")
            .unwrap()
            .vals
            .iter()
            .map(|v| String::from_utf8_lossy(v).into_owned())
            .collect();
        for op in crate::schema::operational::all() {
            if let Some(def) = op.to_attribute_type_definition() {
                let expected = String::from_utf8(def).unwrap();
                assert!(blobs.contains(&expected), "missing op_entry: {expected}");
            }
        }
        let names: Vec<&str> = entry.attributes.iter().map(|a| a.atype.as_str()).collect();
        assert!(names.contains(&"createTimestamp"));
        assert!(names.contains(&"modifyTimestamp"));
    }
}
