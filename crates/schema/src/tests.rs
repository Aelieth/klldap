use crate::{
    public_schema::PublicSchema,
    schema::{
        AttributeList, AttributeSchema,
        AttributeType::{self as AT, Avatar, DateTime, Integer, String},
        PosixSettings,
    },
};
use pretty_assertions::assert_eq;

fn attr(name: &str, aliases: &[&str], attribute_type: AT) -> AttributeSchema {
    AttributeSchema {
        name: name.to_owned(),
        aliases: aliases.iter().map(|a| a.to_string()).collect(),
        attribute_type,
        is_list: false,
        is_visible: true,
        is_editable: false,
        is_hardcoded: true,
        is_readonly: false,
    }
}

fn editable(name: &str, aliases: &[&str], attribute_type: AT) -> AttributeSchema {
    AttributeSchema {
        is_editable: true,
        ..attr(name, aliases, attribute_type)
    }
}

fn readonly(name: &str, aliases: &[&str], attribute_type: AT) -> AttributeSchema {
    AttributeSchema {
        is_readonly: true,
        ..attr(name, aliases, attribute_type)
    }
}

#[test]
fn test_public_schema_is_pinned() {
    let s = PublicSchema::shared();
    assert_eq!(
        *s.user_attributes(),
        AttributeList {
            attributes: vec![
                editable("avatar", &["jpegphoto", "jpegPhoto", "jpeg_photo"], Avatar),
                readonly(
                    "creationdate",
                    &["creation_date", "createTimestamp"],
                    DateTime
                ),
                editable("displayname", &["display_name", "cn", "commonname"], String),
                editable(
                    "firstname",
                    &["first_name", "givenName", "given_name"],
                    String
                ),
                editable("lastname", &["last_name", "sn", "surname"], String),
                editable("mail", &["email"], String),
                readonly(
                    "modifieddate",
                    &["modified_date", "modifyTimestamp"],
                    DateTime
                ),
                readonly(
                    "passwordmodifieddate",
                    &["password_modified_date", "pwdChangedTime"],
                    DateTime,
                ),
                readonly("userid", &["user_id", "uid", "id"], String),
                readonly("uuid", &["entryUUID", "entryuuid"], String),
                attr("uidnumber", &["uid_number", "uidNumber"], Integer),
                attr("gidnumber", &["gid_number", "gidNumber"], Integer),
                attr(
                    "homedirectory",
                    &["home_directory", "homeDirectory"],
                    String
                ),
                attr("loginshell", &["login_shell", "loginShell"], String),
                attr("kerberossync", &["kerberos_sync", "kerberosSync"], Integer),
                AttributeSchema {
                    is_visible: false,
                    is_readonly: true,
                    ..attr(
                        "krbprincipalname",
                        &["krb_principal_name", "krbPrincipalName"],
                        String,
                    )
                },
                AttributeSchema {
                    is_list: true,
                    ..editable(
                        "sshpublickey",
                        &["sshPublicKey", "ssHPublicKey", "ssh_public_key"],
                        String,
                    )
                },
                readonly("ou", &["organizationalunit", "organizationalUnit"], String),
            ],
        },
        "user attributes"
    );
    assert_eq!(
        *s.group_attributes(),
        AttributeList {
            attributes: vec![
                readonly("groupid", &["group_id"], Integer),
                readonly(
                    "creationdate",
                    &["creation_date", "createTimestamp"],
                    DateTime
                ),
                readonly(
                    "modifieddate",
                    &["modified_date", "modifyTimestamp"],
                    DateTime
                ),
                readonly("uuid", &["entryUUID", "entryuuid"], String),
                editable("displayname", &["display_name", "cn", "commonname"], String),
                readonly("ou", &["organizationalunit", "organizationalUnit"], String),
                attr("gidnumber", &["gid_number", "gidNumber"], Integer),
            ],
        },
        "group attributes"
    );
    assert_eq!(
        *s.system_attributes(),
        AttributeList {
            attributes: vec![AttributeSchema {
                is_list: true,
                is_visible: false,
                is_readonly: true,
                ..attr("allowedous", &["allowedOUs", "AllowedOUs"], String)
            }],
        },
        "system attributes"
    );
    let schema = s.get_schema();
    assert_eq!(
        schema.posix_settings,
        PosixSettings {
            user_uidnumber_assign: false,
            user_uidnumber_start: 3001,
            user_uidnumber_max: 3999,
            user_gidnumber_assign: false,
            user_gidnumber_start: 3001,
            user_loginshell_assign: false,
            user_loginshell_default: "/bin/bash".to_owned(),
            user_homedirectory_assign: false,
            user_homedirectory_prefix: "/home".to_owned(),
            group_gidnumber_assign: false,
            group_gidnumber_start: 3001,
            group_gidnumber_max: 3999,
        },
        "posix settings"
    );
    assert_eq!(
        schema.extra_user_object_classes,
        ["inetOrgPerson", "posixAccount", "ldapPublicKey"],
        "user object classes"
    );
    assert_eq!(
        schema.extra_group_object_classes,
        ["posixGroup"],
        "group object classes"
    );
    assert_eq!(
        s.user_attributes().format_for_ldap_schema_description(),
        "avatar $ creationdate $ displayname $ firstname $ lastname $ mail $ modifieddate $ \
         passwordmodifieddate $ userid $ uuid $ uidnumber $ gidnumber $ homedirectory $ \
         loginshell $ kerberossync $ krbprincipalname $ sshpublickey $ ou",
        "user description order"
    );
    assert_eq!(
        s.group_attributes().format_for_ldap_schema_description(),
        "groupid $ creationdate $ modifieddate $ uuid $ displayname $ ou $ gidnumber",
        "group description order"
    );
}

#[test]
fn test_alias_resolution_is_case_insensitive_and_list_scoped() {
    let s = PublicSchema::shared();
    let u = s.user_attributes();
    assert_eq!(u.resolve_canonical_name("displayname"), Some("displayname"));
    assert_eq!(u.resolve_canonical_name("cn"), Some("displayname"));
    assert_eq!(
        u.resolve_canonical_name("display_name"),
        Some("displayname")
    );
    assert_eq!(u.resolve_canonical_name("email"), Some("mail"));
    assert_eq!(u.resolve_canonical_name("uid"), Some("userid"));
    assert_eq!(u.resolve_canonical_name("USERID"), Some("userid"));
    assert_eq!(u.resolve_canonical_name("jpegPHOTO"), Some("avatar"));
    assert_eq!(
        u.resolve_canonical_name("CREATETIMESTAMP"),
        Some("creationdate")
    );
    assert_eq!(u.resolve_canonical_name("surname"), Some("lastname"));
    assert_eq!(u.resolve_canonical_name("commonname"), Some("displayname"));
    assert_eq!(u.resolve_canonical_name("given_name"), Some("firstname"));
    assert_eq!(u.resolve_canonical_name("nope"), None);
    assert_eq!(
        s.group_attributes().resolve_canonical_name("jpegPhoto"),
        None
    );

    assert!(u.contains_name_or_alias("userid"));
    assert!(u.contains_name_or_alias("uid"));
    assert!(u.contains_name_or_alias("UID"));
    assert!(!u.contains_name_or_alias("nope"));
    let all: Vec<&str> = u.all_names_and_aliases().collect();
    assert!(all.contains(&"userid"));
    assert!(all.contains(&"uid"));
    assert!(all.contains(&"entryUUID"));
}

#[test]
fn test_attribute_type_lookup_and_projections() {
    let u = PublicSchema::shared().user_attributes();
    assert_eq!(
        u.get_attribute_type("sshpublickey"),
        Some((AT::String, true))
    );
    assert_eq!(
        u.get_attribute_type("uidnumber"),
        Some((AT::Integer, false))
    );
    assert_eq!(u.get_attribute_type("avatar"), Some((AT::Avatar, false)));
    assert_eq!(
        u.get_attribute_type("creationdate"),
        Some((AT::DateTime, false))
    );
    assert_eq!(u.get_attribute_type("nope"), None);

    // The Display, wire and parse projections disagree by design.
    assert_eq!(AT::DateTime.to_string(), "DateTime");
    assert_eq!(<&'static str>::from(AT::DateTime), "DATE_TIME");
    assert_eq!("DATE_TIME".parse::<AT>().unwrap(), AT::DateTime);
}

#[test]
fn test_preferred_ldap_name_parity() {
    let s = PublicSchema::shared();
    let expect = |list: &AttributeList, name: &str, want: &str| {
        assert_eq!(list.preferred_ldap_name(name), Some(want), "attr {name}");
    };
    let u = s.user_attributes();
    expect(u, "avatar", "jpegphoto");
    expect(u, "creationdate", "createTimestamp");
    expect(u, "displayname", "cn");
    expect(u, "firstname", "givenName");
    expect(u, "lastname", "sn");
    expect(u, "mail", "mail");
    expect(u, "modifieddate", "modifyTimestamp");
    expect(u, "passwordmodifieddate", "pwdChangedTime");
    expect(u, "userid", "uid");
    expect(u, "uuid", "entryUUID");
    expect(u, "uidnumber", "uidNumber");
    expect(u, "gidnumber", "gidNumber");
    expect(u, "homedirectory", "homeDirectory");
    expect(u, "loginshell", "loginShell");
    expect(u, "kerberossync", "kerberossync");
    expect(u, "krbprincipalname", "krbPrincipalName");
    expect(u, "sshpublickey", "sshPublicKey");
    expect(u, "ou", "ou");
    let g = s.group_attributes();
    expect(g, "groupid", "groupid");
    expect(g, "creationdate", "createTimestamp");
    expect(g, "modifieddate", "modifyTimestamp");
    expect(g, "uuid", "entryUUID");
    expect(g, "displayname", "cn");
    expect(g, "ou", "ou");
    expect(g, "gidnumber", "gidNumber");
}
