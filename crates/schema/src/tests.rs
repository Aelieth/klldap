use crate::public_schema::PublicSchema;
use crate::schema::{AttributeList, AttributeType as AT};

struct E {
    name: &'static str,
    aliases: &'static [&'static str],
    t: AT,
    is_list: bool,
    is_visible: bool,
    is_editable: bool,
    is_hardcoded: bool,
    is_readonly: bool,
}

#[allow(clippy::too_many_arguments)]
fn e(
    name: &'static str,
    aliases: &'static [&'static str],
    t: AT,
    is_list: bool,
    is_visible: bool,
    is_editable: bool,
    is_hardcoded: bool,
    is_readonly: bool,
) -> E {
    E {
        name,
        aliases,
        t,
        is_list,
        is_visible,
        is_editable,
        is_hardcoded,
        is_readonly,
    }
}

fn check(list: &AttributeList, expected: &[E]) {
    assert_eq!(list.attributes.len(), expected.len(), "attribute count");
    for (actual, x) in list.attributes.iter().zip(expected) {
        assert_eq!(actual.name, x.name, "name");
        let aliases: Vec<&str> = actual.aliases.iter().map(String::as_str).collect();
        assert_eq!(aliases.as_slice(), x.aliases, "aliases for {}", x.name);
        assert_eq!(actual.attribute_type, x.t, "type for {}", x.name);
        assert_eq!(actual.is_list, x.is_list, "is_list for {}", x.name);
        assert_eq!(actual.is_visible, x.is_visible, "is_visible for {}", x.name);
        assert_eq!(
            actual.is_editable, x.is_editable,
            "is_editable for {}",
            x.name
        );
        assert_eq!(
            actual.is_hardcoded, x.is_hardcoded,
            "is_hardcoded for {}",
            x.name
        );
        assert_eq!(
            actual.is_readonly, x.is_readonly,
            "is_readonly for {}",
            x.name
        );
    }
}

#[test]
fn user_schema_is_pinned() {
    #[rustfmt::skip]
    let expected = [
        e("avatar", &["jpegphoto", "jpegPhoto", "jpeg_photo"], AT::Avatar, false, true, true, true, false),
        e("creationdate", &["creation_date", "createTimestamp"], AT::DateTime, false, true, false, true, true),
        e("displayname", &["display_name", "cn", "commonname"], AT::String, false, true, true, true, false),
        e("firstname", &["first_name", "givenName", "given_name"], AT::String, false, true, true, true, false),
        e("lastname", &["last_name", "sn", "surname"], AT::String, false, true, true, true, false),
        e("mail", &["email"], AT::String, false, true, true, true, false),
        e("modifieddate", &["modified_date", "modifyTimestamp"], AT::DateTime, false, true, false, true, true),
        e("passwordmodifieddate", &["password_modified_date", "pwdChangedTime"], AT::DateTime, false, true, false, true, true),
        e("userid", &["user_id", "uid", "id"], AT::String, false, true, false, true, true),
        e("uuid", &["entryUUID", "entryuuid"], AT::String, false, true, false, true, true),
        e("uidnumber", &["uid_number", "uidNumber"], AT::Integer, false, true, false, true, false),
        e("gidnumber", &["gid_number", "gidNumber"], AT::Integer, false, true, false, true, false),
        e("homedirectory", &["home_directory", "homeDirectory"], AT::String, false, true, false, true, false),
        e("loginshell", &["login_shell", "loginShell"], AT::String, false, true, false, true, false),
        e("kerberossync", &["kerberos_sync", "kerberosSync"], AT::Integer, false, true, false, true, false),
        e("krbprincipalname", &["krb_principal_name", "krbPrincipalName"], AT::String, false, false, false, true, true),
        e("sshpublickey", &["sshPublicKey", "ssHPublicKey", "ssh_public_key"], AT::String, true, true, true, true, false),
        e("ou", &["organizationalunit", "organizationalUnit"], AT::String, false, true, false, true, true),
    ];
    check(PublicSchema::shared().user_attributes(), &expected);
}

#[test]
fn group_schema_is_pinned() {
    #[rustfmt::skip]
    let expected = [
        e("groupid", &["group_id"], AT::Integer, false, true, false, true, true),
        e("creationdate", &["creation_date", "createTimestamp"], AT::DateTime, false, true, false, true, true),
        e("modifieddate", &["modified_date", "modifyTimestamp"], AT::DateTime, false, true, false, true, true),
        e("uuid", &["entryUUID", "entryuuid"], AT::String, false, true, false, true, true),
        e("displayname", &["display_name", "cn", "commonname"], AT::String, false, true, true, true, false),
        e("ou", &["organizationalunit", "organizationalUnit"], AT::String, false, true, false, true, true),
        e("gidnumber", &["gid_number", "gidNumber"], AT::Integer, false, true, false, true, false),
    ];
    check(PublicSchema::shared().group_attributes(), &expected);
}

#[test]
fn system_schema_is_pinned() {
    let expected = [e(
        "allowedous",
        &["allowedOUs", "AllowedOUs"],
        AT::String,
        true,
        false,
        false,
        true,
        true,
    )];
    check(PublicSchema::shared().system_attributes(), &expected);
}

#[test]
fn posix_settings_and_object_classes_are_pinned() {
    let s = PublicSchema::shared();
    let p = s.posix_settings();
    assert!(!p.user_uidnumber_assign);
    assert_eq!(p.user_uidnumber_start, 3001);
    assert_eq!(p.user_uidnumber_max, 3999);
    assert!(!p.user_gidnumber_assign);
    assert_eq!(p.user_gidnumber_start, 3001);
    assert!(!p.user_loginshell_assign);
    assert_eq!(p.user_loginshell_default, "/bin/bash");
    assert!(!p.user_homedirectory_assign);
    assert_eq!(p.user_homedirectory_prefix, "/home");
    assert!(!p.group_gidnumber_assign);
    assert_eq!(p.group_gidnumber_start, 3001);
    assert_eq!(p.group_gidnumber_max, 3999);

    let sch = s.get_schema();
    let user_oc: Vec<&str> = sch
        .extra_user_object_classes
        .iter()
        .map(String::as_str)
        .collect();
    assert_eq!(user_oc, ["inetOrgPerson", "posixAccount", "ldapPublicKey"]);
    let group_oc: Vec<&str> = sch
        .extra_group_object_classes
        .iter()
        .map(String::as_str)
        .collect();
    assert_eq!(group_oc, ["posixGroup"]);
}

#[test]
fn ldap_description_order_is_pinned() {
    let s = PublicSchema::shared();
    assert_eq!(
        s.user_attributes().format_for_ldap_schema_description(),
        "avatar $ creationdate $ displayname $ firstname $ lastname $ mail $ modifieddate $ \
         passwordmodifieddate $ userid $ uuid $ uidnumber $ gidnumber $ homedirectory $ \
         loginshell $ kerberossync $ krbprincipalname $ sshpublickey $ ou"
    );
    assert_eq!(
        s.group_attributes().format_for_ldap_schema_description(),
        "groupid $ creationdate $ modifieddate $ uuid $ displayname $ ou $ gidnumber"
    );
}

#[test]
fn alias_resolution_is_case_insensitive_and_list_scoped() {
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
}

#[test]
fn get_attribute_type_is_pinned() {
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
}

#[test]
fn generated_attributes_are_neither_editable_nor_readonly() {
    let s = PublicSchema::shared();
    let u = s.user_attributes();
    for name in [
        "uidnumber",
        "gidnumber",
        "homedirectory",
        "loginshell",
        "kerberossync",
    ] {
        let a = u.get_by_name_or_alias(name).unwrap();
        assert!(!a.is_editable && !a.is_readonly, "{name}");
    }
    let g = s
        .group_attributes()
        .get_by_name_or_alias("gidnumber")
        .unwrap();
    assert!(!g.is_editable && !g.is_readonly, "group gidnumber");
}

#[test]
fn attribute_type_string_projections_disagree_by_design() {
    assert_eq!(AT::DateTime.to_string(), "DateTime");
    assert_eq!(<&'static str>::from(AT::DateTime), "DATE_TIME");
    assert_eq!("DATE_TIME".parse::<AT>().unwrap(), AT::DateTime);
}

#[test]
fn name_membership_and_flatten() {
    let u = PublicSchema::shared().user_attributes();
    assert!(u.contains_name_or_alias("userid"));
    assert!(u.contains_name_or_alias("uid"));
    assert!(u.contains_name_or_alias("UID"));
    assert!(!u.contains_name_or_alias("nope"));

    let all: Vec<&str> = u.all_names_and_aliases().collect();
    assert!(all.contains(&"userid"));
    assert!(all.contains(&"uid"));
    assert!(all.contains(&"entryUUID"));
    let expected_count: usize = u.attributes.iter().map(|a| 1 + a.aliases.len()).sum();
    assert_eq!(all.len(), expected_count);
}

#[test]
fn preferred_ldap_name_parity() {
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
