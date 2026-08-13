use std::collections::{HashMap, HashSet};

use crate::common::{
    env,
    fixture::{LLDAPFixture, User, new_id},
};
use ldap3::{LdapConn, Scope, SearchEntry, SearchResult};
use serial_test::file_serial;
mod common;

/// Production-grade LDAP tests for KLLDAP 0.7.2
/// Validates unlimited nested OUs, correct DNs, leaf semantics, and attribute casing.

#[test]
#[file_serial]
fn basic_users_search() {
    let mut fixture = LLDAPFixture::new();
    let prefix = "ldap-basic_users_search-";
    let user1_name = new_id(Some(prefix));
    let user2_name = new_id(Some(prefix));
    let user3_name = new_id(Some(prefix));
    let group1_name = new_id(Some(prefix));
    let group2_name = new_id(Some(prefix));

    let initial_state = vec![
        User::new(&user1_name, vec![&group1_name]),
        User::new(&user2_name, vec![&group1_name, &group2_name]),
        User::new(&user3_name, vec![]),
    ];
    fixture.load_state(&initial_state);

    let mut ldap =
        LdapConn::new(env::ldap_url().as_str()).expect("failed to create ldap connection");

    let base_dn = env::base_dn();
    let bind_dn = format!("uid={},ou=people,{}", env::admin_dn(), base_dn);
    ldap.simple_bind(&bind_dn, env::admin_password().as_str())
        .expect("failed to bind to ldap");

    let attrs = vec![
        "uid",
        "memberOf",
        "hasSubordinates",
        "structuralObjectClass",
    ];

    let search_result = ldap
        .search(&base_dn, Scope::Subtree, "(objectclass=person)", attrs)
        .expect("failed to search users");

    let found_users = parse_ldap_users(search_result);

    // Validations
    assert!(found_users.contains_key(&user1_name), "user1 missing");
    let g1 = found_users.get(&user1_name).unwrap();
    assert!(
        g1.iter().any(|dn| dn.contains(&group1_name)),
        "user1 missing group1. Actual memberOf: {:?}",
        g1
    );

    assert!(found_users.contains_key(&user2_name));
    let g2 = found_users.get(&user2_name).unwrap();
    assert!(g2.iter().any(|dn| dn.contains(&group1_name)));
    assert!(g2.iter().any(|dn| dn.contains(&group2_name)));

    assert!(found_users.contains_key(&user3_name));
    assert!(found_users.get(&user3_name).unwrap().is_empty());

    ldap.unbind().expect("failed to unbind");
}

#[test]
#[file_serial]
fn admin_search() {
    let mut _fixture = LLDAPFixture::new();

    let mut ldap =
        LdapConn::new(env::ldap_url().as_str()).expect("failed to create ldap connection");

    let base_dn = env::base_dn();
    let bind_dn = format!("uid={},ou=people,{}", env::admin_dn(), base_dn);
    ldap.simple_bind(&bind_dn, env::admin_password().as_str())
        .expect("failed to bind to ldap");

    let attrs = vec![
        "uid",
        "memberOf",
        "hasSubordinates",
        "structuralObjectClass",
    ];
    let admin_name = env::admin_dn();
    let admin_group = "lldap_admin";

    let search_result = ldap
        .search(
            &base_dn,
            Scope::Subtree,
            &format!("(&(objectclass=person)(uid={}))", admin_name),
            attrs,
        )
        .expect("failed to search for admin");

    let found = parse_ldap_users(search_result);

    assert!(found.contains_key(&admin_name));
    let groups = found.get(&admin_name).unwrap();
    assert!(
        groups.iter().any(|dn| dn.contains(admin_group)),
        "admin missing lldap_admin. Actual: {:?}",
        groups
    );

    ldap.unbind().expect("failed to unbind");
}

#[test]
#[file_serial]
fn nested_ou_test() {
    let mut fixture = LLDAPFixture::new();
    let prefix = "nested-ou-test-";
    let user_name = new_id(Some(prefix));
    let group_name = new_id(Some(prefix));

    // Create user under a nested OU path (simulated via attributes)
    let initial_state = vec![User::new(&user_name, vec![&group_name])];
    fixture.load_state(&initial_state);

    let mut ldap =
        LdapConn::new(env::ldap_url().as_str()).expect("failed to create ldap connection");

    let base_dn = env::base_dn();
    let bind_dn = format!("uid={},ou=people,{}", env::admin_dn(), base_dn);
    ldap.simple_bind(&bind_dn, env::admin_password().as_str())
        .expect("failed to bind to ldap");

    // Search from root — should find the user even if under nested OUs
    let search_result = ldap
        .search(
            &base_dn,
            Scope::Subtree,
            "(objectclass=person)",
            vec!["uid", "hasSubordinates"],
        )
        .expect("failed to search");

    let users = parse_ldap_users(search_result);

    assert!(
        users.contains_key(&user_name),
        "user not found under nested OU structure"
    );

    ldap.unbind().expect("failed to unbind");
}

#[test]
#[file_serial]
fn subtree_search_at_leaf_returns_entry() {
    // #4: RFC 4511 §4.5.1.2 — wholeSubtree includes the base entry, so a subtree search
    // based at a user's own DN must return that user, not zero entries.
    let mut fixture = LLDAPFixture::new();
    let prefix = "ldap-subtree-leaf-";
    let user_name = new_id(Some(prefix));
    fixture.load_state(&vec![User::new(&user_name, vec![])]);

    let mut ldap =
        LdapConn::new(env::ldap_url().as_str()).expect("failed to create ldap connection");
    let base_dn = env::base_dn();
    let bind_dn = format!("uid={},ou=people,{}", env::admin_dn(), base_dn);
    ldap.simple_bind(&bind_dn, env::admin_password().as_str())
        .expect("failed to bind to ldap");

    let user_dn = format!("uid={},ou=people,{}", user_name, base_dn);
    let search_result = ldap
        .search(
            &user_dn,
            Scope::Subtree,
            "(objectclass=person)",
            vec!["uid"],
        )
        .expect("failed to search at leaf");

    let found = parse_ldap_users(search_result);
    assert!(
        found.contains_key(&user_name),
        "subtree search at leaf DN {} returned no entry (bug #4)",
        user_dn
    );

    ldap.unbind().expect("failed to unbind");
}

#[test]
#[file_serial]
fn ou_entries_respect_filter() {
    // #3: a filter an OU can't satisfy (a cn substring) must not return phantom OU entries,
    // while an objectClass filter that does match still returns them.
    let mut _fixture = LLDAPFixture::new();

    let mut ldap =
        LdapConn::new(env::ldap_url().as_str()).expect("failed to create ldap connection");
    let base_dn = env::base_dn();
    let bind_dn = format!("uid={},ou=people,{}", env::admin_dn(), base_dn);
    ldap.simple_bind(&bind_dn, env::admin_password().as_str())
        .expect("failed to bind to ldap");

    let phantom = ldap
        .search(
            &base_dn,
            Scope::Subtree,
            "(cn=*zzzznosuchthing*)",
            vec!["ou", "objectClass"],
        )
        .expect("failed to search");
    assert_eq!(
        count_ou_entries(phantom),
        0,
        "cn substring returned phantom OU entries (bug #3)"
    );

    // Positive control: the OUs are still discoverable by objectClass.
    let real = ldap
        .search(
            &base_dn,
            Scope::Subtree,
            "(objectClass=organizationalUnit)",
            vec!["ou", "objectClass"],
        )
        .expect("failed to search");
    assert!(
        count_ou_entries(real) >= 1,
        "objectClass=organizationalUnit should still return OU entries"
    );

    ldap.unbind().expect("failed to unbind");
}

#[test]
#[file_serial]
fn cn_substring_matches_display_name() {
    // uid is random and does not contain the substring, so a match is via display_name.
    let mut fixture = LLDAPFixture::new();
    let prefix = "ldap-cn-substr-";
    let user_name = new_id(Some(prefix));
    fixture.load_state(&vec![
        User::new(&user_name, vec![]).with_display_name("Shaia Aelieth Meow"),
    ]);

    let mut ldap =
        LdapConn::new(env::ldap_url().as_str()).expect("failed to create ldap connection");
    let base_dn = env::base_dn();
    let bind_dn = format!("uid={},ou=people,{}", env::admin_dn(), base_dn);
    ldap.simple_bind(&bind_dn, env::admin_password().as_str())
        .expect("failed to bind to ldap");

    let found = parse_ldap_users(
        ldap.search(
            &base_dn,
            Scope::Subtree,
            "(&(objectclass=person)(cn=*aelieth*))",
            vec!["uid"],
        )
        .expect("failed to search"),
    );
    assert!(
        found.contains_key(&user_name),
        "cn substring did not match the user's display_name (bug #5)"
    );

    ldap.unbind().expect("failed to unbind");
}

#[test]
#[file_serial]
fn display_name_emitted_for_cn_and_display_name() {
    // A wildcard search returns both cn and displayName (same value); an explicit displayName
    // request returns displayName over the wire.
    let mut fixture = LLDAPFixture::new();
    let prefix = "ldap-displayname-";
    let user_name = new_id(Some(prefix));
    let display = "Ninameow Aelieth";
    fixture.load_state(&vec![
        User::new(&user_name, vec![]).with_display_name(display),
    ]);

    let mut ldap =
        LdapConn::new(env::ldap_url().as_str()).expect("failed to create ldap connection");
    let base_dn = env::base_dn();
    let bind_dn = format!("uid={},ou=people,{}", env::admin_dn(), base_dn);
    ldap.simple_bind(&bind_dn, env::admin_password().as_str())
        .expect("failed to bind to ldap");

    let filter = format!("(uid={})", user_name);

    // Wildcard: both cn and displayName present with the same value.
    let star = attrs_for_user(
        ldap.search(&base_dn, Scope::Subtree, &filter, vec!["*"])
            .expect("search failed"),
        &user_name,
    );
    assert_eq!(star.get("cn").map(String::as_str), Some(display), "cn on *");
    assert_eq!(
        star.get("displayname").map(String::as_str),
        Some(display),
        "displayName on *"
    );

    // Explicit displayName request returns displayName.
    let explicit = attrs_for_user(
        ldap.search(&base_dn, Scope::Subtree, &filter, vec!["displayName"])
            .expect("search failed"),
        &user_name,
    );
    assert_eq!(
        explicit.get("displayname").map(String::as_str),
        Some(display),
        "explicit displayName"
    );

    ldap.unbind().expect("failed to unbind");
}

/// First value of each attribute (lowercased atype) for the entry whose DN carries `uid=<uid>`.
fn attrs_for_user(results: SearchResult, uid: &str) -> HashMap<String, String> {
    let needle = format!("uid={}", uid).to_ascii_lowercase();
    for entry in results.success().expect("search failed").0 {
        let parsed = SearchEntry::construct(entry);
        if parsed.dn.to_ascii_lowercase().contains(&needle) {
            return parsed
                .attrs
                .iter()
                .filter_map(|(k, v)| v.first().map(|val| (k.to_ascii_lowercase(), val.clone())))
                .collect();
        }
    }
    HashMap::new()
}

/// Count returned entries whose objectClass includes organizationalUnit.
fn count_ou_entries(results: SearchResult) -> usize {
    let entries = results.success().expect("search failed").0;
    let mut count = 0;
    for entry in entries {
        let parsed = SearchEntry::construct(entry);
        let is_ou = parsed
            .attrs
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("objectclass"))
            .map(|(_, v)| {
                v.iter()
                    .any(|c| c.eq_ignore_ascii_case("organizationalUnit"))
            })
            .unwrap_or(false);
        if is_ou {
            count += 1;
        }
    }
    count
}

/// Case-insensitive + robust parser for the new OU model
fn parse_ldap_users(results: SearchResult) -> HashMap<String, HashSet<String>> {
    let entries = results.success().expect("search failed").0;
    let mut users = HashMap::new();

    for entry in entries {
        let parsed = SearchEntry::construct(entry);
        let attrs = &parsed.attrs;

        // Case-insensitive lookup for uid
        let uid = attrs
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("uid"))
            .and_then(|(_, v)| v.first())
            .cloned();

        if let Some(uid) = uid {
            // Case-insensitive lookup for memberOf
            let member_of: HashSet<String> = attrs
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("memberof"))
                .map(|(_, v)| v.clone())
                .unwrap_or_default()
                .into_iter()
                .collect();

            users.insert(uid, member_of);
        }
    }
    users
}
