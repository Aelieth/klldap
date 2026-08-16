use crate::common::{
    auth::get_token,
    env,
    fixture::{LLDAPFixture, User, new_id},
    graphql::{
        GetUserDetails, ListGroups, ListUsers, get_user_details, list_groups, list_users, post,
    },
};
use reqwest::blocking::ClientBuilder;
use std::collections::HashSet;
mod common;

#[test]
fn list_users() {
    let mut fixture = LLDAPFixture::new();
    let prefix = "graphql-list_users-";
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

    let client = ClientBuilder::new()
        .connect_timeout(std::time::Duration::from_secs(2))
        .timeout(std::time::Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("failed to make http client");
    let token = get_token(&client, &fixture.http_url());
    let result = post::<ListUsers>(
        &client,
        &fixture.http_url(),
        &token,
        list_users::Variables {},
    )
    .expect("failed to list users");
    let users: HashSet<String> = result.users.iter().map(|user| user.id.clone()).collect();
    assert!(users.contains(&user1_name));
    assert!(users.contains(&user2_name));
    assert!(users.contains(&user3_name));
}

#[test]
fn get_admin() {
    let fixture = LLDAPFixture::new();
    let client = ClientBuilder::new()
        .connect_timeout(std::time::Duration::from_secs(2))
        .timeout(std::time::Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("failed to make http client");
    let admin_name = env::admin_dn();
    let admin_group_name = "lldap_admin";
    let token = get_token(&client, &fixture.http_url());
    let result = post::<GetUserDetails>(
        &client,
        &fixture.http_url(),
        &token,
        get_user_details::Variables { id: admin_name },
    )
    .expect("failed to get admin");
    let admin_groups: HashSet<String> = result
        .user
        .groups
        .iter()
        .map(|group| group.display_name.clone())
        .collect();
    assert!(admin_groups.contains(admin_group_name));
}

#[test]
fn disabled_user_jwt_is_rejected() {
    let mut fixture = LLDAPFixture::new();
    let user_name = new_id(Some("graphql-disabled-"));
    fixture.load_state(&vec![User::new(&user_name, vec![])]);

    let client = ClientBuilder::new()
        .connect_timeout(std::time::Duration::from_secs(2))
        .timeout(std::time::Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("failed to make http client");
    let admin_token = get_token(&client, &fixture.http_url());
    let password = "disabled-session-pass";
    let set_password = client
        .post(format!("{}/api/graphql", fixture.http_url()))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {admin_token}"),
        )
        .json(&serde_json::json!({
            "query": "mutation($id: String!, $password: String!) { setUserPassword(userId: $id, password: $password) { ok } }",
            "variables": { "id": user_name, "password": password }
        }))
        .send()
        .expect("setUserPassword request")
        .error_for_status()
        .expect("setUserPassword HTTP");
    let set_body: serde_json::Value = set_password.json().expect("setUserPassword json");
    assert!(
        set_body.get("errors").and_then(|e| e.as_array()).is_none()
            || set_body["errors"].as_array().unwrap().is_empty(),
        "setUserPassword failed: {set_body}"
    );

    let login = client
        .post(format!("{}/auth/simple/login", fixture.http_url()))
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(
            serde_json::to_string(&lldap_auth::login::ClientSimpleLoginRequest {
                username: user_name.clone().into(),
                password: password.to_owned(),
            })
            .unwrap(),
        )
        .send()
        .expect("user login")
        .error_for_status()
        .expect("user login HTTP");
    let user_token = serde_json::from_str::<lldap_auth::login::ServerLoginResponse>(
        &login.text().expect("login body"),
    )
    .expect("login json")
    .token;

    let groups = post::<ListGroups>(
        &client,
        &fixture.http_url(),
        &admin_token,
        list_groups::Variables {},
    )
    .expect("list groups");
    let disabled_id = groups
        .groups
        .iter()
        .find(|g| g.display_name == "lldap_disabled")
        .map(|g| g.id)
        .expect("lldap_disabled exists at boot");
    post::<crate::common::graphql::AddUserToGroup>(
        &client,
        &fixture.http_url(),
        &admin_token,
        crate::common::graphql::add_user_to_group::Variables {
            user: user_name.clone(),
            group: disabled_id,
        },
    )
    .expect("add to lldap_disabled");

    let rejected = client
        .post(format!("{}/api/graphql", fixture.http_url()))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {user_token}"),
        )
        .json(&serde_json::json!({
            "query": "query { apiVersion }"
        }))
        .send()
        .expect("graphql with disabled jwt");
    assert_eq!(
        rejected.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "disabled user's existing JWT must not reach GraphQL: {}",
        rejected.text().unwrap_or_default()
    );
}
