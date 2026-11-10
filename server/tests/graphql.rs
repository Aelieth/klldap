use crate::common::{
    auth::get_token,
    env,
    fixture::{LLDAPFixture, User, new_id},
    graphql::{GetUserDetails, ListUsers, get_user_details, list_users, post},
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

fn graphql_get(
    client: &reqwest::blocking::Client,
    base_url: &str,
    token: &str,
    query: &str,
    operation_name: Option<&str>,
) -> reqwest::blocking::Response {
    let mut params = vec![("query", query)];
    if let Some(name) = operation_name {
        params.push(("operationName", name));
    }
    client
        .get(format!("{base_url}/api/graphql"))
        .header(reqwest::header::AUTHORIZATION, format!("Bearer {token}"))
        .query(&params)
        .send()
        .expect("graphql GET")
}

#[test]
fn get_refuses_a_mutation_and_answers_a_query() {
    let mut fixture = LLDAPFixture::new();
    let user_name = new_id(Some("graphql-get-"));
    fixture.load_state(&vec![User::new(&user_name, vec![])]);
    let client = ClientBuilder::new()
        .connect_timeout(std::time::Duration::from_secs(2))
        .timeout(std::time::Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("failed to make http client");
    let token = get_token(&client, &fixture.http_url());
    let base = fixture.http_url();

    let listed = graphql_get(
        &client,
        &base,
        &token,
        "{ users(where: null) { id } }",
        None,
    );
    assert!(listed.status().is_success(), "{}", listed.status());
    let body: serde_json::Value = listed.json().expect("query json");
    let ids: Vec<&str> = body["data"]["users"]
        .as_array()
        .expect("users")
        .iter()
        .filter_map(|user| user["id"].as_str())
        .collect();
    assert!(ids.contains(&user_name.as_str()), "{body}");

    let mixed = format!(
        r#"query Q {{ users(where: null) {{ id }} }} mutation M {{ deleteUser(userId: "{user_name}") {{ ok }} }}"#
    );
    let named = graphql_get(&client, &base, &token, &mixed, Some("Q"));
    assert!(named.status().is_success(), "{}", named.status());
    let named_body: serde_json::Value = named.json().expect("named query json");
    let named_ids: Vec<&str> = named_body["data"]["users"]
        .as_array()
        .expect("users")
        .iter()
        .filter_map(|user| user["id"].as_str())
        .collect();
    assert!(named_ids.contains(&user_name.as_str()), "{named_body}");

    let mutation = format!(r#"mutation {{ deleteUser(userId: "{user_name}") {{ ok }} }}"#);
    let refused = graphql_get(&client, &base, &token, &mutation, None);
    let status = refused.status();
    let text = refused.text().expect("mutation body");
    assert!(!status.is_success(), "{status} {text}");
    assert!(
        text.contains("Only a single query operation is accepted over GET"),
        "{text}"
    );

    let result = post::<ListUsers>(&client, &base, &token, list_users::Variables {})
        .expect("user still listed");
    assert!(result.users.iter().any(|user| user.id == user_name));
}
