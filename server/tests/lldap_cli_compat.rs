use crate::common::{env, fixture::LLDAPFixture};
use reqwest::blocking::{Client, ClientBuilder};
use serde_json::{Value, json};
mod common;

// Replays lldap-cli's exact REST and GraphQL shapes (Zepmann/lldap-cli) against a live
// server: raw JSON bodies, not graphql_client codegen, so upstream client compatibility
// is what is actually asserted.

fn make_client() -> Client {
    ClientBuilder::new()
        .connect_timeout(std::time::Duration::from_secs(2))
        .timeout(std::time::Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("failed to make http client")
}

fn simple_login(client: &Client, base_url: &str) -> (String, String) {
    let body: Value = client
        .post(format!("{base_url}/auth/simple/login"))
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(json!({"username": env::admin_dn(), "password": env::admin_password()}).to_string())
        .send()
        .expect("login send failed")
        .error_for_status()
        .expect("login failed")
        .json()
        .expect("login response not json");
    (
        body["token"].as_str().expect("no token").to_string(),
        body["refreshToken"]
            .as_str()
            .expect("no refreshToken")
            .to_string(),
    )
}

fn gql(client: &Client, base_url: &str, token: &str, query: &str, variables: Value) -> Value {
    let body: Value = client
        .post(format!("{base_url}/api/graphql"))
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .bearer_auth(token)
        .body(json!({"query": query, "variables": variables}).to_string())
        .send()
        .expect("graphql send failed")
        .error_for_status()
        .expect("graphql http error")
        .json()
        .expect("graphql response not json");
    assert!(
        body.get("errors").is_none_or(Value::is_null),
        "graphql errors for {query}: {body}"
    );
    body["data"].clone()
}

#[test]
fn test_lldap_cli_operation_sequence() {
    let fixture = LLDAPFixture::new();
    let client = make_client();
    let base_url = fixture.http_url();

    let (token, refresh_token) = simple_login(&client, &base_url);
    let refreshed: Value = client
        .get(format!("{base_url}/auth/refresh"))
        .header(
            reqwest::header::COOKIE,
            format!("refresh_token={refresh_token}"),
        )
        .send()
        .expect("refresh send failed")
        .error_for_status()
        .expect("refresh failed")
        .json()
        .expect("refresh response not json");
    assert!(refreshed["token"].as_str().is_some_and(|t| !t.is_empty()));

    let user_id = "cli-compat-user";
    let group_name = "cli-compat-group";

    let created = gql(
        &client,
        &base_url,
        &token,
        r#"mutation CreateUser($user: CreateUserInput!) {
            createUser(user: $user) {id email displayName firstName lastName avatar}
        }"#,
        json!({"user": {"id": user_id, "email": format!("{user_id}@example.com")}}),
    );
    assert_eq!(created["createUser"]["id"], user_id);

    let users = gql(
        &client,
        &base_url,
        &token,
        r#"{users{id creationDate uuid email displayName firstName lastName}}"#,
        json!({}),
    );
    assert!(
        users["users"]
            .as_array()
            .unwrap()
            .iter()
            .any(|u| u["id"] == user_id)
    );

    let attrs = gql(
        &client,
        &base_url,
        &token,
        r#"query GetUserAttributes($id: String!) {
            user(userId: $id) { attributes { name value } }
        }"#,
        json!({"id": user_id}),
    );
    let attrs = attrs["user"]["attributes"].as_array().unwrap();
    assert!(!attrs.is_empty());
    assert!(
        attrs
            .iter()
            .all(|a| a["name"].as_str().is_some_and(|n| !n.is_empty()))
    );

    gql(
        &client,
        &base_url,
        &token,
        r#"mutation UpdateUser($user: UpdateUserInput!) {updateUser(user: $user) {ok}}"#,
        json!({"user": {"id": user_id, "insertAttributes": [{"name": "firstname", "value": ["Cli"]}]}}),
    );

    let group = gql(
        &client,
        &base_url,
        &token,
        r#"mutation CreateGroup($group: String!) {createGroup(name: $group) {id}}"#,
        json!({"group": group_name}),
    );
    let group_id = group["createGroup"]["id"].as_i64().unwrap();

    let groups = gql(
        &client,
        &base_url,
        &token,
        r#"{groups{id creationDate uuid displayName}}"#,
        json!({}),
    );
    assert!(
        groups["groups"]
            .as_array()
            .unwrap()
            .iter()
            .any(|g| g["id"].as_i64() == Some(group_id))
    );
    gql(
        &client,
        &base_url,
        &token,
        r#"mutation UpdateGroup($group: UpdateGroupInput!) {updateGroup(group: $group) {ok}}"#,
        json!({"group": {"id": group_id, "insertAttributes": []}}),
    );

    for (name, attr_type) in [("clistrattr", "STRING"), ("clijpegattr", "JPEG_PHOTO")] {
        gql(
            &client,
            &base_url,
            &token,
            r#"mutation AddUserAttribute($name: String!, $attributeType: AttributeType!) {
                addUserAttribute(name: $name, attributeType: $attributeType,
                                 isList: false, isVisible: true, isEditable: true) {ok}
            }"#,
            json!({"name": name, "attributeType": attr_type}),
        );
    }
    let schema = gql(
        &client,
        &base_url,
        &token,
        r#"{schema{userSchema{attributes{name attributeType isList isVisible isEditable}}}}"#,
        json!({}),
    );
    let schema_attrs = schema["schema"]["userSchema"]["attributes"]
        .as_array()
        .unwrap();
    let jpeg_attr = schema_attrs
        .iter()
        .find(|a| a["name"] == "clijpegattr")
        .expect("clijpegattr missing from schema");
    assert_eq!(jpeg_attr["attributeType"], "AVATAR");

    gql(
        &client,
        &base_url,
        &token,
        r#"mutation AddUserObjectClass($name: String!) {addUserObjectClass(name: $name) {ok}}"#,
        json!({"name": "cliCompatClass"}),
    );
    let classes = gql(
        &client,
        &base_url,
        &token,
        r#"{schema{userSchema{extraLdapObjectClasses}}}"#,
        json!({}),
    );
    assert!(
        classes["schema"]["userSchema"]["extraLdapObjectClasses"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c == "cliCompatClass")
    );
    gql(
        &client,
        &base_url,
        &token,
        r#"mutation DeleteUserObjectClass($name: String!) {deleteUserObjectClass(name: $name) {ok}}"#,
        json!({"name": "cliCompatClass"}),
    );

    for name in ["clistrattr", "clijpegattr"] {
        gql(
            &client,
            &base_url,
            &token,
            r#"mutation DeleteUserAttribute($name: String!) {deleteUserAttribute(name: $name) {ok}}"#,
            json!({"name": name}),
        );
    }
    gql(
        &client,
        &base_url,
        &token,
        r#"mutation DeleteGroup($id: Int!) {deleteGroup(groupId: $id) {ok}}"#,
        json!({"id": group_id}),
    );
    gql(
        &client,
        &base_url,
        &token,
        r#"mutation DeleteUser($userId: String!) {deleteUser(userId: $userId) {ok}}"#,
        json!({"userId": user_id}),
    );

    client
        .get(format!("{base_url}/auth/logout"))
        .header(
            reqwest::header::COOKIE,
            format!("refresh_token={refresh_token}"),
        )
        .send()
        .expect("logout send failed")
        .error_for_status()
        .expect("logout failed");
}
