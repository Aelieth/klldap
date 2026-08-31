use crate::common::{
    auth::{get_token, get_token_for},
    fixture::{LLDAPFixture, User},
};
use reqwest::blocking::{Client, ClientBuilder};
use serde_json::{Value, json};
mod common;

const CATALOG: &str = "{ policyItemCatalog { key enforced } }";
const CREATE: &str = r#"mutation($n: String!, $i: [PolicyItemInput!]) { createPolicy(name: $n, items: $i) { id name } }"#;
const SET: &str = r#"mutation($o: String!, $p: Int!) { setOuPolicy(ou: $o, policyId: $p) { ok } }"#;
const EFFECTIVE: &str = r#"query($o: String!) { effectivePolicyItems(ou: $o) { key value sourceOu sourcePolicyName } }"#;
const STATES: &str = "{ ouPolicyStates { ou policyId blockInheritance } }";
const BLOCK: &str =
    r#"mutation($o: String!, $b: Boolean!) { setOuPolicyInheritance(ou: $o, blocked: $b) { ok } }"#;
const DELETE_POLICY: &str = r#"mutation($p: Int!) { deletePolicy(policyId: $p) { ok } }"#;
const POLICIES: &str = "{ policies { id linkedOus } }";
const LOGS: &str = "{ logs(filter: {kinds: [POLICY_CHANGE]}, limit: 50) { kind target detail } }";

fn client() -> Client {
    ClientBuilder::new()
        .connect_timeout(std::time::Duration::from_secs(2))
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .expect("http client")
}

fn gql(client: &Client, base_url: &str, token: &str, query: &str, variables: Value) -> Value {
    client
        .post(format!("{base_url}/api/graphql"))
        .bearer_auth(token)
        .json(&json!({"query": query, "variables": variables}))
        .send()
        .expect("graphql send")
        .json()
        .expect("graphql json")
}

fn has_error(body: &Value, needle: &str) -> bool {
    body["errors"].as_array().is_some_and(|errors| {
        errors
            .iter()
            .any(|e| e["message"].as_str().is_some_and(|m| m.contains(needle)))
    })
}

fn settings(client: &Client, base_url: &str) -> Value {
    client
        .get(format!("{base_url}/settings"))
        .send()
        .expect("settings")
        .json()
        .expect("settings json")
}

#[test]
fn test_policy_lifecycle_over_graphql() {
    let mut fixture = LLDAPFixture::new();
    fixture.load_state(&vec![User::new("bob", vec![])]);
    let client = client();
    let url = fixture.http_url();
    let admin = get_token(&client, &url);
    let set_pw = gql(
        &client,
        &url,
        &admin,
        r#"mutation($id: String!, $password: String!) { setUserPassword(userId: $id, password: $password) { ok } }"#,
        json!({"id": "bob", "password": "bobpass"}),
    );
    assert_eq!(set_pw["data"]["setUserPassword"]["ok"], true, "{set_pw}");
    let bob = get_token_for(&client, &url, "bob", "bobpass");

    let catalog = gql(&client, &url, &admin, CATALOG, json!({}));
    let items = catalog["data"]["policyItemCatalog"]
        .as_array()
        .expect("catalog");
    assert_eq!(items.len(), 6, "{catalog}");
    assert!(items.iter().all(|i| i["enforced"] == false), "{catalog}");

    let bad = gql(
        &client,
        &url,
        &admin,
        CREATE,
        json!({"n": "Hours", "i": [{"key": "nope", "value": "1"}]}),
    );
    assert!(has_error(&bad, "Unknown policy item"), "{bad}");

    let created = gql(
        &client,
        &url,
        &admin,
        CREATE,
        json!({"n": "Hours", "i": [{"key": "require-mfa", "value": "off"}]}),
    );
    let root_id = created["data"]["createPolicy"]["id"].as_i64().expect("id") as i32;
    let dup = gql(
        &client,
        &url,
        &admin,
        CREATE,
        json!({"n": "hours", "i": []}),
    );
    assert!(has_error(&dup, "already exists"), "{dup}");

    let leaf = gql(
        &client,
        &url,
        &admin,
        CREATE,
        json!({"n": "Labs", "i": [{"key": "require-mfa", "value": "always"}]}),
    );
    let leaf_id = leaf["data"]["createPolicy"]["id"].as_i64().expect("leaf") as i32;

    let ou = gql(
        &client,
        &url,
        &admin,
        r#"mutation { createOu(name: "people\labs") { ok } }"#,
        json!({}),
    );
    assert_eq!(ou["data"]["createOu"]["ok"], true, "{ou}");

    assert_eq!(
        gql(&client, &url, &admin, SET, json!({"o": "", "p": root_id}))["data"]["setOuPolicy"]["ok"],
        true
    );
    assert_eq!(
        gql(
            &client,
            &url,
            &admin,
            SET,
            json!({"o": "people\\labs", "p": leaf_id})
        )["data"]["setOuPolicy"]["ok"],
        true
    );

    let effective = gql(
        &client,
        &url,
        &admin,
        EFFECTIVE,
        json!({"o": "people\\labs"}),
    );
    let require = effective["data"]["effectivePolicyItems"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["key"] == "require-mfa")
        .unwrap();
    assert_eq!(require["value"], "always", "{effective}");
    assert_eq!(require["sourceOu"], "people\\labs", "{effective}");
    assert_eq!(require["sourcePolicyName"], "Labs", "{effective}");

    let replace = gql(
        &client,
        &url,
        &admin,
        CREATE,
        json!({"n": "Labs2", "i": [{"key": "require-mfa", "value": "enrolled"}]}),
    );
    let replace_id = replace["data"]["createPolicy"]["id"].as_i64().unwrap() as i32;
    assert_eq!(
        gql(
            &client,
            &url,
            &admin,
            SET,
            json!({"o": "people\\labs", "p": replace_id})
        )["data"]["setOuPolicy"]["ok"],
        true
    );
    let effective = gql(
        &client,
        &url,
        &admin,
        EFFECTIVE,
        json!({"o": "people\\labs"}),
    );
    let require = effective["data"]["effectivePolicyItems"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["key"] == "require-mfa")
        .unwrap();
    assert_eq!(require["value"], "enrolled", "{effective}");

    assert_eq!(
        gql(
            &client,
            &url,
            &admin,
            BLOCK,
            json!({"o": "people\\labs", "b": true})
        )["data"]["setOuPolicyInheritance"]["ok"],
        true
    );
    let states = gql(&client, &url, &admin, STATES, json!({}));
    let leaf_state = states["data"]["ouPolicyStates"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["ou"] == "people\\labs")
        .unwrap();
    assert_eq!(leaf_state["blockInheritance"], true, "{states}");

    let delete_ou = gql(
        &client,
        &url,
        &admin,
        r#"mutation { deleteOu(name: "people\labs") { ok } }"#,
        json!({}),
    );
    assert_eq!(delete_ou["data"]["deleteOu"]["ok"], true, "{delete_ou}");
    let states = gql(&client, &url, &admin, STATES, json!({}));
    assert!(
        states["data"]["ouPolicyStates"]
            .as_array()
            .unwrap()
            .iter()
            .all(|s| s["ou"] != "people\\labs"),
        "{states}"
    );

    gql(
        &client,
        &url,
        &admin,
        DELETE_POLICY,
        json!({"p": replace_id}),
    );
    let listed = gql(&client, &url, &admin, POLICIES, json!({}));
    assert!(
        listed["data"]["policies"]
            .as_array()
            .unwrap()
            .iter()
            .all(|p| p["id"] != replace_id),
        "{listed}"
    );

    let denied = gql(&client, &url, &bob, POLICIES, json!({}));
    assert!(has_error(&denied, "Unauthorized"), "{denied}");

    let settings = settings(&client, &url);
    assert_eq!(settings["domain"], "example.com", "{settings}");

    let logs = gql(&client, &url, &admin, LOGS, json!({}));
    assert!(
        logs["data"]["logs"]
            .as_array()
            .is_some_and(|rows| !rows.is_empty()),
        "{logs}"
    );
}
