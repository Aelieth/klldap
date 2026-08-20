use crate::common::{
    auth::{get_token, get_token_for},
    fixture::{LLDAPFixture, User},
};
use reqwest::blocking::{Client, ClientBuilder};
use serde_json::{Value, json};
mod common;

const START: &str = "mutation($c: String) { startMfaEnrollment(currentCode: $c) { otpauthUri secretBase32 state } }";
const FINISH: &str =
    "mutation($s: String!, $c: String!) { finishMfaEnrollment(state: $s, code: $c) { ok } }";
const RESET_OWN: &str = "mutation($c: String!) { resetOwnMfa(code: $c) { ok } }";
const RESET_USER: &str = "mutation($u: String!) { resetUserMfa(userId: $u) { ok } }";
const USERS: &str = "{ users { id } }";
const MFA_LOGS: &str =
    "{ logs(filter: {kinds: [MFA_ENROLL, MFA_RESET]}) { actor kind success detail } }";

fn client() -> Client {
    ClientBuilder::new()
        .connect_timeout(std::time::Duration::from_secs(2))
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .expect("failed to make http client")
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

fn set_password(client: &Client, base_url: &str, admin_token: &str, user: &str, password: &str) {
    let body = gql(
        client,
        base_url,
        admin_token,
        "mutation($id: String!, $password: String!) { setUserPassword(userId: $id, password: $password) { ok } }",
        json!({"id": user, "password": password}),
    );
    assert_eq!(body["data"]["setUserPassword"]["ok"], true, "{body}");
}

fn add_to_group(client: &Client, base_url: &str, admin_token: &str, user: &str, group: &str) {
    let groups = gql(
        client,
        base_url,
        admin_token,
        "{ groups { id displayName } }",
        json!({}),
    );
    let group_id = groups["data"]["groups"]
        .as_array()
        .expect("groups")
        .iter()
        .find(|g| g["displayName"] == group)
        .map(|g| g["id"].clone())
        .unwrap_or_else(|| panic!("{group} exists at boot: {groups}"));
    let body = gql(
        client,
        base_url,
        admin_token,
        "mutation($u: String!, $g: Int!) { addUserToGroup(userId: $u, groupId: $g) { ok } }",
        json!({"u": user, "g": group_id}),
    );
    assert_eq!(body["data"]["addUserToGroup"]["ok"], true, "{body}");
}

fn mfa_enrolled(client: &Client, base_url: &str, token: &str, user: &str) -> Value {
    let body = gql(
        client,
        base_url,
        token,
        "query($id: String!) { user(userId: $id) { mfaEnrolled } }",
        json!({"id": user}),
    );
    assert!(body["errors"].is_null(), "{body}");
    body["data"]["user"]["mfaEnrolled"].clone()
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn code_at(secret_base32: &str, unix: u64) -> String {
    let seed = lldap_mfa::seed_from_base32(secret_base32).expect("base32 secret");
    lldap_mfa::format_code(lldap_mfa::totp_code(&seed, unix).unwrap())
}

// The current step's code and a different one from a neighbouring step, both accepted now.
fn fresh_codes(secret_base32: &str) -> (String, String) {
    let now = unix_now();
    let current = code_at(secret_base32, now);
    let next = [now + 30, now - 30]
        .iter()
        .map(|t| code_at(secret_base32, *t))
        .find(|c| *c != current)
        .unwrap();
    (current, next)
}

fn wrong_code(secret_base32: &str) -> String {
    let now = unix_now();
    let valid: Vec<String> = [now - 30, now, now + 30]
        .iter()
        .map(|t| code_at(secret_base32, *t))
        .collect();
    (0..)
        .map(|c| format!("{c:06}"))
        .find(|c| !valid.contains(c))
        .unwrap()
}

fn start_enrollment(
    client: &Client,
    base_url: &str,
    token: &str,
    current_code: Option<&str>,
) -> Value {
    gql(client, base_url, token, START, json!({"c": current_code}))
}

fn enroll(client: &Client, base_url: &str, token: &str) -> String {
    let body = start_enrollment(client, base_url, token, None);
    let start = &body["data"]["startMfaEnrollment"];
    let secret = start["secretBase32"]
        .as_str()
        .unwrap_or_else(|| panic!("{body}"))
        .to_owned();
    let (current, _) = fresh_codes(&secret);
    let body = gql(
        client,
        base_url,
        token,
        FINISH,
        json!({"s": start["state"], "c": current}),
    );
    assert_eq!(body["data"]["finishMfaEnrollment"]["ok"], true, "{body}");
    secret
}

// The writer lingers before it inserts a batch: poll until the rows are visible.
fn wait_for_mfa_logs(
    client: &Client,
    base_url: &str,
    admin_token: &str,
    min_rows: usize,
) -> Vec<Value> {
    for _ in 0..40 {
        let body = gql(client, base_url, admin_token, MFA_LOGS, json!({}));
        assert!(body["errors"].is_null(), "{body}");
        let rows = body["data"]["logs"].as_array().cloned().unwrap_or_default();
        if rows.len() >= min_rows {
            return rows;
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
    panic!("fewer than {min_rows} mfa log rows appeared");
}

fn has_row(rows: &[Value], actor: &str, kind: &str, success: bool, detail: Option<&str>) -> bool {
    rows.iter().any(|r| {
        r["actor"] == actor
            && r["kind"] == kind
            && r["success"] == success
            && r["detail"] == detail.map_or(Value::Null, Value::from)
    })
}

#[test]
fn test_mfa_disabled_refuses_enrollment() {
    let mut fixture = LLDAPFixture::new();
    fixture.load_state(&vec![User::new("bob", vec![])]);
    let client = client();
    let url = fixture.http_url();
    let admin = get_token(&client, &url);
    set_password(&client, &url, &admin, "bob", "bobpass");
    let bob = get_token_for(&client, &url, "bob", "bobpass");

    let settings = settings(&client, &url);
    assert_eq!(settings["mfa_enabled"], false, "{settings}");
    assert_eq!(settings["mfa_required"], false, "{settings}");

    let body = start_enrollment(&client, &url, &bob, None);
    assert!(has_error(&body, "MFA is disabled"), "{body}");
    let body = gql(&client, &url, &admin, RESET_USER, json!({"u": "bob"}));
    assert_eq!(body["data"]["resetUserMfa"]["ok"], true, "{body}");
}

#[test]
fn test_mfa_enrollment_over_graphql() {
    let mut fixture = LLDAPFixture::new_with_env(&[("LLDAP_ENABLE_MFA", "true")]);
    fixture.load_state(&vec![User::new("bob", vec![]), User::new("eve", vec![])]);
    let client = client();
    let url = fixture.http_url();
    let admin = get_token(&client, &url);
    set_password(&client, &url, &admin, "bob", "bobpass");
    set_password(&client, &url, &admin, "eve", "evepass");
    add_to_group(&client, &url, &admin, "eve", "lldap_strict_readonly");
    let bob = get_token_for(&client, &url, "bob", "bobpass");
    let eve = get_token_for(&client, &url, "eve", "evepass");

    let settings = settings(&client, &url);
    assert_eq!(settings["mfa_enabled"], true, "{settings}");
    assert_eq!(settings["mfa_required"], false, "{settings}");

    let body = start_enrollment(&client, &url, &bob, None);
    let start = body["data"]["startMfaEnrollment"].clone();
    let uri = start["otpauthUri"]
        .as_str()
        .unwrap_or_else(|| panic!("{body}"));
    let secret = start["secretBase32"].as_str().unwrap().to_owned();
    let state = start["state"].as_str().unwrap().to_owned();
    assert!(uri.starts_with("otpauth://totp/KLLDAP:bob?"), "{uri}");
    assert!(uri.contains(&secret), "{uri}");

    let body = gql(
        &client,
        &url,
        &bob,
        FINISH,
        json!({"s": state, "c": wrong_code(&secret)}),
    );
    assert!(has_error(&body, "Invalid TOTP code"), "{body}");
    assert_eq!(mfa_enrolled(&client, &url, &bob, "bob"), false);

    let (current, next) = fresh_codes(&secret);
    let body = gql(
        &client,
        &url,
        &bob,
        FINISH,
        json!({"s": state, "c": current}),
    );
    assert_eq!(body["data"]["finishMfaEnrollment"]["ok"], true, "{body}");
    assert_eq!(mfa_enrolled(&client, &url, &bob, "bob"), true);
    assert_eq!(mfa_enrolled(&client, &url, &admin, "bob"), true);
    assert_eq!(mfa_enrolled(&client, &url, &eve, "bob"), Value::Null);

    let body = start_enrollment(&client, &url, &bob, None);
    assert!(has_error(&body, "Current TOTP code required"), "{body}");

    let body = gql(&client, &url, &bob, RESET_OWN, json!({"c": next}));
    assert_eq!(body["data"]["resetOwnMfa"]["ok"], true, "{body}");
    assert_eq!(mfa_enrolled(&client, &url, &bob, "bob"), false);

    enroll(&client, &url, &bob);
    assert_eq!(mfa_enrolled(&client, &url, &admin, "bob"), true);
    let body = gql(&client, &url, &admin, RESET_USER, json!({"u": "bob"}));
    assert_eq!(body["data"]["resetUserMfa"]["ok"], true, "{body}");
    assert_eq!(mfa_enrolled(&client, &url, &bob, "bob"), false);

    let rows = wait_for_mfa_logs(&client, &url, &admin, 7);
    for (actor, kind, success, detail) in [
        ("bob", "MFA_ENROLL", true, Some("started")),
        ("bob", "MFA_ENROLL", false, Some("invalid code")),
        ("bob", "MFA_ENROLL", true, Some("totp")),
        ("bob", "MFA_RESET", true, Some("self")),
        ("admin", "MFA_RESET", true, None),
    ] {
        assert!(
            has_row(&rows, actor, kind, success, detail),
            "{actor} {kind} {success} {detail:?} missing from {rows:?}"
        );
    }
}

#[test]
fn test_mfa_always_confines_api_until_enrolled() {
    let fixture = LLDAPFixture::new_with_env(&[("LLDAP_ENABLE_MFA", "always")]);
    let client = client();
    let url = fixture.http_url();
    let admin = get_token(&client, &url);

    let settings = settings(&client, &url);
    assert_eq!(settings["mfa_enabled"], true, "{settings}");
    assert_eq!(settings["mfa_required"], true, "{settings}");

    let body = gql(&client, &url, &admin, USERS, json!({}));
    assert!(has_error(&body, "Unauthorized"), "{body}");
    assert_eq!(mfa_enrolled(&client, &url, &admin, "admin"), false);

    enroll(&client, &url, &admin);
    let body = gql(&client, &url, &admin, USERS, json!({}));
    assert!(body["errors"].is_null(), "{body}");
    assert!(
        body["data"]["users"]
            .as_array()
            .is_some_and(|users| !users.is_empty())
    );
    assert_eq!(mfa_enrolled(&client, &url, &admin, "admin"), true);

    let body = gql(&client, &url, &admin, RESET_USER, json!({"u": "admin"}));
    assert!(has_error(&body, "Cannot reset your own MFA"), "{body}");
}
