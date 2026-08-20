use crate::common::{
    auth::{get_token, get_token_for, opaque_login, register_password_over_http},
    env,
    fixture::{LLDAPFixture, User, create_lldap_command, exec_sql, spawn_and_wait_healthy},
};
use ldap3::LdapConn;
use lldap_mfa::MFA_ENROLLMENT_REQUIRED;
use reqwest::StatusCode;
use reqwest::blocking::{Client, ClientBuilder};
use serde_json::{Value, json};
mod common;

const START: &str = "mutation($c: String) { startMfaEnrollment(currentCode: $c) { otpauthUri secretBase32 state } }";
const FINISH: &str =
    "mutation($s: String!, $c: String!) { finishMfaEnrollment(state: $s, code: $c) { ok } }";
const RESET_OWN: &str = "mutation($c: String!) { resetOwnMfa(code: $c) { ok } }";
const RESET_USER: &str = "mutation($u: String!) { resetUserMfa(userId: $u) { ok } }";
const USERS: &str = "{ users { id } }";

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

fn create_user(client: &Client, base_url: &str, admin_token: &str, user: &str) {
    let body = gql(
        client,
        base_url,
        admin_token,
        "mutation($u: CreateUserInput!) { createUser(user: $u) { id } }",
        json!({"u": {"id": user, "email": format!("{user}@example.com")}}),
    );
    assert_eq!(body["data"]["createUser"]["id"], user, "{body}");
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

fn simple_login(
    client: &Client,
    base_url: &str,
    user: &str,
    password: &str,
) -> (StatusCode, String) {
    let response = client
        .post(format!("{base_url}/auth/simple/login"))
        .json(&json!({"username": user, "password": password}))
        .send()
        .expect("simple login send");
    (
        response.status(),
        response.text().expect("simple login body"),
    )
}

fn ldap_bind(ldap_url: &str, user: &str, password: &str) -> (u32, String) {
    let mut ldap = LdapConn::new(ldap_url).expect("ldap connection");
    let result = ldap
        .simple_bind(
            &format!("uid={user},ou=people,{}", env::base_dn()),
            password,
        )
        .expect("bind send");
    let _ = ldap.unbind();
    (result.rc, result.text)
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

// Enrolls with the current step's code and returns the secret; the neighbouring step's
// code is the first one the doors accept afterwards.
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

fn has_row(rows: &[Value], actor: &str, kind: &str, success: bool, detail: Option<&str>) -> bool {
    rows.iter().any(|r| {
        r["actor"] == actor
            && r["kind"] == kind
            && r["success"] == success
            && r["detail"] == detail.map_or(Value::Null, Value::from)
    })
}

// The writer lingers before it inserts a batch: poll until every expected row is visible.
fn wait_for_rows(
    client: &Client,
    base_url: &str,
    admin_token: &str,
    kinds: &str,
    expected: &[(&str, &str, bool, Option<&str>)],
) {
    let query = format!(
        "{{ logs(filter: {{kinds: [{kinds}]}}, limit: 500) {{ actor kind success detail }} }}"
    );
    let mut rows = Vec::new();
    for _ in 0..40 {
        let body = gql(client, base_url, admin_token, &query, json!({}));
        assert!(body["errors"].is_null(), "{body}");
        rows = body["data"]["logs"].as_array().cloned().unwrap_or_default();
        if expected
            .iter()
            .all(|(actor, kind, success, detail)| has_row(&rows, actor, kind, *success, *detail))
        {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
    for (actor, kind, success, detail) in expected {
        assert!(
            has_row(&rows, actor, kind, *success, *detail),
            "{actor} {kind} {success} {detail:?} missing from {rows:?}"
        );
    }
}

fn server_with_env(
    db_url: &str,
    extra_env: &[(&str, &str)],
) -> crate::common::fixture::ServerGuard {
    spawn_and_wait_healthy(|sub| {
        let mut command = create_lldap_command(sub, db_url);
        command.envs(extra_env.iter().copied());
        command
    })
}

#[test]
fn test_mfa_disabled_keeps_plain_binds() {
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

    // The suffix is never split: a trailing :digits is part of the password.
    assert_eq!(ldap_bind(&fixture.ldap_url(), "bob", "bobpass").0, 0);
    let (rc, text) = ldap_bind(&fixture.ldap_url(), "bob", "bobpass:123456");
    assert_eq!((rc, text.as_str()), (49, ""));
    let (status, body) = opaque_login(&client, &url, "bob", "bobpass", Some("123456"));
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body["token"].is_string(), "{body}");
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

    wait_for_rows(
        &client,
        &url,
        &admin,
        "MFA_ENROLL, MFA_RESET",
        &[
            ("bob", "MFA_ENROLL", true, Some("started")),
            ("bob", "MFA_ENROLL", false, Some("invalid code")),
            ("bob", "MFA_ENROLL", true, Some("totp")),
            ("bob", "MFA_RESET", true, Some("self")),
            ("admin", "MFA_RESET", true, None),
        ],
    );
}

// One enrolled user per door: each enrollment spends the current step's code and each
// door check the neighbouring one, so the ±1-step budget is never exceeded.
#[test]
fn test_mfa_enrollment_and_doors() {
    let mut fixture = LLDAPFixture::new_with_env(&[("LLDAP_ENABLE_MFA", "true")]);
    let users = ["bob", "eve", "kim", "sam"];
    fixture.load_state(&users.iter().map(|u| User::new(u, vec![])).collect());
    let client = client();
    let url = fixture.http_url();
    let ldap_url = fixture.ldap_url();
    let admin = get_token(&client, &url);
    for user in users {
        set_password(&client, &url, &admin, user, &format!("{user}pass"));
    }
    add_to_group(&client, &url, &admin, "sam", "lldap_mfa_disabled");
    let token_for = |user: &str| get_token_for(&client, &url, user, &format!("{user}pass"));
    let (bob, eve, kim, sam) = (
        token_for("bob"),
        token_for("eve"),
        token_for("kim"),
        token_for("sam"),
    );

    // LDAP simple bind: the diagnostic only after the password verified.
    let secret = enroll(&client, &url, &bob);
    let (rc, text) = ldap_bind(&ldap_url, "bob", "bobpass");
    assert_eq!(
        (rc, text.as_str()),
        (49, "TOTP code required: append ':' and the code")
    );
    let (rc, text) = ldap_bind(
        &ldap_url,
        "bob",
        &format!("bobpass:{}", wrong_code(&secret)),
    );
    assert_eq!((rc, text.as_str()), (49, ""));
    let (rc, text) = ldap_bind(
        &ldap_url,
        "bob",
        &format!("wrong:{}", fresh_codes(&secret).1),
    );
    assert_eq!((rc, text.as_str()), (49, ""));
    let (_, next) = fresh_codes(&secret);
    assert_eq!(ldap_bind(&ldap_url, "bob", &format!("bobpass:{next}")).0, 0);
    let (rc, text) = ldap_bind(&ldap_url, "bob", &format!("bobpass:{next}"));
    assert_eq!(
        (rc, text.as_str()),
        (49, "TOTP code already used, wait for the next one")
    );

    // Simple login: the same combined format.
    let secret = enroll(&client, &url, &eve);
    let (status, text) = simple_login(&client, &url, "eve", "evepass");
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{text}");
    assert!(text.contains("TOTP code required"), "{text}");
    let (_, next) = fresh_codes(&secret);
    let (status, text) = simple_login(&client, &url, "eve", &format!("evepass:{next}"));
    assert_eq!(status, StatusCode::OK, "{text}");

    // Web login: the code rides the OPAQUE finish; without it the server challenges.
    let secret = enroll(&client, &url, &kim);
    let (status, body) = opaque_login(&client, &url, "kim", "kimpass", None);
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body, json!({"mfaRequired": true}));
    let (status, body) = opaque_login(&client, &url, "kim", "kimpass", Some(&wrong_code(&secret)));
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    let (_, next) = fresh_codes(&secret);
    let (status, body) = opaque_login(&client, &url, "kim", "kimpass", Some(&next));
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        body["token"].is_string() && body["refreshToken"].is_string(),
        "{body}"
    );
    assert!(body.get("mfaEnrollmentRequired").is_none(), "{body}");

    // An exempt member binds with the password alone even when enrolled.
    enroll(&client, &url, &sam);
    assert_eq!(ldap_bind(&ldap_url, "sam", "sampass").0, 0);
    let (status, _) = simple_login(&client, &url, "sam", "sampass");
    assert_eq!(status, StatusCode::OK);

    wait_for_rows(
        &client,
        &url,
        &admin,
        "BIND, LOGIN",
        &[
            ("bob", "BIND", false, Some("invalid totp")),
            ("bob", "BIND", false, Some("invalid credentials")),
            ("bob", "BIND", true, Some("totp")),
            ("bob", "BIND", false, Some("totp replayed")),
            // Eve's second success falls in the coalescing window of her first: one row.
            ("kim", "LOGIN", false, Some("invalid totp")),
            ("kim", "LOGIN", true, Some("totp")),
            ("sam", "BIND", true, None),
        ],
    );
}

#[test]
fn test_mfa_always_gates_api_and_doors() {
    let dir = tempfile::TempDir::new().expect("temp dir");
    let db_url = format!("sqlite://{}/users.db?mode=rwc", dir.path().display());
    let server = server_with_env(&db_url, &[("LLDAP_ENABLE_MFA", "always")]);
    let client = client();
    let url = server.http_url();
    let admin_name = env::admin_dn();
    let admin_pass = env::admin_password();

    let settings = settings(&client, &url);
    assert_eq!(settings["mfa_required"], true, "{settings}");

    // The web login admits an unenrolled user, flagged; the other doors refuse them.
    let (status, body) = opaque_login(&client, &url, &admin_name, &admin_pass, None);
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["mfaEnrollmentRequired"], true, "{body}");
    let admin = body["token"].as_str().expect("token").to_owned();
    let refresh_token = body["refreshToken"]
        .as_str()
        .expect("refresh token")
        .to_owned();
    let (status, text) = simple_login(&client, &url, &admin_name, &admin_pass);
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{text}");
    assert!(text.contains("MFA enrollment required"), "{text}");
    let (rc, text) = ldap_bind(&server.ldap_url(), &admin_name, &admin_pass);
    assert_eq!((rc, text.as_str()), (49, MFA_ENROLLMENT_REQUIRED));
    let refreshed: Value = client
        .get(format!("{url}/auth/refresh"))
        .header("refresh-token", &refresh_token)
        .send()
        .expect("refresh send")
        .json()
        .expect("refresh json");
    assert_eq!(refreshed["mfaEnrollmentRequired"], true, "{refreshed}");

    // The API is confined to read-self and enrollment until the factor is in place.
    let body = gql(&client, &url, &admin, USERS, json!({}));
    assert!(has_error(&body, "Unauthorized"), "{body}");
    assert_eq!(mfa_enrolled(&client, &url, &admin, &admin_name), false);
    let secret = enroll(&client, &url, &admin);
    let body = gql(&client, &url, &admin, USERS, json!({}));
    assert!(body["errors"].is_null(), "{body}");
    assert!(
        body["data"]["users"]
            .as_array()
            .is_some_and(|users| !users.is_empty())
    );
    assert_eq!(mfa_enrolled(&client, &url, &admin, &admin_name), true);
    let (_, next) = fresh_codes(&secret);
    assert_eq!(
        ldap_bind(
            &server.ldap_url(),
            &admin_name,
            &format!("{admin_pass}:{next}")
        )
        .0,
        0
    );
    let refreshed: Value = client
        .get(format!("{url}/auth/refresh"))
        .header("refresh-token", &refresh_token)
        .send()
        .expect("refresh send")
        .json()
        .expect("refresh json");
    assert!(
        refreshed.get("mfaEnrollmentRequired").is_none(),
        "{refreshed}"
    );

    let body = gql(&client, &url, &admin, RESET_USER, json!({"u": admin_name}));
    assert!(has_error(&body, "Cannot reset your own MFA"), "{body}");
}

#[test]
fn test_password_reset_clears_mfa() {
    let dir = tempfile::TempDir::new().expect("temp dir");
    let db_url = format!("sqlite://{}/users.db?mode=rwc", dir.path().display());
    let server = server_with_env(
        &db_url,
        &[
            ("LLDAP_ENABLE_MFA", "true"),
            ("LLDAP_SMTP_OPTIONS__ENABLE_PASSWORD_RESET", "true"),
        ],
    );
    let client = client();
    let url = server.http_url();
    let admin = get_token(&client, &url);
    create_user(&client, &url, &admin, "bob");
    set_password(&client, &url, &admin, "bob", "bobpass");
    let bob = get_token_for(&client, &url, "bob", "bobpass");
    enroll(&client, &url, &bob);

    // An ordinary password change is not a recovery: the factor stays.
    set_password(&client, &url, &admin, "bob", "bobpass2");
    assert_eq!(mfa_enrolled(&client, &url, &admin, "bob"), true);

    // A consumed reset link then a committed new password clears it.
    exec_sql(
        &db_url,
        "INSERT INTO password_reset_tokens (token, user_id, expiry_date) VALUES ('reset-token', 'bob', '2099-01-01 00:00:00')",
    );
    let reset: Value = client
        .get(format!("{url}/auth/reset/step2/reset-token"))
        .send()
        .expect("reset step2 send")
        .error_for_status()
        .expect("reset step2 status")
        .json()
        .expect("reset step2 json");
    let reset_jwt = reset["token"].as_str().expect("reset jwt");
    register_password_over_http(&client, &url, reset_jwt, "bob", "bobpass3");
    assert_eq!(mfa_enrolled(&client, &url, &admin, "bob"), false);
    assert_eq!(ldap_bind(&server.ldap_url(), "bob", "bobpass3").0, 0);
    wait_for_rows(
        &client,
        &url,
        &admin,
        "MFA_RESET",
        &[("bob", "MFA_RESET", true, Some("password reset"))],
    );
}
