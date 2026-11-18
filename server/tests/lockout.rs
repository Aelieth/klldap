use crate::common::{
    auth::{get_token, opaque_login},
    fixture::{LLDAPFixture, User, create_lldap_command, query_i64},
};
use lldap_auth::{login, opaque, types::UserId};
use reqwest::blocking::{Client, ClientBuilder};
use serde_json::{Value, json};
mod common;

const USER: &str = "lockweb";
const RIGHT: &str = "LockWebPass2026!";

fn client() -> Client {
    ClientBuilder::new()
        .connect_timeout(std::time::Duration::from_secs(2))
        .timeout(std::time::Duration::from_secs(10))
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

fn failed_login_rows(db_url: &str) -> i64 {
    query_i64(
        db_url,
        &format!(
            "SELECT COUNT(*) FROM logs WHERE kind = 'login' AND actor = '{USER}' AND NOT success"
        ),
    )
}

fn settled_rows(db_url: &str, want: i64) -> i64 {
    let mut rows = failed_login_rows(db_url);
    for _ in 0..20 {
        if rows >= want {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
        rows = failed_login_rows(db_url);
    }
    rows
}

fn login_start(
    client: &Client,
    base_url: &str,
    password: &str,
) -> (
    opaque::client::login::ClientLogin,
    login::ServerLoginStartResponse,
) {
    let mut rng = rand::rngs::OsRng;
    let start = opaque::client::login::start_login(password, &mut rng).expect("login start");
    let response = client
        .post(format!("{base_url}/auth/opaque/login/start"))
        .json(&login::ClientLoginStartRequest {
            username: UserId::new(USER),
            login_start_request: start.message,
        })
        .send()
        .expect("login start send")
        .error_for_status()
        .expect("login start status")
        .json()
        .expect("login start json");
    (start.state, response)
}

// As the web app does: a wrong password fails in the client, which then sends no finish.
fn wrong_like_the_app(client: &Client, base_url: &str, password: &str) -> bool {
    let (state, response) = login_start(client, base_url, password);
    let mut rng = rand::rngs::OsRng;
    opaque::client::login::finish_login(
        state,
        password.as_bytes(),
        response.credential_response,
        &mut rng,
    )
    .is_err()
}

// A finish that reaches the server and fails there: one session's finalization sent with another session's state.
fn failing_finish(client: &Client, base_url: &str) -> reqwest::StatusCode {
    let mut rng = rand::rngs::OsRng;
    let (first, first_response) = login_start(client, base_url, RIGHT);
    let finalization = opaque::client::login::finish_login(
        first,
        RIGHT.as_bytes(),
        first_response.credential_response,
        &mut rng,
    )
    .expect("the right password finishes in the client")
    .message;
    let (_, second_response) = login_start(client, base_url, RIGHT);
    client
        .post(format!("{base_url}/auth/opaque/login/finish"))
        .json(&login::ClientLoginFinishRequest {
            server_data: second_response.server_data,
            credential_finalization: finalization,
            totp_code: None,
            enrollment_proof: None,
            session: None,
        })
        .send()
        .expect("login finish send")
        .status()
}

#[test]
fn test_lockout_facts_at_web_login() {
    let mut fixture = LLDAPFixture::new();
    fixture.load_state(&vec![User::new(USER, vec![])]);
    let client = client();
    let url = fixture.http_url();
    let admin = get_token(&client, &url);
    let set = gql(
        &client,
        &url,
        &admin,
        r#"mutation($id: String!, $pw: String!) { setUserPassword(userId: $id, password: $pw) { ok } }"#,
        json!({"id": USER, "pw": RIGHT}),
    );
    assert_eq!(set["data"]["setUserPassword"]["ok"], true, "{set}");
    let db = fixture.db_url().to_owned();

    let mut report = Vec::new();
    let stopped = (0..50)
        .filter(|i| wrong_like_the_app(&client, &url, &format!("wrong-{i}")))
        .count();
    assert_eq!(
        stopped, 50,
        "a wrong password must fail in the OPAQUE client"
    );
    let app_rows = settled_rows(&db, 1);
    report.push(format!(
        "L1.web-app: 50 wrong passwords as the web app sends them: {app_rows} failure rows | when enforced: each one counts"
    ));
    if app_rows != 50 {
        report.push(format!(
            "FINDING L1.web-app-rows: the server wrote {app_rows} rows for 50 wrong web logins; it never sees a wrong OPAQUE password unless the client sends a finish"
        ));
    }

    for _ in 0..10 {
        let status = failing_finish(&client, &url);
        assert!(
            !status.is_success(),
            "a mismatched finish must fail, got {status}"
        );
    }
    let forged_rows = settled_rows(&db, app_rows + 10) - app_rows;
    report.push(format!(
        "L1.web-finish: 10 finishes that fail at the server: {forged_rows} failure rows | when enforced: each one counts"
    ));
    if forged_rows != 10 {
        report.push(format!(
            "FINDING L1.web-finish-rows: {forged_rows} rows for 10 failed finishes"
        ));
    }

    let (status, body) = opaque_login(&client, &url, USER, RIGHT, None);
    let allowed = status.is_success() && body["token"].is_string();
    report.push(format!(
        "L1.web-right: the right password after 60 failures: today {} | when enforced: refused while locked",
        if allowed { "allowed" } else { "REFUSED" }
    ));
    let path = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("l1-web-login.txt");
    std::fs::write(&path, report.join("\n") + "\n").expect("write the L1 report");
    println!("L1 rows: {}", path.display());
    assert_eq!(
        app_rows, 0,
        "today a wrong password typed in the web app never reaches the server"
    );
    assert_eq!(
        forged_rows, 10,
        "today each failed finish writes one failure row"
    );
    assert!(
        allowed,
        "today the right password still logs in after 60 failures: {status} {body}"
    );
}

const LOCKED: &str = "e1lock";

fn simple_status(client: &Client, base_url: &str, password: &str) -> u16 {
    client
        .post(format!("{base_url}/auth/simple/login"))
        .json(&login::ClientSimpleLoginRequest {
            username: UserId::new(LOCKED),
            password: password.to_owned(),
            enrollment_proof: None,
        })
        .send()
        .expect("simple login send")
        .status()
        .as_u16()
}

// The start is answered either way; a locked user's, like a wrong password's, cannot finish.
fn web_finishes_in_the_client(client: &Client, base_url: &str, password: &str) -> bool {
    let mut rng = rand::rngs::OsRng;
    let start = opaque::client::login::start_login(password, &mut rng).expect("login start");
    let response: login::ServerLoginStartResponse = client
        .post(format!("{base_url}/auth/opaque/login/start"))
        .json(&login::ClientLoginStartRequest {
            username: UserId::new(LOCKED),
            login_start_request: start.message,
        })
        .send()
        .expect("login start send")
        .error_for_status()
        .expect("login start status")
        .json()
        .expect("login start json");
    opaque::client::login::finish_login(
        start.state,
        password.as_bytes(),
        response.credential_response,
        &mut rng,
    )
    .is_ok()
}

#[test]
fn test_a_threshold_locks_each_directory_door_and_each_unlock_releases() {
    let fixture = LLDAPFixture::new();
    let client = client();
    let url = fixture.http_url();
    let admin = get_token(&client, &url);
    let ok = |query: &str, variables: Value, field: &str| {
        let answer = gql(&client, &url, &admin, query, variables);
        assert!(answer["errors"].is_null(), "{field}: {answer}");
        answer["data"][field].clone()
    };
    ok(
        "mutation($n: String!) { createOu(name: $n) { ok } }",
        json!({"n": LOCKED}),
        "createOu",
    );
    ok(
        "mutation($u: CreateUserInput!) { createUser(user: $u) { id } }",
        json!({"u": {"id": LOCKED, "email": "e1lock@example.com"}}),
        "createUser",
    );
    ok(
        "mutation($id: String!, $pw: String!) { setUserPassword(userId: $id, password: $pw) { ok } }",
        json!({"id": LOCKED, "pw": RIGHT}),
        "setUserPassword",
    );
    ok(
        "mutation($ids: [String!]!, $ou: String!) { changeUserOu(userIds: $ids, newOu: $ou) { ok } }",
        json!({"ids": [LOCKED], "ou": LOCKED}),
        "changeUserOu",
    );
    let policy = ok(
        "mutation($n: String!, $i: [PolicyItemInput!]) { createPolicy(name: $n, items: $i) { id } }",
        json!({"n": "e1 lock", "i": [
            {"key": "lockout-threshold", "value": "3"},
            {"key": "lockout-duration-seconds", "value": "0"},
        ]}),
        "createPolicy",
    );
    ok(
        "mutation($o: String!, $p: Int!) { setOuPolicy(ou: $o, policyId: $p) { ok } }",
        json!({"o": LOCKED, "p": policy["id"]}),
        "setOuPolicy",
    );

    let wrong: Vec<u16> = (0..3)
        .map(|i| simple_status(&client, &url, &format!("wrong-{i}")))
        .collect();
    assert_eq!(wrong, [401; 3]);
    assert_eq!(simple_status(&client, &url, RIGHT), 401, "locked at 3");
    let tool = create_lldap_command("unlock", fixture.db_url())
        .arg(LOCKED)
        .output()
        .expect("lldap unlock");
    let said = String::from_utf8_lossy(&tool.stdout);
    assert!(
        tool.status.success() && said.contains("Unlocked e1lock"),
        "{said}"
    );
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while simple_status(&client, &url, RIGHT) != 200 {
        assert!(
            std::time::Instant::now() < deadline,
            "a bind reads the row the tool wrote"
        );
        std::thread::sleep(std::time::Duration::from_millis(250));
    }

    for i in 0..3 {
        assert!(!web_finishes_in_the_client(
            &client,
            &url,
            &format!("wrong-{i}")
        ));
    }
    assert!(
        !web_finishes_in_the_client(&client, &url, RIGHT),
        "a locked user's start is answered as an unknown name's"
    );
    ok(
        "mutation($u: String!) { unlockUser(userId: $u) { ok } }",
        json!({"u": LOCKED}),
        "unlockUser",
    );
    let (status, body) = opaque_login(&client, &url, LOCKED, RIGHT, None);
    assert!(
        status.is_success() && body["token"].is_string(),
        "{status} {body}"
    );
    let unlocks = |detail: &str| {
        query_i64(
            fixture.db_url(),
            &format!(
                "SELECT COUNT(*) FROM logs WHERE kind = 'account_unlock' \
                 AND target = '{LOCKED}' AND detail = '{detail}'"
            ),
        )
    };
    assert_eq!((unlocks("lldap unlock"), unlocks("unlockUser")), (1, 1));
}
