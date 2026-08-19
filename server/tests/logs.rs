use crate::common::{
    auth::get_token,
    env,
    fixture::{create_lldap_command, query_i64, spawn_and_wait_healthy},
    graphql::{
        AddUserToGroup, CreateUser, ListGroups, add_user_to_group, create_user, list_groups, post,
    },
};
use ldap3::LdapConn;
use reqwest::blocking::ClientBuilder;
mod common;

fn client() -> reqwest::blocking::Client {
    ClientBuilder::new()
        .connect_timeout(std::time::Duration::from_secs(2))
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .expect("failed to make http client")
}

fn log_rows(db_url: &str, condition: &str) -> i64 {
    query_i64(
        db_url,
        &format!("SELECT COUNT(*) FROM logs WHERE {condition}"),
    )
}

// The whole response body: the log query is also asserted on its errors.
fn gql_raw(
    client: &reqwest::blocking::Client,
    base_url: &str,
    token: &str,
    query: &str,
) -> serde_json::Value {
    client
        .post(format!("{base_url}/api/graphql"))
        .bearer_auth(token)
        .json(&serde_json::json!({"query": query}))
        .send()
        .expect("graphql send")
        .json()
        .expect("graphql json")
}

// The writer lingers a moment before it inserts a batch.
fn wait_for_row(db_url: &str, condition: &str) -> i64 {
    for _ in 0..20 {
        let rows = log_rows(db_url, condition);
        if rows > 0 {
            return rows;
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
    0
}

// Boot, act over HTTP and LDAP, stop: the rows are in the database with their peer,
// survive a restart, and the writer flushes on shutdown.
#[test]
fn test_logs_persist_across_a_restart() {
    let dir = tempfile::TempDir::new().expect("temp dir");
    let db_url = format!("sqlite://{}/users.db?mode=rwc", dir.path().display());
    let command = |sub: &str| create_lldap_command(sub, &db_url);
    let base_dn = env::base_dn();

    {
        let server = spawn_and_wait_healthy(command);
        let client = client();
        let token = get_token(&client, &server.http_url());
        post::<CreateUser>(
            &client,
            &server.http_url(),
            &token,
            create_user::Variables {
                user: create_user::CreateUserInput {
                    id: "logged-user".to_owned(),
                    email: Some("logged-user@example.com".to_owned()),
                    display_name: None,
                    first_name: None,
                    last_name: None,
                    avatar: None,
                    attributes: None,
                },
            },
        )
        .expect("create user");

        // A proxied wrong-password login: the header travels with the row, the peer stays.
        let forwarded = client
            .post(format!("{}/auth/simple/login", server.http_url()))
            .header("X-Forwarded-For", "203.0.113.9, 10.0.0.1")
            .json(&serde_json::json!({"username": "logged-user", "password": "wrong"}))
            .send()
            .expect("login send");
        assert_eq!(forwarded.status(), 401);

        let mut ldap = LdapConn::new(&server.ldap_url()).expect("ldap connection");
        let result = ldap
            .simple_bind(&format!("uid=nobody,ou=people,{base_dn}"), "wrong")
            .expect("bind send");
        assert_eq!(result.rc, 49, "invalid credentials expected: {result:?}");
        let admin_dn = format!("uid={},ou=people,{base_dn}", env::admin_dn());
        ldap.simple_bind(&admin_dn, &env::admin_password())
            .expect("bind send")
            .success()
            .expect("admin bind");
        let _ = ldap.unbind();
        // A second successful admin bind inside the coalescing window: printed, not stored.
        let mut again = LdapConn::new(&server.ldap_url()).expect("ldap connection");
        again
            .simple_bind(&admin_dn, &env::admin_password())
            .expect("bind send")
            .success()
            .expect("admin bind again");
        let _ = again.unbind();

        wait_for_row(&db_url, "kind = 'bind' AND actor = 'nobody'");
        wait_for_row(&db_url, "kind = 'bind' AND actor = 'logged-user'");
        let failed = gql_raw(
            &client,
            &server.http_url(),
            &token,
            r#"{ logs(filter: {kinds: [BIND], success: false, actor: "nobody"}) { id actor peer protocol forwardedFor detail } }"#,
        );
        assert!(failed["errors"].is_null(), "{failed}");
        let row = &failed["data"]["logs"][0];
        assert_eq!(row["actor"], "nobody");
        assert_eq!(row["peer"], "127.0.0.1");
        assert_eq!(row["protocol"], "LDAP");
        assert_eq!(row["detail"], "unknown user");
        assert!(row["forwardedFor"].is_null());

        let summary = gql_raw(
            &client,
            &server.http_url(),
            &token,
            r#"{ logSummary(filter: {kinds: [BIND], success: false}, groupBy: [ACTOR, PROTOCOL]) { actor protocol peer count first last } }"#,
        );
        assert!(summary["errors"].is_null(), "{summary}");
        let buckets = summary["data"]["logSummary"].as_array().expect("buckets");
        assert!(
            buckets.iter().any(|b| b["actor"] == "nobody"
                && b["protocol"] == "LDAP"
                && b["peer"].is_null()
                && b["count"] == 1
                && b["first"] == b["last"]),
            "{summary}"
        );
        assert!(
            buckets
                .iter()
                .any(|b| b["actor"] == "logged-user" && b["protocol"] == "HTTP" && b["count"] == 1),
            "{summary}"
        );

        let activity = gql_raw(
            &client,
            &server.http_url(),
            &token,
            r#"{ logActivity(actor: "nobody") { actor lastSuccess { id } lastFailure { detail peer } failuresSinceLastSuccess } }"#,
        );
        assert!(activity["errors"].is_null(), "{activity}");
        let nobody = &activity["data"]["logActivity"];
        assert_eq!(nobody["actor"], "nobody");
        assert!(nobody["lastSuccess"].is_null());
        assert_eq!(nobody["lastFailure"]["detail"], "unknown user");
        assert_eq!(nobody["lastFailure"]["peer"], "127.0.0.1");
        assert_eq!(nobody["failuresSinceLastSuccess"], 1);
        let admin = gql_raw(
            &client,
            &server.http_url(),
            &token,
            &format!(
                r#"{{ logActivity(actor: "{}") {{ lastSuccess {{ kind }} failuresSinceLastSuccess }} }}"#,
                env::admin_dn()
            ),
        );
        assert_eq!(
            admin["data"]["logActivity"]["lastSuccess"]["kind"], "BIND",
            "{admin}"
        );
        assert_eq!(admin["data"]["logActivity"]["failuresSinceLastSuccess"], 0);

        let tail = gql_raw(
            &client,
            &server.http_url(),
            &token,
            r#"{ logs(afterId: "0", limit: 2) { id } }"#,
        );
        let ids: Vec<i64> = tail["data"]["logs"]
            .as_array()
            .expect("tail rows")
            .iter()
            .map(|r| r["id"].as_str().unwrap().parse().unwrap())
            .collect();
        assert_eq!(ids, vec![1, 2], "{tail}");

        let first = gql_raw(
            &client,
            &server.http_url(),
            &token,
            "{ logs(limit: 1) { id } }",
        );
        let first_id = first["data"]["logs"][0]["id"]
            .as_str()
            .expect("id")
            .to_owned();
        let older = gql_raw(
            &client,
            &server.http_url(),
            &token,
            &format!(r#"{{ logs(limit: 1, beforeId: "{first_id}") {{ id }} }}"#),
        );
        let older_id = older["data"]["logs"][0]["id"].as_str().expect("older id");
        assert!(
            older_id.parse::<i64>().unwrap() < first_id.parse::<i64>().unwrap(),
            "{first_id} then {older_id}"
        );
    }

    assert!(log_rows(&db_url, "kind = 'server_start'") >= 1);
    assert_eq!(
        log_rows(&db_url, "kind = 'admin_bootstrap' AND actor IS NULL"),
        1
    );
    assert_eq!(
        log_rows(
            &db_url,
            "kind = 'user_create' AND target = 'logged-user' AND actor = 'admin' \
             AND protocol = 'graphql' AND peer = '127.0.0.1'"
        ),
        1
    );
    assert_eq!(
        log_rows(
            &db_url,
            "kind = 'bind' AND success = 0 AND actor = 'nobody' AND protocol = 'ldap' \
             AND peer = '127.0.0.1' AND detail = 'unknown user'"
        ),
        1
    );
    assert_eq!(
        log_rows(
            &db_url,
            &format!(
                "kind = 'bind' AND success = 1 AND protocol = 'ldap' AND actor = '{}'",
                env::admin_dn()
            )
        ),
        1,
        "two admin binds inside the coalescing window are stored once"
    );
    assert!(
        log_rows(
            &db_url,
            "kind = 'bind' AND success = 1 AND protocol = 'http'"
        ) >= 1
    );
    assert_eq!(
        log_rows(
            &db_url,
            "kind = 'bind' AND success = 0 AND actor = 'logged-user' AND protocol = 'http'              AND peer = '127.0.0.1' AND forwarded_for = '203.0.113.9, 10.0.0.1'"
        ),
        1
    );
    let before_restart = log_rows(&db_url, "1 = 1");

    {
        let server = spawn_and_wait_healthy(command);
        // The read-only lookup pool serves rows a previous boot wrote.
        let client = client();
        let token = get_token(&client, &server.http_url());
        let oldest = gql_raw(
            &client,
            &server.http_url(),
            &token,
            r#"{ logs(afterId: "0", limit: 1) { id } }"#,
        );
        assert!(oldest["errors"].is_null(), "{oldest}");
        assert_eq!(oldest["data"]["logs"][0]["id"], "1", "{oldest}");
    }
    assert!(log_rows(&db_url, "1 = 1") > before_restart);
    assert!(log_rows(&db_url, "kind = 'server_start'") >= 2);
}

// A unique-name spray stores its first rows one-to-one, opens a bind_flood incident the
// moment it is flagged, and resolves it with the totals on shutdown.
#[test]
fn test_unknown_bind_flood_is_bracketed_by_started_and_resolved() {
    let dir = tempfile::TempDir::new().expect("temp dir");
    let db_url = format!("sqlite://{}/users.db?mode=rwc", dir.path().display());
    let command = |sub: &str| create_lldap_command(sub, &db_url);
    let base_dn = env::base_dn();

    {
        let server = spawn_and_wait_healthy(command);
        let mut ldap = LdapConn::new(&server.ldap_url()).expect("ldap connection");
        for i in 0..12 {
            let result = ldap
                .simple_bind(&format!("uid=flood-{i:02},ou=people,{base_dn}"), "wrong")
                .expect("bind send");
            assert_eq!(result.rc, 49, "attempt {i}: {result:?}");
        }
        let _ = ldap.unbind();
    }

    assert_eq!(
        log_rows(
            &db_url,
            "kind = 'bind' AND success = 0 AND detail = 'unknown user' AND actor LIKE 'flood-%'"
        ),
        8
    );
    assert_eq!(
        log_rows(
            &db_url,
            "kind = 'bind_flood' AND success = 0 AND actor IS NULL AND protocol = 'ldap' \
             AND peer = '127.0.0.1' AND detail = 'unknown-user bind flood started'"
        ),
        1,
        "the incident opens the moment the source is flagged"
    );
    assert_eq!(
        log_rows(
            &db_url,
            "kind = 'bind_flood' AND success = 0 AND actor IS NULL AND protocol = 'ldap' \
             AND peer = '127.0.0.1' \
             AND detail LIKE 'unknown-user bind flood resolved: 4 binds, 4 names, %s'"
        ),
        1,
        "and resolves with the totals and duration"
    );
}

// A junk-JWT flood is recorded (first few one-to-one) and bracketed by an access_denied_flood
// started/resolved pair, so an anonymous spammer is visible without filling the table.
#[test]
fn test_access_denied_flood_is_bracketed_by_started_and_resolved() {
    let dir = tempfile::TempDir::new().expect("temp dir");
    let db_url = format!("sqlite://{}/users.db?mode=rwc", dir.path().display());
    let command = |sub: &str| create_lldap_command(sub, &db_url);

    {
        let server = spawn_and_wait_healthy(command);
        let client = client();
        for _ in 0..12 {
            let junk = client
                .post(format!("{}/api/graphql", server.http_url()))
                .header(reqwest::header::AUTHORIZATION, "Bearer not-a-jwt")
                .json(&serde_json::json!({"query": "query { apiVersion }"}))
                .send()
                .expect("junk bearer");
            assert_eq!(junk.status(), reqwest::StatusCode::UNAUTHORIZED);
        }
    }

    assert_eq!(
        log_rows(
            &db_url,
            "kind = 'access_denied' AND detail = 'Invalid JWT' AND protocol = 'graphql'"
        ),
        8,
        "the first denials are stored one-to-one"
    );
    assert_eq!(
        log_rows(
            &db_url,
            "kind = 'access_denied_flood' AND actor IS NULL AND protocol = 'graphql' \
             AND peer = '127.0.0.1' AND detail = 'access-denied flood started'"
        ),
        1
    );
    assert_eq!(
        log_rows(
            &db_url,
            "kind = 'access_denied_flood' AND protocol = 'graphql' AND peer = '127.0.0.1' \
             AND detail LIKE 'access-denied flood resolved: 4 denials, 1 actors, %s'"
        ),
        1
    );
}

#[test]
fn test_log_persistence_can_be_disabled() {
    let dir = tempfile::TempDir::new().expect("temp dir");
    let db_url = format!("sqlite://{}/users.db?mode=rwc", dir.path().display());
    let command = |sub: &str| {
        let mut cmd = create_lldap_command(sub, &db_url);
        cmd.env("LLDAP_LOG_OPTIONS__PERSIST", "false");
        cmd
    };
    {
        let server = spawn_and_wait_healthy(command);
        get_token(&client(), &server.http_url());
    }
    assert_eq!(log_rows(&db_url, "1 = 1"), 0);
}

#[test]
fn test_junk_and_disabled_jwt_are_recorded_denials() {
    let dir = tempfile::TempDir::new().expect("temp dir");
    let db_url = format!("sqlite://{}/users.db?mode=rwc", dir.path().display());
    let command = |sub: &str| create_lldap_command(sub, &db_url);
    {
        let server = spawn_and_wait_healthy(command);
        let client = client();
        let admin = get_token(&client, &server.http_url());
        let junk = client
            .post(format!("{}/api/graphql", server.http_url()))
            .header(reqwest::header::AUTHORIZATION, "Bearer not-a-jwt")
            .json(&serde_json::json!({"query": "query { apiVersion }"}))
            .send()
            .expect("junk bearer");
        assert_eq!(junk.status(), reqwest::StatusCode::UNAUTHORIZED);

        post::<CreateUser>(
            &client,
            &server.http_url(),
            &admin,
            create_user::Variables {
                user: create_user::CreateUserInput {
                    id: "disabled-logger".to_owned(),
                    email: Some("disabled-logger@example.com".to_owned()),
                    display_name: None,
                    first_name: None,
                    last_name: None,
                    avatar: None,
                    attributes: None,
                },
            },
        )
        .expect("create user");
        let set_pw = client
            .post(format!("{}/api/graphql", server.http_url()))
            .header(reqwest::header::AUTHORIZATION, format!("Bearer {admin}"))
            .json(&serde_json::json!({
                "query": "mutation($id: String!, $password: String!) { setUserPassword(userId: $id, password: $password) { ok } }",
                "variables": { "id": "disabled-logger", "password": "DisabledPass2026!" }
            }))
            .send()
            .expect("setUserPassword")
            .error_for_status()
            .expect("setUserPassword HTTP");
        let set_body: serde_json::Value = set_pw.json().expect("setUserPassword json");
        assert!(
            set_body.get("errors").and_then(|e| e.as_array()).is_none()
                || set_body["errors"].as_array().unwrap().is_empty(),
            "setUserPassword failed: {set_body}"
        );
        let login = client
            .post(format!("{}/auth/simple/login", server.http_url()))
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(
                serde_json::to_string(&lldap_auth::login::ClientSimpleLoginRequest {
                    username: "disabled-logger".into(),
                    password: "DisabledPass2026!".to_owned(),
                })
                .unwrap(),
            )
            .send()
            .expect("login")
            .error_for_status()
            .expect("login HTTP");
        let user_token = serde_json::from_str::<lldap_auth::login::ServerLoginResponse>(
            &login.text().expect("login body"),
        )
        .expect("login json")
        .token;
        let denied = gql_raw(
            &client,
            &server.http_url(),
            &user_token,
            "{ logs(limit: 1) { id } }",
        );
        assert!(
            denied["errors"][0]["message"]
                .as_str()
                .is_some_and(|m| m.contains("Unauthorized to read the logs")),
            "{denied}"
        );

        let groups = post::<ListGroups>(
            &client,
            &server.http_url(),
            &admin,
            list_groups::Variables {},
        )
        .expect("list groups");
        let disabled_id = groups
            .groups
            .iter()
            .find(|g| g.display_name == "lldap_disabled")
            .map(|g| g.id)
            .expect("lldap_disabled");
        post::<AddUserToGroup>(
            &client,
            &server.http_url(),
            &admin,
            add_user_to_group::Variables {
                user: "disabled-logger".to_owned(),
                group: disabled_id,
            },
        )
        .expect("disable user");
        let rejected = client
            .post(format!("{}/api/graphql", server.http_url()))
            .header(
                reqwest::header::AUTHORIZATION,
                format!("Bearer {user_token}"),
            )
            .json(&serde_json::json!({"query": "query { apiVersion }"}))
            .send()
            .expect("disabled jwt");
        assert_eq!(rejected.status(), reqwest::StatusCode::UNAUTHORIZED);
    }
    // Junk JWTs are now recorded (so a spammer is visible), not terminal-only.
    assert_eq!(
        log_rows(&db_url, "kind = 'access_denied' AND detail = 'Invalid JWT'"),
        1
    );
    assert_eq!(
        log_rows(
            &db_url,
            "kind = 'access_denied' AND detail = 'Account disabled' AND actor = 'disabled-logger'"
        ),
        1
    );
    assert_eq!(
        log_rows(
            &db_url,
            "kind = 'access_denied' AND detail = 'Unauthorized to read the logs' \
             AND actor = 'disabled-logger' AND protocol = 'graphql'"
        ),
        1
    );
}
