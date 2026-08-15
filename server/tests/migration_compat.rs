use crate::common::{env, fixture::create_lldap_command_with_key_file};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use nix::{
    sys::signal::{self, Signal},
    unistd::Pid,
};
use reqwest::blocking::{Client, ClientBuilder};
use sea_orm::{ConnectionTrait, Database, DbBackend, Statement};
use serde_json::{Value, json};
use serial_test::file_serial;
use std::process::Child as ChildProcess;
use std::{thread, time::Duration};
mod common;

// A stock lldap 0.6.3 (schema v11) database and server_key, produced by
// scripts/generate_lldap_fixture.sh, boot into KLLDAP, migrate through v12+v13, and keep data
// and passwords intact. The constants mirror fixtures/fixture.md.

const LLDAP_V11_SQL: &str = include_str!("fixtures/lldap_v11.sql");
const SERVER_KEY_B64: &str = include_str!("fixtures/server_key.b64");
const ADMIN_PASS: &str = "FixtureAdminPass2026!";
const BOB_PASS: &str = "FixtureBobPass2026!";
const DATE_EPOCH: i64 = 1714564800; // 2024-05-01T12:00:00Z
const GROUP_NAME: &str = "Fixture Crew";
const GROUP_NOTE: &str = "stock group attribute survives";
const JPEG_B64: &str = "/9j/4AAQSkZJRgABAgAAAQABAAD/wAARCAAEAAQDAREAAhEBAxEB/9sAQwAIBgYHBgUIBwcHCQkICgwUDQwLCwwZEhMPFB0aHx4dGhwcICQuJyAiLCMcHCg3KSwwMTQ0NB8nOT04MjwuMzQy/9sAQwEJCQkMCwwYDQ0YMiEcITIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIy/8QAHwAAAQUBAQEBAQEAAAAAAAAAAAECAwQFBgcICQoL/8QAtRAAAgEDAwIEAwUFBAQAAAF9AQIDAAQRBRIhMUEGE1FhByJxFDKBkaEII0KxwRVS0fAkM2JyggkKFhcYGRolJicoKSo0NTY3ODk6Q0RFRkdISUpTVFVWV1hZWmNkZWZnaGlqc3R1dnd4eXqDhIWGh4iJipKTlJWWl5iZmqKjpKWmp6ipqrKztLW2t7i5usLDxMXGx8jJytLT1NXW19jZ2uHi4+Tl5ufo6erx8vP09fb3+Pn6/8QAHwEAAwEBAQEBAQEBAQAAAAAAAAECAwQFBgcICQoL/8QAtREAAgECBAQDBAcFBAQAAQJ3AAECAxEEBSExBhJBUQdhcRMiMoEIFEKRobHBCSMzUvAVYnLRChYkNOEl8RcYGRomJygpKjU2Nzg5OkNERUZHSElKU1RVVldYWVpjZGVmZ2hpanN0dXZ3eHl6goOEhYaHiImKkpOUlZaXmJmaoqOkpaanqKmqsrO0tba3uLm6wsPExcbHyMnK0tPU1dbX2Nna4uPk5ebn6Onq8vP09fb3+Pn6/9oADAMBAAIRAxEAPwDa8KW8f9gQfLXLmGT4T279093NKkvrMj//2Q==";

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime")
}

// The dump's transaction markers are skipped; each statement runs in autocommit.
fn load_fixture_dump(db_url: &str) {
    runtime().block_on(async {
        let mut opts = sea_orm::ConnectOptions::new(db_url.to_owned());
        opts.max_connections(1);
        let db = Database::connect(opts).await.expect("connect fixture db");
        db.execute(Statement::from_string(
            DbBackend::Sqlite,
            "PRAGMA foreign_keys = OFF;",
        ))
        .await
        .expect("disable foreign keys for load");
        let mut statement = String::new();
        for line in LLDAP_V11_SQL.lines() {
            if statement.is_empty()
                && (line.starts_with("--")
                    || line == "BEGIN TRANSACTION;"
                    || line == "COMMIT;"
                    || line.trim().is_empty())
            {
                continue;
            }
            statement.push_str(line);
            statement.push('\n');
            if line.trim_end().ends_with(';') {
                db.execute(Statement::from_string(DbBackend::Sqlite, statement.clone()))
                    .await
                    .unwrap_or_else(|e| panic!("fixture statement failed: {e}\n{statement}"));
                statement.clear();
            }
        }
        assert!(statement.trim().is_empty(), "trailing partial statement");
    });
}

fn query_optional_bytes(db_url: &str, sql: &str) -> Option<Vec<u8>> {
    runtime().block_on(async {
        let db = Database::connect(db_url).await.expect("connect db");
        let row = db
            .query_one(Statement::from_string(DbBackend::Sqlite, sql.to_owned()))
            .await
            .expect("query")
            .expect("no row");
        row.try_get_by_index::<Option<Vec<u8>>>(0).expect("column")
    })
}

fn query_i64(db_url: &str, sql: &str) -> i64 {
    runtime().block_on(async {
        let db = Database::connect(db_url).await.expect("connect db");
        let row = db
            .query_one(Statement::from_string(DbBackend::Sqlite, sql.to_owned()))
            .await
            .expect("query")
            .expect("no row");
        row.try_get_by_index::<i64>(0).expect("column")
    })
}

struct FixtureFiles {
    db_path: std::path::PathBuf,
    key_path: std::path::PathBuf,
}

impl Drop for FixtureFiles {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.db_path);
        let _ = std::fs::remove_file(&self.key_path);
    }
}

struct ServerGuard {
    child: ChildProcess,
}

impl Drop for ServerGuard {
    fn drop(&mut self) {
        let _ = signal::kill(
            Pid::from_raw(self.child.id().try_into().unwrap()),
            Signal::SIGTERM,
        );
        for _ in 0..12 {
            if let Ok(Some(_)) = self.child.try_wait() {
                return;
            }
            thread::sleep(Duration::from_millis(1000));
        }
        let _ = self.child.kill();
    }
}

fn spawn_and_wait_healthy(db_url: &str, key_file: &str) -> ServerGuard {
    let child = create_lldap_command_with_key_file("run", db_url, key_file)
        .spawn()
        .expect("unable to start server");
    let guard = ServerGuard { child };
    for _ in 0..30 {
        let healthy = create_lldap_command_with_key_file("healthcheck", db_url, key_file)
            .status()
            .expect("healthcheck failed to execute")
            .success();
        if healthy {
            return guard;
        }
        thread::sleep(Duration::from_millis(1000));
    }
    panic!("migrated server did not become healthy");
}

fn make_client() -> Client {
    ClientBuilder::new()
        .connect_timeout(std::time::Duration::from_secs(2))
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .expect("failed to make http client")
}

fn simple_login(client: &Client, username: &str, password: &str) -> reqwest::blocking::Response {
    client
        .post(format!("{}/auth/simple/login", env::http_url()))
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(json!({"username": username, "password": password}).to_string())
        .send()
        .expect("login send failed")
}

fn login_token(client: &Client, username: &str, password: &str) -> String {
    let body: Value = simple_login(client, username, password)
        .error_for_status()
        .unwrap_or_else(|e| panic!("login as {username} failed: {e}"))
        .json()
        .expect("login response not json");
    body["token"].as_str().expect("no token").to_string()
}

fn gql(client: &Client, token: &str, query: &str, variables: Value) -> Value {
    let body: Value = client
        .post(format!("{}/api/graphql", env::http_url()))
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

fn attribute_values<'a>(attributes: &'a Value, name: &str) -> Option<&'a Value> {
    attributes
        .as_array()
        .expect("attributes not a list")
        .iter()
        .find(|a| a["name"] == name)
        .map(|a| &a["value"])
}

#[test]
#[file_serial]
fn test_stock_lldap_database_migrates_with_data_and_passwords() {
    let run_id = uuid::Uuid::new_v4().simple().to_string();
    let db_path = std::env::temp_dir().join(format!("klldap_migration_{run_id}.db"));
    let key_path = std::env::temp_dir().join(format!("klldap_migration_{run_id}_server_key"));
    let db_url = format!("sqlite://{}?mode=rwc", db_path.display());
    std::fs::write(
        &key_path,
        BASE64
            .decode(SERVER_KEY_B64.trim())
            .expect("server_key.b64 invalid"),
    )
    .expect("write server key");
    let _files = FixtureFiles {
        db_path: db_path.clone(),
        key_path: key_path.clone(),
    };
    let key_file = key_path.to_str().expect("key path utf-8").to_owned();

    load_fixture_dump(&db_url);
    let legacy_bob_hash = query_optional_bytes(
        &db_url,
        "SELECT password_hash FROM users WHERE user_id = 'bob'",
    )
    .expect("bob must have a stock password hash");

    {
        let _server = spawn_and_wait_healthy(&db_url, &key_file);
        let client = make_client();

        // First bind runs the legacy OPAQUE ceremony and transparently re-enrolls;
        // the second must succeed against the re-enrolled current-format hash.
        login_token(&client, "bob", BOB_PASS);
        login_token(&client, "bob", BOB_PASS);
        assert!(
            !simple_login(&client, "bob", "not-the-password")
                .status()
                .is_success(),
            "wrong password must not bind"
        );
        assert!(
            !simple_login(&client, "charlie", "anything")
                .status()
                .is_success(),
            "charlie never had a password"
        );

        let mut ldap = ldap3::LdapConn::new(&env::ldap_url()).expect("ldap connect");
        ldap.simple_bind(&format!("uid=bob,ou=people,{}", env::base_dn()), BOB_PASS)
            .expect("ldap bind send")
            .success()
            .expect("ldap bind as bob must succeed");
        let _ = ldap.unbind();

        let admin_token = login_token(&client, "admin", ADMIN_PASS);
        let user = gql(
            &client,
            &admin_token,
            r#"query($id: String!) { user(userId: $id) {
                displayName
                attributes { name value }
                groups { id displayName }
            } }"#,
            json!({"id": "bob"}),
        );
        let bob = &user["user"];
        assert_eq!(bob["displayName"], "Bob Fixture");
        let attributes = &bob["attributes"];
        assert_eq!(
            attribute_values(attributes, "first_name"),
            None,
            "alias EAV rows must be folded to canonical names"
        );
        assert_eq!(
            attribute_values(attributes, "firstname").expect("firstname"),
            &json!(["Bincode Bob"])
        );
        assert_eq!(
            attribute_values(attributes, "lastname").expect("lastname"),
            &json!(["Fixtureson"])
        );
        assert_eq!(
            attribute_values(attributes, "fixturetags").expect("fixturetags"),
            &json!(["alpha", "beta"])
        );
        assert_eq!(
            attribute_values(attributes, "fixturenumber").expect("fixturenumber"),
            &json!(["4242"])
        );
        assert_eq!(
            attribute_values(attributes, "fixturejpeg").expect("fixturejpeg"),
            &json!([JPEG_B64]),
            "JPEG must survive byte-identical"
        );
        assert_eq!(
            attribute_values(attributes, "avatar").expect("avatar"),
            &json!([JPEG_B64])
        );
        let date = attribute_values(attributes, "fixturedate").expect("fixturedate")[0]
            .as_str()
            .expect("date value")
            .to_owned();
        assert_eq!(
            chrono::DateTime::parse_from_rfc3339(&date)
                .unwrap_or_else(|e| panic!("fixturedate {date:?} not RFC3339: {e}"))
                .timestamp(),
            DATE_EPOCH
        );

        let groups = bob["groups"].as_array().expect("groups");
        let crew = groups
            .iter()
            .find(|g| g["displayName"] == GROUP_NAME)
            .expect("bob must be in the fixture group");
        let crew_details = gql(
            &client,
            &admin_token,
            r#"query($id: Int!) { group(groupId: $id) { attributes { name value } } }"#,
            json!({"id": crew["id"]}),
        );
        assert_eq!(
            attribute_values(&crew_details["group"]["attributes"], "fixturegroupnote")
                .expect("group note"),
            &json!([GROUP_NOTE])
        );

        let schema = gql(
            &client,
            &admin_token,
            r#"{ schema { userSchema { attributes { name attributeType } } } }"#,
            json!({}),
        );
        let schema_attributes = &schema["schema"]["userSchema"]["attributes"];
        let type_of = |name: &str| {
            schema_attributes
                .as_array()
                .expect("schema attributes")
                .iter()
                .find(|a| a["name"] == name)
                .map(|a| a["attributeType"].clone())
        };
        assert_eq!(type_of("first_name"), None, "ghost schema row must be gone");
        assert_eq!(type_of("last_name"), None, "ghost schema row must be gone");
        assert!(type_of("firstname").is_some());
        assert_eq!(
            type_of("fixturejpeg"),
            Some(json!("AVATAR")),
            "custom JpegPhoto attributes must migrate to Avatar"
        );
    }

    // Server is down; byte-level assertions on the migrated database.
    assert_eq!(
        query_i64(&db_url, "SELECT version FROM metadata"),
        13,
        "migration must reach v13"
    );
    let jpeg_bytes = BASE64.decode(JPEG_B64).expect("jpeg b64");
    let eav = |name: &str| {
        query_optional_bytes(
            &db_url,
            &format!(
                "SELECT user_attribute_value FROM user_attributes \
                 WHERE user_attribute_user_id = 'bob' AND user_attribute_name = '{name}'"
            ),
        )
        .unwrap_or_else(|| panic!("bob attribute {name} missing"))
    };
    assert_eq!(
        eav("fixturejpeg"),
        jpeg_bytes,
        "raw JPEG, no bincode prefix"
    );
    assert_eq!(eav("avatar"), jpeg_bytes);
    assert_eq!(eav("fixturedate"), b"1714564800");
    assert_eq!(eav("fixturetags"), br#"["alpha","beta"]"#);
    assert_eq!(eav("fixturenumber"), b"4242");
    assert_eq!(eav("firstname"), b"Bincode Bob");
    assert_eq!(
        query_optional_bytes(
            &db_url,
            "SELECT group_attribute_value FROM group_attributes \
             WHERE group_attribute_name = 'fixturegroupnote'",
        )
        .expect("group note missing"),
        GROUP_NOTE.as_bytes()
    );
    let upgraded_bob_hash = query_optional_bytes(
        &db_url,
        "SELECT password_hash FROM users WHERE user_id = 'bob'",
    )
    .expect("bob hash after migration");
    assert_ne!(
        upgraded_bob_hash, legacy_bob_hash,
        "first bind must re-enroll the password in the current format"
    );
    assert_eq!(
        query_optional_bytes(
            &db_url,
            "SELECT password_hash FROM users WHERE user_id = 'charlie'",
        ),
        None,
        "charlie must remain passwordless"
    );
}
