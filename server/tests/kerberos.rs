use crate::common::{
    auth::{get_token, get_token_for, register_sealed, register_start_status},
    env,
    fixture::{LLDAPFixture, exec_sql, free_port, query_i64},
};
use ldap3::LdapConn;
use lldap_auth::kerberos_envelope::seal_kerberos_envelope;
use reqwest::StatusCode;
use reqwest::blocking::{Client, ClientBuilder};
use serde_json::{Value, json};
use std::io::Write;
use std::net::UdpSocket;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant, SystemTime};

mod common;

const REALM: &str = "EXAMPLE.COM";
const USER: &str = "livebob";
const FIRST: &str = "LivebobPass2026!";
const SECOND: &str = "LivebobNext2026!";
const HOST: &str = "kc.test";

struct KrbClient {
    config: PathBuf,
    ccache: PathBuf,
}

impl KrbClient {
    fn command(&self, program: &str) -> Command {
        if !self.config.is_file() {
            panic!(
                "refusing to run {program}: Kerberos client config {} does not exist yet",
                self.config.display()
            );
        }
        let mut cmd = Command::new(program);
        cmd.env("KRB5_CONFIG", &self.config);
        cmd.env("KRB5CCNAME", format!("FILE:{}", self.ccache.display()));
        cmd.env_remove("KRB5_KTNAME");
        cmd.env_remove("KRB5_CLIENT_KTNAME");
        cmd.env_remove("KRB5_TRACE");
        cmd.stdin(Stdio::piped());
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());
        cmd
    }

    fn run(&self, program: &str, args: &[&str], password: Option<&str>) -> Output {
        let mut child = self
            .command(program)
            .args(args)
            .spawn()
            .unwrap_or_else(|err| panic!("{program} failed to execute: {err}"));
        if let Some(password) = password {
            let mut stdin = child.stdin.take().expect("stdin");
            stdin
                .write_all(format!("{password}\n").as_bytes())
                .unwrap_or_else(|err| panic!("write to {program}: {err}"));
        }
        child
            .wait_with_output()
            .unwrap_or_else(|err| panic!("{program} failed to execute: {err}"))
    }
}

fn output_text(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn expect_ok(output: &Output, what: &str) {
    assert!(
        output.status.success(),
        "{what} failed ({:?}): {}",
        output.status,
        output_text(output)
    );
}

fn expect_fail(output: &Output, what: &str) {
    assert!(
        !output.status.success(),
        "{what} succeeded but should have failed: {}",
        output_text(output)
    );
}

fn client() -> Client {
    ClientBuilder::new()
        .connect_timeout(Duration::from_secs(3))
        .timeout(Duration::from_secs(20))
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

fn group_id(client: &Client, base_url: &str, token: &str, name: &str) -> i64 {
    let body = gql(
        client,
        base_url,
        token,
        "{ groups { id displayName } }",
        json!({}),
    );
    body["data"]["groups"]
        .as_array()
        .unwrap_or_else(|| panic!("groups: {body}"))
        .iter()
        .find(|group| group["displayName"] == name)
        .unwrap_or_else(|| panic!("{name} missing: {body}"))["id"]
        .as_i64()
        .unwrap_or_else(|| panic!("{name} id: {body}"))
}

fn kinit(krb: &KrbClient, password: &str) -> Output {
    krb.run("kinit", &["-r", "1d", USER], Some(password))
}

fn kinit_user(krb: &KrbClient, user: &str, password: &str) -> Output {
    krb.run("kinit", &["-r", "1d", user], Some(password))
}

struct Realm {
    _dir: tempfile::TempDir,
    fixture: LLDAPFixture,
    krb: KrbClient,
    admin_keytab: PathBuf,
    keycloak_keytab: PathBuf,
    client_config: PathBuf,
    data_dir: PathBuf,
    kdc_port: u16,
}

fn start_realm(capture_log: bool) -> Realm {
    start_realm_at(capture_log, false, free_port())
}

fn start_realm_at(capture_log: bool, answering: bool, kdc_port: u16) -> Realm {
    start_realm_seeded(capture_log, answering, kdc_port, &[], |_| {})
}

fn start_realm_seeded(
    capture_log: bool,
    answering: bool,
    kdc_port: u16,
    extra_env: &[(&str, &str)],
    seed: impl FnOnce(&Path),
) -> Realm {
    let realm_dir = tempfile::TempDir::new().expect("realm dir");
    let kadmin_port = free_port();
    let data_dir = realm_dir.path().join("data");
    let admin_keytab = realm_dir.path().join("kadm5.keytab");
    let keycloak_keytab = realm_dir.path().join("keycloak-http.keytab");
    let client_config = realm_dir.path().join("krb5.conf");
    let ccache = realm_dir.path().join("cc");
    let kdc_port_s = kdc_port.to_string();
    let kadmin_port_s = kadmin_port.to_string();
    let data_dir_s = data_dir.display().to_string();
    let admin_keytab_s = admin_keytab.display().to_string();
    let keycloak_keytab_s = keycloak_keytab.display().to_string();
    let client_config_s = client_config.display().to_string();
    let mut env = vec![
        ("LLDAP_KERBEROS_OPTIONS__KDC_HOST", "127.0.0.1"),
        ("LLDAP_KERBEROS_OPTIONS__KDC_PORT", kdc_port_s.as_str()),
        ("LLDAP_KERBEROS_OPTIONS__KADMIN_HOST", "127.0.0.1"),
        (
            "LLDAP_KERBEROS_OPTIONS__KADMIN_PORT",
            kadmin_port_s.as_str(),
        ),
        ("LLDAP_KERBEROS_OPTIONS__DATA_DIR", data_dir_s.as_str()),
        (
            "LLDAP_KERBEROS_OPTIONS__ADMIN_KEYTAB",
            admin_keytab_s.as_str(),
        ),
        ("LLDAP_KEYCLOAK_OPTIONS__KEYTAB", keycloak_keytab_s.as_str()),
        (
            "LLDAP_KERBEROS_OPTIONS__CLIENT_CONFIG",
            client_config_s.as_str(),
        ),
    ];
    env.extend_from_slice(extra_env);
    seed(&data_dir);
    let fixture = if answering {
        LLDAPFixture::new_with_env_answering(&env)
    } else if capture_log {
        LLDAPFixture::new_with_env_logged(&env)
    } else {
        LLDAPFixture::new_with_env(&env)
    };
    let krb = KrbClient {
        config: client_config.clone(),
        ccache,
    };
    Realm {
        _dir: realm_dir,
        fixture,
        krb,
        admin_keytab,
        keycloak_keytab,
        client_config,
        data_dir,
        kdc_port,
    }
}

fn expect_revoked(output: &Output, what: &str) {
    expect_fail(output, what);
    let text = output_text(output);
    assert!(
        text.contains("credentials have been revoked"),
        "{what}: {text}"
    );
}

fn assert_log_line(fixture: &LLDAPFixture, line: &str) {
    let log = fixture.server_log();
    assert!(log.contains(line), "missing {line}\n{log}");
}

#[test]
fn kerberos_lifecycle() {
    let mut realm = start_realm(false);
    let http = client();
    let base = realm.fixture.http_url();
    let mut token = get_token(&http, &base);
    let krb = KrbClient {
        config: realm.krb.config.clone(),
        ccache: realm.krb.ccache.clone(),
    };
    let admin_keytab_s = realm.admin_keytab.display().to_string();
    let keycloak_keytab_s = realm.keycloak_keytab.display().to_string();
    let client_config = realm.client_config.clone();

    let created = gql(
        &http,
        &base,
        &token,
        "mutation($u: CreateUserInput!) { createUser(user: $u) { id } }",
        json!({"u": {
            "id": USER,
            "email": "livebob@example.com",
            "attributes": [{"name": "kerberossync", "value": ["1"]}]
        }}),
    );
    assert_eq!(created["data"]["createUser"]["id"], USER, "{created}");

    let set = gql(
        &http,
        &base,
        &token,
        "mutation($id: String!, $password: String!) { setUserPassword(userId: $id, password: $password) { ok } }",
        json!({"id": USER, "password": FIRST}),
    );
    assert_eq!(set["data"]["setUserPassword"]["ok"], true, "{set}");

    let started = Instant::now();
    let first_kinit = kinit(&krb, FIRST);
    let round_trip = started.elapsed();
    expect_ok(&first_kinit, "kinit");
    eprintln!("kinit round-trip: {round_trip:?}");

    let listed = krb.run("klist", &["-f"], None);
    expect_ok(&listed, "klist -f");
    let flags = output_text(&listed);
    let flags_line = flags
        .lines()
        .find(|line| line.contains("Flags:"))
        .unwrap_or("");
    assert!(flags_line.contains('R'), "renewable flag missing: {flags}");

    let princ = krb.run(
        "kadmin",
        &[
            "-k",
            "-t",
            admin_keytab_s.as_str(),
            "-p",
            "admin/admin",
            "-q",
            "getprinc livebob",
        ],
        None,
    );
    expect_ok(&princ, "getprinc livebob");
    assert!(
        output_text(&princ).contains("REQUIRES_PRE_AUTH"),
        "{}",
        output_text(&princ)
    );

    let disabled = group_id(&http, &base, &token, "lldap_disabled");
    let added = gql(
        &http,
        &base,
        &token,
        "mutation($u: String!, $g: Int!) { addUserToGroup(userId: $u, groupId: $g) { ok } }",
        json!({"u": USER, "g": disabled}),
    );
    assert_eq!(added["data"]["addUserToGroup"]["ok"], true, "{added}");
    expect_fail(&kinit(&krb, FIRST), "kinit while disabled");

    let removed = gql(
        &http,
        &base,
        &token,
        "mutation($u: String!, $g: Int!) { removeUserFromGroup(userId: $u, groupId: $g) { ok } }",
        json!({"u": USER, "g": disabled}),
    );
    assert_eq!(
        removed["data"]["removeUserFromGroup"]["ok"], true,
        "{removed}"
    );
    expect_ok(&kinit(&krb, FIRST), "kinit after leaving lldap_disabled");

    let rotated = gql(
        &http,
        &base,
        &token,
        "mutation($id: String!, $password: String!) { setUserPassword(userId: $id, password: $password) { ok } }",
        json!({"id": USER, "password": SECOND}),
    );
    assert_eq!(rotated["data"]["setUserPassword"]["ok"], true, "{rotated}");
    expect_fail(&kinit(&krb, FIRST), "kinit with the old password");
    expect_ok(&kinit(&krb, SECOND), "kinit with the new password");

    let keytab_before = std::fs::metadata(&admin_keytab_s)
        .expect("admin keytab")
        .modified()
        .unwrap_or(SystemTime::UNIX_EPOCH);
    std::thread::sleep(Duration::from_secs(1));
    realm.fixture.restart();
    token = get_token(&http, &base);
    expect_ok(&kinit(&krb, SECOND), "kinit after restart");
    let keytab_after = std::fs::metadata(&admin_keytab_s)
        .expect("admin keytab after restart")
        .modified()
        .unwrap_or(SystemTime::UNIX_EPOCH);
    assert!(
        keytab_after > keytab_before,
        "admin keytab was not rewritten"
    );

    let off = gql(
        &http,
        &base,
        &token,
        "mutation($user: UpdateUserInput!) { updateUser(user: $user) { ok } }",
        json!({"user": {"id": USER, "insertAttributes": [{"name": "kerberossync", "value": ["0"]}]}}),
    );
    assert_eq!(off["data"]["updateUser"]["ok"], true, "{off}");
    let not_found = kinit(&krb, SECOND);
    expect_fail(&not_found, "kinit after sync off");
    assert!(
        output_text(&not_found).contains("not found"),
        "{}",
        output_text(&not_found)
    );
    let on = gql(
        &http,
        &base,
        &token,
        "mutation($user: UpdateUserInput!) { updateUser(user: $user) { ok } }",
        json!({"user": {"id": USER, "insertAttributes": [{"name": "kerberossync", "value": ["1"]}]}}),
    );
    assert_eq!(on["data"]["updateUser"]["ok"], true, "{on}");
    let again = gql(
        &http,
        &base,
        &token,
        "mutation($id: String!, $password: String!) { setUserPassword(userId: $id, password: $password) { ok } }",
        json!({"id": USER, "password": SECOND}),
    );
    assert_eq!(again["data"]["setUserPassword"]["ok"], true, "{again}");
    expect_ok(
        &kinit(&krb, SECOND),
        "kinit after sync on and a new password",
    );

    let deleted = gql(
        &http,
        &base,
        &token,
        "mutation($id: String!) { deleteUser(userId: $id) { ok } }",
        json!({"id": USER}),
    );
    assert_eq!(deleted["data"]["deleteUser"]["ok"], true, "{deleted}");
    let gone = krb.run(
        "kadmin",
        &[
            "-k",
            "-t",
            admin_keytab_s.as_str(),
            "-p",
            "admin/admin",
            "-q",
            "getprinc livebob",
        ],
        None,
    );
    let gone_text = output_text(&gone).to_ascii_lowercase();
    assert!(
        gone_text.contains("not exist") || gone_text.contains("no such"),
        "{gone_text}"
    );

    let exported = gql(
        &http,
        &base,
        &token,
        "mutation($h: String!) { exportKeytabForKeycloak(hostname: $h) { ok path errorMsg } }",
        json!({"h": HOST}),
    );
    assert_eq!(
        exported["data"]["exportKeytabForKeycloak"]["ok"], true,
        "{exported}"
    );
    let listed_keytab = krb.run("klist", &["-kt", keycloak_keytab_s.as_str()], None);
    expect_ok(&listed_keytab, "klist -kt");
    let principal = format!("HTTP/{HOST}@{REALM}");
    assert_eq!(
        output_text(&listed_keytab)
            .matches(principal.as_str())
            .count(),
        1,
        "{}",
        output_text(&listed_keytab)
    );
    assert!(Path::new(&client_config).is_file());
}

#[test]
fn kerberos_disabled_ticket() {
    const BOB: &str = "bob";
    const PASS: &str = "BobSmoke-2026!";
    const SERVICE_HOST: &str = "kc.example.com";
    let principal = format!("{BOB}@{REALM}");
    let service = format!("HTTP/{SERVICE_HOST}@{REALM}");
    let realm = start_realm(true);
    let http = client();
    let base = realm.fixture.http_url();
    let token = get_token(&http, &base);
    let krb = &realm.krb;

    let created = gql(
        &http,
        &base,
        &token,
        "mutation($u: CreateUserInput!) { createUser(user: $u) { id } }",
        json!({"u": {
            "id": BOB,
            "email": "bob@example.com",
            "attributes": [{"name": "kerberossync", "value": ["1"]}]
        }}),
    );
    assert_eq!(created["data"]["createUser"]["id"], BOB, "{created}");
    let set = gql(
        &http,
        &base,
        &token,
        "mutation($id: String!, $password: String!) { setUserPassword(userId: $id, password: $password) { ok } }",
        json!({"id": BOB, "password": PASS}),
    );
    assert_eq!(set["data"]["setUserPassword"]["ok"], true, "{set}");
    let exported = gql(
        &http,
        &base,
        &token,
        "mutation($h: String!) { exportKeytabForKeycloak(hostname: $h) { ok path errorMsg } }",
        json!({"h": SERVICE_HOST}),
    );
    assert_eq!(
        exported["data"]["exportKeytabForKeycloak"]["ok"], true,
        "{exported}"
    );

    expect_ok(&kinit_user(krb, BOB, PASS), "kinit bob");
    expect_ok(&krb.run("kvno", &[service.as_str()], None), "control kvno");
    expect_ok(&krb.run("kinit", &["-R"], None), "control kinit -R");

    let disabled = group_id(&http, &base, &token, "lldap_disabled");
    let added = gql(
        &http,
        &base,
        &token,
        "mutation($u: String!, $g: Int!) { addUserToGroup(userId: $u, groupId: $g) { ok } }",
        json!({"u": BOB, "g": disabled}),
    );
    assert_eq!(added["data"]["addUserToGroup"]["ok"], true, "{added}");
    expect_revoked(&krb.run("kvno", &[service.as_str()], None), "disabled kvno");
    expect_revoked(&krb.run("kinit", &["-R"], None), "disabled kinit -R");
    let listed = krb.run("klist", &[], None);
    expect_ok(&listed, "klist while disabled");
    assert!(
        output_text(&listed).contains(&format!("krbtgt/{REALM}@{REALM}")),
        "{}",
        output_text(&listed)
    );
    assert_log_line(
        &realm.fixture,
        &format!("Refused a Kerberos ticket request from {principal}: the principal is disabled"),
    );

    let removed = gql(
        &http,
        &base,
        &token,
        "mutation($u: String!, $g: Int!) { removeUserFromGroup(userId: $u, groupId: $g) { ok } }",
        json!({"u": BOB, "g": disabled}),
    );
    assert_eq!(
        removed["data"]["removeUserFromGroup"]["ok"], true,
        "{removed}"
    );
    expect_ok(&krb.run("kvno", &[service.as_str()], None), "enabled kvno");
    expect_ok(&krb.run("kinit", &["-R"], None), "enabled kinit -R");

    let deleted = gql(
        &http,
        &base,
        &token,
        "mutation($id: String!) { deleteUser(userId: $id) { ok } }",
        json!({"id": BOB}),
    );
    assert_eq!(deleted["data"]["deleteUser"]["ok"], true, "{deleted}");
    expect_revoked(&krb.run("kvno", &[service.as_str()], None), "deleted kvno");
    expect_revoked(&krb.run("kinit", &["-R"], None), "deleted kinit -R");
    let listed = krb.run("klist", &[], None);
    expect_ok(&listed, "klist after delete");
    assert!(
        output_text(&listed).contains(&format!("krbtgt/{REALM}@{REALM}")),
        "{}",
        output_text(&listed)
    );
    let gone = || {
        query_i64(
            realm.fixture.db_url(),
            "SELECT COUNT(*) FROM logs WHERE kind = 'access_denied' AND target LIKE 'bob%' \
             AND detail = 'the principal is gone'",
        )
    };
    let landed = (0..50).any(|_| {
        std::thread::sleep(std::time::Duration::from_millis(100));
        gone() >= 1
    });
    assert!(landed, "no access_denied row for the gone principal");
}

fn login(http: &Client, base: &str, username: &str, password: &str) -> (StatusCode, String) {
    let response = http
        .post(format!("{base}/auth/simple/login"))
        .json(&json!({"username": username, "password": password}))
        .send()
        .expect("login send");
    let status = response.status();
    let body = response.text().expect("login body");
    (status, body)
}

fn health(http: &Client, base: &str) -> (StatusCode, Value) {
    let response = http
        .get(format!("{base}/health"))
        .send()
        .expect("health send");
    let status = response.status();
    (status, response.json().expect("health body"))
}

const ON_REALM_FAILURE: &str = "LLDAP_KERBEROS_OPTIONS__ON_REALM_FAILURE";
const NOT_OPEN: &str = "the Kerberos realm did not open; the server log has the cause";

/// The body of `/health` for a realm that did not open: the state, and no path or count.
fn closed(state: &str) -> Value {
    json!({"kerberos": state, "cause": NOT_OPEN})
}

fn ready() -> (StatusCode, Value) {
    (StatusCode::OK, json!({"kerberos": "ready"}))
}

fn user_with_password(http: &Client, base: &str, user: &str, sync: &str, password: &str) {
    let token = get_token(http, base);
    let created = gql(
        http,
        base,
        &token,
        "mutation($u: CreateUserInput!) { createUser(user: $u) { id } }",
        json!({"u": {
            "id": user,
            "email": format!("{user}@example.com"),
            "attributes": [{"name": "kerberossync", "value": [sync]}]
        }}),
    );
    assert_eq!(created["data"]["createUser"]["id"], user, "{created}");
    let set = gql(
        http,
        base,
        &token,
        "mutation($id: String!, $password: String!) { setUserPassword(userId: $id, password: $password) { ok } }",
        json!({"id": user, "password": password}),
    );
    assert_eq!(set["data"]["setUserPassword"]["ok"], true, "{set}");
}

fn bind_rc(url: &str, username: &str, password: &str) -> u32 {
    let mut ldap = LdapConn::new(url).expect("ldap connection");
    let dn = format!("uid={username},ou=people,{}", env::base_dn());
    let result = ldap.simple_bind(&dn, password).expect("bind send");
    let rc = result.rc;
    let _ = ldap.unbind();
    rc
}

fn hold_kdc(port: u16) -> UdpSocket {
    UdpSocket::bind(("127.0.0.1", port)).unwrap_or_else(|err| panic!("hold KDC port {port}: {err}"))
}

#[test]
fn kerberos_closed_realm_admin_only() {
    const BOB: &str = "bob";
    const PASS: &str = "BobSmoke-2026!";
    let admin_only = [(ON_REALM_FAILURE, "admin-only")];
    let mut realm = start_realm_seeded(true, false, free_port(), &admin_only, |_| {});
    let http = client();
    let base = realm.fixture.http_url();
    let token = get_token(&http, &base);
    user_with_password(&http, &base, BOB, "0", PASS);
    let bob_token = get_token_for(&http, &base, BOB, PASS);
    let kdc_port = realm.kdc_port;
    let ldap_url = realm.fixture.ldap_url();

    let holder = realm.fixture.restart_after(|| hold_kdc(kdc_port));
    let down = (StatusCode::SERVICE_UNAVAILABLE, closed("admin-only"));
    assert_eq!(health(&http, &base), down);
    assert_log_line(
        &realm.fixture,
        "Only admins may sign in, over LDAP on 127.0.0.1 and HTTP on 127.0.0.1",
    );

    let check = realm.fixture.healthcheck_output(false);
    let check_text = output_text(&check);
    assert!(
        !check.status.success(),
        "healthcheck succeeded: {check_text}"
    );
    assert!(
        check_text.contains(&format!(
            "503 Service Unavailable: Kerberos is admin-only: {NOT_OPEN}"
        )),
        "{check_text}"
    );

    let admin = env::admin_dn();
    let admin_pass = env::admin_password();
    let (status, body) = login(&http, &base, &admin, &admin_pass);
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(bind_rc(&ldap_url, &admin, &admin_pass), 0);
    assert_eq!(bind_rc(&ldap_url, &admin, "wrong"), 49);

    let (status, body) = login(&http, &base, BOB, PASS);
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(bind_rc(&ldap_url, BOB, PASS), 52);
    let (status, body) = login(&http, &base, BOB, "wrong");
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(bind_rc(&ldap_url, BOB, "wrong"), 49);

    let old = http
        .post(format!("{base}/api/graphql"))
        .bearer_auth(&bob_token)
        .json(&json!({"query": "{ user(userId: \"bob\") { id } }", "variables": {}}))
        .send()
        .expect("graphql send");
    assert_eq!(old.status(), StatusCode::SERVICE_UNAVAILABLE, "{old:?}");

    let write = http
        .post(format!("{base}/api/graphql"))
        .bearer_auth(&token)
        .json(&json!({
            "query": "mutation($u: CreateUserInput!) { createUser(user: $u) { id } }",
            "variables": {"u": {"id": "carol", "email": "carol@example.com"}}
        }))
        .send()
        .expect("createUser send");
    let write_status = write.status();
    let write_body = write.text().expect("createUser body");
    assert!(
        write_body.contains("did not open"),
        "status {write_status}: {write_body}"
    );

    drop(holder);
    realm.fixture.restart();
    assert_eq!(health(&http, &base), ready());
    let (status, body) = login(&http, &base, BOB, PASS);
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(bind_rc(&ldap_url, BOB, PASS), 0);

    let fresh_port = free_port();
    let fresh_holder = hold_kdc(fresh_port);
    let fresh = start_realm_seeded(false, true, fresh_port, &admin_only, |_| {});
    let fresh_http = client();
    let fresh_base = fresh.fixture.http_url();
    assert_eq!(health(&fresh_http, &fresh_base), down);
    let (status, body) = login(&fresh_http, &fresh_base, &admin, &admin_pass);
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(bind_rc(&fresh.fixture.ldap_url(), &admin, &admin_pass), 0);
    drop(fresh);
    drop(fresh_holder);
}

#[test]
fn kerberos_closed_realm_directory_only() {
    use ldap3::exop::PasswordModify;
    const BOB: &str = "bob";
    const SUE: &str = "sue";
    const PASS: &str = "BobSmoke-2026!";
    const NEXT: &str = "BobNext-2026!";
    let mut realm = start_realm(true);
    let http = client();
    let base = realm.fixture.http_url();
    user_with_password(&http, &base, BOB, "0", PASS);
    user_with_password(&http, &base, SUE, "1", PASS);
    let kdc_port = realm.kdc_port;
    let ldap_url = realm.fixture.ldap_url();

    let holder = realm.fixture.restart_after(|| hold_kdc(kdc_port));
    let serving = (StatusCode::OK, closed("directory-only"));
    assert_eq!(health(&http, &base), serving);
    assert_log_line(
        &realm.fixture,
        "the directory is served to everyone, over LDAP on 0.0.0.0 and HTTP on 0.0.0.0",
    );
    let plain = realm.fixture.healthcheck_output(false);
    expect_ok(&plain, "the plain healthcheck of a directory-only server");
    let flagged = realm.fixture.healthcheck_output(true);
    expect_fail(&flagged, "healthcheck --kerberos with the realm closed");
    let flagged = output_text(&flagged);
    assert!(
        flagged.contains(
            "--kerberos passes only a ready Kerberos realm, and this server's is directory-only"
        ),
        "{flagged}"
    );

    let (status, body) = login(&http, &base, BOB, PASS);
    assert_eq!(status, StatusCode::OK, "an ordinary user signs in: {body}");
    assert_eq!(
        (
            bind_rc(&ldap_url, BOB, PASS),
            bind_rc(&ldap_url, BOB, "wrong")
        ),
        (0, 49)
    );

    let token = get_token(&http, &base);
    let (key, status, body) = register_sealed(&http, &base, &token, BOB, NEXT, |_, _| None);
    assert_eq!(
        (key, status),
        (None, StatusCode::OK),
        "a user without sync changes a password: {body}"
    );
    assert_eq!(
        (bind_rc(&ldap_url, BOB, NEXT), bind_rc(&ldap_url, BOB, PASS)),
        (0, 49)
    );

    let (status, body) = register_start_status(&http, &base, &token, SUE, NEXT);
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    let base_dn = env::base_dn();
    let mut ldap = LdapConn::new(&ldap_url).expect("ldap connection");
    ldap.simple_bind(
        &format!("uid={},ou=people,{base_dn}", env::admin_dn()),
        &env::admin_password(),
    )
    .expect("bind send")
    .success()
    .expect("admin bind");
    let modified = ldap
        .extended(PasswordModify {
            user_id: Some(&format!("uid={SUE},ou=people,{base_dn}")),
            old_pass: None,
            new_pass: Some(NEXT),
        })
        .expect("password modify send");
    let _ = ldap.unbind();
    assert_eq!(
        (
            modified.1.rc,
            bind_rc(&ldap_url, SUE, PASS),
            bind_rc(&ldap_url, SUE, NEXT)
        ),
        (52, 0, 49),
        "a synced user's password stays as it was: {}",
        modified.1.text
    );

    drop(holder);
    realm.fixture.restart();
    assert_eq!(health(&http, &base), ready());
    expect_ok(
        &kinit_user(&realm.krb, SUE, PASS),
        "kinit with the password from before, once the realm is open again",
    );

    let fresh_port = free_port();
    let fresh_holder = hold_kdc(fresh_port);
    let fresh = start_realm_at(false, true, fresh_port);
    let fresh_health = health(&client(), &fresh.fixture.http_url());
    assert_eq!(
        fresh_health, serving,
        "a first start made the realm before the KDC's port failed: it holds the realm's row"
    );
    drop(fresh);
    drop(fresh_holder);
}

fn seed_0_7_2_realm(data_dir: &Path) {
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/krb5kdc");
    std::fs::create_dir_all(data_dir).expect("data dir");
    for name in [".k5.LIVEBOB.TEST", "principal.dump"] {
        std::fs::copy(fixture.join(name), data_dir.join(name)).expect(name);
    }
}

#[test]
fn kerberos_migrates_a_dump() {
    // As on an upgrade, the directory has the user, with sync as 0.7.2 set it, before the realm
    // comes over: a first start without Kerberos creates livebob, and the restart imports the dump.
    let mut realm = start_realm_seeded(
        true,
        false,
        free_port(),
        &[
            ("LLDAP_KERBEROS_OPTIONS__REALM", "LIVEBOB.TEST"),
            ("LLDAP_KERBEROS_OPTIONS__ENABLED", "false"),
        ],
        seed_0_7_2_realm,
    );
    let http = client();
    let base = realm.fixture.http_url();
    let created = gql(
        &http,
        &base,
        &get_token(&http, &base),
        "mutation($u: CreateUserInput!) { createUser(user: $u) { id } }",
        json!({"u": {"id": USER, "email": "livebob@example.com"}}),
    );
    assert_eq!(created["data"]["createUser"]["id"], USER, "{created}");
    let db_url = realm.fixture.db_url().to_owned();
    realm.fixture.restart_after(|| {
        let user = format!("user_attribute_user_id = '{USER}'");
        exec_sql(
            &db_url,
            &format!(
                "DELETE FROM user_attributes WHERE {user} AND user_attribute_name = 'kerberossync'"
            ),
        );
        exec_sql(
            &db_url,
            &format!(
                "INSERT INTO user_attributes (user_attribute_user_id, user_attribute_name, \
                 user_attribute_value) VALUES ('{USER}', 'kerberossync', X'31')"
            ),
        );
    });
    realm
        .fixture
        .restart_with_env("LLDAP_KERBEROS_OPTIONS__ENABLED", "true");
    expect_ok(
        &kinit(&realm.krb, FIRST),
        "kinit livebob on the migrated realm",
    );
    assert!(realm.data_dir.join("mit-db2.bak/principal.dump").is_file());
    let marked_rows = |detail: &str| {
        query_i64(
            &db_url,
            &format!(
                "SELECT COUNT(*) FROM logs WHERE kind = 'kerberos_sync' AND detail LIKE '{detail}'"
            ),
        )
    };
    assert_eq!(
        marked_rows("marked at start: 1 principals"),
        1,
        "the first start marks livebob"
    );
    realm.fixture.restart();
    expect_ok(
        &kinit(&realm.krb, FIRST),
        "kinit livebob after the second boot",
    );
    assert_eq!(
        marked_rows("marked at start:%"),
        1,
        "a second start marks nothing"
    );
    let log = realm.fixture.server_log();
    assert_eq!(log.matches("Migrated the MIT realm").count(), 1, "{log}");
}

#[test]
fn kerberos_migrates_a_dump_for_a_user_without_sync() {
    // A 0.7.x operator could give a user without sync a principal with kadmin: the first start
    // disables it, keeps it, and says why.
    let mut realm = start_realm_seeded(
        true,
        false,
        free_port(),
        &[
            ("LLDAP_KERBEROS_OPTIONS__REALM", "LIVEBOB.TEST"),
            ("LLDAP_KERBEROS_OPTIONS__ENABLED", "false"),
        ],
        seed_0_7_2_realm,
    );
    let http = client();
    let base = realm.fixture.http_url();
    let created = gql(
        &http,
        &base,
        &get_token(&http, &base),
        "mutation($u: CreateUserInput!) { createUser(user: $u) { id } }",
        json!({"u": {"id": USER, "email": "livebob@example.com"}}),
    );
    assert_eq!(created["data"]["createUser"]["id"], USER, "{created}");
    realm
        .fixture
        .restart_with_env("LLDAP_KERBEROS_OPTIONS__ENABLED", "true");
    expect_revoked(
        &kinit(&realm.krb, FIRST),
        "kinit livebob without sync on the migrated realm",
    );
    let admin_keytab = realm.admin_keytab.display().to_string();
    let princ = realm.krb.run(
        "kadmin",
        &[
            "-k",
            "-t",
            admin_keytab.as_str(),
            "-p",
            "admin/admin",
            "-q",
            "getprinc livebob",
        ],
        None,
    );
    expect_ok(&princ, "getprinc livebob");
    assert!(
        output_text(&princ).contains("DISALLOW_ALL_TIX"),
        "{}",
        output_text(&princ)
    );
    let db_url = realm.fixture.db_url().to_owned();
    let disabled_rows = || {
        query_i64(
            &db_url,
            "SELECT COUNT(*) FROM logs WHERE kind = 'kerberos_sync' AND target LIKE 'livebob%' \
             AND detail LIKE 'disabled at start:%'",
        )
    };
    assert_eq!(disabled_rows(), 1, "one row names the disabled principal");
    realm.fixture.restart();
    expect_revoked(
        &kinit(&realm.krb, FIRST),
        "kinit livebob without sync after the second boot",
    );
    assert_eq!(disabled_rows(), 1, "a second start disables nothing again");
    let base = realm.fixture.http_url();
    let updated = gql(
        &http,
        &base,
        &get_token(&http, &base),
        "mutation($user: UpdateUserInput!) { updateUser(user: $user) { ok } }",
        json!({"user": {"id": USER, "insertAttributes": [{"name": "kerberossync", "value": ["1"]}]}}),
    );
    assert_eq!(updated["data"]["updateUser"]["ok"], true, "{updated}");
    expect_revoked(
        &kinit(&realm.krb, FIRST),
        "kinit livebob right after sync on: adopted, still disabled",
    );
    let adopted_rows = query_i64(
        &db_url,
        "SELECT COUNT(*) FROM logs WHERE kind = 'kerberos_sync' AND target LIKE 'livebob%' \
         AND detail LIKE 'adopted:%'",
    );
    assert_eq!(adopted_rows, 1, "one row names the adopted principal");
    let token = get_token(&http, &base);
    let disabled = group_id(&http, &base, &token, "lldap_disabled");
    for mutation in ["addUserToGroup", "removeUserFromGroup"] {
        let toggled = gql(
            &http,
            &base,
            &token,
            &format!(
                "mutation($u: String!, $g: Int!) {{ {mutation}(userId: $u, groupId: $g) {{ ok }} }}"
            ),
            json!({"u": USER, "g": disabled}),
        );
        assert_eq!(toggled["data"][mutation]["ok"], true, "{toggled}");
    }
    let old = kinit(&realm.krb, FIRST);
    expect_fail(
        &old,
        "kinit livebob with the dump's password once the group enabled it",
    );
    assert!(
        !output_text(&old).contains("credentials have been revoked"),
        "enabled, and the dump's password still fails: {}",
        output_text(&old)
    );
    let set = gql(
        &http,
        &base,
        &get_token(&http, &base),
        "mutation($id: String!, $password: String!) { setUserPassword(userId: $id, password: $password) { ok } }",
        json!({"id": USER, "password": SECOND}),
    );
    assert_eq!(set["data"]["setUserPassword"]["ok"], true, "{set}");
    expect_ok(
        &kinit(&realm.krb, SECOND),
        "kinit livebob with the first password the directory set",
    );
    expect_fail(
        &kinit(&realm.krb, FIRST),
        "kinit livebob with the dump's password",
    );
}

#[test]
fn kerberos_rolls_krbtgt_when_the_first_type_changes() {
    let mut realm = start_realm(true);
    let http = client();
    let base = realm.fixture.http_url();
    let token = get_token(&http, &base);
    let created = gql(
        &http,
        &base,
        &token,
        "mutation($u: CreateUserInput!) { createUser(user: $u) { id } }",
        json!({"u": {
            "id": USER,
            "email": "livebob@example.com",
            "attributes": [{"name": "kerberossync", "value": ["1"]}]
        }}),
    );
    assert_eq!(created["data"]["createUser"]["id"], USER, "{created}");
    let set = gql(
        &http,
        &base,
        &token,
        "mutation($id: String!, $password: String!) { setUserPassword(userId: $id, password: $password) { ok } }",
        json!({"id": USER, "password": FIRST}),
    );
    assert_eq!(set["data"]["setUserPassword"]["ok"], true, "{set}");
    let export = |token: &str| {
        let exported = gql(
            &http,
            &base,
            token,
            "mutation($h: String!) { exportKeytabForKeycloak(hostname: $h) { ok path errorMsg } }",
            json!({"h": HOST}),
        );
        assert_eq!(
            exported["data"]["exportKeytabForKeycloak"]["ok"], true,
            "{exported}"
        );
    };
    export(&token);
    expect_ok(&kinit(&realm.krb, FIRST), "kinit before the roll");

    realm.fixture.restart_with_env(
        "LLDAP_KERBEROS_OPTIONS__SUPPORTED_ENCTYPES",
        "[aes128-cts-hmac-sha1-96, aes256-cts-hmac-sha1-96]",
    );
    let admin_keytab_s = realm.admin_keytab.display().to_string();
    let getprinc = format!("getprinc krbtgt/{REALM}");
    let tgs = realm.krb.run(
        "kadmin",
        &[
            "-k",
            "-t",
            admin_keytab_s.as_str(),
            "-p",
            "admin/admin",
            "-q",
            getprinc.as_str(),
        ],
        None,
    );
    expect_ok(&tgs, "getprinc krbtgt");
    let text = output_text(&tgs);
    let keys: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with("Key: "))
        .collect();
    assert_eq!(
        keys,
        [
            "Key: vno 2, aes128-cts-hmac-sha1-96",
            "Key: vno 2, aes256-cts-hmac-sha1-96",
            "Key: vno 1, aes256-cts-hmac-sha1-96",
        ],
        "{text}"
    );
    let service = format!("HTTP/{HOST}@{REALM}");
    expect_ok(
        &realm.krb.run("kvno", &[service.as_str()], None),
        "kvno with the ticket from before the roll",
    );
    realm.fixture.restart();
    let log = realm.fixture.server_log();
    assert_eq!(
        log.matches(&format!("Rolled the keys of krbtgt/{REALM}"))
            .count(),
        1,
        "{log}"
    );

    export(&get_token(&http, &base));
    let keytab = realm.keycloak_keytab.display().to_string();
    let listed = realm.krb.run("klist", &["-kte", keytab.as_str()], None);
    expect_ok(&listed, "klist -kte");
    let listed = output_text(&listed);
    let types: Vec<&str> = listed
        .lines()
        .filter(|line| line.contains(service.as_str()))
        .filter_map(|line| line.rsplit('(').next())
        .map(|etype| etype.trim().trim_end_matches(')'))
        .collect();
    assert_eq!(
        types,
        ["aes128-cts-hmac-sha1-96", "aes256-cts-hmac-sha1-96"],
        "{listed}"
    );
}

#[test]
fn kerberos_refuses_a_dump_whose_user_is_missing() {
    let realm = start_realm_seeded(
        false,
        true,
        free_port(),
        &[("LLDAP_KERBEROS_OPTIONS__REALM", "LIVEBOB.TEST")],
        seed_0_7_2_realm,
    );
    let http = client();
    let base = realm.fixture.http_url();
    assert_eq!(
        health(&http, &base),
        (StatusCode::SERVICE_UNAVAILABLE, closed("admin-only")),
        "a database with no realm yet stays admin-only under the default on_realm_failure"
    );
    let info = gql(
        &http,
        &base,
        &get_token(&http, &base),
        "{ kerberosInfo { state cause } }",
        json!({}),
    );
    let info = &info["data"]["kerberosInfo"];
    assert_eq!(info["state"], "admin-only", "{info}");
    let said = info["cause"].as_str().unwrap_or_default();
    for cause in [
        "the Kerberos realm LIVEBOB.TEST did not open",
        "principal livebob names user livebob, and there is no such user",
        "create the user it names, or remove the principal on 0.7.2 and dump again",
    ] {
        assert!(said.contains(cause), "{cause}: {info}");
    }
    for table in ["kerberos_realm", "kerberos_principals"] {
        let rows = query_i64(
            realm.fixture.db_url(),
            &format!("SELECT COUNT(*) FROM {table}"),
        );
        assert_eq!(rows, 0, "{table}");
    }
    assert!(realm.data_dir.join("principal.dump").is_file());
    assert!(!realm.data_dir.join("mit-db2.bak").exists());
}

#[test]
fn kerberos_client_case_fold() {
    let mut realm = start_realm(false);
    let http = client();
    let base = realm.fixture.http_url();
    let token = get_token(&http, &base);
    let created = gql(
        &http,
        &base,
        &token,
        "mutation($u: CreateUserInput!) { createUser(user: $u) { id } }",
        json!({"u": {
            "id": USER,
            "email": "livebob@example.com",
            "attributes": [{"name": "kerberossync", "value": ["1"]}]
        }}),
    );
    assert_eq!(created["data"]["createUser"]["id"], USER, "{created}");
    let set = gql(
        &http,
        &base,
        &token,
        "mutation($id: String!, $password: String!) { setUserPassword(userId: $id, password: $password) { ok } }",
        json!({"id": USER, "password": FIRST}),
    );
    assert_eq!(set["data"]["setUserPassword"]["ok"], true, "{set}");
    let exported = gql(
        &http,
        &base,
        &token,
        "mutation($h: String!) { exportKeytabForKeycloak(hostname: $h) { ok path errorMsg } }",
        json!({"h": HOST}),
    );
    assert_eq!(
        exported["data"]["exportKeytabForKeycloak"]["ok"], true,
        "{exported}"
    );
    let service = format!("HTTP/{HOST}@{REALM}");

    expect_ok(
        &kinit_user(&realm.krb, "Livebob", FIRST),
        "kinit Livebob, fold on by default",
    );
    let listed = realm.krb.run("klist", &[], None);
    expect_ok(&listed, "klist");
    let listed = output_text(&listed);
    assert!(
        listed.contains(&format!("Default principal: Livebob@{REALM}")),
        "{listed}"
    );
    expect_ok(
        &realm.krb.run("kvno", &[service.as_str()], None),
        "kvno with Livebob's ticket",
    );

    realm
        .fixture
        .restart_with_env("LLDAP_KERBEROS_OPTIONS__CLIENT_CASE_FOLD", "false");
    let refused = kinit_user(&realm.krb, "Livebob", FIRST);
    expect_fail(&refused, "kinit Livebob, fold off");
    let refused = output_text(&refused);
    assert!(refused.contains("not found"), "{refused}");
    expect_ok(&kinit(&realm.krb, FIRST), "kinit livebob, fold off");
}

fn seal_for(key: &str, user: &str, server_data: &str, password: &str) -> String {
    seal_kerberos_envelope(key, user, server_data, password).expect("seal")
}

#[test]
fn kerberos_web_password_path() {
    const SYNCED: &str = "webbob";
    const PLAIN: &str = "webeve";
    const FIRST: &str = "WebbobPass2026!";
    const SECOND: &str = "WebbobNext2026!";
    const DECOY: &str = "WebbobDecoy2026!";
    const WRONG: &str = "WebbobWrong2026!";
    const EVE_FIRST: &str = "WebevePass2026!";
    const EVE_SECOND: &str = "WebeveNext2026!";
    const NUL: &str = "a\0aaaaaaa";
    let realm = start_realm(true);
    let http = client();
    let base = realm.fixture.http_url();
    let ldap = realm.fixture.ldap_url();
    let token = get_token(&http, &base);

    let unknown = login(&http, &base, SYNCED, WRONG);
    for (user, sync, password) in [(SYNCED, "1", FIRST), (PLAIN, "0", EVE_FIRST)] {
        let created = gql(
            &http,
            &base,
            &token,
            "mutation($u: CreateUserInput!) { createUser(user: $u) { id } }",
            json!({"u": {
                "id": user,
                "email": format!("{user}@example.com"),
                "attributes": [{"name": "kerberossync", "value": [sync]}]
            }}),
        );
        assert_eq!(created["data"]["createUser"]["id"], user, "{created}");
        let set = gql(
            &http,
            &base,
            &token,
            "mutation($id: String!, $password: String!) { setUserPassword(userId: $id, password: $password) { ok } }",
            json!({"id": user, "password": password}),
        );
        assert_eq!(set["data"]["setUserPassword"]["ok"], true, "{set}");
    }
    let wrong = login(&http, &base, SYNCED, WRONG);
    assert_eq!(unknown.0, StatusCode::UNAUTHORIZED, "{unknown:?}");
    assert_eq!(
        wrong, unknown,
        "M: a wrong password answers as an unknown user does"
    );

    let info = gql(
        &http,
        &base,
        &token,
        "{ kerberosInfo { publicKeyDerBase64 } }",
        json!({}),
    );
    let any_key = info["data"]["kerberosInfo"]["publicKeyDerBase64"]
        .as_str()
        .unwrap_or_else(|| panic!("{info}"))
        .to_owned();
    type Row = (
        &'static str,
        &'static str,
        &'static str,
        Option<(&'static str, &'static str)>,
        u16,
        &'static str,
        &'static str,
        &'static [&'static str],
    );
    let rows: [Row; 7] = [
        (
            "an envelope for a user without sync",
            PLAIN,
            EVE_SECOND,
            Some((PLAIN, EVE_SECOND)),
            400,
            "only for a user with Kerberos sync",
            EVE_FIRST,
            &[EVE_SECOND],
        ),
        (
            "a user without sync, upstream's finish",
            PLAIN,
            EVE_SECOND,
            None,
            200,
            "",
            EVE_SECOND,
            &[EVE_FIRST],
        ),
        (
            "a synced user without an envelope",
            SYNCED,
            SECOND,
            None,
            400,
            "needs the Kerberos password envelope",
            FIRST,
            &[SECOND],
        ),
        (
            "sealed for another user",
            SYNCED,
            SECOND,
            Some((PLAIN, SECOND)),
            400,
            "did not open",
            FIRST,
            &[SECOND],
        ),
        (
            "too short",
            SYNCED,
            "Short-7",
            Some((SYNCED, "Short-7")),
            400,
            "at least 8 characters",
            FIRST,
            &["Short-7"],
        ),
        (
            "a NUL in nine characters",
            SYNCED,
            NUL,
            Some((SYNCED, NUL)),
            400,
            "must not contain a NUL character",
            FIRST,
            &["a"],
        ),
        (
            "sealed for the user beside a decoy upload",
            SYNCED,
            DECOY,
            Some((SYNCED, SECOND)),
            200,
            "",
            SECOND,
            &[FIRST, DECOY],
        ),
    ];
    for (row, user, upload, envelope, status, says, now, refused) in rows {
        let (key, got, body) = register_sealed(&http, &base, &token, user, upload, |key, start| {
            envelope.map(|(sealed_for, password)| {
                seal_for(key.unwrap_or(any_key.as_str()), sealed_for, start, password)
            })
        });
        assert_eq!(key.is_some(), user == SYNCED, "{row}: the start's key");
        assert_eq!(got.as_u16(), status, "{row}: {body}");
        assert!(body.contains(says), "{row}: {body}");
        assert_eq!(bind_rc(&ldap, user, now), 0, "{row}: bind with {now}");
        for password in refused {
            assert_ne!(
                bind_rc(&ldap, user, password),
                0,
                "{row}: bind with {password}"
            );
        }
        if user == SYNCED {
            expect_ok(&kinit_user(&realm.krb, user, now), row);
            for password in refused {
                expect_fail(&kinit_user(&realm.krb, user, password), row);
            }
        }
    }
    let log = realm.fixture.server_log();
    let plaintexts = [
        FIRST, SECOND, DECOY, WRONG, EVE_FIRST, EVE_SECOND, "Short-7", NUL,
    ];
    let found: Vec<_> = plaintexts.iter().filter(|p| log.contains(**p)).collect();
    assert!(
        found.is_empty() && log.contains("Kerberos principal synced for user webbob"),
        "the server's log holds a password ({found:?}), or the capture is empty"
    );
}

#[test]
fn kerberos_forced_reset_of_a_synced_admin() {
    const NEXT: &str = "AdminNext-2026!";
    let mut realm = start_realm(true);
    let http = client();
    let base = realm.fixture.http_url();
    let token = get_token(&http, &base);
    let admin = env::admin_dn();
    let configured = env::admin_password();
    let synced = gql(
        &http,
        &base,
        &token,
        "mutation($user: UpdateUserInput!) { updateUser(user: $user) { ok } }",
        json!({"user": {"id": admin, "insertAttributes": [{"name": "kerberossync", "value": ["1"]}]}}),
    );
    assert_eq!(synced["data"]["updateUser"]["ok"], true, "{synced}");
    let set = gql(
        &http,
        &base,
        &token,
        "mutation($id: String!, $password: String!) { setUserPassword(userId: $id, password: $password) { ok } }",
        json!({"id": admin, "password": NEXT}),
    );
    assert_eq!(set["data"]["setUserPassword"]["ok"], true, "{set}");
    expect_ok(
        &kinit_user(&realm.krb, &admin, NEXT),
        "kinit admin before the reset",
    );

    realm
        .fixture
        .restart_with_env("LLDAP_FORCE_LDAP_USER_PASS_RESET", "always");
    let ldap_url = realm.fixture.ldap_url();
    expect_ok(
        &kinit_user(&realm.krb, &admin, &configured),
        "kinit admin with the configured password",
    );
    expect_fail(
        &kinit_user(&realm.krb, &admin, NEXT),
        "kinit admin with the password before the reset",
    );
    assert_eq!(bind_rc(&ldap_url, &admin, &configured), 0);
    assert_eq!(bind_rc(&ldap_url, &admin, NEXT), 49);
    let log = realm.fixture.server_log();
    // A span's lines are written when it closes, so the order is the lines' times, not places.
    let stamps = |needle: &str| -> Vec<String> {
        log.lines()
            .filter(|line| line.contains(needle))
            .filter_map(|line| line.get(..35).map(str::to_owned))
            .collect()
    };
    let waited = stamps("password waits for the Kerberos realm")
        .pop()
        .unwrap_or_else(|| panic!("the deferral is not logged\n{log}"));
    let after = |needle: &str| {
        stamps(needle)
            .into_iter()
            .find(|stamp| *stamp > waited)
            .unwrap_or_else(|| panic!("{needle}: not logged after the deferral\n{log}"))
    };
    let opened = after("Kerberos realm EXAMPLE.COM opened");
    let reset = after("Reset the password and the Kerberos keys of admin");
    let serving = after("Kerberos realm EXAMPLE.COM serving");
    let ldap_listens = after("Starting the LDAP server on port");
    let http_listens = after("Starting the API/web server on port");
    assert!(
        opened < reset && reset < serving && serving < ldap_listens && serving < http_listens,
        "the realm opens, the reset runs, the KDC serves, then LDAP and HTTP take connections\n{log}"
    );
    let rows = query_i64(
        realm.fixture.db_url(),
        "SELECT COUNT(*) FROM logs WHERE kind = 'admin_bootstrap' \
         AND detail = 'admin password and Kerberos keys reset from the configuration'",
    );
    assert_eq!(rows, 1, "one row for the reset");

    let ((), status, output) = realm
        .fixture
        .refused_start(|| (), &[("LLDAP_LDAP_USER_PASS", "Short7!")]);
    assert!(status.is_some_and(|s| !s.success()), "{status:?}\n{output}");
    assert!(
        output.contains("needs at least 8 characters in ldap_user_pass"),
        "{output}"
    );
    assert!(!output.contains("Short7!"), "the password is never printed");

    realm.fixture.restart();
    let token = get_token(&http, &base);
    let set = gql(
        &http,
        &base,
        &token,
        "mutation($id: String!, $password: String!) { setUserPassword(userId: $id, password: $password) { ok } }",
        json!({"id": admin, "password": NEXT}),
    );
    assert_eq!(set["data"]["setUserPassword"]["ok"], true, "{set}");
    let ((), status, output) = realm
        .fixture
        .refused_start(|| (), &[("LLDAP_FORCE_LDAP_USER_PASS_RESET", "true")]);
    assert!(
        status.is_some_and(|s| !s.success()) && output.contains("Restart the server without"),
        "mode true: the reset runs, then the start stops\n{output}"
    );
    realm
        .fixture
        .restart_with_env("LLDAP_FORCE_LDAP_USER_PASS_RESET", "false");
    let ldap_url = realm.fixture.ldap_url();
    expect_ok(
        &kinit_user(&realm.krb, &admin, &configured),
        "kinit admin with the password mode true set",
    );
    expect_fail(
        &kinit_user(&realm.krb, &admin, NEXT),
        "kinit admin with the password before mode true",
    );
    assert_eq!(
        (
            bind_rc(&ldap_url, &admin, &configured),
            bind_rc(&ldap_url, &admin, NEXT)
        ),
        (0, 49)
    );

    let db_url = realm.fixture.db_url().to_owned();
    let count = |sql: String| query_i64(&db_url, &sql);
    let synced = || {
        count(format!(
            "SELECT COUNT(*) FROM user_attributes WHERE user_attribute_user_id = '{admin}' \
             AND user_attribute_name = 'kerberossync'"
        ))
    };
    let turned_off = || {
        count(format!(
            "SELECT COUNT(*) FROM logs WHERE kind = 'kerberos_sync' AND target = '{admin}' \
             AND detail LIKE 'Kerberos sync turned off by the forced reset%'"
        ))
    };
    let principals = || {
        count(format!(
            "SELECT COUNT(*) FROM kerberos_principals WHERE name = '{admin}'"
        ))
    };
    let removed = || {
        count(format!(
            "SELECT COUNT(*) FROM logs WHERE kind = 'kerberos_sync' AND target = '{admin}' \
             AND detail = 'removed at start: no sync'"
        ))
    };
    let warned = |log: String| log.matches("turned its Kerberos sync off").count();
    let set_next = |token: &str| {
        let set = gql(
            &http,
            &base,
            token,
            "mutation($id: String!, $password: String!) { setUserPassword(userId: $id, password: $password) { ok } }",
            json!({"id": admin, "password": NEXT}),
        );
        assert_eq!(set["data"]["setUserPassword"]["ok"], true, "{set}");
    };

    set_next(&get_token(&http, &base));
    let kdc_port = realm.kdc_port;
    realm
        .fixture
        .set_env("LLDAP_FORCE_LDAP_USER_PASS_RESET", "always");
    let holder = realm.fixture.restart_after(|| hold_kdc(kdc_port));
    let realm_closed = (
        health(&http, &realm.fixture.http_url()),
        bind_rc(&ldap_url, &admin, &configured),
        bind_rc(&ldap_url, &admin, NEXT),
        synced(),
        turned_off(),
        warned(realm.fixture.server_log()),
    );
    let open_to_all = (StatusCode::OK, closed("directory-only"));
    assert_eq!(
        realm_closed,
        (open_to_all, 0, 49, 0, 1, 1),
        "the realm cannot open: the reset, sync off, one row, the warning, and it serves everyone"
    );
    drop(holder);
    realm
        .fixture
        .restart_with_env("LLDAP_FORCE_LDAP_USER_PASS_RESET", "false");
    expect_fail(
        &kinit_user(&realm.krb, &admin, NEXT),
        "kinit admin once the start pass removed the principal",
    );
    assert_eq!(
        (principals(), removed()),
        (0, 1),
        "Kerberos back: the start pass removes the principal left behind"
    );

    let token = get_token(&http, &base);
    let synced_again = gql(
        &http,
        &base,
        &token,
        "mutation($user: UpdateUserInput!) { updateUser(user: $user) { ok } }",
        json!({"user": {"id": admin, "insertAttributes": [{"name": "kerberossync", "value": ["1"]}]}}),
    );
    assert_eq!(
        synced_again["data"]["updateUser"]["ok"], true,
        "{synced_again}"
    );
    set_next(&token);
    expect_ok(
        &kinit_user(&realm.krb, &admin, NEXT),
        "kinit admin synced again",
    );
    realm
        .fixture
        .set_env("LLDAP_KERBEROS_OPTIONS__ENABLED", "false");
    realm
        .fixture
        .restart_with_env("LLDAP_FORCE_LDAP_USER_PASS_RESET", "always");
    let kerberos_off = (
        bind_rc(&ldap_url, &admin, &configured),
        bind_rc(&ldap_url, &admin, NEXT),
        synced(),
        turned_off(),
        warned(realm.fixture.server_log()),
    );
    assert_eq!(
        kerberos_off,
        (0, 49, 0, 2, 2),
        "Kerberos disabled: the reset, sync off, one row, the warning, and it serves"
    );
    realm
        .fixture
        .set_env("LLDAP_KERBEROS_OPTIONS__ENABLED", "true");
    realm
        .fixture
        .restart_with_env("LLDAP_FORCE_LDAP_USER_PASS_RESET", "false");
    assert_eq!(
        (principals(), removed()),
        (0, 2),
        "Kerberos back: the start pass removes the principal left behind"
    );
}

fn toggle_disabled(http: &Client, base: &str, mutation: &str) {
    let token = get_token(http, base);
    let disabled = group_id(http, base, &token, "lldap_disabled");
    let toggled = gql(
        http,
        base,
        &token,
        &format!(
            "mutation($u: String!, $g: Int!) {{ {mutation}(userId: $u, groupId: $g) {{ ok }} }}"
        ),
        json!({"u": USER, "g": disabled}),
    );
    assert_eq!(toggled["data"][mutation]["ok"], true, "{toggled}");
}

#[test]
fn lldap_disabled_changed_without_the_realm_is_followed_when_it_opens() {
    const ENABLED: &str = "LLDAP_KERBEROS_OPTIONS__ENABLED";
    let mut realm = start_realm(false);
    let http = client();
    let base = realm.fixture.http_url();
    let token = get_token(&http, &base);
    let created = gql(
        &http,
        &base,
        &token,
        "mutation($u: CreateUserInput!) { createUser(user: $u) { id } }",
        json!({"u": {
            "id": USER,
            "email": "livebob@example.com",
            "attributes": [{"name": "kerberossync", "value": ["1"]}]
        }}),
    );
    assert_eq!(created["data"]["createUser"]["id"], USER, "{created}");
    let set = gql(
        &http,
        &base,
        &token,
        "mutation($id: String!, $password: String!) { setUserPassword(userId: $id, password: $password) { ok } }",
        json!({"id": USER, "password": FIRST}),
    );
    assert_eq!(set["data"]["setUserPassword"]["ok"], true, "{set}");
    expect_ok(&kinit(&realm.krb, FIRST), "kinit before any change");

    for (mutation, enabled) in [("addUserToGroup", false), ("removeUserFromGroup", true)] {
        realm.fixture.restart_with_env(ENABLED, "false");
        toggle_disabled(&http, &realm.fixture.http_url(), mutation);
        realm.fixture.restart_with_env(ENABLED, "true");
        let after = kinit(&realm.krb, FIRST);
        match enabled {
            true => expect_ok(&after, "kinit once the start enabled it"),
            false => expect_revoked(&after, "kinit once the start disabled it"),
        }
    }

    let kdc_port = realm.kdc_port;
    for (mutation, enabled, mode) in [
        ("addUserToGroup", false, "admin-only"),
        ("removeUserFromGroup", true, "directory-only"),
    ] {
        realm.fixture.set_env(ON_REALM_FAILURE, mode);
        let holder = realm.fixture.restart_after(|| hold_kdc(kdc_port));
        toggle_disabled(&http, &realm.fixture.http_url(), mutation);
        drop(holder);
        realm.fixture.restart();
        let after = kinit(&realm.krb, FIRST);
        match enabled {
            true => expect_ok(&after, "kinit once the repaired realm enabled it"),
            false => expect_revoked(&after, "kinit once the repaired realm disabled it"),
        }
    }

    let db_url = realm.fixture.db_url().to_owned();
    let rows = |detail: &str| {
        query_i64(
            &db_url,
            &format!(
                "SELECT COUNT(*) FROM logs WHERE kind = 'kerberos_sync' AND target LIKE \
                 'livebob%' AND detail LIKE '{detail}%'"
            ),
        )
    };
    assert_eq!(
        [
            rows("Kerberos is disabled: the status of a principal, if there is one,"),
            rows("the Kerberos realm is not ready: the status of a principal, if there is one,"),
            rows("the Kerberos realm is closed on this server: the status of a principal, if"),
            rows("disabled as the realm opened: the user is in lldap_disabled"),
            rows("enabled as the realm opened: the user is not in lldap_disabled"),
        ],
        [2, 1, 1, 2, 2],
        "one row for each change left, admin-only then directory-only, and one for each status \
         the opening set"
    );
}

#[test]
fn kerberos_forced_reset_of_an_admin_without_sync_waits_for_the_realm() {
    const NEXT: &str = "AdminNext-2026!";
    let admin_only = [(ON_REALM_FAILURE, "admin-only")];
    let mut realm = start_realm_seeded(true, false, free_port(), &admin_only, |_| {});
    let http = client();
    let base = realm.fixture.http_url();
    let admin = env::admin_dn();
    let configured = env::admin_password();
    let set = gql(
        &http,
        &base,
        &get_token(&http, &base),
        "mutation($id: String!, $password: String!) { setUserPassword(userId: $id, password: $password) { ok } }",
        json!({"id": admin, "password": NEXT}),
    );
    assert_eq!(set["data"]["setUserPassword"]["ok"], true, "{set}");

    realm
        .fixture
        .restart_with_env("LLDAP_FORCE_LDAP_USER_PASS_RESET", "always");
    let ldap_url = realm.fixture.ldap_url();
    assert_eq!(
        (
            bind_rc(&ldap_url, &admin, &configured),
            bind_rc(&ldap_url, &admin, NEXT)
        ),
        (0, 49)
    );
    let log = realm.fixture.server_log();
    let stamps = |needle: &str| -> Vec<String> {
        log.lines()
            .filter(|line| line.contains(needle))
            .filter_map(|line| line.get(..35).map(str::to_owned))
            .collect()
    };
    let waited = stamps("password waits for the Kerberos realm: Kerberos is enabled")
        .pop()
        .unwrap_or_else(|| panic!("the deferral is not logged\n{log}"));
    let after = |needle: &str| {
        stamps(needle)
            .into_iter()
            .find(|stamp| *stamp > waited)
            .unwrap_or_else(|| panic!("{needle}: not logged after the deferral\n{log}"))
    };
    let opened = after("Kerberos realm EXAMPLE.COM opened");
    let reset = after("Reset the password of admin from the configuration");
    let serving = after("Kerberos realm EXAMPLE.COM serving");
    let ldap_listens = after("Starting the LDAP server on port");
    assert!(
        opened < reset && reset < serving && serving < ldap_listens,
        "the realm opens, the reset runs, the KDC serves, then LDAP takes connections\n{log}"
    );

    let set = gql(
        &http,
        &base,
        &get_token(&http, &base),
        "mutation($id: String!, $password: String!) { setUserPassword(userId: $id, password: $password) { ok } }",
        json!({"id": admin, "password": NEXT}),
    );
    assert_eq!(set["data"]["setUserPassword"]["ok"], true, "{set}");
    let db_url = realm.fixture.db_url().to_owned();
    let resets = || {
        query_i64(
            &db_url,
            "SELECT COUNT(*) FROM logs WHERE kind = 'admin_bootstrap' \
             AND detail = 'admin password reset from the configuration'",
        )
    };
    let before = resets();
    let kdc_port = realm.kdc_port;
    let holder = realm.fixture.restart_after(|| hold_kdc(kdc_port));
    let closed_health = health(&http, &realm.fixture.http_url());
    let ldap_url = realm.fixture.ldap_url();
    assert_eq!(
        (
            closed_health,
            bind_rc(&ldap_url, &admin, &configured),
            bind_rc(&ldap_url, &admin, NEXT),
            resets() - before
        ),
        (
            (StatusCode::SERVICE_UNAVAILABLE, closed("admin-only")),
            0,
            49,
            1
        ),
        "the realm cannot open: the reset runs as upstream's and the server serves its admins"
    );
    drop(holder);
}

#[test]
fn a_nul_in_the_admin_password_refuses_the_first_start_and_a_forced_reset() {
    const NUL: &str = "ldap_user_pass = \"a\\u0000aaaaaaa\"\n";
    let mut fixture = LLDAPFixture::new();
    let (status, output, fresh) = fixture.refused_start_with_config(NUL, true);
    assert!(status.is_some_and(|s| !s.success()), "{status:?}\n{output}");
    assert!(
        output.contains(
            "The admin password in ldap_user_pass is refused: the password must not contain a \
             NUL character (U+0000)"
        ),
        "{output}"
    );
    assert_eq!(
        query_i64(&fresh, "SELECT COUNT(*) FROM users"),
        0,
        "no admin is made"
    );

    let reset = format!("{NUL}force_ldap_user_pass_reset = \"always\"\n");
    let (status, output, _) = fixture.refused_start_with_config(&reset, false);
    assert!(status.is_some_and(|s| !s.success()), "{status:?}\n{output}");
    assert!(
        output.contains("cannot take a NUL character (U+0000) in ldap_user_pass"),
        "{output}"
    );
    fixture.restart();
    let configured = bind_rc(
        &fixture.ldap_url(),
        &env::admin_dn(),
        &env::admin_password(),
    );
    assert_eq!(configured, 0, "the configured password still binds");
}

fn gql_status(
    client: &Client,
    base: &str,
    token: &str,
    query: &str,
    variables: Value,
) -> (StatusCode, String) {
    let response = client
        .post(format!("{base}/api/graphql"))
        .bearer_auth(token)
        .json(&json!({"query": query, "variables": variables}))
        .send()
        .expect("graphql send");
    let status = response.status();
    (status, response.text().expect("graphql body"))
}

#[test]
fn the_server_refuses_what_kerberos_could_never_take() {
    use ldap3::Mod;
    use ldap3::exop::PasswordModify;
    use std::collections::HashSet;
    const SHORT: &str = "Short-7";
    const SET: &str = "mutation($id: String!, $password: String!) { setUserPassword(userId: $id, password: $password) { ok } }";
    const CREATE: &str = "mutation($u: CreateUserInput!) { createUser(user: $u) { id } }";
    const UPDATE: &str = "mutation($user: UpdateUserInput!) { updateUser(user: $user) { ok } }";
    const FLOOR: &str = "the password must be at least 8 characters";
    const NUL: &str = "a\0aaaaaaa";
    const NUL_REFUSAL: &str = "the password must not contain a NUL character (U+0000)";
    let fixture = common::fixture::LLDAPFixture::new();
    let http = client();
    let base = fixture.http_url();
    let token = get_token(&http, &base);
    let created = gql(
        &http,
        &base,
        &token,
        CREATE,
        json!({"u": {"id": "flooruser", "email": "flooruser@example.com"}}),
    );
    assert_eq!(
        created["data"]["createUser"]["id"], "flooruser",
        "{created}"
    );

    let base_dn = env::base_dn();
    let dn = format!("uid=flooruser,ou=people,{base_dn}");
    let add_dn = format!("uid=flooradd,ou=people,{base_dn}");
    let admin_dn = format!("uid={},ou=people,{base_dn}", env::admin_dn());
    for (password, refusal) in [(SHORT, FLOOR), (NUL, NUL_REFUSAL)] {
        let (status, body) = gql_status(
            &http,
            &base,
            &token,
            SET,
            json!({"id": "flooruser", "password": password}),
        );
        assert_eq!(
            (status, body.contains(refusal)),
            (StatusCode::OK, true),
            "{body}"
        );

        let mut ldap = LdapConn::new(&fixture.ldap_url()).expect("ldap connection");
        ldap.simple_bind(&admin_dn, &env::admin_password())
            .expect("bind send")
            .success()
            .expect("admin bind");
        let modified = ldap
            .extended(PasswordModify {
                user_id: Some(&dn),
                old_pass: None,
                new_pass: Some(password),
            })
            .expect("password modify send");
        let replaced = ldap
            .modify(
                &dn,
                vec![Mod::Replace("userPassword", HashSet::from([password]))],
            )
            .expect("modify send");
        let added = ldap
            .add(
                &add_dn,
                vec![
                    ("objectClass", HashSet::from(["inetOrgPerson", "person"])),
                    ("uid", HashSet::from(["flooradd"])),
                    ("cn", HashSet::from(["flooradd"])),
                    ("sn", HashSet::from(["flooradd"])),
                    ("mail", HashSet::from(["flooradd@example.com"])),
                    ("userPassword", HashSet::from([password])),
                ],
            )
            .expect("add send");
        let _ = ldap.unbind();
        assert_eq!(
            (modified.1.rc, replaced.rc, added.rc),
            (53, 53, 53),
            "{modified:?} {replaced:?} {added:?}"
        );
        assert_eq!(
            (modified.1.text, replaced.text, added.text),
            (refusal.to_owned(), refusal.to_owned(), refusal.to_owned())
        );
        let (_, body) = gql_status(
            &http,
            &base,
            &token,
            "{ user(userId: \"flooradd\") { id } }",
            json!({}),
        );
        assert!(
            !body.contains("\"id\":\"flooradd\""),
            "the Add made nothing: {body}"
        );
    }
    let refusals = || {
        query_i64(
            fixture.db_url(),
            "SELECT COUNT(*) FROM logs WHERE success = 0 AND target IN ('flooruser', 'flooradd') \
             AND kind IN ('password_change', 'user_create')",
        )
    };
    let deadline = Instant::now() + Duration::from_secs(10);
    while refusals() < 8 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(250));
    }
    std::thread::sleep(Duration::from_millis(500));
    assert_eq!(refusals(), 8, "one failure row for each refused change");

    let rule = "Kerberos sync cannot be turned on for user jürgen: Kerberos username must be ASCII alphanumeric plus '.', '_' or '-'";
    let (status, body) = gql_status(
        &http,
        &base,
        &token,
        CREATE,
        json!({"u": {"id": "jürgen", "email": "j@example.com", "attributes": [{"name": "kerberossync", "value": ["1"]}]}}),
    );
    assert_eq!(
        (status, body.contains(rule)),
        (StatusCode::OK, true),
        "{body}"
    );
    let created = gql(
        &http,
        &base,
        &token,
        CREATE,
        json!({"u": {"id": "jürgen", "email": "j@example.com"}}),
    );
    assert_eq!(created["data"]["createUser"]["id"], "jürgen", "{created}");
    let (status, body) = gql_status(
        &http,
        &base,
        &token,
        UPDATE,
        json!({"user": {"id": "jürgen", "insertAttributes": [{"name": "kerberossync", "value": ["1"]}]}}),
    );
    assert_eq!(
        (status, body.contains(rule)),
        (StatusCode::OK, true),
        "{body}"
    );
}
