use crate::common::{
    auth::{get_token, get_token_for},
    env,
    fixture::{LLDAPFixture, free_port},
};
use ldap3::LdapConn;
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
    assert_log_line(
        &realm.fixture,
        &format!(
            "Refused a Kerberos ticket request from {principal}: the principal no longer exists"
        ),
    );
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

fn health(http: &Client, base: &str) -> (StatusCode, String) {
    let response = http
        .get(format!("{base}/health"))
        .send()
        .expect("health send");
    let status = response.status();
    let body = response.text().expect("health body");
    (status, body)
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
fn kerberos_degraded() {
    const BOB: &str = "bob";
    const PASS: &str = "BobSmoke-2026!";
    let mut realm = start_realm(false);
    let http = client();
    let base = realm.fixture.http_url();
    let token = get_token(&http, &base);
    let created = gql(
        &http,
        &base,
        &token,
        "mutation($u: CreateUserInput!) { createUser(user: $u) { id } }",
        json!({"u": {"id": BOB, "email": "bob@example.com"}}),
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
    let bob_token = get_token_for(&http, &base, BOB, PASS);
    let kdc_port = realm.kdc_port;
    let ldap_url = realm.fixture.ldap_url();

    let holder = realm.fixture.restart_after(|| hold_kdc(kdc_port));
    let base = realm.fixture.http_url();
    let (status, body) = health(&http, &base);
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert!(body.contains("did not open"), "{body}");

    let check = realm.fixture.healthcheck_output();
    let check_text = output_text(&check);
    assert!(
        !check.status.success(),
        "healthcheck succeeded: {check_text}"
    );
    assert!(
        check_text.contains("503 Service Unavailable: the Kerberos realm"),
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
    let base = realm.fixture.http_url();
    let ldap_url = realm.fixture.ldap_url();
    let (status, body) = health(&http, &base);
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = login(&http, &base, BOB, PASS);
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(bind_rc(&ldap_url, BOB, PASS), 0);

    let fresh_port = free_port();
    let fresh_holder = hold_kdc(fresh_port);
    let fresh = start_realm_at(false, true, fresh_port);
    let fresh_http = client();
    let fresh_base = fresh.fixture.http_url();
    let (status, body) = health(&fresh_http, &fresh_base);
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert!(body.contains("did not open"), "{body}");
    let (status, body) = login(&fresh_http, &fresh_base, &admin, &admin_pass);
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(bind_rc(&fresh.fixture.ldap_url(), &admin, &admin_pass), 0);
    drop(fresh);
    drop(fresh_holder);
}

#[test]
fn kerberos_migrates_a_dump() {
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/krb5kdc");
    let mut realm = start_realm_seeded(
        true,
        false,
        free_port(),
        &[("LLDAP_KERBEROS_OPTIONS__REALM", "LIVEBOB.TEST")],
        |data_dir| {
            std::fs::create_dir_all(data_dir).expect("data dir");
            for name in [".k5.LIVEBOB.TEST", "principal.dump"] {
                std::fs::copy(fixture.join(name), data_dir.join(name)).expect(name);
            }
        },
    );
    expect_ok(
        &kinit(&realm.krb, FIRST),
        "kinit livebob on the migrated realm",
    );
    assert!(realm.data_dir.join("mit-db2.bak/principal.dump").is_file());
    realm.fixture.restart();
    expect_ok(
        &kinit(&realm.krb, FIRST),
        "kinit livebob after the second boot",
    );
    let log = realm.fixture.server_log();
    assert_eq!(log.matches("Migrated the MIT realm").count(), 1, "{log}");
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
