use crate::common::{
    auth::get_token,
    fixture::{LLDAPFixture, free_port},
};
use reqwest::blocking::{Client, ClientBuilder};
use serde_json::{Value, json};
use std::io::Write;
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

#[test]
fn kerberos_lifecycle() {
    let realm_dir = tempfile::TempDir::new().expect("realm dir");
    let kdc_port = free_port();
    let kadmin_port = free_port();
    let data_dir = realm_dir.path().join("data");
    let admin_keytab = realm_dir.path().join("kadm5.keytab");
    let keycloak_keytab = realm_dir.path().join("keycloak-http.keytab");
    let client_config = realm_dir.path().join("krb5.conf");
    let ccache = realm_dir.path().join("cc");
    let kdc_port_s = kdc_port.to_string();
    let kadmin_bind = format!("127.0.0.1:{kadmin_port}");
    let data_dir_s = data_dir.display().to_string();
    let admin_keytab_s = admin_keytab.display().to_string();
    let keycloak_keytab_s = keycloak_keytab.display().to_string();
    let client_config_s = client_config.display().to_string();
    let env = [
        ("LLDAP_KERBEROS_OPTIONS__ENABLED", "true"),
        ("LLDAP_KERBEROS_OPTIONS__KDC_BIND", "127.0.0.1"),
        ("LLDAP_KERBEROS_OPTIONS__KDC_PORT", kdc_port_s.as_str()),
        ("LLDAP_KERBEROS_OPTIONS__KADMIN_BIND", kadmin_bind.as_str()),
        ("LLDAP_KERBEROS_OPTIONS__DATA_DIR", data_dir_s.as_str()),
        (
            "LLDAP_KERBEROS_OPTIONS__ADMIN_KEYTAB",
            admin_keytab_s.as_str(),
        ),
        (
            "LLDAP_KERBEROS_OPTIONS__KEYCLOAK_KEYTAB",
            keycloak_keytab_s.as_str(),
        ),
        (
            "LLDAP_KERBEROS_OPTIONS__CLIENT_CONFIG",
            client_config_s.as_str(),
        ),
    ];
    let mut fixture = LLDAPFixture::new_with_env(&env);
    let http = client();
    let base = fixture.http_url();
    let mut token = get_token(&http, &base);
    let krb = KrbClient {
        config: client_config.clone(),
        ccache,
    };

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

    let keytab_before = std::fs::metadata(&admin_keytab)
        .expect("admin keytab")
        .modified()
        .unwrap_or(SystemTime::UNIX_EPOCH);
    std::thread::sleep(Duration::from_secs(1));
    fixture.restart();
    token = get_token(&http, &base);
    expect_ok(&kinit(&krb, SECOND), "kinit after restart");
    let keytab_after = std::fs::metadata(&admin_keytab)
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
        2,
        "{}",
        output_text(&listed_keytab)
    );
    assert!(Path::new(&client_config).is_file());
}
