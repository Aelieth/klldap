#![allow(dead_code)]
use crate::common::{
    auth::get_token,
    env,
    graphql::{
        AddUserToGroup, CreateGroup, CreateUser, DeleteGroupQuery, DeleteUserQuery,
        add_user_to_group, create_group, create_user, delete_group_query, delete_user_query, post,
    },
};
use assert_cmd::cargo_bin;
use nix::{
    sys::signal::{self, Signal},
    unistd::Pid,
};
use reqwest::blocking::{Client, ClientBuilder};
use sea_orm::{ConnectionTrait, Database, DbBackend, Statement};
use std::collections::{HashMap, HashSet};
use std::fs::OpenOptions;
use std::path::{Path, PathBuf};
use std::process::{Child as ChildProcess, Command, Stdio};
use std::sync::{LazyLock, Mutex};
use std::{fs::canonicalize, thread, time::Duration};
use uuid::Uuid;

#[derive(Clone)]
pub struct User {
    pub username: String,
    pub groups: Vec<String>,
    pub display_name: Option<String>,
}

impl User {
    pub fn new(username: &str, groups: Vec<&str>) -> Self {
        let username = username.to_owned();
        let groups = groups.iter().map(|g| g.to_string()).collect();
        Self {
            username,
            groups,
            display_name: None,
        }
    }

    pub fn with_display_name(mut self, display_name: &str) -> Self {
        self.display_name = Some(display_name.to_owned());
        self
    }
}

pub struct LLDAPFixture {
    token: String,
    client: Client,
    child: ChildProcess,
    users: HashSet<String>,
    groups: HashMap<String, i64>,
    ldap_port: u16,
    http_port: u16,
    db_url: String,
    extra_env: Vec<(String, String)>,
    server_log: Option<PathBuf>,
    _dir: tempfile::TempDir,
}

const MAX_HEALTHCHECK_ATTEMPS: u8 = 30;

impl LLDAPFixture {
    pub fn new() -> Self {
        Self::new_with_env(&[])
    }

    pub fn new_with_env(extra_env: &[(&str, &str)]) -> Self {
        Self::start(extra_env, false)
    }

    pub fn new_with_env_logged(extra_env: &[(&str, &str)]) -> Self {
        Self::start(extra_env, true)
    }

    pub fn new_with_env_answering(extra_env: &[(&str, &str)]) -> Self {
        Self::start_ready(extra_env, false, true)
    }

    fn start(extra_env: &[(&str, &str)], capture_log: bool) -> Self {
        Self::start_ready(extra_env, capture_log, false)
    }

    fn start_ready(extra_env: &[(&str, &str)], capture_log: bool, answering: bool) -> Self {
        let dir = tempfile::TempDir::new().expect("temp dir");
        let server_log = capture_log.then(|| dir.path().join("server.log"));
        let db_url = format!("sqlite://{}/users.db?mode=rwc", dir.path().display());
        let ldap_port = free_port();
        let http_port = free_port();
        let extra_env = extra_env
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect::<Vec<_>>();
        let child = spawn_server(
            &db_url,
            ldap_port,
            http_port,
            &extra_env,
            server_log.as_deref(),
        );
        if answering {
            wait_until_answering(http_port);
        } else {
            wait_until_healthy(&db_url, ldap_port, http_port, &extra_env);
        }

        let client = ClientBuilder::new()
            .connect_timeout(std::time::Duration::from_secs(3))
            .timeout(std::time::Duration::from_secs(8))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("failed to make http client");

        let token = get_token(&client, &http_url(http_port));
        Self {
            client,
            token,
            child,
            users: HashSet::new(),
            groups: HashMap::new(),
            ldap_port,
            http_port,
            db_url,
            extra_env,
            server_log,
            _dir: dir,
        }
    }

    pub fn server_log(&self) -> String {
        let path = self
            .server_log
            .as_ref()
            .expect("server log was not requested");
        std::fs::read_to_string(path).unwrap_or_default()
    }

    pub fn restart(&mut self) {
        stop_child(&mut self.child);
        self.child = spawn_server(
            &self.db_url,
            self.ldap_port,
            self.http_port,
            &self.extra_env,
            self.server_log.as_deref(),
        );
        wait_until_healthy(
            &self.db_url,
            self.ldap_port,
            self.http_port,
            &self.extra_env,
        );
        self.token = get_token(&self.client, &self.http_url());
    }

    pub fn restart_with_env(&mut self, key: &str, value: &str) {
        self.extra_env.retain(|(name, _)| name != key);
        self.extra_env.push((key.to_owned(), value.to_owned()));
        self.restart();
    }

    pub fn restart_after<T>(&mut self, between: impl FnOnce() -> T) -> T {
        stop_child(&mut self.child);
        let value = between();
        self.child = spawn_server(
            &self.db_url,
            self.ldap_port,
            self.http_port,
            &self.extra_env,
            self.server_log.as_deref(),
        );
        wait_until_answering(self.http_port);
        self.token = get_token(&self.client, &self.http_url());
        value
    }

    pub fn healthcheck_output(&self) -> std::process::Output {
        server_command(
            "healthcheck",
            &self.db_url,
            self.ldap_port,
            self.http_port,
            &self.extra_env,
        )
        .output()
        .expect("healthcheck command failed to execute")
    }

    pub fn ldap_url(&self) -> String {
        format!("ldap://localhost:{}", self.ldap_port)
    }

    pub fn http_url(&self) -> String {
        http_url(self.http_port)
    }

    pub fn load_state(&mut self, state: &Vec<User>) {
        let mut seen: HashSet<String> = HashSet::new();
        let mut groups: HashSet<String> = HashSet::new();

        for user in state {
            if seen.insert(user.username.clone()) {
                self.add_user(user);
            }
            groups.extend(user.groups.clone());
        }

        for group in &groups {
            self.add_group(group);
        }
        for User {
            username, groups, ..
        } in state
        {
            for group in groups {
                self.add_user_to_group(username, group);
            }
        }
    }

    fn add_user(&mut self, user: &User) {
        post::<CreateUser>(
            &self.client,
            &self.http_url(),
            &self.token,
            create_user::Variables {
                user: create_user::CreateUserInput {
                    id: user.username.clone(),
                    email: Some(format!("{}@lldap.test", user.username)),
                    avatar: None,
                    display_name: user.display_name.clone(),
                    first_name: None,
                    last_name: None,
                    attributes: None,
                },
            },
        )
        .unwrap_or_else(|e| panic!("failed to add user '{}': {e:#}", user.username));
        self.users.insert(user.username.clone());
    }

    fn add_group(&mut self, group: &str) {
        let id = post::<CreateGroup>(
            &self.client,
            &self.http_url(),
            &self.token,
            create_group::Variables {
                group: create_group::CreateGroupInput {
                    display_name: group.to_owned(),
                    attributes: None,
                },
            },
        )
        .unwrap_or_else(|e| panic!("failed to add group '{group}': {e:#}"))
        .create_group
        .id;
        self.groups.insert(group.to_owned(), id);
    }

    fn add_user_to_group(&mut self, user: &str, group: &String) {
        let group_id = *self
            .groups
            .get(group)
            .expect("group id missing when adding user");
        post::<AddUserToGroup>(
            &self.client,
            &self.http_url(),
            &self.token,
            add_user_to_group::Variables {
                user: user.to_owned(),
                group: group_id,
            },
        )
        .unwrap_or_else(|e| panic!("failed to add user '{user}' to group '{group}': {e:#}"));
    }

    // Cleanup must not panic inside Drop.
    fn delete_user(&mut self, user: &String) {
        if let Err(e) = post::<DeleteUserQuery>(
            &self.client,
            &self.http_url(),
            &self.token,
            delete_user_query::Variables { user: user.clone() },
        ) {
            eprintln!("could not delete user {user}: {e:#}");
        }
        self.users.remove(user);
    }

    fn delete_group(&mut self, group: &String) {
        let Some(group_id) = self.groups.remove(group) else {
            return;
        };
        if let Err(e) = post::<DeleteGroupQuery>(
            &self.client,
            &self.http_url(),
            &self.token,
            delete_group_query::Variables { group_id },
        ) {
            eprintln!("could not delete group {group}: {e:#}");
        }
    }
}

impl Drop for LLDAPFixture {
    fn drop(&mut self) {
        for user in self.users.clone() {
            self.delete_user(&user);
        }
        for group in self.groups.keys().cloned().collect::<Vec<_>>() {
            self.delete_group(&group);
        }
        stop_child(&mut self.child);
    }
}

fn server_command(
    subcommand: &str,
    db_url: &str,
    ldap_port: u16,
    http_port: u16,
    extra_env: &[(String, String)],
) -> Command {
    let mut cmd = create_lldap_command(subcommand, db_url);
    if extra_env
        .iter()
        .any(|(key, _)| key.starts_with("LLDAP_KERBEROS_OPTIONS__"))
    {
        cmd.env_remove(KERBEROS_ENABLED);
    }
    cmd.env("LLDAP_LDAP_PORT", ldap_port.to_string())
        .env("LLDAP_HTTP_PORT", http_port.to_string())
        .envs(
            extra_env
                .iter()
                .map(|(key, value)| (key.as_str(), value.as_str())),
        );
    cmd
}

fn spawn_server(
    db_url: &str,
    ldap_port: u16,
    http_port: u16,
    extra_env: &[(String, String)],
    log: Option<&Path>,
) -> ChildProcess {
    let mut cmd = server_command("run", db_url, ldap_port, http_port, extra_env);
    cmd.arg("--verbose");
    if let Some(path) = log {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .expect("server log");
        let err = file.try_clone().expect("server log");
        cmd.stdout(Stdio::from(file)).stderr(Stdio::from(err));
    }
    cmd.spawn().expect("Unable to start server")
}

fn wait_until_healthy(
    db_url: &str,
    ldap_port: u16,
    http_port: u16,
    extra_env: &[(String, String)],
) {
    let mut started = false;
    for attempt in 0..MAX_HEALTHCHECK_ATTEMPS {
        let status = server_command("healthcheck", db_url, ldap_port, http_port, extra_env)
            .status()
            .expect("healthcheck command failed to execute");
        if status.success() {
            started = true;
            break;
        }
        if attempt == MAX_HEALTHCHECK_ATTEMPS - 1 {
            panic!(
                "LLDAP failed to start after {} attempts. Check lldap_test_*.log if logs were captured.",
                MAX_HEALTHCHECK_ATTEMPS
            );
        }
        thread::sleep(Duration::from_millis(800));
    }
    assert!(started, "Server did not become healthy");
}

fn wait_until_answering(http_port: u16) {
    let client = ClientBuilder::new()
        .connect_timeout(Duration::from_secs(3))
        .timeout(Duration::from_secs(8))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("failed to make http client");
    let url = format!("{}/health", http_url(http_port));
    for attempt in 0..MAX_HEALTHCHECK_ATTEMPS {
        if client.get(&url).send().is_ok() {
            return;
        }
        if attempt == MAX_HEALTHCHECK_ATTEMPS - 1 {
            panic!("LLDAP did not answer /health after {MAX_HEALTHCHECK_ATTEMPS} attempts");
        }
        thread::sleep(Duration::from_millis(800));
    }
}

fn stop_child(child: &mut ChildProcess) {
    let result = signal::kill(
        Pid::from_raw(child.id().try_into().unwrap()),
        Signal::SIGTERM,
    );
    if let Err(err) = result {
        println!("Failed to send SIGTERM: {err:?}");
        let _ = child.kill();
        let _ = child.wait();
        return;
    }
    for _ in 0..12 {
        match child.try_wait() {
            Ok(Some(status)) => {
                if !status.success() {
                    println!("LLDAP exited with status {status}");
                }
                return;
            }
            Ok(None) => {
                println!("LLDAP still running, sleeping for 1 second...");
            }
            Err(e) => {
                println!("Error waiting for LLDAP: {e}");
                break;
            }
        }
        thread::sleep(Duration::from_millis(1000));
    }
    println!("LLDAP did not exit gracefully after 12s, forcing kill.");
    let _ = child.kill();
    let _ = child.wait();
}

pub fn new_id(prefix: Option<&str>) -> String {
    let id = Uuid::new_v4();
    let id = format!("{}-lldap-test", id.simple());
    match prefix {
        Some(prefix) => format!("{prefix}{id}"),
        None => id,
    }
}

pub fn http_url(port: u16) -> String {
    format!("http://localhost:{port}")
}

pub fn free_port() -> u16 {
    static HANDED_OUT: LazyLock<Mutex<HashSet<u16>>> = LazyLock::new(|| Mutex::new(HashSet::new()));
    let mut handed_out = HANDED_OUT.lock().expect("port set");
    loop {
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .expect("bind an ephemeral port")
            .local_addr()
            .expect("local addr")
            .port();
        if handed_out.insert(port) {
            return port;
        }
    }
}

// A test that sets no kerberos_options variable runs without a realm; one that does gets the
// code's default unless it names `enabled` itself.
const KERBEROS_ENABLED: &str = "LLDAP_KERBEROS_OPTIONS__ENABLED";

pub fn create_lldap_command(subcommand: &str, db_url: &str) -> Command {
    let mut cmd = Command::new(cargo_bin!());
    let path = canonicalize("..").expect("canonical path to repo root");
    cmd.current_dir(path);
    cmd.env(env::DB_KEY, db_url);
    cmd.env(env::PRIVATE_KEY_SEED, "Random value for test");
    cmd.env(env::JWT_SECRET, "Random JWT secret for test");
    cmd.env(KERBEROS_ENABLED, "false");
    cmd.env(env::LDAP_USER_PASSWORD, "password");
    cmd.arg(subcommand);
    cmd.arg("--config-file=/dev/null");
    cmd.arg("--server-key-file=''");
    cmd
}

/// The migration tests bring their own database and key: no seed, no admin password.
pub fn create_lldap_command_with_key_file(
    subcommand: &str,
    db_url: &str,
    key_file: &str,
) -> Command {
    let mut cmd = Command::new(cargo_bin!());
    let path = canonicalize("..").expect("canonical path to repo root");
    cmd.current_dir(path);
    cmd.env(env::DB_KEY, db_url);
    cmd.env_remove(env::PRIVATE_KEY_SEED);
    cmd.env(env::JWT_SECRET, "Random JWT secret for test");
    cmd.env(KERBEROS_ENABLED, "false");
    cmd.arg(subcommand);
    cmd.arg("--config-file=/dev/null");
    cmd.arg(format!("--server-key-file={key_file}"));
    cmd
}

pub struct ServerGuard {
    child: ChildProcess,
    ldap_port: u16,
    http_port: u16,
}

impl ServerGuard {
    pub fn http_url(&self) -> String {
        http_url(self.http_port)
    }
    pub fn ldap_url(&self) -> String {
        format!("ldap://localhost:{}", self.ldap_port)
    }
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

/// Boots `run` on ephemeral ports and waits for `healthcheck`; the guard stops it with
/// SIGTERM, so a test can inspect the database after a clean shutdown and boot again.
pub fn spawn_and_wait_healthy(make_command: impl Fn(&str) -> Command) -> ServerGuard {
    let ldap_port = free_port();
    let http_port = free_port();
    let child = make_command("run")
        .env("LLDAP_LDAP_PORT", ldap_port.to_string())
        .env("LLDAP_HTTP_PORT", http_port.to_string())
        .spawn()
        .expect("unable to start server");
    let guard = ServerGuard {
        child,
        ldap_port,
        http_port,
    };
    for _ in 0..30 {
        let healthy = make_command("healthcheck")
            .env("LLDAP_LDAP_PORT", ldap_port.to_string())
            .env("LLDAP_HTTP_PORT", http_port.to_string())
            .status()
            .expect("healthcheck failed to execute")
            .success();
        if healthy {
            return guard;
        }
        thread::sleep(Duration::from_millis(1000));
    }
    panic!("server did not become healthy");
}

pub fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime")
}

pub fn exec_sql(db_url: &str, sql: &str) {
    runtime().block_on(async {
        let db = Database::connect(db_url).await.expect("connect db");
        db.execute(Statement::from_string(DbBackend::Sqlite, sql.to_owned()))
            .await
            .expect("execute");
    });
}

pub fn query_i64(db_url: &str, sql: &str) -> i64 {
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
