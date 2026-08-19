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
use std::process::{Child as ChildProcess, Command};
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
    _dir: tempfile::TempDir,
}

const MAX_HEALTHCHECK_ATTEMPS: u8 = 30;

impl LLDAPFixture {
    pub fn new() -> Self {
        let dir = tempfile::TempDir::new().expect("temp dir");
        let db_path = format!("sqlite://{}/users.db?mode=rwc", dir.path().display());
        let ldap_port = free_port();
        let http_port = free_port();
        let child = create_lldap_command("run", &db_path)
            .env("LLDAP_LDAP_PORT", ldap_port.to_string())
            .env("LLDAP_HTTP_PORT", http_port.to_string())
            .arg("--verbose")
            .spawn()
            .expect("Unable to start server");

        let mut started = false;
        for attempt in 0..MAX_HEALTHCHECK_ATTEMPS {
            let status = create_lldap_command("healthcheck", &db_path)
                .env("LLDAP_LDAP_PORT", ldap_port.to_string())
                .env("LLDAP_HTTP_PORT", http_port.to_string())
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
            _dir: dir,
        }
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
        let result = signal::kill(
            Pid::from_raw(self.child.id().try_into().unwrap()),
            Signal::SIGTERM,
        );

        if let Err(err) = result {
            println!("Failed to send SIGTERM: {err:?}");
            let _ = self.child.kill();
            return;
        }

        for _ in 0..12 {
            match self.child.try_wait() {
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
        let _ = self.child.kill();
    }
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
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind an ephemeral port")
        .local_addr()
        .expect("local addr")
        .port()
}

pub fn create_lldap_command(subcommand: &str, db_url: &str) -> Command {
    let mut cmd = Command::new(cargo_bin!());
    let path = canonicalize("..").expect("canonical path to repo root");
    cmd.current_dir(path);
    cmd.env(env::DB_KEY, db_url);
    cmd.env(env::PRIVATE_KEY_SEED, "Random value for test");
    cmd.env(env::JWT_SECRET, "Random JWT secret for test");
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
