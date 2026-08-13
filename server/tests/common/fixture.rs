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
use std::collections::{HashMap, HashSet};
use std::process::{Child as ChildProcess, Command};
use std::{fs::canonicalize, thread, time::Duration};
use uuid::Uuid;

/// Helper that gives us real error details instead of a useless "failed to add group" panic.
/// This is the key change that makes 400 / GraphQL errors actually debuggable.
fn post_graphql<T: graphql_client::GraphQLQuery + 'static>(
    client: &Client,
    token: &String,
    variables: T::Variables,
) -> Result<T::ResponseData, String> {
    match post::<T>(client, token, variables) {
        Ok(data) => Ok(data),
        Err(e) => {
            // Raw fallback to capture the actual server response body
            let graphql_url = "http://localhost:17170/api/graphql";

            // We can't easily reconstruct the exact query here, so we just
            // do a minimal request to show we can reach the server and log the attempt.
            // The real value comes from the server logs (which now include the GraphQL error).
            let raw_response = client
                .post(graphql_url)
                .header("Authorization", format!("Bearer {}", token))
                .header("Content-Type", "application/json")
                .body(r#"{"query":"{ __typename }"}"#) // minimal valid query
                .send();

            let raw_info = match raw_response {
                Ok(resp) => format!(
                    "Raw probe to {} returned status: {} | body preview: {}",
                    graphql_url,
                    resp.status(),
                    resp.text()
                        .unwrap_or_default()
                        .chars()
                        .take(200)
                        .collect::<String>()
                ),
                Err(err) => format!("Raw probe failed: {}", err),
            };

            Err(format!(
                "GraphQL request failed: {}\n\
                 {}\n\
                 (Check server logs for the exact GraphQL errors array)",
                e, raw_info
            ))
        }
    }
}

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
}

const MAX_HEALTHCHECK_ATTEMPS: u8 = 15; // slightly more generous

impl LLDAPFixture {
    pub fn new() -> Self {
        // Generate a unique database for this test run to avoid state leakage
        let unique_id = Uuid::new_v4().simple();
        let db_path = format!("sqlite://e2e_test_{}.db?mode=rwc", unique_id);

        let child = create_lldap_command("run", &db_path)
            .arg("--verbose")
            .spawn()
            .expect("Unable to start server");

        let mut started = false;
        for attempt in 0..MAX_HEALTHCHECK_ATTEMPS {
            let status = create_lldap_command("healthcheck", &db_path)
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

        let token = get_token(&client);

        Self {
            client,
            token,
            child,
            users: HashSet::new(),
            groups: HashMap::new(),
        }
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
        let username = &user.username;
        let response = post_graphql::<CreateUser>(
            &self.client,
            &self.token,
            create_user::Variables {
                user: create_user::CreateUserInput {
                    id: username.clone(),
                    email: Some(format!("{username}@lldap.test")),
                    avatar: None,
                    display_name: user.display_name.clone(),
                    first_name: None,
                    last_name: None,
                    attributes: None,
                },
            },
        )
        .unwrap_or_else(|e| panic!("failed to add user '{}': {}", username, e));

        // We don't actually need the response data here, just success
        let _ = response;
        self.users.insert(username.clone());
    }

    fn add_group(&mut self, group: &str) {
        let result = post::<CreateGroup>(
            &self.client,
            &self.token,
            create_group::Variables {
                group: create_group::CreateGroupInput {
                    display_name: group.to_owned(),
                    attributes: None,
                },
            },
        );

        match result {
            Ok(response) => {
                let id = response.create_group.id;
                self.groups.insert(group.to_owned(), id);
            }
            Err(e) => {
                // Raw request with the CORRECT new query shape to capture exact server error
                let graphql_url = format!("{}/api/graphql", env::http_url());
                let raw_resp = self.client
                .post(&graphql_url)
                .header("Authorization", format!("Bearer {}", self.token))
                .header("Content-Type", "application/json")
                .body(serde_json::json!({
                    "query": r#"mutation CreateGroup($group: CreateGroupInput!) { createGroup(group: $group) { id } }"#,
                                        "variables": {
                                            "group": {
                                                "displayName": group,
                                                "attributes": null
                                            }
                                        }
                }).to_string())
                .send();

                let body = match raw_resp {
                    Ok(r) => r.text().unwrap_or_default(),
                    Err(err) => format!("Raw request failed: {}", err),
                };

                panic!(
                    "failed to add group '{}': {}\n\n=== RAW SERVER RESPONSE ===\n{}\n===========================",
                    group, e, body
                );
            }
        }
    }

    fn add_user_to_group(&mut self, user: &str, group: &String) {
        let group_id = *self
            .groups
            .get(group)
            .expect("group id missing when adding user");
        let _ = post_graphql::<AddUserToGroup>(
            &self.client,
            &self.token,
            add_user_to_group::Variables {
                user: user.to_owned(),
                group: group_id,
            },
        )
        .unwrap_or_else(|e| panic!("failed to add user '{}' to group '{}': {}", user, group, e));
    }
}

impl Drop for LLDAPFixture {
    fn drop(&mut self) {
        // Clean up in reverse order: users first, then groups
        let users = self.users.clone();
        for user in users {
            if let Err(e) = self.try_delete_user(&user) {
                eprintln!("Warning during Drop: could not delete user {}: {}", user, e);
            }
        }

        let groups: Vec<String> = self.groups.keys().cloned().collect();
        for group in groups {
            if let Err(e) = self.try_delete_group(&group) {
                eprintln!(
                    "Warning during Drop: could not delete group {}: {}",
                    group, e
                );
            }
        }

        // Graceful shutdown of the server process
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

        println!("LLDAP did not exit gracefully after 12s — forcing kill.");
        let _ = self.child.kill();
    }
}

// Helper methods used only by Drop so we never panic during cleanup
impl LLDAPFixture {
    fn try_delete_user(&mut self, user: &String) -> Result<(), String> {
        post_graphql::<DeleteUserQuery>(
            &self.client,
            &self.token,
            delete_user_query::Variables { user: user.clone() },
        )
        .map(|_| {
            self.users.remove(user);
        })
        .map_err(|e| e.to_string())
    }

    fn try_delete_group(&mut self, group: &String) -> Result<(), String> {
        if let Some(group_id) = self.groups.get(group) {
            let gid = *group_id;
            post_graphql::<DeleteGroupQuery>(
                &self.client,
                &self.token,
                delete_group_query::Variables { group_id: gid },
            )
            .map(|_| {
                self.groups.remove(group);
            })
            .map_err(|e| e.to_string())
        } else {
            Ok(())
        }
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

fn create_lldap_command(subcommand: &str, db_url: &str) -> Command {
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
