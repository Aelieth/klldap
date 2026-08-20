#![allow(dead_code)]
use crate::common::env;
use lldap_auth::types::UserId;
use lldap_auth::{login, opaque, registration};
use reqwest::StatusCode;
use reqwest::blocking::Client;
use serde_json::Value;

pub fn get_token(client: &Client, base_url: &str) -> String {
    get_token_for(client, base_url, &env::admin_dn(), &env::admin_password())
}

pub fn get_token_for(client: &Client, base_url: &str, username: &str, password: &str) -> String {
    let response = client
        .post(format!("{base_url}/auth/simple/login"))
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(
            serde_json::to_string(&login::ClientSimpleLoginRequest {
                username: UserId::new(username),
                password: password.to_owned(),
            })
            .expect("Failed to encode the username/password as json to log in"),
        )
        .send()
        .expect("Failed to send auth request")
        .error_for_status()
        .expect("Auth attempt failed");
    serde_json::from_str::<login::ServerLoginResponse>(
        &response.text().expect("Failed to get response text"),
    )
    .expect("Failed to parse json")
    .token
}

// The web login ceremony: the finish status and body — a token, the TOTP challenge, or
// the refusal text.
pub fn opaque_login(
    client: &Client,
    base_url: &str,
    username: &str,
    password: &str,
    totp_code: Option<&str>,
) -> (StatusCode, Value) {
    let mut rng = rand::rngs::OsRng;
    let start = opaque::client::login::start_login(password, &mut rng).expect("login start");
    let start_response: login::ServerLoginStartResponse = client
        .post(format!("{base_url}/auth/opaque/login/start"))
        .json(&login::ClientLoginStartRequest {
            username: UserId::new(username),
            login_start_request: start.message,
        })
        .send()
        .expect("login start send")
        .error_for_status()
        .expect("login start status")
        .json()
        .expect("login start json");
    let finish = opaque::client::login::finish_login(
        start.state,
        password.as_bytes(),
        start_response.credential_response,
        &mut rng,
    )
    .expect("login finish");
    let response = client
        .post(format!("{base_url}/auth/opaque/login/finish"))
        .json(&login::ClientLoginFinishRequest {
            server_data: start_response.server_data,
            credential_finalization: finish.message,
            totp_code: totp_code.map(str::to_owned),
        })
        .send()
        .expect("login finish send");
    let status = response.status();
    let text = response.text().expect("login finish body");
    (
        status,
        serde_json::from_str(&text).unwrap_or(Value::String(text)),
    )
}

// Sets a password through the OPAQUE registration endpoints with the given bearer.
pub fn register_password_over_http(
    client: &Client,
    base_url: &str,
    bearer: &str,
    username: &str,
    password: &str,
) {
    let mut rng = rand::rngs::OsRng;
    let start = opaque::client::registration::start_registration(password.as_bytes(), &mut rng)
        .expect("registration start");
    let start_response: registration::ServerRegistrationStartResponse = client
        .post(format!("{base_url}/auth/opaque/register/start"))
        .bearer_auth(bearer)
        .json(&registration::ClientRegistrationStartRequest {
            username: UserId::new(username),
            registration_start_request: start.message,
        })
        .send()
        .expect("register start send")
        .error_for_status()
        .expect("register start status")
        .json()
        .expect("register start json");
    let finish = opaque::client::registration::finish_registration(
        start.state,
        password.as_bytes(),
        start_response.registration_response,
        &mut rng,
    )
    .expect("registration finish");
    client
        .post(format!("{base_url}/auth/opaque/register/finish"))
        .bearer_auth(bearer)
        .json(&registration::ClientRegistrationFinishRequest {
            server_data: start_response.server_data,
            registration_upload: finish.message,
        })
        .send()
        .expect("register finish send")
        .error_for_status()
        .expect("register finish status");
}
