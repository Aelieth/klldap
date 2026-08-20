use crate::common::env;
use lldap_auth::types::UserId;
use reqwest::blocking::Client;

pub fn get_token(client: &Client, base_url: &str) -> String {
    get_token_for(client, base_url, &env::admin_dn(), &env::admin_password())
}

pub fn get_token_for(client: &Client, base_url: &str, username: &str, password: &str) -> String {
    let response = client
        .post(format!("{base_url}/auth/simple/login"))
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(
            serde_json::to_string(&lldap_auth::login::ClientSimpleLoginRequest {
                username: UserId::new(username),
                password: password.to_owned(),
            })
            .expect("Failed to encode the username/password as json to log in"),
        )
        .send()
        .expect("Failed to send auth request")
        .error_for_status()
        .expect("Auth attempt failed");
    serde_json::from_str::<lldap_auth::login::ServerLoginResponse>(
        &response.text().expect("Failed to get response text"),
    )
    .expect("Failed to parse json")
    .token
}
