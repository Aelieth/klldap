#![forbid(unsafe_code)]

use std::env;

use anyhow::{Context, Result, bail, ensure};
use clap::Parser;
use lldap_auth::kerberos_envelope::seal_kerberos_envelope;
use lldap_auth::{opaque, registration};
use reqwest::Url;
use serde::Serialize;

#[derive(Debug, Parser, Clone)]
#[command(about = "Set the password for a user in LLDAP")]
pub struct CliOpts {
    #[clap(short, long, help = "Base LLDAP url, e.g. \"https://lldap/\"")]
    pub base_url: Url,

    #[clap(long, default_value = "admin", help = "Admin username")]
    pub admin_username: String,

    #[clap(long, help = "Admin password")]
    pub admin_password: Option<String>,

    #[clap(short, long, help = "Connection token (JWT)")]
    pub token: Option<String>,

    #[clap(short, long, help = "Username")]
    pub username: String,

    #[clap(
        short,
        long,
        help = "New password for the user, required. Can also be passed as the environment variable LLDAP_USER_PASSWORD. An empty one is refused"
    )]
    pub password: Option<String>,

    #[clap(
        long,
        help = "Skip the minimum length check. An empty password is still refused. Unsafe"
    )]
    pub bypass_password_policy: bool,
}

fn append_to_url(base_url: &Url, path: &str) -> Url {
    let mut new_url = base_url.clone();
    new_url.path_segments_mut().unwrap().extend(path.split('/'));
    new_url
}

fn get_token(base_url: &Url, username: &str, password: &str) -> Result<String> {
    let client = reqwest::blocking::Client::new();
    let response = client
        .post(append_to_url(base_url, "auth/simple/login"))
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(
            serde_json::to_string(&lldap_auth::login::ClientSimpleLoginRequest {
                username: username.into(),
                password: password.to_string(),
                enrollment_proof: None,
            })
            .expect("Failed to encode the username/password as json to log in"),
        )
        .send()?
        .error_for_status()?;
    Ok(serde_json::from_str::<lldap_auth::login::ServerLoginResponse>(&response.text()?)?.token)
}

fn call_server(url: Url, token: &str, body: impl Serialize) -> Result<String> {
    let client = reqwest::blocking::Client::new();
    let request = client
        .post(url)
        .header("Content-Type", "application/json")
        .bearer_auth(token)
        .body(serde_json::to_string(&body)?);
    let response = request.send()?;
    let status = response.status();
    let text = response.text()?;
    if !status.is_success() {
        bail!("{status}: {text}");
    }
    Ok(text)
}

pub fn register_start(
    base_url: &Url,
    token: &str,
    request: registration::ClientRegistrationStartRequest,
) -> Result<registration::ServerRegistrationStart> {
    let request = Some(request);
    let data = call_server(
        append_to_url(base_url, "auth/opaque/register/start"),
        token,
        request,
    )?;
    serde_json::from_str(&data).context("Could not parse response")
}

/// The user's minimum from the start's answer; an old server sends none.
fn check_min_length(password: &str, min: Option<u32>, bypass: bool) -> Result<()> {
    if let Some(min) = min.filter(|_| !bypass) {
        ensure!(
            password.chars().count() >= min as usize,
            "New password is too short, expected at least {min} characters"
        );
    }
    Ok(())
}

pub fn register_finish(
    base_url: &Url,
    token: &str,
    request: registration::ClientRegistrationFinish,
) -> Result<()> {
    let request = Some(request);
    call_server(
        append_to_url(base_url, "auth/opaque/register/finish"),
        token,
        request,
    )
    .map(|_| ())
}

fn main() -> Result<()> {
    let opts = CliOpts::parse();

    let password = opts
        .password
        .or_else(|| env::var("LLDAP_USER_PASSWORD").ok())
        .filter(|password| !password.is_empty())
        .context("no password given: pass --password or set LLDAP_USER_PASSWORD")?;

    ensure!(
        opts.bypass_password_policy || password.chars().count() >= 8,
        "New password is too short, expected at least 8 characters"
    );
    ensure!(
        opts.base_url.scheme() == "http" || opts.base_url.scheme() == "https",
        "Base URL should start with `http://` or `https://`"
    );
    let token = match (opts.token.as_ref(), opts.admin_password.as_ref()) {
        (Some(token), _) => token.clone(),
        (None, Some(password)) => {
            get_token(&opts.base_url, &opts.admin_username, password).context("While logging in")?
        }
        (None, None) => bail!("Either the token or the admin password is required"),
    };

    let mut rng = rand::rngs::OsRng;
    let registration_start_request =
        opaque::client::registration::start_registration(password.as_bytes(), &mut rng)
            .context("Could not initiate password change")?;
    let start_request = registration::ClientRegistrationStartRequest {
        username: opts.username.clone().into(),
        registration_start_request: registration_start_request.message,
    };
    let registration::ServerRegistrationStart {
        response: res,
        kerberos_envelope_key,
        password_min_length,
    } = register_start(&opts.base_url, &token, start_request)?;
    check_min_length(&password, password_min_length, opts.bypass_password_policy)?;

    let registration_finish = opaque::client::registration::finish_registration(
        registration_start_request.state,
        password.as_bytes(),
        res.registration_response,
        &mut rng,
    )
    .context("Error during password change")?;
    let kerberos_password_envelope = kerberos_envelope_key
        .map(|key| seal_kerberos_envelope(&key, &opts.username, &password))
        .transpose()?;
    let req = registration::ClientRegistrationFinish {
        request: registration::ClientRegistrationFinishRequest {
            server_data: res.server_data,
            registration_upload: registration_finish.message,
        },
        kerberos_password_envelope,
    };

    register_finish(&opts.base_url, &token, req)?;

    println!("Successfully changed {}'s password", &opts.username);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_the_servers_minimum_stops_a_shorter_password_before_the_finish() {
        const SEVEN: &str = "Seven-7";
        const ELEVEN: &str = "Eleven-11ch";
        const TWELVE: &str = "Twelve-12chr";
        const ELEVEN_UMLAUTS: &str = "pässwörter1";
        let too_short = "New password is too short, expected at least 12 characters";
        let rows = [
            (ELEVEN, Some(12), false, Err(too_short)),
            (ELEVEN_UMLAUTS, Some(12), false, Err(too_short)),
            (TWELVE, Some(12), false, Ok(())),
            (ELEVEN, Some(12), true, Ok(())),
            (ELEVEN, None, false, Ok(())),
            (SEVEN, None, false, Ok(())),
        ];
        assert_eq!(
            [SEVEN, ELEVEN, TWELVE, ELEVEN_UMLAUTS].map(|p| (p.chars().count(), p.len())),
            [(7, 7), (11, 11), (12, 12), (11, 13)]
        );
        for (password, min, bypass, expected) in rows {
            let got = check_min_length(password, min, bypass).map_err(|e| e.to_string());
            let expected = expected.map_err(str::to_owned);
            assert_eq!(got, expected, "{password} {min:?} {bypass}");
        }
    }
}
