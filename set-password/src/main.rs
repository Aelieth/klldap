#![forbid(unsafe_code)]

use std::env;

use anyhow::{Context, Result, bail, ensure};
use clap::Parser;
use lldap_auth::kerberos_envelope::{SealTo, finish_with_envelope};
use lldap_auth::{
    PASSWORD_LENGTH_UNIT, PASSWORD_MIN_LENGTH, PasswordShapeError, opaque, password_shape,
    registration,
};
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
        help = "Skip the minimum password length only (8, and the user's minimum from the server). An empty password, or one with a NUL character, is still refused. Unsafe"
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

/// The bypass skips the minimum only, never the empty or NUL check.
fn check_shape(password: &str, min: usize, bypass: bool) -> Result<()> {
    match password_shape(password, if bypass { 0 } else { min }) {
        Ok(()) => Ok(()),
        Err(PasswordShapeError::TooShort(_)) => {
            bail!("New password is too short, expected at least {min} {PASSWORD_LENGTH_UNIT}")
        }
        Err(other) => bail!("{other}"),
    }
}

fn check_min_length(password: &str, min: Option<u32>, bypass: bool) -> Result<()> {
    check_shape(password, min.map_or(0, |min| min as usize), bypass)
}

fn check_floor(password: &str, bypass: bool) -> Result<()> {
    check_shape(password, PASSWORD_MIN_LENGTH, bypass)
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
        .context("no password given: pass --password or set LLDAP_USER_PASSWORD")?;

    check_floor(&password, opts.bypass_password_policy)?;
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
    let request = registration::ClientRegistrationFinishRequest {
        server_data: res.server_data,
        registration_upload: registration_finish.message,
    };
    let key = kerberos_envelope_key.as_deref();
    let req = finish_with_envelope(request, key, SealTo::Answered, &opts.username, &password)?;

    register_finish(&opts.base_url, &token, req)?;

    println!("Successfully changed {}'s password", &opts.username);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use lldap_auth::password_length;

    #[test]
    fn test_the_tool_counts_a_new_password_as_password_length() {
        const SHORT_8: &str = "New password is too short, expected at least 8 characters";
        const SHORT_12: &str = "New password is too short, expected at least 12 characters";
        const EMPTY: &str = "the password must not be empty";
        type Row = (
            &'static str,
            u32,
            (usize, usize),
            Result<(), &'static str>,
            Result<(), &'static str>,
            Result<(), &'static str>,
        );
        let rows: [Row; 5] = [
            ("ääääääää", 12, (8, 16), Ok(()), Err(SHORT_12), Ok(())),
            ("ääää", 8, (4, 8), Err(SHORT_8), Err(SHORT_8), Ok(())),
            ("äääääää", 12, (7, 14), Err(SHORT_8), Err(SHORT_12), Ok(())),
            (
                "e\u{301}e\u{301}e\u{301}e\u{301}",
                8,
                (8, 12),
                Ok(()),
                Ok(()),
                Ok(()),
            ),
            ("", 8, (0, 0), Err(EMPTY), Err(EMPTY), Err(EMPTY)),
        ];
        let text = |checked: Result<()>| checked.map_err(|e| e.to_string());
        let got = rows.map(|(password, min, ..)| {
            (
                password,
                min,
                (password_length(password), password.len()),
                text(check_floor(password, false)),
                text(check_min_length(password, Some(min), false)),
                (
                    text(check_floor(password, true)),
                    text(check_min_length(password, Some(min), true)),
                ),
            )
        });
        let want = rows.map(|(password, min, counts, floor, minimum, bypassed)| {
            let owned = |r: Result<(), &str>| r.map_err(str::to_owned);
            let bypassed = (owned(bypassed), owned(bypassed));
            (
                password,
                min,
                counts,
                owned(floor),
                owned(minimum),
                bypassed,
            )
        });
        assert_eq!(got, want);
        for (password, min, _, floor, minimum, _) in rows {
            let length = password_length(password);
            assert_eq!(
                (floor.is_err(), minimum.is_err()),
                (length < 8, length < min as usize),
                "{password:?}: the floor and the server's minimum count alike"
            );
        }
    }

    #[test]
    fn test_the_bypass_skips_the_minimum_only_never_the_nul_check() {
        const SHORT_8: &str = "New password is too short, expected at least 8 characters";
        const SHORT_12: &str = "New password is too short, expected at least 12 characters";
        const NUL: &str = "the password must not contain a NUL character (U+0000)";
        const EMPTY: &str = "the password must not be empty";
        type Row = (
            &'static str,
            bool,
            Result<(), &'static str>,
            Result<(), &'static str>,
        );
        let rows: [Row; 10] = [
            ("abc", true, Ok(()), Ok(())),
            ("abc", false, Err(SHORT_8), Err(SHORT_12)),
            ("", false, Err(EMPTY), Err(EMPTY)),
            ("", true, Err(EMPTY), Err(EMPTY)),
            ("\0", true, Err(NUL), Err(NUL)),
            ("a\0b", true, Err(NUL), Err(NUL)),
            ("a\0b", false, Err(NUL), Err(NUL)),
            ("Twelve-12chr\0", false, Err(NUL), Err(NUL)),
            ("Twelve-12chr", false, Ok(()), Ok(())),
            ("Twelve-12chr", true, Ok(()), Ok(())),
        ];
        let text = |checked: Result<()>| checked.map_err(|e| e.to_string());
        let got = rows.map(|(password, bypass, ..)| {
            let floor = text(check_floor(password, bypass));
            let minimum = text(check_min_length(password, Some(12), bypass));
            (password, bypass, floor, minimum)
        });
        let want = rows.map(|(password, bypass, floor, minimum)| {
            let owned = |r: Result<(), &str>| r.map_err(str::to_owned);
            (password, bypass, owned(floor), owned(minimum))
        });
        assert_eq!(got, want);
    }

    #[test]
    fn test_the_servers_minimum_stops_a_shorter_password_before_the_finish() {
        const SEVEN: &str = "Seven-7";
        const ELEVEN: &str = "Eleven-11ch";
        const TWELVE: &str = "Twelve-12chr";
        const ELEVEN_UMLAUTS: &str = "pässwörter1";
        let too_short = "New password is too short, expected at least 12 characters";
        let empty = "the password must not be empty";
        let rows = [
            (ELEVEN, Some(12), false, Err(too_short)),
            (ELEVEN_UMLAUTS, Some(12), false, Err(too_short)),
            (TWELVE, Some(12), false, Ok(())),
            (ELEVEN, Some(12), true, Ok(())),
            (ELEVEN, None, false, Ok(())),
            (SEVEN, None, false, Ok(())),
            ("", None, false, Err(empty)),
            ("", None, true, Err(empty)),
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
