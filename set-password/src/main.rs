#![forbid(unsafe_code)]

use std::env;
use std::io::{BufRead, Write};

use anyhow::{Context, Result, bail, ensure};
use clap::Parser;
use lldap_auth::kerberos_envelope::{SealTo, finish_with_envelope};
use lldap_auth::{
    PASSWORD_LENGTH_UNIT, PASSWORD_MIN_LENGTH, PasswordShapeError, login, opaque, password_shape,
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

    #[clap(
        long,
        help = "Admin password, proved to the server by an OPAQUE login. With a second factor, the code is asked next"
    )]
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

/// A token as given, or the admin's OPAQUE login and the envelope key it bound.
#[derive(Debug, PartialEq, Eq)]
enum SignedIn {
    Token(String),
    Login {
        token: String,
        bound_key: Option<String>,
    },
}

impl SignedIn {
    fn bearer(&self) -> &str {
        match self {
            SignedIn::Token(token) | SignedIn::Login { token, .. } => token,
        }
    }

    /// A token binds no key: the tool given one seals to the key as the start answers it.
    fn seal_to(&self) -> SealTo<'_> {
        match self {
            SignedIn::Token(_) => SealTo::Answered,
            SignedIn::Login { bound_key, .. } => SealTo::Bound(bound_key.as_deref()),
        }
    }
}

const ENROLL_FIRST: &str = "the admin must enroll a second factor first, through the web interface";

#[derive(Debug, PartialEq, Eq)]
enum Finished {
    Token(String),
    CodeRequired,
}

fn finished(body: &str) -> Result<Finished> {
    let challenge = serde_json::from_str::<login::ServerMfaRequiredResponse>(body);
    if challenge.is_ok_and(|challenge| challenge.mfa_required) {
        return Ok(Finished::CodeRequired);
    }
    let answer: login::ServerLoginResponse =
        serde_json::from_str(body).context("Could not parse the login's answer")?;
    if answer.mfa_enrollment_required == Some(true) {
        bail!("{ENROLL_FIRST}");
    }
    Ok(Finished::Token(answer.token))
}

fn login_start(
    username: &str,
    password: &str,
) -> Result<(opaque::client::login::ClientLogin, login::ClientLoginStart)> {
    let start = opaque::client::login::start_login(password, &mut rand::rngs::OsRng)
        .context("Could not start the login")?;
    let request = login::ClientLoginStart {
        request: login::ClientLoginStartRequest {
            username: username.into(),
            login_start_request: start.message,
        },
        kerberos_envelope_key: Some(true),
    };
    Ok((start.state, request))
}

fn login_once(
    base_url: &Url,
    username: &str,
    password: &str,
    totp_code: Option<String>,
) -> Result<(Finished, Option<String>)> {
    let (state, request) = login_start(username, password)?;
    let started = call_server(
        append_to_url(base_url, "auth/opaque/login/start"),
        None,
        request,
    )?;
    let answer: login::ServerLoginStart =
        serde_json::from_str(&started).context("Could not parse the login's start")?;
    let (request, bound_key) =
        login::finish_bound(state, password.as_bytes(), answer, &mut rand::rngs::OsRng)
            .context("Invalid username or password")?;
    let request = login::ClientLoginFinishRequest {
        totp_code,
        ..request
    };
    let body = call_server(
        append_to_url(base_url, "auth/opaque/login/finish"),
        None,
        request,
    )?;
    Ok((finished(&body)?, bound_key))
}

/// An admin with a second factor is asked the code, as the web login asks, and signs in again.
fn sign_in(
    base_url: &Url,
    username: &str,
    password: &str,
    ask_code: impl FnOnce() -> Result<String>,
) -> Result<SignedIn> {
    let (first, bound_key) = login_once(base_url, username, password, None)?;
    let (answer, bound_key) = match first {
        Finished::CodeRequired => login_once(base_url, username, password, Some(ask_code()?))?,
        signed_in => (signed_in, bound_key),
    };
    let Finished::Token(token) = answer else {
        bail!("The server asked for the code again");
    };
    Ok(SignedIn::Login { token, bound_key })
}

fn read_code(admin: &str) -> Result<String> {
    eprint!("Code from {admin}'s authenticator: ");
    std::io::stderr().flush()?;
    let mut code = String::new();
    std::io::stdin().lock().read_line(&mut code)?;
    Ok(code.trim().to_owned())
}

fn call_server(url: Url, token: Option<&str>, body: impl Serialize) -> Result<String> {
    let client = reqwest::blocking::Client::new();
    let mut request = client
        .post(url)
        .header("Content-Type", "application/json")
        .body(serde_json::to_string(&body)?);
    if let Some(token) = token {
        request = request.bearer_auth(token);
    }
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
        Some(token),
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
        Some(token),
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
    let signed_in = match (opts.token.as_ref(), opts.admin_password.as_ref()) {
        (Some(token), _) => SignedIn::Token(token.clone()),
        (None, Some(admin_password)) => {
            let admin = &opts.admin_username;
            let ask_code = || read_code(admin);
            sign_in(&opts.base_url, admin, admin_password, ask_code).context("While logging in")?
        }
        (None, None) => bail!("Either the token or the admin password is required"),
    };
    let token = signed_in.bearer();

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
    } = register_start(&opts.base_url, token, start_request)?;
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
    let seal_to = signed_in.seal_to();
    let req = finish_with_envelope(request, key, seal_to, &opts.username, &password)?;

    register_finish(&opts.base_url, token, req)?;

    println!("Successfully changed {}'s password", &opts.username);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use lldap_auth::kerberos_envelope::KeyNotBound;
    use lldap_auth::password_length;
    use lldap_auth::types::UserId;

    const BOB_PASS: &str = "Bob-Password-1";

    fn finish_request() -> registration::ClientRegistrationFinishRequest {
        let mut rng = rand::rngs::OsRng;
        let password = BOB_PASS.as_bytes();
        let start = opaque::client::registration::start_registration(password, &mut rng).unwrap();
        let setup = opaque::server::ServerSetup::new(&mut rng);
        let bob = UserId::new("bob");
        let answer =
            opaque::server::registration::start_registration(&setup, start.message, &bob).unwrap();
        let finish = opaque::client::registration::finish_registration(
            start.state,
            password,
            answer.message,
            &mut rng,
        )
        .unwrap();
        registration::ClientRegistrationFinishRequest {
            server_data: "sealed".to_owned(),
            registration_upload: finish.message,
        }
    }

    #[test]
    fn test_the_tool_seals_only_to_the_key_its_login_bound() {
        type Row = (
            &'static str,
            SignedIn,
            Option<&'static str>,
            Result<bool, String>,
        );
        let token = || SignedIn::Token("t".to_owned());
        let logged_in = |key: Option<&str>| SignedIn::Login {
            token: "t".to_owned(),
            bound_key: key.map(str::to_owned),
        };
        let not_bound = Err(KeyNotBound.to_string());
        let sealed = Err("Base64 decode of the Kerberos envelope key failed".to_owned());
        let rows: [Row; 6] = [
            (
                "a token, a key answered",
                token(),
                Some("no key!"),
                sealed.clone(),
            ),
            ("a token, none answered", token(), None, Ok(false)),
            (
                "the login's own key",
                logged_in(Some("no key!")),
                Some("no key!"),
                sealed,
            ),
            (
                "another key",
                logged_in(Some("other")),
                Some("no key!"),
                not_bound.clone(),
            ),
            (
                "the login bound none",
                logged_in(None),
                Some("no key!"),
                not_bound,
            ),
            ("none answered", logged_in(Some("no key!")), None, Ok(false)),
        ];
        let request = finish_request();
        for (row, signed_in, answered, expected) in rows {
            assert_eq!(signed_in.bearer(), "t", "{row}");
            let seal_to = signed_in.seal_to();
            let got = finish_with_envelope(request.clone(), answered, seal_to, "bob", BOB_PASS)
                .map(|finish| finish.kerberos_password_envelope.is_some())
                .map_err(|e| e.to_string());
            assert_eq!(got, expected, "{row}");
        }
    }

    #[test]
    fn test_the_tools_login_takes_a_token_or_asks_the_code() {
        let unread = "Could not parse the login's answer";
        let rows = [
            (
                r#"{"token": "t", "refreshToken": "r"}"#,
                Ok(Finished::Token("t".to_owned())),
            ),
            (
                r#"{"token": "t", "mfaEnrollmentRequired": true}"#,
                Err(ENROLL_FIRST),
            ),
            (r#"{"mfaRequired": true}"#, Ok(Finished::CodeRequired)),
            (r#"{"mfaRequired": false}"#, Err(unread)),
            (r#"{"verified": true}"#, Err(unread)),
        ];
        for (body, expected) in rows {
            let got = finished(body).map_err(|e| e.to_string());
            assert_eq!(got, expected.map_err(str::to_owned), "{body}");
        }
    }

    #[test]
    fn test_the_tools_login_start_asks_for_the_key_and_carries_no_password() {
        let (_, start) = login_start("admin", "Admin-Pass-1").unwrap();
        let wire = serde_json::to_value(&start).unwrap();
        let text = wire.to_string();
        assert_eq!(
            (
                wire["kerberos_envelope_key"].as_bool(),
                wire["username"].as_str(),
                text.contains("Admin-Pass-1")
            ),
            (Some(true), Some("admin"), false)
        );
    }

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
