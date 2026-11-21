//! Client half of the OPAQUE ceremonies: registration for the create-user,
//! change-password and reset-password flows, login for the login form, the old-password
//! check and the two-factor pages. Each caller stashes the returned state in its own
//! component field between the start and finish steps.

use crate::infra::encrypt::seal_kerberos_envelope;
use anyhow::{Context, Result, bail, ensure};
use lldap_auth::{login, opaque, registration};

pub type RegistrationState = opaque::client::registration::ClientRegistration;
pub type LoginState = opaque::client::login::ClientLogin;

const START_FAILED: &str = "Could not initiate registration";
const POLICY_UNREADABLE: &str = "the password policy could not be read; try again";

/// The line a failed start shows: the server's sentence only for the unreadable-policy 400.
pub fn start_failure_message(failure: &str) -> &'static str {
    if failure.contains("[400 ") && failure.contains(POLICY_UNREADABLE) {
        POLICY_UNREADABLE
    } else {
        START_FAILED
    }
}

pub fn registration_started<T>(res: Result<T>) -> Result<T> {
    res.map_err(|e| {
        let shown = start_failure_message(&format!("{e:#}"));
        e.context(shown)
    })
}

/// Begins registration: returns the client state to stash and the start request
/// to POST to the server.
pub fn begin_registration(
    username: &str,
    password: &str,
) -> Result<(
    RegistrationState,
    registration::ClientRegistrationStartRequest,
)> {
    ensure!(!password.is_empty(), "a password is required");
    let mut rng = rand::rngs::OsRng;
    let start = opaque::client::registration::start_registration(password.as_bytes(), &mut rng)
        .context(START_FAILED)?;
    let request = registration::ClientRegistrationStartRequest {
        username: username.into(),
        registration_start_request: start.message,
    };
    Ok((start.state, request))
}

/// The user's `password-min-length` from the start's answer when `password` is shorter.
pub fn unmet_min_length(password: &str, min: Option<u32>) -> Option<u32> {
    min.filter(|&min| password.chars().count() < min as usize)
}

/// Completes registration from the stashed state and the server's start
/// response, producing the finish request to POST.
pub fn finish_registration(
    state: RegistrationState,
    username: &str,
    password: &str,
    start: registration::ServerRegistrationStart,
) -> Result<registration::ClientRegistrationFinish> {
    let registration::ServerRegistrationStart {
        response,
        kerberos_envelope_key,
        password_min_length,
    } = start;
    if let Some(min) = unmet_min_length(password, password_min_length) {
        bail!("Invalid password. Min length: {min}");
    }
    let mut rng = rand::rngs::OsRng;
    let finish = opaque::client::registration::finish_registration(
        state,
        password.as_bytes(),
        response.registration_response,
        &mut rng,
    )
    .context("Error during registration")?;
    let kerberos_password_envelope = kerberos_envelope_key
        .map(|key| seal_kerberos_envelope(&key, username, password))
        .transpose()?;
    Ok(registration::ClientRegistrationFinish {
        request: registration::ClientRegistrationFinishRequest {
            server_data: response.server_data,
            registration_upload: finish.message,
        },
        kerberos_password_envelope,
    })
}

/// Begins a login: returns the client state to stash and the start request to POST.
pub fn begin_login(
    username: &str,
    password: &str,
) -> Result<(LoginState, login::ClientLoginStartRequest)> {
    let mut rng = rand::rngs::OsRng;
    let start = opaque::client::login::start_login(password, &mut rng)
        .context("Could not initialize login")?;
    let request = login::ClientLoginStartRequest {
        username: username.into(),
        login_start_request: start.message,
    };
    Ok((start.state, request))
}

/// What a login finish asks the server for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FinishFor {
    /// A session, with the second factor's code once the server asked for one.
    SignIn(Option<String>),
    /// The server's check of the password, and no session.
    PasswordCheck,
    /// The same check, answered with a first-enrollment proof.
    EnrollmentProof,
}

impl FinishFor {
    fn fields(self) -> (Option<String>, Option<bool>, Option<bool>) {
        match self {
            FinishFor::SignIn(totp_code) => (totp_code, None, None),
            FinishFor::PasswordCheck => (None, None, Some(false)),
            FinishFor::EnrollmentProof => (None, Some(true), Some(false)),
        }
    }
}

/// Completes the login proof from the stashed state and the server's start response,
/// producing the finish request to POST; a wrong password fails here, client-side.
pub fn finish_login(
    state: LoginState,
    password: &str,
    response: login::ServerLoginStartResponse,
    finish_for: FinishFor,
) -> Result<login::ClientLoginFinishRequest> {
    let mut rng = rand::rngs::OsRng;
    let finish = opaque::client::login::finish_login(
        state,
        password.as_bytes(),
        response.credential_response,
        &mut rng,
    )
    .context("Invalid username or password")?;
    let (totp_code, enrollment_proof, session) = finish_for.fields();
    Ok(login::ClientLoginFinishRequest {
        server_data: response.server_data,
        credential_finalization: finish.message,
        totp_code,
        enrollment_proof,
        session,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_a_password_shorter_than_the_servers_minimum_is_not_finished() {
        const SEVEN: &str = "Seven-7";
        const ELEVEN: &str = "Eleven-11ch";
        const TWELVE: &str = "Twelve-12chr";
        const ELEVEN_UMLAUTS: &str = "pässwörter1";
        let rows = [
            (ELEVEN, Some(12), Some(12)),
            (ELEVEN_UMLAUTS, Some(12), Some(12)),
            (TWELVE, Some(12), None),
            (TWELVE, Some(8), None),
            (ELEVEN, None, None),
            (SEVEN, None, None),
        ];
        assert_eq!(
            [SEVEN, ELEVEN, TWELVE, ELEVEN_UMLAUTS].map(|p| (p.chars().count(), p.len())),
            [(7, 7), (11, 11), (12, 12), (11, 13)]
        );
        for (password, min, expected) in rows {
            assert_eq!(
                unmet_min_length(password, min),
                expected,
                "{password} {min:?}"
            );
        }
    }

    #[test]
    fn test_only_the_unreadable_policy_refusal_shows_the_servers_sentence() {
        const UNREADABLE: &str = "the password policy could not be read; try again";
        const GENERIC: &str = "Could not initiate registration";
        let refused =
            |status: &str, body: &str| format!("Could not start registration: [{status}]: {body}");
        let rows = [
            (
                refused(
                    "400 Bad Request",
                    "Bad request: `the password policy could not be read; try again`",
                ),
                UNREADABLE,
            ),
            (
                refused(
                    "400 ",
                    "Bad request: `the password policy could not be read; try again`",
                ),
                UNREADABLE,
            ),
            (
                refused(
                    "500 Internal Server Error",
                    "the password policy could not be read; try again",
                ),
                GENERIC,
            ),
            (
                refused(
                    "400 Bad Request",
                    "Bad request: `the password must be at least 12 characters`",
                ),
                GENERIC,
            ),
            (
                refused(
                    "401 Unauthorized",
                    "Unauthorized: `Not authorized to change the user's password`",
                ),
                GENERIC,
            ),
            ("Could not parse response".to_owned(), GENERIC),
        ];
        for (failure, expected) in rows {
            assert_eq!(start_failure_message(&failure), expected, "{failure}");
            let shown = registration_started::<()>(Err(anyhow::anyhow!("{failure}")))
                .unwrap_err()
                .to_string();
            assert_eq!(shown, expected, "{failure}");
        }
        assert_eq!(registration_started(Ok(7)).unwrap(), 7);
    }

    #[test]
    fn test_only_a_sign_in_asks_for_a_session() {
        let code = || Some("123456".to_owned());
        let rows = [
            (FinishFor::SignIn(None), (None, None, None)),
            (FinishFor::SignIn(code()), (code(), None, None)),
            (FinishFor::PasswordCheck, (None, None, Some(false))),
            (FinishFor::EnrollmentProof, (None, Some(true), Some(false))),
        ];
        for (finish_for, expected) in rows {
            let label = format!("{finish_for:?}");
            assert_eq!(finish_for.fields(), expected, "{label}");
        }
    }

    #[test]
    fn test_no_page_registers_an_empty_password() {
        let started = |password| {
            begin_registration("bob", password)
                .map(drop)
                .map_err(|e| e.to_string())
        };
        assert_eq!(
            (started(""), started("Bob-Password-1")),
            (Err("a password is required".to_owned()), Ok(()))
        );
    }
}
