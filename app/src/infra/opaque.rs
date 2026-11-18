//! Client half of the OPAQUE ceremonies: registration for the create-user,
//! change-password and reset-password flows, login for the login form, the old-password
//! check and the two-factor pages. Each caller stashes the returned state in its own
//! component field between the start and finish steps.

use crate::infra::encrypt::seal_kerberos_envelope;
use anyhow::{Context, Result};
use lldap_auth::{login, opaque, registration};

pub type RegistrationState = opaque::client::registration::ClientRegistration;
pub type LoginState = opaque::client::login::ClientLogin;

/// Begins registration: returns the client state to stash and the start request
/// to POST to the server.
pub fn begin_registration(
    username: &str,
    password: &str,
) -> Result<(
    RegistrationState,
    registration::ClientRegistrationStartRequest,
)> {
    let mut rng = rand::rngs::OsRng;
    let start = opaque::client::registration::start_registration(password.as_bytes(), &mut rng)
        .context("Could not initiate registration")?;
    let request = registration::ClientRegistrationStartRequest {
        username: username.into(),
        registration_start_request: start.message,
    };
    Ok((start.state, request))
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
    } = start;
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
}
