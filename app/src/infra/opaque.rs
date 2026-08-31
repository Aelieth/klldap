//! Client half of the OPAQUE ceremonies: registration for the create-user,
//! change-password and reset-password flows, login for the login form, the old-password
//! proof and the two-factor pages. Each caller stashes the returned state in its own
//! component field between the start and finish steps.

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
    password: &str,
    response: registration::ServerRegistrationStartResponse,
) -> Result<registration::ClientRegistrationFinishRequest> {
    let mut rng = rand::rngs::OsRng;
    let finish = opaque::client::registration::finish_registration(
        state,
        password.as_bytes(),
        response.registration_response,
        &mut rng,
    )
    .context("Error during registration")?;
    Ok(registration::ClientRegistrationFinishRequest {
        server_data: response.server_data,
        registration_upload: finish.message,
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

/// Completes the login proof from the stashed state and the server's start response,
/// producing the finish request to POST; a wrong password fails here, client-side.
pub fn finish_login(
    state: LoginState,
    password: &str,
    response: login::ServerLoginStartResponse,
    totp_code: Option<String>,
) -> Result<login::ClientLoginFinishRequest> {
    let mut rng = rand::rngs::OsRng;
    let finish = opaque::client::login::finish_login(
        state,
        password.as_bytes(),
        response.credential_response,
        &mut rng,
    )
    .context("Invalid username or password")?;
    Ok(login::ClientLoginFinishRequest {
        server_data: response.server_data,
        credential_finalization: finish.message,
        totp_code,
    })
}
