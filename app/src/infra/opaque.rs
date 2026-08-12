//! Client half of the OPAQUE registration ceremony, shared by the create-user,
//! change-password, and reset-password flows. Each caller stashes the returned
//! state in its own component field between the start and finish steps.

use anyhow::{Context, Result};
use lldap_auth::{opaque, registration};

pub type RegistrationState = opaque::client::registration::ClientRegistration;

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
