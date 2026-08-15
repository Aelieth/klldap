#![forbid(unsafe_code)]
use async_trait::async_trait;
use lldap_domain::types::UserId;
use lldap_domain_model::error::Result;

use lldap_auth::opaque;
pub use lldap_auth::{login, registration};

#[async_trait]
pub trait OpaqueHandler: Send + Sync {
    async fn login_start(
        &self,
        request: login::ClientLoginStartRequest,
    ) -> Result<login::ServerLoginStartResponse>;
    async fn login_finish(&self, request: login::ClientLoginFinishRequest) -> Result<UserId>;
    async fn registration_start(
        &self,
        request: registration::ClientRegistrationStartRequest,
    ) -> Result<registration::ServerRegistrationStartResponse>;
    async fn registration_finish(
        &self,
        request: registration::ClientRegistrationFinishRequest,
    ) -> Result<()>;
}

/// Runs the OPAQUE registration ceremony in-process, playing the client against `handler`.
pub async fn register_password(
    handler: &(impl OpaqueHandler + ?Sized),
    username: UserId,
    password: &[u8],
) -> Result<()> {
    let mut rng = rand::rngs::OsRng;
    let registration_start = opaque::client::registration::start_registration(password, &mut rng)?;
    let start_response = handler
        .registration_start(registration::ClientRegistrationStartRequest {
            username,
            registration_start_request: registration_start.message,
        })
        .await?;
    let registration_finish = opaque::client::registration::finish_registration(
        registration_start.state,
        password,
        start_response.registration_response,
        &mut rng,
    )?;
    handler
        .registration_finish(registration::ClientRegistrationFinishRequest {
            server_data: start_response.server_data,
            registration_upload: registration_finish.message,
        })
        .await
}
