use crate::types::UserId;
use generic_array::GenericArray;
use opaque_ke::ciphersuite::CipherSuite;
use rand::{CryptoRng, RngCore};

#[derive(thiserror::Error, Debug)]
pub enum AuthenticationError {
    #[error("Protocol error: `{0}`")]
    ProtocolError(#[from] opaque_ke::errors::ProtocolError),
}

pub type AuthenticationResult<T> = std::result::Result<T, AuthenticationError>;

impl AuthenticationError {
    /// What the server's finish answers when the client's proof does not verify.
    pub fn failed_proof() -> Self {
        Self::ProtocolError(opaque_ke::errors::ProtocolError::InvalidLoginError)
    }
}

pub use opaque_ke::keypair::{PrivateKey, PublicKey};
pub type KeyPair = opaque_ke::keypair::KeyPair<opaque_ke::Ristretto255>;

pub struct ArgonHasher;

/// OPAQUE's KSF, not a password hash: the salt is fixed and public by design.
impl ArgonHasher {
    const SALT: &'static [u8] = b"lldap_opaque_salt";
    const CONFIG: &'static argon2::Config<'static> = &argon2::Config {
        ad: &[],
        hash_length: 128,
        lanes: 1,
        mem_cost: 50 * 1024, // 50 MB, in KB
        secret: &[],
        time_cost: 1,
        variant: argon2::Variant::Argon2id,
        version: argon2::Version::Version13,
    };
}

/// Must match the old SlowHash output so existing password files still verify.
pub struct ArgonKsf;

impl Default for ArgonKsf {
    fn default() -> Self {
        ArgonKsf
    }
}

impl opaque_ke::ksf::Ksf for ArgonKsf {
    fn hash<L: generic_array::ArrayLength<u8>>(
        &self,
        input: GenericArray<u8, L>,
    ) -> Result<GenericArray<u8, L>, opaque_ke::errors::InternalError> {
        let hash = argon2::hash_raw(&input, ArgonHasher::SALT, ArgonHasher::CONFIG)
            .map_err(|_| opaque_ke::errors::InternalError::KsfError)?;

        let mut output: GenericArray<u8, L> = GenericArray::default();
        let copy_len = std::cmp::min(hash.len(), L::to_usize());
        output.as_mut_slice()[..copy_len].copy_from_slice(&hash[..copy_len]);
        Ok(output)
    }
}

pub struct DefaultSuite;
impl CipherSuite for DefaultSuite {
    type OprfCs = opaque_ke::Ristretto255;
    type KeyExchange = opaque_ke::TripleDh<opaque_ke::Ristretto255, sha2::Sha512>;
    type Ksf = ArgonKsf;
}

#[cfg(feature = "opaque_client")]
pub mod client {
    pub use super::*;
    pub mod registration {
        pub use super::*;
        pub type ClientRegistration = opaque_ke::ClientRegistration<DefaultSuite>;
        pub type ClientRegistrationStartResult =
            opaque_ke::ClientRegistrationStartResult<DefaultSuite>;
        pub type ClientRegistrationFinishResult =
            opaque_ke::ClientRegistrationFinishResult<DefaultSuite>;
        pub type RegistrationResponse = opaque_ke::RegistrationResponse<DefaultSuite>;
        pub use opaque_ke::ClientRegistrationFinishParameters;
        pub fn start_registration<R: RngCore + CryptoRng>(
            password: &[u8],
            rng: &mut R,
        ) -> AuthenticationResult<ClientRegistrationStartResult> {
            Ok(ClientRegistration::start(rng, password)?)
        }

        pub fn finish_registration<R: RngCore + CryptoRng>(
            registration_start: ClientRegistration,
            password: &[u8],
            registration_response: RegistrationResponse,
            rng: &mut R,
        ) -> AuthenticationResult<ClientRegistrationFinishResult> {
            Ok(registration_start.finish(
                rng,
                password,
                registration_response,
                ClientRegistrationFinishParameters::default(),
            )?)
        }
    }

    pub mod login {
        pub use super::*;
        pub type ClientLogin = opaque_ke::ClientLogin<DefaultSuite>;
        pub type ClientLoginFinishResult = opaque_ke::ClientLoginFinishResult<DefaultSuite>;
        pub type ClientLoginStartResult = opaque_ke::ClientLoginStartResult<DefaultSuite>;
        pub type CredentialResponse = opaque_ke::CredentialResponse<DefaultSuite>;
        pub type CredentialFinalization = opaque_ke::CredentialFinalization<DefaultSuite>;
        pub use opaque_ke::ClientLoginFinishParameters;

        pub fn start_login<R: RngCore + CryptoRng>(
            password: &str,
            rng: &mut R,
        ) -> AuthenticationResult<ClientLoginStartResult> {
            Ok(ClientLogin::start(rng, password.as_bytes())?)
        }

        pub fn finish_login<R: RngCore + CryptoRng>(
            login_start: ClientLogin,
            password: &[u8],
            login_response: CredentialResponse,
            rng: &mut R,
        ) -> AuthenticationResult<ClientLoginFinishResult> {
            finish_login_in_context(login_start, password, login_response, &[], rng)
        }

        pub fn finish_login_in_context<R: RngCore + CryptoRng>(
            login_start: ClientLogin,
            password: &[u8],
            login_response: CredentialResponse,
            context: &[u8],
            rng: &mut R,
        ) -> AuthenticationResult<ClientLoginFinishResult> {
            let parameters = ClientLoginFinishParameters {
                context: Some(context),
                ..Default::default()
            };
            Ok(login_start.finish(rng, password, login_response, parameters)?)
        }
    }
}

#[cfg(feature = "opaque_server")]
pub mod server {
    pub use super::*;
    pub type ServerRegistration = opaque_ke::ServerRegistration<DefaultSuite>;
    pub type ServerSetup = opaque_ke::ServerSetup<DefaultSuite>;

    pub fn generate_random_private_key() -> ServerSetup {
        let mut rng = rand::rngs::OsRng;
        ServerSetup::new(&mut rng)
    }

    pub mod registration {
        pub use super::*;
        pub type RegistrationRequest = opaque_ke::RegistrationRequest<DefaultSuite>;
        pub type RegistrationUpload = opaque_ke::RegistrationUpload<DefaultSuite>;
        pub type ServerRegistrationStartResult =
            opaque_ke::ServerRegistrationStartResult<DefaultSuite>;
        pub fn start_registration(
            server_setup: &ServerSetup,
            registration_request: RegistrationRequest,
            username: &UserId,
        ) -> AuthenticationResult<ServerRegistrationStartResult> {
            Ok(ServerRegistration::start(
                server_setup,
                registration_request,
                username.as_str().as_bytes(),
            )?)
        }

        pub fn get_password_file(registration_upload: RegistrationUpload) -> ServerRegistration {
            ServerRegistration::finish(registration_upload)
        }
    }

    pub mod login {
        pub use super::*;
        pub type CredentialFinalization = opaque_ke::CredentialFinalization<DefaultSuite>;
        pub type CredentialRequest = opaque_ke::CredentialRequest<DefaultSuite>;
        pub type ServerLogin = opaque_ke::ServerLogin<DefaultSuite>;
        pub type ServerLoginStartResult = opaque_ke::ServerLoginStartResult<DefaultSuite>;
        pub type ServerLoginFinishResult = opaque_ke::ServerLoginFinishResult<DefaultSuite>;
        pub use opaque_ke::ServerLoginParameters;

        pub fn start_login<R: RngCore + CryptoRng>(
            rng: &mut R,
            server_setup: &ServerSetup,
            password_file: Option<ServerRegistration>,
            credential_request: CredentialRequest,
            username: &UserId,
        ) -> AuthenticationResult<ServerLoginStartResult> {
            start_login_in_context(
                rng,
                server_setup,
                password_file,
                credential_request,
                username,
                &[],
            )
        }

        pub fn start_login_in_context<R: RngCore + CryptoRng>(
            rng: &mut R,
            server_setup: &ServerSetup,
            password_file: Option<ServerRegistration>,
            credential_request: CredentialRequest,
            username: &UserId,
            context: &[u8],
        ) -> AuthenticationResult<ServerLoginStartResult> {
            let parameters = ServerLoginParameters {
                context: Some(context),
                ..Default::default()
            };
            Ok(ServerLogin::start(
                rng,
                server_setup,
                password_file,
                credential_request,
                username.as_str().as_bytes(),
                parameters,
            )?)
        }

        pub fn finish_login(
            login_start: ServerLogin,
            credential_finalization: CredentialFinalization,
        ) -> AuthenticationResult<ServerLoginFinishResult> {
            Ok(login_start.finish(credential_finalization, ServerLoginParameters::default())?)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::login::{ServerLoginStart, ServerLoginStartResponse, envelope_key_context};

    const PASSWORD: &str = "correct horse battery staple";

    fn registered(setup: &server::ServerSetup, user: &UserId) -> server::ServerRegistration {
        let mut rng = rand::rngs::OsRng;
        let password = PASSWORD.as_bytes();
        let start = client::registration::start_registration(password, &mut rng).unwrap();
        let answer = server::registration::start_registration(setup, start.message, user).unwrap();
        let upload = client::registration::finish_registration(
            start.state,
            password,
            answer.message,
            &mut rng,
        )
        .unwrap();
        server::registration::get_password_file(upload.message)
    }

    #[test]
    fn test_a_login_finishes_only_when_both_sides_hold_the_same_envelope_key() {
        type Row = (
            &'static str,
            Vec<u8>,
            Option<&'static str>,
            &'static str,
            bool,
        );
        let mut rng = rand::rngs::OsRng;
        let setup = server::ServerSetup::new(&mut rng);
        let alice = UserId::new("alice");
        let file = registered(&setup, &alice);
        let (key, other) = (Some("the server's key"), Some("another key"));
        let bound = envelope_key_context(key);
        let rows: [Row; 7] = [
            ("the same key", bound.clone(), key, PASSWORD, true),
            (
                "another key in the answer",
                bound.clone(),
                other,
                PASSWORD,
                false,
            ),
            (
                "the key taken out of the answer",
                bound.clone(),
                None,
                PASSWORD,
                false,
            ),
            (
                "the ask taken out of the start",
                Vec::new(),
                None,
                PASSWORD,
                false,
            ),
            ("a key put into an answer", Vec::new(), key, PASSWORD, false),
            (
                "none on both sides",
                envelope_key_context(None),
                None,
                PASSWORD,
                true,
            ),
            (
                "the same key and a wrong password",
                bound,
                key,
                "wrong password",
                false,
            ),
        ];
        for (row, context, answered, password, finishes) in rows {
            let start = client::login::start_login(password, &mut rng).unwrap();
            let file = Some(file.clone());
            let started = server::login::start_login_in_context(
                &mut rng,
                &setup,
                file,
                start.message,
                &alice,
                &context,
            )
            .unwrap();
            let answer = ServerLoginStart {
                response: ServerLoginStartResponse {
                    server_data: String::new(),
                    credential_response: started.message,
                },
                kerberos_envelope_key: answered.map(str::to_owned),
            };
            let finished =
                crate::login::finish_bound(start.state, password.as_bytes(), answer, &mut rng);
            let got = finished.and_then(|(request, held)| {
                server::login::finish_login(started.state, request.credential_finalization)?;
                Ok(held)
            });
            let want = finishes.then(|| answered.map(str::to_owned));
            assert_eq!(got.ok(), want, "{row}");
        }
    }

    #[test]
    fn test_a_start_in_no_context_is_todays_login() {
        let mut rng = rand::rngs::OsRng;
        let setup = server::ServerSetup::new(&mut rng);
        let alice = UserId::new("alice");
        let file = registered(&setup, &alice);
        let start = client::login::start_login(PASSWORD, &mut rng).unwrap();
        let started =
            server::login::start_login(&mut rng, &setup, Some(file), start.message, &alice)
                .unwrap();
        let finish = client::login::finish_login(
            start.state,
            PASSWORD.as_bytes(),
            started.message,
            &mut rng,
        )
        .unwrap();
        assert!(server::login::finish_login(started.state, finish.message).is_ok());
    }
}
