#![forbid(non_ascii_idents)]
#![forbid(unsafe_code)]
#![allow(clippy::nonstandard_macro_braces)]
use chrono::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fmt;
use uuid::Uuid;

pub mod access_control;
pub mod kerberos_envelope;
pub mod opaque;

pub const PASSWORD_LENGTH_UNIT: &str = "characters";
pub const PASSWORD_HAS_NUL: &str = "the password must not contain a NUL character (U+0000)";
pub const PASSWORD_EMPTY: &str = "the password must not be empty";
pub const PASSWORD_MIN_LENGTH: usize = 8;

pub fn password_length(password: &str) -> usize {
    password.chars().count()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PasswordShapeError {
    Empty,
    HasNul,
    TooShort(usize),
}

impl fmt::Display for PasswordShapeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str(PASSWORD_EMPTY),
            Self::HasNul => f.write_str(PASSWORD_HAS_NUL),
            Self::TooShort(min) => {
                write!(
                    f,
                    "the password must be at least {min} {PASSWORD_LENGTH_UNIT}"
                )
            }
        }
    }
}

impl std::error::Error for PasswordShapeError {}

/// Every door's rule for a new password: not empty, no NUL character, then `min`.
pub fn password_shape(password: &str, min: usize) -> Result<(), PasswordShapeError> {
    if password.is_empty() {
        return Err(PasswordShapeError::Empty);
    }
    if password.contains('\0') {
        return Err(PasswordShapeError::HasNul);
    }
    if password_length(password) < min {
        return Err(PasswordShapeError::TooShort(min));
    }
    Ok(())
}

pub mod login {
    use super::{types::UserId, *};

    #[derive(Serialize, Deserialize, Clone)]
    pub struct ServerData {
        pub username: UserId,
        pub server_login: opaque::server::login::ServerLogin,
        /// The start's own +1 beside the user's row; only its verified finish removes it.
        #[serde(with = "fixed_width_overlay")]
        pub overlay: Option<u64>,
        /// The start, in seconds since the Unix epoch, and its id: its finish is taken once.
        pub issued_at: i64,
        pub id: [u8; 16],
    }

    /// One flag and one id whether or not the start counted, so its length tells nothing.
    mod fixed_width_overlay {
        use serde::{Deserialize, Deserializer, Serialize, Serializer};

        pub fn serialize<S: Serializer>(overlay: &Option<u64>, to: S) -> Result<S::Ok, S::Error> {
            let id = overlay.unwrap_or_else(|| rand::RngCore::next_u64(&mut rand::rngs::OsRng));
            (overlay.is_some(), id).serialize(to)
        }

        pub fn deserialize<'de, D: Deserializer<'de>>(from: D) -> Result<Option<u64>, D::Error> {
            let (counted, id) = <(bool, u64)>::deserialize(from)?;
            Ok(counted.then_some(id))
        }
    }

    #[derive(Serialize, Deserialize, Clone)]
    pub struct ClientLoginStartRequest {
        pub username: UserId,
        pub login_start_request: opaque::server::login::CredentialRequest,
    }

    #[derive(Serialize, Deserialize, Clone)]
    pub struct ServerLoginStartResponse {
        /// Base64, encrypted; the client returns it unchanged.
        pub server_data: String,
        pub credential_response: opaque::client::login::CredentialResponse,
    }

    /// login/start's body: upstream's, and whether to answer the Kerberos envelope key.
    #[derive(Serialize, Deserialize, Clone)]
    pub struct ClientLoginStart {
        #[serde(flatten)]
        pub request: ClientLoginStartRequest,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub kerberos_envelope_key: Option<bool>,
    }

    impl From<ClientLoginStartRequest> for ClientLoginStart {
        fn from(request: ClientLoginStartRequest) -> Self {
            Self {
                request,
                kerberos_envelope_key: None,
            }
        }
    }

    /// login/start's answer: upstream's, and the envelope key the login is bound to.
    #[derive(Serialize, Deserialize, Clone)]
    pub struct ServerLoginStart {
        #[serde(flatten)]
        pub response: ServerLoginStartResponse,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub kerberos_envelope_key: Option<String>,
    }

    const ENVELOPE_KEY_CONTEXT: &[u8] = b"klldap-kerberos-envelope-key-v1:";

    /// SHA-256 of the key's text as the start answered it, or `none` when it answered none.
    pub fn envelope_key_context(key: Option<&str>) -> Vec<u8> {
        use sha2::{Digest, Sha256};
        let mut context = ENVELOPE_KEY_CONTEXT.to_vec();
        match key {
            Some(key) => context.extend_from_slice(&Sha256::digest(key.as_bytes())),
            None => context.extend_from_slice(b"none"),
        }
        context
    }

    /// The client's finish, only when the server bound the key it answered; gives that key.
    pub fn finish_bound<R: rand::RngCore + rand::CryptoRng>(
        state: opaque::client::login::ClientLogin,
        password: &[u8],
        answer: ServerLoginStart,
        rng: &mut R,
    ) -> opaque::AuthenticationResult<(ClientLoginFinishRequest, Option<String>)> {
        let ServerLoginStart {
            response,
            kerberos_envelope_key: key,
        } = answer;
        let context = envelope_key_context(key.as_deref());
        let finish = opaque::client::login::finish_login_in_context(
            state,
            password,
            response.credential_response,
            &context,
            rng,
        )?;
        let request = ClientLoginFinishRequest {
            server_data: response.server_data,
            credential_finalization: finish.message,
            totp_code: None,
            enrollment_proof: None,
            session: None,
        };
        Ok((request, key))
    }

    #[derive(Serialize, Deserialize, Clone)]
    pub struct ClientLoginFinishRequest {
        pub server_data: String,
        pub credential_finalization: opaque::client::login::CredentialFinalization,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub totp_code: Option<String>,
        /// Present only when this finish should mint a first-enrollment proof.
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            rename = "enrollmentProof"
        )]
        pub enrollment_proof: Option<bool>,
        /// `false`: check the password and mint no session. Absent: a session, as before.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub session: Option<bool>,
    }

    #[derive(Serialize, Deserialize, Clone)]
    pub struct ClientSimpleLoginRequest {
        pub username: UserId,
        pub password: String,
        /// Present only when this login should mint a first-enrollment proof.
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            rename = "enrollmentProof"
        )]
        pub enrollment_proof: Option<bool>,
    }

    impl fmt::Debug for ClientSimpleLoginRequest {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("ClientSimpleLoginRequest")
                .field("username", &self.username.as_str())
                .field("password", &"***********")
                .finish()
        }
    }

    #[derive(Serialize, Deserialize, Clone)]
    pub struct ServerLoginResponse {
        pub token: String,
        #[serde(rename = "refreshToken", skip_serializing_if = "Option::is_none")]
        pub refresh_token: Option<String>,
        #[serde(
            rename = "mfaEnrollmentRequired",
            default,
            skip_serializing_if = "Option::is_none"
        )]
        pub mfa_enrollment_required: Option<bool>,
        /// A first-enrollment proof. Absent unless this login asked for one.
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            rename = "enrollmentProof"
        )]
        pub enrollment_proof: Option<String>,
    }

    /// The answer to a finish with `"session": false` whose password verified.
    #[derive(Serialize, Deserialize, Clone)]
    pub struct ServerLoginVerifiedResponse {
        pub verified: bool,
        #[serde(
            rename = "mfaEnrollmentRequired",
            default,
            skip_serializing_if = "Option::is_none"
        )]
        pub mfa_enrollment_required: Option<bool>,
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            rename = "enrollmentProof"
        )]
        pub enrollment_proof: Option<String>,
    }

    /// Missing TOTP after a right password: retry with `password:123456`.
    #[derive(Serialize, Deserialize, Clone)]
    pub struct ServerMfaRequiredResponse {
        #[serde(rename = "mfaRequired")]
        pub mfa_required: bool,
    }
}

pub mod registration {
    use super::{types::UserId, *};

    /// Who makes a web or tool start and presents its finish: a token's user, its id, its kind.
    #[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
    pub struct Presenter {
        pub actor: UserId,
        pub session: [u8; 16],
        pub reset: bool,
    }

    #[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
    pub struct StartBinding {
        pub id: [u8; 16],
        pub by: Presenter,
        /// SHA-256 of the envelope key the start answered with.
        pub envelope_key: Option<[u8; 32]>,
    }

    #[derive(Serialize, Deserialize, Clone)]
    pub struct ServerData {
        pub username: UserId,
        /// The start, in seconds since the Unix epoch.
        pub issued_at: i64,
        /// None for a start made in process: its finish never leaves the call.
        pub start: Option<StartBinding>,
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Claim {
        pub user: UserId,
        pub envelope_key: Option<[u8; 32]>,
    }

    #[derive(Serialize, Deserialize, Clone)]
    pub struct ClientRegistrationStartRequest {
        pub username: UserId,
        pub registration_start_request: opaque::server::registration::RegistrationRequest,
    }

    #[derive(Serialize, Deserialize, Clone)]
    pub struct ServerRegistrationStartResponse {
        /// Base64, encrypted; the client returns it unchanged.
        pub server_data: String,
        pub registration_response: opaque::client::registration::RegistrationResponse,
    }

    #[derive(Serialize, Deserialize, Clone)]
    pub struct ClientRegistrationFinishRequest {
        pub server_data: String,
        pub registration_upload: opaque::server::registration::RegistrationUpload,
    }

    pub const KERBEROS_ENVELOPE_LABEL_PREFIX: &str = "klldap-kerberos-envelope-v2:";
    /// RSA-3072 with OAEP-SHA-256 seals at most 384 - 2 * 32 - 2 bytes.
    pub const KERBEROS_ENVELOPE_MAX_BYTES: usize = 318;

    /// The OAEP label of a password envelope: one key, one purpose, one user, one start.
    pub fn kerberos_envelope_label(user: &UserId, server_data: &str) -> String {
        format!(
            "{KERBEROS_ENVELOPE_LABEL_PREFIX}{}:{server_data}",
            user.as_str()
        )
    }

    pub fn fits_kerberos_envelope(password: &str) -> bool {
        password.len() <= KERBEROS_ENVELOPE_MAX_BYTES
    }

    /// register/start's answer: upstream's, plus a synced user's sealing key and the min length.
    #[derive(Serialize, Deserialize, Clone)]
    pub struct ServerRegistrationStart {
        #[serde(flatten)]
        pub response: ServerRegistrationStartResponse,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub kerberos_envelope_key: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub password_min_length: Option<u32>,
    }

    /// register/finish's body: upstream's, and for a user with Kerberos sync the sealed password.
    #[derive(Serialize, Deserialize, Clone)]
    pub struct ClientRegistrationFinish {
        #[serde(flatten)]
        pub request: ClientRegistrationFinishRequest,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub kerberos_password_envelope: Option<String>,
    }
}

pub mod password_reset {
    use super::*;

    #[derive(Serialize, Deserialize, Clone)]
    pub struct ServerPasswordResetResponse {
        #[serde(rename = "userId")]
        pub user_id: String,
        pub token: String,
    }
}

pub mod types {
    use serde::{Deserialize, Serialize};

    #[cfg(feature = "sea_orm")]
    use sea_orm::{DbErr, DeriveValueType, TryFromU64, Value};

    #[derive(
        PartialEq, Eq, PartialOrd, Ord, Clone, Debug, Default, Hash, Serialize, Deserialize,
    )]
    #[cfg_attr(feature = "sea_orm", derive(DeriveValueType))]
    #[serde(from = "String")]
    pub struct CaseInsensitiveString(String);

    impl CaseInsensitiveString {
        pub fn new(s: &str) -> Self {
            Self(s.to_ascii_lowercase())
        }

        pub fn as_str(&self) -> &str {
            self.0.as_str()
        }

        pub fn into_string(self) -> String {
            self.0
        }
    }

    impl From<String> for CaseInsensitiveString {
        fn from(mut s: String) -> Self {
            s.make_ascii_lowercase();
            Self(s)
        }
    }

    impl From<&String> for CaseInsensitiveString {
        fn from(s: &String) -> Self {
            Self::new(s.as_str())
        }
    }

    impl From<&str> for CaseInsensitiveString {
        fn from(s: &str) -> Self {
            Self::new(s)
        }
    }

    #[derive(
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Clone,
        Default,
        Hash,
        Serialize,
        Deserialize,
        derive_more::Debug,
        derive_more::Display,
    )]
    #[cfg_attr(feature = "sea_orm", derive(DeriveValueType))]
    #[serde(from = "CaseInsensitiveString")]
    #[debug(r#""{}""#, _0.as_str())]
    #[display("{}", _0.as_str())]
    pub struct UserId(CaseInsensitiveString);

    impl UserId {
        pub fn new(s: &str) -> Self {
            s.into()
        }
        pub fn as_str(&self) -> &str {
            self.0.as_str()
        }
        pub fn into_string(self) -> String {
            self.0.into_string()
        }
    }
    impl<T> From<T> for UserId
    where
        T: Into<CaseInsensitiveString>,
    {
        fn from(s: T) -> Self {
            Self(s.into())
        }
    }

    #[cfg(feature = "sea_orm")]
    impl From<&UserId> for Value {
        fn from(user_id: &UserId) -> Self {
            user_id.as_str().into()
        }
    }
    #[cfg(feature = "sea_orm")]
    impl TryFromU64 for UserId {
        fn try_from_u64(_n: u64) -> Result<Self, DbErr> {
            Err(DbErr::ConvertFromU64(
                "UserId cannot be constructed from u64",
            ))
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct JWTClaims {
    #[serde(with = "chrono::serde::ts_seconds")]
    pub exp: DateTime<Utc>,
    #[serde(with = "chrono::serde::ts_seconds")]
    pub iat: DateTime<Utc>,
    pub jti: Uuid,
    pub user: String,
    pub groups: HashSet<String>,
    // Defaulted so tokens issued before this field existed still parse.
    #[serde(default)]
    pub password_reset: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_a_password_length_counts_characters_not_bytes() {
        type Row = (&'static str, usize, usize);
        let rows: [Row; 7] = [
            ("", 0, 0),
            ("Eight-88", 8, 8),
            ("ääää", 4, 8),
            ("ääääääää", 8, 16),
            ("e\u{301}e\u{301}e\u{301}e\u{301}", 8, 12),
            ("  Cafe\u{301}-Pass-12  ", 17, 18),
            ("  Caf\u{e9}-Pass-12  ", 16, 17),
        ];
        let got = rows.map(|(text, ..)| (text, password_length(text), text.len()));
        assert_eq!(got, rows);
        assert_eq!(PASSWORD_LENGTH_UNIT, "characters");
    }

    #[test]
    fn test_the_shared_rule_refuses_a_nul_at_any_minimum_then_counts_characters() {
        use PasswordShapeError::{Empty, HasNul, TooShort};
        type Row = (&'static str, usize, Result<(), PasswordShapeError>);
        let rows: [Row; 15] = [
            ("", 0, Err(Empty)),
            ("", 1, Err(Empty)),
            ("", 8, Err(Empty)),
            ("", 128, Err(Empty)),
            ("\0", 0, Err(HasNul)),
            ("\0", 8, Err(HasNul)),
            ("a\0aaaaaaa", 8, Err(HasNul)),
            ("aaaaaaaaaaaa\0", 0, Err(HasNul)),
            ("abc", 0, Ok(())),
            (" ", 0, Ok(())),
            ("ääää", 8, Err(TooShort(8))),
            ("ääääääää", 8, Ok(())),
            ("ääääääää", 9, Err(TooShort(9))),
            ("e\u{301}e\u{301}e\u{301}e\u{301}", 8, Ok(())),
            ("Twelve-12chr", 12, Ok(())),
        ];
        let got = rows.map(|(text, min, _)| (text, min, password_shape(text, min)));
        assert_eq!(got, rows);
        let texts = [Empty, HasNul, TooShort(8), TooShort(12)].map(|e| e.to_string());
        assert_eq!(
            texts,
            [
                "the password must not be empty",
                "the password must not contain a NUL character (U+0000)",
                "the password must be at least 8 characters",
                "the password must be at least 12 characters",
            ]
        );
        assert_eq!(PASSWORD_MIN_LENGTH, 8);
    }

    #[test]
    fn test_a_login_binds_the_hash_of_the_key_it_was_answered_or_none() {
        use sha2::{Digest, Sha256};
        let prefix = b"klldap-kerberos-envelope-key-v1:".to_vec();
        let key = "MIIBigKCAYEA";
        let hashed = [prefix.clone(), Sha256::digest(key.as_bytes()).to_vec()].concat();
        let none = [prefix, b"none".to_vec()].concat();
        let got = [Some(key), Some("MIIBigKCAYEB"), None].map(login::envelope_key_context);
        assert_eq!((&got[0], &got[2]), (&hashed, &none));
        assert_ne!(got[0], got[1], "another key, another context");
        assert!(
            !got[2].is_empty(),
            "an empty context is a start that did not ask"
        );
    }
}
