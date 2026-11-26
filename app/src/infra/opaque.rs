//! Client half of the OPAQUE ceremonies: registration for the create-user,
//! change-password and reset-password flows, login for the login form, the old-password
//! check and the two-factor pages. Each caller stashes the returned state in its own
//! component field between the start and finish steps.

use crate::infra::encrypt::{SealTo, finish_with_envelope};
use anyhow::{Context, Result, bail};
use lldap_auth::{
    PASSWORD_LENGTH_UNIT, PASSWORD_MIN_LENGTH, PasswordShapeError, login, opaque, password_shape,
    registration,
};
use std::cell::RefCell;
use validator::ValidationError;

thread_local! {
    /// The envelope key this page's sign-in bound, in the page's memory only: a reload loses it.
    static SIGNED_IN_KEY: RefCell<Option<String>> = const { RefCell::new(None) };
}

pub fn keep_signed_in_key(key: Option<String>) {
    SIGNED_IN_KEY.with(|held| *held.borrow_mut() = key);
}

pub fn signed_in_key() -> Option<String> {
    SIGNED_IN_KEY.with(|held| held.borrow().clone())
}

pub type RegistrationState = opaque::client::registration::ClientRegistration;
pub type LoginState = opaque::client::login::ClientLogin;

const START_FAILED: &str = "Could not initiate registration";
const POLICY_UNREADABLE: &str = "the password policy could not be read; try again";

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
    if let Some(refused) = refusal(password, 0, min_length_message) {
        bail!("{refused}");
    }
    let mut rng = rand::rngs::OsRng;
    let start = opaque::client::registration::start_registration(password.as_bytes(), &mut rng)
        .context(START_FAILED)?;
    let request = registration::ClientRegistrationStartRequest {
        username: username.into(),
        registration_start_request: start.message,
    };
    Ok((start.state, request))
}

fn refusal(password: &str, min: usize, too_short: fn(usize) -> String) -> Option<String> {
    match password_shape(password, min) {
        Ok(()) => None,
        Err(PasswordShapeError::TooShort(_)) => Some(too_short(min)),
        Err(other) => Some(other.to_string()),
    }
}

pub fn finish_refusal(password: &str, min: Option<u32>) -> Option<String> {
    let min = min.map_or(0, |min| min as usize);
    refusal(password, min, min_length_message)
}

pub fn min_length_message(min: usize) -> String {
    format!("Invalid password. Min length: {min}")
}

fn below_the_floor(password: &str, text: fn(usize) -> String) -> Result<(), ValidationError> {
    let Some(refused) = refusal(password, PASSWORD_MIN_LENGTH, text) else {
        return Ok(());
    };
    let mut error = ValidationError::new("password");
    error.message = Some(refused.into());
    Err(error)
}

pub fn new_password_at_the_floor(password: &str) -> Result<(), ValidationError> {
    below_the_floor(password, min_length_message)
}

pub fn new_user_password_at_the_floor(password: &str) -> Result<(), ValidationError> {
    below_the_floor(password, |min| {
        format!("Password must be at least {min} {PASSWORD_LENGTH_UNIT}")
    })
}

/// Completes registration from the stashed state and the server's start
/// response, producing the finish request to POST; a synced user's password is sealed only to
/// the key `seal_to` allows.
pub fn finish_registration(
    state: RegistrationState,
    username: &str,
    password: &str,
    start: registration::ServerRegistrationStart,
    seal_to: SealTo<'_>,
) -> Result<registration::ClientRegistrationFinish> {
    let registration::ServerRegistrationStart {
        response,
        kerberos_envelope_key,
        password_min_length,
    } = start;
    if let Some(refused) = finish_refusal(password, password_min_length) {
        bail!("{refused}");
    }
    let mut rng = rand::rngs::OsRng;
    let finish = opaque::client::registration::finish_registration(
        state,
        password.as_bytes(),
        response.registration_response,
        &mut rng,
    )
    .context("Error during registration")?;
    let request = registration::ClientRegistrationFinishRequest {
        server_data: response.server_data,
        registration_upload: finish.message,
    };
    finish_with_envelope(
        request,
        kerberos_envelope_key.as_deref(),
        seal_to,
        username,
        password,
    )
}

/// Begins a login that asks for the envelope key: returns the client state to stash and the start
/// request to POST.
pub fn begin_login(
    username: &str,
    password: &str,
) -> Result<(LoginState, login::ClientLoginStart)> {
    let mut rng = rand::rngs::OsRng;
    let start = opaque::client::login::start_login(password, &mut rng)
        .context("Could not initialize login")?;
    let request = login::ClientLoginStartRequest {
        username: username.into(),
        login_start_request: start.message,
    };
    let request = login::ClientLoginStart {
        request,
        kerberos_envelope_key: Some(true),
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
/// producing the finish request to POST and the envelope key the login bound; a wrong password,
/// or a key the server did not bind, fails here, client-side.
pub fn finish_login(
    state: LoginState,
    password: &str,
    response: login::ServerLoginStart,
    finish_for: FinishFor,
) -> Result<(login::ClientLoginFinishRequest, Option<String>)> {
    let mut rng = rand::rngs::OsRng;
    let (request, bound_key) = login::finish_bound(state, password.as_bytes(), response, &mut rng)
        .context("Invalid username or password")?;
    let (totp_code, enrollment_proof, session) = finish_for.fields();
    let request = login::ClientLoginFinishRequest {
        totp_code,
        enrollment_proof,
        session,
        ..request
    };
    Ok((request, bound_key))
}

#[cfg(test)]
mod tests {
    use super::*;
    use lldap_auth::kerberos_envelope::KeyNotBound;
    use lldap_auth::password_length;
    use lldap_auth::types::UserId;

    const BOB_PASS: &str = "Bob-Password-1";

    fn registered(
        setup: &opaque::server::ServerSetup,
        user: &UserId,
    ) -> opaque::server::ServerRegistration {
        let mut rng = rand::rngs::OsRng;
        let (state, request) = begin_registration(user.as_str(), BOB_PASS).unwrap();
        let start = request.registration_start_request;
        let answer = opaque::server::registration::start_registration(setup, start, user).unwrap();
        let upload = opaque::client::registration::finish_registration(
            state,
            BOB_PASS.as_bytes(),
            answer.message,
            &mut rng,
        )
        .unwrap();
        opaque::server::registration::get_password_file(upload.message)
    }

    #[test]
    fn test_a_password_shorter_than_the_servers_minimum_is_not_finished() {
        const SEVEN: &str = "Seven-7";
        const ELEVEN: &str = "Eleven-11ch";
        const TWELVE: &str = "Twelve-12chr";
        const ELEVEN_UMLAUTS: &str = "pässwörter1";
        const MIN_12: &str = "Invalid password. Min length: 12";
        let rows = [
            (ELEVEN, Some(12), Some(MIN_12)),
            (ELEVEN_UMLAUTS, Some(12), Some(MIN_12)),
            (TWELVE, Some(12), None),
            (TWELVE, Some(8), None),
            (ELEVEN, None, None),
            (SEVEN, None, None),
            ("", None, Some("the password must not be empty")),
        ];
        assert_eq!(
            [SEVEN, ELEVEN, TWELVE, ELEVEN_UMLAUTS].map(|p| (p.chars().count(), p.len())),
            [(7, 7), (11, 11), (12, 12), (11, 13)]
        );
        for (password, min, expected) in rows {
            assert_eq!(
                finish_refusal(password, min).as_deref(),
                expected,
                "{password} {min:?}"
            );
        }
    }

    #[test]
    fn test_the_pages_count_a_new_password_as_password_length() {
        const PAGE: &str = "Invalid password. Min length: 8";
        const CREATE: &str = "Password must be at least 8 characters";
        const MIN_12: &str = "Invalid password. Min length: 12";
        const EMPTY: &str = "the password must not be empty";
        type Row = (
            &'static str,
            u32,
            (usize, usize),
            Option<&'static str>,
            Option<&'static str>,
            Option<&'static str>,
        );
        let rows: [Row; 5] = [
            ("ääääääää", 12, (8, 16), Some(MIN_12), None, None),
            ("ääää", 8, (4, 8), Some(PAGE), Some(PAGE), Some(CREATE)),
            (
                "äääääää",
                12,
                (7, 14),
                Some(MIN_12),
                Some(PAGE),
                Some(CREATE),
            ),
            (
                "e\u{301}e\u{301}e\u{301}e\u{301}",
                8,
                (8, 12),
                None,
                None,
                None,
            ),
            ("", 8, (0, 0), Some(EMPTY), Some(EMPTY), Some(EMPTY)),
        ];
        let shown = |checked: Result<(), ValidationError>| {
            checked
                .err()
                .and_then(|e| e.message)
                .map(|text| text.into_owned())
        };
        let got = rows.map(|(text, min, ..)| {
            (
                text,
                min,
                (password_length(text), text.len()),
                finish_refusal(text, Some(min)),
                shown(new_password_at_the_floor(text)),
                shown(new_user_password_at_the_floor(text)),
            )
        });
        let want = rows.map(|(text, min, counts, unmet, page, create)| {
            let owned = |text: Option<&str>| text.map(str::to_owned);
            (text, min, counts, owned(unmet), owned(page), owned(create))
        });
        assert_eq!(got, want);
        for (text, min, _, unmet, page, _) in rows {
            let length = password_length(text);
            assert_eq!(
                (unmet.is_some(), page.is_some()),
                (length < min as usize, length < 8),
                "{text:?}: the finish and the pages count alike"
            );
        }
        assert_eq!(min_length_message(12), "Invalid password. Min length: 12");
    }

    #[test]
    fn test_the_pages_refuse_a_nul_in_the_shared_words_and_an_empty_password_at_the_floor() {
        const PAGE: &str = "Invalid password. Min length: 8";
        const CREATE: &str = "Password must be at least 8 characters";
        const MIN_12: &str = "Invalid password. Min length: 12";
        const NUL: &str = "the password must not contain a NUL character (U+0000)";
        const EMPTY: &str = "the password must not be empty";
        type Row = (
            &'static str,
            Option<&'static str>,
            Option<&'static str>,
            Option<&'static str>,
        );
        let rows: [Row; 7] = [
            ("", Some(EMPTY), Some(EMPTY), Some(EMPTY)),
            ("\0", Some(NUL), Some(NUL), Some(NUL)),
            ("a\0aaaaaaa", Some(NUL), Some(NUL), Some(NUL)),
            ("Twelve-12chr\0", Some(NUL), Some(NUL), Some(NUL)),
            ("\0Twelve-12chr", Some(NUL), Some(NUL), Some(NUL)),
            ("Seven-7", Some(PAGE), Some(CREATE), Some(MIN_12)),
            ("Twelve-12chr", None, None, None),
        ];
        let shown = |checked: Result<(), ValidationError>| {
            checked.err().and_then(|e| e.message).map(String::from)
        };
        let got = rows.map(|(text, ..)| {
            (
                text,
                shown(new_password_at_the_floor(text)),
                shown(new_user_password_at_the_floor(text)),
                finish_refusal(text, Some(12)),
            )
        });
        let want = rows.map(|(text, page, create, finish)| {
            let owned = |text: Option<&str>| text.map(str::to_owned);
            (text, owned(page), owned(create), owned(finish))
        });
        assert_eq!(got, want);
        assert_eq!(
            [finish_refusal("", None), finish_refusal("a\0b", None)],
            [Some(EMPTY.to_owned()), Some(NUL.to_owned())],
            "no minimum from the server: the shared rule still applies"
        );
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
            (Err("the password must not be empty".to_owned()), Ok(()))
        );
    }

    #[test]
    fn test_a_page_login_asks_for_the_key_and_gives_only_a_key_the_server_bound() {
        type Row = (
            &'static str,
            Option<&'static str>,
            Option<&'static str>,
            Result<Option<&'static str>, &'static str>,
        );
        let mut rng = rand::rngs::OsRng;
        let setup = opaque::server::ServerSetup::new(&mut rng);
        let bob = UserId::new("bob");
        let file = registered(&setup, &bob);
        let refused = "Invalid username or password";
        let rows: [Row; 4] = [
            (
                "the key the server bound",
                Some("key"),
                Some("key"),
                Ok(Some("key")),
            ),
            (
                "another key answered",
                Some("key"),
                Some("other"),
                Err(refused),
            ),
            (
                "a key the server did not bind",
                None,
                Some("key"),
                Err(refused),
            ),
            ("none bound, none answered", None, None, Ok(None)),
        ];
        for (row, bound, answered, expected) in rows {
            let (state, start) = begin_login("bob", BOB_PASS).unwrap();
            assert_eq!(start.kerberos_envelope_key, Some(true), "{row}: asked");
            let context = login::envelope_key_context(bound);
            let started = opaque::server::login::start_login_in_context(
                &mut rng,
                &setup,
                Some(file.clone()),
                start.request.login_start_request,
                &bob,
                &context,
            )
            .unwrap();
            let response = login::ServerLoginStart {
                response: login::ServerLoginStartResponse {
                    server_data: "sealed".to_owned(),
                    credential_response: started.message,
                },
                kerberos_envelope_key: answered.map(str::to_owned),
            };
            let got = finish_login(state, BOB_PASS, response, FinishFor::PasswordCheck)
                .map(|(request, key)| (request.server_data, request.session, key))
                .map_err(|e| e.to_string());
            let expected = expected
                .map(|key| ("sealed".to_owned(), Some(false), key.map(str::to_owned)))
                .map_err(str::to_owned);
            assert_eq!(got, expected, "{row}");
        }
    }

    #[test]
    fn test_a_page_seals_a_synced_users_password_only_to_the_key_its_sign_in_bound() {
        type Row = (
            &'static str,
            Option<&'static str>,
            SealTo<'static>,
            Result<bool, String>,
        );
        let mut rng = rand::rngs::OsRng;
        let setup = opaque::server::ServerSetup::new(&mut rng);
        let bob = UserId::new("bob");
        let not_bound = Err(KeyNotBound.to_string());
        let sealed = Err("Base64 decode of the Kerberos envelope key failed".to_owned());
        let rows: [Row; 6] = [
            ("no key answered", None, SealTo::Bound(None), Ok(false)),
            (
                "another key bound",
                Some("no key!"),
                SealTo::Bound(Some("other")),
                not_bound.clone(),
            ),
            (
                "no key held",
                Some("no key!"),
                SealTo::Bound(None),
                not_bound,
            ),
            (
                "the bound key",
                Some("no key!"),
                SealTo::Bound(Some("no key!")),
                sealed.clone(),
            ),
            ("the reset page", Some("no key!"), SealTo::Answered, sealed),
            ("the reset page, no key", None, SealTo::Answered, Ok(false)),
        ];
        for (row, answered, seal_to, expected) in rows {
            let (state, request) = begin_registration("bob", BOB_PASS).unwrap();
            let start = request.registration_start_request;
            let answer = opaque::server::registration::start_registration(&setup, start, &bob);
            let start = registration::ServerRegistrationStart {
                response: registration::ServerRegistrationStartResponse {
                    server_data: "sealed".to_owned(),
                    registration_response: answer.unwrap().message,
                },
                kerberos_envelope_key: answered.map(str::to_owned),
                password_min_length: None,
            };
            let got = finish_registration(state, "bob", BOB_PASS, start, seal_to)
                .map(|finish| finish.kerberos_password_envelope.is_some())
                .map_err(|e| e.to_string());
            assert_eq!(got, expected, "{row}");
        }
    }

    #[test]
    fn test_a_page_holds_the_key_its_sign_in_bound_until_it_signs_out() {
        assert_eq!(signed_in_key(), None, "a page that has not signed in");
        keep_signed_in_key(Some("key".to_owned()));
        assert_eq!(signed_in_key().as_deref(), Some("key"));
        keep_signed_in_key(None);
        assert_eq!(signed_in_key(), None, "signed out");
    }
}
