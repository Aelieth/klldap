use crate::SqlBackendHandler;
use crate::sql_log_handler::{BUSY_DETAIL, UNKNOWN_USER_DETAIL};
use crate::sql_mfa_handler::{TotpRejection, now_unix};
use crate::sql_mfa_windows::with_proof;
use crate::sql_used_starts::{CLOCK_TOLERANCE_SECS, take_start_id};
use crate::sql_user_backend_handler::sync_still_off;
use async_trait::async_trait;
use base64::Engine;
use lldap_auth::opaque;
use lldap_domain::types::{GroupId, LoginOutcome, UserId};
use lldap_domain_handlers::enforcement::{Attempt, Door, admit, before_credential, door_read};
use lldap_domain_handlers::handler::{BindRequest, LoginHandler};
use lldap_domain_handlers::instant::Timestamp;
use lldap_domain_handlers::kerberos::{
    LDAP_ADMINS_ONLY, kerberos_backend, refusal_while_degraded, require_kdc_ready,
};
use lldap_domain_handlers::lockout::{LockState, Step, lock_clock};
use lldap_domain_handlers::logging::{self, LogKind, NO_PASSWORD};
use lldap_domain_handlers::mfa::MfaRequirement;
use lldap_domain_handlers::password::refuse_unfinishable;
use lldap_domain_handlers::warn_limited;
use lldap_domain_model::{
    error::{DomainError, Result},
    model::{self, UserColumn},
};
use lldap_mfa::{MFA_ENROLLMENT_REQUIRED, TOTP_CODE_REQUIRED, split_totp_suffix, without_password};
use lldap_opaque_handler::{
    OpaqueHandler, STRETCH_BUSY, STRETCH_FAILED, StretchError, StretchGate, login, registration,
};
use sea_orm::{
    ActiveModelTrait, ActiveValue, ConnectionTrait, DbErr, EntityTrait, QuerySelect,
    TransactionTrait,
};
use tracing::{debug, info, instrument, warn};

type SqlOpaqueHandler = SqlBackendHandler;

/// A bind's password found wrong, or not tried: no stretch permit in time, or a stretch that
/// did not complete.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Unmatched {
    Wrong,
    Busy,
    NotRun,
}

fn stretched(answer: std::result::Result<Result<()>, StretchError>) -> Option<Unmatched> {
    match answer {
        Ok(Ok(())) => None,
        Ok(Err(_)) => Some(Unmatched::Wrong),
        Err(StretchError::Busy) => Some(Unmatched::Busy),
        Err(StretchError::Failed) => Some(Unmatched::NotRun),
    }
}

#[instrument(skip_all, level = "debug", fields(username = %username.as_str()))]
async fn passwords_match(
    gate: &StretchGate,
    password_file_bytes: &[u8],
    clear_password: &str,
    opaque_setup: &opaque::server::ServerSetup,
    username: &UserId,
) -> Option<Unmatched> {
    let password_file_bytes = password_file_bytes.to_vec();
    let clear_password = clear_password.to_owned();
    let opaque_setup = opaque_setup.clone();
    let username = username.clone();
    let answer = gate.stretch(move || -> Result<()> {
        use opaque::{client, server};
        let mut rng = rand::rngs::OsRng;
        let client_login_start_result = client::login::start_login(&clear_password, &mut rng)?;
        let password_file = server::ServerRegistration::deserialize(&password_file_bytes)
            .map_err(opaque::AuthenticationError::ProtocolError)?;
        let server_login_start_result = server::login::start_login(
            &mut rng,
            &opaque_setup,
            Some(password_file),
            client_login_start_result.message,
            &username,
        )?;
        client::login::finish_login(
            client_login_start_result.state,
            clear_password.as_bytes(),
            server_login_start_result.message,
            &mut rng,
        )?;
        Ok(())
    });
    stretched(answer.await)
}

const LOGIN_STATE_KEY_INFO: &[u8] = b"lldap-opaque-login-state-v1";
const REGISTRATION_STATE_KEY_INFO: &[u8] = b"lldap-opaque-registration-state-v1";
/// A finish must follow its start within two minutes.
const REGISTRATION_MAX_AGE: i64 = 120;
const REGISTRATION_TOO_LONG: &str = "the registration took too long; start again";
const REGISTRATION_UNMARKED: &str =
    "this registration could not be recorded as finished; try again";

/// bincode as `bincode::serialize` writes it, refusing trailing bytes.
fn decode_exact<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> bincode::Result<T> {
    use bincode::Options;
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
        .deserialize(bytes)
}

impl SqlBackendHandler {
    /// One key per kind of sealed state, derived from the server key.
    fn get_orion_secret_key(&self, purpose: &[u8]) -> Result<orion::aead::SecretKey> {
        let mut key = [0u8; 32];
        orion::hazardous::kdf::hkdf::sha256::derive_key(
            &[],
            self.opaque_setup.keypair().private().serialize().as_ref(),
            Some(purpose),
            &mut key,
        )?;
        Ok(orion::aead::SecretKey::from_slice(&key)?)
    }

    fn open_registration(&self, server_data: &str) -> Result<registration::ServerData> {
        let secret_key = self.get_orion_secret_key(REGISTRATION_STATE_KEY_INFO)?;
        Ok(decode_exact(&orion::aead::open(
            &secret_key,
            &base64::engine::general_purpose::STANDARD.decode(server_data)?,
        )?)?)
    }

    fn start_registration(
        &self,
        request: registration::ClientRegistrationStartRequest,
        start: Option<registration::StartBinding>,
    ) -> Result<registration::ServerRegistrationStartResponse> {
        let start_response = opaque::server::registration::start_registration(
            &self.opaque_setup,
            request.registration_start_request,
            &request.username,
        )?;
        let secret_key = self.get_orion_secret_key(REGISTRATION_STATE_KEY_INFO)?;
        let server_data = registration::ServerData {
            username: request.username,
            issued_at: now_unix(),
            start,
        };
        let encrypted_state = orion::aead::seal(&secret_key, &bincode::serialize(&server_data)?)?;
        Ok(registration::ServerRegistrationStartResponse {
            server_data: base64::engine::general_purpose::STANDARD.encode(encrypted_state),
            registration_response: start_response.message,
        })
    }

    fn took_too_long(user: &UserId) -> DomainError {
        let target = Some(user.as_str());
        logging::record_failure(LogKind::PasswordChange, target, REGISTRATION_TOO_LONG);
        DomainError::AuthenticationError(REGISTRATION_TOO_LONG.to_owned())
    }

    /// Fails closed: a start that cannot be marked is not finished.
    fn unmarked(user: &UserId, e: &DomainError) -> DomainError {
        warn!("The used registration starts could not be read or written for {user}: {e}");
        let target = Some(user.as_str());
        logging::record_failure(LogKind::PasswordChange, target, REGISTRATION_UNMARKED);
        DomainError::AuthenticationError(REGISTRATION_UNMARKED.to_owned())
    }

    #[instrument(skip(self), level = "debug", err(level = "debug"))]
    async fn get_password_file_for_user(&self, user_id: UserId) -> Result<Option<Vec<u8>>> {
        Ok(model::User::find_by_id(user_id)
            .select_only()
            .column(UserColumn::PasswordHash)
            .into_tuple::<(Option<Vec<u8>>,)>()
            .one(&self.sql_pool)
            .await?
            .and_then(|u| u.0))
    }

    #[instrument(skip(self), level = "debug")]
    pub async fn is_user_disabled(&self, user_id: &UserId) -> Result<bool> {
        // Membership in lldap_disabled blocks login and makes the LDAP layer synthesize
        // loginDisabled=TRUE for SSSD access filters; leaving the group clears both.
        self.is_member_of(user_id, "lldap_disabled").await
    }

    pub(crate) async fn is_member_of(&self, user_id: &UserId, group_name: &str) -> Result<bool> {
        Ok(member_of(&self.sql_pool, user_id, group_name).await?)
    }

    pub(crate) async fn is_member_of_exactly(
        &self,
        user_id: &UserId,
        group_name: &str,
    ) -> Result<bool> {
        Ok(member_of_exactly(&self.sql_pool, user_id, group_name).await?)
    }
}

/// `is_user_disabled` on any connection.
pub(crate) async fn user_disabled_in(
    db: &impl ConnectionTrait,
    user_id: &UserId,
) -> std::result::Result<bool, DbErr> {
    member_of(db, user_id, "lldap_disabled").await
}

async fn member_of(
    db: &impl ConnectionTrait,
    user_id: &UserId,
    group_name: &str,
) -> std::result::Result<bool, DbErr> {
    use lldap_domain_model::model::groups;
    use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};

    let Some(group) = groups::Entity::find()
        .filter(groups::Column::DisplayName.eq(group_name))
        .one(db)
        .await?
    else {
        return Ok(false);
    };
    in_group(db, user_id, group.group_id).await
}

/// The group of exactly this name, whatever the database's collation makes of `=`.
async fn member_of_exactly(
    db: &impl ConnectionTrait,
    user_id: &UserId,
    group_name: &str,
) -> std::result::Result<bool, DbErr> {
    use lldap_domain_model::model::groups;
    use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};

    let named = groups::Entity::find()
        .filter(groups::Column::DisplayName.eq(group_name))
        .all(db)
        .await?;
    let exact = named
        .into_iter()
        .find(|g| g.display_name.as_str() == group_name);
    match exact {
        Some(group) => in_group(db, user_id, group.group_id).await,
        None => Ok(false),
    }
}

async fn in_group(
    db: &impl ConnectionTrait,
    user_id: &UserId,
    group_id: GroupId,
) -> std::result::Result<bool, DbErr> {
    use lldap_domain_model::model::memberships;
    use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};

    Ok(memberships::Entity::find()
        .filter(memberships::Column::UserId.eq(user_id.as_str()))
        .filter(memberships::Column::GroupId.eq(group_id))
        .one(db)
        .await?
        .is_some())
}

pub(crate) fn invalid_credentials(user_id: &UserId) -> DomainError {
    DomainError::AuthenticationError(format!(r#"for user "{}""#, user_id))
}

fn unknown_user(name: &UserId) -> DomainError {
    debug!(r#"User "{}" doesn't exist or has no password"#, name);
    logging::record_as(
        Some(name),
        LogKind::Bind,
        None,
        false,
        Some(UNKNOWN_USER_DETAIL),
    );
    invalid_credentials(name)
}

impl SqlBackendHandler {
    /// A refusal is the door's one row and answers as the wrong-credentials error. The items are
    /// judged at the instant the lockout was.
    async fn admit_at(
        &self,
        user: &UserId,
        door: Door,
        second_factor: bool,
        now: Timestamp,
    ) -> Result<()> {
        let attempt = Attempt {
            second_factor,
            now,
            ..Attempt::new(user, door)
        };
        admit(self, &attempt)
            .await
            .map_err(|_| invalid_credentials(user))
    }

    /// The items, then the enable-mfa value's read, judged when a web sign-in starts, before any
    /// password.
    async fn admitted_at_start(&self, user: &UserId, now: Timestamp) -> bool {
        let items = self
            .admit_at(user, Door::WebLogin, false, now)
            .await
            .is_ok();
        items && self.door_policy(user, LogKind::Login).await.is_ok()
    }

    /// After the proof verified: a proof that does not verify, answered at once. The finish's split
    /// is already queued; the run loop writes it well inside the start's hold.
    fn refuse_finish() -> DomainError {
        opaque::AuthenticationError::failed_proof().into()
    }

    /// The password of a user read without sync in directory-only: the user's row is written
    /// first, then `sync_still_off`, in one transaction.
    async fn finish_with_sync_off(
        &self,
        user_update: model::users::ActiveModel,
        user: &UserId,
    ) -> Result<()> {
        let user = user.clone();
        self.sql_pool
            .transaction::<_, (), DomainError>(|transaction| {
                Box::pin(async move {
                    user_update.update(transaction).await?;
                    sync_still_off(transaction, &user).await
                })
            })
            .await?;
        Ok(())
    }

    /// While the realm is unavailable only admins get in; a refusal is the door's one row.
    async fn admit_while_degraded(&self, user: &UserId, door: Door) -> Result<()> {
        let unavailable = kerberos_backend().unavailable();
        if unavailable.is_none() || self.is_member_of(user, "lldap_admin").await? {
            return Ok(());
        }
        let cause = match door {
            Door::LdapBind => {
                logging::record_as(
                    Some(user),
                    LogKind::AccessDenied,
                    Some(user.as_str()),
                    false,
                    Some(LDAP_ADMINS_ONLY),
                );
                unavailable
            }
            _ => refusal_while_degraded(user, false, unavailable),
        };
        cause.map_or(Ok(()), |cause| Err(DomainError::KdcUnavailable(cause)))
    }

    /// Only a wrong password is counted; a bind with no stretch permit has its own row and answer.
    async fn refuse_unmatched(
        &self,
        name: &UserId,
        unmatched: Unmatched,
        lock: Option<&LockState>,
        door: Door,
        now: Timestamp,
    ) -> DomainError {
        let row = |detail| logging::record_as(Some(name), LogKind::Bind, None, false, Some(detail));
        match unmatched {
            Unmatched::Wrong => {
                row("invalid credentials");
                self.count_failure(lock, door, now).await;
                invalid_credentials(name)
            }
            Unmatched::Busy => {
                row(BUSY_DETAIL);
                DomainError::Busy(STRETCH_BUSY.to_owned())
            }
            Unmatched::NotRun => DomainError::InternalError(STRETCH_FAILED.to_owned()),
        }
    }

    /// The bind once its password matched.
    async fn bind_proved(
        &self,
        name: &UserId,
        requirement: MfaRequirement,
        code: Option<&str>,
        lock: Option<&LockState>,
        door: Door,
        now: Timestamp,
    ) -> Result<()> {
        // Judged without the factor before any answer that only a right password gets.
        self.admit_at(name, door, false, now).await?;
        match (requirement, code) {
            (MfaRequirement::None, _) => {
                self.admit_while_degraded(name, door).await?;
                logging::record_as(Some(name), LogKind::Bind, None, true, None);
                self.count_success(lock, door, now).await;
                self.note_activity(name, now).await;
                Ok(())
            }
            (MfaRequirement::Enrollment, _) => {
                logging::record_as(
                    Some(name),
                    LogKind::Bind,
                    None,
                    false,
                    Some("mfa enrollment required"),
                );
                Err(DomainError::AuthenticationError(format!(
                    r#"{MFA_ENROLLMENT_REQUIRED} for user "{name}""#
                )))
            }
            (MfaRequirement::Totp, None) => {
                debug!(r#"Bind for "{}" carries no TOTP code"#, name);
                logging::record_as(
                    Some(name),
                    LogKind::Bind,
                    None,
                    false,
                    Some("totp code required"),
                );
                Err(DomainError::AuthenticationError(format!(
                    r#"{TOTP_CODE_REQUIRED} for user "{name}""#
                )))
            }
            (MfaRequirement::Totp, Some(code)) => match self.verify_user_totp(name, code).await? {
                Ok(()) => {
                    self.admit_at(name, door, true, now).await?;
                    self.admit_while_degraded(name, door).await?;
                    let stored = self.note_proof(name, now_unix()).await;
                    let detail = with_proof("totp", stored);
                    logging::record_as(Some(name), LogKind::Bind, None, true, Some(&detail));
                    self.count_success(lock, door, now).await;
                    self.note_activity(name, now).await;
                    Ok(())
                }
                Err(rejection) => {
                    logging::record_as(
                        Some(name),
                        LogKind::Bind,
                        None,
                        false,
                        Some(rejection.detail()),
                    );
                    if rejection == TotpRejection::Invalid {
                        self.count_failure(lock, door, now).await;
                    }
                    Err(rejection.into_error(name))
                }
            },
        }
    }

    /// The web login's finish once its proof verified.
    async fn finish_proved(
        &self,
        username: UserId,
        lock: Option<LockState>,
        foreign: Option<u64>,
        totp_code: Option<String>,
        now: Timestamp,
    ) -> Result<LoginOutcome> {
        let split = match foreign {
            Some(id) => self.lockout.split(&username, id, false),
            None => Step::default(),
        };
        let admitted = self.admit_at(&username, Door::WebLogin, false, now);
        if admitted.await.is_err() {
            return Err(Self::refuse_finish());
        }
        let requirement = match self.door_requirement(&username, LogKind::Login).await {
            Err(DomainError::AuthenticationError(_)) => {
                return Err(Self::refuse_finish());
            }
            requirement => requirement?,
        };
        let (detail, mfa_enrollment_pending) = match requirement {
            MfaRequirement::None => (None, false),
            MfaRequirement::Enrollment => (Some("mfa enrollment pending"), true),
            MfaRequirement::Totp => match totp_code.as_deref() {
                // A right password with no code is its own failure row, then the code step.
                None => {
                    debug!(r#"OPAQUE login for "{}" awaits the TOTP code"#, &username);
                    logging::record_as(
                        Some(&username),
                        LogKind::Login,
                        None,
                        false,
                        Some("totp code required"),
                    );
                    self.lockout.carry(self, &username, split).await;
                    return Ok(LoginOutcome::TotpRequired);
                }
                Some(code) => match self.verify_user_totp(&username, code).await? {
                    Ok(()) => (Some("totp"), false),
                    Err(rejection) => {
                        warn_limited!(
                            r#"TOTP refused for "{}": {}"#,
                            &username,
                            rejection.detail()
                        );
                        logging::record_as(
                            Some(&username),
                            LogKind::Login,
                            None,
                            false,
                            Some(rejection.detail()),
                        );
                        if rejection == TotpRejection::Invalid {
                            self.count_failure(lock.as_ref(), Door::WebLogin, now).await;
                        }
                        return Err(rejection.into_error(&username));
                    }
                },
            },
        };
        let second_factor = detail == Some("totp");
        if second_factor
            && self
                .admit_at(&username, Door::WebLogin, true, now)
                .await
                .is_err()
        {
            return Err(Self::refuse_finish());
        }
        self.admit_while_degraded(&username, Door::WebLogin).await?;
        let stored = !second_factor || self.note_proof(&username, now_unix()).await;
        let detail = detail.map(|detail| with_proof(detail, stored));
        debug!(r#"OPAQUE login successful for "{}""#, &username);
        logging::record_as(
            Some(&username),
            LogKind::Login,
            None,
            true,
            detail.as_deref(),
        );
        self.count_success(lock.as_ref(), Door::WebLogin, now).await;
        self.note_activity(&username, now).await;
        if let Some(id) = foreign {
            let step = self.lockout.split(&username, id, true);
            self.lockout.carry(self, &username, step).await;
        }
        Ok(LoginOutcome::Authenticated {
            user_id: username,
            mfa_enrollment_pending,
        })
    }
}

#[async_trait]
impl LoginHandler for SqlBackendHandler {
    #[instrument(skip_all, level = "debug", err(level = "debug"))]
    async fn bind(&self, request: BindRequest) -> Result<()> {
        let BindRequest { name, password } = request;
        if without_password(&password) {
            logging::record_as(Some(&name), LogKind::Bind, None, false, Some(NO_PASSWORD));
            return Err(invalid_credentials(&name));
        }
        if door_read(self.is_user_disabled(&name)).await? {
            debug!(r#"Login attempt denied for disabled user "{}""#, &name);
            logging::record_as(
                Some(&name),
                LogKind::Bind,
                None,
                false,
                Some("account disabled"),
            );
            return Err(invalid_credentials(&name));
        }
        let Some(requirement) = self.bind_requirement(&name).await? else {
            return Err(unknown_user(&name));
        };
        // An enrolled user binds with password:code; the password is checked first either way.
        let (password, code) = match requirement {
            MfaRequirement::Totp => match split_totp_suffix(&password) {
                Some((password, code)) => (password, Some(code)),
                None => (password.as_str(), None),
            },
            _ => (password.as_str(), None),
        };
        let password_file = door_read(self.get_password_file_for_user(name.clone()));
        let Some(password_hash) = password_file.await? else {
            return Err(unknown_user(&name));
        };
        let (now, door) = (lock_clock(), Door::of_bind());
        let lock = self
            .lock_state(&name)
            .await
            .map_err(|e| Self::lock_unreadable(&name, LogKind::Bind, e))?;
        if lock.as_ref().is_some_and(|lock| lock.locked(now)) {
            self.refuse_locked(&name, LogKind::Bind);
            return Err(invalid_credentials(&name));
        }
        debug!(r#"Login attempt for "{}""#, &name);
        let (gate, setup) = (self.stretch_gate, &self.opaque_setup);
        let unmatched = passwords_match(gate, &password_hash, password, setup, &name).await;
        if let Some(unmatched) = unmatched {
            let refused = self.refuse_unmatched(&name, unmatched, lock.as_ref(), door, now);
            return Err(refused.await);
        }
        let proved = self.bind_proved(&name, requirement, code, lock.as_ref(), door, now);
        logging::proved(proved).await
    }
}

#[async_trait]
impl OpaqueHandler for SqlOpaqueHandler {
    #[instrument(skip_all, level = "debug", err(level = "debug"))]
    async fn login_start(
        &self,
        request: login::ClientLoginStartRequest,
    ) -> Result<login::ServerLoginStartResponse> {
        let user_id = request.username;

        if door_read(self.is_user_disabled(&user_id)).await? {
            debug!(
                r#"OPAQUE login attempt denied for disabled user "{}""#,
                &user_id
            );
            logging::record_as(
                Some(&user_id),
                LogKind::Login,
                None,
                false,
                Some("account disabled"),
            );
            return Err(DomainError::AuthenticationError(format!(
                r#"for user "{}""#,
                user_id
            )));
        }

        debug!(r#"OPAQUE login attempt for "{}""#, &user_id);
        let maybe_password_file = door_read(self.get_password_file_for_user(user_id.clone()))
            .await?
            .map(|bytes| {
                opaque::server::ServerRegistration::deserialize(&bytes).map_err(|_| {
                    DomainError::InternalError(format!("Corrupted password file for {}", user_id))
                })
            })
            .transpose()?;
        let now = lock_clock();
        let mut rng = rand::rngs::OsRng;
        let mut overlay = None;
        let lock = match maybe_password_file {
            Some(_) => self
                .lock_state(&user_id)
                .await
                .map_err(|e| Self::lock_unreadable(&user_id, LogKind::Login, e))?,
            None => None,
        };
        // A locked user, and one the items or an unreadable enable-mfa value refuse, is answered as
        // a name with no password file is.
        let maybe_password_file = match lock {
            Some(lock) => {
                let id = rand::RngCore::next_u64(&mut rng);
                if lock.locked(now) {
                    self.refuse_locked(&user_id, LogKind::Login);
                    None
                } else if !self.admitted_at_start(&user_id, now).await {
                    None
                } else if !self.lockout.start(&lock, id, now) {
                    self.refuse_locked(&user_id, LogKind::Login);
                    None
                } else {
                    overlay = Some(id);
                    maybe_password_file
                }
            }
            None if maybe_password_file.is_some() => {
                let admitted = self.admitted_at_start(&user_id, now).await;
                maybe_password_file.filter(|_| admitted)
            }
            None => None,
        };

        let start_response = opaque::server::login::start_login(
            &mut rng,
            &self.opaque_setup,
            maybe_password_file,
            request.login_start_request,
            &user_id,
        )?;
        let secret_key = self.get_orion_secret_key(LOGIN_STATE_KEY_INFO)?;
        let server_data = login::ServerData {
            username: user_id,
            server_login: start_response.state,
            overlay,
        };
        let encrypted_state = orion::aead::seal(&secret_key, &bincode::serialize(&server_data)?)?;

        Ok(login::ServerLoginStartResponse {
            server_data: base64::engine::general_purpose::STANDARD.encode(encrypted_state),
            credential_response: start_response.message,
        })
    }

    #[instrument(skip_all, level = "debug", err(level = "debug"))]
    async fn login_finish(&self, request: login::ClientLoginFinishRequest) -> Result<LoginOutcome> {
        let login::ClientLoginFinishRequest {
            server_data,
            credential_finalization,
            totp_code,
            enrollment_proof: _,
            session: _,
        } = request;
        let secret_key = self.get_orion_secret_key(LOGIN_STATE_KEY_INFO)?;
        let login::ServerData {
            username,
            server_login,
            overlay,
        } = decode_exact(&orion::aead::open(
            &secret_key,
            &base64::engine::general_purpose::STANDARD.decode(&server_data)?,
        )?)?;

        // Checked again in case login_start was bypassed.
        if door_read(self.is_user_disabled(&username)).await? {
            debug!(
                r#"OPAQUE login_finish denied for disabled user "{}""#,
                &username
            );
            logging::record_as(
                Some(&username),
                LogKind::Login,
                None,
                false,
                Some("account disabled"),
            );
            return Err(invalid_credentials(&username));
        }

        let verified = opaque::server::login::finish_login(server_login, credential_finalization);
        let found = match overlay {
            Some(id) if verified.is_ok() => self.lockout.finish(&username, id),
            _ => false,
        };
        let now = lock_clock();
        // A proof that did not verify is no credential, and its name, if no user, has no lock.
        let lock = match verified.is_ok() {
            true => self.lock_state(&username).await,
            false => before_credential(self.lock_state(&username)).await,
        };
        let lock = match lock {
            Err(DomainError::EntityNotFound(_)) if verified.is_err() => None,
            lock => lock.map_err(|e| Self::lock_unreadable(&username, LogKind::Login, e))?,
        };
        // Judged before the proof's result shows: a locked user gets the failed proof's answer.
        if lock.as_ref().is_some_and(|lock| lock.locked(now)) {
            self.refuse_locked(&username, LogKind::Login);
            return Err(opaque::AuthenticationError::failed_proof().into());
        }
        if let Err(e) = verified {
            debug!(r#"OPAQUE login attempt failed for "{}""#, &username);
            logging::record_as(
                Some(&username),
                LogKind::Login,
                None,
                false,
                Some("invalid credentials"),
            );
            return Err(e.into());
        }
        let foreign = overlay.filter(|_| !found);
        let proved = self.finish_proved(username, lock, foreign, totp_code, now);
        logging::proved(proved).await
    }

    #[instrument(skip_all, level = "debug", err)]
    async fn registration_start(
        &self,
        request: registration::ClientRegistrationStartRequest,
    ) -> Result<registration::ServerRegistrationStartResponse> {
        self.start_registration(request, None)
    }

    #[instrument(skip_all, level = "debug", err)]
    async fn registration_finish(
        &self,
        request: registration::ClientRegistrationFinishRequest,
    ) -> Result<UserId> {
        require_kdc_ready()?;
        let registration::ServerData { username, .. } =
            self.open_registration(&request.server_data)?;

        let password_file =
            opaque::server::registration::get_password_file(request.registration_upload);
        let now = chrono::Utc::now().naive_utc();
        let user_update = model::users::ActiveModel {
            user_id: ActiveValue::Set(username.clone()),
            password_hash: ActiveValue::Set(Some(password_file.serialize().to_vec())),
            password_modified_date: ActiveValue::Set(now),
            modified_date: ActiveValue::Set(now),
            ..Default::default()
        };
        match kerberos_backend().directory_only() {
            Some(_) => self.finish_with_sync_off(user_update, &username).await?,
            None => {
                user_update.update(&self.sql_pool).await?;
            }
        }
        info!(r#"Successfully (re)set password for "{}""#, &username);
        logging::record(LogKind::PasswordChange, Some(username.as_str()), None);
        Ok(username)
    }

    #[instrument(skip_all, level = "debug", err)]
    async fn registration_start_by(
        &self,
        request: registration::ClientRegistrationStartRequest,
        by: registration::Presenter,
        envelope_key: Option<[u8; 32]>,
    ) -> Result<registration::ServerRegistrationStartResponse> {
        let mut id = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut id);
        let start = registration::StartBinding {
            id,
            by,
            envelope_key,
        };
        self.start_registration(request, Some(start))
    }

    #[instrument(skip_all, level = "debug", err(level = "debug"))]
    async fn registration_claim(
        &self,
        request: &registration::ClientRegistrationFinishRequest,
        presenter: &registration::Presenter,
    ) -> Result<registration::Claim> {
        let registration::ServerData {
            username,
            issued_at,
            start,
        } = self.open_registration(&request.server_data)?;
        let Some(start) = start.filter(|start| start.by == *presenter) else {
            return Err(refuse_unfinishable(&username));
        };
        if now_unix() - issued_at > REGISTRATION_MAX_AGE {
            return Err(Self::took_too_long(&username));
        }
        let expires_at = issued_at + REGISTRATION_MAX_AGE + CLOCK_TOLERANCE_SECS;
        match take_start_id(&self.sql_pool, &start.id, expires_at).await {
            Ok(true) => {
                self.note_codes_written();
                Ok(registration::Claim {
                    user: username,
                    envelope_key: start.envelope_key,
                })
            }
            Ok(false) => Err(refuse_unfinishable(&username)),
            Err(e) => Err(Self::unmarked(&username, &e)),
        }
    }
}

#[cfg(test)]
mod networks_rows;

#[cfg(test)]
mod start_rows;

#[cfg(test)]
mod line_rows;

#[cfg(test)]
mod tests {
    use self::opaque::server::generate_random_private_key;

    use super::*;
    use crate::sql_backend_handler::tests::{
        get_initialized_db, insert_group, insert_membership, insert_user, insert_user_no_password,
    };
    use crate::sql_used_starts::tests::{kept, session, web_registration};
    use lldap_domain_handlers::handler::MfaBackendHandler;
    use lldap_domain_handlers::password::REGISTRATION_UNFINISHABLE;
    use lldap_opaque_handler::register_password;

    async fn attempt_login(
        opaque_handler: &SqlOpaqueHandler,
        username: &str,
        password: &str,
        totp_code: Option<&str>,
    ) -> Result<LoginOutcome> {
        attempt_login_with(opaque_handler, username, password, totp_code, None).await
    }

    async fn attempt_login_with(
        opaque_handler: &SqlOpaqueHandler,
        username: &str,
        password: &str,
        totp_code: Option<&str>,
        session: Option<bool>,
    ) -> Result<LoginOutcome> {
        let mut rng = rand::rngs::OsRng;
        use login::*;
        let login_start = opaque::client::login::start_login(password, &mut rng)?;
        let start_response = opaque_handler
            .login_start(ClientLoginStartRequest {
                username: UserId::new(username),
                login_start_request: login_start.message,
            })
            .await?;
        let login_finish = opaque::client::login::finish_login(
            login_start.state,
            password.as_bytes(),
            start_response.credential_response,
            &mut rng,
        )?;
        let finish = opaque_handler.login_finish(ClientLoginFinishRequest {
            server_data: start_response.server_data,
            credential_finalization: login_finish.message,
            totp_code: totp_code.map(str::to_owned),
            enrollment_proof: None,
            session,
        });
        match session {
            Some(false) => logging::without_session(finish).await,
            _ => finish.await,
        }
    }

    #[tokio::test]
    async fn test_opaque_flow() -> Result<()> {
        let sql_pool = get_initialized_db().await;
        crate::logging::init_for_tests();
        let backend_handler = SqlBackendHandler::new(generate_random_private_key(), sql_pool);
        insert_user_no_password(&backend_handler, "bob").await;
        insert_user_no_password(&backend_handler, "john").await;
        attempt_login(&backend_handler, "bob", "bob00", None)
            .await
            .unwrap_err();
        register_password(&backend_handler, UserId::new("bob"), b"bob00").await?;
        attempt_login(&backend_handler, "bob", "wrong_password", None)
            .await
            .unwrap_err();
        attempt_login(&backend_handler, "bob", "bob00", None).await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_the_prepared_record_is_the_one_registration_stores() {
        let sql_pool = get_initialized_db().await;
        let handler = SqlBackendHandler::new(generate_random_private_key(), sql_pool);
        insert_user_no_password(&handler, "bob").await;
        let (record, request) =
            lldap_opaque_handler::prepare_registration(&handler, UserId::new("bob"), b"bob00")
                .await
                .unwrap();
        handler.registration_finish(request).await.unwrap();
        let stored = handler
            .get_password_file_for_user(UserId::new("bob"))
            .await
            .unwrap();
        assert!(stored == Some(record), "the stored record differs");
        attempt_login(&handler, "bob", "bob00", None).await.unwrap();
    }

    #[tokio::test]
    async fn test_bind_user() {
        let sql_pool = get_initialized_db().await;
        let handler = SqlOpaqueHandler::new(generate_random_private_key(), sql_pool.clone());
        insert_user(&handler, "bob", "bob00").await;

        handler
            .bind(BindRequest {
                name: UserId::new("bob"),
                password: "bob00".to_string(),
            })
            .await
            .unwrap();
        handler
            .bind(BindRequest {
                name: UserId::new("andrew"),
                password: "bob00".to_string(),
            })
            .await
            .unwrap_err();
        handler
            .bind(BindRequest {
                name: UserId::new("bob"),
                password: "wrong_password".to_string(),
            })
            .await
            .unwrap_err();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_bind_stretches_off_the_worker() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let sql_pool = get_initialized_db().await;
        let handler = SqlOpaqueHandler::new(generate_random_private_key(), sql_pool);
        insert_user(&handler, "bob", "bob00").await;
        let ticks = Arc::new(AtomicUsize::new(0));
        let ticks_for_ticker = Arc::clone(&ticks);
        let ticker = tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_millis(10));
            loop {
                interval.tick().await;
                ticks_for_ticker.fetch_add(1, Ordering::SeqCst);
            }
        });
        while ticks.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
        let baseline = ticks.load(Ordering::SeqCst);
        let bind = handler.bind(BindRequest {
            name: UserId::new("bob"),
            password: "bob00".to_string(),
        });
        tokio::pin!(bind);
        tokio::select! {
            _ = async {
                loop {
                    if ticks.load(Ordering::SeqCst) > baseline {
                        break;
                    }
                    tokio::task::yield_now().await;
                }
            } => {}
            result = &mut bind => panic!("bind returned before the counter moved: {result:?}"),
        }
        bind.await.unwrap();
        ticker.abort();
    }

    #[tokio::test]
    async fn test_user_no_password() {
        let sql_pool = get_initialized_db().await;
        let handler = SqlBackendHandler::new(generate_random_private_key(), sql_pool.clone());
        insert_user_no_password(&handler, "bob").await;

        handler
            .bind(BindRequest {
                name: UserId::new("bob"),
                password: "bob00".to_string(),
            })
            .await
            .unwrap_err();
    }

    #[tokio::test]
    async fn test_disabled_membership_refuses_the_bind_without_leaking_why() {
        let sql_pool = get_initialized_db().await;
        let handler = SqlOpaqueHandler::new(generate_random_private_key(), sql_pool.clone());
        insert_user(&handler, "bob", "bob00").await;
        assert!(
            !handler.is_user_disabled(&UserId::new("bob")).await.unwrap(),
            "fresh user is not disabled"
        );
        let disabled_gid = insert_group(&handler, "lldap_disabled").await;
        insert_membership(&handler, disabled_gid, "bob").await;
        assert!(
            handler.is_user_disabled(&UserId::new("bob")).await.unwrap(),
            "membership in lldap_disabled must be detected"
        );

        let err = handler
            .bind(BindRequest {
                name: UserId::new("bob"),
                password: "bob00".to_string(),
            })
            .await
            .unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains(r#"for user "bob""#),
            "disabled login must look like a failed bind, got: {msg}"
        );
        assert!(
            !msg.to_lowercase().contains("disabled"),
            "must not leak account-disabled to the client: {msg}"
        );
    }

    use crate::sql_mfa_handler::pin_clock;
    use lldap_domain_handlers::logging::{RequestMeta, with_request};
    use lldap_domain_handlers::mfa::{MFA_DISABLED_GROUP, MfaPolicy};
    use lldap_mfa::{TOTP_STEP_SECS, format_code, totp_code};

    const AT: u64 = 1_770_000_015;
    use lldap_test_utils::recording_log::LogGuard;
    use serial_test::serial;

    async fn mfa_handler(policy: MfaPolicy) -> SqlBackendHandler {
        SqlBackendHandler::new(generate_random_private_key(), get_initialized_db().await)
            .with_mfa_policy(policy)
    }

    // Enrolls through the engine; the current step's code is spent on the confirmation.
    async fn enroll(handler: &SqlBackendHandler, user: &str, now: u64) -> Vec<u8> {
        let user_id = UserId::new(user);
        let proof = handler
            .seal_enrollment_proof(&user_id)
            .await
            .unwrap()
            .unwrap();
        let start = handler
            .start_totp_enrollment(&user_id, None, Some(proof))
            .await
            .unwrap();
        let seed = lldap_mfa::seed_from_base32(&start.secret_base32).unwrap();
        handler
            .finish_totp_enrollment(
                &user_id,
                &start.state,
                &format_code(totp_code(&seed, now).unwrap()),
            )
            .await
            .unwrap();
        seed
    }

    // A fresh code from the neighbouring step and one invalid at every accepted step.
    fn fresh_and_wrong(seed: &[u8], now: u64) -> (String, String) {
        let at = |t: u64| format_code(totp_code(seed, t).unwrap());
        let current = at(now);
        let fresh = [now + TOTP_STEP_SECS, now - TOTP_STEP_SECS]
            .into_iter()
            .map(at)
            .find(|c| *c != current)
            .unwrap();
        let valid = [at(now - TOTP_STEP_SECS), current, at(now + TOTP_STEP_SECS)];
        let wrong = (0..)
            .map(|c| format!("{c:06}"))
            .find(|c| !valid.contains(c))
            .unwrap();
        (fresh, wrong)
    }

    fn bind_request(user: &str, password: &str) -> BindRequest {
        BindRequest {
            name: UserId::new(user),
            password: password.to_owned(),
        }
    }

    fn auth_rows(guard: &LogGuard, peer: &str) -> Vec<(LogKind, bool, Option<String>)> {
        guard
            .recorder()
            .take_events()
            .into_iter()
            .filter(|e| e.peer.as_deref() == Some(peer))
            .filter(|e| matches!(e.kind, LogKind::Bind | LogKind::Login))
            .map(|e| (e.kind, e.success, e.detail))
            .collect()
    }

    #[tokio::test]
    #[serial]
    async fn test_bind_enforces_totp() {
        let _clock = pin_clock(AT as i64);
        let guard = LogGuard::install_on_this_thread();
        let peer = "10.77.1.1";
        let handler = mfa_handler(MfaPolicy::Enrolled).await;
        insert_user(&handler, "bob", "bob00").await;
        let seed = enroll(&handler, "bob", AT).await;
        let (fresh, wrong) = fresh_and_wrong(&seed, AT);
        let wrong = format!("bob00:{wrong}");
        let right = format_code(totp_code(&seed, AT + TOTP_STEP_SECS).unwrap());
        let right = format!("bob00:{right}");
        let step = (UserId::new("bob"), (AT / TOTP_STEP_SECS) as i64);
        let (mut answers, mut kept) = (Vec::new(), None);
        with_request(
            RequestMeta::ldap(None, Some(peer.parse().unwrap())),
            async {
                // A verified password without a code is its own failure row.
                let err = handler
                    .bind(bind_request("bob", "bob00"))
                    .await
                    .unwrap_err();
                assert!(err.to_string().contains(TOTP_CODE_REQUIRED), "{err}");
                let err = handler.bind(bind_request("bob", &wrong)).await.unwrap_err();
                assert!(err.to_string().contains("Invalid TOTP code"), "{err}");
                // A wrong password is refused before the code is looked at.
                let err = handler
                    .bind(bind_request("bob", &format!("nope:{fresh}")))
                    .await
                    .unwrap_err();
                assert!(!err.to_string().contains("TOTP"), "{err}");
                handler
                    .bind(bind_request("bob", &format!("bob00:{fresh}")))
                    .await
                    .unwrap();
                let err = handler
                    .bind(bind_request("bob", &format!("bob00:{fresh}")))
                    .await
                    .unwrap_err();
                assert!(err.to_string().contains("already used"), "{err}");
                let row = model::TotpSteps::find_by_id(step.clone());
                kept = row
                    .one(&handler.sql_pool)
                    .await
                    .unwrap()
                    .map(|row| row.failures);
                // The gate runs before verification: even a valid code is refused.
                for password in [&wrong, &wrong, &wrong, &wrong, &wrong, &right] {
                    let err = handler
                        .bind(bind_request("bob", password))
                        .await
                        .unwrap_err();
                    answers.push(err.to_string().contains("Too many TOTP attempts"));
                }
            },
        )
        .await;
        assert_eq!(
            (kept, answers),
            (Some(1), vec![false, false, false, false, true, true]),
            "the earlier wrong code is the step's one failure; four more answer invalid, then two \
             are past the limit"
        );
        let row =
            |success, detail: Option<&str>| (LogKind::Bind, success, detail.map(str::to_owned));
        let mut expected = vec![
            row(false, Some("totp code required")),
            row(false, Some("invalid totp")),
            row(false, Some("invalid credentials")),
            row(true, Some("totp")),
            row(false, Some("totp replayed")),
        ];
        expected.extend((0..4).map(|_| row(false, Some("invalid totp"))));
        expected.extend((0..2).map(|_| row(false, Some("totp attempts exceeded"))));
        assert_eq!(auth_rows(&guard, peer), expected);
    }

    #[tokio::test]
    async fn test_bind_exempt_unenrolled_and_disabled_policy() {
        let _clock = pin_clock(AT as i64);
        let handler = mfa_handler(MfaPolicy::Always).await;
        insert_user(&handler, "bob", "bob00").await;
        insert_user(&handler, "eve", "eve00").await;
        let exempt = insert_group(&handler, MFA_DISABLED_GROUP).await;
        insert_membership(&handler, exempt, "eve").await;
        // The password is checked before the policy answers anything.
        let err = handler
            .bind(bind_request("bob", "wrong"))
            .await
            .unwrap_err();
        assert!(!err.to_string().contains("MFA"), "{err}");
        let err = handler
            .bind(bind_request("bob", "bob00"))
            .await
            .unwrap_err();
        assert!(err.to_string().contains(MFA_ENROLLMENT_REQUIRED), "{err}");
        handler.bind(bind_request("eve", "eve00")).await.unwrap();
        // Exemption beats enrollment under both positive modes.
        enroll(&handler, "eve", AT).await;
        handler.bind(bind_request("eve", "eve00")).await.unwrap();
        let handler = handler.with_mfa_policy(MfaPolicy::Enrolled);
        handler.bind(bind_request("eve", "eve00")).await.unwrap();
        handler.bind(bind_request("bob", "bob00")).await.unwrap();
        // Disabled never splits: a password that ends in :digits is the whole password.
        insert_user(&handler, "kim", "kim:123456").await;
        enroll(&handler, "kim", AT).await;
        let handler = handler.with_mfa_policy(MfaPolicy::Disabled);
        handler
            .bind(bind_request("kim", "kim:123456"))
            .await
            .unwrap();
        handler.bind(bind_request("kim", "kim")).await.unwrap_err();
    }

    #[tokio::test]
    #[serial]
    async fn test_login_finish_enforces_totp() {
        let _clock = pin_clock(AT as i64);
        let guard = LogGuard::install_on_this_thread();
        let peer = "10.77.1.2";
        let handler = mfa_handler(MfaPolicy::Always).await;
        insert_user(&handler, "bob", "bob00").await;
        let bob = UserId::new("bob");
        with_request(
            RequestMeta::http(Some(peer.parse().unwrap()), None),
            async {
                assert_eq!(
                    attempt_login(&handler, "bob", "bob00", None).await.unwrap(),
                    LoginOutcome::Authenticated {
                        user_id: bob.clone(),
                        mfa_enrollment_pending: true,
                    }
                );
                let seed = enroll(&handler, "bob", AT).await;
                let (fresh, wrong) = fresh_and_wrong(&seed, AT);
                assert_eq!(
                    attempt_login(&handler, "bob", "bob00", None).await.unwrap(),
                    LoginOutcome::TotpRequired
                );
                let err = attempt_login(&handler, "bob", "bob00", Some(&wrong))
                    .await
                    .unwrap_err();
                assert!(err.to_string().contains("Invalid TOTP code"), "{err}");
                assert_eq!(
                    attempt_login(&handler, "bob", "bob00", Some(&fresh))
                        .await
                        .unwrap(),
                    LoginOutcome::Authenticated {
                        user_id: bob.clone(),
                        mfa_enrollment_pending: false,
                    }
                );
            },
        )
        .await;
        let row =
            |success, detail: Option<&str>| (LogKind::Login, success, detail.map(str::to_owned));
        assert_eq!(
            auth_rows(&guard, peer),
            vec![
                row(true, Some("mfa enrollment pending")),
                row(false, Some("totp code required")),
                row(false, Some("invalid totp")),
                row(true, Some("totp")),
            ]
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_a_sessionless_finish_writes_the_doors_one_row_saying_no_session() {
        let _clock = pin_clock(AT as i64);
        let guard = LogGuard::install_on_this_thread();
        let peer = "10.77.1.3";
        let handler = mfa_handler(MfaPolicy::Always).await;
        insert_user(&handler, "bob", "bob00").await;
        let bob = UserId::new("bob");
        let check = Some(false);
        with_request(
            RequestMeta::http(Some(peer.parse().unwrap()), None),
            async {
                assert_eq!(
                    attempt_login_with(&handler, "bob", "bob00", None, check)
                        .await
                        .unwrap(),
                    LoginOutcome::Authenticated {
                        user_id: bob.clone(),
                        mfa_enrollment_pending: true,
                    }
                );
                let seed = enroll(&handler, "bob", AT).await;
                let (fresh, wrong) = fresh_and_wrong(&seed, AT);
                assert_eq!(
                    attempt_login_with(&handler, "bob", "bob00", None, check)
                        .await
                        .unwrap(),
                    LoginOutcome::TotpRequired
                );
                attempt_login_with(&handler, "bob", "bob00", Some(&wrong), check)
                    .await
                    .unwrap_err();
                attempt_login_with(&handler, "bob", "bob00", Some(&fresh), check)
                    .await
                    .unwrap();
                let plain = handler.clone().with_mfa_policy(MfaPolicy::Disabled);
                for session in [Some(false), Some(true), None] {
                    attempt_login_with(&plain, "bob", "bob00", None, session)
                        .await
                        .unwrap();
                }
            },
        )
        .await;
        let row =
            |success, detail: Option<&str>| (LogKind::Login, success, detail.map(str::to_owned));
        assert_eq!(
            auth_rows(&guard, peer),
            vec![
                row(true, Some("mfa enrollment pending; no session")),
                row(false, Some("totp code required; no session")),
                row(false, Some("invalid totp; no session")),
                row(true, Some("totp; no session")),
                row(true, Some(logging::NO_SESSION)),
                row(true, None),
                row(true, None),
            ]
        );
    }

    async fn client_registration(
        handler: &SqlOpaqueHandler,
        user: &str,
        password: &str,
    ) -> registration::ClientRegistrationFinishRequest {
        let mut rng = rand::rngs::OsRng;
        let start = opaque::client::registration::start_registration(password.as_bytes(), &mut rng)
            .unwrap();
        let response = handler
            .registration_start(registration::ClientRegistrationStartRequest {
                username: UserId::new(user),
                registration_start_request: start.message,
            })
            .await
            .unwrap();
        let finish = opaque::client::registration::finish_registration(
            start.state,
            password.as_bytes(),
            response.registration_response,
            &mut rng,
        )
        .unwrap();
        registration::ClientRegistrationFinishRequest {
            server_data: response.server_data,
            registration_upload: finish.message,
        }
    }

    fn one_row(detail: &str) -> Vec<(LogKind, Option<String>, Option<String>)> {
        vec![(
            LogKind::PasswordChange,
            Some("bob".to_owned()),
            Some(detail.to_owned()),
        )]
    }

    fn failures(log: &LogGuard) -> Vec<(LogKind, Option<String>, Option<String>)> {
        let events = log.recorder().take_events().into_iter();
        let failed = events.filter(|e| !e.success);
        failed.map(|e| (e.kind, e.target, e.detail)).collect()
    }

    fn unfinishable() -> String {
        DomainError::AuthenticationError(REGISTRATION_UNFINISHABLE.to_owned()).to_string()
    }

    #[tokio::test]
    #[serial]
    async fn test_a_start_is_finished_once() {
        let setup = generate_random_private_key();
        let handler = SqlOpaqueHandler::new(setup.clone(), get_initialized_db().await);
        insert_user(&handler, "bob", "bob00").await;
        let bob = UserId::new("bob");
        let before = handler
            .get_password_file_for_user(bob.clone())
            .await
            .unwrap();
        let admin = session("admin", 1);
        let key = Some([9u8; 32]);
        let request = web_registration(&handler, "bob", "bob-new-1", &admin, key).await;
        let claim = registration::Claim {
            user: bob.clone(),
            envelope_key: key,
        };
        let log = LogGuard::install_on_this_thread();
        assert_eq!(
            handler.registration_claim(&request, &admin).await.unwrap(),
            claim
        );
        assert_eq!((kept(&handler.sql_pool).await, failures(&log)), (1, vec![]));
        assert_eq!(
            handler
                .get_password_file_for_user(bob.clone())
                .await
                .unwrap(),
            before,
            "a claim writes its mark and nothing of the user"
        );
        let restarted = SqlOpaqueHandler::new(setup, handler.sql_pool.clone());
        for (label, server) in [("the same server", &handler), ("a restart", &restarted)] {
            let again = server.registration_claim(&request, &admin).await;
            assert_eq!(
                (
                    again.map_err(|e| e.to_string()),
                    failures(&log),
                    kept(&handler.sql_pool).await
                ),
                (Err(unfinishable()), one_row(REGISTRATION_UNFINISHABLE), 1),
                "{label}"
            );
        }
        drop(log);
        attempt_login(&handler, "bob", "bob00", None).await.unwrap();

        let other =
            SqlOpaqueHandler::new(generate_random_private_key(), get_initialized_db().await);
        let mut garbled = request.clone();
        garbled.server_data = "bm90IHNlYWxlZA==".to_owned();
        for (label, server, request, marks) in [
            ("another server's key", &other, &request, 0),
            ("not sealed", &handler, &garbled, 1),
        ] {
            let claimed = server.registration_claim(request, &admin).await;
            assert_eq!(
                (claimed.is_err(), kept(&server.sql_pool).await),
                (true, marks),
                "{label}"
            );
        }
    }

    #[tokio::test]
    #[serial]
    async fn test_a_finish_from_another_session_is_refused_and_takes_no_mark() {
        let handler =
            SqlOpaqueHandler::new(generate_random_private_key(), get_initialized_db().await);
        let reset = |user: &str, id: u8| registration::Presenter {
            reset: true,
            ..session(user, id)
        };
        let rows = [
            ("another user", session("bob", 1), session("carol", 1)),
            (
                "the same user's other session",
                session("bob", 1),
                session("bob", 2),
            ),
            (
                "a session token on a reset start",
                reset("bob", 1),
                session("bob", 1),
            ),
            (
                "a reset token on a session start",
                session("bob", 1),
                reset("bob", 1),
            ),
        ];
        let log = LogGuard::install_on_this_thread();
        for (n, (row, by, presenter)) in rows.into_iter().enumerate() {
            let request = web_registration(&handler, "bob", "bob-new-1", &by, None).await;
            let refused = handler.registration_claim(&request, &presenter).await;
            assert_eq!(
                (
                    refused.map_err(|e| e.to_string()),
                    failures(&log),
                    kept(&handler.sql_pool).await
                ),
                (
                    Err(unfinishable()),
                    one_row(REGISTRATION_UNFINISHABLE),
                    n as i64
                ),
                "{row}"
            );
            let taken = handler.registration_claim(&request, &by).await;
            assert_eq!(
                (taken.is_ok(), kept(&handler.sql_pool).await),
                (true, n as i64 + 1),
                "{row}: the start's own session still finishes it"
            );
        }
    }

    #[tokio::test]
    #[serial]
    async fn test_a_start_made_in_process_is_not_taken_at_the_web_finish() {
        let handler =
            SqlOpaqueHandler::new(generate_random_private_key(), get_initialized_db().await);
        let request = client_registration(&handler, "bob", "bob-new-1").await;
        let log = LogGuard::install_on_this_thread();
        let refused = handler
            .registration_claim(&request, &session("bob", 1))
            .await;
        assert_eq!(
            (
                refused.map_err(|e| e.to_string()),
                failures(&log),
                kept(&handler.sql_pool).await
            ),
            (Err(unfinishable()), one_row(REGISTRATION_UNFINISHABLE), 0)
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_the_in_process_doors_take_no_mark() {
        let handler =
            SqlOpaqueHandler::new(generate_random_private_key(), get_initialized_db().await);
        insert_user_no_password(&handler, "bob").await;
        let request = client_registration(&handler, "bob", "bob-new-1").await;
        let sealed = handler.open_registration(&request.server_data).unwrap();
        assert!(sealed.start.is_none());
        for label in ["the first write", "the same request again"] {
            let written = handler.registration_finish(request.clone()).await;
            assert_eq!(
                (written.is_ok(), kept(&handler.sql_pool).await),
                (true, 0),
                "{label}"
            );
        }
        register_password(&handler, UserId::new("bob"), b"bob-next-1")
            .await
            .unwrap();
        assert_eq!(kept(&handler.sql_pool).await, 0);
        attempt_login(&handler, "bob", "bob-next-1", None)
            .await
            .unwrap();
    }

    #[tokio::test]
    #[serial]
    async fn test_a_start_that_cannot_be_marked_refuses_the_finish_with_one_row() {
        use sea_orm::{DbBackend, Statement};
        let handler =
            SqlOpaqueHandler::new(generate_random_private_key(), get_initialized_db().await);
        let bob = session("bob", 1);
        let request = web_registration(&handler, "bob", "bob-new-1", &bob, None).await;
        let rename = |from: &str, to: &str| {
            let sql = format!("ALTER TABLE {from} RENAME TO {to}");
            Statement::from_string(DbBackend::Sqlite, sql)
        };
        let (table, away) = ("used_registration_starts", "used_registration_starts_away");
        handler.sql_pool.execute(rename(table, away)).await.unwrap();
        let log = LogGuard::install_on_this_thread();
        let refused = handler.registration_claim(&request, &bob).await;
        let unmarked = DomainError::AuthenticationError(REGISTRATION_UNMARKED.to_owned());
        assert_eq!(
            (refused.map_err(|e| e.to_string()), failures(&log)),
            (Err(unmarked.to_string()), one_row(REGISTRATION_UNMARKED))
        );
        handler.sql_pool.execute(rename(away, table)).await.unwrap();
        handler.registration_claim(&request, &bob).await.unwrap();
    }

    async fn login_state(handler: &SqlOpaqueHandler, user: &str) -> String {
        let mut rng = rand::rngs::OsRng;
        let start = opaque::client::login::start_login("anything", &mut rng).unwrap();
        handler
            .login_start(login::ClientLoginStartRequest {
                username: UserId::new(user),
                login_start_request: start.message,
            })
            .await
            .unwrap()
            .server_data
    }

    #[tokio::test]
    #[serial]
    async fn test_each_kind_of_state_opens_only_as_its_own_kind_across_users() {
        let handler =
            SqlOpaqueHandler::new(generate_random_private_key(), get_initialized_db().await);
        insert_user(&handler, "bob", "bob00").await;
        insert_user(&handler, "carol", "carol00").await;
        let bob = UserId::new("bob");
        let mixed = registration::ClientRegistrationFinishRequest {
            server_data: login_state(&handler, "bob").await,
            ..client_registration(&handler, "carol", "carol-new-1").await
        };
        let before = handler
            .get_password_file_for_user(bob.clone())
            .await
            .unwrap();
        assert!(handler.registration_finish(mixed).await.is_err());
        assert_eq!(
            handler
                .get_password_file_for_user(bob.clone())
                .await
                .unwrap(),
            before
        );
        attempt_login(&handler, "bob", "bob00", None).await.unwrap();
    }

    #[tokio::test]
    #[serial]
    async fn test_each_kind_of_state_opens_only_as_its_own_kind_for_one_user() {
        let handler =
            SqlOpaqueHandler::new(generate_random_private_key(), get_initialized_db().await);
        insert_user(&handler, "bob", "bob00").await;
        let bob = UserId::new("bob");
        let before = handler
            .get_password_file_for_user(bob.clone())
            .await
            .unwrap();
        let mixed = registration::ClientRegistrationFinishRequest {
            server_data: login_state(&handler, "bob").await,
            ..client_registration(&handler, "bob", "bob-other-1").await
        };
        assert!(handler.registration_finish(mixed).await.is_err());
        assert_eq!(
            handler.get_password_file_for_user(bob).await.unwrap(),
            before
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_each_kind_of_state_opens_only_as_its_own_kind_for_a_long_name() {
        let handler =
            SqlOpaqueHandler::new(generate_random_private_key(), get_initialized_db().await);
        insert_user(&handler, "bob", "bob00").await;
        let long_name = format!("{}bob", "\u{1}".repeat(600));
        let mixed = registration::ClientRegistrationFinishRequest {
            server_data: login_state(&handler, &long_name).await,
            ..client_registration(&handler, "bob", "bob-other-1").await
        };
        assert!(handler.registration_finish(mixed).await.is_err());
    }

    #[tokio::test]
    #[serial]
    async fn test_each_kind_of_state_opens_only_as_its_own_kind_at_login() {
        let handler =
            SqlOpaqueHandler::new(generate_random_private_key(), get_initialized_db().await);
        insert_user(&handler, "bob", "bob00").await;
        let mut rng = rand::rngs::OsRng;
        let start = opaque::client::login::start_login("bob00", &mut rng).unwrap();
        let answer = handler
            .login_start(login::ClientLoginStartRequest {
                username: UserId::new("bob"),
                login_start_request: start.message,
            })
            .await
            .unwrap();
        let finish = opaque::client::login::finish_login(
            start.state,
            b"bob00",
            answer.credential_response,
            &mut rng,
        )
        .unwrap();
        let registration_state = client_registration(&handler, "bob", "bob-new-1")
            .await
            .server_data;
        assert!(
            handler
                .login_finish(login::ClientLoginFinishRequest {
                    server_data: registration_state,
                    credential_finalization: finish.message,
                    totp_code: None,
                    enrollment_proof: None,
                    session: None,
                })
                .await
                .is_err()
        );
    }

    fn server_key(handler: &SqlOpaqueHandler) -> Vec<u8> {
        handler
            .opaque_setup
            .keypair()
            .private()
            .serialize()
            .to_vec()
    }

    #[tokio::test]
    #[serial]
    async fn test_a_claim_opens_only_its_own_kind() {
        let handler =
            SqlOpaqueHandler::new(generate_random_private_key(), get_initialized_db().await);
        insert_user(&handler, "bob", "bob00").await;
        let mixed = registration::ClientRegistrationFinishRequest {
            server_data: login_state(&handler, "bob").await,
            ..client_registration(&handler, "bob", "bob-other-1").await
        };
        let claimed = handler.registration_claim(&mixed, &session("bob", 1)).await;
        assert!(claimed.is_err());
        assert_eq!(kept(&handler.sql_pool).await, 0);
    }

    #[tokio::test]
    #[serial]
    async fn test_no_sealed_kind_opens_as_another() {
        use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
        let handler =
            SqlOpaqueHandler::new(generate_random_private_key(), get_initialized_db().await);
        insert_user(&handler, "bob", "bob00").await;
        let key = server_key(&handler);
        let now = chrono::Utc::now().timestamp();
        let upload = client_registration(&handler, "bob", "bob-x-1")
            .await
            .registration_upload;
        let finish_with = |server_data: String| registration::ClientRegistrationFinishRequest {
            server_data,
            registration_upload: upload.clone(),
        };
        let long_name = format!("{}bob", "\u{1}".repeat(600));
        let login = login_state(&handler, &long_name).await;
        let by = session("bob", 1);
        assert!(
            handler
                .registration_claim(&finish_with(login.clone()), &by)
                .await
                .is_err()
        );
        let login_bytes = STANDARD.decode(&login).unwrap();
        assert!(
            lldap_mfa::open_enrollment(&key, &URL_SAFE_NO_PAD.encode(login_bytes), now).is_err()
        );

        let enrollment =
            lldap_mfa::seal_enrollment(&key, "bob", &lldap_mfa::generate_seed(), None, now)
                .unwrap();
        let enrollment_bytes = URL_SAFE_NO_PAD.decode(&enrollment).unwrap();
        assert!(
            handler
                .registration_claim(&finish_with(STANDARD.encode(&enrollment_bytes)), &by)
                .await
                .is_err()
        );
        let registration = client_registration(&handler, "bob", "bob-new-1")
            .await
            .server_data;
        let registration_bytes = STANDARD.decode(&registration).unwrap();
        assert!(
            lldap_mfa::open_enrollment(&key, &URL_SAFE_NO_PAD.encode(registration_bytes), now)
                .is_err()
        );

        // Proofs share the login and registration states' alphabet: only the key refuses them.
        for (label, sealed) in [
            ("a long name's login", &login),
            ("a registration", &registration),
        ] {
            let opened = lldap_mfa::open_enrollment_proof(&key, sealed, now);
            assert!(
                matches!(opened, Err(lldap_mfa::MfaError::Crypto(_))),
                "{label} state as a proof: {:?}",
                opened.err()
            );
        }
        let proof = lldap_mfa::seal_enrollment_proof(&key, "bob", now).unwrap();
        let refused = handler
            .registration_claim(&finish_with(proof.clone()), &by)
            .await
            .unwrap_err();
        assert!(
            matches!(refused, DomainError::UnknownCryptoError(_)),
            "{refused}"
        );
        let bob = UserId::new("bob");
        let before = handler
            .get_password_file_for_user(bob.clone())
            .await
            .unwrap();
        assert!(
            handler
                .registration_finish(finish_with(proof.clone()))
                .await
                .is_err()
        );
        assert_eq!(
            handler.get_password_file_for_user(bob).await.unwrap(),
            before
        );
        let mut rng = rand::rngs::OsRng;
        let start = opaque::client::login::start_login("bob00", &mut rng).unwrap();
        let answer = handler
            .login_start(login::ClientLoginStartRequest {
                username: UserId::new("bob"),
                login_start_request: start.message,
            })
            .await
            .unwrap();
        let finish = opaque::client::login::finish_login(
            start.state,
            b"bob00",
            answer.credential_response,
            &mut rng,
        )
        .unwrap();
        let refused = handler
            .login_finish(login::ClientLoginFinishRequest {
                server_data: proof,
                credential_finalization: finish.message,
                totp_code: None,
                enrollment_proof: None,
                session: None,
            })
            .await
            .unwrap_err();
        assert!(
            matches!(refused, DomainError::UnknownCryptoError(_)),
            "{refused}"
        );
    }

    fn sealed_at(handler: &SqlOpaqueHandler, user: &UserId, issued_at: i64, id: u8) -> String {
        let key = handler
            .get_orion_secret_key(REGISTRATION_STATE_KEY_INFO)
            .unwrap();
        let data = registration::ServerData {
            username: user.clone(),
            issued_at,
            start: Some(registration::StartBinding {
                id: [id; 16],
                by: session("bob", 1),
                envelope_key: None,
            }),
        };
        let sealed = orion::aead::seal(&key, &bincode::serialize(&data).unwrap()).unwrap();
        base64::engine::general_purpose::STANDARD.encode(sealed)
    }

    #[tokio::test]
    #[serial]
    async fn test_a_finish_must_follow_its_start_within_two_minutes() {
        let handler =
            SqlOpaqueHandler::new(generate_random_private_key(), get_initialized_db().await);
        insert_user(&handler, "bob", "bob00").await;
        let bob = UserId::new("bob");
        let now = AT as i64;
        let _clock = pin_clock(now);
        let request = client_registration(&handler, "bob", "bob-new-1").await;
        let issued = |age: i64, id: u8| registration::ClientRegistrationFinishRequest {
            server_data: sealed_at(&handler, &bob, now - age, id),
            ..request.clone()
        };
        let rows = [
            ("just started", 0, true),
            ("ninety seconds", 90, true),
            ("two minutes", 120, true),
            ("a second over two minutes", 121, false),
            ("nine minutes", 540, false),
            ("a day", 86_400, false),
        ];
        let log = LogGuard::install_on_this_thread();
        let mut marks = 0;
        for (id, (label, age, opens)) in (1u8..).zip(rows) {
            let got = handler
                .registration_claim(&issued(age, id), &session("bob", 1))
                .await;
            let too_long = DomainError::AuthenticationError(REGISTRATION_TOO_LONG.to_owned());
            let expected = if opens {
                Ok(bob.clone())
            } else {
                Err(too_long.to_string())
            };
            let row = one_row(REGISTRATION_TOO_LONG);
            marks += i64::from(opens);
            assert_eq!(
                (
                    got.map(|claim| claim.user).map_err(|e| e.to_string()),
                    failures(&log),
                    kept(&handler.sql_pool).await
                ),
                (expected, if opens { vec![] } else { row }, marks),
                "{label}"
            );
        }
        drop(log);
        attempt_login(&handler, "bob", "bob00", None).await.unwrap();
        handler.registration_finish(issued(0, 9)).await.unwrap();
        attempt_login(&handler, "bob", "bob-new-1", None)
            .await
            .unwrap();
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn test_a_policy_refusal_is_the_doors_one_row_with_no_success_row() {
        use lldap_domain_handlers::logging::{Protocol, RequestMeta, with_request};
        use lldap_test_utils::enforcement::EnforcementGuard;
        use lldap_test_utils::recording_log::LogGuard;
        let log = LogGuard::install_on_this_thread();
        let handler =
            SqlOpaqueHandler::new(generate_random_private_key(), get_initialized_db().await);
        insert_user(&handler, "e0door", "e0door00").await;
        let rows = [
            (
                "the LDAP bind",
                Door::LdapBind,
                LogKind::Bind,
                Protocol::Ldap,
            ),
            (
                "the simple login",
                Door::SimpleLogin,
                LogKind::Bind,
                Protocol::Http,
            ),
            (
                "the web login",
                Door::WebLogin,
                LogKind::Login,
                Protocol::Http,
            ),
        ];
        for (label, door, kind, protocol) in rows {
            for refused in [false, true] {
                let guard = match refused {
                    true => EnforcementGuard::refusing(&["e0door"], "login-hours"),
                    false => EnforcementGuard::allowing(&["e0door"], "login-hours"),
                };
                let meta = match protocol {
                    Protocol::Ldap => RequestMeta::ldap(None, None),
                    _ => RequestMeta::http(None, None),
                };
                let answered = with_request(meta, async {
                    match door {
                        Door::WebLogin => attempt_login(&handler, "e0door", "e0door00", None)
                            .await
                            .map(drop),
                        _ => handler
                            .bind(bind_request("e0door", "e0door00"))
                            .await
                            .map(drop),
                    }
                })
                .await;
                let rows: Vec<_> = log
                    .recorder()
                    .take_events()
                    .into_iter()
                    .filter(|e| e.actor.as_deref() == Some("e0door"))
                    .map(|e| (e.kind, e.success, e.protocol, e.detail))
                    .collect();
                let detail = refused.then(|| "policy: login-hours".to_owned());
                let doors: Vec<_> = guard.take_seen().into_iter().map(|s| s.door).collect();
                let judged = match (door, refused) {
                    (Door::WebLogin, false) => vec![door; 2],
                    _ => vec![door],
                };
                assert_eq!(
                    (answered.is_ok(), rows, doors),
                    (!refused, vec![(kind, !refused, protocol, detail)], judged),
                    "{label}, refused {refused}: the web login is judged when the sign-in starts \
                     and, admitted, again after the password"
                );
            }
        }
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn test_a_policy_read_that_fails_refuses_each_bind_door_with_its_one_row() {
        use lldap_domain_handlers::logging::{Protocol, RequestMeta, with_request};
        use lldap_test_utils::enforcement::EnforcementGuard;
        const DROPPED: &str = "DROP TABLE ou_policies";
        let log = LogGuard::install_on_this_thread();
        let rows = [
            (Door::LdapBind, LogKind::Bind, Protocol::Ldap),
            (Door::SimpleLogin, LogKind::Bind, Protocol::Http),
            (Door::WebLogin, LogKind::Login, Protocol::Http),
        ];
        for (door, kind, protocol) in rows {
            let handler =
                SqlOpaqueHandler::new(generate_random_private_key(), get_initialized_db().await);
            insert_user(&handler, "k2door", "k2door00").await;
            let pool = &handler.sql_pool;
            pool.execute_unprepared(DROPPED).await.unwrap();
            let _guard = EnforcementGuard::allowing(&["k2door"], "login-hours");
            let meta = match protocol {
                Protocol::Ldap => RequestMeta::ldap(None, None),
                _ => RequestMeta::http(None, None),
            };
            log.recorder().take_events();
            let answered = with_request(meta, async {
                match door {
                    Door::WebLogin => attempt_login(&handler, "k2door", "k2door00", None)
                        .await
                        .map(drop),
                    _ => handler
                        .bind(bind_request("k2door", "k2door00"))
                        .await
                        .map(drop),
                }
            })
            .await;
            let rows: Vec<_> = log
                .recorder()
                .take_events()
                .into_iter()
                .filter(|e| e.actor.as_deref() == Some("k2door"))
                .map(|e| (e.kind, e.success, e.protocol, e.detail))
                .collect();
            let row = (kind, false, protocol, Some("policy: unreadable".to_owned()));
            assert_eq!((answered.is_ok(), rows), (false, vec![row]), "{door:?}");
        }
    }

    #[tokio::test]
    #[serial]
    async fn test_a_degraded_realm_refusal_is_the_doors_one_row_with_no_success_row() {
        use lldap_domain_handlers::kerberos::{ADMINS_ONLY, LDAP_ADMINS_ONLY};
        use lldap_domain_handlers::logging::Protocol;
        use lldap_test_utils::enforcement::EnforcementGuard;
        use lldap_test_utils::recording_kerberos::{DEGRADED_CAUSE, DegradedGuard};
        let log = LogGuard::install_on_this_thread();
        let _guard = EnforcementGuard::none();
        let handler =
            SqlOpaqueHandler::new(generate_random_private_key(), get_initialized_db().await);
        insert_user(&handler, "e1down", "e1down00").await;
        insert_user(&handler, "e1admin", "e1admin00").await;
        let admins = insert_group(&handler, "lldap_admin").await;
        insert_membership(&handler, admins, "e1admin").await;
        let rows = [
            (
                "the LDAP bind",
                Door::LdapBind,
                LogKind::Bind,
                Protocol::Ldap,
            ),
            (
                "the simple login",
                Door::SimpleLogin,
                LogKind::Bind,
                Protocol::Http,
            ),
            (
                "the web login",
                Door::WebLogin,
                LogKind::Login,
                Protocol::Http,
            ),
        ];
        for directory_only in [false, true] {
            let _kdc = match directory_only {
                true => DegradedGuard::install_directory_only(),
                false => DegradedGuard::install(),
            };
            for (label, door, kind, protocol) in rows {
                for user in ["e1down", "e1admin"] {
                    let password = format!("{user}00");
                    let meta = match protocol {
                        Protocol::Ldap => RequestMeta::ldap(None, None),
                        _ => RequestMeta::http(None, None),
                    };
                    let answered = with_request(meta, async {
                        match door {
                            Door::WebLogin => attempt_login(&handler, user, &password, None)
                                .await
                                .map(drop),
                            _ => handler.bind(bind_request(user, &password)).await,
                        }
                    })
                    .await;
                    let rows: Vec<_> = log
                        .recorder()
                        .take_events()
                        .into_iter()
                        .filter(|e| e.actor.as_deref() == Some(user))
                        .map(|e| (e.kind, e.success, e.protocol, e.target, e.detail))
                        .collect();
                    let (answer, expected) = match (user, door) {
                        ("e1admin", _) => (Ok(()), (kind, true, protocol, None, None)),
                        _ if directory_only => (Ok(()), (kind, true, protocol, None, None)),
                        (_, Door::LdapBind) => (
                            Err(DEGRADED_CAUSE.to_owned()),
                            (
                                LogKind::AccessDenied,
                                false,
                                protocol,
                                Some(user.to_owned()),
                                Some(LDAP_ADMINS_ONLY.to_owned()),
                            ),
                        ),
                        _ => (
                            Err(DEGRADED_CAUSE.to_owned()),
                            (
                                LogKind::AccessDenied,
                                false,
                                protocol,
                                None,
                                Some(ADMINS_ONLY.to_owned()),
                            ),
                        ),
                    };
                    let answered = answered.map_err(|e| match e {
                        DomainError::KdcUnavailable(cause) => cause,
                        other => format!("not KdcUnavailable: {other}"),
                    });
                    assert_eq!(
                        (answered, rows),
                        (answer, vec![expected]),
                        "{label}, {user}, directory-only {directory_only}: one row, and no \
                         success row for a refusal"
                    );
                }
            }
        }
    }

    #[tokio::test]
    #[serial]
    async fn test_a_policy_refusal_after_a_right_totp_code_is_the_binds_one_row() {
        let _clock = pin_clock(AT as i64);
        use lldap_test_utils::enforcement::EnforcementGuard;
        let log = LogGuard::install_on_this_thread();
        let peer = "10.77.1.9";
        let handler = mfa_handler(MfaPolicy::Enrolled).await;
        insert_user(&handler, "e0totp", "e0totp00").await;
        let seed = enroll(&handler, "e0totp", AT).await;
        let (fresh, _) = fresh_and_wrong(&seed, AT);
        let guard = EnforcementGuard::refusing(&["e0totp"], "login-hours");
        let meta = RequestMeta::ldap(None, Some(peer.parse().unwrap()));
        let request = bind_request("e0totp", &format!("e0totp00:{fresh}"));
        let answered = with_request(meta, handler.bind(request)).await;
        let seen = guard.take_seen().into_iter();
        let seen: Vec<_> = seen.map(|s| (s.door, s.second_factor)).collect();
        let refused = (LogKind::Bind, false, Some("policy: login-hours".to_owned()));
        assert_eq!(
            (answered.is_ok(), auth_rows(&log, peer), seen),
            (false, vec![refused], vec![(Door::LdapBind, false)]),
            "judged once, without the factor, before the code is looked at: the refusal is the \
             one row and no success row"
        );
        drop(guard);
        let guard = EnforcementGuard::allowing(&["e0totp"], "login-hours");
        let meta = RequestMeta::ldap(None, Some(peer.parse().unwrap()));
        let request = bind_request("e0totp", &format!("e0totp00:{fresh}"));
        let answered = with_request(meta, handler.bind(request)).await;
        let seen = guard.take_seen().into_iter();
        let seen: Vec<_> = seen.map(|s| (s.door, s.second_factor)).collect();
        let rows = auth_rows(&log, peer).into_iter();
        let rows: Vec<_> = rows.map(|(kind, success, _)| (kind, success)).collect();
        assert_eq!(
            (answered.is_ok(), rows, seen),
            (
                true,
                vec![(LogKind::Bind, true)],
                vec![(Door::LdapBind, false), (Door::LdapBind, true)]
            ),
            "admitted, with the same code: judged without the factor, then again with it; one \
             success row"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_a_policy_refusal_at_the_web_login_leaves_its_totp_code_unspent() {
        let _clock = pin_clock(AT as i64);
        use lldap_test_utils::enforcement::EnforcementGuard;
        let log = LogGuard::install_on_this_thread();
        let peer = "10.77.1.10";
        let handler = mfa_handler(MfaPolicy::Enrolled).await;
        insert_user(&handler, "e0webcode", "e0webcode00").await;
        let seed = enroll(&handler, "e0webcode", AT).await;
        let (fresh, _) = fresh_and_wrong(&seed, AT);
        let finish = || {
            let meta = RequestMeta::http(Some(peer.parse().unwrap()), None);
            let login = attempt_login(&handler, "e0webcode", "e0webcode00", Some(fresh.as_str()));
            with_request(meta, login)
        };
        let guard = EnforcementGuard::refusing(&["e0webcode"], "login-hours");
        let answered = finish().await.map_err(|e| e.to_string());
        let seen = guard.take_seen().into_iter();
        let seen: Vec<_> = seen.map(|s| (s.door, s.second_factor)).collect();
        let refused = (answered, auth_rows(&log, peer), seen);
        drop(guard);
        let guard = EnforcementGuard::allowing(&["e0webcode"], "login-hours");
        let meta = RequestMeta::http(Some(peer.parse().unwrap()), None);
        let wrong = attempt_login(&handler, "e0webcode", "e0webcode-wrong", None);
        let wrong = with_request(meta, wrong).await.map_err(|e| e.to_string());
        guard.take_seen();
        let row = (
            LogKind::Login,
            false,
            Some("policy: login-hours".to_owned()),
        );
        assert!(wrong.is_err(), "{wrong:?}");
        assert_eq!(
            refused,
            (wrong, vec![row], vec![(Door::WebLogin, false)]),
            "judged once when the sign-in starts, without the factor, before the code is looked \
             at: a wrong password's answer and the refusal as the one row"
        );
        let answered = finish().await.map_err(|e| e.to_string());
        let seen = guard.take_seen().into_iter();
        let seen: Vec<_> = seen.map(|s| (s.door, s.second_factor)).collect();
        let rows = auth_rows(&log, peer).into_iter();
        let rows: Vec<_> = rows.map(|(kind, success, _)| (kind, success)).collect();
        let signed_in = LoginOutcome::Authenticated {
            user_id: UserId::new("e0webcode"),
            mfa_enrollment_pending: false,
        };
        assert_eq!(
            (answered, rows, seen),
            (
                Ok(signed_in),
                vec![(LogKind::Login, true)],
                vec![
                    (Door::WebLogin, false),
                    (Door::WebLogin, false),
                    (Door::WebLogin, true)
                ]
            ),
            "admitted with the same code: judged when the sign-in starts, then without and with \
             the factor; the code was never spent; one success row"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_a_bind_with_no_password_is_refused_first_whoever_the_name_is() {
        use crate::sql_backend_handler::tests::get_in_memory_db;
        use crate::sql_lockout_handler::tests as doors;
        use lldap_domain_handlers::lockout::{DURATION, THRESHOLD};
        let _clock = pin_clock(AT as i64);
        let directory = doors::handler().await.with_mfa_policy(MfaPolicy::Enrolled);
        let users = [
            ("e3on", "e3ou"),
            ("e3off", "e3ou"),
            ("e3lock", "e3lockou"),
            ("e3code", "e3ou"),
        ];
        for (user, ou) in users {
            doors::user_in(&directory, user, ou).await;
        }
        let disabled = insert_group(&directory, "lldap_disabled").await;
        insert_membership(&directory, disabled, "e3off").await;
        doors::policy_on(&directory, "e3lockou", &[(THRESHOLD, "2"), (DURATION, "0")]).await;
        for wrong in ["e3lock-wrong-1", "e3lock-wrong-2"] {
            doors::bind_as(&directory, "e3lock", wrong)
                .await
                .unwrap_err();
        }
        let seed = enroll(&directory, "e3code", AT).await;
        let (code, _) = fresh_and_wrong(&seed, AT);
        let no_tables =
            SqlBackendHandler::new(generate_random_private_key(), get_in_memory_db().await);
        let log = LogGuard::install_on_this_thread();
        let failed = |user: &str| format!(r#"Authentication error for user "{user}""#);
        type Case = (
            String,
            bool,
            &'static str,
            String,
            std::result::Result<(), String>,
            Option<(bool, Option<&'static str>)>,
        );
        let mut cases: Vec<Case> = Vec::new();
        let names = [
            ("a user", "e3on"),
            ("a disabled user", "e3off"),
            ("a locked user", "e3lock"),
            ("an enrolled user", "e3code"),
            ("an unknown name", "e3nobody"),
        ];
        for (who, user) in names {
            for (what, password) in [
                ("no password", String::new()),
                ("a code alone", format!(":{code}")),
            ] {
                for (place, bare) in [("", false), (", no tables", true)] {
                    cases.push((
                        format!("{who}, {what}{place}"),
                        bare,
                        user,
                        password.clone(),
                        Err(failed(user)),
                        Some((false, Some("no password given"))),
                    ));
                }
            }
        }
        let right = doors::RIGHT.to_owned();
        cases.extend([
            (
                "control: a user, the password".to_owned(),
                false,
                "e3on",
                right.clone(),
                Ok(()),
                Some((true, None)),
            ),
            (
                "control: a disabled user, the password".to_owned(),
                false,
                "e3off",
                right.clone(),
                Err(failed("e3off")),
                Some((false, Some("account disabled"))),
            ),
            (
                "control: a locked user, the password".to_owned(),
                false,
                "e3lock",
                right.clone(),
                Err(failed("e3lock")),
                Some((false, Some("locked out"))),
            ),
            (
                "control: an enrolled user, the password alone".to_owned(),
                false,
                "e3code",
                right.clone(),
                Err(r#"Authentication error TOTP code required for user "e3code""#.to_owned()),
                Some((false, Some("totp code required"))),
            ),
            (
                "control: an unknown name, a password".to_owned(),
                false,
                "e3nobody",
                right.clone(),
                Err(failed("e3nobody")),
                Some((false, Some("unknown user"))),
            ),
            (
                "control: a password, no tables".to_owned(),
                true,
                "e3on",
                right,
                Err("<database error>".to_owned()),
                None,
            ),
        ]);
        let (mut got, mut wanted) = (Vec::new(), Vec::new());
        for (label, bare, user, password, answer, row) in cases {
            let handler = if bare { &no_tables } else { &directory };
            let got_answer =
                handler
                    .bind(bind_request(user, &password))
                    .await
                    .map_err(|e| match e {
                        DomainError::DatabaseError(_) => "<database error>".to_owned(),
                        e => e.to_string(),
                    });
            let rows: Vec<_> = log
                .recorder()
                .take_events()
                .into_iter()
                .filter(|e| e.kind == LogKind::Bind)
                .map(|e| (e.success, e.actor, e.detail))
                .collect();
            let row = row.map(|(success, detail)| {
                (success, Some(user.to_owned()), detail.map(str::to_owned))
            });
            got.push((label.clone(), got_answer, rows));
            wanted.push((label, answer, Vec::from_iter(row)));
        }
        assert_eq!(got, wanted, "per row: the answer and its one row");
    }

    fn instant(text: &str) -> Timestamp {
        text.parse().unwrap()
    }

    /// One user under `mon 08:00-18:00` on its own OU, the real check judging only that user.
    async fn under_hours(
        user: &str,
    ) -> (
        SqlBackendHandler,
        lldap_test_utils::enforcement::EnforcementGuard,
    ) {
        use crate::sql_lockout_handler::tests as doors;
        use lldap_domain_handlers::enforcement::{ItemFlags, policy_cache};
        use lldap_domain_handlers::login_hours::LoginHoursCheck;
        use lldap_test_utils::enforcement::EnforcementGuard;
        let handler = doors::handler().await;
        doors::user_in(&handler, user, "h2ou").await;
        doors::policy_on(&handler, "h2ou", &[("login-hours", "mon 08:00-18:00")]).await;
        let check = std::sync::Arc::new(LoginHoursCheck::on(policy_cache()));
        let guard = EnforcementGuard::judging(&[user], check);
        policy_cache().set_item_flags(ItemFlags {
            login_hours: true,
            ..ItemFlags::default()
        });
        (handler, guard)
    }

    #[tokio::test]
    #[serial]
    async fn test_login_hours_refuse_outside_and_admit_inside_at_each_directory_door() {
        use crate::sql_lockout_handler::tests as doors;
        use lldap_domain_handlers::logging::Protocol;
        let log = LogGuard::install_on_this_thread();
        let (handler, guard) = under_hours("h2door").await;
        let rows = [
            (
                "the LDAP bind",
                Door::LdapBind,
                LogKind::Bind,
                Protocol::Ldap,
            ),
            (
                "the simple login",
                Door::SimpleLogin,
                LogKind::Bind,
                Protocol::Http,
            ),
            (
                "the web login",
                Door::WebLogin,
                LogKind::Login,
                Protocol::Http,
            ),
        ];
        let instants = [
            ("2026-11-16T07:59:59Z", false),
            ("2026-11-16T08:00:00Z", true),
            ("2026-11-16T17:59:59Z", true),
            ("2026-11-16T18:00:00Z", false),
        ];
        let outside = "policy: login-hours (outside login hours)";
        for (label, door, kind, protocol) in rows {
            for (at, inside) in instants {
                guard.pin_clock(instant(at));
                let meta = match protocol {
                    Protocol::Ldap => RequestMeta::ldap(None, None),
                    _ => RequestMeta::http(None, None),
                };
                let answered = with_request(meta, async {
                    match door {
                        Door::WebLogin => doors::web(&handler, "h2door", doors::RIGHT, None)
                            .await
                            .is_ok(),
                        _ => doors::bind(&handler, "h2door", doors::RIGHT).await,
                    }
                })
                .await;
                let rows: Vec<_> = log
                    .recorder()
                    .take_events()
                    .into_iter()
                    .filter(|e| e.actor.as_deref() == Some("h2door"))
                    .map(|e| (e.kind, e.success, e.detail))
                    .collect();
                let detail = (!inside).then(|| outside.to_owned());
                let seen = guard.take_seen().into_iter();
                let seen: Vec<_> = seen.map(|seen| (seen.door, seen.now)).collect();
                let judged = match (door, inside) {
                    (Door::WebLogin, true) => 2,
                    _ => 1,
                };
                assert_eq!(
                    (answered, rows, seen),
                    (
                        inside,
                        vec![(kind, inside, detail)],
                        vec![(door, instant(at)); judged]
                    ),
                    "{label} at {at}: judged at the pinned instant, the web login when the sign-in \
                     starts and, admitted, again after the password; one row"
                );
            }
        }
    }

    #[tokio::test]
    #[serial]
    async fn test_outside_the_hours_a_right_password_is_answered_as_a_wrong_one_byte_for_byte() {
        use crate::sql_lockout_handler::tests as doors;
        let (handler, guard) = under_hours("h2same").await;
        guard.pin_clock(instant("2026-11-16T18:00:00Z"));
        let text = |e: DomainError| e.to_string();
        let bind = async |password: &str| {
            let bound = doors::bind_as(&handler, "h2same", password).await;
            bound.map_err(text)
        };
        let both = async || (bind(doors::RIGHT).await, bind("Wrong-Pass-1").await);
        let ldap = with_request(RequestMeta::ldap(None, None), both()).await;
        let simple = with_request(RequestMeta::http(None, None), both()).await;
        let web = async |password: &str| {
            let signed_in = doors::web(&handler, "h2same", password, None);
            with_request(RequestMeta::http(None, None), signed_in).await
        };
        let right = web(doors::RIGHT).await;
        guard.pin_clock(instant("2026-11-16T12:00:00Z"));
        let wrong = web("Wrong-Pass-1").await;
        let invalid = Err(invalid_credentials(&UserId::new("h2same")).to_string());
        assert_eq!(
            (ldap, simple, right),
            (
                (invalid.clone(), invalid.clone()),
                (invalid.clone(), invalid),
                wrong
            ),
            "the LDAP bind and the simple login: the right password outside the hours, then a \
             wrong one; the web login: the right password outside the hours fails as a wrong one \
             inside them does"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_outside_the_hours_a_totp_users_right_password_gets_a_wrong_ones_answer_first() {
        use crate::sql_lockout_handler::tests as doors;
        use lldap_domain_handlers::enforcement::{ItemFlags, policy_cache};
        use lldap_domain_handlers::lockout::{DURATION, THRESHOLD};
        use lldap_domain_handlers::logging::Protocol;
        use lldap_test_utils::enforcement::EnforcementGuard;
        const USER: &str = "q31hours";
        let _clock = pin_clock(AT as i64);
        let log = LogGuard::install_on_this_thread();
        let handler = doors::handler().await.with_mfa_policy(MfaPolicy::Enrolled);
        doors::user_in(&handler, USER, "q31ou").await;
        let items = [
            ("login-hours", "mon 08:00-18:00"),
            (THRESHOLD, "5"),
            (DURATION, "0"),
        ];
        doors::policy_on(&handler, "q31ou", &items).await;
        enroll(&handler, USER, AT).await;
        let guard = EnforcementGuard::default_checks();
        policy_cache().set_item_flags(ItemFlags {
            login_hours: true,
            ..ItemFlags::default()
        });
        let user = UserId::new(USER);
        let answer = |e: DomainError| (std::mem::discriminant(&e), e.to_string());
        let bind = async |protocol: Protocol, password: &str| {
            let meta = match protocol {
                Protocol::Ldap => RequestMeta::ldap(None, None),
                _ => RequestMeta::http(None, None),
            };
            let bound = with_request(meta, doors::bind_as(&handler, USER, password)).await;
            bound.map_err(answer)
        };
        let web = async |password: &str| {
            let signed_in = with_request(RequestMeta::http(None, None), async {
                let started = doors::start(&handler, USER, password).await;
                match doors::finish_request(started, password, None) {
                    Some(request) => Some(handler.login_finish(request).await.map_err(answer)),
                    None => None,
                }
            });
            signed_in.await
        };
        let right = async || {
            let ldap = bind(Protocol::Ldap, doors::RIGHT).await;
            let simple = bind(Protocol::Http, doors::RIGHT).await;
            (ldap, simple, web(doors::RIGHT).await)
        };
        let rows = || -> Vec<(LogKind, bool, Option<String>)> {
            let events = log.recorder().take_events().into_iter();
            let ours = events.filter(|e| e.actor.as_deref() == Some(USER));
            ours.map(|e| (e.kind, e.success, e.detail)).collect()
        };
        let counted = || {
            handler
                .lockout
                .effective(&user)
                .map_or(0, |row| row.fail_count)
        };
        log.recorder().take_events();
        guard.pin_clock(instant("2026-11-16T12:00:00Z"));
        let inside = (right().await, rows());
        guard.pin_clock(instant("2026-11-16T18:00:00Z"));
        let outside = (right().await, rows(), counted());
        let wrong = (
            bind(Protocol::Ldap, "Wrong-Pass-1").await,
            bind(Protocol::Http, "Wrong-Pass-1").await,
            counted(),
        );
        guard.pin_clock(instant("2026-11-16T12:00:00Z"));
        let wrong_web = web("Wrong-Pass-1").await;
        let code = format!(r#"{TOTP_CODE_REQUIRED} for user "{USER}""#);
        let code = Err(answer(DomainError::AuthenticationError(code)));
        let invalid = Err(answer(invalid_credentials(&user)));
        let row = |kind, detail: &str| (kind, false, Some(detail.to_owned()));
        let (asked, refused) = (
            "totp code required",
            "policy: login-hours (outside login hours)",
        );
        assert_eq!(
            inside,
            (
                (code.clone(), code, Some(Ok(LoginOutcome::TotpRequired))),
                vec![
                    row(LogKind::Bind, asked),
                    row(LogKind::Bind, asked),
                    row(LogKind::Login, asked)
                ]
            ),
            "inside the hours: the code step, as today"
        );
        assert_eq!(
            outside,
            (
                (invalid.clone(), invalid.clone(), None),
                vec![
                    row(LogKind::Bind, refused),
                    row(LogKind::Bind, refused),
                    row(LogKind::Login, refused)
                ],
                0
            ),
            "outside, the right password and no code: a wrong password's answer, the refusal as \
             the one row, nothing counted; at the web login the sign-in cannot finish"
        );
        assert_eq!(
            (wrong, wrong_web),
            ((invalid.clone(), invalid, 2), None),
            "a wrong password at the LDAP bind and the simple login: the same answers, variant \
             and text, and the wrong binds count; at the web login inside the hours, a wrong \
             password cannot finish either"
        );
    }

    type Said = (std::mem::Discriminant<DomainError>, String);
    type Doors = (
        std::result::Result<(), Said>,
        std::result::Result<(), Said>,
        Option<std::result::Result<LoginOutcome, Said>>,
    );
    type Rows = Vec<(LogKind, bool, Option<String>)>;

    const HOURS: &str = "policy: login-hours (outside login hours)";

    fn said(e: DomainError) -> Said {
        (std::mem::discriminant(&e), e.to_string())
    }

    fn hours_on() -> lldap_domain_handlers::enforcement::ItemFlags {
        lldap_domain_handlers::enforcement::ItemFlags {
            login_hours: true,
            ..Default::default()
        }
    }

    /// A user on its own OU under `items` and a lockout of 5; the real checks, `flags` on.
    async fn q31_user(
        user: &str,
        policy: MfaPolicy,
        items: &[(&str, &str)],
        flags: lldap_domain_handlers::enforcement::ItemFlags,
    ) -> (
        SqlBackendHandler,
        lldap_test_utils::enforcement::EnforcementGuard,
    ) {
        use crate::sql_lockout_handler::tests as doors;
        use lldap_domain_handlers::enforcement::policy_cache;
        use lldap_domain_handlers::lockout::{DURATION, THRESHOLD};
        use lldap_test_utils::enforcement::EnforcementGuard;
        let handler = doors::handler().await.with_mfa_policy(policy);
        let ou = format!("{user}ou");
        doors::user_in(&handler, user, &ou).await;
        let mut items = items.to_vec();
        items.extend([(THRESHOLD, "5"), (DURATION, "0")]);
        doors::policy_on(&handler, &ou, &items).await;
        let guard = EnforcementGuard::default_checks();
        policy_cache().set_item_flags(flags);
        (handler, guard)
    }

    /// The right password, with `code` when given, at the LDAP bind, the simple login and the
    /// web login; `None` there when the sign-in cannot finish.
    async fn at_three_doors(handler: &SqlBackendHandler, user: &str, code: Option<&str>) -> Doors {
        use crate::sql_lockout_handler::tests as doors;
        let password = match code {
            Some(code) => format!("{}:{code}", doors::RIGHT),
            None => doors::RIGHT.to_owned(),
        };
        let ldap = doors::bind_as(handler, user, &password);
        let ldap = with_request(RequestMeta::ldap(None, None), ldap).await;
        let simple = doors::bind_as(handler, user, &password);
        let simple = with_request(RequestMeta::http(None, None), simple).await;
        let web = with_request(RequestMeta::http(None, None), async {
            let started = doors::start(handler, user, doors::RIGHT).await;
            match doors::finish_request(started, doors::RIGHT, code) {
                Some(request) => Some(handler.login_finish(request).await.map_err(said)),
                None => None,
            }
        });
        (ldap.map_err(said), simple.map_err(said), web.await)
    }

    fn q31_rows(log: &LogGuard, user: &str) -> Rows {
        let events = log.recorder().take_events().into_iter();
        let ours = events.filter(|e| e.actor.as_deref() == Some(user));
        ours.map(|e| (e.kind, e.success, e.detail)).collect()
    }

    fn three_rows(detail: &str) -> Rows {
        let kinds = [LogKind::Bind, LogKind::Bind, LogKind::Login];
        kinds
            .map(|kind| (kind, false, Some(detail.to_owned())))
            .to_vec()
    }

    fn counted(handler: &SqlBackendHandler, user: &str) -> u32 {
        let row = handler.lockout.effective(&UserId::new(user));
        row.map_or(0, |row| row.fail_count)
    }

    fn wrong_answers(user: &str) -> Doors {
        let invalid = Err(said(invalid_credentials(&UserId::new(user))));
        (invalid.clone(), invalid, None)
    }

    fn code_asked(user: &str) -> Doors {
        let asked = format!(r#"{TOTP_CODE_REQUIRED} for user "{user}""#);
        let asked = Err(said(DomainError::AuthenticationError(asked)));
        (asked.clone(), asked, Some(Ok(LoginOutcome::TotpRequired)))
    }

    #[tokio::test]
    #[serial]
    async fn test_an_inactive_totp_users_right_password_gets_a_wrong_ones_answer_first() {
        use lldap_domain_handlers::enforcement::{INACTIVITY_DAYS, ItemFlags, policy_cache};
        use lldap_domain_handlers::inactivity::Recording;
        use lldap_domain_handlers::instant::SignedDuration;
        const USER: &str = "q31idle";
        let _clock = pin_clock(AT as i64);
        let log = LogGuard::install_on_this_thread();
        let flags = ItemFlags {
            inactivity: true,
            ..ItemFlags::default()
        };
        let idle = [(INACTIVITY_DAYS, "1")];
        let (handler, guard) = q31_user(USER, MfaPolicy::Enrolled, &idle, flags).await;
        enroll(&handler, USER, AT).await;
        let since = Timestamp::now();
        policy_cache().set_recording(Recording::Since(since));
        q31_rows(&log, USER);
        guard.pin_clock(since + SignedDuration::from_hours(1));
        let active = (
            at_three_doors(&handler, USER, None).await,
            q31_rows(&log, USER),
        );
        guard.pin_clock(since + SignedDuration::from_hours(72));
        let doors = at_three_doors(&handler, USER, None).await;
        let inactive = (doors, q31_rows(&log, USER), counted(&handler, USER));
        assert_eq!(
            active,
            (code_asked(USER), three_rows("totp code required")),
            "an hour after the item turned on: the code step, as today"
        );
        assert_eq!(
            inactive,
            (
                wrong_answers(USER),
                three_rows("policy: inactivity-days (inactive)"),
                0
            ),
            "three days on, the right password and no code: a wrong password's answer, the \
             refusal as the one row, nothing counted"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_an_item_refuses_a_user_who_must_enrol_with_a_wrong_passwords_answer() {
        const USER: &str = "q31enrol";
        let log = LogGuard::install_on_this_thread();
        let hours = [("login-hours", "mon 08:00-18:00")];
        let (handler, guard) = q31_user(USER, MfaPolicy::Always, &hours, hours_on()).await;
        q31_rows(&log, USER);
        guard.pin_clock(instant("2026-11-16T12:00:00Z"));
        let inside = (
            at_three_doors(&handler, USER, None).await,
            q31_rows(&log, USER),
        );
        guard.pin_clock(instant("2026-11-16T18:00:00Z"));
        let doors = at_three_doors(&handler, USER, None).await;
        let outside = (doors, q31_rows(&log, USER), counted(&handler, USER));
        let enrol = format!(r#"{MFA_ENROLLMENT_REQUIRED} for user "{USER}""#);
        let enrol = Err(said(DomainError::AuthenticationError(enrol)));
        let pending = LoginOutcome::Authenticated {
            user_id: UserId::new(USER),
            mfa_enrollment_pending: true,
        };
        let detail = |text: &str| Some(text.to_owned());
        assert_eq!(
            inside,
            (
                (enrol.clone(), enrol, Some(Ok(pending))),
                vec![
                    (LogKind::Bind, false, detail("mfa enrollment required")),
                    (LogKind::Bind, false, detail("mfa enrollment required")),
                    (LogKind::Login, true, detail("mfa enrollment pending"))
                ]
            ),
            "inside the hours: enrolment required at the bind, admitted to enrol on the web"
        );
        assert_eq!(
            outside,
            (wrong_answers(USER), three_rows(HOURS), 0),
            "outside the hours: a wrong password's answer, never \"enrollment required\""
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_refused_between_the_two_steps_the_code_step_answers_as_a_wrong_password() {
        use crate::sql_lockout_handler::tests as doors;
        const USER: &str = "q31late";
        let _clock = pin_clock(AT as i64);
        let log = LogGuard::install_on_this_thread();
        let hours = [("login-hours", "mon 08:00-18:00")];
        let (handler, guard) = q31_user(USER, MfaPolicy::Enrolled, &hours, hours_on()).await;
        let seed = enroll(&handler, USER, AT).await;
        let (fresh, wrong) = fresh_and_wrong(&seed, AT);
        let bind = async |password: String| {
            let bound = doors::bind_as(&handler, USER, &password);
            with_request(RequestMeta::ldap(None, None), bound)
                .await
                .map_err(said)
        };
        let web = async |request: login::ClientLoginFinishRequest| {
            let finished = handler.login_finish(request);
            let finished = with_request(RequestMeta::http(None, None), finished).await;
            finished.map_err(said)
        };
        q31_rows(&log, USER);
        guard.pin_clock(instant("2026-11-16T17:59:59Z"));
        let started = doors::start(&handler, USER, doors::RIGHT).await;
        let kept = doors::finish_request(started, doors::RIGHT, None).unwrap();
        let with_code = |code: &str| login::ClientLoginFinishRequest {
            totp_code: Some(code.to_owned()),
            ..kept.clone()
        };
        let first = (
            bind(doors::RIGHT.to_owned()).await,
            web(kept.clone()).await,
            q31_rows(&log, USER),
        );
        guard.pin_clock(instant("2026-11-16T18:00:00Z"));
        let answers = (
            bind(format!("{}:{fresh}", doors::RIGHT)).await,
            bind(format!("{}:{wrong}", doors::RIGHT)).await,
            web(with_code(fresh.as_str())).await,
            web(with_code(wrong.as_str())).await,
        );
        let second = (answers, q31_rows(&log, USER), counted(&handler, USER));
        let (asked, _, _) = code_asked(USER);
        let (invalid, _, _) = wrong_answers(USER);
        let failed = Err(said(opaque::AuthenticationError::failed_proof().into()));
        let row = |kind, detail: &str| (kind, false, Some(detail.to_owned()));
        assert_eq!(
            first,
            (
                asked,
                Ok(LoginOutcome::TotpRequired),
                vec![
                    row(LogKind::Bind, "totp code required"),
                    row(LogKind::Login, "totp code required")
                ]
            ),
            "17:59:59, the right password: the code step"
        );
        assert_eq!(
            second,
            (
                (invalid.clone(), invalid, failed.clone(), failed),
                vec![
                    row(LogKind::Bind, HOURS),
                    row(LogKind::Bind, HOURS),
                    row(LogKind::Login, HOURS),
                    row(LogKind::Login, HOURS)
                ],
                0
            ),
            "18:00:00, the code step with a right code and with a wrong one: a wrong password's \
             answer, never a wrong code's; one refusal row each; nothing counted"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_an_attempt_the_items_refuse_never_reaches_the_degraded_realms_answer() {
        use crate::sql_lockout_handler::tests as doors;
        use lldap_test_utils::recording_kerberos::{DEGRADED_CAUSE, DegradedGuard};
        const USER: &str = "q31down";
        let _clock = pin_clock(AT as i64);
        let log = LogGuard::install_on_this_thread();
        let hours = [("login-hours", "mon 08:00-18:00")];
        let (handler, guard) = q31_user(USER, MfaPolicy::Enrolled, &hours, hours_on()).await;
        let seed = enroll(&handler, USER, AT).await;
        let (fresh, _) = fresh_and_wrong(&seed, AT);
        let _kdc = DegradedGuard::install();
        q31_rows(&log, USER);
        guard.pin_clock(instant("2026-11-16T18:00:00Z"));
        let outside = (
            at_three_doors(&handler, USER, None).await,
            at_three_doors(&handler, USER, Some(fresh.as_str())).await,
            q31_rows(&log, USER),
        );
        guard.pin_clock(instant("2026-11-16T12:00:00Z"));
        let password = format!("{}:{fresh}", doors::RIGHT);
        let inside = doors::bind_as(&handler, USER, &password);
        let inside = with_request(RequestMeta::ldap(None, None), inside).await;
        let mut refused = three_rows(HOURS);
        refused.extend(three_rows(HOURS));
        assert_eq!(
            outside,
            (wrong_answers(USER), wrong_answers(USER), refused),
            "outside the hours with the realm degraded, with no code and with a right one: a \
             wrong password's answer, never the outage's"
        );
        assert_eq!(
            inside.map_err(said),
            Err(said(DomainError::KdcUnavailable(DEGRADED_CAUSE.to_owned()))),
            "inside the hours the items admit, and the outage is told"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_a_totp_sign_in_writes_one_success_row_and_clears_the_count_once() {
        use crate::sql_lockout_handler::tests as doors;
        use lldap_domain_handlers::lockout::LockStore;
        const USER: &str = "q31once";
        let _clock = pin_clock(AT as i64);
        let log = LogGuard::install_on_this_thread();
        let hours = [("login-hours", "mon 08:00-18:00")];
        let (handler, guard) = q31_user(USER, MfaPolicy::Enrolled, &hours, hours_on()).await;
        let seed = enroll(&handler, USER, AT).await;
        let code = |at: u64| format_code(totp_code(&seed, at).unwrap());
        let noon = instant("2026-11-16T12:00:00Z");
        guard.pin_clock(noon);
        let wrong = doors::bind_as(&handler, USER, "Wrong-Pass-1");
        let wrong = with_request(RequestMeta::ldap(None, None), wrong).await;
        let failed = (wrong.is_err(), counted(&handler, USER));
        q31_rows(&log, USER);
        let stored = async || {
            let row = handler.read_lock(&UserId::new(USER)).await.unwrap();
            row.map(|row| (row.fail_count, row.last_success))
        };
        let successes = |rows: Rows| -> Vec<(LogKind, bool)> {
            rows.into_iter()
                .map(|(kind, success, _)| (kind, success))
                .collect()
        };
        let password = format!("{}:{}", doors::RIGHT, code(AT - TOTP_STEP_SECS));
        let bound = doors::bind_as(&handler, USER, &password);
        let bound = with_request(RequestMeta::ldap(None, None), bound).await;
        let bind = (
            bound.is_ok(),
            successes(q31_rows(&log, USER)),
            counted(&handler, USER),
            stored().await,
        );
        let late = code(AT + TOTP_STEP_SECS);
        let started = doors::start(&handler, USER, doors::RIGHT).await;
        let request = doors::finish_request(started, doors::RIGHT, Some(late.as_str())).unwrap();
        let finished = handler.login_finish(request);
        let finished = with_request(RequestMeta::http(None, None), finished).await;
        let web = (
            finished.is_ok(),
            successes(q31_rows(&log, USER)),
            counted(&handler, USER),
            stored().await,
        );
        let cleared = Some((0, Some(noon)));
        assert_eq!(failed, (true, 1), "a wrong password first: one count");
        assert_eq!(
            (bind, web),
            (
                (true, vec![(LogKind::Bind, true)], 0, cleared),
                (true, vec![(LogKind::Login, true)], 0, cleared)
            ),
            "judged without and with the factor, the web login also when the sign-in starts; \
             written once: one success row per sign-in, the count cleared at the sign-in's instant"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_an_unreadable_enable_mfa_value_answers_as_a_wrong_password_at_each_door() {
        use crate::sql_lockout_handler::tests as doors;
        const USER: &str = "q32lost";
        let log = LogGuard::install_on_this_thread();
        let handler = doors::handler().await;
        doors::user_in(&handler, USER, "q32ou").await;
        let started = doors::start(&handler, USER, doors::RIGHT).await;
        let right = doors::finish_request(started, doors::RIGHT, None).unwrap();
        let started = doors::start(&handler, USER, doors::RIGHT).await;
        let mut forged = doors::finish_request(started, doors::RIGHT, None).unwrap();
        forged.credential_finalization = right.credential_finalization.clone();
        handler.policy_cache.set_mfa_item_unknown();
        q31_rows(&log, USER);
        let bind = async |meta: RequestMeta, password: &str| {
            let bound = with_request(meta, doors::bind_as(&handler, USER, password)).await;
            bound.map_err(said)
        };
        let binds = [
            bind(RequestMeta::ldap(None, None), doors::RIGHT).await,
            bind(RequestMeta::ldap(None, None), "Wrong-Pass-1").await,
            bind(RequestMeta::http(None, None), doors::RIGHT).await,
            bind(RequestMeta::http(None, None), "Wrong-Pass-1").await,
        ];
        let bind_rows = q31_rows(&log, USER);
        let web = [
            handler.login_finish(right).await.map(drop).map_err(said),
            handler.login_finish(forged).await.map(drop).map_err(said),
        ];
        let web_rows = q31_rows(&log, USER);
        let invalid = Err(said(invalid_credentials(&UserId::new(USER))));
        let failed = Err(said(opaque::AuthenticationError::failed_proof().into()));
        let row = |kind, detail: &str| (kind, false, Some(detail.to_owned()));
        assert_eq!(
            (binds, bind_rows),
            (
                [invalid.clone(), invalid.clone(), invalid.clone(), invalid],
                vec![row(LogKind::Bind, "policy: unreadable"); 4]
            ),
            "the bind reads the value before the password: the right one and a wrong one get the \
             same answer and the same row, as before"
        );
        assert_eq!(
            (web, web_rows),
            (
                [failed.clone(), failed],
                vec![
                    row(LogKind::Login, "policy: unreadable"),
                    row(LogKind::Login, "invalid credentials")
                ]
            ),
            "the value unreadable only after the starts: at the web finish the right proof gets \
             the failed proof, as one that does not verify does; only the row tells them apart"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_a_sign_in_whose_read_never_answers_is_given_up_at_the_bound_at_each_door() {
        use crate::sql_lockout_handler::tests as doors;
        use lldap_domain_handlers::enforcement::gave_up;
        use lldap_domain_handlers::policies::POLICY_READ_WAIT;
        const USER: &str = "r1held";
        let log = LogGuard::install_on_this_thread();
        let handler = doors::handler().await;
        doors::user_in(&handler, USER, "r1ou").await;
        let started = doors::start(&handler, USER, doors::RIGHT).await;
        let finish = doors::finish_request(started, doors::RIGHT, None).unwrap();
        let mut rng = rand::rngs::OsRng;
        let begun = opaque::client::login::start_login(doors::RIGHT, &mut rng).unwrap();
        let start = login::ClientLoginStartRequest {
            username: UserId::new(USER),
            login_start_request: begun.message,
        };
        q31_rows(&log, USER);
        let bind = |meta| with_request(meta, doors::bind_as(&handler, USER, doors::RIGHT));
        let held = handler.sql_pool.begin().await.unwrap();
        let clock = std::time::Instant::now();
        let signing_in = async {
            tokio::join!(
                bind(RequestMeta::ldap(None, None)),
                bind(RequestMeta::http(None, None)),
                async { handler.login_start(start).await.map(drop) },
                async { handler.login_finish(finish).await.map(drop) },
            )
        };
        let answers = tokio::time::timeout(POLICY_READ_WAIT * 2, signing_in).await;
        let took = clock.elapsed();
        held.rollback().await.unwrap();
        let given_up = answers.map(|(ldap, simple, web_start, web_finish)| {
            [ldap, simple, web_start, web_finish].map(|answer| answer.is_err_and(|e| gave_up(&e)))
        });
        assert_eq!(
            (
                given_up.ok(),
                took >= POLICY_READ_WAIT,
                q31_rows(&log, USER)
            ),
            (Some([true; 4]), true, Vec::new()),
            "the LDAP bind, the simple login, the web start and the web finish, the one \
             connection held: each is given up at the bound as a read that failed, with no row"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_a_bind_with_no_stretch_permit_in_time_is_answered_busy_and_counts_nothing() {
        use crate::sql_lockout_handler::tests as doors;
        use lldap_domain_handlers::lockout::{DURATION, THRESHOLD};
        const USER: &str = "r1busy";
        let log = LogGuard::install_on_this_thread();
        let h = doors::handler().await;
        doors::user_in(&h, USER, "r1busyou").await;
        doors::policy_on(&h, "r1busyou", &[(THRESHOLD, "3"), (DURATION, "0")]).await;
        q31_rows(&log, USER);
        for (label, waiters) in [("no place to wait", 0), ("no permit within the wait", 1)] {
            let permits = std::sync::Arc::new(tokio::sync::Semaphore::new(0));
            let wait = std::time::Duration::from_millis(50);
            let gate = StretchGate::on(permits, waiters, wait);
            let h = h.clone().with_stretch_gate(Box::leak(Box::new(gate)));
            let answered = doors::bind_as(&h, USER, doors::RIGHT).await;
            let busy = DomainError::Busy(STRETCH_BUSY.to_owned());
            assert_eq!(
                (
                    answered.map_err(said),
                    q31_rows(&log, USER),
                    counted(&h, USER),
                    h.lockout.pending(&UserId::new(USER))
                ),
                (
                    Err(said(busy)),
                    vec![(LogKind::Bind, false, Some(BUSY_DETAIL.to_owned()))],
                    0,
                    false
                ),
                "{label}: the right password under a threshold; the one row, nothing counted"
            );
        }
    }

    #[tokio::test]
    #[serial]
    async fn test_a_stretch_that_began_and_did_not_complete_is_no_wrong_password() {
        use crate::sql_lockout_handler::tests as doors;
        use lldap_domain_handlers::lockout::{DURATION, THRESHOLD};
        const USER: &str = "r1stretch";
        let log = LogGuard::install_on_this_thread();
        let h = doors::handler().await;
        doors::user_in(&h, USER, "r1stretchou").await;
        doors::policy_on(&h, "r1stretchou", &[(THRESHOLD, "3"), (DURATION, "0")]).await;
        let user = UserId::new(USER);
        let lock = h.lock_state(&user).await.unwrap();
        type Answer = std::result::Result<Result<()>, StretchError>;
        type Row = (&'static str, Answer, Option<&'static str>, DomainError);
        let rows: [Row; 2] = [
            (
                "the work ran and refused the password",
                Ok(Err(invalid_credentials(&user))),
                Some("invalid credentials"),
                invalid_credentials(&user),
            ),
            (
                "the work began and did not complete",
                Err(StretchError::Failed),
                None,
                DomainError::InternalError(STRETCH_FAILED.to_owned()),
            ),
        ];
        q31_rows(&log, USER);
        for (label, answer, detail, error) in rows {
            let (unmatched, door, now) = (stretched(answer).unwrap(), Door::LdapBind, lock_clock());
            let refused = h.refuse_unmatched(&user, unmatched, lock.as_ref(), door, now);
            let refused = said(refused.await);
            let row = detail.map(|detail| (LogKind::Bind, false, Some(detail.to_owned())));
            assert_eq!(
                (refused, q31_rows(&log, USER), counted(&h, USER)),
                (said(error), row.into_iter().collect(), 1),
                "{label}: the one wrong password is the one count"
            );
        }
    }
}
