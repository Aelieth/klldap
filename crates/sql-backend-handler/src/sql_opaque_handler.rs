use crate::SqlBackendHandler;
use crate::sql_log_handler::UNKNOWN_USER_DETAIL;
use crate::sql_mfa_handler::{TotpRejection, now_unix};
use crate::sql_mfa_windows::with_proof;
use async_trait::async_trait;
use base64::Engine;
use chrono::NaiveDateTime;
use lldap_auth::opaque;
use lldap_domain::types::{GroupId, LoginOutcome, UserId};
use lldap_domain_handlers::enforcement::{Attempt, Door, admit};
use lldap_domain_handlers::handler::{BindRequest, LoginHandler};
use lldap_domain_handlers::kerberos::{
    LDAP_ADMINS_ONLY, kerberos_backend, refusal_while_degraded, require_kdc_ready,
};
use lldap_domain_handlers::lockout::{Step, lock_clock};
use lldap_domain_handlers::logging::{self, LogKind, NO_PASSWORD};
use lldap_domain_handlers::mfa::MfaRequirement;
use lldap_domain_model::{
    error::{DomainError, Result},
    model::{self, UserColumn},
};
use lldap_mfa::{MFA_ENROLLMENT_REQUIRED, TOTP_CODE_REQUIRED, split_totp_suffix, without_password};
use lldap_opaque_handler::{OpaqueHandler, STRETCH_FAILED, login, registration, stretch};
use sea_orm::{ActiveModelTrait, ActiveValue, ConnectionTrait, DbErr, EntityTrait, QuerySelect};
use tracing::{debug, info, instrument, warn};

type SqlOpaqueHandler = SqlBackendHandler;

#[instrument(skip_all, level = "debug", err(level = "debug"), fields(username = %username.as_str()))]
async fn passwords_match(
    password_file_bytes: &[u8],
    clear_password: &str,
    opaque_setup: &opaque::server::ServerSetup,
    username: &UserId,
) -> Result<()> {
    let password_file_bytes = password_file_bytes.to_vec();
    let clear_password = clear_password.to_owned();
    let opaque_setup = opaque_setup.clone();
    let username = username.clone();
    stretch(move || {
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
    })
    .await
    .map_err(|_| DomainError::InternalError(STRETCH_FAILED.to_string()))?
}

const LOGIN_STATE_KEY_INFO: &[u8] = b"lldap-opaque-login-state-v1";
const REGISTRATION_STATE_KEY_INFO: &[u8] = b"lldap-opaque-registration-state-v1";
/// A finish must follow its start within ten minutes.
const REGISTRATION_MAX_AGE: i64 = 600;
const REGISTRATION_TOO_LONG: &str = "the registration took too long; start again";

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

    fn registration_within_age(&self, server_data: &str, now: i64) -> Result<UserId> {
        let secret_key = self.get_orion_secret_key(REGISTRATION_STATE_KEY_INFO)?;
        let registration::ServerData {
            username,
            issued_at,
        } = decode_exact(&orion::aead::open(
            &secret_key,
            &base64::engine::general_purpose::STANDARD.decode(server_data)?,
        )?)?;
        if now - issued_at > REGISTRATION_MAX_AGE {
            let target = Some(username.as_str());
            logging::record_failure(LogKind::PasswordChange, target, REGISTRATION_TOO_LONG);
            return Err(DomainError::AuthenticationError(
                REGISTRATION_TOO_LONG.to_owned(),
            ));
        }
        Ok(username)
    }

    #[instrument(skip(self), level = "debug", err)]
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

impl SqlBackendHandler {
    /// After the credentials and before the door's row: a refusal is that row, and answers as
    /// the wrong-credentials error. The items are judged at the instant the lockout was.
    async fn admit_at(
        &self,
        user: &UserId,
        door: Door,
        second_factor: bool,
        now: NaiveDateTime,
    ) -> Result<()> {
        let attempt = Attempt {
            second_factor,
            now: now.and_utc(),
            ..Attempt::new(user, door)
        };
        admit(self, &attempt)
            .await
            .map_err(|_| invalid_credentials(user))
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
        if self.is_user_disabled(&name).await? {
            warn!(r#"Login attempt denied for disabled user "{}""#, &name);
            logging::record_as(
                Some(&name),
                LogKind::Bind,
                None,
                false,
                Some("account disabled"),
            );
            return Err(invalid_credentials(&name));
        }
        let requirement = self.door_requirement(&name, LogKind::Bind).await?;
        // An enrolled user binds with password:code; the password is checked first either way.
        let (password, code) = match requirement {
            MfaRequirement::Totp => match split_totp_suffix(&password) {
                Some((password, code)) => (password, Some(code)),
                None => (password.as_str(), None),
            },
            _ => (password.as_str(), None),
        };
        let Some(password_hash) = self.get_password_file_for_user(name.clone()).await? else {
            debug!(r#"User "{}" doesn't exist or has no password"#, &name);
            logging::record_as(
                Some(&name),
                LogKind::Bind,
                None,
                false,
                Some(UNKNOWN_USER_DETAIL),
            );
            return Err(invalid_credentials(&name));
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
        if passwords_match(&password_hash, password, &self.opaque_setup, &name)
            .await
            .is_err()
        {
            logging::record_as(
                Some(&name),
                LogKind::Bind,
                None,
                false,
                Some("invalid credentials"),
            );
            self.count_failure(lock.as_ref(), door, now).await;
            return Err(invalid_credentials(&name));
        }
        match (requirement, code) {
            (MfaRequirement::None, _) => {
                self.admit_at(&name, door, false, now).await?;
                self.admit_while_degraded(&name, door).await?;
                logging::record_as(Some(&name), LogKind::Bind, None, true, None);
                self.count_success(lock.as_ref(), door, now).await;
                Ok(())
            }
            (MfaRequirement::Enrollment, _) => {
                logging::record_as(
                    Some(&name),
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
                debug!(r#"Bind for "{}" carries no TOTP code"#, &name);
                logging::record_as(
                    Some(&name),
                    LogKind::Bind,
                    None,
                    false,
                    Some("totp code required"),
                );
                Err(DomainError::AuthenticationError(format!(
                    r#"{TOTP_CODE_REQUIRED} for user "{name}""#
                )))
            }
            (MfaRequirement::Totp, Some(code)) => match self.verify_user_totp(&name, code).await? {
                Ok(()) => {
                    self.admit_at(&name, door, true, now).await?;
                    self.admit_while_degraded(&name, door).await?;
                    let stored = self.note_proof(&name, now_unix()).await;
                    let detail = with_proof("totp", stored);
                    logging::record_as(Some(&name), LogKind::Bind, None, true, Some(&detail));
                    self.count_success(lock.as_ref(), door, now).await;
                    Ok(())
                }
                Err(rejection) => {
                    logging::record_as(
                        Some(&name),
                        LogKind::Bind,
                        None,
                        false,
                        Some(rejection.detail()),
                    );
                    if rejection == TotpRejection::Invalid {
                        self.count_failure(lock.as_ref(), door, now).await;
                    }
                    Err(rejection.into_error(&name))
                }
            },
        }
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

        if self.is_user_disabled(&user_id).await? {
            warn!(
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

        info!(r#"OPAQUE login attempt for "{}""#, &user_id);
        let maybe_password_file = self
            .get_password_file_for_user(user_id.clone())
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
        // A locked user is answered as a name with no password file is.
        let maybe_password_file = match lock {
            Some(lock) => {
                let id = rand::RngCore::next_u64(&mut rng);
                if lock.locked(now) || !self.lockout.start(&lock, id, now) {
                    self.refuse_locked(&user_id, LogKind::Login);
                    None
                } else {
                    overlay = Some(id);
                    maybe_password_file
                }
            }
            None => maybe_password_file,
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
        if self.is_user_disabled(&username).await? {
            warn!(
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
        let lock = self
            .lock_state(&username)
            .await
            .map_err(|e| Self::lock_unreadable(&username, LogKind::Login, e))?;
        // Judged before the proof's result shows: a locked user gets the failed proof's answer.
        if lock.as_ref().is_some_and(|lock| lock.locked(now)) {
            self.refuse_locked(&username, LogKind::Login);
            return Err(opaque::AuthenticationError::failed_proof().into());
        }
        if let Err(e) = verified {
            warn!(r#"OPAQUE login attempt failed for "{}""#, &username);
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
        let split = match foreign {
            Some(id) => self.lockout.split(&username, id, false),
            None => Step::default(),
        };
        let requirement = self.door_requirement(&username, LogKind::Login).await?;
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
                        warn!(
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
        self.admit_at(&username, Door::WebLogin, second_factor, now)
            .await?;
        self.admit_while_degraded(&username, Door::WebLogin).await?;
        let stored = !second_factor || self.note_proof(&username, now_unix()).await;
        let detail = detail.map(|detail| with_proof(detail, stored));
        info!(r#"OPAQUE login successful for "{}""#, &username);
        logging::record_as(
            Some(&username),
            LogKind::Login,
            None,
            true,
            detail.as_deref(),
        );
        self.count_success(lock.as_ref(), Door::WebLogin, now).await;
        if let Some(id) = foreign {
            let step = self.lockout.split(&username, id, true);
            self.lockout.carry(self, &username, step).await;
        }
        Ok(LoginOutcome::Authenticated {
            user_id: username,
            mfa_enrollment_pending,
        })
    }

    #[instrument(skip_all, level = "debug", err)]
    async fn registration_start(
        &self,
        request: registration::ClientRegistrationStartRequest,
    ) -> Result<registration::ServerRegistrationStartResponse> {
        let start_response = opaque::server::registration::start_registration(
            &self.opaque_setup,
            request.registration_start_request,
            &request.username,
        )?;
        let secret_key = self.get_orion_secret_key(REGISTRATION_STATE_KEY_INFO)?;
        let server_data = registration::ServerData {
            username: request.username,
            issued_at: chrono::Utc::now().timestamp(),
        };
        let encrypted_state = orion::aead::seal(&secret_key, &bincode::serialize(&server_data)?)?;
        Ok(registration::ServerRegistrationStartResponse {
            server_data: base64::engine::general_purpose::STANDARD.encode(encrypted_state),
            registration_response: start_response.message,
        })
    }

    #[instrument(skip_all, level = "debug", err)]
    async fn registration_finish(
        &self,
        request: registration::ClientRegistrationFinishRequest,
    ) -> Result<UserId> {
        require_kdc_ready()?;
        let secret_key = self.get_orion_secret_key(REGISTRATION_STATE_KEY_INFO)?;
        let registration::ServerData { username, .. } = decode_exact(&orion::aead::open(
            &secret_key,
            &base64::engine::general_purpose::STANDARD.decode(&request.server_data)?,
        )?)?;

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
        user_update.update(&self.sql_pool).await?;
        info!(r#"Successfully (re)set password for "{}""#, &username);
        logging::record(LogKind::PasswordChange, Some(username.as_str()), None);
        Ok(username)
    }

    #[instrument(skip_all, level = "debug", err)]
    async fn registration_user(
        &self,
        request: &registration::ClientRegistrationFinishRequest,
    ) -> Result<UserId> {
        self.registration_within_age(&request.server_data, chrono::Utc::now().timestamp())
    }
}

#[cfg(test)]
mod tests {
    use self::opaque::server::generate_random_private_key;

    use super::*;
    use crate::sql_backend_handler::tests::{
        get_initialized_db, insert_group, insert_membership, insert_user, insert_user_no_password,
    };
    use lldap_domain_handlers::handler::MfaBackendHandler;
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

    #[tokio::test]
    #[serial]
    async fn test_registration_user_opens_the_server_data_and_writes_nothing() {
        let handler =
            SqlOpaqueHandler::new(generate_random_private_key(), get_initialized_db().await);
        insert_user(&handler, "bob", "bob00").await;
        let bob = UserId::new("bob");
        let before = handler
            .get_password_file_for_user(bob.clone())
            .await
            .unwrap();
        let request = client_registration(&handler, "bob", "bob-new-1").await;
        assert_eq!(handler.registration_user(&request).await.unwrap(), bob);
        assert_eq!(
            handler
                .get_password_file_for_user(bob.clone())
                .await
                .unwrap(),
            before
        );
        attempt_login(&handler, "bob", "bob00", None).await.unwrap();

        let other =
            SqlOpaqueHandler::new(generate_random_private_key(), get_initialized_db().await);
        let mut garbled = request.clone();
        garbled.server_data = "bm90IHNlYWxlZA==".to_owned();
        for (label, handler, request) in [
            ("another server's key", &other, &request),
            ("not sealed", &handler, &garbled),
        ] {
            assert!(handler.registration_user(request).await.is_err(), "{label}");
        }
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
    async fn test_registration_user_opens_only_its_own_kind() {
        let handler =
            SqlOpaqueHandler::new(generate_random_private_key(), get_initialized_db().await);
        insert_user(&handler, "bob", "bob00").await;
        let mixed = registration::ClientRegistrationFinishRequest {
            server_data: login_state(&handler, "bob").await,
            ..client_registration(&handler, "bob", "bob-other-1").await
        };
        assert!(handler.registration_user(&mixed).await.is_err());
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
        assert!(
            handler
                .registration_user(&finish_with(login.clone()))
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
                .registration_user(&finish_with(STANDARD.encode(&enrollment_bytes)))
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
            .registration_user(&finish_with(proof.clone()))
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

    fn sealed_at(handler: &SqlOpaqueHandler, user: &UserId, issued_at: i64) -> String {
        let key = handler
            .get_orion_secret_key(REGISTRATION_STATE_KEY_INFO)
            .unwrap();
        let data = registration::ServerData {
            username: user.clone(),
            issued_at,
        };
        let sealed = orion::aead::seal(&key, &bincode::serialize(&data).unwrap()).unwrap();
        base64::engine::general_purpose::STANDARD.encode(sealed)
    }

    // A finish must follow its start within ten minutes, checked by KLLDAP's `registration_user`.
    #[tokio::test]
    #[serial]
    async fn test_a_finish_must_follow_its_start_within_ten_minutes() {
        let handler =
            SqlOpaqueHandler::new(generate_random_private_key(), get_initialized_db().await);
        insert_user(&handler, "bob", "bob00").await;
        let bob = UserId::new("bob");
        let now = chrono::Utc::now().timestamp();
        let request = client_registration(&handler, "bob", "bob-new-1").await;
        let issued = |age: i64| registration::ClientRegistrationFinishRequest {
            server_data: sealed_at(&handler, &bob, now - age),
            ..request.clone()
        };
        let rows = [
            ("just started", 0, true),
            ("nine minutes", 540, true),
            ("eleven minutes", 660, false),
            ("a day", 86_400, false),
        ];
        let log = LogGuard::install_on_this_thread();
        for (label, age, opens) in rows {
            let got = handler.registration_user(&issued(age)).await;
            let refused = got
                .as_ref()
                .err()
                .map(|e| e.to_string().contains(REGISTRATION_TOO_LONG));
            let failures: Vec<_> = log
                .recorder()
                .take_events()
                .into_iter()
                .filter(|e| !e.success)
                .map(|e| (e.kind, e.target, e.detail))
                .collect();
            let row = (
                LogKind::PasswordChange,
                Some("bob".to_owned()),
                Some(REGISTRATION_TOO_LONG.to_owned()),
            );
            assert_eq!(
                (got.is_ok(), refused, failures),
                (
                    opens,
                    (!opens).then_some(true),
                    (!opens).then_some(row).into_iter().collect::<Vec<_>>()
                ),
                "{label}"
            );
        }
        drop(log);
        attempt_login(&handler, "bob", "bob00", None).await.unwrap();
        handler.registration_finish(issued(0)).await.unwrap();
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
                assert_eq!(
                    (answered.is_ok(), rows, doors),
                    (
                        !refused,
                        vec![(kind, !refused, protocol, detail)],
                        vec![door]
                    ),
                    "{label}, refused {refused}"
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
        let _kdc = DegradedGuard::install();
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
                    "{label}, {user}: one row, and no success row for a refusal"
                );
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
            (false, vec![refused], vec![(Door::LdapBind, true)]),
            "the code was right; the refusal is the one row and no success row"
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
}
