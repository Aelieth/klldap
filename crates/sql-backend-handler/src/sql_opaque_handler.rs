use crate::SqlBackendHandler;
use crate::sql_log_handler::UNKNOWN_USER_DETAIL;
use async_trait::async_trait;
use base64::Engine;
use lldap_auth::opaque;
use lldap_domain::types::{LoginOutcome, UserId};
use lldap_domain_handlers::handler::{BindRequest, LoginHandler, MfaBackendHandler};
use lldap_domain_handlers::kerberos::require_kdc_ready;
use lldap_domain_handlers::logging::{self, LogKind};
use lldap_domain_handlers::mfa::MfaRequirement;
use lldap_domain_model::{
    error::{DomainError, Result},
    model::{self, UserColumn},
};
use lldap_mfa::{MFA_ENROLLMENT_REQUIRED, TOTP_CODE_REQUIRED, split_totp_suffix};
use lldap_opaque_handler::{OpaqueHandler, login, registration};
use sea_orm::{ActiveModelTrait, ActiveValue, EntityTrait, QuerySelect};
use tracing::{debug, info, instrument, warn};

type SqlOpaqueHandler = SqlBackendHandler;

#[instrument(skip_all, level = "debug", err(level = "debug"), fields(username = %username.as_str()))]
fn passwords_match(
    password_file_bytes: &[u8],
    clear_password: &str,
    opaque_setup: &opaque::server::ServerSetup,
    username: &UserId,
) -> Result<()> {
    use opaque::{client, server};
    let mut rng = rand::rngs::OsRng;
    let client_login_start_result = client::login::start_login(clear_password, &mut rng)?;

    let password_file = server::ServerRegistration::deserialize(password_file_bytes)
        .map_err(opaque::AuthenticationError::ProtocolError)?;
    let server_login_start_result = server::login::start_login(
        &mut rng,
        opaque_setup,
        Some(password_file),
        client_login_start_result.message,
        username,
    )?;
    client::login::finish_login(
        client_login_start_result.state,
        clear_password.as_bytes(),
        server_login_start_result.message,
        &mut rng,
    )?;
    Ok(())
}

impl SqlBackendHandler {
    fn get_orion_secret_key(&self) -> Result<orion::aead::SecretKey> {
        Ok(orion::aead::SecretKey::from_slice(
            self.opaque_setup.keypair().private().serialize().as_ref(),
        )?)
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
        use lldap_domain_model::model::{groups, memberships};
        use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};

        let Some(group) = groups::Entity::find()
            .filter(groups::Column::DisplayName.eq(group_name))
            .one(&self.sql_pool)
            .await?
        else {
            return Ok(false);
        };
        Ok(memberships::Entity::find()
            .filter(memberships::Column::UserId.eq(user_id.as_str()))
            .filter(memberships::Column::GroupId.eq(group.group_id))
            .one(&self.sql_pool)
            .await?
            .is_some())
    }
}

fn invalid_credentials(user_id: &UserId) -> DomainError {
    DomainError::AuthenticationError(format!(r#"for user "{}""#, user_id))
}

#[async_trait]
impl LoginHandler for SqlBackendHandler {
    #[instrument(skip_all, level = "debug", err(level = "debug"))]
    async fn bind(&self, request: BindRequest) -> Result<()> {
        let BindRequest { name, password } = request;
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
        let requirement = self.mfa_requirement(&name).await?;
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
        debug!(r#"Login attempt for "{}""#, &name);
        if passwords_match(&password_hash, password, &self.opaque_setup, &name).is_err() {
            logging::record_as(
                Some(&name),
                LogKind::Bind,
                None,
                false,
                Some("invalid credentials"),
            );
            return Err(invalid_credentials(&name));
        }
        match (requirement, code) {
            (MfaRequirement::None, _) => {
                logging::record_as(Some(&name), LogKind::Bind, None, true, None);
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
                Err(DomainError::AuthenticationError(format!(
                    r#"{TOTP_CODE_REQUIRED} for user "{name}""#
                )))
            }
            (MfaRequirement::Totp, Some(code)) => match self.verify_user_totp(&name, code).await? {
                Ok(()) => {
                    logging::record_as(Some(&name), LogKind::Bind, None, true, Some("totp"));
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

        let mut rng = rand::rngs::OsRng;
        let start_response = opaque::server::login::start_login(
            &mut rng,
            &self.opaque_setup,
            maybe_password_file,
            request.login_start_request,
            &user_id,
        )?;
        let secret_key = self.get_orion_secret_key()?;
        let server_data = login::ServerData {
            username: user_id,
            server_login: start_response.state,
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
        } = request;
        let secret_key = self.get_orion_secret_key()?;
        let login::ServerData {
            username,
            server_login,
        } = bincode::deserialize(&orion::aead::open(
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

        if let Err(e) = opaque::server::login::finish_login(server_login, credential_finalization) {
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
        let authenticated = |detail: Option<&str>, mfa_enrollment_pending: bool| {
            info!(r#"OPAQUE login successful for "{}""#, &username);
            logging::record_as(Some(&username), LogKind::Login, None, true, detail);
            LoginOutcome::Authenticated {
                user_id: username.clone(),
                mfa_enrollment_pending,
            }
        };
        match self.mfa_requirement(&username).await? {
            MfaRequirement::None => Ok(authenticated(None, false)),
            MfaRequirement::Enrollment => Ok(authenticated(Some("mfa enrollment pending"), true)),
            MfaRequirement::Totp => match totp_code.as_deref() {
                // The challenge is a protocol step, not an outcome: no row.
                None => {
                    debug!(r#"OPAQUE login for "{}" awaits the TOTP code"#, &username);
                    Ok(LoginOutcome::TotpRequired)
                }
                Some(code) => match self.verify_user_totp(&username, code).await? {
                    Ok(()) => Ok(authenticated(Some("totp"), false)),
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
                        Err(rejection.into_error(&username))
                    }
                },
            },
        }
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
        let secret_key = self.get_orion_secret_key()?;
        let server_data = registration::ServerData {
            username: request.username,
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
        let secret_key = self.get_orion_secret_key()?;
        let registration::ServerData { username } = bincode::deserialize(&orion::aead::open(
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
}

#[cfg(test)]
mod tests {
    use self::opaque::server::generate_random_private_key;

    use super::*;
    use crate::sql_backend_handler::tests::{
        get_initialized_db, insert_group, insert_membership, insert_user, insert_user_no_password,
    };
    use lldap_opaque_handler::register_password;

    async fn attempt_login(
        opaque_handler: &SqlOpaqueHandler,
        username: &str,
        password: &str,
        totp_code: Option<&str>,
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
        opaque_handler
            .login_finish(ClientLoginFinishRequest {
                server_data: start_response.server_data,
                credential_finalization: login_finish.message,
                totp_code: totp_code.map(str::to_owned),
            })
            .await
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

    use lldap_domain_handlers::logging::{RequestMeta, with_request};
    use lldap_domain_handlers::mfa::{MFA_DISABLED_GROUP, MfaPolicy};
    use lldap_mfa::{TOTP_MAX_ATTEMPTS_PER_STEP, TOTP_STEP_SECS, format_code, totp_code};
    use lldap_test_utils::recording_log::LogGuard;
    use serial_test::serial;

    async fn mfa_handler(policy: MfaPolicy) -> SqlBackendHandler {
        SqlBackendHandler::new(generate_random_private_key(), get_initialized_db().await)
            .with_mfa_policy(policy)
    }

    // Enrolls through the engine; the current step's code is spent on the confirmation.
    async fn enroll(handler: &SqlBackendHandler, user: &str) -> Vec<u8> {
        let user_id = UserId::new(user);
        let start = handler.start_totp_enrollment(&user_id, None).await.unwrap();
        let seed = lldap_mfa::seed_from_base32(&start.secret_base32).unwrap();
        let now = chrono::Utc::now().timestamp() as u64;
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
    fn fresh_and_wrong(seed: &[u8]) -> (String, String) {
        let now = chrono::Utc::now().timestamp() as u64;
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
        let guard = LogGuard::install();
        let peer = "10.77.1.1";
        let handler = mfa_handler(MfaPolicy::Enrolled).await;
        insert_user(&handler, "bob", "bob00").await;
        let seed = enroll(&handler, "bob").await;
        let (fresh, wrong) = fresh_and_wrong(&seed);
        with_request(
            RequestMeta::ldap(None, Some(peer.parse().unwrap())),
            async {
                // The challenge: a verified password without a code is an error, not a row.
                let err = handler
                    .bind(bind_request("bob", "bob00"))
                    .await
                    .unwrap_err();
                assert!(err.to_string().contains(TOTP_CODE_REQUIRED), "{err}");
                let err = handler
                    .bind(bind_request("bob", &format!("bob00:{wrong}")))
                    .await
                    .unwrap_err();
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

                // Spend the next step too, or a boundary crossed mid-test refills the
                // allowance; reserving it first prunes the older steps' counts.
                let uuid = model::User::find_by_id(UserId::new("bob"))
                    .one(&handler.sql_pool)
                    .await
                    .unwrap()
                    .unwrap()
                    .uuid;
                let next_step = chrono::Utc::now().timestamp() as u64 + TOTP_STEP_SECS;
                for _ in 0..TOTP_MAX_ATTEMPTS_PER_STEP {
                    assert!(
                        handler
                            .failed_totp_attempts
                            .reserve(uuid.as_str(), next_step)
                    );
                }
                for _ in 0..TOTP_MAX_ATTEMPTS_PER_STEP {
                    let (_, wrong) = fresh_and_wrong(&seed);
                    let _ = handler
                        .bind(bind_request("bob", &format!("bob00:{wrong}")))
                        .await;
                }
                // The gate runs before verification: even a valid code is refused.
                let (fresh, _) = fresh_and_wrong(&seed);
                let err = handler
                    .bind(bind_request("bob", &format!("bob00:{fresh}")))
                    .await
                    .unwrap_err();
                assert!(err.to_string().contains("Too many TOTP attempts"), "{err}");
            },
        )
        .await;
        let row =
            |success, detail: Option<&str>| (LogKind::Bind, success, detail.map(str::to_owned));
        let mut expected = vec![
            row(false, Some("invalid totp")),
            row(false, Some("invalid credentials")),
            row(true, Some("totp")),
            row(false, Some("totp replayed")),
        ];
        expected.extend((0..TOTP_MAX_ATTEMPTS_PER_STEP).map(|_| row(false, Some("invalid totp"))));
        expected.push(row(false, Some("totp attempts exceeded")));
        assert_eq!(auth_rows(&guard, peer), expected);
    }

    #[tokio::test]
    async fn test_bind_exempt_unenrolled_and_disabled_policy() {
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
        enroll(&handler, "eve").await;
        handler.bind(bind_request("eve", "eve00")).await.unwrap();
        let handler = handler.with_mfa_policy(MfaPolicy::Enrolled);
        handler.bind(bind_request("eve", "eve00")).await.unwrap();
        handler.bind(bind_request("bob", "bob00")).await.unwrap();
        // Disabled never splits: a password that ends in :digits is the whole password.
        insert_user(&handler, "kim", "kim:123456").await;
        enroll(&handler, "kim").await;
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
        let guard = LogGuard::install();
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
                let seed = enroll(&handler, "bob").await;
                let (fresh, wrong) = fresh_and_wrong(&seed);
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
                row(false, Some("invalid totp")),
                row(true, Some("totp")),
            ]
        );
    }
}
