use crate::SqlBackendHandler;
use async_trait::async_trait;
use base64::Engine;
use lldap_auth::opaque;
use lldap_domain::types::UserId;
use lldap_domain_handlers::handler::{BindRequest, LoginHandler};
use lldap_domain_model::{
    error::{DomainError, Result},
    model::{self, UserColumn},
};
use lldap_opaque_handler::{OpaqueHandler, login, registration};
use sea_orm::{ActiveModelTrait, ActiveValue, EntityTrait, QuerySelect};
use tracing::{debug, info, instrument, warn};

type SqlOpaqueHandler = SqlBackendHandler;

#[instrument(skip_all, level = "debug", err, fields(username = %username.as_str()))]
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
        // Fetch the previously registered password file from the DB.
        Ok(model::User::find_by_id(user_id)
            .select_only()
            .column(UserColumn::PasswordHash)
            .into_tuple::<(Option<Vec<u8>>,)>()
            .one(&self.sql_pool)
            .await?
            .and_then(|u| u.0))
    }

    #[instrument(skip(self), level = "debug")]
    async fn is_user_disabled(&self, user_id: &UserId) -> Result<bool> {
        use lldap_domain_model::model::{groups, memberships};
        use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};

        // Find the lldap_disabled group (built-in, created at startup, protected from deletion).
        // Membership here both blocks login (below) *and* causes the LDAP layer to synthesize
        // loginDisabled=TRUE (see crates/ldap/src/attributes.rs). This provides the standards
        // info for SSSD (nds login policy, ldap_user_nds_login_disabled, access filters using
        // (!(loginDisabled=TRUE))). Removal from the group removes the attr.
        let group = groups::Entity::find()
            .filter(groups::Column::DisplayName.eq("lldap_disabled"))
            .one(&self.sql_pool)
            .await?;

        let Some(group) = group else {
            debug!("lldap_disabled group not found - treating as not disabled");
            return Ok(false);
        };

        // Check if user is member
        let membership = memberships::Entity::find()
            .filter(memberships::Column::UserId.eq(user_id.as_str()))
            .filter(memberships::Column::GroupId.eq(group.group_id))
            .one(&self.sql_pool)
            .await?;

        Ok(membership.is_some())
    }

    // A verified plaintext lets us transparently re-enroll a migrated 0.6.x password in
    // the current OPAQUE format. Writes only password_hash: the password didn't change,
    // so the modified dates must not move (unlike registration_finish).
    async fn reregister_password(&self, username: &UserId, password: &str) -> Result<()> {
        use opaque::{client, server};
        let mut rng = rand::rngs::OsRng;
        let registration_start =
            client::registration::start_registration(password.as_bytes(), &mut rng)?;
        let server_start = server::registration::start_registration(
            &self.opaque_setup,
            registration_start.message,
            username,
        )?;
        let registration_finish = client::registration::finish_registration(
            registration_start.state,
            password.as_bytes(),
            server_start.message,
            &mut rng,
        )?;
        let password_file = server::registration::get_password_file(registration_finish.message);
        let user_update = model::users::ActiveModel {
            user_id: ActiveValue::Set(username.clone()),
            password_hash: ActiveValue::Set(Some(password_file.serialize().to_vec())),
            ..Default::default()
        };
        user_update.update(&self.sql_pool).await?;
        Ok(())
    }
}

#[async_trait]
impl LoginHandler for SqlBackendHandler {
    #[instrument(skip_all, level = "debug", err)]
    async fn bind(&self, request: BindRequest) -> Result<()> {
        // Login interception for lldap_disabled (improved with explicit standards tie-in).
        // Corresponds to loginDisabled attr synthesis for SSSD.
        if self.is_user_disabled(&request.name).await? {
            warn!(
                r#"Login attempt denied for disabled user "{}""#,
                &request.name
            );
            return Err(DomainError::AuthenticationError(
                "- Account disabled. Contact administrator.".to_string(),
            ));
        }

        if let Some(password_hash) = self
            .get_password_file_for_user(request.name.clone())
            .await?
        {
            info!(r#"Login attempt for "{}""#, &request.name);
            if passwords_match(
                &password_hash,
                &request.password,
                &self.opaque_setup,
                &request.name,
            )
            .is_ok()
            {
                return Ok(());
            }
            if let Some(legacy) = &self.legacy_opaque_setup
                && legacy.verify_password(&password_hash, request.name.as_str(), &request.password)
            {
                info!(
                    r#"Verified "{}" against the legacy password format; re-enrolling"#,
                    &request.name
                );
                if let Err(e) = self
                    .reregister_password(&request.name, &request.password)
                    .await
                {
                    warn!(
                        r#"Failed to re-enroll "{}" in the current password format (will retry next login): {}"#,
                        &request.name, e
                    );
                }
                return Ok(());
            }
        } else {
            debug!(
                r#"User "{}" doesn't exist or has no password"#,
                &request.name
            );
        }
        Err(DomainError::AuthenticationError(format!(
            r#"for user "{}""#,
            request.name
        )))
    }
}

#[async_trait]
impl OpaqueHandler for SqlOpaqueHandler {
    #[instrument(skip_all, level = "debug", err)]
    async fn login_start(
        &self,
        request: login::ClientLoginStartRequest,
    ) -> Result<login::ServerLoginStartResponse> {
        let user_id = request.username;

        // Login interception for lldap_disabled (improved with explicit standards tie-in).
        // Corresponds to loginDisabled attr synthesis for SSSD.
        if self.is_user_disabled(&user_id).await? {
            warn!(
                r#"OPAQUE login attempt denied for disabled user "{}""#,
                &user_id
            );
            return Err(DomainError::AuthenticationError(
                "- Account disabled. Contact administrator.".to_string(),
            ));
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
        // Get the CredentialResponse for the user, or a dummy one if no user/no password.
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

    #[instrument(skip_all, level = "debug", err)]
    async fn login_finish(&self, request: login::ClientLoginFinishRequest) -> Result<UserId> {
        let secret_key = self.get_orion_secret_key()?;
        let login::ServerData {
            username,
            server_login,
        } = bincode::deserialize(&orion::aead::open(
            &secret_key,
            &base64::engine::general_purpose::STANDARD.decode(&request.server_data)?,
        )?)?;

        // Extra safety check (in case login_start check is ever bypassed)
        // Login interception for lldap_disabled (improved with explicit standards tie-in).
        // Corresponds to loginDisabled attr synthesis for SSSD.
        if self.is_user_disabled(&username).await? {
            warn!(
                r#"OPAQUE login_finish denied for disabled user "{}""#,
                &username
            );
            return Err(DomainError::AuthenticationError(
                "- Account disabled. Contact administrator.".to_string(),
            ));
        }

        // Finish the login: this makes sure the client data is correct, and gives a session key we
        // don't need.
        match opaque::server::login::finish_login(server_login, request.credential_finalization) {
            Ok(session) => {
                info!(r#"OPAQUE login successful for "{}""#, &username);
                let _ = session.session_key;
            }
            Err(e) => {
                warn!(r#"OPAQUE login attempt failed for "{}""#, &username);
                return Err(e.into());
            }
        };

        Ok(username)
    }

    #[instrument(skip_all, level = "debug", err)]
    async fn registration_start(
        &self,
        request: registration::ClientRegistrationStartRequest,
    ) -> Result<registration::ServerRegistrationStartResponse> {
        // Generate the server-side key and derive the data to send back.
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
    ) -> Result<()> {
        let secret_key = self.get_orion_secret_key()?;
        let registration::ServerData { username } = bincode::deserialize(&orion::aead::open(
            &secret_key,
            &base64::engine::general_purpose::STANDARD.decode(&request.server_data)?,
        )?)?;

        let password_file =
            opaque::server::registration::get_password_file(request.registration_upload);
        // Set the user password to the new password.
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
        Ok(())
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
    ) -> Result<()> {
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
            })
            .await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_opaque_flow() -> Result<()> {
        let sql_pool = get_initialized_db().await;
        crate::logging::init_for_tests();
        let backend_handler = SqlBackendHandler::new(generate_random_private_key(), sql_pool);
        insert_user_no_password(&backend_handler, "bob").await;
        insert_user_no_password(&backend_handler, "john").await;
        attempt_login(&backend_handler, "bob", "bob00")
            .await
            .unwrap_err();
        register_password(&backend_handler, UserId::new("bob"), b"bob00").await?;
        attempt_login(&backend_handler, "bob", "wrong_password")
            .await
            .unwrap_err();
        attempt_login(&backend_handler, "bob", "bob00").await?;
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
    async fn test_disabled_user_cannot_login() {
        // Basic test covering lldap_disabled login interception (the three check sites)
        // + the group-driven loginDisabled=TRUE synthesis contract (see attributes.rs).
        let sql_pool = get_initialized_db().await;
        let handler = SqlOpaqueHandler::new(generate_random_private_key(), sql_pool.clone());
        insert_user(&handler, "bob", "bob00").await;
        let disabled_gid = insert_group(&handler, "lldap_disabled").await;
        insert_membership(&handler, disabled_gid, "bob").await;

        // Bind (and OPAQUE paths) must reject.
        let err = handler
            .bind(BindRequest {
                name: UserId::new("bob"),
                password: "bob00".to_string(),
            })
            .await
            .unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("disabled") || msg.contains("Account disabled"),
            "unexpected error: {msg}"
        );
    }

    fn reassembled_setup(
        legacy: &lldap_opaque_legacy::LegacyServerSetup,
    ) -> opaque::server::ServerSetup {
        opaque::server::ServerSetup::deserialize(&legacy.reassemble_for_current()).unwrap()
    }

    async fn set_raw_password_hash(
        sql_pool: &crate::sql_tables::DbConnection,
        user: &str,
        hash: Vec<u8>,
    ) {
        let user_update = model::users::ActiveModel {
            user_id: ActiveValue::Set(UserId::new(user)),
            password_hash: ActiveValue::Set(Some(hash)),
            ..Default::default()
        };
        user_update.update(sql_pool).await.unwrap();
    }

    #[tokio::test]
    async fn test_bind_upgrades_legacy_password() {
        let sql_pool = get_initialized_db().await;
        let legacy = lldap_opaque_legacy::generate_random();
        let handler = SqlBackendHandler::new_with_legacy(
            reassembled_setup(&legacy),
            Some(legacy.clone()),
            sql_pool.clone(),
        );
        insert_user_no_password(&handler, "bob").await;
        let legacy_file = legacy.register_password("bob", "bob00").unwrap();
        set_raw_password_hash(&sql_pool, "bob", legacy_file.clone()).await;

        handler
            .bind(BindRequest {
                name: UserId::new("bob"),
                password: "wrong_password".to_string(),
            })
            .await
            .unwrap_err();
        handler
            .bind(BindRequest {
                name: UserId::new("bob"),
                password: "bob00".to_string(),
            })
            .await
            .unwrap();
        let new_hash = handler
            .get_password_file_for_user(UserId::new("bob"))
            .await
            .unwrap()
            .unwrap();
        assert_ne!(new_hash, legacy_file);

        // The re-enrolled hash verifies without any legacy support.
        let handler = SqlBackendHandler::new(reassembled_setup(&legacy), sql_pool.clone());
        handler
            .bind(BindRequest {
                name: UserId::new("bob"),
                password: "bob00".to_string(),
            })
            .await
            .unwrap();
        handler
            .bind(BindRequest {
                name: UserId::new("bob"),
                password: "wrong_password".to_string(),
            })
            .await
            .unwrap_err();
    }

    #[tokio::test]
    async fn test_bind_with_legacy_enabled_leaves_current_hashes_alone() {
        let sql_pool = get_initialized_db().await;
        let legacy = lldap_opaque_legacy::generate_random();
        let handler = SqlBackendHandler::new_with_legacy(
            reassembled_setup(&legacy),
            Some(legacy),
            sql_pool.clone(),
        );
        insert_user(&handler, "john", "john00").await;
        let before = handler
            .get_password_file_for_user(UserId::new("john"))
            .await
            .unwrap()
            .unwrap();
        handler
            .bind(BindRequest {
                name: UserId::new("john"),
                password: "john00".to_string(),
            })
            .await
            .unwrap();
        let after = handler
            .get_password_file_for_user(UserId::new("john"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(before, after);
        handler
            .bind(BindRequest {
                name: UserId::new("john"),
                password: "bad_password".to_string(),
            })
            .await
            .unwrap_err();
    }
}
