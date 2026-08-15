use crate::{
    core::{
        error::{LdapError, LdapResult},
        utils::LdapInfo,
    },
    dn::get_user_id_from_distinguished_name,
    handler::make_extended_response,
};
use anyhow::Result;
use ldap3_proto::proto::{
    LdapBindCred, LdapBindRequest, LdapOp, LdapPasswordModifyRequest, LdapResultCode,
};
use lldap_access_control::{AccessControlledBackendHandler, UserReadableBackendHandler};
use lldap_auth::access_control::ValidationResults;
use lldap_domain::types::UserId;
use lldap_domain_handlers::handler::{BackendHandler, BindRequest, LoginHandler};
use lldap_domain_handlers::kerberos::kerberos_backend;
use lldap_opaque_handler::OpaqueHandler;
use tracing::{info, warn};

pub(crate) async fn do_bind(
    ldap_info: &LdapInfo,
    request: &LdapBindRequest,
    login_handler: &impl LoginHandler,
) -> LdapResult<UserId> {
    if request.dn.is_empty() {
        return Err(LdapError {
            code: LdapResultCode::InappropriateAuthentication,
            message: "Anonymous bind not allowed".to_string(),
        });
    }
    let user_id = match get_user_id_from_distinguished_name(
        &request.dn.to_ascii_lowercase(),
        &ldap_info.base_dn,
        &ldap_info.base_dn_str,
    ) {
        Ok(s) => s,
        Err(e) => {
            return Err(LdapError {
                code: LdapResultCode::NamingViolation,
                message: e.to_string(),
            });
        }
    };
    let password = if let LdapBindCred::Simple(password) = &request.cred {
        password
    } else {
        return Err(LdapError {
            code: LdapResultCode::UnwillingToPerform,
            message: "SASL not supported".to_string(),
        });
    };
    match login_handler
        .bind(BindRequest {
            name: user_id.clone(),
            password: password.clone(),
        })
        .await
    {
        Ok(()) => Ok(user_id),
        Err(_) => Err(LdapError {
            code: LdapResultCode::InvalidCredentials,
            message: "".to_string(),
        }),
    }
}

pub(crate) async fn change_password<B: OpaqueHandler>(
    backend_handler: &B,
    user: UserId,
    password: &[u8],
) -> Result<()> {
    use lldap_auth::*;
    let mut rng = rand::rngs::OsRng;
    let registration_start_request =
        opaque::client::registration::start_registration(password, &mut rng)?;
    let req = registration::ClientRegistrationStartRequest {
        username: user.clone(),
        registration_start_request: registration_start_request.message,
    };
    let registration_start_response = backend_handler.registration_start(req).await?;
    let registration_finish = opaque::client::registration::finish_registration(
        registration_start_request.state,
        password,
        registration_start_response.registration_response,
        &mut rng,
    )?;
    let req = registration::ClientRegistrationFinishRequest {
        server_data: registration_start_response.server_data,
        registration_upload: registration_finish.message,
    };
    backend_handler.registration_finish(req).await?;

    Ok(())
}

pub(crate) async fn do_password_modification<Handler: BackendHandler + OpaqueHandler>(
    credentials: &ValidationResults,
    ldap_info: &LdapInfo,
    backend_handler: &AccessControlledBackendHandler<Handler>,
    opaque_handler: &impl OpaqueHandler,
    request: &LdapPasswordModifyRequest,
) -> LdapResult<Vec<LdapOp>> {
    match (&request.user_identity, &request.new_password) {
        (Some(user), Some(password)) => {
            match get_user_id_from_distinguished_name(
                &user.to_ascii_lowercase(),
                &ldap_info.base_dn,
                &ldap_info.base_dn_str,
            ) {
                Ok(uid) => {
                    let user_is_admin = backend_handler
                        .get_readable_handler(credentials, uid.clone())
                        .expect("Unexpected permission error")
                        .get_user_groups(&uid)
                        .await
                        .map_err(|e| LdapError {
                            code: LdapResultCode::OperationsError,
                            message: format!(
                                "Internal error while requesting user's groups: {e:#?}"
                            ),
                        })?
                        .iter()
                        .any(|g| g.display_name == "lldap_admin".into());
                    if !credentials.can_change_password(&uid, user_is_admin) {
                        Err(LdapError {
                            code: LdapResultCode::InsufficentAccessRights,
                            message: format!(
                                r#"User `{}` cannot modify the password of user `{}`"#,
                                credentials.user, uid
                            ),
                        })
                    } else if let Err(e) =
                        change_password(opaque_handler, uid.clone(), password.as_bytes()).await
                    {
                        Err(LdapError {
                            code: LdapResultCode::Other,
                            message: format!("Error while changing the password: {e:#?}"),
                        })
                    } else {
                        // Kerberos sync for LDAP-native password changes (OS/PAM/ldapmodify support)
                        let readable = backend_handler
                            .get_readable_handler(credentials, uid.clone())
                            .expect("Unexpected permission error");
                        let user_details =
                            readable
                                .get_user_details(&uid)
                                .await
                                .map_err(|e| LdapError {
                                    code: LdapResultCode::OperationsError,
                                    message: format!("Failed to fetch user for Kerberos sync: {e}"),
                                })?;

                        let sync_enabled =
                            lldap_domain::types::kerberos_sync_enabled(&user_details.attributes);

                        if sync_enabled {
                            if let Err(e) =
                                kerberos_backend().sync_principal(uid.as_str(), password.as_str())
                            {
                                warn!(
                                    "Kerberos principal sync failed after LDAP password change: {}",
                                    e
                                );
                            } else {
                                info!(
                                    "Kerberos principal synced for user {} (LDAP password change)",
                                    uid
                                );
                            }

                            let inner = backend_handler.unsafe_get_handler();
                            if let Err(e) = inner
                                .ensure_kerberos_principal_consistency(&uid, true)
                                .await
                            {
                                warn!(
                                    "Failed to record Kerberos principal name for {}: {}",
                                    uid, e
                                );
                            }

                            // A first password for an already-disabled user would otherwise mint a live principal.
                            if let Ok(groups) = readable.get_user_groups(&uid).await
                                && groups
                                    .iter()
                                    .any(|g| g.display_name == "lldap_disabled".into())
                            {
                                kerberos_backend().reassert_disabled(uid.as_str());
                            }
                        }

                        Ok(vec![make_extended_response(
                            LdapResultCode::Success,
                            "".to_string(),
                        )])
                    }
                }
                Err(e) => Err(LdapError {
                    code: LdapResultCode::InvalidDNSyntax,
                    message: format!("Invalid username: {e}"),
                }),
            }
        }
        _ => Err(LdapError {
            code: LdapResultCode::ConstraintViolation,
            message: "Missing either user_id or password".to_string(),
        }),
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::handler::{
        LdapHandler,
        tests::{
            setup_bound_admin_handler, setup_bound_password_manager_handler,
            setup_bound_readonly_handler,
        },
    };
    use chrono::TimeZone;
    use ldap3_proto::proto::{LdapBindCred, LdapBindResponse, LdapOp, LdapResult as LdapResultOp};
    use lldap_domain::types::{GroupDetails, GroupId, UserId, Uuid};
    use lldap_test_utils::{MockTestBackendHandler, setup_default_ldap_mock};
    use mockall::predicate::eq;
    use pretty_assertions::assert_eq;
    use std::collections::HashSet;

    pub fn make_bind_result(code: LdapResultCode, message: &str) -> Vec<LdapOp> {
        vec![LdapOp::BindResponse(LdapBindResponse {
            res: LdapResultOp {
                code,
                matcheddn: "".to_string(),
                message: message.to_string(),
                referral: vec![],
            },
            saslcreds: None,
        })]
    }

    pub fn make_bind_success() -> Vec<LdapOp> {
        make_bind_result(LdapResultCode::Success, "")
    }

    // ========================================================================
    // BIND TESTS
    // ========================================================================

    #[tokio::test]
    async fn test_bind() {
        let mut mock = MockTestBackendHandler::new();
        setup_default_ldap_mock(&mut mock);

        mock.expect_bind()
            .with(eq(lldap_domain_handlers::handler::BindRequest {
                name: UserId::new("bob"),
                password: "pass".to_string(),
            }))
            .times(1)
            .return_once(|_| Ok(()));

        let mut ldap_handler = LdapHandler::new_for_tests(mock, "dc=example,dc=com");

        let request = LdapOp::BindRequest(LdapBindRequest {
            dn: "uid=bob,ou=people,dc=example,dc=com".to_string(),
            cred: LdapBindCred::Simple("pass".to_string()),
        });

        assert_eq!(
            ldap_handler.handle_ldap_message(request).await.unwrap(),
            make_bind_success()
        );
    }

    #[tokio::test]
    async fn test_admin_bind() {
        let mut mock = MockTestBackendHandler::new();
        setup_default_ldap_mock(&mut mock);

        mock.expect_bind()
            .with(eq(lldap_domain_handlers::handler::BindRequest {
                name: UserId::new("test"),
                password: "pass".to_string(),
            }))
            .times(1)
            .return_once(|_| Ok(()));

        let mut admin_groups = HashSet::new();
        admin_groups.insert(GroupDetails {
            group_id: GroupId(1),
            display_name: "lldap_admin".into(),
            creation_date: chrono::Utc.timestamp_opt(0, 0).unwrap().naive_utc(),
            uuid: Uuid::from_name_and_date(
                "test",
                &chrono::Utc.timestamp_opt(0, 0).unwrap().naive_utc(),
            ),
            attributes: vec![],
            modified_date: chrono::Utc.timestamp_opt(0, 0).unwrap().naive_utc(),
        });

        mock.expect_get_user_groups()
            .with(eq(UserId::new("test")))
            .return_once(move |_| Ok(admin_groups));

        let mut ldap_handler = LdapHandler::new_for_tests(mock, "dc=example,dc=com");

        let request = LdapBindRequest {
            dn: "uid=test,ou=people,dc=example,dc=com".to_string(),
            cred: LdapBindCred::Simple("pass".to_string()),
        };

        assert_eq!(ldap_handler.do_bind(&request).await, make_bind_success());
    }

    #[tokio::test]
    async fn test_bind_invalid_dn() {
        let mut mock = MockTestBackendHandler::new();
        setup_default_ldap_mock(&mut mock);

        // Valid cases reach bind(), so provide a successful expectation
        mock.expect_bind().returning(|_| Ok(()));

        let mut ldap_handler = LdapHandler::new_for_tests(mock, "dc=example,dc=com");

        // INVALID: wrong base DN → should be rejected with NamingViolation
        let request = LdapBindRequest {
            dn: "cn=bob,ou=people,dc=place,dc=com".to_string(),
            cred: LdapBindCred::Simple("pass".to_string()),
        };
        assert_eq!(
            ldap_handler.do_bind(&request).await,
            make_bind_result(
                LdapResultCode::NamingViolation,
                "Not a subtree of the base tree"
            ),
        );

        let request = LdapBindRequest {
            dn: "cn=bob,ou=people,dc=other,dc=com".to_string(),
            cred: LdapBindCred::Simple("pass".to_string()),
        };
        assert_eq!(
            ldap_handler.do_bind(&request).await,
            make_bind_result(
                LdapResultCode::NamingViolation,
                "Not a subtree of the base tree"
            ),
        );

        // VALID: correct base DN + uid= RDN type → Success (POSIX style)
        let request = LdapBindRequest {
            dn: "uid=bob,ou=people,dc=example,dc=com".to_string(),
            cred: LdapBindCred::Simple("pass".to_string()),
        };
        assert_eq!(ldap_handler.do_bind(&request).await, make_bind_success());

        // VALID: correct base DN + cn= RDN type for user in people OU → Success (dual resolution)
        // Both uid= and cn= must succeed and return the user "bob"
        let request = LdapBindRequest {
            dn: "cn=bob,ou=people,dc=example,dc=com".to_string(),
            cred: LdapBindCred::Simple("pass".to_string()),
        };
        assert_eq!(ldap_handler.do_bind(&request).await, make_bind_success());
    }

    // ========================================================================
    // PASSWORD CHANGE TESTS (Self-Service + Admin + Password Manager)
    // ========================================================================

    fn setup_password_change_expectations(mock: &mut MockTestBackendHandler, user: &str) {
        use lldap_auth::{opaque, registration};

        let mut rng = rand::rngs::OsRng;
        let registration_start_request =
            opaque::client::registration::start_registration("password".as_bytes(), &mut rng)
                .unwrap();

        let request = registration::ClientRegistrationStartRequest {
            username: user.into(),
            registration_start_request: registration_start_request.message,
        };

        let start_response = opaque::server::registration::start_registration(
            &opaque::server::ServerSetup::new(&mut rng),
            request.registration_start_request,
            &request.username,
        )
        .unwrap();

        mock.expect_registration_start()
            .times(1)
            .return_once(move |_| {
                Ok(registration::ServerRegistrationStartResponse {
                    server_data: "".to_string(),
                    registration_response: start_response.message,
                })
            });

        mock.expect_registration_finish()
            .times(1)
            .return_once(|_| Ok(()));
    }

    #[tokio::test]
    async fn test_self_service_password_change() {
        let mut mock = MockTestBackendHandler::new();
        setup_default_ldap_mock(&mut mock);
        setup_password_change_expectations(&mut mock, "bob");

        let mut ldap_handler = setup_bound_admin_handler(mock).await;

        let request = LdapOp::ExtendedRequest(
            LdapPasswordModifyRequest {
                user_identity: Some("uid=bob,ou=people,dc=example,dc=com".to_string()),
                old_password: None,
                new_password: Some("newpassword".to_string()),
            }
            .into(),
        );

        assert_eq!(
            ldap_handler.handle_ldap_message(request).await,
            Some(vec![make_extended_response(
                LdapResultCode::Success,
                "".to_string()
            )])
        );
    }

    #[tokio::test]
    async fn test_admin_changes_user_password() {
        let mut mock = MockTestBackendHandler::new();
        setup_default_ldap_mock(&mut mock);
        setup_password_change_expectations(&mut mock, "bob");

        let mut ldap_handler = setup_bound_admin_handler(mock).await;

        let request = LdapOp::ExtendedRequest(
            LdapPasswordModifyRequest {
                user_identity: Some("uid=bob,ou=people,dc=example,dc=com".to_string()),
                old_password: None,
                new_password: Some("newpassword".to_string()),
            }
            .into(),
        );

        assert_eq!(
            ldap_handler.handle_ldap_message(request).await,
            Some(vec![make_extended_response(
                LdapResultCode::Success,
                "".to_string()
            )])
        );
    }

    #[tokio::test]
    async fn test_password_manager_changes_user_password() {
        let mut mock = MockTestBackendHandler::new();
        setup_default_ldap_mock(&mut mock);
        setup_password_change_expectations(&mut mock, "bob");

        let mut ldap_handler = setup_bound_password_manager_handler(mock).await;

        let request = LdapOp::ExtendedRequest(
            LdapPasswordModifyRequest {
                user_identity: Some("uid=bob,ou=people,dc=example,dc=com".to_string()),
                old_password: None,
                new_password: Some("newpassword".to_string()),
            }
            .into(),
        );

        assert_eq!(
            ldap_handler.handle_ldap_message(request).await,
            Some(vec![make_extended_response(
                LdapResultCode::Success,
                "".to_string()
            )])
        );
    }

    #[tokio::test]
    async fn test_password_change_unauthorized_readonly() {
        let mut mock = MockTestBackendHandler::new();
        setup_default_ldap_mock(&mut mock);

        let mut ldap_handler = setup_bound_readonly_handler(mock).await;

        let request = LdapOp::ExtendedRequest(
            LdapPasswordModifyRequest {
                user_identity: Some("uid=bob,ou=people,dc=example,dc=com".to_string()),
                old_password: Some("pass".to_string()),
                new_password: Some("password".to_string()),
            }
            .into(),
        );

        assert_eq!(
            ldap_handler.handle_ldap_message(request).await,
            Some(vec![make_extended_response(
                LdapResultCode::InsufficentAccessRights,
                "User `test` cannot modify the password of user `bob`".to_string(),
            )])
        );
    }

    #[tokio::test]
    async fn test_password_change_errors() {
        let mut mock = MockTestBackendHandler::new();
        setup_default_ldap_mock(&mut mock);

        let mut ldap_handler = setup_bound_admin_handler(mock).await;

        let request = LdapOp::ExtendedRequest(
            LdapPasswordModifyRequest {
                user_identity: None,
                old_password: None,
                new_password: None,
            }
            .into(),
        );
        assert_eq!(
            ldap_handler.handle_ldap_message(request).await,
            Some(vec![make_extended_response(
                LdapResultCode::ConstraintViolation,
                "Missing either user_id or password".to_string(),
            )])
        );
    }
}
