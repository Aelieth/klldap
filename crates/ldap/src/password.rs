use crate::{
    core::{
        error::{LdapError, LdapResult},
        utils::LdapInfo,
    },
    dn::get_user_id_from_distinguished_name,
    handler::make_extended_response,
};
use ldap3_proto::proto::{
    LdapBindCred, LdapBindRequest, LdapOp, LdapPasswordModifyRequest, LdapResultCode,
};
use lldap_access_control::{AccessControlledBackendHandler, UserReadableBackendHandler};
use lldap_auth::access_control::ValidationResults;
use lldap_domain::types::{UserId, kerberos_sync_enabled};
use lldap_domain_handlers::handler::{BackendHandler, BindRequest, LoginHandler};
use lldap_domain_handlers::password::{
    PasswordChangeError, PasswordSync, change_password_everywhere, min_length_of,
};
use lldap_domain_handlers::warn_limited;
use lldap_domain_model::error::DomainError;
use lldap_mfa::{MFA_ENROLLMENT_REQUIRED, TOTP_SEPARATOR, TotpFailure, totp_failure};
use lldap_opaque_handler::OpaqueHandler;
use tracing::{info, warn};
use zeroize::Zeroizing;

pub(crate) fn parse_bind_request<'a>(
    ldap_info: &LdapInfo,
    request: &'a LdapBindRequest,
) -> LdapResult<(UserId, &'a str)> {
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
    let LdapBindCred::Simple(password) = &request.cred else {
        return Err(LdapError {
            code: LdapResultCode::UnwillingToPerform,
            message: "SASL not supported".to_string(),
        });
    };
    Ok((user_id, password))
}

pub(crate) async fn bind(
    login_handler: &impl LoginHandler,
    user_id: UserId,
    password: &str,
) -> LdapResult<UserId> {
    match login_handler
        .bind(BindRequest {
            name: user_id.clone(),
            password: password.to_owned(),
        })
        .await
    {
        Ok(()) => Ok(user_id),
        Err(DomainError::KdcUnavailable(cause)) => Err(LdapError {
            code: LdapResultCode::Unavailable,
            message: cause,
        }),
        Err(e) => {
            say_fault(&e);
            Err(LdapError {
                code: LdapResultCode::InvalidCredentials,
                message: totp_diagnostic(&e.to_string()),
            })
        }
    }
}

/// A refusal has its row; an error of the server's own is said here, for the answer hides it.
fn say_fault(e: &DomainError) {
    let refused = matches!(
        e,
        DomainError::AuthenticationError(_) | DomainError::AuthenticationProtocolError(_)
    );
    if !refused {
        warn_limited!("A bind was refused on an error of the server's own: {e}");
    }
}

// The login handler emits these markers only after the password verified, so naming the
// second factor here reveals nothing to a password guess.
fn totp_diagnostic(message: &str) -> String {
    match totp_failure(message) {
        TotpFailure::CodeRequired => {
            format!("TOTP code required: append '{TOTP_SEPARATOR}' and the code")
        }
        TotpFailure::EnrollmentRequired => MFA_ENROLLMENT_REQUIRED.to_owned(),
        TotpFailure::Replayed => "TOTP code already used, wait for the next one".to_owned(),
        TotpFailure::TooManyAttempts => "Too many TOTP attempts, wait for the next one".to_owned(),
        TotpFailure::Other => String::new(),
    }
}

pub(crate) fn password_change_error(e: PasswordChangeError) -> LdapError {
    let code = match &e {
        PasswordChangeError::TooShort(_)
        | PasswordChangeError::HasNul
        | PasswordChangeError::PolicyUnreadable
        | PasswordChangeError::Refused(_)
        | PasswordChangeError::SyncChanged
        | PasswordChangeError::KerberosDisabled(_) => LdapResultCode::UnwillingToPerform,
        PasswordChangeError::InProgress => LdapResultCode::Busy,
        PasswordChangeError::Unavailable(_) => LdapResultCode::Unavailable,
        PasswordChangeError::NoSuchUser => LdapResultCode::NoSuchObject,
        PasswordChangeError::Failed(_) | PasswordChangeError::Unknown => LdapResultCode::Other,
    };
    LdapError {
        code,
        message: e.to_string(),
    }
}

/// Changes the directory password and, with kerberossync on, the KDC's keys in the same
/// transaction, which also sets the principal's status from `lldap_disabled`.
pub(crate) async fn change_password<Handler: BackendHandler + OpaqueHandler>(
    backend_handler: &AccessControlledBackendHandler<Handler>,
    readable_handler: &impl UserReadableBackendHandler,
    opaque_handler: &impl OpaqueHandler,
    user_id: &UserId,
    password: &str,
) -> LdapResult<()> {
    let user = readable_handler
        .get_user_details(user_id)
        .await
        .map_err(|e| LdapError {
            code: LdapResultCode::Other,
            message: format!("Failed to fetch user for Kerberos sync check: {e}"),
        })?;
    let sync_enabled = kerberos_sync_enabled(&user.attributes);
    let sync = PasswordSync::of(sync_enabled);
    let changed = match min_length_of(backend_handler.unsafe_get_handler(), user_id).await {
        Ok(min) => change_password_everywhere(opaque_handler, user_id, password, sync, min).await,
        Err(e) => Err(e),
    };
    if let Err(e) = changed {
        warn!("LDAP password change for {user_id} failed: {e}");
        return Err(password_change_error(e));
    }
    if sync_enabled {
        info!("Kerberos principal synced for user {user_id} (LDAP password change)");
    } else if let Err(e) = backend_handler
        .ensure_kerberos_principal_consistency(user_id, false)
        .await
    {
        warn!("Failed to clear the Kerberos principal name for {user_id}: {e}");
    }
    Ok(())
}

/// A PasswordModify request whose passwords are wiped when it is dropped.
pub(crate) struct PasswordModify {
    user_identity: Option<String>,
    new_password: Option<Zeroizing<String>>,
    _old_password: Option<Zeroizing<String>>,
}

impl From<LdapPasswordModifyRequest> for PasswordModify {
    fn from(request: LdapPasswordModifyRequest) -> Self {
        Self {
            user_identity: request.user_identity,
            new_password: request.new_password.map(Zeroizing::new),
            _old_password: request.old_password.map(Zeroizing::new),
        }
    }
}

pub(crate) async fn do_password_modification<Handler: BackendHandler + OpaqueHandler>(
    credentials: &ValidationResults,
    ldap_info: &LdapInfo,
    backend_handler: &AccessControlledBackendHandler<Handler>,
    opaque_handler: &impl OpaqueHandler,
    request: PasswordModify,
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
                        .ok_or_else(|| LdapError {
                            code: LdapResultCode::InsufficentAccessRights,
                            message: format!(
                                "User `{}` cannot modify user `{}`",
                                credentials.user.as_str(),
                                uid.as_str()
                            ),
                        })?
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
                    } else {
                        let readable = backend_handler
                            .get_readable_handler(credentials, uid.clone())
                            .expect("Unexpected permission error");
                        change_password(backend_handler, readable, opaque_handler, &uid, password)
                            .await?;
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
            setup_bound_admin_handler, setup_bound_handler_with_group, setup_bound_readonly_handler,
        },
    };
    use chrono::TimeZone;
    use ldap3_proto::proto::{
        LdapBindCred, LdapBindResponse, LdapExtendedRequest, LdapOp, LdapResult as LdapResultOp,
    };
    use lldap_domain::types::{GroupDetails, GroupId, UserId, Uuid};
    use lldap_domain_handlers::kerberos::{CommitError, SYNC_CHANGED, closed_to_writes};
    use lldap_domain_handlers::password::{
        PASSWORD_CHANGE_IN_PROGRESS, RESULT_UNKNOWN, realm_not_ready,
    };
    use lldap_test_utils::recording_kerberos::{
        DEGRADED_CAUSE, DegradedGuard, KerberosOp, RecordingGuard,
    };
    use lldap_test_utils::{MockTestBackendHandler, setup_default_ldap_mock};
    use mockall::predicate::eq;
    use pretty_assertions::assert_eq;
    use serial_test::serial;
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

    #[tokio::test]
    async fn test_bind_totp_diagnostics() {
        use lldap_mfa::{TOTP_CODE_ALREADY_USED, TOTP_CODE_REQUIRED, TOTP_TOO_MANY_ATTEMPTS};
        for (error, message) in [
            (
                format!("{TOTP_CODE_REQUIRED} for user \"bob\""),
                "TOTP code required: append ':' and the code".to_owned(),
            ),
            (
                format!("{MFA_ENROLLMENT_REQUIRED} for user \"bob\""),
                MFA_ENROLLMENT_REQUIRED.to_owned(),
            ),
            (
                format!("{TOTP_CODE_ALREADY_USED} for bob"),
                "TOTP code already used, wait for the next one".to_owned(),
            ),
            (
                format!("{TOTP_TOO_MANY_ATTEMPTS} for bob"),
                "Too many TOTP attempts, wait for the next one".to_owned(),
            ),
            ("Invalid TOTP code for bob".to_owned(), String::new()),
            ("for user \"bob\"".to_owned(), String::new()),
        ] {
            let mut mock = MockTestBackendHandler::new();
            setup_default_ldap_mock(&mut mock);
            mock.expect_bind().return_once(move |_| {
                Err(lldap_domain_model::error::DomainError::AuthenticationError(
                    error,
                ))
            });
            let mut ldap_handler = LdapHandler::new_for_tests(mock, "dc=example,dc=com");
            let request = LdapOp::BindRequest(LdapBindRequest {
                dn: "uid=bob,ou=people,dc=example,dc=com".to_string(),
                cred: LdapBindCred::Simple("pass:123456".to_string()),
            });
            assert_eq!(
                ldap_handler.handle_ldap_message(request).await.unwrap(),
                make_bind_result(LdapResultCode::InvalidCredentials, &message)
            );
        }
    }

    #[tokio::test]
    #[serial]
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
    #[serial]
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
    #[serial]
    async fn test_bind_invalid_dn() {
        let mut mock = MockTestBackendHandler::new();
        setup_default_ldap_mock(&mut mock);
        mock.expect_bind().returning(|_| Ok(()));
        let mut ldap_handler = LdapHandler::new_for_tests(mock, "dc=example,dc=com");
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
        let request = LdapBindRequest {
            dn: "uid=bob,ou=people,dc=example,dc=com".to_string(),
            cred: LdapBindCred::Simple("pass".to_string()),
        };
        assert_eq!(ldap_handler.do_bind(&request).await, make_bind_success());
        let request = LdapBindRequest {
            dn: "cn=bob,ou=people,dc=example,dc=com".to_string(),
            cred: LdapBindCred::Simple("pass".to_string()),
        };
        assert_eq!(ldap_handler.do_bind(&request).await, make_bind_success());
    }

    pub fn expect_password_registration(mock: &mut MockTestBackendHandler, user: &str) {
        expect_registration_start(mock, user);
        mock.expect_registration_finish()
            .times(1)
            .return_once(|_| Ok(UserId::new("bob")));
    }

    /// A synced change derives its record with the server's start, then writes it elsewhere.
    pub fn expect_registration_start(mock: &mut MockTestBackendHandler, user: &str) {
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
        mock.expect_registration_start().times(1).return_once(|_| {
            Ok(registration::ServerRegistrationStartResponse {
                server_data: "".to_string(),
                registration_response: start_response.message,
            })
        });
    }

    pub fn expect_password_change(mock: &mut MockTestBackendHandler, user: &str) {
        expect_password_registration(mock, user);
        // Every password change records (or clears) the principal name.
        mock.expect_ensure_kerberos_principal_consistency()
            .times(1)
            .returning(|_, _| Ok(()));
    }

    #[tokio::test]
    #[serial]
    async fn test_password_modify_extended_matrix() {
        let success = || make_extended_response(LdapResultCode::Success, "".to_string());
        let cases = [
            (
                "admin changes a user's password",
                "lldap_admin",
                "bob",
                true,
                success(),
            ),
            (
                "password manager changes a user's password",
                "lldap_password_manager",
                "bob",
                true,
                success(),
            ),
            (
                "regular user changes their own password",
                "",
                "test",
                true,
                success(),
            ),
            (
                "regular user changes another user's password",
                "",
                "bob",
                false,
                make_extended_response(
                    LdapResultCode::InsufficentAccessRights,
                    "User `test` cannot modify user `bob`".to_string(),
                ),
            ),
        ];
        for (label, group, target, changes, expected) in cases {
            let mut mock = MockTestBackendHandler::new();
            setup_default_ldap_mock(&mut mock);
            if changes {
                expect_password_change(&mut mock, target);
            }
            let mut ldap_handler = setup_bound_handler_with_group(mock, group).await;
            let request = LdapOp::ExtendedRequest(
                LdapPasswordModifyRequest {
                    user_identity: Some(format!("uid={target},ou=people,dc=example,dc=com")),
                    old_password: None,
                    new_password: Some("newpassword".to_string()),
                }
                .into(),
            );
            assert_eq!(
                ldap_handler.handle_ldap_message(request).await,
                Some(vec![expected]),
                "{label}"
            );
        }
    }

    pub fn synced_user(uid: &UserId) -> lldap_domain::types::User {
        lldap_domain::types::User {
            user_id: uid.clone(),
            email: format!("{}@example.com", uid.as_str()).into(),
            display_name: None,
            creation_date: chrono::Utc::now().naive_utc(),
            modified_date: chrono::Utc::now().naive_utc(),
            password_modified_date: chrono::Utc::now().naive_utc(),
            uuid: Uuid::from_name_and_date(uid.as_str(), &chrono::Utc::now().naive_utc()),
            attributes: vec![lldap_domain::types::Attribute {
                name: "kerberossync".into(),
                value: 1i64.into(),
            }],
            krb_principal_name: None,
            mfa_type: None,
        }
    }

    pub fn committed(user: &str, password: &str) -> KerberosOp {
        KerberosOp::CommitPassword {
            username: user.into(),
            password: password.into(),
            rows: vec![
                format!("password {user}"),
                format!("synced {user}"),
                "log password_change".into(),
            ],
        }
    }

    fn password_modify_request(user: &str) -> LdapOp {
        LdapOp::ExtendedRequest(
            LdapPasswordModifyRequest {
                user_identity: Some(format!("uid={user},ou=people,dc=example,dc=com")),
                old_password: None,
                new_password: Some("newpassword".to_string()),
            }
            .into(),
        )
    }

    #[tokio::test]
    #[serial]
    async fn test_the_encoded_passwords_of_a_password_modify_are_zeroed_on_every_exit() {
        let request = |user: Option<&str>| {
            LdapExtendedRequest::from(LdapPasswordModifyRequest {
                user_identity: user.map(|u| format!("uid={u},ou=people,dc=example,dc=com")),
                old_password: Some("oldpassword".to_string()),
                new_password: Some("newpassword".to_string()),
            })
        };
        let mut cut = request(Some("bob"));
        let value = cut.value.as_mut().unwrap();
        value.truncate(value.len() - 1);
        let answer = |code, message: &str| make_extended_response(code, message.to_string());
        let success = answer(LdapResultCode::Success, "");
        let rows = [
            (
                "changed",
                Some("lldap_admin"),
                request(Some("bob")),
                success.clone(),
            ),
            (
                "refused",
                Some("regular"),
                request(Some("bob")),
                answer(
                    LdapResultCode::InsufficentAccessRights,
                    "User `test` cannot modify user `bob`",
                ),
            ),
            (
                "no user",
                Some("lldap_admin"),
                request(None),
                answer(
                    LdapResultCode::ConstraintViolation,
                    "Missing either user_id or password",
                ),
            ),
            (
                "not BER",
                Some("lldap_admin"),
                cut,
                answer(
                    LdapResultCode::ProtocolError,
                    "Error while parsing password modify request: PasswordModifyRequestBer",
                ),
            ),
            (
                "unbound",
                None,
                request(Some("bob")),
                answer(
                    LdapResultCode::InsufficentAccessRights,
                    "No user currently bound",
                ),
            ),
        ];
        for (label, group, request, expected) in rows {
            let mut mock = MockTestBackendHandler::new();
            setup_default_ldap_mock(&mut mock);
            if expected == success {
                expect_password_change(&mut mock, "bob");
            }
            let ldap_handler = match group {
                Some(group) => setup_bound_handler_with_group(mock, group).await,
                None => LdapHandler::new_for_tests(mock, "dc=example,dc=com"),
            };
            let zeroed = request.value.as_ref().map(|v| vec![0u8; v.len()]);
            let mut op = LdapOp::ExtendedRequest(request);
            let response = ldap_handler.answer_and_wipe(&mut op).await;
            let LdapOp::ExtendedRequest(request) = op else {
                unreachable!()
            };
            assert!(zeroed.as_ref().is_some_and(|z| !z.is_empty()), "{label}");
            assert_eq!(
                (response, request.value),
                (vec![expected], zeroed),
                "{label}"
            );
        }
    }

    #[tokio::test]
    #[serial]
    async fn test_password_modify_reports_a_failed_change_in_any_group() {
        const CAUSE: &str = "the database did not answer";
        let disabled = HashSet::from([GroupDetails {
            group_id: GroupId(2),
            display_name: "lldap_disabled".into(),
            creation_date: chrono::Utc::now().naive_utc(),
            modified_date: chrono::Utc::now().naive_utc(),
            uuid: Uuid::from_name_and_date("lldap_disabled", &chrono::Utc::now().naive_utc()),
            attributes: vec![],
        }]);
        let rows = [
            ("in no group", HashSet::new()),
            ("in lldap_disabled", disabled),
        ];
        for (label, groups) in rows {
            let guard = RecordingGuard::install_failing(CAUSE);
            let mut mock = MockTestBackendHandler::new();
            mock.expect_get_user_details()
                .returning(|uid| Ok(synced_user(uid)));
            mock.expect_get_user_groups()
                .returning(move |_| Ok(groups.clone()));
            setup_default_ldap_mock(&mut mock);
            expect_registration_start(&mut mock, "bob");
            mock.expect_registration_finish().times(0);
            mock.expect_ensure_kerberos_principal_consistency().times(0);
            let mut ldap_handler = setup_bound_admin_handler(mock).await;
            assert_eq!(
                ldap_handler
                    .handle_ldap_message(password_modify_request("bob"))
                    .await,
                Some(vec![make_extended_response(
                    LdapResultCode::Other,
                    format!("password change failed: {CAUSE}"),
                )]),
                "{label}"
            );
            assert_eq!(
                guard.recorder().take_ops(),
                vec![committed("bob", "newpassword")],
                "{label}"
            );
        }
    }

    #[derive(Clone, Debug)]
    pub(crate) enum Kdc {
        Refusing,
        Offline,
        DirectoryOnly,
        Answering(Result<(), CommitError>),
    }

    pub(crate) const REFUSAL: &str = "password policy: min_length 40";

    pub(crate) fn kdc_rows() -> Vec<(Kdc, LdapResultCode, String)> {
        let failed = |e| Kdc::Answering(Err(e));
        vec![
            (
                Kdc::Refusing,
                LdapResultCode::UnwillingToPerform,
                format!("refused by Kerberos: {REFUSAL}"),
            ),
            (
                Kdc::Offline,
                LdapResultCode::Unavailable,
                realm_not_ready(DEGRADED_CAUSE).to_string(),
            ),
            (
                Kdc::DirectoryOnly,
                LdapResultCode::Unavailable,
                format!(
                    "Kerberos KDC unavailable: {}",
                    closed_to_writes(DEGRADED_CAUSE)
                ),
            ),
            (
                failed(CommitError::Busy),
                LdapResultCode::Busy,
                PASSWORD_CHANGE_IN_PROGRESS.to_owned(),
            ),
            (
                failed(CommitError::Failed("late".to_owned())),
                LdapResultCode::Other,
                "password change failed: late".to_owned(),
            ),
            (
                failed(CommitError::Refused(SYNC_CHANGED.to_owned())),
                LdapResultCode::UnwillingToPerform,
                "the user's Kerberos sync changed; try again".to_owned(),
            ),
            (
                failed(CommitError::UserGone),
                LdapResultCode::NoSuchObject,
                "password change failed: no such user".to_owned(),
            ),
            (
                failed(CommitError::Unknown("late".to_owned())),
                LdapResultCode::Other,
                RESULT_UNKNOWN.to_owned(),
            ),
            (
                Kdc::Answering(Ok(())),
                LdapResultCode::Success,
                String::new(),
            ),
        ]
    }

    // Each KDC answer, the guard that plays it, and whether the change reached the commit.
    pub(crate) fn install(kdc: Kdc) -> (Option<RecordingGuard>, Option<DegradedGuard>, bool) {
        match kdc {
            Kdc::Refusing => (Some(RecordingGuard::install_refusing(REFUSAL)), None, false),
            Kdc::Offline => (None, Some(DegradedGuard::install()), false),
            Kdc::DirectoryOnly => (None, Some(DegradedGuard::install_directory_only()), false),
            Kdc::Answering(answer) => (Some(RecordingGuard::install_answering(answer)), None, true),
        }
    }

    #[tokio::test]
    #[serial]
    async fn test_password_modify_answers_each_outcome_of_a_synced_change() {
        use lldap_test_utils::recording_log::LogGuard;
        for (kdc, code, message) in kdc_rows() {
            let (guard, _offline, reached) = install(kdc.clone());
            let log = LogGuard::install_on_this_thread();
            let public = matches!(kdc, Kdc::DirectoryOnly);
            let mut mock = MockTestBackendHandler::new();
            mock.expect_get_user_details()
                .returning(|uid| Ok(synced_user(uid)));
            setup_default_ldap_mock(&mut mock);
            if reached {
                expect_registration_start(&mut mock, "bob");
            } else {
                mock.expect_registration_start().times(0);
            }
            mock.expect_registration_finish().times(0);
            mock.expect_ensure_kerberos_principal_consistency().times(0);
            let mut ldap_handler = setup_bound_admin_handler(mock).await;
            assert_eq!(
                ldap_handler
                    .handle_ldap_message(password_modify_request("bob"))
                    .await,
                Some(vec![make_extended_response(code, message.clone())]),
                "{kdc:?}"
            );
            let ops = guard.map(|g| g.recorder().take_ops()).unwrap_or_default();
            let expected = match reached {
                true => vec![committed("bob", "newpassword")],
                false => vec![],
            };
            assert_eq!(ops, expected, "{kdc:?}");
            let full = format!("Kerberos KDC unavailable: {DEGRADED_CAUSE}");
            let kept = log.recorder().take_events().into_iter();
            let kept = kept.filter(|e| public && e.detail.as_deref() == Some(full.as_str()));
            assert_eq!(
                (kept.count(), public && message.contains(DEGRADED_CAUSE)),
                (usize::from(public), false),
                "{kdc:?}: in directory-only the full cause is in the row, not in the answer"
            );
        }
    }

    #[tokio::test]
    #[serial]
    async fn test_password_modify_without_sync_is_the_directory_write_alone() {
        let guard = RecordingGuard::install();
        let mut mock = MockTestBackendHandler::new();
        setup_default_ldap_mock(&mut mock);
        expect_password_change(&mut mock, "bob");
        let mut ldap_handler = setup_bound_admin_handler(mock).await;
        assert_eq!(
            ldap_handler
                .handle_ldap_message(password_modify_request("bob"))
                .await,
            Some(vec![make_extended_response(
                LdapResultCode::Success,
                "".to_string()
            )])
        );
        assert_eq!(guard.recorder().take_ops(), vec![]);
    }

    #[tokio::test]
    #[serial]
    async fn test_password_modify_without_sync_is_refused_where_the_realm_is_not_ready() {
        let mut mock = MockTestBackendHandler::new();
        setup_default_ldap_mock(&mut mock);
        mock.expect_registration_start().times(0);
        mock.expect_registration_finish().times(0);
        mock.expect_ensure_kerberos_principal_consistency().times(0);
        let mut ldap_handler = setup_bound_admin_handler(mock).await;
        let _offline = DegradedGuard::install();
        assert_eq!(
            ldap_handler
                .handle_ldap_message(password_modify_request("bob"))
                .await,
            Some(vec![make_extended_response(
                LdapResultCode::Unavailable,
                realm_not_ready(DEGRADED_CAUSE).to_string(),
            )])
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_password_modify_without_sync_goes_on_in_directory_only() {
        let mut mock = MockTestBackendHandler::new();
        setup_default_ldap_mock(&mut mock);
        expect_password_change(&mut mock, "bob");
        let mut ldap_handler = setup_bound_admin_handler(mock).await;
        let _closed = DegradedGuard::install_directory_only();
        assert_eq!(
            ldap_handler
                .handle_ldap_message(password_modify_request("bob"))
                .await,
            Some(vec![make_extended_response(
                LdapResultCode::Success,
                "".to_string()
            )])
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_password_modify_without_sync_is_refused_when_the_switch_turned_on() {
        let changed = Err(CommitError::Refused(SYNC_CHANGED.to_owned()));
        let _guard = RecordingGuard::install_holding(changed);
        let mut mock = MockTestBackendHandler::new();
        setup_default_ldap_mock(&mut mock);
        expect_registration_start(&mut mock, "bob");
        mock.expect_registration_finish().times(0);
        let mut ldap_handler = setup_bound_admin_handler(mock).await;
        assert_eq!(
            ldap_handler
                .handle_ldap_message(password_modify_request("bob"))
                .await,
            Some(vec![make_extended_response(
                LdapResultCode::UnwillingToPerform,
                SYNC_CHANGED.to_owned(),
            )])
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_password_modify_of_a_synced_user_with_kerberos_disabled_names_both_ways_on() {
        use lldap_domain_handlers::kerberos::{SYNC_OFF_FIRST, while_disabled};
        let mut mock = MockTestBackendHandler::new();
        mock.expect_get_user_details()
            .returning(|uid| Ok(synced_user(uid)));
        setup_default_ldap_mock(&mut mock);
        mock.expect_registration_start().times(0);
        mock.expect_registration_finish().times(0);
        let mut ldap_handler = setup_bound_admin_handler(mock).await;
        assert_eq!(
            ldap_handler
                .handle_ldap_message(password_modify_request("bob"))
                .await,
            Some(vec![make_extended_response(
                LdapResultCode::UnwillingToPerform,
                while_disabled(SYNC_OFF_FIRST),
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

    #[tokio::test]
    async fn test_a_bind_says_an_error_of_the_servers_own_within_the_budget_and_no_refusal() {
        use lldap_domain_handlers::logging::capture::{BUDGET, Lines};
        type Failure = fn() -> DomainError;
        let refusal: Failure = || DomainError::AuthenticationError("for bob".to_owned());
        let fault: Failure = || DomainError::InternalError("the database is away".to_owned());
        for (label, failure, said) in [("a refusal", refusal, 0), ("a fault", fault, BUDGET)] {
            let mut mock = MockTestBackendHandler::new();
            mock.expect_bind().returning(move |_| Err(failure()));
            let (lines, _guard) = Lines::capture();
            for _ in 0..100 {
                let answered = bind(&mock, UserId::new("bob"), "pass").await;
                let code = answered.map_err(|e| e.code);
                assert_eq!(code, Err(LdapResultCode::InvalidCredentials), "{label}");
            }
            assert_eq!(lines.take_loud().len(), said, "{label}");
        }
    }
}
