use crate::{
    compare,
    core::{
        error::{LdapError, LdapResult},
        utils::LdapInfo,
    },
    create, delete,
    dn::internal_ou_to_ldap_rdn_chain,
    modify,
    password::{self, do_password_modification},
    search::{
        is_root_dse_request, is_subschema_entry_request, make_ldap_subschema_entry,
        make_search_error, make_search_request, make_search_success, root_dse_response,
    },
};
use ldap3_proto::proto::{
    LdapAddRequest, LdapBindRequest, LdapBindResponse, LdapCompareRequest, LdapExtendedRequest,
    LdapExtendedResponse, LdapFilter, LdapModifyRequest, LdapOp, LdapPasswordModifyRequest,
    LdapResult as LdapResultOp, LdapResultCode, LdapSearchRequest, OID_PASSWORD_MODIFY, OID_WHOAMI,
};
use lldap_access_control::AccessControlledBackendHandler;
use lldap_auth::access_control::ValidationResults;
use lldap_domain::types::UserId;
use lldap_domain_handlers::handler::{BackendHandler, LoginHandler};
use lldap_domain_handlers::logging::{self, LogKind, RequestMeta, with_request};
use lldap_opaque_handler::OpaqueHandler;
use lldap_schema::PublicSchema;
use std::net::IpAddr;
use tracing::{debug, instrument};

use super::delete::make_del_response;

pub(crate) fn make_add_response(code: LdapResultCode, message: String) -> LdapOp {
    LdapOp::AddResponse(LdapResultOp {
        code,
        matcheddn: "".to_string(),
        message,
        referral: vec![],
    })
}

pub(crate) fn make_extended_response(code: LdapResultCode, message: String) -> LdapOp {
    LdapOp::ExtendedResponse(LdapExtendedResponse {
        res: LdapResultOp {
            code,
            matcheddn: "".to_string(),
            message,
            referral: vec![],
        },
        name: None,
        value: None,
    })
}

pub(crate) fn make_modify_response(code: LdapResultCode, message: String) -> LdapOp {
    LdapOp::ModifyResponse(LdapResultOp {
        code,
        matcheddn: "".to_string(),
        message,
        referral: vec![],
    })
}

pub struct LdapHandler<Backend> {
    user_info: Option<ValidationResults>,
    backend_handler: AccessControlledBackendHandler<Backend>,
    ldap_info: &'static LdapInfo,
    session_uuid: uuid::Uuid,
    peer: Option<IpAddr>,
}

impl<Backend> LdapHandler<Backend> {
    pub fn session_uuid(&self) -> &uuid::Uuid {
        &self.session_uuid
    }
}

impl<Backend: LoginHandler> LdapHandler<Backend> {
    pub fn get_login_handler(&self) -> &(impl LoginHandler + use<Backend>) {
        self.backend_handler.unsafe_get_handler()
    }
}

impl<Backend: OpaqueHandler> LdapHandler<Backend> {
    pub fn get_opaque_handler(&self) -> &(impl OpaqueHandler + use<Backend>) {
        self.backend_handler.unsafe_get_handler()
    }
}

enum Credentials<'s> {
    Bound(&'s ValidationResults),
    Unbound(Vec<LdapOp>),
}

impl<Backend: BackendHandler + LoginHandler + OpaqueHandler> LdapHandler<Backend> {
    pub fn new(
        backend_handler: AccessControlledBackendHandler<Backend>,
        ldap_info: &'static LdapInfo,
        session_uuid: uuid::Uuid,
        peer: Option<IpAddr>,
    ) -> Self {
        Self {
            user_info: None,
            backend_handler,
            ldap_info,
            session_uuid,
            peer,
        }
    }

    #[cfg(test)]
    pub fn new_for_tests(backend_handler: Backend, ldap_base_dn: &str) -> Self {
        Self::new(
            AccessControlledBackendHandler::new(backend_handler),
            Box::leak(Box::new(
                LdapInfo::new(ldap_base_dn, Vec::new(), Vec::new()).unwrap(),
            )),
            uuid::Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap(),
            Some(std::net::Ipv4Addr::LOCALHOST.into()),
        )
    }

    fn get_credentials(&self) -> Credentials<'_> {
        match self.user_info.as_ref() {
            Some(user_info) => Credentials::Bound(user_info),
            None => Credentials::Unbound(vec![make_extended_response(
                LdapResultCode::InsufficentAccessRights,
                "No user currently bound".to_string(),
            )]),
        }
    }

    pub async fn do_search_or_dse(&self, request: &LdapSearchRequest) -> LdapResult<Vec<LdapOp>> {
        if is_root_dse_request(request) {
            debug!("rootDSE request");
            return Ok(vec![
                root_dse_response(&self.ldap_info.base_dn_str),
                make_search_success(),
            ]);
        } else if is_subschema_entry_request(request) {
            debug!("Schema request");
            if self.user_info.is_none() {
                return Err(LdapError {
                    code: LdapResultCode::InsufficentAccessRights,
                    message: "No user currently bound".to_string(),
                });
            }
            return Ok(vec![
                make_ldap_subschema_entry(
                    crate::schema::get_schema_manager(),
                    &self.ldap_info.base_dn_str,
                ),
                make_search_success(),
            ]);
        }
        self.do_search(request).await
    }

    #[instrument(skip_all, level = "debug")]
    async fn do_search(&self, request: &LdapSearchRequest) -> LdapResult<Vec<LdapOp>> {
        let user_info = self.user_info.as_ref().ok_or_else(|| LdapError {
            code: LdapResultCode::InsufficentAccessRights,
            message: "No user currently bound".to_string(),
        })?;
        let backend_handler = self
            .backend_handler
            .get_user_restricted_lister_handler(user_info);

        let allowed_ous = self
            .backend_handler
            .unsafe_get_handler()
            .get_allowed_ous()
            .await
            .unwrap_or_else(|_| vec!["people".to_string(), "groups".to_string()]);

        debug!(?request.base, ?request.scope, "Handler calling do_search");
        crate::search::do_search(&backend_handler, self.ldap_info, request, &allowed_ous).await
    }

    #[instrument(skip_all, level = "debug", fields(dn = %request.dn))]
    pub async fn do_bind(&mut self, request: &LdapBindRequest) -> Vec<LdapOp> {
        let (code, message) = match self.authenticate(request).await {
            Ok(user_id) => {
                self.user_info = self
                    .backend_handler
                    .get_permissions_for_user(user_id)
                    .await
                    .ok();
                (LdapResultCode::Success, "".to_string())
            }
            Err(err) => (err.code, err.message),
        };
        vec![LdapOp::BindResponse(LdapBindResponse {
            res: LdapResultOp {
                code,
                matcheddn: "".to_string(),
                message,
                referral: vec![],
            },
            saslcreds: None,
        })]
    }

    // A known user bound under the wrong OU is refused before any password work, so the
    // login handler never records a success for a bind the server rejects.
    async fn authenticate(&self, request: &LdapBindRequest) -> LdapResult<UserId> {
        let (user_id, password) = password::parse_bind_request(self.ldap_info, request)
            .inspect_err(|err| {
                logging::record_as(
                    None,
                    LogKind::Bind,
                    (!request.dn.is_empty()).then_some(request.dn.as_str()),
                    false,
                    Some(&err.message),
                );
            })?;
        let inner = self.backend_handler.unsafe_get_handler();
        if let Ok(user) = inner.get_user_details(&user_id).await {
            let stored_ou = crate::attributes::get_user_ou(&user);
            let provided_ou =
                match crate::dn::parse_distinguished_name(&request.dn.to_ascii_lowercase()) {
                    Ok(parts) => crate::dn::get_internal_ou_from_dn_parts(&parts),
                    Err(_) => String::new(),
                };
            if !provided_ou.eq_ignore_ascii_case(&stored_ou) {
                debug!(
                    "Bind rejected - OU mismatch: provided='{}', stored='{}'",
                    provided_ou, stored_ou
                );
                logging::record_as(
                    Some(&user_id),
                    LogKind::Bind,
                    None,
                    false,
                    Some("ou mismatch"),
                );
                return Err(LdapError {
                    code: LdapResultCode::InvalidCredentials,
                    message: "".to_string(),
                });
            }
        }
        // Wrong passwords and unknown users are recorded by the login handler itself.
        password::bind(self.get_login_handler(), user_id, password).await
    }

    #[instrument(skip_all, level = "debug")]
    async fn do_extended_request(&self, request: &LdapExtendedRequest) -> Vec<LdapOp> {
        match request.name.as_str() {
            OID_PASSWORD_MODIFY => match LdapPasswordModifyRequest::try_from(request) {
                Ok(password_request) => {
                    let credentials = match self.get_credentials() {
                        Credentials::Bound(cred) => cred,
                        Credentials::Unbound(err) => return err,
                    };
                    do_password_modification(
                        credentials,
                        self.ldap_info,
                        &self.backend_handler,
                        self.get_opaque_handler(),
                        &password_request,
                    )
                    .await
                    .unwrap_or_else(|e: LdapError| vec![make_extended_response(e.code, e.message)])
                }
                Err(e) => vec![make_extended_response(
                    LdapResultCode::ProtocolError,
                    format!("Error while parsing password modify request: {e:#?}"),
                )],
            },
            OID_WHOAMI => {
                let credentials = match self.get_credentials() {
                    Credentials::Bound(cred) => cred,
                    Credentials::Unbound(err) => return err,
                };
                let user_id = credentials.user.clone();

                let backend = self.backend_handler.unsafe_get_handler();

                let user_filter = LdapFilter::Equality("uid".to_string(), user_id.to_string());
                let users = crate::search::get_user_list(
                    self.ldap_info,
                    &user_filter,
                    false,
                    &self.ldap_info.base_dn_str,
                    backend,
                    PublicSchema::shared(),
                )
                .await
                .unwrap_or_default();

                let user_ou = if let Some(uag) = users.first() {
                    crate::attributes::get_user_ou(&uag.user)
                } else {
                    crate::dn::DEFAULT_PRIMARY_USER_OU.to_string()
                };

                let rdn_chain = internal_ou_to_ldap_rdn_chain(&user_ou);
                let ou_part: String = rdn_chain
                    .iter()
                    .map(|(k, v)| format!("{}={}", k, v))
                    .collect::<Vec<_>>()
                    .join(",");

                let authz_id = if ou_part.is_empty() {
                    format!("dn:uid={},{}", user_id, self.ldap_info.base_dn_str)
                } else {
                    format!(
                        "dn:uid={},{},{}",
                        user_id, ou_part, self.ldap_info.base_dn_str
                    )
                };

                vec![make_extended_response(LdapResultCode::Success, authz_id)]
            }
            _ => vec![make_extended_response(
                LdapResultCode::UnwillingToPerform,
                format!("Unsupported extended operation: {}", request.name),
            )],
        }
    }

    #[instrument(skip_all, level = "debug", fields(dn = %request.dn))]
    pub async fn do_modify_request(&self, request: &LdapModifyRequest) -> Vec<LdapOp> {
        let credentials = match self.get_credentials() {
            Credentials::Bound(cred) => cred,
            Credentials::Unbound(err) => return err,
        };
        modify::handle_modify_request(
            self.get_opaque_handler(),
            &self.backend_handler,
            self.ldap_info,
            credentials,
            request,
        )
        .await
        .unwrap_or_else(|e: LdapError| vec![make_modify_response(e.code, e.message)])
    }

    #[instrument(skip_all, level = "debug")]
    pub async fn create_user_or_group(&self, request: LdapAddRequest) -> LdapResult<Vec<LdapOp>> {
        let backend_handler = self
            .user_info
            .as_ref()
            .and_then(|u| self.backend_handler.get_admin_handler(u))
            .ok_or_else(|| LdapError {
                code: LdapResultCode::InsufficentAccessRights,
                message: "Unauthorized write".to_string(),
            })?;
        create::create_user_or_group(backend_handler, self.ldap_info, request).await
    }

    #[instrument(skip_all, level = "debug")]
    pub async fn delete_user_or_group(&self, request: String) -> LdapResult<Vec<LdapOp>> {
        let backend_handler = self
            .user_info
            .as_ref()
            .and_then(|u| self.backend_handler.get_admin_handler(u))
            .ok_or_else(|| LdapError {
                code: LdapResultCode::InsufficentAccessRights,
                message: "Unauthorized write".to_string(),
            })?;
        delete::delete_user_or_group(backend_handler, self.ldap_info, request).await
    }

    #[instrument(skip_all, level = "debug")]
    pub async fn do_compare(&self, request: LdapCompareRequest) -> LdapResult<Vec<LdapOp>> {
        let req = make_search_request::<String>(
            &self.ldap_info.base_dn_str,
            LdapFilter::Equality("dn".to_string(), request.dn.to_string()),
            vec![request.atype.clone()],
        );
        compare::compare(
            request,
            self.do_search(&req).await?,
            &self.ldap_info.base_dn_str,
        )
    }

    pub async fn handle_ldap_message(&mut self, ldap_op: LdapOp) -> Option<Vec<LdapOp>> {
        let meta = RequestMeta::ldap(self.user_info.as_ref().map(|u| u.user.clone()), self.peer);
        with_request(meta, async {
            let response = self.dispatch(ldap_op).await;
            record_denial(response.as_deref());
            response
        })
        .await
    }

    async fn dispatch(&mut self, ldap_op: LdapOp) -> Option<Vec<LdapOp>> {
        Some(match ldap_op {
            LdapOp::BindRequest(request) => self.do_bind(&request).await,
            LdapOp::SearchRequest(request) => self
                .do_search_or_dse(&request)
                .await
                .unwrap_or_else(|e: LdapError| vec![make_search_error(e.code, e.message)]),
            LdapOp::UnbindRequest => {
                debug!(
                    "Unbind request for {}",
                    self.user_info
                        .as_ref()
                        .map(|u| u.user.as_str())
                        .unwrap_or("<not bound>"),
                );
                self.user_info = None;
                return None;
            }
            LdapOp::ModifyRequest(request) => self.do_modify_request(&request).await,
            LdapOp::ExtendedRequest(request) => self.do_extended_request(&request).await,
            LdapOp::AddRequest(request) => self
                .create_user_or_group(request)
                .await
                .unwrap_or_else(|e: LdapError| vec![make_add_response(e.code, e.message)]),
            LdapOp::DelRequest(request) => self
                .delete_user_or_group(request)
                .await
                .unwrap_or_else(|e: LdapError| vec![make_del_response(e.code, e.message)]),
            LdapOp::CompareRequest(request) => self
                .do_compare(request)
                .await
                .unwrap_or_else(|e: LdapError| vec![make_search_error(e.code, e.message)]),
            op => vec![make_extended_response(
                LdapResultCode::UnwillingToPerform,
                format!("Unsupported operation: {op:#?}"),
            )],
        })
    }
}

// Every denial ends in a result op with InsufficentAccessRights, so one look at the
// response covers all of them.
fn record_denial(response: Option<&[LdapOp]>) {
    let Some(result) = response.and_then(|ops| ops.last()).and_then(result_of) else {
        return;
    };
    if result.code == LdapResultCode::InsufficentAccessRights {
        logging::record_failure(LogKind::AccessDenied, None, &result.message);
    }
}

fn result_of(op: &LdapOp) -> Option<&LdapResultOp> {
    match op {
        LdapOp::BindResponse(response) => Some(&response.res),
        LdapOp::ExtendedResponse(response) => Some(&response.res),
        LdapOp::SearchResultDone(result)
        | LdapOp::ModifyResponse(result)
        | LdapOp::AddResponse(result)
        | LdapOp::DelResponse(result)
        | LdapOp::CompareResult(result)
        | LdapOp::ModifyDNResponse(result) => Some(result),
        _ => None,
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use lldap_auth::access_control::{Permission, ValidationResults};
    use lldap_domain::types::UserId;
    use lldap_domain_handlers::logging::Protocol;
    use lldap_domain_model::error::DomainError;
    use lldap_test_utils::{
        MockTestBackendHandler, recording_log::LogGuard, setup_default_ldap_mock,
    };
    use pretty_assertions::assert_eq;
    use serial_test::serial;

    // Non-serial tests record too; a private peer address keeps each test's events apart.
    fn events_from(guard: &LogGuard, peer: &str) -> Vec<lldap_domain_handlers::logging::LogEvent> {
        guard
            .recorder()
            .take_events()
            .into_iter()
            .filter(|e| e.peer.as_deref() == Some(peer))
            .collect()
    }

    pub async fn setup_bound_handler_with_group(
        mock: MockTestBackendHandler,
        group: &str,
    ) -> LdapHandler<MockTestBackendHandler> {
        let permission = match group {
            "lldap_admin" => Permission::Admin,
            "lldap_password_manager" => Permission::PasswordManager,
            "lldap_strict_readonly" => Permission::Readonly,
            _ => Permission::Regular,
        };
        let mut handler = LdapHandler::new_for_tests(mock, "dc=example,dc=com");
        handler.user_info = Some(ValidationResults {
            user: UserId::new("test"),
            permission,
        });
        handler
    }

    pub async fn setup_bound_admin_handler(
        mock: MockTestBackendHandler,
    ) -> LdapHandler<MockTestBackendHandler> {
        setup_bound_handler_with_group(mock, "lldap_admin").await
    }

    pub async fn setup_bound_password_manager_handler(
        mock: MockTestBackendHandler,
    ) -> LdapHandler<MockTestBackendHandler> {
        setup_bound_handler_with_group(mock, "lldap_password_manager").await
    }

    pub async fn setup_bound_readonly_handler(
        mock: MockTestBackendHandler,
    ) -> LdapHandler<MockTestBackendHandler> {
        setup_bound_handler_with_group(mock, "lldap_strict_readonly").await
    }

    #[tokio::test]
    #[serial]
    async fn test_denied_write_records_access_denied_with_actor_and_peer() {
        let mut mock = MockTestBackendHandler::new();
        setup_default_ldap_mock(&mut mock);
        let mut handler = setup_bound_handler_with_group(mock, "regular").await;
        handler.peer = Some("198.51.100.1".parse().unwrap());
        let guard = LogGuard::install();

        let response = handler
            .handle_ldap_message(LdapOp::DelRequest(
                "uid=bob,ou=people,dc=example,dc=com".to_string(),
            ))
            .await;
        assert_eq!(
            response,
            Some(vec![make_del_response(
                LdapResultCode::InsufficentAccessRights,
                "Unauthorized write".to_string(),
            )])
        );

        let events = events_from(&guard, "198.51.100.1");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, LogKind::AccessDenied);
        assert!(!events[0].success);
        assert_eq!(events[0].actor.as_deref(), Some("test"));
        assert_eq!(events[0].protocol, Protocol::Ldap);
        assert_eq!(events[0].detail.as_deref(), Some("Unauthorized write"));
    }

    #[tokio::test]
    #[serial]
    async fn test_unbound_request_records_access_denied_without_an_actor() {
        let mut handler =
            LdapHandler::new_for_tests(MockTestBackendHandler::new(), "dc=example,dc=com");
        handler.peer = Some("198.51.100.2".parse().unwrap());
        let guard = LogGuard::install();

        handler
            .handle_ldap_message(LdapOp::ExtendedRequest(LdapExtendedRequest {
                name: OID_WHOAMI.to_string(),
                value: None,
            }))
            .await;

        let events = events_from(&guard, "198.51.100.2");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, LogKind::AccessDenied);
        assert_eq!(events[0].actor, None);
        assert_eq!(events[0].detail.as_deref(), Some("No user currently bound"));
    }

    #[tokio::test]
    #[serial]
    async fn test_ldap_layer_records_only_non_credential_bind_failures() {
        use ldap3_proto::proto::LdapBindCred;
        let mut mock = MockTestBackendHandler::new();
        setup_default_ldap_mock(&mut mock);
        mock.expect_bind()
            .returning(|_| Err(DomainError::AuthenticationError("nope".to_string())));
        let mut handler = LdapHandler::new_for_tests(mock, "dc=example,dc=com");
        handler.peer = Some("198.51.100.3".parse().unwrap());
        let guard = LogGuard::install();

        for (dn, cred) in [
            (
                "uid=bob,ou=people,dc=example,dc=com",
                LdapBindCred::Simple("wrong".to_string()),
            ),
            ("", LdapBindCred::Simple("wrong".to_string())),
            (
                "uid=bob,ou=people,dc=example,dc=com",
                LdapBindCred::SASL(ldap3_proto::proto::SaslCredentials {
                    mechanism: "GSSAPI".to_string(),
                    credentials: vec![],
                }),
            ),
            (
                "cn=bob,ou=people,dc=other,dc=com",
                LdapBindCred::Simple("wrong".to_string()),
            ),
        ] {
            handler
                .handle_ldap_message(LdapOp::BindRequest(LdapBindRequest {
                    dn: dn.to_string(),
                    cred,
                }))
                .await;
        }

        let events = events_from(&guard, "198.51.100.3");
        let summary: Vec<_> = events
            .iter()
            .map(|e| (e.kind, e.target.as_deref(), e.detail.as_deref()))
            .collect();
        // The wrong password is the login handler's row, not the LDAP layer's.
        assert_eq!(
            summary,
            vec![
                (LogKind::Bind, None, Some("Anonymous bind not allowed")),
                (
                    LogKind::Bind,
                    Some("uid=bob,ou=people,dc=example,dc=com"),
                    Some("SASL not supported")
                ),
                (
                    LogKind::Bind,
                    Some("cn=bob,ou=people,dc=other,dc=com"),
                    Some("Not a subtree of the base tree")
                ),
            ]
        );
        assert!(events.iter().all(|e| !e.success && e.actor.is_none()));
    }

    #[tokio::test]
    #[serial]
    async fn test_ou_mismatch_bind_records_a_failure_for_the_user() {
        use ldap3_proto::proto::LdapBindCred;
        let mut mock = MockTestBackendHandler::new();
        setup_default_ldap_mock(&mut mock);
        // Refused before the password is checked: no login-handler success row.
        mock.expect_bind().times(0);
        let mut handler = LdapHandler::new_for_tests(mock, "dc=example,dc=com");
        handler.peer = Some("198.51.100.4".parse().unwrap());
        let guard = LogGuard::install();

        let response = handler
            .handle_ldap_message(LdapOp::BindRequest(LdapBindRequest {
                dn: "uid=bob,ou=lab,dc=example,dc=com".to_string(),
                cred: LdapBindCred::Simple("pass".to_string()),
            }))
            .await;
        assert_eq!(
            response,
            Some(crate::password::tests::make_bind_result(
                LdapResultCode::InvalidCredentials,
                ""
            ))
        );

        let events = events_from(&guard, "198.51.100.4");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, LogKind::Bind);
        assert_eq!(events[0].actor.as_deref(), Some("bob"));
        assert_eq!(events[0].detail.as_deref(), Some("ou mismatch"));
    }

    #[tokio::test]
    async fn test_subschema_requires_bind() {
        let mut handler =
            LdapHandler::new_for_tests(MockTestBackendHandler::new(), "dc=example,dc=com");
        let request = crate::search::make_search_request(
            "cn=Subschema,dc=example,dc=com",
            ldap3_proto::LdapFilter::Present("objectClass".to_string()),
            vec!["*", "+"],
        );
        assert_eq!(
            handler
                .handle_ldap_message(LdapOp::SearchRequest(request))
                .await,
            Some(vec![crate::search::make_search_error(
                LdapResultCode::InsufficentAccessRights,
                "No user currently bound".to_string(),
            )])
        );
    }
}
