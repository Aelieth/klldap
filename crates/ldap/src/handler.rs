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
use lldap_domain_handlers::handler::{BackendHandler, LoginHandler};
use lldap_opaque_handler::OpaqueHandler;
use lldap_schema::PublicSchema;
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
    ) -> Self {
        Self {
            user_info: None,
            backend_handler,
            ldap_info,
            session_uuid,
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
        let (code, message) = {
            match password::do_bind(self.ldap_info, request, self.get_login_handler()).await {
                Ok(user_id) => {
                    // Strict OU enforcement
                    let inner = self.backend_handler.unsafe_get_handler();
                    match inner.get_user_details(&user_id).await {
                        Ok(user) => {
                            let stored_ou = crate::attributes::get_user_ou(&user);
                            let provided_ou = if let Ok(parts) = crate::dn::parse_distinguished_name(
                                &request.dn.to_ascii_lowercase(),
                            ) {
                                crate::dn::get_internal_ou_from_dn_parts(&parts)
                            } else {
                                String::new()
                            };

                            if provided_ou.eq_ignore_ascii_case(&stored_ou) {
                                self.user_info = self
                                    .backend_handler
                                    .get_permissions_for_user(user_id)
                                    .await
                                    .ok();
                                debug!("Success! OU verified: {}", stored_ou);
                                (LdapResultCode::Success, "".to_string())
                            } else {
                                debug!(
                                    "Bind rejected - OU mismatch: provided='{}', stored='{}'",
                                    provided_ou, stored_ou
                                );
                                (LdapResultCode::InvalidCredentials, "".to_string())
                            }
                        }
                        Err(_) => (LdapResultCode::InvalidCredentials, "".to_string()),
                    }
                }
                Err(err) => (err.code, err.message),
            }
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
            |credentials, user_id| {
                self.backend_handler
                    .get_readable_handler(credentials, user_id)
            },
            |credentials, user_id| {
                self.backend_handler
                    .get_writeable_handler(credentials, user_id)
            },
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

#[cfg(test)]
pub mod tests {
    use super::*;
    use lldap_auth::access_control::{Permission, ValidationResults};
    use lldap_domain::types::UserId;
    use lldap_test_utils::MockTestBackendHandler;

    pub async fn setup_bound_admin_handler(
        mock: MockTestBackendHandler,
    ) -> LdapHandler<MockTestBackendHandler> {
        let mut handler = LdapHandler::new_for_tests(mock, "dc=example,dc=com");
        handler.user_info = Some(ValidationResults {
            user: UserId::new("test"),
            permission: Permission::Admin,
        });
        handler
    }

    pub async fn setup_bound_password_manager_handler(
        mock: MockTestBackendHandler,
    ) -> LdapHandler<MockTestBackendHandler> {
        let handler = setup_bound_admin_handler(mock).await;
        // In real impl this would have password-manager group; for test we reuse admin-like
        handler
    }

    pub async fn setup_bound_readonly_handler(
        mock: MockTestBackendHandler,
    ) -> LdapHandler<MockTestBackendHandler> {
        let mut handler = LdapHandler::new_for_tests(mock, "dc=example,dc=com");
        handler.user_info = Some(ValidationResults {
            user: UserId::new("test"),
            permission: Permission::Readonly,
        });
        handler
    }

    pub async fn setup_bound_handler_with_group(
        mock: MockTestBackendHandler,
        group: &str,
    ) -> LdapHandler<MockTestBackendHandler> {
        let mut handler = LdapHandler::new_for_tests(mock, "dc=example,dc=com");
        let permission = if group.eq_ignore_ascii_case("regular") {
            Permission::Readonly // non-admin; self-changes still allowed by can_change_password policy
        } else {
            Permission::Admin
        };
        handler.user_info = Some(ValidationResults {
            user: UserId::new("test"),
            permission,
        });
        handler
    }
}
