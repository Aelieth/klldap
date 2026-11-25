use crate::{
    tcp_backend_handler::*,
    tcp_server::{AppState, TcpError, TcpResult, error_to_http_response},
};
use actix_web::{
    HttpRequest, HttpResponse,
    cookie::{Cookie, SameSite},
    dev::{Service, ServiceRequest, ServiceResponse, Transform},
    error::{ErrorBadRequest, ErrorServiceUnavailable, ErrorUnauthorized},
    web,
};
use actix_web_httpauth::extractors::bearer::BearerAuth;
use anyhow::Result;
use chrono::prelude::*;
use futures::future::{Ready, ok};
use futures_util::FutureExt;
use hmac::Hmac;
use jwt::{SignWithKey, VerifyWithKey};
use lldap_access_control::{ReadonlyBackendHandler, UserReadableBackendHandler};
use lldap_auth::{
    JWTClaims,
    access_control::{Permission, ValidationResults},
    login, password_reset, registration,
};
use lldap_domain::types::{GroupDetails, GroupName, LoginOutcome, UserId, kerberos_sync_enabled};
use lldap_domain_handlers::enforcement::{Attempt, Door, admit, refuse_unreadable};
use lldap_domain_handlers::handler::{
    BackendHandler, BindRequest, LoginHandler, MfaBackendHandler, PolicyBackendHandler,
    UserRequestFilter,
};
use lldap_domain_handlers::kerberos::{
    KerberosState, SYNC_OFF_FIRST, kerberos_backend, refusal_while_degraded, settled_state,
    while_disabled,
};
use lldap_domain_handlers::logging::{self, LogKind, with_actor};
use lldap_domain_handlers::mfa::{MfaPolicy, MfaRequirement, MfaResetReason};
use lldap_domain_handlers::password::{
    PasswordChangeError, finish_plain, finish_synced_registration, min_length_of, realm_not_ready,
    record_failed,
};
use lldap_domain_model::{error::DomainError, model::UserColumn};
use lldap_graphql_server::{open_password_envelope, public_key_der_base64};
use lldap_opaque_handler::OpaqueHandler;
use sha2::Sha512;
use std::{
    collections::HashSet,
    hash::Hash,
    pin::Pin,
    task::{Context, Poll},
};
use time::ext::NumericalDuration;
use tracing::{debug, info, instrument, warn};
use uuid::Uuid;
use zeroize::Zeroizing;

type Token<S> = jwt::Token<jwt::Header, JWTClaims, S>;
type SignedToken = Token<jwt::token::Signed>;

fn default_hash<T: Hash + ?Sized>(token: &T) -> u64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::Hasher;
    let mut s = DefaultHasher::new();
    token.hash(&mut s);
    s.finish()
}

async fn create_jwt<Handler: TcpBackendHandler>(
    handler: &Handler,
    key: &Hmac<Sha512>,
    user: &UserId,
    groups: HashSet<GroupDetails>,
    password_reset: bool,
) -> SignedToken {
    let claims = JWTClaims {
        exp: Utc::now() + chrono::Duration::days(1),
        iat: Utc::now(),
        jti: Uuid::new_v4(),
        user: user.to_string(),
        groups: groups
            .into_iter()
            .map(|g| g.display_name.into_string())
            .collect(),
        password_reset,
    };
    let expiry = claims.exp.naive_utc();
    let header = jwt::Header {
        algorithm: jwt::AlgorithmType::Hs512,
        ..Default::default()
    };
    let token = jwt::Token::new(header, claims).sign_with_key(key).unwrap();
    handler
        .register_jwt(user, default_hash(token.as_str()), expiry)
        .await
        .unwrap();
    token
}

fn parse_refresh_token(token: &str) -> TcpResult<(u64, UserId)> {
    match token.split_once('+') {
        None => Err(DomainError::AuthenticationError("Invalid refresh token".to_string()).into()),
        Some((token, u)) => Ok((default_hash(token), UserId::new(u))),
    }
}

fn get_refresh_token(request: HttpRequest) -> TcpResult<(u64, UserId)> {
    match (
        request.cookie("refresh_token"),
        request.headers().get("refresh-token"),
    ) {
        (Some(c), _) => parse_refresh_token(c.value()),
        (_, Some(t)) => match t.to_str() {
            Ok(t) => parse_refresh_token(t),
            Err(_) => {
                Err(DomainError::AuthenticationError("Invalid refresh token".to_string()).into())
            }
        },
        (None, None) => {
            Err(DomainError::AuthenticationError("Missing refresh token".to_string()).into())
        }
    }
}

#[instrument(skip_all, level = "debug")]
async fn get_refresh<Backend>(
    data: web::Data<AppState<Backend>>,
    request: HttpRequest,
) -> TcpResult<HttpResponse>
where
    Backend: TcpBackendHandler + BackendHandler + 'static,
{
    let (refresh_token_hash, user) = get_refresh_token(request)?;
    let found = data
        .get_tcp_handler()
        .check_token(refresh_token_hash, &user)
        .await?;
    if !found {
        logging::record_as(
            Some(&user),
            LogKind::TokenRefresh,
            None,
            false,
            Some("invalid refresh token"),
        );
        return Err(TcpError::DomainError(DomainError::AuthenticationError(
            "Invalid refresh token".to_string(),
        )));
    }
    logging::proved(refresh_found(data, user)).await
}

/// The refresh once its token was found.
async fn refresh_found<Backend>(
    data: web::Data<AppState<Backend>>,
    user: UserId,
) -> TcpResult<HttpResponse>
where
    Backend: TcpBackendHandler + BackendHandler + 'static,
{
    let jwt_key = &data.jwt_key;
    let mut path = data.server_url.path().to_string();
    if !path.ends_with('/') {
        path.push('/');
    };
    if account_is_disabled(&data, &user).await {
        logging::record_as(
            Some(&user),
            LogKind::TokenRefresh,
            None,
            false,
            Some("account disabled"),
        );
        return Err(TcpError::DomainError(DomainError::AuthenticationError(
            "Account disabled".to_string(),
        )));
    }
    let groups = data.get_readonly_handler().get_user_groups(&user).await?;
    if let Some(cause) =
        refusal_while_degraded(&user, is_admin(&groups), kerberos_backend().unavailable())
    {
        return Err(TcpError::DomainError(DomainError::KdcUnavailable(cause)));
    }
    let handler = data.backend_handler.unsafe_get_handler();
    admit_refresh(handler, &user).await?;
    let mfa = data.get_mfa_handler();
    let mfa_enrollment_pending = match mfa.mfa_requirement(&user).await {
        Ok(requirement) => requirement == MfaRequirement::Enrollment,
        Err(e) => {
            mfa_unreadable(&user, Door::Refresh, &e);
            return Err(refresh_refused(&user));
        }
    };
    let token = create_jwt(data.get_tcp_handler(), jwt_key, &user, groups, false).await;
    logging::record_as(Some(&user), LogKind::TokenRefresh, None, true, None);
    handler.note_sign_in(&user).await;
    Ok(HttpResponse::Ok()
        .cookie(
            Cookie::build("token", token.as_str())
                .max_age(1.days())
                .path(&path)
                .http_only(true)
                .same_site(SameSite::Strict)
                .finish(),
        )
        .json(&login::ServerLoginResponse {
            token: token.as_str().to_owned(),
            refresh_token: None,
            mfa_enrollment_required: mfa_enrollment_pending.then_some(true),
            enrollment_proof: None,
        }))
}

async fn get_refresh_handler<Backend>(
    data: web::Data<AppState<Backend>>,
    request: HttpRequest,
) -> HttpResponse
where
    Backend: TcpBackendHandler + BackendHandler + 'static,
{
    get_refresh(data, request)
        .await
        .unwrap_or_else(error_to_http_response)
}

#[instrument(skip_all, level = "debug")]
async fn get_password_reset_step1<Backend>(
    data: web::Data<AppState<Backend>>,
    request: HttpRequest,
) -> TcpResult<()>
where
    Backend: TcpBackendHandler + BackendHandler + 'static,
{
    let user_string = request
        .match_info()
        .get("user_id")
        .ok_or_else(|| TcpError::BadRequest("Missing user ID".to_string()))?;
    let user_results = data
        .get_readonly_handler()
        .list_users(
            Some(UserRequestFilter::Or(vec![
                UserRequestFilter::UserId(UserId::new(user_string)),
                UserRequestFilter::Equality(UserColumn::Email, user_string.to_owned()),
            ])),
            false,
        )
        .await?;
    // The response stays silent about unknown or disabled accounts; the log does not.
    if user_results.is_empty() {
        logging::record_as(
            None,
            LogKind::PasswordResetRequest,
            Some(user_string),
            false,
            Some("unknown user"),
        );
        return Ok(());
    } else if user_results.len() > 1 {
        logging::record_as(
            None,
            LogKind::PasswordResetRequest,
            Some(user_string),
            false,
            Some("ambiguous user id or email"),
        );
        return Err(TcpError::InternalServerError(
            "Ambiguous user id or email".to_owned(),
        ));
    }
    let user = &user_results[0].user;
    let token = match data
        .get_tcp_handler()
        .start_password_reset(&user.user_id)
        .await?
    {
        None => {
            logging::record_as(
                None,
                LogKind::PasswordResetRequest,
                Some(user.user_id.as_str()),
                false,
                Some("account disabled"),
            );
            return Ok(());
        }
        Some(token) => token,
    };
    if let Err(e) = super::mail::send_password_reset_email(
        user.display_name
            .as_deref()
            .unwrap_or_else(|| user.user_id.as_str()),
        user.user_id.as_str(),
        user.email.as_str(),
        &token,
        &data.server_url,
        &data.mail_options,
    )
    .await
    {
        warn!("Error sending email: {:#?}", e);
        debug!("Reset token: {}", token);
        logging::record_as(
            None,
            LogKind::PasswordResetRequest,
            Some(user.user_id.as_str()),
            false,
            Some("could not send email"),
        );
        return Err(TcpError::InternalServerError(format!(
            "Could not send email: {e}"
        )));
    }
    logging::record_as(
        None,
        LogKind::PasswordResetRequest,
        Some(user.user_id.as_str()),
        true,
        None,
    );
    Ok(())
}

async fn get_password_reset_step1_handler<Backend>(
    data: web::Data<AppState<Backend>>,
    request: HttpRequest,
) -> HttpResponse
where
    Backend: TcpBackendHandler + BackendHandler + 'static,
{
    get_password_reset_step1(data, request)
        .await
        .map(|()| HttpResponse::Ok().finish())
        .unwrap_or_else(error_to_http_response)
}

#[instrument(skip_all, level = "debug")]
async fn get_password_reset_step2<Backend>(
    data: web::Data<AppState<Backend>>,
    request: HttpRequest,
) -> TcpResult<HttpResponse>
where
    Backend: TcpBackendHandler + BackendHandler + 'static,
{
    let token = request
        .match_info()
        .get("token")
        .ok_or_else(|| TcpError::BadRequest("Missing reset token".to_owned()))?;
    let user_id = data
        .get_tcp_handler()
        .get_user_id_for_password_reset_token(token)
        .await
        .map_err(|e| {
            debug!("Reset token error: {e:#}");
            logging::record_as(
                None,
                LogKind::PasswordResetComplete,
                None,
                false,
                Some("wrong or expired reset token"),
            );
            TcpError::NotFoundError("Wrong or expired reset token".to_owned())
        })?;
    let _ = data
        .get_tcp_handler()
        .delete_password_reset_token(token)
        .await;
    logging::record_as(
        Some(&user_id),
        LogKind::PasswordResetComplete,
        None,
        true,
        None,
    );
    let groups = HashSet::new();
    let token = create_jwt(
        data.get_tcp_handler(),
        &data.jwt_key,
        &user_id,
        groups,
        true,
    )
    .await;
    let mut path = data.server_url.path().to_string();
    if !path.ends_with('/') {
        path.push('/');
    };
    Ok(HttpResponse::Ok()
        .cookie(
            Cookie::build("token", token.as_str())
                .max_age(5.minutes())
                // Cookie is only valid to reset the password.
                .path(format!("{path}auth"))
                .http_only(true)
                .same_site(SameSite::Strict)
                .finish(),
        )
        .json(&password_reset::ServerPasswordResetResponse {
            user_id: user_id.to_string(),
            token: token.as_str().to_owned(),
        }))
}

async fn get_password_reset_step2_handler<Backend>(
    data: web::Data<AppState<Backend>>,
    request: HttpRequest,
) -> HttpResponse
where
    Backend: TcpBackendHandler + BackendHandler + 'static,
{
    get_password_reset_step2(data, request)
        .await
        .unwrap_or_else(error_to_http_response)
}

#[instrument(skip_all, level = "debug")]
async fn get_logout<Backend>(
    data: web::Data<AppState<Backend>>,
    request: HttpRequest,
) -> TcpResult<HttpResponse>
where
    Backend: TcpBackendHandler + BackendHandler + 'static,
{
    let (refresh_token_hash, user) = get_refresh_token(request)?;
    let handler = data.get_tcp_handler();
    // Only a token the server holds for this user ends anything; the cookies are cleared anyway.
    if handler.check_token(refresh_token_hash, &user).await? {
        handler.delete_refresh_token(refresh_token_hash).await?;
        let new_blacklisted_jwt_hashes = handler.blacklist_jwts(&user).await?;
        let mut jwt_blacklist = data.jwt_blacklist.write().unwrap();
        for jwt_hash in new_blacklisted_jwt_hashes {
            jwt_blacklist.insert(jwt_hash);
        }
        logging::record_as(Some(&user), LogKind::Logout, None, true, None);
    } else {
        debug!(?user, "The refresh token is not one held for this user");
    }
    let mut path = data.server_url.path().to_string();
    if !path.ends_with('/') {
        path.push('/');
    };
    Ok(HttpResponse::Ok()
        .cookie(
            Cookie::build("token", "")
                .max_age(0.days())
                .path(&path)
                .http_only(true)
                .same_site(SameSite::Strict)
                .finish(),
        )
        .cookie(
            Cookie::build("refresh_token", "")
                .max_age(0.days())
                .path(format!("{path}auth"))
                .http_only(true)
                .same_site(SameSite::Strict)
                .finish(),
        )
        .finish())
}

async fn get_logout_handler<Backend>(
    data: web::Data<AppState<Backend>>,
    request: HttpRequest,
) -> HttpResponse
where
    Backend: TcpBackendHandler + BackendHandler + 'static,
{
    get_logout(data, request)
        .await
        .unwrap_or_else(error_to_http_response)
}

pub(crate) fn error_to_api_response<T, E: Into<TcpError>>(error: E) -> ApiResult<T> {
    ApiResult::Right(error_to_http_response(error.into()))
}

pub type ApiResult<M> = actix_web::Either<web::Json<M>, HttpResponse>;

#[instrument(skip_all, level = "debug")]
async fn opaque_login_start<Backend>(
    data: web::Data<AppState<Backend>>,
    request: web::Json<login::ClientLoginStartRequest>,
) -> ApiResult<login::ServerLoginStartResponse>
where
    Backend: OpaqueHandler + 'static,
{
    data.get_opaque_handler()
        .login_start(request.into_inner())
        .await
        .map(|res| ApiResult::Left(web::Json(res)))
        .unwrap_or_else(error_to_api_response)
}

#[instrument(skip_all, level = "debug")]
async fn get_login_successful_response<Backend>(
    data: &web::Data<AppState<Backend>>,
    name: &UserId,
    mfa_enrollment_pending: bool,
    enrollment_proof: Option<String>,
) -> TcpResult<HttpResponse>
where
    Backend: TcpBackendHandler + BackendHandler,
{
    // The authentication was successful, we need to fetch the groups to create the JWT
    // token.
    let groups = data.get_readonly_handler().get_user_groups(name).await?;
    let (refresh_token, max_age) = data.get_tcp_handler().create_refresh_token(name).await?;
    let token = create_jwt(data.get_tcp_handler(), &data.jwt_key, name, groups, false).await;
    let refresh_token_plus_name = refresh_token + "+" + name.as_str();
    let mut path = data.server_url.path().to_string();
    if !path.ends_with('/') {
        path.push('/');
    };
    Ok(HttpResponse::Ok()
        .cookie(
            Cookie::build("token", token.as_str())
                .max_age(1.days())
                .path(&path)
                .http_only(true)
                .same_site(SameSite::Strict)
                .finish(),
        )
        .cookie(
            Cookie::build("refresh_token", refresh_token_plus_name.clone())
                .max_age(max_age.num_days().days())
                .path(format!("{path}auth"))
                .http_only(true)
                .same_site(SameSite::Strict)
                .finish(),
        )
        .json(&login::ServerLoginResponse {
            token: token.as_str().to_owned(),
            refresh_token: Some(refresh_token_plus_name),
            mfa_enrollment_required: mfa_enrollment_pending.then_some(true),
            enrollment_proof,
        }))
}

#[instrument(skip_all, level = "debug")]
async fn opaque_login_finish<Backend>(
    data: web::Data<AppState<Backend>>,
    request: web::Json<login::ClientLoginFinishRequest>,
) -> TcpResult<HttpResponse>
where
    Backend: TcpBackendHandler + BackendHandler + OpaqueHandler + 'static,
{
    let request = request.into_inner();
    let ask = request.enrollment_proof == Some(true);
    let session = request.session != Some(false);
    let finish = data.get_opaque_handler().login_finish(request);
    let outcome = match session {
        true => finish.await?,
        false => logging::without_session(finish).await?,
    };
    match outcome {
        LoginOutcome::Authenticated {
            user_id,
            mfa_enrollment_pending,
        } => {
            let enrollment_proof = if ask {
                data.get_mfa_handler()
                    .seal_enrollment_proof(&user_id)
                    .await?
            } else {
                None
            };
            if !session {
                return Ok(
                    HttpResponse::Ok().json(&login::ServerLoginVerifiedResponse {
                        verified: true,
                        mfa_enrollment_required: mfa_enrollment_pending.then_some(true),
                        enrollment_proof,
                    }),
                );
            }
            get_login_successful_response(&data, &user_id, mfa_enrollment_pending, enrollment_proof)
                .await
        }
        // The password verified; the client sends the code with a new login.
        LoginOutcome::TotpRequired => {
            Ok(HttpResponse::Ok().json(&login::ServerMfaRequiredResponse { mfa_required: true }))
        }
    }
}

async fn opaque_login_finish_handler<Backend>(
    data: web::Data<AppState<Backend>>,
    request: web::Json<login::ClientLoginFinishRequest>,
) -> HttpResponse
where
    Backend: TcpBackendHandler + BackendHandler + OpaqueHandler + 'static,
{
    opaque_login_finish(data, request)
        .await
        .unwrap_or_else(error_to_http_response)
}

#[instrument(skip_all, level = "debug")]
async fn simple_login<Backend>(
    data: web::Data<AppState<Backend>>,
    request: web::Json<login::ClientSimpleLoginRequest>,
) -> TcpResult<HttpResponse>
where
    Backend: TcpBackendHandler + BackendHandler + OpaqueHandler + LoginHandler + 'static,
{
    let login::ClientSimpleLoginRequest {
        username,
        password,
        enrollment_proof,
    } = request.into_inner();
    let bind_request = BindRequest {
        name: username.clone(),
        password,
    };
    data.get_login_handler().bind(bind_request).await?;
    let enrollment_proof = if enrollment_proof == Some(true) {
        data.get_mfa_handler()
            .seal_enrollment_proof(&username)
            .await?
    } else {
        None
    };
    get_login_successful_response(&data, &username, false, enrollment_proof).await
}

async fn simple_login_handler<Backend>(
    data: web::Data<AppState<Backend>>,
    request: web::Json<login::ClientSimpleLoginRequest>,
) -> HttpResponse
where
    Backend: TcpBackendHandler + BackendHandler + OpaqueHandler + LoginHandler + 'static,
{
    simple_login(data, request)
        .await
        .unwrap_or_else(error_to_http_response)
}

#[instrument(skip_all, level = "debug")]
async fn opaque_register_start<Backend>(
    request: actix_web::HttpRequest,
    payload: actix_web::web::Payload,
    data: web::Data<AppState<Backend>>,
) -> TcpResult<registration::ServerRegistrationStart>
where
    Backend: BackendHandler + OpaqueHandler + 'static,
{
    use actix_web::FromRequest;
    let inner_payload = &mut payload.into_inner();
    let bearer = BearerAuth::from_request(&request, inner_payload).await.ok();
    // A rejected token is recorded by check_if_token_is_valid; only a missing one is not.
    let validation_result = match bearer {
        Some(bearer) => check_if_token_is_valid(&data, bearer.token()).await.ok(),
        None => {
            logging::record_failure(
                LogKind::AccessDenied,
                None,
                "Not authorized to change the user's password",
            );
            None
        }
    }
    .ok_or_else(|| {
        TcpError::UnauthorizedError("Not authorized to change the user's password".to_string())
    })?;
    let registration_start_request =
        web::Json::<registration::ClientRegistrationStartRequest>::from_request(
            &request,
            inner_payload,
        )
        .await
        .map_err(|e| TcpError::BadRequest(format!("{e:#?}")))?
        .into_inner();
    let user_id = &registration_start_request.username;
    let user_is_admin = data
        .get_readonly_handler()
        .get_user_groups(user_id)
        .await?
        .iter()
        .any(|g| g.display_name == "lldap_admin".into());
    if !validation_result.can_change_password(user_id, user_is_admin) {
        logging::record_as(
            Some(&validation_result.user),
            LogKind::AccessDenied,
            Some(user_id.as_str()),
            false,
            Some("Not authorized to change the user's password"),
        );
        return Err(TcpError::UnauthorizedError(
            "Not authorized to change the user's password".to_string(),
        ));
    }
    start_answer(
        data.get_password_handler(),
        registration_start_request,
        settled_state(),
        public_key_der_base64,
    )
    .await
}

async fn start_answer(
    handler: &(impl OpaqueHandler + UserReadableBackendHandler + PolicyBackendHandler),
    request: registration::ClientRegistrationStartRequest,
    state: KerberosState,
    key: impl FnOnce() -> String,
) -> TcpResult<registration::ServerRegistrationStart> {
    let user_id = request.username.clone();
    let kerberos_envelope_key = envelope_key_for(handler, &user_id, state, key).await?;
    let min = min_length_of(handler, &user_id)
        .await
        .map_err(password_change_error)?;
    let response = handler.registration_start(request).await?;
    Ok(registration::ServerRegistrationStart {
        response,
        kerberos_envelope_key,
        password_min_length: Some(min as u32),
    })
}

/// Only a user with Kerberos sync gets the key; anyone else's start answer has none.
async fn envelope_key_for(
    handler: &impl UserReadableBackendHandler,
    user_id: &UserId,
    state: KerberosState,
    key: impl FnOnce() -> String,
) -> TcpResult<Option<String>> {
    match handler.get_user_details(user_id).await {
        Ok(user) if !kerberos_sync_enabled(&user.attributes) => Ok(None),
        Ok(_) => match state {
            KerberosState::Ready => Ok(Some(key())),
            KerberosState::Disabled => Err(refused_change(user_id, synced_without_kerberos())),
            KerberosState::NotReady(cause) => Err(not_ready(user_id, cause)),
        },
        Err(DomainError::EntityNotFound(_)) => Ok(None),
        Err(e) => Err(e.into()),
    }
}

fn synced_without_kerberos() -> String {
    while_disabled(SYNC_OFF_FIRST)
}

fn not_ready(user: &UserId, cause: String) -> TcpError {
    let refused = realm_not_ready(&cause);
    record_failed(LogKind::PasswordChange, user, &refused);
    password_change_error(refused)
}

/// One failure row for a refused change of `user`'s password, and its 400.
fn refused_change(user: &UserId, why: String) -> TcpError {
    logging::record_failure(LogKind::PasswordChange, Some(user.as_str()), &why);
    TcpError::BadRequest(why)
}

async fn opaque_register_start_handler<Backend>(
    request: actix_web::HttpRequest,
    payload: actix_web::web::Payload,
    data: web::Data<AppState<Backend>>,
) -> ApiResult<registration::ServerRegistrationStart>
where
    Backend: BackendHandler + OpaqueHandler + 'static,
{
    opaque_register_start(request, payload, data)
        .await
        .map(|res| ApiResult::Left(web::Json(res)))
        .unwrap_or_else(error_to_api_response)
}

const ENVELOPE_WITHOUT_SYNC: &str =
    "a Kerberos password envelope is taken only for a user with Kerberos sync";
const ENVELOPE_MISSING: &str =
    "a user with Kerberos sync needs the Kerberos password envelope; reload the page and retry";
const ENVELOPE_UNOPENED: &str = "the Kerberos password envelope did not open";
const RESET_FOR_ANOTHER: &str = "Password reset token does not match the registered user";

/// A synced user's sealed password is registered by the server, in one transaction with the keys.
async fn finish_registration<Handler>(
    handler: &Handler,
    reset_user: Option<&UserId>,
    body: registration::ClientRegistrationFinish,
    open: impl FnOnce(&str, &UserId) -> anyhow::Result<Zeroizing<String>>,
) -> TcpResult<UserId>
where
    Handler: OpaqueHandler + UserReadableBackendHandler + PolicyBackendHandler,
{
    let registration::ClientRegistrationFinish {
        request,
        kerberos_password_envelope,
    } = body;
    let user_id = handler.registration_user(&request).await?;
    if reset_user.is_some_and(|reset_user| *reset_user != user_id) {
        logging::record_failure(
            LogKind::AccessDenied,
            Some(user_id.as_str()),
            RESET_FOR_ANOTHER,
        );
        return Err(TcpError::UnauthorizedError(RESET_FOR_ANOTHER.to_string()));
    }
    let user = handler.get_user_details(&user_id).await?;
    let envelope = match (
        kerberos_sync_enabled(&user.attributes),
        kerberos_password_envelope,
    ) {
        (false, None) => {
            let done = finish_plain(handler, &user_id, request).await;
            return done.map_err(password_change_error);
        }
        (false, Some(_)) => {
            warn!("Refused a Kerberos password envelope for {user_id}, who has no Kerberos sync");
            return Err(refused_change(&user_id, ENVELOPE_WITHOUT_SYNC.to_owned()));
        }
        (true, None) => return Err(refused_change(&user_id, ENVELOPE_MISSING.to_owned())),
        (true, Some(envelope)) => match settled_state() {
            KerberosState::Ready => envelope,
            KerberosState::Disabled => {
                return Err(refused_change(&user_id, synced_without_kerberos()));
            }
            KerberosState::NotReady(cause) => return Err(not_ready(&user_id, cause)),
        },
    };
    let min = min_length_of(handler, &user_id)
        .await
        .map_err(password_change_error)?;
    let password = open(&envelope, &user_id).map_err(|e| {
        warn!("A Kerberos password envelope for {user_id} did not open: {e}");
        refused_change(&user_id, format!("{ENVELOPE_UNOPENED}: {e}"))
    })?;
    match finish_synced_registration(handler, &user_id, &password, min).await {
        Ok(()) => {
            info!("Kerberos principal synced for user {user_id}");
            Ok(user_id)
        }
        Err(e) => {
            warn!("Password set for {user_id} failed: {e}");
            Err(password_change_error(e))
        }
    }
}

fn password_change_error(e: PasswordChangeError) -> TcpError {
    match e {
        PasswordChangeError::Refused(_)
        | PasswordChangeError::TooShort(_)
        | PasswordChangeError::HasNul
        | PasswordChangeError::PolicyUnreadable
        | PasswordChangeError::SyncChanged
        | PasswordChangeError::KerberosDisabled(_) => TcpError::BadRequest(e.to_string()),
        PasswordChangeError::InProgress => TcpError::Conflict(e.to_string()),
        PasswordChangeError::Unavailable(cause) => DomainError::KdcUnavailable(cause).into(),
        PasswordChangeError::NoSuchUser => TcpError::NotFoundError(e.to_string()),
        PasswordChangeError::Failed(_) | PasswordChangeError::Unknown => {
            TcpError::InternalServerError(e.to_string())
        }
    }
}

#[instrument(skip_all, level = "debug")]
async fn opaque_register_finish<Backend>(
    http_request: HttpRequest,
    data: web::Data<AppState<Backend>>,
    request: web::Json<registration::ClientRegistrationFinish>,
) -> TcpResult<HttpResponse>
where
    Backend: TcpBackendHandler + BackendHandler + OpaqueHandler + 'static,
{
    use actix_web::FromRequest;
    // The ceremony authenticates itself through server_data; the bearer only names the actor
    // and, after a reset e-mail, marks the registration as a recovery.
    let claims = BearerAuth::from_request(&http_request, &mut actix_web::dev::Payload::None)
        .await
        .ok()
        .and_then(|bearer| verified_claims(&data.jwt_key, bearer.token()));
    let actor = claims.as_ref().map(|claims| UserId::new(&claims.user));
    let reset_user = claims
        .filter(|claims| claims.password_reset)
        .map(|claims| UserId::new(&claims.user));
    with_actor(
        actor.clone(),
        finish_registration(
            data.get_password_handler(),
            reset_user.as_ref(),
            request.into_inner(),
            open_password_envelope,
        ),
    )
    .await?;
    // A recovery clears the second factor only once the new password is committed.
    if let Some(user_id) = reset_user {
        with_actor(
            actor,
            data.get_mfa_handler()
                .reset_user_mfa(&user_id, MfaResetReason::PasswordReset),
        )
        .await?;
    }
    Ok(HttpResponse::Ok().finish())
}

async fn opaque_register_finish_handler<Backend>(
    http_request: HttpRequest,
    data: web::Data<AppState<Backend>>,
    request: web::Json<registration::ClientRegistrationFinish>,
) -> HttpResponse
where
    Backend: TcpBackendHandler + BackendHandler + OpaqueHandler + 'static,
{
    opaque_register_finish(http_request, data, request)
        .await
        .unwrap_or_else(error_to_http_response)
}

pub struct CookieToHeaderTranslatorFactory;

impl<S> Transform<S, ServiceRequest> for CookieToHeaderTranslatorFactory
where
    S: Service<ServiceRequest, Response = ServiceResponse, Error = actix_web::Error>,
    S::Future: 'static,
{
    type Response = ServiceResponse;
    type Error = actix_web::Error;
    type InitError = ();
    type Transform = CookieToHeaderTranslator<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(CookieToHeaderTranslator { service })
    }
}

pub struct CookieToHeaderTranslator<S> {
    service: S,
}

impl<S> Service<ServiceRequest> for CookieToHeaderTranslator<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse, Error = actix_web::Error>,
    S::Future: 'static,
{
    type Response = ServiceResponse;
    type Error = actix_web::Error;
    #[allow(clippy::type_complexity)]
    type Future = Pin<Box<dyn core::future::Future<Output = Result<Self::Response, Self::Error>>>>;

    fn poll_ready(&self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&self, mut req: ServiceRequest) -> Self::Future {
        if let Some(token_cookie) = req.cookie("token") {
            if let Ok(header_value) = actix_http::header::HeaderValue::from_str(&format!(
                "Bearer {}",
                token_cookie.value()
            )) {
                req.headers_mut()
                    .insert(actix_http::header::AUTHORIZATION, header_value);
            } else {
                return async move {
                    Ok(req.error_response(ErrorBadRequest("Invalid token cookie")))
                }
                .boxed_local();
            }
        };

        Box::pin(self.service.call(req))
    }
}

async fn account_is_disabled<Backend: BackendHandler>(
    state: &AppState<Backend>,
    user: &UserId,
) -> bool {
    match state.get_readonly_handler().get_user_groups(user).await {
        Ok(groups) => groups
            .iter()
            .any(|g| g.display_name == "lldap_disabled".into()),
        Err(_) => true,
    }
}

// Signature and expiry only: names the user without the blacklist and disabled-account
// checks, and without recording anything.
fn verified_claims(jwt_key: &Hmac<Sha512>, token_str: &str) -> Option<JWTClaims> {
    let token: Token<_> = VerifyWithKey::verify_with_key(token_str, jwt_key).ok()?;
    (token.claims().exp > Utc::now()).then(|| token.claims().clone())
}

#[instrument(skip_all, level = "debug", err, ret)]
pub(crate) async fn check_if_token_is_valid<Backend: BackendHandler + OpaqueHandler>(
    state: &AppState<Backend>,
    token_str: &str,
) -> Result<ValidationResults, actix_web::Error> {
    let token: Token<_> =
        VerifyWithKey::verify_with_key(token_str, &state.jwt_key).map_err(|_| {
            // Recorded (not terminal-only) so a junk-JWT flood is visible and coalesces.
            logging::record_failure(LogKind::AccessDenied, None, "Invalid JWT");
            ErrorUnauthorized("Invalid JWT")
        })?;
    if token.claims().exp.lt(&Utc::now()) {
        logging::record_failure(LogKind::AccessDenied, None, "Expired JWT");
        return Err(ErrorUnauthorized("Expired JWT"));
    }
    let user = UserId::new(&token.claims().user);
    if token.header().algorithm != jwt::AlgorithmType::Hs512 {
        logging::record_as(
            Some(&user),
            LogKind::AccessDenied,
            None,
            false,
            Some("Unsupported JWT algorithm"),
        );
        return Err(ErrorUnauthorized(format!(
            "Unsupported JWT algorithm: '{:?}'. Supported ones are: ['HS512']",
            token.header().algorithm
        )));
    }
    let jwt_hash = default_hash(token_str);
    if state.jwt_blacklist.read().unwrap().contains(&jwt_hash) {
        logging::record_as(
            Some(&user),
            LogKind::AccessDenied,
            None,
            false,
            Some("JWT was logged out"),
        );
        return Err(ErrorUnauthorized("JWT was logged out"));
    }
    if account_is_disabled(state, &user).await {
        logging::record_as(
            Some(&user),
            LogKind::AccessDenied,
            None,
            false,
            Some("Account disabled"),
        );
        return Err(ErrorUnauthorized("Account disabled"));
    }
    let validation = state.backend_handler.get_permissions_from_groups(
        user,
        token
            .claims()
            .groups
            .iter()
            .map(|s| GroupName::from(s.as_str())),
    );
    if let Some(cause) = refusal_while_degraded(
        &validation.user,
        validation.permission == Permission::Admin,
        kerberos_backend().unavailable(),
    ) {
        return Err(ErrorServiceUnavailable(cause));
    }
    admit_token_use(state.backend_handler.unsafe_get_handler(), &validation.user).await?;
    Ok(validation)
}

const ACCESS_REFUSED: &str = "Access refused";

// The reason is only in the row `admit` writes; the web and simple logins admit in the handler.
async fn admit_refresh<H: BackendHandler + ?Sized>(handler: &H, user: &UserId) -> TcpResult<()> {
    admit(handler, &Attempt::new(user, Door::Refresh))
        .await
        .map_err(|_| refresh_refused(user))
}

fn refresh_refused(user: &UserId) -> TcpError {
    TcpError::DomainError(DomainError::AuthenticationError(format!(
        r#"for user "{user}""#
    )))
}

fn mfa_unreadable(user: &UserId, door: Door, e: &DomainError) {
    warn!(r#"The OU policy of "{user}" could not be read for enable-mfa at {door:?}: {e}"#);
    refuse_unreadable(user, door);
}

/// The session's value and its hold to enrolment; one that cannot be read refuses with its row.
pub(crate) async fn session_mfa<Backend: MfaBackendHandler>(
    state: &AppState<Backend>,
    user: &UserId,
) -> Result<(MfaPolicy, bool), actix_web::Error> {
    let mfa = state.get_mfa_handler();
    let read = async {
        let policy = mfa.mfa_mode(user).await?;
        let pending = policy == MfaPolicy::Always && mfa.enrollment_pending(user).await?;
        Ok::<_, DomainError>((policy, pending))
    };
    read.await.map_err(|e| {
        mfa_unreadable(user, Door::TokenUse, &e);
        ErrorUnauthorized(ACCESS_REFUSED)
    })
}

async fn admit_token_use<H: BackendHandler + ?Sized>(
    handler: &H,
    user: &UserId,
) -> Result<(), actix_web::Error> {
    admit(handler, &Attempt::new(user, Door::TokenUse))
        .await
        .map_err(|_| ErrorUnauthorized(ACCESS_REFUSED))
}

fn is_admin(groups: &HashSet<GroupDetails>) -> bool {
    groups
        .iter()
        .any(|g| g.display_name == "lldap_admin".into())
}

pub fn configure_server<Backend>(cfg: &mut web::ServiceConfig, enable_password_reset: bool)
where
    Backend: TcpBackendHandler + LoginHandler + OpaqueHandler + BackendHandler + 'static,
{
    cfg.service(
        web::resource("/opaque/login/start").route(web::post().to(opaque_login_start::<Backend>)),
    )
    .service(
        web::resource("/opaque/login/finish")
            .route(web::post().to(opaque_login_finish_handler::<Backend>)),
    )
    .service(web::resource("/simple/login").route(web::post().to(simple_login_handler::<Backend>)))
    .service(web::resource("/refresh").route(web::get().to(get_refresh_handler::<Backend>)))
    .service(web::resource("/logout").route(web::get().to(get_logout_handler::<Backend>)))
    .service(
        web::scope("/opaque/register")
            .wrap(CookieToHeaderTranslatorFactory)
            .service(
                web::resource("/start")
                    .route(web::post().to(opaque_register_start_handler::<Backend>)),
            )
            .service(
                web::resource("/finish")
                    .route(web::post().to(opaque_register_finish_handler::<Backend>)),
            ),
    );
    if enable_password_reset {
        cfg.service(
            web::resource("/reset/step1/{user_id}")
                .route(web::post().to(get_password_reset_step1_handler::<Backend>)),
        )
        .service(
            web::resource("/reset/step2/{token}")
                .route(web::get().to(get_password_reset_step2_handler::<Backend>)),
        );
    } else {
        cfg.service(
            web::resource("/reset/step1/{user_id}").route(web::post().to(HttpResponse::NotFound)),
        );
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use lldap_auth::opaque;
    use lldap_domain::types::{Attribute, User};
    use lldap_domain_handlers::instant::{Timestamp, days};
    use lldap_domain_handlers::kerberos::CommitError;
    use lldap_domain_handlers::logging::{Protocol, RequestMeta, with_request};
    use lldap_domain_handlers::password::PASSWORD_MIN_LENGTH;
    use lldap_domain_model::error::{DomainError, Result as DomainResult};
    use lldap_test_utils::enforcement::{EnforcementGuard, SeenAttempt};
    use lldap_test_utils::recording_kerberos::{KerberosOp, RecordingGuard};
    use lldap_test_utils::{MockTestBackendHandler, minimum_entry};
    use mockall::predicate::eq;
    use pretty_assertions::assert_eq;
    use std::cell::Cell;

    mod door_rows;
    mod networks_rows;
    mod start_rows;

    pub(crate) static ONE_BACKEND: std::sync::LazyLock<tokio::sync::Mutex<()>> =
        std::sync::LazyLock::new(|| tokio::sync::Mutex::new(()));

    fn alice(sync: bool) -> User {
        let attributes = sync.then(|| Attribute {
            name: "kerberossync".into(),
            value: 1i64.into(),
        });
        User {
            user_id: UserId::new("alice"),
            attributes: attributes.into_iter().collect(),
            ..User::default()
        }
    }

    fn start_response() -> registration::ServerRegistrationStartResponse {
        let mut rng = rand::rngs::OsRng;
        let start =
            opaque::client::registration::start_registration(b"s3cret-pass", &mut rng).unwrap();
        let response = opaque::server::registration::start_registration(
            &opaque::server::ServerSetup::new(&mut rng),
            start.message,
            &UserId::new("alice"),
        )
        .unwrap()
        .message;
        registration::ServerRegistrationStartResponse {
            server_data: "sealed".to_owned(),
            registration_response: response,
        }
    }

    fn finish_body(envelope: Option<&str>) -> registration::ClientRegistrationFinish {
        registration::ClientRegistrationFinish {
            request: finish_request(),
            kerberos_password_envelope: envelope.map(str::to_owned),
        }
    }

    fn never_opened(_: &str, _: &UserId) -> anyhow::Result<Zeroizing<String>> {
        unreachable!("no envelope was sent")
    }

    // Stands in for the RSA envelope: "for:<user>" opens only for that user.
    fn open_as(
        password: &'static str,
    ) -> impl Fn(&str, &UserId) -> anyhow::Result<Zeroizing<String>> {
        move |envelope, user| match envelope.strip_prefix("for:") {
            Some(sealed_for) if sealed_for == user.as_str() => {
                Ok(Zeroizing::new(password.to_owned()))
            }
            _ => anyhow::bail!("Decryption failed"),
        }
    }

    #[tokio::test]
    async fn test_only_a_synced_user_gets_the_envelope_key() {
        use KerberosState as K;
        let starting = || K::NotReady("starting".to_owned());
        let rows = [
            ("with sync", Ok(true), K::Ready, Ok(Some("the key"))),
            (
                "with sync, Kerberos disabled",
                Ok(true),
                K::Disabled,
                Err(400),
            ),
            (
                "with sync, Kerberos not ready",
                Ok(true),
                starting(),
                Err(503),
            ),
            ("without sync", Ok(false), K::Ready, Ok(None)),
            (
                "without sync, Kerberos disabled",
                Ok(false),
                K::Disabled,
                Ok(None),
            ),
            (
                "without sync, Kerberos not ready",
                Ok(false),
                starting(),
                Ok(None),
            ),
            ("no such user", Err(false), K::Ready, Ok(None)),
            ("the read fails", Err(true), K::Ready, Err(500)),
        ];
        for (row, found, state, expected) in rows {
            let mut mock = MockTestBackendHandler::new();
            mock.expect_get_user_details()
                .with(eq(UserId::new("alice")))
                .times(1)
                .returning(move |_| match found {
                    Ok(sync) => Ok(alice(sync)),
                    Err(false) => Err(DomainError::EntityNotFound("alice".to_owned())),
                    Err(true) => Err(DomainError::InternalError("down".to_owned())),
                });
            let given = Cell::new(false);
            let key = || {
                given.set(true);
                "the key".to_owned()
            };
            let got = envelope_key_for(&mock, &UserId::new("alice"), state, key)
                .await
                .map_err(|e| error_to_http_response(e).status().as_u16());
            assert_eq!(
                given.get(),
                expected == Ok(Some("the key")),
                "{row}: the key made"
            );
            let expected = expected.map(|key| key.map(str::to_owned));
            assert_eq!(got, expected, "{row}");
        }
    }

    #[test]
    fn test_without_a_key_or_an_envelope_the_wire_carries_only_the_minimum() {
        let start = start_response();
        let plain = serde_json::to_value(&start).unwrap();
        let mut keyed = plain.clone();
        keyed["kerberos_envelope_key"] = "the key".into();
        let mut twelve = plain.clone();
        twelve["password_min_length"] = 12.into();
        let mut both = keyed.clone();
        both["password_min_length"] = 12.into();
        let rows = [
            (None, None, plain.clone()),
            (Some("the key"), None, keyed),
            (None, Some(12), twelve),
            (Some("the key"), Some(12), both),
        ];
        for (key, min, wire) in rows {
            let answer = registration::ServerRegistrationStart {
                response: start.clone(),
                kerberos_envelope_key: key.map(str::to_owned),
                password_min_length: min,
            };
            assert_eq!(
                serde_json::to_value(&answer).unwrap(),
                wire,
                "{key:?} {min:?}"
            );
            let read: registration::ServerRegistrationStart =
                serde_json::from_value(wire.clone()).unwrap();
            assert_eq!(
                (
                    read.kerberos_envelope_key.as_deref(),
                    read.password_min_length
                ),
                (key, min),
                "{key:?} {min:?}"
            );
            let upstream: registration::ServerRegistrationStartResponse =
                serde_json::from_value(wire).unwrap();
            assert_eq!(
                serde_json::to_value(&upstream).unwrap(),
                plain,
                "{key:?} {min:?}"
            );
        }
        let request = finish_request();
        let plain = serde_json::to_value(&request).unwrap();
        let mut sealed = plain.clone();
        sealed["kerberos_password_envelope"] = "sealed".into();
        for (envelope, wire) in [(None, plain.clone()), (Some("sealed"), sealed)] {
            let body = registration::ClientRegistrationFinish {
                request: request.clone(),
                kerberos_password_envelope: envelope.map(str::to_owned),
            };
            assert_eq!(serde_json::to_value(&body).unwrap(), wire, "{envelope:?}");
            let read: registration::ClientRegistrationFinish =
                serde_json::from_value(wire.clone()).unwrap();
            assert_eq!(read.kerberos_password_envelope.as_deref(), envelope);
            assert_eq!(serde_json::to_value(read.request).unwrap(), plain);
            let upstream: registration::ClientRegistrationFinishRequest =
                serde_json::from_value(wire).unwrap();
            assert_eq!(serde_json::to_value(upstream).unwrap(), plain);
        }
    }

    fn finish_request() -> registration::ClientRegistrationFinishRequest {
        let mut rng = rand::rngs::OsRng;
        let start =
            opaque::client::registration::start_registration(b"s3cret-pass", &mut rng).unwrap();
        let response = opaque::server::registration::start_registration(
            &opaque::server::ServerSetup::new(&mut rng),
            start.message,
            &UserId::new("alice"),
        )
        .unwrap()
        .message;
        let finish = opaque::client::registration::finish_registration(
            start.state,
            b"s3cret-pass",
            response,
            &mut rng,
        )
        .unwrap();
        registration::ClientRegistrationFinishRequest {
            server_data: "sealed".to_owned(),
            registration_upload: finish.message,
        }
    }

    #[tokio::test]
    async fn test_a_reset_for_another_user_is_refused_before_any_write() {
        let _backend = ONE_BACKEND.lock().await;
        let alice_id = UserId::new("alice");
        let rows = [
            ("no reset token", None, Ok("alice"), Ok(())),
            ("the token's user", Some("alice"), Ok("alice"), Ok(())),
            ("another user", Some("alice"), Ok("bob"), Err(401)),
            ("unsealable", Some("alice"), Err(()), Err(500)),
        ];
        for (row, reset, target, expected) in rows {
            let mut mock = MockTestBackendHandler::new();
            mock.expect_registration_user()
                .times(1)
                .returning(move |_| match target {
                    Ok(user) => Ok(UserId::new(user)),
                    Err(()) => Err(DomainError::InternalError("not sealed".to_owned())),
                });
            let written = usize::from(expected.is_ok());
            mock.expect_get_user_details()
                .times(written)
                .returning(|_| Ok(alice(false)));
            mock.expect_registration_finish()
                .times(written)
                .returning(|_| Ok(UserId::new("alice")));
            let reset = reset.map(UserId::new);
            let got = finish_registration(&mock, reset.as_ref(), finish_body(None), never_opened)
                .await
                .map_err(|e| error_to_http_response(e).status().as_u16());
            assert_eq!(got, expected.map(|()| alice_id.clone()), "{row}");
        }
    }

    // One test, so no other row swaps the process-wide Kerberos backend under it.
    #[tokio::test]
    async fn test_a_synced_users_finish_is_one_transaction_and_takes_only_its_own_envelope() {
        let _backend = ONE_BACKEND.lock().await;
        use lldap_domain_handlers::kerberos::{ANSWER_UNSETTLED, SYNC_CHANGED};
        use lldap_domain_handlers::password::PASSWORD_HAS_NUL;
        use lldap_test_utils::recording_log::LogGuard;
        const OPENED: &str = "Opened-pass-1";
        const REFUSAL: &str = "password policy: min_length 40";
        use lldap_test_utils::recording_kerberos::NotReadyGuard;
        enum Kdc {
            Ready,
            Disabled,
            NotReady,
            Unsettled,
            Refusing,
            Answering(Result<(), CommitError>),
            Holding(CommitError),
        }
        let starting = realm_not_ready("the Kerberos KDC is still starting; retry shortly");
        let starting = starting.to_string();
        let starting = starting.as_str();
        let unsettled = realm_not_ready(ANSWER_UNSETTLED).to_string();
        let refused = Kdc::Answering(Err(CommitError::Refused(REFUSAL.to_owned())));
        let changed = Kdc::Answering(Err(CommitError::Refused(SYNC_CHANGED.to_owned())));
        let failed = Kdc::Answering(Err(CommitError::Failed("the batch".to_owned())));
        let by_kerberos = format!("refused by Kerberos: {REFUSAL}");
        let disabled = synced_without_kerberos();
        type Row<'a> = (
            &'static str,
            bool,
            Option<&'static str>,
            &'static str,
            Kdc,
            u16,
            bool,
            Option<&'a str>,
        );
        let rows: Vec<Row> = vec![
            (
                "no sync, no envelope",
                false,
                None,
                OPENED,
                Kdc::Ready,
                200,
                false,
                None,
            ),
            (
                "no sync, an envelope",
                false,
                Some("for:alice"),
                OPENED,
                Kdc::Ready,
                400,
                false,
                Some(ENVELOPE_WITHOUT_SYNC),
            ),
            (
                "sync, no envelope",
                true,
                None,
                OPENED,
                Kdc::Ready,
                400,
                false,
                Some(ENVELOPE_MISSING),
            ),
            (
                "sync, sealed for bob",
                true,
                Some("for:bob"),
                OPENED,
                Kdc::Ready,
                400,
                false,
                Some("the Kerberos password envelope did not open: Decryption failed"),
            ),
            (
                "sync, Kerberos disabled: never opened",
                true,
                Some("for:alice"),
                OPENED,
                Kdc::Disabled,
                400,
                false,
                Some(disabled.as_str()),
            ),
            (
                "sync, the KDC not ready: never opened",
                true,
                Some("for:alice"),
                OPENED,
                Kdc::NotReady,
                503,
                false,
                Some(starting),
            ),
            (
                "no sync, the KDC not ready: nothing written",
                false,
                None,
                OPENED,
                Kdc::NotReady,
                503,
                false,
                Some(starting),
            ),
            (
                "sync, the last write unsettled: never opened",
                true,
                Some("for:alice"),
                OPENED,
                Kdc::Unsettled,
                503,
                false,
                Some(unsettled.as_str()),
            ),
            (
                "no sync, the last write unsettled: nothing written",
                false,
                None,
                OPENED,
                Kdc::Unsettled,
                503,
                false,
                Some(unsettled.as_str()),
            ),
            (
                "no sync, the switch turned on meanwhile: nothing written",
                false,
                None,
                OPENED,
                Kdc::Holding(CommitError::Refused(SYNC_CHANGED.to_owned())),
                400,
                false,
                Some(SYNC_CHANGED),
            ),
            (
                "sync, too short",
                true,
                Some("for:alice"),
                "Short-7",
                Kdc::Ready,
                400,
                false,
                Some("the password must be at least 8 characters"),
            ),
            (
                "sync, a NUL in nine characters",
                true,
                Some("for:alice"),
                "a\0aaaaaaa",
                Kdc::Ready,
                400,
                false,
                Some(PASSWORD_HAS_NUL),
            ),
            (
                "sync, Kerberos's check refuses",
                true,
                Some("for:alice"),
                OPENED,
                Kdc::Refusing,
                400,
                false,
                Some(by_kerberos.as_str()),
            ),
            (
                "sync, the commit is refused",
                true,
                Some("for:alice"),
                OPENED,
                refused,
                400,
                true,
                Some(by_kerberos.as_str()),
            ),
            (
                "sync, the sync changed before the commit",
                true,
                Some("for:alice"),
                OPENED,
                changed,
                400,
                true,
                Some(SYNC_CHANGED),
            ),
            (
                "sync, the commit fails",
                true,
                Some("for:alice"),
                OPENED,
                failed,
                500,
                true,
                Some("password change failed: the batch"),
            ),
            (
                "sync, committed",
                true,
                Some("for:alice"),
                OPENED,
                Kdc::Ready,
                200,
                true,
                None,
            ),
        ];
        let log = LogGuard::install_on_this_thread();
        let reader = || Some(UserId::new("row-reader"));
        let failures = || -> Vec<(LogKind, Option<String>, Option<String>)> {
            log.recorder()
                .take_events()
                .into_iter()
                .filter(|e| !e.success && e.actor.as_deref() == Some("row-reader"))
                .map(|e| (e.kind, e.target, e.detail))
                .collect()
        };
        let one_row =
            |kind, detail: &str| vec![(kind, Some("alice".to_owned()), Some(detail.to_owned()))];
        for (row, sync, envelope, password, kdc, status, committed, refusal) in rows {
            let opens = !matches!(kdc, Kdc::Disabled | Kdc::NotReady | Kdc::Unsettled);
            let _not_ready = matches!(kdc, Kdc::NotReady).then(NotReadyGuard::install);
            let guard = match &kdc {
                Kdc::Ready => Some(RecordingGuard::install()),
                Kdc::Disabled | Kdc::NotReady => None,
                Kdc::Unsettled => Some(RecordingGuard::install_unsettled(ANSWER_UNSETTLED)),
                Kdc::Refusing => Some(RecordingGuard::install_refusing(REFUSAL)),
                Kdc::Answering(answer) => Some(RecordingGuard::install_answering(answer.clone())),
                Kdc::Holding(held) => Some(RecordingGuard::install_holding(Err(held.clone()))),
            };
            let upstream = !sync && envelope.is_none() && matches!(kdc, Kdc::Ready);
            let mut mock = MockTestBackendHandler::new();
            mock.expect_registration_user()
                .times(1)
                .returning(|_| Ok(UserId::new("alice")));
            mock.expect_get_user_details()
                .with(eq(UserId::new("alice")))
                .times(1)
                .returning(move |_| Ok(alice(sync)));
            mock.expect_registration_finish()
                .times(usize::from(upstream))
                .returning(|_| Ok(UserId::new("alice")));
            mock.expect_bounded_policy_entry()
                .returning(|uid| Ok(minimum_entry(uid, PASSWORD_MIN_LENGTH)));
            let start = start_response();
            mock.expect_registration_start()
                .times(usize::from(committed))
                .returning(move |_| Ok(start.clone()));
            let opened = Cell::new(false);
            let finish = finish_registration(&mock, None, finish_body(envelope), |sealed, user| {
                opened.set(true);
                open_as(password)(sealed, user)
            });
            let got = with_actor(reader(), finish)
                .await
                .map_err(|e| error_to_http_response(e).status().as_u16());
            let expected = match status {
                200 => Ok(UserId::new("alice")),
                status => Err(status),
            };
            assert_eq!(got, expected, "{row}");
            assert_eq!(
                opened.get(),
                sync && envelope.is_some() && opens,
                "{row}: opened"
            );
            let commit = KerberosOp::CommitPassword {
                username: "alice".into(),
                password: password.into(),
                rows: vec![
                    "password alice".into(),
                    "synced alice".into(),
                    "log password_change".into(),
                ],
            };
            let expected_ops = if committed { vec![commit] } else { vec![] };
            let ops = guard.map(|g| g.recorder().take_ops()).unwrap_or_default();
            assert_eq!(ops, expected_ops, "{row}");
            let expected_rows = refusal
                .map(|detail| one_row(LogKind::PasswordChange, detail))
                .unwrap_or_default();
            assert_eq!(failures(), expected_rows, "{row}: one failure row");
        }

        let mut mock = MockTestBackendHandler::new();
        mock.expect_get_user_details()
            .returning(|_| Ok(alice(true)));
        let alice_id = UserId::new("alice");
        let start = envelope_key_for(&mock, &alice_id, KerberosState::Disabled, || unreachable!());
        let start = with_actor(reader(), start)
            .await
            .map_err(|e| error_to_http_response(e).status().as_u16());
        assert_eq!(
            (start, failures()),
            (
                Err(400),
                one_row(LogKind::PasswordChange, disabled.as_str())
            ),
            "the start with Kerberos disabled: refused, no key, one row"
        );

        let ready = RecordingGuard::install();
        let mut mock = MockTestBackendHandler::new();
        mock.expect_registration_user()
            .returning(|_| Ok(UserId::new("alice")));
        mock.expect_get_user_details()
            .returning(|_| Ok(alice(false)));
        mock.expect_registration_finish()
            .times(1)
            .returning(|_| Err(DomainError::InternalError("the disk is full".to_owned())));
        let stored = finish_registration(&mock, None, finish_body(None), never_opened);
        let stored = with_actor(reader(), stored)
            .await
            .map_err(|e| error_to_http_response(e).status().as_u16());
        let full = "password change failed: Internal error: `the disk is full`";
        assert_eq!(
            (stored, failures()),
            (Err(500), one_row(LogKind::PasswordChange, full)),
            "the plain store fails: one row"
        );
        drop(ready);

        let mut mock = MockTestBackendHandler::new();
        mock.expect_registration_user()
            .returning(|_| Ok(UserId::new("alice")));
        mock.expect_get_user_details().times(0);
        let bob = UserId::new("bob");
        let reset = finish_registration(&mock, Some(&bob), finish_body(None), never_opened);
        let reset = with_actor(reader(), reset)
            .await
            .map_err(|e| error_to_http_response(e).status().as_u16());
        assert_eq!(
            (reset, failures()),
            (Err(401), one_row(LogKind::AccessDenied, RESET_FOR_ANOTHER)),
            "a reset for another user: refused, one row"
        );
    }

    #[test]
    fn test_a_password_change_error_answers_its_status() {
        let rows = [
            (PasswordChangeError::Refused("policy".to_owned()), 400),
            (PasswordChangeError::TooShort(8), 400),
            (PasswordChangeError::TooShort(12), 400),
            (PasswordChangeError::HasNul, 400),
            (PasswordChangeError::PolicyUnreadable, 400),
            (PasswordChangeError::SyncChanged, 400),
            (PasswordChangeError::KerberosDisabled("off".to_owned()), 400),
            (PasswordChangeError::InProgress, 409),
            (PasswordChangeError::Unavailable("down".to_owned()), 503),
            (PasswordChangeError::NoSuchUser, 404),
            (PasswordChangeError::Failed("the batch".to_owned()), 500),
            (PasswordChangeError::Unknown, 500),
        ];
        for (error, status) in rows {
            let text = error.to_string();
            let response = error_to_http_response(password_change_error(error));
            assert_eq!(response.status().as_u16(), status, "{text}");
        }
        assert_eq!(
            PasswordChangeError::TooShort(PASSWORD_MIN_LENGTH).to_string(),
            "the password must be at least 8 characters"
        );
    }

    #[tokio::test]
    async fn test_a_synced_finish_asks_the_users_minimum_before_it_opens_the_envelope() {
        let _backend = ONE_BACKEND.lock().await;
        use lldap_test_utils::recording_log::LogGuard;
        const ELEVEN: &str = "Eleven-11ch";
        const TWELVE: &str = "Twelve-12chr";
        type Row = (Option<usize>, &'static str, u16, bool, Option<&'static str>);
        let rows: [Row; 3] = [
            (
                Some(12),
                ELEVEN,
                400,
                true,
                Some("the password must be at least 12 characters"),
            ),
            (Some(12), TWELVE, 200, true, None),
            (
                None,
                TWELVE,
                400,
                false,
                Some("the password policy could not be read; try again"),
            ),
        ];
        assert_eq!((ELEVEN.chars().count(), TWELVE.chars().count()), (11, 12));
        let log = LogGuard::install_on_this_thread();
        for (min, password, status, opens, refusal) in rows {
            let guard = RecordingGuard::install();
            let committed = status == 200;
            let mut mock = MockTestBackendHandler::new();
            mock.expect_registration_user()
                .times(1)
                .returning(|_| Ok(UserId::new("alice")));
            mock.expect_get_user_details()
                .with(eq(UserId::new("alice")))
                .times(1)
                .returning(|_| Ok(alice(true)));
            mock.expect_bounded_policy_entry()
                .with(eq(UserId::new("alice")))
                .times(1)
                .returning(move |uid| {
                    let entry = min.map(|min| minimum_entry(uid, min));
                    entry.ok_or_else(|| DomainError::InternalError("down".to_owned()))
                });
            mock.expect_registration_finish().times(0);
            let start = start_response();
            mock.expect_registration_start()
                .times(usize::from(committed))
                .returning(move |_| Ok(start.clone()));
            let opened = Cell::new(false);
            let finish =
                finish_registration(&mock, None, finish_body(Some("for:alice")), |e, u| {
                    opened.set(true);
                    open_as(password)(e, u)
                });
            let got = finish
                .await
                .map_err(|e| error_to_http_response(e).status().as_u16());
            let ops = guard.recorder().take_ops().len();
            let rows: Vec<_> = log
                .recorder()
                .take_events()
                .into_iter()
                .filter(|e| e.kind == LogKind::PasswordChange && !e.success)
                .map(|e| (e.target, e.detail))
                .collect();
            let expected = match status {
                200 => Ok(UserId::new("alice")),
                status => Err(status),
            };
            let one_row = refusal.map(|text| (Some("alice".to_owned()), Some(text.to_owned())));
            assert_eq!(
                (got, opened.get(), ops, rows),
                (
                    expected,
                    opens,
                    usize::from(committed),
                    one_row.into_iter().collect::<Vec<_>>()
                ),
                "{min:?} {password}"
            );
        }
    }

    #[tokio::test]
    async fn test_every_start_answers_the_users_minimum_and_an_unreadable_one_refuses() {
        let _backend = ONE_BACKEND.lock().await;
        use lldap_test_utils::recording_log::LogGuard;
        type Answer = Result<(Option<&'static str>, Option<u32>), (u16, &'static str)>;
        let rows: [(&str, bool, Option<usize>, Answer); 4] = [
            ("without sync, 12", false, Some(12), Ok((None, Some(12)))),
            ("without sync, 8", false, Some(8), Ok((None, Some(8)))),
            (
                "with sync, 12",
                true,
                Some(12),
                Ok((Some("the key"), Some(12))),
            ),
            (
                "unreadable",
                false,
                None,
                Err((
                    400,
                    "Bad request: `the password policy could not be read; try again`",
                )),
            ),
        ];
        let log = LogGuard::install_on_this_thread();
        for (row, sync, min, expected) in rows {
            let mut mock = MockTestBackendHandler::new();
            mock.expect_get_user_details()
                .with(eq(UserId::new("alice")))
                .times(1)
                .returning(move |_| Ok(alice(sync)));
            mock.expect_bounded_policy_entry()
                .with(eq(UserId::new("alice")))
                .times(1)
                .returning(move |uid| {
                    let entry = min.map(|min| minimum_entry(uid, min));
                    entry.ok_or_else(|| DomainError::InternalError("down".to_owned()))
                });
            let start = start_response();
            mock.expect_registration_start()
                .times(usize::from(expected.is_ok()))
                .returning(move |_| Ok(start.clone()));
            let mut rng = rand::rngs::OsRng;
            let request = registration::ClientRegistrationStartRequest {
                username: UserId::new("alice"),
                registration_start_request: opaque::client::registration::start_registration(
                    b"s3cret-pass",
                    &mut rng,
                )
                .unwrap()
                .message,
            };
            let got = start_answer(&mock, request, KerberosState::Ready, || {
                "the key".to_owned()
            })
            .await
            .map(|answer| (answer.kerberos_envelope_key, answer.password_min_length))
            .map_err(|e| {
                let text = e.to_string();
                (error_to_http_response(e).status().as_u16(), text)
            });
            let rows: Vec<_> = log
                .recorder()
                .take_events()
                .into_iter()
                .filter(|e| e.kind == LogKind::PasswordChange && !e.success)
                .map(|e| (e.target, e.detail))
                .collect();
            let one_row = expected.is_err().then(|| {
                (
                    Some("alice".to_owned()),
                    Some("the password policy could not be read; try again".to_owned()),
                )
            });
            let expected = expected
                .map(|(key, min)| (key.map(str::to_owned), min))
                .map_err(|(status, text)| (status, text.to_owned()));
            assert_eq!(
                (got, rows),
                (expected, one_row.into_iter().collect::<Vec<_>>()),
                "{row}"
            );
        }
    }

    #[async_trait::async_trait]
    impl TcpBackendHandler for MockTestBackendHandler {
        async fn get_jwt_blacklist(&self) -> anyhow::Result<HashSet<u64>> {
            unimplemented!()
        }
        async fn create_refresh_token(
            &self,
            _: &UserId,
        ) -> DomainResult<(String, chrono::Duration)> {
            unimplemented!()
        }
        async fn register_jwt(&self, _: &UserId, _: u64, _: NaiveDateTime) -> DomainResult<()> {
            Ok(())
        }
        async fn check_token(&self, _: u64, _: &UserId) -> DomainResult<bool> {
            Ok(true)
        }
        async fn blacklist_jwts(&self, _: &UserId) -> DomainResult<HashSet<u64>> {
            unimplemented!()
        }
        async fn delete_refresh_token(&self, _: u64) -> DomainResult<()> {
            unimplemented!()
        }
        async fn start_password_reset(&self, _: &UserId) -> DomainResult<Option<String>> {
            unimplemented!()
        }
        async fn get_user_id_for_password_reset_token(&self, _: &str) -> DomainResult<UserId> {
            unimplemented!()
        }
        async fn delete_password_reset_token(&self, _: &str) -> DomainResult<()> {
            unimplemented!()
        }
    }

    pub(crate) fn app_state<B: BackendHandler + lldap_opaque_handler::OpaqueHandler>(
        backend: B,
    ) -> web::Data<AppState<B>> {
        use hmac::Mac;
        web::Data::new(AppState {
            backend_handler: lldap_access_control::AccessControlledBackendHandler::new(backend),
            jwt_key: Hmac::new_from_slice(b"a test secret").unwrap(),
            jwt_blacklist: std::sync::RwLock::new(HashSet::new()),
            server_url: url::Url::parse("http://localhost").unwrap(),
            assets_path: std::path::PathBuf::new(),
            mail_options: crate::configuration::MailOptionsBuilder::default()
                .build()
                .unwrap(),
            mfa_policy: None,
            domain: "example.com".to_owned(),
            keycloak: std::sync::Arc::new(lldap_keycloak::KeycloakSettings {
                base_dn: "dc=example,dc=com".to_owned(),
                config_file: std::path::PathBuf::new(),
                admin_pass: None,
            }),
        })
    }

    fn reset_token(key: &Hmac<Sha512>, user: &str) -> String {
        let claims = JWTClaims {
            exp: Utc::now() + chrono::Duration::hours(1),
            iat: Utc::now(),
            jti: Uuid::new_v4(),
            user: user.to_owned(),
            groups: HashSet::new(),
            password_reset: true,
        };
        let header = jwt::Header {
            algorithm: jwt::AlgorithmType::Hs512,
            ..Default::default()
        };
        jwt::Token::new(header, claims)
            .sign_with_key(key)
            .unwrap()
            .as_str()
            .to_owned()
    }

    #[actix_web::test]
    async fn test_the_finish_route_refuses_a_reset_for_another_user_before_any_write() {
        let _backend = ONE_BACKEND.lock().await;
        for (sealed_for, status, writes) in [("alice", 200, 1), ("bob", 401, 0)] {
            let mut mock = MockTestBackendHandler::new();
            mock.expect_registration_user()
                .times(1)
                .returning(move |_| Ok(UserId::new(sealed_for)));
            mock.expect_get_user_details()
                .times(writes)
                .returning(|_| Ok(alice(false)));
            mock.expect_registration_finish()
                .times(writes)
                .returning(|_| Ok(UserId::new("alice")));
            mock.expect_reset_user_mfa()
                .times(writes)
                .returning(|_, _| Ok(()));
            let state = app_state(mock);
            let token = reset_token(&state.jwt_key, "alice");
            let request = actix_web::test::TestRequest::post()
                .insert_header(("Authorization", format!("Bearer {token}")))
                .to_http_request();
            let response =
                opaque_register_finish_handler(request, state, web::Json(finish_body(None))).await;
            assert_eq!(
                response.status().as_u16(),
                status,
                "sealed for {sealed_for}"
            );
        }
    }

    /// A directory on SQLite with these users and their passwords, as the server keeps it.
    pub(crate) async fn sql_handler_with(
        users: &[(&str, &str)],
    ) -> lldap_sql_backend_handler::SqlBackendHandler {
        use lldap_domain_handlers::handler::UserBackendHandler;
        let mut options = sea_orm::ConnectOptions::new("sqlite::memory:".to_owned());
        options.max_connections(1);
        let pool = sea_orm::Database::connect(options).await.unwrap();
        lldap_sql_backend_handler::sql_tables::init_table(&pool)
            .await
            .unwrap();
        crate::jwt_sql_tables::init_table(&pool).await.unwrap();
        let key = opaque::server::generate_random_private_key();
        let handler = lldap_sql_backend_handler::SqlBackendHandler::new(key, pool);
        for (user, password) in users {
            let request = lldap_domain::requests::CreateUserRequest {
                user_id: UserId::new(user),
                email: format!("{user}@example.com").into(),
                ..Default::default()
            };
            handler.create_user(request).await.unwrap();
            let id = UserId::new(user);
            lldap_opaque_handler::register_password(&handler, id, password.as_bytes())
                .await
                .unwrap();
        }
        handler
    }

    pub(crate) struct PinnedEnrollmentClock;

    impl Drop for PinnedEnrollmentClock {
        fn drop(&mut self) {
            lldap_sql_backend_handler::set_enrollment_clock(None);
        }
    }

    /// e3plain, e3off in `lldap_disabled` and e3code enrolled, each with its own password. The
    /// code is one e3code's next sign-in accepts.
    pub(crate) async fn doors_directory() -> (
        lldap_sql_backend_handler::SqlBackendHandler,
        PinnedEnrollmentClock,
        String,
    ) {
        use lldap_domain_handlers::handler::{GroupBackendHandler, UserBackendHandler};
        let users = [
            ("e3plain", "e3plain-pass-1"),
            ("e3off", "e3off-pass-1"),
            ("e3code", "e3code-pass-1"),
        ];
        let handler = sql_handler_with(&users)
            .await
            .with_mfa_policy(MfaPolicy::Enrolled);
        let disabled = lldap_domain::requests::CreateGroupRequest {
            display_name: "lldap_disabled".into(),
            ..Default::default()
        };
        let disabled = handler.create_group(disabled).await.unwrap();
        handler
            .add_user_to_group(&UserId::new("e3off"), disabled)
            .await
            .unwrap();
        let now = Utc::now().timestamp();
        lldap_sql_backend_handler::set_enrollment_clock(Some(now));
        let clock = PinnedEnrollmentClock;
        let (now, id) = (now as u64, UserId::new("e3code"));
        let proof = handler.seal_enrollment_proof(&id).await.unwrap().unwrap();
        let start = handler
            .start_totp_enrollment(&id, None, Some(proof))
            .await
            .unwrap();
        let seed = lldap_mfa::seed_from_base32(&start.secret_base32).unwrap();
        let code_at = |t: u64| lldap_mfa::format_code(lldap_mfa::totp_code(&seed, t).unwrap());
        let spent = code_at(now);
        handler
            .finish_totp_enrollment(&id, &start.state, &spent)
            .await
            .unwrap();
        let code = [code_at(now + 30), code_at(now - 30)]
            .into_iter()
            .find(|c| *c != spent)
            .unwrap();
        (handler, clock, code)
    }

    #[tokio::test]
    async fn test_a_simple_login_with_no_password_answers_as_any_failure_and_mints_nothing() {
        use lldap_test_utils::recording_log::LogGuard;
        let _backend = ONE_BACKEND.lock().await;
        let _guard = EnforcementGuard::none();
        let (handler, _clock, code) = doors_directory().await;
        let pool = handler.pool().clone();
        let state = app_state(handler);
        let mut options = sea_orm::ConnectOptions::new("sqlite::memory:".to_owned());
        options.max_connections(1);
        let db = sea_orm::Database::connect(options).await.unwrap();
        let key = opaque::server::generate_random_private_key();
        let no_tables = app_state(lldap_sql_backend_handler::SqlBackendHandler::new(key, db));
        let log = LogGuard::install_on_this_thread();
        let failed = |user: &str| format!("`Authentication error for user \"{user}\"`");
        type Case = (
            String,
            bool,
            &'static str,
            String,
            u16,
            String,
            Option<(bool, Option<&'static str>)>,
        );
        let mut cases: Vec<Case> = Vec::new();
        let names = [
            ("a user", "e3plain"),
            ("a disabled user", "e3off"),
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
                        401,
                        failed(user),
                        Some((false, Some("no password given"))),
                    ));
                }
            }
        }
        cases.extend([
            (
                "control: a user, a wrong password".to_owned(),
                false,
                "e3plain",
                "e3plain-wrong-1".to_owned(),
                401,
                failed("e3plain"),
                Some((false, Some("invalid credentials"))),
            ),
            (
                "control: a disabled user, the password".to_owned(),
                false,
                "e3off",
                "e3off-pass-1".to_owned(),
                401,
                failed("e3off"),
                Some((false, Some("account disabled"))),
            ),
            (
                "control: an enrolled user, the password alone".to_owned(),
                false,
                "e3code",
                "e3code-pass-1".to_owned(),
                401,
                "`Authentication error TOTP code required for user \"e3code\"`".to_owned(),
                Some((false, Some("totp code required"))),
            ),
            (
                "control: an unknown name, a password".to_owned(),
                false,
                "e3nobody",
                "e3plain-wrong-1".to_owned(),
                401,
                failed("e3nobody"),
                Some((false, Some("unknown user"))),
            ),
            (
                "control: a password, no tables".to_owned(),
                true,
                "e3plain",
                "e3plain-pass-1".to_owned(),
                500,
                "<database error>".to_owned(),
                None,
            ),
            (
                "control: a user, the password".to_owned(),
                false,
                "e3plain",
                "e3plain-pass-1".to_owned(),
                200,
                "<session>".to_owned(),
                Some((true, None)),
            ),
        ]);
        let (mut got, mut wanted) = (Vec::new(), Vec::new());
        for (label, bare, user, password, status, body, row) in cases {
            let door = if bare { &no_tables } else { &state };
            let before = minted(&pool).await;
            let request = login::ClientSimpleLoginRequest {
                username: UserId::new(user),
                password,
                enrollment_proof: None,
            };
            let response = simple_login_handler(door.clone(), web::Json(request)).await;
            let got_status = response.status().as_u16();
            let cookies = response.cookies().count();
            let bytes = actix_web::body::to_bytes(response.into_body())
                .await
                .unwrap();
            let got_body = match got_status {
                200 => "<session>".to_owned(),
                500 => "<database error>".to_owned(),
                _ => String::from_utf8_lossy(&bytes).into_owned(),
            };
            let rows: Vec<_> = log
                .recorder()
                .take_events()
                .into_iter()
                .filter(|e| e.actor.as_deref() == Some(user))
                .map(|e| (e.kind, e.success, e.detail))
                .collect();
            let (cookies_wanted, minted_wanted) = match status {
                200 => (2_usize, (before.0 + 1, before.1 + 1)),
                _ => (0, before),
            };
            let row =
                row.map(|(success, detail)| (LogKind::Bind, success, detail.map(str::to_owned)));
            got.push((
                label.clone(),
                got_status,
                got_body,
                cookies,
                minted(&pool).await,
                rows,
            ));
            wanted.push((
                label,
                status,
                body,
                cookies_wanted,
                minted_wanted,
                Vec::from_iter(row),
            ));
        }
        assert_eq!(
            got, wanted,
            "per row: status, body, cookies, minted tokens, its one row"
        );
    }

    #[tokio::test]
    async fn test_a_policy_refusal_at_the_web_and_simple_login_routes_is_one_row_with_its_peer() {
        use lldap_test_utils::recording_log::LogGuard;
        const PASSWORD: &str = "e0route-pass-1";
        let _backend = ONE_BACKEND.lock().await;
        let handler = sql_handler_with(&[("e0route", PASSWORD)]).await;
        let log = LogGuard::install_on_this_thread();
        let _guard = EnforcementGuard::refusing(&["e0route"], "login-hours");
        let state = app_state(handler);
        let user = UserId::new("e0route");
        let rows = [
            ("the simple login", "192.0.2.61", LogKind::Bind, (401, None)),
            (
                "the web login",
                "192.0.2.62",
                LogKind::Login,
                (200, Some(false)),
            ),
        ];
        for (label, peer, kind, answer) in rows {
            let meta = RequestMeta::http(Some(peer.parse().unwrap()), None);
            let status = with_request(meta, async {
                if kind == LogKind::Bind {
                    let request = login::ClientSimpleLoginRequest {
                        username: user.clone(),
                        password: PASSWORD.to_owned(),
                        enrollment_proof: None,
                    };
                    let response = simple_login_handler(state.clone(), web::Json(request)).await;
                    return (response.status().as_u16(), None);
                }
                let (status, _, finishes) =
                    login_start_answer(&state, user.as_str(), PASSWORD).await;
                (status, Some(finishes))
            })
            .await;
            let rows: Vec<_> = log
                .recorder()
                .take_events()
                .into_iter()
                .filter(|e| e.actor.as_deref() == Some("e0route"))
                .map(|e| (e.kind, e.success, e.peer, e.detail))
                .collect();
            let refused = (
                kind,
                false,
                Some(peer.to_owned()),
                Some("policy: login-hours".to_owned()),
            );
            assert_eq!(
                (status, rows),
                (answer, vec![refused]),
                "{label}: the route's status, whether the sign-in can finish, the one row"
            );
        }
    }

    async fn login_started<B: BackendHandler + OpaqueHandler>(
        state: &web::Data<AppState<B>>,
        user: &str,
        password: &str,
    ) -> (
        opaque::client::login::ClientLogin,
        login::ServerLoginStartResponse,
    ) {
        let mut rng = rand::rngs::OsRng;
        let start = opaque::client::login::start_login(password, &mut rng).unwrap();
        let started = state
            .get_opaque_handler()
            .login_start(login::ClientLoginStartRequest {
                username: UserId::new(user),
                login_start_request: start.message,
            })
            .await
            .unwrap();
        (start.state, started)
    }

    async fn login_finish_request<B: BackendHandler + OpaqueHandler>(
        state: &web::Data<AppState<B>>,
        user: &str,
        password: &str,
    ) -> login::ClientLoginFinishRequest {
        let (client, started) = login_started(state, user, password).await;
        let finish = opaque::client::login::finish_login(
            client,
            password.as_bytes(),
            started.credential_response,
            &mut rand::rngs::OsRng,
        )
        .unwrap();
        login::ClientLoginFinishRequest {
            server_data: started.server_data,
            credential_finalization: finish.message,
            totp_code: None,
            enrollment_proof: None,
            session: None,
        }
    }

    /// The start route's status and body keys, and whether the sign-in can then finish.
    async fn login_start_answer<B: BackendHandler + OpaqueHandler + 'static>(
        state: &web::Data<AppState<B>>,
        user: &str,
        password: &str,
    ) -> (u16, Vec<String>, bool) {
        let mut rng = rand::rngs::OsRng;
        let start = opaque::client::login::start_login(password, &mut rng).unwrap();
        let request = login::ClientLoginStartRequest {
            username: UserId::new(user),
            login_start_request: start.message,
        };
        match opaque_login_start(state.clone(), web::Json(request)).await {
            actix_web::Either::Left(web::Json(started)) => {
                let body = serde_json::to_value(&started).unwrap();
                let keys = body.as_object().unwrap().keys().cloned().collect();
                let finished = opaque::client::login::finish_login(
                    start.state,
                    password.as_bytes(),
                    started.credential_response,
                    &mut rng,
                );
                (200, keys, finished.is_ok())
            }
            actix_web::Either::Right(response) => (response.status().as_u16(), vec![], false),
        }
    }

    /// Refresh-token rows and registered JWTs.
    async fn minted(pool: &sea_orm::DatabaseConnection) -> (u64, u64) {
        use lldap_domain_model::model::{JwtRefreshStorage, JwtStorage};
        use sea_orm::{EntityTrait, PaginatorTrait};
        (
            JwtRefreshStorage::find().count(pool).await.unwrap(),
            JwtStorage::find().count(pool).await.unwrap(),
        )
    }

    #[tokio::test]
    async fn test_a_finish_without_a_session_mints_nothing_in_any_outcome() {
        use lldap_test_utils::recording_log::LogGuard;
        use serde_json::json;
        const BOB_PASS: &str = "q1bob-pass-1";
        const KIM_PASS: &str = "q1kim-pass-1";
        let _backend = ONE_BACKEND.lock().await;
        let _guard = EnforcementGuard::none();
        let handler = sql_handler_with(&[("q1bob", BOB_PASS), ("q1kim", KIM_PASS)])
            .await
            .with_mfa_policy(lldap_domain_handlers::mfa::MfaPolicy::Enrolled);
        struct ClockOnThisThread;
        impl Drop for ClockOnThisThread {
            fn drop(&mut self) {
                lldap_sql_backend_handler::set_enrollment_clock(None);
            }
        }
        let now = Utc::now().timestamp();
        lldap_sql_backend_handler::set_enrollment_clock(Some(now));
        let _clock = ClockOnThisThread;
        let now = now as u64;
        let kim = UserId::new("q1kim");
        let proof = handler.seal_enrollment_proof(&kim).await.unwrap().unwrap();
        let start = handler
            .start_totp_enrollment(&kim, None, Some(proof))
            .await
            .unwrap();
        let seed = lldap_mfa::seed_from_base32(&start.secret_base32).unwrap();
        let code_at = |t: u64| lldap_mfa::format_code(lldap_mfa::totp_code(&seed, t).unwrap());
        let spent = code_at(now);
        handler
            .finish_totp_enrollment(&kim, &start.state, &spent)
            .await
            .unwrap();
        let valid = [code_at(now - 30), spent.clone(), code_at(now + 30)];
        let fresh = valid.iter().find(|c| **c != spent).unwrap().clone();
        let wrong = (0..)
            .map(|c| format!("{c:06}"))
            .find(|c| !valid.contains(c))
            .unwrap();
        let pool = handler.pool().clone();
        let state = app_state(handler);
        let log = LogGuard::install_on_this_thread();

        let (first, first_started) = login_started(&state, "q1bob", BOB_PASS).await;
        let crossed = opaque::client::login::finish_login(
            first,
            BOB_PASS.as_bytes(),
            first_started.credential_response,
            &mut rand::rngs::OsRng,
        )
        .unwrap()
        .message;
        let check = |request: login::ClientLoginFinishRequest| login::ClientLoginFinishRequest {
            session: Some(false),
            ..request
        };
        let rows = [
            (
                "verified",
                check(login_finish_request(&state, "q1bob", BOB_PASS).await),
                200,
                json!({"verified": true}),
            ),
            (
                "verified, a proof asked",
                login::ClientLoginFinishRequest {
                    enrollment_proof: Some(true),
                    ..check(login_finish_request(&state, "q1bob", BOB_PASS).await)
                },
                200,
                json!({"verified": true, "enrollmentProof": "<proof>"}),
            ),
            (
                "second factor required",
                check(login_finish_request(&state, "q1kim", KIM_PASS).await),
                200,
                json!({"mfaRequired": true}),
            ),
            (
                "refused at the second factor",
                login::ClientLoginFinishRequest {
                    totp_code: Some(wrong),
                    ..check(login_finish_request(&state, "q1kim", KIM_PASS).await)
                },
                401,
                json!(null),
            ),
            (
                "refused at the password",
                login::ClientLoginFinishRequest {
                    credential_finalization: crossed,
                    ..check(login_finish_request(&state, "q1bob", BOB_PASS).await)
                },
                401,
                json!(null),
            ),
            (
                "an enrolled user's code verified, a proof asked",
                login::ClientLoginFinishRequest {
                    totp_code: Some(fresh),
                    enrollment_proof: Some(true),
                    ..check(login_finish_request(&state, "q1kim", KIM_PASS).await)
                },
                200,
                json!({"verified": true}),
            ),
        ];
        for (label, request, status, expected) in rows {
            let before = minted(&pool).await;
            let response = opaque_login_finish_handler(state.clone(), web::Json(request)).await;
            let got_status = response.status().as_u16();
            let cookies = response.cookies().count();
            let bytes = actix_web::body::to_bytes(response.into_body())
                .await
                .unwrap();
            let mut body: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or_default();
            if body["enrollmentProof"].is_string() {
                body["enrollmentProof"] = json!("<proof>");
            }
            assert_eq!(
                (got_status, cookies, minted(&pool).await),
                (status, 0, before),
                "{label}: no cookie, no refresh-token row, no JWT row"
            );
            if status == 200 {
                assert_eq!(body, expected, "{label}");
            }
        }

        let before = minted(&pool).await;
        let response = opaque_login_finish_handler(
            state.clone(),
            web::Json(login_finish_request(&state, "q1bob", BOB_PASS).await),
        )
        .await;
        assert_eq!(
            (response.status().as_u16(), response.cookies().count()),
            (200, 2),
            "the same finish with a session"
        );
        assert_eq!(minted(&pool).await, (before.0 + 1, before.1 + 1));

        let rows: Vec<_> = log
            .recorder()
            .take_events()
            .into_iter()
            .filter(|e| e.kind == LogKind::Login)
            .map(|e| (e.actor, e.success, e.detail))
            .collect();
        let row = |user: &str, success, detail: Option<&str>| {
            (Some(user.to_owned()), success, detail.map(str::to_owned))
        };
        assert_eq!(
            rows,
            vec![
                row("q1bob", true, Some("no session")),
                row("q1bob", true, Some("no session")),
                row("q1kim", false, Some("totp code required; no session")),
                row("q1kim", false, Some("invalid totp; no session")),
                row("q1bob", false, Some("invalid credentials; no session")),
                row("q1kim", true, Some("totp; no session")),
                row("q1bob", true, None),
            ],
            "one row per finish, each sessionless one saying so"
        );
    }

    struct DegradedOnThisThread;

    impl Drop for DegradedOnThisThread {
        fn drop(&mut self) {
            lldap_domain_handlers::kerberos::set_thread_kerberos_backend(None);
        }
    }

    #[tokio::test]
    async fn test_a_finish_without_a_session_refused_while_kerberos_is_down_mints_nothing() {
        use lldap_domain_handlers::kerberos::{
            ADMINS_ONLY, DegradedKerberos, set_thread_kerberos_backend,
        };
        use lldap_test_utils::recording_log::LogGuard;
        const PASS: &str = "q1down-pass-1";
        let _backend = ONE_BACKEND.lock().await;
        let _guard = EnforcementGuard::none();
        let handler = sql_handler_with(&[("q1down", PASS)]).await;
        let pool = handler.pool().clone();
        let state = app_state(handler);
        let log = LogGuard::install_on_this_thread();
        let request = login::ClientLoginFinishRequest {
            enrollment_proof: Some(true),
            session: Some(false),
            ..login_finish_request(&state, "q1down", PASS).await
        };
        let degraded = DegradedKerberos::new("EXAMPLE.COM".to_owned(), "down".to_owned());
        set_thread_kerberos_backend(Some(std::sync::Arc::new(degraded)));
        let _restore = DegradedOnThisThread;
        let before = minted(&pool).await;
        let response = opaque_login_finish_handler(state.clone(), web::Json(request)).await;
        let status = response.status().as_u16();
        let cookies = response.cookies().count();
        let bytes = actix_web::body::to_bytes(response.into_body())
            .await
            .unwrap();
        let body = String::from_utf8_lossy(&bytes);
        assert_eq!(
            (status, cookies, minted(&pool).await),
            (503, 0, before),
            "{body}"
        );
        assert!(
            !body.contains("enrollmentProof") && !body.contains("verified"),
            "{body}"
        );
        let rows: Vec<_> = log
            .recorder()
            .take_events()
            .into_iter()
            .filter(|e| e.actor.as_deref() == Some("q1down"))
            .map(|e| (e.kind, e.success, e.detail))
            .collect();
        assert_eq!(
            rows,
            vec![(
                LogKind::AccessDenied,
                false,
                Some(format!("{ADMINS_ONLY}; no session"))
            )],
            "the refusal is the finish's one row: no login success row"
        );
    }

    #[tokio::test]
    async fn test_the_session_doors_refuse_a_non_admin_while_kerberos_is_down_with_one_row() {
        use lldap_domain_handlers::handler::{GroupBackendHandler, UserBackendHandler};
        use lldap_domain_handlers::kerberos::{
            ADMINS_ONLY, DegradedKerberos, set_thread_kerberos_backend,
        };
        use lldap_test_utils::recording_log::LogGuard;
        const PASS: &str = "b2down-pass-1";
        const ADMIN_PASS: &str = "b2admin-pass-1";
        let _backend = ONE_BACKEND.lock().await;
        let _guard = EnforcementGuard::none();
        let handler = sql_handler_with(&[("b2down", PASS), ("b2admin", ADMIN_PASS)]).await;
        let admins = handler
            .create_group(lldap_domain::requests::CreateGroupRequest {
                display_name: "lldap_admin".into(),
                ..Default::default()
            })
            .await
            .unwrap();
        handler
            .add_user_to_group(&UserId::new("b2admin"), admins)
            .await
            .unwrap();
        let pool = handler.pool().clone();
        let state = app_state(handler);
        let log = LogGuard::install_on_this_thread();
        let degraded = DegradedKerberos::new("EXAMPLE.COM".to_owned(), "down".to_owned());
        set_thread_kerberos_backend(Some(std::sync::Arc::new(degraded)));
        let _restore = DegradedOnThisThread;
        for (user, password) in [("b2down", PASS), ("b2admin", ADMIN_PASS)] {
            for door in [LogKind::Login, LogKind::Bind] {
                let before = minted(&pool).await;
                let response = match door {
                    LogKind::Login => {
                        let request = login_finish_request(&state, user, password).await;
                        opaque_login_finish_handler(state.clone(), web::Json(request)).await
                    }
                    _ => {
                        let request = login::ClientSimpleLoginRequest {
                            username: UserId::new(user),
                            password: password.to_owned(),
                            enrollment_proof: None,
                        };
                        simple_login_handler(state.clone(), web::Json(request)).await
                    }
                };
                let status = response.status().as_u16();
                let got = (status, response.cookies().count(), minted(&pool).await);
                let rows: Vec<_> = log
                    .recorder()
                    .take_events()
                    .into_iter()
                    .filter(|e| e.actor.as_deref() == Some(user))
                    .map(|e| (e.kind, e.success, e.target, e.detail))
                    .collect();
                let (want, row) = match user {
                    "b2admin" => (
                        (200, 2, (before.0 + 1, before.1 + 1)),
                        (door, true, None, None),
                    ),
                    _ => (
                        (503, 0, before),
                        (
                            LogKind::AccessDenied,
                            false,
                            None,
                            Some(ADMINS_ONLY.to_owned()),
                        ),
                    ),
                };
                assert_eq!(
                    (got, rows),
                    (want, vec![row]),
                    "{door:?} {user}: one row, and no success row for a refusal"
                );
            }
        }
    }

    fn session_token(key: &Hmac<Sha512>, user: &str) -> String {
        let claims = JWTClaims {
            exp: Utc::now() + chrono::Duration::hours(1),
            iat: Utc::now(),
            jti: Uuid::new_v4(),
            user: user.to_owned(),
            groups: HashSet::new(),
            password_reset: false,
        };
        let header = jwt::Header {
            algorithm: jwt::AlgorithmType::Hs512,
            ..Default::default()
        };
        let token = jwt::Token::new(header, claims).sign_with_key(key).unwrap();
        token.as_str().to_owned()
    }

    #[tokio::test]
    async fn test_the_refresh_and_token_routes_refuse_by_policy_with_401_and_one_row() {
        use lldap_test_utils::recording_log::LogGuard;
        let _backend = ONE_BACKEND.lock().await;
        let log = LogGuard::install_on_this_thread();
        let user = UserId::new("e0http");
        for (n, door) in [Door::Refresh, Door::TokenUse].into_iter().enumerate() {
            for allow in [None, Some(true), Some(false)] {
                let guard = match allow {
                    None => EnforcementGuard::none(),
                    Some(true) => EnforcementGuard::allowing(&["e0http"], "login-hours"),
                    Some(false) => EnforcementGuard::refusing(&["e0http"], "login-hours"),
                };
                let reads = usize::from(allow.is_some());
                let mut mock = MockTestBackendHandler::new();
                mock.expect_get_user_groups()
                    .returning(|_| Ok(HashSet::new()));
                mock.expect_bounded_policy_entry()
                    .with(eq(UserId::new("e0http")))
                    .times(reads)
                    .returning(|_| Ok((alice(false), vec![])));
                mock.expect_mfa_requirement()
                    .returning(|_| Ok(MfaRequirement::None));
                let state = app_state(mock);
                let peer = format!("192.0.2.{}", 40 + n);
                let meta = RequestMeta::http(Some(peer.parse().unwrap()), None);
                let status = with_request(meta, async {
                    if door == Door::Refresh {
                        let request = actix_web::test::TestRequest::get()
                            .insert_header(("refresh-token", "e0-refresh+e0http"))
                            .to_http_request();
                        return get_refresh_handler(state, request).await.status().as_u16();
                    }
                    let token = session_token(&state.jwt_key, "e0http");
                    match check_if_token_is_valid(&state, &token).await {
                        Ok(_) => 200,
                        Err(e) => e.as_response_error().status_code().as_u16(),
                    }
                })
                .await;
                let label = format!("{door:?} {allow:?}");
                let refused = allow == Some(false);
                assert_eq!(status, if refused { 401 } else { 200 }, "{label}");
                let rows: Vec<_> = log
                    .recorder()
                    .take_events()
                    .into_iter()
                    .filter(|e| e.peer.as_deref() == Some(peer.as_str()))
                    .map(|e| (e.kind, e.success, e.protocol, e.target, e.detail))
                    .collect();
                let e0http = Some("e0http".to_owned());
                let expected = match (door, refused) {
                    (_, true) => vec![(
                        door.log_kind(),
                        false,
                        Protocol::Http,
                        e0http,
                        Some("policy: login-hours".to_owned()),
                    )],
                    (Door::Refresh, false) => {
                        vec![(LogKind::TokenRefresh, true, Protocol::Http, None, None)]
                    }
                    _ => vec![],
                };
                assert_eq!(
                    rows, expected,
                    "{label}: one row, never a success beside a refusal"
                );
                let seen = allow.map(|_| {
                    let peer = peer.parse::<std::net::IpAddr>().ok();
                    (user.clone(), door, peer, false, String::new())
                });
                let attempt = |s: SeenAttempt| (s.user, s.door, s.peer, s.second_factor, s.value);
                assert_eq!(
                    guard.seen().into_iter().map(attempt).collect::<Vec<_>>(),
                    seen.into_iter().collect::<Vec<_>>(),
                    "{label}"
                );
            }
        }
    }

    fn hours_level() -> lldap_domain_handlers::policies::PolicyLevel {
        use lldap_domain_handlers::policies::{AttachedPolicy, PolicyId, PolicyLevel};
        let items = [("login-hours".to_owned(), "mon 08:00-18:00".to_owned())];
        PolicyLevel {
            ou_key: String::new(),
            blocked: false,
            policy: Some(AttachedPolicy {
                id: PolicyId(1),
                name: "Hours".to_owned(),
                items: items.into(),
            }),
        }
    }

    /// The real check, judging only `user`, its item on in the cache.
    fn real_hours(user: &str) -> EnforcementGuard {
        use lldap_domain_handlers::enforcement::{ItemFlags, policy_cache};
        use lldap_domain_handlers::login_hours::LoginHoursCheck;
        let check = std::sync::Arc::new(LoginHoursCheck::on(policy_cache()));
        let guard = EnforcementGuard::judging(&[user], check);
        policy_cache().set_item_flags(ItemFlags {
            login_hours: true,
            ..ItemFlags::default()
        });
        guard
    }

    fn instant(text: &str) -> Timestamp {
        text.parse().unwrap()
    }

    #[tokio::test]
    async fn test_login_hours_refuse_outside_and_admit_inside_at_the_refresh_and_token_use() {
        use lldap_test_utils::recording_log::LogGuard;
        let _backend = ONE_BACKEND.lock().await;
        let log = LogGuard::install_on_this_thread();
        let guard = real_hours("h2http");
        let instants = [
            ("2026-11-16T07:59:59Z", false),
            ("2026-11-16T08:00:00Z", true),
            ("2026-11-16T17:59:59Z", true),
            ("2026-11-16T18:00:00Z", false),
        ];
        let outside = "policy: login-hours (outside login hours)";
        for (n, door) in [Door::Refresh, Door::TokenUse].into_iter().enumerate() {
            for (m, (at, inside)) in instants.into_iter().enumerate() {
                guard.pin_clock(instant(at));
                let mut mock = MockTestBackendHandler::new();
                mock.expect_get_user_groups()
                    .returning(|_| Ok(HashSet::new()));
                mock.expect_bounded_policy_entry()
                    .with(eq(UserId::new("h2http")))
                    .times(1)
                    .returning(|_| Ok((alice(false), vec![hours_level()])));
                mock.expect_mfa_requirement()
                    .returning(|_| Ok(MfaRequirement::None));
                let state = app_state(mock);
                let peer = format!("192.0.2.{}", 120 + 4 * n + m);
                let meta = RequestMeta::http(Some(peer.parse().unwrap()), None);
                let status = with_request(meta, async {
                    if door == Door::Refresh {
                        let request = actix_web::test::TestRequest::get()
                            .insert_header(("refresh-token", "h2-refresh+h2http"))
                            .to_http_request();
                        return get_refresh_handler(state, request).await.status().as_u16();
                    }
                    let token = session_token(&state.jwt_key, "h2http");
                    match check_if_token_is_valid(&state, &token).await {
                        Ok(_) => 200,
                        Err(e) => e.as_response_error().status_code().as_u16(),
                    }
                })
                .await;
                let rows: Vec<_> = log
                    .recorder()
                    .take_events()
                    .into_iter()
                    .filter(|e| e.peer.as_deref() == Some(peer.as_str()))
                    .map(|e| (e.kind, e.success, e.detail))
                    .collect();
                let expected = match (door, inside) {
                    (_, false) => vec![(door.log_kind(), false, Some(outside.to_owned()))],
                    (Door::Refresh, true) => vec![(LogKind::TokenRefresh, true, None)],
                    _ => vec![],
                };
                let seen = guard.take_seen().into_iter();
                let seen: Vec<_> = seen.map(|s| (s.door, s.now)).collect();
                assert_eq!(
                    (status, rows, seen),
                    (
                        if inside { 200 } else { 401 },
                        expected,
                        vec![(door, instant(at))]
                    ),
                    "{door:?} at {at}"
                );
            }
        }
    }

    #[tokio::test]
    async fn test_outside_the_hours_the_login_routes_answer_a_right_password_as_a_wrong_one() {
        use lldap_domain_handlers::enforcement::{Entries, policy_cache};
        use lldap_domain_handlers::policies::{EffectiveItem, PolicyScope};
        const PASSWORD: &str = "h2route-pass-1";
        let _backend = ONE_BACKEND.lock().await;
        let handler = sql_handler_with(&[("h2route", PASSWORD)]).await;
        let guard = real_hours("h2route");
        let hours = EffectiveItem {
            key: "login-hours".to_owned(),
            scope: PolicyScope::User,
            value: "mon 08:00-18:00".to_owned(),
            enforced: true,
            source: None,
        };
        policy_cache().replace(Entries {
            ous_of_users: [(UserId::new("h2route"), "h2ou".to_owned())].into(),
            items_of_ous: [("h2ou".to_owned(), vec![hours].into())].into(),
            ..Entries::default()
        });
        guard.pin_clock(instant("2026-11-16T18:00:00Z"));
        let state = app_state(handler);
        let answer = async |response: HttpResponse| {
            let status = response.status().as_u16();
            let body = actix_web::body::to_bytes(response.into_body()).await;
            (status, body.unwrap().to_vec())
        };
        let simple = async |password: &str| {
            let request = login::ClientSimpleLoginRequest {
                username: UserId::new("h2route"),
                password: password.to_owned(),
                enrollment_proof: None,
            };
            answer(simple_login_handler(state.clone(), web::Json(request)).await).await
        };
        let meta = || RequestMeta::http(Some("192.0.2.140".parse().unwrap()), None);
        let simple = with_request(meta(), async {
            (simple(PASSWORD).await, simple("h2route-wrong-1").await)
        })
        .await;
        let right = with_request(meta(), login_start_answer(&state, "h2route", PASSWORD)).await;
        let judged = guard.take_seen().len();
        guard.pin_clock(instant("2026-11-16T12:00:00Z"));
        let wrong = login_start_answer(&state, "h2route", "h2route-wrong-1");
        let wrong = with_request(meta(), wrong).await;
        assert_eq!(
            (simple.0.0, right.0, right.2, judged),
            (401, 200, false, 2),
            "both refused by the hours, the web login when the sign-in starts"
        );
        assert_eq!(
            (simple.0, right),
            (simple.1, wrong),
            "the simple login: the right password outside the hours and a wrong one, status and \
             body alike; the web login: the right password outside the hours fails as a wrong one \
             inside them does, the start's status and body keys alike"
        );
    }

    async fn idle_after(handler: &lldap_sql_backend_handler::SqlBackendHandler, days: &str) {
        use lldap_domain_handlers::enforcement::INACTIVITY_DAYS;
        use lldap_domain_handlers::policies::CreatePolicyRequest;
        let request = CreatePolicyRequest {
            name: "e6 idle".to_owned(),
            description: String::new(),
            items: [(INACTIVITY_DAYS.to_owned(), days.to_owned())].into(),
        };
        let id = handler.create_policy(request).await.unwrap();
        handler.set_ou_policy("", id).await.unwrap();
    }

    #[tokio::test]
    async fn test_a_refresh_writes_a_success_and_a_token_use_does_not() {
        let _backend = ONE_BACKEND.lock().await;
        let _guard = EnforcementGuard::default_checks();
        let handler = sql_handler_with(&[("e6refresh", "e6refresh-pass-1")]).await;
        idle_after(&handler, "30").await;
        let user = UserId::new("e6refresh");
        let (refresh, _) = handler.create_refresh_token(&user).await.unwrap();
        let state = app_state(handler.clone());
        let stored = async || handler.read_activity(Some(&user)).await.unwrap().len();
        let token = session_token(&state.jwt_key, "e6refresh");
        let used = check_if_token_is_valid(&state, &token).await.is_ok();
        let after_use = stored().await;
        let request = actix_web::test::TestRequest::get()
            .insert_header(("refresh-token", format!("{refresh}+e6refresh")))
            .to_http_request();
        let refreshed = get_refresh_handler(state, request).await.status().as_u16();
        let after_refresh = stored().await;
        handler.clear_ou_policy("").await.unwrap();
        assert_eq!(
            (used, after_use, refreshed, after_refresh),
            (true, 0, 200, 1),
            "a token's use writes nothing; the refresh writes the success"
        );
    }

    #[tokio::test]
    async fn test_a_logout_acts_only_on_a_refresh_token_the_server_holds_for_that_user() {
        use lldap_test_utils::recording_log::LogGuard;
        let _backend = ONE_BACKEND.lock().await;
        let users = [("o1ann", "o1ann-pass-1"), ("o1ben", "o1ben-pass-1")];
        let handler = sql_handler_with(&users).await;
        let state = app_state(handler.clone());
        let log = LogGuard::install_on_this_thread();
        let (ann, ben) = (UserId::new("o1ann"), UserId::new("o1ben"));
        let rows = [
            ("a held token of the user", Some("HELD+o1ann"), 200, true),
            (
                "a token not held, a known user",
                Some("o1-other+o1ann"),
                200,
                false,
            ),
            (
                "a held token under another user's name",
                Some("HELD+o1ben"),
                200,
                false,
            ),
            ("no token", None, 401, false),
        ];
        for (label, presented, status, acts) in rows {
            let (held, _) = handler.create_refresh_token(&ann).await.unwrap();
            let ann_jwt = create_jwt(&handler, &state.jwt_key, &ann, HashSet::new(), false).await;
            let ben_jwt = create_jwt(&handler, &state.jwt_key, &ben, HashSet::new(), false).await;
            let jwts = [ann_jwt, ben_jwt].map(|token| default_hash(token.as_str()));
            let _ = log.recorder().take_events();
            let mut request = actix_web::test::TestRequest::get();
            if let Some(presented) = presented {
                let token = presented.replace("HELD", &held);
                request = request.insert_header(("refresh-token", token));
            }
            let response = get_logout_handler(state.clone(), request.to_http_request()).await;
            let mut cleared: Vec<_> = response
                .cookies()
                .filter(|c| c.value().is_empty() && c.max_age() == Some(0.days()))
                .map(|c| c.name().to_owned())
                .collect();
            cleared.sort();
            let kept = handler.check_token(default_hash(held.as_str()), &ann).await;
            let stored = handler.get_jwt_blacklist().await.unwrap();
            let in_memory = state.jwt_blacklist.read().unwrap().clone();
            let ended = |set: &HashSet<u64>| jwts.map(|hash| set.contains(&hash));
            let rows: Vec<_> = log
                .recorder()
                .take_events()
                .into_iter()
                .filter(|e| e.kind == LogKind::Logout)
                .map(|e| (e.actor, e.success))
                .collect();
            let cookies = match status {
                200 => vec!["refresh_token".to_owned(), "token".to_owned()],
                _ => vec![],
            };
            let row = acts.then(|| (Some("o1ann".to_owned()), true));
            assert_eq!(
                (
                    response.status().as_u16(),
                    cleared,
                    kept.unwrap(),
                    ended(&stored),
                    ended(&in_memory),
                    rows
                ),
                (
                    status,
                    cookies,
                    !acts,
                    [acts, false],
                    [acts, false],
                    Vec::from_iter(row)
                ),
                "{label}: the status, the cookies cleared, whether o1ann keeps the refresh token, \
                 the access tokens of o1ann and o1ben ended in the table and in memory, the \
                 logout rows"
            );
        }
    }

    #[tokio::test]
    async fn test_a_reset_token_of_an_inactive_user_is_refused_where_register_start_checks_it() {
        use lldap_test_utils::recording_log::LogGuard;
        let _backend = ONE_BACKEND.lock().await;
        let log = LogGuard::install_on_this_thread();
        let guard = EnforcementGuard::default_checks();
        let handler = sql_handler_with(&[("e6reset", "e6reset-pass-1")]).await;
        idle_after(&handler, "1").await;
        guard.pin_clock(Timestamp::now() + days(3));
        let state = app_state(handler.clone());
        let _ = log.recorder().take_events();
        let token = reset_token(&state.jwt_key, "e6reset");
        let checked = check_if_token_is_valid(&state, &token).await;
        let status = checked
            .map(drop)
            .map_err(|e| e.as_response_error().status_code());
        let rows: Vec<_> = log
            .recorder()
            .take_events()
            .into_iter()
            .filter(|e| e.actor.as_deref() == Some("e6reset"))
            .map(|e| (e.kind, e.success, e.detail))
            .collect();
        handler.clear_ou_policy("").await.unwrap();
        let inactive = Some("policy: inactivity-days (inactive)".to_owned());
        assert_eq!(
            (status.map_err(|code| code.as_u16()), rows),
            (Err(401), vec![(LogKind::AccessDenied, false, inactive)]),
            "a reset mail's token is a token's use: an inactive user is refused before \
             register/start"
        );
    }

    async fn answered(response: HttpResponse) -> (u16, Vec<u8>) {
        let status = response.status().as_u16();
        let bytes = actix_web::body::to_bytes(response.into_body());
        (status, bytes.await.unwrap().to_vec())
    }

    #[tokio::test]
    async fn test_an_inactive_users_right_password_gets_a_wrong_ones_body_byte_for_byte() {
        const PASSWORD: &str = "e6http-pass-1";
        let _backend = ONE_BACKEND.lock().await;
        let guard = EnforcementGuard::default_checks();
        let handler = sql_handler_with(&[("e6http", PASSWORD)]).await;
        idle_after(&handler, "1").await;
        let state = app_state(handler.clone());
        let simple = async |password: &str| {
            let request = login::ClientSimpleLoginRequest {
                username: UserId::new("e6http"),
                password: password.to_owned(),
                enrollment_proof: None,
            };
            answered(simple_login_handler(state.clone(), web::Json(request)).await).await
        };
        let active = simple(PASSWORD).await.0;
        let wrong_while_active = login_start_answer(&state, "e6http", "e6http-wrong-1").await;
        guard.pin_clock(Timestamp::now() + days(3));
        let simple = (simple(PASSWORD).await, simple("e6http-wrong-1").await);
        let right = login_start_answer(&state, "e6http", PASSWORD).await;
        handler.clear_ou_policy("").await.unwrap();
        assert_eq!(active, 200, "the same password while the user is active");
        assert_eq!(
            simple.0.0,
            401,
            "{:?}",
            String::from_utf8_lossy(&simple.0.1)
        );
        assert_eq!(
            simple.0, simple.1,
            "the simple login: the right password and a wrong one"
        );
        assert_eq!((right.0, right.2), (200, false), "{right:?}");
        assert_eq!(
            right, wrong_while_active,
            "the web login: the right password of the inactive user fails as a wrong one did \
             while active, the start's status and body keys alike"
        );
    }

    #[tokio::test]
    async fn test_outside_the_hours_a_totp_users_right_password_gets_a_wrong_ones_body_first() {
        use lldap_domain_handlers::enforcement::{Entries, policy_cache};
        use lldap_domain_handlers::policies::{EffectiveItem, PolicyScope};
        const PASSWORD: &str = "q31http-pass-1";
        struct EnrolmentClock;
        impl Drop for EnrolmentClock {
            fn drop(&mut self) {
                lldap_sql_backend_handler::set_enrollment_clock(None);
            }
        }
        let _backend = ONE_BACKEND.lock().await;
        let handler = sql_handler_with(&[("q31http", PASSWORD)])
            .await
            .with_mfa_policy(lldap_domain_handlers::mfa::MfaPolicy::Enrolled);
        let now = Utc::now().timestamp();
        lldap_sql_backend_handler::set_enrollment_clock(Some(now));
        let _clock = EnrolmentClock;
        let user = UserId::new("q31http");
        let proof = handler.seal_enrollment_proof(&user).await.unwrap().unwrap();
        let start = handler
            .start_totp_enrollment(&user, None, Some(proof))
            .await
            .unwrap();
        let seed = lldap_mfa::seed_from_base32(&start.secret_base32).unwrap();
        let spent = lldap_mfa::format_code(lldap_mfa::totp_code(&seed, now as u64).unwrap());
        handler
            .finish_totp_enrollment(&user, &start.state, &spent)
            .await
            .unwrap();
        let guard = real_hours("q31http");
        let hours = EffectiveItem {
            key: "login-hours".to_owned(),
            scope: PolicyScope::User,
            value: "mon 08:00-18:00".to_owned(),
            enforced: true,
            source: None,
        };
        policy_cache().replace(Entries {
            ous_of_users: [(user.clone(), "q31ou".to_owned())].into(),
            items_of_ous: [("q31ou".to_owned(), vec![hours].into())].into(),
            ..Entries::default()
        });
        let state = app_state(handler);
        let simple = async |password: &str| {
            let request = login::ClientSimpleLoginRequest {
                username: UserId::new("q31http"),
                password: password.to_owned(),
                enrollment_proof: None,
            };
            answered(simple_login_handler(state.clone(), web::Json(request)).await).await
        };
        let finish = async |request: login::ClientLoginFinishRequest| {
            answered(opaque_login_finish_handler(state.clone(), web::Json(request)).await).await
        };
        guard.pin_clock(instant("2026-11-16T12:00:00Z"));
        let asked = (
            simple(PASSWORD).await,
            finish(login_finish_request(&state, "q31http", PASSWORD).await).await,
        );
        let wrong_inside = login_start_answer(&state, "q31http", "q31http-wrong-1").await;
        guard.pin_clock(instant("2026-11-16T18:00:00Z"));
        let simple = (simple(PASSWORD).await, simple("q31http-wrong-1").await);
        let right = login_start_answer(&state, "q31http", PASSWORD).await;
        let text = |body: &[u8]| String::from_utf8_lossy(body).into_owned();
        assert_eq!(
            (
                asked.0.0,
                text(&asked.0.1).contains("TOTP code required"),
                asked.1.0
            ),
            (401, true, 200),
            "inside the hours: the code step, as today ({})",
            text(&asked.1.1)
        );
        assert_eq!(simple.0.0, 401, "{}", text(&simple.0.1));
        assert_eq!(
            simple.0, simple.1,
            "outside, the simple login: the right password and no code, then a wrong password"
        );
        assert_eq!((right.0, right.2), (200, false), "{right:?}");
        assert_eq!(
            right, wrong_inside,
            "outside, the web login: the right password and no code fails as a wrong password \
             inside the hours does, the start's status and body keys alike"
        );
    }

    #[tokio::test]
    async fn test_an_unreadable_enable_mfa_value_gets_a_wrong_passwords_body_at_the_web_finish() {
        use lldap_domain_handlers::enforcement::PolicyCache;
        const PASSWORD: &str = "q32http-pass-1";
        let _backend = ONE_BACKEND.lock().await;
        let cache: &'static PolicyCache = Box::leak(Box::new(PolicyCache::new()));
        let handler = sql_handler_with(&[("q32http", PASSWORD)])
            .await
            .with_policy_cache(cache);
        let state = app_state(handler);
        let right = login_finish_request(&state, "q32http", PASSWORD).await;
        let mut forged = login_finish_request(&state, "q32http", PASSWORD).await;
        forged.credential_finalization = right.credential_finalization.clone();
        cache.set_mfa_item_unknown();
        let finish = async |request: login::ClientLoginFinishRequest| {
            answered(opaque_login_finish_handler(state.clone(), web::Json(request)).await).await
        };
        let finished = (finish(right).await, finish(forged).await);
        let text = |body: &[u8]| String::from_utf8_lossy(body).into_owned();
        assert_eq!(finished.0.0, 401, "{}", text(&finished.0.1));
        assert_eq!(
            finished.0, finished.1,
            "the enable-mfa value unreadable only after the starts: the right proof and a proof \
             that does not verify get the same status and body"
        );
    }

    #[tokio::test]
    async fn test_an_attempt_the_items_refuse_never_reaches_the_enrolment_read_at_the_web_finish() {
        use lldap_domain_handlers::enforcement::{Entries, PolicyCache, policy_cache};
        use lldap_domain_handlers::policies::{EffectiveItem, PolicyScope};
        use sea_orm::ConnectionTrait;
        const PASSWORD: &str = "q34http-pass-1";
        let _backend = ONE_BACKEND.lock().await;
        let cache: &'static PolicyCache = Box::leak(Box::new(PolicyCache::new()));
        let handler = sql_handler_with(&[("q34http", PASSWORD)])
            .await
            .with_policy_cache(cache)
            .with_mfa_policy(lldap_domain_handlers::mfa::MfaPolicy::Enrolled);
        let pool = handler.pool().clone();
        let guard = real_hours("q34http");
        let hours = EffectiveItem {
            key: "login-hours".to_owned(),
            scope: PolicyScope::User,
            value: "mon 08:00-18:00".to_owned(),
            enforced: true,
            source: None,
        };
        policy_cache().replace(Entries {
            ous_of_users: [(UserId::new("q34http"), "q34ou".to_owned())].into(),
            items_of_ous: [("q34ou".to_owned(), vec![hours].into())].into(),
            ..Entries::default()
        });
        let state = app_state(handler);
        guard.pin_clock(instant("2026-11-16T12:00:00Z"));
        let right = login_finish_request(&state, "q34http", PASSWORD).await;
        let mut forged = login_finish_request(&state, "q34http", PASSWORD).await;
        forged.credential_finalization = right.credential_finalization.clone();
        let admitted = login_finish_request(&state, "q34http", PASSWORD).await;
        pool.execute_unprepared("ALTER TABLE users RENAME TO users_away")
            .await
            .unwrap();
        let finish = async |request: login::ClientLoginFinishRequest| {
            answered(opaque_login_finish_handler(state.clone(), web::Json(request)).await).await
        };
        guard.pin_clock(instant("2026-11-16T18:00:00Z"));
        let refused = (finish(right).await, finish(forged).await);
        guard.pin_clock(instant("2026-11-16T12:00:00Z"));
        let outage = finish(admitted).await.0;
        pool.execute_unprepared("ALTER TABLE users_away RENAME TO users")
            .await
            .unwrap();
        let text = |body: &[u8]| String::from_utf8_lossy(body).into_owned();
        assert_eq!(refused.0.0, 401, "{}", text(&refused.0.1));
        assert_eq!(
            refused.0, refused.1,
            "started inside the hours, finished outside them, the enrolment read failing: the \
             right proof and a proof that does not verify get the same status and body"
        );
        assert_eq!(
            outage, 500,
            "inside the hours the items admit, and the failing read is answered as an outage"
        );
    }

    #[tokio::test]
    async fn test_a_policy_read_error_refuses_the_refresh_and_the_token_with_one_row() {
        use lldap_domain_handlers::enforcement::POLICY_UNANSWERED;
        use lldap_test_utils::recording_log::LogGuard;
        let _backend = ONE_BACKEND.lock().await;
        let log = LogGuard::install_on_this_thread();
        let _guard = EnforcementGuard::allowing(&["k2http"], "login-hours");
        let rows = [
            (Door::Refresh, "canceling statement due to lock timeout"),
            (Door::TokenUse, POLICY_UNANSWERED),
        ];
        for (n, (door, cause)) in rows.into_iter().enumerate() {
            let mut mock = MockTestBackendHandler::new();
            mock.expect_get_user_groups()
                .returning(|_| Ok(HashSet::new()));
            mock.expect_bounded_policy_entry()
                .with(eq(UserId::new("k2http")))
                .times(1)
                .returning(move |_| Err(DomainError::InternalError(cause.to_owned())));
            let state = app_state(mock);
            let peer = format!("192.0.2.{}", 80 + n);
            let meta = RequestMeta::http(Some(peer.parse().unwrap()), None);
            let status = with_request(meta, async {
                if door == Door::Refresh {
                    let request = actix_web::test::TestRequest::get()
                        .insert_header(("refresh-token", "k2-refresh+k2http"))
                        .to_http_request();
                    return get_refresh_handler(state, request).await.status().as_u16();
                }
                let token = session_token(&state.jwt_key, "k2http");
                match check_if_token_is_valid(&state, &token).await {
                    Ok(_) => 200,
                    Err(e) => e.as_response_error().status_code().as_u16(),
                }
            })
            .await;
            let rows: Vec<_> = log
                .recorder()
                .take_events()
                .into_iter()
                .filter(|e| e.peer.as_deref() == Some(peer.as_str()))
                .map(|e| (e.kind, e.success, e.target, e.detail))
                .collect();
            let refused = (
                door.log_kind(),
                false,
                Some("k2http".to_owned()),
                Some("policy: unreadable".to_owned()),
            );
            assert_eq!((status, rows), (401, vec![refused]), "{door:?}");
        }
    }

    #[tokio::test]
    async fn test_an_unreadable_mfa_value_refuses_the_refresh_and_the_token_with_one_row() {
        use lldap_test_utils::recording_log::LogGuard;
        let _backend = ONE_BACKEND.lock().await;
        let log = LogGuard::install_on_this_thread();
        let _guard = EnforcementGuard::none();
        let user = UserId::new("e2http");
        for (n, door) in [Door::Refresh, Door::TokenUse].into_iter().enumerate() {
            let unreadable = || DomainError::InternalError("not read yet".to_owned());
            let mut mock = MockTestBackendHandler::new();
            mock.expect_get_user_groups()
                .returning(|_| Ok(HashSet::new()));
            mock.expect_mfa_requirement()
                .returning(move |_| Err(unreadable()));
            mock.expect_mfa_mode().returning(move |_| Err(unreadable()));
            let state = app_state(mock);
            let peer = format!("192.0.2.{}", 60 + n);
            let meta = RequestMeta::http(Some(peer.parse().unwrap()), None);
            let status = with_request(meta, async {
                if door == Door::Refresh {
                    let request = actix_web::test::TestRequest::get()
                        .insert_header(("refresh-token", "e2-refresh+e2http"))
                        .to_http_request();
                    return get_refresh_handler(state, request).await.status().as_u16();
                }
                match session_mfa(&state, &user).await {
                    Ok(_) => 200,
                    Err(e) => e.as_response_error().status_code().as_u16(),
                }
            })
            .await;
            let rows: Vec<_> = log
                .recorder()
                .take_events()
                .into_iter()
                .filter(|e| e.peer.as_deref() == Some(peer.as_str()))
                .map(|e| (e.kind, e.success, e.target, e.detail))
                .collect();
            let refused = (
                door.log_kind(),
                false,
                Some("e2http".to_owned()),
                Some("policy: unreadable".to_owned()),
            );
            assert_eq!(
                (status, rows),
                (401, vec![refused]),
                "{door:?}: a refusal with its one row, not a 500"
            );
        }
    }

    #[test]
    fn test_only_admins_keep_a_session_while_kerberos_is_unavailable() {
        let cause = || Some("the Kerberos realm did not open".to_owned());
        let rows = [
            (true, None, None),
            (false, None, None),
            (true, cause(), None),
            (false, cause(), cause()),
        ];
        for (admin, unavailable, expected) in rows {
            let got = refusal_while_degraded(&UserId::new("bob"), admin, unavailable.clone());
            assert_eq!(got, expected, "admin {admin}, unavailable {unavailable:?}");
        }
    }

    #[test]
    fn test_every_user_signs_in_while_the_last_write_is_unsettled() {
        use lldap_domain_handlers::kerberos::{ANSWER_UNSETTLED, DegradedKerberos, KerberosSync};
        use lldap_test_utils::recording_kerberos::RecordingKerberos;
        let degraded = DegradedKerberos::new("EXAMPLE.COM".to_owned(), "down".to_owned());
        let unsettled = RecordingKerberos::unsettled(ANSWER_UNSETTLED);
        let bob = UserId::new("bob");
        assert_eq!(
            (
                refusal_while_degraded(&bob, false, degraded.unavailable()),
                refusal_while_degraded(&bob, false, unsettled.unavailable()),
                unsettled.unsettled(),
            ),
            (
                Some("down".to_owned()),
                None,
                Some(ANSWER_UNSETTLED.to_owned())
            ),
            "a degraded realm keeps out all but admins; a held one whose last write is \
             unsettled keeps no one out"
        );
    }
}
