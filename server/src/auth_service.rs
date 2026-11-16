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
use lldap_domain::types::{GroupDetails, GroupName, LoginOutcome, UserId};
use lldap_domain_handlers::handler::{
    BackendHandler, BindRequest, LoginHandler, MfaBackendHandler, UserRequestFilter,
};
use lldap_domain_handlers::kerberos::kerberos_backend;
use lldap_domain_handlers::logging::{self, LogKind, with_actor};
use lldap_domain_handlers::mfa::{MfaRequirement, MfaResetReason};
use lldap_domain_model::{error::DomainError, model::UserColumn};
use lldap_opaque_handler::OpaqueHandler;
use sha2::Sha512;
use std::{
    collections::HashSet,
    hash::Hash,
    pin::Pin,
    task::{Context, Poll},
};
use time::ext::NumericalDuration;
use tracing::{debug, instrument, warn};
use uuid::Uuid;

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
    let jwt_key = &data.jwt_key;
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
    let mfa_enrollment_pending =
        data.get_mfa_handler().mfa_requirement(&user).await? == MfaRequirement::Enrollment;
    let token = create_jwt(data.get_tcp_handler(), jwt_key, &user, groups, false).await;
    logging::record_as(Some(&user), LogKind::TokenRefresh, None, true, None);
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
    data.get_tcp_handler()
        .delete_refresh_token(refresh_token_hash)
        .await?;
    let new_blacklisted_jwt_hashes = data.get_tcp_handler().blacklist_jwts(&user).await?;
    let mut jwt_blacklist = data.jwt_blacklist.write().unwrap();
    for jwt_hash in new_blacklisted_jwt_hashes {
        jwt_blacklist.insert(jwt_hash);
    }
    logging::record_as(Some(&user), LogKind::Logout, None, true, None);
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
) -> TcpResult<HttpResponse>
where
    Backend: TcpBackendHandler + BackendHandler,
{
    // The authentication was successful, we need to fetch the groups to create the JWT
    // token.
    let groups = data.get_readonly_handler().get_user_groups(name).await?;
    if let Some(cause) =
        refusal_while_degraded(name, is_admin(&groups), kerberos_backend().unavailable())
    {
        return Err(TcpError::DomainError(DomainError::KdcUnavailable(cause)));
    }
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
    match data
        .get_opaque_handler()
        .login_finish(request.into_inner())
        .await?
    {
        LoginOutcome::Authenticated {
            user_id,
            mfa_enrollment_pending,
        } => get_login_successful_response(&data, &user_id, mfa_enrollment_pending).await,
        // The password verified; the client retries with password:code.
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
    let login::ClientSimpleLoginRequest { username, password } = request.into_inner();
    let bind_request = BindRequest {
        name: username.clone(),
        password,
    };
    data.get_login_handler().bind(bind_request).await?;
    get_login_successful_response(&data, &username, false).await
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
) -> TcpResult<registration::ServerRegistrationStartResponse>
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
    Ok(data
        .get_opaque_handler()
        .registration_start(registration_start_request)
        .await?)
}

async fn opaque_register_start_handler<Backend>(
    request: actix_web::HttpRequest,
    payload: actix_web::web::Payload,
    data: web::Data<AppState<Backend>>,
) -> ApiResult<registration::ServerRegistrationStartResponse>
where
    Backend: BackendHandler + OpaqueHandler + 'static,
{
    opaque_register_start(request, payload, data)
        .await
        .map(|res| ApiResult::Left(web::Json(res)))
        .unwrap_or_else(error_to_api_response)
}

async fn finish_registration<Handler: OpaqueHandler>(
    handler: &Handler,
    reset_user: Option<&UserId>,
    request: registration::ClientRegistrationFinishRequest,
) -> TcpResult<UserId> {
    if let Some(user_id) = reset_user
        && handler.registration_user(&request).await? != *user_id
    {
        return Err(TcpError::UnauthorizedError(
            "Password reset token does not match the registered user".to_string(),
        ));
    }
    Ok(handler.registration_finish(request).await?)
}

#[instrument(skip_all, level = "debug")]
async fn opaque_register_finish<Backend>(
    http_request: HttpRequest,
    data: web::Data<AppState<Backend>>,
    request: web::Json<registration::ClientRegistrationFinishRequest>,
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
            data.get_opaque_handler(),
            reset_user.as_ref(),
            request.into_inner(),
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
    request: web::Json<registration::ClientRegistrationFinishRequest>,
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
    Ok(validation)
}

const ADMINS_ONLY: &str = "only admins may sign in while Kerberos is unavailable";

fn is_admin(groups: &HashSet<GroupDetails>) -> bool {
    groups
        .iter()
        .any(|g| g.display_name == "lldap_admin".into())
}

fn refusal_while_degraded(
    user: &UserId,
    is_admin: bool,
    unavailable: Option<String>,
) -> Option<String> {
    let cause = unavailable.filter(|_| !is_admin)?;
    logging::record_as(
        Some(user),
        LogKind::AccessDenied,
        None,
        false,
        Some(ADMINS_ONLY),
    );
    Some(cause)
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
mod tests {
    use super::*;
    use lldap_auth::opaque;
    use lldap_domain_model::error::{DomainError, Result as DomainResult};
    use lldap_test_utils::MockTestBackendHandler;
    use pretty_assertions::assert_eq;

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
        let alice = UserId::new("alice");
        let rows = [
            ("no reset token", None, None, Ok(())),
            ("the token's user", Some("alice"), Some(Ok("alice")), Ok(())),
            ("another user", Some("alice"), Some(Ok("bob")), Err(401)),
            ("unsealable", Some("alice"), Some(Err(())), Err(500)),
        ];
        for (row, reset, target, expected) in rows {
            let mut mock = MockTestBackendHandler::new();
            mock.expect_registration_user()
                .times(usize::from(target.is_some()))
                .returning(move |_| match target.unwrap() {
                    Ok(user) => Ok(UserId::new(user)),
                    Err(()) => Err(DomainError::InternalError("not sealed".to_owned())),
                });
            mock.expect_registration_finish()
                .times(usize::from(expected.is_ok()))
                .returning(|_| Ok(UserId::new("alice")));
            let reset = reset.map(UserId::new);
            let got = finish_registration(&mock, reset.as_ref(), finish_request())
                .await
                .map_err(|e| error_to_http_response(e).status().as_u16());
            assert_eq!(got, expected.map(|()| alice.clone()), "{row}");
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
            unimplemented!()
        }
        async fn check_token(&self, _: u64, _: &UserId) -> DomainResult<bool> {
            unimplemented!()
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

    fn app_state(mock: MockTestBackendHandler) -> web::Data<AppState<MockTestBackendHandler>> {
        use hmac::Mac;
        web::Data::new(AppState {
            backend_handler: lldap_access_control::AccessControlledBackendHandler::new(mock),
            jwt_key: Hmac::new_from_slice(b"a test secret").unwrap(),
            jwt_blacklist: std::sync::RwLock::new(HashSet::new()),
            server_url: url::Url::parse("http://localhost").unwrap(),
            assets_path: std::path::PathBuf::new(),
            mail_options: crate::configuration::MailOptionsBuilder::default()
                .build()
                .unwrap(),
            mfa_policy: lldap_domain_handlers::mfa::MfaPolicy::Disabled,
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
        for (sealed_for, status, writes) in [("alice", 200, 1), ("bob", 401, 0)] {
            let mut mock = MockTestBackendHandler::new();
            mock.expect_registration_user()
                .times(1)
                .returning(move |_| Ok(UserId::new(sealed_for)));
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
                opaque_register_finish_handler(request, state, web::Json(finish_request())).await;
            assert_eq!(
                response.status().as_u16(),
                status,
                "sealed for {sealed_for}"
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
}
