use crate::{
    auth_service,
    configuration::{Configuration, MailOptions},
    logging::CustomRootSpanBuilder,
    tcp_backend_handler::*,
};
use actix_files::Files;
use actix_http::{HttpServiceBuilder, header};
use actix_server::ServerBuilder;
use actix_service::map_config;
use actix_web::{
    App, Error, HttpResponse, Responder,
    body::MessageBody,
    dev::{AppConfig, ServiceRequest, ServiceResponse},
    guard,
    middleware::{Next, from_fn},
    web,
};
use anyhow::{Context, Result};
use hmac::Hmac;
use lldap_access_control::{
    AccessControlledBackendHandler, ReadonlyBackendHandler, UserReadableBackendHandler,
};
use lldap_domain_handlers::enforcement::{mfa_can_be_on, policy_cache};
use lldap_domain_handlers::handler::{
    BackendHandler, LoginHandler, MfaBackendHandler, PolicyBackendHandler,
};
use lldap_domain_handlers::kerberos::{
    RealmHealth, domain_from_base_dn, public_cause, realm_health,
};
use lldap_domain_handlers::logging::{RequestMeta, with_request};
use lldap_domain_handlers::mfa::MfaPolicy;
use lldap_domain_handlers::networks::resolve_client;
use lldap_domain_handlers::warn_limited;
use lldap_domain_model::error::DomainError;
use lldap_kerberos::boot::with_port_hint;
use lldap_keycloak::KeycloakSettings;
use lldap_opaque_handler::OpaqueHandler;
use serde::{Deserialize, Serialize};
use sha2::Sha512;
use std::collections::HashSet;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use tracing::{info, warn};

async fn log_request_scope(
    req: ServiceRequest,
    next: Next<impl MessageBody>,
) -> Result<ServiceResponse<impl MessageBody>, Error> {
    let forwarded_for = req
        .headers()
        .get_all("x-forwarded-for")
        .filter_map(|value| value.to_str().ok())
        .collect::<Vec<_>>()
        .join(", ");
    let peer = req.peer_addr().map(|addr| addr.ip());
    let mut meta = RequestMeta::http(peer, (!forwarded_for.is_empty()).then_some(forwarded_for));
    meta.client_address = client_address(&req, peer);
    with_request(meta, next.call(req)).await
}

/// The address allowed-networks judges; an unreadable header line is an entry that is no address.
fn client_address(req: &ServiceRequest, peer: Option<IpAddr>) -> Option<IpAddr> {
    let lines: Vec<&str> = req
        .headers()
        .get_all("x-forwarded-for")
        .map(|value| value.to_str().unwrap_or_default())
        .collect();
    resolve_client(peer, &lines, &policy_cache().trusted_proxies())
}

async fn index<Backend>(data: web::Data<AppState<Backend>>) -> actix_web::Result<impl Responder> {
    let mut file = std::fs::read_to_string(data.assets_path.join("index.html"))?;

    if data.server_url.path() != "/" {
        file = file.replace(
            "<base href=\"/\">",
            format!("<base href=\"{}/\">", data.server_url.path()).as_str(),
        );
    }

    Ok(file
        .customize()
        .insert_header((header::CONTENT_TYPE, "text/html; charset=utf-8")))
}

#[derive(thiserror::Error, Debug)]
pub enum TcpError {
    #[error("`{0}`")]
    DomainError(#[from] DomainError),
    #[error("Bad request: `{0}`")]
    BadRequest(String),
    #[error("Internal server error: `{0}`")]
    InternalServerError(String),
    #[error("Not found: `{0}`")]
    NotFoundError(String),
    #[error("Unauthorized: `{0}`")]
    UnauthorizedError(String),
    #[error("Conflict: `{0}`")]
    Conflict(String),
}

pub type TcpResult<T> = std::result::Result<T, TcpError>;

/// The body of `/health`, as the server writes it and `lldap healthcheck` reads it.
#[derive(Debug, PartialEq, Eq, Deserialize, Serialize)]
pub(crate) struct Health {
    pub kerberos: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cause: Option<String>,
}

fn health(realm: &RealmHealth) -> HttpResponse {
    let body = Health {
        kerberos: realm.word().to_owned(),
        cause: public_cause(realm),
    };
    match realm.healthy() {
        true => HttpResponse::Ok().json(body),
        false => HttpResponse::ServiceUnavailable().json(body),
    }
}

pub(crate) fn error_to_http_response(error: TcpError) -> HttpResponse {
    match error {
        TcpError::DomainError(ref de) => match de {
            DomainError::AuthenticationError(_) | DomainError::AuthenticationProtocolError(_) => {
                HttpResponse::Unauthorized()
            }
            DomainError::DatabaseError(_)
            | DomainError::DatabaseTransactionError(_)
            | DomainError::InternalError(_)
            | DomainError::UnknownCryptoError(_) => {
                warn_limited!("A request was answered with an internal error: {de}");
                HttpResponse::InternalServerError()
            }
            DomainError::Base64DecodeError(_)
            | DomainError::BinarySerializationError(_)
            | DomainError::EntityNotFound(_) => HttpResponse::BadRequest(),
            DomainError::KdcUnavailable(_) | DomainError::Busy(_) => {
                HttpResponse::ServiceUnavailable()
            }
        },
        TcpError::BadRequest(_) => HttpResponse::BadRequest(),
        TcpError::NotFoundError(_) => HttpResponse::NotFound(),
        TcpError::InternalServerError(_) => HttpResponse::InternalServerError(),
        TcpError::UnauthorizedError(_) => HttpResponse::Unauthorized(),
        TcpError::Conflict(_) => HttpResponse::Conflict(),
    }
    .body(error.to_string())
}

async fn main_js_handler<Backend>(
    data: web::Data<AppState<Backend>>,
) -> actix_web::Result<impl Responder> {
    let mut file = std::fs::read_to_string(data.assets_path.join("static/main.js"))?;

    if data.server_url.path() != "/" {
        file = file.replace("/pkg/", format!("{}/pkg/", data.server_url.path()).as_str());
    }

    Ok(file
        .customize()
        .insert_header((header::CONTENT_TYPE, "text/javascript")))
}

async fn wasm_handler<Backend>(
    data: web::Data<AppState<Backend>>,
) -> actix_web::Result<impl Responder> {
    Ok(actix_files::NamedFile::open(
        data.assets_path.join("pkg/lldap_app_bg.wasm"),
    )?)
}

async fn wasm_handler_compressed<Backend>(
    data: web::Data<AppState<Backend>>,
) -> actix_web::Result<impl Responder> {
    Ok(
        actix_files::NamedFile::open(data.assets_path.join("pkg/lldap_app_bg.wasm.gz"))?
            .customize()
            .insert_header(header::ContentEncoding::Gzip)
            .insert_header((header::CONTENT_TYPE, "application/wasm")),
    )
}

async fn get_settings<Backend>(data: web::Data<AppState<Backend>>) -> HttpResponse {
    HttpResponse::Ok().json(lldap_frontend_options::Options {
        password_reset_enabled: data.mail_options.enable_password_reset,
        mfa_enabled: mfa_can_be_on(data.mfa_policy, policy_cache()),
        mfa_required: data.mfa_policy == Some(MfaPolicy::Always),
        mfa_server_wide: data.mfa_policy.map(|policy| policy.item().to_owned()),
        domain: data.domain.clone(),
        login_hours_timezone: policy_cache()
            .login_hours_zone()
            .and_then(|zone| zone.iana_name().map(str::to_owned))
            .unwrap_or_default(),
    })
}

// The configuration every worker copies into its AppState.
#[derive(Clone)]
struct WebOptions {
    server_url: url::Url,
    assets_path: PathBuf,
    mail_options: MailOptions,
    mfa_policy: Option<MfaPolicy>,
    domain: String,
    keycloak: Arc<KeycloakSettings>,
}

fn http_config<Backend>(
    cfg: &mut web::ServiceConfig,
    backend_handler: Backend,
    jwt_secret: secstr::SecUtf8,
    jwt_blacklist: HashSet<u64>,
    options: WebOptions,
) where
    Backend: TcpBackendHandler + BackendHandler + LoginHandler + OpaqueHandler + Clone + 'static,
{
    let WebOptions {
        server_url,
        assets_path,
        mail_options,
        mfa_policy,
        domain,
        keycloak,
    } = options;
    let enable_password_reset = mail_options.enable_password_reset;
    cfg.app_data(web::Data::new(AppState::<Backend> {
        backend_handler: AccessControlledBackendHandler::new(backend_handler),
        jwt_key: hmac::Mac::new_from_slice(jwt_secret.unsecure().as_bytes()).unwrap(),
        jwt_blacklist: RwLock::new(jwt_blacklist),
        server_url,
        assets_path: assets_path.clone(),
        mail_options,
        mfa_policy,
        domain,
        keycloak,
    }))
    .route("/health", web::get().to(async || health(&realm_health())))
    .route("/settings", web::get().to(get_settings::<Backend>))
    .service(
        web::scope("/auth")
            .configure(|cfg| auth_service::configure_server::<Backend>(cfg, enable_password_reset)),
    )
    // API endpoint.
    .service(
        web::scope("/api")
            .wrap(auth_service::CookieToHeaderTranslatorFactory)
            .configure(crate::graphql_server::configure_endpoint::<Backend>),
    )
    .service(
        web::resource("/pkg/lldap_app_bg.wasm.gz")
            .route(web::route().to(wasm_handler_compressed::<Backend>)),
    )
    .service(
        web::resource("/pkg/lldap_app_bg.wasm").route(web::route().to(wasm_handler::<Backend>)),
    )
    .service(web::resource("/static/main.js").route(web::route().to(main_js_handler::<Backend>)))
    // Serve the /pkg path with the compiled WASM app.
    .service(Files::new("/pkg", assets_path.join("pkg")))
    // Serve static files
    .service(Files::new("/static", assets_path.join("static")))
    // Serve static fonts
    .service(Files::new(
        "/static/fonts",
        assets_path.join("static/fonts"),
    ))
    // Default to serve index.html for unknown routes, to support routing.
    .default_service(web::route().guard(guard::Get()).to(index::<Backend>));
}

pub(crate) struct AppState<Backend> {
    pub backend_handler: AccessControlledBackendHandler<Backend>,
    pub jwt_key: Hmac<Sha512>,
    pub jwt_blacklist: RwLock<HashSet<u64>>,
    pub server_url: url::Url,
    pub assets_path: PathBuf,
    pub mail_options: MailOptions,
    pub mfa_policy: Option<MfaPolicy>,
    pub domain: String,
    pub keycloak: Arc<KeycloakSettings>,
}

impl<Backend: BackendHandler> AppState<Backend> {
    pub fn get_readonly_handler(&self) -> &(impl ReadonlyBackendHandler + use<Backend>) {
        self.backend_handler.unsafe_get_handler()
    }
}
impl<Backend: TcpBackendHandler> AppState<Backend> {
    pub fn get_tcp_handler(&self) -> &(impl TcpBackendHandler + use<Backend>) {
        self.backend_handler.unsafe_get_handler()
    }
}
impl<Backend: OpaqueHandler> AppState<Backend> {
    pub fn get_opaque_handler(&self) -> &(impl OpaqueHandler + use<Backend>) {
        self.backend_handler.unsafe_get_handler()
    }
}
/// KLLDAP's password path; `get_opaque_handler` stays upstream's.
impl<Backend: BackendHandler + OpaqueHandler> AppState<Backend> {
    pub fn get_password_handler(
        &self,
    ) -> &(impl OpaqueHandler + UserReadableBackendHandler + PolicyBackendHandler + use<Backend>)
    {
        self.backend_handler.unsafe_get_handler()
    }
}
impl<Backend: LoginHandler> AppState<Backend> {
    pub fn get_login_handler(&self) -> &(impl LoginHandler + use<Backend>) {
        self.backend_handler.unsafe_get_handler()
    }
}
impl<Backend: MfaBackendHandler> AppState<Backend> {
    pub fn get_mfa_handler(&self) -> &(impl MfaBackendHandler + use<Backend>) {
        self.backend_handler.unsafe_get_handler()
    }
}

pub async fn build_tcp_server<Backend>(
    config: &Configuration,
    backend_handler: Backend,
    server_builder: ServerBuilder,
) -> Result<ServerBuilder>
where
    Backend: TcpBackendHandler + BackendHandler + LoginHandler + OpaqueHandler + Clone + 'static,
{
    let jwt_secret = config.jwt_secret.clone().unwrap();
    let jwt_blacklist = backend_handler
        .get_jwt_blacklist()
        .await
        .context("while getting the jwt blacklist")?;
    let options = WebOptions {
        server_url: config.http_url.0.clone(),
        assets_path: config.assets_path.clone(),
        mail_options: config.smtp_options.clone(),
        mfa_policy: config.mfa_policy(),
        domain: domain_from_base_dn(&config.ldap_base_dn),
        keycloak: Arc::new(KeycloakSettings {
            base_dn: config.ldap_base_dn.clone(),
            config_file: config.keycloak_options.config_file.clone(),
            admin_pass: config.keycloak_options.admin_pass.clone(),
        }),
    };
    let verbose = config.verbose;
    if !options.assets_path.join("index.html").exists() {
        warn!(
            "Cannot find {}, please ensure that assets_path is set correctly and that the front-end files exist.",
            options.assets_path.to_string_lossy()
        )
    }
    info!("Starting the API/web server on port {}", config.http_port);
    server_builder
        .bind(
            "http",
            (config.http_host.clone(), config.http_port),
            move || {
                let backend_handler = backend_handler.clone();
                let jwt_secret = jwt_secret.clone();
                let jwt_blacklist = jwt_blacklist.clone();
                let options = options.clone();
                HttpServiceBuilder::default()
                    .finish(map_config(
                        App::new()
                            .wrap(from_fn(log_request_scope))
                            .wrap(actix_web::middleware::Condition::new(
                                verbose,
                                tracing_actix_web::TracingLogger::<CustomRootSpanBuilder>::new(),
                            ))
                            .configure(move |cfg| {
                                http_config(
                                    cfg,
                                    backend_handler,
                                    jwt_secret,
                                    jwt_blacklist,
                                    options,
                                )
                            }),
                        |_| AppConfig::default(),
                    ))
                    .tcp()
            },
        )
        .map_err(|e| with_port_hint(e, config.http_port))
        .with_context(|| {
            format!(
                "While bringing up the TCP server with port {}",
                config.http_port
            )
        })
}

#[cfg(test)]
mod networks_rows;

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::body::to_bytes;
    use pretty_assertions::assert_eq;

    #[actix_web::test]
    async fn test_health_names_the_state_and_keeps_the_full_cause_out_of_the_body() {
        use lldap_domain_handlers::kerberos::{ANSWER_UNSETTLED, REALM_LOST, REALM_NOT_OPEN};
        let full = || "stash /data/kerberos/.k5.EXAMPLE.COM, 3 records".to_owned();
        let rows = [
            (RealmHealth::Disabled, 200, None),
            (RealmHealth::Ready, 200, None),
            (
                RealmHealth::Unsettled(ANSWER_UNSETTLED.to_owned()),
                503,
                Some(ANSWER_UNSETTLED),
            ),
            (RealmHealth::Lost(full()), 503, Some(REALM_LOST)),
            (RealmHealth::AdminOnly(full()), 503, Some(REALM_NOT_OPEN)),
            (
                RealmHealth::DirectoryOnly(full()),
                200,
                Some(REALM_NOT_OPEN),
            ),
        ];
        for (realm, status, cause) in rows {
            let state = realm.word();
            let body = match cause {
                Some(cause) => format!(r#"{{"kerberos":"{state}","cause":"{cause}"}}"#),
                None => format!(r#"{{"kerberos":"{state}"}}"#),
            };
            let response = health(&realm);
            let got_status = response.status().as_u16();
            let got_body = to_bytes(response.into_body()).await.unwrap();
            let got_body = String::from_utf8_lossy(&got_body).into_owned();
            assert_eq!((got_status, got_body), (status, body), "{state}");
        }
    }

    #[actix_web::test]
    async fn test_the_settings_name_the_login_hours_zone_and_an_old_answer_still_parses() {
        use crate::auth_service::tests::{ONE_BACKEND, app_state};
        use lldap_domain_handlers::enforcement::{ZONE_FILES, load_zone_from};
        use lldap_test_utils::MockTestBackendHandler;
        let _backend = ONE_BACKEND.lock().await;
        let named = async |name: &str| {
            let loaded = load_zone_from(std::path::Path::new(ZONE_FILES), name).unwrap();
            policy_cache().set_login_hours_zone(loaded.zone);
            let response = get_settings(app_state(MockTestBackendHandler::new())).await;
            let body = to_bytes(response.into_body()).await.unwrap();
            let settings: serde_json::Value = serde_json::from_slice(&body).unwrap();
            settings["login_hours_timezone"].clone()
        };
        let got = (named("America/Chicago").await, named("utc").await);
        assert_eq!(
            got,
            (
                serde_json::json!("America/Chicago"),
                serde_json::json!("UTC")
            ),
            "the zone the cache holds, by name only"
        );
        let old = r#"{"password_reset_enabled":false,"mfa_enabled":false,"mfa_required":false,"mfa_server_wide":null,"domain":"example.com"}"#;
        let parsed: lldap_frontend_options::Options = serde_json::from_str(old).unwrap();
        assert_eq!(
            (parsed.domain, parsed.login_hours_timezone),
            ("example.com".to_owned(), String::new()),
            "an answer without the field still parses"
        );
    }

    #[test]
    fn test_an_internal_error_is_said_within_the_budget_where_it_is_answered_and_no_refusal() {
        use lldap_domain_handlers::logging::capture::{BUDGET, Lines};
        type Failure = fn() -> DomainError;
        let refusal: Failure = || DomainError::AuthenticationError("for bob".to_owned());
        let fault: Failure = || DomainError::InternalError("the database is away".to_owned());
        let busy: Failure = || DomainError::Busy("no permit".to_owned());
        for (failure, status, said) in [(refusal, 401, 0), (fault, 500, BUDGET), (busy, 503, 0)] {
            let (lines, _guard) = Lines::capture();
            for _ in 0..100 {
                let response = error_to_http_response(TcpError::DomainError(failure()));
                assert_eq!(response.status().as_u16(), status);
            }
            assert_eq!(lines.take_loud().len(), said, "{status}");
        }
    }
}
