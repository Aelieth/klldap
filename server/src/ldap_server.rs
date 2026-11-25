use crate::configuration::{Configuration, LdapsOptions};
use crate::tls;
use actix_rt::net::TcpStream;
use actix_server::ServerBuilder;
use actix_service::{ServiceFactoryExt, fn_service};
use anyhow::{Context, Result};
use ldap3_proto::{LdapCodec, control::LdapControl, proto::LdapMsg, proto::LdapOp};
use lldap_access_control::AccessControlledBackendHandler;
use lldap_domain_handlers::handler::{BackendHandler, LoginHandler};
use lldap_domain_handlers::{info_limited, warn_limited};
use lldap_kerberos::boot::with_port_hint;
use lldap_ldap::{LdapHandler, LdapInfo};
use lldap_opaque_handler::OpaqueHandler;
use std::net::IpAddr;
use tokio_rustls::TlsAcceptor as RustlsTlsAcceptor;
use tokio_util::codec::{FramedRead, FramedWrite};
use tracing::{debug, info, instrument};
use uuid::Uuid;

#[instrument(skip_all, level = "debug", name = "LDAP request", fields(session_id = %session.session_uuid()))]
async fn handle_ldap_message<Backend, Writer>(
    msg: Result<LdapMsg, std::io::Error>,
    resp: &mut Writer,
    session: &mut LdapHandler<Backend>,
) -> Result<bool>
where
    Backend: BackendHandler + LoginHandler + OpaqueHandler,
    Writer: futures_util::Sink<LdapMsg> + Unpin,
    <Writer as futures_util::Sink<LdapMsg>>::Error: std::error::Error + Send + Sync + 'static,
{
    use futures_util::SinkExt;
    let msg = msg.context("while receiving LDAP op")?;
    for control in msg.ctrl.iter() {
        if let LdapControl::Unknown { oid, .. } = control {
            debug!("Received unknown control: {}, ignoring", oid);
        }
    }
    debug!(?msg);

    // Modify, add, delete and extended still matter to an admin at info; binds have their
    // own log events, and searches (the 30-second keepalive pings) stay debug.
    let is_real_operation = matches!(
        msg.op,
        LdapOp::ModifyRequest(_)
            | LdapOp::AddRequest(_)
            | LdapOp::DelRequest(_)
            | LdapOp::ExtendedRequest(_)
    );

    match session.handle_ldap_message(msg.op).await {
        None => return Ok(false),
        Some(result) => {
            if result.is_empty() {
                debug!("No response");
            }

            if is_real_operation {
                info_limited!("LDAP request session_id: {}", session.session_uuid());
            } else {
                debug!("LDAP request session_id: {}", session.session_uuid());
            }

            let results: i64 = result.len().try_into().unwrap();
            for response in result.into_iter() {
                debug!(?response);
                let controls = if matches!(response, LdapOp::SearchResultDone(_)) {
                    vec![LdapControl::SimplePagedResults {
                        size: results - 1,
                        cookie: vec![],
                    }]
                } else {
                    vec![]
                };
                resp.send(LdapMsg {
                    msgid: msg.msgid,
                    op: response,
                    ctrl: controls,
                })
                .await
                .context("while sending a response: {:#}")?
            }

            resp.flush()
                .await
                .context("while flushing responses: {:#}")?
        }
    }
    Ok(true)
}

async fn handle_ldap_stream<Stream, Backend>(
    stream: Stream,
    backend_handler: Backend,
    ldap_info: &'static LdapInfo,
    peer: Option<IpAddr>,
) -> Result<Stream>
where
    Backend: BackendHandler + LoginHandler + OpaqueHandler + 'static,
    Stream: tokio::io::AsyncRead + tokio::io::AsyncWrite + std::marker::Unpin,
{
    use tokio_stream::StreamExt;
    let (r, w) = tokio::io::split(stream);
    let mut requests = FramedRead::new(r, LdapCodec::default());
    let mut resp = FramedWrite::new(w, LdapCodec::default());

    let session_uuid = Uuid::new_v4();
    let mut session = LdapHandler::new(
        AccessControlledBackendHandler::new(backend_handler),
        ldap_info,
        session_uuid,
        peer,
    );

    debug!("LDAP session start: {}", session_uuid);

    while let Some(msg) = requests.next().await {
        if !handle_ldap_message(msg, &mut resp, &mut session)
            .await
            .context("while handling incoming messages")?
        {
            break;
        }
    }

    debug!("LDAP session end: {}", session_uuid);
    Ok(requests.into_inner().unsplit(resp.into_inner()))
}

fn get_tls_acceptor(ldaps_options: &LdapsOptions) -> Result<RustlsTlsAcceptor> {
    let certs = tls::load_certificates(&ldaps_options.cert_file)?;
    let private_key = tls::load_private_key(&ldaps_options.key_file)?;

    let server_config = std::sync::Arc::new(
        rustls::ServerConfig::builder_with_provider(
            rustls::crypto::ring::default_provider().into(),
        )
        .with_safe_default_protocol_versions()
        .context("Failed to set default protocol versions")?
        .with_no_client_auth()
        .with_single_cert(certs, private_key)?,
    );
    Ok(server_config.into())
}

pub fn build_ldap_server<Backend>(
    config: &Configuration,
    backend_handler: Backend,
    server_builder: ServerBuilder,
) -> Result<ServerBuilder>
where
    Backend: BackendHandler + LoginHandler + OpaqueHandler + Clone + 'static,
{
    let context = (
        backend_handler,
        Box::leak(Box::new(
            LdapInfo::new(
                &config.ldap_base_dn,
                config.ignored_user_attributes.clone(),
                config.ignored_group_attributes.clone(),
            )
            .with_context(|| {
                format!(
                    "Invalid value for ldap_base_dn in configuration: {}",
                    config.ldap_base_dn
                )
            })?,
        )) as &'static LdapInfo,
    );

    let context_for_tls = context.clone();

    let binder = move || {
        let context = context.clone();
        fn_service(move |stream: TcpStream| {
            let context = context.clone();
            async move {
                let (handler, ldap_info) = context;
                let peer = stream.peer_addr().ok().map(|addr| addr.ip());
                handle_ldap_stream(stream, handler, ldap_info, peer).await
            }
        })
        .map_err(|err: anyhow::Error| warn_limited!("[LDAP] Service Error: {:#}", err))
    };

    info!("Starting the LDAP server on port {}", config.ldap_port);
    let server_builder = server_builder
        .bind("ldap", (config.ldap_host.clone(), config.ldap_port), binder)
        .map_err(|e| with_port_hint(e, config.ldap_port))
        .with_context(|| format!("while binding to the port {}", config.ldap_port));
    if config.ldaps_options.enabled {
        let tls_context = (
            context_for_tls,
            get_tls_acceptor(&config.ldaps_options)
                .context("while setting up the SSL certificate")?,
        );
        let tls_binder = move || {
            let tls_context = tls_context.clone();
            fn_service(move |stream: TcpStream| {
                let tls_context = tls_context.clone();
                async move {
                    let ((handler, ldap_info), tls_acceptor) = tls_context;
                    let peer = stream.peer_addr().ok().map(|addr| addr.ip());
                    let tls_stream = tls_acceptor.accept(stream).await?;
                    handle_ldap_stream(tls_stream, handler, ldap_info, peer).await
                }
            })
            .map_err(|err: anyhow::Error| warn_limited!("[LDAPS] Service Error: {:#}", err))
        };

        info!(
            "Starting the LDAPS server on port {}",
            config.ldaps_options.port
        );
        server_builder.and_then(|s| {
            s.bind(
                "ldaps",
                (config.ldap_host.clone(), config.ldaps_options.port),
                tls_binder,
            )
            .map_err(|e| with_port_hint(e, config.ldaps_options.port))
            .with_context(|| format!("while binding to the port {}", config.ldaps_options.port))
        })
    } else {
        server_builder
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth_service::tests::{ONE_BACKEND, sql_handler_with};
    use ldap3_proto::proto::{
        LdapBindCred, LdapBindRequest, LdapExtendedRequest, LdapResultCode, OID_WHOAMI,
    };
    use lldap_domain_handlers::logging::{LogKind, Protocol};
    use lldap_test_utils::enforcement::EnforcementGuard;
    use lldap_test_utils::recording_log::LogGuard;
    use pretty_assertions::assert_eq;

    fn bind(user: &str, password: &str) -> LdapOp {
        LdapOp::BindRequest(LdapBindRequest {
            dn: format!("uid={user},ou=people,dc=example,dc=com"),
            cred: LdapBindCred::Simple(password.to_owned()),
        })
    }

    fn answered(ops: Option<Vec<LdapOp>>) -> (LdapResultCode, String) {
        match ops.as_deref() {
            Some([LdapOp::BindResponse(r)]) => (r.res.code.clone(), r.res.message.clone()),
            Some([LdapOp::ExtendedResponse(r)]) => (r.res.code.clone(), r.res.message.clone()),
            other => panic!("unexpected answer {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_a_failed_bind_keeps_the_connections_identity_and_its_row_names_the_peer() {
        let _backend = ONE_BACKEND.lock().await;
        let users = [("e0first", "e0first-pass-1"), ("e0ldap", "e0ldap-pass-1")];
        let handler = sql_handler_with(&users).await;
        let log = LogGuard::install_on_this_thread();
        let _guard = EnforcementGuard::refusing(&["e0ldap"], "login-hours");
        let info = LdapInfo::new("dc=example,dc=com", Vec::new(), Vec::new()).unwrap();
        let peer: IpAddr = "198.51.100.7".parse().unwrap();
        let backend = AccessControlledBackendHandler::new(handler);
        let mut session = LdapHandler::new(
            backend,
            Box::leak(Box::new(info)),
            Uuid::new_v4(),
            Some(peer),
        );
        let whoami = LdapOp::ExtendedRequest(LdapExtendedRequest {
            name: OID_WHOAMI.to_owned(),
            value: None,
        });
        let first = "dn:uid=e0first,ou=people,dc=example,dc=com".to_owned();
        type Row<'a> = (&'a str, LdapOp, LdapResultCode, Option<(&'a str, &'a str)>);
        let rows: [Row; 3] = [
            (
                "bound",
                bind("e0first", "e0first-pass-1"),
                LdapResultCode::Success,
                None,
            ),
            (
                "a wrong password",
                bind("e0first", "e0first-wrong-1"),
                LdapResultCode::InvalidCredentials,
                Some(("e0first", "invalid credentials")),
            ),
            (
                "a policy refusal",
                bind("e0ldap", "e0ldap-pass-1"),
                LdapResultCode::InvalidCredentials,
                Some(("e0ldap", "policy: login-hours")),
            ),
        ];
        for (label, request, code, failure) in rows {
            let bound = answered(session.handle_ldap_message(request).await);
            let identity = answered(session.handle_ldap_message(whoami.clone()).await);
            let events = log.recorder().take_events().into_iter();
            let failed: Vec<_> = events
                .filter(|e| !e.success)
                .map(|e| (e.kind, e.protocol, e.actor, e.peer, e.detail))
                .collect();
            let row = failure.map(|(actor, detail)| {
                let actor = Some(actor.to_owned());
                (
                    LogKind::Bind,
                    Protocol::Ldap,
                    actor,
                    Some(peer.to_string()),
                    Some(detail.to_owned()),
                )
            });
            assert_eq!(
                (bound, identity, failed),
                (
                    (code, String::new()),
                    (LdapResultCode::Success, first.clone()),
                    row.into_iter().collect::<Vec<_>>()
                ),
                "{label}: upstream keeps the earlier identity after a failed bind"
            );
        }
    }

    type Answer = (LdapResultCode, String);
    type Bound = (Answer, Answer, Vec<(bool, Option<String>, Option<String>)>);

    async fn bind_and_ask_who<B>(backend: B, log: &LogGuard, dn: String, password: String) -> Bound
    where
        B: BackendHandler + LoginHandler + OpaqueHandler,
    {
        let info = LdapInfo::new("dc=example,dc=com", Vec::new(), Vec::new()).unwrap();
        let peer: IpAddr = "198.51.100.33".parse().unwrap();
        let mut session = LdapHandler::new(
            AccessControlledBackendHandler::new(backend),
            Box::leak(Box::new(info)),
            Uuid::new_v4(),
            Some(peer),
        );
        let bind = LdapOp::BindRequest(LdapBindRequest {
            dn,
            cred: LdapBindCred::Simple(password),
        });
        let bound = answered(session.handle_ldap_message(bind).await);
        let binds = log
            .recorder()
            .take_events()
            .into_iter()
            .filter(|e| e.kind == LogKind::Bind)
            .map(|e| (e.success, e.actor, e.detail))
            .collect();
        let whoami = LdapOp::ExtendedRequest(LdapExtendedRequest {
            name: OID_WHOAMI.to_owned(),
            value: None,
        });
        let identity = answered(session.handle_ldap_message(whoami).await);
        let _ = log.recorder().take_events();
        (bound, identity, binds)
    }

    #[tokio::test]
    async fn test_a_bind_with_a_name_and_no_password_is_refused_before_any_lookup() {
        use crate::auth_service::tests::doors_directory;
        use lldap_test_utils::MockTestBackendHandler;
        let _backend = ONE_BACKEND.lock().await;
        let _guard = EnforcementGuard::none();
        let (handler, _clock, code) = doors_directory().await;
        let log = LogGuard::install_on_this_thread();
        let refused: Answer = (
            LdapResultCode::UnwillingToPerform,
            "a bind with a name needs a password".to_owned(),
        );
        let wrong: Answer = (LdapResultCode::InvalidCredentials, String::new());
        let unbound: Answer = (
            LdapResultCode::InsufficentAccessRights,
            "No user currently bound".to_owned(),
        );
        type Case = (
            String,
            bool,
            &'static str,
            &'static str,
            String,
            Answer,
            Answer,
            (bool, Option<&'static str>),
        );
        let mut cases: Vec<Case> = Vec::new();
        let names = [
            ("a user", "e3plain", "people"),
            ("a disabled user", "e3off", "people"),
            ("an enrolled user", "e3code", "people"),
            ("an unknown name", "e3nobody", "people"),
            ("a user under another OU", "e3plain", "lab"),
            ("an unknown name under another OU", "e3nobody", "lab"),
        ];
        for (who, user, ou) in names {
            for (what, password) in [
                ("no password", String::new()),
                ("a code alone", format!(":{code}")),
            ] {
                for (place, mock) in [("", false), (", a backend that answers nothing", true)] {
                    cases.push((
                        format!("{who}, {what}{place}"),
                        mock,
                        user,
                        ou,
                        password.clone(),
                        refused.clone(),
                        unbound.clone(),
                        (false, Some("no password given")),
                    ));
                }
            }
        }
        cases.extend([
            (
                "control: a user, a wrong password".to_owned(),
                false,
                "e3plain",
                "people",
                "e3plain-wrong-1".to_owned(),
                wrong.clone(),
                unbound.clone(),
                (false, Some("invalid credentials")),
            ),
            (
                "control: a disabled user, the password".to_owned(),
                false,
                "e3off",
                "people",
                "e3off-pass-1".to_owned(),
                wrong.clone(),
                unbound.clone(),
                (false, Some("account disabled")),
            ),
            (
                "control: an enrolled user, the password alone".to_owned(),
                false,
                "e3code",
                "people",
                "e3code-pass-1".to_owned(),
                (
                    LdapResultCode::InvalidCredentials,
                    "TOTP code required: append ':' and the code".to_owned(),
                ),
                unbound.clone(),
                (false, Some("totp code required")),
            ),
            (
                "control: an unknown name, a password".to_owned(),
                false,
                "e3nobody",
                "people",
                "e3plain-wrong-1".to_owned(),
                wrong.clone(),
                unbound.clone(),
                (false, Some("unknown user")),
            ),
            (
                "control: a user under another OU, the password".to_owned(),
                false,
                "e3plain",
                "lab",
                "e3plain-pass-1".to_owned(),
                wrong,
                unbound,
                (false, Some("ou mismatch")),
            ),
            (
                "control: a user, the password".to_owned(),
                false,
                "e3plain",
                "people",
                "e3plain-pass-1".to_owned(),
                (LdapResultCode::Success, String::new()),
                (
                    LdapResultCode::Success,
                    "dn:uid=e3plain,ou=people,dc=example,dc=com".to_owned(),
                ),
                (true, None),
            ),
        ]);
        let (mut got, mut wanted) = (Vec::new(), Vec::new());
        for (label, mock, user, ou, password, bind_answer, whoami_answer, row) in cases {
            let dn = format!("uid={user},ou={ou},dc=example,dc=com");
            let answers = match mock {
                true => bind_and_ask_who(MockTestBackendHandler::new(), &log, dn, password).await,
                false => bind_and_ask_who(handler.clone(), &log, dn, password).await,
            };
            let (success, detail) = row;
            let row = (success, Some(user.to_owned()), detail.map(str::to_owned));
            got.push((label.clone(), answers));
            wanted.push((label, (bind_answer, whoami_answer, vec![row])));
        }
        assert_eq!(
            got, wanted,
            "per row: the bind's answer, who the connection is after it, its one row"
        );
    }

    #[tokio::test]
    async fn test_an_unknown_control_prints_nothing_and_a_requests_line_shares_the_budget() {
        use lldap_domain_handlers::logging::capture::{BUDGET, Lines};
        use lldap_test_utils::MockTestBackendHandler;
        let info = LdapInfo::new("dc=example,dc=com", Vec::new(), Vec::new()).unwrap();
        let info: &'static LdapInfo = Box::leak(Box::new(info));
        let backend = AccessControlledBackendHandler::new(MockTestBackendHandler::new());
        let mut session = LdapHandler::new(backend, info, Uuid::new_v4(), None);
        let unknown = || LdapControl::Unknown {
            oid: "1.2.3.4".to_owned(),
            criticality: false,
            value: None,
        };
        let whoami = LdapOp::ExtendedRequest(LdapExtendedRequest {
            name: OID_WHOAMI.to_owned(),
            value: None,
        });
        let (lines, _guard) = Lines::capture();
        let mut answers: Vec<LdapMsg> = Vec::new();
        for msgid in 0..100 {
            let msg = LdapMsg {
                msgid,
                op: whoami.clone(),
                ctrl: vec![unknown(), unknown()],
            };
            let served = handle_ldap_message(Ok(msg), &mut answers, &mut session).await;
            assert!(served.unwrap(), "{msgid}");
        }
        let loud = lines.take_loud();
        let of_requests = |text: &str| loud.iter().filter(|l| l.text.starts_with(text)).count();
        assert_eq!(
            (
                of_requests("Received unknown control"),
                of_requests("LDAP request session_id") > 0,
                loud.len()
            ),
            (0, true, BUDGET),
            "200 unknown controls on 100 unbound requests: {loud:?}"
        );
    }
}
