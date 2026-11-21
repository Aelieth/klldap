use super::*;
use lldap_domain_handlers::enforcement::ALLOWED_NETWORKS;
use lldap_domain_handlers::handler::PolicyBackendHandler;
use lldap_domain_handlers::networks::{parse_list, resolve_client};
use lldap_domain_handlers::policies::CreatePolicyRequest;
use lldap_sql_backend_handler::SqlBackendHandler;
use lldap_test_utils::recording_log::LogGuard;
use pretty_assertions::assert_eq;

const NOT_ALLOWED: &str = "policy: allowed-networks (address not allowed)";

type Row = (LogKind, Option<String>, Option<String>, Option<String>);

/// The request as the HTTP fill site makes it, behind `trusted`.
fn http(peer: &str, forwarded: Option<&str>, trusted: &str) -> RequestMeta {
    let peer = peer.parse().ok();
    let lines: Vec<&str> = forwarded.into_iter().collect();
    let trusted = parse_list(trusted).unwrap();
    RequestMeta {
        client_address: resolve_client(peer, &lines, &trusted),
        ..RequestMeta::http(peer, forwarded.map(str::to_owned))
    }
}

async fn listed_on_the_root(handler: &SqlBackendHandler, list: &str) {
    let request = CreatePolicyRequest {
        name: "e5 nets".to_owned(),
        description: String::new(),
        items: [(ALLOWED_NETWORKS.to_owned(), list.to_owned())].into(),
    };
    let id = handler.create_policy(request).await.unwrap();
    handler.set_ou_policy("", id).await.unwrap();
}

fn refusals(log: &LogGuard, user: &str) -> Vec<Row> {
    let events = log.recorder().take_events().into_iter();
    let ours = events.filter(|e| !e.success && e.actor.as_deref() == Some(user));
    ours.map(|e| (e.kind, e.peer, e.forwarded_for, e.detail))
        .collect()
}

fn row(kind: LogKind, peer: &str, forwarded: Option<&str>, detail: &str) -> Row {
    let forwarded = forwarded.map(str::to_owned);
    (
        kind,
        Some(peer.to_owned()),
        forwarded,
        Some(detail.to_owned()),
    )
}

#[tokio::test]
async fn test_the_refresh_and_a_tokens_use_admit_inside_and_refuse_outside_with_401_and_one_row() {
    let _backend = ONE_BACKEND.lock().await;
    let log = LogGuard::install_on_this_thread();
    let _guard = EnforcementGuard::default_checks();
    let handler = sql_handler_with(&[("e5http", "e5http-pass-1")]).await;
    listed_on_the_root(&handler, "10.73.0.0/16").await;
    let user = UserId::new("e5http");
    let state = app_state(handler.clone());
    let _ = log.recorder().take_events();
    let forwarded = Some("10.73.0.9");
    let metas = [
        http("10.73.0.5", None, ""),
        http("192.0.2.5", None, ""),
        http("10.9.0.1", forwarded, "10.9.0.1/32"),
        http("10.9.0.1", forwarded, ""),
    ];
    let mut answers = Vec::new();
    for meta in metas {
        let (refresh, _) = handler.create_refresh_token(&user).await.unwrap();
        let asked = with_request(meta, async {
            let request = actix_web::test::TestRequest::get()
                .insert_header(("refresh-token", format!("{refresh}+e5http")))
                .to_http_request();
            let refreshed = get_refresh_handler(state.clone(), request).await;
            let token = session_token(&state.jwt_key, "e5http");
            let used = match check_if_token_is_valid(&state, &token).await {
                Ok(_) => 200,
                Err(e) => e.as_response_error().status_code().as_u16(),
            };
            (refreshed.status().as_u16(), used)
        });
        answers.push(asked.await);
    }
    let rows = refusals(&log, "e5http");
    handler.clear_ou_policy("").await.unwrap();
    assert_eq!(
        answers,
        vec![(200, 200), (401, 401), (200, 200), (401, 401)],
        "inside, outside, behind a listed proxy, behind the same proxy unlisted"
    );
    assert_eq!(
        rows,
        vec![
            row(LogKind::TokenRefresh, "192.0.2.5", None, NOT_ALLOWED),
            row(LogKind::AccessDenied, "192.0.2.5", None, NOT_ALLOWED),
            row(LogKind::TokenRefresh, "10.9.0.1", forwarded, NOT_ALLOWED),
            row(LogKind::AccessDenied, "10.9.0.1", forwarded, NOT_ALLOWED),
        ],
        "one row each; the row keeps the socket peer and the header as they came"
    );
}

#[tokio::test]
async fn test_a_right_password_from_outside_gets_a_wrong_ones_body_byte_for_byte() {
    const PASSWORD: &str = "e5body-pass-1";
    let _backend = ONE_BACKEND.lock().await;
    let _guard = EnforcementGuard::default_checks();
    let handler = sql_handler_with(&[("e5body", PASSWORD)]).await;
    listed_on_the_root(&handler, "10.73.0.0/16").await;
    let state = app_state(handler.clone());
    let simple = async |meta: RequestMeta, password: &str| {
        let request = login::ClientSimpleLoginRequest {
            username: UserId::new("e5body"),
            password: password.to_owned(),
            enrollment_proof: None,
        };
        let response = with_request(
            meta,
            simple_login_handler(state.clone(), web::Json(request)),
        );
        answered(response.await).await
    };
    let finish = async |meta: RequestMeta| {
        let response = with_request(meta, async {
            let request = login_finish_request(&state, "e5body", PASSWORD).await;
            opaque_login_finish_handler(state.clone(), web::Json(request)).await
        });
        answered(response.await).await
    };
    let start = async |meta: RequestMeta, password: &str| {
        with_request(meta, login_start_answer(&state, "e5body", password)).await
    };
    let (inside, outside) = (http("10.73.0.5", None, ""), http("192.0.2.5", None, ""));
    let simple_in = simple(inside.clone(), PASSWORD).await.0;
    let finish_in = finish(inside.clone()).await.0;
    let simple_out = (
        simple(outside.clone(), PASSWORD).await,
        simple(outside.clone(), "e5body-wrong-1").await,
    );
    let start_out = (
        start(outside, PASSWORD).await,
        start(inside, "e5body-wrong-1").await,
    );
    handler.clear_ou_policy("").await.unwrap();
    assert_eq!((simple_in, finish_in), (200, 200), "from inside");
    assert_eq!(
        simple_out.0.0,
        401,
        "{:?}",
        String::from_utf8_lossy(&simple_out.0.1)
    );
    assert_eq!(
        simple_out.0, simple_out.1,
        "the simple login from outside: the right password and a wrong one"
    );
    assert_eq!(
        (start_out.0.0, start_out.0.2),
        (200, false),
        "{:?}",
        start_out.0
    );
    assert_eq!(
        start_out.0, start_out.1,
        "the web login: the right password from outside fails as a wrong one from inside does, \
         the start's status and body keys alike"
    );
}

#[tokio::test]
async fn test_an_enrolled_user_outside_gets_a_wrong_passwords_body_before_any_code() {
    const PASSWORD: &str = "e3code-pass-1";
    let _backend = ONE_BACKEND.lock().await;
    let log = LogGuard::install_on_this_thread();
    let _guard = EnforcementGuard::default_checks();
    let (handler, _clock, _) = doors_directory().await;
    listed_on_the_root(&handler, "10.73.0.0/16").await;
    let state = app_state(handler.clone());
    let simple = async |meta: RequestMeta, password: &str| {
        let request = login::ClientSimpleLoginRequest {
            username: UserId::new("e3code"),
            password: password.to_owned(),
            enrollment_proof: None,
        };
        let response = with_request(
            meta,
            simple_login_handler(state.clone(), web::Json(request)),
        );
        answered(response.await).await
    };
    let finish = async |meta: RequestMeta| {
        let response = with_request(meta, async {
            let request = login_finish_request(&state, "e3code", PASSWORD).await;
            opaque_login_finish_handler(state.clone(), web::Json(request)).await
        });
        answered(response.await).await
    };
    let start = async |meta: RequestMeta, password: &str| {
        with_request(meta, login_start_answer(&state, "e3code", password)).await
    };
    let (inside, outside) = (http("10.73.0.5", None, ""), http("192.0.2.5", None, ""));
    let _ = log.recorder().take_events();
    let simple_out = (
        simple(outside.clone(), PASSWORD).await,
        simple(outside.clone(), "e3code-wrong-1").await,
    );
    let start_out = (
        start(outside, PASSWORD).await,
        start(inside.clone(), "e3code-wrong-1").await,
    );
    let simple_in = simple(inside.clone(), PASSWORD).await;
    let finish_in = finish(inside).await;
    let rows = refusals(&log, "e3code");
    handler.clear_ou_policy("").await.unwrap();
    assert_eq!(
        (simple_out.0.0, start_out.0.0, start_out.0.2),
        (401, 200, false),
        "{:?} {:?}",
        String::from_utf8_lossy(&simple_out.0.1),
        start_out.0
    );
    assert_eq!(
        (simple_out.0, start_out.0),
        (simple_out.1.clone(), start_out.1),
        "the right password with no code from outside answers as a wrong password: at the simple \
         login, status and body; at the web login, as a wrong one from inside, the start's status \
         and body keys alike"
    );
    assert_eq!(simple_in.0, 401, "from inside the code is asked for");
    assert_ne!(simple_in, simple_out.1, "and that answer is the code's own");
    assert_eq!(
        finish_in,
        (200, br#"{"mfaRequired":true}"#.to_vec()),
        "the web login asks for the code from inside, as today"
    );
    let (out, inn) = ("192.0.2.5", "10.73.0.5");
    assert_eq!(
        rows,
        vec![
            row(LogKind::Bind, out, None, NOT_ALLOWED),
            row(LogKind::Bind, out, None, "invalid credentials"),
            row(LogKind::Login, out, None, NOT_ALLOWED),
            row(LogKind::Bind, inn, None, "totp code required"),
            row(LogKind::Login, inn, None, "totp code required"),
        ],
        "the item's row for the right password from outside at each door, the wrong password's \
         at the simple login, the code's from inside"
    );
}
