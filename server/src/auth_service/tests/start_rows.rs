use super::*;
use pretty_assertions::assert_eq;

const PASSWORD: &str = "f5http-pass-1";

/// The start's status, its body's keys and the length of its `server_data`.
async fn start_shape(
    state: &web::Data<AppState<lldap_sql_backend_handler::SqlBackendHandler>>,
    user: &str,
) -> (u16, Vec<String>, usize) {
    let start = opaque::client::login::start_login(PASSWORD, &mut rand::rngs::OsRng).unwrap();
    let request = login::ClientLoginStartRequest {
        username: UserId::new(user),
        login_start_request: start.message,
    };
    let meta = RequestMeta::http(Some("192.0.2.65".parse().unwrap()), None);
    match with_request(meta, opaque_login_start(state.clone(), web::Json(request))).await {
        actix_web::Either::Left(answer) => {
            let body = serde_json::to_value(&answer.0).unwrap();
            let keys = body.as_object().unwrap().keys().cloned().collect();
            (200, keys, answer.0.server_data.len())
        }
        actix_web::Either::Right(response) => (response.status().as_u16(), vec![], 0),
    }
}

#[tokio::test]
async fn test_a_web_start_answers_alike_whether_the_items_refuse_or_admit() {
    let _backend = ONE_BACKEND.lock().await;
    let handler = sql_handler_with(&[("f5http", PASSWORD)]).await;
    let state = app_state(handler);
    let refusing = EnforcementGuard::refusing(&["f5http"], "login-hours");
    let refused = start_shape(&state, "f5http").await;
    drop(refusing);
    let _allowing = EnforcementGuard::allowing(&["f5http"], "login-hours");
    let admitted = start_shape(&state, "f5http").await;
    assert_eq!(refused.0, 200, "a refused start is answered");
    assert_eq!(refused, admitted, "the same status and the same shape");
}
