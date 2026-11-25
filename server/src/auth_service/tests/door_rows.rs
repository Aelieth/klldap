use super::*;
use lldap_domain_handlers::handler::{PolicyBackendHandler, UserBackendHandler};
use lldap_domain_handlers::lockout::{DURATION, THRESHOLD};
use lldap_domain_handlers::mfa::ENABLE_MFA;
use lldap_domain_handlers::policies::CreatePolicyRequest;
use lldap_sql_backend_handler::SqlBackendHandler;
use lldap_test_utils::recording_log::LogGuard;
use pretty_assertions::assert_eq;

const LOCKED_OUT: &str = "locked out";
const INACTIVE: &str = "policy: inactivity-days (inactive)";

type Row = (LogKind, bool, Option<String>);
type State = web::Data<AppState<SqlBackendHandler>>;
type Session = std::result::Result<(MfaPolicy, bool), u16>;
type Held = (u16, Option<bool>, u16, Session, Vec<Row>);

async fn policy_on(handler: &SqlBackendHandler, name: &str, ou: &str, items: &[(&str, &str)]) {
    let items = items
        .iter()
        .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()));
    let request = CreatePolicyRequest {
        name: name.to_owned(),
        description: String::new(),
        items: items.collect(),
    };
    let id = handler.create_policy(request).await.unwrap();
    handler.set_ou_policy(ou, id).await.unwrap();
}

async fn user_in(handler: &SqlBackendHandler, user: &str, ou: &str) {
    let request = lldap_domain::requests::CreateUserRequest {
        user_id: UserId::new(user),
        email: format!("{user}@example.com").into(),
        attributes: vec![Attribute {
            name: "ou".into(),
            value: ou.to_owned().into(),
        }],
        ..Default::default()
    };
    handler.create_user(request).await.unwrap();
}

fn rows(log: &LogGuard, user: &str) -> Vec<Row> {
    let events = log.recorder().take_events().into_iter();
    let ours = events.filter(|e| e.actor.as_deref() == Some(user));
    ours.map(|e| (e.kind, e.success, e.detail)).collect()
}

fn refused(kind: LogKind, detail: &str) -> Row {
    (kind, false, Some(detail.to_owned()))
}

async fn refreshed_by(handler: &SqlBackendHandler, state: &State, user: &str) -> HttpResponse {
    let (refresh, _) = handler
        .create_refresh_token(&UserId::new(user))
        .await
        .unwrap();
    let request = actix_web::test::TestRequest::get()
        .insert_header(("refresh-token", format!("{refresh}+{user}")))
        .to_http_request();
    get_refresh_handler(state.clone(), request).await
}

async fn token_use(state: &State, user: &str) -> u16 {
    let token = session_token(&state.jwt_key, user);
    match check_if_token_is_valid(state, &token).await {
        Ok(_) => 200,
        Err(e) => e.as_response_error().status_code().as_u16(),
    }
}

/// The refresh's status, then a token's at its use.
async fn doors(handler: &SqlBackendHandler, user: &str) -> (u16, u16) {
    let state = app_state(handler.clone());
    let refreshed = refreshed_by(handler, &state, user).await.status().as_u16();
    (refreshed, token_use(&state, user).await)
}

/// The refresh's status and enrolment flag, a token's use, the session's value and hold, the rows.
async fn held_at_the_doors(handler: &SqlBackendHandler, log: &LogGuard, user: &str) -> Held {
    let _ = log.recorder().take_events();
    let state = app_state(handler.clone());
    let (status, body) = answered(refreshed_by(handler, &state, user).await).await;
    let answer = serde_json::from_slice::<login::ServerLoginResponse>(&body);
    let enroll = answer.ok().and_then(|sent| sent.mfa_enrollment_required);
    let used = token_use(&state, user).await;
    let session = session_mfa(&state, &UserId::new(user)).await;
    let session = session.map_err(|e| e.as_response_error().status_code().as_u16());
    (status, enroll, used, session, rows(log, user))
}

#[tokio::test]
async fn test_a_locked_users_refresh_and_token_use_are_refused_with_401_and_one_row_each() {
    let _backend = ONE_BACKEND.lock().await;
    let log = LogGuard::install_on_this_thread();
    let _guard = EnforcementGuard::default_checks();
    let handler = sql_handler_with(&[("e1door", "e1door-pass-1")]).await;
    let lock = [(THRESHOLD, "1"), (DURATION, "0")];
    policy_on(&handler, "e1 lock", "", &lock).await;
    let _ = log.recorder().take_events();
    let unlocked = (doors(&handler, "e1door").await, rows(&log, "e1door"));
    let wrong = BindRequest {
        name: UserId::new("e1door"),
        password: "e1door-wrong-1".to_owned(),
    };
    let bound = (handler.bind(wrong).await.is_ok(), rows(&log, "e1door"));
    let locked = (doors(&handler, "e1door").await, rows(&log, "e1door"));
    handler.clear_ou_policy("").await.unwrap();
    let refreshed: Vec<Row> = vec![(LogKind::TokenRefresh, true, None)];
    assert_eq!(
        unlocked,
        ((200, 200), refreshed),
        "before the wrong password: both admit, the refresh writes its success"
    );
    assert_eq!(
        bound,
        (false, vec![refused(LogKind::Bind, "invalid credentials")]),
        "the wrong password is refused and counted"
    );
    assert_eq!(
        locked,
        (
            (401, 401),
            vec![
                refused(LogKind::TokenRefresh, LOCKED_OUT),
                refused(LogKind::AccessDenied, LOCKED_OUT),
            ]
        ),
        "locked at a threshold of 1 until unlocked: the refresh and a token's use are refused \
         with 401, one row each and no success row"
    );
}

#[tokio::test]
async fn test_a_refresh_row_is_marked_proved_only_once_its_token_was_found() {
    let _backend = ONE_BACKEND.lock().await;
    let log = LogGuard::install_on_this_thread();
    let _guard = EnforcementGuard::default_checks();
    let handler = sql_handler_with(&[("r1fresh", "r1fresh-pass-1")]).await;
    let lock = [(THRESHOLD, "1"), (DURATION, "0")];
    policy_on(&handler, "r1 lock", "", &lock).await;
    let wrong = BindRequest {
        name: UserId::new("r1fresh"),
        password: "r1fresh-wrong-1".to_owned(),
    };
    let _ = handler.bind(wrong).await;
    let _ = log.recorder().take_events();
    let state = app_state(handler.clone());
    let request = actix_web::test::TestRequest::get()
        .insert_header(("refresh-token", "r1-not-held+r1fresh"))
        .to_http_request();
    let not_held = get_refresh_handler(state.clone(), request).await;
    let locked = refreshed_by(&handler, &state, "r1fresh").await;
    handler.clear_ou_policy("").await.unwrap();
    let events = log.recorder().take_events().into_iter();
    let marks: Vec<_> = events
        .filter(|e| e.kind == LogKind::TokenRefresh)
        .map(|e| (e.detail, e.proved))
        .collect();
    assert_eq!(
        (not_held.status().as_u16(), locked.status().as_u16(), marks),
        (
            401,
            401,
            vec![
                (Some("invalid refresh token".to_owned()), false),
                (Some(LOCKED_OUT.to_owned()), true),
            ]
        ),
        "a token the server does not hold, then a held token of a locked user"
    );
}

#[tokio::test]
async fn test_an_inactive_users_refresh_and_token_use_are_refused_with_401_and_one_row_each() {
    let _backend = ONE_BACKEND.lock().await;
    let log = LogGuard::install_on_this_thread();
    let guard = EnforcementGuard::default_checks();
    let handler = sql_handler_with(&[("e6door", "e6door-pass-1")]).await;
    idle_after(&handler, "1").await;
    let _ = log.recorder().take_events();
    let active = (doors(&handler, "e6door").await, rows(&log, "e6door"));
    guard.pin_clock(Timestamp::now() + days(3));
    let idle = (doors(&handler, "e6door").await, rows(&log, "e6door"));
    handler.clear_ou_policy("").await.unwrap();
    let refreshed: Vec<Row> = vec![(LogKind::TokenRefresh, true, None)];
    assert_eq!(
        active,
        ((200, 200), refreshed),
        "within the limit: both admit, the refresh writes its success"
    );
    assert_eq!(
        idle,
        (
            (401, 401),
            vec![
                refused(LogKind::TokenRefresh, INACTIVE),
                refused(LogKind::AccessDenied, INACTIVE),
            ]
        ),
        "three days on, past a limit of one: the refresh and a token's use are refused with 401, \
         one row each and no success row"
    );
}

#[tokio::test]
async fn test_an_ous_always_holds_the_refresh_and_a_tokens_use_to_enrolment_as_server_wide() {
    let _backend = ONE_BACKEND.lock().await;
    let log = LogGuard::install_on_this_thread();
    let _guard = EnforcementGuard::default_checks();
    let server_wide = sql_handler_with(&[])
        .await
        .with_mfa_policy(MfaPolicy::Always);
    user_in(&server_wide, "e2wide", "e2ou").await;
    let wide = held_at_the_doors(&server_wide, &log, "e2wide").await;
    let handler = sql_handler_with(&[]).await.with_mfa_setting(None);
    user_in(&handler, "e2door", "e2ou").await;
    let unset = held_at_the_doors(&handler, &log, "e2door").await;
    policy_on(&handler, "e2 always", "e2ou", &[(ENABLE_MFA, "always")]).await;
    let from_the_ou = held_at_the_doors(&handler, &log, "e2door").await;
    handler.clear_ou_policy("e2ou").await.unwrap();
    let refreshed: Vec<Row> = vec![(LogKind::TokenRefresh, true, None)];
    let enroll: Held = (
        200,
        Some(true),
        200,
        Ok((MfaPolicy::Always, true)),
        refreshed.clone(),
    );
    let off: Held = (200, None, 200, Ok((MfaPolicy::Disabled, false)), refreshed);
    assert_eq!(
        wide, enroll,
        "always server-wide, no factor: the refresh admits and asks to enroll, the token admits \
         and its session is held to enrolment, no refusal row"
    );
    assert_eq!(
        unset, off,
        "nothing set server-wide or on the OU: the same doors ask nothing"
    );
    assert_eq!(
        from_the_ou, wide,
        "always from the user's OU policy, nothing set server-wide: the answers of the \
         server-wide always"
    );
}
