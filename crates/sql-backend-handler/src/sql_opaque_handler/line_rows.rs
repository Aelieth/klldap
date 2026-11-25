use crate::SqlBackendHandler;
use crate::sql_backend_handler::tests::{insert_group, insert_membership};
use crate::sql_lockout_handler::tests as doors;
use crate::sql_used_starts::tests::{session, web_registration};
use lldap_auth::{login, opaque};
use lldap_domain::types::UserId;
use lldap_domain_handlers::lockout::{DURATION, THRESHOLD};
use lldap_domain_handlers::logging::capture::{BUDGET, Lines};
use lldap_opaque_handler::OpaqueHandler;
use lldap_test_utils::enforcement::EnforcementGuard;
use pretty_assertions::assert_eq;
use sea_orm::ConnectionTrait;
use serial_test::serial;
use tracing::Level;

const REQUESTS: usize = 100;

enum Request {
    Bind(&'static str),
    /// `#` in the name is the request's number.
    Start(&'static str),
    Finish(Box<login::ClientLoginFinishRequest>),
}

async fn send(h: &SqlBackendHandler, request: &Request, number: usize) {
    match request {
        Request::Bind(user) => {
            let _ = doors::bind_as(h, user, doors::RIGHT).await;
        }
        Request::Start(user) => {
            let mut rng = rand::rngs::OsRng;
            let start = opaque::client::login::start_login(doors::RIGHT, &mut rng).unwrap();
            let request = login::ClientLoginStartRequest {
                username: UserId::new(&user.replace('#', &number.to_string())),
                login_start_request: start.message,
            };
            let _ = h.login_start(request).await;
        }
        Request::Finish(finish) => {
            let _ = h.login_finish(finish.as_ref().clone()).await;
        }
    }
}

/// Of a hundred requests' lines at INFO and above: the event lines, and the others' texts.
async fn printed(h: &SqlBackendHandler, request: &Request) -> (usize, Vec<String>) {
    let (lines, _guard) = Lines::capture();
    for number in 0..REQUESTS {
        send(h, request, number).await;
    }
    let loud = lines.take_loud();
    let events = loud.iter().filter(|line| line.target == "logs").count();
    let others = loud.into_iter().filter(|line| line.target != "logs");
    (events, others.map(|line| line.text).collect())
}

/// Half the budget each: a line with the cause, then the row's line.
async fn assert_both_limited(h: &SqlBackendHandler, request: &Request, cause: &str, label: &str) {
    let (events, others) = printed(h, request).await;
    let with_cause = others.iter().filter(|text| text.starts_with(cause)).count();
    assert_eq!(
        (events, with_cause, others.len()),
        (BUDGET / 2, BUDGET / 2, BUDGET / 2),
        "{label}: {others:?}"
    );
}

async fn finish_of(h: &SqlBackendHandler, user: &str) -> Box<login::ClientLoginFinishRequest> {
    let started = doors::start(h, user, doors::RIGHT).await;
    Box::new(doors::finish_request(started, doors::RIGHT, None).unwrap())
}

#[tokio::test]
#[serial]
async fn test_a_hundred_refused_requests_print_the_rows_lines_alone_within_the_budget() {
    let h = doors::handler().await;
    doors::user_in(&h, "c1off", "c1ou").await;
    doors::user_in(&h, "c1plain", "c1ou").await;
    doors::user_in(&h, "c1locked", "c1lockou").await;
    let off = finish_of(&h, "c1off").await;
    let disabled = insert_group(&h, "lldap_disabled").await;
    insert_membership(&h, disabled, "c1off").await;
    let mut unverified = finish_of(&h, "c1plain").await;
    let another = *finish_of(&h, "c1plain").await;
    unverified.credential_finalization = another.credential_finalization;
    doors::policy_on(&h, "c1lockou", &[(THRESHOLD, "1"), (DURATION, "0")]).await;
    assert!(!doors::bind(&h, "c1locked", "Wrong-Pass-1").await);
    let rows = [
        ("bind, disabled", Request::Bind("c1off"), BUDGET),
        ("start, disabled", Request::Start("c1off"), BUDGET),
        ("finish, disabled", Request::Finish(off), BUDGET),
        ("bind, locked", Request::Bind("c1locked"), BUDGET),
        ("start, locked", Request::Start("c1locked"), BUDGET),
        ("start, no account", Request::Start("c1nobody#"), 0),
        ("finish, unverified", Request::Finish(unverified), BUDGET),
    ];
    for (label, request, events) in rows {
        assert_eq!(printed(&h, &request).await, (events, vec![]), "{label}");
    }
    let bind = Request::Bind("c1plain");
    h.policy_cache.set_lockout_unknown();
    assert_both_limited(&h, &bind, "The lockout of", "the lockout unread").await;
    h.policy_cache.set_mfa_item_unknown();
    assert_both_limited(&h, &bind, "The OU policy of", "the enable-mfa value unread").await;
}

#[tokio::test]
#[serial]
async fn test_a_policy_that_cannot_be_read_when_a_web_sign_in_starts_is_said_within_the_budget() {
    let h = doors::handler().await;
    doors::user_in(&h, "c1unread", "c1unreadou").await;
    let dropped = h.sql_pool.execute_unprepared("DROP TABLE ou_policies");
    dropped.await.unwrap();
    let _guard = EnforcementGuard::allowing(&["c1unread"], "login-hours");
    let start = Request::Start("c1unread");
    assert_both_limited(&h, &start, "The policy of", "the policy unread").await;
}

#[tokio::test]
async fn test_a_registration_finish_with_junk_server_data_prints_no_line_at_error() {
    let h = doors::handler().await;
    let bob = session("bob", 1);
    let mut request = web_registration(&h, "bob", "bob-new-1", &bob, None).await;
    request.server_data = "junk".to_owned();
    let (lines, _guard) = Lines::capture();
    let refused = h.registration_claim(&request, &bob).await;
    let levels: Vec<_> = lines.take().into_iter().map(|line| line.level).collect();
    assert!(
        refused.is_err() && !levels.is_empty() && !levels.contains(&Level::ERROR),
        "the refusal is said, at debug: {levels:?}"
    );
}
