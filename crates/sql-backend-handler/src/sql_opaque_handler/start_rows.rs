use crate::SqlBackendHandler;
use crate::sql_backend_handler::tests::{get_initialized_db, insert_user_no_password};
use crate::sql_lockout_handler::tests as doors;
use lldap_auth::opaque::server::generate_random_private_key;
use lldap_domain::requests::CreateUserRequest;
use lldap_domain::types::{Attribute, LoginOutcome, UserId};
use lldap_domain_handlers::enforcement::{Door, ItemFlags, policy_cache};
use lldap_domain_handlers::handler::UserBackendHandler;
use lldap_domain_handlers::instant::Timestamp;
use lldap_domain_handlers::lockout::{DURATION, LOCKED_OUT, THRESHOLD};
use lldap_domain_handlers::logging::LogKind;
use lldap_domain_handlers::logging::capture::Lines;
use lldap_domain_handlers::mfa::{ENABLE_MFA, MfaPolicy};
use lldap_opaque_handler::{OpaqueHandler, prepare_registration};
use lldap_test_utils::enforcement::EnforcementGuard;
use lldap_test_utils::recording_log::LogGuard;
use pretty_assertions::assert_eq;
use serial_test::serial;
use std::sync::{Arc, Mutex};

const WRONG: &str = "Wrong-Pass-1";
const OUTSIDE: &str = "policy: login-hours (outside login hours)";

type Row = (LogKind, Option<String>, Option<String>);

fn row(user: &str, detail: &str) -> Row {
    (
        LogKind::Login,
        Some(user.to_owned()),
        Some(detail.to_owned()),
    )
}

fn seen(guard: &EnforcementGuard) -> Vec<(Door, bool)> {
    let seen = guard.take_seen().into_iter();
    seen.map(|seen| (seen.door, seen.second_factor)).collect()
}

fn signed_in(user: &str) -> Result<LoginOutcome, &'static str> {
    Ok(LoginOutcome::Authenticated {
        user_id: UserId::new(user),
        mfa_enrollment_pending: false,
    })
}

fn instant(text: &str) -> Timestamp {
    text.parse().unwrap()
}

#[tokio::test]
#[serial]
async fn test_the_items_are_judged_when_a_web_sign_in_starts() {
    let log = LogGuard::install_on_this_thread();
    let h = doors::handler().await;
    doors::user_in(&h, "f5same", "f5sameou").await;
    let guard = EnforcementGuard::refusing(&["f5same"], "login-hours");
    let started = doors::start(&h, "f5same", doors::RIGHT).await;
    let at_start = doors::rows(&log, &[LogKind::Login]);
    let right = doors::finish_request(started, doors::RIGHT, None).is_some();
    let refused = (at_start, seen(&guard), right);
    drop(guard);
    let guard = EnforcementGuard::allowing(&["f5same"], "login-hours");
    let started = doors::start(&h, "f5same", WRONG).await;
    let wrong = doors::finish_request(started, WRONG, None).is_some();
    seen(&guard);
    let admitted = doors::web(&h, "f5same", doors::RIGHT, None).await;
    assert_eq!(
        refused,
        (
            vec![row("f5same", "policy: login-hours")],
            vec![(Door::WebLogin, false)],
            wrong
        ),
        "refused: its one row when the sign-in starts, and the same answer as a wrong password gets"
    );
    assert_eq!(
        (admitted, seen(&guard)),
        (signed_in("f5same"), vec![(Door::WebLogin, false); 2]),
        "admitted: judged when it starts and again after the password; the same password signs in"
    );
}

/// The sign-in rows with their marks: was a password or a proof verified before the row.
fn marks(log: &LogGuard) -> Vec<(LogKind, Option<String>, bool)> {
    let events = log.recorder().take_events().into_iter();
    let doors = events.filter(|e| matches!(e.kind, LogKind::Bind | LogKind::Login));
    doors.map(|e| (e.kind, e.detail, e.proved)).collect()
}

#[tokio::test]
#[serial]
async fn test_a_row_is_marked_proved_only_after_the_password_or_the_proof_verified() {
    let log = LogGuard::install_on_this_thread();
    let h = doors::handler().await;
    doors::user_in(&h, "r1mark", "r1markou").await;
    let allowing = EnforcementGuard::allowing(&["r1mark"], "login-hours");
    let _ = doors::bind_as(&h, "r1mark", WRONG).await;
    let _ = doors::bind_as(&h, "r1mark", doors::RIGHT).await;
    let first = doors::start(&h, "r1mark", doors::RIGHT).await;
    let second = doors::start(&h, "r1mark", doors::RIGHT).await;
    let mut crossed = doors::finish_request(first, doors::RIGHT, None).unwrap();
    crossed.server_data = second.1.server_data;
    let _ = h.login_finish(crossed).await;
    let started = doors::start(&h, "r1mark", doors::RIGHT).await;
    drop(allowing);
    let admitted = marks(&log);
    let _refusing = EnforcementGuard::refusing(&["r1mark"], "login-hours");
    let _ = doors::bind_as(&h, "r1mark", doors::RIGHT).await;
    let finish = doors::finish_request(started, doors::RIGHT, None).unwrap();
    let _ = h.login_finish(finish).await;
    doors::start(&h, "r1mark", doors::RIGHT).await;
    let wrong = Some("invalid credentials".to_owned());
    let hours = Some("policy: login-hours".to_owned());
    assert_eq!(
        admitted,
        vec![
            (LogKind::Bind, wrong.clone(), false),
            (LogKind::Bind, None, true),
            (LogKind::Login, wrong, false),
        ],
        "a wrong password at the bind, a right one, and a finish whose proof does not verify"
    );
    assert_eq!(
        marks(&log),
        vec![
            (LogKind::Bind, hours.clone(), true),
            (LogKind::Login, hours.clone(), true),
            (LogKind::Login, hours, false),
        ],
        "refused by an item: the bind after its password, the finish after its proof, and the \
         start, which comes before any"
    );
}

#[tokio::test]
#[serial]
async fn test_a_name_with_no_password_starts_as_before_and_is_judged_nowhere() {
    let log = LogGuard::install_on_this_thread();
    let h = doors::handler().await;
    insert_user_no_password(&h, "f5nopass").await;
    let guard = EnforcementGuard::refusing(&["f5nopass", "f5nobody"], "login-hours");
    let no_password = doors::web(&h, "f5nopass", doors::RIGHT, None).await;
    let nobody = doors::web(&h, "f5nobody", doors::RIGHT, None).await;
    assert_eq!(
        (
            no_password,
            doors::rows(&log, &[LogKind::Login]),
            seen(&guard)
        ),
        (nobody, vec![], vec![]),
        "answered as an unknown name, with no row and no judgement"
    );
}

#[tokio::test]
#[serial]
async fn test_refused_web_starts_count_nothing_and_the_lock_is_judged_first() {
    let log = LogGuard::install_on_this_thread();
    let guard = EnforcementGuard::default_checks();
    let h = doors::handler().await;
    let hours = ("login-hours", "mon 08:00-18:00");
    for (user, ou, threshold) in [("f5starts", "f5ou3", "3"), ("f5locked", "f5ou1", "1")] {
        doors::user_in(&h, user, ou).await;
        let items = [hours, (THRESHOLD, threshold), (DURATION, "0")];
        doors::policy_on(&h, ou, &items).await;
    }
    policy_cache().set_item_flags(ItemFlags {
        login_hours: true,
        ..ItemFlags::default()
    });
    guard.pin_clock(instant("2026-11-16T07:00:00Z"));
    assert!(!doors::bind(&h, "f5locked", WRONG).await);
    doors::rows(&log, &[LogKind::Login]);
    for _ in 0..5 {
        doors::start(&h, "f5starts", doors::RIGHT).await;
    }
    doors::start(&h, "f5locked", doors::RIGHT).await;
    let user = UserId::new("f5starts");
    let counted = (
        h.lockout.effective(&user).map_or(0, |row| row.fail_count),
        h.lockout.overlays(&user),
        h.lockout.pending(&user),
    );
    assert_eq!(
        (doors::rows(&log, &[LogKind::Login]), counted),
        (
            [
                vec![row("f5starts", OUTSIDE); 5],
                vec![row("f5locked", LOCKED_OUT)]
            ]
            .concat(),
            (0, 0, false)
        ),
        "one row for each refused start, nothing counted; a locked user's start is the lock's row \
         alone"
    );
    guard.pin_clock(instant("2026-11-16T09:00:00Z"));
    assert_eq!(
        doors::web(&h, "f5starts", doors::RIGHT, None).await,
        signed_in("f5starts"),
        "inside the hours the same user signs in: five refused starts locked nothing"
    );
}

#[tokio::test]
#[serial]
async fn test_an_unreadable_enable_mfa_value_refuses_when_a_web_sign_in_starts() {
    let log = LogGuard::install_on_this_thread();
    let h = doors::handler().await;
    doors::user_in(&h, "f5lost", "f5lostou").await;
    doors::policy_on(&h, "f5lostou", &[(THRESHOLD, "3"), (DURATION, "0")]).await;
    insert_user_no_password(&h, "f5bare").await;
    h.policy_cache.set_mfa_item_unknown();
    doors::rows(&log, &[LogKind::Login]);
    let refused = doors::web(&h, "f5lost", doors::RIGHT, None).await;
    let no_password = doors::web(&h, "f5bare", doors::RIGHT, None).await;
    let user = UserId::new("f5lost");
    let counted = (
        h.lockout.effective(&user).map_or(0, |row| row.fail_count),
        h.lockout.overlays(&user),
        h.lockout.pending(&user),
    );
    assert_eq!(
        (refused, doors::rows(&log, &[LogKind::Login]), counted),
        (
            no_password,
            vec![row("f5lost", "policy: unreadable")],
            (0, 0, false)
        ),
        "the right password is answered as a name with no password file is; the refusal is the \
         one row, the name with no password file has none; nothing counted"
    );
}

#[tokio::test]
#[serial]
async fn test_an_enrolled_user_refused_when_the_sign_in_starts_is_asked_for_no_code() {
    let (_clock, at) = doors::pinned();
    let log = LogGuard::install_on_this_thread();
    let h = doors::handler().await.with_mfa_policy(MfaPolicy::Enrolled);
    doors::user_in(&h, "f5coded", "f5codedou").await;
    doors::enroll(&h, "f5coded", at).await;
    let guard = EnforcementGuard::refusing(&["f5coded"], "login-hours");
    let refused = doors::web(&h, "f5coded", doors::RIGHT, None).await;
    let refused = (refused, doors::rows(&log, &[LogKind::Login]), seen(&guard));
    drop(guard);
    let _guard = EnforcementGuard::allowing(&["f5coded"], "login-hours");
    let wrong = doors::web(&h, "f5coded", WRONG, None).await;
    let admitted = doors::web(&h, "f5coded", doors::RIGHT, None).await;
    assert_eq!(
        (refused, admitted),
        (
            (
                wrong,
                vec![row("f5coded", "policy: login-hours")],
                vec![(Door::WebLogin, false)]
            ),
            Ok(LoginOutcome::TotpRequired)
        ),
        "refused when it starts: a wrong password's answer and its one row, no code asked; \
         admitted: the code step"
    );
}

fn bind_row(user: &str, detail: &str) -> Row {
    let (_, user, detail) = row(user, detail);
    (LogKind::Bind, user, detail)
}

#[tokio::test]
#[serial]
async fn test_a_bind_whose_enable_mfa_read_finds_no_user_answers_unknown_user_at_once() {
    let log = LogGuard::install_on_this_thread();
    let statements = Arc::new(Mutex::new(Vec::<String>::new()));
    let mut pool = get_initialized_db().await;
    let seen = statements.clone();
    pool.set_metric_callback(move |info| {
        seen.lock().unwrap().push(info.statement.sql.clone());
    });
    let h = doors::own(SqlBackendHandler::new(generate_random_private_key(), pool));
    doors::policy_on(&h, "r1askou", &[(ENABLE_MFA, "always")]).await;
    statements.lock().unwrap().clear();
    for _ in 0..100 {
        assert!(!doors::bind(&h, "r1nobody", doors::RIGHT).await);
    }
    let sql = statements.lock().unwrap();
    let of_users = |text: &&String| text.contains(r#"FROM "users""#);
    assert_eq!(
        (
            doors::rows(&log, &[LogKind::Bind]),
            sql.iter().filter(of_users).count()
        ),
        (vec![bind_row("r1nobody", "unknown user"); 100], 1),
        "a hundred binds of one name inside the hold: each its unknown-user row, and one read of \
         the users in all, the enable-mfa read; no enrolment and no password file is read"
    );
}

#[tokio::test]
#[serial]
async fn test_a_remembered_miss_refuses_the_bind_and_is_not_asked_once_a_proof_verified() {
    let log = LogGuard::install_on_this_thread();
    let (pool, key) = (get_initialized_db().await, generate_random_private_key());
    let here = doors::own(SqlBackendHandler::new(key.clone(), pool.clone()));
    let elsewhere = doors::own(SqlBackendHandler::new(key, pool));
    doors::policy_on(&here, "r1lateou", &[(ENABLE_MFA, "always")]).await;
    let user = UserId::new("r1late");
    // The slow part of the user's making comes first, so that the rest fits inside the hold.
    let prepared = prepare_registration(&elsewhere, user.clone(), doors::RIGHT.as_bytes());
    let (_, registration) = prepared.await.unwrap();
    assert!(!doors::bind(&here, "r1late", doors::RIGHT).await);
    let request = CreateUserRequest {
        user_id: user,
        email: "r1late@example.com".to_owned().into(),
        attributes: vec![Attribute {
            name: "ou".into(),
            value: "r1lateou".to_owned().into(),
        }],
        ..Default::default()
    };
    elsewhere.create_user(request).await.unwrap();
    elsewhere.registration_finish(registration).await.unwrap();
    doors::rows(&log, &[LogKind::Bind]);
    let bound = doors::bind(&here, "r1late", doors::RIGHT).await;
    let at_bind = doors::rows(&log, &[LogKind::Bind]);
    let confined = LoginOutcome::Authenticated {
        user_id: UserId::new("r1late"),
        mfa_enrollment_pending: true,
    };
    assert_eq!(
        (
            bound,
            at_bind,
            doors::web(&here, "r1late", doors::RIGHT, None).await
        ),
        (
            false,
            vec![bind_row("r1late", "unknown user")],
            Ok(confined)
        ),
        "a user made by another server inside the hold: its bind is answered from the miss; its \
         web sign-in, the proof verified, is read and judged by its OU's always"
    );
}

#[tokio::test]
#[serial]
async fn test_at_a_finish_a_name_that_is_no_user_has_no_lock_only_if_its_proof_did_not_verify() {
    let log = LogGuard::install_on_this_thread();
    let h = doors::handler().await;
    doors::user_in(&h, "r1real", "r1lockou").await;
    doors::user_in(&h, "r1gone", "r1lockou").await;
    doors::policy_on(&h, "r1lockou", &[(THRESHOLD, "3"), (DURATION, "0")]).await;
    let real = doors::start(&h, "r1real", doors::RIGHT).await;
    let ghost = doors::start(&h, "r1ghost", doors::RIGHT).await;
    let mut unverified = doors::finish_request(real, doors::RIGHT, None).unwrap();
    unverified.server_data = ghost.1.server_data;
    let gone = doors::start(&h, "r1gone", doors::RIGHT).await;
    let verified = doors::finish_request(gone, doors::RIGHT, None).unwrap();
    h.delete_user(&UserId::new("r1gone")).await.unwrap();
    doors::rows(&log, &[LogKind::Login]);
    let (lines, _guard) = Lines::capture();
    let rows = [
        ("r1ghost", unverified, "invalid credentials", 0),
        ("r1gone", verified, "policy: unreadable", 1),
    ];
    for (user, finish, detail, said) in rows {
        let refused = h.login_finish(finish).await.is_err();
        let others = lines.take_loud().into_iter();
        assert_eq!(
            (
                refused,
                doors::rows(&log, &[LogKind::Login]),
                others.filter(|line| line.target != "logs").count()
            ),
            (true, vec![row(user, detail)], said),
            "{user}: with a threshold live, a proof that fails for a name with no account is a \
             wrong password's row and no line beside it; a proof that verifies for a user gone \
             since its start is refused as unreadable, with its line"
        );
    }
}
