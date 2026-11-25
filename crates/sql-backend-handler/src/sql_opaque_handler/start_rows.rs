use crate::sql_backend_handler::tests::insert_user_no_password;
use crate::sql_lockout_handler::tests as doors;
use lldap_domain::types::{LoginOutcome, UserId};
use lldap_domain_handlers::enforcement::{Door, ItemFlags, policy_cache};
use lldap_domain_handlers::instant::Timestamp;
use lldap_domain_handlers::lockout::{DURATION, LOCKED_OUT, THRESHOLD};
use lldap_domain_handlers::logging::LogKind;
use lldap_domain_handlers::mfa::MfaPolicy;
use lldap_test_utils::enforcement::EnforcementGuard;
use lldap_test_utils::recording_log::LogGuard;
use pretty_assertions::assert_eq;
use serial_test::serial;

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
