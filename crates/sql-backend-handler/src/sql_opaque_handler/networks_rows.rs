use super::invalid_credentials;
use crate::SqlBackendHandler;
use crate::sql_backend_handler::tests::get_initialized_db;
use crate::sql_lockout_handler::tests as doors;
use lldap_auth::opaque::server::generate_random_private_key;
use lldap_domain::types::{LoginOutcome, UserId};
use lldap_domain_handlers::enforcement::{
    ALLOWED_NETWORKS, ItemFlags, fill_policy_cache, policy_cache,
};
use lldap_domain_handlers::handler::PolicyBackendHandler;
use lldap_domain_handlers::lockout::{DURATION, LockStore, THRESHOLD};
use lldap_domain_handlers::logging::{LogKind, RequestMeta, with_request};
use lldap_domain_handlers::mfa::MfaPolicy;
use lldap_domain_handlers::networks::{author_warnings, parse_list, resolve_client};
use lldap_domain_handlers::policies::CreatePolicyRequest;
use lldap_test_utils::enforcement::EnforcementGuard;
use lldap_test_utils::recording_log::LogGuard;
use pretty_assertions::assert_eq;
use serial_test::serial;
use std::net::IpAddr;

const LIST: &str = "10.73.0.0/16, 2001:db8:73::/48";
const NOT_ALLOWED: &str = "policy: allowed-networks (address not allowed)";

type Row = (LogKind, Option<String>, Option<String>, Option<String>);

fn at(text: &str) -> Option<IpAddr> {
    text.parse().ok()
}

fn ldap(peer: Option<&str>) -> RequestMeta {
    RequestMeta::ldap(None, peer.and_then(at))
}

/// The request as the HTTP fill site makes it, behind `trusted`.
fn http(peer: &str, forwarded: Option<&str>, trusted: &str) -> RequestMeta {
    let lines: Vec<&str> = forwarded.into_iter().collect();
    let trusted = parse_list(trusted).unwrap();
    RequestMeta {
        client_address: resolve_client(at(peer), &lines, &trusted),
        ..RequestMeta::http(at(peer), forwarded.map(str::to_owned))
    }
}

/// A handler with its own lockout; the doors' items read the global cache, filled from it.
async fn directory(users: &[&str], ou: &str, items: &[(&str, &str)]) -> SqlBackendHandler {
    let h = doors::own(SqlBackendHandler::new(
        generate_random_private_key(),
        get_initialized_db().await,
    ));
    for user in users {
        doors::user_in(&h, user, ou).await;
    }
    doors::policy_on(&h, ou, items).await;
    h
}

async fn on_the_doors(h: &SqlBackendHandler) {
    let flags = ItemFlags {
        networks: true,
        ..ItemFlags::default()
    };
    policy_cache().set_item_flags(flags);
    fill_policy_cache(h, policy_cache()).await.unwrap();
}

async fn bind(h: &SqlBackendHandler, meta: RequestMeta, user: &str, password: &str) -> String {
    let bound = with_request(meta, doors::bind_as(h, user, password)).await;
    bound.map_or_else(|e| e.to_string(), |()| "ok".to_owned())
}

/// The web login with `password` and no code.
async fn web(h: &SqlBackendHandler, meta: RequestMeta, user: &str, password: &str) -> String {
    match with_request(meta, doors::web(h, user, password, None)).await {
        Ok(LoginOutcome::TotpRequired) => "totp required".to_owned(),
        Ok(_) => "ok".to_owned(),
        Err(step) => step.to_owned(),
    }
}

fn refusals(log: &LogGuard, user: &str) -> Vec<Row> {
    let events = log.recorder().take_events().into_iter();
    let ours = events.filter(|e| !e.success && e.actor.as_deref() == Some(user));
    let doors = ours.filter(|e| matches!(e.kind, LogKind::Bind | LogKind::Login));
    doors
        .map(|e| (e.kind, e.peer, e.forwarded_for, e.detail))
        .collect()
}

fn row(kind: LogKind, peer: Option<&str>, forwarded: Option<&str>, detail: &str) -> Row {
    let owned = |text: Option<&str>| text.map(str::to_owned);
    (kind, owned(peer), owned(forwarded), Some(detail.to_owned()))
}

#[tokio::test]
#[serial]
async fn test_each_password_door_admits_inside_and_answers_outside_as_a_wrong_password() {
    let log = LogGuard::install_on_this_thread();
    let _guard = EnforcementGuard::default_checks();
    let h = directory(&["e5door"], "e5doorou", &[(ALLOWED_NETWORKS, LIST)]).await;
    on_the_doors(&h).await;
    let _ = log.recorder().take_events();
    let wrong = invalid_credentials(&UserId::new("e5door")).to_string();
    let answers = [
        bind(&h, ldap(Some("10.73.0.5")), "e5door", doors::RIGHT).await,
        bind(&h, ldap(Some("2001:db8:73::5")), "e5door", doors::RIGHT).await,
        bind(&h, ldap(Some("192.0.2.5")), "e5door", doors::RIGHT).await,
        bind(&h, ldap(Some("192.0.2.5")), "e5door", "Wrong-Pass-1").await,
        bind(&h, ldap(None), "e5door", doors::RIGHT).await,
        bind(&h, http("10.73.0.6", None, ""), "e5door", doors::RIGHT).await,
        bind(&h, http("2001:db9::6", None, ""), "e5door", doors::RIGHT).await,
        bind(&h, http("2001:db9::6", None, ""), "e5door", "Wrong-Pass-1").await,
        web(&h, http("10.73.0.7", None, ""), "e5door", doors::RIGHT).await,
        web(&h, http("198.51.100.7", None, ""), "e5door", doors::RIGHT).await,
    ];
    let web_wrong = web(&h, http("10.73.0.7", None, ""), "e5door", "Wrong-Pass-1").await;
    let ok = "ok".to_owned();
    assert_eq!(
        answers,
        [
            ok.clone(),
            ok.clone(),
            wrong.clone(),
            wrong.clone(),
            wrong.clone(),
            ok.clone(),
            wrong.clone(),
            wrong,
            ok,
            web_wrong,
        ],
        "LDAP bind (v4 and v6 inside, outside right and wrong, no address), the simple login \
         (inside, outside right and wrong), the web login (inside; outside, as a wrong password \
         inside)"
    );
    assert_eq!(
        refusals(&log, "e5door"),
        vec![
            row(LogKind::Bind, Some("192.0.2.5"), None, NOT_ALLOWED),
            row(
                LogKind::Bind,
                Some("192.0.2.5"),
                None,
                "invalid credentials"
            ),
            row(LogKind::Bind, None, None, NOT_ALLOWED),
            row(LogKind::Bind, Some("2001:db9::6"), None, NOT_ALLOWED),
            row(
                LogKind::Bind,
                Some("2001:db9::6"),
                None,
                "invalid credentials"
            ),
            row(LogKind::Login, Some("198.51.100.7"), None, NOT_ALLOWED),
        ],
        "one row each, with the socket peer; only the row tells a refusal from a wrong password"
    );
}

#[tokio::test]
#[serial]
async fn test_the_http_doors_believe_the_forwarded_address_only_from_a_listed_proxy() {
    let log = LogGuard::install_on_this_thread();
    let _guard = EnforcementGuard::default_checks();
    let h = directory(&["e5proxy"], "e5proxyou", &[(ALLOWED_NETWORKS, LIST)]).await;
    on_the_doors(&h).await;
    let _ = log.recorder().take_events();
    let listed = "10.9.0.1/32";
    let wrong = invalid_credentials(&UserId::new("e5proxy")).to_string();
    let forwarded = Some("10.73.0.9");
    let answers = [
        bind(
            &h,
            http("10.9.0.1", forwarded, listed),
            "e5proxy",
            doors::RIGHT,
        )
        .await,
        bind(&h, http("10.9.0.1", forwarded, ""), "e5proxy", doors::RIGHT).await,
        bind(
            &h,
            http("10.9.0.2", forwarded, listed),
            "e5proxy",
            doors::RIGHT,
        )
        .await,
        web(
            &h,
            http("10.9.0.1", forwarded, listed),
            "e5proxy",
            doors::RIGHT,
        )
        .await,
        web(&h, http("10.9.0.1", forwarded, ""), "e5proxy", doors::RIGHT).await,
        bind(&h, ldap(Some("10.9.0.1")), "e5proxy", doors::RIGHT).await,
    ];
    let believed = http("10.9.0.1", forwarded, listed);
    let web_wrong = web(&h, believed, "e5proxy", "Wrong-Pass-1").await;
    let ok = "ok".to_owned();
    assert_eq!(
        answers,
        [
            ok.clone(),
            wrong.clone(),
            wrong.clone(),
            ok,
            web_wrong,
            wrong,
        ],
        "the simple login and the web login: believed from the listed proxy, not without the \
         list (the web login as a wrong password from inside), not from an unlisted peer; LDAP \
         reads no header"
    );
    assert_eq!(
        refusals(&log, "e5proxy"),
        vec![
            row(LogKind::Bind, Some("10.9.0.1"), forwarded, NOT_ALLOWED),
            row(LogKind::Bind, Some("10.9.0.2"), forwarded, NOT_ALLOWED),
            row(LogKind::Login, Some("10.9.0.1"), forwarded, NOT_ALLOWED),
            row(LogKind::Bind, Some("10.9.0.1"), None, NOT_ALLOWED),
        ],
        "the row keeps the socket peer and the header as they came"
    );
}

#[tokio::test]
#[serial]
async fn test_an_entry_that_is_no_address_from_a_listed_proxy_inside_the_list_is_refused() {
    let log = LogGuard::install_on_this_thread();
    let _guard = EnforcementGuard::default_checks();
    let h = directory(&["e5odd"], "e5oddou", &[(ALLOWED_NETWORKS, LIST)]).await;
    on_the_doors(&h).await;
    let _ = log.recorder().take_events();
    let (proxy, listed) = ("10.73.0.1", "10.73.0.1/32");
    let simple = async |forwarded: Option<&str>| {
        let meta = http(proxy, forwarded, listed);
        bind(&h, meta, "e5odd", doors::RIGHT).await
    };
    let answers = [
        simple(None).await,
        simple(Some("10.73.0.9")).await,
        simple(Some("10.73.0.9:443")).await,
        simple(Some("[2001:db8:73::9]")).await,
        simple(Some("unknown")).await,
        simple(Some("10.73.0.9, , 10.73.0.1")).await,
        web(
            &h,
            http(proxy, Some("unknown"), listed),
            "e5odd",
            doors::RIGHT,
        )
        .await,
    ];
    let web_wrong = web(&h, http(proxy, None, listed), "e5odd", "Wrong-Pass-1").await;
    let (ok, wrong) = (
        "ok".to_owned(),
        invalid_credentials(&UserId::new("e5odd")).to_string(),
    );
    assert_eq!(
        answers,
        [
            ok.clone(),
            ok,
            wrong.clone(),
            wrong.clone(),
            wrong.clone(),
            wrong,
            web_wrong,
        ],
        "the proxy's own request and a bare address are admitted; a port, brackets, a name or an \
         empty element leave the client unknown, refused under the list though the proxy is in \
         it; the web login as a wrong password from the proxy's own request"
    );
    let by = Some(proxy);
    assert_eq!(
        refusals(&log, "e5odd"),
        vec![
            row(LogKind::Bind, by, Some("10.73.0.9:443"), NOT_ALLOWED),
            row(LogKind::Bind, by, Some("[2001:db8:73::9]"), NOT_ALLOWED),
            row(LogKind::Bind, by, Some("unknown"), NOT_ALLOWED),
            row(
                LogKind::Bind,
                by,
                Some("10.73.0.9, , 10.73.0.1"),
                NOT_ALLOWED
            ),
            row(LogKind::Login, by, Some("unknown"), NOT_ALLOWED),
        ],
        "the row keeps the socket peer and the header as they came"
    );
}

#[tokio::test]
#[serial]
async fn test_an_enrolled_user_outside_gets_a_wrong_passwords_answer_before_any_code() {
    let log = LogGuard::install_on_this_thread();
    let _guard = EnforcementGuard::default_checks();
    let (_clock, now) = doors::pinned();
    let h = doors::own(SqlBackendHandler::new(
        generate_random_private_key(),
        get_initialized_db().await,
    ))
    .with_mfa_policy(MfaPolicy::Enrolled);
    doors::user_in(&h, "e5mfa", "e5mfaou").await;
    let seed = doors::enroll(&h, "e5mfa", now).await;
    let items = [(THRESHOLD, "3"), (DURATION, "0"), (ALLOWED_NETWORKS, LIST)];
    doors::policy_on(&h, "e5mfaou", &items).await;
    on_the_doors(&h).await;
    let user = UserId::new("e5mfa");
    let counted = async || {
        let stored = h.read_lock(&user).await.unwrap();
        stored.map_or(0, |row| row.fail_count)
    };
    let _ = log.recorder().take_events();
    let outside = [
        bind(&h, ldap(Some("192.0.2.5")), "e5mfa", doors::RIGHT).await,
        bind(&h, http("192.0.2.5", None, ""), "e5mfa", doors::RIGHT).await,
        web(&h, http("192.0.2.5", None, ""), "e5mfa", doors::RIGHT).await,
    ];
    let after_right = counted().await;
    let wrong_one = bind(&h, ldap(Some("192.0.2.5")), "e5mfa", "Wrong-Pass-1").await;
    let after_wrong = counted().await;
    let ([code, _], _) = doors::codes(&seed, now);
    let with_code = format!("{}:{code}", doors::RIGHT);
    let inside = [
        bind(&h, ldap(Some("10.73.0.5")), "e5mfa", doors::RIGHT).await,
        web(&h, http("10.73.0.5", None, ""), "e5mfa", doors::RIGHT).await,
        bind(&h, ldap(Some("10.73.0.5")), "e5mfa", &with_code).await,
    ];
    let web_wrong = web(&h, http("10.73.0.5", None, ""), "e5mfa", "Wrong-Pass-1").await;
    let wrong = invalid_credentials(&user).to_string();
    assert_eq!(
        (outside, after_right),
        ([wrong.clone(), wrong.clone(), web_wrong], 0),
        "the right password with no code from outside: LDAP bind and simple login answer as a \
         wrong password, the web login as a wrong password from inside, and nothing is counted"
    );
    assert_eq!(
        (wrong_one, after_wrong),
        (wrong, 1),
        "a wrong password: the same answer, counted"
    );
    let required = r#"Authentication error TOTP code required for user "e5mfa""#;
    assert_eq!(
        inside,
        [
            required.to_owned(),
            "totp required".to_owned(),
            "ok".to_owned()
        ],
        "from inside: the code is asked for as today, and the code admits"
    );
    let (out, inn) = (Some("192.0.2.5"), Some("10.73.0.5"));
    assert_eq!(
        refusals(&log, "e5mfa"),
        vec![
            row(LogKind::Bind, out, None, NOT_ALLOWED),
            row(LogKind::Bind, out, None, NOT_ALLOWED),
            row(LogKind::Login, out, None, NOT_ALLOWED),
            row(LogKind::Bind, out, None, "invalid credentials"),
            row(LogKind::Bind, inn, None, "totp code required"),
            row(LogKind::Login, inn, None, "totp code required"),
        ],
        "one refusal row for each attempt from outside, the item's"
    );
}

#[tokio::test]
async fn test_the_warning_follows_the_authors_own_list_after_each_save() {
    let h = doors::handler().await;
    doors::user_in(&h, "e5author", "e5team\\lab").await;
    let author = UserId::new("e5author");
    let outside = at("192.0.2.5");
    let said =
        async |address: Option<IpAddr>| author_warnings(&h, h.policy_cache, &author, address).await;
    let none = said(outside).await;
    let request = CreatePolicyRequest {
        name: "e5 nets".to_owned(),
        description: String::new(),
        items: [(ALLOWED_NETWORKS.to_owned(), "10.73.0.0/16".to_owned())].into(),
    };
    let id = h.create_policy(request).await.unwrap();
    h.set_ou_policy("e5other", id).await.unwrap();
    let unlinked = said(outside).await;
    h.set_ou_policy("e5team\\lab", id).await.unwrap();
    let linked = (
        said(outside).await,
        said(at("10.73.0.9")).await,
        said(None).await,
    );
    h.clear_ou_policy("e5team\\lab").await.unwrap();
    h.set_ou_policy("e5team", id).await.unwrap();
    let inherited = said(outside).await;
    h.set_ou_policy_inheritance("e5team\\lab", true)
        .await
        .unwrap();
    let blocked = said(outside).await;
    h.set_ou_policy_inheritance("e5team\\lab", false)
        .await
        .unwrap();
    let unblocked = said(outside).await;
    let request = CreatePolicyRequest {
        name: "e5 wide".to_owned(),
        description: String::new(),
        items: [(ALLOWED_NETWORKS.to_owned(), "192.0.2.0/24".to_owned())].into(),
    };
    let wide = h.create_policy(request).await.unwrap();
    h.set_ou_policy("e5team\\lab", wide).await.unwrap();
    let closer = said(outside).await;
    h.clear_ou_policy("e5team\\lab").await.unwrap();
    let cleared = said(outside).await;
    h.set_ou_policy("e5team\\lab", wide).await.unwrap();
    let admitted = said(outside).await;
    h.delete_policy(wide).await.unwrap();
    let deleted = said(outside).await;
    let text = |seen: &str, ou: &str| {
        vec![format!(
            "allowed-networks: the list that now applies to you does not contain the address the \
             server sees you as ({seen}). The way back, on the host: lldap policy-unlink \
             --config-file <config> '{ou}'"
        )]
    };
    assert_eq!(
        (none, unlinked, linked, inherited, blocked),
        (
            vec![],
            vec![],
            (
                text("192.0.2.5", "e5team\\lab"),
                vec![],
                text("unknown", "e5team\\lab")
            ),
            text("192.0.2.5", "e5team"),
            vec![]
        ),
        "nothing set, unlinked from the author, linked (outside, inside, no address), inherited, \
         blocked"
    );
    assert_eq!(
        (unblocked, closer, cleared, admitted, deleted),
        (
            text("192.0.2.5", "e5team"),
            vec![],
            text("192.0.2.5", "e5team"),
            vec![],
            text("192.0.2.5", "e5team")
        ),
        "unblocked: inherited again; a closer list that admits; that one cleared: inherited again; \
         linked again, then deleted: inherited again"
    );
}
