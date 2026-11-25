use super::*;
use krb5_types::{Ticket, flag_bit};
use pretty_assertions::assert_eq;
use serial_test::serial;

type Asked = Result<(), Said>;

fn no_fresh_proof() -> Said {
    (PROOF_CODE, Some(PROOF_TEXT.to_owned()))
}

/// A TGT the user may renew, issued on the password.
fn renewable_tgt(store: &SharedDump, user: &str) -> IssuedAs {
    let padata = vec![krb5_protocol::pa_enc_timestamp(&user_key(user, PASSWORD)).unwrap()];
    let mut request = krb5_protocol::as_req(name(user), REALM, nonce(), Some(padata)).unwrap();
    let options = request.0.req_body.kdc_options.clone();
    request.0.req_body.kdc_options = options.with_bit(flag_bit::RENEWABLE, true);
    request.0.req_body.rtime = Some(request.0.req_body.till.add_hours(48).unwrap());
    krb5_kdc::issue_as(&*store.read().unwrap(), &request).unwrap()
}

fn tgs_wire(
    store: &SharedDump,
    tgt: &IssuedAs,
    user: &str,
    sname: PrincipalName,
    kdc_options: KdcOptions,
    additional_tickets: Option<Vec<Ticket>>,
) -> Asked {
    let cname = name(user);
    let params = TgsReqParams {
        ticket: tgt.rep.0.ticket.clone(),
        session: &tgt.session_key,
        crealm: REALM,
        cname: &cname,
        sname,
        realm: REALM,
        nonce: nonce(),
        kdc_options,
        additional_tickets,
        extra_padata: Vec::new(),
        etypes: vec![EncryptionType::Aes256CtsHmacSha196.to_iana()],
        addresses: None,
        from: None,
        enc_authorization_data: None,
        till: None,
        subkey: None,
        time_offset: 0,
    };
    let request = tgs_req_ex(params).unwrap();
    answer(store, &encode(&request).unwrap()).map(drop)
}

fn renewed(store: &SharedDump, tgt: &IssuedAs, user: &str) -> Asked {
    let options = KdcOptions::forwardable()
        .with_bit(flag_bit::RENEWABLE, true)
        .with_bit(flag_bit::RENEW, true);
    let krbtgt = PrincipalName::krbtgt(REALM);
    tgs_wire(store, tgt, user, krbtgt, options, None)
}

/// User-to-user towards the service, its TGT as the second ticket.
fn user_to_user(store: &SharedDump, tgt: &IssuedAs, user: &str, svc: &Service) -> Asked {
    let options = KdcOptions::forwardable().with_bit(flag_bit::ENC_TKT_IN_SKEY, true);
    let second = Some(vec![svc.tgt.rep.0.ticket.clone()]);
    tgs_wire(store, tgt, user, svc.name.clone(), options, second)
}

fn kinit_said(store: &SharedDump, user: &str) -> Asked {
    match kinit(store, user, Some(PASSWORD)) {
        (0, None) => Ok(()),
        refused => Err(refused),
    }
}

#[tokio::test]
#[serial]
async fn test_at_the_wire_the_authentication_time_decides_and_s4u_by_a_service_is_not_judged() {
    let user = "e2kwkinds";
    let (temp, _embedded, store) = realm(&[user]).await;
    let svc = service(&temp, &store);
    let at = proving(
        &store,
        &[user],
        "e2kwkindsou",
        Some(MfaPolicy::Enrolled),
        false,
    )
    .await;
    let issued_at = Utc::now().timestamp();
    let tgt = renewable_tgt(&store, user);
    at.enrol(user).await;
    let log = LogGuard::install_on_this_thread();
    let asked = || {
        vec![
            service_ticket(&store, &tgt, user, &svc).map(drop),
            renewed(&store, &tgt, user),
            user_to_user(&store, &tgt, user, &svc),
            s4u2self(&store, &svc, user, false).map(drop),
        ]
    };
    let refused = || -> Asked { Err(no_fresh_proof()) };
    let judged = vec![refused(), refused(), Ok(()), Ok(())];
    let denied = row(
        LogKind::AccessDenied,
        false,
        user,
        &proof_detail(Door::KerberosTgs),
    );
    let before = (asked(), kdc_rows(&log));
    assert!(at.prove(user, issued_at + 120, "").await, "stored");
    let opened_later = (asked(), kdc_rows(&log));
    assert!(at.prove(user, issued_at - 30, "").await, "stored");
    let covered = (asked(), kdc_rows(&log));
    assert_eq!(
        (before, opened_later, covered),
        (
            (judged.clone(), vec![denied.clone(); 2]),
            (judged, vec![denied; 2]),
            (vec![Ok(()); 4], vec![])
        ),
        "a service ticket and a renewal on a ticket from before the enrolment: 12 and the text, \
         one row each; a window opened two minutes after the ticket does not cover it; one \
         opened 30 s before does. User-to-user towards the service is not judged: the KDC asks \
         about the second ticket's client. A service asking S4U2Self for the user is not judged"
    );
}

#[tokio::test]
#[serial]
async fn test_at_the_wire_an_ou_change_after_issue_reaches_kinit_and_the_renewal() {
    let user = "e2kwafter";
    let (_temp, _embedded, store) = realm(&[user]).await;
    let at = proving(&store, &[user], "e2kwafterou", None, false).await;
    let item = |value: &str| [(ENABLE_MFA.to_owned(), value.to_owned())].into();
    let request = CreatePolicyRequest {
        name: "e2k wire after".to_owned(),
        description: String::new(),
        items: item("off"),
    };
    let id = at.handler.create_policy(request).await.unwrap();
    at.handler.set_ou_policy("e2kwafterou", id).await.unwrap();
    at.enrol(user).await;
    let tgt = renewable_tgt(&store, user);
    let asked = || (kinit_said(&store, user), renewed(&store, &tgt, user));
    let before = asked();
    let change = UpdatePolicyRequest {
        id,
        name: None,
        description: None,
        items: Some(item("always")),
    };
    at.handler.update_policy(change).await.unwrap();
    let changed = asked();
    assert!(at.prove(user, Utc::now().timestamp() - 700, "").await);
    let held = at.cache.get().windows_of(&UserId::new(user)).len();
    let refused = || -> Asked { Err(no_fresh_proof()) };
    assert_eq!(
        (before, changed, held, asked()),
        (
            (Ok(()), Ok(())),
            (refused(), refused()),
            1,
            (refused(), refused())
        ),
        "the OU at off: a ticket and its renewal. Changed to always: kinit and the renewal of \
         the ticket issued before are refused. A window that ended 100 s ago covers neither"
    );
}

#[tokio::test]
#[serial]
async fn test_at_the_wire_a_locked_user_who_needs_a_proof_is_refused_as_locked() {
    let user = "e2kwlocked";
    let (_temp, _embedded, store) = realm(&[user]).await;
    let at = proving(
        &store,
        &[user],
        "e2kwlockou",
        Some(MfaPolicy::Enrolled),
        false,
    )
    .await;
    at.locking("e2kwlockou").await;
    let tgt = renewable_tgt(&store, user);
    for _ in 0..3 {
        let _ = kinit(&store, user, Some("Wrong-Pass-1"));
    }
    at.enrol(user).await;
    let revoked = (err::CLIENT_REVOKED, None);
    assert_eq!(
        (kinit_said(&store, user), renewed(&store, &tgt, user)),
        (Err(revoked.clone()), Err(revoked)),
        "the lockout is judged first: 18 with no text, not 12"
    );
}

#[tokio::test]
#[serial]
async fn test_at_the_wire_a_disabled_user_without_a_proof_is_answered_12_not_18() {
    let user = "e2kwdisabled";
    let (temp, embedded, store) = realm(&[user]).await;
    let svc = service(&temp, &store);
    let at = proving(
        &store,
        &[user],
        "e2kwdisou",
        Some(MfaPolicy::Enrolled),
        false,
    )
    .await;
    let tgt = issue_tgt(&store, user);
    embedded
        .set_principal_enabled(&UserId::new(user), false)
        .await
        .unwrap();
    let disabled = service_ticket(&store, &tgt, user, &svc).map(drop);
    at.enrol(user).await;
    let both = service_ticket(&store, &tgt, user, &svc).map(drop);
    let locked = (err::CLIENT_REVOKED, Some("CLIENT LOCKED OUT".to_owned()));
    assert_eq!(
        (disabled, both),
        (Err(locked), Err(no_fresh_proof())),
        "disabled alone: the live-client check's 18. Disabled and owing a proof: the second \
         factor is judged before the live client, so 12 as in 0.8.1"
    );
}

#[tokio::test]
#[serial]
async fn test_at_the_wire_with_the_address_tie_a_kinit_from_no_known_address_is_refused() {
    let user = "e2kwtied";
    let (_temp, _embedded, store) = realm(&[user]).await;
    let at = proving(&store, &[user], "people", Some(MfaPolicy::Always), true).await;
    assert!(at.prove(user, Utc::now().timestamp(), PEER).await);
    assert!(at.prove(user, 1_700_000_000, PEER).await);
    let log = LogGuard::install_on_this_thread();
    let wire = kinit_said(&store, user);
    let rows = kdc_rows(&log);
    let from_peer = as_asks_of(&at.verdict, &store, user, false);
    let refused = row(LogKind::Login, false, user, &proof_detail(Door::KerberosAs));
    assert_eq!(
        (wire, rows, from_peer),
        (Err(no_fresh_proof()), vec![refused], Ok(())),
        "inside a window made from {PEER}, a request with no peer address is refused; the \
         question asked from {PEER} at its own instant is admitted"
    );
}
