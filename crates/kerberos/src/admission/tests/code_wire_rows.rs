use super::proof_wire_rows::renewed;
use super::*;
use crate::otp::KlldapTotp;
use krb5_crypto::{KeyUsage, decrypt, encrypt};
use krb5_types::otp::{PaOtpEncRequest, PaOtpRequest};
use krb5_types::{AsReq, EncryptedData, KerberosFlags, PaData, flag_bit, ku};
use lldap_domain_handlers::kdc_code::{
    CODE_KEY, CODE_OFFER, CODE_TYPE, CodeVerdict, KdcCode, KdcCodeStore, KdcCodes,
};
use pretty_assertions::assert_eq;
use serial_test::serial;
use std::sync::Mutex;

const CODE: &str = "123456";

/// The doors' check as a stub: one right code, any other wrong; every value it was asked.
#[derive(Default)]
struct Codes {
    asked: Mutex<Vec<String>>,
}

#[async_trait::async_trait]
impl KdcCodeStore for Codes {
    async fn check_kdc_code(&self, _user: &UserId, code: KdcCode<'_>) -> CodeVerdict {
        self.asked.lock().unwrap().push(code.as_str().to_owned());
        match code.as_str() {
            CODE => CodeVerdict::Accepted,
            _ => CodeVerdict::Wrong,
        }
    }
}

impl Codes {
    fn asked(&self) -> Vec<String> {
        self.asked.lock().unwrap().clone()
    }
}

/// The verifier's `block_on` needs a runtime whose threads are not the test's own.
fn own_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap()
}

struct Coded {
    _temp: TempRealm,
    _embedded: EmbeddedKerberos,
    store: SharedDump,
    svc: Service,
    at: Proving,
    codes: Arc<Codes>,
}

fn code_desk(runtime: &tokio::runtime::Runtime, user: &str, ou: &str) -> Coded {
    let (temp, embedded, store) = runtime.block_on(realm(&[user]));
    let svc = service(&temp, &store);
    let at = runtime.block_on(async {
        let at = proving(&store, &[user], ou, Some(MfaPolicy::Enrolled), false).await;
        at.locking(ou).await;
        at.take_code(user).await;
        at
    });
    let codes = Arc::new(Codes::default());
    let served: &'static KdcCodes = Box::leak(Box::default());
    served.serve(codes.clone(), runtime.handle().clone());
    let verifier = KlldapTotp::on(REALM, at.cache, served, notes(), Duration::from_secs(2));
    let mut guard = store.write().unwrap();
    guard.policy.plugins.unregister_otp_verifier(CODE_TYPE);
    guard
        .policy
        .plugins
        .register_otp_verifier(Arc::new(verifier))
        .unwrap();
    guard
        .change_committing(committing(&*temp.own()), |s| {
            s.set_string_in(&name(user), REALM, CODE_KEY, Some(CODE_OFFER), "test")
        })
        .unwrap()
        .unwrap();
    drop(guard);
    Coded {
        _temp: temp,
        _embedded: embedded,
        store,
        svc,
        at,
        codes,
    }
}

fn password_ask(user: &str, password: &str, life: i64) -> AsReq {
    let padata = vec![krb5_protocol::pa_enc_timestamp(&user_key(user, password)).unwrap()];
    let mut request = krb5_protocol::as_req(name(user), REALM, nonce(), Some(padata)).unwrap();
    renewable(&mut request, life);
    request
}

fn renewable(request: &mut AsReq, life: i64) {
    let body = &mut request.0.req_body;
    body.till = KerberosTime::now().add_seconds(life).unwrap();
    body.kdc_options = body.kdc_options.clone().with_bit(flag_bit::RENEWABLE, true);
    body.rtime = Some(KerberosTime::now().add_hours(48).unwrap());
}

fn pa_otp(key: &ProtocolKey, value: &[u8]) -> PaData {
    let mut fresh = vec![7u8; 4 + key.as_bytes().len()];
    fresh[..4].copy_from_slice(&KerberosTime::now().unix_seconds().to_be_bytes());
    let plain = encode(&PaOtpEncRequest {
        nonce: fresh.into(),
    })
    .unwrap();
    let usage = KeyUsage::new(ku::PA_OTP_REQUEST).unwrap();
    let cipher = encrypt(key, usage, &plain).unwrap();
    let request = PaOtpRequest {
        flags: KerberosFlags::from_slice(&[0; 4]),
        nonce: None,
        enc_data: EncryptedData {
            etype: key.etype().to_iana(),
            kvno: None,
            cipher: cipher.into(),
        },
        hash_alg: None,
        iteration_count: None,
        otp_value: Some(value.to_vec().into()),
        pin: None,
        challenge: None,
        time: None,
        counter: None,
        format: None,
        token_id: None,
        alg_id: None,
        vendor: None,
    };
    PaData {
        padata_type: pa::OTP_REQUEST,
        padata_value: encode(&request).unwrap().into(),
    }
}

/// `kinit -T`: armored by the user's own short ticket, the value typed at the code prompt.
fn code_ask(user: &str, armor: &IssuedAs, value: &[u8]) -> AsReq {
    let sub = ProtocolKey::from_bytes(EncryptionType::Aes256CtsHmacSha196, &[0x4b; 32]);
    let sub = sub.unwrap();
    let (armor_ticket, session) = (armor.rep.0.ticket.clone(), &armor.session_key);
    let crealm = ascii(REALM);
    let shield = build_fast_armor(armor_ticket, session, &crealm, &name(user), Some(&sub));
    let shield = shield.unwrap();
    let key = armor_key(session, Some(&sub)).unwrap();
    let mut request = krb5_protocol::as_req(name(user), REALM, nonce(), None).unwrap();
    renewable(&mut request, 86_400);
    attach_fast(&mut request, &shield, &key, vec![pa_otp(&key, value)]).unwrap();
    request
}

fn issued(store: &SharedDump, request: &AsReq) -> IssuedAs {
    krb5_kdc::issue_as(&*store.read().unwrap(), request).unwrap()
}

fn sent(store: &SharedDump, request: &AsReq) -> i32 {
    answer(store, &encode(request).unwrap()).map_or_else(|(code, _)| code, |_| 0)
}

/// The ticket's life, and how long after its issue it may still be renewed.
fn lives(ticket_of: &IssuedAs) -> (i64, Option<i64>) {
    let usage = KeyUsage::new(ku::AS_REP_ENC_PART).unwrap();
    let cipher = ticket_of.rep.0.enc_part.cipher.as_ref();
    let plain = decrypt(&ticket_of.as_rep_key, usage, cipher).unwrap();
    let part = krb5_asn1::decode_enc_kdc_rep_part(&plain).unwrap();
    let issued_at = i64::from(part.authtime.unix_seconds());
    let end = i64::from(part.endtime.unix_seconds()) - issued_at;
    let renew = part
        .renew_till
        .map(|till| i64::from(till.unix_seconds()) - issued_at);
    (end, renew)
}

fn policy_refusal() -> Said {
    (PROOF_CODE, Some(PROOF_TEXT.to_owned()))
}

#[test]
#[serial]
fn test_at_the_wire_a_short_password_ticket_then_the_code_gives_a_ticket_with_the_mark() {
    let user = "e8wcode";
    let runtime = own_runtime();
    let _context = runtime.enter();
    let desk = code_desk(&runtime, user, "e8wcodeou");
    let store = &desk.store;
    let svc = &desk.svc;
    let failures = || {
        let lock = desk.at.counter.row(&UserId::new(user));
        lock.map_or(0, |lock| lock.fail_count)
    };
    let log = LogGuard::install_on_this_thread();
    let wrong = sent(store, &password_ask(user, "Wrong-Pass-1", 86_400));
    let after_wrong = failures();
    let normal = answer(
        store,
        &encode(&password_ask(user, PASSWORD, 86_400)).unwrap(),
    );
    let armor = issued(store, &password_ask(user, PASSWORD, 600));
    let on_armor = [
        service_ticket(store, &armor, user, svc).map(drop),
        renewed(store, &armor, user),
    ];
    let both_ways = (PROOF_CODE, Some(CODE_TEXT.to_owned()));
    let ours = |detail: &str| row(LogKind::Login, false, user, detail);
    let denied = row(
        LogKind::AccessDenied,
        false,
        user,
        &proof_detail(Door::KerberosTgs),
    );
    assert_eq!(
        (
            (wrong, after_wrong),
            normal.map(drop),
            lives(&armor),
            failures(),
            on_armor,
            kdc_rows(&log)
        ),
        (
            (err::PREAUTH_FAILED, 1),
            Err(both_ways),
            (ARMOR_LIFE, Some(ARMOR_LIFE)),
            1,
            [Err(policy_refusal()), Err(policy_refusal())],
            vec![
                ours("pre-authentication failed (encrypted timestamp)"),
                ours(&proof_detail(Door::KerberosAs)),
                ours("totp code required (armor ticket; encrypted timestamp)"),
                denied.clone(),
                denied,
            ]
        ),
        "a wrong password now counts; the right one alone is answered 12 after it, with both \
         ways; a short ask is a five-minute armor ticket, counted nowhere, that gets no service \
         ticket and no renewal"
    );
    let not_six = sent(store, &code_ask(user, &armor, b"pw:123456"));
    let wrong_code = sent(store, &code_ask(user, &armor, b"654321"));
    let after_wrong_code = failures();
    let with_code = issued(store, &code_ask(user, &armor, CODE.as_bytes()));
    let on_code = [
        service_ticket(store, &with_code, user, svc).map(drop),
        renewed(store, &with_code, user),
    ];
    let failed = err::PREAUTH_FAILED;
    assert_eq!(
        (
            [not_six, wrong_code],
            after_wrong_code,
            failures(),
            on_code,
            desk.codes.asked(),
            kdc_rows(&log)
        ),
        (
            [failed, failed],
            2,
            0,
            [Ok(()), Ok(())],
            vec!["654321".to_owned(), CODE.to_owned()],
            vec![
                ours("no six-digit code (OTP)"),
                ours("invalid totp (OTP)"),
                row(LogKind::Login, true, user, "ticket issued (OTP)"),
            ]
        ),
        "kinit -T armored by that ticket: the password and a code never reach the check; a \
         wrong code counts; the right one clears the count and its ticket, with the mark, gets \
         service tickets and renewals with no window"
    );
}

#[test]
#[serial]
fn test_at_the_wire_a_factor_change_ends_the_codes_tickets_and_a_locked_user_is_asked_no_code() {
    let user = "e8wlater";
    let runtime = own_runtime();
    let _context = runtime.enter();
    let desk = code_desk(&runtime, user, "e8wlaterou");
    let store = &desk.store;
    let svc = &desk.svc;
    let armor = issued(store, &password_ask(user, PASSWORD, 600));
    let with_code = issued(store, &code_ask(user, &armor, CODE.as_bytes()));
    let opened = Utc::now().timestamp();
    assert!(runtime.block_on(desk.at.prove(user, opened, "")), "stored");
    let in_window = [
        service_ticket(store, &armor, user, svc).map(drop),
        service_ticket(store, &with_code, user, svc).map(drop),
    ];
    assert_eq!(
        in_window,
        [Err(policy_refusal()), Ok(())],
        "inside a window opened after it, the armor ticket still gets nothing"
    );
    let changed_at = format!("mfa_changed_at = {}", opened + 5);
    runtime.block_on(desk.at.update(user, &changed_at));
    let log = LogGuard::install_on_this_thread();
    let after_change = [
        service_ticket(store, &with_code, user, svc).map(drop),
        renewed(store, &with_code, user),
    ];
    let changed = row(
        LogKind::AccessDenied,
        false,
        user,
        &mfa_detail(Door::KerberosTgs, FACTOR_CHANGED),
    );
    assert_eq!(
        (after_change, kdc_rows(&log)),
        (
            [Err(policy_refusal()), Err(policy_refusal())],
            vec![changed.clone(), changed]
        ),
        "the factor changed after the code: its ticket gets no service ticket and no renewal"
    );
    for _ in 0..3 {
        sent(store, &password_ask(user, "Wrong-Pass-1", 86_400));
    }
    let before = desk.codes.asked().len();
    let locked = sent(store, &code_ask(user, &armor, CODE.as_bytes()));
    assert_eq!(
        (locked, desk.codes.asked().len() - before),
        (err::CLIENT_REVOKED, 0),
        "three wrong passwords lock the user: kinit -T is refused as locked, the code not looked at"
    );
}
