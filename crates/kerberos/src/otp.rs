use crate::admission::{ip_of, user_named, user_of};
use krb5_kdc::{OtpVerdict, OtpVerifier, OtpVerifyRequest};
use lldap_domain::types::UserId;
use lldap_domain_handlers::enforcement::{PolicyCache, policy_cache};
use lldap_domain_handlers::kdc_code::{
    CODE_TYPE, CODE_UNREAD, CodeVerdict, KdcCode, KdcCodes, NO_SIX_DIGITS, NOT_ASKED, WRONG_CODE,
    check_code, code_asked, kdc_codes,
};
use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::{LazyLock, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

/// Under kerber-rust's five seconds for a token type with no profile section.
const CODE_WAIT: Duration = Duration::from_secs(2);
const NOT_OURS: &str = "not a directory user";
const FOREIGN_ARMOR: &str = "armor is not the user's own ticket";
const NOTE_LIFE: Duration = Duration::from_secs(30);
const NOTES_EACH: usize = 8;

/// The KDC's check of a code typed at kinit; inert while no principal carries the `otp` string.
pub(crate) struct KlldapTotp {
    realm: String,
    cache: &'static PolicyCache,
    codes: &'static KdcCodes,
    notes: &'static Notes,
    wait: Duration,
}

impl KlldapTotp {
    pub(crate) fn new(realm: &str) -> Self {
        Self::on(realm, policy_cache(), kdc_codes(), notes(), CODE_WAIT)
    }

    pub(crate) fn on(
        realm: &str,
        cache: &'static PolicyCache,
        codes: &'static KdcCodes,
        notes: &'static Notes,
        wait: Duration,
    ) -> Self {
        Self {
            realm: realm.to_owned(),
            cache,
            codes,
            notes,
            wait,
        }
    }

    /// A directory user, armored by a ticket of its own, whom the KDC asks a code.
    fn asked(&self, req: &OtpVerifyRequest) -> Result<UserId, String> {
        let client = &req.principal;
        let owned = user_of(client, &self.realm).filter(|_| client.host_owned());
        let user = owned.ok_or_else(|| NOT_OURS.to_owned())?;
        let armor = user_named(&req.armor_client, &req.armor_realm, &self.realm);
        if armor.as_ref() != Some(&user) {
            let armor = req.armor_client.unparse_with_realm_lossy(&req.armor_realm);
            return Err(format!("{FOREIGN_ARMOR}: {armor}"));
        }
        match code_asked(self.cache, &user) {
            true => Ok(user),
            false => Err(NOT_ASKED.to_owned()),
        }
    }

    /// The doors' check on the server's runtime, bounded; the value is borrowed, never copied.
    fn checked(&self, user: &UserId, value: &[u8]) -> CodeVerdict {
        let Some(reader) = self.codes.reader() else {
            return CodeVerdict::Refused(CODE_UNREAD);
        };
        let store = &*reader.store;
        let bounded = async {
            let check = check_code(store, user, value);
            tokio::time::timeout(self.wait, check).await
        };
        let answered = reader.runtime.block_on(bounded);
        answered.unwrap_or(CodeVerdict::Refused(CODE_UNREAD))
    }

    fn judge(&self, req: &OtpVerifyRequest) -> Result<(), (Outcome, String)> {
        if KdcCode::read(&req.otp_value).is_none() {
            return Err((Outcome::Errored, NO_SIX_DIGITS.to_owned()));
        }
        let user = self
            .asked(req)
            .map_err(|detail| (Outcome::Errored, detail))?;
        match self.checked(&user, &req.otp_value) {
            CodeVerdict::Accepted => Ok(()),
            CodeVerdict::Wrong => Err((Outcome::Rejected, WRONG_CODE.to_owned())),
            CodeVerdict::Refused(detail) => Err((Outcome::Errored, detail.to_owned())),
        }
    }
}

impl OtpVerifier for KlldapTotp {
    fn name(&self) -> &'static str {
        CODE_TYPE
    }

    fn verify(&self, req: &OtpVerifyRequest) -> OtpVerdict {
        let Err((outcome, detail)) = self.judge(req) else {
            return OtpVerdict::Accept;
        };
        let peer = req.peer.as_ref().and_then(ip_of);
        let note = Note {
            outcome,
            peer,
            detail: detail.clone(),
            at: Instant::now(),
        };
        self.notes.put(req.principal.id(), note);
        match outcome {
            Outcome::Rejected => OtpVerdict::Reject,
            Outcome::Errored => OtpVerdict::Error(detail),
        }
    }
}

/// A refused code as kerber-rust's notice names it: a reject counts, an error does not.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Outcome {
    Rejected,
    Errored,
}

#[derive(Clone, Debug)]
pub(crate) struct Note {
    outcome: Outcome,
    peer: Option<IpAddr>,
    detail: String,
    at: Instant,
}

/// The verifier's reasons, from its worker to the notice on the serving thread.
#[derive(Default)]
pub(crate) struct Notes {
    held: Mutex<HashMap<String, VecDeque<Note>>>,
}

static NOTES: LazyLock<Notes> = LazyLock::new(Notes::default);

pub(crate) fn notes() -> &'static Notes {
    &NOTES
}

impl Notes {
    fn held(&self) -> MutexGuard<'_, HashMap<String, VecDeque<Note>>> {
        self.held.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub(crate) fn put(&self, client: String, note: Note) {
        let mut held = self.held();
        forget_old(&mut held, note.at);
        let queue = held.entry(client).or_default();
        if queue.len() == NOTES_EACH {
            queue.pop_front();
        }
        queue.push_back(note);
    }

    pub(crate) fn take(
        &self,
        client: &str,
        outcome: Outcome,
        peer: Option<IpAddr>,
    ) -> Option<String> {
        self.take_at(client, outcome, peer, Instant::now())
    }

    fn take_at(
        &self,
        client: &str,
        outcome: Outcome,
        peer: Option<IpAddr>,
        now: Instant,
    ) -> Option<String> {
        let mut held = self.held();
        forget_old(&mut held, now);
        let queue = held.get_mut(client)?;
        let at = queue
            .iter()
            .position(|note| note.outcome == outcome && note.peer == peer)?;
        let note = queue.remove(at)?;
        if queue.is_empty() {
            held.remove(client);
        }
        Some(note.detail)
    }
}

fn forget_old(held: &mut HashMap<String, VecDeque<Note>>, now: Instant) {
    held.retain(|_, queue| {
        queue.retain(|note| now.saturating_duration_since(note.at) < NOTE_LIFE);
        !queue.is_empty()
    });
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::embedded::tests::TempRealm;
    use krb5_kdc::{Principal, PrincipalBuilder, TL_KERBER_HOST_OWNED, TlData};
    use krb5_types::PrincipalName;
    use lldap_domain::types::Uuid;
    use lldap_domain_handlers::enforcement::{Entries, UserFacts};
    use lldap_domain_handlers::instant::Timestamp;
    use lldap_domain_handlers::kdc_code::KdcCodeStore;
    use lldap_domain_handlers::mfa::MfaPolicy;
    use pretty_assertions::assert_eq;
    use serial_test::serial;
    use std::sync::Arc;

    const REALM: &str = "EXAMPLE.COM";
    const BOB: &str = "e8kbob";
    const BOUND: Duration = Duration::from_millis(300);

    pub(crate) fn note(outcome: Outcome, peer: Option<IpAddr>, detail: &str) -> Note {
        Note {
            outcome,
            peer,
            detail: detail.to_owned(),
            at: Instant::now(),
        }
    }

    fn named(user: &str) -> PrincipalName {
        PrincipalName::new(PrincipalName::NT_PRINCIPAL, [user])
    }

    fn host() -> PrincipalName {
        PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", "ws.example.com"])
    }

    fn client(name: PrincipalName, realm: &str, marked: bool) -> Principal {
        let mut principal = PrincipalBuilder::new(name, realm).build();
        if marked {
            let tl = TlData {
                ty: TL_KERBER_HOST_OWNED,
                contents: Vec::new(),
            };
            principal.tl_data.push(tl);
        }
        principal
    }

    fn bob() -> Principal {
        client(named(BOB), REALM, true)
    }

    fn asking(
        principal: Principal,
        armor: &(PrincipalName, &str),
        value: &[u8],
    ) -> OtpVerifyRequest {
        let mut req = OtpVerifyRequest::for_test(principal, REALM, CODE_TYPE, BOB, value);
        req.armor_client = armor.0.clone();
        req.armor_realm = armor.1.to_owned();
        req
    }

    fn facts(enrolled: bool, code_at_kinit: bool) -> UserFacts {
        UserFacts {
            uuid: Uuid::from_name_and_date(BOB, &Default::default()),
            enrolled,
            exempt: false,
            code_at_kinit,
            mfa_changed_at: None,
            created: Timestamp::UNIX_EPOCH,
            recorded: None,
        }
    }

    struct Stub {
        answer: CodeVerdict,
        delay: Duration,
        calls: Mutex<Vec<(String, String)>>,
    }

    #[async_trait::async_trait]
    impl KdcCodeStore for Stub {
        async fn check_kdc_code(&self, user: &UserId, code: KdcCode<'_>) -> CodeVerdict {
            let call = (user.as_str().to_owned(), code.as_str().to_owned());
            self.calls.lock().unwrap().push(call);
            tokio::time::sleep(self.delay).await;
            self.answer
        }
    }

    /// A verifier on its own memory, store, notes and runtime: the worker is a plain thread.
    struct Desk {
        verifier: KlldapTotp,
        store: Arc<Stub>,
        notes: &'static Notes,
        _runtime: tokio::runtime::Runtime,
    }

    impl Desk {
        fn new(
            answer: CodeVerdict,
            facts: Option<UserFacts>,
            served: bool,
            delay: Duration,
        ) -> Self {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(1)
                .enable_all()
                .build()
                .unwrap();
            let calls = Mutex::default();
            let store = Arc::new(Stub {
                answer,
                delay,
                calls,
            });
            let codes: &'static KdcCodes = Box::leak(Box::default());
            if served {
                codes.serve(store.clone(), runtime.handle().clone());
            }
            let cache: &'static PolicyCache = Box::leak(Box::default());
            cache.set_mfa_policy(Some(MfaPolicy::Enrolled));
            let facts = facts.map(|facts| (UserId::new(BOB), facts));
            cache.replace(Entries {
                facts: facts.into_iter().collect(),
                ..Entries::default()
            });
            let notes: &'static Notes = Box::leak(Box::default());
            Self {
                verifier: KlldapTotp::on(REALM, cache, codes, notes, BOUND),
                store,
                notes,
                _runtime: runtime,
            }
        }

        fn asked_of(answer: CodeVerdict) -> Self {
            Self::new(answer, Some(facts(true, true)), true, Duration::ZERO)
        }

        fn calls(&self) -> Vec<(String, String)> {
            self.store.calls.lock().unwrap().clone()
        }

        fn noted(&self, req: &OtpVerifyRequest) -> Option<(Outcome, String)> {
            [Outcome::Rejected, Outcome::Errored]
                .into_iter()
                .find_map(|outcome| {
                    let taken = self.notes.take(&req.principal.id(), outcome, None);
                    taken.map(|detail| (outcome, detail))
                })
        }
    }

    type Checked = (OtpVerdict, Vec<(String, String)>, Option<(Outcome, String)>);

    fn reached(code: &str) -> Checked {
        let call = (BOB.to_owned(), code.to_owned());
        (OtpVerdict::Accept, vec![call], None)
    }

    fn refused(detail: &str) -> Checked {
        let note = Some((Outcome::Errored, detail.to_owned()));
        (OtpVerdict::Error(detail.to_owned()), vec![], note)
    }

    #[test]
    fn test_a_value_not_six_digits_is_refused_first_and_never_reaches_the_store() {
        let own = (named(BOB), REALM);
        let host = (host(), REALM);
        let long = "1".repeat(128);
        type Row<'a> = (
            &'a str,
            Principal,
            &'a (PrincipalName, &'a str),
            &'a [u8],
            bool,
        );
        let rows: [Row; 9] = [
            ("six digits", bob(), &own, b"123456", true),
            ("leading zeros", bob(), &own, b"000042", true),
            ("five", bob(), &own, b"12345", false),
            ("seven", bob(), &own, b"1234567", false),
            (
                "the password and the code",
                bob(),
                &own,
                b"pw:123456",
                false,
            ),
            ("a newline after six", bob(), &own, b"123456\n", false),
            (
                "full-width digits",
                bob(),
                &own,
                "１２３４５６".as_bytes(),
                false,
            ),
            ("128 digits", bob(), &own, long.as_bytes(), false),
            (
                "the password and the code under a host's armor, for no directory user",
                client(named("e8kstray"), REALM, false),
                &host,
                b"pw:123456",
                false,
            ),
        ];
        for (label, principal, armor, value, reaches) in rows {
            let desk = Desk::asked_of(CodeVerdict::Accepted);
            let req = asking(principal, armor, value);
            let got = (desk.verifier.verify(&req), desk.calls(), desk.noted(&req));
            let expected = match reaches {
                true => reached(std::str::from_utf8(value).unwrap()),
                false => refused(NO_SIX_DIGITS),
            };
            assert_eq!(
                got, expected,
                "{label}: refused before anything else is read"
            );
        }
    }

    #[test]
    fn test_only_a_directory_user_armored_by_its_own_ticket_and_asked_a_code_reaches_the_store() {
        let own = (named(BOB), REALM);
        let host_armor = (host(), REALM);
        let anonymous = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["WELLKNOWN", "ANONYMOUS"]);
        let armors = [
            (named("E8KBob"), REALM),
            (named("e8kann"), REALM),
            (
                PrincipalName::new(PrincipalName::NT_PRINCIPAL, [BOB, "admin"]),
                REALM,
            ),
            (named(BOB), "OTHER.ORG"),
            (anonymous, "WELLKNOWN:ANONYMOUS"),
        ];
        let foreign = |armor: &(PrincipalName, &str)| {
            let name = armor.0.unparse_with_realm_lossy(armor.1);
            refused(&format!("{FOREIGN_ARMOR}: {name}"))
        };
        let asked = Some(facts(true, true));
        type Row<'a> = (
            &'a str,
            Principal,
            &'a (PrincipalName, &'a str),
            Option<UserFacts>,
            Checked,
        );
        let rows: [Row; 13] = [
            (
                "the user's own ticket",
                bob(),
                &own,
                asked.clone(),
                reached("123456"),
            ),
            (
                "its own, in another case",
                bob(),
                &armors[0],
                asked.clone(),
                reached("123456"),
            ),
            (
                "another user's ticket",
                bob(),
                &armors[1],
                asked.clone(),
                foreign(&armors[1]),
            ),
            (
                "a host's ticket",
                bob(),
                &host_armor,
                asked.clone(),
                foreign(&host_armor),
            ),
            (
                "a two-part name",
                bob(),
                &armors[2],
                asked.clone(),
                foreign(&armors[2]),
            ),
            (
                "its name in another realm",
                bob(),
                &armors[3],
                asked.clone(),
                foreign(&armors[3]),
            ),
            (
                "an anonymous ticket",
                bob(),
                &armors[4],
                asked.clone(),
                foreign(&armors[4]),
            ),
            (
                "a one-part principal the directory does not own",
                client(named(BOB), REALM, false),
                &own,
                asked.clone(),
                refused(NOT_OURS),
            ),
            (
                "a service that carries the string",
                client(host(), REALM, true),
                &host_armor,
                asked.clone(),
                refused(NOT_OURS),
            ),
            (
                "a user of another realm",
                client(named(BOB), "OTHER.ORG", true),
                &own,
                asked.clone(),
                refused(NOT_OURS),
            ),
            (
                "not turned on",
                bob(),
                &own,
                Some(facts(true, false)),
                refused(NOT_ASKED),
            ),
            (
                "no factor",
                bob(),
                &own,
                Some(facts(false, true)),
                refused(NOT_ASKED),
            ),
            (
                "a user the memory lacks",
                bob(),
                &own,
                None,
                refused(NOT_ASKED),
            ),
        ];
        for (label, principal, armor, facts, expected) in rows {
            let desk = Desk::new(CodeVerdict::Accepted, facts, true, Duration::ZERO);
            let req = asking(principal, armor, b"123456");
            let got = (desk.verifier.verify(&req), desk.calls(), desk.noted(&req));
            assert_eq!(got, expected, "{label}");
        }
    }

    #[test]
    fn test_each_answer_of_the_store_is_one_verdict_and_one_note() {
        let own = (named(BOB), REALM);
        let rows = [
            (CodeVerdict::Accepted, OtpVerdict::Accept, None),
            (
                CodeVerdict::Wrong,
                OtpVerdict::Reject,
                Some((Outcome::Rejected, WRONG_CODE)),
            ),
            (
                CodeVerdict::Refused("totp replayed"),
                OtpVerdict::Error("totp replayed".to_owned()),
                Some((Outcome::Errored, "totp replayed")),
            ),
            (
                CodeVerdict::Refused("totp attempts exceeded"),
                OtpVerdict::Error("totp attempts exceeded".to_owned()),
                Some((Outcome::Errored, "totp attempts exceeded")),
            ),
            (
                CodeVerdict::Refused("not enrolled"),
                OtpVerdict::Error("not enrolled".to_owned()),
                Some((Outcome::Errored, "not enrolled")),
            ),
            (
                CodeVerdict::Refused(CODE_UNREAD),
                OtpVerdict::Error(CODE_UNREAD.to_owned()),
                Some((Outcome::Errored, CODE_UNREAD)),
            ),
        ];
        for (answer, verdict, noted) in rows {
            let desk = Desk::asked_of(answer);
            let req = asking(bob(), &own, b"654321");
            let call = vec![(BOB.to_owned(), "654321".to_owned())];
            let noted = noted.map(|(outcome, detail)| (outcome, detail.to_owned()));
            assert_eq!(
                (desk.verifier.verify(&req), desk.calls(), desk.noted(&req)),
                (verdict, call, noted),
                "{answer:?}: the verifier counts nothing itself"
            );
        }
    }

    #[test]
    fn test_no_reader_or_a_store_past_the_bound_refuses_as_unreadable() {
        let own = (named(BOB), REALM);
        let rows = [
            ("no store handed over", false, Duration::ZERO, 0, false),
            ("a store that does not answer", true, BOUND * 10, 1, true),
        ];
        for (label, served, delay, calls, waited) in rows {
            let desk = Desk::new(
                CodeVerdict::Accepted,
                Some(facts(true, true)),
                served,
                delay,
            );
            let req = asking(bob(), &own, b"123456");
            let started = Instant::now();
            let verdict = desk.verifier.verify(&req);
            let took = started.elapsed();
            assert_eq!(
                (verdict, desk.calls().len(), took >= BOUND, took < BOUND * 5),
                (
                    OtpVerdict::Error(CODE_UNREAD.to_owned()),
                    calls,
                    waited,
                    true
                ),
                "{label}: {took:?}"
            );
        }
    }

    #[test]
    fn test_a_note_waits_for_its_own_notice_once_and_not_for_ever() {
        let notes = Notes::default();
        let client = format!("{BOB}@{REALM}");
        let peer: Option<IpAddr> = "192.0.2.7".parse().ok();
        let other: Option<IpAddr> = "192.0.2.8".parse().ok();
        notes.put(client.clone(), note(Outcome::Rejected, peer, WRONG_CODE));
        notes.put(
            client.clone(),
            note(Outcome::Errored, peer, "totp replayed"),
        );
        let now = Instant::now();
        let takes = [
            ("another address", Outcome::Errored, other, now, None),
            (
                "an error, two attempts in flight",
                Outcome::Errored,
                peer,
                now,
                Some("totp replayed"),
            ),
            (
                "the reject, two attempts in flight",
                Outcome::Rejected,
                peer,
                now,
                Some(WRONG_CODE),
            ),
            ("each is taken once", Outcome::Rejected, peer, now, None),
        ];
        for (label, outcome, from, at, expected) in takes {
            let taken = notes.take_at(&client, outcome, from, at);
            assert_eq!(taken.as_deref(), expected, "{label}");
        }
        notes.put(
            client.clone(),
            note(Outcome::Errored, peer, "totp replayed"),
        );
        let late = notes.take_at(&client, Outcome::Errored, peer, Instant::now() + NOTE_LIFE);
        for n in 0..=NOTES_EACH {
            notes.put(client.clone(), note(Outcome::Errored, None, &n.to_string()));
        }
        let first = notes.take(&client, Outcome::Errored, None);
        assert_eq!(
            (late, first, notes.held().len()),
            (None, Some("1".to_owned()), 1),
            "a note no notice took is gone after its life; a user keeps the last few only"
        );
    }

    #[tokio::test]
    #[serial]
    #[cfg_attr(feature = "test-admission", ignore = "a row of the default build")]
    async fn test_the_verifier_is_registered_once_however_often_the_plugins_go_in() {
        let temp = TempRealm::new();
        let (_embedded, store) = temp.embedded();
        let mut guard = store.write().unwrap();
        crate::boot::install_plugins(&mut guard);
        crate::boot::install_plugins(&mut guard);
        let again = Arc::new(KlldapTotp::new(REALM));
        let twice = guard.policy.plugins.register_otp_verifier(again);
        assert!(
            twice.is_err(),
            "the realm's plugins hold one verifier named {CODE_TYPE}"
        );
    }
}
