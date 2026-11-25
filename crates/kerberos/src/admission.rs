use crate::otp::{Outcome, notes};
use crate::policy::NOT_FOUND;
use krb5_kdc::admission::{
    AsNotice, AsQuestion, AsReason, HostAdmission, KdcRefusal, Mechanism, TgsClient, TgsKind,
    TgsQuestion,
};
use krb5_kdc::{KdcPolicy, PolicyAdjustment, Principal, PrincipalRead};
use krb5_types::{EncTicketPart, HostAddress, KdcReqBody, PrincipalName, err};
use lldap_domain::types::UserId;
use lldap_domain_handlers::enforcement::{
    Attempt, Door, PolicyCache, Refusal, admit_at_kdc_with, item_checks, policy_cache,
    record_kdc_row,
};
use lldap_domain_handlers::kdc_proof::{
    ProofVerdict, kdc_verdict, proof_at_as, proof_at_tgs, proofs_live,
};
use lldap_domain_handlers::kerberos::user_id_for_principal_name;
use lldap_domain_handlers::lockout::{Lockout, THRESHOLD, lock_clock, lock_detail, lockout};
use lldap_domain_handlers::logging::LogKind;
use lldap_domain_handlers::mfa::ENABLE_MFA;
use std::cell::RefCell;
use std::net::IpAddr;

const REFUSED: KdcRefusal = KdcRefusal {
    code: err::CLIENT_REVOKED,
    e_text: None,
};
const GONE: &str = "the principal is gone";
const UNREAD: &str = "the principal could not be read";

/// As the KDC answered a client whose entry is gone before the module was asked.
fn gone() -> KdcRefusal {
    KdcRefusal {
        code: err::CLIENT_REVOKED,
        e_text: Some(NOT_FOUND.to_owned()),
    }
}
const NOT_SAID: &str = "refused by the directory";
/// One code and one ASCII text for every user who needs a fresh proof: a text that is not
/// ASCII never reaches the client.
const PROOF_CODE: i32 = err::POLICY;
pub(crate) const PROOF_TEXT: &str = "second factor needed: sign in to the directory with your \
    code (enrol there first if you have none), then run kinit again";
const NO_FRESH_PROOF: &str = "no fresh proof";

fn proof_refusal() -> KdcRefusal {
    KdcRefusal {
        code: PROOF_CODE,
        e_text: Some(PROOF_TEXT.to_owned()),
    }
}

fn proof_detail(door: Door) -> String {
    let refusal = Refusal {
        item: ENABLE_MFA,
        door,
        reason: None,
    };
    format!("{} ({NO_FRESH_PROOF})", refusal.detail())
}

/// A renewal, a validation, a service ticket or user-to-user: the user is the one asking.
fn present(kind: TgsKind) -> bool {
    !matches!(kind, TgsKind::S4u2Self | TgsKind::S4u2Proxy)
}

/// The service a refused request was made by follows the detail: `(S4U2Proxy by <service>)`.
fn on_behalf(detail: String, request: &str, service: Option<String>) -> String {
    let by = service.map_or_else(String::new, |service| format!(" by {service}"));
    format!("{detail} ({request}{by})")
}

fn tgs_door(kind: TgsKind) -> Door {
    match present(kind) {
        true => Door::KerberosTgs,
        false => Door::KerberosS4u,
    }
}

thread_local! {
    static AS_REFUSAL: RefCell<Option<(String, String)>> = const { RefCell::new(None) };
}

/// The directory's verdict at the KDC, from memory under the store's read guard.
pub(crate) struct KdcVerdict {
    realm: String,
    cache: &'static PolicyCache,
    lockout: &'static Lockout,
}

impl KdcVerdict {
    pub(crate) fn new(realm: &str) -> Self {
        Self {
            realm: realm.to_owned(),
            cache: policy_cache(),
            lockout: lockout(),
        }
    }

    #[cfg(test)]
    fn on(realm: &str, cache: &'static PolicyCache, lockout: &'static Lockout) -> Self {
        Self {
            realm: realm.to_owned(),
            cache,
            lockout,
        }
    }

    fn confirm_lock(&self, user: &UserId, refusal: &Refusal) {
        if refusal.item == THRESHOLD {
            self.lockout.confirm_soon(user);
        }
    }

    /// The directory's items, the lockout among them, judged before the second factor.
    fn judge_items(
        &self,
        user: &UserId,
        door: Door,
        peer: Option<IpAddr>,
        now: u32,
    ) -> Result<(), Refusal> {
        let checks = item_checks();
        if !checks.iter().any(|check| check.live(self.cache)) {
            return Ok(());
        }
        let attempt = Attempt::at_kdc(user, door, peer, now);
        let verdict = admit_at_kdc_with(self.cache, self.lockout, &attempt, &checks);
        if let Err(refusal) = &verdict {
            self.confirm_lock(user, refusal);
        }
        verdict
    }

    /// A refusal for want of a fresh proof asks for the user's windows again.
    fn no_fresh_proof(&self, user: &UserId, verdict: ProofVerdict, door: Door) -> Option<String> {
        let verdict = kdc_verdict(self.cache, user, verdict);
        (verdict == ProofVerdict::NoFreshProof).then(|| proof_detail(door))
    }

    /// Kerberos counts in the directory's one table; an S4U2Self gets no notice, so never counts.
    fn count(&self, user: &UserId, n: &AsNotice, peer: Option<IpAddr>) {
        if !self.cache.lockout_live() || !self.lockout.kdc_counts() {
            return;
        }
        let Some(lock) = self.lockout.kdc_state(self.cache, user) else {
            return;
        };
        let at = lock_clock();
        let step = match n.reason {
            AsReason::PreauthFailed => self.lockout.failure(&lock, at),
            AsReason::Issued => self.lockout.ticket_issued(self.cache, &lock, at),
            _ => return,
        };
        if step.lock_logged {
            let detail = lock_detail(Door::KerberosAs);
            let kind = LogKind::AccountLock;
            record_kdc_row(None, user.as_str(), kind, true, peer, &detail, false);
        }
        self.lockout.carry_from_kdc(user, step);
    }

    /// A ticket issued at AS is a sign-in for inactivity-days, with its own carry.
    fn note_issued(&self, user: &UserId, n: &AsNotice) {
        if n.reason == AsReason::Issued {
            self.cache.carry_success_from_kdc(user, lock_clock());
        }
    }

    /// The row of a subject with no entry to judge, named from the subject.
    fn subject_row(&self, q: &TgsQuestion<'_>, peer: Option<IpAddr>, detail: &str) {
        let user = user_named(q.subject, &self.realm, &self.realm);
        let name = q.subject.unparse_with_realm_lossy(&self.realm);
        let target = user.as_ref().map_or(name.as_str(), UserId::as_str);
        let kind = LogKind::AccessDenied;
        record_kdc_row(user.as_ref(), target, kind, false, peer, detail, false);
    }
}

pub(crate) fn ip_of(peer: &HostAddress) -> Option<IpAddr> {
    let bytes: &[u8] = &peer.address;
    match peer.addr_type {
        HostAddress::ADDRTYPE_INET => <[u8; 4]>::try_from(bytes).ok().map(IpAddr::from),
        HostAddress::ADDRTYPE_INET6 => <[u8; 16]>::try_from(bytes).ok().map(IpAddr::from),
        _ => None,
    }
}

pub(crate) fn user_named(name: &PrincipalName, of: &str, realm: &str) -> Option<UserId> {
    if of != realm {
        return None;
    }
    let joined = name.try_components_joined()?;
    user_id_for_principal_name(&joined).map(UserId::new)
}

pub(crate) fn user_of(client: &Principal, realm: &str) -> Option<UserId> {
    user_named(&client.name, &client.realm, realm)
}

fn user_of_id(id: &str, realm: &str) -> Option<UserId> {
    let (name, of) = id.rsplit_once('@')?;
    if of != realm {
        return None;
    }
    user_id_for_principal_name(name).map(UserId::new)
}

fn mechanism_name(mechanism: Mechanism) -> &'static str {
    match mechanism {
        Mechanism::EncTimestamp => "encrypted timestamp",
        Mechanism::EncChallenge => "encrypted challenge",
        Mechanism::Spake => "SPAKE",
        Mechanism::Pkinit => "PKINIT",
        Mechanism::Otp => "OTP",
    }
}

/// Pre-authentication passed, or was not required, before this notice.
fn proved(n: &AsNotice) -> bool {
    matches!(n.reason, AsReason::PolicyRefused | AsReason::Issued)
}

/// The verifier's reason for an OTP refusal, left for this notice; taken once.
fn otp_said(n: &AsNotice, peer: Option<IpAddr>) -> Option<String> {
    let outcome = match (n.mechanism, n.reason) {
        (Some(Mechanism::Otp), AsReason::PreauthFailed) => Outcome::Rejected,
        (Some(Mechanism::Otp), AsReason::PreauthNotCompleted) => Outcome::Errored,
        _ => return None,
    };
    notes().take(&n.client, outcome, peer)
}

fn notice_detail(n: &AsNotice, said: Option<&str>) -> String {
    let outcome = match (n.reason, said) {
        (AsReason::HostRefused, Some(said)) => said.to_owned(),
        (AsReason::HostRefused, None) => NOT_SAID.to_owned(),
        (AsReason::PreauthFailed | AsReason::PreauthNotCompleted, Some(said)) => said.to_owned(),
        (AsReason::Issued, _) => "ticket issued".to_owned(),
        (AsReason::PreauthFailed, _) => "pre-authentication failed".to_owned(),
        (AsReason::PreauthNotCompleted, _) => "pre-authentication not completed".to_owned(),
        (AsReason::PolicyRefused, _) => {
            format!("refused after pre-authentication, code {}", n.code)
        }
        (AsReason::EntryRefused, _) => format!("refused by the entry check, code {}", n.code),
    };
    match n.mechanism {
        Some(mechanism) => format!("{outcome} ({})", mechanism_name(mechanism)),
        None => outcome,
    }
}

impl HostAdmission for KdcVerdict {
    fn check_as(&self, q: &AsQuestion<'_>) -> Result<(), KdcRefusal> {
        AS_REFUSAL.with(|held| *held.borrow_mut() = None);
        let Some(user) = user_of(q.client, &self.realm) else {
            return Ok(());
        };
        let door = if q.s4u2self {
            Door::KerberosS4u
        } else {
            Door::KerberosAs
        };
        let peer = q.peer.and_then(ip_of);
        let (detail, answer) = match self.judge_items(&user, door, peer, q.now) {
            Err(refusal) => (refusal.detail(), REFUSED),
            Ok(()) if q.s4u2self => return Ok(()),
            Ok(()) => {
                let verdict = proof_at_as(self.cache, &user, i64::from(q.now), peer);
                match self.no_fresh_proof(&user, verdict, door) {
                    Some(detail) => (detail, proof_refusal()),
                    None => return Ok(()),
                }
            }
        };
        if q.s4u2self {
            let service = q.request.sname.as_ref();
            let service = service.map(|service| service.unparse_with_realm_lossy(&self.realm));
            let detail = on_behalf(detail, "S4U2Self", service);
            record_kdc_row(
                Some(&user),
                user.as_str(),
                door.log_kind(),
                false,
                peer,
                &detail,
                false,
            );
        } else {
            AS_REFUSAL.with(|held| *held.borrow_mut() = Some((q.client.id(), detail)));
        }
        Err(answer)
    }

    fn as_notice(&self, n: AsNotice) {
        let held = AS_REFUSAL.with(|held| held.borrow_mut().take());
        if matches!(
            n.code,
            err::PREAUTH_REQUIRED | err::MORE_PREAUTH_DATA_REQUIRED
        ) {
            return;
        }
        let peer = n.peer.as_ref().and_then(ip_of);
        let said = match n.reason {
            AsReason::HostRefused => held
                .filter(|(client, _)| *client == n.client)
                .map(|(_, detail)| detail),
            _ => otp_said(&n, peer),
        };
        let user = user_of_id(&n.client, &self.realm);
        let target = user.as_ref().map_or(n.client.as_str(), UserId::as_str);
        let issued = n.reason == AsReason::Issued;
        let detail = notice_detail(&n, said.as_deref());
        let (kind, proved) = (LogKind::Login, proved(&n));
        record_kdc_row(user.as_ref(), target, kind, issued, peer, &detail, proved);
        if let Some(user) = &user {
            self.count(user, &n, peer);
            self.note_issued(user, &n);
        }
    }

    fn check_tgs(&self, q: &TgsQuestion<'_>) -> Result<(), KdcRefusal> {
        let peer = q.peer.and_then(ip_of);
        let client = match q.client {
            TgsClient::Found(client) => client,
            TgsClient::NoEntry => {
                self.subject_row(q, peer, GONE);
                return Err(gone());
            }
            TgsClient::ReadFailed => {
                self.subject_row(q, peer, UNREAD);
                return Err(REFUSED);
            }
        };
        let Some(user) = user_of(client, &self.realm) else {
            return Ok(());
        };
        let door = tgs_door(q.kind);
        let Err(refusal) = self.judge_items(&user, door, peer, q.now) else {
            return Ok(());
        };
        let detail = refusal.detail();
        let by = || {
            let realm = String::from_utf8_lossy(q.ticket.crealm.as_bytes());
            Some(q.ticket.cname.unparse_with_realm_lossy(&realm))
        };
        let detail = match q.kind {
            TgsKind::S4u2Self => on_behalf(detail, "S4U2Self", by()),
            TgsKind::S4u2Proxy => on_behalf(detail, "S4U2Proxy", by()),
            _ => detail,
        };
        record_kdc_row(
            Some(&user),
            user.as_str(),
            door.log_kind(),
            false,
            peer,
            &detail,
            false,
        );
        Err(REFUSED)
    }
}

/// The second factor at TGS: the presented ticket's authentication time lies in a window.
pub(crate) struct SecondFactor {
    realm: String,
    cache: &'static PolicyCache,
}

impl SecondFactor {
    pub(crate) const NAME: &'static str = "lldap_second_factor";

    pub(crate) fn new(realm: &str, cache: &'static PolicyCache) -> Self {
        Self {
            realm: realm.to_owned(),
            cache,
        }
    }

    /// The ticket's client as the KDC finds it, an alias resolved, owned by the directory.
    fn owes_a_proof(&self, store: &dyn PrincipalRead, ticket: &EncTicketPart) -> Option<UserId> {
        if !proofs_live(self.cache) || ticket.crealm.as_bytes() != self.realm.as_bytes() {
            return None;
        }
        let client = store.fetch_client(&ticket.cname).ok().flatten()?;
        let user = user_of(&client, &self.realm).filter(|_| client.host_owned())?;
        let authtime = i64::from(ticket.authtime.unix_seconds());
        let verdict = kdc_verdict(self.cache, &user, proof_at_tgs(self.cache, &user, authtime));
        (verdict == ProofVerdict::NoFreshProof).then_some(user)
    }
}

impl KdcPolicy for SecondFactor {
    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn check_as(
        &self,
        _store: &dyn PrincipalRead,
        _client: &Principal,
        _indicators: &[String],
    ) -> Result<PolicyAdjustment, krb5_kdc::Error> {
        Ok(PolicyAdjustment::default())
    }

    fn check_tgs(
        &self,
        _store: &dyn PrincipalRead,
        _sname: &PrincipalName,
        _indicators: &[String],
    ) -> Result<PolicyAdjustment, krb5_kdc::Error> {
        Ok(PolicyAdjustment::default())
    }

    // `_status` stays unset: a status word would replace the text the client is sent.
    fn check_tgs_from(
        &self,
        _request: &KdcReqBody,
        store: &dyn PrincipalRead,
        _server: &Principal,
        ticket: &EncTicketPart,
        _indicators: &[String],
        peer: Option<&HostAddress>,
        _status: &mut Option<&'static str>,
    ) -> Result<PolicyAdjustment, krb5_kdc::Error> {
        let Some(user) = self.owes_a_proof(store, ticket) else {
            return Ok(PolicyAdjustment::default());
        };
        let (door, peer) = (Door::KerberosTgs, peer.and_then(ip_of));
        let detail = proof_detail(door);
        record_kdc_row(
            Some(&user),
            user.as_str(),
            door.log_kind(),
            false,
            peer,
            &detail,
            false,
        );
        let refusal = proof_refusal();
        Err(krb5_kdc::Error::Protocol {
            code: refusal.code,
            text: refusal.e_text,
            e_data: None,
            detail: None,
        })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::embedded::EmbeddedKerberos;
    use crate::embedded::tests::{TempRealm, ask, synced};
    use crate::policy::tests::{tgs_body, ticket};
    use crate::seam::committing;
    use chrono::Utc;
    use krb5_asn1::{decode, encode};
    use krb5_crypto::{EncryptionType, ProtocolKey, string_to_key};
    use krb5_kdc::admission::{TgsClient, TgsKind};
    use krb5_kdc::{IssuedAs, PrincipalRead, SharedDump};
    use krb5_protocol::{
        TgsReqParams, armor_key, attach_fast, build_fast_armor, fx_fast_padata_over, tgs_req_ex,
        unwrap_fast_rep,
    };
    use krb5_types::{KdcOptions, KrbError, MethodData, TgsRep, ascii, pa};
    use lldap_auth::opaque::server::generate_random_private_key;
    use lldap_domain::requests::CreateUserRequest;
    use lldap_domain::types::Attribute;
    use lldap_domain_handlers::enforcement::{
        Entries, INACTIVITY_DAYS, ItemFlags, UserFacts, fill_policy_cache, start_policy_cache,
        start_policy_filler,
    };
    use lldap_domain_handlers::handler::{PolicyBackendHandler, UserBackendHandler};
    use lldap_domain_handlers::inactivity::{Recorded, Recording};
    use lldap_domain_handlers::instant::{SignedDuration, Timestamp, to_naive};
    use lldap_domain_handlers::kdc_proof::ProofSettings;
    use lldap_domain_handlers::kerberos::KerberosSync;
    use lldap_domain_handlers::logging::{Protocol, RequestMeta, with_request};
    use lldap_domain_handlers::login_hours::LoginHoursCheck;
    use lldap_domain_handlers::mfa::{ENABLE_MFA, MfaPolicy};
    use lldap_domain_handlers::policies::{
        CreatePolicyRequest, EffectiveItem, PolicyScope, UpdatePolicyRequest,
    };
    use lldap_sql_backend_handler::SqlBackendHandler;
    use lldap_sql_backend_handler::sql_tables::init_table;
    use lldap_test_utils::enforcement::EnforcementGuard;
    use lldap_test_utils::recording_log::LogGuard;
    use pretty_assertions::assert_eq;
    use sea_orm::{
        ConnectOptions, ConnectionTrait, Database, DatabaseConnection, DbBackend, Statement,
        TransactionTrait,
    };
    use serial_test::serial;
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::{Duration, Instant};

    mod networks_rows;
    mod proof_wire_rows;

    const REALM: &str = "EXAMPLE.COM";
    const PASSWORD: &str = "Kdc-Pass-1";
    const SERVICE: &str = "HTTP/svc.example.com";
    const PEER: &str = "192.0.2.7";
    const OUTSIDE: &str = "outside login hours";
    const REFUSED_USER: &str = "e0refused";
    const ALLOWED_USER: &str = "e0allowed";
    const DISABLED_USER: &str = "e0disabled";
    const GONE_USER: &str = "e0gone";
    const HERE_USER: &str = "e0here";
    const ELSEWHERE_USER: &str = "e0elsewhere";
    const OURS: &[&str] = &[
        REFUSED_USER,
        ALLOWED_USER,
        DISABLED_USER,
        GONE_USER,
        HERE_USER,
        ELSEWHERE_USER,
    ];

    type Answer = Result<Vec<u8>, (i32, Option<String>)>;
    type KdcRow = (
        LogKind,
        bool,
        Option<String>,
        Option<String>,
        Option<String>,
    );

    fn nonce() -> u32 {
        static NEXT: AtomicU32 = AtomicU32::new(1);
        NEXT.fetch_add(1, Ordering::Relaxed)
    }

    fn name(user: &str) -> PrincipalName {
        PrincipalName::new(PrincipalName::NT_PRINCIPAL, [user])
    }

    fn peer() -> HostAddress {
        HostAddress::from_socket(format!("{PEER}:88").parse().unwrap())
    }

    fn answer(store: &SharedDump, request: &[u8]) -> Answer {
        let guard = store.read().unwrap();
        let reply = krb5_kdc::handle_request(&*guard, request).unwrap();
        match decode::<KrbError>(&reply) {
            Ok(e) => {
                let text = e
                    .e_text
                    .map(|t| String::from_utf8_lossy(t.as_bytes()).into_owned());
                Err((e.error_code, text))
            }
            Err(_) => Ok(reply),
        }
    }

    fn user_key(user: &str, password: &str) -> ProtocolKey {
        let salt = name(user).default_salt(REALM);
        string_to_key(EncryptionType::Aes256CtsHmacSha196, password, salt, None).unwrap()
    }

    pub(crate) fn kinit(
        store: &SharedDump,
        user: &str,
        password: Option<&str>,
    ) -> (i32, Option<String>) {
        let padata = password.map(|password| {
            vec![krb5_protocol::pa_enc_timestamp(&user_key(user, password)).unwrap()]
        });
        let request = krb5_protocol::as_req(name(user), REALM, nonce(), padata).unwrap();
        answer(store, &encode(&request).unwrap())
            .err()
            .unwrap_or((0, None))
    }

    fn issue_tgt(store: &SharedDump, user: &str) -> IssuedAs {
        let padata = vec![krb5_protocol::pa_enc_timestamp(&user_key(user, PASSWORD)).unwrap()];
        let request = krb5_protocol::as_req(name(user), REALM, nonce(), Some(padata)).unwrap();
        krb5_kdc::issue_as(&*store.read().unwrap(), &request).unwrap()
    }

    pub(crate) fn with_verdict(store: &SharedDump) {
        let verdict = Arc::new(KdcVerdict::new(REALM));
        store
            .write()
            .unwrap()
            .policy
            .plugins
            .set_host_admission(verdict);
    }

    async fn realm(users: &[&str]) -> (TempRealm, EmbeddedKerberos, SharedDump) {
        let temp = TempRealm::new();
        let (embedded, store) = temp.embedded();
        for user in users {
            synced(&embedded, &UserId::new(user), PASSWORD)
                .await
                .unwrap();
        }
        with_verdict(&store);
        (temp, embedded, store)
    }

    struct Service {
        name: PrincipalName,
        key: ProtocolKey,
        tgt: IssuedAs,
    }

    fn service(temp: &TempRealm, store: &SharedDump) -> Service {
        let name = PrincipalName::new(PrincipalName::NT_SRV_HST, SERVICE.split('/'));
        store
            .write()
            .unwrap()
            .change_committing(committing(&*temp.own()), |s| {
                s.insert_new_randkey(&name, REALM, &[], "test")
            })
            .unwrap()
            .unwrap();
        let guard = store.read().unwrap();
        let key = guard
            .get_name(&name)
            .unwrap()
            .best_key()
            .unwrap()
            .key
            .clone();
        let padata = vec![krb5_protocol::pa_enc_timestamp(&key).unwrap()];
        let request = krb5_protocol::as_req(name.clone(), REALM, nonce(), Some(padata)).unwrap();
        let tgt = krb5_kdc::issue_as(&*guard, &request).unwrap();
        Service { name, key, tgt }
    }

    fn service_ticket(store: &SharedDump, tgt: &IssuedAs, user: &str, svc: &Service) -> Answer {
        let ticket = tgt.rep.0.ticket.clone();
        let sname = svc.name.clone();
        let request = krb5_protocol::tgs_req(
            ticket,
            &tgt.session_key,
            REALM,
            &name(user),
            sname,
            REALM,
            nonce(),
        )
        .unwrap();
        answer(store, &encode(&request).unwrap())
    }

    /// The reply's client, the ticket's client and server; or the error code and e-text.
    type Outcome = Result<[String; 3], (i32, Option<String>)>;

    fn s4u2self(store: &SharedDump, svc: &Service, user: &str, x509: bool) -> Outcome {
        let nonce = nonce();
        let session = &svc.tgt.session_key;
        let for_user = if x509 {
            krb5_protocol::pa_s4u_x509_user(session, name(user), REALM, nonce)
        } else {
            krb5_protocol::pa_for_user(session, name(user), REALM)
        };
        let ticket = svc.tgt.rep.0.ticket.clone();
        let mut request = krb5_protocol::tgs_req(
            ticket,
            session,
            REALM,
            &svc.name,
            svc.name.clone(),
            REALM,
            nonce,
        )
        .unwrap();
        request
            .0
            .padata
            .get_or_insert_with(Vec::new)
            .push(for_user.unwrap());
        let reply = answer(store, &encode(&request).unwrap())?;
        let rep = decode::<TgsRep>(&reply).unwrap().0;
        let part = krb5_kdc::decrypt_ticket_part(&svc.key, &rep.ticket).unwrap();
        Ok([
            rep.cname.unparse_with_realm_lossy(REALM),
            part.cname.unparse_with_realm_lossy(REALM),
            rep.ticket.sname.unparse_with_realm_lossy(REALM),
        ])
    }

    fn tgs_asks(
        store: &SharedDump,
        client: Option<&str>,
        subject: &str,
        kind: TgsKind,
    ) -> Result<(), i32> {
        tgs_asks_of(&KdcVerdict::new(REALM), store, client, subject, kind)
    }

    fn tgs_asks_of(
        verdict: &KdcVerdict,
        store: &SharedDump,
        client: Option<&str>,
        subject: &str,
        kind: TgsKind,
    ) -> Result<(), i32> {
        let guard = store.read().unwrap();
        let found = |user: &str| TgsClient::Found(guard.get_name(&name(user)).unwrap());
        let client = client.map_or(TgsClient::NoEntry, found);
        let krbtgt = PrincipalName::new(PrincipalName::NT_SRV_INST, ["krbtgt", REALM]);
        let server = guard.fetch_name(&krbtgt).unwrap().unwrap();
        let ticket = ticket(REALM, subject);
        let request = tgs_body(&ticket);
        let (subject, peer) = (name(subject), peer());
        let q = TgsQuestion {
            client,
            subject: &subject,
            server: &server,
            ticket: &ticket,
            request: &request,
            peer: Some(&peer),
            now: 1_700_000_000,
            kind,
        };
        verdict.check_tgs(&q).map_err(|r| r.code)
    }

    /// A service's header ticket and the subject's entry gone, as an S4U2Proxy or a U2U asks.
    fn asked_behind_a_service(
        store: &SharedDump,
        client: Option<&str>,
        subject: &PrincipalName,
        kind: TgsKind,
    ) -> Result<(), (i32, Option<String>)> {
        let guard = store.read().unwrap();
        let found = |user: &str| TgsClient::Found(guard.get_name(&name(user)).unwrap());
        let client = client.map_or(TgsClient::NoEntry, found);
        asked_with(&guard, client, subject, kind)
    }

    fn asked_with(
        guard: &krb5_kdc::PrincipalStore,
        client: TgsClient<'_>,
        subject: &PrincipalName,
        kind: TgsKind,
    ) -> Result<(), (i32, Option<String>)> {
        let krbtgt = PrincipalName::new(PrincipalName::NT_SRV_INST, ["krbtgt", REALM]);
        let server = guard.fetch_name(&krbtgt).unwrap().unwrap();
        let mut header = ticket(REALM, "unused");
        header.cname = PrincipalName::new(PrincipalName::NT_SRV_HST, SERVICE.split('/'));
        let request = tgs_body(&header);
        let peer = peer();
        let q = TgsQuestion {
            client,
            subject,
            server: &server,
            ticket: &header,
            request: &request,
            peer: Some(&peer),
            now: 1_700_000_000,
            kind,
        };
        let verdict = KdcVerdict::new(REALM).check_tgs(&q);
        verdict.map_err(|r| (r.code, r.e_text))
    }

    fn as_asks(store: &SharedDump, user: &str, s4u2self: bool) -> Result<(), i32> {
        as_asks_of(&KdcVerdict::new(REALM), store, user, s4u2self)
    }

    fn as_asks_of(
        verdict: &KdcVerdict,
        store: &SharedDump,
        user: &str,
        s4u2self: bool,
    ) -> Result<(), i32> {
        let guard = store.read().unwrap();
        let client = guard.get_name(&name(user)).unwrap();
        let krbtgt = PrincipalName::new(PrincipalName::NT_SRV_INST, ["krbtgt", REALM]);
        let server = guard.fetch_name(&krbtgt).unwrap().unwrap();
        let mut request = tgs_body(&ticket(REALM, user));
        let service = PrincipalName::new(PrincipalName::NT_SRV_HST, SERVICE.split('/'));
        request.sname = Some(service);
        let (requested, peer) = (name(user), peer());
        let q = AsQuestion {
            client,
            requested: &requested,
            server: &server,
            peer: Some(&peer),
            now: 1_700_000_000,
            request: &request,
            s4u2self,
        };
        verdict.check_as(&q).map_err(|r| r.code)
    }

    fn hours(value: &str) -> Arc<[EffectiveItem]> {
        let item = EffectiveItem {
            key: "login-hours".to_owned(),
            scope: PolicyScope::User,
            value: value.to_owned(),
            enforced: false,
            source: None,
        };
        vec![item].into()
    }

    /// The refused users sit in an OU whose value the check refuses.
    fn cached(refused: &[&str], allowed: &[&str]) {
        cached_values(refused, allowed, ["refuse", "any"]);
    }

    fn cached_values(refused: &[&str], allowed: &[&str], [labs, people]: [&str; 2]) {
        let mut ous_of_users = HashMap::new();
        for (users, ou) in [(refused, "people\\labs"), (allowed, "people")] {
            for user in users {
                ous_of_users.insert(UserId::new(user), ou.to_owned());
            }
        }
        let items_of_ous = HashMap::from([
            ("people\\labs".to_owned(), hours(labs)),
            ("people".to_owned(), hours(people)),
        ]);
        policy_cache().replace(Entries {
            ous_of_users,
            items_of_ous,
            facts: HashMap::new(),
            windows: HashMap::new(),
            built_at: Timestamp::now(),
        });
    }

    fn deciding() -> EnforcementGuard {
        EnforcementGuard::deciding(OURS, "login-hours", |value| value != "refuse")
    }

    fn kdc_rows(log: &LogGuard) -> Vec<KdcRow> {
        let events = log.recorder().take_events().into_iter();
        let ours = events.filter(|e| e.protocol == Protocol::Kerberos);
        ours.map(|e| (e.kind, e.success, e.target, e.peer, e.detail))
            .collect()
    }

    fn row(kind: LogKind, success: bool, user: &str, detail: &str) -> KdcRow {
        (
            kind,
            success,
            Some(user.to_owned()),
            None,
            Some(detail.to_owned()),
        )
    }

    fn peered((kind, success, user, _, detail): KdcRow) -> KdcRow {
        (kind, success, user, Some(PEER.to_owned()), detail)
    }

    fn doors(guard: &EnforcementGuard) -> Vec<(String, Door)> {
        let seen = guard.take_seen().into_iter();
        seen.map(|s| (s.user.as_str().to_owned(), s.door)).collect()
    }

    async fn memory_pool() -> DatabaseConnection {
        let mut options = ConnectOptions::new("sqlite::memory:".to_owned());
        options.max_connections(1);
        let pool = Database::connect(options).await.unwrap();
        init_table(&pool).await.unwrap();
        pool
    }

    async fn directory_user(handler: &SqlBackendHandler, user: &str, ou: &str) {
        let request = CreateUserRequest {
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

    async fn strict_labs(handler: &SqlBackendHandler) {
        let request = CreatePolicyRequest {
            name: "Strict".to_owned(),
            description: String::new(),
            items: [("enable-mfa".to_owned(), "always".to_owned())].into(),
        };
        let id = handler.create_policy(request).await.unwrap();
        handler.set_ou_policy("people\\labs", id).await.unwrap();
    }

    fn strict() -> EnforcementGuard {
        EnforcementGuard::deciding(OURS, "enable-mfa", |value| value != "always")
    }

    #[test]
    fn test_ip_of_table() {
        let socket = |text: &str| HostAddress::from_socket(text.parse().unwrap());
        let rows = [
            ("v4", socket("192.0.2.7:88"), Some("192.0.2.7")),
            ("v6", socket("[2001:db8::7]:88"), Some("2001:db8::7")),
            (
                "v4 mapped",
                socket("[::ffff:192.0.2.7]:88"),
                Some("192.0.2.7"),
            ),
            (
                "netbios",
                HostAddress {
                    addr_type: HostAddress::ADDRTYPE_NETBIOS,
                    address: b"HOST".to_vec().into(),
                },
                None,
            ),
            (
                "short",
                HostAddress {
                    addr_type: HostAddress::ADDRTYPE_INET,
                    address: vec![192, 0, 2].into(),
                },
                None,
            ),
        ];
        for (row, address, expected) in rows {
            let expected = expected.map(|ip| ip.parse::<IpAddr>().unwrap());
            assert_eq!(ip_of(&address), expected, "{row}");
        }
    }

    #[test]
    fn test_only_a_one_part_name_of_the_realm_is_a_directory_user() {
        let service = PrincipalName::new(PrincipalName::NT_SRV_HST, ["HTTP", "svc.example.com"]);
        let rows = [
            ("one part, lowercased", name("Sable"), REALM, Some("sable")),
            ("two parts", service, REALM, None),
            ("another realm", name("sable"), "OTHER.ORG", None),
        ];
        for (row, principal, of, expected) in rows {
            let got = user_named(&principal, of, REALM);
            assert_eq!(got.as_ref().map(UserId::as_str), expected, "{row}");
        }
        let ids = [
            ("sable@EXAMPLE.COM", Some("sable")),
            ("HTTP/svc.example.com@EXAMPLE.COM", None),
            ("sable@OTHER.ORG", None),
            ("sable", None),
        ];
        for (id, expected) in ids {
            let got = user_of_id(id, REALM);
            assert_eq!(got.as_ref().map(UserId::as_str), expected, "{id}");
        }
    }

    #[tokio::test]
    #[serial]
    async fn test_with_no_check_the_verdict_reads_nothing_fills_nothing_and_allows() {
        let (temp, _embedded, store) = realm(&[REFUSED_USER]).await;
        let svc = service(&temp, &store);
        let _guard = EnforcementGuard::none();
        let reads = policy_cache().reads();
        let tgt = issue_tgt(&store, REFUSED_USER);
        let answers = (
            kinit(&store, REFUSED_USER, Some(PASSWORD)),
            service_ticket(&store, &tgt, REFUSED_USER, &svc).map(drop),
            tgs_asks(&store, None, REFUSED_USER, TgsKind::Renew),
        );
        let handler = SqlBackendHandler::new(generate_random_private_key(), memory_pool().await);
        let filler = start_policy_cache(&handler).await;
        assert_eq!(
            (answers, policy_cache().reads() - reads, filler.is_none()),
            (((0, None), Ok(()), Err(err::CLIENT_REVOKED)), 0, true),
            "no check: AS and TGS as today, the cache is not read, no filler starts; a subject \
             whose entry is gone is refused whatever is registered"
        );
    }

    #[test]
    #[serial]
    fn test_one_login_row_per_notice_with_its_reason() {
        let log = LogGuard::install_on_this_thread();
        let verdict = KdcVerdict::new(REALM);
        let client = format!("{REFUSED_USER}@{REALM}");
        let notice = |reason, code, mechanism| AsNotice {
            client: client.clone(),
            requested: client.clone(),
            peer: Some(peer()),
            time: 1_700_000_000,
            code,
            reason,
            mechanism,
        };
        let rows = [
            (
                notice(AsReason::Issued, 0, Some(Mechanism::EncTimestamp)),
                true,
                true,
                "ticket issued (encrypted timestamp)",
            ),
            (
                notice(
                    AsReason::PreauthFailed,
                    err::PREAUTH_FAILED,
                    Some(Mechanism::EncChallenge),
                ),
                false,
                false,
                "pre-authentication failed (encrypted challenge)",
            ),
            (
                notice(
                    AsReason::PreauthNotCompleted,
                    err::PREAUTH_FAILED,
                    Some(Mechanism::Otp),
                ),
                false,
                false,
                "pre-authentication not completed (OTP)",
            ),
            (
                notice(AsReason::PolicyRefused, err::POLICY, None),
                false,
                true,
                "refused after pre-authentication, code 12",
            ),
            (
                notice(AsReason::EntryRefused, err::CLIENT_REVOKED, None),
                false,
                false,
                "refused by the entry check, code 18",
            ),
            (
                notice(AsReason::HostRefused, err::CLIENT_REVOKED, None),
                false,
                false,
                NOT_SAID,
            ),
        ];
        for (n, success, proved, detail) in rows {
            verdict.as_notice(n);
            let events = log.recorder().take_events();
            let marks: Vec<_> = events.iter().map(|e| e.proved).collect();
            let rows = events.into_iter();
            let rows: Vec<KdcRow> = rows
                .map(|e| (e.kind, e.success, e.target, e.peer, e.detail))
                .collect();
            let expected = vec![peered(row(LogKind::Login, success, REFUSED_USER, detail))];
            assert_eq!(
                (rows, marks),
                (expected, vec![proved]),
                "{detail}: the row, and whether pre-authentication passed before it"
            );
        }
        let more = Some(Mechanism::Spake);
        verdict.as_notice(notice(
            AsReason::PreauthNotCompleted,
            err::PREAUTH_REQUIRED,
            None,
        ));
        verdict.as_notice(notice(
            AsReason::PreauthNotCompleted,
            err::MORE_PREAUTH_DATA_REQUIRED,
            more,
        ));
        assert_eq!(
            kdc_rows(&log),
            vec![],
            "a request for pre-authentication is no sign-in"
        );
    }

    #[test]
    #[serial]
    fn test_an_otp_refusal_row_gives_the_verifiers_reason_once() {
        use crate::otp::tests::note;
        let log = LogGuard::install_on_this_thread();
        let verdict = KdcVerdict::new(REALM);
        let user = "e8knote";
        let client = format!("{user}@{REALM}");
        let from = ip_of(&peer());
        let wrong = note(crate::otp::Outcome::Rejected, from, "invalid totp");
        notes().put(client.clone(), wrong);
        notes().put(
            client.clone(),
            note(crate::otp::Outcome::Errored, from, "totp replayed"),
        );
        let notice = |reason, code| AsNotice {
            client: client.clone(),
            requested: client.clone(),
            peer: Some(peer()),
            time: 1_700_000_000,
            code,
            reason,
            mechanism: Some(Mechanism::Otp),
        };
        let failed = err::PREAUTH_FAILED;
        let rows = [
            (
                AsReason::PreauthNotCompleted,
                failed,
                false,
                "totp replayed (OTP)",
            ),
            (AsReason::PreauthFailed, failed, false, "invalid totp (OTP)"),
            (
                AsReason::PreauthFailed,
                failed,
                false,
                "pre-authentication failed (OTP)",
            ),
            (AsReason::Issued, 0, true, "ticket issued (OTP)"),
        ];
        for (reason, code, success, detail) in rows {
            verdict.as_notice(notice(reason, code));
            assert_eq!(
                kdc_rows(&log),
                vec![peered(row(LogKind::Login, success, user, detail))],
                "{detail}: two attempts in flight, each row its own reason, taken once"
            );
        }
    }

    #[tokio::test]
    #[serial]
    async fn test_a_kerberos_sign_in_leaves_one_row_and_a_bare_ask_none() {
        let b = ALLOWED_USER;
        let (_temp, _embedded, store) = realm(&[b]).await;
        let log = LogGuard::install_on_this_thread();
        let _guard = EnforcementGuard::none();
        let issued = "ticket issued (encrypted timestamp)";
        let failed = "pre-authentication failed (encrypted timestamp)";
        type Row<'a> = (&'a str, Option<&'a str>, [i32; 2], Vec<KdcRow>);
        let rows: [Row; 3] = [
            (
                "a kinit: asked, then pre-authenticated",
                Some(PASSWORD),
                [err::PREAUTH_REQUIRED, 0],
                vec![row(LogKind::Login, true, b, issued)],
            ),
            (
                "a wrong password",
                Some("Wrong-Pass-1"),
                [err::PREAUTH_REQUIRED, err::PREAUTH_FAILED],
                vec![row(LogKind::Login, false, b, failed)],
            ),
            (
                "only asking, twice",
                None,
                [err::PREAUTH_REQUIRED; 2],
                vec![],
            ),
        ];
        for (label, password, codes, expected) in rows {
            let got = [kinit(&store, b, None).0, kinit(&store, b, password).0];
            assert_eq!((got, kdc_rows(&log)), (codes, expected), "{label}");
        }
    }

    #[tokio::test]
    #[serial]
    async fn test_check_as_refuses_before_preauth_and_the_notice_writes_the_one_row() {
        let (_temp, _embedded, store) = realm(&[REFUSED_USER, ALLOWED_USER]).await;
        let log = LogGuard::install_on_this_thread();
        let guard = deciding();
        cached(&[REFUSED_USER], &[ALLOWED_USER]);
        let (a, b) = (REFUSED_USER, ALLOWED_USER);
        let refused = vec![row(LogKind::Login, false, a, "policy: login-hours")];
        let failed = "pre-authentication failed (encrypted timestamp)";
        let issued = "ticket issued (encrypted timestamp)";
        type Row<'a> = (&'a str, &'a str, Option<&'a str>, i32, Vec<KdcRow>);
        let rows: [Row; 5] = [
            (
                "refused, no padata",
                a,
                None,
                err::CLIENT_REVOKED,
                refused.clone(),
            ),
            (
                "refused, the right password",
                a,
                Some(PASSWORD),
                err::CLIENT_REVOKED,
                refused,
            ),
            ("allowed, no padata", b, None, err::PREAUTH_REQUIRED, vec![]),
            (
                "allowed, a wrong password",
                b,
                Some("Wrong-Pass-1"),
                err::PREAUTH_FAILED,
                vec![row(LogKind::Login, false, b, failed)],
            ),
            (
                "allowed, the right password",
                b,
                Some(PASSWORD),
                0,
                vec![row(LogKind::Login, true, b, issued)],
            ),
        ];
        for (label, user, password, code, expected) in rows {
            let (got, text) = kinit(&store, user, password);
            let seen = guard.take_seen().into_iter();
            let seen: Vec<_> = seen
                .map(|s| (s.user.as_str().to_owned(), s.door, s.peer))
                .collect();
            assert_eq!(
                (got, kdc_rows(&log), seen),
                (
                    code,
                    expected,
                    vec![(user.to_owned(), Door::KerberosAs, None)]
                ),
                "{label}"
            );
            if code == err::CLIENT_REVOKED {
                assert_eq!(text, None, "{label}: no e-text");
            }
        }
    }

    #[tokio::test]
    #[serial]
    async fn test_the_verdict_takes_the_questions_peer_and_pairs_a_refusal_with_its_notice() {
        let (a, b) = (REFUSED_USER, ALLOWED_USER);
        let (_temp, _embedded, store) = realm(&[a, b]).await;
        let log = LogGuard::install_on_this_thread();
        let guard = deciding();
        cached(&[a], &[b]);
        let peer_ip: IpAddr = PEER.parse().unwrap();
        let notice = |user: &str| AsNotice {
            client: format!("{user}@{REALM}"),
            requested: format!("{user}@{REALM}"),
            peer: Some(peer()),
            time: 1_700_000_000,
            code: err::CLIENT_REVOKED,
            reason: AsReason::HostRefused,
            mechanism: None,
        };
        let verdict = KdcVerdict::new(REALM);
        let by = format!("policy: login-hours (S4U2Self by {SERVICE}@{REALM})");
        let rows = [
            (
                "a login, refused",
                a,
                false,
                Err(err::CLIENT_REVOKED),
                vec![],
                Door::KerberosAs,
            ),
            (
                "an S4U2Self, refused",
                a,
                true,
                Err(err::CLIENT_REVOKED),
                vec![peered(row(LogKind::AccessDenied, false, a, &by))],
                Door::KerberosS4u,
            ),
            (
                "a login, allowed",
                b,
                false,
                Ok(()),
                vec![],
                Door::KerberosAs,
            ),
        ];
        for (label, user, s4u2self, expected, rows, door) in rows {
            let got = as_asks(&store, user, s4u2self);
            let seen = guard.take_seen().into_iter();
            let seen: Vec<_> = seen
                .map(|s| (s.user.as_str().to_owned(), s.door, s.peer))
                .collect();
            assert_eq!(
                (got, kdc_rows(&log), seen),
                (expected, rows, vec![(user.to_owned(), door, Some(peer_ip))]),
                "{label}"
            );
        }
        assert_eq!(as_asks(&store, a, false), Err(err::CLIENT_REVOKED));
        verdict.as_notice(notice(b));
        verdict.as_notice(notice(a));
        let refused = peered(row(LogKind::Login, false, a, "policy: login-hours"));
        let other = peered(row(LogKind::Login, false, b, NOT_SAID));
        assert_eq!(
            kdc_rows(&log),
            vec![other, peered(row(LogKind::Login, false, a, NOT_SAID))],
            "a held refusal names only its own client's notice, and only the next one"
        );
        assert_eq!(as_asks(&store, a, false), Err(err::CLIENT_REVOKED));
        verdict.as_notice(notice(a));
        assert_eq!(
            kdc_rows(&log),
            vec![refused],
            "the notice that follows names the item"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_check_tgs_refuses_from_the_clients_record_with_a_row_each() {
        let (temp, _embedded, store) = realm(&[REFUSED_USER, ALLOWED_USER]).await;
        let svc = service(&temp, &store);
        let tgts = [REFUSED_USER, ALLOWED_USER].map(|user| issue_tgt(&store, user));
        let log = LogGuard::install_on_this_thread();
        let guard = deciding();
        cached(&[REFUSED_USER], &[ALLOWED_USER]);
        let (a, b) = (REFUSED_USER, ALLOWED_USER);
        let revoked = Err(err::CLIENT_REVOKED);
        let denied = || vec![row(LogKind::AccessDenied, false, a, "policy: login-hours")];
        let at_tgs = |user: &str| vec![(user.to_owned(), Door::KerberosTgs)];
        type Row = (
            &'static str,
            Result<(), i32>,
            Vec<KdcRow>,
            Vec<(String, Door)>,
        );
        let rows: [Row; 6] = [
            ("a service ticket, refused", revoked, denied(), at_tgs(a)),
            (
                "a renewal, refused",
                revoked,
                vec![peered(denied()[0].clone())],
                at_tgs(a),
            ),
            ("a service ticket, allowed", Ok(()), vec![], at_tgs(b)),
            ("a renewal, allowed", Ok(()), vec![], at_tgs(b)),
            (
                "the entry gone",
                revoked,
                vec![peered(row(LogKind::AccessDenied, false, a, GONE))],
                vec![],
            ),
            (
                "named from the client, not the subject",
                revoked,
                vec![peered(denied()[0].clone())],
                at_tgs(a),
            ),
        ];
        for (label, expected, rows, seen) in rows {
            let ticket_for = |tgt: &IssuedAs, user: &str| {
                let answered = service_ticket(&store, tgt, user, &svc);
                answered.map(drop).map_err(|(code, _)| code)
            };
            let got = match label {
                "a service ticket, refused" => ticket_for(&tgts[0], a),
                "a service ticket, allowed" => ticket_for(&tgts[1], b),
                "a renewal, refused" => tgs_asks(&store, Some(a), a, TgsKind::Renew),
                "a renewal, allowed" => tgs_asks(&store, Some(b), b, TgsKind::Renew),
                "the entry gone" => tgs_asks(&store, None, a, TgsKind::Normal),
                _ => tgs_asks(&store, Some(a), b, TgsKind::Renew),
            };
            assert_eq!(
                (got, kdc_rows(&log), doors(&guard)),
                (expected, rows, seen),
                "{label}"
            );
        }
        for _ in 0..10 {
            let _ = tgs_asks(&store, Some(a), a, TgsKind::Renew);
        }
        assert_eq!(
            kdc_rows(&log),
            vec![peered(denied()[0].clone()); 10],
            "one access_denied row each: the log writer coalesces them as a flood"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_every_gone_subject_is_refused_with_one_row_named_from_the_subject() {
        let (_temp, _embedded, store) = realm(&[ALLOWED_USER]).await;
        let log = LogGuard::install_on_this_thread();
        let (gone, here) = (GONE_USER, ALLOWED_USER);
        let kinds = [
            TgsKind::S4u2Proxy,
            TgsKind::U2u,
            TgsKind::Renew,
            TgsKind::Normal,
        ];
        let not_found = Err((err::CLIENT_REVOKED, Some("CLIENT_NOT_FOUND".to_owned())));
        for registered in [false, true] {
            let _guard = if registered {
                deciding()
            } else {
                EnforcementGuard::none()
            };
            for kind in kinds {
                let label = format!("{kind:?}, a check registered: {registered}");
                let asked = asked_behind_a_service(&store, None, &name(gone), kind);
                let row = peered(row(LogKind::AccessDenied, false, gone, GONE));
                assert_eq!(
                    (asked, kdc_rows(&log)),
                    (not_found.clone(), vec![row]),
                    "{label}"
                );
            }
        }
        let inert = EnforcementGuard::none();
        let reads = policy_cache().reads();
        for kind in kinds {
            let asked = asked_behind_a_service(&store, Some(here), &name(here), kind);
            let label = format!("{kind:?}, a user who exists, no check registered");
            assert_eq!((asked, kdc_rows(&log)), (Ok(()), vec![]), "{label}");
        }
        assert_eq!(
            policy_cache().reads(),
            reads,
            "a user who exists costs no lookup"
        );
        drop(inert);
        let service = PrincipalName::new(PrincipalName::NT_SRV_HST, ["HTTP", "gone.example.com"]);
        assert_eq!(
            asked_behind_a_service(&store, None, &service, TgsKind::S4u2Proxy),
            not_found,
            "a gone subject that is no directory user is refused too"
        );
        let named = kdc_rows(&log)
            .into_iter()
            .map(|row| row.2)
            .collect::<Vec<_>>();
        let expected = format!("HTTP/gone.example.com@{REALM}");
        assert_eq!(
            named,
            vec![Some(expected)],
            "named by the subject, never the service"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_s4u2self_has_its_own_door_and_writes_its_own_row() {
        let (disabled, gone) = (DISABLED_USER, GONE_USER);
        let (a, b) = (REFUSED_USER, ALLOWED_USER);
        let (temp, embedded, store) = realm(&[a, b, disabled, gone]).await;
        let disabled_id = UserId::new(disabled);
        let disable = embedded.set_principal_enabled(&disabled_id, false);
        disable.await.unwrap();
        embedded.delete_principal(&UserId::new(gone)).await.unwrap();
        let svc = service(&temp, &store);
        let log = LogGuard::install_on_this_thread();
        let guard = deciding();
        cached(&[a, disabled, gone], &[b]);
        let by = format!("policy: login-hours (S4U2Self by {SERVICE}@{REALM})");
        let issued = |user: &str| -> Outcome {
            let user = format!("{user}@{REALM}");
            Ok([user.clone(), user, format!("{SERVICE}@{REALM}")])
        };
        let text = |t: &str| Some(t.to_owned());
        type Row = (
            &'static str,
            &'static str,
            Outcome,
            Vec<KdcRow>,
            Vec<(String, Door)>,
        );
        let rows: [Row; 4] = [
            (
                "refused",
                a,
                Err((err::CLIENT_REVOKED, None)),
                vec![row(LogKind::AccessDenied, false, a, &by)],
                vec![(a.to_owned(), Door::KerberosS4u)],
            ),
            (
                "allowed",
                b,
                issued(b),
                vec![],
                vec![
                    (b.to_owned(), Door::KerberosS4u),
                    (b.to_owned(), Door::KerberosS4u),
                ],
            ),
            (
                "disabled: the entry check, the module not asked",
                disabled,
                Err((err::CLIENT_REVOKED, text("CLIENT LOCKED OUT"))),
                vec![],
                vec![],
            ),
            (
                "gone: the module not asked",
                gone,
                Err((err::C_PRINCIPAL_UNKNOWN, text("UNKNOWN_S4U2SELF_PRINCIPAL"))),
                vec![],
                vec![],
            ),
        ];
        for (label, user, outcome, rows, seen) in rows {
            for x509 in [false, true] {
                let got = s4u2self(&store, &svc, user, x509);
                assert_eq!(
                    (got, kdc_rows(&log), doors(&guard)),
                    (outcome.clone(), rows.clone(), seen.clone()),
                    "{label}, PA-S4U-X509-USER {x509}"
                );
            }
        }
        assert!(
            !Door::KerberosS4u.is_login(),
            "an S4U2Self counts no attempt"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_each_tgs_kind_is_judged_at_its_door() {
        let (_temp, _embedded, store) = realm(&[ALLOWED_USER]).await;
        let guard = deciding();
        cached(&[], &[ALLOWED_USER]);
        let b = ALLOWED_USER;
        let rows = [
            (TgsKind::Normal, Door::KerberosTgs),
            (TgsKind::Renew, Door::KerberosTgs),
            (TgsKind::Validate, Door::KerberosTgs),
            (TgsKind::U2u, Door::KerberosTgs),
            (TgsKind::S4u2Self, Door::KerberosS4u),
            (TgsKind::S4u2Proxy, Door::KerberosS4u),
        ];
        for (kind, door) in rows {
            let asked = tgs_asks(&store, Some(b), b, kind);
            assert_eq!(
                (tgs_door(kind), asked, doors(&guard)),
                (door, Ok(()), vec![(b.to_owned(), door)]),
                "{kind:?}"
            );
        }
        assert_eq!(
            (as_asks(&store, b, true), doors(&guard)),
            (Ok(()), vec![(b.to_owned(), Door::KerberosS4u)]),
            "an AS asked with s4u2self"
        );
        assert_eq!(Door::KerberosS4u.name(), "kerberos S4U");
    }

    #[tokio::test]
    #[serial]
    async fn test_a_checks_reason_reaches_the_row_and_the_kdc_still_answers_18_with_no_text() {
        let (_temp, _embedded, store) = realm(&[REFUSED_USER]).await;
        let log = LogGuard::install_on_this_thread();
        let allow = |value: &str| value != "refuse";
        let _guard = EnforcementGuard::deciding_with_reason(OURS, "login-hours", OUTSIDE, allow);
        cached(&[REFUSED_USER], &[]);
        let a = REFUSED_USER;
        let reasoned = "policy: login-hours (outside login hours)";
        let by = format!("{reasoned} (S4U2Self by {SERVICE}@{REALM})");
        assert_eq!(
            (kinit(&store, a, Some(PASSWORD)), kdc_rows(&log)),
            (
                (err::CLIENT_REVOKED, None),
                vec![row(LogKind::Login, false, a, reasoned)]
            ),
            "kinit: 18 with no text, the reason in the row"
        );
        assert_eq!(
            (as_asks(&store, a, true), kdc_rows(&log)),
            (
                Err(err::CLIENT_REVOKED),
                vec![peered(row(LogKind::AccessDenied, false, a, &by))]
            ),
            "an S4U2Self at the AS: the reason, then the service"
        );
        assert_eq!(
            (tgs_asks(&store, Some(a), a, TgsKind::Renew), kdc_rows(&log)),
            (
                Err(err::CLIENT_REVOKED),
                vec![peered(row(LogKind::AccessDenied, false, a, reasoned))]
            ),
            "a renewal"
        );
        let rows = [
            (TgsKind::S4u2Self, "S4U2Self"),
            (TgsKind::S4u2Proxy, "S4U2Proxy"),
        ];
        for (kind, named) in rows {
            let asked = asked_behind_a_service(&store, Some(a), &name(a), kind);
            let by = format!("{reasoned} ({named} by {SERVICE}@{REALM})");
            assert_eq!(
                (asked.map_err(|(code, _)| code), kdc_rows(&log)),
                (
                    Err(err::CLIENT_REVOKED),
                    vec![peered(row(LogKind::AccessDenied, false, a, &by))]
                ),
                "{kind:?} at the TGS"
            );
        }
    }

    #[tokio::test]
    #[serial]
    async fn test_an_s4u2proxy_refusal_names_the_asking_service_as_an_s4u2self_does() {
        let (_temp, _embedded, store) = realm(&[REFUSED_USER, ALLOWED_USER]).await;
        let log = LogGuard::install_on_this_thread();
        let _guard = deciding();
        cached(&[REFUSED_USER], &[ALLOWED_USER]);
        let (a, b) = (REFUSED_USER, ALLOWED_USER);
        let by = format!("policy: login-hours (S4U2Proxy by {SERVICE}@{REALM})");
        let proxied = |user: &str| {
            let asked = asked_behind_a_service(&store, Some(user), &name(user), TgsKind::S4u2Proxy);
            asked.map_err(|(code, _)| code)
        };
        assert_eq!(
            (proxied(a), kdc_rows(&log)),
            (
                Err(err::CLIENT_REVOKED),
                vec![peered(row(LogKind::AccessDenied, false, a, &by))]
            ),
            "refused: the item, then the service that asked for the user"
        );
        assert_eq!(
            (proxied(b), kdc_rows(&log)),
            (Ok(()), vec![]),
            "allowed: no row"
        );
    }

    const DAYTIME: &str = "tue 08:00-18:00";
    const EVENING: &str = "tue 22:00-23:00";

    /// The real check for our users, its item on: 1_700_000_000 is Tuesday 22:13:20 UTC.
    fn real_hours() -> EnforcementGuard {
        let check = Arc::new(LoginHoursCheck::on(policy_cache()));
        let guard = EnforcementGuard::judging(OURS, check);
        policy_cache().set_item_flags(ItemFlags {
            login_hours: true,
            ..ItemFlags::default()
        });
        guard
    }

    #[tokio::test]
    #[serial]
    async fn test_login_hours_judge_the_as_a_renewal_and_a_service_ticket_at_the_kdcs_instant() {
        let (a, b) = (REFUSED_USER, ALLOWED_USER);
        let (_temp, _embedded, store) = realm(&[a, b]).await;
        let log = LogGuard::install_on_this_thread();
        let guard = real_hours();
        cached_values(&[a], &[b], [DAYTIME, EVENING]);
        let asked_at = Timestamp::from_second(1_700_000_000).unwrap();
        let reasoned = "policy: login-hours (outside login hours)";
        let denied = vec![peered(row(LogKind::AccessDenied, false, a, reasoned))];
        let revoked = Err(err::CLIENT_REVOKED);
        type Row = (
            &'static str,
            &'static str,
            Result<(), i32>,
            Vec<KdcRow>,
            Door,
        );
        let rows: [Row; 6] = [
            ("the AS, outside", a, revoked, vec![], Door::KerberosAs),
            ("the AS, inside", b, Ok(()), vec![], Door::KerberosAs),
            (
                "a renewal, outside",
                a,
                revoked,
                denied.clone(),
                Door::KerberosTgs,
            ),
            ("a renewal, inside", b, Ok(()), vec![], Door::KerberosTgs),
            (
                "a service ticket, outside",
                a,
                revoked,
                denied,
                Door::KerberosTgs,
            ),
            (
                "a service ticket, inside",
                b,
                Ok(()),
                vec![],
                Door::KerberosTgs,
            ),
        ];
        for (label, user, expected, rows, door) in rows {
            let got = match label.split(',').next() {
                Some("the AS") => as_asks(&store, user, false),
                Some("a renewal") => tgs_asks(&store, Some(user), user, TgsKind::Renew),
                _ => tgs_asks(&store, Some(user), user, TgsKind::Normal),
            };
            let seen = guard.take_seen().into_iter();
            let seen: Vec<_> = seen
                .map(|s| (s.user.as_str().to_owned(), s.door, s.now))
                .collect();
            assert_eq!(
                (got, kdc_rows(&log), seen),
                (expected, rows, vec![(user.to_owned(), door, asked_at)]),
                "{label}: judged at the KDC's instant"
            );
        }
        let renewed = asked_behind_a_service(&store, Some(a), &name(a), TgsKind::Renew);
        assert_eq!(
            (renewed, kdc_rows(&log)),
            (
                Err((err::CLIENT_REVOKED, None)),
                vec![peered(row(LogKind::AccessDenied, false, a, reasoned))]
            ),
            "a renewal outside the hours: 18 with no text, the reason in the row"
        );
        assert_eq!(as_asks(&store, a, false), revoked);
        KdcVerdict::new(REALM).as_notice(AsNotice {
            client: format!("{a}@{REALM}"),
            requested: format!("{a}@{REALM}"),
            peer: Some(peer()),
            time: 1_700_000_000,
            code: err::CLIENT_REVOKED,
            reason: AsReason::HostRefused,
            mechanism: None,
        });
        assert_eq!(
            kdc_rows(&log),
            vec![peered(row(LogKind::Login, false, a, reasoned))],
            "the AS's refusal is its notice's one row, with the reason; 18 with no text"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_s4u2self_and_s4u2proxy_are_not_judged_by_login_hours() {
        let (a, unheld) = (REFUSED_USER, HERE_USER);
        let (_temp, _embedded, store) = realm(&[a, unheld]).await;
        let log = LogGuard::install_on_this_thread();
        let guard = real_hours();
        cached_values(&[a], &[], [DAYTIME, EVENING]);
        for user in [a, unheld] {
            let behind =
                asked_behind_a_service(&store, Some(user), &name(user), TgsKind::S4u2Proxy);
            let asked = [
                as_asks(&store, user, true),
                tgs_asks(&store, Some(user), user, TgsKind::S4u2Self),
                tgs_asks(&store, Some(user), user, TgsKind::S4u2Proxy),
                behind.map_err(|(code, _)| code),
            ];
            assert_eq!(
                (asked, kdc_rows(&log), guard.take_seen().len()),
                ([Ok(()); 4], vec![], 0),
                "{user}: outside the hours, or not in the cache, a service is answered"
            );
        }
        assert_eq!(
            (as_asks(&store, unheld, false), guard.take_seen().len()),
            (Err(err::CLIENT_REVOKED), 0),
            "the user the cache lacks, at the AS: not loaded yet"
        );
    }

    fn proofs(same_address: bool) -> ProofSettings {
        ProofSettings::new(600, same_address, 3600)
    }

    /// A server whose verdict asks proofs, on its own cache and lockout.
    struct Proving {
        handler: SqlBackendHandler,
        cache: &'static PolicyCache,
        counter: &'static Lockout,
        verdict: Arc<KdcVerdict>,
        factor: Arc<SecondFactor>,
        pool: DatabaseConnection,
    }

    async fn proving(
        store: &SharedDump,
        users: &[&str],
        ou: &str,
        server: Option<MfaPolicy>,
        same_address: bool,
    ) -> Proving {
        let cache: &'static PolicyCache = Box::leak(Box::new(PolicyCache::new()));
        let counter: &'static Lockout = Box::leak(Box::default());
        let pool = memory_pool().await;
        let handler = SqlBackendHandler::new(generate_random_private_key(), pool.clone())
            .with_lockout(counter)
            .with_policy_cache(cache)
            .with_mfa_setting(server)
            .with_proofs(Some(proofs(same_address)));
        for user in users {
            directory_user(&handler, user, ou).await;
        }
        fill_policy_cache(&handler, cache).await.unwrap();
        let verdict = Arc::new(KdcVerdict::on(REALM, cache, counter));
        let factor = Arc::new(SecondFactor::new(REALM, cache));
        crate::boot::install_judges(&mut store.write().unwrap(), verdict.clone(), factor.clone());
        Proving {
            handler,
            cache,
            counter,
            verdict,
            factor,
            pool,
        }
    }

    impl Proving {
        async fn enrol(&self, user: &str) {
            let sql = format!("UPDATE users SET mfa_type = 'totp' WHERE user_id = '{user}'");
            let enrolled = Statement::from_string(DbBackend::Sqlite, sql);
            self.pool.execute(enrolled).await.unwrap();
            fill_policy_cache(&self.handler, self.cache).await.unwrap();
        }

        /// A directory door's proof, made from `from`.
        async fn prove(&self, user: &str, at: i64, from: &str) -> bool {
            let user = UserId::new(user);
            let meta = RequestMeta::http(from.parse().ok(), None);
            with_request(meta, self.handler.note_proof(&user, at)).await
        }

        /// Three wrong passwords in a row lock the OU's users, and the KDC counts.
        async fn locking(&self, ou: &str) {
            let items = [
                ("lockout-threshold", "3"),
                ("lockout-duration-seconds", "0"),
            ];
            let request = CreatePolicyRequest {
                name: format!("lock {ou}"),
                description: String::new(),
                items: items.map(|(k, v)| (k.to_owned(), v.to_owned())).into(),
            };
            let id = self.handler.create_policy(request).await.unwrap();
            self.handler.set_ou_policy(ou, id).await.unwrap();
            let store = Arc::new(self.handler.clone());
            self.counter
                .serve_kdc(store, tokio::runtime::Handle::current());
        }
    }

    fn reply(store: &SharedDump, request: &[u8]) -> Vec<u8> {
        let guard = store.read().unwrap();
        krb5_kdc::handle_request(&*guard, request).unwrap()
    }

    type Said = (i32, Option<String>);

    fn said(e: &KrbError) -> Said {
        let text = e.e_text.as_ref();
        let text = text.map(|t| String::from_utf8_lossy(t.as_bytes()).into_owned());
        (e.error_code, text)
    }

    /// The KRB-ERROR's code and text, and those of the error FAST carries inside it.
    fn fast_said(reply: &[u8], armor: &ProtocolKey) -> [Said; 2] {
        let outer = decode::<KrbError>(reply).unwrap();
        let carried = outer.e_data.as_ref().unwrap();
        let padata: MethodData = decode(carried.as_ref()).unwrap();
        let fast = unwrap_fast_rep(armor, &Some(padata)).unwrap();
        let inner = fast.padata.iter().find(|p| p.padata_type == pa::FX_ERROR);
        let inner = decode::<KrbError>(inner.unwrap().padata_value.as_ref()).unwrap();
        [said(&outer), said(&inner)]
    }

    fn fast_kinit(store: &SharedDump, svc: &Service, user: &str) -> [Said; 2] {
        let sub = ProtocolKey::from_bytes(EncryptionType::Aes256CtsHmacSha196, &[0x47; 32]);
        let sub = sub.unwrap();
        let (ticket, session) = (svc.tgt.rep.0.ticket.clone(), &svc.tgt.session_key);
        let realm = ascii(REALM);
        let armor = build_fast_armor(ticket, session, &realm, &svc.name, Some(&sub)).unwrap();
        let akey = armor_key(session, Some(&sub)).unwrap();
        let mut request = krb5_protocol::as_req(name(user), REALM, nonce(), None).unwrap();
        let inner = vec![krb5_protocol::pa_enc_timestamp(&user_key(user, PASSWORD)).unwrap()];
        attach_fast(&mut request, &armor, &akey, inner).unwrap();
        fast_said(&reply(store, &encode(&request).unwrap()), &akey)
    }

    /// A service ticket asked inside FAST, armored by the TGT's own session and a subkey.
    fn fast_service_ticket(
        store: &SharedDump,
        tgt: &IssuedAs,
        user: &str,
        svc: &Service,
    ) -> [Said; 2] {
        let sub = ProtocolKey::from_bytes(EncryptionType::Aes256CtsHmacSha196, &[0x51; 32]);
        let sub = sub.unwrap();
        let cname = name(user);
        let params = TgsReqParams {
            ticket: tgt.rep.0.ticket.clone(),
            session: &tgt.session_key,
            crealm: REALM,
            cname: &cname,
            sname: svc.name.clone(),
            realm: REALM,
            nonce: nonce(),
            kdc_options: KdcOptions::forwardable(),
            additional_tickets: None,
            extra_padata: Vec::new(),
            etypes: vec![EncryptionType::Aes256CtsHmacSha196.to_iana()],
            addresses: None,
            from: None,
            enc_authorization_data: None,
            till: None,
            subkey: Some(&sub),
            time_offset: 0,
        };
        let mut request = tgs_req_ex(params).unwrap();
        let akey = armor_key(&tgt.session_key, Some(&sub)).unwrap();
        let ap = request.0.padata.as_ref().unwrap()[0]
            .padata_value
            .as_ref()
            .to_vec();
        let options = krb5_types::fast::fast_options_none();
        let body = &request.0.req_body;
        let fast = fx_fast_padata_over(None, &akey, &ap, body, Vec::new(), &options).unwrap();
        request.0.padata.get_or_insert_with(Vec::new).push(fast);
        fast_said(&reply(store, &encode(&request).unwrap()), &akey)
    }

    #[test]
    fn test_the_refusal_is_one_code_and_one_ascii_text() {
        let refusal = proof_refusal();
        let text = "second factor needed: sign in to the directory with your code (enrol there \
                    first if you have none), then run kinit again";
        assert_eq!(
            (refusal.code, PROOF_CODE, refusal.e_text.as_deref()),
            (12, err::POLICY, Some(text))
        );
        assert!(
            text.is_ascii(),
            "a text that is not ASCII is dropped on the wire"
        );
        assert_eq!(
            proof_detail(Door::KerberosAs),
            "policy: enable-mfa (no fresh proof)"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_under_the_default_checks_always_asks_a_fresh_proof_at_as_and_tgs_not_at_s4u() {
        let (bare, enrolled) = (REFUSED_USER, ALLOWED_USER);
        let (temp, _embedded, store) = realm(&[bare, enrolled]).await;
        let svc = service(&temp, &store);
        let at = proving(&store, &[bare, enrolled], "people\\labs", None, false).await;
        at.enrol(enrolled).await;
        strict_labs(&at.handler).await;
        let registered: Vec<_> = item_checks().iter().map(|check| check.key()).collect();
        let ordered = [
            THRESHOLD,
            "inactivity-days",
            "allowed-networks",
            ENABLE_MFA,
            "login-hours",
        ];
        assert_eq!(registered, ordered, "the default checks");
        let log = LogGuard::install_on_this_thread();
        let refused = (PROOF_CODE, Some(PROOF_TEXT.to_owned()));
        let impersonated = |user: &str| -> Outcome {
            let user = format!("{user}@{REALM}");
            Ok([user.clone(), user, format!("{SERVICE}@{REALM}")])
        };
        for user in [bare, enrolled] {
            let asked = (
                kinit(&store, user, Some(PASSWORD)),
                s4u2self(&store, &svc, user, false),
            );
            let label = format!("{user}: always, no proof yet");
            assert_eq!(asked, (refused.clone(), impersonated(user)), "{label}");
        }
        let no_proof = |user| row(LogKind::Login, false, user, &proof_detail(Door::KerberosAs));
        assert_eq!(
            kdc_rows(&log),
            vec![no_proof(bare), no_proof(enrolled)],
            "one row for each refusal, none for S4U2Self"
        );
        at.enrol(bare).await;
        let mut tickets = Vec::new();
        for user in [bare, enrolled] {
            assert!(
                at.prove(user, Utc::now().timestamp(), "").await,
                "{user}: stored"
            );
            let tgt = issue_tgt(&store, user);
            let served = service_ticket(&store, &tgt, user, &svc).is_ok();
            tickets.push((kinit(&store, user, Some(PASSWORD)).0, served));
        }
        assert_eq!(
            tickets,
            vec![(0, true), (0, true)],
            "with a fresh proof, enrolled now or before: a ticket, and service tickets on it"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_on_the_wire_12_and_the_text_plain_and_inside_fast_at_as_and_tgs_count_nothing() {
        use lldap_domain_handlers::lockout::LockStore;
        let user = "e2kwire";
        let (temp, _embedded, store) = realm(&[user]).await;
        let svc = service(&temp, &store);
        let at = proving(
            &store,
            &[user],
            "e2kwireou",
            Some(MfaPolicy::Enrolled),
            false,
        )
        .await;
        at.locking("e2kwireou").await;
        let tgt = issue_tgt(&store, user);
        at.enrol(user).await;
        let log = LogGuard::install_on_this_thread();
        let ours: Said = (PROOF_CODE, Some(PROOF_TEXT.to_owned()));
        let refused = kinit(&store, user, Some(PASSWORD));
        let served = service_ticket(&store, &tgt, user, &svc);
        let plain = [refused, served.map(drop).unwrap_err()];
        let fast = [
            fast_kinit(&store, &svc, user),
            fast_service_ticket(&store, &tgt, user, &svc),
        ];
        let stored = at.handler.read_lock(&UserId::new(user)).await.unwrap();
        let viewed = at
            .counter
            .row(&UserId::new(user))
            .map(|lock| lock.fail_count);
        let both = [ours.clone(), ours.clone()];
        assert_eq!(
            (
                plain,
                fast,
                stored.map(|lock| lock.fail_count),
                viewed.unwrap_or(0)
            ),
            (both.clone(), [both.clone(), both], None, 0),
            "a kinit without a proof, and a ticket from before the enrolment: 12 and the text, \
             plain and inside FAST, and nothing counted, in the table or in memory"
        );
        let as_row = row(LogKind::Login, false, user, &proof_detail(Door::KerberosAs));
        let tgs_row = row(
            LogKind::AccessDenied,
            false,
            user,
            &proof_detail(Door::KerberosTgs),
        );
        assert_eq!(
            kdc_rows(&log),
            vec![as_row.clone(), tgs_row.clone(), as_row, tgs_row],
            "one row for each refusal"
        );
    }

    fn tgs_judged(
        at: &Proving,
        store: &SharedDump,
        user: &str,
        header: &PrincipalName,
        kind: TgsKind,
    ) -> Result<(), i32> {
        let guard = store.read().unwrap();
        let client = TgsClient::Found(guard.get_name(&name(user)).unwrap());
        let krbtgt = PrincipalName::new(PrincipalName::NT_SRV_INST, ["krbtgt", REALM]);
        let server = guard.fetch_name(&krbtgt).unwrap().unwrap();
        let mut ticket = ticket(REALM, user);
        ticket.cname = header.clone();
        let request = tgs_body(&ticket);
        let (subject, peer) = (name(user), peer());
        let q = TgsQuestion {
            client,
            subject: &subject,
            server: &server,
            ticket: &ticket,
            request: &request,
            peer: Some(&peer),
            now: 1_700_000_000,
            kind,
        };
        at.verdict.check_tgs(&q).map_err(|r| r.code)?;
        factor_asks(at, &*guard, &ticket)
    }

    fn factor_asks(
        at: &Proving,
        store: &dyn PrincipalRead,
        ticket: &EncTicketPart,
    ) -> Result<(), i32> {
        let krbtgt = PrincipalName::new(PrincipalName::NT_SRV_INST, ["krbtgt", REALM]);
        let server = store.fetch_name(&krbtgt).unwrap().unwrap();
        let (request, peer) = (tgs_body(ticket), peer());
        let mut status = None;
        let factor = &at.factor;
        let asked = factor.check_tgs_from(
            &request,
            store,
            &server,
            ticket,
            &[],
            Some(&peer),
            &mut status,
        );
        asked.map(drop).map_err(|e| match e {
            krb5_kdc::Error::Protocol { code, text, .. }
                if status.is_none() && text.as_deref() == Some(PROOF_TEXT) =>
            {
                code
            }
            e => panic!("unexpected {e:?}, status {status:?}"),
        })
    }

    #[tokio::test]
    #[serial]
    async fn test_at_tgs_a_users_own_ticket_is_judged_by_its_authtime_whatever_the_kind() {
        let user = "e2kkinds";
        let (_temp, _embedded, store) = realm(&[user]).await;
        let at = proving(&store, &[user], "people", Some(MfaPolicy::Always), false).await;
        let kinds = [
            TgsKind::Normal,
            TgsKind::Renew,
            TgsKind::Validate,
            TgsKind::U2u,
            TgsKind::S4u2Self,
            TgsKind::S4u2Proxy,
        ];
        let service = PrincipalName::new(PrincipalName::NT_SRV_HST, SERVICE.split('/'));
        let asked =
            |header: &PrincipalName| kinds.map(|kind| tgs_judged(&at, &store, user, header, kind));
        let items = kinds.map(|kind| tgs_asks_of(&at.verdict, &store, Some(user), user, kind));
        let before = [asked(&name(user)), asked(&service)];
        at.prove(user, 1_700_000_000 - 30, "").await;
        let refused = Err(PROOF_CODE);
        assert_eq!(
            (items, before, [asked(&name(user)), asked(&service)]),
            ([Ok(()); 6], [[refused; 6], [Ok(()); 6]], [[Ok(()); 6]; 2]),
            "the directory's verdict judges the items only. A renewal, a validation, a service \
             ticket and U2U ask the ticket's authentication time inside a window, long passed \
             now; so does an S4U request made with the user's own ticket, which 0.8.1 skipped: \
             the policy hook is not told the request's kind. A service's ticket is not judged"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_the_second_factor_judges_only_a_principal_the_directory_owns() {
        let (owned, foreign, unsynced) = ("e2kowned", "e2kforeign", "e2kunsynced");
        let (temp, _embedded, store) = realm(&[owned]).await;
        let foreign_name = name(foreign);
        store
            .write()
            .unwrap()
            .change_committing(committing(&*temp.own()), |s| {
                s.insert_new_randkey(&foreign_name, REALM, &[], "test")
            })
            .unwrap()
            .unwrap();
        let users = [owned, foreign, unsynced];
        let at = proving(&store, &users, "people", Some(MfaPolicy::Always), false).await;
        let log = LogGuard::install_on_this_thread();
        let asked = users.map(|user| {
            let guard = store.read().unwrap();
            factor_asks(&at, &*guard, &ticket(REALM, user))
        });
        let detail = proof_detail(Door::KerberosTgs);
        let denied = peered(row(LogKind::AccessDenied, false, owned, &detail));
        assert_eq!(
            (asked, kdc_rows(&log)),
            ([Err(PROOF_CODE), Ok(()), Ok(())], vec![denied]),
            "each owes a proof; only the principal the directory owns is refused, with one row. \
             One of the same name it does not own, or none, is left to the live-client check"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_an_ou_change_after_issue_reaches_the_ticket_and_an_ended_window_opens_nothing() {
        let user = "e2kafter";
        let (_temp, _embedded, store) = realm(&[user]).await;
        let at = proving(&store, &[user], "e2kafterou", None, false).await;
        let item = |value: &str| [(ENABLE_MFA.to_owned(), value.to_owned())].into();
        let request = CreatePolicyRequest {
            name: "e2k after".to_owned(),
            description: String::new(),
            items: item("off"),
        };
        let id = at.handler.create_policy(request).await.unwrap();
        at.handler.set_ou_policy("e2kafterou", id).await.unwrap();
        at.enrol(user).await;
        let asked = || {
            let renewal = tgs_judged(&at, &store, user, &name(user), TgsKind::Renew);
            (as_asks_of(&at.verdict, &store, user, false), renewal)
        };
        let before = asked();
        let change = UpdatePolicyRequest {
            id,
            name: None,
            description: None,
            items: Some(item("always")),
        };
        at.handler.update_policy(change).await.unwrap();
        let changed = asked();
        assert!(at.prove(user, 1_700_000_000 - 700, "").await);
        let held = at.cache.get().windows_of(&UserId::new(user)).len();
        let refused = Err(PROOF_CODE);
        assert_eq!(
            (before, changed, held, asked()),
            ((Ok(()), Ok(())), (refused, refused), 1, (refused, refused)),
            "the OU at off: no proof asked. Its value changed to always after the ticket was \
             issued: kinit and the ticket's renewal are refused. A window that ended 100 s ago, \
             held in memory, covers neither the kinit nor the ticket"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_with_the_address_tie_only_a_proof_from_the_kinits_address_opens_it() {
        let (here, there) = ("e2khere", "e2kthere");
        let (_temp, _embedded, store) = realm(&[here, there]).await;
        let at = proving(
            &store,
            &[here, there],
            "people",
            Some(MfaPolicy::Always),
            true,
        )
        .await;
        let stored = [
            at.prove(here, 1_700_000_000, PEER).await,
            at.prove(there, 1_700_000_000, "198.51.100.9").await,
        ];
        let asked = [here, there].map(|user| as_asks_of(&at.verdict, &store, user, false));
        assert_eq!(
            (stored, asked),
            ([true, true], [Ok(()), Err(PROOF_CODE)]),
            "the kinit comes from {PEER}: only the proof made from there opens it"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_a_locked_user_who_also_needs_a_proof_is_refused_as_locked() {
        let user = "e2klocked";
        let (_temp, _embedded, store) = realm(&[user]).await;
        let at = proving(
            &store,
            &[user],
            "e2klockou",
            Some(MfaPolicy::Enrolled),
            false,
        )
        .await;
        at.locking("e2klockou").await;
        for _ in 0..3 {
            let _ = kinit(&store, user, Some("Wrong-Pass-1"));
        }
        at.enrol(user).await;
        let renewal = tgs_asks_of(&at.verdict, &store, Some(user), user, TgsKind::Renew);
        assert_eq!(
            (kinit(&store, user, Some(PASSWORD)).0, renewal),
            (err::CLIENT_REVOKED, Err(err::CLIENT_REVOKED)),
            "the lockout is judged first: 18, not 12"
        );
    }

    #[tokio::test]
    #[serial]
    #[cfg_attr(feature = "test-admission", ignore = "a row of the default build")]
    async fn test_the_default_build_installs_the_verdict() {
        let temp = TempRealm::new();
        let (embedded, store) = temp.embedded();
        let user = UserId::new(REFUSED_USER);
        synced(&embedded, &user, PASSWORD).await.unwrap();
        crate::boot::install_plugins(&mut store.write().unwrap());
        let log = LogGuard::install_on_this_thread();
        let _guard = deciding();
        cached(&[REFUSED_USER], &[]);
        let refused = row(LogKind::Login, false, REFUSED_USER, "policy: login-hours");
        assert_eq!(
            (kinit(&store, REFUSED_USER, None), kdc_rows(&log)),
            ((err::CLIENT_REVOKED, None), vec![refused])
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_a_user_written_here_is_found_at_once_and_another_writers_after_a_poke() {
        let (here, elsewhere) = (HERE_USER, ELSEWHERE_USER);
        let (_temp, _embedded, store) = realm(&[ALLOWED_USER, here, elsewhere]).await;
        let pool = memory_pool().await;
        let handler = SqlBackendHandler::new(generate_random_private_key(), pool.clone());
        let its_own: &'static PolicyCache = Box::leak(Box::new(PolicyCache::new()));
        let other = SqlBackendHandler::new(generate_random_private_key(), pool);
        let other = other.with_policy_cache(its_own);
        directory_user(&handler, ALLOWED_USER, "people").await;
        let _guard = strict();
        let filler = start_policy_cache(&handler)
            .await
            .expect("a check is registered");
        let code = |user| kinit(&store, user, Some(PASSWORD)).0;
        assert_eq!(code(ALLOWED_USER), 0, "filled at start");
        filler.abort();
        let _ = filler.await;
        directory_user(&handler, here, "people").await;
        assert_eq!(
            code(here),
            0,
            "a user created on this server is found at once"
        );
        let filler = start_policy_filler(handler.clone(), policy_cache());
        directory_user(&other, elsewhere, "people").await;
        assert_eq!(code(elsewhere), err::CLIENT_REVOKED, "a miss refuses");
        let deadline = Instant::now() + Duration::from_secs(1);
        while code(elsewhere) != 0 {
            assert!(
                Instant::now() < deadline,
                "the poked fill took more than a second"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        filler.abort();
    }

    #[tokio::test]
    #[serial]
    #[cfg_attr(feature = "test-admission", ignore = "a row of the default build")]
    async fn test_a_request_sent_before_serve_is_answered_after_it_from_the_filled_cache() {
        let temp = TempRealm::new();
        let (embedded, _store) = temp.embedded();
        for user in [REFUSED_USER, ALLOWED_USER] {
            synced(&embedded, &UserId::new(user), PASSWORD)
                .await
                .unwrap();
            temp.host.set_sync(user, true);
        }
        temp.host.set_directory(Some(&[]));
        drop(embedded);
        let handler = SqlBackendHandler::new(generate_random_private_key(), memory_pool().await);
        directory_user(&handler, REFUSED_USER, "people\\labs").await;
        directory_user(&handler, ALLOWED_USER, "people").await;
        strict_labs(&handler).await;
        let _guard = strict();
        let filler = start_policy_cache(&handler)
            .await
            .expect("a check is registered");
        let (_engine, opened) = EmbeddedKerberos::open_on(&temp.settings, temp.own()).unwrap();
        let asked = [ALLOWED_USER, REFUSED_USER].map(|user| ask(opened.kdc_udp(), user, PASSWORD));
        tokio::time::sleep(Duration::from_millis(200)).await;
        let unanswered = asked.iter().all(|asked| !asked.is_finished());
        let served = Instant::now();
        let threads = opened.serve().unwrap();
        let answers = asked.map(|asked| asked.join().unwrap());
        threads.stop();
        filler.abort();
        assert_eq!(
            (unanswered, answers.map(|(at, code)| (at > served, code))),
            (true, [(true, 0), (true, err::CLIENT_REVOKED)]),
            "sent before serve, answered after it: the allowed user gets a ticket, not a miss"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[serial]
    async fn test_kinit_counts_in_the_one_table_and_s4u2self_is_refused_but_never_counts() {
        use lldap_domain_handlers::handler::LockoutBackendHandler;
        use lldap_domain_handlers::lockout::LockStore;
        let b = "e1kinit";
        let (temp, _embedded, store) = realm(&[b]).await;
        let svc = service(&temp, &store);
        let cache: &'static PolicyCache = Box::leak(Box::new(PolicyCache::new()));
        let counter: &'static Lockout = Box::leak(Box::default());
        let handler = SqlBackendHandler::new(generate_random_private_key(), memory_pool().await)
            .with_policy_cache(cache)
            .with_lockout(counter);
        directory_user(&handler, b, "e1kdcou").await;
        let request = CreatePolicyRequest {
            name: "e1 kdc".to_owned(),
            description: String::new(),
            items: [
                ("lockout-threshold".to_owned(), "3".to_owned()),
                ("lockout-duration-seconds".to_owned(), "0".to_owned()),
            ]
            .into(),
        };
        let id = handler.create_policy(request).await.unwrap();
        handler.set_ou_policy("e1kdcou", id).await.unwrap();
        fill_policy_cache(&handler, cache).await.unwrap();
        let user = UserId::new(b);
        let verdict = Arc::new(KdcVerdict::on(REALM, cache, counter));
        store
            .write()
            .unwrap()
            .policy
            .plugins
            .set_host_admission(verdict.clone());
        let tgt = issue_tgt(&store, b);
        counter.serve_kdc(Arc::new(handler.clone()), tokio::runtime::Handle::current());
        let log = LogGuard::install_on_this_thread();
        let stored = async || {
            handler
                .read_lock(&user)
                .await
                .unwrap()
                .map(|r| r.fail_count)
        };
        let failed = row(
            LogKind::Login,
            false,
            b,
            "pre-authentication failed (encrypted timestamp)",
        );
        let issued = row(
            LogKind::Login,
            true,
            b,
            "ticket issued (encrypted timestamp)",
        );
        let locked = row(LogKind::Login, false, b, "locked out");
        let lock = row(LogKind::AccountLock, true, b, "locked: kerberos");
        for (n, rows) in [
            (1, vec![failed.clone()]),
            (2, vec![failed.clone()]),
            (3, vec![failed.clone(), lock]),
        ] {
            let got = kinit(&store, b, Some("Wrong-Pass-1")).0;
            let state = (got, stored().await, kdc_rows(&log));
            assert_eq!(state, (err::PREAUTH_FAILED, Some(n), rows), "wrong {n}");
        }
        let got = kinit(&store, b, Some(PASSWORD));
        let state = (got, stored().await, kdc_rows(&log));
        assert_eq!(
            state,
            ((err::CLIENT_REVOKED, None), Some(3), vec![locked.clone()]),
            "the right password while locked: 18 before pre-authentication, not counted"
        );
        let got = kinit(&store, b, Some("Wrong-Pass-2"));
        let state = (got, stored().await, kdc_rows(&log));
        assert_eq!(
            state,
            ((err::CLIENT_REVOKED, None), Some(3), vec![locked]),
            "a wrong password while locked: the same 18, not counted"
        );
        let service = service_ticket(&store, &tgt, b, &svc);
        let renewal = tgs_asks_of(&verdict, &store, Some(b), b, TgsKind::Renew);
        let denied = row(LogKind::AccessDenied, false, b, "locked out");
        assert_eq!(
            (
                service.map(drop).map_err(|(code, _)| code),
                renewal,
                stored().await,
                kdc_rows(&log)
            ),
            (
                Err(err::CLIENT_REVOKED),
                Err(err::CLIENT_REVOKED),
                Some(3),
                vec![denied.clone(), peered(denied)]
            ),
            "on a ticket issued before the lock, a service ticket and a renewal are refused, \
             never counted"
        );
        let by = format!("locked out (S4U2Self by {SERVICE}@{REALM})");
        for x509 in [false, true] {
            let got = s4u2self(&store, &svc, b, x509);
            let state = (got, stored().await, kdc_rows(&log));
            let denied = vec![row(LogKind::AccessDenied, false, b, &by)];
            assert_eq!(
                state,
                (Err((err::CLIENT_REVOKED, None)), Some(3), denied),
                "S4U2Self, PA-S4U-X509-USER {x509}: refused, never counted"
            );
        }
        handler.unlock_user(&user).await.unwrap();
        let got = kinit(&store, b, Some(PASSWORD)).0;
        assert_eq!(
            (got, stored().await, kdc_rows(&log)),
            (0, Some(0), vec![issued.clone()]),
            "unlocked: a ticket, and a count of 0 writes nothing"
        );
        let user_at = format!("{b}@{REALM}");
        let ticket = Ok([user_at.clone(), user_at, format!("{SERVICE}@{REALM}")]);
        assert_eq!(
            s4u2self(&store, &svc, b, false),
            ticket,
            "S4U2Self after the unlock"
        );
        assert_eq!(
            kinit(&store, b, Some("Wrong-Pass-1")).0,
            err::PREAUTH_FAILED
        );
        assert_eq!(
            stored().await,
            Some(1),
            "the count restarts after the unlock"
        );
        assert_eq!(kinit(&store, b, Some(PASSWORD)).0, 0);
        assert_eq!(stored().await, Some(0), "a ticket clears a count");
        assert_eq!(
            kdc_rows(&log),
            vec![failed, issued],
            "one row per sign-in, no S4U2Self row once allowed"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[serial]
    async fn test_a_kinit_after_an_unlock_by_another_process_is_answered_at_the_second_try() {
        let b = "e1tool";
        let (_temp, _embedded, store) = realm(&[b]).await;
        let cache: &'static PolicyCache = Box::leak(Box::new(PolicyCache::new()));
        let counter: &'static Lockout = Box::leak(Box::default());
        let handler = SqlBackendHandler::new(generate_random_private_key(), memory_pool().await)
            .with_policy_cache(cache)
            .with_lockout(counter);
        directory_user(&handler, b, "e1toolou").await;
        let request = CreatePolicyRequest {
            name: "e1 tool".to_owned(),
            description: String::new(),
            items: [
                ("lockout-threshold".to_owned(), "3".to_owned()),
                ("lockout-duration-seconds".to_owned(), "0".to_owned()),
            ]
            .into(),
        };
        let id = handler.create_policy(request).await.unwrap();
        handler.set_ou_policy("e1toolou", id).await.unwrap();
        let verdict = Arc::new(KdcVerdict::on(REALM, cache, counter));
        store
            .write()
            .unwrap()
            .policy
            .plugins
            .set_host_admission(verdict);
        counter.serve_kdc(Arc::new(handler.clone()), tokio::runtime::Handle::current());
        for _ in 0..3 {
            assert_eq!(
                kinit(&store, b, Some("Wrong-Pass-1")).0,
                err::PREAUTH_FAILED
            );
        }
        let user = UserId::new(b);
        let row = lldap_domain_handlers::logging::event(
            LogKind::AccountUnlock,
            Some(b),
            true,
            Some(lldap_domain_handlers::lockout::UNLOCKED_BY_TOOL),
        );
        let at = lock_clock();
        lldap_sql_backend_handler::unlock_login_on(handler.pool(), &user, at, row)
            .await
            .unwrap();
        let started = Instant::now();
        let mut tries = vec![kinit(&store, b, Some(PASSWORD)).0];
        while tries.last() != Some(&0) && started.elapsed() < Duration::from_secs(2) {
            tokio::time::sleep(Duration::from_millis(100)).await;
            tries.push(kinit(&store, b, Some(PASSWORD)).0);
        }
        assert_eq!(
            (tries.first(), tries.last()),
            (Some(&err::CLIENT_REVOKED), Some(&0)),
            "the first try is judged from memory and asks for a read; a later one within two \
             seconds sees the unlock: {tries:?}"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[serial]
    async fn test_a_slow_database_never_holds_the_kdcs_answer_past_the_bound() {
        use lldap_domain_handlers::lockout::LockStore;
        let b = "e1slow";
        let (_temp, _embedded, store) = realm(&[b]).await;
        let cache: &'static PolicyCache = Box::leak(Box::new(PolicyCache::new()));
        let counter: &'static Lockout = Box::leak(Box::default());
        let pool = memory_pool().await;
        let handler = SqlBackendHandler::new(generate_random_private_key(), pool.clone())
            .with_policy_cache(cache)
            .with_lockout(counter);
        directory_user(&handler, b, "e1slowou").await;
        let request = CreatePolicyRequest {
            name: "e1 slow".to_owned(),
            description: String::new(),
            items: [("lockout-threshold".to_owned(), "3".to_owned())].into(),
        };
        let id = handler.create_policy(request).await.unwrap();
        handler.set_ou_policy("e1slowou", id).await.unwrap();
        let verdict = Arc::new(KdcVerdict::on(REALM, cache, counter));
        store
            .write()
            .unwrap()
            .policy
            .plugins
            .set_host_admission(verdict);
        counter.serve_kdc(Arc::new(handler.clone()), tokio::runtime::Handle::current());
        let held = pool.begin().await.unwrap();
        let released = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(2)).await;
            held.rollback().await.unwrap();
        });
        let started = Instant::now();
        let got = kinit(&store, b, Some("Wrong-Pass-1")).0;
        let (took, still_held) = (started.elapsed(), !released.is_finished());
        assert_eq!(got, err::PREAUTH_FAILED);
        assert!(
            still_held && took < Duration::from_secs(1),
            "the KDC answered after {took:?}, the database still held: {still_held}"
        );
        released.await.unwrap();
        let user = UserId::new(b);
        assert_eq!(
            handler.read_lock(&user).await.unwrap(),
            None,
            "not landed yet"
        );
        assert_eq!(counter.drain(&handler).await, 1, "owed, not dropped");
        let landed = handler
            .read_lock(&user)
            .await
            .unwrap()
            .map(|r| r.fail_count);
        assert_eq!(landed, Some(1), "the count is right once the write lands");
    }

    #[tokio::test]
    #[serial]
    async fn test_the_verdict_answers_at_once_while_the_pools_only_connection_is_held() {
        let (_temp, _embedded, store) = realm(&[REFUSED_USER, ALLOWED_USER]).await;
        let pool = memory_pool().await;
        let handler = SqlBackendHandler::new(generate_random_private_key(), pool.clone());
        directory_user(&handler, REFUSED_USER, "people\\labs").await;
        directory_user(&handler, ALLOWED_USER, "people").await;
        strict_labs(&handler).await;
        let _guard = strict();
        fill_policy_cache(&handler, policy_cache()).await.unwrap();
        let held = pool.begin().await.unwrap();
        let started = Instant::now();
        let answers = (
            kinit(&store, ALLOWED_USER, Some(PASSWORD)).0,
            kinit(&store, REFUSED_USER, Some(PASSWORD)).0,
            tgs_asks(&store, Some(REFUSED_USER), REFUSED_USER, TgsKind::Renew),
        );
        let took = started.elapsed();
        held.rollback().await.unwrap();
        assert_eq!(answers, (0, err::CLIENT_REVOKED, Err(err::CLIENT_REVOKED)));
        assert!(took < Duration::from_secs(1), "{took:?}");
    }

    fn idle_facts(name: &str, created: Timestamp) -> UserFacts {
        UserFacts {
            uuid: lldap_domain::types::Uuid::from_name_and_date(name, &to_naive(created)),
            enrolled: false,
            exempt: false,
            code_at_kinit: false,
            created,
            recorded: Some(Recorded::default()),
        }
    }

    #[tokio::test]
    #[serial]
    async fn test_inactivity_refuses_at_as_tgs_and_s4u_with_18_and_no_text() {
        let (idle, fresh) = ("e6idle", "e6fresh");
        let (temp, _embedded, store) = realm(&[idle, fresh]).await;
        let svc = service(&temp, &store);
        let _guard = EnforcementGuard::default_checks();
        let cache: &'static PolicyCache = Box::leak(Box::new(PolicyCache::new()));
        let counter: &'static Lockout = Box::leak(Box::default());
        let long_ago = Timestamp::from_second(1_600_000_000).unwrap();
        let thirty = EffectiveItem {
            key: INACTIVITY_DAYS.to_owned(),
            scope: PolicyScope::User,
            value: "30".to_owned(),
            enforced: true,
            source: None,
        };
        let (idle_id, fresh_id) = (UserId::new(idle), UserId::new(fresh));
        cache.replace(Entries {
            ous_of_users: HashMap::from([
                (idle_id.clone(), "e6ou".to_owned()),
                (fresh_id.clone(), "e6ou".to_owned()),
            ]),
            items_of_ous: HashMap::from([("e6ou".to_owned(), vec![thirty].into())]),
            facts: HashMap::from([
                (idle_id, idle_facts(idle, long_ago)),
                (fresh_id, idle_facts(fresh, Timestamp::now())),
            ]),
            windows: HashMap::new(),
            built_at: Timestamp::now(),
        });
        let flags = ItemFlags {
            inactivity: true,
            ..ItemFlags::default()
        };
        cache.set_item_flags(flags);
        cache.set_recording(Recording::Since(long_ago));
        let verdict = Arc::new(KdcVerdict::on(REALM, cache, counter));
        store
            .write()
            .unwrap()
            .policy
            .plugins
            .set_host_admission(verdict.clone());
        let log = LogGuard::install_on_this_thread();
        let asked = |user, kind| tgs_asks_of(&verdict, &store, Some(user), user, kind);
        let answers = (
            kinit(&store, idle, Some(PASSWORD)),
            kinit(&store, fresh, Some(PASSWORD)),
            asked(idle, TgsKind::Renew),
            asked(idle, TgsKind::Normal),
            asked(fresh, TgsKind::Renew),
        );
        let inactive = "policy: inactivity-days (inactive)";
        assert_eq!(
            (answers, kdc_rows(&log)),
            (
                (
                    (err::CLIENT_REVOKED, None),
                    (0, None),
                    Err(err::CLIENT_REVOKED),
                    Err(err::CLIENT_REVOKED),
                    Ok(())
                ),
                vec![
                    row(LogKind::Login, false, idle, inactive),
                    row(
                        LogKind::Login,
                        true,
                        fresh,
                        "ticket issued (encrypted timestamp)"
                    ),
                    peered(row(LogKind::AccessDenied, false, idle, inactive)),
                    peered(row(LogKind::AccessDenied, false, idle, inactive)),
                ]
            ),
            "AS and TGS: code 18 with no text; the reason in the row only"
        );
        let asked_for = [TgsKind::S4u2Self, TgsKind::S4u2Proxy].map(|kind| asked(idle, kind));
        let asked_rows = kdc_rows(&log);
        let impersonated = s4u2self(&store, &svc, idle, false).map(drop);
        let by = |request: &str, asker: &str| format!("{inactive} ({request} by {asker}@{REALM})");
        let at_tgs = |request: &str| {
            let detail = by(request, idle);
            peered(row(LogKind::AccessDenied, false, idle, &detail))
        };
        let by_service = by("S4U2Self", SERVICE);
        assert_eq!(
            (asked_for, asked_rows, impersonated, kdc_rows(&log)),
            (
                [Err(err::CLIENT_REVOKED); 2],
                vec![at_tgs("S4U2Self"), at_tgs("S4U2Proxy")],
                Err((err::CLIENT_REVOKED, None)),
                vec![row(LogKind::AccessDenied, false, idle, &by_service)]
            ),
            "a user refused everywhere is not impersonated: inactivity judges at S4U, and each \
             row names the request and who asked"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[serial]
    async fn test_judging_a_renewal_or_a_service_ticket_writes_no_activity() {
        let b = "e6kdcrenew";
        let (_temp, _embedded, store) = realm(&[b]).await;
        let guard = EnforcementGuard::default_checks();
        let cache: &'static PolicyCache = Box::leak(Box::new(PolicyCache::new()));
        let counter: &'static Lockout = Box::leak(Box::default());
        let pool = memory_pool().await;
        let handler = SqlBackendHandler::new(generate_random_private_key(), pool.clone())
            .with_policy_cache(cache)
            .with_lockout(counter);
        directory_user(&handler, b, "e6kdcrenewou").await;
        let request = CreatePolicyRequest {
            name: "e6 kdc renew".to_owned(),
            description: String::new(),
            items: [(INACTIVITY_DAYS.to_owned(), "30".to_owned())].into(),
        };
        let id = handler.create_policy(request).await.unwrap();
        handler.set_ou_policy("e6kdcrenewou", id).await.unwrap();
        let verdict = Arc::new(KdcVerdict::on(REALM, cache, counter));
        store
            .write()
            .unwrap()
            .policy
            .plugins
            .set_host_admission(verdict.clone());
        cache.serve_successes(Arc::new(handler.clone()), tokio::runtime::Handle::current());
        let user = UserId::new(b);
        let stored = async || {
            let rows = handler.read_activity(Some(&user)).await.unwrap();
            rows.first().and_then(|(_, row)| row.last_success)
        };
        let start = lock_clock();
        guard.pin_clock(start);
        let issued = kinit(&store, b, Some(PASSWORD)).0;
        let written = stored().await;
        guard.pin_clock(start + SignedDuration::from_secs(3_600));
        let asked = [TgsKind::Renew, TgsKind::Normal]
            .map(|kind| tgs_asks_of(&verdict, &store, Some(b), b, kind));
        cache.drain_successes(&handler).await;
        assert_eq!(
            (
                issued,
                written,
                asked,
                cache.owed_successes(),
                stored().await
            ),
            (0, Some(start), [Ok(()), Ok(())], 0, Some(start)),
            "judging a renewal or a service ticket writes no activity"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[serial]
    async fn test_an_issued_ticket_is_carried_as_a_success_and_owed_while_the_database_is_held() {
        let b = "e6kdc";
        let (_temp, _embedded, store) = realm(&[b]).await;
        let guard = EnforcementGuard::default_checks();
        let cache: &'static PolicyCache = Box::leak(Box::new(PolicyCache::new()));
        let counter: &'static Lockout = Box::leak(Box::default());
        let pool = memory_pool().await;
        let handler = SqlBackendHandler::new(generate_random_private_key(), pool.clone())
            .with_policy_cache(cache)
            .with_lockout(counter);
        directory_user(&handler, b, "e6kdcou").await;
        let request = CreatePolicyRequest {
            name: "e6 kdc".to_owned(),
            description: String::new(),
            items: [(INACTIVITY_DAYS.to_owned(), "30".to_owned())].into(),
        };
        let id = handler.create_policy(request).await.unwrap();
        handler.set_ou_policy("e6kdcou", id).await.unwrap();
        let verdict = Arc::new(KdcVerdict::on(REALM, cache, counter));
        store
            .write()
            .unwrap()
            .policy
            .plugins
            .set_host_admission(verdict);
        cache.serve_successes(Arc::new(handler.clone()), tokio::runtime::Handle::current());
        let user = UserId::new(b);
        let stored = async || {
            let rows = handler.read_activity(Some(&user)).await.unwrap();
            rows.first().and_then(|(_, row)| row.last_success)
        };
        let start = lock_clock();
        let later = start + SignedDuration::from_secs(3_600);
        guard.pin_clock(start);
        let first = kinit(&store, b, Some(PASSWORD)).0;
        let written = stored().await;
        let held = pool.begin().await.unwrap();
        guard.pin_clock(later);
        let second = kinit(&store, b, Some(PASSWORD)).0;
        tokio::time::sleep(Duration::from_millis(500)).await;
        let owed = cache.owed_successes();
        let facts = cache.get().facts_of(&user).and_then(|facts| facts.recorded);
        let in_memory = facts.and_then(|row| row.last_success);
        held.rollback().await.unwrap();
        let drained = (
            cache.drain_successes(&handler).await,
            cache.owed_successes(),
        );
        assert_eq!(
            (first, written, second, owed, in_memory),
            (0, Some(start), 0, 1, Some(later)),
            "an issued ticket is written off the KDC's thread; with the database held it is owed, \
             and this server's memory has it at once"
        );
        assert_eq!(
            (drained, stored().await),
            ((1, 0), Some(later)),
            "the owed success lands once the database answers"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_a_subject_whose_entry_could_not_be_read_is_refused_and_not_called_gone() {
        let (_temp, _embedded, store) = realm(&[ALLOWED_USER]).await;
        let log = LogGuard::install_on_this_thread();
        let _inert = EnforcementGuard::none();
        let user = ALLOWED_USER;
        let service = PrincipalName::new(PrincipalName::NT_SRV_HST, SERVICE.split('/'));
        let named = format!("{SERVICE}@{REALM}");
        let rows = [
            ("a renewal", name(user), TgsKind::Renew, user),
            ("a service ticket", name(user), TgsKind::Normal, user),
            ("an S4U2Proxy", name(user), TgsKind::S4u2Proxy, user),
            ("no directory user", service, TgsKind::U2u, named.as_str()),
        ];
        for (label, subject, kind, target) in rows {
            let guard = store.read().unwrap();
            let asked = asked_with(&guard, TgsClient::ReadFailed, &subject, kind);
            let row = peered(row(LogKind::AccessDenied, false, target, UNREAD));
            assert_eq!(
                (asked, kdc_rows(&log)),
                (Err((err::CLIENT_REVOKED, None)), vec![row]),
                "{label}"
            );
        }
    }
}
