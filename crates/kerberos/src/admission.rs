use crate::policy::NOT_FOUND;
use krb5_kdc::Principal;
use krb5_kdc::admission::{
    AsNotice, AsQuestion, AsReason, HostAdmission, KdcRefusal, Mechanism, TgsQuestion,
};
use krb5_types::{HostAddress, PrincipalName, err};
use lldap_domain::types::UserId;
use lldap_domain_handlers::enforcement::{
    Attempt, Door, PolicyCache, Refusal, admit_at_kdc_with, item_checks, policy_cache,
    record_kdc_row,
};
use lldap_domain_handlers::kerberos::user_id_for_principal_name;
use lldap_domain_handlers::lockout::{Lockout, THRESHOLD, lock_clock, lock_detail, lockout};
use lldap_domain_handlers::logging::LogKind;
use std::cell::RefCell;
use std::net::IpAddr;

const REFUSED: KdcRefusal = KdcRefusal {
    code: err::CLIENT_REVOKED,
    e_text: None,
};
const GONE: &str = "the principal is gone";

/// As the KDC answered a client whose entry is gone before the module was asked.
fn gone() -> KdcRefusal {
    KdcRefusal {
        code: err::CLIENT_REVOKED,
        e_text: Some(NOT_FOUND.to_owned()),
    }
}
const NOT_SAID: &str = "refused by the directory";

thread_local! {
    static AS_REFUSAL: RefCell<Option<(String, &'static str)>> = const { RefCell::new(None) };
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
            record_kdc_row(None, user.as_str(), kind, true, peer, &detail);
        }
        self.lockout.carry_from_kdc(user, step);
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

fn user_named(name: &PrincipalName, of: &str, realm: &str) -> Option<UserId> {
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

fn notice_detail(n: &AsNotice, item: Option<&'static str>) -> String {
    let outcome = match (n.reason, item) {
        (AsReason::HostRefused, Some(item)) => Refusal {
            item,
            door: Door::KerberosAs,
        }
        .detail(),
        (AsReason::HostRefused, None) => NOT_SAID.to_owned(),
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
        let checks = item_checks();
        if !checks.iter().any(|check| check.live(self.cache)) {
            return Ok(());
        }
        let Some(user) = user_of(q.client, &self.realm) else {
            return Ok(());
        };
        let door = if q.s4u2self {
            Door::KerberosS4u
        } else {
            Door::KerberosAs
        };
        let peer = q.peer.and_then(ip_of);
        let attempt = Attempt::at_kdc(&user, door, peer, q.now);
        let Err(refusal) = admit_at_kdc_with(self.cache, self.lockout, &attempt, &checks) else {
            return Ok(());
        };
        self.confirm_lock(&user, &refusal);
        if q.s4u2self {
            let by = q
                .request
                .sname
                .as_ref()
                .map_or_else(String::new, |service| {
                    format!(" by {}", service.unparse_with_realm_lossy(&self.realm))
                });
            let detail = format!("{} (S4U2Self{by})", refusal.detail());
            record_kdc_row(
                Some(&user),
                user.as_str(),
                door.log_kind(),
                false,
                peer,
                &detail,
            );
        } else {
            AS_REFUSAL.with(|held| *held.borrow_mut() = Some((q.client.id(), refusal.item)));
        }
        Err(REFUSED)
    }

    fn as_notice(&self, n: AsNotice) {
        let held = AS_REFUSAL.with(|held| held.borrow_mut().take());
        if matches!(
            n.code,
            err::PREAUTH_REQUIRED | err::MORE_PREAUTH_DATA_REQUIRED
        ) {
            return;
        }
        let item = held
            .filter(|(client, _)| *client == n.client)
            .map(|(_, item)| item);
        let user = user_of_id(&n.client, &self.realm);
        let target = user.as_ref().map_or(n.client.as_str(), UserId::as_str);
        let peer = n.peer.as_ref().and_then(ip_of);
        let issued = n.reason == AsReason::Issued;
        let detail = notice_detail(&n, item);
        record_kdc_row(user.as_ref(), target, LogKind::Login, issued, peer, &detail);
        if let Some(user) = &user {
            self.count(user, &n, peer);
        }
    }

    fn check_tgs(&self, q: &TgsQuestion<'_>) -> Result<(), KdcRefusal> {
        let peer = q.peer.and_then(ip_of);
        let Some(client) = q.client else {
            let user = user_named(q.subject, &self.realm, &self.realm);
            let name = q.subject.unparse_with_realm_lossy(&self.realm);
            let target = user.as_ref().map_or(name.as_str(), UserId::as_str);
            let kind = LogKind::AccessDenied;
            record_kdc_row(user.as_ref(), target, kind, false, peer, GONE);
            return Err(gone());
        };
        let checks = item_checks();
        if !checks.iter().any(|check| check.live(self.cache)) {
            return Ok(());
        }
        let Some(user) = user_of(client, &self.realm) else {
            return Ok(());
        };
        let door = Door::KerberosTgs;
        let attempt = Attempt::at_kdc(&user, door, peer, q.now);
        let Err(refusal) = admit_at_kdc_with(self.cache, self.lockout, &attempt, &checks) else {
            return Ok(());
        };
        self.confirm_lock(&user, &refusal);
        let detail = refusal.detail();
        record_kdc_row(
            Some(&user),
            user.as_str(),
            door.log_kind(),
            false,
            peer,
            &detail,
        );
        Err(REFUSED)
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
    use krb5_kdc::admission::TgsKind;
    use krb5_kdc::{IssuedAs, PrincipalRead, SharedDump};
    use krb5_types::{KrbError, TgsRep};
    use lldap_auth::opaque::server::generate_random_private_key;
    use lldap_domain::requests::CreateUserRequest;
    use lldap_domain::types::Attribute;
    use lldap_domain_handlers::enforcement::cached_mfa_policy;
    use lldap_domain_handlers::enforcement::{Entries, fill_policy_cache, start_policy_cache};
    use lldap_domain_handlers::handler::{PolicyBackendHandler, UserBackendHandler};
    use lldap_domain_handlers::kerberos::KerberosSync;
    use lldap_domain_handlers::logging::Protocol;
    use lldap_domain_handlers::mfa::{ENABLE_MFA, MfaPolicy};
    use lldap_domain_handlers::policies::{CreatePolicyRequest, EffectiveItem, PolicyScope};
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

    const REALM: &str = "EXAMPLE.COM";
    const PASSWORD: &str = "Kdc-Pass-1";
    const SERVICE: &str = "HTTP/svc.example.com";
    const PEER: &str = "192.0.2.7";
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
        let client = client.map(|user| guard.get_name(&name(user)).unwrap());
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
        let client = client.map(|user| guard.get_name(&name(user)).unwrap());
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
        KdcVerdict::new(REALM).check_as(&q).map_err(|r| r.code)
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
        let mut ous_of_users = HashMap::new();
        for (users, ou) in [(refused, "people\\labs"), (allowed, "people")] {
            for user in users {
                ous_of_users.insert(UserId::new(user), ou.to_owned());
            }
        }
        let items_of_ous = HashMap::from([
            ("people\\labs".to_owned(), hours("refuse")),
            ("people".to_owned(), hours("any")),
        ]);
        policy_cache().replace(Entries {
            ous_of_users,
            items_of_ous,
            facts: HashMap::new(),
            built_at: Utc::now(),
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
                "ticket issued (encrypted timestamp)",
            ),
            (
                notice(
                    AsReason::PreauthFailed,
                    err::PREAUTH_FAILED,
                    Some(Mechanism::EncChallenge),
                ),
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
                "pre-authentication not completed (OTP)",
            ),
            (
                notice(AsReason::PolicyRefused, err::POLICY, None),
                false,
                "refused after pre-authentication, code 12",
            ),
            (
                notice(AsReason::EntryRefused, err::CLIENT_REVOKED, None),
                false,
                "refused by the entry check, code 18",
            ),
            (
                notice(AsReason::HostRefused, err::CLIENT_REVOKED, None),
                false,
                NOT_SAID,
            ),
        ];
        for (n, success, detail) in rows {
            verdict.as_notice(n);
            let expected = vec![peered(row(LogKind::Login, success, REFUSED_USER, detail))];
            assert_eq!(kdc_rows(&log), expected, "{detail}");
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
                    (b.to_owned(), Door::KerberosTgs),
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
    async fn test_under_the_default_checks_always_takes_no_ticket_at_as_tgs_or_s4u2self() {
        let (bare, enrolled) = (REFUSED_USER, ALLOWED_USER);
        let (temp, _embedded, store) = realm(&[bare, enrolled]).await;
        let svc = service(&temp, &store);
        let cache: &'static PolicyCache = Box::leak(Box::new(PolicyCache::new()));
        let counter: &'static Lockout = Box::leak(Box::default());
        let pool = memory_pool().await;
        let handler = SqlBackendHandler::new(generate_random_private_key(), pool.clone());
        let handler = handler.with_lockout(counter).with_policy_cache(cache);
        for user in [bare, enrolled] {
            directory_user(&handler, user, "people\\labs").await;
        }
        let enrol = format!("UPDATE users SET mfa_type = 'totp' WHERE user_id = '{enrolled}'");
        let enrol = Statement::from_string(DbBackend::Sqlite, enrol);
        pool.execute(enrol).await.unwrap();
        strict_labs(&handler).await;
        let verdict = Arc::new(KdcVerdict::on(REALM, cache, counter));
        store
            .write()
            .unwrap()
            .policy
            .plugins
            .set_host_admission(verdict);
        let registered: Vec<_> = item_checks().iter().map(|check| check.key()).collect();
        assert_eq!(registered, [THRESHOLD, ENABLE_MFA], "the default checks");
        let entries = cache.get();
        let resolved = |user: &str| {
            let user = UserId::new(user);
            let enrolled = entries.facts.get(&user).map(|facts| facts.enrolled);
            (cached_mfa_policy(cache, &entries, &user), enrolled)
        };
        assert_eq!(
            [bare, enrolled].map(resolved),
            [
                (Some(MfaPolicy::Always), Some(false)),
                (Some(MfaPolicy::Always), Some(true))
            ],
            "resolved always from memory, one enrolled and one not"
        );
        let log = LogGuard::install_on_this_thread();
        for user in [bare, enrolled] {
            let as_code = kinit(&store, user, Some(PASSWORD)).0;
            let tgt = issue_tgt(&store, user);
            let tgs = service_ticket(&store, &tgt, user, &svc).is_ok();
            let s4u = s4u2self(&store, &svc, user, false).is_ok();
            assert_eq!(
                (as_code, tgs, s4u),
                (0, true, true),
                "{user}: a ticket at each"
            );
        }
        let refusals = kdc_rows(&log).into_iter().filter(|row| !row.1);
        assert_eq!(refusals.count(), 0, "no refusal row at any Kerberos door");
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
        directory_user(&handler, here, "people").await;
        assert_eq!(
            code(here),
            0,
            "a user created on this server is found at once"
        );
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
            tokio::time::sleep(Duration::from_millis(600)).await;
            held.rollback().await.unwrap();
        });
        let started = Instant::now();
        let got = kinit(&store, b, Some("Wrong-Pass-1")).0;
        let took = started.elapsed();
        assert_eq!(got, err::PREAUTH_FAILED);
        assert!(
            took < Duration::from_millis(300),
            "the KDC answered after {took:?}"
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
}
