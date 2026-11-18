use crate::policy::AllowAll;
use krb5_kdc::admission::{AsNotice, AsQuestion, HostAdmission, KdcRefusal, TgsQuestion};
use krb5_types::{HostAddress, err};
use std::ffi::OsString;
use std::fmt::Write as _;
use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::warn;

pub(crate) const REFUSE: &str = "LLDAP_TEST_ADMISSION_REFUSE";
pub(crate) const NOTICES: &str = "LLDAP_TEST_ADMISSION_NOTICES";

/// Test image only: refuses the names listed in `REFUSE`, writes one JSON line per notice to
/// `NOTICES`, and is `AllowAll` when neither is set.
pub(crate) fn from_env() -> Arc<dyn HostAdmission> {
    from_vars(std::env::var_os(REFUSE), std::env::var_os(NOTICES))
}

fn from_vars(refuse: Option<OsString>, notices: Option<OsString>) -> Arc<dyn HostAdmission> {
    let path = |var: Option<OsString>| var.filter(|v| !v.is_empty()).map(PathBuf::from);
    match (path(refuse), path(notices)) {
        (None, None) => Arc::new(AllowAll),
        (refuse, notices) => {
            warn!(
                "Kerberos logins of directory users go through the test admission module \
                 ({REFUSE}, {NOTICES}); this build is for tests only"
            );
            Arc::new(TestAdmission::installed(refuse, notices))
        }
    }
}

struct TestAdmission {
    refuse: Option<PathBuf>,
    notices: Option<PathBuf>,
}

impl TestAdmission {
    fn installed(refuse: Option<PathBuf>, notices: Option<PathBuf>) -> Self {
        let module = Self { refuse, notices };
        let now = since_epoch();
        module.append(&format!(
            "{{\"installed\":{},\"installed_ms\":{}}}\n",
            now.as_secs(),
            now.as_millis()
        ));
        module
    }

    fn listed(&self, name: &str) -> bool {
        self.refuse
            .as_ref()
            .and_then(|path| fs::read_to_string(path).ok())
            .is_some_and(|names| names.lines().any(|line| line.trim() == name))
    }

    fn append(&self, line: &str) {
        let Some(path) = &self.notices else {
            return;
        };
        let written = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .and_then(|mut file| file.write_all(line.as_bytes()));
        if let Err(e) = written {
            warn!(
                "The test admission module did not write {}: {e}",
                path.display()
            );
        }
    }
}

impl HostAdmission for TestAdmission {
    fn check_as(&self, q: &AsQuestion<'_>) -> Result<(), KdcRefusal> {
        if self.listed(&q.client.id()) {
            return Err(revoked());
        }
        Ok(())
    }

    fn as_notice(&self, notice: AsNotice) {
        if self.notices.is_some() {
            self.append(&notice_line(&notice, since_epoch().as_millis()));
        }
    }

    fn check_tgs(&self, q: &TgsQuestion<'_>) -> Result<(), KdcRefusal> {
        match q.client {
            Some(client) if !self.listed(&client.id()) => Ok(()),
            _ => Err(revoked()),
        }
    }
}

fn revoked() -> KdcRefusal {
    KdcRefusal {
        code: err::CLIENT_REVOKED,
        e_text: None,
    }
}

fn since_epoch() -> Duration {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
}

fn notice_line(n: &AsNotice, time_ms: u128) -> String {
    format!(
        "{{\"time\":{},\"time_ms\":{time_ms},\"client\":{},\"requested\":{},\
         \"peer\":{},\"code\":{},\"reason\":{},\"mechanism\":{}}}\n",
        n.time,
        text(&n.client),
        text(&n.requested),
        or_null(n.peer.as_ref().map(peer_text)),
        n.code,
        text(&format!("{:?}", n.reason)),
        or_null(n.mechanism.map(|m| format!("{m:?}"))),
    )
}

fn or_null(value: Option<String>) -> String {
    value.map_or_else(|| "null".to_owned(), |v| text(&v))
}

fn text(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for c in value.chars() {
        match c {
            '"' | '\\' => {
                out.push('\\');
                out.push(c);
            }
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c < ' ' => {
                let _ = write!(out, "\\u{:04x}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn peer_text(peer: &HostAddress) -> String {
    let bytes: &[u8] = &peer.address;
    let ip = match peer.addr_type {
        HostAddress::ADDRTYPE_INET => <[u8; 4]>::try_from(bytes).ok().map(IpAddr::from),
        HostAddress::ADDRTYPE_INET6 => <[u8; 16]>::try_from(bytes).ok().map(IpAddr::from),
        _ => None,
    };
    ip.map_or_else(
        || {
            let hex = bytes.iter().fold(String::new(), |mut hex, b| {
                let _ = write!(hex, "{b:02x}");
                hex
            });
            format!("{}:{hex}", peer.addr_type)
        },
        |ip| ip.to_string(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::embedded::tests::{TempRealm, synced};
    use crate::policy::tests::{tgs_body, ticket};
    use crate::seam::committing;
    use krb5_asn1::{decode, encode};
    use krb5_crypto::{EncryptionType, ProtocolKey, string_to_key};
    use krb5_kdc::admission::{AsReason, Mechanism, TgsKind};
    use krb5_kdc::{IssuedAs, KDB_DISALLOW_ALL_TIX, Principal, PrincipalRead, SharedDump};
    use krb5_types::{KrbError, PrincipalName, TgsRep};
    use lldap_domain::types::UserId;
    use lldap_domain_handlers::kerberos::KerberosSync;
    use pretty_assertions::assert_eq;
    use serial_test::serial;
    use std::path::Path;
    use std::process::Command;
    use std::sync::Mutex;

    const REALM: &str = "EXAMPLE.COM";
    const PASSWORD: &str = "bob-pass-1";
    const CHILD: &str = "admission_test::tests::child_signs_in_bob_through_install_plugins";
    const SERVICE: &str = "HTTP/svc.example.com";

    struct Scratch(PathBuf);

    impl Scratch {
        fn new(row: &str) -> Self {
            let dir =
                std::env::temp_dir().join(format!("klldap-admission-{}-{row}", std::process::id()));
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }

        fn file(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn lines(path: &Path) -> Vec<String> {
        fs::read_to_string(path)
            .map(|text| text.lines().map(str::to_owned).collect())
            .unwrap_or_default()
    }

    fn name(user: &str) -> PrincipalName {
        PrincipalName::new(PrincipalName::NT_PRINCIPAL, [user])
    }

    fn as_code(store: &SharedDump, user: &str, password: Option<&str>, nonce: u32) -> i32 {
        let padata = password.map(|password| {
            let salt = name(user).default_salt(REALM);
            let key =
                string_to_key(EncryptionType::Aes256CtsHmacSha196, password, salt, None).unwrap();
            vec![krb5_protocol::pa_enc_timestamp(&key).unwrap()]
        });
        let request = krb5_protocol::as_req(name(user), REALM, nonce, padata).unwrap();
        let reply =
            krb5_kdc::handle_request(&*store.read().unwrap(), &encode(&request).unwrap()).unwrap();
        decode::<KrbError>(&reply).map_or(0, |e| e.error_code)
    }

    /// The KDC's `time`, the module's `time_ms`, and the rest of the line.
    fn split_times(line: &str) -> (u64, u128, &str) {
        let rest = line.strip_prefix("{\"time\":").expect(line);
        let (time, rest) = rest.split_once(",\"time_ms\":").expect(line);
        let (time_ms, rest) = rest.split_once(',').expect(line);
        (
            time.parse().expect(line),
            time_ms.parse().expect(line),
            rest,
        )
    }

    fn installed_ms(line: &str) -> u128 {
        let (secs, ms) = line
            .strip_prefix("{\"installed\":")
            .and_then(|rest| rest.strip_suffix('}'))
            .and_then(|rest| rest.split_once(",\"installed_ms\":"))
            .expect(line);
        let (secs, ms): (u64, u128) = (secs.parse().expect(line), ms.parse().expect(line));
        assert_eq!(ms / 1000, u128::from(secs), "{line}");
        ms
    }

    fn rest_of(user: &str, code: i32, reason: AsReason, mechanism: Option<Mechanism>) -> String {
        let mechanism = mechanism.map_or_else(|| "null".to_owned(), |m| format!("\"{m:?}\""));
        format!(
            "\"client\":\"{user}@{REALM}\",\"requested\":\"{user}@{REALM}\",\"peer\":null,\
             \"code\":{code},\"reason\":\"{reason:?}\",\"mechanism\":{mechanism}}}"
        )
    }

    /// Hands each question to `inner`, keeping one line per question or notice and each subject.
    struct Recording {
        inner: Arc<dyn HostAdmission>,
        seen: Mutex<Vec<String>>,
        subjects: Mutex<Vec<String>>,
    }

    impl Recording {
        fn around(inner: Arc<dyn HostAdmission>) -> Arc<Self> {
            Arc::new(Self {
                inner,
                seen: Mutex::default(),
                subjects: Mutex::default(),
            })
        }

        fn take(&self) -> (Vec<String>, Vec<String>) {
            let take = |list: &Mutex<Vec<String>>| std::mem::take(&mut *list.lock().unwrap());
            (take(&self.seen), take(&self.subjects))
        }

        fn note(&self, line: String) {
            self.seen.lock().unwrap().push(line);
        }
    }

    impl HostAdmission for Recording {
        fn check_as(&self, q: &AsQuestion<'_>) -> Result<(), KdcRefusal> {
            self.note(format!("as {} s4u2self {}", q.client.id(), q.s4u2self));
            self.inner.check_as(q)
        }

        fn as_notice(&self, notice: AsNotice) {
            self.note(format!("notice {}", notice.client));
            self.inner.as_notice(notice);
        }

        fn check_tgs(&self, q: &TgsQuestion<'_>) -> Result<(), KdcRefusal> {
            let client = q.client.map_or_else(|| "none".to_owned(), Principal::id);
            self.note(format!("tgs {client} {:?}", q.kind));
            let subject = q.subject.unparse_with_realm_lossy(REALM);
            self.subjects.lock().unwrap().push(subject);
            self.inner.check_tgs(q)
        }
    }

    struct Service {
        name: PrincipalName,
        key: ProtocolKey,
        tgt: IssuedAs,
    }

    /// Random keys and no directory user, written as the kadmin rows write; then its TGT.
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
        let request = krb5_protocol::as_req(name.clone(), REALM, 100, Some(padata)).unwrap();
        let tgt = krb5_kdc::issue_as(&*guard, &request).unwrap();
        Service { name, key, tgt }
    }

    /// The reply's client, the ticket's client and server; or the error code and e-text.
    type Outcome = Result<[String; 3], (i32, Option<String>)>;

    fn s4u2self(store: &SharedDump, svc: &Service, user: &str, x509: bool, nonce: u32) -> Outcome {
        let session = &svc.tgt.session_key;
        let for_user = if x509 {
            krb5_protocol::pa_s4u_x509_user(session, name(user), REALM, nonce)
        } else {
            krb5_protocol::pa_for_user(session, name(user), REALM)
        };
        let mut request = krb5_protocol::tgs_req(
            svc.tgt.rep.0.ticket.clone(),
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
        let reply =
            krb5_kdc::handle_request(&*store.read().unwrap(), &encode(&request).unwrap()).unwrap();
        if let Ok(e) = decode::<KrbError>(&reply) {
            let text = e
                .e_text
                .map(|t| String::from_utf8_lossy(t.as_bytes()).into_owned());
            return Err((e.error_code, text));
        }
        let rep = decode::<TgsRep>(&reply).unwrap().0;
        let part = krb5_kdc::decrypt_ticket_part(&svc.key, &rep.ticket).unwrap();
        Ok([
            rep.cname.unparse_with_realm_lossy(REALM),
            part.cname.unparse_with_realm_lossy(REALM),
            rep.ticket.sname.unparse_with_realm_lossy(REALM),
        ])
    }

    #[tokio::test]
    #[serial]
    async fn test_a_listed_client_is_refused_before_preauth_and_each_outcome_is_noted() {
        let temp = TempRealm::new();
        let (embedded, store) = temp.embedded();
        synced(&embedded, &UserId::new("bob"), PASSWORD)
            .await
            .unwrap();
        let scratch = Scratch::new("as");
        let (refuse, notices) = (scratch.file("refuse"), scratch.file("notices.jsonl"));
        let module = from_vars(Some(refuse.clone().into()), Some(notices.clone().into()));
        store
            .write()
            .unwrap()
            .policy
            .plugins
            .set_host_admission(module);
        let bob = "bob@EXAMPLE.COM\n";
        let enc_ts = Some(Mechanism::EncTimestamp);
        type Notice = Option<(AsReason, Option<Mechanism>)>;
        type Row<'a> = (&'a str, &'a str, &'a str, Option<&'a str>, i32, Notice);
        let rows: [Row; 6] = [
            (
                "listed, no padata",
                bob,
                "bob",
                None,
                err::CLIENT_REVOKED,
                Some((AsReason::HostRefused, None)),
            ),
            (
                "listed, the right password",
                bob,
                "bob",
                Some(PASSWORD),
                err::CLIENT_REVOKED,
                Some((AsReason::HostRefused, None)),
            ),
            (
                "allowed, no padata",
                "",
                "bob",
                None,
                err::PREAUTH_REQUIRED,
                None,
            ),
            (
                "allowed, a wrong password",
                "",
                "bob",
                Some("wrong-pass-1"),
                err::PREAUTH_FAILED,
                Some((AsReason::PreauthFailed, enc_ts)),
            ),
            (
                "allowed, the right password",
                "",
                "bob",
                Some(PASSWORD),
                0,
                Some((AsReason::Issued, enc_ts)),
            ),
            (
                "an unknown client, listed",
                "alice@EXAMPLE.COM\n",
                "alice",
                None,
                err::C_PRINCIPAL_UNKNOWN,
                None,
            ),
        ];
        let first = lines(&notices);
        assert_eq!(first.len(), 1, "{first:?}");
        let installed = installed_ms(&first[0]);
        for (nonce, (row, names, user, password, code, notice)) in (1..).zip(rows) {
            fs::write(&refuse, names).unwrap();
            let before = lines(&notices).len();
            assert_eq!(as_code(&store, user, password, nonce), code, "{row}");
            let got: Vec<String> = lines(&notices)
                .split_off(before)
                .iter()
                .map(|line| {
                    let (time, time_ms, rest) = split_times(line);
                    let secs = u128::from(time);
                    assert!(time_ms >= installed, "{row}: {line}");
                    assert!(
                        (secs..=secs + 60).contains(&(time_ms / 1000)),
                        "{row}: {line}"
                    );
                    rest.to_owned()
                })
                .collect();
            let expected: Vec<String> = notice
                .into_iter()
                .map(|(reason, mechanism)| rest_of(user, code, reason, mechanism))
                .collect();
            assert_eq!(got, expected, "{row}");
        }
    }

    #[tokio::test]
    #[serial]
    async fn test_check_tgs_refuses_a_deleted_or_listed_subject() {
        let temp = TempRealm::new();
        let (embedded, store) = temp.embedded();
        synced(&embedded, &UserId::new("bob"), PASSWORD)
            .await
            .unwrap();
        let scratch = Scratch::new("tgs");
        let refuse = scratch.file("refuse");
        let guard = store.read().unwrap();
        let subject = name("bob");
        let bob = guard.get_name(&subject).unwrap();
        let krbtgt = PrincipalName::new(PrincipalName::NT_SRV_INST, ["krbtgt", REALM]);
        let server = guard.fetch_name(&krbtgt).unwrap().unwrap();
        let ticket = ticket(REALM, "bob");
        let request = tgs_body(&ticket);
        let refused = Err(err::CLIENT_REVOKED);
        type Row<'a> = (&'a str, Option<&'a str>, bool, Result<(), i32>);
        let rows: [Row; 5] = [
            ("variables unset, a deleted user", None, false, Ok(())),
            ("a deleted user", Some(""), false, refused),
            ("a listed subject", Some("bob@EXAMPLE.COM\n"), true, refused),
            (
                "another name listed",
                Some("alice@EXAMPLE.COM\n"),
                true,
                Ok(()),
            ),
            ("nothing listed", Some(""), true, Ok(())),
        ];
        for (row, names, present, expected) in rows {
            let module = match names {
                None => from_vars(None, None),
                Some(names) => {
                    fs::write(&refuse, names).unwrap();
                    from_vars(Some(refuse.clone().into()), None)
                }
            };
            let q = TgsQuestion {
                client: present.then_some(bob),
                subject: &subject,
                server: &server,
                ticket: &ticket,
                request: &request,
                peer: None,
                now: 0,
                kind: TgsKind::Renew,
            };
            assert_eq!(module.check_tgs(&q).map_err(|r| r.code), expected, "{row}");
        }
    }

    #[test]
    fn test_a_notice_is_one_json_line_after_the_install_line() {
        let scratch = Scratch::new("lines");
        let notices = scratch.file("notices.jsonl");
        let module = from_vars(None, Some(notices.clone().into()));
        let notice = |client: &str, peer: Option<&str>| AsNotice {
            client: client.to_owned(),
            requested: "bob@EXAMPLE.COM".to_owned(),
            peer: peer.map(|p| HostAddress::from_socket(p.parse().unwrap())),
            time: 1_700_000_000,
            code: err::PREAUTH_FAILED,
            reason: AsReason::PreauthFailed,
            mechanism: Some(Mechanism::EncChallenge),
        };
        let netbios = AsNotice {
            peer: Some(HostAddress {
                addr_type: HostAddress::ADDRTYPE_NETBIOS,
                address: b"PC".to_vec().into(),
            }),
            ..notice("bob@EXAMPLE.COM", None)
        };
        let tail = r#""requested":"bob@EXAMPLE.COM","#;
        let end = r#""code":24,"reason":"PreauthFailed","mechanism":"EncChallenge"}"#;
        let rows = [
            (
                notice("bob@EXAMPLE.COM", None),
                r#""client":"bob@EXAMPLE.COM","#,
                r#""peer":null,"#,
            ),
            (
                notice("a\"b\\c\nd\u{1}@EXAMPLE.COM", Some("192.0.2.7:88")),
                r#""client":"a\"b\\c\nd\u0001@EXAMPLE.COM","#,
                r#""peer":"192.0.2.7","#,
            ),
            (
                notice("bob@EXAMPLE.COM", Some("[2001:db8::1]:88")),
                r#""client":"bob@EXAMPLE.COM","#,
                r#""peer":"2001:db8::1","#,
            ),
            (
                netbios,
                r#""client":"bob@EXAMPLE.COM","#,
                r#""peer":"20:5043","#,
            ),
        ];
        for (n, ..) in &rows {
            module.as_notice(n.clone());
        }
        let got = lines(&notices);
        assert_eq!(got.len(), rows.len() + 1, "{got:?}");
        let installed = installed_ms(&got[0]);
        for (line, (_, client, peer)) in got[1..].iter().zip(&rows) {
            let (time, time_ms, rest) = split_times(line);
            assert!(time_ms >= installed, "{line}");
            assert_eq!(
                (time, rest),
                (1_700_000_000, format!("{client}{tail}{peer}{end}").as_str())
            );
        }
    }

    #[tokio::test]
    #[serial]
    #[ignore = "a child process of test_install_plugins_reads_the_variables"]
    async fn child_signs_in_bob_through_install_plugins() {
        let temp = TempRealm::new();
        let (embedded, store) = temp.embedded();
        synced(&embedded, &UserId::new("bob"), PASSWORD)
            .await
            .unwrap();
        crate::boot::install_plugins(&mut store.write().unwrap());
        println!("code {}", as_code(&store, "bob", None, 1));
    }

    #[test]
    fn test_install_plugins_reads_the_variables() {
        let scratch = Scratch::new("env");
        let (refuse, notices) = (scratch.file("refuse"), scratch.file("notices.jsonl"));
        fs::write(&refuse, "bob@EXAMPLE.COM\n").unwrap();
        let (listed, written_to, empty) = (refuse.as_path(), notices.as_path(), Path::new(""));
        type Row<'a> = (&'a str, Vec<(&'a str, &'a Path)>, &'a str, usize);
        let rows: [Row; 4] = [
            ("both unset", vec![], "code 25", 0),
            (
                "empty counts as unset",
                vec![(REFUSE, empty), (NOTICES, empty)],
                "code 25",
                0,
            ),
            ("the refusals only", vec![(REFUSE, listed)], "code 18", 0),
            (
                "both set",
                vec![(REFUSE, listed), (NOTICES, written_to)],
                "code 18",
                2,
            ),
        ];
        for (row, vars, code, written) in rows {
            let mut child = Command::new(std::env::current_exe().unwrap());
            child
                .args([
                    CHILD,
                    "--exact",
                    "--ignored",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env_remove(REFUSE)
                .env_remove(NOTICES)
                .envs(vars);
            let out = child.output().unwrap();
            let stdout = String::from_utf8_lossy(&out.stdout);
            assert!(
                out.status.success() && stdout.contains("1 passed") && stdout.contains(code),
                "{row}: {stdout}{}",
                String::from_utf8_lossy(&out.stderr)
            );
            let got = lines(&notices);
            assert_eq!(got.len(), written, "{row}: {got:?}");
        }
        let got = lines(&notices);
        assert!(installed_ms(&got[0]) > 0, "{got:?}");
        let (_, _, rest) = split_times(&got[1]);
        let expected = rest_of("bob", err::CLIENT_REVOKED, AsReason::HostRefused, None);
        assert_eq!(rest, expected);
    }

    #[tokio::test]
    #[serial]
    async fn test_s4u2self_is_decided_on_the_impersonated_user() {
        let temp = TempRealm::new();
        let (embedded, store) = temp.embedded();
        for user in ["bob", "carol", "dave", "erin"] {
            synced(&embedded, &UserId::new(user), PASSWORD)
                .await
                .unwrap();
        }
        embedded
            .set_principal_enabled(&UserId::new("dave"), false)
            .await
            .unwrap();
        embedded
            .delete_principal(&UserId::new("erin"))
            .await
            .unwrap();
        let svc = service(&temp, &store);
        let entries = {
            let guard = store.read().unwrap();
            let disabled = guard
                .get_name(&name("dave"))
                .map(|p| p.attributes & KDB_DISALLOW_ALL_TIX);
            (disabled, guard.get_name(&name("erin")).is_none())
        };
        assert_eq!(entries, (Some(KDB_DISALLOW_ALL_TIX), true));
        let text = |t: &str| Some(t.to_owned());
        assert_eq!(
            s4u2self(&store, &svc, "bob", false, 1),
            Err((err::CLIENT_REVOKED, text("LOCKED_OUT"))),
            "no module installed"
        );
        let scratch = Scratch::new("s4u");
        let refuse = scratch.file("refuse");
        fs::write(&refuse, "carol@EXAMPLE.COM\n").unwrap();
        let module = Recording::around(from_vars(Some(refuse.into()), None));
        {
            let mut guard = store.write().unwrap();
            crate::boot::install_plugins(&mut guard);
            guard.policy.plugins.set_host_admission(module.clone());
        }
        let asked = |user: &str| format!("as {user}@{REALM} s4u2self true");
        let issued = |user: &str| -> Outcome {
            let user = format!("{user}@{REALM}");
            Ok([user.clone(), user, format!("{SERVICE}@{REALM}")])
        };
        type Row<'a> = (&'a str, &'a str, Outcome, Vec<String>);
        let rows: [Row; 4] = [
            (
                "(a) listed",
                "carol",
                Err((err::CLIENT_REVOKED, None)),
                vec![asked("carol")],
            ),
            (
                "(b) disabled",
                "dave",
                Err((err::CLIENT_REVOKED, text("CLIENT LOCKED OUT"))),
                vec![],
            ),
            (
                "(c) allowed",
                "bob",
                issued("bob"),
                vec![asked("bob"), format!("tgs bob@{REALM} S4u2Self")],
            ),
            (
                "(e) gone",
                "erin",
                Err((err::C_PRINCIPAL_UNKNOWN, text("UNKNOWN_S4U2SELF_PRINCIPAL"))),
                vec![],
            ),
        ];
        for (nonce, (row, user, outcome, seen)) in (10..).step_by(2).zip(rows) {
            for (x509, nonce) in [(false, nonce), (true, nonce + 1)] {
                let got = s4u2self(&store, &svc, user, x509, nonce);
                assert_eq!(
                    (got, module.take().0),
                    (outcome.clone(), seen.clone()),
                    "{row}, PA-S4U-X509-USER {x509}"
                );
            }
        }
    }

    #[tokio::test]
    #[serial]
    async fn test_s4u2self_asks_about_the_impersonated_user_as_its_subject() {
        let temp = TempRealm::new();
        let (embedded, store) = temp.embedded();
        synced(&embedded, &UserId::new("bob"), PASSWORD)
            .await
            .unwrap();
        let svc = service(&temp, &store);
        let module = Recording::around(Arc::new(AllowAll));
        store
            .write()
            .unwrap()
            .policy
            .plugins
            .set_host_admission(module.clone());
        let bob = format!("bob@{REALM}");
        for (x509, nonce) in [(false, 1), (true, 2)] {
            let got = s4u2self(&store, &svc, "bob", x509, nonce).map(|[client, ..]| client);
            let (seen, subjects) = module.take();
            assert_eq!(
                (got, seen.last().cloned(), subjects),
                (
                    Ok(bob.clone()),
                    Some(format!("tgs {bob} S4u2Self")),
                    vec![bob.clone()]
                ),
                "PA-S4U-X509-USER {x509}"
            );
        }
    }
}
