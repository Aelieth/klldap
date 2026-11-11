use crate::boot::{self, OpenRealm, RealmSettings};
use anyhow::{Context, Result, anyhow};
use async_trait::async_trait;
use krb5_admin::{
    Kadmind, KadmindConfig, Listeners, Programs, ServeLimits, Services, TracingAdmin,
};
use krb5_config::KadmindListen;
use krb5_crypto::{EncryptionType, KeySalt};
use krb5_kdc::{
    AdminEnt, AdminFields, Error as StoreError, KDB_REQUIRES_PRE_AUTH, KdcLog, ListenLimits,
    PrincipalRead, PrincipalStore, SharedDump, SharedStore, Shutdown, kadm5_mask,
};
use krb5_types::PrincipalName;
use lldap_domain::types::UserId;
use lldap_domain_handlers::kerberos::{
    KerberosSync, validate_kerberos_username, validate_keytab_hostname,
};
use lldap_domain_handlers::logging::{LogKind, current_request, record_outcome, with_request_sync};
use std::panic::{self, AssertUnwindSafe};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::Duration;
use tokio::sync::{Mutex, mpsc};
use tracing::{Span, error, info};
use zeroize::Zeroizing;

const KEYCLOAK_ETYPES: [EncryptionType; 2] = [
    EncryptionType::Aes256CtsHmacSha196,
    EncryptionType::Aes128CtsHmacSha196,
];
const KADMIND_START: Duration = Duration::from_secs(10);

pub struct EmbeddedKerberos {
    realm: String,
    domain: String,
    actor: String,
    store: SharedDump,
    enctypes: Vec<KeySalt>,
    max_renewable_life: u32,
    keycloak_keytab: PathBuf,
    ready: Arc<AtomicBool>,
    writes: Arc<Mutex<()>>,
}

/// The KDC and kadmind threads. A thread that stops on its own stops the other one and
/// reports through `died`; the server then shuts down.
pub struct RealmThreads {
    shutdown: Shutdown,
    stopping: Arc<AtomicBool>,
    handles: Vec<JoinHandle<()>>,
    died: mpsc::UnboundedReceiver<String>,
}

impl EmbeddedKerberos {
    pub fn start(settings: &RealmSettings) -> Result<(Arc<Self>, RealmThreads)> {
        let OpenRealm {
            store,
            profile,
            acl,
            kdc_udp,
            kdc_tcp,
            kadmin,
        } = boot::open(settings)?;
        let shutdown = Shutdown::new();
        let stopping = Arc::new(AtomicBool::new(false));
        let ready = Arc::new(AtomicBool::new(false));
        let (died_tx, died) = mpsc::unbounded_channel();
        let watch = Watch {
            shutdown: shutdown.clone(),
            stopping: stopping.clone(),
            ready: ready.clone(),
            died: died_tx,
        };

        let kdc_store: SharedStore = store.clone();
        let flag = shutdown.stop_flag();
        let kdc = spawn("krb5-kdc", watch.clone(), move || {
            krb5_kdc::serve_all_until(
                kdc_store,
                kdc_udp,
                kdc_tcp,
                flag,
                ListenLimits::default(),
                &KdcLog::process(),
            )
            .context("the KDC stopped serving")
        })?;

        let (built_tx, built) = std::sync::mpsc::channel();
        let kadmind_store = store.clone();
        let kadmind_stop = shutdown.clone();
        let realm = settings.realm.clone();
        let kadmind = spawn("krb5-kadmind", watch, move || {
            let listen = KadmindListen::for_realm(Some(&profile.kdc_context), &realm, None);
            let config = KadmindConfig {
                profile: Arc::new(profile),
                services: Services {
                    kpasswd_udp: false,
                    kpasswd_tcp: false,
                    kadm5: true,
                    iprop: false,
                },
                listen,
                limits: ServeLimits::default(),
                acl,
                auth_modules: Vec::new(),
                log: Arc::new(TracingAdmin),
                pwqual: Vec::new(),
                hooks: Vec::new(),
                iprop: None,
            };
            let listeners = Listeners::from_sockets(
                Vec::new(),
                Vec::new(),
                vec![kadmin],
                Programs {
                    kadm: true,
                    iprop: false,
                },
            );
            let mut server = match Kadmind::new(kadmind_store, config) {
                Ok(server) => server,
                Err(e) => {
                    let e = anyhow!("kadmind could not start: {e}");
                    let _ = built_tx.send(Err(format!("{e:#}")));
                    return Err(e);
                }
            };
            let _ = built_tx.send(Ok(()));
            server
                .serve(&listeners, &kadmind_stop)
                .map(drop)
                .context("kadmind stopped serving")
        })?;
        let threads = RealmThreads {
            shutdown,
            stopping,
            handles: vec![kdc, kadmind],
            died,
        };
        match built.recv_timeout(KADMIND_START) {
            Ok(Ok(())) => {}
            Ok(Err(cause)) => {
                threads.stop();
                return Err(anyhow!(cause));
            }
            Err(_) => {
                threads.stop();
                return Err(anyhow!("kadmind did not start within {KADMIND_START:?}"));
            }
        }
        ready.store(true, Ordering::Relaxed);
        info!(
            "🎟️ Kerberos realm {} serving: kdc {}:{}, kadmin {}",
            settings.realm, settings.kdc_bind, settings.kdc_port, settings.kadmin_bind
        );
        Ok((Arc::new(Self::new(store, settings, ready)), threads))
    }

    pub(crate) fn new(store: SharedDump, settings: &RealmSettings, ready: Arc<AtomicBool>) -> Self {
        Self {
            realm: settings.realm.clone(),
            domain: settings.domain.clone(),
            actor: format!("admin/admin@{}", settings.realm),
            store,
            enctypes: settings
                .supported_enctypes
                .iter()
                .map(|&e| e.into())
                .collect(),
            max_renewable_life: u32::try_from(settings.max_renewable_life).unwrap_or(u32::MAX),
            keycloak_keytab: settings.keycloak_keytab.clone(),
            ready,
            writes: Arc::new(Mutex::new(())),
        }
    }

    /// Brings every listed principal up to the realm's settings: pre-authentication required
    /// and the configured renewable life. Returns how many were updated and how many are missing.
    pub async fn reconcile(&self, users: Vec<UserId>) -> Result<(usize, usize)> {
        let (store, realm, actor) = (self.store.clone(), self.realm.clone(), self.actor.clone());
        let max_renewable_life = u64::from(self.max_renewable_life);
        let serial = self.writes.clone().lock_owned().await;
        tokio::task::spawn_blocking(move || {
            let _serial = serial;
            in_change(&store, |s| {
                let (mut updated, mut missing) = (0, 0);
                for user in &users {
                    let name = user_principal(user);
                    let Some(principal) = s.fetch_name(&name)? else {
                        missing += 1;
                        continue;
                    };
                    let fields = AdminFields {
                        attributes: Some(principal.attributes | KDB_REQUIRES_PRE_AUTH),
                        max_renewable_life: Some(max_renewable_life),
                        ..Default::default()
                    };
                    s.apply_admin_fields_in(&name, &realm, fields, &actor)?;
                    updated += 1;
                }
                Ok((updated, missing))
            })
            .map_err(|e| anyhow!("while reconciling principals: {e}"))
        })
        .await
        .context("the reconcile did not complete")?
    }

    fn new_principal(&self) -> AdminEnt {
        AdminEnt {
            mask: kadm5_mask::ATTRIBUTES | kadm5_mask::MAX_RLIFE,
            attributes: KDB_REQUIRES_PRE_AUTH,
            max_renewable_life: self.max_renewable_life,
            ..Default::default()
        }
    }
}

#[async_trait]
impl KerberosSync for EmbeddedKerberos {
    fn ready(&self) -> bool {
        self.ready.load(Ordering::Relaxed)
    }
    fn realm(&self) -> &str {
        &self.realm
    }
    async fn sync_principal(&self, user: &UserId, password: &str) -> Result<(), String> {
        validate_kerberos_username(user.as_str())?;
        let (store, realm, actor) = (self.store.clone(), self.realm.clone(), self.actor.clone());
        let (name, enctypes, ent) = (
            user_principal(user),
            self.enctypes.clone(),
            self.new_principal(),
        );
        let password = Zeroizing::new(password.as_bytes().to_vec());
        logged(
            &self.writes,
            LogKind::KerberosSync,
            user.as_str(),
            "sync",
            move || {
                set_password(&store, &name, &realm, &password, &enctypes, &ent, &actor)
                    .map_err(|e| anyhow!("while setting the Kerberos password: {e}"))
            },
        )
        .await
    }
    async fn delete_principal(&self, user: &UserId) -> Result<(), String> {
        let (store, realm, name) = (self.store.clone(), self.realm.clone(), user_principal(user));
        logged(
            &self.writes,
            LogKind::KerberosSync,
            user.as_str(),
            "delete",
            move || match in_change(&store, |s| s.remove_in(&name, &realm)) {
                Ok(()) | Err(StoreError::NotFound) => Ok(()),
                Err(e) => Err(anyhow!("while deleting the principal: {e}")),
            },
        )
        .await
    }
    async fn set_principal_enabled(&self, user: &UserId, enabled: bool) -> Result<(), String> {
        let op = if enabled { "enable" } else { "disable" };
        let (store, actor, name) = (self.store.clone(), self.actor.clone(), user_principal(user));
        logged(
            &self.writes,
            LogKind::KerberosSync,
            user.as_str(),
            op,
            move || {
                in_change(&store, |s| match s.fetch_name(&name)? {
                    Some(principal) => s.set_status(&name, !enabled, principal.pw_expire, &actor),
                    None => Ok(()),
                })
                .map_err(|e| anyhow!("while setting the principal's status: {e}"))
            },
        )
        .await
    }
    async fn export_keytab_for_keycloak(&self, hostname: &str) -> Result<String, String> {
        let host = match hostname.trim() {
            "" | "keycloak" => format!("keycloak.{}", self.domain),
            host => host.to_owned(),
        };
        validate_keytab_hostname(&host)?;
        let (store, realm, actor) = (self.store.clone(), self.realm.clone(), self.actor.clone());
        let path = self.keycloak_keytab.clone();
        let name = PrincipalName::new(PrincipalName::NT_SRV_HST, ["HTTP", host.as_str()]);
        logged(
            &self.writes,
            LogKind::KeytabExport,
            &host,
            "keycloak",
            move || {
                let etypes = KEYCLOAK_ETYPES.map(KeySalt::from);
                let keytab = in_change(&store, |s| {
                    if s.fetch_name(&name)?.is_none() {
                        s.insert_new_randkey(&name, &realm, &etypes, &actor)?;
                    }
                    s.chrand_etypes_keepold_in(&name, &realm, &etypes, 0, &actor)?;
                    s.export_keytab_local(&name)
                })
                .map_err(|e| anyhow!("while rotating the Keycloak service key: {e}"))?;
                if let Some(dir) = path.parent() {
                    std::fs::create_dir_all(dir)
                        .with_context(|| format!("while creating {}", dir.display()))?;
                }
                keytab
                    .write_file(&path)
                    .with_context(|| format!("while writing {}", path.display()))?;
                Ok(path.display().to_string())
            },
        )
        .await
    }
}

impl RealmThreads {
    /// The cause, once a Kerberos thread has stopped on its own.
    pub async fn died(&mut self) -> String {
        self.died
            .recv()
            .await
            .unwrap_or_else(|| "the Kerberos threads ended".to_owned())
    }

    pub fn stop(self) {
        self.stopping.store(true, Ordering::Relaxed);
        self.shutdown.trigger();
        for handle in self.handles {
            if handle.join().is_err() {
                error!("💥 A Kerberos thread could not be joined");
            }
        }
    }
}

#[derive(Clone)]
struct Watch {
    shutdown: Shutdown,
    stopping: Arc<AtomicBool>,
    ready: Arc<AtomicBool>,
    died: mpsc::UnboundedSender<String>,
}

impl Watch {
    fn finished(&self, thread: &str, failure: Option<String>) {
        if self.stopping.load(Ordering::Relaxed) {
            return;
        }
        let cause = format!(
            "{thread}: {}",
            failure.unwrap_or_else(|| "stopped serving".to_owned())
        );
        self.ready.store(false, Ordering::Relaxed);
        error!("💥 Kerberos thread {cause}");
        self.shutdown.trigger();
        if self.died.send(cause).is_err() {
            error!("💥 The server was already stopping");
        }
    }
}

fn spawn(
    name: &str,
    watch: Watch,
    body: impl FnOnce() -> Result<()> + Send + 'static,
) -> Result<JoinHandle<()>> {
    let thread = name.to_owned();
    thread::Builder::new()
        .name(thread.clone())
        .spawn(move || {
            let failure = match panic::catch_unwind(AssertUnwindSafe(body)) {
                Ok(Ok(())) => None,
                Ok(Err(e)) => Some(format!("{e:#}")),
                Err(_) => Some("panicked".to_owned()),
            };
            watch.finished(&thread, failure);
        })
        .with_context(|| format!("while starting the {name} thread"))
}

#[derive(Debug, PartialEq)]
enum Next {
    Done,
    Create,
    ChangeAgain,
    Fail(StoreError),
}

fn after_change(result: Result<(), StoreError>) -> Next {
    match result {
        Ok(()) => Next::Done,
        Err(StoreError::NotFound) => Next::Create,
        Err(e) => Next::Fail(e),
    }
}

// A kadmin client can create the principal between our change and our create.
fn after_create(result: Result<(), StoreError>) -> Next {
    match result {
        Ok(()) => Next::Done,
        Err(StoreError::AlreadyExists) => Next::ChangeAgain,
        Err(e) => Next::Fail(e),
    }
}

fn set_password(
    store: &SharedDump,
    name: &PrincipalName,
    realm: &str,
    password: &[u8],
    enctypes: &[KeySalt],
    ent: &AdminEnt,
    actor: &str,
) -> Result<(), StoreError> {
    let change = || {
        krb5_kdc::change_password_shared(store, name, realm, password, 0, actor, enctypes, |_| {
            Ok(())
        })
    };
    let mut next = after_change(change());
    if next == Next::Create {
        next = after_create(krb5_kdc::create_password_shared(
            store, name, realm, password, enctypes, ent, actor,
        ));
    }
    if next == Next::ChangeAgain {
        next = after_change(change());
    }
    match next {
        Next::Done => Ok(()),
        Next::Fail(e) => Err(e),
        Next::Create | Next::ChangeAgain => Err(StoreError::NotFound),
    }
}

fn in_change<T>(
    store: &SharedDump,
    f: impl FnOnce(&mut PrincipalStore) -> Result<T, StoreError>,
) -> Result<T, StoreError> {
    let mut store = store.write().map_err(|_| {
        StoreError::InvalidArgument("the principal store was poisoned by a panic".to_owned())
    })?;
    store.change(f)?
}

fn user_principal(user: &UserId) -> PrincipalName {
    PrincipalName::new(PrincipalName::NT_PRINCIPAL, [user.as_str()])
}

// One store write at a time; the guard and the log row go with the call, so a dropped caller
// keeps both.
async fn logged<T: Send + 'static>(
    writes: &Arc<Mutex<()>>,
    kind: LogKind,
    target: &str,
    op: &'static str,
    f: impl FnOnce() -> Result<T> + Send + 'static,
) -> Result<T, String> {
    let meta = current_request();
    let span = Span::current();
    let target = target.to_owned();
    let serial = writes.clone().lock_owned().await;
    tokio::task::spawn_blocking(move || {
        let _serial = serial;
        span.in_scope(|| {
            with_request_sync(meta, || {
                let result = f().map_err(|e| format!("{e:#}"));
                record_outcome(kind, Some(&target), result.is_ok(), Some(op));
                result
            })
        })
    })
    .await
    .unwrap_or_else(|e| Err(format!("Kerberos call did not complete: {e}")))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use krb5_kdc::KDB_DISALLOW_ALL_TIX;
    use lldap_domain_handlers::logging::{RequestMeta, with_request};
    use lldap_test_utils::recording_log::LogGuard;
    use pretty_assertions::assert_eq;
    use serial_test::serial;
    use std::sync::atomic::AtomicUsize;

    pub(crate) struct TempRealm {
        pub settings: RealmSettings,
    }

    impl TempRealm {
        pub(crate) fn new() -> Self {
            static SEQ: AtomicUsize = AtomicUsize::new(0);
            let dir = std::env::temp_dir().join(format!(
                "lldap-kerberos-{}-{}",
                std::process::id(),
                SEQ.fetch_add(1, Ordering::Relaxed)
            ));
            Self {
                settings: RealmSettings {
                    realm: "EXAMPLE.COM".to_owned(),
                    domain: "example.com".to_owned(),
                    ticket_lifetime: 86_400,
                    renew_lifetime: 604_800,
                    max_renewable_life: 604_800,
                    forwardable: true,
                    supported_enctypes: vec![EncryptionType::Aes256CtsHmacSha196],
                    kdc_bind: [127, 0, 0, 1].into(),
                    kdc_port: 0,
                    kadmin_bind: ([127, 0, 0, 1], 0).into(),
                    kadmin_acl_file: None,
                    data_dir: dir.join("kdc"),
                    admin_keytab: dir.join("kadm5.keytab"),
                    keycloak_keytab: dir.join("keycloak.keytab"),
                    client_config: dir.join("krb5.conf"),
                },
            }
        }

        pub(crate) fn embedded(&self) -> (EmbeddedKerberos, SharedDump) {
            let profile = boot::profile(&self.settings);
            let store = krb5_kdc::shared_dump(boot::open_store(&self.settings, &profile).unwrap());
            let ready = Arc::new(AtomicBool::new(true));
            (
                EmbeddedKerberos::new(store.clone(), &self.settings, ready),
                store,
            )
        }
    }

    impl Drop for TempRealm {
        fn drop(&mut self) {
            if let Some(dir) = self.settings.data_dir.parent() {
                let _ = std::fs::remove_dir_all(dir);
            }
        }
    }

    #[test]
    fn test_change_or_create_decisions() {
        let denied = || Err(StoreError::AclDenied);
        type Decide = fn(Result<(), StoreError>) -> Next;
        let rows: [(&str, Decide, Result<(), StoreError>, Next); 6] = [
            ("change ok", after_change, Ok(()), Next::Done),
            (
                "change missing",
                after_change,
                Err(StoreError::NotFound),
                Next::Create,
            ),
            (
                "change denied",
                after_change,
                denied(),
                Next::Fail(StoreError::AclDenied),
            ),
            ("create ok", after_create, Ok(()), Next::Done),
            (
                "create raced",
                after_create,
                Err(StoreError::AlreadyExists),
                Next::ChangeAgain,
            ),
            (
                "create denied",
                after_create,
                denied(),
                Next::Fail(StoreError::AclDenied),
            ),
        ];
        for (row, decide, result, expected) in rows {
            assert_eq!(decide(result), expected, "{row}");
        }
    }

    #[tokio::test]
    async fn test_disable_and_enable_keep_the_password_expiry() {
        let temp = TempRealm::new();
        let (embedded, store) = temp.embedded();
        let bob = UserId::new("bob");
        embedded
            .sync_principal(&bob, "Bob-Password-1")
            .await
            .unwrap();
        in_change(&store, |s| {
            s.set_status(&user_principal(&bob), false, 2_000_000_000, "test")
        })
        .unwrap();
        for (enabled, locked) in [(false, true), (true, false)] {
            embedded.set_principal_enabled(&bob, enabled).await.unwrap();
            let principal = store
                .read()
                .unwrap()
                .fetch_name(&user_principal(&bob))
                .unwrap()
                .unwrap();
            assert_eq!(
                (
                    principal.attributes & KDB_DISALLOW_ALL_TIX != 0,
                    principal.pw_expire
                ),
                (locked, 2_000_000_000),
                "enabled = {enabled}"
            );
        }
    }

    #[tokio::test]
    #[serial]
    async fn test_a_dropped_caller_keeps_the_write_lock_and_its_log_row() {
        let guard = LogGuard::install();
        let writes = Arc::new(Mutex::new(()));
        let (release, held) = std::sync::mpsc::channel::<()>();
        let alice = RequestMeta::ldap(Some(UserId::new("alice")), None);
        let call = logged(&writes, LogKind::KerberosSync, "bob", "sync", move || {
            Ok(held.recv()?)
        });
        let waited =
            tokio::time::timeout(Duration::from_millis(50), with_request(alice, call)).await;
        assert!(
            waited.is_err(),
            "the caller gives up while the call is blocked"
        );
        assert!(
            writes.try_lock().is_err(),
            "a dropped caller freed the lock mid-call"
        );

        release.send(()).unwrap();
        drop(writes.lock().await);
        let rows: Vec<_> = guard
            .recorder()
            .take_events()
            .into_iter()
            .map(|e| (e.target, e.actor))
            .collect();
        assert_eq!(
            rows,
            vec![(Some("bob".to_owned()), Some("alice".to_owned()))],
            "the dropped call's row keeps its request's actor"
        );
    }

    #[test]
    fn test_a_realm_that_cannot_open_fails_to_start() {
        let held = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut port_taken = TempRealm::new();
        port_taken.settings.kdc_port = held.local_addr().unwrap().port();
        let dir_is_a_file = TempRealm::new();
        let parent = dir_is_a_file.settings.data_dir.parent().unwrap();
        std::fs::create_dir_all(parent).unwrap();
        std::fs::write(&dir_is_a_file.settings.data_dir, b"").unwrap();
        for (temp, cause) in [
            (&port_taken, "while binding the KDC on UDP"),
            (&dir_is_a_file, "while creating"),
        ] {
            let error = EmbeddedKerberos::start(&temp.settings).err().unwrap();
            assert!(format!("{error:#}").contains(cause), "{error:#}");
        }
    }
}
