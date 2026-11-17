use crate::boot::{self, OpenRealm, RealmSettings};
use crate::rotate;
use crate::seam::{Host, SqlRealm, committing};
use anyhow::{Context, Result, anyhow};
use async_trait::async_trait;
use krb5_admin::{
    Kadmind, KadmindConfig, Listeners, Programs, ServeLimits, Services, TracingAdmin,
};
use krb5_config::KadmindListen;
use krb5_crypto::KeySalt;
use krb5_kdc::{
    AdminEnt, AdminFields, CreateKeys, CreatePlan, Error as StoreError, KDB_REQUIRES_PRE_AUTH,
    KdcLog, ListenLimits, PrincipalRead, PrincipalStore, SharedDump, SharedStore, Shutdown,
    kadm5_mask,
};
use krb5_types::PrincipalName;
use lldap_domain::types::UserId;
use lldap_domain_handlers::kerberos::{
    KerberosSync, validate_kerberos_username, validate_keytab_hostname,
};
use lldap_domain_handlers::logging::{
    LogKind, current_request, record, record_outcome, with_request_sync,
};
use std::collections::HashMap;
use std::panic::{self, AssertUnwindSafe};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::Duration;
use tokio::sync::{Mutex, mpsc};
use tracing::{Span, error, info};
use zeroize::Zeroizing;

const KADMIND_START: Duration = Duration::from_secs(10);
const USER_GONE: &str = "user gone";
const NO_SYNC: &str = "no sync";
const DISABLED_AT_START: &str =
    "disabled at start: a directory user without Kerberos sync has a principal";

pub struct EmbeddedKerberos {
    realm: String,
    domain: String,
    actor: String,
    store: SharedDump,
    host: Arc<dyn Host>,
    enctypes: Vec<KeySalt>,
    max_life: u32,
    max_renewable_life: u32,
    key_grace: u64,
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
    /// Opens the realm in the directory's database and starts the KDC and kadmind. It blocks on
    /// the database, so it runs off the async runtime's workers.
    pub fn start(
        settings: &RealmSettings,
        store: Arc<dyn lldap_domain_handlers::kerberos::KerberosStore>,
    ) -> Result<(Arc<Self>, RealmThreads)> {
        Self::start_on(settings, Arc::new(SqlRealm::new(store)))
    }

    pub(crate) fn start_on(
        settings: &RealmSettings,
        host: Arc<dyn Host>,
    ) -> Result<(Arc<Self>, RealmThreads)> {
        let OpenRealm {
            store,
            profile,
            acl,
            kdc_udp,
            kdc_tcp,
            kadmin,
        } = boot::open(settings, host.clone())?;
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
            "🎟️ Kerberos realm {} serving: kdc {}:{}, kadmin {}:{}",
            settings.realm,
            settings.kdc_host,
            settings.kdc_port,
            settings.kadmin_host,
            settings.kadmin_port
        );
        Ok((Arc::new(Self::new(store, settings, ready, host)), threads))
    }

    pub(crate) fn new(
        store: SharedDump,
        settings: &RealmSettings,
        ready: Arc<AtomicBool>,
        host: Arc<dyn Host>,
    ) -> Self {
        Self {
            realm: settings.realm.clone(),
            domain: settings.domain.clone(),
            actor: format!("admin/admin@{}", settings.realm),
            store,
            host,
            enctypes: settings
                .supported_enctypes
                .iter()
                .map(|&e| e.into())
                .collect(),
            max_life: u32::try_from(settings.ticket_lifetime).unwrap_or(u32::MAX),
            max_renewable_life: u32::try_from(settings.renew_lifetime).unwrap_or(u32::MAX),
            key_grace: settings.ticket_lifetime + settings.renew_lifetime,
            keycloak_keytab: settings.keycloak_keytab.clone(),
            ready,
            writes: Arc::new(Mutex::new(())),
        }
    }

    /// Brings krbtgt and every listed principal up to the realm's lifetimes, and the users to
    /// required pre-authentication. Returns how many were written and how many users have no
    /// principal; one that already matches is not written.
    pub async fn reconcile(&self, users: Vec<UserId>) -> Result<(usize, usize)> {
        let own = self.own();
        let max_life = u64::from(self.max_life);
        let max_renewable_life = u64::from(self.max_renewable_life);
        let serial = self.writes.clone().lock_owned().await;
        tokio::task::spawn_blocking(move || {
            let _serial = serial;
            let tgs = (PrincipalName::krbtgt(&own.realm), false);
            let names = std::iter::once(tgs).chain(users.iter().map(|u| (user_principal(u), true)));
            let (mut stale, mut missing) = (Vec::new(), 0);
            let mut store = own
                .store
                .write()
                .map_err(|_| anyhow!("the principal store was poisoned"))?;
            for (name, user) in names {
                let Some(principal) = store
                    .fetch_name(&name)
                    .map_err(|e| anyhow!("while reading principals: {e}"))?
                else {
                    missing += usize::from(user);
                    continue;
                };
                let preauth = principal.attributes | KDB_REQUIRES_PRE_AUTH;
                if (user && preauth != principal.attributes)
                    || principal.max_life != max_life
                    || principal.max_renewable_life != max_renewable_life
                {
                    let fields = AdminFields {
                        attributes: user.then_some(preauth),
                        max_life: Some(max_life),
                        max_renewable_life: Some(max_renewable_life),
                        ..Default::default()
                    };
                    stale.push((name, fields));
                }
            }
            if !stale.is_empty() {
                store
                    .change_committing(committing(own.host.as_ref()), |s| {
                        for (name, fields) in &stale {
                            s.apply_admin_fields_in(name, &own.realm, fields.clone(), &own.actor)?;
                        }
                        Ok::<_, StoreError>(())
                    })
                    .and_then(|changed| changed)
                    .map_err(|e| anyhow!("while reconciling principals: {e}"))?;
            }
            Ok((stale.len(), missing))
        })
        .await
        .context("the reconcile did not complete")?
    }

    /// The hourly purge of key versions no ticket can still need.
    pub async fn purge_old_keys(&self) -> Result<usize> {
        let own = self.own();
        let grace = self.key_grace;
        let serial = self.writes.clone().lock_owned().await;
        tokio::task::spawn_blocking(move || {
            let _serial = serial;
            let mut store = own
                .store
                .write()
                .map_err(|_| anyhow!("the principal store was poisoned"))?;
            let now = rotate::unix_now();
            rotate::purge_old_keys(&mut store, &own.realm, grace, now, &own.actor, &*own.host)
                .map_err(|e| anyhow!("while purging old Kerberos keys: {e}"))
        })
        .await
        .context("the purge did not complete")?
    }

    /// Once at start, before the listeners, on users read beforehand with their sync: marks each
    /// synced user's principal, removes a marked one no synced user has, and disables an
    /// unmarked one of a user without sync. A second run writes nothing.
    pub async fn start_pass(&self, users: Vec<(UserId, bool)>) -> Result<StartPass> {
        let own = self.own();
        let serial = self.writes.clone().lock_owned().await;
        let swept = tokio::task::spawn_blocking(move || {
            let _serial = serial;
            let directory: HashMap<String, bool> = users
                .into_iter()
                .map(|(user, sync)| (user.into_string(), sync))
                .collect();
            let mut store = own
                .store
                .write()
                .map_err(|_| anyhow!("the principal store was poisoned"))?;
            store
                .change_committing(committing(own.host.as_ref()), |s| {
                    let swept = sweep_plan(s, &own.realm, &directory);
                    for one in &swept {
                        match one.sweep {
                            Sweep::Mark => s.set_host_owned_in(&one.name, &own.realm, true)?,
                            Sweep::Remove(_) => s.remove_in(&one.name, &own.realm)?,
                            Sweep::Disable => {
                                s.set_status(&one.name, true, one.pw_expire, &own.actor)?;
                            }
                        }
                    }
                    Ok::<_, StoreError>(swept)
                })
                .and_then(|swept| swept)
                .map_err(|e| anyhow!("while sweeping the Kerberos principals at start: {e}"))
                .inspect(|_| own.host.start_pass_committed())
        })
        .await
        .context("the start pass did not complete")??;
        let mut pass = StartPass::default();
        for one in &swept {
            let target = Some(one.target.as_str());
            match one.sweep {
                Sweep::Mark => pass.marked += 1,
                Sweep::Remove(reason) => {
                    pass.removed += 1;
                    let detail = format!("removed at start: {reason}");
                    record(LogKind::KerberosSync, target, Some(&detail));
                }
                Sweep::Disable => {
                    pass.disabled += 1;
                    record(LogKind::KerberosSync, target, Some(DISABLED_AT_START));
                }
            }
        }
        if pass.marked > 0 {
            let detail = format!("marked at start: {} principals", pass.marked);
            record(LogKind::KerberosSync, None, Some(&detail));
        }
        Ok(pass)
    }

    fn own(&self) -> Own {
        Own {
            store: self.store.clone(),
            host: self.host.clone(),
            realm: self.realm.clone(),
            actor: self.actor.clone(),
        }
    }

    fn new_principal(&self) -> AdminEnt {
        AdminEnt {
            mask: kadm5_mask::ATTRIBUTES | kadm5_mask::MAX_LIFE | kadm5_mask::MAX_RLIFE,
            attributes: KDB_REQUIRES_PRE_AUTH,
            max_life: self.max_life,
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
        let own = self.own();
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
                set_password(&own, &name, &password, &enctypes, &ent)
                    .map_err(|e| anyhow!("while setting the Kerberos password: {e}"))
            },
        )
        .await
    }
    async fn delete_principal(&self, user: &UserId) -> Result<(), String> {
        let (own, name) = (self.own(), user_principal(user));
        logged(
            &self.writes,
            LogKind::KerberosSync,
            user.as_str(),
            "delete",
            move || match in_change(&own, |s| s.remove_in(&name, &own.realm)) {
                Ok(()) | Err(StoreError::NotFound) => Ok(()),
                Err(e) => Err(anyhow!("while deleting the principal: {e}")),
            },
        )
        .await
    }
    async fn set_principal_enabled(&self, user: &UserId, enabled: bool) -> Result<(), String> {
        let op = if enabled { "enable" } else { "disable" };
        let (own, name) = (self.own(), user_principal(user));
        logged(
            &self.writes,
            LogKind::KerberosSync,
            user.as_str(),
            op,
            move || {
                in_change(&own, |s| match s.fetch_name(&name)? {
                    Some(principal) => {
                        s.set_status(&name, !enabled, principal.pw_expire, &own.actor)
                    }
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
        let own = self.own();
        let (path, etypes) = (self.keycloak_keytab.clone(), self.enctypes.clone());
        let name = PrincipalName::new(PrincipalName::NT_SRV_HST, ["HTTP", host.as_str()]);
        logged(
            &self.writes,
            LogKind::KeytabExport,
            &host,
            "keycloak",
            move || {
                let keytab = in_change(&own, |s| {
                    if s.fetch_name(&name)?.is_none() {
                        s.insert_new_randkey(&name, &own.realm, &etypes, &own.actor)?;
                    }
                    s.chrand_etypes_keepold_in(&name, &own.realm, &etypes, 0, &own.actor)?;
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

// What a write of our own needs; kerber-rust hands its change to `committing`, as `Embedded`.
struct Own {
    store: SharedDump,
    host: Arc<dyn Host>,
    realm: String,
    actor: String,
}

fn set_password(
    own: &Own,
    name: &PrincipalName,
    password: &[u8],
    enctypes: &[KeySalt],
    ent: &AdminEnt,
) -> Result<(), StoreError> {
    let change = || {
        krb5_kdc::change_password_shared_committing(
            &own.store,
            name,
            &own.realm,
            password,
            0,
            &own.actor,
            enctypes,
            |_| Ok(()),
            committing(own.host.as_ref()),
        )
    };
    let mut next = after_change(change());
    if next == Next::Create {
        next = after_create(create_marked(own, name, password, enctypes, ent));
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

fn create_marked(
    own: &Own,
    name: &PrincipalName,
    password: &[u8],
    enctypes: &[KeySalt],
    ent: &AdminEnt,
) -> Result<(), StoreError> {
    let planned = {
        let (g, read) = krb5_kdc::read_fresh(&own.store);
        match read {
            Err(_) => None,
            Ok(()) => Some(g.plan_create_password(name, &own.realm, password, enctypes, ent)?),
        }
    };
    let prepared = planned.map(CreatePlan::derive).transpose()?;
    let mut store = own.store.write().map_err(|_| poisoned())?;
    store.change_committing(committing(own.host.as_ref()), |s| {
        let created = match prepared {
            Some(p) => s.create_prepared(p, &own.actor)?,
            None => false,
        };
        if !created {
            let keys = CreateKeys::Password(password);
            s.create_principal_3_in(name, &own.realm, keys, enctypes, ent, &own.actor)?;
        }
        s.set_host_owned_in(name, &own.realm, true)
    })?
}

fn in_change<T>(
    own: &Own,
    f: impl FnOnce(&mut PrincipalStore) -> Result<T, StoreError>,
) -> Result<T, StoreError> {
    let mut store = own.store.write().map_err(|_| poisoned())?;
    store.change_committing(committing(own.host.as_ref()), f)?
}

fn poisoned() -> StoreError {
    StoreError::InvalidArgument("the principal store was poisoned by a panic".to_owned())
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct StartPass {
    pub marked: usize,
    pub removed: usize,
    pub disabled: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Sweep {
    Mark,
    Remove(&'static str),
    Disable,
}

struct Swept {
    name: PrincipalName,
    target: String,
    pw_expire: u32,
    sweep: Sweep,
}

// `user` is the sync of the directory user the one-part name matches, or None.
fn sweep_of(owned: bool, locked: bool, user: Option<bool>) -> Option<Sweep> {
    match (owned, user) {
        (false, Some(true)) => Some(Sweep::Mark),
        (true, None) => Some(Sweep::Remove(USER_GONE)),
        (true, Some(false)) => Some(Sweep::Remove(NO_SYNC)),
        (false, Some(false)) if !locked => Some(Sweep::Disable),
        _ => None,
    }
}

fn sweep_plan(
    store: &PrincipalStore,
    realm: &str,
    directory: &HashMap<String, bool>,
) -> Vec<Swept> {
    store
        .ids()
        .iter()
        .filter_map(|id| store.get_raw(id))
        .filter(|p| p.realm == realm && p.alias_target().is_none())
        .filter_map(|p| {
            let user = (p.name.name_string.len() == 1)
                .then(|| p.name.try_components_joined())
                .flatten()
                .and_then(|one| directory.get(&one).copied());
            Some(Swept {
                name: p.name.clone(),
                target: p.name.unparse_no_realm_lossy(),
                pw_expire: p.pw_expire,
                sweep: sweep_of(p.host_owned(), p.locked(), user)?,
            })
        })
        .collect()
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
    use crate::seam::verdict;
    use krb5_crypto::EncryptionType;
    use krb5_kdc::KDB_DISALLOW_ALL_TIX;
    use krb5_kdc::host::{
        HostChange, KerberosStore, KerberosStoreError, LoadedRealm, MemoryRealm, Operation,
    };
    use lldap_domain_handlers::logging::{RequestMeta, with_request};
    use lldap_test_utils::recording_log::LogGuard;
    use pretty_assertions::assert_eq;
    use serial_test::serial;
    use std::collections::BTreeMap;
    use std::path::Path;
    use std::sync::atomic::AtomicUsize;

    /// kerber-rust's in-memory host with SqlRealm's verdict, keeping what reaches it.
    #[derive(Default)]
    pub(crate) struct Counting {
        pub(crate) realm: MemoryRealm,
        changes: std::sync::Mutex<Vec<Operation>>,
        own: AtomicUsize,
    }

    impl KerberosStore for Counting {
        fn load(&self) -> Result<LoadedRealm, KerberosStoreError> {
            self.realm.load()
        }
        fn commit_change(&self, change: HostChange) -> Result<(), KerberosStoreError> {
            self.changes.lock().unwrap().push(change.intent.operation);
            verdict(&change)?;
            self.realm.commit(change.batch)
        }
    }

    impl Host for Counting {
        fn write_own(&self, change: HostChange) -> Result<(), KerberosStoreError> {
            self.own.fetch_add(1, Ordering::Relaxed);
            self.realm.commit(change.batch)
        }

        fn start_pass_committed(&self) {}
    }

    pub(crate) struct TempRealm {
        pub settings: RealmSettings,
        pub host: Arc<Counting>,
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
                host: Arc::default(),
                settings: RealmSettings {
                    realm: "EXAMPLE.COM".to_owned(),
                    domain: "example.com".to_owned(),
                    ticket_lifetime: 86_400,
                    renew_lifetime: 604_800,
                    forwardable: true,
                    supported_enctypes: vec![EncryptionType::Aes256CtsHmacSha196],
                    kdc_host: "127.0.0.1".to_owned(),
                    kdc_port: 0,
                    kadmin_host: "127.0.0.1".to_owned(),
                    kadmin_port: 0,
                    kadmin_acl: None,
                    data_dir: dir.join("kdc"),
                    admin_keytab: dir.join("kadm5.keytab"),
                    keycloak_keytab: dir.join("keycloak.keytab"),
                    client_config: dir.join("krb5.conf"),
                    client_case_fold: false,
                },
            }
        }

        pub(crate) fn host(&self) -> Arc<dyn KerberosStore> {
            self.host.clone()
        }

        pub(crate) fn own(&self) -> Arc<dyn Host> {
            self.host.clone()
        }

        pub(crate) fn commits(&self) -> usize {
            self.changes().len() + self.own_writes()
        }

        pub(crate) fn changes(&self) -> Vec<Operation> {
            self.host.changes.lock().unwrap().clone()
        }

        pub(crate) fn own_writes(&self) -> usize {
            self.host.own.load(Ordering::Relaxed)
        }

        pub(crate) fn embedded(&self) -> (EmbeddedKerberos, SharedDump) {
            let profile = boot::profile(&self.settings);
            let opened = boot::open_store(&self.settings, &profile, self.host()).unwrap();
            let store = krb5_kdc::shared_dump(opened);
            let ready = Arc::new(AtomicBool::new(true));
            (
                EmbeddedKerberos::new(store.clone(), &self.settings, ready, self.own()),
                store,
            )
        }

        pub(crate) fn reopened(&self) -> PrincipalStore {
            boot::open_store(&self.settings, &boot::profile(&self.settings), self.host()).unwrap()
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
    #[serial]
    async fn test_disable_and_enable_keep_the_password_expiry() {
        let temp = TempRealm::new();
        let (embedded, store) = temp.embedded();
        let bob = UserId::new("bob");
        embedded
            .sync_principal(&bob, "Bob-Password-1")
            .await
            .unwrap();
        in_change(&embedded.own(), |s| {
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

    fn files(dir: &Path) -> BTreeMap<PathBuf, (Vec<u8>, std::time::SystemTime)> {
        std::fs::read_dir(dir)
            .unwrap()
            .map(|entry| {
                let path = entry.unwrap().path();
                let modified = std::fs::metadata(&path).unwrap().modified().unwrap();
                (path.clone(), (std::fs::read(&path).unwrap(), modified))
            })
            .collect()
    }

    #[tokio::test]
    #[serial]
    async fn test_a_boot_with_nothing_to_change_writes_nothing() {
        let temp = TempRealm::new();
        let (embedded, store) = temp.embedded();
        let bob = UserId::new("bob");
        embedded
            .sync_principal(&bob, "Bob-Password-1")
            .await
            .unwrap();
        let users = vec![bob, UserId::new("nobody")];
        embedded.reconcile(users.clone()).await.unwrap();
        let (before, commits) = (files(&temp.settings.data_dir), temp.commits());
        let again = embedded.reconcile(users).await.unwrap();
        let profile = boot::profile(&temp.settings);
        let mut reopened = boot::open_store(&temp.settings, &profile, temp.host()).unwrap();
        let own = temp.own();
        boot::rotate_keys(&mut reopened, &temp.settings, own.as_ref()).unwrap();
        boot::rotate_keys(&mut store.write().unwrap(), &temp.settings, own.as_ref()).unwrap();
        assert_eq!((again, temp.commits()), ((0, 1), commits));
        assert_eq!(files(&temp.settings.data_dir), before);
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
            let error = EmbeddedKerberos::start_on(&temp.settings, temp.own())
                .err()
                .unwrap();
            assert!(format!("{error:#}").contains(cause), "{error:#}");
        }
    }

    fn bob() -> UserId {
        UserId::new("bob")
    }

    fn marked(store: &SharedDump, user: &str) -> Option<(bool, bool)> {
        let name = user_principal(&UserId::new(user));
        let guard = store.read().unwrap();
        let principal = guard.get_name(&name)?;
        Some((principal.host_owned(), principal.locked()))
    }

    pub(crate) fn unmarked(embedded: &EmbeddedKerberos, user: &str, locked: bool) {
        let name = user_principal(&UserId::new(user));
        in_change(&embedded.own(), |s| {
            s.insert_new_randkey(&name, "EXAMPLE.COM", &[], "test")?;
            s.set_status(&name, locked, 0, "test")
        })
        .unwrap();
    }

    #[tokio::test]
    #[serial]
    async fn test_each_own_write_commits_through_the_closure() {
        let temp = TempRealm::new();
        let (embedded, _store) = temp.embedded();
        unmarked(&embedded, "carol", false);
        let carol = UserId::new("carol");
        let mut seen = temp.own_writes();
        let sites = [
            "sync, create",
            "sync, change",
            "disable",
            "enable",
            "reconcile",
            "keytab",
            "start pass",
            "delete",
        ];
        for site in sites {
            match site {
                "sync, create" | "sync, change" => {
                    embedded
                        .sync_principal(&bob(), "Bob-Password-1")
                        .await
                        .unwrap();
                }
                "disable" => embedded.set_principal_enabled(&bob(), false).await.unwrap(),
                "enable" => embedded.set_principal_enabled(&bob(), true).await.unwrap(),
                "reconcile" => {
                    embedded.reconcile(vec![carol.clone()]).await.unwrap();
                }
                "keytab" => {
                    embedded.export_keytab_for_keycloak("").await.unwrap();
                }
                "start pass" => {
                    let users = vec![(bob(), true), (carol.clone(), true)];
                    embedded.start_pass(users).await.unwrap();
                }
                "delete" => embedded.delete_principal(&bob()).await.unwrap(),
                _ => unreachable!(),
            }
            let now = temp.own_writes();
            assert_eq!(
                (temp.changes(), now > seen),
                (vec![Operation::Bootstrap], true),
                "{site}"
            );
            seen = now;
        }
    }

    #[tokio::test]
    #[serial]
    async fn test_a_synced_create_is_marked_in_its_own_change() {
        let temp = TempRealm::new();
        let (embedded, store) = temp.embedded();
        let before = temp.own_writes();
        embedded
            .sync_principal(&bob(), "Bob-Password-1")
            .await
            .unwrap();
        embedded
            .sync_principal(&bob(), "Bob-Password-2")
            .await
            .unwrap();
        let reopened = temp.reopened();
        let kept = reopened
            .get_name(&user_principal(&bob()))
            .map(|p| p.host_owned());
        assert_eq!(
            (temp.own_writes() - before, marked(&store, "bob"), kept),
            (2, Some((true, false)), Some(true))
        );
    }

    #[test]
    fn test_what_the_start_pass_does_with_each_principal() {
        type Row = (&'static str, bool, bool, Option<bool>, Option<Sweep>);
        let rows: [Row; 9] = [
            (
                "synced, unmarked",
                false,
                false,
                Some(true),
                Some(Sweep::Mark),
            ),
            (
                "synced and disabled",
                false,
                true,
                Some(true),
                Some(Sweep::Mark),
            ),
            ("synced, marked", true, false, Some(true), None),
            (
                "marked, user gone",
                true,
                false,
                None,
                Some(Sweep::Remove(USER_GONE)),
            ),
            (
                "marked, disabled, gone",
                true,
                true,
                None,
                Some(Sweep::Remove(USER_GONE)),
            ),
            (
                "marked, no sync",
                true,
                false,
                Some(false),
                Some(Sweep::Remove(NO_SYNC)),
            ),
            (
                "unmarked, no sync",
                false,
                false,
                Some(false),
                Some(Sweep::Disable),
            ),
            (
                "unmarked, no sync, disabled",
                false,
                true,
                Some(false),
                None,
            ),
            ("unmarked, no user", false, false, None, None),
        ];
        for (row, owned, locked, user, expected) in rows {
            assert_eq!(sweep_of(owned, locked, user), expected, "{row}");
        }
    }

    #[tokio::test]
    #[serial]
    async fn test_the_start_pass_marks_removes_and_disables_once() {
        let guard = LogGuard::install();
        let temp = TempRealm::new();
        let (embedded, store) = temp.embedded();
        for user in ["alice", "gone", "nosync"] {
            embedded
                .sync_principal(&UserId::new(user), "A-Password-1")
                .await
                .unwrap();
        }
        unmarked(&embedded, "carol", false);
        unmarked(&embedded, "dave", false);
        unmarked(&embedded, "eve", true);
        unmarked(&embedded, "foreign", false);
        let users: Vec<(UserId, bool)> = [
            ("alice", true),
            ("carol", true),
            ("nosync", false),
            ("dave", false),
            ("eve", false),
            ("frank", true),
        ]
        .into_iter()
        .map(|(user, sync)| (UserId::new(user), sync))
        .collect();
        guard.recorder().take_events();

        let pass = embedded.start_pass(users.clone()).await.unwrap();
        let after: Vec<_> = ["alice", "carol", "gone", "nosync", "dave", "eve", "foreign"]
            .into_iter()
            .map(|user| (user, marked(&store, user)))
            .collect();
        assert_eq!(
            (pass, after),
            (
                StartPass {
                    marked: 1,
                    removed: 2,
                    disabled: 1
                },
                vec![
                    ("alice", Some((true, false))),
                    ("carol", Some((true, false))),
                    ("gone", None),
                    ("nosync", None),
                    ("dave", Some((false, true))),
                    ("eve", Some((false, true))),
                    ("foreign", Some((false, false))),
                ]
            )
        );
        let rows: Vec<_> = guard
            .recorder()
            .take_events()
            .into_iter()
            .map(|e| (e.target, e.detail))
            .collect();
        let row = |target: Option<&str>, detail: &str| {
            (target.map(str::to_owned), Some(detail.to_owned()))
        };
        assert_eq!(
            rows,
            vec![
                row(Some("dave"), DISABLED_AT_START),
                row(Some("gone"), "removed at start: user gone"),
                row(Some("nosync"), "removed at start: no sync"),
                row(None, "marked at start: 1 principals"),
            ]
        );

        let (writes, changes) = (temp.own_writes(), temp.changes());
        let again = embedded.start_pass(users).await.unwrap();
        assert_eq!(
            (
                again,
                temp.own_writes(),
                temp.changes(),
                guard.recorder().take_events()
            ),
            (StartPass::default(), writes, changes, Vec::new())
        );
        let reopened = temp.reopened();
        assert!(
            reopened
                .get_name(&user_principal(&UserId::new("carol")))
                .is_some_and(|p| p.host_owned()),
            "the upgrade's mark survives a reload"
        );
    }
}
