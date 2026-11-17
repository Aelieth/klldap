use crate::boot::{self, OpenRealm, RealmSettings};
use crate::rotate;
pub use crate::seam::Records;
use crate::seam::{Host, SqlRealm, committing, committing_with, stored_aliases};
use anyhow::{Context, Result, anyhow};
use async_trait::async_trait;
use krb5_admin::{
    Kadmind, KadmindConfig, Listeners, Programs, ServeLimits, Services, TracingAdmin,
};
use krb5_config::KadmindListen;
use krb5_crypto::KeySalt;
use krb5_kdc::host::{HostChange, KerberosStoreError};
use krb5_kdc::{
    AdminEnt, AdminFields, CreateKeys, CreatePlan, Error as StoreError, KDB_DISALLOW_ALL_TIX,
    KDB_REQUIRES_PRE_AUTH, KdcLog, ListenLimits, PasswordPlan, PrincipalRead, PrincipalStore,
    SharedDump, SharedStore, Shutdown, kadm5_mask, lookup_principal_id,
};
use krb5_types::PrincipalName;
use lldap_domain::types::UserId;
use lldap_domain_handlers::kerberos::{
    CommitError, HostRow, KerberosSync, PasswordCommit, UNREAD_AFTER_COMMIT,
    USER_GONE as NO_USER_ROW, validate_kerberos_username, validate_keytab_hostname,
};
use lldap_domain_handlers::logging::{
    self, LogKind, current_request, record, record_outcome, with_request_sync,
};
use lldap_domain_handlers::password::{kill_point, record_commit_failure, record_unreported};
use std::collections::HashMap;
use std::panic::{self, AssertUnwindSafe};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, PoisonError};
use std::thread::{self, JoinHandle};
use std::time::Duration;
use tokio::sync::{Mutex, mpsc};
use tracing::{Span, error, info};
use zeroize::Zeroizing;

const KADMIND_START: Duration = Duration::from_secs(10);
const WRITE_WAIT: Duration = Duration::from_secs(10);
const USER_GONE: &str = "user gone";
const NO_SYNC: &str = "no sync";
const DISABLED_AT_START: &str =
    "disabled at start: a directory user without Kerberos sync has a principal";
const STATE_UNREAD: &str = "the user's lldap_disabled membership was not read";
const START_CHUNK: usize = 100;

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
    write_wait: Duration,
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
        records: Records,
    ) -> Result<(Arc<Self>, RealmThreads)> {
        let host = SqlRealm::new(store).serving(&settings.realm, Some(records));
        Self::start_on(settings, Arc::new(host))
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
        {
            let (opened, _) = krb5_kdc::read_fresh(&store);
            host.seed_aliases(stored_aliases(&opened, &settings.realm));
        }
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
            write_wait: WRITE_WAIT,
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
            let mut store = own
                .store
                .write()
                .map_err(|_| anyhow!("the principal store was poisoned"))?;
            let tgs = (PrincipalName::krbtgt(&own.realm), false);
            let users = users
                .iter()
                .filter(|u| alias_of(&store, &own.realm, u).is_none());
            let names = std::iter::once(tgs).chain(users.map(|u| (user_principal(u), true)));
            let (mut stale, mut missing) = (Vec::new(), 0);
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

    /// At each start, before the listeners, on users read beforehand with their sync: marks each
    /// synced user's principal, removes a marked one no synced user has, and disables an
    /// unmarked one of a user without sync, `START_CHUNK` per change. A second run writes nothing.
    pub async fn start_pass(&self, users: Vec<(UserId, bool)>) -> Result<StartPass> {
        self.start_pass_in(users, START_CHUNK).await
    }

    async fn start_pass_in(&self, users: Vec<(UserId, bool)>, chunk: usize) -> Result<StartPass> {
        let own = self.own();
        let serial = self.writes.clone().lock_owned().await;
        let (swept, aliases) = tokio::task::spawn_blocking(move || {
            let _serial = serial;
            let (swept, aliases) = {
                let store = own
                    .store
                    .read()
                    .map_err(|_| anyhow!("the principal store was poisoned"))?;
                let aliases: Vec<_> = users
                    .iter()
                    .filter_map(|(user, _)| {
                        Some((user.clone(), alias_of(&store, &own.realm, user)?))
                    })
                    .collect();
                let directory: HashMap<String, bool> = users
                    .into_iter()
                    .map(|(user, sync)| (user.into_string(), sync))
                    .collect();
                (sweep_plan(&store, &own.realm, &directory), aliases)
            };
            for part in swept.chunks(chunk) {
                let mut store = own
                    .store
                    .write()
                    .map_err(|_| anyhow!("the principal store was poisoned"))?;
                store
                    .change_committing(committing(own.host.as_ref()), |s| {
                        for one in part {
                            match one.sweep {
                                Sweep::Mark => s.set_host_owned_in(&one.name, &own.realm, true)?,
                                Sweep::Remove(_) => s.remove_in(&one.name, &own.realm)?,
                                Sweep::Disable => {
                                    s.set_status(&one.name, true, one.pw_expire, &own.actor)?;
                                }
                            }
                        }
                        Ok::<_, StoreError>(())
                    })
                    .and_then(|done| done)
                    .map_err(|e| anyhow!("while sweeping the Kerberos principals at start: {e}"))?;
            }
            own.host.start_pass_committed();
            Ok::<_, anyhow::Error>((swept, aliases))
        })
        .await
        .context("the start pass did not complete")??;
        for (user, target) in &aliases {
            let detail = aliased(user, target);
            record(LogKind::KerberosSync, Some(user.as_str()), Some(&detail));
        }
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

impl EmbeddedKerberos {
    /// A user whose principal name is an alias: the store is not touched, and one row says so.
    async fn skipped_as_alias(&self, user: &UserId, op: &str) -> Result<bool, String> {
        let (store, realm, id) = (self.store.clone(), self.realm.clone(), user.clone());
        let alias = read_store(move || {
            let (store, fresh) = krb5_kdc::read_fresh(&store);
            fresh?;
            Ok(alias_of(&store, &realm, &id))
        })
        .await?;
        let Some(target) = alias else {
            return Ok(false);
        };
        let detail = format!("{}: {op} skipped", aliased(user, &target));
        record(LogKind::KerberosSync, Some(user.as_str()), Some(&detail));
        Ok(true)
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
        let (id, enctypes, ent) = (user.clone(), self.enctypes.clone(), self.new_principal());
        let password = Zeroizing::new(password.as_bytes().to_vec());
        logged(
            &self.writes,
            LogKind::KerberosSync,
            user.as_str(),
            "sync",
            move || {
                set_password(&own, &id, &password, &enctypes, &ent, None, || {
                    committing(own.host.as_ref())
                })
                .map_err(|e| anyhow!("while setting the Kerberos password: {e}"))
            },
        )
        .await
    }
    async fn check_password(&self, user: &UserId, password: &str) -> Result<(), String> {
        validate_kerberos_username(user.as_str())?;
        let (store, realm, id) = (self.store.clone(), self.realm.clone(), user.clone());
        let password = Zeroizing::new(password.as_bytes().to_vec());
        read_store(move || {
            let (store, fresh) = krb5_kdc::read_fresh(&store);
            fresh?;
            not_an_alias(&store, &realm, &id)?;
            store.check_password_quality(&user_principal(&id), &password)
        })
        .await
    }
    async fn commit_password(
        &self,
        change: PasswordCommit,
        password: &str,
    ) -> Result<(), CommitError> {
        let (kind, user) = (change.kind, change.user.clone());
        if let Err(why) = validate_kerberos_username(user.as_str()) {
            let refused = CommitError::Refused(why);
            record_commit_failure(kind, &user, &refused);
            return Err(refused);
        }
        let (own, enctypes, ent) = (self.own(), self.enctypes.clone(), self.new_principal());
        let password = Zeroizing::new(password.as_bytes().to_vec());
        let serial = tokio::time::timeout(self.write_wait, self.writes.clone().lock_owned())
            .await
            .map_err(|_| CommitError::Busy)?;
        let (span, meta) = (Span::current(), current_request());
        let worker = user.clone();
        tokio::task::spawn_blocking(move || {
            let _serial = serial;
            span.in_scope(|| {
                with_request_sync(meta, || {
                    let printed = logged_rows(&change.rows);
                    let done = panic::catch_unwind(AssertUnwindSafe(|| {
                        commit_owned(&own, &password, &enctypes, &ent, change)
                    }));
                    match &done {
                        Ok(Ok(())) => printed.iter().for_each(logging::print),
                        Ok(Err(e)) => record_commit_failure(kind, &worker, e),
                        Err(_) => record_unreported(kind, &worker, PANICKED),
                    }
                    done.unwrap_or_else(|_| Err(CommitError::Unknown(PANICKED.to_owned())))
                })
            })
        })
        .await
        .unwrap_or_else(|e| {
            let cause = format!("the password change did not run: {e}");
            record_unreported(kind, &user, &cause);
            Err(CommitError::Unknown(cause))
        })
    }
    async fn delete_principal(&self, user: &UserId) -> Result<(), String> {
        if self.skipped_as_alias(user, "delete").await? {
            return Ok(());
        }
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
        if self.skipped_as_alias(user, op).await? {
            return Ok(());
        }
        let (own, name, id) = (self.own(), user_principal(user), user.clone());
        logged(
            &self.writes,
            LogKind::KerberosSync,
            user.as_str(),
            op,
            move || {
                in_change(&own, |s| {
                    not_an_alias(s, &own.realm, &id)?;
                    match s.fetch_name(&name)? {
                        Some(principal) => {
                            s.set_status(&name, !enabled, principal.pw_expire, &own.actor)
                        }
                        None => Ok(()),
                    }
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

// `commit` makes each attempt's closure; at most one of them reaches the host. `locked` is the
// directory's state for an existing principal, set with its keys; None leaves its status.
fn set_password<C>(
    own: &Own,
    user: &UserId,
    password: &[u8],
    enctypes: &[KeySalt],
    ent: &AdminEnt,
    locked: Option<bool>,
    commit: impl Fn() -> C,
) -> Result<(), StoreError>
where
    C: FnOnce(HostChange) -> Result<(), KerberosStoreError>,
{
    let name = user_principal(user);
    let change = || match locked {
        Some(locked) => change_following(own, user, password, enctypes, locked, commit()),
        None => krb5_kdc::change_password_shared_committing(
            &own.store,
            &name,
            &own.realm,
            password,
            0,
            &own.actor,
            enctypes,
            |s| not_an_alias(s, &own.realm, user),
            commit(),
        ),
    };
    let mut next = after_change(change());
    if next == Next::Create {
        next = after_create(create_marked(own, user, password, enctypes, ent, commit()));
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

// kerber-rust v1.2.3-rc.1 `change_password_shared_committing` (crates/krb5-kdc/src/store/
// password.rs:300-332) with the status set to the directory's in the same change.
fn change_following(
    own: &Own,
    user: &UserId,
    password: &[u8],
    enctypes: &[KeySalt],
    locked: bool,
    commit: impl FnOnce(HostChange) -> Result<(), KerberosStoreError>,
) -> Result<(), StoreError> {
    let name = user_principal(user);
    let planned = {
        let (g, read) = krb5_kdc::read_fresh(&own.store);
        match read {
            Err(_) => Ok(None),
            Ok(()) => not_an_alias(&g, &own.realm, user)
                .and_then(|()| g.plan_password(&name, &own.realm, password, enctypes)),
        }
    };
    let prepared = planned.and_then(|plan| plan.map(PasswordPlan::derive).transpose())?;
    let mut store = own.store.write().unwrap_or_else(PoisonError::into_inner);
    store.change_committing(commit, |s| {
        let applied = match prepared {
            Some(p) => s.apply_password(p, 0, &own.actor)?,
            None => false,
        };
        if !applied {
            not_an_alias(s, &own.realm, user)?;
            s.set_password_etypes_keepold_n_in(
                &name, &own.realm, password, 0, &own.actor, enctypes,
            )?;
        }
        let now = s.get_name(&name).map(|p| (p.locked(), p.pw_expire));
        match now {
            Some((was, pw_expire)) if was != locked => {
                s.set_status(&name, locked, pw_expire, &own.actor)
            }
            _ => Ok(()),
        }
    })?
}

fn create_marked(
    own: &Own,
    user: &UserId,
    password: &[u8],
    enctypes: &[KeySalt],
    ent: &AdminEnt,
    commit: impl FnOnce(HostChange) -> Result<(), KerberosStoreError>,
) -> Result<(), StoreError> {
    let name = user_principal(user);
    let planned = {
        let (g, read) = krb5_kdc::read_fresh(&own.store);
        match read {
            Err(_) => None,
            Ok(()) => Some(g.plan_create_password(&name, &own.realm, password, enctypes, ent)?),
        }
    };
    let prepared = planned.map(CreatePlan::derive).transpose()?;
    let mut store = own.store.write().map_err(|_| poisoned())?;
    store.change_committing(commit, |s| {
        not_an_alias(s, &own.realm, user)?;
        let created = match prepared {
            Some(p) => s.create_prepared(p, &own.actor)?,
            None => false,
        };
        if !created {
            let keys = CreateKeys::Password(password);
            s.create_principal_3_in(&name, &own.realm, keys, enctypes, ent, &own.actor)?;
        }
        s.set_host_owned_in(&name, &own.realm, true)
    })?
}

const PANICKED: &str = "the password change panicked";

fn logged_rows(rows: &[HostRow]) -> Vec<logging::LogEvent> {
    rows.iter()
        .filter_map(|row| match row {
            HostRow::Log(event) => Some(event.clone()),
            _ => None,
        })
        .collect()
}

// A synced user's change from step 5 on, on the blocking task that owns the `writes` guard.
fn commit_owned(
    own: &Own,
    password: &[u8],
    enctypes: &[KeySalt],
    ent: &AdminEnt,
    change: PasswordCommit,
) -> Result<(), CommitError> {
    let PasswordCommit { user, rows, .. } = change;
    let disabled = own
        .host
        .user_disabled(&user)
        .map_err(|e| CommitError::Failed(format!("{STATE_UNREAD}: {e}")))?;
    let mut ent = ent.clone();
    if disabled {
        ent.attributes |= KDB_DISALLOW_ALL_TIX;
    }
    let made = set_password(own, &user, password, enctypes, &ent, Some(disabled), || {
        committing_with(own.host.as_ref(), rows.clone())
    });
    if let Err(StoreError::InvalidArgument(why)) = &made
        && why.starts_with(&aliased(&user, ""))
    {
        return Err(CommitError::Refused(why.clone()));
    }
    made.map_err(commit_error)?;
    kill_point("kerberos-changed");
    Ok(())
}

fn commit_error(e: StoreError) -> CommitError {
    match e {
        StoreError::Host(KerberosStoreError::Failed(why))
            if why.starts_with(UNREAD_AFTER_COMMIT) =>
        {
            CommitError::Unknown(why)
        }
        StoreError::Host(KerberosStoreError::Failed(why) | KerberosStoreError::NotReady(why)) => {
            CommitError::Failed(why)
        }
        StoreError::Host(KerberosStoreError::Refused(why)) if why == NO_USER_ROW => {
            CommitError::UserGone
        }
        e @ (StoreError::PasswordPolicy(_) | StoreError::PassTooSoon { .. }) => {
            CommitError::Refused(e.to_string())
        }
        e => CommitError::Failed(e.to_string()),
    }
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

/// The principal that `user`'s own name is an alias record of, read unresolved.
pub(crate) fn alias_of(store: &PrincipalStore, realm: &str, user: &UserId) -> Option<String> {
    let id = lookup_principal_id(&user_principal(user), realm)?;
    store.get_raw(&id)?.alias_target()
}

fn aliased(user: &UserId, target: &str) -> String {
    format!(
        "the principal name of user {} is an alias of {target}",
        user.as_str()
    )
}

fn not_an_alias(store: &PrincipalStore, realm: &str, user: &UserId) -> Result<(), StoreError> {
    match alias_of(store, realm, user) {
        Some(target) => Err(StoreError::InvalidArgument(aliased(user, &target))),
        None => Ok(()),
    }
}

// A read waits for the write lock behind it, so it runs off the async workers too.
async fn read_store<T: Send + 'static>(
    f: impl FnOnce() -> Result<T, StoreError> + Send + 'static,
) -> Result<T, String> {
    tokio::task::spawn_blocking(move || f().map_err(|e| e.to_string()))
        .await
        .unwrap_or_else(|e| Err(format!("Kerberos call did not complete: {e}")))
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
    use crate::seam::{Verdict, verdict};
    use krb5_crypto::EncryptionType;
    use krb5_kdc::KDB_DISALLOW_ALL_TIX;
    use krb5_kdc::host::{
        Denial, HostChange, KerberosStore, KerberosStoreError, LoadedRealm, MemoryRealm, Operation,
    };
    use lldap_domain_handlers::kerberos::HostRow;
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
        started_at: std::sync::Mutex<Option<usize>>,
        rows: std::sync::Mutex<Vec<String>>,
        records: std::sync::Mutex<HashMap<String, Vec<u8>>>,
        fault: std::sync::Mutex<Option<Fault>>,
        disabled: std::sync::Mutex<Vec<String>>,
        unread: AtomicBool,
        delay: std::sync::Mutex<Duration>,
    }

    /// What the committer answers after its own read-back; nothing is written.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) enum Fault {
        Failed,
        Unknown,
        UserGone,
        Panic,
    }

    impl Counting {
        pub(crate) fn set_fault(&self, fault: Option<Fault>) {
            *self.fault.lock().unwrap() = fault;
        }

        pub(crate) fn set_delay(&self, delay: Duration) {
            *self.delay.lock().unwrap() = delay;
        }

        pub(crate) fn password_record(&self, user: &UserId) -> Option<Vec<u8>> {
            self.records.lock().unwrap().get(user.as_str()).cloned()
        }

        pub(crate) fn rows(&self) -> Vec<String> {
            self.rows.lock().unwrap().clone()
        }

        pub(crate) fn set_directory(&self, disabled: Option<&[&str]>) {
            self.unread.store(disabled.is_none(), Ordering::Relaxed);
            let users = disabled.unwrap_or_default().iter().map(|u| (*u).to_owned());
            *self.disabled.lock().unwrap() = users.collect();
        }

        fn fault(&self) -> Option<Fault> {
            *self.fault.lock().unwrap()
        }
    }

    fn unanswered_db() -> KerberosStoreError {
        KerberosStoreError::Failed("the database did not answer".to_owned())
    }

    fn unread_db() -> KerberosStoreError {
        KerberosStoreError::Failed(format!(
            "{UNREAD_AFTER_COMMIT}: the database did not answer"
        ))
    }

    impl KerberosStore for Counting {
        fn load(&self) -> Result<LoadedRealm, KerberosStoreError> {
            self.realm.load()
        }
        fn commit_change(&self, change: HostChange) -> Result<(), KerberosStoreError> {
            self.changes.lock().unwrap().push(change.intent.operation);
            if let Verdict::Deny { code, .. } = verdict(&change, "EXAMPLE.COM")? {
                return Err(KerberosStoreError::Denied(Denial {
                    kadm5_code: code,
                    text: String::new(),
                }));
            }
            self.realm.commit(change.batch)
        }
    }

    impl Host for Counting {
        fn write_own(
            &self,
            change: HostChange,
            rows: Vec<HostRow>,
        ) -> Result<(), KerberosStoreError> {
            self.own.fetch_add(1, Ordering::Relaxed);
            std::thread::sleep(*self.delay.lock().unwrap());
            match self.fault() {
                Some(Fault::Failed) => return Err(unanswered_db()),
                Some(Fault::Unknown) => return Err(unread_db()),
                Some(Fault::UserGone) => {
                    return Err(KerberosStoreError::Refused(NO_USER_ROW.to_owned()));
                }
                Some(Fault::Panic) | None => {}
            }
            self.realm.commit(change.batch)?;
            for row in &rows {
                if let HostRow::SetPassword { user, record, .. } = row {
                    let mut records = self.records.lock().unwrap();
                    records.insert(user.as_str().to_owned(), record.clone());
                }
            }
            self.rows
                .lock()
                .unwrap()
                .extend(rows.iter().map(HostRow::label));
            Ok(())
        }

        fn user_disabled(&self, user: &UserId) -> Result<bool, KerberosStoreError> {
            if self.fault() == Some(Fault::Panic) {
                panic!("the test host panicked");
            }
            if self.unread.load(Ordering::Relaxed) {
                return Err(unanswered_db());
            }
            Ok(self
                .disabled
                .lock()
                .unwrap()
                .iter()
                .any(|u| u == user.as_str()))
        }

        fn start_pass_committed(&self) {
            *self.started_at.lock().unwrap() = Some(self.own.load(Ordering::Relaxed));
        }
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

    impl EmbeddedKerberos {
        pub(crate) async fn hold_writes(&self) -> tokio::sync::OwnedMutexGuard<()> {
            self.writes.clone().lock_owned().await
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

    #[tokio::test]
    #[serial]
    async fn test_the_start_pass_commits_in_chunks_and_sets_the_flag_after_the_last() {
        let temp = TempRealm::new();
        let (embedded, store) = temp.embedded();
        let names = ["u1", "u2", "u3", "u4", "u5"];
        for user in names {
            unmarked(&embedded, user, false);
        }
        let users: Vec<_> = names.iter().map(|u| (UserId::new(u), true)).collect();
        let before = temp.own_writes();
        let pass = embedded.start_pass_in(users.clone(), 2).await.unwrap();
        let after: Vec<_> = names.iter().map(|u| marked(&store, u)).collect();
        let flagged_at = temp.host.started_at.lock().unwrap().take();
        assert_eq!(
            (pass.marked, temp.own_writes() - before, flagged_at, after),
            (5, 3, Some(temp.own_writes()), vec![Some((true, false)); 5])
        );
        let again = embedded.start_pass_in(users, 2).await.unwrap();
        assert_eq!(
            (again, temp.own_writes() - before),
            (StartPass::default(), 3),
            "a second start writes nothing"
        );
    }

    fn fields(store: &SharedDump, user: &str) -> Option<(u32, u64, bool, Option<u32>)> {
        let guard = store.read().unwrap();
        let p = guard.get_name(&user_principal(&UserId::new(user)))?;
        let kvno = p.keys.iter().map(|k| k.kvno).max();
        Some((p.attributes, p.max_life, p.locked(), kvno))
    }

    #[tokio::test]
    #[serial]
    async fn test_a_user_name_that_is_an_alias_is_never_written_through() {
        let guard = LogGuard::install();
        let temp = TempRealm::new();
        let (embedded, store) = temp.embedded();
        unmarked(&embedded, "svc", false);
        let aliases = [("bob", "svc"), ("carl", "nobody")];
        for (alias, target) in aliases {
            let name = |user| user_principal(&UserId::new(user));
            in_change(&embedded.own(), |s| {
                s.create_alias_in(
                    &name(alias),
                    "EXAMPLE.COM",
                    &name(target),
                    "EXAMPLE.COM",
                    "test",
                )
            })
            .unwrap();
        }
        embedded.reconcile(Vec::new()).await.unwrap();
        let (writes, svc) = (temp.own_writes(), fields(&store, "svc"));
        let users: Vec<_> = aliases
            .iter()
            .map(|(alias, _)| UserId::new(alias))
            .collect();
        let sentences: Vec<_> = aliases
            .iter()
            .map(|(a, t)| format!("the principal name of user {a} is an alias of {t}@EXAMPLE.COM"))
            .collect();
        let mut named = Vec::new();
        for (user, why) in users.iter().zip(&sentences) {
            let synced = embedded.sync_principal(user, "A-Password-1").await;
            guard.recorder().take_events();
            let disabled = embedded.set_principal_enabled(user, false).await;
            let skipped: Vec<_> = guard
                .recorder()
                .take_events()
                .into_iter()
                .map(|e| (e.target, e.detail))
                .collect();
            let deleted = embedded.delete_principal(user).await;
            let delete_rows: Vec<_> = guard
                .recorder()
                .take_events()
                .into_iter()
                .map(|e| (e.target, e.detail))
                .collect();
            let row = |op: &str| {
                vec![(
                    Some(user.as_str().to_owned()),
                    Some(format!("{why}: {op} skipped")),
                )]
            };
            named.push((
                synced.unwrap_err().ends_with(why.as_str()),
                disabled.is_ok() && skipped == row("disable"),
                deleted.is_ok() && delete_rows == row("delete"),
            ));
        }
        let reconciled = embedded.reconcile(users.clone()).await.unwrap();
        guard.recorder().take_events();
        let synced = users.iter().map(|u| (u.clone(), true)).collect();
        let pass = embedded.start_pass(synced).await.unwrap();
        let rows: Vec<_> = guard
            .recorder()
            .take_events()
            .into_iter()
            .map(|e| (e.target, e.detail))
            .collect();
        let raw: Vec<_> = aliases
            .iter()
            .map(|(alias, _)| {
                let read = store.read().unwrap();
                let p = read.get_raw(&format!("{alias}@EXAMPLE.COM"))?;
                Some((p.alias_target(), p.host_owned()))
            })
            .collect();
        assert_eq!(
            (
                named,
                reconciled,
                pass,
                temp.own_writes(),
                fields(&store, "svc")
            ),
            (
                vec![(true, true, true); 2],
                (0, 0),
                StartPass::default(),
                writes,
                svc
            )
        );
        let expected_rows: Vec<_> = aliases
            .iter()
            .zip(&sentences)
            .map(|((alias, _), why)| (Some((*alias).to_owned()), Some(why.clone())))
            .collect();
        let expected_raw = vec![
            Some((Some("svc@EXAMPLE.COM".to_owned()), false)),
            Some((Some("nobody@EXAMPLE.COM".to_owned()), false)),
        ];
        assert_eq!((rows, raw), (expected_rows, expected_raw));
    }

    fn commit_of(user: &str, record: &[u8]) -> PasswordCommit {
        use lldap_domain_handlers::logging::event;
        PasswordCommit {
            user: UserId::new(user),
            kind: LogKind::PasswordChange,
            rows: vec![
                HostRow::SetPassword {
                    user: UserId::new(user),
                    record: record.to_vec(),
                    now: chrono::Utc::now().naive_utc(),
                },
                HostRow::Log(event(LogKind::PasswordChange, Some(user), true, None)),
            ],
        }
    }

    fn kvno_in(store: &PrincipalStore, user: &str) -> Option<u32> {
        store
            .get_name(&user_principal(&UserId::new(user)))
            .and_then(|p| p.top_kvno())
    }

    #[tokio::test]
    #[serial]
    async fn test_each_answer_of_the_commit_and_what_the_door_learns() {
        const RECORD: &[u8] = b"record-2";
        type Row = (&'static str, Option<Fault>, Result<(), CommitError>, bool);
        let rows: [Row; 4] = [
            (
                "committed, or its lost answer read back as written",
                None,
                Ok(()),
                true,
            ),
            (
                "failed: the record read back is not this one",
                Some(Fault::Failed),
                Err(CommitError::Failed(
                    "the database did not answer".to_owned(),
                )),
                false,
            ),
            (
                "unknown: the record could not be read back",
                Some(Fault::Unknown),
                Err(CommitError::Unknown(format!(
                    "{UNREAD_AFTER_COMMIT}: the database did not answer"
                ))),
                false,
            ),
            (
                "the user was deleted in between",
                Some(Fault::UserGone),
                Err(CommitError::UserGone),
                false,
            ),
        ];
        for (label, fault, expected, new) in rows {
            let temp = TempRealm::new();
            let (embedded, store) = temp.embedded();
            embedded
                .sync_principal(&bob(), "Bob-Password-1")
                .await
                .unwrap();
            let old = kvno_in(&store.read().unwrap(), "bob").unwrap();
            temp.host.set_fault(fault);
            let got = embedded
                .commit_password(commit_of("bob", RECORD), "Bob-Password-2")
                .await;
            temp.host.set_fault(None);
            let kvno = old + u32::from(new);
            let stored = temp.host.password_record(&bob());
            assert_eq!(
                (
                    got,
                    kvno_in(&store.read().unwrap(), "bob"),
                    kvno_in(&temp.reopened(), "bob"),
                    stored.as_deref() == Some(RECORD),
                ),
                (expected, Some(kvno), Some(kvno), new),
                "{label}"
            );
        }
    }

    #[test]
    fn test_each_store_failure_and_the_door_answer() {
        let unread = format!("{UNREAD_AFTER_COMMIT}: late; the database did not answer");
        type Row = (StoreError, CommitError);
        let rows: [Row; 7] = [
            (
                StoreError::Host(KerberosStoreError::Failed("late".to_owned())),
                CommitError::Failed("late".to_owned()),
            ),
            (
                StoreError::Host(KerberosStoreError::Failed(unread.clone())),
                CommitError::Unknown(unread),
            ),
            (
                StoreError::Host(KerberosStoreError::NotReady("not held".to_owned())),
                CommitError::Failed("not held".to_owned()),
            ),
            (
                StoreError::Host(KerberosStoreError::Refused(NO_USER_ROW.to_owned())),
                CommitError::UserGone,
            ),
            (
                StoreError::Host(KerberosStoreError::Refused("a row".to_owned())),
                CommitError::Failed("Kerberos store refused the change: a row".to_owned()),
            ),
            (
                StoreError::PasswordPolicy("too short".to_owned()),
                CommitError::Refused("password policy: too short".to_owned()),
            ),
            (
                StoreError::NotFound,
                CommitError::Failed("principal not found".to_owned()),
            ),
        ];
        for (error, expected) in rows {
            let label = error.to_string();
            assert_eq!(commit_error(error), expected, "{label}");
        }
    }

    // X1 grade 3: the row of a change whose caller went away is the blocking task's.
    #[tokio::test]
    #[serial]
    async fn test_a_dropped_caller_of_a_password_change_still_gets_its_row() {
        use lldap_domain_handlers::password::UNKNOWN_ROW;
        let guard = LogGuard::install();
        type Row = (
            &'static str,
            Option<Fault>,
            Vec<(bool, String)>,
            Vec<String>,
        );
        let rows: [Row; 3] = [
            (
                "committed: its row is in the transaction",
                None,
                Vec::new(),
                vec!["password bob".to_owned(), "log password_change".to_owned()],
            ),
            (
                "failed",
                Some(Fault::Failed),
                vec![(
                    false,
                    "password change failed: the database did not answer".to_owned(),
                )],
                Vec::new(),
            ),
            (
                "unknown",
                Some(Fault::Unknown),
                vec![(false, UNKNOWN_ROW.to_owned())],
                Vec::new(),
            ),
        ];
        for (label, fault, logged, written) in rows {
            let temp = TempRealm::new();
            let (embedded, _store) = temp.embedded();
            embedded
                .sync_principal(&bob(), "Bob-Password-1")
                .await
                .unwrap();
            guard.recorder().take_events();
            temp.host.set_fault(fault);
            temp.host.set_delay(Duration::from_millis(300));
            let alice = RequestMeta::ldap(Some(UserId::new("alice")), None);
            let call = embedded.commit_password(commit_of("bob", b"record"), "Bob-Pass-2");
            let gave_up =
                tokio::time::timeout(Duration::from_millis(50), with_request(alice, call))
                    .await
                    .is_err();
            drop(embedded.writes.clone().lock_owned().await);
            temp.host.set_delay(Duration::ZERO);
            let events: Vec<_> = guard
                .recorder()
                .take_events()
                .into_iter()
                .filter(|e| e.kind == LogKind::PasswordChange)
                .map(|e| (e.actor, (e.success, e.detail.unwrap_or_default())))
                .collect();
            let by_alice: Vec<_> = logged
                .into_iter()
                .map(|row| (Some("alice".to_owned()), row))
                .collect();
            assert_eq!(
                (gave_up, events, temp.host.rows()),
                (true, by_alice, written),
                "{label}"
            );
        }
    }

    #[tokio::test]
    #[serial]
    async fn test_a_change_that_panicked_is_unknown_and_its_row_says_it_did_not_report() {
        use lldap_domain_handlers::password::UNREPORTED_ROW;
        let guard = LogGuard::install();
        let temp = TempRealm::new();
        let (embedded, store) = temp.embedded();
        guard.recorder().take_events();
        temp.host.set_fault(Some(Fault::Panic));
        let alice = RequestMeta::ldap(Some(UserId::new("alice")), None);
        let call = embedded.commit_password(commit_of("bob", b"record"), "Bob-Password-1");
        let got = with_request(alice, call).await;
        temp.host.set_fault(None);
        let events: Vec<_> = guard
            .recorder()
            .take_events()
            .into_iter()
            .filter(|e| e.kind == LogKind::PasswordChange)
            .map(|e| (e.success, e.detail.unwrap_or_default()))
            .collect();
        assert_eq!(
            (got, events, temp.host.rows(), marked(&store, "bob")),
            (
                Err(CommitError::Unknown(PANICKED.to_owned())),
                vec![(false, UNREPORTED_ROW.to_owned())],
                Vec::<String>::new(),
                None
            )
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_the_wait_for_the_write_lock_is_bounded_and_writes_nothing() {
        let temp = TempRealm::new();
        let (mut embedded, store) = temp.embedded();
        embedded.write_wait = Duration::from_millis(20);
        let held = embedded.writes.clone().lock_owned().await;
        let writes = temp.own_writes();
        let busy = embedded
            .commit_password(commit_of("bob", b"record"), "Bob-Password-1")
            .await;
        assert_eq!(
            (busy, temp.own_writes(), marked(&store, "bob")),
            (Err(CommitError::Busy), writes, None)
        );
        drop(held);
        let done = embedded
            .commit_password(commit_of("bob", b"record"), "Bob-Password-1")
            .await;
        assert_eq!((done, marked(&store, "bob")), (Ok(()), Some((true, false))));
    }

    #[test]
    fn test_change_following_mirrors_a_helper_of_this_signature() {
        type Checks = fn(&PrincipalStore) -> Result<(), StoreError>;
        type Commit = fn(HostChange) -> Result<(), KerberosStoreError>;
        type Mirrored = fn(
            &SharedDump,
            &PrincipalName,
            &str,
            &[u8],
            u32,
            &str,
            &[KeySalt],
            Checks,
            Commit,
        ) -> Result<(), StoreError>;
        let _: Mirrored = krb5_kdc::change_password_shared_committing;
    }

    #[tokio::test]
    #[serial]
    async fn test_the_principal_takes_the_directory_state_in_the_change_of_its_keys() {
        enum Before {
            Nothing,
            Marked(bool),
            Unmarked(bool),
        }
        const ENABLED: Option<&[&str]> = Some(&[]);
        const DISABLED: Option<&[&str]> = Some(&["dora"]);
        let unread = Err(CommitError::Failed(format!(
            "{STATE_UNREAD}: Kerberos store failed: the database did not answer"
        )));
        let done = || Ok(());
        type Row = (
            &'static str,
            Before,
            Option<&'static [&'static str]>,
            Result<(), CommitError>,
            (bool, bool),
        );
        let rows: [Row; 8] = [
            (
                "new, enabled user",
                Before::Nothing,
                ENABLED,
                done(),
                (true, false),
            ),
            (
                "new, disabled user",
                Before::Nothing,
                DISABLED,
                done(),
                (true, true),
            ),
            (
                "marked and disabled, enabled user: enabled",
                Before::Marked(true),
                ENABLED,
                done(),
                (true, false),
            ),
            (
                "marked and enabled, disabled user: disabled",
                Before::Marked(false),
                DISABLED,
                done(),
                (true, true),
            ),
            (
                "marked and disabled, disabled user",
                Before::Marked(true),
                DISABLED,
                done(),
                (true, true),
            ),
            (
                "unmarked and enabled, disabled user: disabled",
                Before::Unmarked(false),
                DISABLED,
                done(),
                (false, true),
            ),
            (
                "unmarked and disabled, enabled user: enabled, not marked",
                Before::Unmarked(true),
                ENABLED,
                done(),
                (false, false),
            ),
            (
                "the state is not read: nothing written",
                Before::Marked(false),
                None,
                unread,
                (true, false),
            ),
        ];
        let dora = UserId::new("dora");
        for (label, before, directory, expected, after) in rows {
            let temp = TempRealm::new();
            let (embedded, store) = temp.embedded();
            match before {
                Before::Nothing => {}
                Before::Marked(locked) => {
                    embedded
                        .sync_principal(&dora, "Dora-Password-0")
                        .await
                        .unwrap();
                    in_change(&embedded.own(), |s| {
                        s.set_status(&user_principal(&dora), locked, 0, "test")
                    })
                    .unwrap();
                }
                Before::Unmarked(locked) => unmarked(&embedded, "dora", locked),
            }
            temp.host.set_directory(directory);
            let (kvno, writes) = (kvno_in(&store.read().unwrap(), "dora"), temp.own_writes());
            let got = embedded
                .commit_password(commit_of("dora", b"record"), "Dora-Password-1")
                .await;
            let written = got.is_ok();
            let reopened = temp
                .reopened()
                .get_name(&user_principal(&dora))
                .map(|p| (p.host_owned(), p.locked()));
            let rows = match written {
                true => vec!["password dora".to_owned(), "log password_change".to_owned()],
                false => vec![],
            };
            assert_eq!(
                (
                    got,
                    marked(&store, "dora"),
                    reopened,
                    temp.own_writes() - writes,
                    kvno_in(&store.read().unwrap(), "dora") != kvno,
                    temp.host.rows()
                ),
                (
                    expected,
                    Some(after),
                    Some(after),
                    usize::from(written),
                    written,
                    rows
                ),
                "{label}"
            );
        }
    }

    #[tokio::test]
    #[serial]
    async fn test_the_password_check_writes_nothing() {
        let temp = TempRealm::new();
        let (embedded, store) = temp.embedded();
        assert_eq!(
            embedded.check_password(&bob(), "short").await,
            Ok(()),
            "no principal yet, so no policy"
        );
        embedded
            .sync_principal(&bob(), "Bob-Password-1")
            .await
            .unwrap();
        let mut policy = krb5_kdc::NamedPolicy::new("min12");
        policy.min_length = 12;
        store.write().unwrap().put_policy(policy).unwrap();
        in_change(&embedded.own(), |s| {
            s.set_principal_policy(&user_principal(&bob()), Some("min12".to_owned()))
        })
        .unwrap();
        let commits = temp.commits();
        let refused = embedded.check_password(&bob(), "short").await.unwrap_err();
        assert!(refused.contains("password policy"), "{refused}");
        assert_eq!(
            embedded
                .check_password(&bob(), "Long-Enough-Password-2")
                .await,
            Ok(())
        );
        assert!(
            embedded
                .check_password(&UserId::new("bob/admin"), "Long-Enough-Password-3")
                .await
                .is_err()
        );
        assert_eq!(temp.commits(), commits, "the check commits nothing");
    }

    #[tokio::test]
    #[serial]
    async fn test_a_password_change_for_a_user_name_that_is_an_alias_is_refused() {
        let temp = TempRealm::new();
        let (embedded, store) = temp.embedded();
        unmarked(&embedded, "svc", false);
        let passed = embedded.check_password(&bob(), "Bob-Password-1").await;
        let svc_name = user_principal(&UserId::new("svc"));
        in_change(&embedded.own(), |s| {
            s.create_alias_in(
                &user_principal(&bob()),
                "EXAMPLE.COM",
                &svc_name,
                "EXAMPLE.COM",
                "test",
            )
        })
        .unwrap();
        let why = "the principal name of user bob is an alias of svc@EXAMPLE.COM".to_owned();
        let (writes, svc) = (temp.own_writes(), fields(&store, "svc"));
        let checked = embedded.check_password(&bob(), "Bob-Password-1").await;
        assert_eq!(
            (passed, checked),
            (Ok(()), Err(why.clone())),
            "the check refuses once the name is an alias"
        );
        let committed = embedded
            .commit_password(commit_of("bob", b"record"), "Bob-Password-1")
            .await;
        let raw = store
            .read()
            .unwrap()
            .get_raw("bob@EXAMPLE.COM")
            .map(|p| (p.alias_target(), p.host_owned()));
        assert_eq!(
            (
                committed,
                fields(&store, "svc"),
                temp.own_writes(),
                temp.host.rows(),
                temp.host.password_record(&bob()),
                raw
            ),
            (
                Err(CommitError::Refused(why)),
                svc,
                writes,
                Vec::<String>::new(),
                None,
                Some((Some("svc@EXAMPLE.COM".to_owned()), false))
            ),
            "the commit refuses and nothing is written"
        );
    }
}
