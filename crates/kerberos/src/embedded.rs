use crate::boot::{self, OpenRealm, RealmSettings};
use crate::rotate;
pub use crate::seam::Records;
use crate::seam::{Host, SqlRealm, committing, committing_with, row_name};
use anyhow::{Context, Result, anyhow};
use async_trait::async_trait;
use krb5_admin::{
    Kadmind, KadmindConfig, Listeners, Programs, ServeLimits, Services, TracingAdmin,
};
use krb5_config::KadmindListen;
use krb5_crypto::KeySalt;
use krb5_kdc::host::{HostChange, KerberosStoreError};
use krb5_kdc::{
    AdminEnt, AdminFields, Error as StoreError, KDB_DISALLOW_ALL_TIX, KDB_REQUIRES_PRE_AUTH,
    KdcLog, ListenLimits, PrincipalRead, PrincipalStore, SharedDump, SharedStore, Shutdown,
    kadm5_mask, lookup_principal_id,
};
use krb5_types::PrincipalName;
use lldap_domain::types::UserId;
use lldap_domain_handlers::enforcement::{CommitFollower, touched_users};
use lldap_domain_handlers::kerberos::{
    CommitError, Held, HostRow, KerberosSync, PasswordCommit, SYNC_CHANGED, UNREAD_AFTER_COMMIT,
    USER_GONE as NO_USER_ROW, UserChange, UserStep, validate_kerberos_username,
    validate_keytab_hostname,
};
use lldap_domain_handlers::logging::{
    self, LogKind, current_request, record, record_outcome, with_request_sync,
};
use lldap_domain_handlers::password::{
    PASSWORD_MIN_LENGTH, kill_point, password_rules, record_commit_failure, record_unreported,
};
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::panic::{self, AssertUnwindSafe};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock, RwLock, Weak};
use std::thread::{self, JoinHandle};
use std::time::Duration;
use tokio::sync::{Mutex, mpsc};
use tracing::{Span, error, info, warn};
use zeroize::Zeroizing;

const KADMIND_START: Duration = Duration::from_secs(10);
const WRITE_WAIT: Duration = Duration::from_secs(10);
const USER_GONE: &str = "user gone";
const NO_SYNC: &str = "no sync";
const DISABLED_AT_START: &str =
    "disabled at start: a directory user without Kerberos sync has a principal";
const STATE_UNREAD: &str = "the user's lldap_disabled membership was not read";
const STATUSES_UNREAD: &str =
    "the users' Kerberos sync and lldap_disabled membership were not read";
const SYNC_UNREAD: &str = "the user's Kerberos sync was not read";
pub(crate) const ADOPTED: &str = "adopted: the principal is kept, marked and given random keys, \
     and stays disabled until its status is set from lldap_disabled at the next password change, \
     kadmin cpw, opening of the realm or status pass";
pub(crate) const ENABLED_AFTER_CPW: &str =
    "enabled after kadmin change_password: the user is not in lldap_disabled";
pub(crate) const DISABLED_AFTER_CPW: &str =
    "disabled after kadmin change_password: the user is in lldap_disabled";
pub(crate) const NOT_FOLLOWED: &str =
    "after kadmin change_password the status was not set from lldap_disabled and stays as it was";
pub(crate) const REALM_STOPPED: &str = "the realm stopped";
pub(crate) const DISABLED_AT_OPEN: &str =
    "disabled as the realm opened: the user is in lldap_disabled";
pub(crate) const ENABLED_AT_OPEN: &str =
    "enabled as the realm opened: the user is not in lldap_disabled";
pub(crate) const DISABLED_AT_TURN: &str =
    "disabled by the holder's status pass: the user is in lldap_disabled";
pub(crate) const ENABLED_AT_TURN: &str =
    "enabled by the holder's status pass: the user is not in lldap_disabled";
pub(crate) const REMOVED_AT_TURN: &str = "removed by the holder's status pass";
const USERS_UNREAD: &str = "the directory users of the marked principals were not read";

/// What a pass writes; a pass that removes also takes out the principals of users gone or
/// without sync.
#[derive(Clone, Copy)]
struct StatusRows {
    disabled: &'static str,
    enabled: &'static str,
    removed: Option<&'static str>,
}

const AT_OPEN: StatusRows = StatusRows {
    disabled: DISABLED_AT_OPEN,
    enabled: ENABLED_AT_OPEN,
    removed: None,
};
const AT_TURN: StatusRows = StatusRows {
    disabled: DISABLED_AT_TURN,
    enabled: ENABLED_AT_TURN,
    removed: Some(REMOVED_AT_TURN),
};
pub(crate) const STATUSES_UNSET: &str = "the status of the marked principals was not set from \
     lldap_disabled: the holder's next status pass sets it, within a minute, or the next opening \
     of the realm";
const START_CHUNK: usize = 100;
pub const FOLLOW_EVERY: Duration = Duration::from_secs(60);

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
    follower: OnceLock<Arc<dyn CommitFollower>>,
}

/// The KDC and kadmind threads. A thread that stops on its own stops the other one and
/// reports through `died`; the server then shuts down.
pub struct RealmThreads {
    shutdown: Shutdown,
    stopping: Arc<AtomicBool>,
    handles: Vec<JoinHandle<()>>,
    died: mpsc::UnboundedReceiver<String>,
    turns: Option<tokio::task::JoinHandle<()>>,
}

/// The realm opened and its sockets bound; nothing is answered until `serve`.
pub struct Opened {
    open: OpenRealm,
    realm: String,
    ready: Arc<AtomicBool>,
    serving: String,
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

    /// Opens the realm, binds its sockets and sets each marked principal's status; the engine is
    /// ready for the start's own passes, and the KDC and kadmind serve only from `serve`.
    pub fn open(
        settings: &RealmSettings,
        store: Arc<dyn lldap_domain_handlers::kerberos::KerberosStore>,
        records: Records,
    ) -> Result<(Arc<Self>, Opened)> {
        let host = SqlRealm::new(store).serving(&settings.realm, Some(records));
        Self::open_on(settings, Arc::new(host))
    }

    pub(crate) fn start_on(
        settings: &RealmSettings,
        host: Arc<dyn Host>,
    ) -> Result<(Arc<Self>, RealmThreads)> {
        let (engine, opened) = Self::open_on(settings, host)?;
        Ok((engine, opened.serve()?))
    }

    pub(crate) fn open_on(
        settings: &RealmSettings,
        host: Arc<dyn Host>,
    ) -> Result<(Arc<Self>, Opened)> {
        let open = boot::open(settings, host.clone())?;
        let own = Own {
            store: open.store.clone(),
            host: host.clone(),
            realm: settings.realm.clone(),
            actor: format!("admin/admin@{}", settings.realm),
        };
        follow_statuses(&own, None, START_CHUNK, AT_OPEN)?;
        info!("🎟️ Kerberos realm {} opened", settings.realm);
        let ready = Arc::new(AtomicBool::new(true));
        let serving = format!(
            "🎟️ Kerberos realm {} serving: kdc {}:{}, kadmin {}:{}",
            settings.realm,
            settings.kdc_host,
            settings.kdc_port,
            settings.kadmin_host,
            settings.kadmin_port
        );
        let engine = Self::new(open.store.clone(), settings, ready.clone(), host);
        let opened = Opened {
            open,
            realm: settings.realm.clone(),
            ready,
            serving,
        };
        Ok((Arc::new(engine), opened))
    }

    pub(crate) fn new(
        store: SharedDump,
        settings: &RealmSettings,
        ready: Arc<AtomicBool>,
        host: Arc<dyn Host>,
    ) -> Self {
        let engine = Self {
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
            follower: OnceLock::new(),
        };
        engine.host.follow_with(engine.follow());
        engine
    }

    /// Told of every directory row this engine commits, after the realm's locks are released.
    pub fn follow_commits(&self, follower: Arc<dyn CommitFollower>) {
        if self.follower.set(follower).is_err() {
            error!("💥 The realm's commits already have a follower");
        }
    }

    async fn followed(&self, users: &[UserId], answer: &Result<(), CommitError>) {
        if let Some(follower) = self.follower.get() {
            follower.committed(users, answer).await;
        }
    }

    /// Every `every`, each marked principal of a user with sync takes `lldap_disabled` again; a
    /// turn that fails writes its row and the next turn tries again.
    pub fn follow_every(&self, every: Duration) -> tokio::task::JoinHandle<()> {
        let follow = self.follow();
        tokio::spawn(async move {
            let mut turns = tokio::time::interval(every);
            turns.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            turns.tick().await;
            loop {
                turns.tick().await;
                if follow.store.strong_count() == 0 {
                    return;
                }
                let queued = Arc::new(AtomicBool::new(true));
                follow.clone().statuses_as(queued, AT_TURN).await;
            }
        })
    }

    fn follow(&self) -> Follow {
        Follow {
            store: Arc::downgrade(&self.store),
            host: Arc::downgrade(&self.host),
            realm: self.realm.clone(),
            actor: self.actor.clone(),
            writes: self.writes.clone(),
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
    /// synced user's principal, removes a marked one no synced user has, disables an unmarked one
    /// of a user without sync, clears marked ones' Kerberos policies. A second run writes nothing.
    pub async fn start_pass(&self, users: Vec<(UserId, bool)>) -> Result<StartPass> {
        self.start_pass_in(users, START_CHUNK).await
    }

    async fn start_pass_in(&self, users: Vec<(UserId, bool)>, chunk: usize) -> Result<StartPass> {
        let own = self.own();
        let serial = self.writes.clone().lock_owned().await;
        let (swept, aliases, followed, cleared) = tokio::task::spawn_blocking(move || {
            let _serial = serial;
            let (swept, aliases, listed) = {
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
                let listed = alias_rows(&store, &own.realm);
                (sweep_plan(&store, &own.realm, &directory), aliases, listed)
            };
            let mut filled = 0;
            for part in listed.chunks(chunk) {
                filled += own
                    .host
                    .fill_alias_targets(part)
                    .map_err(|e| anyhow!("while filling the alias targets at start: {e}"))?;
            }
            if filled > 0 {
                info!("Filled the alias target of {filled} alias rows written before the column");
            }
            for part in swept.chunks(chunk) {
                let rows = swept_rows(part, &own.realm);
                let mut store = own
                    .store
                    .write()
                    .map_err(|_| anyhow!("the principal store was poisoned"))?;
                let logged = rows.iter().cloned().map(HostRow::Log).collect();
                store
                    .change_committing(committing_with(own.host.as_ref(), logged), |s| {
                        for one in part {
                            match one.sweep {
                                Sweep::Mark => {
                                    s.set_host_owned_in(&one.name, &own.realm, true)?;
                                    clear_policy(s, &one.name, &own)?;
                                }
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
                drop(store);
                rows.iter().for_each(logging::print);
            }
            let cleared = clear_policies(&own, chunk);
            let marked: Vec<_> = swept
                .iter()
                .filter(|one| one.sweep == Sweep::Mark)
                .map(|one| one.name.clone())
                .collect();
            let followed = follow_statuses(&own, Some(marked.as_slice()), chunk, AT_OPEN)?;
            own.host.start_pass_committed();
            Ok::<_, anyhow::Error>((swept, aliases, followed, cleared))
        })
        .await
        .context("the start pass did not complete")??;
        for (user, target) in &aliases {
            let detail = aliased(user, target);
            record(LogKind::KerberosSync, Some(user.as_str()), Some(&detail));
        }
        let mut pass = StartPass::default();
        for one in &swept {
            match one.sweep {
                Sweep::Mark => pass.marked += 1,
                Sweep::Remove(_) => pass.removed += 1,
                Sweep::Disable => pass.disabled += 1,
            }
        }
        let bound_at_mark = swept.iter().filter(|one| one.cleared().is_some()).count();
        pass.followed = followed;
        pass.cleared = bound_at_mark + cleared;
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
    async fn password_committed(
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
                        Ok(Ok(noted)) => printed.iter().chain(noted).for_each(logging::print),
                        Ok(Err(e)) => record_commit_failure(kind, &worker, e),
                        Err(_) => record_unreported(kind, &worker, PANICKED),
                    }
                    done.unwrap_or_else(|_| Err(CommitError::Unknown(PANICKED.to_owned())))
                        .map(drop)
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

    async fn user_committed(&self, change: UserChange) -> Result<(), CommitError> {
        let own = self.own();
        let waited = tokio::time::timeout(self.write_wait, self.writes.clone().lock_owned()).await;
        let Ok(serial) = waited else {
            return Err(CommitError::Busy);
        };
        let (span, meta) = (Span::current(), current_request());
        let done = tokio::task::spawn_blocking(move || {
            let _serial = serial;
            span.in_scope(|| {
                with_request_sync(meta, || {
                    let printed = logged_rows(&change.rows);
                    let done = panic::catch_unwind(AssertUnwindSafe(|| user_change(&own, change)));
                    let done = done
                        .unwrap_or_else(|_| Err(CommitError::Unknown(CHANGE_PANICKED.to_owned())));
                    if let Ok(noted) = &done {
                        printed.iter().chain(noted).for_each(logging::print);
                    }
                    done.map(drop)
                })
            })
        })
        .await;
        done.unwrap_or_else(|e| Err(CommitError::Unknown(format!("the change did not run: {e}"))))
    }

    /// A user whose principal name is an alias: the store is not touched, and one row says so.
    async fn skipped_as_alias(&self, user: &UserId, op: &str) -> Result<bool, String> {
        let Some(target) = self.alias_target(user).await? else {
            return Ok(false);
        };
        let detail = format!("{}: {op} skipped", aliased(user, &target));
        record(LogKind::KerberosSync, Some(user.as_str()), Some(&detail));
        Ok(true)
    }

    async fn alias_target(&self, user: &UserId) -> Result<Option<String>, String> {
        let (store, realm, id) = (self.store.clone(), self.realm.clone(), user.clone());
        read_store(move || {
            let (store, fresh) = krb5_kdc::read_fresh(&store);
            fresh?;
            Ok(alias_of(&store, &realm, &id))
        })
        .await
    }
}

#[async_trait]
impl KerberosSync for EmbeddedKerberos {
    fn ready(&self) -> bool {
        self.ready.load(Ordering::Relaxed) && self.host.realm_not_held().is_none()
    }
    fn unavailable(&self) -> Option<String> {
        self.host.realm_not_held()
    }
    fn unsettled(&self) -> Option<String> {
        self.host.realm_unsettled()
    }
    fn realm(&self) -> &str {
        &self.realm
    }
    async fn check_password(&self, user: &UserId, password: &str) -> Result<(), String> {
        validate_kerberos_username(user.as_str())?;
        password_rules(password, PASSWORD_MIN_LENGTH).map_err(|e| e.to_string())?;
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
        let touched = touched_users(&change.rows);
        let answer = self.password_committed(change, password).await;
        self.followed(&touched, &answer).await;
        answer
    }
    async fn sync_on_refused(&self, user: &UserId) -> Result<(), String> {
        match self.alias_target(user).await? {
            Some(target) => Err(alias_refusal(user, &target, &self.realm)),
            None => Ok(()),
        }
    }
    async fn hold_plain(&self, user: &UserId) -> Result<Option<Held>, CommitError> {
        let serial = tokio::time::timeout(self.write_wait, self.writes.clone().lock_owned())
            .await
            .map_err(|_| CommitError::Busy)?;
        let (host, id) = (self.host.clone(), user.clone());
        let synced = tokio::task::spawn_blocking(move || host.user_synced(&id))
            .await
            .map_err(|e| CommitError::Failed(format!("{SYNC_UNREAD}: {e}")))?
            .map_err(|e| CommitError::Failed(format!("{SYNC_UNREAD}: {e}")))?;
        match synced {
            true => Err(CommitError::Refused(SYNC_CHANGED.to_owned())),
            false => {
                let held: Held = Box::new(serial);
                Ok(Some(held))
            }
        }
    }
    async fn commit_user(&self, change: UserChange) -> Option<Result<(), CommitError>> {
        let touched = touched_users(&change.rows);
        let answer = self.user_committed(change).await;
        self.followed(&touched, &answer).await;
        Some(answer)
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

impl Opened {
    /// Spawns the KDC and kadmind on the sockets `open` bound.
    pub fn serve(self) -> Result<RealmThreads> {
        let Self {
            open:
                OpenRealm {
                    store,
                    profile,
                    acl,
                    kdc_udp,
                    kdc_tcp,
                    kadmin,
                },
            realm,
            ready,
            serving,
        } = self;
        let shutdown = Shutdown::new();
        let stopping = Arc::new(AtomicBool::new(false));
        let (died_tx, died) = mpsc::unbounded_channel();
        let watch = Watch {
            shutdown: shutdown.clone(),
            stopping: stopping.clone(),
            ready,
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
            turns: None,
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
        info!("{serving}");
        Ok(threads)
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

    /// The holder's turns of the status pass stop with the realm.
    pub fn following(mut self, turns: tokio::task::JoinHandle<()>) -> Self {
        self.turns = Some(turns);
        self
    }

    pub fn stop(self) {
        if let Some(turns) = &self.turns {
            turns.abort();
        }
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

/// Queued by a committed kadmin `cpw`; weak, so the host the store holds keeps no realm alive.
#[derive(Clone)]
pub(crate) struct Follow {
    store: Weak<RwLock<PrincipalStore>>,
    host: Weak<dyn Host>,
    realm: String,
    actor: String,
    writes: Arc<Mutex<()>>,
}

impl Follow {
    pub(crate) async fn run(self, user: UserId, client: String) {
        let Self {
            store,
            host,
            realm,
            actor,
            writes,
        } = self;
        let serial = writes.lock_owned().await;
        let id = user.clone();
        let done = tokio::task::spawn_blocking(move || {
            let _serial = serial;
            let (Some(store), Some(host)) = (store.upgrade(), host.upgrade()) else {
                return Err(REALM_STOPPED.to_owned());
            };
            let own = Own {
                store,
                host,
                realm,
                actor,
            };
            follow_status(&own, &id)
        })
        .await
        .unwrap_or_else(|e| Err(format!("the step did not run: {e}")));
        let (success, detail) = match done {
            Ok(None) => return,
            Ok(Some(false)) => (true, ENABLED_AFTER_CPW.to_owned()),
            Ok(Some(true)) => (true, DISABLED_AFTER_CPW.to_owned()),
            Err(why) => (false, format!("{NOT_FOLLOWED}: {why}")),
        };
        let target = Some(user.as_str());
        logging::record_kadmin(
            &client,
            LogKind::KerberosSync,
            target,
            success,
            Some(&detail),
        );
    }
}

impl Follow {
    pub(crate) async fn statuses(self, queued: Arc<AtomicBool>) {
        self.statuses_as(queued, AT_OPEN).await;
    }

    async fn statuses_as(self, queued: Arc<AtomicBool>, rows: StatusRows) {
        self.statuses_in(queued, rows, START_CHUNK).await;
    }

    async fn statuses_in(self, queued: Arc<AtomicBool>, rows: StatusRows, chunk: usize) {
        let Self {
            store,
            host,
            realm,
            actor,
            writes,
        } = self;
        let serial = writes.lock_owned().await;
        let done = tokio::task::spawn_blocking(move || {
            let _serial = serial;
            let (Some(store), Some(host)) = (store.upgrade(), host.upgrade()) else {
                return Err(anyhow!(REALM_STOPPED));
            };
            let own = Own {
                store,
                host,
                realm,
                actor,
            };
            follow_statuses(&own, None, chunk, rows)
        })
        .await
        .unwrap_or_else(|e| Err(anyhow!("the step did not run: {e}")));
        if let Err(e) = done {
            let detail = format!("{STATUSES_UNSET}: {e:#}");
            logging::record_failure(LogKind::KerberosSync, None, &detail);
        }
        queued.store(false, Ordering::Release);
    }
}

#[derive(Clone, Copy)]
enum Turn {
    Status(bool),
    Remove(&'static str),
}

/// Each marked principal of a synced user takes the user's `lldap_disabled`; `only` narrows it.
/// Each chunk's rows commit with its statuses, so a later chunk's failure keeps them.
fn follow_statuses(
    own: &Own,
    only: Option<&[PrincipalName]>,
    chunk: usize,
    rows: StatusRows,
) -> Result<usize> {
    let marked = {
        let store = own.store.read();
        let store = store.map_err(|_| anyhow!("the principal store was poisoned"))?;
        marked_users(&store, &own.realm)
    };
    let marked: Vec<_> = marked
        .into_iter()
        .filter(|(name, _, _)| only.is_none_or(|only| only.contains(name)))
        .collect();
    let statuses = own.host.synced_statuses();
    let statuses = statuses.map_err(|e| anyhow!("{STATUSES_UNREAD}: {e}"))?;
    let statuses: HashMap<UserId, bool> = statuses.into_iter().collect();
    let unsynced: Vec<_> = marked
        .iter()
        .filter(|(_, user, _)| rows.removed.is_some() && !statuses.contains_key(user))
        .map(|(_, user, _)| user.clone())
        .collect();
    let present: HashSet<UserId> = match unsynced.is_empty() {
        true => HashSet::new(),
        false => own
            .host
            .directory_users(&unsynced)
            .map_err(|e| anyhow!("{USERS_UNREAD}: {e}"))?
            .into_iter()
            .collect(),
    };
    let plan: Vec<_> = marked
        .into_iter()
        .filter_map(|(name, user, locked)| {
            let turn = match statuses.get(&user) {
                Some(&disabled) if disabled != locked => Turn::Status(disabled),
                Some(_) => return None,
                None if rows.removed.is_none() => return None,
                None if present.contains(&user) => Turn::Remove(NO_SYNC),
                None => Turn::Remove(USER_GONE),
            };
            Some((name, user, turn))
        })
        .collect();
    let mut followed = 0;
    for part in plan.chunks(chunk) {
        let logged: RefCell<Vec<logging::LogEvent>> = RefCell::new(Vec::new());
        let host = own.host.as_ref();
        let commit = |change: HostChange| {
            let written = logged.borrow().iter().cloned().map(HostRow::Log).collect();
            committing_with(host, written)(change)
        };
        let edit = |s: &mut PrincipalStore| -> Result<(), StoreError> {
            for (name, user, turn) in part {
                let Some(p) = s.fetch_name(name)?.filter(|p| p.host_owned()) else {
                    continue;
                };
                let detail = match *turn {
                    Turn::Status(disabled) if p.locked() != disabled => {
                        s.set_status(name, disabled, p.pw_expire, &own.actor)?;
                        let row = if disabled {
                            rows.disabled
                        } else {
                            rows.enabled
                        };
                        row.to_owned()
                    }
                    Turn::Status(_) => continue,
                    Turn::Remove(_) if alias_of(s, &own.realm, user).is_some() => continue,
                    Turn::Remove(reason) => {
                        s.remove_in(name, &own.realm)?;
                        format!("{}: {reason}", rows.removed.unwrap_or(REMOVED_AT_TURN))
                    }
                };
                let row = logging::event(
                    LogKind::KerberosSync,
                    Some(user.as_str()),
                    true,
                    Some(&detail),
                );
                logged.borrow_mut().push(row);
            }
            Ok(())
        };
        let mut store = own
            .store
            .write()
            .map_err(|_| anyhow!("the principal store was poisoned"))?;
        store
            .change_committing(commit, edit)
            .and_then(|done| done)
            .map_err(|e| {
                anyhow!("while setting the principals' status from lldap_disabled: {e}")
            })?;
        drop(store);
        let written = logged.into_inner();
        written.iter().for_each(logging::print);
        followed += written.len();
    }
    Ok(followed)
}

fn marked_users(store: &PrincipalStore, realm: &str) -> Vec<(PrincipalName, UserId, bool)> {
    store
        .ids()
        .iter()
        .filter_map(|id| store.get_raw(id))
        .filter(|p| p.realm == realm && p.alias_target().is_none() && p.host_owned())
        .filter_map(|p| {
            let one = (p.name.name_string.len() == 1)
                .then(|| p.name.try_components_joined())
                .flatten()?;
            Some((p.name.clone(), UserId::new(&one), p.locked()))
        })
        .collect()
}

fn follow_status(own: &Own, user: &UserId) -> Result<Option<bool>, String> {
    let disabled = own
        .host
        .user_disabled(user)
        .map_err(|e| format!("{STATE_UNREAD}: {e}"))?;
    let name = user_principal(user);
    in_change(own, |s| {
        not_an_alias(s, &own.realm, user)?;
        let now = s.fetch_name(&name)?;
        match now.map(|p| (p.host_owned(), p.locked(), p.pw_expire)) {
            Some((true, locked, pw_expire)) if locked != disabled => s
                .set_status(&name, disabled, pw_expire, &own.actor)
                .map(|()| Some(disabled)),
            _ => Ok(None),
        }
    })
    .map_err(|e| e.to_string())
}

// What a write of our own needs; kerber-rust hands its change to `committing`, as `Embedded`.
struct Own {
    store: SharedDump,
    host: Arc<dyn Host>,
    realm: String,
    actor: String,
}

// `commit` makes each attempt's closure, given the rows the mark adds; at most one reaches the
// host. `locked` is the directory's state for an existing principal; None leaves its status.
fn set_password<C>(
    own: &Own,
    user: &UserId,
    password: &[u8],
    enctypes: &[KeySalt],
    ent: &AdminEnt,
    locked: Option<bool>,
    commit: impl Fn() -> C,
) -> Result<Option<logging::LogEvent>, StoreError>
where
    C: FnOnce(HostChange, Vec<HostRow>) -> Result<(), KerberosStoreError>,
{
    let name = user_principal(user);
    let noted: RefCell<Option<logging::LogEvent>> = RefCell::new(None);
    let change = || {
        let (made, noted) = (commit(), &noted);
        krb5_kdc::change_password_shared_committing_then(
            &own.store,
            &name,
            &own.realm,
            password,
            0,
            &own.actor,
            enctypes,
            |s| not_an_alias(s, &own.realm, user),
            move |host_change| {
                let rows = noted.borrow().iter().cloned().map(HostRow::Log).collect();
                made(host_change, rows)
            },
            |s| {
                follow_directory(s, &name, locked, &own.actor)?;
                let cleared = mark(s, &name, own)?;
                *noted.borrow_mut() =
                    cleared.map(|policy| cleared_row(user.as_str(), &policy, &name, &own.realm));
                Ok(())
            },
        )
    };
    let mut next = after_change(change());
    if next == Next::Create {
        let made = commit();
        let created = create_owned(own, user, password, enctypes, ent, locked, |change| {
            made(change, Vec::new())
        });
        next = after_create(created);
    }
    if next == Next::ChangeAgain {
        next = after_change(change());
    }
    match next {
        Next::Done => Ok(noted.into_inner()),
        Next::Fail(e) => Err(e),
        Next::Create | Next::ChangeAgain => Err(StoreError::NotFound),
    }
}

// kerber-rust runs `checks` again under the write lock, right before the create.
fn create_owned(
    own: &Own,
    user: &UserId,
    password: &[u8],
    enctypes: &[KeySalt],
    ent: &AdminEnt,
    locked: Option<bool>,
    commit: impl FnOnce(HostChange) -> Result<(), KerberosStoreError>,
) -> Result<(), StoreError> {
    let name = user_principal(user);
    krb5_kdc::create_password_shared_committing_then(
        &own.store,
        &name,
        &own.realm,
        password,
        enctypes,
        ent,
        &own.actor,
        |s| not_an_alias(s, &own.realm, user),
        commit,
        |s| {
            follow_directory(s, &name, locked, &own.actor)?;
            s.set_host_owned_in(&name, &own.realm, true)
        },
    )
}

fn mark(
    s: &mut PrincipalStore,
    name: &PrincipalName,
    own: &Own,
) -> Result<Option<String>, StoreError> {
    match s.get_name(name).map(|p| p.host_owned()) {
        Some(false) => {
            s.set_host_owned_in(name, &own.realm, true)?;
            clear_policy(s, name, own)
        }
        _ => Ok(None),
    }
}

/// As kadmin's `-clearpolicy`, with the password expiry the policy set; the policy stays.
fn clear_policy(
    s: &mut PrincipalStore,
    name: &PrincipalName,
    own: &Own,
) -> Result<Option<String>, StoreError> {
    let Some(policy) = s.get_name(name).and_then(|p| p.pw_policy.clone()) else {
        return Ok(None);
    };
    let fields = AdminFields {
        clear_policy: true,
        ..Default::default()
    };
    s.apply_admin_fields_in(name, &own.realm, fields, &own.actor)?;
    Ok(Some(policy))
}

fn policy_cleared(policy: &str, principal: &str) -> String {
    format!(
        "Kerberos password policy {policy} cleared from {principal}: the directory's \
         password-min-length applies"
    )
}

fn cleared_row(target: &str, policy: &str, name: &PrincipalName, realm: &str) -> logging::LogEvent {
    let detail = policy_cleared(policy, &name.unparse_with_realm_lossy(realm));
    logging::event(LogKind::KerberosSync, Some(target), true, Some(&detail))
}

// `set_status` also writes `pw_expire`: the one the keys or the create left goes through.
fn follow_directory(
    s: &mut PrincipalStore,
    name: &PrincipalName,
    locked: Option<bool>,
    actor: &str,
) -> Result<(), StoreError> {
    let now = s.get_name(name).map(|p| (p.locked(), p.pw_expire));
    match (locked, now) {
        (Some(locked), Some((was, pw_expire))) if was != locked => {
            s.set_status(name, locked, pw_expire, actor)
        }
        _ => Ok(()),
    }
}

const PANICKED: &str = "the password change panicked";
const CHANGE_PANICKED: &str = "the user's change panicked";

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
) -> Result<Option<logging::LogEvent>, CommitError> {
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
        let rows = rows.clone();
        move |host_change: HostChange, noted: Vec<HostRow>| {
            let rows = [rows, noted].concat();
            committing_with(own.host.as_ref(), rows)(host_change)
        }
    });
    if let Err(StoreError::InvalidArgument(why)) = &made
        && why.starts_with(&aliased(&user, ""))
    {
        return Err(CommitError::Refused(why.clone()));
    }
    let noted = made.map_err(commit_error)?;
    kill_point("kerberos-changed");
    Ok(noted)
}

// A synced user's delete, sync change or `lldap_disabled` change, on the blocking task that owns
// `writes`: the principal's change and `rows` in one transaction. A name that is an alias is
// never written through.
fn user_change(own: &Own, change: UserChange) -> Result<Vec<logging::LogEvent>, CommitError> {
    let UserChange {
        user,
        step,
        mut rows,
    } = change;
    let status = matches!(step, UserStep::Disable | UserStep::Enable);
    let synced = match status {
        true => own
            .host
            .user_synced(&user)
            .map_err(|e| CommitError::Failed(format!("{SYNC_UNREAD}: {e}")))?,
        false => true,
    };
    if status
        && synced
        && let Some(cause) = own.host.realm_unsettled()
    {
        return Err(CommitError::Unsettled(cause));
    }
    if status {
        rows.insert(0, HostRow::SyncIs(user.clone(), synced));
    }
    let name = user_principal(&user);
    let noted = RefCell::new(Vec::new());
    let note = |detail: String| {
        let row = logging::event(
            LogKind::KerberosSync,
            Some(user.as_str()),
            true,
            Some(&detail),
        );
        noted.borrow_mut().push(row);
    };
    let (host, extra) = (own.host.as_ref(), &noted);
    let commit = move |change: HostChange| {
        let mut rows = rows;
        rows.extend(extra.borrow().iter().cloned().map(HostRow::Log));
        committing_with(host, rows)(change)
    };
    let edit = |s: &mut PrincipalStore| -> Result<(), StoreError> {
        if !step.touches_principal() || !synced {
            return Ok(());
        }
        if let Some(target) = alias_of(s, &own.realm, &user) {
            if step.turns_sync_on() {
                let why = alias_refusal(&user, &target, &own.realm);
                return Err(StoreError::InvalidArgument(why));
            }
            note(format!(
                "{}: {} skipped",
                aliased(&user, &target),
                step.op()
            ));
            return Ok(());
        }
        let Some(principal) = s.fetch_name(&name)? else {
            return Ok(());
        };
        match step {
            UserStep::Delete | UserStep::SyncOff => s.remove_in(&name, &own.realm),
            UserStep::SyncOn | UserStep::Create => {
                let cleared = adopt(s, &name, own, principal.pw_expire)?;
                note(ADOPTED.to_owned());
                if let Some(policy) = cleared {
                    let full = name.unparse_with_realm_lossy(&own.realm);
                    note(policy_cleared(&policy, &full));
                }
                Ok(())
            }
            UserStep::Disable | UserStep::Enable => {
                let locked = step == UserStep::Disable;
                match principal.host_owned() && principal.locked() != locked {
                    true => s.set_status(&name, locked, principal.pw_expire, &own.actor),
                    false => Ok(()),
                }
            }
            UserStep::DeleteWithoutSync | UserStep::SyncUnchanged => Ok(()),
        }
    };
    let mut store = own
        .store
        .write()
        .map_err(|_| CommitError::Failed(poisoned().to_string()))?;
    let done = store.change_committing(commit, edit).and_then(|done| done);
    drop(store);
    match done {
        Ok(()) => {
            kill_point("kerberos-changed");
            Ok(noted.into_inner())
        }
        Err(StoreError::InvalidArgument(why)) => Err(CommitError::Refused(why)),
        Err(StoreError::Host(KerberosStoreError::Refused(why))) if why != NO_USER_ROW => {
            Err(CommitError::Refused(why))
        }
        Err(e) => Err(commit_error(e)),
    }
}

/// The principal stays, without its Kerberos password policy; its keys are replaced, the old ones
/// dropped, so no password the directory never saw works on it.
fn adopt(
    s: &mut PrincipalStore,
    name: &PrincipalName,
    own: &Own,
    pw_expire: u32,
) -> Result<Option<String>, StoreError> {
    s.set_host_owned_in(name, &own.realm, true)?;
    let cleared = clear_policy(s, name, own)?;
    s.chrand_etypes_keepold_in(name, &own.realm, &[], 0, &own.actor)?;
    let pw_expire = s.get_name(name).map_or(pw_expire, |p| p.pw_expire);
    s.set_status(name, true, pw_expire, &own.actor)?;
    Ok(cleared)
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
        StoreError::Host(KerberosStoreError::Refused(why)) if why == SYNC_CHANGED => {
            CommitError::Refused(why)
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
    pub followed: usize,
    pub cleared: usize,
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
    policy: Option<String>,
    sweep: Sweep,
}

impl Swept {
    fn cleared(&self) -> Option<&str> {
        match self.sweep {
            Sweep::Mark => self.policy.as_deref(),
            Sweep::Remove(_) | Sweep::Disable => None,
        }
    }
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
                policy: p.pw_policy.clone(),
                sweep: sweep_of(p.host_owned(), p.locked(), user)?,
            })
        })
        .collect()
}

/// The rows of one chunk of the start pass: removals, disables, cleared policies, marks counted.
fn swept_rows(part: &[Swept], realm: &str) -> Vec<logging::LogEvent> {
    let row = |target: Option<&str>, detail: &str| {
        logging::event(LogKind::KerberosSync, target, true, Some(detail))
    };
    let mut rows = Vec::new();
    for one in part {
        let target = Some(one.target.as_str());
        match one.sweep {
            Sweep::Mark => {
                if let Some(policy) = one.cleared() {
                    rows.push(cleared_row(&one.target, policy, &one.name, realm));
                }
            }
            Sweep::Remove(reason) => rows.push(row(target, &format!("removed at start: {reason}"))),
            Sweep::Disable => rows.push(row(target, DISABLED_AT_START)),
        }
    }
    let marked = part.iter().filter(|one| one.sweep == Sweep::Mark).count();
    if marked > 0 {
        rows.push(row(None, &format!("marked at start: {marked} principals")));
    }
    rows
}

/// Marked principals lose their Kerberos policy, `chunk` per change, failures at the next start.
fn clear_policies(own: &Own, chunk: usize) -> usize {
    let bound = own.store.read().map(|s| bound_principals(&s, &own.realm));
    let Ok(bound) = bound else {
        warn!("No Kerberos password policy was cleared: the principal store was poisoned");
        return 0;
    };
    let mut cleared = 0;
    for (at, part) in bound.chunks(chunk).enumerate() {
        match clear_chunk(own, part) {
            Ok(written) => {
                written.iter().for_each(logging::print);
                cleared += written.len();
            }
            Err(e) => {
                let left = bound.len() - at * chunk;
                warn!(
                    "The Kerberos password policy of {left} directory principals was not \
                     cleared; the next start tries again: {e}"
                );
                break;
            }
        }
    }
    cleared
}

fn bound_principals(store: &PrincipalStore, realm: &str) -> Vec<PrincipalName> {
    store
        .ids()
        .iter()
        .filter_map(|id| store.get_raw(id))
        .filter(|p| directory_bound(p, realm))
        .map(|p| p.name.clone())
        .collect()
}

fn directory_bound(p: &krb5_kdc::Principal, realm: &str) -> bool {
    p.realm == realm && p.alias_target().is_none() && p.host_owned() && p.pw_policy.is_some()
}

fn clear_chunk(own: &Own, part: &[PrincipalName]) -> Result<Vec<logging::LogEvent>, StoreError> {
    let logged: RefCell<Vec<logging::LogEvent>> = RefCell::new(Vec::new());
    let host = own.host.as_ref();
    let commit = |change: HostChange| {
        let written = logged.borrow().iter().cloned().map(HostRow::Log).collect();
        committing_with(host, written)(change)
    };
    let edit = |s: &mut PrincipalStore| -> Result<(), StoreError> {
        for name in part {
            let id = lookup_principal_id(name, &own.realm);
            let still = id.and_then(|id| s.get_raw(&id).map(|p| directory_bound(p, &own.realm)));
            if still != Some(true) {
                continue;
            }
            if let Some(policy) = clear_policy(s, name, own)? {
                let target = name.unparse_no_realm_lossy();
                let row = cleared_row(&target, &policy, name, &own.realm);
                logged.borrow_mut().push(row);
            }
        }
        Ok(())
    };
    let mut store = own.store.write().map_err(|_| poisoned())?;
    store
        .change_committing(commit, edit)
        .and_then(|done| done)?;
    drop(store);
    Ok(logged.into_inner())
}

fn user_principal(user: &UserId) -> PrincipalName {
    PrincipalName::new(PrincipalName::NT_PRINCIPAL, [user.as_str()])
}

/// Each alias record's row name and target, as the opened store holds them.
fn alias_rows(store: &PrincipalStore, realm: &str) -> Vec<(String, String)> {
    store
        .ids()
        .iter()
        .filter_map(|id| store.get_raw(id))
        .filter_map(|p| Some((row_name(p.id(), realm), p.alias_target()?)))
        .collect()
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

fn alias_refusal(user: &UserId, target: &str, realm: &str) -> String {
    let why = aliased(user, target);
    format!("{why}; remove that alias first (kadmin delprinc {user}@{realm})")
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
    use lldap_domain_handlers::kerberos::{CREATED_FIRST, HostRow};
    use lldap_domain_handlers::logging::{RequestMeta, with_request};
    use lldap_domain_handlers::password::PASSWORD_HAS_NUL;
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
        sync: std::sync::Mutex<HashMap<String, bool>>,
        unread: AtomicBool,
        delay: std::sync::Mutex<Duration>,
        first_commit: std::sync::Mutex<Option<FirstCommit>>,
        pub(crate) not_held: std::sync::Mutex<Option<String>>,
        pub(crate) unsettled: std::sync::Mutex<Option<String>>,
        fault_after: std::sync::Mutex<Option<(usize, Fault)>>,
        logged: std::sync::Mutex<Vec<logging::LogEvent>>,
    }

    /// The realm's first commit, once: refused, or written with its answer lost.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) enum FirstCommit {
        Refused,
        AnswerLost,
        CreatedFirst,
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

        /// The next `writes` own writes go through; each one after them answers `fault`.
        pub(crate) fn set_fault_after(&self, writes: usize, fault: Fault) {
            let at = self.own.load(Ordering::Relaxed) + writes;
            *self.fault_after.lock().unwrap() = Some((at, fault));
        }

        pub(crate) fn logged(&self) -> Vec<(LogKind, Option<String>, Option<String>)> {
            let logged = self.logged.lock().unwrap();
            let rows = logged.iter().cloned();
            rows.map(|e| (e.kind, e.target, e.detail)).collect()
        }

        pub(crate) fn set_first_commit(&self, fault: Option<FirstCommit>) {
            *self.first_commit.lock().unwrap() = fault;
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

        /// The sync the directory holds now, which a `SyncIs` row is checked against.
        pub(crate) fn set_sync(&self, user: &str, on: bool) {
            self.sync.lock().unwrap().insert(user.to_owned(), on);
        }

        pub(crate) fn set_directory(&self, disabled: Option<&[&str]>) {
            self.unread.store(disabled.is_none(), Ordering::Relaxed);
            let users = disabled.unwrap_or_default().iter().map(|u| (*u).to_owned());
            *self.disabled.lock().unwrap() = users.collect();
        }

        fn fault(&self) -> Option<Fault> {
            match *self.fault_after.lock().unwrap() {
                Some((at, fault)) if self.own.load(Ordering::Relaxed) > at => Some(fault),
                _ => *self.fault.lock().unwrap(),
            }
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
            let first = match change.intent.operation {
                Operation::Bootstrap => self.first_commit.lock().unwrap().take(),
                _ => None,
            };
            match first {
                Some(FirstCommit::Refused) => Err(unanswered_db()),
                Some(FirstCommit::CreatedFirst) => Err(KerberosStoreError::Failed(format!(
                    "the database did not answer; {CREATED_FIRST}"
                ))),
                Some(FirstCommit::AnswerLost) => {
                    self.realm.commit(change.batch)?;
                    Err(unanswered_db())
                }
                None => self.realm.commit(change.batch),
            }
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
            let sync = self.sync.lock().unwrap();
            let changed = |row: &HostRow| match row {
                HostRow::SyncIs(user, on) => sync.get(user.as_str()).is_some_and(|now| now != on),
                _ => false,
            };
            if rows.iter().any(changed) {
                return Err(KerberosStoreError::Refused(SYNC_CHANGED.to_owned()));
            }
            drop(sync);
            self.realm.commit(change.batch)?;
            for row in &rows {
                match row {
                    HostRow::SetPassword { user, record, .. } => {
                        let mut records = self.records.lock().unwrap();
                        records.insert(user.as_str().to_owned(), record.clone());
                    }
                    HostRow::Log(event) => self.logged.lock().unwrap().push(event.clone()),
                    _ => {}
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

        fn user_synced(&self, user: &UserId) -> Result<bool, KerberosStoreError> {
            if self.unread.load(Ordering::Relaxed) {
                return Err(unanswered_db());
            }
            Ok(self.sync.lock().unwrap().get(user.as_str()) == Some(&true))
        }

        fn synced_statuses(&self) -> Result<Vec<(UserId, bool)>, KerberosStoreError> {
            if self.unread.load(Ordering::Relaxed) {
                return Err(unanswered_db());
            }
            let disabled = self.disabled.lock().unwrap().clone();
            let sync = self.sync.lock().unwrap();
            let synced = sync.iter().filter(|(_, on)| **on);
            Ok(synced
                .map(|(user, _)| (UserId::new(user), disabled.contains(user)))
                .collect())
        }

        fn directory_users(&self, users: &[UserId]) -> Result<Vec<UserId>, KerberosStoreError> {
            if self.unread.load(Ordering::Relaxed) {
                return Err(unanswered_db());
            }
            let sync = self.sync.lock().unwrap();
            let present = users.iter().filter(|u| sync.contains_key(u.as_str()));
            Ok(present.cloned().collect())
        }

        fn start_pass_committed(&self) {
            *self.started_at.lock().unwrap() = Some(self.own.load(Ordering::Relaxed));
        }

        fn fill_alias_targets(&self, _: &[(String, String)]) -> Result<u64, KerberosStoreError> {
            Ok(0)
        }

        fn realm_not_held(&self) -> Option<String> {
            self.not_held.lock().unwrap().clone()
        }

        fn realm_unsettled(&self) -> Option<String> {
            self.unsettled.lock().unwrap().clone()
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
        synced(&embedded, &bob, "Bob-Password-1").await.unwrap();
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
        synced(&embedded, &bob, "Bob-Password-1").await.unwrap();
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

    /// A test's synced principal, made by the change a synced user's password takes.
    pub(crate) async fn synced(
        embedded: &EmbeddedKerberos,
        user: &UserId,
        password: &str,
    ) -> Result<(), CommitError> {
        let change = PasswordCommit {
            user: user.clone(),
            rows: Vec::new(),
            kind: LogKind::PasswordChange,
        };
        embedded.commit_password(change, password).await
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
                    synced(&embedded, &bob(), "Bob-Password-1").await.unwrap();
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
        synced(&embedded, &bob(), "Bob-Password-1").await.unwrap();
        synced(&embedded, &bob(), "Bob-Password-2").await.unwrap();
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
        let guard = LogGuard::install_on_this_thread();
        let temp = TempRealm::new();
        let (embedded, store) = temp.embedded();
        for user in ["alice", "gone", "nosync"] {
            synced(&embedded, &UserId::new(user), "A-Password-1")
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
                    disabled: 1,
                    followed: 0,
                    cleared: 0
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
        let rows: Vec<_> = temp
            .host
            .logged()
            .into_iter()
            .map(|(_, target, detail)| (target, detail))
            .collect();
        let row = |target: Option<&str>, detail: &str| {
            (target.map(str::to_owned), Some(detail.to_owned()))
        };
        assert_eq!(
            (rows, guard.recorder().take_events().len()),
            (
                vec![
                    row(Some("dave"), DISABLED_AT_START),
                    row(Some("gone"), "removed at start: user gone"),
                    row(Some("nosync"), "removed at start: no sync"),
                    row(None, "marked at start: 1 principals"),
                ],
                0
            ),
            "the rows commit in the sweep's transaction"
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
    async fn test_a_start_pass_keeps_the_rows_of_each_sweep_chunk_committed_before_one_fails() {
        let temp = TempRealm::new();
        let (embedded, store) = temp.embedded();
        let gone = ["ga", "gb", "gc", "gd"];
        for user in gone {
            synced(&embedded, &UserId::new(user), "A-Password-1")
                .await
                .unwrap();
        }
        let logged = temp.host.logged().len();
        temp.host.set_fault_after(1, Fault::Failed);
        let pass = embedded.start_pass_in(Vec::new(), 2).await;
        let after: Vec<_> = gone
            .into_iter()
            .map(|user| (user, marked(&store, user).is_some()))
            .collect();
        let committed = temp.host.logged().split_off(logged);
        let row = |user: &str| {
            let detail = Some("removed at start: user gone".to_owned());
            (LogKind::KerberosSync, Some(user.to_owned()), detail)
        };
        let sweep = "while sweeping the Kerberos principals at start";
        assert_eq!(
            (
                pass.map_err(|e| format!("{e:#}").contains(sweep)),
                after,
                committed
            ),
            (
                Err(true),
                vec![("ga", false), ("gb", false), ("gc", true), ("gd", true)],
                vec![row("ga"), row("gb")]
            ),
            "the first chunk's removals and their rows commit together and stay; the failed \
             chunk removes nothing and writes no row"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_each_marked_principal_follows_lldap_disabled_as_the_realm_opens() {
        use krb5_types::err::CLIENT_REVOKED;
        let guard = LogGuard::install_on_this_thread();
        let temp = TempRealm::new();
        let (embedded, store) = temp.embedded();
        for user in ["ann", "ben", "cy", "dee"] {
            synced(&embedded, &UserId::new(user), "A-Password-1")
                .await
                .unwrap();
        }
        embedded
            .set_principal_enabled(&UserId::new("ben"), false)
            .await
            .unwrap();
        unmarked(&embedded, "eve", false);
        for user in ["ann", "ben", "cy"] {
            temp.host.set_sync(user, true);
        }
        temp.host.set_directory(Some(&["ann", "dee", "eve"]));
        guard.recorder().take_events();
        let (writes, logged) = (temp.own_writes(), temp.host.logged().len());

        let followed = follow_statuses(&embedded.own(), None, 2, AT_OPEN).unwrap();
        let rows = temp.host.logged().split_off(logged);
        let recorded = guard.recorder().take_events().len();
        let after: Vec<_> = ["ann", "ben", "cy", "dee", "eve"]
            .into_iter()
            .map(|user| (user, marked(&store, user)))
            .collect();
        let row = |user: &str, detail: &str| {
            let user = Some(user.to_owned());
            (LogKind::KerberosSync, user, Some(detail.to_owned()))
        };
        assert_eq!(
            (followed, temp.own_writes() - writes, recorded, after, rows),
            (
                2,
                1,
                0,
                vec![
                    ("ann", Some((true, true))),
                    ("ben", Some((true, false))),
                    ("cy", Some((true, false))),
                    ("dee", Some((true, false))),
                    ("eve", Some((false, false))),
                ],
                vec![row("ann", DISABLED_AT_OPEN), row("ben", ENABLED_AT_OPEN)]
            ),
            "one change, its rows in it; a marked principal of a synced user follows, no other \
             is touched"
        );
        assert_eq!(
            (
                kinit_code(&store, "ann", "A-Password-1"),
                kinit_code(&store, "ben", "A-Password-1")
            ),
            (CLIENT_REVOKED, 0)
        );

        let again = follow_statuses(&embedded.own(), None, 2, AT_OPEN).unwrap();
        temp.host.set_directory(None);
        let unread = follow_statuses(&embedded.own(), None, 2, AT_OPEN);
        assert_eq!(
            (
                again,
                unread.map_err(|e| format!("{e:#}").starts_with(STATUSES_UNREAD)),
                temp.own_writes() - writes,
                marked(&store, "ann")
            ),
            (0, Err(true), 1, Some((true, true))),
            "a second opening writes nothing; an unread directory changes nothing"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_the_start_pass_sets_the_status_of_each_principal_it_marks() {
        let guard = LogGuard::install_on_this_thread();
        let temp = TempRealm::new();
        let (embedded, store) = temp.embedded();
        for user in ["fay", "gus"] {
            unmarked(&embedded, user, false);
            temp.host.set_sync(user, true);
        }
        temp.host.set_directory(Some(&["fay"]));
        guard.recorder().take_events();
        let users = vec![(UserId::new("fay"), true), (UserId::new("gus"), true)];
        let pass = embedded.start_pass(users.clone()).await.unwrap();
        let mut rows: Vec<_> = guard
            .recorder()
            .take_events()
            .into_iter()
            .map(|e| (e.target, e.detail))
            .collect();
        let committed = temp.host.logged().into_iter();
        rows.extend(committed.map(|(_, target, detail)| (target, detail)));
        let again = embedded.start_pass(users).await.unwrap();
        assert_eq!(
            (
                pass,
                again,
                marked(&store, "fay"),
                marked(&store, "gus"),
                rows
            ),
            (
                StartPass {
                    marked: 2,
                    followed: 1,
                    ..StartPass::default()
                },
                StartPass::default(),
                Some((true, true)),
                Some((true, false)),
                vec![
                    (None, Some("marked at start: 2 principals".to_owned())),
                    (Some("fay".to_owned()), Some(DISABLED_AT_OPEN.to_owned())),
                ]
            )
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_a_status_pass_keeps_the_rows_of_each_chunk_committed_before_one_fails() {
        let guard = LogGuard::install_on_this_thread();
        let temp = TempRealm::new();
        let (embedded, store) = temp.embedded();
        let users = ["ann", "ben", "cy", "dee"];
        for user in users {
            synced(&embedded, &UserId::new(user), "A-Password-1")
                .await
                .unwrap();
            temp.host.set_sync(user, true);
        }
        temp.host.set_directory(Some(&users[..]));
        guard.recorder().take_events();
        let logged = temp.host.logged().len();
        temp.host.set_fault_after(1, Fault::Failed);
        let queued = Arc::new(AtomicBool::new(true));
        let follow = embedded.follow();
        follow.statuses_in(queued.clone(), AT_TURN, 2).await;
        let after: Vec<_> = users
            .into_iter()
            .map(|user| (user, marked(&store, user)))
            .collect();
        let committed = temp.host.logged().split_off(logged);
        let recorded: Vec<_> = guard
            .recorder()
            .take_events()
            .into_iter()
            .map(|e| {
                let unset = e.detail.is_some_and(|d| d.starts_with(STATUSES_UNSET));
                (e.kind, e.target, e.success, unset)
            })
            .collect();
        let row = |user: &str| {
            let user = Some(user.to_owned());
            (
                LogKind::KerberosSync,
                user,
                Some(DISABLED_AT_TURN.to_owned()),
            )
        };
        assert_eq!(
            (after, committed, recorded, queued.load(Ordering::Acquire)),
            (
                vec![
                    ("ann", Some((true, true))),
                    ("ben", Some((true, true))),
                    ("cy", Some((true, false))),
                    ("dee", Some((true, false))),
                ],
                vec![row("ann"), row("ben")],
                vec![(LogKind::KerberosSync, None, false, true)],
                false
            ),
            "the first chunk's statuses and its rows commit together and stay; the failed chunk \
             changes nothing and writes no row, and the pass writes one failure row"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_the_holders_turn_removes_a_marked_principal_left_behind() {
        use krb5_types::err::C_PRINCIPAL_UNKNOWN;
        let guard = LogGuard::install_on_this_thread();
        let temp = TempRealm::new();
        let (embedded, store) = temp.embedded();
        for user in ["gone", "keep", "off"] {
            synced(&embedded, &UserId::new(user), "A-Password-1")
                .await
                .unwrap();
        }
        unmarked(&embedded, "kadm", false);
        temp.host.set_sync("keep", true);
        temp.host.set_sync("off", false);
        temp.host.set_directory(Some(&[]));
        guard.recorder().take_events();
        let logged = temp.host.logged().len();
        let queued = Arc::new(AtomicBool::new(true));
        embedded.follow().statuses_in(queued, AT_TURN, 2).await;
        let after: Vec<_> = ["gone", "keep", "off", "kadm"]
            .into_iter()
            .map(|user| (user, marked(&store, user)))
            .collect();
        let tickets: Vec<_> = ["gone", "keep", "off"]
            .into_iter()
            .map(|user| kinit_code(&store, user, "A-Password-1"))
            .collect();
        let committed = temp.host.logged().split_off(logged);
        let row = |user: &str, reason: &str| {
            let detail = format!("{REMOVED_AT_TURN}: {reason}");
            (LogKind::KerberosSync, Some(user.to_owned()), Some(detail))
        };
        assert_eq!(
            (
                after,
                tickets,
                committed,
                guard.recorder().take_events().len()
            ),
            (
                vec![
                    ("gone", None),
                    ("keep", Some((true, false))),
                    ("off", None),
                    ("kadm", Some((false, false))),
                ],
                vec![C_PRINCIPAL_UNKNOWN, 0, C_PRINCIPAL_UNKNOWN],
                vec![row("gone", USER_GONE), row("off", NO_SYNC)],
                0
            ),
            "a marked principal whose user is gone or has no sync goes at the turn, with its row \
             in the same transaction; an unmarked one stays"
        );

        let opened = follow_statuses(&embedded.own(), None, START_CHUNK, AT_OPEN).unwrap();
        assert_eq!(opened, 0, "an opening leaves removals to the start pass");
    }

    #[tokio::test]
    #[serial]
    async fn test_sync_turned_on_again_adopts_a_marked_principal_and_on_again_is_a_no_op() {
        use krb5_types::err::CLIENT_REVOKED;
        let temp = TempRealm::new();
        let (embedded, store) = temp.embedded();
        let dora = UserId::new("dora");
        synced(&embedded, &dora, "Dora-Password-0").await.unwrap();
        let before = kinit_code(&store, "dora", "Dora-Password-0");
        let on = embedded.commit_user(life("dora", UserStep::SyncOn)).await;
        let adopted = (
            marked(&store, "dora"),
            kinit_code(&store, "dora", "Dora-Password-0"),
        );
        temp.host.set_sync("dora", true);
        temp.host.set_directory(Some(&[]));
        let queued = Arc::new(AtomicBool::new(true));
        embedded.follow().statuses_in(queued, AT_TURN, 2).await;
        let enabled = (
            marked(&store, "dora"),
            kinit_code(&store, "dora", "Dora-Password-0") == 0,
        );
        synced(&embedded, &dora, "Dora-Password-1").await.unwrap();
        let again = embedded
            .commit_user(life("dora", UserStep::SyncUnchanged))
            .await;
        let kept = (
            marked(&store, "dora"),
            kinit_code(&store, "dora", "Dora-Password-1"),
        );
        assert_eq!(
            (before, on, adopted, enabled, again, kept),
            (
                0,
                Some(Ok(())),
                (Some((true, true)), CLIENT_REVOKED),
                (Some((true, false)), false),
                Some(Ok(())),
                (Some((true, false)), 0)
            ),
            "off to on adopts the marked principal: disabled, and once enabled the old password \
             gets no ticket; on to on changes nothing"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_a_lost_realm_is_not_ready_and_an_unsettled_one_is_held() {
        use lldap_auth::opaque::server::generate_random_private_key;
        use lldap_domain_handlers::kerberos::{
            ANSWER_UNSETTLED, KerberosState, NoopKerberos, require_kdc_ready, set_kerberos_backend,
            settled_state_of, state_of,
        };
        use lldap_domain_handlers::password::{
            PasswordSync, change_password_everywhere, realm_not_ready,
        };
        let lost = "the Kerberos realm was lost: another server took it";
        let mut states = Vec::new();
        let hooks = [
            (None, None),
            (Some(lost), None),
            (None, Some(ANSWER_UNSETTLED)),
        ];
        for (not_held, unsettled) in hooks {
            let temp = TempRealm::new();
            let (embedded, _store) = temp.embedded();
            *temp.host.not_held.lock().unwrap() = not_held.map(str::to_owned);
            *temp.host.unsettled.lock().unwrap() = unsettled.map(str::to_owned);
            states.push((
                state_of(&embedded),
                settled_state_of(&embedded),
                embedded.unavailable(),
            ));
        }
        let not_ready = |cause: &str| KerberosState::NotReady(cause.to_owned());
        assert_eq!(
            states,
            vec![
                (KerberosState::Ready, KerberosState::Ready, None),
                (not_ready(lost), not_ready(lost), Some(lost.to_owned())),
                (KerberosState::Ready, not_ready(ANSWER_UNSETTLED), None),
            ],
            "lost: not held; unsettled: held, and not settled"
        );

        let temp = TempRealm::new();
        let (embedded, _store) = temp.embedded();
        *temp.host.unsettled.lock().unwrap() = Some(ANSWER_UNSETTLED.to_owned());
        let pool = sea_orm::Database::connect("sqlite::memory:").await.unwrap();
        let handler =
            lldap_sql_backend_handler::SqlBackendHandler::new(generate_random_private_key(), pool);
        set_kerberos_backend(Arc::new(embedded));
        let log = LogGuard::install_on_this_thread();
        let plain = PasswordSync::Off;
        let answer = change_password_everywhere(
            &handler,
            &bob(),
            "Bob-Password-1",
            plain,
            PASSWORD_MIN_LENGTH,
        )
        .await;
        let directory = require_kdc_ready().is_ok();
        set_kerberos_backend(Arc::new(NoopKerberos::default()));
        let rows: Vec<_> = log
            .recorder()
            .take_events()
            .into_iter()
            .map(|e| (e.kind, e.target, e.success, e.detail))
            .collect();
        let refused = realm_not_ready(ANSWER_UNSETTLED);
        assert_eq!(
            (answer, directory, rows),
            (
                Err(refused.clone()),
                true,
                vec![(
                    LogKind::PasswordChange,
                    Some("bob".to_owned()),
                    false,
                    Some(refused.to_string())
                )]
            ),
            "while the last write is unsettled a password change is refused with one row, and a \
             directory write goes on"
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
            let changed = synced(&embedded, user, "A-Password-1").await;
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
                matches!(&changed, Err(CommitError::Refused(text)) if text.ends_with(why.as_str())),
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
                    now: lldap_domain_handlers::instant::Timestamp::now(),
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
                "committed, or its lost answer settled by the realm's generation",
                None,
                Ok(()),
                true,
            ),
            (
                "failed: the realm's generation did not move",
                Some(Fault::Failed),
                Err(CommitError::Failed(
                    "the database did not answer".to_owned(),
                )),
                false,
            ),
            (
                "unknown: the realm's generation could not be read back",
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
            synced(&embedded, &bob(), "Bob-Password-1").await.unwrap();
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
            synced(&embedded, &bob(), "Bob-Password-1").await.unwrap();
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
    fn test_the_committing_helpers_take_the_edit_after_their_own_arguments() {
        type Checks = fn(&PrincipalStore) -> Result<(), StoreError>;
        type Commit = fn(HostChange) -> Result<(), KerberosStoreError>;
        type Edit = fn(&mut PrincipalStore) -> Result<(), StoreError>;
        type Change = fn(
            &SharedDump,
            &PrincipalName,
            &str,
            &[u8],
            u32,
            &str,
            &[KeySalt],
            Checks,
            Commit,
            Edit,
        ) -> Result<(), StoreError>;
        type Create = fn(
            &SharedDump,
            &PrincipalName,
            &str,
            &[u8],
            &[KeySalt],
            &AdminEnt,
            &str,
            Checks,
            Commit,
            Edit,
        ) -> Result<(), StoreError>;
        let _: Change = krb5_kdc::change_password_shared_committing_then;
        let _: Create = krb5_kdc::create_password_shared_committing_then;
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
                "unmarked and enabled, disabled user: disabled and marked",
                Before::Unmarked(false),
                DISABLED,
                done(),
                (true, true),
            ),
            (
                "unmarked and disabled, enabled user: enabled and marked",
                Before::Unmarked(true),
                ENABLED,
                done(),
                (true, false),
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
                    synced(&embedded, &dora, "Dora-Password-0").await.unwrap();
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
            embedded.check_password(&bob(), "Short-7").await,
            Err("the password must be at least 8 characters".to_owned()),
            "no principal yet, and still the directory's floor"
        );
        assert_eq!(
            embedded.check_password(&bob(), "a\0aaaaaaa").await,
            Err(PASSWORD_HAS_NUL.to_owned()),
            "a NUL is refused before Kerberos reads the text"
        );
        synced(&embedded, &bob(), "Bob-Password-1").await.unwrap();
        let mut policy = krb5_kdc::NamedPolicy::new("min12");
        policy.min_length = 12;
        store.write().unwrap().put_policy(policy).unwrap();
        in_change(&embedded.own(), |s| {
            s.set_principal_policy(&user_principal(&bob()), Some("min12".to_owned()))
        })
        .unwrap();
        let commits = temp.commits();
        let refused = embedded
            .check_password(&bob(), "Short-10ch")
            .await
            .unwrap_err();
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
    async fn test_the_create_refuses_a_name_that_became_an_alias() {
        let temp = TempRealm::new();
        let (embedded, store) = temp.embedded();
        unmarked(&embedded, "svc", false);
        let (own, svc) = (embedded.own(), user_principal(&UserId::new("svc")));
        in_change(&own, |s| {
            s.create_alias_in(
                &user_principal(&bob()),
                "EXAMPLE.COM",
                &svc,
                "EXAMPLE.COM",
                "test",
            )?;
            s.remove_in(&svc, "EXAMPLE.COM")
        })
        .unwrap();
        let alias = || {
            let store = store.read().unwrap();
            let bob = store.get_raw("bob@EXAMPLE.COM");
            (
                bob.and_then(|p| p.alias_target()),
                bob.is_some_and(|p| p.keys.is_empty()),
            )
        };
        let (before, writes, called) = (alias(), temp.own_writes(), std::cell::Cell::new(false));
        let created = create_owned(
            &own,
            &bob(),
            b"Bob-Password-1",
            &embedded.enctypes,
            &embedded.new_principal(),
            Some(false),
            |_| {
                called.set(true);
                Ok(())
            },
        );
        let why = "the principal name of user bob is an alias of svc@EXAMPLE.COM";
        assert!(
            matches!(&created, Err(StoreError::InvalidArgument(text)) if text == why),
            "{created:?}"
        );
        assert_eq!(
            (
                before.clone(),
                alias(),
                temp.own_writes() - writes,
                called.get()
            ),
            ((Some("svc@EXAMPLE.COM".to_owned()), true), before, 0, false),
            "the dangling alias stays as it was and nothing reaches the host"
        );
    }

    pub(crate) fn kinit_code(store: &SharedDump, user: &str, password: &str) -> i32 {
        kinit_as(store, user, password, EncryptionType::Aes256CtsHmacSha196)
    }

    fn as_req_of(user: &str, password: &str, etype: EncryptionType) -> Vec<u8> {
        let name = user_principal(&UserId::new(user));
        let salt = name.default_salt("EXAMPLE.COM");
        let key = krb5_crypto::string_to_key(etype, password, salt, None).unwrap();
        let padata = vec![krb5_protocol::pa_enc_timestamp(&key).unwrap()];
        let request = krb5_protocol::as_req(name, "EXAMPLE.COM", 7, Some(padata)).unwrap();
        krb5_asn1::encode(&request).unwrap()
    }

    fn error_code(reply: &[u8]) -> i32 {
        krb5_asn1::decode::<krb5_types::KrbError>(reply).map_or(0, |e| e.error_code)
    }

    fn kinit_as(store: &SharedDump, user: &str, password: &str, etype: EncryptionType) -> i32 {
        let request = as_req_of(user, password, etype);
        let admission = Arc::new(crate::policy::AllowAll);
        store
            .write()
            .unwrap()
            .policy
            .plugins
            .set_host_admission(admission);
        let reply = krb5_kdc::handle_request(&*store.read().unwrap(), &request).unwrap();
        error_code(&reply)
    }

    /// An AS-REQ sent to `kdc` before this returns; the thread waits for its answer.
    pub(crate) fn ask(
        kdc: std::net::SocketAddr,
        user: &str,
        password: &str,
    ) -> std::thread::JoinHandle<(std::time::Instant, i32)> {
        let request = as_req_of(user, password, EncryptionType::Aes256CtsHmacSha196);
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        socket.send_to(&request, kdc).unwrap();
        std::thread::spawn(move || {
            socket
                .set_read_timeout(Some(Duration::from_secs(30)))
                .unwrap();
            let mut reply = vec![0; 65_536];
            let read = socket.recv(&mut reply).unwrap();
            (std::time::Instant::now(), error_code(&reply[..read]))
        })
    }

    impl Opened {
        pub(crate) fn kdc_udp(&self) -> std::net::SocketAddr {
            self.open.kdc_udp[0].local_addr().unwrap()
        }

        pub(crate) fn kadmin(&self) -> std::net::SocketAddr {
            self.open.kadmin.local_addr().unwrap()
        }

        pub(crate) fn store(&self) -> SharedDump {
            self.open.store.clone()
        }
    }

    #[tokio::test]
    #[serial]
    async fn test_an_imported_principal_is_answered_only_after_the_start_from_its_new_state() {
        use krb5_types::err::CLIENT_REVOKED;
        const PASSWORD: &str = "Ann-Password-1";
        let temp = TempRealm::new();
        let ann = UserId::new("ann");
        let (embedded, _store) = temp.embedded();
        let etypes: Vec<KeySalt> = temp
            .settings
            .supported_enctypes
            .iter()
            .map(|&e| e.into())
            .collect();
        in_change(&embedded.own(), |s| {
            let name = user_principal(&ann);
            s.insert_new_randkey(&name, "EXAMPLE.COM", &[], "test")?;
            let password = PASSWORD.as_bytes();
            s.set_password_etypes_keepold_n_in(&name, "EXAMPLE.COM", password, 0, "test", &etypes)
        })
        .unwrap();
        drop(embedded);
        temp.host.set_sync("ann", true);
        temp.host.set_directory(Some(&["ann"]));
        let imported = kinit_code(&krb5_kdc::shared_dump(temp.reopened()), "ann", PASSWORD);

        let (embedded, opened) = EmbeddedKerberos::open_on(&temp.settings, temp.own()).unwrap();
        let asked = ask(opened.kdc_udp(), "ann", PASSWORD);
        tokio::time::sleep(Duration::from_millis(200)).await;
        let at_open = asked.is_finished();
        let pass = embedded
            .start_pass(vec![(ann.clone(), true)])
            .await
            .unwrap();
        let served = std::time::Instant::now();
        let threads = opened.serve().unwrap();
        let (answered, code) = asked.join().unwrap();
        threads.stop();
        assert_eq!(
            (imported, at_open, pass.marked, pass.followed),
            (0, false, 1, 1),
            "the imported principal would have issued a ticket; the open answered nothing"
        );
        assert_eq!(
            (answered > served, code),
            (true, CLIENT_REVOKED),
            "the request sent before the passes is answered after serve, from the new state"
        );
    }

    fn life(user: &str, step: UserStep) -> UserChange {
        use lldap_domain::requests::UpdateUserRequest;
        use lldap_domain_handlers::logging::event;
        let id = UserId::new(user);
        let (row, kind) = match step {
            UserStep::Delete => (HostRow::DeleteUser(id.clone()), LogKind::UserDelete),
            _ => (
                HostRow::UpdateUser(UpdateUserRequest {
                    user_id: id.clone(),
                    ..Default::default()
                }),
                LogKind::UserUpdate,
            ),
        };
        UserChange {
            user: id,
            step,
            rows: vec![row, HostRow::Log(event(kind, Some(user), true, None))],
        }
    }

    #[tokio::test]
    #[serial]
    async fn test_a_delete_or_a_sync_change_and_its_principal_commit_together() {
        use krb5_types::err::{C_PRINCIPAL_UNKNOWN, CLIENT_REVOKED};
        #[derive(Clone, Copy)]
        enum Before {
            Nothing,
            Marked,
            Unmarked,
        }
        let failed = || {
            Err(CommitError::Failed(
                "the database did not answer".to_owned(),
            ))
        };
        let delete = vec!["delete dora", "log user_delete"];
        let update = vec!["update dora", "log user_update"];
        let adopted = vec!["update dora", "log user_update", "log kerberos_sync"];
        type Row = (
            &'static str,
            Before,
            UserStep,
            Option<Fault>,
            Result<(), CommitError>,
            Option<(bool, bool)>,
            Option<i32>,
            Vec<&'static str>,
        );
        let rows: Vec<Row> = vec![
            (
                "delete: the principal goes with the user",
                Before::Marked,
                UserStep::Delete,
                None,
                Ok(()),
                None,
                Some(C_PRINCIPAL_UNKNOWN),
                delete.clone(),
            ),
            (
                "delete without a principal: the user alone",
                Before::Nothing,
                UserStep::Delete,
                None,
                Ok(()),
                None,
                Some(C_PRINCIPAL_UNKNOWN),
                delete,
            ),
            (
                "delete fails: both stay",
                Before::Marked,
                UserStep::Delete,
                Some(Fault::Failed),
                failed(),
                Some((true, false)),
                Some(0),
                vec![],
            ),
            (
                "delete of a user gone meanwhile: both stay",
                Before::Marked,
                UserStep::Delete,
                Some(Fault::UserGone),
                Err(CommitError::UserGone),
                Some((true, false)),
                Some(0),
                vec![],
            ),
            (
                "sync off: the principal goes with the attribute",
                Before::Marked,
                UserStep::SyncOff,
                None,
                Ok(()),
                None,
                Some(C_PRINCIPAL_UNKNOWN),
                update.clone(),
            ),
            (
                "sync off fails: both stay",
                Before::Marked,
                UserStep::SyncOff,
                Some(Fault::Failed),
                failed(),
                Some((true, false)),
                Some(0),
                vec![],
            ),
            (
                "sync on, an unmarked principal: adopted and disabled, one row",
                Before::Unmarked,
                UserStep::SyncOn,
                None,
                Ok(()),
                Some((true, true)),
                Some(CLIENT_REVOKED),
                adopted.clone(),
            ),
            (
                "sync on, a marked principal left behind: adopted and disabled, one row",
                Before::Marked,
                UserStep::SyncOn,
                None,
                Ok(()),
                Some((true, true)),
                Some(CLIENT_REVOKED),
                adopted,
            ),
            (
                "sync on, no principal: the attribute alone",
                Before::Nothing,
                UserStep::SyncOn,
                None,
                Ok(()),
                None,
                Some(C_PRINCIPAL_UNKNOWN),
                update,
            ),
            (
                "sync on fails: not adopted",
                Before::Unmarked,
                UserStep::SyncOn,
                Some(Fault::Failed),
                failed(),
                Some((false, false)),
                None,
                vec![],
            ),
        ];
        let dora = UserId::new("dora");
        for (label, before, step, fault, expected, after, kinit, written) in rows {
            let temp = TempRealm::new();
            let (embedded, store) = temp.embedded();
            match before {
                Before::Nothing => {}
                Before::Marked => synced(&embedded, &dora, "Dora-Password-0").await.unwrap(),
                Before::Unmarked => unmarked(&embedded, "dora", false),
            }
            temp.host.set_fault(fault);
            let got = embedded.commit_user(life("dora", step)).await;
            temp.host.set_fault(None);
            let reopened = temp
                .reopened()
                .get_name(&user_principal(&dora))
                .map(|p| (p.host_owned(), p.locked()));
            assert_eq!(
                (got, marked(&store, "dora"), reopened, temp.host.rows()),
                (
                    Some(expected),
                    after,
                    after,
                    written
                        .iter()
                        .map(|r| (*r).to_owned())
                        .collect::<Vec<String>>()
                ),
                "{label}"
            );
            if let Some(code) = kinit {
                assert_eq!(
                    kinit_code(&store, "dora", "Dora-Password-0"),
                    code,
                    "{label}"
                );
            }
        }
    }

    fn status(user: &str, add: bool) -> UserChange {
        use lldap_domain::types::GroupId;
        use lldap_domain_handlers::logging::event;
        let id = UserId::new(user);
        let (step, kind) = match add {
            true => (UserStep::Disable, LogKind::MembershipAdd),
            false => (UserStep::Enable, LogKind::MembershipRemove),
        };
        let membership = HostRow::Membership {
            user: id.clone(),
            group: GroupId(7),
            add,
        };
        let log = event(kind, Some(user), true, Some("lldap_disabled"));
        UserChange {
            user: id,
            step,
            rows: vec![membership, HostRow::Log(log)],
        }
    }

    #[tokio::test]
    #[serial]
    async fn test_a_status_change_found_synced_under_the_lock_waits_until_the_realm_settles() {
        use lldap_domain_handlers::kerberos::ANSWER_UNSETTLED;
        let temp = TempRealm::new();
        let (embedded, store) = temp.embedded();
        synced(&embedded, &UserId::new("dora"), "Dora-Password-0")
            .await
            .unwrap();
        *temp.host.unsettled.lock().unwrap() = Some(ANSWER_UNSETTLED.to_owned());
        let writes = temp.own_writes();
        temp.host.set_sync("dora", true);
        let synced_user = embedded.commit_user(status("dora", true)).await;
        let held = (
            marked(&store, "dora"),
            temp.own_writes() - writes,
            temp.host.rows(),
        );
        temp.host.set_sync("dora", false);
        let plain_user = embedded.commit_user(status("dora", true)).await;
        let unsynced = (marked(&store, "dora"), temp.host.rows());
        assert_eq!(
            (synced_user, held, plain_user, unsynced),
            (
                Some(Err(CommitError::Unsettled(ANSWER_UNSETTLED.to_owned()))),
                (Some((true, false)), 0, Vec::new()),
                Some(Ok(())),
                (
                    Some((true, false)),
                    vec![
                        "unsynced dora".to_owned(),
                        "add dora to group 7".to_owned(),
                        "log membership_add".to_owned()
                    ]
                )
            ),
            "a user found synced under the lock waits for an unsettled realm and nothing \
             changes; a user found without sync goes on"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_a_disable_or_an_enable_and_its_principal_commit_together() {
        use krb5_types::err::{C_PRINCIPAL_UNKNOWN, CLIENT_REVOKED};
        #[derive(Clone, Copy)]
        enum Before {
            Nothing,
            Enabled,
            Disabled,
            Unmarked,
        }
        let failed = || {
            Err(CommitError::Failed(
                "the database did not answer".to_owned(),
            ))
        };
        let disable = vec!["synced dora", "add dora to group 7", "log membership_add"];
        let enable = vec![
            "synced dora",
            "remove dora from group 7",
            "log membership_remove",
        ];
        type Row = (
            &'static str,
            Before,
            bool,
            Option<Fault>,
            Result<(), CommitError>,
            Option<(bool, bool)>,
            Option<i32>,
            Vec<&'static str>,
        );
        let rows: Vec<Row> = vec![
            (
                "disable: the principal with the membership",
                Before::Enabled,
                true,
                None,
                Ok(()),
                Some((true, true)),
                Some(CLIENT_REVOKED),
                disable.clone(),
            ),
            (
                "disable fails: neither changes",
                Before::Enabled,
                true,
                Some(Fault::Failed),
                failed(),
                Some((true, false)),
                Some(0),
                vec![],
            ),
            (
                "enable: the principal with the membership",
                Before::Disabled,
                false,
                None,
                Ok(()),
                Some((true, false)),
                Some(0),
                enable,
            ),
            (
                "enable fails: neither changes",
                Before::Disabled,
                false,
                Some(Fault::Failed),
                failed(),
                Some((true, true)),
                Some(CLIENT_REVOKED),
                vec![],
            ),
            (
                "disable, a principal not marked: the membership alone",
                Before::Unmarked,
                true,
                None,
                Ok(()),
                Some((false, false)),
                None,
                disable.clone(),
            ),
            (
                "disable, no principal: the membership alone",
                Before::Nothing,
                true,
                None,
                Ok(()),
                None,
                Some(C_PRINCIPAL_UNKNOWN),
                disable,
            ),
            (
                "disable, a user without sync read under the lock: the membership alone",
                Before::Enabled,
                true,
                None,
                Ok(()),
                Some((true, false)),
                Some(0),
                vec!["unsynced dora", "add dora to group 7", "log membership_add"],
            ),
        ];
        let dora = UserId::new("dora");
        for (label, before, add, fault, expected, after, kinit, written) in rows {
            let temp = TempRealm::new();
            let (embedded, store) = temp.embedded();
            temp.host.set_sync("dora", !label.contains("without sync"));
            match before {
                Before::Nothing => {}
                Before::Enabled => synced(&embedded, &dora, "Dora-Password-0").await.unwrap(),
                Before::Disabled => {
                    synced(&embedded, &dora, "Dora-Password-0").await.unwrap();
                    embedded.set_principal_enabled(&dora, false).await.unwrap();
                }
                Before::Unmarked => unmarked(&embedded, "dora", false),
            }
            temp.host.set_fault(fault);
            let got = embedded.commit_user(status("dora", add)).await;
            temp.host.set_fault(None);
            let reopened = temp
                .reopened()
                .get_name(&user_principal(&dora))
                .map(|p| (p.host_owned(), p.locked()));
            let written: Vec<String> = written.iter().map(|r| (*r).to_owned()).collect();
            assert_eq!(
                (got, marked(&store, "dora"), reopened, temp.host.rows()),
                (Some(expected), after, after, written),
                "{label}"
            );
            if let Some(code) = kinit {
                assert_eq!(
                    kinit_code(&store, "dora", "Dora-Password-0"),
                    code,
                    "{label}"
                );
            }
        }
    }

    #[tokio::test]
    #[serial]
    async fn test_an_adopted_principal_takes_both_forms_at_the_next_change() {
        let temp = TempRealm::new();
        let (embedded, store) = temp.embedded();
        let dora = UserId::new("dora");
        unmarked(&embedded, "dora", false);
        temp.host.set_directory(Some(&[]));
        let adopted = embedded.commit_user(life("dora", UserStep::SyncOn)).await;
        let written = temp.host.rows();
        let after_adoption = marked(&store, "dora");
        let changed = embedded
            .commit_password(commit_of("dora", b"record-1"), "Dora-Password-1")
            .await;
        assert_eq!(
            (
                adopted,
                written,
                after_adoption,
                changed,
                marked(&store, "dora"),
                temp.host.password_record(&dora),
                kinit_code(&store, "dora", "Dora-Password-1")
            ),
            (
                Some(Ok(())),
                vec![
                    "update dora".to_owned(),
                    "log user_update".to_owned(),
                    "log kerberos_sync".to_owned()
                ],
                Some((true, true)),
                Ok(()),
                Some((true, false)),
                Some(b"record-1".to_vec()),
                0
            )
        );
    }

    fn put_policy(store: &SharedDump, name: &str, min_length: u32, pw_max_life: u32) {
        let mut policy = krb5_kdc::NamedPolicy::new(name);
        policy.min_length = min_length;
        policy.pw_max_life = pw_max_life;
        store.write().unwrap().put_policy(policy).unwrap();
    }

    fn bind_policy(embedded: &EmbeddedKerberos, name: &PrincipalName, policy: &str) {
        in_change(&embedded.own(), |s| {
            s.set_principal_policy(name, Some(policy.to_owned()))
        })
        .unwrap();
    }

    type Keys = Vec<(u32, EncryptionType, Vec<u8>)>;

    fn keys_of(store: &SharedDump, user: &str) -> Option<Keys> {
        let guard = store.read().unwrap();
        let p = guard.get_name(&user_principal(&UserId::new(user)))?;
        let keys = p.keys.iter();
        Some(
            keys.map(|k| (k.kvno, k.etype, k.key.as_bytes().to_vec()))
                .collect(),
        )
    }

    fn binding(store: &SharedDump, user: &str) -> Option<(bool, Option<String>, bool)> {
        let guard = store.read().unwrap();
        let p = guard.get_name(&user_principal(&UserId::new(user)))?;
        Some((p.host_owned(), p.pw_policy.clone(), p.pw_expire > 0))
    }

    const EXPIRES: u32 = 2_000_000_000;

    fn expire_at(embedded: &EmbeddedKerberos, user: &str, at: u32) {
        let fields = AdminFields {
            expiration: Some(at),
            ..Default::default()
        };
        let name = user_principal(&UserId::new(user));
        in_change(&embedded.own(), |s| {
            s.apply_admin_fields_in(&name, "EXAMPLE.COM", fields, "test")
        })
        .unwrap();
    }

    fn expiries(store: &SharedDump, user: &str) -> Option<(u32, u32)> {
        let guard = store.read().unwrap();
        let p = guard.get_name(&user_principal(&UserId::new(user)))?;
        Some((p.pw_expire, p.expiration))
    }

    type Logged = Vec<(LogKind, Option<String>, Option<String>)>;

    fn sync_rows(rows: Logged) -> Vec<(Option<String>, Option<String>)> {
        let rows = rows
            .into_iter()
            .filter(|(kind, ..)| *kind == LogKind::KerberosSync);
        rows.map(|(_, target, detail)| (target, detail)).collect()
    }

    fn cleared_from(user: &str, policy: &str) -> (Option<String>, Option<String>) {
        let detail = policy_cleared(policy, &format!("{user}@EXAMPLE.COM"));
        (Some(user.to_owned()), Some(detail))
    }

    #[tokio::test]
    #[serial]
    async fn test_the_bytes_judged_are_the_bytes_keyed() {
        use krb5_types::err::PREAUTH_FAILED;
        use lldap_auth::opaque::server::generate_random_private_key;
        use lldap_auth::password_length;
        use lldap_domain_handlers::kerberos::{NoopKerberos, set_kerberos_backend};
        use lldap_domain_handlers::password::{PasswordSync, change_password_everywhere};
        const TYPED: &str = "  Cafe\u{301}-Pass-12  ";
        const TRIMMED: &str = "Cafe\u{301}-Pass-12";
        const COMPOSED: &str = "  Caf\u{e9}-Pass-12  ";
        const LOWERED: &str = "  cafe\u{301}-pass-12  ";
        assert_eq!(
            [TYPED, TRIMMED, COMPOSED, LOWERED].map(|p| (password_length(p), p.len())),
            [(17, 18), (13, 14), (16, 17), (17, 18)]
        );
        let temp = TempRealm::new();
        let (embedded, store) = temp.embedded();
        temp.host.set_sync("bob", true);
        let pool = sea_orm::Database::connect("sqlite::memory:").await.unwrap();
        let handler =
            lldap_sql_backend_handler::SqlBackendHandler::new(generate_random_private_key(), pool);
        set_kerberos_backend(Arc::new(embedded));
        let changed = change_password_everywhere(
            &handler,
            &bob(),
            TYPED,
            PasswordSync::On,
            PASSWORD_MIN_LENGTH,
        )
        .await;
        set_kerberos_backend(Arc::new(NoopKerberos::default()));
        let tried = [TYPED, TRIMMED, COMPOSED, LOWERED].map(|p| (p, kinit_code(&store, "bob", p)));
        assert_eq!(
            (changed, temp.host.password_record(&bob()).is_some(), tried),
            (
                Ok(()),
                true,
                [
                    (TYPED, 0),
                    (TRIMMED, PREAUTH_FAILED),
                    (COMPOSED, PREAUTH_FAILED),
                    (LOWERED, PREAUTH_FAILED)
                ]
            ),
            "the synced change keys the bytes as typed: not trimmed, not composed, not lowered"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_an_adopted_principal_loses_its_kerberos_policy_and_the_directory_minimum_applies()
    {
        use lldap_auth::opaque::server::generate_random_private_key;
        use lldap_domain_handlers::kerberos::{NoopKerberos, set_kerberos_backend};
        use lldap_domain_handlers::password::{
            PasswordChangeError, PasswordSync, change_password_everywhere,
        };
        const SEVEN: &str = "Dora-P7";
        const EIGHT: &str = "Dora-Pw8";
        const ELEVEN: &str = "Dora-Pass-1";
        const ELEVEN_IN_13_BYTES: &str = "Dörä-Pass-1";
        assert_eq!(
            [SEVEN, EIGHT, ELEVEN, ELEVEN_IN_13_BYTES].map(|p| (p.chars().count(), p.len())),
            [(7, 7), (8, 8), (11, 11), (11, 13)]
        );
        let dora = UserId::new("dora");
        let adoption_rows = vec![
            (Some("dora".to_owned()), Some(ADOPTED.to_owned())),
            cleared_from("dora", "min12"),
        ];
        let too_short = vec![(
            Some("dora".to_owned()),
            Some("the password must be at least 8 characters".to_owned()),
        )];
        let pool = sea_orm::Database::connect("sqlite::memory:").await.unwrap();
        let handler =
            lldap_sql_backend_handler::SqlBackendHandler::new(generate_random_private_key(), pool);
        let log = LogGuard::install_on_this_thread();
        for password in [EIGHT, ELEVEN] {
            let temp = TempRealm::new();
            let (embedded, store) = temp.embedded();
            unmarked(&embedded, "dora", false);
            expire_at(&embedded, "dora", EXPIRES);
            put_policy(&store, "min12", 12, 86_400);
            bind_policy(&embedded, &user_principal(&dora), "min12");
            temp.host.set_directory(Some(&[]));
            let before = (
                binding(&store, "dora"),
                expiries(&store, "dora").map(|e| e.1),
            );
            let logged = temp.host.logged().len();
            let adopted = embedded.commit_user(life("dora", UserStep::SyncOn)).await;
            let after_adoption = (binding(&store, "dora"), expiries(&store, "dora"));
            let rows = sync_rows(temp.host.logged().split_off(logged));
            let in_bytes = embedded.check_password(&dora, ELEVEN_IN_13_BYTES).await;
            log.recorder().take_events();
            set_kerberos_backend(Arc::new(embedded));
            let change = |password: &'static str| {
                let (handler, dora) = (&handler, &dora);
                async move {
                    let on = PasswordSync::On;
                    change_password_everywhere(handler, dora, password, on, PASSWORD_MIN_LENGTH)
                        .await
                }
            };
            let answer = change(password).await;
            let (record, keys) = (temp.host.password_record(&dora), keys_of(&store, "dora"));
            let taken = (record.is_some(), kinit_code(&store, "dora", password));
            let refused = change(SEVEN).await;
            let unmoved = (
                temp.host.password_record(&dora) == record,
                keys_of(&store, "dora") == keys,
                kinit_code(&store, "dora", password),
            );
            set_kerberos_backend(Arc::new(NoopKerberos::default()));
            let failed: Vec<_> = log
                .recorder()
                .take_events()
                .into_iter()
                .filter(|e| e.kind == LogKind::PasswordChange && !e.success)
                .map(|e| (e.target, e.detail))
                .collect();
            assert_eq!(
                (before, adopted, after_adoption, rows, in_bytes),
                (
                    (Some((false, Some("min12".to_owned()), true)), Some(EXPIRES)),
                    Some(Ok(())),
                    (Some((true, None, false)), Some((0, EXPIRES))),
                    adoption_rows.clone(),
                    Ok(())
                ),
                "{password}: the adoption clears the binding and the password expiry it set in \
                 its own change, with its row, and the principal's own expiry stays; the 13-byte \
                 check answers as with no policy"
            );
            assert_eq!(
                (
                    answer,
                    taken,
                    refused,
                    unmoved,
                    failed,
                    binding(&store, "dora"),
                    expiries(&store, "dora")
                ),
                (
                    Ok(()),
                    (true, 0),
                    Err(PasswordChangeError::TooShort(PASSWORD_MIN_LENGTH)),
                    (true, true, 0),
                    too_short.clone(),
                    Some((true, None, false)),
                    Some((0, EXPIRES))
                ),
                "{password}: taken on both sides; 7 characters are refused by the directory's \
                 floor and neither the record nor the keys move"
            );
        }
    }

    #[tokio::test]
    #[serial]
    async fn test_an_add_with_a_password_onto_a_bound_principal_is_judged_once_by_its_old_policy() {
        use lldap_auth::opaque::server::generate_random_private_key;
        use lldap_domain::requests::CreateUserRequest;
        use lldap_domain_handlers::kerberos::{NoopKerberos, set_kerberos_backend};
        use lldap_domain_handlers::password::{
            PasswordChangeError, PasswordSync, change_password_everywhere, create_synced_user,
        };
        const REFUSED: &str = "password policy: min_length 12";
        const EIGHT: &str = "Fred-Pw8";
        const TWELVE: &str = "Fred-Pass-12";
        const NINE: &str = "Fred-Pw-9";
        assert_eq!(
            [EIGHT, TWELVE, NINE].map(|p| (p.chars().count(), p.len())),
            [(8, 8), (12, 12), (9, 9)]
        );
        let fred = UserId::new("fred");
        let temp = TempRealm::new();
        let (embedded, store) = temp.embedded();
        unmarked(&embedded, "fred", false);
        put_policy(&store, "min12", 12, 86_400);
        bind_policy(&embedded, &user_principal(&fred), "min12");
        temp.host.set_directory(Some(&[]));
        let (keys, logged) = (keys_of(&store, "fred"), temp.host.logged().len());
        let pool = sea_orm::Database::connect("sqlite::memory:").await.unwrap();
        let handler =
            lldap_sql_backend_handler::SqlBackendHandler::new(generate_random_private_key(), pool);
        let log = LogGuard::install_on_this_thread();
        set_kerberos_backend(Arc::new(embedded));
        let add = |password: &'static str| {
            let request = CreateUserRequest {
                user_id: fred.clone(),
                ..Default::default()
            };
            create_synced_user(&handler, request, password, PASSWORD_MIN_LENGTH)
        };
        let refused = add(EIGHT).await;
        let after_refusal = (
            binding(&store, "fred"),
            keys_of(&store, "fred") == keys,
            temp.host.rows(),
            temp.host.password_record(&fred),
        );
        let failed: Vec<_> = log
            .recorder()
            .take_events()
            .into_iter()
            .filter(|e| e.kind == LogKind::UserCreate && !e.success)
            .map(|e| (e.target, e.detail))
            .collect();
        let added = add(TWELVE).await;
        let after_add = (
            binding(&store, "fred"),
            expiries(&store, "fred").map(|(pw_expire, _)| pw_expire),
            temp.host.rows(),
            sync_rows(temp.host.logged().split_off(logged)),
            temp.host.password_record(&fred).is_some(),
            kinit_code(&store, "fred", TWELVE),
        );
        let next = change_password_everywhere(
            &handler,
            &fred,
            NINE,
            PasswordSync::On,
            PASSWORD_MIN_LENGTH,
        )
        .await;
        let after_next = (binding(&store, "fred"), kinit_code(&store, "fred", NINE));
        set_kerberos_backend(Arc::new(NoopKerberos::default()));
        assert_eq!(
            (refused, after_refusal, failed),
            (
                Err(PasswordChangeError::Refused(REFUSED.to_owned())),
                (
                    Some((false, Some("min12".to_owned()), true)),
                    true,
                    Vec::<String>::new(),
                    None
                ),
                vec![(
                    Some("fred".to_owned()),
                    Some(format!("refused by Kerberos: {REFUSED}"))
                )]
            ),
            "the known moment: the add that would adopt is judged by the principal's old policy \
             before the mark; refused, nothing is made and the principal stays as it was"
        );
        assert_eq!(
            (added, after_add, next, after_next),
            (
                Ok(()),
                (
                    Some((true, None, false)),
                    Some(0),
                    [
                        "create fred",
                        "password fred",
                        "synced fred",
                        "log user_create",
                        "log password_change",
                        "log kerberos_sync"
                    ]
                    .map(str::to_owned)
                    .to_vec(),
                    vec![cleared_from("fred", "min12")],
                    true,
                    0
                ),
                Ok(()),
                (Some((true, None, false)), 0)
            ),
            "a password both take adopts the principal and clears the binding and the password \
             expiry it set in the mark's change, with its row; the next change is judged by the \
             directory's minimum alone"
        );
    }

    type View = Vec<(String, bool, Option<String>, bool)>;

    fn policy_view(store: &SharedDump) -> View {
        let guard = store.read().unwrap();
        let ids = guard.ids();
        let all = ids.iter().filter_map(|id| guard.get_raw(id));
        all.filter(|p| p.host_owned() || p.pw_policy.is_some())
            .map(|p| {
                let name = p.name.unparse_no_realm_lossy();
                (name, p.host_owned(), p.pw_policy.clone(), p.pw_expire > 0)
            })
            .collect()
    }

    fn service_principal(embedded: &EmbeddedKerberos) -> PrincipalName {
        let svc = PrincipalName::new(PrincipalName::NT_SRV_HST, ["svc", "host"]);
        in_change(&embedded.own(), |s| {
            s.insert_new_randkey(&svc, "EXAMPLE.COM", &[], "test")
        })
        .unwrap();
        svc
    }

    fn view(
        name: &str,
        owned: bool,
        policy: Option<&str>,
        expires: bool,
    ) -> (String, bool, Option<String>, bool) {
        (name.to_owned(), owned, policy.map(str::to_owned), expires)
    }

    #[tokio::test]
    #[serial]
    async fn test_the_start_pass_clears_the_kerberos_policy_of_each_directory_principal_once() {
        let guard = LogGuard::install_on_this_thread();
        let temp = TempRealm::new();
        let (embedded, store) = temp.embedded();
        temp.host.set_directory(Some(&[]));
        put_policy(&store, "min12", 12, 86_400);
        for user in ["pat", "quinn", "rae"] {
            synced(&embedded, &UserId::new(user), "A-Password-1")
                .await
                .unwrap();
        }
        expire_at(&embedded, "pat", EXPIRES);
        unmarked(&embedded, "sam", false);
        unmarked(&embedded, "tess", true);
        let svc = service_principal(&embedded);
        let bound = [
            ("pat", "min12"),
            ("quinn", "gone"),
            ("sam", "min12"),
            ("tess", "min12"),
        ];
        for (user, policy) in bound {
            bind_policy(&embedded, &user_principal(&UserId::new(user)), policy);
        }
        bind_policy(&embedded, &svc, "min12");
        let users: Vec<(UserId, bool)> = [
            ("pat", true),
            ("quinn", true),
            ("rae", true),
            ("sam", true),
            ("tess", false),
        ]
        .into_iter()
        .map(|(user, sync)| (UserId::new(user), sync))
        .collect();
        let policies = store.read().unwrap().policies().clone();
        let logged = temp.host.logged().len();
        guard.recorder().take_events();

        let pass = embedded.start_pass_in(users.clone(), 2).await.unwrap();
        let rows = sync_rows(temp.host.logged().split_off(logged));
        let reloaded = temp
            .reopened()
            .get_name(&user_principal(&UserId::new("pat")))
            .map(|p| p.pw_policy.clone());
        assert_eq!(
            (
                pass,
                policy_view(&store),
                rows,
                guard.recorder().take_events().len()
            ),
            (
                StartPass {
                    marked: 1,
                    cleared: 3,
                    ..StartPass::default()
                },
                vec![
                    view("pat", true, None, false),
                    view("quinn", true, None, false),
                    view("rae", true, None, false),
                    view("sam", true, None, false),
                    view("svc/host", false, Some("min12"), true),
                    view("tess", false, Some("min12"), true),
                ],
                vec![
                    cleared_from("sam", "min12"),
                    (None, Some("marked at start: 1 principals".to_owned())),
                    cleared_from("pat", "min12"),
                    cleared_from("quinn", "gone"),
                ],
                0
            ),
            "a principal the start marks loses its binding in the mark's change; one marked \
             before loses it, its policy found or not, with its expiry, one row each in the \
             change; a principal the directory does not own keeps its binding"
        );
        assert_eq!(
            (
                store.read().unwrap().policies() == &policies,
                reloaded,
                expiries(&store, "pat")
            ),
            (true, Some(None), Some((0, EXPIRES))),
            "no policy is removed, the clear reached the host, and pat's own expiry stays"
        );

        let (writes, logged) = (temp.own_writes(), temp.host.logged().len());
        let again = embedded.start_pass_in(users, 2).await.unwrap();
        assert_eq!(
            (again, temp.own_writes(), temp.host.logged().len()),
            (StartPass::default(), writes, logged),
            "a second start finds no binding and writes nothing"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_a_policy_clear_that_fails_at_start_leaves_the_start_going_and_the_next_clears_it()
    {
        let temp = TempRealm::new();
        let (embedded, store) = temp.embedded();
        temp.host.set_directory(Some(&[]));
        put_policy(&store, "min12", 12, 0);
        let names = ["pat", "quinn", "rae"];
        for user in names {
            synced(&embedded, &UserId::new(user), "A-Password-1")
                .await
                .unwrap();
            bind_policy(&embedded, &user_principal(&UserId::new(user)), "min12");
        }
        let users: Vec<_> = names.iter().map(|u| (UserId::new(u), true)).collect();
        let bound = || names.map(|u| binding(&store, u).and_then(|(_, policy, _)| policy));
        let min12 = || Some("min12".to_owned());
        let logged = temp.host.logged().len();
        temp.host.set_fault_after(1, Fault::Failed);
        let failed = embedded.start_pass_in(users.clone(), 2).await;
        let flagged = temp.host.started_at.lock().unwrap().take().is_some();
        let after_failure = (bound(), sync_rows(temp.host.logged().split_off(logged)));
        assert_eq!(
            (failed.map_err(|e| format!("{e:#}")), flagged, after_failure),
            (
                Ok(StartPass {
                    cleared: 2,
                    ..StartPass::default()
                }),
                true,
                (
                    [None, None, min12()],
                    vec![cleared_from("pat", "min12"), cleared_from("quinn", "min12")]
                )
            ),
            "the first chunk's clears commit with their rows; the failed chunk changes nothing \
             and writes no row, and the start goes on to its end"
        );

        *temp.host.fault_after.lock().unwrap() = None;
        let logged = temp.host.logged().len();
        let next = embedded.start_pass_in(users.clone(), 2).await;
        let rows = sync_rows(temp.host.logged().split_off(logged));
        let writes = temp.own_writes();
        let again = embedded.start_pass_in(users, 2).await;
        assert_eq!(
            (
                next.map_err(|e| format!("{e:#}")),
                bound(),
                rows,
                again.map_err(|e| format!("{e:#}")),
                temp.own_writes() - writes
            ),
            (
                Ok(StartPass {
                    cleared: 1,
                    ..StartPass::default()
                }),
                [None, None, None],
                vec![cleared_from("rae", "min12")],
                Ok(StartPass::default()),
                0
            ),
            "the next start clears what was left, once"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_a_principal_the_directory_stops_owning_after_the_listing_keeps_its_policy() {
        let temp = TempRealm::new();
        let (embedded, store) = temp.embedded();
        temp.host.set_directory(Some(&[]));
        put_policy(&store, "min12", 12, 86_400);
        for user in ["pat", "quinn"] {
            synced(&embedded, &UserId::new(user), "A-Password-1")
                .await
                .unwrap();
            bind_policy(&embedded, &user_principal(&UserId::new(user)), "min12");
        }
        let listed = bound_principals(&store.read().unwrap(), "EXAMPLE.COM");
        let quinn = user_principal(&UserId::new("quinn"));
        in_change(&embedded.own(), |s| {
            s.set_host_owned_in(&quinn, "EXAMPLE.COM", false)
        })
        .unwrap();
        let logged = temp.host.logged().len();
        let cleared = clear_chunk(&embedded.own(), &listed).map(|written| written.len());
        let rows = sync_rows(temp.host.logged().split_off(logged));
        let names: Vec<String> = listed.iter().map(|n| n.unparse_no_realm_lossy()).collect();
        assert_eq!(
            (
                names,
                cleared.map_err(|e| e.to_string()),
                rows,
                policy_view(&store)
            ),
            (
                vec!["pat".to_owned(), "quinn".to_owned()],
                Ok(1),
                vec![cleared_from("pat", "min12")],
                vec![
                    view("pat", true, None, false),
                    view("quinn", false, Some("min12"), true),
                ]
            ),
            "a principal the directory no longer owns when the change runs keeps its binding \
             and its expiry, with no row; the one still owned is cleared"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_after_adoption_no_rule_of_the_old_policy_survives() {
        use lldap_auth::opaque::server::generate_random_private_key;
        use lldap_domain_handlers::kerberos::{NoopKerberos, set_kerberos_backend};
        use lldap_domain_handlers::password::{PasswordSync, change_password_everywhere};
        const FIRST: &str = "Hana-Pass-1";
        const SECOND: &str = "Hana-Pass-2";
        const LOWER: &str = "allinlowercase";
        let hana = UserId::new("hana");
        let name = user_principal(&hana);
        let temp = TempRealm::new();
        let (embedded, store) = temp.embedded();
        unmarked(&embedded, "hana", false);
        let mut policy = krb5_kdc::NamedPolicy::new("rules");
        policy.history = 2;
        policy.min_classes = 3;
        store.write().unwrap().put_policy(policy).unwrap();
        bind_policy(&embedded, &name, "rules");
        for password in [FIRST, SECOND] {
            in_change(&embedded.own(), |s| {
                let etypes = &embedded.enctypes;
                let bytes = password.as_bytes();
                s.set_password_etypes_keepold_n_in(&name, "EXAMPLE.COM", bytes, 0, "test", etypes)
            })
            .unwrap();
        }
        temp.host.set_directory(Some(&[]));
        let mut old_rules = Vec::new();
        for password in [FIRST, SECOND, LOWER] {
            old_rules.push(embedded.check_password(&hana, password).await);
        }
        let adopted = embedded.commit_user(life("hana", UserStep::SyncOn)).await;
        let pool = sea_orm::Database::connect("sqlite::memory:").await.unwrap();
        let handler =
            lldap_sql_backend_handler::SqlBackendHandler::new(generate_random_private_key(), pool);
        set_kerberos_backend(Arc::new(embedded));
        let mut taken = Vec::new();
        for password in [FIRST, FIRST, LOWER] {
            let on = PasswordSync::On;
            let answer =
                change_password_everywhere(&handler, &hana, password, on, PASSWORD_MIN_LENGTH)
                    .await;
            taken.push((answer, kinit_code(&store, "hana", password)));
        }
        set_kerberos_backend(Arc::new(NoopKerberos::default()));
        let refused =
            |rule: &str| -> Result<(), String> { Err(format!("password policy: {rule}")) };
        assert_eq!(
            (old_rules, adopted, taken, binding(&store, "hana")),
            (
                vec![
                    refused("history"),
                    refused("history"),
                    refused("min_classes 3")
                ],
                Some(Ok(())),
                vec![(Ok(()), 0), (Ok(()), 0), (Ok(()), 0)],
                Some((true, None, false))
            ),
            "before adoption the policy refuses the previous and the current password by history \
             and an all-lowercase one by classes; after it, the previous password, the same one \
             again and the all-lowercase one are each taken on both sides"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_no_directory_principal_keeps_a_kerberos_policy_both_sides_agree_at_the_minimum() {
        use lldap_auth::opaque::server::generate_random_private_key;
        use lldap_domain::requests::CreateUserRequest;
        use lldap_domain_handlers::kerberos::{NoopKerberos, set_kerberos_backend};
        use lldap_domain_handlers::logging::event;
        use lldap_domain_handlers::password::{
            PasswordChangeError, PasswordSync, change_password_everywhere,
        };
        const MIN: usize = 12;
        let (twelve, eleven) = ("ä".repeat(MIN), "ä".repeat(MIN - 1));
        assert_eq!(
            [&twelve, &eleven].map(|p| (p.chars().count(), p.len())),
            [(12, 24), (11, 22)]
        );
        let temp = TempRealm::new();
        let (embedded, store) = temp.embedded();
        temp.host.set_directory(Some(&[]));
        put_policy(&store, "default", 30, 0);
        put_policy(&store, "min40", 40, 0);
        synced(&embedded, &UserId::new("ann"), "Ann-Password-1")
            .await
            .unwrap();
        unmarked(&embedded, "ben", false);
        unmarked(&embedded, "cy", false);
        unmarked(&embedded, "dan", true);
        let svc = service_principal(&embedded);
        let bound = [
            ("ann", "default"),
            ("ben", "default"),
            ("cy", "min40"),
            ("dan", "default"),
        ];
        for (user, policy) in bound {
            bind_policy(&embedded, &user_principal(&UserId::new(user)), policy);
        }
        bind_policy(&embedded, &svc, "default");
        let users: Vec<(UserId, bool)> =
            [("ann", true), ("ben", true), ("cy", false), ("dan", false)]
                .into_iter()
                .map(|(user, sync)| (UserId::new(user), sync))
                .collect();
        let logged = temp.host.logged().len();

        let pass = embedded.start_pass(users).await.unwrap();
        let adopted = embedded.commit_user(life("cy", UserStep::SyncOn)).await;
        let eve = UserId::new("eve");
        let request = CreateUserRequest {
            user_id: eve.clone(),
            ..Default::default()
        };
        let created = embedded
            .commit_user(UserChange {
                user: eve.clone(),
                step: UserStep::Create,
                rows: vec![
                    HostRow::CreateUser(request),
                    HostRow::Log(event(LogKind::UserCreate, Some("eve"), true, None)),
                ],
            })
            .await;
        synced(&embedded, &eve, "Eve-Password-1").await.unwrap();
        let rows = sync_rows(temp.host.logged().split_off(logged));
        assert_eq!(
            (pass, adopted, created, policy_view(&store), rows),
            (
                StartPass {
                    marked: 1,
                    disabled: 1,
                    cleared: 2,
                    ..StartPass::default()
                },
                Some(Ok(())),
                Some(Ok(())),
                vec![
                    view("ann", true, None, false),
                    view("ben", true, None, false),
                    view("cy", true, None, false),
                    view("dan", false, Some("default"), false),
                    view("eve", true, None, false),
                    view("svc/host", false, Some("default"), false),
                ],
                vec![
                    cleared_from("ben", "default"),
                    (Some("cy".to_owned()), Some(DISABLED_AT_START.to_owned())),
                    (None, Some("marked at start: 1 principals".to_owned())),
                    cleared_from("ann", "default"),
                    (Some("cy".to_owned()), Some(ADOPTED.to_owned())),
                    cleared_from("cy", "min40"),
                ]
            ),
            "after the start, an adoption and a create with sync while a policy named default \
             exists, no principal the directory owns carries a binding; the others keep theirs"
        );

        let ben = UserId::new("ben");
        let pool = sea_orm::Database::connect("sqlite::memory:").await.unwrap();
        let handler =
            lldap_sql_backend_handler::SqlBackendHandler::new(generate_random_private_key(), pool);
        let embedded = Arc::new(embedded);
        set_kerberos_backend(embedded.clone());
        let unowned = embedded.check_password(&UserId::new("dan"), &twelve).await;
        let at_min =
            change_password_everywhere(&handler, &ben, &twelve, PasswordSync::On, MIN).await;
        let (record, keys) = (temp.host.password_record(&ben), keys_of(&store, "ben"));
        let taken = (record.is_some(), kinit_code(&store, "ben", &twelve));
        let below =
            change_password_everywhere(&handler, &ben, &eleven, PasswordSync::On, MIN).await;
        let unmoved = (
            temp.host.password_record(&ben) == record,
            keys_of(&store, "ben") == keys,
            kinit_code(&store, "ben", &twelve),
        );
        set_kerberos_backend(Arc::new(NoopKerberos::default()));
        assert_eq!(
            (unowned, at_min, taken, below, unmoved),
            (
                Err("password policy: min_length 30".to_owned()),
                Ok(()),
                (true, 0),
                Err(PasswordChangeError::TooShort(MIN)),
                (true, true, 0)
            ),
            "12 characters in 24 bytes, under the 30 bytes of the policy ben was bound to: the \
             directory takes them and so does the KDC; 11 are refused and nothing moves. The \
             unowned dan is still held to its policy"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_a_user_name_that_is_an_alias_deletes_the_user_alone_and_refuses_sync_on() {
        let temp = TempRealm::new();
        let (embedded, store) = temp.embedded();
        unmarked(&embedded, "svc", false);
        in_change(&embedded.own(), |s| {
            s.create_alias_in(
                &user_principal(&bob()),
                "EXAMPLE.COM",
                &user_principal(&UserId::new("svc")),
                "EXAMPLE.COM",
                "test",
            )
        })
        .unwrap();
        let why = "the principal name of user bob is an alias of svc@EXAMPLE.COM; \
                   remove that alias first (kadmin delprinc bob@EXAMPLE.COM)";
        let (svc, writes) = (fields(&store, "svc"), temp.own_writes());
        let asked = (
            embedded.sync_on_refused(&bob()).await,
            embedded.sync_on_refused(&UserId::new("svc")).await,
        );
        assert_eq!(
            asked,
            (Err(why.to_owned()), Ok(())),
            "asked before a create"
        );
        let sync_on = embedded.commit_user(life("bob", UserStep::SyncOn)).await;
        let refused = (temp.own_writes() - writes, temp.host.rows());
        let deleted = embedded.commit_user(life("bob", UserStep::Delete)).await;
        let raw = store
            .read()
            .unwrap()
            .get_raw("bob@EXAMPLE.COM")
            .map(|p| p.alias_target());
        assert_eq!(
            (
                sync_on,
                refused,
                deleted,
                temp.host.rows(),
                raw,
                fields(&store, "svc")
            ),
            (
                Some(Err(CommitError::Refused(why.to_owned()))),
                (0, Vec::new()),
                Some(Ok(())),
                vec![
                    "delete bob".to_owned(),
                    "log user_delete".to_owned(),
                    "log kerberos_sync".to_owned()
                ],
                Some(Some("svc@EXAMPLE.COM".to_owned())),
                svc
            )
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_a_user_change_waits_for_the_write_lock_only_so_long() {
        let temp = TempRealm::new();
        let (mut embedded, store) = temp.embedded();
        synced(&embedded, &bob(), "Bob-Password-1").await.unwrap();
        embedded.write_wait = Duration::from_millis(20);
        let held = embedded.writes.clone().lock_owned().await;
        let writes = temp.own_writes();
        let busy = embedded.commit_user(life("bob", UserStep::Delete)).await;
        assert_eq!(
            (busy, temp.own_writes(), marked(&store, "bob")),
            (Some(Err(CommitError::Busy)), writes, Some((true, false)))
        );
        drop(held);
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

    #[tokio::test]
    #[serial]
    async fn test_a_password_change_and_a_sync_off_in_either_order() {
        let synced_change = || {
            let mut change = commit_of("bob", b"record");
            change.rows.insert(1, HostRow::SyncIs(bob(), true));
            change
        };
        let temp = TempRealm::new();
        let (embedded, store) = temp.embedded();
        temp.host.set_sync("bob", false);
        let refused = embedded
            .commit_password(synced_change(), "Bob-Password-1")
            .await;
        let reopened = temp.reopened().get_name(&user_principal(&bob())).is_some();
        assert_eq!(
            (
                refused,
                marked(&store, "bob"),
                reopened,
                temp.host.rows(),
                temp.host.password_record(&bob())
            ),
            (
                Err(CommitError::Refused(SYNC_CHANGED.to_owned())),
                None,
                false,
                Vec::<String>::new(),
                None
            ),
            "the sync off first: refused, no principal is made and no row is written"
        );

        let temp = TempRealm::new();
        let (embedded, store) = temp.embedded();
        temp.host.set_sync("bob", true);
        let written = embedded
            .commit_password(synced_change(), "Bob-Password-1")
            .await;
        let after_change = (
            marked(&store, "bob"),
            kinit_code(&store, "bob", "Bob-Password-1"),
        );
        let mut off = life("bob", UserStep::SyncOff);
        off.rows.insert(0, HostRow::SyncIs(bob(), true));
        let turned_off = embedded.commit_user(off).await;
        temp.host.set_sync("bob", false);
        assert_eq!(
            (written, after_change, turned_off, marked(&store, "bob")),
            (Ok(()), (Some((true, false)), 0), Some(Ok(())), None),
            "the change first: written, then the sync off takes the principal with it"
        );
        assert_eq!(
            temp.host.rows(),
            [
                "password bob",
                "synced bob",
                "log password_change",
                "synced bob",
                "update bob",
                "log user_update"
            ]
            .map(str::to_owned)
            .to_vec()
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_an_adopted_principal_keeps_no_key_the_directory_never_saw() {
        use krb5_kdc::host::{Caller, WriteIntent};
        use krb5_types::err::CLIENT_REVOKED;
        const OLD: &str = "Dora-Old-Pass-1";
        const CPW: &str = "Dora-Cpw-Pass-2";
        let temp = TempRealm::new();
        let (embedded, store) = temp.embedded();
        let wrong_key =
            |password| ![0, CLIENT_REVOKED].contains(&kinit_code(&store, "dora", password));
        let (dora, name) = (UserId::new("dora"), user_principal(&UserId::new("dora")));
        unmarked(&embedded, "dora", false);
        in_change(&embedded.own(), |s| {
            let etypes = &embedded.enctypes;
            s.set_password_etypes_keepold_n_in(
                &name,
                "EXAMPLE.COM",
                OLD.as_bytes(),
                0,
                "test",
                etypes,
            )
        })
        .unwrap();
        let before = kinit_code(&store, "dora", OLD);
        let adopted = embedded.commit_user(life("dora", UserStep::SyncOn)).await;
        let while_adopted = kinit_code(&store, "dora", OLD);
        embedded.set_principal_enabled(&dora, true).await.unwrap();
        assert_eq!(
            (
                before,
                adopted,
                while_adopted,
                marked(&store, "dora"),
                wrong_key(OLD)
            ),
            (0, Some(Ok(())), CLIENT_REVOKED, Some((true, false)), true),
            "enabled through the group, the old password still fails"
        );

        embedded.set_principal_enabled(&dora, false).await.unwrap();
        let admin = "admin/admin@EXAMPLE.COM";
        let mut intent = WriteIntent::new(
            Operation::ChangePassword,
            Caller::Kadmind {
                client: admin.to_owned(),
                initial: false,
                changepw_service: false,
                self_service: false,
            },
        );
        intent.password = Some(Zeroizing::new(CPW.as_bytes().to_vec()));
        intent.keepold = Some(0);
        let cpw = store
            .write()
            .unwrap()
            .change_as(intent, None, |s| {
                let etypes = &embedded.enctypes;
                s.set_password_etypes_keepold_n_in(
                    &name,
                    "EXAMPLE.COM",
                    CPW.as_bytes(),
                    0,
                    admin,
                    etypes,
                )
            })
            .and_then(|done| done);
        let after_cpw = (marked(&store, "dora"), kinit_code(&store, "dora", CPW));
        embedded.set_principal_enabled(&dora, true).await.unwrap();
        assert_eq!(
            (
                cpw.is_ok(),
                after_cpw,
                kinit_code(&store, "dora", CPW),
                wrong_key(OLD)
            ),
            (true, (Some((true, true)), CLIENT_REVOKED), 0, true),
            "kadmin cpw sets the keys; the test host queues no step after it, so the enable does"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_the_step_after_a_kadmin_cpw_follows_the_directory() {
        use lldap_domain_handlers::logging::Protocol;
        const ADMIN: &str = "admin/admin@EXAMPLE.COM";
        let log = LogGuard::install();
        let temp = TempRealm::new();
        let (embedded, store) = temp.embedded();
        let dora = UserId::new("dora");
        unmarked(&embedded, "dora", false);
        let adopted = embedded.commit_user(life("dora", UserStep::SyncOn)).await;
        assert_eq!(
            (adopted, marked(&store, "dora")),
            (Some(Ok(())), Some((true, true)))
        );
        log.recorder().take_events();
        let unread = format!(
            "{NOT_FOLLOWED}: {STATE_UNREAD}: Kerberos store failed: the database did not answer"
        );
        let stopped = format!("{NOT_FOLLOWED}: {REALM_STOPPED}");
        type Row<'a> = (
            &'a str,
            Option<&'a [&'a str]>,
            bool,
            Option<(bool, &'a str)>,
        );
        let rows: [Row; 4] = [
            ("not read", None, true, Some((false, unread.as_str()))),
            ("in lldap_disabled", Some(&["dora"]), true, None),
            ("enabled", Some(&[]), false, Some((true, ENABLED_AFTER_CPW))),
            (
                "disabled again",
                Some(&["dora"]),
                true,
                Some((true, DISABLED_AFTER_CPW)),
            ),
        ];
        let logged = || -> Vec<_> {
            let events = log.recorder().take_events().into_iter();
            events
                .map(|e| (e.protocol, e.actor, e.target, e.success, e.detail))
                .collect()
        };
        let row = |success: bool, detail: &str| {
            let (admin, target) = (Some(ADMIN.to_owned()), Some("dora".to_owned()));
            vec![(
                Protocol::Kadmin,
                admin,
                target,
                success,
                Some(detail.to_owned()),
            )]
        };
        for (label, directory, locked, written) in rows {
            temp.host.set_directory(directory);
            embedded.follow().run(dora.clone(), ADMIN.to_owned()).await;
            let expected = written.map_or_else(Vec::new, |(ok, detail)| row(ok, detail));
            assert_eq!(
                (marked(&store, "dora"), logged()),
                (Some((true, locked)), expected),
                "{label}"
            );
        }
        let follow = embedded.follow();
        drop((embedded, store));
        follow.run(dora, ADMIN.to_owned()).await;
        assert_eq!(logged(), row(false, &stopped), "the realm stopped first");
    }

    #[tokio::test]
    #[serial]
    async fn test_a_create_with_sync_adopts_the_principal_of_its_name() {
        use lldap_domain::requests::CreateUserRequest;
        use lldap_domain_handlers::logging::event;
        const KADMIN: &str = "Kadmin-Pass-1";
        let etypes = [
            EncryptionType::Aes256CtsHmacSha196,
            EncryptionType::Aes128CtsHmacSha196,
            EncryptionType::Aes128CtsHmacSha256128,
            EncryptionType::Aes256CtsHmacSha384192,
        ];
        let temp = TempRealm::new();
        let (embedded, store) = temp.embedded();
        temp.host.set_directory(Some(&[]));
        let kept = |user: &str| {
            let name = user_principal(&UserId::new(user));
            let guard = store.read().unwrap();
            let p = guard.get_name(&name)?;
            Some((p.id(), p.rid, p.max_life, p.key_history.len()))
        };
        let old_password = || etypes.map(|etype| kinit_as(&store, "erin", KADMIN, etype));
        for user in ["erin", "fred"] {
            unmarked(&embedded, user, false);
            in_change(&embedded.own(), |s| {
                let name = user_principal(&UserId::new(user));
                let keysalts: Vec<KeySalt> = etypes.iter().map(|&e| e.into()).collect();
                let fields = AdminFields {
                    max_life: Some(3600),
                    ..Default::default()
                };
                s.apply_admin_fields_in(&name, "EXAMPLE.COM", fields, "test")?;
                s.set_password_etypes_keepold_n_in(
                    &name,
                    "EXAMPLE.COM",
                    KADMIN.as_bytes(),
                    0,
                    "test",
                    &keysalts,
                )
            })
            .unwrap();
        }
        let (before, made) = (kept("erin"), old_password());
        let create = |user: &str| {
            let id = UserId::new(user);
            let request = CreateUserRequest {
                user_id: id.clone(),
                ..Default::default()
            };
            let log = event(LogKind::UserCreate, Some(user), true, None);
            vec![HostRow::CreateUser(request), HostRow::Log(log)]
        };
        let change = UserChange {
            user: UserId::new("erin"),
            step: UserStep::Create,
            rows: create("erin"),
        };
        let created = embedded.commit_user(change).await;
        let adopted = (marked(&store, "erin"), kept("erin"), old_password());
        embedded
            .set_principal_enabled(&UserId::new("erin"), true)
            .await
            .unwrap();
        let enabled = (marked(&store, "erin"), old_password());
        // The realm issues only the enctypes it supports: those that took the old password must refuse it.
        let took: Vec<usize> = (0..made.len()).filter(|&i| made[i] == 0).collect();
        let refused = |codes: [i32; 4]| took.iter().all(|&i| codes[i] != 0);
        assert_eq!(
            (
                !took.is_empty(),
                created,
                (adopted.0, adopted.1 == before, refused(adopted.2)),
                (enabled.0, refused(enabled.1))
            ),
            (
                true,
                Some(Ok(())),
                (Some((true, true)), true, true),
                (Some((true, false)), true)
            ),
            "adopted: marked and disabled, the same principal; no enctype takes the old password, \
             disabled or enabled"
        );
        assert_eq!(before.map(|(_, _, max_life, _)| max_life), Some(3600));

        let mut add = commit_of("fred", b"fred-record");
        add.kind = LogKind::UserCreate;
        add.rows.insert(0, create("fred").remove(0));
        let added = embedded.commit_password(add, "Fred-Pass-1").await;
        assert_eq!(
            (
                added,
                marked(&store, "fred"),
                kinit_code(&store, "fred", "Fred-Pass-1"),
                temp.host.password_record(&UserId::new("fred"))
            ),
            (
                Ok(()),
                Some((true, false)),
                0,
                Some(b"fred-record".to_vec())
            ),
            "an LDAP Add with a password: both forms set, and the principal marked"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_a_synced_users_kinit_with_an_empty_password_is_refused() {
        use krb5_types::err::PREAUTH_FAILED;
        let temp = TempRealm::new();
        let (embedded, store) = temp.embedded();
        synced(&embedded, &bob(), "Bob-Password-1").await.unwrap();
        let rows = [
            ("its password", "Bob-Password-1", 0),
            ("an empty password", "", PREAUTH_FAILED),
            (
                "control: a wrong password",
                "Bob-Password-2",
                PREAUTH_FAILED,
            ),
        ];
        let got: Vec<_> = rows
            .iter()
            .map(|(label, password, _)| (*label, kinit_code(&store, "bob", password)))
            .collect();
        let wanted: Vec<_> = rows
            .iter()
            .map(|(label, _, code)| (*label, *code))
            .collect();
        assert_eq!(got, wanted, "per row: kinit's answer");
    }
}
