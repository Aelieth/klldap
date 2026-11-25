use crate::sql_backend_handler::SqlBackendHandler;
use crate::sql_kerberos_handler::{
    KerberosSqlError, RealmHold, alias_chain, clear_open, commit_batch_with_transaction,
    fill_alias_targets, heartbeat, load_realm, mysql_locked_hold, mysql_realm_probe,
    probe_realm_row, read_first_row, read_hold, read_hold_locked, take_realm,
};
use crate::sql_lockout_handler::unlock_statement;
use crate::sql_log_handler::to_active_model;
use crate::sql_opaque_handler::user_disabled_in;
use crate::sql_tables::DbConnection;
use lldap_domain::types::{AttributeName, MFA_TYPE_TOTP, UserId, kerberos_sync_enabled};
use lldap_domain_handlers::instant::{Timestamp, to_naive};
use lldap_domain_handlers::kerberos::{
    ANSWER_UNSETTLED, AliasOnto, CREATED_FIRST, DIRECTORY_TARGET, DIRECTORY_USER, HostRow,
    KerberosStore, KerberosStoreError, LoadedRealm, NoopKerberosStore, RealmBatch, RealmState,
    SYNC_CHANGED, SyncedStatus, UNREAD_AFTER_COMMIT, USER_GONE, set_kerberos_store,
};
use lldap_domain_handlers::password::{ANSWER_LOST, kill_point};
use lldap_domain_model::error::DomainError;
use lldap_domain_model::model::{self, UserColumn, codec};
use lldap_schema::{KERBEROS_SYNC, PublicSchema};
use sea_orm::sea_query::Expr;
use sea_orm::sqlx::{self, MySql, Row, mysql::MySqlRow, pool::PoolConnection};
use sea_orm::{
    ColumnTrait, ConnectionTrait, DatabaseTransaction, DbBackend, DbErr, EntityTrait, QueryFilter,
    QuerySelect, TransactionTrait,
};
use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, oneshot, watch};
use tracing::warn;

const HEARTBEAT: Duration = Duration::from_secs(10);
const LOST_AFTER: Duration = Duration::from_secs(20);
const WATCH: Duration = Duration::from_secs(35);
const STEP: Duration = Duration::from_secs(5);
const RETRY: Duration = Duration::from_secs(1);
const FIRST_PROBE: Duration = Duration::from_secs(60);
const QUEUE: usize = 16;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KerberosLost {
    Replaced,
    Occupied,
    DatabaseUnreachable,
    HeartbeatTooLate,
}

impl std::fmt::Display for KerberosLost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Replaced => write!(
                f,
                "the realm's generation moved: another server took the realm, or this server's \
                 last commit was answered too late"
            ),
            Self::Occupied => write!(
                f,
                "another server holds the Kerberos realm in this database; this one wrote \
                 nothing and stops"
            ),
            Self::DatabaseUnreachable => {
                write!(f, "no write reached the database for twenty seconds")
            }
            Self::HeartbeatTooLate => write!(
                f,
                "the heartbeat started too late to confirm a lost answer; the realm is given up"
            ),
        }
    }
}

type HoldReply = oneshot::Sender<Result<bool, KerberosStoreError>>;

enum Job {
    Load(oneshot::Sender<Result<LoadedRealm, KerberosStoreError>>),
    Hold(HoldReply),
    Commit(
        Vec<HostRow>,
        RealmBatch,
        Arc<AtomicBool>,
        oneshot::Sender<Result<(), KerberosStoreError>>,
    ),
    Users(
        Vec<UserId>,
        oneshot::Sender<Result<Vec<UserId>, KerberosStoreError>>,
    ),
    Disabled(UserId, oneshot::Sender<Result<bool, KerberosStoreError>>),
    Synced(UserId, oneshot::Sender<Result<bool, KerberosStoreError>>),
    Statuses(oneshot::Sender<Result<Vec<(UserId, SyncedStatus)>, KerberosStoreError>>),
    Chain(
        String,
        usize,
        oneshot::Sender<Result<Vec<String>, KerberosStoreError>>,
    ),
    FillAliases(
        Vec<(String, String)>,
        oneshot::Sender<Result<u64, KerberosStoreError>>,
    ),
    Shutdown(oneshot::Sender<()>),
}

struct CommitterStore {
    tx: mpsc::Sender<Job>,
    lost: watch::Receiver<Option<KerberosLost>>,
    unsettled: watch::Receiver<bool>,
}

impl KerberosStore for CommitterStore {
    fn load(&self) -> Result<LoadedRealm, KerberosStoreError> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .blocking_send(Job::Load(tx))
            .map_err(|_| stopped())?;
        rx.blocking_recv().map_err(|_| stopped())?
    }

    fn commit(&self, batch: RealmBatch) -> Result<(), KerberosStoreError> {
        self.commit_with(Vec::new(), batch)
    }

    fn commit_with(&self, host: Vec<HostRow>, batch: RealmBatch) -> Result<(), KerberosStoreError> {
        let (tx, rx) = oneshot::channel();
        let taken = Arc::new(AtomicBool::new(false));
        self.tx
            .blocking_send(Job::Commit(host, batch, taken.clone(), tx))
            .map_err(|_| stopped())?;
        rx.blocking_recv().map_err(|_| dropped(&taken))?
    }

    fn directory_users(&self, users: &[UserId]) -> Result<Vec<UserId>, KerberosStoreError> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .blocking_send(Job::Users(users.to_vec(), tx))
            .map_err(|_| stopped())?;
        rx.blocking_recv().map_err(|_| stopped())?
    }

    fn user_disabled(&self, user: &UserId) -> Result<bool, KerberosStoreError> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .blocking_send(Job::Disabled(user.clone(), tx))
            .map_err(|_| stopped())?;
        rx.blocking_recv().map_err(|_| stopped())?
    }

    fn user_synced(&self, user: &UserId) -> Result<bool, KerberosStoreError> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .blocking_send(Job::Synced(user.clone(), tx))
            .map_err(|_| stopped())?;
        rx.blocking_recv().map_err(|_| stopped())?
    }

    fn synced_statuses(&self) -> Result<Vec<(UserId, SyncedStatus)>, KerberosStoreError> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .blocking_send(Job::Statuses(tx))
            .map_err(|_| stopped())?;
        rx.blocking_recv().map_err(|_| stopped())?
    }

    fn alias_chain(&self, start: &str, hops: usize) -> Result<Vec<String>, KerberosStoreError> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .blocking_send(Job::Chain(start.to_owned(), hops, tx))
            .map_err(|_| stopped())?;
        rx.blocking_recv().map_err(|_| stopped())?
    }

    fn fill_alias_targets(&self, rows: &[(String, String)]) -> Result<u64, KerberosStoreError> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .blocking_send(Job::FillAliases(rows.to_vec(), tx))
            .map_err(|_| stopped())?;
        rx.blocking_recv().map_err(|_| stopped())?
    }

    fn realm_row_held(&self) -> Result<bool, KerberosStoreError> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .blocking_send(Job::Hold(tx))
            .map_err(|_| stopped())?;
        rx.blocking_recv().map_err(|_| stopped())?
    }

    fn realm_not_held(&self) -> Option<String> {
        let lost = self.lost.borrow();
        let cause = lost.as_ref()?;
        Some(format!("the Kerberos realm was lost: {cause}"))
    }

    fn realm_unsettled(&self) -> Option<String> {
        let unsettled = *self.unsettled.borrow() && self.lost.borrow().is_none();
        unsettled.then(|| ANSWER_UNSETTLED.to_owned())
    }
}

fn stopped() -> KerberosStoreError {
    KerberosStoreError::Failed("kerberos committer stopped".to_owned())
}

fn dropped(taken: &AtomicBool) -> KerberosStoreError {
    if taken.load(Ordering::Acquire) {
        unsettled("kerberos committer stopped", "the commit was under way")
    } else {
        stopped()
    }
}

fn not_held() -> KerberosStoreError {
    KerberosStoreError::NotReady("the Kerberos realm is not held".to_owned())
}

pub struct KerberosCommitterHandle {
    tx: mpsc::Sender<Job>,
    task: tokio::task::JoinHandle<()>,
    lost: watch::Receiver<Option<KerberosLost>>,
    unsettled: watch::Receiver<bool>,
    registered: bool,
}

impl KerberosCommitterHandle {
    pub fn lost(&self) -> watch::Receiver<Option<KerberosLost>> {
        self.lost.clone()
    }

    pub fn store(&self) -> Arc<dyn KerberosStore> {
        Arc::new(CommitterStore {
            tx: self.tx.clone(),
            lost: self.lost.clone(),
            unsettled: self.unsettled.clone(),
        })
    }

    pub async fn shutdown(self) {
        if self.registered {
            set_kerberos_store(Arc::new(NoopKerberosStore));
        }
        let (tx, rx) = oneshot::channel();
        let _ = self.tx.send(Job::Shutdown(tx)).await;
        let _ = rx.await;
        let _ = self.task.await;
    }
}

struct Timings {
    heartbeat: Duration,
    lost_after: Duration,
    watch: Duration,
    step: Duration,
    /// How long the realm's first commit is probed for after its answer was lost.
    first_probe: Duration,
    /// Tests only: the next password COMMIT that succeeds is answered as lost.
    lose_an_answer: AtomicBool,
    /// Tests only: a wait after COMMIT, so the step runs out once COMMIT was sent.
    stall_after_commit: Duration,
    /// Tests only: the next heartbeat that commits is answered as lost.
    lose_a_beat: AtomicBool,
    /// Tests only: the next heartbeat rolls back after its UPDATE and is answered as lost.
    drop_a_beat: AtomicBool,
    /// Tests only: a wait between a lost answer and its read-back.
    stall_before_read: Duration,
}

/// Whether this database's realm row is marked open, read once; false when it cannot be read.
pub async fn realm_marked_open(pool: &DbConnection) -> bool {
    matches!(read_hold(pool).await, Ok(Some(hold)) if hold.open)
}

pub fn start_kerberos_committer(pool: DbConnection) -> KerberosCommitterHandle {
    start_kerberos_committer_for(pool, HEARTBEAT, LOST_AFTER, WATCH, STEP)
}

fn standard(lose_an_answer: bool) -> Timings {
    Timings {
        heartbeat: HEARTBEAT,
        lost_after: LOST_AFTER,
        watch: WATCH,
        step: STEP,
        first_probe: FIRST_PROBE,
        lose_an_answer: AtomicBool::new(lose_an_answer),
        stall_after_commit: Duration::ZERO,
        lose_a_beat: AtomicBool::new(false),
        drop_a_beat: AtomicBool::new(false),
        stall_before_read: Duration::ZERO,
    }
}

/// A committer whose store is not the process's, for kerber-rust's conformance suite.
pub fn start_unregistered_committer(pool: DbConnection) -> KerberosCommitterHandle {
    spawn_committer(pool, standard(false))
}

/// For tests: the first password change that commits is answered as if its answer was lost.
#[cfg(feature = "test-hooks")]
pub fn start_committer_losing_an_answer(pool: DbConnection) -> KerberosCommitterHandle {
    spawn_committer(pool, standard(true))
}

/// For tests: a realm row left open is watched for `watch` before it is taken.
#[cfg(feature = "test-hooks")]
pub fn start_committer_watching_for(
    pool: DbConnection,
    watch: Duration,
) -> KerberosCommitterHandle {
    spawn_committer(
        pool,
        Timings {
            watch,
            ..standard(false)
        },
    )
}

pub(crate) fn start_kerberos_committer_for(
    pool: DbConnection,
    heartbeat: Duration,
    lost_after: Duration,
    watch: Duration,
    step: Duration,
) -> KerberosCommitterHandle {
    let mut handle = spawn_committer(
        pool,
        Timings {
            heartbeat,
            lost_after,
            watch,
            step,
            ..standard(false)
        },
    );
    set_kerberos_store(handle.store());
    handle.registered = true;
    handle
}

fn spawn_committer(pool: DbConnection, timings: Timings) -> KerberosCommitterHandle {
    let (tx, rx) = mpsc::channel(QUEUE);
    let (lost_tx, lost) = watch::channel(None);
    let (unsettled_tx, unsettled) = watch::channel(false);
    let task = tokio::spawn(run(rx, pool, lost_tx, unsettled_tx, timings));
    KerberosCommitterHandle {
        tx,
        task,
        lost,
        unsettled,
        registered: false,
    }
}

struct Held {
    generation: i64,
    row: bool,
    last_ok: Instant,
    next: Instant,
    unsettled: bool,
}

enum Phase {
    Starting { since: Instant, next: Instant },
    Watching { generation: i64, until: Instant },
    Held(Held),
    Lost,
}

enum Incoming {
    Job(Job),
    Closed,
    Timer,
}

async fn run(
    mut rx: mpsc::Receiver<Job>,
    pool: DbConnection,
    lost_tx: watch::Sender<Option<KerberosLost>>,
    unsettled_tx: watch::Sender<bool>,
    timings: Timings,
) {
    let mut phase = open_phase(&pool, &timings, &lost_tx).await;
    let mut waiting = Vec::new();
    let mut asking = Vec::new();
    loop {
        publish_unsettled(&unsettled_tx, &phase);
        let due = wake_time(&phase).is_some_and(|at| at <= Instant::now());
        let incoming = if due {
            Incoming::Timer
        } else {
            let wake = wake_at(&phase);
            tokio::select! {
                biased;
                job = rx.recv() => match job {
                    Some(job) => Incoming::Job(job),
                    None => Incoming::Closed,
                },
                _ = sleep_until(wake), if wake.is_some() => Incoming::Timer,
            }
        };
        match incoming {
            Incoming::Job(Job::Load(reply)) => {
                phase =
                    answer_load(&pool, phase, reply, &mut waiting, &lost_tx, timings.step).await;
            }
            Incoming::Job(Job::Hold(reply)) => {
                answer_hold(&phase, reply, &mut asking, &lost_tx);
            }
            Incoming::Job(Job::Commit(host, batch, taken, reply)) => {
                taken.store(true, Ordering::Release);
                let watches = (&lost_tx, &unsettled_tx);
                phase = commit_job(&pool, phase, &host, batch, reply, watches, &timings).await;
                release_loads(&pool, &phase, &mut waiting, &lost_tx, timings.step).await;
                release_holds(&phase, &mut asking, &lost_tx);
            }
            Incoming::Job(Job::Users(users, reply)) => {
                let _ = reply.send(read_users(&pool, &users, timings.step).await);
            }
            Incoming::Job(Job::Disabled(user, reply)) => {
                let _ = reply.send(read_disabled(&pool, &user, timings.step).await);
            }
            Incoming::Job(Job::Synced(user, reply)) => {
                let _ = reply.send(read_synced(&pool, &user, timings.step).await);
            }
            Incoming::Job(Job::Statuses(reply)) => {
                let _ = reply.send(read_statuses(&pool, timings.step).await);
            }
            Incoming::Job(Job::Chain(start, hops, reply)) => {
                let _ = reply.send(read_chain(&pool, &start, hops, timings.step).await);
            }
            Incoming::Job(Job::FillAliases(rows, reply)) => {
                let _ = reply.send(fill_aliases(&pool, &phase, &rows, timings.step).await);
            }
            Incoming::Job(Job::Shutdown(reply)) => {
                clear_held(&pool, &phase, timings.step).await;
                cancel_loads(&mut waiting);
                cancel_holds(&mut asking);
                let _ = reply.send(());
                break;
            }
            Incoming::Timer => {
                phase = on_wake(&pool, phase, &timings, &lost_tx).await;
                release_loads(&pool, &phase, &mut waiting, &lost_tx, timings.step).await;
                release_holds(&phase, &mut asking, &lost_tx);
            }
            Incoming::Closed => {
                clear_held(&pool, &phase, timings.step).await;
                cancel_loads(&mut waiting);
                cancel_holds(&mut asking);
                break;
            }
        }
    }
}

async fn open_phase(
    pool: &DbConnection,
    timings: &Timings,
    lost_tx: &watch::Sender<Option<KerberosLost>>,
) -> Phase {
    let started = Instant::now();
    match hold_within(pool, timings.step).await {
        Ok(None) => Phase::Held(fresh(0, false, timings)),
        Ok(Some(hold)) if !hold.open => match take_owned(pool, hold.generation, timings.step).await
        {
            Ok(generation) => Phase::Held(fresh_from(started, generation, true, timings)),
            Err(Step::Replaced) => lose(lost_tx, KerberosLost::Occupied),
            Err(Step::Database | Step::Late) => starting(timings),
        },
        Ok(Some(hold)) => Phase::Watching {
            generation: hold.generation,
            until: Instant::now() + timings.watch,
        },
        Err(_) => starting(timings),
    }
}

fn starting(timings: &Timings) -> Phase {
    starting_from(Instant::now(), timings)
}

fn starting_from(since: Instant, timings: &Timings) -> Phase {
    Phase::Starting {
        since,
        next: Instant::now() + RETRY.min(timings.lost_after),
    }
}

fn fresh(generation: i64, row: bool, timings: &Timings) -> Held {
    fresh_from(Instant::now(), generation, row, timings)
}

// From the write's start: a watcher may have read the new generation from then on.
fn fresh_from(started: Instant, generation: i64, row: bool, timings: &Timings) -> Held {
    Held {
        generation,
        row,
        last_ok: started,
        next: Instant::now() + timings.heartbeat,
        unsettled: false,
    }
}

fn wake_time(phase: &Phase) -> Option<Instant> {
    match phase {
        Phase::Starting { next, .. } => Some(*next),
        Phase::Watching { until, .. } => Some(*until),
        Phase::Held(held) if held.row => Some(held.next),
        Phase::Held(_) | Phase::Lost => None,
    }
}

fn wake_at(phase: &Phase) -> Option<tokio::time::Instant> {
    wake_time(phase).map(Into::into)
}

async fn sleep_until(at: Option<tokio::time::Instant>) {
    match at {
        Some(at) => tokio::time::sleep_until(at).await,
        None => std::future::pending().await,
    }
}

enum Step {
    Replaced,
    Database,
    Late,
}

// Bounded so an unreachable database fails the step instead of waiting out the pool's acquire.
async fn within<T, E>(
    step: Duration,
    late: impl FnOnce() -> E,
    work: impl Future<Output = Result<T, E>>,
) -> Result<T, E> {
    tokio::time::timeout(step, work)
        .await
        .unwrap_or_else(|_| Err(late()))
}

fn late(step: Duration) -> String {
    format!("the database did not answer within {step:?}")
}

async fn hold_within(
    pool: &DbConnection,
    step: Duration,
) -> Result<Option<RealmHold>, KerberosSqlError> {
    within(
        step,
        || KerberosSqlError::Failed(late(step)),
        read_hold(pool),
    )
    .await
}

async fn take_owned(pool: &DbConnection, generation: i64, step: Duration) -> Result<i64, Step> {
    within(step, || Step::Database, async {
        let txn = pool.begin().await.map_err(|_| Step::Database)?;
        match take_realm(&txn, generation).await {
            Ok(next) => {
                txn.commit().await.map_err(|_| Step::Database)?;
                Ok(next)
            }
            Err(KerberosSqlError::GenerationMoved { .. }) => {
                let _ = txn.rollback().await;
                Err(Step::Replaced)
            }
            Err(_) => {
                let _ = txn.rollback().await;
                Err(Step::Database)
            }
        }
    })
    .await
}

async fn beat(
    pool: &DbConnection,
    held: &Held,
    started: Instant,
    timings: &Timings,
) -> Result<i64, Step> {
    let generation = held.generation;
    let sent = AtomicBool::new(false);
    let beaten = within(timings.step, || Step::Database, async {
        let txn = pool.begin().await.map_err(|_| Step::Database)?;
        match heartbeat(&txn, generation).await {
            Ok(_) if timings.drop_a_beat.swap(false, Ordering::AcqRel) => {
                sent.store(true, Ordering::Release);
                let _ = txn.rollback().await;
                Err(Step::Database)
            }
            Ok(next) => {
                sent.store(true, Ordering::Release);
                txn.commit().await.map_err(|_| Step::Database)?;
                Ok(next)
            }
            Err(KerberosSqlError::GenerationMoved { .. }) => {
                let _ = txn.rollback().await;
                Err(Step::Replaced)
            }
            Err(_) => {
                let _ = txn.rollback().await;
                Err(Step::Database)
            }
        }
    })
    .await;
    let lost = match &beaten {
        Ok(_) => timings.lose_a_beat.swap(false, Ordering::AcqRel),
        Err(Step::Database) => sent.load(Ordering::Acquire),
        Err(Step::Replaced | Step::Late) => false,
    };
    if !lost {
        return beaten;
    }
    if !beat_reads_back(held, started, timings) {
        return Err(Step::Late);
    }
    match settle(pool, held, started, None, timings).await {
        Settled::Landed => Ok(generation + 1),
        Settled::Unchanged | Settled::Unread(_) => Err(Step::Database),
        Settled::Moved | Settled::CreatedElsewhere => Err(Step::Replaced),
    }
}

fn beat_reads_back(held: &Held, started: Instant, timings: &Timings) -> bool {
    started < held.last_ok + timings.lost_after
}

#[derive(Debug)]
enum WriteError {
    Unreachable(String),
    /// COMMIT was sent, and its answer is an error or did not come within the step.
    Unanswered(String),
    Batch(KerberosSqlError),
    Host(KerberosStoreError),
}

// The kill points mark the steps of a password change, a delete and a sync change only.
fn point(marked: bool, name: &str) {
    if marked {
        kill_point(name);
    }
}

fn has_kill_points(host: &[HostRow]) -> bool {
    host.iter().any(HostRow::has_kill_points)
}

async fn write_batch(
    pool: &DbConnection,
    host: &[HostRow],
    batch: &RealmBatch,
    generation: i64,
    sent: &AtomicBool,
) -> Result<(), WriteError> {
    let password = has_kill_points(host);
    let txn = pool
        .begin()
        .await
        .map_err(|err| WriteError::Unreachable(err.to_string()))?;
    if let Err(err) = write_host_rows(&txn, host).await {
        let _ = txn.rollback().await;
        return Err(WriteError::Host(err));
    }
    point(password, "directory-written");
    match commit_batch_with_transaction(&txn, batch, generation).await {
        Ok(()) => {
            point(password, "batch-written");
            sent.store(true, Ordering::Release);
            txn.commit()
                .await
                .map_err(|err| WriteError::Unanswered(err.to_string()))
        }
        Err(err) => {
            let _ = txn.rollback().await;
            Err(WriteError::Batch(err))
        }
    }
}

async fn write_host_rows(
    txn: &DatabaseTransaction,
    host: &[HostRow],
) -> Result<(), KerberosStoreError> {
    for row in host {
        match row {
            HostRow::SetPassword { user, record, now } => {
                set_password_in(txn, user, record, *now).await?;
            }
            HostRow::CreateUser(request) => {
                SqlBackendHandler::create_user_in(txn, request.clone())
                    .await
                    .map_err(|e| {
                        KerberosStoreError::Refused(format!("while creating the user: {e}"))
                    })?;
            }
            HostRow::Log(event) => {
                model::Logs::insert(to_active_model(event.clone()))
                    .exec_without_returning(txn)
                    .await
                    .map_err(row_failed)?;
            }
            HostRow::NoUser(users) => {
                if first_user(txn, users).await?.is_some() {
                    return Err(KerberosStoreError::Refused(DIRECTORY_USER.to_owned()));
                }
            }
            HostRow::NoAliasOnto(onto) => {
                if let Some(name) = first_aliased(txn, onto).await? {
                    let refusal = format!("{DIRECTORY_TARGET}: {name}");
                    return Err(KerberosStoreError::Refused(refusal));
                }
            }
            HostRow::DeleteUser(user) => delete_user_in(txn, user).await?,
            HostRow::SyncIs(user, on) => {
                if synced_in(txn, user).await? != *on {
                    return Err(KerberosStoreError::Refused(SYNC_CHANGED.to_owned()));
                }
            }
            HostRow::UpdateUser(request) => {
                SqlBackendHandler::update_user_with_transaction(txn, request.clone())
                    .await
                    .map_err(|e| match e {
                        DomainError::DatabaseError(DbErr::RecordNotUpdated) => {
                            KerberosStoreError::Refused(USER_GONE.to_owned())
                        }
                        e => KerberosStoreError::Refused(format!("while updating the user: {e}")),
                    })?;
            }
            HostRow::Membership { user, group, add } => {
                if first_user(txn, std::slice::from_ref(user)).await?.is_none() {
                    return Err(KerberosStoreError::Refused(USER_GONE.to_owned()));
                }
                SqlBackendHandler::change_membership_in(txn, user.clone(), *group, *add)
                    .await
                    .map_err(membership_failed)?;
            }
            HostRow::Unlock { user, at } => {
                if first_user(txn, std::slice::from_ref(user)).await?.is_some() {
                    let statement = unlock_statement(txn.get_database_backend(), user, *at);
                    txn.execute(statement).await.map_err(row_failed)?;
                }
            }
        }
    }
    Ok(())
}

const GROUP_GONE: &str = "the group is gone";

fn membership_failed(err: DbErr) -> KerberosStoreError {
    match err {
        DbErr::RecordNotUpdated => KerberosStoreError::Refused(GROUP_GONE.to_owned()),
        DbErr::Custom(why) => KerberosStoreError::Refused(why),
        err => row_failed(err),
    }
}

async fn synced_in(txn: &impl ConnectionTrait, user: &UserId) -> Result<bool, KerberosStoreError> {
    synced_on(txn, user).await.map_err(row_failed)
}

/// The user's sync as the doors read it, read in the transaction that writes.
pub(crate) async fn synced_on(txn: &impl ConnectionTrait, user: &UserId) -> Result<bool, DbErr> {
    let schema = PublicSchema::shared().user_attributes();
    let stored = model::UserAttributes::find()
        .filter(model::UserAttributesColumn::UserId.eq(user))
        .filter(model::UserAttributesColumn::AttributeName.eq(AttributeName::new(KERBEROS_SYNC)))
        .all(txn)
        .await?;
    let attributes: Vec<_> = stored
        .into_iter()
        .filter_map(|row| codec::decode_attribute(row.attribute_name, &row.value, schema).ok())
        .collect();
    Ok(kerberos_sync_enabled(&attributes))
}

async fn delete_user_in(
    txn: &DatabaseTransaction,
    user: &UserId,
) -> Result<(), KerberosStoreError> {
    let deleted = model::User::delete_by_id(user.clone())
        .exec(txn)
        .await
        .map_err(row_failed)?;
    if deleted.rows_affected == 1 {
        Ok(())
    } else {
        Err(KerberosStoreError::Refused(USER_GONE.to_owned()))
    }
}

async fn first_user(
    txn: &DatabaseTransaction,
    users: &[UserId],
) -> Result<Option<UserId>, KerberosStoreError> {
    let found = existing_users(txn, users).await.map_err(row_failed)?;
    Ok(users.iter().find(|user| found.contains(user)).cloned())
}

/// The first name on the targets' chains, read in the transaction, that is a directory user's.
async fn first_aliased(
    txn: &DatabaseTransaction,
    onto: &AliasOnto,
) -> Result<Option<String>, KerberosStoreError> {
    let mut named = Vec::new();
    for target in &onto.targets {
        let chain = alias_chain(txn, target, onto.hops)
            .await
            .map_err(|err| KerberosStoreError::Refused(format!("while reading an alias: {err}")))?;
        named.extend(
            chain
                .into_iter()
                .filter_map(|name| Some(((onto.user_of)(name.as_str())?, name))),
        );
    }
    let users: Vec<UserId> = named.iter().map(|(user, _)| user.clone()).collect();
    let found = existing_users(txn, &users).await.map_err(row_failed)?;
    Ok(named
        .into_iter()
        .find(|(user, _)| found.contains(user))
        .map(|(_, name)| name))
}

async fn existing_users(db: &impl ConnectionTrait, users: &[UserId]) -> Result<Vec<UserId>, DbErr> {
    if users.is_empty() {
        return Ok(Vec::new());
    }
    let found = model::User::find()
        .select_only()
        .column(UserColumn::UserId)
        .filter(UserColumn::UserId.is_in(users.iter().cloned()))
        .into_tuple::<(String,)>()
        .all(db)
        .await?;
    Ok(found
        .into_iter()
        .map(|(user,)| UserId::from(user))
        .collect())
}

async fn set_password_in(
    txn: &DatabaseTransaction,
    user: &UserId,
    record: &[u8],
    now: Timestamp,
) -> Result<(), KerberosStoreError> {
    let now = to_naive(now);
    let updated = model::User::update_many()
        .col_expr(UserColumn::PasswordHash, Expr::value(record.to_vec()))
        .col_expr(UserColumn::PasswordModifiedDate, Expr::value(now))
        .col_expr(UserColumn::ModifiedDate, Expr::value(now))
        .filter(ColumnTrait::eq(&UserColumn::UserId, user.clone()))
        .exec(txn)
        .await
        .map_err(row_failed)?;
    if updated.rows_affected == 1 {
        Ok(())
    } else {
        Err(KerberosStoreError::Refused(USER_GONE.to_owned()))
    }
}

fn row_failed(err: DbErr) -> KerberosStoreError {
    KerberosStoreError::Refused(format!("while writing a directory row: {err}"))
}

async fn read_users(
    pool: &DbConnection,
    users: &[UserId],
    step: Duration,
) -> Result<Vec<UserId>, KerberosStoreError> {
    within(step, || KerberosStoreError::Failed(late(step)), async {
        existing_users(pool, users)
            .await
            .map_err(|err| KerberosStoreError::Failed(err.to_string()))
    })
    .await
}

async fn read_disabled(
    pool: &DbConnection,
    user: &UserId,
    step: Duration,
) -> Result<bool, KerberosStoreError> {
    within(step, || KerberosStoreError::Failed(late(step)), async {
        user_disabled_in(pool, user)
            .await
            .map_err(|err| KerberosStoreError::Failed(err.to_string()))
    })
    .await
}

async fn read_synced(
    pool: &DbConnection,
    user: &UserId,
    step: Duration,
) -> Result<bool, KerberosStoreError> {
    within(
        step,
        || KerberosStoreError::Failed(late(step)),
        synced_in(pool, user),
    )
    .await
}

async fn read_statuses(
    pool: &DbConnection,
    step: Duration,
) -> Result<Vec<(UserId, SyncedStatus)>, KerberosStoreError> {
    within(step, || KerberosStoreError::Failed(late(step)), async {
        statuses_in(pool)
            .await
            .map_err(|err| KerberosStoreError::Failed(err.to_string()))
    })
    .await
}

async fn statuses_in(db: &impl ConnectionTrait) -> Result<Vec<(UserId, SyncedStatus)>, DbErr> {
    let schema = PublicSchema::shared().user_attributes();
    let synced = model::UserAttributes::find()
        .filter(model::UserAttributesColumn::AttributeName.eq(AttributeName::new(KERBEROS_SYNC)))
        .all(db)
        .await?;
    let group = model::Group::find()
        .filter(model::GroupColumn::LowercaseDisplayName.eq("lldap_disabled"))
        .one(db)
        .await?;
    let disabled: Vec<UserId> = match group {
        Some(group) => model::Membership::find()
            .filter(model::MembershipColumn::GroupId.eq(group.group_id))
            .all(db)
            .await?
            .into_iter()
            .map(|membership| membership.user_id)
            .collect(),
        None => Vec::new(),
    };
    let offered: Vec<UserId> = model::User::find()
        .select_only()
        .column(UserColumn::UserId)
        .filter(ColumnTrait::eq(&UserColumn::MfaType, MFA_TYPE_TOTP))
        .filter(ColumnTrait::eq(&UserColumn::CodeAtKinit, true))
        .into_tuple()
        .all(db)
        .await?;
    Ok(synced
        .into_iter()
        .filter_map(|row| {
            let user = row.user_id.clone();
            let sync = codec::decode_attribute(row.attribute_name, &row.value, schema).ok()?;
            kerberos_sync_enabled(&[sync]).then(|| {
                let status = SyncedStatus {
                    disabled: disabled.contains(&user),
                    code_offered: offered.contains(&user),
                };
                (user, status)
            })
        })
        .collect())
}

async fn read_chain(
    pool: &DbConnection,
    start: &str,
    hops: usize,
    step: Duration,
) -> Result<Vec<String>, KerberosStoreError> {
    within(step, || KerberosStoreError::Failed(late(step)), async {
        alias_chain(pool, start, hops).await.map_err(store_err)
    })
    .await
}

/// Outside the realm's batches: the column restates each record, so the generation stays.
async fn fill_aliases(
    pool: &DbConnection,
    phase: &Phase,
    rows: &[(String, String)],
    step: Duration,
) -> Result<u64, KerberosStoreError> {
    if !matches!(phase, Phase::Held(_)) {
        return Err(not_held());
    }
    let failed = |err: DbErr| KerberosStoreError::Failed(err.to_string());
    within(step, || KerberosStoreError::Failed(late(step)), async {
        let txn = pool.begin().await.map_err(failed)?;
        match fill_alias_targets(&txn, rows).await {
            Ok(filled) => {
                txn.commit().await.map_err(failed)?;
                Ok(filled)
            }
            Err(err) => {
                let _ = txn.rollback().await;
                Err(store_err(err))
            }
        }
    })
    .await
}

type Watches<'a> = (
    &'a watch::Sender<Option<KerberosLost>>,
    &'a watch::Sender<bool>,
);

async fn commit_job(
    pool: &DbConnection,
    phase: Phase,
    host: &[HostRow],
    batch: RealmBatch,
    reply: oneshot::Sender<Result<(), KerberosStoreError>>,
    (lost_tx, unsettled_tx): Watches<'_>,
    timings: &Timings,
) -> Phase {
    let password = has_kill_points(host);
    point(password, "callback-entered");
    let Phase::Held(held) = phase else {
        let _ = reply.send(Err(not_held()));
        return phase;
    };
    let started = Instant::now();
    let step = timings.step;
    let sent = AtomicBool::new(false);
    let ran_out = || {
        if sent.load(Ordering::Acquire) {
            WriteError::Unanswered(late(step))
        } else {
            WriteError::Unreachable(late(step))
        }
    };
    let written = within(step, ran_out, async {
        let written = write_batch(pool, host, &batch, held.generation, &sent).await;
        if !timings.stall_after_commit.is_zero() {
            tokio::time::sleep(timings.stall_after_commit).await;
        }
        written
    })
    .await;
    let written = match written {
        Ok(()) if password && timings.lose_an_answer.swap(false, Ordering::AcqRel) => Err(
            WriteError::Unanswered("the answer to COMMIT was lost".to_owned()),
        ),
        written => written,
    };
    match written {
        Ok(()) => {
            point(password, "committed");
            let _ = reply.send(Ok(()));
            Phase::Held(fresh_from(started, held.generation + 1, true, timings))
        }
        Err(WriteError::Unanswered(reason)) => {
            let wrote = Written {
                host,
                realm: batch.realm.as_ref(),
            };
            let (answer, phase) =
                read_back(pool, held, started, wrote, reason, lost_tx, timings).await;
            publish_unsettled(unsettled_tx, &phase);
            let _ = reply.send(answer);
            phase
        }
        Err(WriteError::Host(err)) => {
            let _ = reply.send(Err(err));
            Phase::Held(held)
        }
        Err(WriteError::Unreachable(reason)) => {
            let _ = reply.send(Err(KerberosStoreError::Failed(reason)));
            db_failed(held, timings, lost_tx)
        }
        Err(WriteError::Batch(KerberosSqlError::GenerationMoved { .. })) => {
            let _ = reply.send(Err(KerberosStoreError::Failed(
                KerberosLost::Replaced.to_string(),
            )));
            lose(lost_tx, KerberosLost::Replaced)
        }
        Err(WriteError::Batch(err)) => {
            let database = matches!(err, KerberosSqlError::Failed(_));
            let _ = reply.send(Err(store_err(err)));
            no_row_failure(pool, held, timings, lost_tx, database).await
        }
    }
}

struct Written<'a> {
    host: &'a [HostRow],
    realm: Option<&'a RealmState>,
}

/// A lost answer: only the holder moves the realm's generation, by one per commit.
async fn read_back(
    pool: &DbConnection,
    held: Held,
    started: Instant,
    wrote: Written<'_>,
    reason: String,
    lost_tx: &watch::Sender<Option<KerberosLost>>,
    timings: &Timings,
) -> (Result<(), KerberosStoreError>, Phase) {
    let after = held.generation + 1;
    match settle(pool, &held, started, wrote.realm, timings).await {
        Settled::Landed => {
            match wrote.host.iter().find_map(written_user) {
                Some(user) => warn!("The commit for user {user}: {ANSWER_LOST}"),
                None => warn!("The Kerberos commit to generation {after}: {ANSWER_LOST}"),
            }
            (
                Ok(()),
                Phase::Held(fresh_from(started, after, true, timings)),
            )
        }
        Settled::Unchanged => {
            let phase = db_failed(held, timings, lost_tx);
            (Err(KerberosStoreError::Failed(reason)), phase)
        }
        Settled::Unread(why) => {
            let held = Held {
                unsettled: true,
                ..held
            };
            let phase = db_failed(held, timings, lost_tx);
            (Err(unsettled(&reason, why)), phase)
        }
        Settled::Moved => {
            let why = unsettled(&reason, KerberosLost::Replaced);
            (Err(why), lose(lost_tx, KerberosLost::Replaced))
        }
        Settled::CreatedElsewhere => {
            let why = KerberosStoreError::Failed(format!("{reason}; {CREATED_FIRST}"));
            (Err(why), lose(lost_tx, KerberosLost::Occupied))
        }
    }
}

enum Settled {
    Landed,
    Unchanged,
    Unread(String),
    Moved,
    CreatedElsewhere,
}

async fn settle(
    pool: &DbConnection,
    held: &Held,
    started: Instant,
    ours: Option<&RealmState>,
    timings: &Timings,
) -> Settled {
    if !timings.stall_before_read.is_zero() {
        tokio::time::sleep(timings.stall_before_read).await;
    }
    if !held.row {
        return first_row(pool, held, ours, timings).await;
    }
    let read = settled_hold(pool, timings.step).await;
    let in_time = started < held.last_ok + timings.lost_after
        && Instant::now() < held.last_ok + timings.lost_after + timings.step * 2;
    match read {
        Err(err) => Settled::Unread(err.to_string()),
        Ok(hold) => match hold.map(|hold| hold.generation) {
            Some(now) if now == held.generation + 1 && in_time => Settled::Landed,
            Some(now) if now == held.generation => Settled::Unchanged,
            _ => Settled::Moved,
        },
    }
}

// The first commit INSERTs the realm row: an INSERT of its key waits for that one to end.
async fn first_row(
    pool: &DbConnection,
    held: &Held,
    ours: Option<&RealmState>,
    timings: &Timings,
) -> Settled {
    let until = Instant::now() + timings.first_probe;
    let step = timings.step;
    loop {
        let probed = match probe_within(pool, step).await {
            Ok(true) => within(
                step,
                || KerberosSqlError::Failed(late(step)),
                read_first_row(pool, ours),
            )
            .await
            .map(|row| match row {
                Some(row) if row.generation != held.generation + 1 => Settled::Moved,
                Some(row) if row.ours => Settled::Landed,
                Some(_) => Settled::CreatedElsewhere,
                None => Settled::Moved,
            }),
            Ok(false) => Ok(Settled::Unchanged),
            Err(err) => Err(err),
        };
        match probed {
            Ok(settled) => return settled,
            Err(err) if Instant::now() >= until => return Settled::Unread(err.to_string()),
            Err(_) => tokio::time::sleep(RETRY.min(step)).await,
        }
    }
}

fn sqlite(pool: &DbConnection) -> bool {
    pool.get_database_backend() == DbBackend::Sqlite
}

fn mysql(pool: &DbConnection) -> bool {
    pool.get_database_backend() == DbBackend::MySql
}

fn sql_failed(err: DbErr) -> KerberosSqlError {
    KerberosSqlError::Failed(err.to_string())
}

fn sqlx_failed(err: sqlx::Error) -> KerberosSqlError {
    KerberosSqlError::Failed(err.to_string())
}

// SQLite's one connection reads after the COMMIT in flight; elsewhere the row lock waits for it.
async fn settled_hold(
    pool: &DbConnection,
    step: Duration,
) -> Result<Option<RealmHold>, KerberosSqlError> {
    if sqlite(pool) {
        return hold_within(pool, step).await;
    }
    within(step, || KerberosSqlError::Failed(late(step)), async {
        if mysql(pool) {
            let read = mysql_waiting(pool, step, &mysql_locked_hold()).await?;
            return read
                .and_then(|row| row.map(hold_of).transpose())
                .map_err(sqlx_failed);
        }
        let txn = pool.begin().await.map_err(sql_failed)?;
        lock_timeout(&txn, step).await?;
        let hold = read_hold_locked(&txn).await;
        let _ = txn.rollback().await;
        hold
    })
    .await
}

async fn probe_within(pool: &DbConnection, step: Duration) -> Result<bool, KerberosSqlError> {
    within(step, || KerberosSqlError::Failed(late(step)), async {
        if mysql(pool) {
            return match mysql_waiting(pool, step, &mysql_realm_probe()).await? {
                Ok(_) => Ok(false),
                Err(sqlx::Error::Database(err)) if err.is_unique_violation() => Ok(true),
                Err(err) => Err(sqlx_failed(err)),
            };
        }
        let txn = pool.begin().await.map_err(sql_failed)?;
        lock_timeout(&txn, step).await?;
        let probed = probe_realm_row(&txn).await;
        let _ = txn.rollback().await;
        probed
    })
    .await
}

async fn lock_timeout(txn: &DatabaseTransaction, step: Duration) -> Result<(), KerberosSqlError> {
    if txn.get_database_backend() == DbBackend::Postgres {
        let wait = format!("SET LOCAL lock_timeout = {}", step.as_millis());
        txn.execute_unprepared(&wait).await.map_err(sql_failed)?;
    }
    Ok(())
}

fn hold_of(row: MySqlRow) -> Result<RealmHold, sqlx::Error> {
    Ok(RealmHold {
        generation: row.try_get(0)?,
        open: row.try_get(1)?,
    })
}

// MySQL bounds a lock wait per session: a connection whose bound is not put back is closed.
struct SessionWait {
    conn: PoolConnection<MySql>,
    put_back: bool,
}

impl Drop for SessionWait {
    fn drop(&mut self) {
        if !self.put_back {
            self.conn.close_on_drop();
        }
    }
}

async fn mysql_waiting(
    pool: &DbConnection,
    step: Duration,
    sql: &str,
) -> Result<Result<Option<MySqlRow>, sqlx::Error>, KerberosSqlError> {
    let conn = pool
        .get_mysql_connection_pool()
        .acquire()
        .await
        .map_err(sqlx_failed)?;
    let mut wait = SessionWait {
        conn,
        put_back: false,
    };
    let bound = format!(
        "SET @klldap_wait = @@SESSION.innodb_lock_wait_timeout, \
         SESSION innodb_lock_wait_timeout = {}",
        step.as_secs().max(1)
    );
    sqlx::query(&bound)
        .execute(&mut *wait.conn)
        .await
        .map_err(sqlx_failed)?;
    let mut txn = sqlx::Connection::begin(&mut *wait.conn)
        .await
        .map_err(sqlx_failed)?;
    let done = sqlx::query(sql).fetch_optional(&mut *txn).await;
    txn.rollback().await.map_err(sqlx_failed)?;
    sqlx::query("SET SESSION innodb_lock_wait_timeout = @klldap_wait")
        .execute(&mut *wait.conn)
        .await
        .map_err(sqlx_failed)?;
    wait.put_back = true;
    Ok(done)
}

fn written_user(row: &HostRow) -> Option<&UserId> {
    match row {
        HostRow::SetPassword { user, .. }
        | HostRow::DeleteUser(user)
        | HostRow::Membership { user, .. } => Some(user),
        HostRow::UpdateUser(request) => Some(&request.user_id),
        _ => None,
    }
}

fn unsettled(reason: &str, why: impl std::fmt::Display) -> KerberosStoreError {
    KerberosStoreError::Failed(format!("{UNREAD_AFTER_COMMIT}: {reason}; {why}"))
}

fn db_failed(
    held: Held,
    timings: &Timings,
    lost_tx: &watch::Sender<Option<KerberosLost>>,
) -> Phase {
    if held.last_ok.elapsed() >= timings.lost_after {
        lose(lost_tx, KerberosLost::DatabaseUnreachable)
    } else {
        Phase::Held(retry(held, timings))
    }
}

async fn no_row_failure(
    pool: &DbConnection,
    held: Held,
    timings: &Timings,
    lost_tx: &watch::Sender<Option<KerberosLost>>,
    database: bool,
) -> Phase {
    if held.row {
        return if database {
            db_failed(held, timings, lost_tx)
        } else {
            Phase::Held(held)
        };
    }
    match hold_within(pool, timings.step).await {
        Ok(Some(_)) => lose(lost_tx, KerberosLost::Replaced),
        Ok(None) if database => db_failed(held, timings, lost_tx),
        Ok(None) => Phase::Held(held),
        Err(_) => db_failed(held, timings, lost_tx),
    }
}

fn retry(held: Held, timings: &Timings) -> Held {
    Held {
        next: retry_wake(&held, Instant::now(), timings),
        ..held
    }
}

fn retry_wake(held: &Held, now: Instant, timings: &Timings) -> Instant {
    (now + RETRY).min(held.last_ok + timings.lost_after)
}

async fn on_wake(
    pool: &DbConnection,
    phase: Phase,
    timings: &Timings,
    lost_tx: &watch::Sender<Option<KerberosLost>>,
) -> Phase {
    let started = Instant::now();
    match phase {
        Phase::Starting { since, .. } => {
            if since.elapsed() >= timings.lost_after {
                return lose(lost_tx, KerberosLost::DatabaseUnreachable);
            }
            match hold_within(pool, timings.step).await {
                Ok(None) => Phase::Held(fresh(0, false, timings)),
                Ok(Some(hold)) if !hold.open => {
                    match take_owned(pool, hold.generation, timings.step).await {
                        Ok(generation) => {
                            Phase::Held(fresh_from(started, generation, true, timings))
                        }
                        Err(Step::Replaced) => lose(lost_tx, KerberosLost::Occupied),
                        Err(Step::Database | Step::Late) => starting_from(since, timings),
                    }
                }
                Ok(Some(hold)) => Phase::Watching {
                    generation: hold.generation,
                    until: Instant::now() + timings.watch,
                },
                Err(_) => starting_from(since, timings),
            }
        }
        Phase::Watching { generation, .. } => match hold_within(pool, timings.step).await {
            Ok(Some(hold)) if hold.generation == generation => {
                match take_owned(pool, generation, timings.step).await {
                    Ok(next) => Phase::Held(fresh_from(started, next, true, timings)),
                    Err(Step::Replaced) => lose(lost_tx, KerberosLost::Occupied),
                    Err(Step::Database | Step::Late) => {
                        lose(lost_tx, KerberosLost::DatabaseUnreachable)
                    }
                }
            }
            Ok(_) => lose(lost_tx, KerberosLost::Occupied),
            Err(_) => lose(lost_tx, KerberosLost::DatabaseUnreachable),
        },
        Phase::Held(held) if held.row => {
            let silent = held.last_ok.elapsed();
            match beat(pool, &held, started, timings).await {
                Ok(next) => {
                    if silent >= timings.lost_after {
                        warn!(
                            "Woke {} s after the last write to the Kerberos realm; the heartbeat still held it",
                            silent.as_secs()
                        );
                    }
                    Phase::Held(fresh_from(started, next, true, timings))
                }
                Err(Step::Replaced) => lose(lost_tx, KerberosLost::Replaced),
                Err(Step::Database) => db_failed(held, timings, lost_tx),
                Err(Step::Late) => lose(lost_tx, KerberosLost::HeartbeatTooLate),
            }
        }
        other => other,
    }
}

async fn clear_held(pool: &DbConnection, phase: &Phase, step: Duration) {
    let Phase::Held(held) = phase else {
        return;
    };
    if !held.row {
        return;
    }
    let _ = within(step, || (), async {
        let txn = pool.begin().await.map_err(drop)?;
        match clear_open(&txn, held.generation).await {
            Ok(()) => txn.commit().await.map_err(drop),
            Err(_) => txn.rollback().await.map_err(drop),
        }
    })
    .await;
}

fn publish_unsettled(unsettled_tx: &watch::Sender<bool>, phase: &Phase) {
    let now = matches!(phase, Phase::Held(held) if held.unsettled);
    unsettled_tx.send_if_modified(|was| std::mem::replace(was, now) != now);
}

fn lose(lost_tx: &watch::Sender<Option<KerberosLost>>, cause: KerberosLost) -> Phase {
    let _ = lost_tx.send(Some(cause));
    Phase::Lost
}

async fn read_loaded(
    pool: &DbConnection,
    step: Duration,
) -> Result<LoadedRealm, KerberosStoreError> {
    within(
        step,
        || KerberosSqlError::Failed(late(step)),
        load_realm(pool),
    )
    .await
    .map(|(realm, _)| realm)
    .map_err(store_err)
}

fn lost_answer(lost_tx: &watch::Sender<Option<KerberosLost>>) -> KerberosStoreError {
    match lost_tx.borrow().as_ref() {
        Some(cause) => KerberosStoreError::Failed(cause.to_string()),
        None => stopped(),
    }
}

async fn answer_load(
    pool: &DbConnection,
    phase: Phase,
    reply: oneshot::Sender<Result<LoadedRealm, KerberosStoreError>>,
    waiting: &mut Vec<oneshot::Sender<Result<LoadedRealm, KerberosStoreError>>>,
    lost_tx: &watch::Sender<Option<KerberosLost>>,
    step: Duration,
) -> Phase {
    match phase {
        Phase::Held(held) if held.unsettled => {
            let (loaded, phase) = reload_unsettled(pool, held, lost_tx, step).await;
            let _ = reply.send(loaded);
            phase
        }
        Phase::Held(_) => {
            let _ = reply.send(read_loaded(pool, step).await);
            phase
        }
        Phase::Lost => {
            let _ = reply.send(Err(lost_answer(lost_tx)));
            phase
        }
        Phase::Starting { .. } | Phase::Watching { .. } => {
            waiting.push(reply);
            phase
        }
    }
}

const UNSETTLED: &str = "the realm waits for its last commit to end";

async fn reload_unsettled(
    pool: &DbConnection,
    held: Held,
    lost_tx: &watch::Sender<Option<KerberosLost>>,
    step: Duration,
) -> (Result<LoadedRealm, KerberosStoreError>, Phase) {
    let loaded = within(step, || KerberosSqlError::Failed(late(step)), async {
        settled_hold(pool, step).await?;
        load_realm(pool).await
    })
    .await;
    match loaded {
        Err(err) => {
            let why = KerberosStoreError::NotReady(format!("{UNSETTLED}: {err}"));
            (Err(why), Phase::Held(held))
        }
        Ok((_, generation)) if generation != held.generation => {
            let why = KerberosStoreError::Failed(KerberosLost::Replaced.to_string());
            (Err(why), lose(lost_tx, KerberosLost::Replaced))
        }
        Ok((realm, _)) => {
            let held = Held {
                unsettled: false,
                ..held
            };
            (Ok(realm), Phase::Held(held))
        }
    }
}

async fn release_loads(
    pool: &DbConnection,
    phase: &Phase,
    waiting: &mut Vec<oneshot::Sender<Result<LoadedRealm, KerberosStoreError>>>,
    lost_tx: &watch::Sender<Option<KerberosLost>>,
    step: Duration,
) {
    if waiting.is_empty() {
        return;
    }
    match phase {
        Phase::Held(_) => {
            let loaded = read_loaded(pool, step).await;
            for reply in waiting.drain(..) {
                let _ = reply.send(loaded.clone());
            }
        }
        Phase::Lost => {
            for reply in waiting.drain(..) {
                let _ = reply.send(Err(lost_answer(lost_tx)));
            }
        }
        Phase::Starting { .. } | Phase::Watching { .. } => {}
    }
}

fn cancel_loads(waiting: &mut Vec<oneshot::Sender<Result<LoadedRealm, KerberosStoreError>>>) {
    for reply in waiting.drain(..) {
        let _ = reply.send(Err(stopped()));
    }
}

/// Whether this server holds the realm's row; None while it still looks for another holder.
fn hold_answer(
    phase: &Phase,
    lost_tx: &watch::Sender<Option<KerberosLost>>,
) -> Option<Result<bool, KerberosStoreError>> {
    match phase {
        Phase::Held(held) => Some(Ok(held.row)),
        Phase::Lost => Some(Err(lost_answer(lost_tx))),
        Phase::Starting { .. } | Phase::Watching { .. } => None,
    }
}

fn answer_hold(
    phase: &Phase,
    reply: HoldReply,
    asking: &mut Vec<HoldReply>,
    lost_tx: &watch::Sender<Option<KerberosLost>>,
) {
    match hold_answer(phase, lost_tx) {
        Some(answer) => {
            let _ = reply.send(answer);
        }
        None => asking.push(reply),
    }
}

fn release_holds(
    phase: &Phase,
    asking: &mut Vec<HoldReply>,
    lost_tx: &watch::Sender<Option<KerberosLost>>,
) {
    if asking.is_empty() {
        return;
    }
    if let Some(answer) = hold_answer(phase, lost_tx) {
        for reply in asking.drain(..) {
            let _ = reply.send(answer.clone());
        }
    }
}

fn cancel_holds(asking: &mut Vec<HoldReply>) {
    for reply in asking.drain(..) {
        let _ = reply.send(Err(stopped()));
    }
}

fn store_err(err: KerberosSqlError) -> KerberosStoreError {
    match err {
        KerberosSqlError::Refused(reason) => KerberosStoreError::Refused(reason),
        KerberosSqlError::Failed(reason) => KerberosStoreError::Failed(reason),
        KerberosSqlError::GenerationMoved { .. } => {
            KerberosStoreError::Failed(KerberosLost::Replaced.to_string())
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::sql_migrations::{KerberosRealm, Users};
    use crate::sql_tables::init_table;
    use lldap_domain_handlers::kerberos::{
        LoadedPrincipal, PolicyRow, PrincipalRow, RealmState, kerberos_store,
    };
    use sea_orm::sea_query::{Expr, Query};
    use sea_orm::{ConnectionTrait, Database, TransactionTrait};
    use serial_test::serial;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct Restore;
    impl Drop for Restore {
        fn drop(&mut self) {
            set_kerberos_store(Arc::new(NoopKerberosStore));
        }
    }

    struct Db {
        pool: DbConnection,
        other: DbConnection,
        path: std::path::PathBuf,
    }

    impl Drop for Db {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }

    async fn db() -> Db {
        static N: AtomicU64 = AtomicU64::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("klldap-sql-b4-{}-{n}.db", std::process::id()));
        let url = format!("sqlite://{}?mode=rwc", path.display());
        let open = |url: String| async move {
            let mut opts = sea_orm::ConnectOptions::new(url);
            opts.max_connections(1).sqlx_logging(false);
            Database::connect(opts).await.unwrap()
        };
        let pool = open(url.clone()).await;
        init_table(&pool).await.unwrap();
        let other = open(url).await;
        Db { pool, other, path }
    }

    async fn insert_realm(pool: &impl ConnectionTrait, generation: i64, open: bool) {
        pool.execute(
            pool.get_database_backend().build(
                Query::insert()
                    .into_table(KerberosRealm::Table)
                    .columns([
                        KerberosRealm::Id,
                        KerberosRealm::Realm,
                        KerberosRealm::Generation,
                        KerberosRealm::Open,
                        KerberosRealm::State,
                    ])
                    .values_panic([
                        Expr::value(1i32),
                        Expr::value("EXAMPLE.COM"),
                        Expr::value(generation),
                        Expr::value(open),
                        Expr::value(sea_orm::sea_query::Value::Bytes(Some(Box::new(vec![1])))),
                    ]),
            ),
        )
        .await
        .unwrap();
    }

    async fn hold(pool: &DbConnection) -> (i64, bool) {
        let hold = read_hold(pool).await.unwrap().unwrap();
        (hold.generation, hold.open)
    }

    async fn wait_lost(lost: &mut watch::Receiver<Option<KerberosLost>>) -> KerberosLost {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if let Some(cause) = lost.borrow().clone() {
                return cause;
            }
            if Instant::now() > deadline {
                panic!("lost report did not arrive");
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    async fn wait_thread<T>(rx: std::sync::mpsc::Receiver<T>) -> Result<T, String> {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            match rx.try_recv() {
                Ok(result) => return Ok(result),
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    return Err("dropped".to_owned());
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => {
                    if Instant::now() > deadline {
                        return Err("hung".to_owned());
                    }
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            }
        }
    }

    async fn commit_in_thread(batch: RealmBatch) -> Result<(), String> {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let result = kerberos_store()
                .commit(batch)
                .map_err(|err| err.to_string());
            let _ = tx.send(result);
        });
        wait_thread(rx).await?
    }

    async fn commit_then_load(batch: RealmBatch) -> Result<LoadedRealm, String> {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let result = (|| {
                kerberos_store()
                    .commit(batch)
                    .map_err(|err| err.to_string())?;
                kerberos_store().load().map_err(|err| err.to_string())
            })();
            let _ = tx.send(result);
        });
        wait_thread(rx).await?
    }

    async fn load_in_thread() -> Result<LoadedRealm, String> {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let result = kerberos_store().load().map_err(|err| err.to_string());
            let _ = tx.send(result);
        });
        wait_thread(rx).await?
    }

    fn batch() -> RealmBatch {
        let when =
            chrono::NaiveDateTime::parse_from_str("2026-01-01 00:00:00", "%Y-%m-%d %H:%M:%S")
                .unwrap();
        RealmBatch {
            upsert_principals: vec![PrincipalRow {
                name: "alice".to_owned(),
                record: vec![1],
                has_keys: true,
                disabled: false,
                kvno: 1,
                expiration: None,
                password_expiration: None,
                policy: None,
                modified_date: lldap_domain_handlers::instant::from_naive(when),
                alias_target: None,
            }],
            delete_principals: Vec::new(),
            put_policies: vec![PolicyRow {
                name: "default".to_owned(),
                record: vec![3],
            }],
            delete_policies: Vec::new(),
            realm: Some(RealmState {
                realm: "EXAMPLE.COM".to_owned(),
                state: vec![9],
            }),
        }
    }

    async fn insert_alice(pool: &DbConnection) {
        let when =
            chrono::NaiveDateTime::parse_from_str("2026-01-01 00:00:00", "%Y-%m-%d %H:%M:%S")
                .unwrap();
        pool.execute(
            pool.get_database_backend().build(
                Query::insert()
                    .into_table(Users::Table)
                    .columns([
                        Users::UserId,
                        Users::Email,
                        Users::LowercaseEmail,
                        Users::CreationDate,
                        Users::Uuid,
                        Users::ModifiedDate,
                        Users::PasswordModifiedDate,
                    ])
                    .values_panic([
                        "alice".into(),
                        "alice@ex.com".into(),
                        "alice@ex.com".into(),
                        when.into(),
                        "11111111-1111-1111-1111-111111111111".into(),
                        when.into(),
                        when.into(),
                    ]),
            ),
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    #[serial]
    async fn test_commit_from_a_blocking_thread() {
        let _restore = Restore;
        let db = db().await;
        insert_alice(&db.pool).await;
        let handle = start_kerberos_committer_for(
            db.pool.clone(),
            Duration::from_secs(5),
            Duration::from_secs(5),
            Duration::from_secs(5),
            Duration::from_secs(5),
        );
        let loaded = load_in_thread().await.expect("empty database held");
        assert!(loaded.realm.is_none());
        let loaded = commit_then_load(batch()).await.unwrap();
        assert_eq!(
            loaded.principals,
            vec![LoadedPrincipal {
                name: "alice".to_owned(),
                record: vec![1],
            }]
        );
        handle.shutdown().await;
        assert!(!hold(&db.other).await.1);
    }

    #[tokio::test]
    #[serial]
    async fn test_commit_after_shutdown_does_not_hang() {
        let _restore = Restore;
        let db = db().await;
        let handle = start_kerberos_committer_for(
            db.pool.clone(),
            Duration::from_secs(5),
            Duration::from_secs(5),
            Duration::from_secs(5),
            Duration::from_secs(5),
        );
        handle.shutdown().await;
        let err = commit_in_thread(batch()).await.unwrap_err();
        assert!(!err.is_empty(), "{err}");
    }

    #[tokio::test]
    #[serial]
    async fn test_open_false_is_held_at_once() {
        let _restore = Restore;
        let db = db().await;
        insert_realm(&db.pool, 5, false).await;
        let handle = start_kerberos_committer_for(
            db.pool.clone(),
            Duration::from_secs(5),
            Duration::from_secs(5),
            Duration::from_secs(5),
            Duration::from_secs(5),
        );
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let (generation, open) = hold(&db.other).await;
            if open && generation == 6 {
                break;
            }
            if Instant::now() > deadline {
                panic!("not held: generation {generation} open {open}");
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        handle.shutdown().await;
    }

    #[tokio::test]
    #[serial]
    async fn test_open_true_is_held_after_the_watch() {
        let _restore = Restore;
        let db = db().await;
        insert_realm(&db.pool, 5, true).await;
        let handle = start_kerberos_committer_for(
            db.pool.clone(),
            Duration::from_secs(5),
            Duration::from_secs(5),
            Duration::from_millis(40),
            Duration::from_secs(5),
        );
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let (generation, _) = hold(&db.other).await;
            if generation == 6 {
                break;
            }
            if Instant::now() > deadline {
                panic!("watch did not take, generation {generation}");
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        handle.shutdown().await;
    }

    #[tokio::test]
    #[serial]
    async fn test_moved_number_during_the_watch_writes_nothing() {
        let _restore = Restore;
        let db = db().await;
        insert_realm(&db.pool, 5, true).await;
        let handle = start_kerberos_committer_for(
            db.pool.clone(),
            Duration::from_secs(5),
            Duration::from_secs(5),
            Duration::from_millis(1000),
            Duration::from_secs(5),
        );
        let err = commit_in_thread(batch()).await.unwrap_err();
        assert!(err.contains("the Kerberos realm is not held"), "{err}");
        let txn = db.other.begin().await.unwrap();
        assert_eq!(heartbeat(&txn, 5).await.unwrap(), 6);
        txn.commit().await.unwrap();
        let mut lost = handle.lost();
        let cause = wait_lost(&mut lost).await;
        assert_eq!(cause, KerberosLost::Occupied);
        assert!(
            cause.to_string().contains("this one wrote nothing"),
            "{cause}"
        );
        assert_eq!(hold(&db.other).await, (6, true));
        handle.shutdown().await;
    }

    #[tokio::test]
    #[serial]
    async fn test_heartbeat_raises_the_number() {
        let _restore = Restore;
        let db = db().await;
        insert_realm(&db.pool, 5, false).await;
        let handle = start_kerberos_committer_for(
            db.pool.clone(),
            Duration::from_millis(30),
            Duration::from_secs(5),
            Duration::from_secs(5),
            Duration::from_secs(5),
        );
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let (generation, _) = hold(&db.other).await;
            if generation >= 7 {
                break;
            }
            if Instant::now() > deadline {
                panic!("heartbeat did not run, generation {generation}");
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        handle.shutdown().await;
    }

    #[tokio::test]
    #[serial]
    async fn test_replaced_owner_heartbeat_reports() {
        let _restore = Restore;
        let db = db().await;
        insert_realm(&db.pool, 5, false).await;
        let handle = start_kerberos_committer_for(
            db.pool.clone(),
            Duration::from_millis(40),
            Duration::from_secs(5),
            Duration::from_secs(5),
            Duration::from_secs(5),
        );
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if hold(&db.other).await.1 {
                break;
            }
            if Instant::now() > deadline {
                panic!("take did not finish");
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let (generation, _) = hold(&db.other).await;
        let txn = db.other.begin().await.unwrap();
        heartbeat(&txn, generation).await.unwrap();
        txn.commit().await.unwrap();
        let mut lost = handle.lost();
        assert_eq!(wait_lost(&mut lost).await, KerberosLost::Replaced);
        handle.shutdown().await;
    }

    #[tokio::test]
    #[serial]
    async fn test_shutdown_clears_open_and_the_next_start_holds() {
        let _restore = Restore;
        let db = db().await;
        insert_realm(&db.pool, 5, false).await;
        let handle = start_kerberos_committer_for(
            db.pool.clone(),
            Duration::from_secs(5),
            Duration::from_secs(5),
            Duration::from_secs(5),
            Duration::from_secs(5),
        );
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if hold(&db.other).await.1 {
                break;
            }
            if Instant::now() > deadline {
                panic!("not held");
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        handle.shutdown().await;
        assert!(!hold(&db.other).await.1);
        let handle = start_kerberos_committer_for(
            db.pool.clone(),
            Duration::from_secs(5),
            Duration::from_secs(5),
            Duration::from_secs(5),
            Duration::from_secs(5),
        );
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let (generation, open) = hold(&db.other).await;
            if open {
                assert_eq!(generation, 7);
                break;
            }
            if Instant::now() > deadline {
                panic!("second start did not hold, generation {generation}");
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        handle.shutdown().await;
    }

    #[tokio::test]
    #[serial]
    async fn test_dead_database_reports_after_the_short_twenty() {
        let _restore = Restore;
        let db = db().await;
        insert_realm(&db.pool, 5, false).await;
        let handle = start_kerberos_committer_for(
            db.pool.clone(),
            Duration::from_millis(20),
            Duration::from_millis(60),
            Duration::from_secs(5),
            Duration::from_secs(5),
        );
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if hold(&db.other).await.1 {
                break;
            }
            if Instant::now() > deadline {
                panic!("not held");
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        db.pool.clone().close().await.unwrap();
        let mut lost = handle.lost();
        let cause = wait_lost(&mut lost).await;
        assert_eq!(cause, KerberosLost::DatabaseUnreachable);
        assert_eq!(
            cause.to_string(),
            "no write reached the database for twenty seconds"
        );
        handle.shutdown().await;
    }

    #[tokio::test]
    #[serial]
    async fn test_load_waits_until_the_watch_holds() {
        let _restore = Restore;
        let db = db().await;
        insert_realm(&db.pool, 5, true).await;
        let handle = start_kerberos_committer_for(
            db.pool.clone(),
            Duration::from_secs(5),
            Duration::from_secs(5),
            Duration::from_millis(80),
            Duration::from_secs(5),
        );
        tokio::time::sleep(Duration::from_millis(15)).await;
        let started = Instant::now();
        let loaded = load_in_thread().await.unwrap();
        assert!(started.elapsed() >= Duration::from_millis(40));
        assert_eq!(loaded.realm.unwrap().realm, "EXAMPLE.COM");
        assert_eq!(hold(&db.other).await.0, 6);
        handle.shutdown().await;
    }

    #[tokio::test]
    #[serial]
    async fn test_load_errors_when_the_number_moves() {
        let _restore = Restore;
        let db = db().await;
        insert_realm(&db.pool, 5, true).await;
        let handle = start_kerberos_committer_for(
            db.pool.clone(),
            Duration::from_secs(5),
            Duration::from_secs(5),
            Duration::from_millis(1000),
            Duration::from_secs(5),
        );
        let err = commit_in_thread(batch()).await.unwrap_err();
        assert!(err.contains("the Kerberos realm is not held"), "{err}");
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let result = kerberos_store().load().map_err(|err| err.to_string());
            let _ = tx.send(result);
        });
        let txn = db.other.begin().await.unwrap();
        assert_eq!(heartbeat(&txn, 5).await.unwrap(), 6);
        txn.commit().await.unwrap();
        let err = wait_thread(rx).await.unwrap().unwrap_err();
        assert!(
            err.contains("another server holds the Kerberos realm"),
            "{err}"
        );
        assert_eq!(hold(&db.other).await, (6, true));
        handle.shutdown().await;
    }

    #[tokio::test]
    #[serial]
    async fn test_second_server_on_an_empty_database_is_replaced() {
        let _restore = Restore;
        let db = db().await;
        insert_alice(&db.pool).await;
        let handle = start_kerberos_committer_for(
            db.pool.clone(),
            Duration::from_secs(5),
            Duration::from_secs(5),
            Duration::from_secs(5),
            Duration::from_secs(5),
        );
        let loaded = load_in_thread().await.expect("empty database held");
        assert!(loaded.realm.is_none());
        insert_realm(&db.other, 1, true).await;
        let err = commit_in_thread(batch()).await.unwrap_err();
        assert!(err.contains("the realm's generation moved"), "{err}");
        let mut lost = handle.lost();
        assert_eq!(wait_lost(&mut lost).await, KerberosLost::Replaced);
        assert_eq!(hold(&db.other).await, (1, true));
        handle.shutdown().await;
    }

    async fn hold_in_thread(store: Arc<dyn KerberosStore>) -> Result<bool, String> {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(store.realm_row_held().map_err(|err| err.to_string()));
        });
        wait_thread(rx).await?
    }

    #[tokio::test]
    #[serial]
    async fn test_the_hold_question_waits_out_the_watch_and_tells_a_held_row_from_no_row() {
        let _restore = Restore;
        let long = Duration::from_secs(5);
        let watch = Duration::from_millis(80);
        let rows = [
            ("a row that was not open is taken", Some(false), false, true),
            ("a row left open, after the watch", Some(true), false, true),
            ("the database has no realm row", None, false, false),
            ("the realm's first commit made the row", None, true, true),
        ];
        for (row, open, commits, held) in rows {
            let db = db().await;
            if let Some(open) = open {
                insert_realm(&db.pool, 5, open).await;
            }
            let started = Instant::now();
            let handle = start_kerberos_committer_for(db.pool.clone(), long, long, watch, long);
            if commits {
                insert_alice(&db.pool).await;
                commit_in_thread(batch()).await.unwrap();
            }
            let answer = hold_in_thread(kerberos_store()).await;
            let waited = open != Some(true) || started.elapsed() >= watch;
            assert_eq!((answer, waited), (Ok(held), true), "{row}");
            handle.shutdown().await;
        }
    }

    #[tokio::test]
    #[serial]
    async fn test_the_hold_question_answers_the_loss_when_another_server_holds_the_row() {
        let _restore = Restore;
        let db = db().await;
        insert_realm(&db.pool, 5, true).await;
        let long = Duration::from_secs(5);
        let watch = Duration::from_millis(1000);
        let handle = start_kerberos_committer_for(db.pool.clone(), long, long, watch, long);
        commit_in_thread(batch())
            .await
            .expect_err("the watch has begun");
        let txn = db.other.begin().await.unwrap();
        heartbeat(&txn, 5).await.unwrap();
        txn.commit().await.unwrap();
        let err = hold_in_thread(kerberos_store()).await.unwrap_err();
        assert_eq!(
            err,
            format!("Kerberos store failed: {}", KerberosLost::Occupied)
        );
        handle.shutdown().await;
    }

    #[tokio::test]
    async fn test_the_hold_question_answers_the_database_when_it_cannot_be_reached() {
        let handle = spawn_committer(unreachable_postgres().await, short_timings());
        let err = hold_in_thread(handle.store()).await.unwrap_err();
        assert_eq!(
            err,
            format!(
                "Kerberos store failed: {}",
                KerberosLost::DatabaseUnreachable
            )
        );
        handle.shutdown().await;
    }

    async fn unreachable_postgres() -> DbConnection {
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let mut opts =
            sea_orm::ConnectOptions::new(format!("postgres://lldap:lldap@127.0.0.1:{port}/lldap"));
        opts.connect_lazy(true)
            .acquire_timeout(Duration::from_secs(30))
            .sqlx_logging(false);
        Database::connect(opts).await.unwrap()
    }

    fn short_timings() -> Timings {
        Timings {
            heartbeat: Duration::from_millis(20),
            lost_after: Duration::from_millis(400),
            watch: Duration::from_secs(5),
            step: Duration::from_millis(100),
            first_probe: Duration::from_millis(300),
            ..standard(false)
        }
    }

    fn quiet() -> watch::Sender<bool> {
        watch::channel(false).0
    }

    #[tokio::test]
    async fn test_each_synced_user_its_lldap_disabled_and_its_code_offer_are_read_in_one_step() {
        for name in ["lldap_disabled", "LLDAP_Disabled"] {
            let db = db().await;
            insert_alice(&db.pool).await;
            let step = Duration::from_secs(1);
            let mut got = vec![read_statuses(&db.pool, step).await.unwrap()];
            turn_sync_on(&db.pool, "alice").await;
            got.push(read_statuses(&db.pool, step).await.unwrap());
            for statement in [
                format!(
                    "INSERT INTO groups (group_id, display_name, lowercase_display_name, \
                     creation_date, uuid, modified_date) VALUES (7, '{name}', 'lldap_disabled', \
                     '2026-01-01 00:00:00', 'g7', '2026-01-01 00:00:00')"
                ),
                "INSERT INTO memberships (user_id, group_id) VALUES ('alice', 7)".to_owned(),
            ] {
                db.pool.execute_unprepared(&statement).await.unwrap();
            }
            got.push(read_statuses(&db.pool, step).await.unwrap());
            for statement in [
                "UPDATE users SET code_at_kinit = TRUE WHERE user_id = 'alice'",
                "UPDATE users SET mfa_type = 'totp' WHERE user_id = 'alice'",
                "UPDATE users SET code_at_kinit = FALSE WHERE user_id = 'alice'",
            ] {
                db.pool.execute_unprepared(statement).await.unwrap();
                got.push(read_statuses(&db.pool, step).await.unwrap());
            }
            let disabled = read_disabled(&db.pool, &UserId::new("alice"), step)
                .await
                .unwrap();
            let alice = |disabled, code_offered| {
                let status = SyncedStatus {
                    disabled,
                    code_offered,
                };
                vec![(UserId::new("alice"), status)]
            };
            assert_eq!(
                (got, disabled),
                (
                    vec![
                        Vec::new(),
                        alice(false, false),
                        alice(true, false),
                        alice(true, false),
                        alice(true, true),
                        alice(true, false),
                    ],
                    true
                ),
                "{name}: the group in any case; the code offered only with a factor and the \
                 user's own choice"
            );
        }
    }

    #[tokio::test]
    async fn test_a_realm_row_marked_open_is_seen() {
        let mut got = Vec::new();
        for row in [None, Some(false), Some(true)] {
            let db = db().await;
            if let Some(open) = row {
                insert_realm(&db.pool, 5, open).await;
            }
            got.push(realm_marked_open(&db.pool).await);
        }
        assert_eq!(got, vec![false, false, true]);
    }

    #[test]
    fn test_the_store_names_a_lost_realm_and_an_unsettled_write_apart() {
        let (tx, _rx) = mpsc::channel(1);
        let lost = || {
            Some(format!(
                "the Kerberos realm was lost: {}",
                KerberosLost::Replaced
            ))
        };
        let rows = [
            (None, false, (None, None)),
            (Some(KerberosLost::Replaced), false, (lost(), None)),
            (None, true, (None, Some(ANSWER_UNSETTLED.to_owned()))),
            (Some(KerberosLost::Replaced), true, (lost(), None)),
        ];
        for (cause, unsettled, expected) in rows {
            let (_lost_tx, lost_rx) = watch::channel(cause.clone());
            let (_unsettled_tx, unsettled_rx) = watch::channel(unsettled);
            let store = CommitterStore {
                tx: tx.clone(),
                lost: lost_rx,
                unsettled: unsettled_rx,
            };
            assert_eq!(
                (store.realm_not_held(), store.realm_unsettled()),
                expected,
                "{cause:?}, unsettled {unsettled}"
            );
        }
    }

    #[tokio::test]
    async fn test_unreachable_postgres_fails_a_commit_within_one_step_not_the_acquire_timeout() {
        let pool = unreachable_postgres().await;
        let timings = short_timings();
        let (lost_tx, lost) = watch::channel(None);
        let (reply, answer) = oneshot::channel();
        let started = Instant::now();
        let held = Phase::Held(fresh(5, true, &timings));
        let watches = (&lost_tx, &quiet());
        let phase = commit_job(&pool, held, &[], batch(), reply, watches, &timings).await;
        let took = started.elapsed();
        let err = answer.await.unwrap().unwrap_err().to_string();
        assert!(
            took >= timings.step && took < Duration::from_secs(2),
            "{took:?}"
        );
        assert!(err.contains("did not answer within 100ms"), "{err}");
        assert!(
            matches!(phase, Phase::Held(_)),
            "held just after the failed commit"
        );
        assert_eq!(*lost.borrow(), None);
        tokio::time::sleep(timings.lost_after).await;
        let (reply, _answer) = oneshot::channel();
        let watches = (&lost_tx, &quiet());
        let phase = commit_job(&pool, phase, &[], batch(), reply, watches, &timings).await;
        assert!(matches!(phase, Phase::Lost));
        assert_eq!(*lost.borrow(), Some(KerberosLost::DatabaseUnreachable));
    }

    #[tokio::test]
    async fn test_unreachable_postgres_heartbeat_gives_up_at_lost_after_not_the_acquire_timeout() {
        let pool = unreachable_postgres().await;
        let timings = short_timings();
        let (lost_tx, lost) = watch::channel(None);
        let started = Instant::now();
        let mut phase = Phase::Held(fresh(5, true, &timings));
        while !matches!(phase, Phase::Lost) {
            sleep_until(wake_at(&phase)).await;
            phase = on_wake(&pool, phase, &timings, &lost_tx).await;
            assert!(
                started.elapsed() < Duration::from_secs(2),
                "{:?}",
                started.elapsed()
            );
        }
        let took = started.elapsed();
        assert!(took >= timings.lost_after, "{took:?}");
        assert!(took < timings.lost_after + timings.step * 3, "{took:?}");
        assert_eq!(*lost.borrow(), Some(KerberosLost::DatabaseUnreachable));
    }

    #[tokio::test]
    #[serial]
    async fn test_failing_commit_reports_the_short_twenty() {
        let _restore = Restore;
        let db = db().await;
        insert_realm(&db.pool, 5, false).await;
        let handle = start_kerberos_committer_for(
            db.pool.clone(),
            Duration::from_secs(5),
            Duration::from_millis(60),
            Duration::from_secs(5),
            Duration::from_secs(5),
        );
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if hold(&db.other).await.1 {
                break;
            }
            if Instant::now() > deadline {
                panic!("not held");
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        tokio::time::sleep(Duration::from_millis(70)).await;
        db.pool.clone().close().await.unwrap();
        let _ = commit_in_thread(batch()).await;
        let mut lost = handle.lost();
        assert_eq!(
            wait_lost(&mut lost).await,
            KerberosLost::DatabaseUnreachable
        );
        handle.shutdown().await;
    }

    #[tokio::test]
    #[serial]
    async fn test_a_woken_owner_beats_once_before_it_gives_up() {
        let timings = Timings {
            step: Duration::from_millis(500),
            ..standard(false)
        };
        let rows = [
            ("generation still ours", Some(6), None),
            ("taken meanwhile", None, Some(KerberosLost::Replaced)),
            (
                "database gone",
                None,
                Some(KerberosLost::DatabaseUnreachable),
            ),
            ("a newcomer's take loses the race", Some(6), None),
        ];
        for (row, held_after, cause) in rows {
            let db = db().await;
            insert_realm(&db.pool, 5, true).await;
            match row {
                "taken meanwhile" => {
                    let take = take_owned(&db.other, 5, timings.step).await;
                    assert!(matches!(take, Ok(6)), "{row}");
                }
                "database gone" => db.pool.clone().close().await.unwrap(),
                _ => {}
            }
            let (lost_tx, lost) = watch::channel(None);
            let woken = Held {
                generation: 5,
                row: true,
                last_ok: Instant::now() - Duration::from_secs(25),
                next: Instant::now(),
                unsettled: false,
            };
            let phase = on_wake(&db.pool, Phase::Held(woken), &timings, &lost_tx).await;
            let generation = match phase {
                Phase::Held(held) => Some(held.generation),
                _ => None,
            };
            assert_eq!(
                (generation, lost.borrow().clone()),
                (held_after, cause),
                "{row}"
            );
            if row == "a newcomer's take loses the race" {
                let take = take_owned(&db.other, 5, timings.step).await;
                assert!(matches!(take, Err(Step::Replaced)), "{row}");
                assert_eq!(hold(&db.other).await.0, 6, "{row}");
            }
        }
    }

    fn password_rows(user: &str, record: &[u8]) -> Vec<HostRow> {
        use lldap_domain_handlers::logging::{LogKind, event};
        vec![
            HostRow::SetPassword {
                user: UserId::new(user),
                record: record.to_vec(),
                now: Timestamp::now(),
            },
            HostRow::Log(event(LogKind::PasswordChange, Some(user), true, None)),
        ]
    }

    fn create_rows(user: &str, record: &[u8]) -> Vec<HostRow> {
        use lldap_domain::requests::CreateUserRequest;
        use lldap_domain_handlers::logging::{LogKind, event};
        let mut rows = vec![HostRow::CreateUser(CreateUserRequest {
            user_id: UserId::new(user),
            email: format!("{user}@ex.com").into(),
            ..Default::default()
        })];
        rows.extend(password_rows(user, record));
        rows.push(HostRow::Log(event(
            LogKind::UserCreate,
            Some(user),
            true,
            None,
        )));
        rows
    }

    fn synced_rows(user: &str, record: &[u8]) -> Vec<HostRow> {
        let mut rows = password_rows(user, record);
        rows.insert(1, HostRow::SyncIs(UserId::new(user), true));
        rows
    }

    fn synced_create_rows(user: &str, record: &[u8]) -> Vec<HostRow> {
        use lldap_domain::types::Attribute;
        let mut rows = create_rows(user, record);
        if let HostRow::CreateUser(request) = &mut rows[0] {
            request.attributes.push(Attribute {
                name: KERBEROS_SYNC.into(),
                value: 1i64.into(),
            });
        }
        rows.insert(2, HostRow::SyncIs(UserId::new(user), true));
        rows
    }

    async fn turn_sync_on(pool: &DbConnection, user: &str) {
        use lldap_domain::types::Serialized;
        use sea_orm::ActiveValue::Set;
        model::UserAttributes::insert(model::user_attributes::ActiveModel {
            user_id: Set(UserId::new(user)),
            attribute_name: Set(AttributeName::new(KERBEROS_SYNC)),
            value: Set(Serialized(b"1".to_vec())),
        })
        .exec_without_returning(pool)
        .await
        .unwrap();
    }

    const RECORD: &[u8] = b"opaque-record";

    fn alias_onto(target: &str) -> HostRow {
        HostRow::NoAliasOnto(AliasOnto {
            targets: vec![target.to_owned()],
            hops: 10,
            user_of: Arc::new(|name: &str| Some(UserId::new(name))),
        })
    }

    #[derive(Debug, PartialEq)]
    struct After {
        alice_record: bool,
        carol: bool,
        logs: u64,
        principals: usize,
        generation: i64,
    }

    async fn stored_record(db: &DbConnection, user: &str) -> Option<Vec<u8>> {
        model::User::find_by_id(UserId::new(user))
            .select_only()
            .column(UserColumn::PasswordHash)
            .into_tuple::<(Option<Vec<u8>>,)>()
            .one(db)
            .await
            .unwrap()
            .and_then(|(record,)| record)
    }

    async fn after(db: &Db) -> After {
        use sea_orm::PaginatorTrait;
        let (realm, generation) = load_realm(&db.other).await.unwrap();
        After {
            alice_record: stored_record(&db.other, "alice")
                .await
                .is_some_and(|record| record == RECORD),
            carol: model::User::find_by_id(UserId::new("carol"))
                .one(&db.other)
                .await
                .unwrap()
                .is_some(),
            logs: model::Logs::find().count(&db.other).await.unwrap(),
            principals: realm.principals.len(),
            generation,
        }
    }

    #[derive(Clone, Copy, PartialEq)]
    enum Before {
        Nothing,
        GenerationMoved,
        ConnectionHeld,
        SyncOn,
    }

    #[tokio::test]
    #[serial]
    async fn test_host_rows_and_the_batch_commit_in_one_transaction() {
        let nothing = |generation| After {
            alice_record: false,
            carol: false,
            logs: 0,
            principals: 0,
            generation,
        };
        type Row = (
            &'static str,
            Vec<HostRow>,
            Before,
            Result<(), &'static str>,
            After,
        );
        let rows: Vec<Row> = vec![
            (
                "a password and its row",
                password_rows("alice", RECORD),
                Before::Nothing,
                Ok(()),
                After {
                    alice_record: true,
                    logs: 1,
                    principals: 1,
                    generation: 6,
                    ..nothing(6)
                },
            ),
            (
                "the user is gone",
                password_rows("nobody", RECORD),
                Before::Nothing,
                Err(USER_GONE),
                nothing(5),
            ),
            (
                "a synced user's password, the sync still on",
                synced_rows("alice", RECORD),
                Before::SyncOn,
                Ok(()),
                After {
                    alice_record: true,
                    logs: 1,
                    principals: 1,
                    generation: 6,
                    ..nothing(6)
                },
            ),
            (
                "a synced user's password, the sync turned off before the commit",
                synced_rows("alice", RECORD),
                Before::Nothing,
                Err(SYNC_CHANGED),
                nothing(5),
            ),
            (
                "a synced Add: the sync it writes is read in its transaction",
                synced_create_rows("carol", RECORD),
                Before::Nothing,
                Ok(()),
                After {
                    carol: true,
                    logs: 2,
                    principals: 1,
                    ..nothing(6)
                },
            ),
            (
                "an Add: the user, its record and its rows",
                create_rows("carol", RECORD),
                Before::Nothing,
                Ok(()),
                After {
                    carol: true,
                    logs: 2,
                    principals: 1,
                    ..nothing(6)
                },
            ),
            (
                "an Add of an existing user",
                create_rows("alice", RECORD),
                Before::Nothing,
                Err("while creating the user"),
                nothing(5),
            ),
            (
                "the generation moved",
                password_rows("alice", RECORD),
                Before::GenerationMoved,
                Err("the realm's generation moved"),
                nothing(7),
            ),
            (
                "the step ran out",
                password_rows("alice", RECORD),
                Before::ConnectionHeld,
                Err("did not answer within 100ms"),
                nothing(5),
            ),
            (
                "a new name a directory user holds, in another case",
                vec![HostRow::NoUser(vec![UserId::new("Alice")])],
                Before::Nothing,
                Err(DIRECTORY_USER),
                nothing(5),
            ),
            (
                "a new name no directory user holds",
                vec![HostRow::NoUser(vec![UserId::new("bob")])],
                Before::Nothing,
                Ok(()),
                After {
                    principals: 1,
                    ..nothing(6)
                },
            ),
            (
                "an alias onto a directory user's name, in another case",
                vec![alias_onto("Alice")],
                Before::Nothing,
                Err(DIRECTORY_TARGET),
                nothing(5),
            ),
            (
                "an alias onto a name no directory user holds",
                vec![alias_onto("bob")],
                Before::Nothing,
                Ok(()),
                After {
                    principals: 1,
                    ..nothing(6)
                },
            ),
        ];
        for (label, host, before, answer, expected) in rows {
            let db = db().await;
            insert_alice(&db.pool).await;
            insert_realm(&db.pool, 5, true).await;
            let timings = short_timings();
            let (lost_tx, _lost) = watch::channel(None);
            let (reply, answered) = oneshot::channel();
            let held = Phase::Held(fresh(5, true, &timings));
            if before == Before::SyncOn {
                turn_sync_on(&db.pool, "alice").await;
            }
            if before == Before::GenerationMoved {
                let txn = db.other.begin().await.unwrap();
                heartbeat(&txn, 5).await.unwrap();
                heartbeat(&txn, 6).await.unwrap();
                txn.commit().await.unwrap();
            }
            let holding = match before {
                Before::ConnectionHeld => Some(db.pool.begin().await.unwrap()),
                _ => None,
            };
            let watches = (&lost_tx, &quiet());
            commit_job(&db.pool, held, &host, batch(), reply, watches, &timings).await;
            if let Some(txn) = holding {
                txn.rollback().await.unwrap();
            }
            let got = answered.await.unwrap().map_err(|e| e.to_string());
            match (&got, answer) {
                (Ok(()), Ok(())) => {}
                (Err(e), Err(part)) => assert!(e.contains(part), "{label}: {e}"),
                _ => panic!("{label}: {got:?}"),
            }
            assert_eq!(after(&db).await, expected, "{label}");
        }
    }

    #[tokio::test]
    #[serial]
    async fn test_a_delete_and_an_update_commit_with_the_batch() {
        use lldap_domain::requests::UpdateUserRequest;
        use lldap_domain_handlers::logging::{LogKind, event};
        let removed = || RealmBatch {
            upsert_principals: Vec::new(),
            delete_principals: vec!["alice".to_owned()],
            put_policies: Vec::new(),
            delete_policies: Vec::new(),
            realm: None,
        };
        let delete = |user: &str| {
            vec![
                HostRow::DeleteUser(UserId::new(user)),
                HostRow::Log(event(LogKind::UserDelete, Some(user), true, None)),
            ]
        };
        let update = |user: &str| {
            vec![
                HostRow::UpdateUser(UpdateUserRequest {
                    user_id: UserId::new(user),
                    display_name: Some("Alice A.".to_owned()),
                    ..Default::default()
                }),
                HostRow::Log(event(LogKind::UserUpdate, Some(user), true, None)),
            ]
        };
        let old = (true, None, 1, 1, 0, 1, 6);
        type Row = (
            &'static str,
            Vec<HostRow>,
            Result<(), &'static str>,
            (bool, Option<String>, i64, i64, u64, usize, i64),
        );
        let rows: Vec<Row> = vec![
            (
                "a delete, its principal, its memberships and attributes, and its row",
                delete("alice"),
                Ok(()),
                (false, None, 0, 0, 1, 0, 7),
            ),
            (
                "a delete of a user who is gone",
                delete("nobody"),
                Err(USER_GONE),
                old.clone(),
            ),
            (
                "an update, the principal's removal and its row",
                update("alice"),
                Ok(()),
                (true, Some("Alice A.".to_owned()), 1, 1, 1, 0, 7),
            ),
            (
                "an update of a user who is gone",
                update("nobody"),
                Err(USER_GONE),
                old,
            ),
        ];
        let count = |db: &DbConnection, sql: &'static str| {
            let db = db.clone();
            async move {
                let statement = sea_orm::Statement::from_string(db.get_database_backend(), sql);
                let row = db.query_one(statement).await.unwrap().unwrap();
                row.try_get::<i64>("", "n").unwrap()
            }
        };
        for (label, host, answer, expected) in rows {
            let db = db().await;
            insert_alice(&db.pool).await;
            insert_realm(&db.pool, 5, true).await;
            let txn = db.pool.begin().await.unwrap();
            commit_batch_with_transaction(&txn, &batch(), 5)
                .await
                .unwrap();
            txn.commit().await.unwrap();
            for statement in [
                "INSERT INTO groups (group_id, display_name, lowercase_display_name, \
                 creation_date, uuid, modified_date) VALUES (7, 'grp', 'grp', \
                 '2026-01-01 00:00:00', 'g7', '2026-01-01 00:00:00')",
                "INSERT INTO memberships (user_id, group_id) VALUES ('alice', 7)",
                "INSERT INTO user_attributes (user_attribute_user_id, user_attribute_name, \
                 user_attribute_value) VALUES ('alice', 'firstname', X'41')",
            ] {
                db.pool.execute_unprepared(statement).await.unwrap();
            }
            let timings = short_timings();
            let (lost_tx, _lost) = watch::channel(None);
            let (reply, answered) = oneshot::channel();
            let held = Phase::Held(fresh(6, true, &timings));
            let watches = (&lost_tx, &quiet());
            commit_job(&db.pool, held, &host, removed(), reply, watches, &timings).await;
            let got = answered.await.unwrap().map_err(|e| e.to_string());
            match (&got, answer) {
                (Ok(()), Ok(())) => {}
                (Err(e), Err(part)) => assert!(e.contains(part), "{label}: {e}"),
                _ => panic!("{label}: {got:?}"),
            }
            use sea_orm::PaginatorTrait;
            let alice = model::User::find_by_id(UserId::new("alice"))
                .one(&db.other)
                .await
                .unwrap();
            let (realm, generation) = load_realm(&db.other).await.unwrap();
            let after = (
                alice.is_some(),
                alice.and_then(|user| user.display_name),
                count(&db.other, "SELECT COUNT(*) AS n FROM memberships").await,
                count(&db.other, "SELECT COUNT(*) AS n FROM user_attributes").await,
                model::Logs::find().count(&db.other).await.unwrap(),
                realm.principals.len(),
                generation,
            );
            assert_eq!(after, expected, "{label}");
        }
    }

    #[tokio::test]
    #[serial]
    async fn test_a_membership_commits_with_the_batch() {
        use lldap_domain::types::GroupId;
        use lldap_domain_handlers::logging::{LogKind, event};
        let change = |user: &str, group: i32, add: bool| {
            let kind = match add {
                true => LogKind::MembershipAdd,
                false => LogKind::MembershipRemove,
            };
            vec![
                HostRow::Membership {
                    user: UserId::new(user),
                    group: GroupId(group),
                    add,
                },
                HostRow::Log(event(kind, Some(user), true, Some("grp"))),
            ]
        };
        let refused = "Kerberos store refused the change";
        type Row = (
            &'static str,
            bool,
            Vec<HostRow>,
            Result<(), &'static str>,
            (i64, u64, i64),
        );
        let rows: Vec<Row> = vec![
            ("an add", false, change("alice", 7, true), Ok(()), (1, 1, 7)),
            (
                "a remove",
                true,
                change("alice", 7, false),
                Ok(()),
                (0, 1, 7),
            ),
            (
                "an add for a user who is gone",
                false,
                change("nobody", 7, true),
                Err(USER_GONE),
                (0, 0, 6),
            ),
            (
                "an add to a group that is gone",
                false,
                change("alice", 8, true),
                Err(refused),
                (0, 0, 6),
            ),
            (
                "a remove of no membership",
                false,
                change("alice", 7, false),
                Err("No such membership"),
                (0, 0, 6),
            ),
            (
                "an add of a membership already there",
                true,
                change("alice", 7, true),
                Err(refused),
                (1, 0, 6),
            ),
        ];
        let count = |db: &DbConnection, sql: &'static str| {
            let db = db.clone();
            async move {
                let statement = sea_orm::Statement::from_string(db.get_database_backend(), sql);
                let row = db.query_one(statement).await.unwrap().unwrap();
                row.try_get::<i64>("", "n").unwrap()
            }
        };
        for (label, member, host, answer, expected) in rows {
            use sea_orm::PaginatorTrait;
            let db = db().await;
            insert_alice(&db.pool).await;
            insert_realm(&db.pool, 5, true).await;
            db.pool
                .execute_unprepared(
                    "INSERT INTO groups (group_id, display_name, lowercase_display_name, \
                     creation_date, uuid, modified_date) VALUES (7, 'grp', 'grp', \
                     '2026-01-01 00:00:00', 'g7', '2026-01-01 00:00:00')",
                )
                .await
                .unwrap();
            if member {
                let statement = "INSERT INTO memberships (user_id, group_id) VALUES ('alice', 7)";
                db.pool.execute_unprepared(statement).await.unwrap();
            }
            let timings = short_timings();
            let (lost_tx, _lost) = watch::channel(None);
            let (reply, answered) = oneshot::channel();
            let held = Phase::Held(fresh(6, true, &timings));
            let txn = db.pool.begin().await.unwrap();
            heartbeat(&txn, 5).await.unwrap();
            txn.commit().await.unwrap();
            let watches = (&lost_tx, &quiet());
            commit_job(&db.pool, held, &host, batch(), reply, watches, &timings).await;
            let got = answered.await.unwrap().map_err(|e| e.to_string());
            match (&got, answer) {
                (Ok(()), Ok(())) => {}
                (Err(e), Err(part)) => assert!(e.contains(part), "{label}: {e}"),
                _ => panic!("{label}: {got:?}"),
            }
            let after = (
                count(&db.other, "SELECT COUNT(*) AS n FROM memberships").await,
                model::Logs::find().count(&db.other).await.unwrap(),
                load_realm(&db.other).await.unwrap().1,
            );
            assert_eq!(after, expected, "{label}");
        }
    }

    #[tokio::test]
    #[serial]
    async fn test_the_directory_users_are_read_within_one_step() {
        let db = db().await;
        insert_alice(&db.pool).await;
        let step = Duration::from_millis(100);
        let asked = [UserId::new("Alice"), UserId::new("nobody")];
        let found = read_users(&db.pool, &asked, step).await.unwrap();
        let none = read_users(&db.pool, &[], step).await.unwrap();
        let held = db.pool.begin().await.unwrap();
        let late = read_users(&db.pool, &asked, step).await.unwrap_err();
        held.rollback().await.unwrap();
        assert_eq!(
            (
                found,
                none,
                late.to_string().contains("did not answer within 100ms")
            ),
            (vec![UserId::new("alice")], Vec::new(), true)
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_the_disabled_state_is_read_within_one_step() {
        let db = db().await;
        insert_alice(&db.pool).await;
        let step = Duration::from_millis(100);
        let (alice, nobody) = (UserId::new("alice"), UserId::new("nobody"));
        let no_group = read_disabled(&db.pool, &alice, step).await.unwrap();
        db.pool
            .execute_unprepared(
                "INSERT INTO groups (group_id, display_name, lowercase_display_name, \
                 creation_date, uuid, modified_date) VALUES (7, 'lldap_disabled', \
                 'lldap_disabled', '2026-01-01 00:00:00', 'g7', '2026-01-01 00:00:00')",
            )
            .await
            .unwrap();
        let not_in_it = read_disabled(&db.pool, &alice, step).await.unwrap();
        db.pool
            .execute_unprepared("INSERT INTO memberships (user_id, group_id) VALUES ('alice', 7)")
            .await
            .unwrap();
        let in_it = read_disabled(&db.pool, &alice, step).await.unwrap();
        let no_user = read_disabled(&db.pool, &nobody, step).await.unwrap();
        let held = db.pool.begin().await.unwrap();
        let late = read_disabled(&db.pool, &alice, step).await.unwrap_err();
        held.rollback().await.unwrap();
        assert_eq!(
            (
                (no_group, not_in_it, in_it, no_user),
                late.to_string().contains("did not answer within 100ms")
            ),
            ((false, false, true, false), true)
        );
    }

    #[derive(Clone, Copy, Debug, PartialEq)]
    enum Lost {
        Committed,
        NotCommitted,
        CommittedUnreadable,
        TakenMeanwhile,
    }

    // Q-E, in the committer: after a lost COMMIT answer, the realm's generation decides, once.
    #[tokio::test]
    #[serial]
    async fn test_a_lost_answer_is_settled_by_the_realm_generation() {
        use lldap_domain_handlers::logging::{LogKind, event};
        const LOST: &str = "the answer to COMMIT was lost";
        let mut kadmin_cpw = password_rows("alice", RECORD);
        kadmin_cpw[1] = HostRow::Log(event(
            LogKind::PasswordChange,
            Some("alice@EXAMPLE.COM"),
            true,
            Some("kadmin change_password by admin/admin@EXAMPLE.COM"),
        ));
        let jobs: [(&str, Vec<HostRow>, bool); 4] = [
            ("a password change", password_rows("alice", RECORD), true),
            ("a kadmin cpw", kadmin_cpw, true),
            (
                "a kadmin create",
                vec![HostRow::NoUser(vec![UserId::new("bob")])],
                false,
            ),
            ("an own write", Vec::new(), false),
        ];
        let committed = |password: bool| After {
            alice_record: password,
            carol: false,
            logs: u64::from(password),
            principals: 1,
            generation: 6,
        };
        let untouched = |generation| After {
            alice_record: false,
            carol: false,
            logs: 0,
            principals: 0,
            generation,
        };
        let replaced = (false, Some(KerberosLost::Replaced));
        type Outcome = (
            Lost,
            &'static str,
            Option<i64>,
            (bool, Option<KerberosLost>),
        );
        let outcomes: [Outcome; 4] = [
            (Lost::Committed, "ok", Some(6), (true, None)),
            (Lost::NotCommitted, "failed", Some(5), (true, None)),
            (
                Lost::CommittedUnreadable,
                "unknown",
                Some(5),
                replaced.clone(),
            ),
            (Lost::TakenMeanwhile, "unknown", None, replaced),
        ];
        let (mut got, mut want) = (Vec::new(), Vec::new());
        for (job, host, password) in &jobs {
            for (lost, answer, generation, next) in outcomes.clone() {
                let db = db().await;
                insert_alice(&db.pool).await;
                insert_realm(&db.pool, 5, true).await;
                let timings = short_timings();
                let (lost_tx, cause) = watch::channel(None);
                match lost {
                    Lost::Committed | Lost::CommittedUnreadable => {
                        let sent = AtomicBool::new(false);
                        let wrote = write_batch(&db.pool, host, &batch(), 5, &sent).await;
                        assert!(matches!(wrote, Ok(())), "{job}, {lost:?}");
                    }
                    Lost::TakenMeanwhile => {
                        let txn = db.other.begin().await.unwrap();
                        heartbeat(&txn, 5).await.unwrap();
                        heartbeat(&txn, 6).await.unwrap();
                        txn.commit().await.unwrap();
                    }
                    Lost::NotCommitted => {}
                }
                let holding = match lost {
                    Lost::CommittedUnreadable => Some(db.pool.begin().await.unwrap()),
                    _ => None,
                };
                let held = fresh(5, true, &timings);
                let started = Instant::now();
                let (answered, phase) = read_back(
                    &db.pool,
                    held,
                    started,
                    written(host),
                    LOST.to_owned(),
                    &lost_tx,
                    &timings,
                )
                .await;
                if let Some(txn) = holding {
                    txn.rollback().await.unwrap();
                }
                let answered = answer_of(answered, LOST);
                let at = generation_of(&phase);
                let stored = after(&db).await;
                let (reply, then) = oneshot::channel();
                let watches = (&lost_tx, &quiet());
                commit_job(&db.pool, phase, &[], batch(), reply, watches, &timings).await;
                let then = (then.await.unwrap().is_ok(), cause.borrow().clone());
                got.push((*job, lost, answered, at, stored, then));
                let stored = match lost {
                    Lost::Committed | Lost::CommittedUnreadable => committed(*password),
                    Lost::NotCommitted => untouched(5),
                    Lost::TakenMeanwhile => untouched(7),
                };
                want.push((*job, lost, answer.to_owned(), generation, stored, next));
            }
        }
        assert_eq!(got, want);

        let (mut got, mut want) = (Vec::new(), Vec::new());
        for (job, host, password) in &jobs {
            let db = db().await;
            insert_alice(&db.pool).await;
            insert_realm(&db.pool, 5, true).await;
            let timings = Timings {
                stall_after_commit: Duration::from_millis(300),
                ..short_timings()
            };
            let (lost_tx, cause) = watch::channel(None);
            let (reply, answered) = oneshot::channel();
            let held = Phase::Held(fresh(5, true, &timings));
            let watches = (&lost_tx, &quiet());
            let phase = commit_job(&db.pool, held, host, batch(), reply, watches, &timings).await;
            let at = match &phase {
                Phase::Held(held) => Some(held.generation),
                _ => None,
            };
            let answered = answered.await.unwrap().is_ok();
            got.push((*job, answered, at, after(&db).await, cause.borrow().clone()));
            want.push((*job, true, Some(6), committed(*password), None));
        }
        assert_eq!(got, want, "the step ran out after COMMIT was sent");

        let ms = Duration::from_millis;
        let mut stalled = Vec::new();
        for stall in [ms(50), ms(400)] {
            let db = db().await;
            insert_alice(&db.pool).await;
            insert_realm(&db.pool, 5, true).await;
            let timings = Timings {
                stall_before_read: stall,
                ..short_timings()
            };
            let wrote = write_batch(&db.pool, &[], &batch(), 5, &AtomicBool::new(false)).await;
            assert!(matches!(wrote, Ok(())), "{wrote:?}");
            let (lost_tx, cause) = watch::channel(None);
            let held = Held {
                last_ok: Instant::now() - ms(300),
                ..fresh(5, true, &timings)
            };
            let lost = LOST.to_owned();
            let started = Instant::now();
            let (answered, phase) = read_back(
                &db.pool,
                held,
                started,
                written(&[]),
                lost,
                &lost_tx,
                &timings,
            )
            .await;
            let at = generation_of(&phase);
            stalled.push((stall, answer_of(answered, LOST), at, cause.borrow().clone()));
        }
        assert_eq!(
            stalled,
            vec![
                (ms(50), "ok".to_owned(), Some(6), None),
                (
                    ms(400),
                    "unknown".to_owned(),
                    None,
                    Some(KerberosLost::Replaced)
                ),
            ],
            "the job started in time; a read that returns past lost_after and two steps may be a \
             watcher's take"
        );

        let db = db().await;
        insert_alice(&db.pool).await;
        insert_realm(&db.pool, 5, true).await;
        let timings = short_timings();
        let wrote = write_batch(&db.pool, &[], &batch(), 5, &AtomicBool::new(false)).await;
        assert!(matches!(wrote, Ok(())), "{wrote:?}");
        let (lost_tx, cause) = watch::channel(None);
        let late = Held {
            last_ok: Instant::now() - timings.lost_after * 2,
            ..fresh(5, true, &timings)
        };
        let started = Instant::now();
        let (answered, phase) = read_back(
            &db.pool,
            late,
            started,
            written(&[]),
            LOST.to_owned(),
            &lost_tx,
            &timings,
        )
        .await;
        assert_eq!(
            (
                answer_of(answered, LOST),
                generation_of(&phase),
                cause.borrow().clone()
            ),
            ("unknown".to_owned(), None, Some(KerberosLost::Replaced)),
            "a job started past lost_after: one up may be a watcher's take"
        );
    }

    fn answer_of(answered: Result<(), KerberosStoreError>, lost: &str) -> String {
        match answered {
            Ok(()) => "ok".to_owned(),
            Err(KerberosStoreError::Failed(why)) if why == lost => "failed".to_owned(),
            Err(KerberosStoreError::Failed(why)) if why.ends_with(CREATED_FIRST) => {
                "created first".to_owned()
            }
            Err(KerberosStoreError::Failed(why)) if why.starts_with(UNREAD_AFTER_COMMIT) => {
                "unknown".to_owned()
            }
            Err(e) => e.to_string(),
        }
    }

    fn generation_of(phase: &Phase) -> Option<i64> {
        match phase {
            Phase::Held(held) => Some(held.generation),
            _ => None,
        }
    }

    // Each start from last_ok, to the ms: a beat by the latest wake plus one job's step, a commit
    // before that wake; a write takes a step, a read-back one more (a beat's if `beat_reads_back`).
    #[test]
    fn test_the_longest_hold_from_the_wakes_one_job_and_the_late_beat_rule_leaves_a_step() {
        let timings = standard(false);
        let held = fresh(5, true, &timings);
        let at = |offset: Duration| held.last_ok + offset;
        let renewed = timings.step * 2 + timings.heartbeat;
        let capped = retry_wake(&held, at(timings.watch), &timings) - held.last_ok;
        let latest_wake = renewed.max(capped);
        let last_start = u64::try_from((latest_wake + timings.step).as_millis()).unwrap();
        let longest = |late_rule: bool| {
            (0..=last_start)
                .map(Duration::from_millis)
                .map(|start| {
                    let reads_back = !late_rule || beat_reads_back(&held, at(start), &timings);
                    let beat = start + timings.step * (1 + u32::from(reads_back));
                    let commit = start + timings.step * 2;
                    if start < latest_wake {
                        beat.max(commit)
                    } else {
                        beat
                    }
                })
                .max()
                .unwrap_or_default()
        };
        let (with_rule, without) = (longest(true), longest(false));
        let secs = Duration::from_secs;
        assert_eq!(
            (
                with_rule,
                timings.watch.checked_sub(with_rule),
                timings.watch.checked_sub(without)
            ),
            (secs(30), Some(secs(5)), Some(Duration::ZERO)),
            "the late-beat rule is what leaves the slack"
        );
        assert_eq!(
            (HEARTBEAT, LOST_AFTER, STEP, WATCH, FIRST_PROBE),
            (secs(10), secs(20), secs(5), secs(35), secs(60)),
            "the values docs/kerberos.md states"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_a_beat_decides_after_it_ends_whether_the_realm_is_lost() {
        #[derive(Clone, Copy, PartialEq)]
        enum Fault {
            DroppedAnswer,
            LandedAnswerLost,
            ConnectionHeld,
        }
        let unreachable = Some(KerberosLost::DatabaseUnreachable);
        let late = Duration::from_millis(350);
        let rows = [
            (
                "a dropped answer read back before lost_after",
                Duration::ZERO,
                Fault::DroppedAnswer,
                (Some(5), None, 5),
            ),
            (
                "a dropped answer read back past lost_after",
                late,
                Fault::DroppedAnswer,
                (None, unreachable.clone(), 5),
            ),
            (
                "a beat whose step ends past lost_after",
                late,
                Fault::ConnectionHeld,
                (None, unreachable, 5),
            ),
            (
                "a landed beat read back past lost_after, inside two steps",
                late,
                Fault::LandedAnswerLost,
                (Some(6), None, 6),
            ),
        ];
        let (mut got, mut want) = (Vec::new(), Vec::new());
        for (label, silent, fault, expected) in rows {
            let db = db().await;
            insert_realm(&db.pool, 5, true).await;
            let timings = Timings {
                drop_a_beat: AtomicBool::new(fault == Fault::DroppedAnswer),
                lose_a_beat: AtomicBool::new(fault == Fault::LandedAnswerLost),
                stall_before_read: Duration::from_millis(100),
                ..short_timings()
            };
            let (lost_tx, lost) = watch::channel(None);
            let woken = Held {
                last_ok: Instant::now() - silent,
                ..fresh(5, true, &timings)
            };
            let holding = match fault {
                Fault::ConnectionHeld => Some(db.pool.begin().await.unwrap()),
                _ => None,
            };
            let phase = on_wake(&db.pool, Phase::Held(woken), &timings, &lost_tx).await;
            if let Some(txn) = holding {
                txn.rollback().await.unwrap();
            }
            let cause = lost.borrow().clone();
            got.push((
                label,
                (generation_of(&phase), cause, hold(&db.other).await.0),
            ));
            want.push((label, expected));
        }
        assert_eq!(got, want);
    }

    #[tokio::test]
    #[serial]
    async fn test_a_lost_beat_answer_is_settled_by_the_realm_generation() {
        let mut got = Vec::new();
        for silent in [Duration::ZERO, Duration::from_millis(500)] {
            let db = db().await;
            insert_realm(&db.pool, 5, true).await;
            let timings = Timings {
                lose_a_beat: AtomicBool::new(true),
                ..short_timings()
            };
            let (lost_tx, lost) = watch::channel(None);
            let woken = Held {
                last_ok: Instant::now() - silent,
                ..fresh(5, true, &timings)
            };
            let phase = on_wake(&db.pool, Phase::Held(woken), &timings, &lost_tx).await;
            let first = (generation_of(&phase), lost.borrow().clone());
            let phase = on_wake(&db.pool, phase, &timings, &lost_tx).await;
            let second = (generation_of(&phase), lost.borrow().clone());
            got.push((silent, first, second, hold(&db.other).await.0));
        }
        let given_up = (None, Some(KerberosLost::HeartbeatTooLate));
        assert_eq!(
            got,
            vec![
                (Duration::ZERO, (Some(6), None), (Some(7), None), 7),
                (Duration::from_millis(500), given_up.clone(), given_up, 6),
            ],
            "its own landed beat is held on; past lost_after a lost answer is not read back"
        );

        let ms = Duration::from_millis;
        let cases = [
            ("one up, in time", 6, false, ms(0), ms(0), "landed"),
            ("one up, past lost_after", 6, false, ms(500), ms(0), "moved"),
            (
                "one up, the job in time, its read returned past two steps",
                6,
                false,
                ms(700),
                ms(400),
                "moved",
            ),
            ("unchanged", 5, false, ms(0), ms(0), "unchanged"),
            ("two up: another holder", 7, false, ms(0), ms(0), "moved"),
            ("the connection held", 6, true, ms(0), ms(0), "unread"),
        ];
        let (mut got, mut want) = (Vec::new(), Vec::new());
        for (label, stored, holding, silent, started_ago, expected) in cases {
            let db = db().await;
            insert_realm(&db.pool, stored, true).await;
            let timings = short_timings();
            let held = Held {
                last_ok: Instant::now() - silent,
                ..fresh(5, true, &timings)
            };
            let holding = if holding {
                Some(db.pool.begin().await.unwrap())
            } else {
                None
            };
            let started = Instant::now() - started_ago;
            let settled = settle(&db.pool, &held, started, None, &timings).await;
            if let Some(txn) = holding {
                txn.rollback().await.unwrap();
            }
            let settled = match settled {
                Settled::Landed => "landed",
                Settled::Unchanged => "unchanged",
                Settled::Unread(_) => "unread",
                Settled::Moved => "moved",
                Settled::CreatedElsewhere => "created elsewhere",
            };
            got.push((label, settled));
            want.push((label, expected));
        }
        assert_eq!(got, want);
    }

    #[tokio::test]
    #[serial]
    async fn test_a_reply_dropped_after_the_job_was_taken_is_unknown() {
        let db = db().await;
        insert_alice(&db.pool).await;
        insert_realm(&db.pool, 5, false).await;
        let timings = Timings {
            step: Duration::from_secs(120),
            stall_after_commit: Duration::from_secs(60),
            ..standard(false)
        };
        let handle = spawn_committer(db.pool.clone(), timings);
        let commit = |store: Arc<dyn KerberosStore>| {
            let (tx, rx) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                let _ = tx.send(store.commit(batch()).map_err(|err| err.to_string()));
            });
            rx
        };
        let taken = commit(handle.store());
        let deadline = Instant::now() + Duration::from_secs(2);
        while hold(&db.other).await != (7, true) {
            assert!(Instant::now() < deadline, "the commit did not land");
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let queued = commit(handle.store());
        tokio::time::sleep(Duration::from_millis(50)).await;
        handle.task.abort();
        let answers = [wait_thread(taken).await, wait_thread(queued).await].map(|answer| {
            let err = answer.unwrap().unwrap_err();
            (
                err.contains(UNREAD_AFTER_COMMIT),
                err.contains("kerberos committer stopped"),
            )
        });
        assert_eq!(
            answers,
            [(true, true), (false, true)],
            "taken, then dropped: unknown; still queued: nothing ran"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_the_fill_is_refused_unless_the_realm_is_held() {
        let db = db().await;
        insert_alice(&db.pool).await;
        insert_realm(&db.pool, 5, true).await;
        let wrote = write_batch(&db.pool, &[], &batch(), 5, &AtomicBool::new(false)).await;
        assert!(matches!(wrote, Ok(())), "{wrote:?}");
        let timings = short_timings();
        let rows = [("alice".to_owned(), "y@EXAMPLE.COM".to_owned())];
        let now = Instant::now();
        let phases = [
            (
                "starting",
                Phase::Starting {
                    since: now,
                    next: now,
                },
            ),
            (
                "watching",
                Phase::Watching {
                    generation: 6,
                    until: now,
                },
            ),
            ("lost", Phase::Lost),
            ("held", Phase::Held(fresh(6, true, &timings))),
        ];
        let mut got = Vec::new();
        for (label, phase) in phases {
            let filled = fill_aliases(&db.pool, &phase, &rows, timings.step).await;
            let chain = alias_chain(&db.other, "alice", 1).await.unwrap();
            got.push((label, filled.map_err(|err| err.to_string()), chain));
        }
        let refused = Err(not_held().to_string());
        let alice = vec!["alice".to_owned()];
        assert_eq!(
            got,
            vec![
                ("starting", refused.clone(), alice.clone()),
                ("watching", refused.clone(), alice.clone()),
                ("lost", refused, alice),
                ("held", Ok(1), vec!["alice".to_owned(), "y".to_owned()]),
            ]
        );
    }

    fn written(host: &[HostRow]) -> Written<'_> {
        Written { host, realm: None }
    }

    async fn commit_on(handle: &KerberosCommitterHandle, batch: RealmBatch) -> Result<(), String> {
        let (tx, rx) = std::sync::mpsc::channel();
        let store = handle.store();
        std::thread::spawn(move || {
            let _ = tx.send(store.commit(batch).map_err(|err| err.to_string()));
        });
        wait_thread(rx).await?
    }

    #[tokio::test]
    #[serial]
    async fn test_the_first_commit_is_settled_by_a_probe_of_its_key() {
        const LOST: &str = "the answer to COMMIT was lost";
        #[derive(Clone, Copy, Debug, PartialEq)]
        enum First {
            Ours,
            Nothing,
            Held,
            AnotherCommitter,
            AnotherState,
            OursTakenSince,
        }
        let occupied = Some(KerberosLost::Occupied);
        let rows = [
            (First::Ours, "ok", Some((1, true, false)), None, true),
            (
                First::Nothing,
                "failed",
                Some((0, false, false)),
                None,
                false,
            ),
            (First::Held, "unknown", Some((0, false, true)), None, false),
            (
                First::AnotherCommitter,
                "created first",
                None,
                occupied.clone(),
                true,
            ),
            (First::AnotherState, "created first", None, occupied, true),
            (
                First::OursTakenSince,
                "unknown",
                None,
                Some(KerberosLost::Replaced),
                true,
            ),
        ];
        let ours = batch().realm.unwrap();
        let (mut got, mut want) = (Vec::new(), Vec::new());
        for (first, answer, at, cause, row) in rows {
            let db = db().await;
            insert_alice(&db.pool).await;
            let timings = Timings {
                lost_after: Duration::from_secs(5),
                ..short_timings()
            };
            let mut theirs = None;
            match first {
                First::Ours | First::OursTakenSince => {
                    let wrote =
                        write_batch(&db.pool, &[], &batch(), 0, &AtomicBool::new(false)).await;
                    assert!(matches!(wrote, Ok(())), "{first:?}");
                }
                First::AnotherCommitter => {
                    let other = Timings {
                        heartbeat: Duration::from_secs(60),
                        ..short_timings()
                    };
                    let handle = spawn_committer(db.other.clone(), other);
                    let their_batch = RealmBatch {
                        realm: Some(RealmState {
                            state: vec![8],
                            ..ours.clone()
                        }),
                        ..batch()
                    };
                    assert_eq!(commit_on(&handle, their_batch).await, Ok(()), "{first:?}");
                    theirs = Some(handle);
                }
                First::AnotherState => insert_realm(&db.pool, 1, true).await,
                First::Nothing | First::Held => {}
            }
            if first == First::OursTakenSince {
                let take = take_owned(&db.other, 1, timings.step).await;
                assert!(matches!(take, Ok(2)), "{first:?}");
            }
            let holding = match first {
                First::Held => Some(db.pool.begin().await.unwrap()),
                _ => None,
            };
            let (lost_tx, lost) = watch::channel(None);
            let (empty, reason) = (fresh(0, false, &timings), LOST.to_owned());
            let wrote = Written {
                host: &[],
                realm: Some(&ours),
            };
            let started = Instant::now();
            let (answered, phase) =
                read_back(&db.pool, empty, started, wrote, reason, &lost_tx, &timings).await;
            let took = started.elapsed();
            if let Some(txn) = holding {
                txn.rollback().await.unwrap();
            }
            let held = match phase {
                Phase::Held(held) => Some((held.generation, held.row, held.unsettled)),
                _ => None,
            };
            let stored = read_hold(&db.other).await.unwrap().is_some();
            let probed = (
                took >= timings.first_probe,
                took < timings.first_probe + RETRY.min(timings.step) + timings.step * 2,
            );
            let cause_now = lost.borrow().clone();
            got.push((
                first,
                answer_of(answered, LOST),
                held,
                cause_now,
                stored,
                probed,
            ));
            let probed_out = (first == First::Held, true);
            want.push((first, answer.to_owned(), at, cause, row, probed_out));
            if let Some(handle) = theirs {
                handle.shutdown().await;
            }
        }
        assert_eq!(
            got, want,
            "Ok only for this server's own realm row; probed for first_probe, then at most a \
             pause and the last probe's two steps"
        );
    }

    async fn reload(
        pool: &DbConnection,
        phase: Phase,
        lost_tx: &watch::Sender<Option<KerberosLost>>,
        step: Duration,
    ) -> (String, Phase) {
        let (reply, answer) = oneshot::channel();
        let phase = answer_load(pool, phase, reply, &mut Vec::new(), lost_tx, step).await;
        let replaced = KerberosLost::Replaced.to_string();
        let answer = match answer.await.unwrap() {
            Ok(_) => "loaded".to_owned(),
            Err(KerberosStoreError::NotReady(why)) if why.starts_with(UNSETTLED) => {
                "not ready".to_owned()
            }
            Err(KerberosStoreError::Failed(why)) if why == replaced => "replaced".to_owned(),
            Err(err) => err.to_string(),
        };
        (answer, phase)
    }

    #[tokio::test]
    #[serial]
    async fn test_the_reload_after_an_unknown_starts_with_the_locking_read() {
        const LOST: &str = "the answer to COMMIT was lost";
        let mut got = Vec::new();
        for landed in [true, false] {
            let db = db().await;
            insert_alice(&db.pool).await;
            insert_realm(&db.pool, 5, true).await;
            let timings = Timings {
                lost_after: Duration::from_secs(5),
                ..short_timings()
            };
            if landed {
                let wrote = write_batch(&db.pool, &[], &batch(), 5, &AtomicBool::new(false)).await;
                assert!(matches!(wrote, Ok(())), "{wrote:?}");
            }
            let (lost_tx, cause) = watch::channel(None);
            let holding = db.pool.begin().await.unwrap();
            let (held, lost) = (fresh(5, true, &timings), LOST.to_owned());
            let (answered, phase) = read_back(
                &db.pool,
                held,
                Instant::now(),
                written(&[]),
                lost,
                &lost_tx,
                &timings,
            )
            .await;
            let (during, phase) = reload(&db.pool, phase, &lost_tx, timings.step).await;
            holding.rollback().await.unwrap();
            let (after, phase) = reload(&db.pool, phase, &lost_tx, timings.step).await;
            let (again, phase) = reload(&db.pool, phase, &lost_tx, timings.step).await;
            let reloads = [during, after, again];
            let answered = answer_of(answered, LOST);
            got.push((
                landed,
                answered,
                reloads,
                generation_of(&phase),
                cause.borrow().clone(),
            ));
        }
        let unknown = "unknown".to_owned();
        let reloads = |after: &str| ["not ready".to_owned(), after.to_owned(), after.to_owned()];
        assert_eq!(
            got,
            vec![
                (
                    true,
                    unknown.clone(),
                    reloads("replaced"),
                    None,
                    Some(KerberosLost::Replaced)
                ),
                (false, unknown, reloads("loaded"), Some(5), None),
            ],
            "the realm is not ready until the row's lock is had; a commit that landed late \
             gives the realm up"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_a_lost_answer_reads_unsettled_until_it_is_settled() {
        let db = db().await;
        insert_alice(&db.pool).await;
        insert_realm(&db.pool, 5, false).await;
        let timings = Timings {
            heartbeat: Duration::from_secs(60),
            lost_after: Duration::from_secs(5),
            step: Duration::from_millis(100),
            stall_before_read: Duration::from_millis(300),
            ..standard(true)
        };
        let handle = spawn_committer(db.pool.clone(), timings);
        let deadline = Instant::now() + Duration::from_secs(2);
        while hold(&db.other).await != (6, true) {
            assert!(Instant::now() < deadline, "not held");
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let store = handle.store();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let answer = store.commit_with(password_rows("alice", RECORD), batch());
            let hooks = (store.realm_not_held(), store.realm_unsettled());
            let _ = tx.send((answer.map_err(|e| e.to_string()), hooks));
        });
        while hold(&db.other).await.0 != 7 {
            assert!(Instant::now() < deadline, "the commit did not land");
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let holding = db.pool.begin().await.unwrap();
        let replied = wait_thread(rx).await;
        holding.rollback().await.unwrap();
        let (answer, at_reply) = replied.unwrap();
        let settled = Instant::now() + Duration::from_secs(3);
        while *handle.unsettled.borrow() && Instant::now() < settled {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let lost = format!("the Kerberos realm was lost: {}", KerberosLost::Replaced);
        assert_eq!(
            (
                answer.is_err_and(|e| e.contains(UNREAD_AFTER_COMMIT)),
                at_reply,
                *handle.unsettled.borrow(),
                (
                    handle.store().realm_not_held(),
                    handle.store().realm_unsettled()
                )
            ),
            (
                true,
                (None, Some(ANSWER_UNSETTLED.to_owned())),
                false,
                (Some(lost), None)
            ),
            "held and unsettled from the lost answer on; the next beat finds the commit landed: \
             lost"
        );
        handle.shutdown().await;
    }

    #[tokio::test]
    #[serial]
    async fn test_a_beat_that_holds_the_realm_settles_an_unread_answer() {
        const LOST: &str = "the answer to COMMIT was lost";
        let db = db().await;
        insert_realm(&db.pool, 5, true).await;
        // A beat's commit to a file can take longer than the short step on a loaded host.
        let timings = Timings {
            lost_after: Duration::from_secs(5),
            step: Duration::from_secs(1),
            ..short_timings()
        };
        let (lost_tx, cause) = watch::channel(None);
        let (unsettled_tx, unsettled) = watch::channel(false);
        let holding = db.pool.begin().await.unwrap();
        let held = fresh(5, true, &timings);
        let lost = LOST.to_owned();
        let (answered, phase) = read_back(
            &db.pool,
            held,
            Instant::now(),
            written(&[]),
            lost,
            &lost_tx,
            &timings,
        )
        .await;
        holding.rollback().await.unwrap();
        publish_unsettled(&unsettled_tx, &phase);
        let during = *unsettled.borrow();
        let phase = on_wake(&db.pool, phase, &timings, &lost_tx).await;
        publish_unsettled(&unsettled_tx, &phase);
        assert_eq!(
            (
                answer_of(answered, LOST),
                during,
                generation_of(&phase),
                *unsettled.borrow(),
                cause.borrow().clone()
            ),
            ("unknown".to_owned(), true, Some(6), false, None),
            "a commit that did not land: the next beat holds the realm and settles it"
        );
    }

    async fn flood_reads(tx: mpsc::Sender<Job>, until: Instant) {
        while Instant::now() < until {
            let (reply, _) = oneshot::channel();
            let read = Job::Users(vec![UserId::new("alice")], reply);
            if tx.send(read).await.is_err() {
                return;
            }
        }
    }

    async fn held_at(db: &Db, generation: i64) {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let (now, open) = hold(&db.other).await;
            if open && now >= generation {
                return;
            }
            assert!(Instant::now() < deadline, "not held at {generation}");
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    #[tokio::test]
    #[serial]
    async fn test_a_queue_full_of_reads_does_not_starve_the_heartbeat() {
        let db = db().await;
        insert_alice(&db.pool).await;
        insert_realm(&db.pool, 5, false).await;
        let timings = Timings {
            heartbeat: Duration::from_millis(50),
            ..short_timings()
        };
        let lost_after = timings.lost_after;
        let handle = spawn_committer(db.pool.clone(), timings);
        held_at(&db, 6).await;
        let until = Instant::now() + lost_after * 3;
        let flood = tokio::spawn(flood_reads(handle.tx.clone(), until));
        let (mut last, mut seen, mut widest) = (Instant::now(), 6, Duration::ZERO);
        while Instant::now() < until {
            tokio::time::sleep(Duration::from_millis(10)).await;
            let generation = hold(&db.other).await.0;
            if generation > seen {
                widest = widest.max(last.elapsed());
                (last, seen) = (Instant::now(), generation);
            }
        }
        widest = widest.max(last.elapsed());
        flood.await.unwrap();
        let cause = handle.lost().borrow().clone();
        handle.shutdown().await;
        assert_eq!(
            (widest < lost_after, cause),
            (true, None),
            "the widest gap between beats {widest:?}, generation {seen}"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_a_queue_full_of_reads_after_a_lost_beat_answer_still_ends_inside_the_slack() {
        let db = db().await;
        insert_alice(&db.pool).await;
        insert_realm(&db.pool, 5, false).await;
        let timings = Timings {
            heartbeat: Duration::from_millis(350),
            drop_a_beat: AtomicBool::new(true),
            stall_before_read: Duration::from_millis(100),
            ..short_timings()
        };
        let (lost_after, step) = (timings.lost_after, timings.step);
        let before_the_take = Instant::now();
        let handle = spawn_committer(db.pool.clone(), timings);
        held_at(&db, 6).await;
        let until = before_the_take + lost_after * 3;
        let flood = tokio::spawn(flood_reads(handle.tx.clone(), until));
        let lost = handle.lost();
        let ended = loop {
            if let Some(cause) = lost.borrow().clone() {
                break Some((cause, before_the_take.elapsed()));
            }
            if Instant::now() > until {
                break None;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        };
        flood.await.unwrap();
        let stored = hold(&db.other).await.0;
        handle.shutdown().await;
        let given_up = |cause: &KerberosLost| {
            matches!(
                cause,
                KerberosLost::DatabaseUnreachable | KerberosLost::HeartbeatTooLate
            )
        };
        let inside = ended
            .as_ref()
            .map(|(cause, at)| (given_up(cause), *at < lost_after + step * 2));
        assert_eq!((inside, stored), (Some((true, true)), 6), "{ended:?}");
    }

    #[tokio::test]
    #[serial]
    async fn test_a_beat_held_behind_a_jobs_full_step_then_a_lost_answer_ends_inside_the_slack() {
        let db = db().await;
        insert_alice(&db.pool).await;
        insert_realm(&db.pool, 5, false).await;
        let ms = Duration::from_millis;
        let timings = Timings {
            heartbeat: ms(850),
            lost_after: ms(1000),
            step: ms(300),
            drop_a_beat: AtomicBool::new(true),
            stall_before_read: ms(800),
            ..short_timings()
        };
        let (lost_after, step) = (timings.lost_after, timings.step);
        let job_at = lost_after - step + ms(10);
        let before_the_take = Instant::now();
        let handle = spawn_committer(db.pool.clone(), timings);
        held_at(&db, 6).await;
        let seen = Instant::now();
        tokio::time::sleep_until((seen + job_at).into()).await;
        let holding = db.pool.begin().await.unwrap();
        let (reply, answer) = oneshot::channel();
        let read = Job::Users(vec![UserId::new("alice")], reply);
        assert!(handle.tx.send(read).await.is_ok());
        let job_started = Instant::now();
        let job = answer.await.unwrap().is_err() && job_started.elapsed() >= step;
        holding.rollback().await.unwrap();
        let mut lost = handle.lost();
        let cause = wait_lost(&mut lost).await;
        let ended = before_the_take.elapsed();
        let stored = hold(&db.other).await.0;
        handle.shutdown().await;
        assert_eq!(
            (job, cause, ended < lost_after + step * 2, stored),
            (true, KerberosLost::HeartbeatTooLate, true, 6),
            "taken {:?} after the take began, the job held the beat a step past lost_after; \
             given up at {ended:?}",
            seen - before_the_take
        );
    }

    #[derive(Clone, Copy, Debug, PartialEq)]
    enum Holder {
        Commits,
        RollsBack,
        HoldsPastTheStep,
    }

    async fn clear_realm(pool: &DbConnection) {
        for table in ["kerberos_principals", "kerberos_policies", "kerberos_realm"] {
            pool.execute_unprepared(&format!("DELETE FROM {table}"))
                .await
                .unwrap();
        }
    }

    async fn ends(txn: DatabaseTransaction, holder: Holder, hold_ms: u64) {
        tokio::time::sleep(Duration::from_millis(hold_ms)).await;
        match holder {
            Holder::RollsBack => txn.rollback().await.unwrap(),
            _ => txn.commit().await.unwrap(),
        }
    }

    /// Lane rows: the read-back, and the reload after it, wait for the realm row's holder.
    pub(crate) async fn scenario_read_back_waits_for_the_holder(pool: &DbConnection) {
        const LOST: &str = "the answer to COMMIT was lost";
        init_table(pool).await.unwrap();
        insert_alice(pool).await;
        let loaded = ["loaded", "loaded"];
        type Row = (
            Holder,
            u64,
            u64,
            &'static str,
            bool,
            Option<i64>,
            [&'static str; 2],
            i64,
            (bool, Option<KerberosLost>),
        );
        let rows: [Row; 3] = [
            (
                Holder::Commits,
                200,
                2000,
                "ok",
                true,
                Some(6),
                loaded,
                6,
                (true, None),
            ),
            (
                Holder::RollsBack,
                200,
                2000,
                "failed",
                true,
                Some(5),
                loaded,
                5,
                (true, None),
            ),
            (
                Holder::HoldsPastTheStep,
                1000,
                300,
                "unknown",
                false,
                Some(5),
                ["not ready", "replaced"],
                6,
                (false, Some(KerberosLost::Replaced)),
            ),
        ];
        let (mut got, mut want) = (Vec::new(), Vec::new());
        for (holder, hold_ms, step_ms, answer, waited, at, reloads, stored, then) in rows {
            clear_realm(pool).await;
            let timings = Timings {
                lost_after: Duration::from_secs(5),
                step: Duration::from_millis(step_ms),
                ..short_timings()
            };
            insert_realm(pool, 5, true).await;
            let txn = pool.begin().await.unwrap();
            assert_eq!(heartbeat(&txn, 5).await.unwrap(), 6, "{holder:?}");
            let held = fresh(5, true, &timings);
            let (lost_tx, cause) = watch::channel(None);
            let started = Instant::now();
            let reads = async {
                let lost = LOST.to_owned();
                let (answered, phase) =
                    read_back(pool, held, started, written(&[]), lost, &lost_tx, &timings).await;
                let took = started.elapsed();
                let at = generation_of(&phase);
                let (during, phase) = reload(pool, phase, &lost_tx, timings.step).await;
                (answer_of(answered, LOST), took, at, during, phase)
            };
            let ((answered, took, at_read, during, phase), ()) =
                tokio::join!(reads, ends(txn, holder, hold_ms));
            let (after, phase) = reload(pool, phase, &lost_tx, timings.step).await;
            let read = (
                answered,
                took >= Duration::from_millis(hold_ms),
                took < timings.step + Duration::from_millis(500),
                at_read,
            );
            let generation = load_realm(pool).await.unwrap().1;
            let (reply, next) = oneshot::channel();
            let watches = (&lost_tx, &quiet());
            commit_job(pool, phase, &[], batch(), reply, watches, &timings).await;
            let next = (next.await.unwrap().is_ok(), cause.borrow().clone());
            got.push((holder, read, [during, after], generation, next));
            want.push((
                holder,
                (answer.to_owned(), waited, true, at),
                reloads.map(str::to_owned),
                stored,
                then,
            ));
        }
        assert_eq!(got, want);
    }

    /// Lane rows: the first commit's probe waits for the INSERT of the realm row in flight.
    pub(crate) async fn scenario_the_first_commit_probe_waits_for_the_insert(pool: &DbConnection) {
        const LOST: &str = "the answer to COMMIT was lost";
        init_table(pool).await.unwrap();
        type Row = (
            Holder,
            bool,
            u64,
            &'static str,
            bool,
            bool,
            Option<(i64, bool)>,
            i64,
        );
        let rows: [Row; 4] = [
            (
                Holder::Commits,
                false,
                200,
                "ok",
                true,
                false,
                Some((1, true)),
                1,
            ),
            (
                Holder::Commits,
                true,
                200,
                "created first",
                true,
                false,
                None,
                1,
            ),
            (
                Holder::RollsBack,
                false,
                200,
                "failed",
                true,
                false,
                Some((0, false)),
                0,
            ),
            (
                Holder::HoldsPastTheStep,
                false,
                1500,
                "unknown",
                false,
                true,
                Some((0, false)),
                1,
            ),
        ];
        let (mut got, mut want) = (Vec::new(), Vec::new());
        for (holder, another, hold_ms, answer, waited, probed_out, at, stored) in rows {
            clear_realm(pool).await;
            let timings = Timings {
                lost_after: Duration::from_secs(5),
                step: Duration::from_millis(300),
                first_probe: Duration::from_millis(900),
                ..short_timings()
            };
            let ours = RealmState {
                realm: "EXAMPLE.COM".to_owned(),
                state: if another { vec![8] } else { vec![1] },
            };
            let txn = pool.begin().await.unwrap();
            insert_realm(&txn, 1, true).await;
            let (lost_tx, _cause) = watch::channel(None);
            let started = Instant::now();
            let reads = async {
                let (empty, lost) = (fresh(0, false, &timings), LOST.to_owned());
                let wrote = Written {
                    host: &[],
                    realm: Some(&ours),
                };
                let read = read_back(pool, empty, started, wrote, lost, &lost_tx, &timings).await;
                (read, started.elapsed())
            };
            let (((answered, phase), took), ()) = tokio::join!(reads, ends(txn, holder, hold_ms));
            let held = match phase {
                Phase::Held(held) => Some((held.generation, held.row)),
                _ => None,
            };
            let generation = load_realm(pool).await.unwrap().1;
            let probed = took >= timings.first_probe;
            let read = (
                answer_of(answered, LOST),
                took >= Duration::from_millis(hold_ms),
            );
            got.push((holder, another, read, probed, held, generation));
            want.push((
                holder,
                another,
                (answer.to_owned(), waited),
                probed_out,
                at,
                stored,
            ));
        }
        assert_eq!(got, want);
    }

    async fn five_sessions(pool: &DbConnection) -> (usize, usize) {
        const WAITS: &str = "SELECT CAST(@@SESSION.innodb_lock_wait_timeout AS SIGNED), \
                             CAST(@@GLOBAL.innodb_lock_wait_timeout AS SIGNED)";
        let mysql = pool.get_mysql_connection_pool();
        let mut conns = Vec::new();
        for _ in 0..5 {
            let conn = tokio::time::timeout(Duration::from_secs(5), mysql.acquire()).await;
            conns.extend(conn.ok().and_then(Result::ok));
        }
        let mut put_back = 0;
        for conn in &mut conns {
            let (session, global): (i64, i64) =
                sqlx::query_as(WAITS).fetch_one(&mut **conn).await.unwrap();
            put_back += usize::from(session == global);
        }
        (conns.len(), put_back)
    }

    /// MySQL lane row: a pool of five; the realm row held past the step, or released inside it.
    pub(crate) async fn scenario_the_mysql_lock_wait_is_bounded_and_put_back(pool: &DbConnection) {
        const LOST: &str = "the answer to COMMIT was lost";
        init_table(pool).await.unwrap();
        insert_realm(pool, 5, true).await;
        let rows = [
            (
                "held past the step: the read is dropped",
                2000,
                300,
                "unknown",
            ),
            (
                "released inside the step: the bound is put back",
                300,
                1500,
                "failed",
            ),
        ];
        let (mut got, mut want) = (Vec::new(), Vec::new());
        for (label, hold_ms, step_ms, answer) in rows {
            let timings = Timings {
                lost_after: Duration::from_secs(5),
                step: Duration::from_millis(step_ms),
                ..short_timings()
            };
            let txn = pool.begin().await.unwrap();
            assert_eq!(heartbeat(&txn, 5).await.unwrap(), 6, "{label}");
            let (lost_tx, _cause) = watch::channel(None);
            let started = Instant::now();
            let reads = async {
                let (held, lost) = (fresh(5, true, &timings), LOST.to_owned());
                let (answered, _) =
                    read_back(pool, held, started, written(&[]), lost, &lost_tx, &timings).await;
                (answered, started.elapsed())
            };
            let ((answered, took), ()) = tokio::join!(reads, ends(txn, Holder::RollsBack, hold_ms));
            let within = took < timings.step + Duration::from_secs(1);
            let sessions = five_sessions(pool).await;
            got.push((label, answer_of(answered, LOST), within, sessions));
            want.push((label, answer.to_owned(), true, (5, 5)));
        }
        assert_eq!(got, want);
    }
}
