use crate::sql_backend_handler::SqlBackendHandler;
use crate::sql_kerberos_handler::{
    KerberosSqlError, RealmHold, clear_open, commit_batch_with_transaction, heartbeat, load_realm,
    read_hold, take_realm,
};
use crate::sql_log_handler::to_active_model;
use crate::sql_opaque_handler::user_disabled_in;
use crate::sql_tables::DbConnection;
use lldap_domain::types::UserId;
use lldap_domain_handlers::kerberos::{
    DIRECTORY_TARGET, DIRECTORY_USER, HostRow, KerberosStore, KerberosStoreError, LoadedRealm,
    NoopKerberosStore, RealmBatch, UNREAD_AFTER_COMMIT, USER_GONE, set_kerberos_store,
};
use lldap_domain_handlers::password::{ANSWER_LOST, kill_point};
use lldap_domain_model::model::{self, UserColumn};
use sea_orm::sea_query::Expr;
use sea_orm::{
    ColumnTrait, ConnectionTrait, DatabaseTransaction, DbErr, EntityTrait, QueryFilter,
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
const WATCH: Duration = Duration::from_secs(30);
const STEP: Duration = Duration::from_secs(5);
const RETRY: Duration = Duration::from_secs(1);
const QUEUE: usize = 16;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KerberosLost {
    Replaced,
    Occupied,
    DatabaseUnreachable,
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
        }
    }
}

enum Job {
    Load(oneshot::Sender<Result<LoadedRealm, KerberosStoreError>>),
    Commit(
        Vec<HostRow>,
        RealmBatch,
        oneshot::Sender<Result<(), KerberosStoreError>>,
    ),
    Record(
        UserId,
        oneshot::Sender<Result<Option<Vec<u8>>, KerberosStoreError>>,
    ),
    Users(
        Vec<UserId>,
        oneshot::Sender<Result<Vec<UserId>, KerberosStoreError>>,
    ),
    Disabled(UserId, oneshot::Sender<Result<bool, KerberosStoreError>>),
    Shutdown(oneshot::Sender<()>),
}

struct CommitterStore {
    tx: mpsc::Sender<Job>,
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
        self.tx
            .blocking_send(Job::Commit(host, batch, tx))
            .map_err(|_| stopped())?;
        rx.blocking_recv().map_err(|_| stopped())?
    }

    fn password_record(&self, user: &UserId) -> Result<Option<Vec<u8>>, KerberosStoreError> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .blocking_send(Job::Record(user.clone(), tx))
            .map_err(|_| stopped())?;
        rx.blocking_recv().map_err(|_| stopped())?
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
}

fn stopped() -> KerberosStoreError {
    KerberosStoreError::Failed("kerberos committer stopped".to_owned())
}

fn not_held() -> KerberosStoreError {
    KerberosStoreError::NotReady("the Kerberos realm is not held".to_owned())
}

pub struct KerberosCommitterHandle {
    tx: mpsc::Sender<Job>,
    task: tokio::task::JoinHandle<()>,
    lost: watch::Receiver<Option<KerberosLost>>,
    registered: bool,
}

impl KerberosCommitterHandle {
    pub fn lost(&self) -> watch::Receiver<Option<KerberosLost>> {
        self.lost.clone()
    }

    pub fn store(&self) -> Arc<dyn KerberosStore> {
        Arc::new(CommitterStore {
            tx: self.tx.clone(),
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
    /// Tests only: the next password COMMIT that succeeds is answered as lost.
    lose_an_answer: AtomicBool,
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
        lose_an_answer: AtomicBool::new(lose_an_answer),
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
            lose_an_answer: AtomicBool::new(false),
        },
    );
    set_kerberos_store(handle.store());
    handle.registered = true;
    handle
}

fn spawn_committer(pool: DbConnection, timings: Timings) -> KerberosCommitterHandle {
    let (tx, rx) = mpsc::channel(QUEUE);
    let (lost_tx, lost) = watch::channel(None);
    let task = tokio::spawn(run(rx, pool, lost_tx, timings));
    KerberosCommitterHandle {
        tx,
        task,
        lost,
        registered: false,
    }
}

struct Held {
    generation: i64,
    row: bool,
    last_ok: Instant,
    next: Instant,
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
    timings: Timings,
) {
    let mut phase = open_phase(&pool, &timings, &lost_tx).await;
    let mut waiting = Vec::new();
    loop {
        let wake = wake_at(&phase);
        let incoming = tokio::select! {
            biased;
            job = rx.recv() => match job {
                Some(job) => Incoming::Job(job),
                None => Incoming::Closed,
            },
            _ = sleep_until(wake), if wake.is_some() => Incoming::Timer,
        };
        match incoming {
            Incoming::Job(Job::Load(reply)) => {
                answer_load(&pool, &phase, reply, &mut waiting, &lost_tx, timings.step).await;
            }
            Incoming::Job(Job::Commit(host, batch, reply)) => {
                phase = commit_job(&pool, phase, &host, batch, reply, &lost_tx, &timings).await;
                release_loads(&pool, &phase, &mut waiting, &lost_tx, timings.step).await;
            }
            Incoming::Job(Job::Record(user, reply)) => {
                let _ = reply.send(read_record(&pool, &user, timings.step).await);
            }
            Incoming::Job(Job::Users(users, reply)) => {
                let _ = reply.send(read_users(&pool, &users, timings.step).await);
            }
            Incoming::Job(Job::Disabled(user, reply)) => {
                let _ = reply.send(read_disabled(&pool, &user, timings.step).await);
            }
            Incoming::Job(Job::Shutdown(reply)) => {
                clear_held(&pool, &phase, timings.step).await;
                cancel_loads(&mut waiting);
                let _ = reply.send(());
                break;
            }
            Incoming::Timer => {
                phase = on_wake(&pool, phase, &timings, &lost_tx).await;
                release_loads(&pool, &phase, &mut waiting, &lost_tx, timings.step).await;
            }
            Incoming::Closed => {
                clear_held(&pool, &phase, timings.step).await;
                cancel_loads(&mut waiting);
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
    match hold_within(pool, timings.step).await {
        Ok(None) => Phase::Held(fresh(0, false, timings)),
        Ok(Some(hold)) if !hold.open => match take_owned(pool, hold.generation, timings.step).await
        {
            Ok(generation) => Phase::Held(fresh(generation, true, timings)),
            Err(Step::Replaced) => lose(lost_tx, KerberosLost::Occupied),
            Err(Step::Database) => starting(timings),
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
    let now = Instant::now();
    Held {
        generation,
        row,
        last_ok: now,
        next: now + timings.heartbeat,
    }
}

fn wake_at(phase: &Phase) -> Option<tokio::time::Instant> {
    let at = match phase {
        Phase::Starting { next, .. } => *next,
        Phase::Watching { until, .. } => *until,
        Phase::Held(held) if held.row => held.next,
        Phase::Held(_) | Phase::Lost => return None,
    };
    Some(at.into())
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

async fn beat(pool: &DbConnection, generation: i64, step: Duration) -> Result<i64, Step> {
    within(step, || Step::Database, async {
        let txn = pool.begin().await.map_err(|_| Step::Database)?;
        match heartbeat(&txn, generation).await {
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

enum WriteError {
    Unreachable(String),
    /// COMMIT was sent, and its answer is an error or did not come within the step.
    Unanswered(String),
    Batch(KerberosSqlError),
    Host(KerberosStoreError),
}

// The kill points mark a password change's steps only; other changes pass them by.
fn point(password: bool, name: &str) {
    if password {
        kill_point(name);
    }
}

fn changes_a_password(host: &[HostRow]) -> bool {
    host.iter().any(HostRow::is_password)
}

async fn write_batch(
    pool: &DbConnection,
    host: &[HostRow],
    batch: &RealmBatch,
    generation: i64,
    sent: &AtomicBool,
) -> Result<(), WriteError> {
    let password = changes_a_password(host);
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
            HostRow::NoAliasOnto(users) => {
                if let Some(user) = first_user(txn, users).await? {
                    let refusal = format!("{DIRECTORY_TARGET}: {user}");
                    return Err(KerberosStoreError::Refused(refusal));
                }
            }
        }
    }
    Ok(())
}

async fn first_user(
    txn: &DatabaseTransaction,
    users: &[UserId],
) -> Result<Option<UserId>, KerberosStoreError> {
    let found = existing_users(txn, users).await.map_err(row_failed)?;
    Ok(users.iter().find(|user| found.contains(user)).cloned())
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
    now: chrono::NaiveDateTime,
) -> Result<(), KerberosStoreError> {
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

async fn read_record(
    pool: &DbConnection,
    user: &UserId,
    step: Duration,
) -> Result<Option<Vec<u8>>, KerberosStoreError> {
    within(step, || KerberosStoreError::Failed(late(step)), async {
        model::User::find_by_id(user.clone())
            .select_only()
            .column(UserColumn::PasswordHash)
            .into_tuple::<(Option<Vec<u8>>,)>()
            .one(pool)
            .await
            .map(|row| row.and_then(|(record,)| record))
            .map_err(|err| KerberosStoreError::Failed(err.to_string()))
    })
    .await
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

async fn commit_job(
    pool: &DbConnection,
    phase: Phase,
    host: &[HostRow],
    batch: RealmBatch,
    reply: oneshot::Sender<Result<(), KerberosStoreError>>,
    lost_tx: &watch::Sender<Option<KerberosLost>>,
    timings: &Timings,
) -> Phase {
    let password = changes_a_password(host);
    point(password, "callback-entered");
    let Phase::Held(held) = phase else {
        let _ = reply.send(Err(not_held()));
        return phase;
    };
    let step = timings.step;
    let sent = AtomicBool::new(false);
    let ran_out = || {
        if sent.load(Ordering::Acquire) {
            WriteError::Unanswered(late(step))
        } else {
            WriteError::Unreachable(late(step))
        }
    };
    let written = within(
        step,
        ran_out,
        write_batch(pool, host, &batch, held.generation, &sent),
    )
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
            Phase::Held(fresh(held.generation + 1, true, timings))
        }
        Err(WriteError::Unanswered(reason)) => {
            let (answer, phase) = read_back(pool, held, host, reason, lost_tx, timings).await;
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

/// A password commit whose answer was lost: the user's record says whether it committed.
async fn read_back(
    pool: &DbConnection,
    held: Held,
    host: &[HostRow],
    reason: String,
    lost_tx: &watch::Sender<Option<KerberosLost>>,
    timings: &Timings,
) -> (Result<(), KerberosStoreError>, Phase) {
    let written = host.iter().find_map(|row| match row {
        HostRow::SetPassword { user, record, .. } => Some((user, record)),
        _ => None,
    });
    let Some((user, record)) = written else {
        let phase = db_failed(held, timings, lost_tx);
        return (Err(KerberosStoreError::Failed(reason)), phase);
    };
    match read_record(pool, user, timings.step).await {
        Ok(Some(stored)) if stored == *record => {
            warn!("The commit for user {user}: {ANSWER_LOST}");
            (
                Ok(()),
                Phase::Held(fresh(held.generation + 1, true, timings)),
            )
        }
        Ok(_) => {
            let phase = db_failed(held, timings, lost_tx);
            (Err(KerberosStoreError::Failed(reason)), phase)
        }
        Err(err) => {
            let phase = db_failed(held, timings, lost_tx);
            let why = format!("{UNREAD_AFTER_COMMIT}: {reason}; {err}");
            (Err(KerberosStoreError::Failed(why)), phase)
        }
    }
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
    let lost_at = held.last_ok + timings.lost_after;
    Held {
        next: (Instant::now() + RETRY).min(lost_at),
        ..held
    }
}

async fn on_wake(
    pool: &DbConnection,
    phase: Phase,
    timings: &Timings,
    lost_tx: &watch::Sender<Option<KerberosLost>>,
) -> Phase {
    match phase {
        Phase::Starting { since, .. } => {
            if since.elapsed() >= timings.lost_after {
                return lose(lost_tx, KerberosLost::DatabaseUnreachable);
            }
            match hold_within(pool, timings.step).await {
                Ok(None) => Phase::Held(fresh(0, false, timings)),
                Ok(Some(hold)) if !hold.open => {
                    match take_owned(pool, hold.generation, timings.step).await {
                        Ok(generation) => Phase::Held(fresh(generation, true, timings)),
                        Err(Step::Replaced) => lose(lost_tx, KerberosLost::Occupied),
                        Err(Step::Database) => starting_from(since, timings),
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
                    Ok(next) => Phase::Held(fresh(next, true, timings)),
                    Err(Step::Replaced) => lose(lost_tx, KerberosLost::Occupied),
                    Err(Step::Database) => lose(lost_tx, KerberosLost::DatabaseUnreachable),
                }
            }
            Ok(_) => lose(lost_tx, KerberosLost::Occupied),
            Err(_) => lose(lost_tx, KerberosLost::DatabaseUnreachable),
        },
        Phase::Held(held) if held.row => {
            let silent = held.last_ok.elapsed();
            let overdue = silent >= timings.lost_after;
            match beat(pool, held.generation, timings.step).await {
                Ok(next) => {
                    if overdue {
                        warn!(
                            "Woke {} s after the last write to the Kerberos realm; the heartbeat still held it",
                            silent.as_secs()
                        );
                    }
                    Phase::Held(fresh(next, true, timings))
                }
                Err(Step::Replaced) => lose(lost_tx, KerberosLost::Replaced),
                Err(Step::Database) if overdue => lose(lost_tx, KerberosLost::DatabaseUnreachable),
                Err(Step::Database) => Phase::Held(retry(held, timings)),
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
    phase: &Phase,
    reply: oneshot::Sender<Result<LoadedRealm, KerberosStoreError>>,
    waiting: &mut Vec<oneshot::Sender<Result<LoadedRealm, KerberosStoreError>>>,
    lost_tx: &watch::Sender<Option<KerberosLost>>,
    step: Duration,
) {
    match phase {
        Phase::Held(_) => {
            let _ = reply.send(read_loaded(pool, step).await);
        }
        Phase::Lost => {
            let _ = reply.send(Err(lost_answer(lost_tx)));
        }
        Phase::Starting { .. } | Phase::Watching { .. } => waiting.push(reply),
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
mod tests {
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

    async fn insert_realm(pool: &DbConnection, generation: i64, open: bool) {
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
                modified_date: when,
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
            lose_an_answer: AtomicBool::new(false),
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
        let phase = commit_job(&pool, held, &[], batch(), reply, &lost_tx, &timings).await;
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
        let phase = commit_job(&pool, phase, &[], batch(), reply, &lost_tx, &timings).await;
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

    // X1: the directory's rows ride the batch's transaction; nothing is half written.
    fn password_rows(user: &str, record: &[u8]) -> Vec<HostRow> {
        use lldap_domain_handlers::logging::{LogKind, event};
        vec![
            HostRow::SetPassword {
                user: UserId::new(user),
                record: record.to_vec(),
                now: chrono::Utc::now().naive_utc(),
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

    const RECORD: &[u8] = b"opaque-record";

    #[derive(Debug, PartialEq)]
    struct After {
        alice_record: bool,
        carol: bool,
        logs: u64,
        principals: usize,
        generation: i64,
    }

    async fn after(db: &Db) -> After {
        use sea_orm::PaginatorTrait;
        let step = Duration::from_secs(1);
        let (realm, generation) = load_realm(&db.other).await.unwrap();
        After {
            alice_record: read_record(&db.other, &UserId::new("alice"), step)
                .await
                .unwrap()
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
                vec![HostRow::NoAliasOnto(vec![UserId::new("Alice")])],
                Before::Nothing,
                Err(DIRECTORY_TARGET),
                nothing(5),
            ),
            (
                "an alias onto a name no directory user holds",
                vec![HostRow::NoAliasOnto(vec![UserId::new("bob")])],
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
            commit_job(&db.pool, held, &host, batch(), reply, &lost_tx, &timings).await;
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
    async fn test_the_stored_record_is_read_within_one_step() {
        let db = db().await;
        insert_alice(&db.pool).await;
        let txn = db.pool.begin().await.unwrap();
        set_password_in(&txn, &UserId::new("alice"), b"stored", Default::default())
            .await
            .unwrap();
        txn.commit().await.unwrap();
        let step = Duration::from_millis(100);
        type Row = (
            &'static str,
            &'static str,
            bool,
            Result<Option<Vec<u8>>, &'static str>,
        );
        let rows: [Row; 3] = [
            (
                "a stored record",
                "alice",
                false,
                Ok(Some(b"stored".to_vec())),
            ),
            ("no such user", "nobody", false, Ok(None)),
            (
                "the connection is held",
                "alice",
                true,
                Err("did not answer within 100ms"),
            ),
        ];
        for (label, user, held, expected) in rows {
            let holding = if held {
                Some(db.pool.begin().await.unwrap())
            } else {
                None
            };
            let got = read_record(&db.pool, &UserId::new(user), step).await;
            if let Some(txn) = holding {
                txn.rollback().await.unwrap();
            }
            match (got, expected) {
                (Ok(record), Ok(want)) => assert!(record == want, "{label}"),
                (Err(e), Err(part)) => assert!(e.to_string().contains(part), "{label}: {e}"),
                (got, _) => panic!("{label}: {:?}", got.map(|r| r.map(|r| r.len()))),
            }
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

    #[derive(Clone, Copy, PartialEq)]
    enum Lost {
        Committed,
        NotCommitted,
        CommittedUnreadable,
    }

    // Q-E, in the committer: after a lost COMMIT answer, the user's record decides, once.
    #[tokio::test]
    #[serial]
    async fn test_a_lost_answer_is_settled_by_the_record_read_back() {
        use lldap_domain_handlers::logging::{LogKind, event};
        const LOST: &str = "the answer to COMMIT was lost";
        let mut kadmin = password_rows("alice", RECORD);
        kadmin[1] = HostRow::Log(event(
            LogKind::PasswordChange,
            Some("alice@EXAMPLE.COM"),
            true,
            Some("kadmin change_password by admin/admin@EXAMPLE.COM"),
        ));
        let committed = || After {
            alice_record: true,
            carol: false,
            logs: 1,
            principals: 1,
            generation: 6,
        };
        let untouched = || After {
            alice_record: false,
            carol: false,
            logs: 0,
            principals: 0,
            generation: 5,
        };
        type Row = (
            &'static str,
            Vec<HostRow>,
            Lost,
            &'static str,
            Option<i64>,
            After,
            (bool, Option<KerberosLost>),
        );
        let rows: Vec<Row> = vec![
            (
                "the record is the one written",
                password_rows("alice", RECORD),
                Lost::Committed,
                "ok",
                Some(6),
                committed(),
                (true, None),
            ),
            (
                "the record is another",
                password_rows("alice", RECORD),
                Lost::NotCommitted,
                "failed",
                Some(5),
                untouched(),
                (true, None),
            ),
            (
                "the record cannot be read",
                password_rows("alice", RECORD),
                Lost::CommittedUnreadable,
                "unknown",
                Some(5),
                committed(),
                (false, Some(KerberosLost::Replaced)),
            ),
            (
                "a kadmin cpw, the record the one written",
                kadmin,
                Lost::Committed,
                "ok",
                Some(6),
                committed(),
                (true, None),
            ),
        ];
        for (label, host, lost, answer, generation, expected, next) in rows {
            let db = db().await;
            insert_alice(&db.pool).await;
            insert_realm(&db.pool, 5, true).await;
            let timings = short_timings();
            let (lost_tx, cause) = watch::channel(None);
            if lost != Lost::NotCommitted {
                let wrote =
                    write_batch(&db.pool, &host, &batch(), 5, &AtomicBool::new(false)).await;
                assert!(matches!(wrote, Ok(())), "{label}");
            }
            let holding = match lost {
                Lost::CommittedUnreadable => Some(db.pool.begin().await.unwrap()),
                _ => None,
            };
            let held = fresh(5, true, &timings);
            let (got, phase) =
                read_back(&db.pool, held, &host, LOST.to_owned(), &lost_tx, &timings).await;
            if let Some(txn) = holding {
                txn.rollback().await.unwrap();
            }
            let got = match got {
                Ok(()) => "ok".to_owned(),
                Err(KerberosStoreError::Failed(why)) if why == LOST => "failed".to_owned(),
                Err(KerberosStoreError::Failed(why)) if why.starts_with(UNREAD_AFTER_COMMIT) => {
                    "unknown".to_owned()
                }
                Err(e) => e.to_string(),
            };
            let at = match &phase {
                Phase::Held(held) => Some(held.generation),
                _ => None,
            };
            let stored = after(&db).await;
            let (reply, answered) = oneshot::channel();
            commit_job(&db.pool, phase, &[], batch(), reply, &lost_tx, &timings).await;
            let then = (answered.await.unwrap().is_ok(), cause.borrow().clone());
            assert_eq!(
                (got.as_str(), at, stored, then),
                (answer, generation, expected, next),
                "{label}"
            );
        }
    }
}
