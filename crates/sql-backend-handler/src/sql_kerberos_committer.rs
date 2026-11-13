use crate::sql_kerberos_handler::{
    KerberosSqlError, RealmHold, clear_open, commit_batch_with_transaction, heartbeat, load_realm,
    read_hold, take_realm,
};
use crate::sql_tables::DbConnection;
use lldap_domain_handlers::kerberos::{
    KerberosStore, KerberosStoreError, LoadedRealm, NoopKerberosStore, RealmBatch,
    set_kerberos_store,
};
use sea_orm::TransactionTrait;
use std::future::Future;
use std::sync::Arc;
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
    Commit(RealmBatch, oneshot::Sender<Result<(), KerberosStoreError>>),
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
        let (tx, rx) = oneshot::channel();
        self.tx
            .blocking_send(Job::Commit(batch, tx))
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
}

pub fn start_kerberos_committer(pool: DbConnection) -> KerberosCommitterHandle {
    start_kerberos_committer_for(pool, HEARTBEAT, LOST_AFTER, WATCH, STEP)
}

/// A committer whose store is not the process's, for kerber-rust's conformance suite.
pub fn start_unregistered_committer(pool: DbConnection) -> KerberosCommitterHandle {
    spawn_committer(
        pool,
        Timings {
            heartbeat: HEARTBEAT,
            lost_after: LOST_AFTER,
            watch: WATCH,
            step: STEP,
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
            Incoming::Job(Job::Commit(batch, reply)) => {
                phase = commit_job(&pool, phase, batch, reply, &lost_tx, &timings).await;
                release_loads(&pool, &phase, &mut waiting, &lost_tx, timings.step).await;
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
    Batch(KerberosSqlError),
}

async fn write_batch(
    pool: &DbConnection,
    batch: &RealmBatch,
    generation: i64,
) -> Result<(), WriteError> {
    let txn = pool
        .begin()
        .await
        .map_err(|err| WriteError::Unreachable(err.to_string()))?;
    match commit_batch_with_transaction(&txn, batch, generation).await {
        Ok(()) => txn
            .commit()
            .await
            .map_err(|err| WriteError::Unreachable(err.to_string())),
        Err(err) => {
            let _ = txn.rollback().await;
            Err(WriteError::Batch(err))
        }
    }
}

async fn commit_job(
    pool: &DbConnection,
    phase: Phase,
    batch: RealmBatch,
    reply: oneshot::Sender<Result<(), KerberosStoreError>>,
    lost_tx: &watch::Sender<Option<KerberosLost>>,
    timings: &Timings,
) -> Phase {
    let Phase::Held(held) = phase else {
        let _ = reply.send(Err(not_held()));
        return phase;
    };
    let step = timings.step;
    let written = within(
        step,
        || WriteError::Unreachable(late(step)),
        write_batch(pool, &batch, held.generation),
    )
    .await;
    match written {
        Ok(()) => {
            let _ = reply.send(Ok(()));
            Phase::Held(fresh(held.generation + 1, true, timings))
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
        let phase = commit_job(&pool, held, batch(), reply, &lost_tx, &timings).await;
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
        let phase = commit_job(&pool, phase, batch(), reply, &lost_tx, &timings).await;
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
            heartbeat: HEARTBEAT,
            lost_after: LOST_AFTER,
            watch: WATCH,
            step: Duration::from_millis(500),
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
}
