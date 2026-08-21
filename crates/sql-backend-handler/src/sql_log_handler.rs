use crate::sql_backend_handler::SqlBackendHandler;
use crate::sql_tables::DbConnection;
use async_trait::async_trait;
use lldap_domain::types::UserId;
use lldap_domain_handlers::handler::LogBackendHandler;
use lldap_domain_handlers::logging::{
    LogActivity, LogBucket, LogCursor, LogDimension, LogEvent, LogFilter, LogKind, LogRecord,
    LogSink, NoopLogSink, Protocol, flush_suppressed_warnings, set_log_sink,
};
use lldap_domain_model::{
    error::Result as DomainResult,
    model::{self, Group, GroupColumn, LogsColumn, Membership, MembershipColumn},
};
use sea_orm::{
    ActiveValue, ColumnTrait, Condition, ConnectionTrait, DbBackend, DbErr, EntityTrait,
    FromQueryResult, Order, QueryFilter, QueryOrder, QuerySelect, QueryTrait, Select,
    sea_query::{Expr, SimpleExpr},
};
use std::collections::{HashMap, HashSet};
use std::hash::{DefaultHasher, Hash, Hasher};
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::warn;

const MAX_PAGE: u32 = 1000;
const QUEUE_CAPACITY: usize = 4096;
const BATCH_SIZE: usize = 256;
const DELETE_CHUNK: u64 = 1000;
const COALESCE_CAP: usize = 4096;
const LINGER: Duration = Duration::from_millis(250);
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);
// The writer wakes at least this often so an idle flood window can resolve itself and the
// warn limiter can flush without a fresh event driving the loop.
const WRITER_TICK: Duration = Duration::from_secs(5);
const FLOOD_PASS: u64 = 8;
// A flood window is one incident: it resolves after this much quiet, which also separates
// distinct bursts from the same source.
const FLOOD_IDLE_SECONDS: i64 = 20;
const FLOOD_ACTOR_CAP: usize = 64;

pub(crate) const UNKNOWN_USER_DETAIL: &str = "unknown user";

/// Both limits are off at 0.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LogRetention {
    pub retention_days: u32,
    pub max_entries: u64,
}

struct ChannelLogSink {
    tx: mpsc::Sender<LogEvent>,
    dropped: Arc<AtomicU64>,
}

impl LogSink for ChannelLogSink {
    fn record(&self, event: LogEvent) {
        if self.tx.try_send(event).is_err() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
}

pub struct LogWriterHandle {
    sink: Arc<ChannelLogSink>,
    task: JoinHandle<()>,
}

impl LogWriterHandle {
    pub async fn shutdown(self) {
        set_log_sink(Arc::new(NoopLogSink));
        drop(self.sink);
        match tokio::time::timeout(SHUTDOWN_TIMEOUT, self.task).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => warn!("The log writer stopped early: {e}"),
            Err(_) => warn!("The log writer did not flush in time"),
        }
    }
}

/// `bind_coalesce_seconds`: repeats of a successful bind by the same actor, protocol and
/// peer inside that window are not stored (0 stores every bind).
pub fn start_log_writer(
    pool: DbConnection,
    retention: LogRetention,
    bind_coalesce_seconds: u32,
) -> LogWriterHandle {
    let (sink, rx) = channel_sink(QUEUE_CAPACITY);
    let task = tokio::spawn(run_writer(
        rx,
        pool,
        sink.dropped.clone(),
        retention,
        WriterCoalescers {
            bind: BindCoalescer::new(bind_coalesce_seconds),
            bind_flood: FloodCoalescer::new(FloodClass::UnknownBind, FLOOD_IDLE_SECONDS),
            denied_flood: FloodCoalescer::new(FloodClass::AccessDenied, FLOOD_IDLE_SECONDS),
        },
        WRITER_TICK,
    ));
    set_log_sink(sink.clone());
    LogWriterHandle { sink, task }
}

fn channel_sink(capacity: usize) -> (Arc<ChannelLogSink>, mpsc::Receiver<LogEvent>) {
    let (tx, rx) = mpsc::channel(capacity);
    let sink = Arc::new(ChannelLogSink {
        tx,
        dropped: Arc::new(AtomicU64::new(0)),
    });
    (sink, rx)
}

// Owned by the writer task, so the request path never takes a lock. The first success of a
// window is stored, the repeats were already printed to the terminal.
struct BindCoalescer {
    window: chrono::Duration,
    last: HashMap<(String, Protocol, Option<String>), chrono::NaiveDateTime>,
}

impl BindCoalescer {
    fn new(seconds: u32) -> Self {
        Self {
            window: chrono::Duration::seconds(i64::from(seconds)),
            last: HashMap::new(),
        }
    }

    fn keep(&mut self, event: &LogEvent) -> bool {
        if self.window.is_zero() || event.kind != LogKind::Bind || !event.success {
            return true;
        }
        let key = (
            event.actor.clone().unwrap_or_default(),
            event.protocol,
            event.peer.clone(),
        );
        match self.last.get(&key) {
            Some(stored) if (event.timestamp - *stored).abs() < self.window => false,
            _ => {
                if self.last.len() >= COALESCE_CAP {
                    self.last.clear();
                }
                self.last.insert(key, event.timestamp);
                true
            }
        }
    }

    fn prune(&mut self, now: chrono::NaiveDateTime) {
        self.last.retain(|_, stored| now - *stored < self.window);
        if self.last.len() >= COALESCE_CAP {
            self.last.clear();
        }
    }

    #[cfg(test)]
    fn cached(&self) -> usize {
        self.last.len()
    }
}

struct FloodWindow {
    started: chrono::NaiveDateTime,
    last: chrono::NaiveDateTime,
    passed: u64,
    counted: u64,
    actors: HashSet<u64>,
    more_actors: bool,
}

impl FloodWindow {
    fn open(timestamp: chrono::NaiveDateTime) -> Self {
        Self {
            started: timestamp,
            last: timestamp,
            passed: 1,
            counted: 0,
            actors: HashSet::new(),
            more_actors: false,
        }
    }
}

// The two abuse floods the writer brackets: a unique-name bind spray and an access-denied
// flood (authenticated abuse or a junk-JWT spammer). Both coalesce the same way; the class
// only picks the noun and the row kind.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum FloodClass {
    UnknownBind,
    AccessDenied,
}

impl FloodClass {
    fn classify(event: &LogEvent) -> Option<Self> {
        match event.kind {
            LogKind::Bind
                if !event.success && event.detail.as_deref() == Some(UNKNOWN_USER_DETAIL) =>
            {
                Some(Self::UnknownBind)
            }
            LogKind::AccessDenied if !event.success => Some(Self::AccessDenied),
            _ => None,
        }
    }

    fn kind(self) -> LogKind {
        match self {
            Self::UnknownBind => LogKind::BindFlood,
            Self::AccessDenied => LogKind::AccessDeniedFlood,
        }
    }

    fn started_detail(self) -> &'static str {
        match self {
            Self::UnknownBind => "unknown-user bind flood started",
            Self::AccessDenied => "access-denied flood started",
        }
    }

    fn resolved_detail(self, window: &FloodWindow) -> String {
        let more = if window.more_actors { "+" } else { "" };
        let seconds = (window.last - window.started).num_seconds();
        let (noun, who) = match self {
            Self::UnknownBind => ("binds", "names"),
            Self::AccessDenied => ("denials", "actors"),
        };
        let label = match self {
            Self::UnknownBind => "unknown-user bind flood resolved",
            Self::AccessDenied => "access-denied flood resolved",
        };
        format!(
            "{label}: {} {noun}, {}{more} {who}, {seconds}s",
            window.counted,
            window.actors.len(),
        )
    }
}

// A flood must not push real history out of max_entries: failures beyond the first few per
// source are dropped and the incident is bracketed by a "started" row and a "resolved" row
// with the totals. One incident per source lives until it goes quiet for FLOOD_IDLE_SECONDS;
// events that do not belong to this class pass through untouched.
struct FloodCoalescer {
    class: FloodClass,
    idle: chrono::Duration,
    windows: HashMap<(Option<String>, Protocol), FloodWindow>,
    ready: Vec<LogEvent>,
}

impl FloodCoalescer {
    fn new(class: FloodClass, idle_seconds: i64) -> Self {
        Self {
            class,
            idle: chrono::Duration::seconds(idle_seconds),
            windows: HashMap::new(),
            ready: Vec::new(),
        }
    }

    fn keep(&mut self, event: &LogEvent) -> bool {
        if FloodClass::classify(event) != Some(self.class) {
            return true;
        }
        let key = (event.peer.clone(), event.protocol);
        let Some(entry) = self.windows.get_mut(&key) else {
            if self.windows.len() >= COALESCE_CAP {
                self.flush_into_ready(event.timestamp, true);
            }
            self.windows.insert(key, FloodWindow::open(event.timestamp));
            return true;
        };
        entry.last = event.timestamp;
        if entry.passed < FLOOD_PASS {
            entry.passed += 1;
            return true;
        }
        // The first dropped event opens the incident, visible to an admin at once.
        if entry.counted == 0 {
            let row = self.started_event(&key, event.timestamp);
            self.ready.push(row);
        }
        let entry = self.windows.get_mut(&key).expect("window just inserted");
        entry.counted += 1;
        if entry.actors.len() < FLOOD_ACTOR_CAP {
            let mut hasher = DefaultHasher::new();
            event.actor.hash(&mut hasher);
            entry.actors.insert(hasher.finish());
        } else {
            entry.more_actors = true;
        }
        false
    }

    fn flush(&mut self, now: chrono::NaiveDateTime, all: bool) -> Vec<LogEvent> {
        self.flush_into_ready(now, all);
        std::mem::take(&mut self.ready)
    }

    fn flush_into_ready(&mut self, now: chrono::NaiveDateTime, all: bool) {
        let ready = &mut self.ready;
        let idle = self.idle;
        let class = self.class;
        self.windows.retain(|key, entry| {
            if !all && now - entry.last < idle {
                return true;
            }
            if let Some(row) = resolved_event(class, key, entry) {
                ready.push(row);
            }
            false
        });
    }

    fn started_event(
        &self,
        key: &(Option<String>, Protocol),
        timestamp: chrono::NaiveDateTime,
    ) -> LogEvent {
        let event = LogEvent {
            timestamp,
            kind: self.class.kind(),
            success: false,
            protocol: key.1,
            actor: None,
            target: None,
            peer: key.0.clone(),
            forwarded_for: None,
            detail: Some(self.class.started_detail().to_owned()),
        };
        warn!(target: "logs", "{event}");
        event
    }
}

fn resolved_event(
    class: FloodClass,
    key: &(Option<String>, Protocol),
    window: &FloodWindow,
) -> Option<LogEvent> {
    if window.counted == 0 {
        return None;
    }
    let event = LogEvent {
        timestamp: window.last,
        kind: class.kind(),
        success: false,
        protocol: key.1,
        actor: None,
        target: None,
        peer: key.0.clone(),
        forwarded_for: None,
        detail: Some(class.resolved_detail(window)),
    };
    warn!(target: "logs", "{event}");
    Some(event)
}

// The writer owns its coalescers so the request path never locks.
struct WriterCoalescers {
    bind: BindCoalescer,
    bind_flood: FloodCoalescer,
    denied_flood: FloodCoalescer,
}

// One INSERT per batch: a trickle lingers a moment to fill a batch, a full queue drains
// back-to-back at insert speed. Dropped events surface as a log_gap row.
async fn run_writer(
    mut rx: mpsc::Receiver<LogEvent>,
    pool: DbConnection,
    dropped: Arc<AtomicU64>,
    retention: LogRetention,
    coalescers: WriterCoalescers,
    tick: Duration,
) {
    let WriterCoalescers {
        mut bind,
        mut bind_flood,
        mut denied_flood,
    } = coalescers;
    let mut buffer = Vec::with_capacity(BATCH_SIZE);
    let mut inserted_since_trim = 0u64;
    loop {
        // The tick lets an idle flood window resolve itself and the warn limiter flush even
        // when no new event is driving the loop.
        match tokio::time::timeout(tick, rx.recv_many(&mut buffer, BATCH_SIZE)).await {
            Ok(0) => break,
            Ok(_) => {
                if buffer.len() < BATCH_SIZE {
                    tokio::time::sleep(LINGER).await;
                    while buffer.len() < BATCH_SIZE {
                        match rx.try_recv() {
                            Ok(event) => buffer.push(event),
                            Err(_) => break,
                        }
                    }
                }
                buffer.retain(|event| {
                    bind.keep(event) && bind_flood.keep(event) && denied_flood.keep(event)
                });
            }
            Err(_) => {}
        }
        let now = chrono::Utc::now().naive_utc();
        bind.prune(now);
        flush_suppressed_warnings(now.and_utc().timestamp().max(0) as u64);
        let lost = dropped.swap(0, Ordering::Relaxed);
        let mut rows = Vec::with_capacity(buffer.len() + 1);
        if lost > 0 {
            rows.push(to_active_model(gap_event(lost)));
        }
        rows.extend(buffer.drain(..).map(to_active_model));
        rows.extend(
            bind_flood
                .flush(now, false)
                .into_iter()
                .map(to_active_model),
        );
        rows.extend(
            denied_flood
                .flush(now, false)
                .into_iter()
                .map(to_active_model),
        );
        let batch = rows.len() as u64;
        match insert_rows(&pool, rows).await {
            Ok(()) => inserted_since_trim += batch,
            Err(e) => {
                // A failed batch counts as dropped, so the next gap row still accounts for it.
                dropped.fetch_add(batch, Ordering::Relaxed);
                warn!("Could not persist {batch} log events: {e}");
            }
        }
        if retention.max_entries > 0 && inserted_since_trim >= trim_interval(retention.max_entries)
        {
            inserted_since_trim = 0;
            if let Err(e) = trim_to_max_entries(&pool, retention.max_entries).await {
                warn!("Could not trim the logs table: {e}");
            }
        }
    }
    // The channel is closed: pending flood windows become rows, never lost.
    let now = chrono::Utc::now().naive_utc();
    let mut rows = bind_flood.flush(now, true);
    rows.extend(denied_flood.flush(now, true));
    let rows = rows.into_iter().map(to_active_model).collect::<Vec<_>>();
    if let Err(e) = insert_rows(&pool, rows).await {
        warn!("Could not persist the final log events: {e}");
    }
}

fn trim_interval(max_entries: u64) -> u64 {
    (max_entries / 10).max(1000)
}

fn gap_event(lost: u64) -> LogEvent {
    warn!(target: "logs", "❌ log_gap (system): dropped events: {lost}");
    LogEvent {
        timestamp: chrono::Utc::now().naive_utc(),
        kind: LogKind::LogGap,
        success: false,
        protocol: Protocol::System,
        actor: None,
        target: None,
        peer: None,
        forwarded_for: None,
        detail: Some(format!("dropped events: {lost}")),
    }
}

#[async_trait]
impl LogBackendHandler for SqlBackendHandler {
    async fn list_log_events(
        &self,
        filter: LogFilter,
        limit: u32,
        cursor: LogCursor,
    ) -> DomainResult<Vec<LogRecord>> {
        let query = model::Logs::find().filter(filter_condition(&filter));
        let query = match cursor {
            LogCursor::Newest => query.order_by_desc(LogsColumn::Id),
            LogCursor::Before(id) => query
                .filter(LogsColumn::Id.lt(id))
                .order_by_desc(LogsColumn::Id),
            LogCursor::After(id) => query
                .filter(LogsColumn::Id.gt(id))
                .order_by_asc(LogsColumn::Id),
        };
        let rows = query
            .limit(u64::from(limit.min(MAX_PAGE)))
            .all(&self.read_pool)
            .await?;
        Ok(rows.into_iter().filter_map(from_model).collect())
    }

    async fn summarize_log_events(
        &self,
        filter: LogFilter,
        group_by: Vec<LogDimension>,
        limit: u32,
    ) -> DomainResult<Vec<LogBucket>> {
        let backend = self.read_pool.get_database_backend();
        let mut query = model::Logs::find()
            .select_only()
            .filter(filter_condition(&filter));
        let mut dimensions: Vec<LogDimension> = Vec::new();
        for dimension in group_by {
            if dimensions.contains(&dimension) {
                continue;
            }
            dimensions.push(dimension);
            let alias = dimension.to_string();
            query = match dimension_column(dimension) {
                Some(column) => query.column_as(column, alias).group_by(column),
                None => {
                    let period = period_expr(backend, dimension);
                    query.expr_as(period.clone(), alias).group_by(period)
                }
            };
        }
        let rows = query
            .column_as(LogsColumn::Id.count(), "count")
            .column_as(LogsColumn::Timestamp.min(), "first")
            .column_as(LogsColumn::Timestamp.max(), "last")
            .order_by(LogsColumn::Id.count(), Order::Desc)
            .order_by(LogsColumn::Timestamp.max(), Order::Desc)
            .limit(u64::from(limit.min(MAX_PAGE)))
            .into_model::<BucketRow>()
            .all(&self.read_pool)
            .await?;
        Ok(rows.into_iter().filter_map(bucket_from_row).collect())
    }

    async fn log_activity(
        &self,
        actor: &UserId,
        kinds: Vec<LogKind>,
        since: Option<chrono::NaiveDateTime>,
    ) -> DomainResult<LogActivity> {
        let scope = LogFilter {
            actor: Some(actor.clone()),
            kinds,
            since,
            ..Default::default()
        };
        let last_success = last_event(&scope, true)
            .one(&self.read_pool)
            .await?
            .and_then(from_model);
        let last_failure = last_event(&scope, false)
            .one(&self.read_pool)
            .await?
            .and_then(from_model);
        let (failures,) = failures_after(&scope, last_success.as_ref().map(|r| r.event.timestamp))
            .into_tuple::<(i64,)>()
            .one(&self.read_pool)
            .await?
            .unwrap_or((0,));
        Ok(LogActivity {
            actor: actor.clone(),
            last_success,
            last_failure,
            failures_since_last_success: u64::try_from(failures).unwrap_or(0),
        })
    }
}

fn filter_condition(filter: &LogFilter) -> Condition {
    let kinds = (!filter.kinds.is_empty())
        .then(|| LogsColumn::Kind.is_in(filter.kinds.iter().map(ToString::to_string)));
    let member_of = filter.member_of.as_deref().map(|name| {
        MembershipColumn::GroupId.in_subquery(
            Group::find()
                .select_only()
                .column(GroupColumn::GroupId)
                .filter(GroupColumn::LowercaseDisplayName.eq(name.to_lowercase()))
                .into_query(),
        )
    });
    let member_of_id = filter
        .member_of_id
        .map(|group_id| MembershipColumn::GroupId.eq(group_id));
    Condition::all()
        .add_option(
            filter
                .actor
                .as_ref()
                .map(|actor| LogsColumn::Actor.eq(actor)),
        )
        .add_option(filter.target.as_deref().map(|t| LogsColumn::Target.eq(t)))
        .add_option(kinds)
        .add_option(filter.success.map(|s| LogsColumn::Success.eq(s)))
        .add_option(
            filter
                .protocol
                .map(|p| LogsColumn::Protocol.eq(p.to_string())),
        )
        .add_option(filter.peer.as_deref().map(|p| LogsColumn::Peer.eq(p)))
        .add_option(filter.since.map(|t| LogsColumn::Timestamp.gte(t)))
        .add_option(filter.until.map(|t| LogsColumn::Timestamp.lte(t)))
        .add_option(member_of.map(members))
        .add_option(member_of_id.map(members))
}

fn members(group: SimpleExpr) -> SimpleExpr {
    LogsColumn::Actor.in_subquery(
        Membership::find()
            .select_only()
            .column(MembershipColumn::UserId)
            .filter(group)
            .into_query(),
    )
}

fn dimension_column(dimension: LogDimension) -> Option<LogsColumn> {
    match dimension {
        LogDimension::Actor => Some(LogsColumn::Actor),
        LogDimension::Target => Some(LogsColumn::Target),
        LogDimension::Kind => Some(LogsColumn::Kind),
        LogDimension::Protocol => Some(LogsColumn::Protocol),
        LogDimension::Peer => Some(LogsColumn::Peer),
        LogDimension::Success => Some(LogsColumn::Success),
        LogDimension::Day | LogDimension::Hour => None,
    }
}

// Text on every backend (day `YYYY-MM-DD`, hour `HH`); the placeholder is the builder's.
fn period_expr(backend: DbBackend, dimension: LogDimension) -> SimpleExpr {
    let day = dimension == LogDimension::Day;
    let template = match (backend, day) {
        (DbBackend::Sqlite, true) => "strftime('%Y-%m-%d', ?)",
        (DbBackend::Sqlite, false) => "strftime('%H', ?)",
        (DbBackend::Postgres, true) => "to_char($1, 'YYYY-MM-DD')",
        (DbBackend::Postgres, false) => "to_char($1, 'HH24')",
        (DbBackend::MySql, true) => "DATE_FORMAT(?, '%Y-%m-%d')",
        (DbBackend::MySql, false) => "DATE_FORMAT(?, '%H')",
    };
    Expr::cust_with_expr(template, Expr::col(LogsColumn::Timestamp.as_column_ref()))
}

#[derive(FromQueryResult)]
struct BucketRow {
    actor: Option<String>,
    target: Option<String>,
    kind: Option<String>,
    protocol: Option<String>,
    peer: Option<String>,
    success: Option<bool>,
    day: Option<String>,
    hour: Option<String>,
    count: i64,
    first: Option<chrono::NaiveDateTime>,
    last: Option<chrono::NaiveDateTime>,
}

fn bucket_from_row(row: BucketRow) -> Option<LogBucket> {
    // No match still yields one row of NULL aggregates.
    let (Some(first), Some(last)) = (row.first, row.last) else {
        return None;
    };
    let kind = match row.kind.as_deref().map(LogKind::from_str) {
        Some(Ok(kind)) => Some(kind),
        Some(Err(_)) => {
            warn!("Skipping log bucket with unknown kind {:?}", row.kind);
            return None;
        }
        None => None,
    };
    let protocol = match row.protocol.as_deref().map(Protocol::from_str) {
        Some(Ok(protocol)) => Some(protocol),
        Some(Err(_)) => {
            warn!(
                "Skipping log bucket with unknown protocol {:?}",
                row.protocol
            );
            return None;
        }
        None => None,
    };
    Some(LogBucket {
        actor: row.actor,
        target: row.target,
        kind,
        protocol,
        peer: row.peer,
        success: row.success,
        day: row.day,
        hour: row.hour.and_then(|h| h.parse().ok()),
        count: u64::try_from(row.count).unwrap_or(0),
        first,
        last,
    })
}

// Both ride the (actor, timestamp) index: newest by timestamp, failures after a timestamp.
fn last_event(scope: &LogFilter, success: bool) -> Select<model::Logs> {
    model::Logs::find()
        .filter(filter_condition(scope))
        .filter(LogsColumn::Success.eq(success))
        .order_by_desc(LogsColumn::Timestamp)
        .order_by_desc(LogsColumn::Id)
}

fn failures_after(scope: &LogFilter, after: Option<chrono::NaiveDateTime>) -> Select<model::Logs> {
    let query = model::Logs::find()
        .select_only()
        .column_as(LogsColumn::Id.count(), "count")
        .filter(filter_condition(scope))
        .filter(LogsColumn::Success.eq(false));
    match after {
        Some(after) => query.filter(LogsColumn::Timestamp.gt(after)),
        None => query,
    }
}

// Kinds are append-only, so only a downgraded binary can meet one it does not know.
fn from_model(row: model::logs::Model) -> Option<LogRecord> {
    let (Ok(kind), Ok(protocol)) = (
        LogKind::from_str(&row.kind),
        Protocol::from_str(&row.protocol),
    ) else {
        warn!(
            "Skipping log row {} with unknown kind/protocol {:?}/{:?}",
            row.id, row.kind, row.protocol
        );
        return None;
    };
    Some(LogRecord {
        id: row.id,
        event: LogEvent {
            timestamp: row.timestamp,
            kind,
            success: row.success,
            protocol,
            actor: row.actor,
            target: row.target,
            peer: row.peer,
            forwarded_for: row.forwarded_for,
            detail: row.detail,
        },
    })
}

fn to_active_model(event: LogEvent) -> model::logs::ActiveModel {
    model::logs::ActiveModel {
        id: ActiveValue::NotSet,
        timestamp: ActiveValue::Set(event.timestamp),
        kind: ActiveValue::Set(event.kind.to_string()),
        success: ActiveValue::Set(event.success),
        protocol: ActiveValue::Set(event.protocol.to_string()),
        actor: ActiveValue::Set(event.actor),
        target: ActiveValue::Set(event.target),
        peer: ActiveValue::Set(event.peer),
        forwarded_for: ActiveValue::Set(event.forwarded_for),
        detail: ActiveValue::Set(event.detail),
    }
}

// 10 columns × 256 rows per statement stays far below the bundled SQLite bind limit (32766).
async fn insert_rows(
    pool: &DbConnection,
    rows: Vec<model::logs::ActiveModel>,
) -> Result<(), DbErr> {
    let mut rows = rows.into_iter().peekable();
    while rows.peek().is_some() {
        model::Logs::insert_many(rows.by_ref().take(BATCH_SIZE).collect::<Vec<_>>())
            .exec_without_returning(pool)
            .await?;
    }
    Ok(())
}

pub async fn enforce_log_retention(
    pool: &DbConnection,
    retention: LogRetention,
) -> Result<(), DbErr> {
    if retention.retention_days > 0 {
        let cutoff = chrono::Utc::now().naive_utc()
            - chrono::Duration::days(i64::from(retention.retention_days));
        delete_oldest_chunks(pool, OldestMatch::TimestampBefore(cutoff)).await?;
    }
    if retention.max_entries > 0 {
        trim_to_max_entries(pool, retention.max_entries).await?;
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum OldestMatch {
    IdAtMost(i64),
    TimestampBefore(chrono::NaiveDateTime),
}

// MySQL forbids a DELETE that subqueries its own table; each chunk is a SELECT of
// ids then a DELETE, and `.await` returns the one SQLite connection in between.
async fn delete_oldest_chunks(pool: &DbConnection, bound: OldestMatch) -> Result<(), DbErr> {
    loop {
        let mut pick = model::Logs::find().select_only().column(LogsColumn::Id);
        pick = match bound {
            OldestMatch::IdAtMost(id) => pick.filter(LogsColumn::Id.lte(id)),
            OldestMatch::TimestampBefore(ts) => pick.filter(LogsColumn::Timestamp.lt(ts)),
        };
        let chunk = pick
            .order_by_asc(LogsColumn::Id)
            .limit(DELETE_CHUNK)
            .into_tuple::<(i64,)>()
            .all(pool)
            .await?;
        let Some((last_id,)) = chunk.last() else {
            break;
        };
        let mut delete = model::Logs::delete_many().filter(LogsColumn::Id.lte(*last_id));
        delete = match bound {
            OldestMatch::IdAtMost(id) => delete.filter(LogsColumn::Id.lte(id)),
            OldestMatch::TimestampBefore(ts) => delete.filter(LogsColumn::Timestamp.lt(ts)),
        };
        delete.exec(pool).await?;
        if (chunk.len() as u64) < DELETE_CHUNK {
            break;
        }
    }
    Ok(())
}

async fn trim_to_max_entries(pool: &DbConnection, max_entries: u64) -> Result<(), DbErr> {
    let cutoff = model::Logs::find()
        .select_only()
        .column(LogsColumn::Id)
        .order_by_desc(LogsColumn::Id)
        .offset(max_entries)
        .limit(1)
        .into_tuple::<(i64,)>()
        .one(pool)
        .await?;
    if let Some((id,)) = cutoff {
        delete_oldest_chunks(pool, OldestMatch::IdAtMost(id)).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sql_backend_handler::tests::get_initialized_db;
    use pretty_assertions::assert_eq;

    fn event(kind: LogKind, actor: &str, days_ago: i64) -> LogEvent {
        LogEvent {
            timestamp: chrono::Utc::now().naive_utc() - chrono::Duration::days(days_ago),
            kind,
            success: true,
            protocol: Protocol::Ldap,
            actor: Some(actor.to_owned()),
            target: None,
            peer: Some("127.0.0.1".to_owned()),
            forwarded_for: None,
            detail: None,
        }
    }

    fn at(day: u32, hour: u32, minute: u32) -> chrono::NaiveDateTime {
        chrono::NaiveDate::from_ymd_opt(2024, 5, day)
            .unwrap()
            .and_hms_nano_opt(hour, minute, 40, 123_456_789)
            .unwrap()
    }

    fn event_at(kind: LogKind, actor: &str, timestamp: chrono::NaiveDateTime) -> LogEvent {
        LogEvent {
            timestamp,
            ..event(kind, actor, 0)
        }
    }

    async fn rows(pool: &DbConnection) -> Vec<model::logs::Model> {
        model::Logs::find()
            .order_by_asc(LogsColumn::Id)
            .all(pool)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn test_writer_persists_batches_and_records_a_gap_row() {
        let pool = get_initialized_db().await;
        let (sink, rx) = channel_sink(16);
        let task = tokio::spawn(run_writer(
            rx,
            pool.clone(),
            sink.dropped.clone(),
            LogRetention::default(),
            WriterCoalescers {
                bind: BindCoalescer::new(0),
                bind_flood: FloodCoalescer::new(FloodClass::UnknownBind, FLOOD_IDLE_SECONDS),
                denied_flood: FloodCoalescer::new(FloodClass::AccessDenied, FLOOD_IDLE_SECONDS),
            },
            WRITER_TICK,
        ));
        for name in ["bob", "carol", "dave"] {
            sink.record(event(LogKind::Bind, name, 0));
        }
        drop(sink);
        task.await.unwrap();

        let stored = rows(&pool).await;
        assert_eq!(stored.len(), 3);
        assert_eq!(stored[0].kind, "bind");
        assert_eq!(stored[0].protocol, "ldap");
        assert_eq!(stored[0].actor.as_deref(), Some("bob"));
        assert_eq!(stored[0].peer.as_deref(), Some("127.0.0.1"));
        assert!(stored[0].success);
        assert_eq!(stored[2].actor.as_deref(), Some("dave"));

        let pool = get_initialized_db().await;
        let (sink, rx) = channel_sink(1);
        sink.record(event(LogKind::Login, "bob", 0));
        sink.record(event(LogKind::Login, "carol", 0));
        sink.record(event(LogKind::Login, "dave", 0));
        assert_eq!(sink.dropped.load(Ordering::Relaxed), 2);
        let task = tokio::spawn(run_writer(
            rx,
            pool.clone(),
            sink.dropped.clone(),
            LogRetention::default(),
            WriterCoalescers {
                bind: BindCoalescer::new(0),
                bind_flood: FloodCoalescer::new(FloodClass::UnknownBind, FLOOD_IDLE_SECONDS),
                denied_flood: FloodCoalescer::new(FloodClass::AccessDenied, FLOOD_IDLE_SECONDS),
            },
            WRITER_TICK,
        ));
        drop(sink);
        task.await.unwrap();

        let stored = rows(&pool).await;
        assert_eq!(stored.len(), 2);
        assert_eq!(stored[0].kind, "log_gap");
        assert!(!stored[0].success);
        assert_eq!(stored[0].protocol, "system");
        assert_eq!(stored[0].detail.as_deref(), Some("dropped events: 2"));
        assert_eq!(stored[1].actor.as_deref(), Some("bob"));
    }

    #[tokio::test]
    async fn test_writer_drains_a_full_queue_without_lingering() {
        let pool = get_initialized_db().await;
        let (sink, rx) = channel_sink(QUEUE_CAPACITY);
        for i in 0..QUEUE_CAPACITY {
            sink.record(event(LogKind::Bind, &format!("user{i}"), 0));
        }
        assert_eq!(sink.dropped.load(Ordering::Relaxed), 0);
        let start = std::time::Instant::now();
        let dropped = sink.dropped.clone();
        let task = tokio::spawn(run_writer(
            rx,
            pool.clone(),
            dropped.clone(),
            LogRetention::default(),
            WriterCoalescers {
                bind: BindCoalescer::new(0),
                bind_flood: FloodCoalescer::new(FloodClass::UnknownBind, FLOOD_IDLE_SECONDS),
                denied_flood: FloodCoalescer::new(FloodClass::AccessDenied, FLOOD_IDLE_SECONDS),
            },
            WRITER_TICK,
        ));
        drop(sink);
        task.await.unwrap();

        assert_eq!(rows(&pool).await.len(), QUEUE_CAPACITY);
        assert_eq!(dropped.load(Ordering::Relaxed), 0);
        // Lingering per batch would sleep 16 × LINGER regardless of load; the bound sits
        // under that floor with room for a saturated test host (16 parallel inserts).
        assert!(start.elapsed() < LINGER * 15, "{:?}", start.elapsed());
    }

    #[tokio::test]
    async fn test_enforce_log_retention_by_age_then_size_keeps_the_newest() {
        let pool = get_initialized_db().await;
        insert_rows(&pool, vec![]).await.unwrap();
        assert!(rows(&pool).await.is_empty());
        let mut events = vec![event(LogKind::UserCreate, "old", 40)];
        events.extend((0..5).map(|i| event(LogKind::UserCreate, &format!("new{i}"), 0)));
        insert_rows(&pool, events.into_iter().map(to_active_model).collect())
            .await
            .unwrap();
        assert_eq!(rows(&pool).await.len(), 6);

        enforce_log_retention(
            &pool,
            LogRetention {
                retention_days: 30,
                max_entries: 0,
            },
        )
        .await
        .unwrap();
        let after_age = rows(&pool).await;
        assert_eq!(after_age.len(), 5);
        assert!(after_age.iter().all(|r| r.actor.as_deref() != Some("old")));

        enforce_log_retention(
            &pool,
            LogRetention {
                retention_days: 0,
                max_entries: 3,
            },
        )
        .await
        .unwrap();
        let after_size = rows(&pool).await;
        assert_eq!(
            after_size
                .iter()
                .map(|r| r.actor.clone().unwrap())
                .collect::<Vec<_>>(),
            vec!["new2", "new3", "new4"]
        );

        enforce_log_retention(&pool, LogRetention::default())
            .await
            .unwrap();
        assert_eq!(rows(&pool).await.len(), 3, "0 disables both limits");

        let extras: Vec<_> = (0..(DELETE_CHUNK as usize + 80))
            .map(|i| event(LogKind::UserCreate, &format!("bulk{i}"), 0))
            .collect();
        insert_rows(&pool, extras.into_iter().map(to_active_model).collect())
            .await
            .unwrap();
        enforce_log_retention(
            &pool,
            LogRetention {
                retention_days: 0,
                max_entries: 20,
            },
        )
        .await
        .unwrap();
        let after_chunks = rows(&pool).await;
        assert_eq!(after_chunks.len(), 20);
        assert_eq!(
            after_chunks.last().unwrap().actor.as_deref(),
            Some("bulk1079")
        );
    }

    #[tokio::test]
    async fn test_list_log_events_filters_cursors_and_membership() {
        use crate::sql_backend_handler::tests::{
            insert_group, insert_membership, insert_user_no_password,
        };
        use lldap_auth::opaque::server::generate_random_private_key;

        let pool = get_initialized_db().await;
        let handler = SqlBackendHandler::new(generate_random_private_key(), pool.clone());
        insert_user_no_password(&handler, "bob").await;
        insert_user_no_password(&handler, "carol").await;
        let devs = insert_group(&handler, "Devs").await;
        insert_membership(&handler, devs, "bob").await;
        let mut events = vec![
            event(LogKind::Bind, "bob", 3),
            event(LogKind::Login, "carol", 2),
            event(LogKind::UserCreate, "admin", 1),
            event(LogKind::Bind, "bob", 0),
        ];
        events[1].success = false;
        events[2].protocol = Protocol::Graphql;
        events[2].target = Some("dave".to_owned());
        insert_rows(&pool, events.into_iter().map(to_active_model).collect())
            .await
            .unwrap();
        model::Logs::insert(model::logs::ActiveModel {
            timestamp: ActiveValue::Set(chrono::Utc::now().naive_utc()),
            kind: ActiveValue::Set("computer_create".to_owned()),
            success: ActiveValue::Set(true),
            protocol: ActiveValue::Set("graphql".to_owned()),
            ..Default::default()
        })
        .exec(&pool)
        .await
        .unwrap();
        let list = |filter: LogFilter, limit: u32, cursor: LogCursor| {
            let handler = &handler;
            async move {
                handler
                    .list_log_events(filter, limit, cursor)
                    .await
                    .unwrap()
            }
        };
        let ids = |records: &[LogRecord]| records.iter().map(|r| r.id).collect::<Vec<_>>();
        let actor = |name: &str| LogFilter {
            actor: Some(UserId::new(name)),
            ..Default::default()
        };

        assert_eq!(
            ids(&list(LogFilter::default(), 100, LogCursor::Newest).await),
            vec![4, 3, 2, 1],
            "newest first, the unknown kind skipped"
        );
        assert_eq!(
            ids(&list(
                LogFilter {
                    kinds: vec![LogKind::Bind],
                    ..actor("bob")
                },
                100,
                LogCursor::Newest,
            )
            .await),
            vec![4, 1]
        );
        assert_eq!(
            ids(&list(actor("BOB"), 100, LogCursor::Newest).await),
            vec![4, 1],
            "actors are lowercased user ids"
        );
        assert_eq!(
            ids(&list(actor("bob"), 100, LogCursor::Before(4)).await),
            vec![1]
        );
        let failed = list(
            LogFilter {
                success: Some(false),
                ..Default::default()
            },
            100,
            LogCursor::Newest,
        )
        .await;
        assert_eq!(failed.len(), 1);
        assert_eq!(failed[0].event.actor.as_deref(), Some("carol"));
        assert_eq!(
            ids(&list(
                LogFilter {
                    protocol: Some(Protocol::Graphql),
                    target: Some("dave".to_owned()),
                    ..Default::default()
                },
                100,
                LogCursor::Newest,
            )
            .await),
            vec![3]
        );
        let now = chrono::Utc::now().naive_utc();
        assert_eq!(
            ids(&list(
                LogFilter {
                    since: Some(now - chrono::Duration::hours(36)),
                    until: Some(now),
                    ..Default::default()
                },
                100,
                LogCursor::Newest,
            )
            .await),
            vec![4, 3]
        );

        // The unknown row is skipped after the limit, so a page can come back short.
        let newest = list(LogFilter::default(), 2, LogCursor::Newest).await;
        assert_eq!(newest.len(), 1);
        assert_eq!(newest[0].id, 4);
        assert_eq!(newest[0].event.actor.as_deref(), Some("bob"));
        assert_eq!(newest[0].event.peer.as_deref(), Some("127.0.0.1"));

        let auth = LogFilter {
            kinds: vec![LogKind::Bind, LogKind::Login],
            ..Default::default()
        };
        assert_eq!(
            ids(&list(auth.clone(), 2, LogCursor::Newest).await),
            vec![4, 2]
        );
        assert_eq!(ids(&list(auth, 2, LogCursor::Before(2)).await), vec![1]);
        assert_eq!(
            ids(&list(LogFilter::default(), 2, LogCursor::After(1)).await),
            vec![2, 3]
        );
        assert_eq!(
            ids(&list(LogFilter::default(), 2, LogCursor::After(3)).await),
            vec![4]
        );
        assert_eq!(
            ids(&list(
                LogFilter {
                    member_of: Some("DEVS".to_owned()),
                    ..Default::default()
                },
                2,
                LogCursor::Newest,
            )
            .await),
            vec![4, 1]
        );
        assert_eq!(
            ids(&list(
                LogFilter {
                    member_of_id: Some(devs),
                    kinds: vec![LogKind::Login],
                    ..Default::default()
                },
                2,
                LogCursor::Newest,
            )
            .await),
            Vec::<i64>::new()
        );
        assert_eq!(
            ids(&list(
                LogFilter {
                    member_of: Some("nobody".to_owned()),
                    ..Default::default()
                },
                2,
                LogCursor::Newest,
            )
            .await),
            Vec::<i64>::new()
        );
    }

    fn unknown_bind(actor: &str, peer: &str, timestamp: chrono::NaiveDateTime) -> LogEvent {
        LogEvent {
            success: false,
            detail: Some(UNKNOWN_USER_DETAIL.to_owned()),
            peer: Some(peer.to_owned()),
            ..event_at(LogKind::Bind, actor, timestamp)
        }
    }

    fn started_rows(rows: &[LogEvent]) -> usize {
        rows.iter()
            .filter(|r| r.detail.as_deref() == Some("unknown-user bind flood started"))
            .count()
    }

    fn resolved_rows(rows: &[LogEvent]) -> Vec<&LogEvent> {
        rows.iter()
            .filter(|r| {
                r.detail
                    .as_deref()
                    .is_some_and(|d| d.starts_with("unknown-user bind flood resolved:"))
            })
            .collect()
    }

    #[test]
    fn test_bind_flood_lifecycle() {
        let mut flood = FloodCoalescer::new(FloodClass::UnknownBind, FLOOD_IDLE_SECONDS);
        let base = at(1, 9, 0);
        for i in 0..12 {
            let kept = flood.keep(&unknown_bind(
                &format!("spray-{i}"),
                "10.0.0.1",
                base + chrono::Duration::seconds(i),
            ));
            assert_eq!(kept, i < 8, "event {i}");
        }
        // The started row is queued the moment the source crosses the threshold.
        let opened = flood.flush(base + chrono::Duration::seconds(15), false);
        assert_eq!(opened.len(), 1);
        assert_eq!(opened[0].kind, LogKind::BindFlood);
        assert!(!opened[0].success);
        assert_eq!(opened[0].actor, None);
        assert_eq!(opened[0].peer.as_deref(), Some("10.0.0.1"));
        assert_eq!(opened[0].protocol, Protocol::Ldap);
        assert_eq!(
            opened[0].detail.as_deref(),
            Some("unknown-user bind flood started")
        );

        // The window is still active (last event at +11s), so nothing resolves yet.
        assert!(
            flood
                .flush(base + chrono::Duration::seconds(20), false)
                .is_empty()
        );

        // Quiet past the idle threshold resolves it with no closing event: one row with
        // the totals and the span, stamped with the last event.
        let closed = flood.flush(base + chrono::Duration::seconds(40), false);
        assert_eq!(closed.len(), 1);
        assert_eq!(closed[0].peer.as_deref(), Some("10.0.0.1"));
        assert_eq!(
            closed[0].detail.as_deref(),
            Some("unknown-user bind flood resolved: 4 binds, 4 names, 11s")
        );
        assert_eq!(closed[0].timestamp, base + chrono::Duration::seconds(11));
        assert!(
            flood
                .flush(base + chrono::Duration::seconds(50), false)
                .is_empty()
        );

        // A later burst from the same source is a new incident, not a continuation.
        let second = base + chrono::Duration::seconds(60);
        for i in 0..10 {
            flood.keep(&unknown_bind(&format!("b{i}"), "10.0.0.1", second));
        }
        let closed = flood.flush(second + chrono::Duration::seconds(30), false);
        assert_eq!(started_rows(&closed), 1);
        assert_eq!(
            resolved_rows(&closed)
                .iter()
                .map(|r| r.detail.as_deref().unwrap())
                .collect::<Vec<_>>(),
            vec!["unknown-user bind flood resolved: 2 binds, 2 names, 0s"]
        );

        // Exactly FLOOD_PASS failures from a source pass 1:1 and open nothing.
        let third = second + chrono::Duration::seconds(60);
        for i in 0..FLOOD_PASS {
            assert!(flood.keep(&unknown_bind(&format!("c{i}"), "10.0.0.3", third)));
        }
        assert!(
            flood
                .flush(third + chrono::Duration::seconds(999), true)
                .is_empty()
        );
    }

    #[test]
    fn test_bind_flood_scope_is_unknown_user_bind_failures_only() {
        let mut flood = FloodCoalescer::new(FloodClass::UnknownBind, FLOOD_IDLE_SECONDS);
        let base = at(1, 9, 0);
        for _ in 0..20 {
            let wrong_password = LogEvent {
                detail: Some("invalid credentials".to_owned()),
                ..unknown_bind("bob", "10.0.0.1", base)
            };
            assert!(flood.keep(&wrong_password));
            let success = LogEvent {
                success: true,
                detail: None,
                ..unknown_bind("bob", "10.0.0.1", base)
            };
            assert!(flood.keep(&success));
            let login = LogEvent {
                kind: LogKind::Login,
                ..unknown_bind("ghost", "10.0.0.1", base)
            };
            assert!(flood.keep(&login));
            let no_detail = LogEvent {
                detail: None,
                ..unknown_bind("ghost", "10.0.0.1", base)
            };
            assert!(flood.keep(&no_detail));
        }
        assert!(flood.flush(base, true).is_empty());
    }

    #[test]
    fn test_bind_flood_windows_are_per_peer_and_protocol() {
        let mut flood = FloodCoalescer::new(FloodClass::UnknownBind, FLOOD_IDLE_SECONDS);
        let base = at(1, 9, 0);
        for i in 0..10 {
            flood.keep(&unknown_bind(&format!("a{i}"), "10.0.0.1", base));
            flood.keep(&unknown_bind(&format!("b{i}"), "10.0.0.2", base));
            let http = LogEvent {
                protocol: Protocol::Http,
                ..unknown_bind(&format!("c{i}"), "10.0.0.1", base)
            };
            flood.keep(&http);
        }
        let rows = flood.flush(base, true);
        assert_eq!(started_rows(&rows), 3, "one started per source");
        let mut resolved = resolved_rows(&rows);
        resolved.sort_by_key(|r| (r.peer.clone(), r.protocol.to_string()));
        assert_eq!(
            resolved
                .iter()
                .map(|r| (
                    r.peer.as_deref().unwrap(),
                    r.protocol,
                    r.detail.as_deref().unwrap()
                ))
                .collect::<Vec<_>>(),
            vec![
                (
                    "10.0.0.1",
                    Protocol::Http,
                    "unknown-user bind flood resolved: 2 binds, 2 names, 0s"
                ),
                (
                    "10.0.0.1",
                    Protocol::Ldap,
                    "unknown-user bind flood resolved: 2 binds, 2 names, 0s"
                ),
                (
                    "10.0.0.2",
                    Protocol::Ldap,
                    "unknown-user bind flood resolved: 2 binds, 2 names, 0s"
                ),
            ]
        );
    }

    #[test]
    fn test_coalescers_cap_their_maps() {
        let mut flood = FloodCoalescer::new(FloodClass::UnknownBind, FLOOD_IDLE_SECONDS);
        let base = at(1, 9, 0);
        for i in 0..10 {
            flood.keep(&unknown_bind(&format!("a{i}"), "10.0.0.1", base));
        }
        for i in 0..(COALESCE_CAP - 1) {
            flood.keep(&unknown_bind(
                "x",
                &format!("10.1.{}.{}", i / 256, i % 256),
                base,
            ));
        }
        // The cap flush resolves the counted window before the map resets.
        assert!(flood.keep(&unknown_bind("y", "10.2.0.1", base)));
        let rows = flood.flush(base, false);
        assert_eq!(started_rows(&rows), 1);
        let resolved = resolved_rows(&rows);
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].peer.as_deref(), Some("10.0.0.1"));
        assert_eq!(
            resolved[0].detail.as_deref(),
            Some("unknown-user bind flood resolved: 2 binds, 2 names, 0s")
        );

        let mut flood = FloodCoalescer::new(FloodClass::UnknownBind, FLOOD_IDLE_SECONDS);
        for i in 0..(8 + FLOOD_ACTOR_CAP + 10) {
            flood.keep(&unknown_bind(&format!("spray-{i}"), "10.0.0.1", base));
        }
        let rows = flood.flush(base, true);
        let resolved = resolved_rows(&rows);
        assert_eq!(resolved.len(), 1);
        assert_eq!(
            resolved[0].detail.as_deref(),
            Some("unknown-user bind flood resolved: 74 binds, 64+ names, 0s")
        );

        let mut coalescer = BindCoalescer::new(300);
        let now = chrono::Utc::now().naive_utc();
        for i in 0..(COALESCE_CAP + 80) {
            let bind = LogEvent {
                timestamp: now,
                kind: LogKind::Bind,
                success: true,
                protocol: Protocol::Ldap,
                actor: Some(format!("u{i}")),
                target: None,
                peer: Some("127.0.0.1".to_owned()),
                forwarded_for: None,
                detail: None,
            };
            assert!(coalescer.keep(&bind));
        }
        assert!(coalescer.cached() <= COALESCE_CAP);
        assert!(coalescer.cached() > 0);
    }

    fn denial(actor: Option<&str>, peer: &str, timestamp: chrono::NaiveDateTime) -> LogEvent {
        LogEvent {
            success: false,
            detail: Some("Unauthorized".to_owned()),
            peer: Some(peer.to_owned()),
            actor: actor.map(str::to_owned),
            ..event_at(LogKind::AccessDenied, actor.unwrap_or("nobody"), timestamp)
        }
    }

    #[test]
    fn test_access_denied_flood_started_and_resolved() {
        let mut flood = FloodCoalescer::new(FloodClass::AccessDenied, FLOOD_IDLE_SECONDS);
        let base = at(1, 9, 0);
        for i in 0..12 {
            let kept = flood.keep(&denial(
                Some(&format!("user-{i}")),
                "10.0.0.7",
                base + chrono::Duration::seconds(i),
            ));
            assert_eq!(kept, i < 8, "denial {i}");
        }
        // The started row opens the incident on the first dropped denial.
        let opened = flood.flush(base + chrono::Duration::seconds(12), false);
        assert_eq!(opened.len(), 1);
        assert_eq!(opened[0].kind, LogKind::AccessDeniedFlood);
        assert!(!opened[0].success);
        assert_eq!(opened[0].actor, None);
        assert_eq!(opened[0].peer.as_deref(), Some("10.0.0.7"));
        assert_eq!(
            opened[0].detail.as_deref(),
            Some("access-denied flood started")
        );
        // Quiet past the idle threshold resolves with the denial and actor counts.
        let closed = flood.flush(base + chrono::Duration::seconds(40), false);
        assert_eq!(closed.len(), 1);
        assert_eq!(closed[0].kind, LogKind::AccessDeniedFlood);
        assert_eq!(
            closed[0].detail.as_deref(),
            Some("access-denied flood resolved: 4 denials, 4 actors, 11s")
        );

        // A junk-JWT flood: recorded denials with no actor count as one actor.
        for i in 0..20 {
            flood.keep(&denial(
                None,
                "10.0.0.8",
                base + chrono::Duration::seconds(50 + i),
            ));
        }
        let rows = flood.flush(base + chrono::Duration::seconds(120), true);
        let resolved: Vec<_> = rows
            .iter()
            .filter(|r| {
                r.kind == LogKind::AccessDeniedFlood
                    && r.detail
                        .as_deref()
                        .is_some_and(|d| d.starts_with("access-denied flood resolved"))
            })
            .collect();
        assert_eq!(resolved.len(), 1);
        assert_eq!(
            resolved[0].detail.as_deref(),
            Some("access-denied flood resolved: 12 denials, 1 actors, 19s")
        );
    }

    #[test]
    fn test_bind_and_denied_floods_are_independent_from_one_peer() {
        let mut bind_flood = FloodCoalescer::new(FloodClass::UnknownBind, FLOOD_IDLE_SECONDS);
        let mut denied_flood = FloodCoalescer::new(FloodClass::AccessDenied, FLOOD_IDLE_SECONDS);
        let base = at(1, 9, 0);
        for i in 0..12 {
            let b = unknown_bind(&format!("b{i}"), "10.0.0.1", base);
            let d = denial(Some(&format!("d{i}")), "10.0.0.1", base);
            // Each coalescer claims only its own class and passes the other through.
            assert!(denied_flood.keep(&b), "bind passes the denied coalescer");
            assert!(bind_flood.keep(&d), "denial passes the bind coalescer");
            bind_flood.keep(&b);
            denied_flood.keep(&d);
        }
        let bind_rows = bind_flood.flush(base, true);
        let bind_resolved = resolved_rows(&bind_rows);
        let denied = denied_flood.flush(base, true);
        assert_eq!(bind_resolved.len(), 1);
        assert_eq!(bind_resolved[0].kind, LogKind::BindFlood);
        assert_eq!(
            denied
                .iter()
                .filter(|r| r.kind == LogKind::AccessDeniedFlood
                    && r.detail.as_deref().is_some_and(|d| d.contains("resolved")))
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn test_writer_brackets_a_flood_on_shutdown_and_on_idle() {
        let pool = get_initialized_db().await;
        let (sink, rx) = channel_sink(64);
        let task = tokio::spawn(run_writer(
            rx,
            pool.clone(),
            sink.dropped.clone(),
            LogRetention::default(),
            WriterCoalescers {
                bind: BindCoalescer::new(0),
                bind_flood: FloodCoalescer::new(FloodClass::UnknownBind, FLOOD_IDLE_SECONDS),
                denied_flood: FloodCoalescer::new(FloodClass::AccessDenied, FLOOD_IDLE_SECONDS),
            },
            WRITER_TICK,
        ));
        let base = chrono::Utc::now().naive_utc();
        for i in 0..12 {
            sink.record(unknown_bind(&format!("flood-{i}"), "10.0.0.9", base));
        }
        drop(sink);
        task.await.unwrap();

        let stored = rows(&pool).await;
        let binds = stored.iter().filter(|r| r.kind == "bind").count();
        let started = stored
            .iter()
            .filter(|r| r.detail.as_deref() == Some("unknown-user bind flood started"))
            .count();
        let resolved: Vec<_> = stored
            .iter()
            .filter(|r| {
                r.detail
                    .as_deref()
                    .is_some_and(|d| d.starts_with("unknown-user bind flood resolved:"))
            })
            .collect();
        assert_eq!(binds, 8);
        assert_eq!(started, 1, "the incident opened during the run");
        assert_eq!(resolved.len(), 1, "and resolved on shutdown");
        assert_eq!(resolved[0].kind, "bind_flood");
        assert!(!resolved[0].success);
        assert_eq!(resolved[0].actor, None);
        assert_eq!(resolved[0].peer.as_deref(), Some("10.0.0.9"));
        assert_eq!(
            resolved[0].detail.as_deref(),
            Some("unknown-user bind flood resolved: 4 binds, 4 names, 0s")
        );

        let pool = get_initialized_db().await;
        let (sink, rx) = channel_sink(64);
        let task = tokio::spawn(run_writer(
            rx,
            pool.clone(),
            sink.dropped.clone(),
            LogRetention::default(),
            WriterCoalescers {
                bind: BindCoalescer::new(0),
                bind_flood: FloodCoalescer::new(FloodClass::UnknownBind, 1),
                denied_flood: FloodCoalescer::new(FloodClass::AccessDenied, 1),
            },
            std::time::Duration::from_millis(100),
        ));
        let now = chrono::Utc::now().naive_utc();
        for i in 0..12 {
            sink.record(unknown_bind(&format!("flood-{i}"), "10.0.0.9", now));
        }
        // No closing event: the writer's tick must resolve the idle window on its own.
        tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
        let stored = rows(&pool).await;
        let started = stored
            .iter()
            .filter(|r| r.detail.as_deref() == Some("unknown-user bind flood started"))
            .count();
        let resolved = stored
            .iter()
            .filter(|r| {
                r.detail
                    .as_deref()
                    .is_some_and(|d| d.starts_with("unknown-user bind flood resolved:"))
            })
            .count();
        assert_eq!(started, 1, "opened during the run");
        assert_eq!(
            resolved, 1,
            "resolved by the idle timer with no closing event"
        );
        drop(sink);
        task.await.unwrap();
    }

    #[tokio::test]
    async fn test_log_lookups_run_on_the_read_pool() {
        use lldap_auth::opaque::server::generate_random_private_key;
        use lldap_domain::types::UserId;
        use lldap_domain_handlers::logging::{LOGIN_KINDS, LogCursor, LogDimension, LogFilter};

        let main_pool = get_initialized_db().await;
        let read_pool = get_initialized_db().await;
        insert_rows(
            &main_pool,
            vec![to_active_model(event(LogKind::Bind, "writer", 0))],
        )
        .await
        .unwrap();
        insert_rows(
            &read_pool,
            vec![to_active_model(event(LogKind::Bind, "reader", 0))],
        )
        .await
        .unwrap();
        let handler = SqlBackendHandler::new(generate_random_private_key(), main_pool)
            .with_read_pool(read_pool);

        let listed = handler
            .list_log_events(LogFilter::default(), 10, LogCursor::Newest)
            .await
            .unwrap();
        assert_eq!(
            listed
                .iter()
                .map(|r| r.event.actor.as_deref())
                .collect::<Vec<_>>(),
            vec![Some("reader")]
        );
        let buckets = handler
            .summarize_log_events(LogFilter::default(), vec![LogDimension::Actor], 10)
            .await
            .unwrap();
        assert_eq!(buckets.len(), 1);
        assert_eq!(buckets[0].actor.as_deref(), Some("reader"));
        let reader = handler
            .log_activity(&UserId::new("reader"), LOGIN_KINDS.to_vec(), None)
            .await
            .unwrap();
        assert!(reader.last_success.is_some());
        let writer = handler
            .log_activity(&UserId::new("writer"), LOGIN_KINDS.to_vec(), None)
            .await
            .unwrap();
        assert_eq!(writer.last_success, None, "the main pool is not consulted");
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn test_start_log_writer_installs_the_sink_and_shutdown_flushes() {
        let pool = get_initialized_db().await;
        let writer = start_log_writer(pool.clone(), LogRetention::default(), 0);
        lldap_domain_handlers::logging::record(LogKind::ServerStart, None, Some("flushed"));
        writer.shutdown().await;
        // The default sink is back: this one never reaches the table.
        lldap_domain_handlers::logging::record(LogKind::ServerStart, None, Some("late"));

        // Other tests in this binary record concurrently; only the marker rows matter.
        let details: Vec<_> = rows(&pool)
            .await
            .into_iter()
            .filter(|r| r.kind == "server_start")
            .filter_map(|r| r.detail)
            .collect();
        assert!(details.contains(&"flushed".to_owned()), "{details:?}");
        assert!(!details.contains(&"late".to_owned()), "{details:?}");
    }

    #[tokio::test]
    async fn test_writer_trims_to_max_entries_after_a_burst() {
        let pool = get_initialized_db().await;
        let (sink, rx) = channel_sink(4096);
        let retention = LogRetention {
            retention_days: 0,
            max_entries: 20,
        };
        let dropped = sink.dropped.clone();
        let task = tokio::spawn(run_writer(
            rx,
            pool.clone(),
            dropped.clone(),
            retention,
            WriterCoalescers {
                bind: BindCoalescer::new(0),
                bind_flood: FloodCoalescer::new(FloodClass::UnknownBind, FLOOD_IDLE_SECONDS),
                denied_flood: FloodCoalescer::new(FloodClass::AccessDenied, FLOOD_IDLE_SECONDS),
            },
            WRITER_TICK,
        ));
        for i in 0..(trim_interval(retention.max_entries) + 5) {
            sink.record(event(LogKind::Bind, &format!("user{i}"), 0));
        }
        drop(sink);
        task.await.unwrap();

        // The trim runs after the batch that crosses trim_interval, so at most one more
        // batch survives on top of max_entries.
        let stored = rows(&pool).await;
        assert!(stored.len() >= retention.max_entries as usize);
        assert!(
            stored.len() <= (retention.max_entries + BATCH_SIZE as u64) as usize,
            "got {} rows",
            stored.len()
        );
        assert_eq!(dropped.load(Ordering::Relaxed), 0);
        assert!(stored.iter().all(|r| r.kind == "bind"));
    }

    async fn insert_summary_fixture(pool: &DbConnection) {
        let mut events = vec![
            event_at(LogKind::Bind, "bob", at(1, 9, 0)),
            event_at(LogKind::Bind, "bob", at(1, 12, 0)),
            event_at(LogKind::Bind, "bob", at(2, 12, 30)),
            event_at(LogKind::Bind, "carol", at(1, 12, 5)),
            event_at(LogKind::Bind, "carol", at(2, 8, 0)),
            event_at(LogKind::Login, "dave", at(3, 23, 59)),
        ];
        events[3].success = false;
        events[4].success = false;
        events[4].peer = Some("10.0.0.9".to_owned());
        events[5].protocol = Protocol::Http;
        events[5].target = Some("svc".to_owned());
        insert_rows(pool, events.into_iter().map(to_active_model).collect())
            .await
            .unwrap();
        model::Logs::insert(model::logs::ActiveModel {
            timestamp: ActiveValue::Set(at(3, 12, 0)),
            kind: ActiveValue::Set("computer_create".to_owned()),
            success: ActiveValue::Set(true),
            protocol: ActiveValue::Set("graphql".to_owned()),
            ..Default::default()
        })
        .exec(pool)
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn test_summarize_log_events_buckets_periods_orders_and_limits() {
        use lldap_auth::opaque::server::generate_random_private_key;

        let pool = get_initialized_db().await;
        let handler = SqlBackendHandler::new(generate_random_private_key(), pool.clone());
        assert_eq!(
            handler
                .summarize_log_events(LogFilter::default(), vec![], 100)
                .await
                .unwrap(),
            vec![],
            "an empty table has no bucket"
        );
        insert_summary_fixture(&pool).await;
        let summarize = |filter: LogFilter, group_by: Vec<LogDimension>, limit: u32| {
            let handler = &handler;
            async move {
                handler
                    .summarize_log_events(filter, group_by, limit)
                    .await
                    .unwrap()
            }
        };

        let total = summarize(LogFilter::default(), vec![], 100).await;
        assert_eq!(total.len(), 1);
        assert_eq!(
            total[0].count, 7,
            "the unknown kind counts when kind is not grouped"
        );
        assert_eq!(total[0].first, at(1, 9, 0));
        assert_eq!(total[0].last, at(3, 23, 59));
        assert_eq!(
            (
                total[0].actor.as_deref(),
                total[0].kind,
                total[0].day.as_deref()
            ),
            (None, None, None)
        );

        let by_actor = summarize(LogFilter::default(), vec![LogDimension::Actor], 100).await;
        assert_eq!(
            by_actor
                .iter()
                .map(|b| (b.actor.as_deref(), b.count))
                .collect::<Vec<_>>(),
            vec![
                (Some("bob"), 3),
                (Some("carol"), 2),
                (Some("dave"), 1),
                (None, 1)
            ],
            "most frequent first, then newest"
        );
        assert_eq!(by_actor[0].first, at(1, 9, 0));
        assert_eq!(by_actor[0].last, at(2, 12, 30));

        let by_kind = summarize(
            LogFilter::default(),
            vec![
                LogDimension::Kind,
                LogDimension::Success,
                LogDimension::Kind,
            ],
            100,
        )
        .await;
        assert_eq!(
            by_kind
                .iter()
                .map(|b| (b.kind, b.success, b.count))
                .collect::<Vec<_>>(),
            vec![
                (Some(LogKind::Bind), Some(true), 3),
                (Some(LogKind::Bind), Some(false), 2),
                (Some(LogKind::Login), Some(true), 1),
            ],
            "the unknown kind is skipped once grouped by kind"
        );

        let by_peer = summarize(LogFilter::default(), vec![LogDimension::Peer], 100).await;
        assert_eq!(
            by_peer
                .iter()
                .map(|b| (b.peer.as_deref(), b.count))
                .collect::<Vec<_>>(),
            vec![(Some("127.0.0.1"), 5), (None, 1), (Some("10.0.0.9"), 1)]
        );
        let by_protocol = summarize(LogFilter::default(), vec![LogDimension::Protocol], 100).await;
        assert_eq!(
            by_protocol
                .iter()
                .map(|b| (b.protocol, b.count))
                .collect::<Vec<_>>(),
            vec![
                (Some(Protocol::Ldap), 5),
                (Some(Protocol::Http), 1),
                (Some(Protocol::Graphql), 1),
            ]
        );
        let by_target = summarize(LogFilter::default(), vec![LogDimension::Target], 100).await;
        assert_eq!(
            by_target
                .iter()
                .map(|b| (b.target.as_deref(), b.count))
                .collect::<Vec<_>>(),
            vec![(None, 6), (Some("svc"), 1)]
        );

        let top = summarize(LogFilter::default(), vec![LogDimension::Actor], 2).await;
        assert_eq!(top.len(), 2);
        assert_eq!(top[1].actor.as_deref(), Some("carol"));

        let failed_binds = summarize(
            LogFilter {
                kinds: vec![LogKind::Bind],
                success: Some(false),
                ..Default::default()
            },
            vec![LogDimension::Actor],
            100,
        )
        .await;
        assert_eq!(failed_binds.len(), 1);
        assert_eq!(failed_binds[0].actor.as_deref(), Some("carol"));
        assert_eq!(failed_binds[0].count, 2);
        let by_day = summarize(LogFilter::default(), vec![LogDimension::Day], 100).await;
        assert_eq!(
            by_day
                .iter()
                .map(|b| (b.day.as_deref(), b.count))
                .collect::<Vec<_>>(),
            vec![
                (Some("2024-05-01"), 3),
                (Some("2024-05-03"), 2),
                (Some("2024-05-02"), 2)
            ]
        );
        assert_eq!(by_day[0].hour, None);
        let by_hour = summarize(LogFilter::default(), vec![LogDimension::Hour], 100).await;
        assert_eq!(
            by_hour
                .iter()
                .map(|b| (b.hour, b.count))
                .collect::<Vec<_>>(),
            vec![(Some(12), 4), (Some(23), 1), (Some(8), 1), (Some(9), 1)]
        );
        let timeline = summarize(
            LogFilter::default(),
            vec![LogDimension::Day, LogDimension::Hour],
            100,
        )
        .await;
        assert_eq!(
            timeline
                .iter()
                .map(|b| (b.day.as_deref().unwrap(), b.hour.unwrap(), b.count))
                .collect::<Vec<_>>(),
            vec![
                ("2024-05-01", 12, 2),
                ("2024-05-03", 23, 1),
                ("2024-05-03", 12, 1),
                ("2024-05-02", 12, 1),
                ("2024-05-02", 8, 1),
                ("2024-05-01", 9, 1),
            ]
        );
        let bob_days = summarize(
            LogFilter {
                actor: Some(UserId::new("bob")),
                ..Default::default()
            },
            vec![LogDimension::Actor, LogDimension::Day],
            100,
        )
        .await;
        assert_eq!(
            bob_days
                .iter()
                .map(|b| (b.actor.as_deref(), b.day.as_deref(), b.count))
                .collect::<Vec<_>>(),
            vec![
                (Some("bob"), Some("2024-05-01"), 2),
                (Some("bob"), Some("2024-05-02"), 1),
            ]
        );
    }

    #[tokio::test]
    async fn test_log_activity_reports_last_events_and_failures_since_success() {
        use lldap_auth::opaque::server::generate_random_private_key;
        use lldap_domain_handlers::logging::LOGIN_KINDS;

        let pool = get_initialized_db().await;
        let handler = SqlBackendHandler::new(generate_random_private_key(), pool.clone());
        let mut events = vec![
            event_at(LogKind::Bind, "bob", at(1, 9, 0)),
            event_at(LogKind::Bind, "bob", at(1, 10, 0)),
            event_at(LogKind::Bind, "bob", at(1, 11, 0)),
            event_at(LogKind::Login, "bob", at(1, 12, 0)),
            event_at(LogKind::Bind, "bob", at(1, 13, 0)),
            event_at(LogKind::UserUpdate, "bob", at(1, 14, 0)),
            event_at(LogKind::Bind, "carol", at(1, 15, 0)),
        ];
        for i in [0, 2, 3, 4, 6] {
            events[i].success = false;
        }
        insert_rows(&pool, events.into_iter().map(to_active_model).collect())
            .await
            .unwrap();
        let bob = UserId::new("bob");

        let activity = handler
            .log_activity(&bob, LOGIN_KINDS.to_vec(), None)
            .await
            .unwrap();
        assert_eq!(activity.actor, bob);
        assert_eq!(activity.last_success.as_ref().map(|r| r.id), Some(2));
        assert_eq!(activity.last_failure.as_ref().map(|r| r.id), Some(5));
        assert_eq!(activity.failures_since_last_success, 3);
        assert_eq!(activity.last_failure.unwrap().event.timestamp, at(1, 13, 0));

        let windowed = handler
            .log_activity(&bob, LOGIN_KINDS.to_vec(), Some(at(1, 11, 30)))
            .await
            .unwrap();
        assert_eq!(
            windowed.last_success, None,
            "the success is before the window"
        );
        assert_eq!(windowed.last_failure.as_ref().map(|r| r.id), Some(5));
        assert_eq!(windowed.failures_since_last_success, 2);

        let binds = handler
            .log_activity(&bob, vec![LogKind::Bind], None)
            .await
            .unwrap();
        assert_eq!(
            binds.failures_since_last_success, 2,
            "the login failure is out of scope"
        );

        let any_kind = handler.log_activity(&bob, vec![], None).await.unwrap();
        assert_eq!(any_kind.last_success.as_ref().map(|r| r.id), Some(6));
        assert_eq!(any_kind.failures_since_last_success, 0);

        let nobody = handler
            .log_activity(&UserId::new("nobody"), LOGIN_KINDS.to_vec(), None)
            .await
            .unwrap();
        assert_eq!(nobody.last_success, None);
        assert_eq!(nobody.last_failure, None);
        assert_eq!(nobody.failures_since_last_success, 0);
    }

    // The activity lookups must stay index seeks: they are the shape a lockout policy calls.
    #[tokio::test]
    async fn test_activity_queries_use_the_actor_index_on_sqlite() {
        use lldap_domain_handlers::logging::LOGIN_KINDS;
        use sea_orm::Statement;

        let pool = get_initialized_db().await;
        let scope = LogFilter {
            actor: Some(UserId::new("bob")),
            kinds: LOGIN_KINDS.to_vec(),
            ..Default::default()
        };
        for query in [
            last_event(&scope, true).limit(1),
            failures_after(&scope, Some(at(1, 10, 0))),
        ] {
            let statement = query.build(DbBackend::Sqlite);
            let plan = pool
                .query_all(Statement::from_sql_and_values(
                    DbBackend::Sqlite,
                    format!("EXPLAIN QUERY PLAN {}", statement.sql),
                    statement.values.map(|v| v.0).unwrap_or_default(),
                ))
                .await
                .unwrap();
            let details = plan
                .iter()
                .map(|row| row.try_get::<String>("", "detail").unwrap())
                .collect::<Vec<_>>();
            assert!(
                details.iter().any(|d| d.contains("USING INDEX logs-actor")),
                "{}: {details:?}",
                statement.sql
            );
        }
    }

    #[tokio::test]
    async fn test_writer_coalesces_repeated_successful_binds() {
        let pool = get_initialized_db().await;
        let (sink, rx) = channel_sink(64);
        let task = tokio::spawn(run_writer(
            rx,
            pool.clone(),
            sink.dropped.clone(),
            LogRetention::default(),
            WriterCoalescers {
                bind: BindCoalescer::new(300),
                bind_flood: FloodCoalescer::new(FloodClass::UnknownBind, FLOOD_IDLE_SECONDS),
                denied_flood: FloodCoalescer::new(FloodClass::AccessDenied, FLOOD_IDLE_SECONDS),
            },
            WRITER_TICK,
        ));
        let base = at(1, 9, 0);
        let bind = |seconds: i64, peer: &str, success: bool| LogEvent {
            peer: Some(peer.to_owned()),
            success,
            ..event_at(
                LogKind::Bind,
                "svc",
                base + chrono::Duration::seconds(seconds),
            )
        };
        sink.record(bind(0, "10.0.0.1", true));
        sink.record(bind(10, "10.0.0.1", true));
        sink.record(bind(20, "10.0.0.2", true));
        sink.record(bind(30, "10.0.0.1", false));
        sink.record(LogEvent {
            kind: LogKind::Login,
            ..bind(40, "10.0.0.1", true)
        });
        sink.record(bind(299, "10.0.0.1", true));
        sink.record(bind(300, "10.0.0.1", true));
        sink.record(bind(310, "10.0.0.1", true));
        drop(sink);
        task.await.unwrap();

        let stored = rows(&pool).await;
        assert_eq!(
            stored
                .iter()
                .map(|r| (
                    r.kind.as_str(),
                    r.peer.as_deref().unwrap(),
                    r.success,
                    r.timestamp
                ))
                .collect::<Vec<_>>(),
            vec![
                ("bind", "10.0.0.1", true, base),
                (
                    "bind",
                    "10.0.0.2",
                    true,
                    base + chrono::Duration::seconds(20)
                ),
                (
                    "bind",
                    "10.0.0.1",
                    false,
                    base + chrono::Duration::seconds(30)
                ),
                (
                    "login",
                    "10.0.0.1",
                    true,
                    base + chrono::Duration::seconds(40)
                ),
                (
                    "bind",
                    "10.0.0.1",
                    true,
                    base + chrono::Duration::seconds(300)
                ),
            ]
        );

        let pool = get_initialized_db().await;
        let (sink, rx) = channel_sink(64);
        let task = tokio::spawn(run_writer(
            rx,
            pool.clone(),
            sink.dropped.clone(),
            LogRetention::default(),
            WriterCoalescers {
                bind: BindCoalescer::new(0),
                bind_flood: FloodCoalescer::new(FloodClass::UnknownBind, FLOOD_IDLE_SECONDS),
                denied_flood: FloodCoalescer::new(FloodClass::AccessDenied, FLOOD_IDLE_SECONDS),
            },
            WRITER_TICK,
        ));
        sink.record(bind(0, "10.0.0.1", true));
        sink.record(bind(1, "10.0.0.1", true));
        drop(sink);
        task.await.unwrap();
        assert_eq!(rows(&pool).await.len(), 2, "0 stores every bind");
    }
}
