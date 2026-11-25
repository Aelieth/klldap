use crate::sql_backend_handler::SqlBackendHandler;
use crate::sql_tables::DbConnection;
use async_trait::async_trait;
use lldap_domain::types::UserId;
use lldap_domain_handlers::handler::LogBackendHandler;
use lldap_domain_handlers::instant::{
    SignedDuration, Timestamp, days, earlier, from_naive, to_naive,
};
use lldap_domain_handlers::lockout::LOCKED_OUT;
use lldap_domain_handlers::logging::{
    self, LogActivity, LogBucket, LogCursor, LogDimension, LogEvent, LogFilter, LogKind, LogRecord,
    LogSink, NO_PASSWORD, NoopLogSink, Protocol, flush_suppressed_warnings, set_log_sink,
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
use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::hash::{DefaultHasher, Hash, Hasher};
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{info, warn};

const MAX_PAGE: u32 = 1000;
const QUEUE_CAPACITY: usize = 4096;
const BATCH_SIZE: usize = 256;
const DELETE_CHUNK: u64 = 1000;
const COALESCE_CAP: usize = 4096;
const SIGN_IN_FLOOD_CAP: usize = 512;
const LINGER: Duration = Duration::from_millis(250);
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);
// The writer wakes at least this often so an idle flood window can resolve itself and the
// warn limiter can flush without a fresh event driving the loop.
const WRITER_TICK: Duration = Duration::from_secs(5);
const FLOOD_PASS: u64 = 8;
// A flood window is one incident: it resolves after this much quiet, which also separates
// distinct bursts from the same source.
const FLOOD_IDLE_SECONDS: i64 = 20;
// At most one log_gap row in this many seconds: later drops are said together.
const GAP_WINDOW_SECONDS: i64 = 10;
const FLOOD_ACTOR_CAP: usize = 64;
/// The users of one source that hold a window of their own at a time, in each class; at 0
/// every row is keyed by its source alone.
const FLOOD_USERS_PER_SOURCE: usize = 16;
const MANY_SOURCES: &str = " from many sources";

pub(crate) const UNKNOWN_USER_DETAIL: &str = "unknown user";
/// A bind turned away before its password was tried: keyed by its source alone.
pub(crate) const BUSY_DETAIL: &str = "server busy";
const UNREADABLE_DETAIL: &str = "policy: unreadable";
const DISABLED_DETAIL: &str = "account disabled";
const USER_AT_BIND: [&str; 4] = [
    "invalid credentials",
    LOCKED_OUT,
    DISABLED_DETAIL,
    "ou mismatch",
];
const USER_AT_START: [&str; 3] = [LOCKED_OUT, DISABLED_DETAIL, "policy: "];
const USER_AT_RESET: [&str; 2] = [DISABLED_DETAIL, "could not send email"];

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
        WriterCoalescers::new(bind_coalesce_seconds, FLOOD_IDLE_SECONDS),
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
    window: SignedDuration,
    last: HashMap<(String, Protocol, Option<String>), Timestamp>,
}

impl BindCoalescer {
    fn new(seconds: u32) -> Self {
        Self {
            window: SignedDuration::from_secs(i64::from(seconds)),
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

    fn prune(&mut self, now: Timestamp) {
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
    started: Timestamp,
    last: Timestamp,
    passed: u64,
    counted: u64,
    actors: HashSet<u64>,
    more_actors: bool,
    wide: bool,
    row: LogEvent,
}

impl FloodWindow {
    /// With no key the window is its class's kind-wide one.
    fn open(class: FloodClass, key: Option<&FloodKey>, event: &LogEvent) -> Self {
        let peer = event.peer.clone().filter(|_| key.is_some());
        let judged = event.source.map(|source| source.to_string());
        let judged = judged.filter(|judged| key.is_some() && peer.as_ref() != Some(judged));
        let row = LogEvent {
            timestamp: event.timestamp,
            kind: class.kind(),
            success: false,
            protocol: event.protocol,
            actor: key.and_then(|key| key.actor.clone()),
            target: key.and_then(|key| key.user.clone()),
            peer,
            forwarded_for: judged,
            detail: None,
            source: None,
            proved: false,
        };
        Self {
            started: event.timestamp,
            last: event.timestamp,
            passed: 0,
            counted: 0,
            actors: HashSet::new(),
            more_actors: false,
            wide: key.is_none(),
            row,
        }
    }

    fn passes(&mut self, at: Timestamp, pass: u64) -> bool {
        self.last = at;
        if self.passed == pass {
            return false;
        }
        self.passed += 1;
        true
    }

    fn count(&mut self, name: u64) {
        self.counted += 1;
        if self.actors.len() < FLOOD_ACTOR_CAP {
            self.actors.insert(name);
        } else {
            self.more_actors = true;
        }
    }

    fn flood_row(&self, timestamp: Timestamp, detail: String) -> LogEvent {
        let event = LogEvent {
            timestamp,
            detail: Some(detail),
            ..self.row.clone()
        };
        logging::print(&event);
        event
    }

    fn started_row(&self, class: FloodClass) -> LogEvent {
        self.flood_row(self.last, class.started_detail(self.wide))
    }

    fn resolved_row(&self, class: FloodClass) -> Option<LogEvent> {
        (self.counted > 0).then(|| self.flood_row(self.last, class.resolved_detail(self)))
    }
}

fn hashed(name: impl Hash) -> u64 {
    let mut hasher = DefaultHasher::new();
    name.hash(&mut hasher);
    hasher.finish()
}

fn many(wide: bool) -> &'static str {
    if wide { MANY_SOURCES } else { "" }
}

// The floods the writer brackets: a unique-name bind spray, an access-denied flood
// (authenticated abuse or a junk-JWT spammer), and each kind of sign-in refused before a
// credential was proved. All coalesce the same way; the class picks the texts and the row kind.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum FloodClass {
    UnknownBind,
    AccessDenied,
    Bind,
    Login,
    TokenRefresh,
    ResetRequest,
    ResetComplete,
}

impl FloodClass {
    const ALL: [Self; 7] = [
        Self::UnknownBind,
        Self::AccessDenied,
        Self::Bind,
        Self::Login,
        Self::TokenRefresh,
        Self::ResetRequest,
        Self::ResetComplete,
    ];

    fn classify(event: &LogEvent) -> Option<Self> {
        if event.success {
            return None;
        }
        let unknown = matches!(
            event.detail.as_deref(),
            Some(UNKNOWN_USER_DETAIL | NO_PASSWORD)
        );
        match event.kind {
            LogKind::Bind if unknown => Some(Self::UnknownBind),
            LogKind::AccessDenied => Some(Self::AccessDenied),
            _ if event.proved => None,
            LogKind::Bind => Some(Self::Bind),
            LogKind::Login => Some(Self::Login),
            LogKind::TokenRefresh => Some(Self::TokenRefresh),
            LogKind::PasswordResetRequest => Some(Self::ResetRequest),
            LogKind::PasswordResetComplete => Some(Self::ResetComplete),
            _ => None,
        }
    }

    fn kind(self) -> LogKind {
        match self {
            Self::UnknownBind => LogKind::BindFlood,
            Self::AccessDenied => LogKind::AccessDeniedFlood,
            _ => LogKind::SignInFlood,
        }
    }

    fn cap(self) -> usize {
        match self {
            Self::UnknownBind | Self::AccessDenied => COALESCE_CAP,
            _ => SIGN_IN_FLOOD_CAP,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::UnknownBind => "unknown-user bind flood",
            Self::AccessDenied => "access-denied flood",
            Self::Bind => "bind flood",
            Self::Login => "login flood",
            Self::TokenRefresh => "token_refresh flood",
            Self::ResetRequest => "password_reset_request flood",
            Self::ResetComplete => "password_reset_complete flood",
        }
    }

    fn started_detail(self, wide: bool) -> String {
        format!("{}{} started", self.label(), many(wide))
    }

    fn resolved_detail(self, window: &FloodWindow) -> String {
        let more = if window.more_actors { "+" } else { "" };
        let seconds = (window.last - window.started).as_secs();
        let (noun, who) = match self {
            Self::UnknownBind => ("binds", "names"),
            Self::AccessDenied => ("denials", "actors"),
            _ => ("refusals", "names"),
        };
        let who = if window.wide { "sources" } else { who };
        format!(
            "{}{} resolved: {} {noun}, {}{more} {who}, {seconds}s",
            self.label(),
            many(window.wide),
            window.counted,
            window.actors.len(),
        )
    }

    fn name(self, wide: bool, event: &LogEvent) -> u64 {
        match (wide, self) {
            (true, _) => hashed(event.source),
            (false, Self::AccessDenied) => hashed(&event.actor),
            (false, _) => hashed(event.actor.as_ref().or(event.target.as_ref())),
        }
    }
}

/// The user a refused sign-in is about, where the door that wrote the row had found that
/// user; any other row is keyed by its source alone.
fn known_user(class: FloodClass, event: &LogEvent) -> Option<&str> {
    let detail = event.detail.as_deref()?;
    let says = |known: &[&str]| known.iter().any(|said| detail.starts_with(*said));
    match (class, event.protocol) {
        (FloodClass::Bind, _) if says(&USER_AT_BIND) => event.actor.as_deref(),
        (FloodClass::Login, Protocol::Kerberos) => event.target.as_deref(),
        (FloodClass::Login, _) if says(&USER_AT_START) && !says(&[UNREADABLE_DETAIL]) => {
            event.actor.as_deref()
        }
        (FloodClass::ResetRequest, _) if says(&USER_AT_RESET) => event.target.as_deref(),
        _ => None,
    }
}

// A flood must not push real history out of max_entries: failures beyond the first few per
// key are dropped and the incident is bracketed by a "started" row and a "resolved" row with
// the totals. One incident per key lives until it goes quiet for FLOOD_IDLE_SECONDS; other
// classes' events pass untouched. A key met while the table is full is counted in the class's
// one kind-wide window for its protocol.
struct FloodCoalescer {
    class: FloodClass,
    idle: SignedDuration,
    users_per_source: usize,
    windows: HashMap<FloodKey, FloodWindow>,
    wide: HashMap<Protocol, FloodWindow>,
    ready: Vec<LogEvent>,
}

#[derive(Clone, PartialEq, Eq, Hash)]
struct FloodKey {
    source: Option<IpAddr>,
    protocol: Protocol,
    actor: Option<String>,
    user: Option<String>,
}

impl FloodCoalescer {
    fn new(class: FloodClass, idle_seconds: i64) -> Self {
        Self {
            class,
            idle: SignedDuration::from_secs(idle_seconds),
            users_per_source: FLOOD_USERS_PER_SOURCE,
            windows: HashMap::new(),
            wide: HashMap::new(),
            ready: Vec::new(),
        }
    }

    /// A kadmin refusal coalesces only on the caller's own principal, keyed by the caller.
    fn key(&self, event: &LogEvent) -> Option<FloodKey> {
        let kadmin = event.protocol == Protocol::Kadmin;
        if kadmin && (event.actor.is_none() || event.actor != event.target) {
            return None;
        }
        let plain = FloodKey {
            source: event.source,
            protocol: event.protocol,
            actor: event.actor.clone().filter(|_| kadmin),
            user: None,
        };
        let Some(user) = known_user(self.class, event) else {
            return Some(plain);
        };
        let own = FloodKey {
            user: Some(user.to_owned()),
            ..plain.clone()
        };
        let room = || self.users_of(event.source) < self.users_per_source;
        Some(if self.windows.contains_key(&own) || room() {
            own
        } else {
            plain
        })
    }

    fn users_of(&self, source: Option<IpAddr>) -> usize {
        let keys = self.windows.keys();
        keys.filter(|key| key.source == source && key.user.is_some())
            .count()
    }

    fn window(&mut self, key: FloodKey, event: &LogEvent) -> (&mut FloodWindow, u64) {
        let class = self.class;
        if self.windows.len() >= class.cap() && !self.windows.contains_key(&key) {
            let open = || FloodWindow::open(class, None, event);
            return (self.wide.entry(event.protocol).or_insert_with(open), 0);
        }
        let window = match self.windows.entry(key) {
            Entry::Occupied(held) => held.into_mut(),
            Entry::Vacant(free) => {
                let window = FloodWindow::open(class, Some(free.key()), event);
                free.insert(window)
            }
        };
        (window, FLOOD_PASS)
    }

    fn keep(&mut self, event: &LogEvent) -> bool {
        let class = self.class;
        if FloodClass::classify(event) != Some(class) {
            return true;
        }
        let Some(key) = self.key(event) else {
            return true;
        };
        let (window, pass) = self.window(key, event);
        if window.passes(event.timestamp, pass) {
            return true;
        }
        // The first dropped event opens the incident, visible to an admin at once.
        let started = (window.counted == 0).then(|| window.started_row(class));
        window.count(class.name(window.wide, event));
        self.ready.extend(started);
        false
    }

    fn flush(&mut self, now: Timestamp, all: bool) -> Vec<LogEvent> {
        let (class, idle, ready) = (self.class, self.idle, &mut self.ready);
        let mut open = |window: &FloodWindow| {
            if !all && now - window.last < idle {
                return true;
            }
            ready.extend(window.resolved_row(class));
            false
        };
        self.windows.retain(|_, window| open(window));
        self.wide.retain(|_, window| open(window));
        std::mem::take(&mut self.ready)
    }
}

// The writer owns its coalescers so the request path never locks.
struct WriterCoalescers {
    bind: BindCoalescer,
    floods: [FloodCoalescer; 7],
}

impl WriterCoalescers {
    fn new(bind_coalesce_seconds: u32, flood_idle_seconds: i64) -> Self {
        let flood = |class| FloodCoalescer::new(class, flood_idle_seconds);
        Self {
            bind: BindCoalescer::new(bind_coalesce_seconds),
            floods: FloodClass::ALL.map(flood),
        }
    }

    fn keep(&mut self, event: &LogEvent) -> bool {
        self.bind.keep(event) && self.floods.iter_mut().all(|flood| flood.keep(event))
    }

    fn flush(&mut self, now: Timestamp, all: bool) -> Vec<LogEvent> {
        let floods = self.floods.iter_mut();
        floods.flat_map(|flood| flood.flush(now, all)).collect()
    }
}

/// A stretch of failed writes, said once when it starts and once when it ends.
#[derive(Default)]
struct Outage(Option<(Instant, u64)>);

impl Outage {
    fn failed(&mut self, rows: u64, e: &DbErr) {
        match self.0.as_mut() {
            Some((_, lost)) => *lost += rows,
            None => {
                warn!("Log events are not being stored ({e}); they are counted as dropped");
                self.0 = Some((Instant::now(), rows));
            }
        }
    }

    fn ended(&mut self) {
        if let Some((since, lost)) = self.0.take() {
            let took = since.elapsed();
            info!("Log events are stored again after {took:?}: {lost} lost");
        }
    }
}

/// The dropped events not yet said by a `log_gap` row: the first are said at once, the ones
/// that follow together when the window ends or the writer stops.
#[derive(Default)]
struct Gaps {
    pending: u64,
    said_at: Option<i64>,
}

impl Gaps {
    fn due(&mut self, lost: u64, now: i64, stopping: bool) -> Option<u64> {
        self.pending += lost;
        let open = self.said_at.is_some_and(|at| now - at < GAP_WINDOW_SECONDS);
        if self.pending == 0 || (open && !stopping) {
            return None;
        }
        self.said_at = Some(now);
        Some(std::mem::take(&mut self.pending))
    }
}

// One INSERT per batch: a trickle lingers a moment to fill a batch, a full queue drains
// back-to-back at insert speed. Dropped events surface as log_gap rows, one a window.
async fn run_writer(
    mut rx: mpsc::Receiver<LogEvent>,
    pool: DbConnection,
    dropped: Arc<AtomicU64>,
    retention: LogRetention,
    mut coalescers: WriterCoalescers,
    tick: Duration,
) {
    let mut buffer = Vec::with_capacity(BATCH_SIZE);
    let mut inserted_since_trim = 0u64;
    let mut outage = Outage::default();
    let mut gaps = Gaps::default();
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
                buffer.retain(|event| coalescers.keep(event));
            }
            Err(_) => {}
        }
        let now = Timestamp::now();
        coalescers.bind.prune(now);
        flush_suppressed_warnings(now.as_second().max(0) as u64);
        let lost = dropped.swap(0, Ordering::Relaxed);
        let gap = gaps.due(lost, now.as_second(), false);
        let mut rows = Vec::with_capacity(buffer.len() + 1);
        if let Some(lost) = gap {
            rows.push(to_active_model(gap_event(lost)));
        }
        rows.extend(buffer.drain(..).map(to_active_model));
        let floods = coalescers.flush(now, false);
        rows.extend(floods.into_iter().map(to_active_model));
        let batch = rows.len() as u64;
        match insert_rows(&pool, rows).await {
            Ok(()) if batch == 0 => {}
            Ok(()) => {
                inserted_since_trim += batch;
                outage.ended();
            }
            Err(e) => {
                // A failed batch counts as dropped, its gap row for the events it stood for.
                let own = batch - u64::from(gap.is_some());
                dropped.fetch_add(own + gap.unwrap_or(0), Ordering::Relaxed);
                outage.failed(own, &e);
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
    // The channel is closed: pending flood windows and unsaid drops become rows, never lost.
    let now = Timestamp::now();
    let lost = dropped.swap(0, Ordering::Relaxed);
    let gap = gaps.due(lost, now.as_second(), true).map(gap_event);
    let rows = gap.into_iter().chain(coalescers.flush(now, true));
    let rows = rows.map(to_active_model).collect::<Vec<_>>();
    if let Err(e) = insert_rows(&pool, rows).await {
        warn!("Could not persist the final log events: {e}");
    }
}

fn trim_interval(max_entries: u64) -> u64 {
    (max_entries / 10).max(1000)
}

fn gap_event(lost: u64) -> LogEvent {
    let event = LogEvent {
        timestamp: Timestamp::now(),
        kind: LogKind::LogGap,
        success: false,
        protocol: Protocol::System,
        actor: None,
        target: None,
        peer: None,
        forwarded_for: None,
        detail: Some(format!("dropped events: {lost}")),
        source: None,
        proved: false,
    };
    logging::print(&event);
    event
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
        since: Option<Timestamp>,
    ) -> DomainResult<LogActivity> {
        let scope = LogFilter {
            actor: Some(actor.as_str().to_owned()),
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
        .add_option(filter.actor.as_deref().map(actor_condition))
        .add_option(filter.target.as_deref().map(|t| LogsColumn::Target.eq(t)))
        .add_option(kinds)
        .add_option(filter.success.map(|s| LogsColumn::Success.eq(s)))
        .add_option(
            filter
                .protocol
                .map(|p| LogsColumn::Protocol.eq(p.to_string())),
        )
        .add_option(filter.peer.as_deref().map(|p| LogsColumn::Peer.eq(p)))
        .add_option(filter.since.map(|t| LogsColumn::Timestamp.gte(to_naive(t))))
        .add_option(filter.until.map(|t| LogsColumn::Timestamp.lte(to_naive(t))))
        .add_option(member_of.map(members))
        .add_option(member_of_id.map(members))
}

// A kadmin principal matches as typed; a user id is stored lowercased, `@` allowed.
fn actor_condition(actor: &str) -> SimpleExpr {
    let lowered = UserId::new(actor).into_string();
    if lowered == actor {
        LogsColumn::Actor.eq(actor)
    } else {
        LogsColumn::Actor
            .eq(actor)
            .or(LogsColumn::Actor.eq(lowered))
    }
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
        first: from_naive(first),
        last: from_naive(last),
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

fn failures_after(scope: &LogFilter, after: Option<Timestamp>) -> Select<model::Logs> {
    let query = model::Logs::find()
        .select_only()
        .column_as(LogsColumn::Id.count(), "count")
        .filter(filter_condition(scope))
        .filter(LogsColumn::Success.eq(false));
    match after {
        Some(after) => query.filter(LogsColumn::Timestamp.gt(to_naive(after))),
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
            timestamp: from_naive(row.timestamp),
            kind,
            success: row.success,
            protocol,
            actor: row.actor,
            target: row.target,
            peer: row.peer,
            forwarded_for: row.forwarded_for,
            detail: row.detail,
            source: None,
            proved: false,
        },
    })
}

pub(crate) fn to_active_model(event: LogEvent) -> model::logs::ActiveModel {
    model::logs::ActiveModel {
        id: ActiveValue::NotSet,
        timestamp: ActiveValue::Set(to_naive(event.timestamp)),
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
        let cutoff = earlier(Timestamp::now(), days(i64::from(retention.retention_days)));
        delete_oldest_chunks(pool, OldestMatch::TimestampBefore(to_naive(cutoff))).await?;
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
            timestamp: Timestamp::now() - days(days_ago),
            kind,
            success: true,
            protocol: Protocol::Ldap,
            actor: Some(actor.to_owned()),
            target: None,
            peer: Some("127.0.0.1".to_owned()),
            forwarded_for: None,
            detail: None,
            source: "127.0.0.1".parse().ok(),
            proved: false,
        }
    }

    fn at(day: u32, hour: u32, minute: u32) -> Timestamp {
        let at = chrono::NaiveDate::from_ymd_opt(2024, 5, day)
            .unwrap()
            .and_hms_nano_opt(hour, minute, 40, 123_456_789)
            .unwrap();
        from_naive(at)
    }

    fn event_at(kind: LogKind, actor: &str, timestamp: Timestamp) -> LogEvent {
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
            WriterCoalescers::new(0, FLOOD_IDLE_SECONDS),
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
            WriterCoalescers::new(0, FLOOD_IDLE_SECONDS),
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
            WriterCoalescers::new(0, FLOOD_IDLE_SECONDS),
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
    async fn test_the_actor_filter_matches_the_value_as_given_or_lowercased() {
        use lldap_auth::opaque::server::generate_random_private_key;
        let pool = get_initialized_db().await;
        let handler = SqlBackendHandler::new(generate_random_private_key(), pool.clone());
        let stored = ["admin/admin@GATE.TEST", "bob", "bob@example", "carol"];
        let events = stored.map(|actor| to_active_model(event(LogKind::Bind, actor, 0)));
        insert_rows(&pool, events.into()).await.unwrap();
        let rows = [
            (
                "a kadmin principal with an upper-case realm",
                "admin/admin@GATE.TEST",
            ),
            ("a user id typed in mixed case", "Bob"),
            ("a user id with @ typed in mixed case", "Bob@Example"),
        ];
        let mut got = Vec::new();
        for (label, typed) in rows {
            let filter = LogFilter {
                actor: Some(typed.to_owned()),
                ..Default::default()
            };
            let found = handler
                .list_log_events(filter, 100, LogCursor::Newest)
                .await
                .unwrap();
            let actors: Vec<_> = found.into_iter().filter_map(|r| r.event.actor).collect();
            got.push((label, actors));
        }
        let only = |actor: &str| vec![actor.to_owned()];
        assert_eq!(
            got,
            vec![
                (rows[0].0, only("admin/admin@GATE.TEST")),
                (rows[1].0, only("bob")),
                (rows[2].0, only("bob@example")),
            ]
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
            actor: Some(name.to_owned()),
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
            "a user id typed in another case"
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
        let now = Timestamp::now();
        assert_eq!(
            ids(&list(
                LogFilter {
                    since: Some(now - SignedDuration::from_hours(36)),
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

    fn unknown_bind(actor: &str, peer: &str, timestamp: Timestamp) -> LogEvent {
        LogEvent {
            success: false,
            detail: Some(UNKNOWN_USER_DETAIL.to_owned()),
            ..sent_from(peer, event_at(LogKind::Bind, actor, timestamp))
        }
    }

    /// The row as sent from that address, with no proxy between.
    fn sent_from(peer: &str, row: LogEvent) -> LogEvent {
        LogEvent {
            peer: Some(peer.to_owned()),
            source: peer.parse().ok(),
            ..row
        }
    }

    /// A refused sign-in by bob from 127.0.0.1, no credential proved before it.
    fn refusal(kind: LogKind, protocol: Protocol, detail: &str, timestamp: Timestamp) -> LogEvent {
        LogEvent {
            success: false,
            protocol,
            detail: Some(detail.to_owned()),
            ..event_at(kind, "bob", timestamp)
        }
    }

    fn kept(flood: &mut FloodCoalescer, row: &LogEvent, times: usize) -> usize {
        (0..times).filter(|_| flood.keep(row)).count()
    }

    fn details(rows: &[LogEvent]) -> Vec<&str> {
        rows.iter().filter_map(|r| r.detail.as_deref()).collect()
    }

    fn nanos_after(base: Timestamp, nanos: i64) -> Timestamp {
        base + SignedDuration::from_nanos(nanos)
    }

    #[test]
    fn test_a_floods_span_is_cut_to_whole_seconds_and_it_ends_after_exactly_the_idle_time() {
        let base = at(1, 9, 0);
        let spans = [
            ("under a second", 999_999_999, "0s"),
            ("a second", 1_000_000_000, "1s"),
            (
                "the last event stamped before the first",
                -1_999_999_999,
                "-1s",
            ),
        ];
        for (label, nanos, seconds) in spans {
            let window = FloodWindow {
                last: nanos_after(base, nanos),
                counted: 2,
                wide: false,
                ..FloodWindow::open(
                    FloodClass::UnknownBind,
                    None,
                    &unknown_bind("x", "10.0.0.9", base),
                )
            };
            assert_eq!(
                FloodClass::UnknownBind.resolved_detail(&window),
                format!("unknown-user bind flood resolved: 2 binds, 0 names, {seconds}"),
                "{label}"
            );
        }
        let idle = FLOOD_IDLE_SECONDS * 1_000_000_000;
        let edges = [
            ("one nanosecond short of the idle time", idle - 1, 0),
            ("the idle time", idle, 1),
        ];
        for (label, nanos, resolved) in edges {
            let mut flood = FloodCoalescer::new(FloodClass::UnknownBind, FLOOD_IDLE_SECONDS);
            for i in 0..=FLOOD_PASS {
                flood.keep(&unknown_bind(&format!("g1-{i}"), "10.0.0.9", base));
            }
            let rows = flood.flush(nanos_after(base, nanos), false);
            assert_eq!(resolved_rows(&rows).len(), resolved, "{label}");
        }
    }

    #[tokio::test]
    async fn test_a_log_row_stored_past_the_last_instant_lists_at_the_last_instant() {
        use lldap_auth::opaque::server::generate_random_private_key;
        let pool = get_initialized_db().await;
        let handler = SqlBackendHandler::new(generate_random_private_key(), pool.clone());
        let far = chrono::NaiveDate::from_ymd_opt(9999, 12, 31)
            .unwrap()
            .and_hms_micro_opt(23, 59, 59, 999_999)
            .unwrap();
        let row = model::logs::ActiveModel {
            timestamp: ActiveValue::Set(far),
            ..to_active_model(event(LogKind::Bind, "bob", 0))
        };
        insert_rows(&pool, vec![row]).await.unwrap();
        let listed = handler
            .list_log_events(LogFilter::default(), 10, LogCursor::Newest)
            .await
            .unwrap();
        let stamps: Vec<_> = listed.iter().map(|r| r.event.timestamp).collect();
        assert_eq!(stamps, vec![Timestamp::MAX], "MySQL's largest DATETIME");
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
                base + SignedDuration::from_secs(i),
            ));
            assert_eq!(kept, i < 8, "event {i}");
        }
        // The started row is queued the moment the source crosses the threshold.
        let opened = flood.flush(base + SignedDuration::from_secs(15), false);
        assert_eq!(opened.len(), 1);
        assert_eq!(opened[0].kind, LogKind::BindFlood);
        assert!(!opened[0].success);
        assert_eq!(opened[0].actor, None);
        assert_eq!(opened[0].peer.as_deref(), Some("10.0.0.1"));
        assert_eq!(opened[0].forwarded_for, None, "the peer is the source");
        assert_eq!(opened[0].protocol, Protocol::Ldap);
        assert_eq!(
            opened[0].detail.as_deref(),
            Some("unknown-user bind flood started")
        );

        // The window is still active (last event at +11s), so nothing resolves yet.
        assert!(
            flood
                .flush(base + SignedDuration::from_secs(20), false)
                .is_empty()
        );

        // Quiet past the idle threshold resolves it with no closing event: one row with
        // the totals and the span, stamped with the last event.
        let closed = flood.flush(base + SignedDuration::from_secs(40), false);
        assert_eq!(closed.len(), 1);
        assert_eq!(closed[0].peer.as_deref(), Some("10.0.0.1"));
        assert_eq!(
            closed[0].detail.as_deref(),
            Some("unknown-user bind flood resolved: 4 binds, 4 names, 11s")
        );
        assert_eq!(closed[0].timestamp, base + SignedDuration::from_secs(11));
        assert!(
            flood
                .flush(base + SignedDuration::from_secs(50), false)
                .is_empty()
        );

        // A later burst from the same source is a new incident, not a continuation.
        let second = base + SignedDuration::from_secs(60);
        for i in 0..10 {
            flood.keep(&unknown_bind(&format!("b{i}"), "10.0.0.1", second));
        }
        let closed = flood.flush(second + SignedDuration::from_secs(30), false);
        assert_eq!(started_rows(&closed), 1);
        assert_eq!(
            resolved_rows(&closed)
                .iter()
                .map(|r| r.detail.as_deref().unwrap())
                .collect::<Vec<_>>(),
            vec!["unknown-user bind flood resolved: 2 binds, 2 names, 0s"]
        );

        // Exactly FLOOD_PASS failures from a source pass 1:1 and open nothing.
        let third = second + SignedDuration::from_secs(60);
        for i in 0..FLOOD_PASS {
            assert!(flood.keep(&unknown_bind(&format!("c{i}"), "10.0.0.3", third)));
        }
        assert!(
            flood
                .flush(third + SignedDuration::from_secs(999), true)
                .is_empty()
        );
    }

    #[test]
    fn test_bind_flood_scope_is_unknown_user_bind_failures_only() {
        let mut flood = FloodCoalescer::new(FloodClass::UnknownBind, FLOOD_IDLE_SECONDS);
        let base = at(1, 9, 0);
        for _ in 0..20 {
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
    fn test_a_refusal_before_a_credential_is_proved_coalesces_past_the_first_eight() {
        let base = at(1, 9, 0);
        let rows = [
            (LogKind::Bind, Protocol::Ldap, "invalid credentials", "bind"),
            (LogKind::Bind, Protocol::Http, BUSY_DETAIL, "bind"),
            (
                LogKind::Login,
                Protocol::Http,
                "policy: login-hours (outside login hours)",
                "login",
            ),
            (LogKind::Login, Protocol::Kerberos, "locked out", "login"),
            (
                LogKind::TokenRefresh,
                Protocol::Http,
                "invalid refresh token",
                "token_refresh",
            ),
            (
                LogKind::PasswordResetRequest,
                Protocol::Http,
                "unknown user",
                "password_reset_request",
            ),
            (
                LogKind::PasswordResetComplete,
                Protocol::Http,
                "wrong or expired reset token",
                "password_reset_complete",
            ),
        ];
        for (kind, protocol, detail, label) in rows {
            let row = refusal(kind, protocol, detail, base);
            let class = FloodClass::classify(&row).unwrap();
            let mut flood = FloodCoalescer::new(class, FLOOD_IDLE_SECONDS);
            let passed = kept(&mut flood, &row, 20);
            let rows = flood.flush(base, true);
            let kinds: Vec<_> = rows.iter().map(|r| r.kind).collect();
            let started = format!("{label} flood started");
            let resolved = format!("{label} flood resolved: 12 refusals, 1 names, 0s");
            assert_eq!(
                (passed, kinds, details(&rows)),
                (
                    8,
                    vec![LogKind::SignInFlood; 2],
                    vec![started.as_str(), resolved.as_str()]
                ),
                "{row}"
            );
        }
    }

    #[test]
    fn test_a_refusal_after_a_credential_was_proved_is_kept_every_time() {
        let base = at(1, 9, 0);
        let rows = [
            (
                LogKind::Bind,
                Protocol::Ldap,
                "policy: login-hours (outside login hours)",
            ),
            (LogKind::Bind, Protocol::Http, "totp code required"),
            (LogKind::Bind, Protocol::Ldap, "invalid totp"),
            (LogKind::Login, Protocol::Http, "policy: unreadable"),
            (LogKind::Login, Protocol::Http, "totp attempts exceeded"),
            (
                LogKind::Login,
                Protocol::Kerberos,
                "refused after pre-authentication, code 12",
            ),
            (LogKind::TokenRefresh, Protocol::Http, "account disabled"),
        ];
        let mut coalescers = WriterCoalescers::new(0, FLOOD_IDLE_SECONDS);
        for (kind, protocol, detail) in rows {
            let row = LogEvent {
                proved: true,
                ..refusal(kind, protocol, detail, base)
            };
            let passed = (0..20).filter(|_| coalescers.keep(&row)).count();
            assert_eq!(passed, 20, "{row}");
        }
        assert_eq!(coalescers.flush(base, true), vec![]);
    }

    #[test]
    fn test_unknown_names_and_a_users_wrong_passwords_do_not_share_a_window() {
        let base = at(1, 9, 0);
        let mut coalescers = WriterCoalescers::new(0, FLOOD_IDLE_SECONDS);
        let spray = |i: usize| unknown_bind(&format!("spray-{i}"), "10.0.0.1", base);
        let unknown = (0..20).filter(|i| coalescers.keep(&spray(*i))).count();
        let wrong = refusal(LogKind::Bind, Protocol::Ldap, "invalid credentials", base);
        let wrong = sent_from("10.0.0.1", wrong);
        let known = (0..20).filter(|_| coalescers.keep(&wrong)).count();
        assert_eq!(
            (unknown, known),
            (8, 8),
            "a name spray does not use up the first eight of a user's failed binds from its source"
        );
    }

    #[test]
    fn test_each_known_user_keeps_a_first_eight_per_source_and_a_claimed_name_does_not() {
        let base = at(1, 9, 0);
        let rows = [
            (LogKind::Bind, Protocol::Ldap, "invalid credentials", true),
            (LogKind::Bind, Protocol::Http, "locked out", true),
            (LogKind::Bind, Protocol::Ldap, "account disabled", true),
            (LogKind::Bind, Protocol::Ldap, "ou mismatch", true),
            (LogKind::Bind, Protocol::Ldap, "policy: unreadable", false),
            (LogKind::Bind, Protocol::Ldap, BUSY_DETAIL, false),
            (LogKind::Bind, Protocol::Ldap, "SASL not supported", false),
            (LogKind::Login, Protocol::Http, "locked out", true),
            (LogKind::Login, Protocol::Http, "account disabled", true),
            (
                LogKind::Login,
                Protocol::Http,
                "policy: login-hours (outside login hours)",
                true,
            ),
            (LogKind::Login, Protocol::Http, "policy: unreadable", false),
            (LogKind::Login, Protocol::Http, "invalid credentials", false),
            (
                LogKind::Login,
                Protocol::Kerberos,
                "pre-authentication failed (encrypted timestamp)",
                true,
            ),
            (
                LogKind::TokenRefresh,
                Protocol::Http,
                "invalid refresh token",
                false,
            ),
            (
                LogKind::PasswordResetRequest,
                Protocol::Http,
                "account disabled",
                true,
            ),
            (
                LogKind::PasswordResetRequest,
                Protocol::Http,
                "unknown user",
                false,
            ),
            (
                LogKind::PasswordResetComplete,
                Protocol::Http,
                "wrong or expired reset token",
                false,
            ),
        ];
        for (kind, protocol, detail, own) in rows {
            let about = |user: &str| LogEvent {
                actor: (kind != LogKind::PasswordResetRequest).then(|| user.to_owned()),
                target: Some(user.to_owned()),
                ..refusal(kind, protocol, detail, base)
            };
            let class = FloodClass::classify(&about("ann")).unwrap();
            let mut flood = FloodCoalescer::new(class, FLOOD_IDLE_SECONDS);
            let passed = kept(&mut flood, &about("ann"), 10) + kept(&mut flood, &about("bob"), 10);
            assert_eq!(
                passed,
                if own { 16 } else { 8 },
                "{kind} over {protocol}, {detail}: two names, ten refusals each, one source"
            );
        }
    }

    fn wrong_password(user: &str, peer: &str, timestamp: Timestamp) -> LogEvent {
        let wrong = refusal(
            LogKind::Bind,
            Protocol::Ldap,
            "invalid credentials",
            timestamp,
        );
        LogEvent {
            actor: Some(user.to_owned()),
            ..sent_from(peer, wrong)
        }
    }

    #[test]
    fn test_a_source_holds_a_window_each_for_sixteen_users_and_its_own_for_the_rest() {
        let base = at(1, 9, 0);
        let mut flood = FloodCoalescer::new(FloodClass::Bind, FLOOD_IDLE_SECONDS);
        let user = |i: usize| format!("u{i:02}");
        let passed: Vec<_> = (0..FLOOD_USERS_PER_SOURCE + 2)
            .map(|i| kept(&mut flood, &wrong_password(&user(i), "10.0.0.1", base), 10))
            .collect();
        let elsewhere = kept(&mut flood, &wrong_password("u99", "10.0.0.2", base), 10);
        let open = flood.flush(base, false);
        let resolved_early = open.iter().filter(|r| counted(r) > 0).count();
        let mut closed = flood.flush(base, true);
        closed.sort_by_key(|r| r.target.clone());
        let shown: Vec<_> = closed
            .iter()
            .map(|r| (r.target.clone(), counted(r)))
            .collect();
        let mut expected = vec![(None, 12)];
        expected.extend((0..FLOOD_USERS_PER_SOURCE).map(|i| (Some(user(i)), 2)));
        expected.push((Some("u99".to_owned()), 2));
        assert_eq!(
            (passed, elsewhere, resolved_early, shown),
            (
                [vec![8; FLOOD_USERS_PER_SOURCE], vec![8, 0]].concat(),
                8,
                0,
                expected
            ),
            "the users past the sixteenth share the source's own window; another source's user \
             has its own; no window is resolved to make room"
        );
        assert_eq!(
            closed[0].detail.as_deref(),
            Some("bind flood resolved: 12 refusals, 2 names, 0s")
        );
    }

    #[test]
    fn test_with_no_user_windows_every_row_is_keyed_by_its_source_alone() {
        let base = at(1, 9, 0);
        let mut flood = FloodCoalescer {
            users_per_source: 0,
            ..FloodCoalescer::new(FloodClass::Bind, FLOOD_IDLE_SECONDS)
        };
        let passed = kept(&mut flood, &wrong_password("ann", "10.0.0.1", base), 10)
            + kept(&mut flood, &wrong_password("bob", "10.0.0.1", base), 10);
        let rows = flood.flush(base, true);
        let targets: Vec<_> = rows.iter().map(|r| r.target.as_deref()).collect();
        assert_eq!(
            (passed, targets, details(&rows)),
            (
                8,
                vec![None; 2],
                vec![
                    "bind flood started",
                    "bind flood resolved: 12 refusals, 2 names, 0s"
                ]
            )
        );
    }

    #[test]
    fn test_the_judged_address_and_the_proved_mark_are_not_stored() {
        let row = event_at(LogKind::Login, "bob", at(1, 9, 0));
        let marked = LogEvent {
            source: "203.0.113.9".parse().ok(),
            proved: true,
            ..row.clone()
        };
        let plain = LogEvent {
            source: None,
            ..row
        };
        assert_eq!(to_active_model(marked), to_active_model(plain));
    }

    #[test]
    fn test_binds_with_no_password_coalesce_as_unknown_names_do() {
        let mut flood = FloodCoalescer::new(FloodClass::UnknownBind, FLOOD_IDLE_SECONDS);
        let base = at(1, 9, 0);
        let kept: Vec<bool> = (0..10)
            .map(|i| {
                let no_password = LogEvent {
                    detail: Some("no password given".to_owned()),
                    ..unknown_bind(&format!("spray-{i}"), "10.0.0.9", base)
                };
                flood.keep(&no_password)
            })
            .collect();
        let closed = flood.flush(base + SignedDuration::from_secs(30), false);
        let details: Vec<_> = closed.iter().filter_map(|r| r.detail.as_deref()).collect();
        assert_eq!(
            (kept, details),
            (
                [vec![true; 8], vec![false; 2]].concat(),
                vec![
                    "unknown-user bind flood started",
                    "unknown-user bind flood resolved: 2 binds, 2 names, 0s"
                ]
            ),
            "the first eight pass, the rest are counted in one incident"
        );
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

    /// The count a `resolved` row carries; 0 for any other row.
    fn counted(row: &LogEvent) -> u64 {
        let detail = row.detail.as_deref().unwrap_or_default();
        let totals = detail
            .split_once("resolved: ")
            .map_or("", |(_, totals)| totals);
        let count = totals.split(' ').next().and_then(|n| n.parse().ok());
        count.unwrap_or(0)
    }

    #[test]
    fn test_a_window_is_keyed_by_the_judged_address_whatever_the_socket_peer() {
        let base = at(1, 9, 0);
        let rows = [
            unknown_bind("ghost", "10.0.0.1", base),
            denial(None, "10.0.0.1", base),
            refusal(LogKind::Login, Protocol::Http, "invalid credentials", base),
        ];
        let through = |row: &LogEvent, peer: &str, source: &str| LogEvent {
            peer: Some(peer.to_owned()),
            source: source.parse().ok(),
            ..row.clone()
        };
        for row in rows {
            let class = FloodClass::classify(&row).unwrap();
            let mut flood = FloodCoalescer::new(class, FLOOD_IDLE_SECONDS);
            for _ in 0..10 {
                flood.keep(&through(&row, "10.0.0.1", "203.0.113.1"));
                flood.keep(&through(&row, "10.0.0.1", "203.0.113.2"));
                flood.keep(&through(&row, "10.0.0.2", "203.0.113.2"));
            }
            let rows = flood.flush(base, true);
            let mut resolved: Vec<_> = rows
                .iter()
                .filter(|r| counted(r) > 0)
                .map(|r| (r.peer.as_deref(), r.forwarded_for.as_deref(), counted(r)))
                .collect();
            resolved.sort();
            assert_eq!(
                resolved,
                vec![
                    (Some("10.0.0.1"), Some("203.0.113.1"), 2),
                    (Some("10.0.0.1"), Some("203.0.113.2"), 12),
                ],
                "{class:?}: two sources behind one peer have a window each and one source behind \
                 two peers has one; the row names its first event's peer and the judged address"
            );
        }
    }

    fn address(i: usize) -> String {
        format!("10.{}.{}.{}", 1 + i / 65536, i / 256 % 256, i % 256)
    }

    #[test]
    fn test_a_full_table_opens_one_kind_wide_window_and_resolves_no_other() {
        let base = at(1, 9, 0);
        let idle = SignedDuration::from_secs(FLOOD_IDLE_SECONDS);
        let wrong = refusal(LogKind::Login, Protocol::Http, "invalid credentials", base);
        let rows = [
            (
                unknown_bind("ghost", "10.0.0.1", base),
                COALESCE_CAP,
                "unknown-user bind flood",
                "binds, 1 names",
            ),
            (
                denial(None, "10.0.0.1", base),
                COALESCE_CAP,
                "access-denied flood",
                "denials, 1 actors",
            ),
            (wrong, SIGN_IN_FLOOD_CAP, "login flood", "refusals, 1 names"),
        ];
        for (row, cap, label, counts) in rows {
            let class = FloodClass::classify(&row).unwrap();
            let mut flood = FloodCoalescer::new(class, FLOOD_IDLE_SECONDS);
            let from = |i: usize| sent_from(&address(i), row.clone());
            kept(&mut flood, &sent_from("10.0.0.1", row.clone()), 10);
            for i in 1..cap {
                flood.keep(&from(i));
            }
            let beyond = [cap, cap + 1, cap + 1, cap + 2].map(|i| flood.keep(&from(i)));
            let held = flood.keep(&from(1));
            let open = flood.flush(base, false);
            let windows = flood.windows.len();
            let wide = open.last().map(|r| (r.kind, r.peer.clone()));
            let closed = flood.flush(base + idle, false);
            let noun = counts.split(',').next().unwrap_or_default();
            let said = [
                format!("{label} started"),
                format!("{label} from many sources started"),
                format!("{label} resolved: 2 {counts}, 0s"),
                format!("{label} from many sources resolved: 4 {noun}, 3 sources, 0s"),
            ];
            assert_eq!(
                (beyond, held, windows, wide),
                ([false; 4], true, cap, Some((class.kind(), None))),
                "{label}: past {cap} windows a new key is counted in the one kind-wide window, \
                 which keeps no row and names no peer; a key with a window keeps its own"
            );
            assert_eq!(
                (details(&open), details(&closed)),
                (
                    vec![said[0].as_str(), said[1].as_str()],
                    vec![said[2].as_str(), said[3].as_str()]
                ),
                "{label}: nothing resolves until the idle time has passed"
            );
        }
    }

    #[test]
    fn test_coalescers_cap_their_maps() {
        let base = at(1, 9, 0);
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
        let now = Timestamp::now();
        for i in 0..(COALESCE_CAP + 80) {
            let bind = event_at(LogKind::Bind, &format!("u{i}"), now);
            assert!(coalescer.keep(&bind));
        }
        assert!(coalescer.cached() <= COALESCE_CAP);
        assert!(coalescer.cached() > 0);
    }

    fn denial(actor: Option<&str>, peer: &str, timestamp: Timestamp) -> LogEvent {
        LogEvent {
            success: false,
            detail: Some("Unauthorized".to_owned()),
            actor: actor.map(str::to_owned),
            ..sent_from(peer, event_at(LogKind::AccessDenied, "nobody", timestamp))
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
                base + SignedDuration::from_secs(i),
            ));
            assert_eq!(kept, i < 8, "denial {i}");
        }
        // The started row opens the incident on the first dropped denial.
        let opened = flood.flush(base + SignedDuration::from_secs(12), false);
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
        let closed = flood.flush(base + SignedDuration::from_secs(40), false);
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
                base + SignedDuration::from_secs(50 + i),
            ));
        }
        let rows = flood.flush(base + SignedDuration::from_secs(120), true);
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

    #[test]
    fn test_the_kdcs_refusals_coalesce_per_peer_as_token_use_does() {
        let mut flood = FloodCoalescer::new(FloodClass::AccessDenied, FLOOD_IDLE_SECONDS);
        let base = at(1, 9, 0);
        let details = [
            "policy: login-hours",
            "policy: login-hours (S4U2Self by HTTP/svc.example.com@EXAMPLE.COM)",
        ];
        let kept: Vec<bool> = (0..12)
            .map(|i| {
                let refusal = LogEvent {
                    protocol: Protocol::Kerberos,
                    detail: Some(details[i % 2].to_owned()),
                    ..denial(
                        Some("sable"),
                        "192.0.2.7",
                        base + SignedDuration::from_secs(i as i64),
                    )
                };
                flood.keep(&refusal)
            })
            .collect();
        assert_eq!(kept, (0..12).map(|i| i < 8).collect::<Vec<_>>());
        let rows: Vec<_> = flood
            .flush(base + SignedDuration::from_secs(60), true)
            .into_iter()
            .map(|r| (r.kind, r.protocol, r.peer, r.detail))
            .collect();
        let row = |detail: &str| {
            (
                LogKind::AccessDeniedFlood,
                Protocol::Kerberos,
                Some("192.0.2.7".to_owned()),
                Some(detail.to_owned()),
            )
        };
        assert_eq!(
            rows,
            vec![
                row("access-denied flood started"),
                row("access-denied flood resolved: 4 denials, 1 actors, 11s"),
            ]
        );
    }

    const ADMIN: &str = "admin/admin@EXAMPLE.COM";
    const K1SYNC: &str = "k1sync@EXAMPLE.COM";

    fn kadmin_denial(caller: &str, target: &str, timestamp: Timestamp) -> LogEvent {
        LogEvent {
            timestamp,
            kind: LogKind::AccessDenied,
            success: false,
            protocol: Protocol::Kadmin,
            actor: Some(caller.to_owned()),
            target: Some(target.to_owned()),
            peer: None,
            forwarded_for: None,
            detail: Some(format!(
                "kadmin purge_keys on {target} by {caller}: PROTECT_PRINCIPAL"
            )),
            source: None,
            proved: false,
        }
    }

    type FloodRow<'a> = (
        LogKind,
        Protocol,
        Option<&'a str>,
        Option<&'a str>,
        Option<&'a str>,
    );

    fn flood_rows(rows: &[LogEvent]) -> Vec<FloodRow<'_>> {
        rows.iter()
            .map(|r| {
                let (actor, peer) = (r.actor.as_deref(), r.peer.as_deref());
                (r.kind, r.protocol, actor, peer, r.detail.as_deref())
            })
            .collect()
    }

    #[test]
    fn test_kadmin_refusals_coalesce_only_on_the_callers_own_principal() {
        let mut flood = FloodCoalescer::new(FloodClass::AccessDenied, FLOOD_IDLE_SECONDS);
        let base = at(1, 9, 0);
        let within = |i: i64| base + SignedDuration::from_millis(i * 40);
        let admin: Vec<bool> = (0..20)
            .map(|i| flood.keep(&kadmin_denial(ADMIN, "bob@EXAMPLE.COM", within(i))))
            .collect();
        let no_caller = LogEvent {
            actor: None,
            ..kadmin_denial(ADMIN, "bob@EXAMPLE.COM", base)
        };
        let no_caller_kept = (0..20).all(|_| flood.keep(&no_caller));
        let flushed = flood.flush(base + SignedDuration::from_hours(1), true);
        assert_eq!(
            (admin, no_caller_kept, flushed),
            (vec![true; 20], true, Vec::new()),
            "an admin's refusals on another principal: every row, no flood"
        );

        let own: Vec<bool> = (0..20)
            .map(|i| flood.keep(&kadmin_denial(K1SYNC, K1SYNC, within(i))))
            .collect();
        let pass = usize::try_from(FLOOD_PASS).unwrap();
        let rows = flood.flush(base + SignedDuration::from_secs(60), false);
        assert_eq!(
            (own, flood_rows(&rows)),
            (
                [vec![true; pass], vec![false; 20 - pass]].concat(),
                vec![
                    (
                        LogKind::AccessDeniedFlood,
                        Protocol::Kadmin,
                        Some(K1SYNC),
                        None,
                        Some("access-denied flood started")
                    ),
                    (
                        LogKind::AccessDeniedFlood,
                        Protocol::Kadmin,
                        Some(K1SYNC),
                        None,
                        Some("access-denied flood resolved: 12 denials, 1 actors, 0s")
                    ),
                ]
            ),
            "self-service refusals: keyed by the caller, the usual pass, then the bracket"
        );

        let spray: Vec<bool> = (0..20)
            .map(|i| {
                let own_name = LogEvent {
                    protocol: Protocol::Http,
                    target: Some("bob".to_owned()),
                    ..denial(Some("bob"), "10.0.0.7", within(i))
                };
                flood.keep(&own_name)
            })
            .collect();
        let rows = flood.flush(base + SignedDuration::from_secs(60), false);
        assert_eq!(
            (spray, flood_rows(&rows)),
            (
                [vec![true; pass], vec![false; 20 - pass]].concat(),
                vec![
                    (
                        LogKind::AccessDeniedFlood,
                        Protocol::Http,
                        None,
                        Some("10.0.0.7"),
                        Some("access-denied flood started")
                    ),
                    (
                        LogKind::AccessDeniedFlood,
                        Protocol::Http,
                        None,
                        Some("10.0.0.7"),
                        Some("access-denied flood resolved: 12 denials, 1 actors, 0s")
                    ),
                ]
            ),
            "an HTTP spray is keyed by its peer, as before"
        );
    }

    #[tokio::test]
    async fn test_writer_stores_every_admin_kadmin_refusal() {
        let pool = get_initialized_db().await;
        let (sink, rx) = channel_sink(128);
        let task = tokio::spawn(run_writer(
            rx,
            pool.clone(),
            sink.dropped.clone(),
            LogRetention::default(),
            WriterCoalescers::new(0, FLOOD_IDLE_SECONDS),
            WRITER_TICK,
        ));
        let now = Timestamp::now();
        for i in 0..20 {
            let at = now + SignedDuration::from_millis(i * 40);
            sink.record(kadmin_denial(ADMIN, "bob@EXAMPLE.COM", at));
            sink.record(kadmin_denial(K1SYNC, K1SYNC, at));
            sink.record(denial(Some("mallory"), "10.0.0.7", at));
        }
        drop(sink);
        task.await.unwrap();

        let mut stored: HashMap<(String, String, Option<String>), usize> = HashMap::new();
        for row in rows(&pool).await {
            *stored
                .entry((row.kind, row.protocol, row.actor))
                .or_default() += 1;
        }
        let key = |kind: &str, protocol: &str, actor: Option<&str>| {
            (
                kind.to_owned(),
                protocol.to_owned(),
                actor.map(str::to_owned),
            )
        };
        let pass = usize::try_from(FLOOD_PASS).unwrap();
        assert_eq!(
            stored,
            HashMap::from([
                (key("access_denied", "kadmin", Some(ADMIN)), 20),
                (key("access_denied", "kadmin", Some(K1SYNC)), pass),
                (key("access_denied_flood", "kadmin", Some(K1SYNC)), 2),
                (key("access_denied", "ldap", Some("mallory")), pass),
                (key("access_denied_flood", "ldap", None), 2),
            ])
        );
    }

    fn sign_in_floods(stored: &[model::logs::Model]) -> Vec<&str> {
        let floods = stored.iter().filter(|r| r.kind == "sign_in_flood");
        floods.filter_map(|r| r.detail.as_deref()).collect()
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
            WriterCoalescers::new(0, FLOOD_IDLE_SECONDS),
            WRITER_TICK,
        ));
        let base = Timestamp::now();
        let wrong = refusal(LogKind::Login, Protocol::Http, "invalid credentials", base);
        for i in 0..12 {
            sink.record(unknown_bind(&format!("flood-{i}"), "10.0.0.9", base));
            sink.record(wrong.clone());
        }
        drop(sink);
        task.await.unwrap();

        let stored = rows(&pool).await;
        let logins = stored.iter().filter(|r| r.kind == "login").count();
        assert_eq!(
            (logins, sign_in_floods(&stored)),
            (
                8,
                vec![
                    "login flood started",
                    "login flood resolved: 4 refusals, 1 names, 0s"
                ]
            ),
            "a sign-in refused before a credential is bracketed as an unknown name is"
        );
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
            WriterCoalescers::new(0, 1),
            std::time::Duration::from_millis(100),
        ));
        let now = Timestamp::now();
        let wrong = refusal(LogKind::Login, Protocol::Http, "invalid credentials", now);
        for i in 0..12 {
            sink.record(unknown_bind(&format!("flood-{i}"), "10.0.0.9", now));
            sink.record(wrong.clone());
        }
        // No closing event: the writer's tick must resolve the idle window on its own.
        tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
        let stored = rows(&pool).await;
        assert_eq!(
            sign_in_floods(&stored).len(),
            2,
            "a refused sign-in's window opened and resolved on the idle timer too"
        );
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
            WriterCoalescers::new(0, FLOOD_IDLE_SECONDS),
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
            timestamp: ActiveValue::Set(to_naive(at(3, 12, 0))),
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
                actor: Some("bob".to_owned()),
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

    #[tokio::test]
    async fn test_log_activity_counts_the_rows_the_writer_stored() {
        use lldap_auth::opaque::server::generate_random_private_key;
        use lldap_domain_handlers::logging::LOGIN_KINDS;

        let pool = get_initialized_db().await;
        let (sink, rx) = channel_sink(64);
        let task = tokio::spawn(run_writer(
            rx,
            pool.clone(),
            sink.dropped.clone(),
            LogRetention::default(),
            WriterCoalescers::new(0, FLOOD_IDLE_SECONDS),
            WRITER_TICK,
        ));
        let now = Timestamp::now();
        let wrong = refusal(LogKind::Bind, Protocol::Ldap, "invalid credentials", now);
        for _ in 0..12 {
            sink.record(wrong.clone());
        }
        drop(sink);
        task.await.unwrap();

        let handler = SqlBackendHandler::new(generate_random_private_key(), pool);
        let activity = handler
            .log_activity(&UserId::new("bob"), LOGIN_KINDS.to_vec(), None)
            .await
            .unwrap();
        assert_eq!(
            activity.failures_since_last_success, 8,
            "12 wrong passwords from one source: 8 rows, the other 4 in the flood's count"
        );
    }

    // The activity lookups must stay index seeks: they are the shape a lockout policy calls.
    #[tokio::test]
    async fn test_activity_queries_use_the_actor_index_on_sqlite() {
        use lldap_domain_handlers::logging::LOGIN_KINDS;
        use sea_orm::Statement;

        let pool = get_initialized_db().await;
        let scope = LogFilter {
            actor: Some("bob".to_owned()),
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
            WriterCoalescers::new(300, FLOOD_IDLE_SECONDS),
            WRITER_TICK,
        ));
        let base = at(1, 9, 0);
        let bind = |seconds: i64, peer: &str, success: bool| LogEvent {
            peer: Some(peer.to_owned()),
            success,
            ..event_at(
                LogKind::Bind,
                "svc",
                base + SignedDuration::from_secs(seconds),
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
                    from_naive(r.timestamp)
                ))
                .collect::<Vec<_>>(),
            vec![
                ("bind", "10.0.0.1", true, base),
                (
                    "bind",
                    "10.0.0.2",
                    true,
                    base + SignedDuration::from_secs(20)
                ),
                (
                    "bind",
                    "10.0.0.1",
                    false,
                    base + SignedDuration::from_secs(30)
                ),
                (
                    "login",
                    "10.0.0.1",
                    true,
                    base + SignedDuration::from_secs(40)
                ),
                (
                    "bind",
                    "10.0.0.1",
                    true,
                    base + SignedDuration::from_secs(300)
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
            WriterCoalescers::new(0, FLOOD_IDLE_SECONDS),
            WRITER_TICK,
        ));
        sink.record(bind(0, "10.0.0.1", true));
        sink.record(bind(1, "10.0.0.1", true));
        drop(sink);
        task.await.unwrap();
        assert_eq!(rows(&pool).await.len(), 2, "0 stores every bind");
    }

    use lldap_domain_handlers::logging::capture::{BUDGET, Line, Lines};

    #[test]
    fn test_the_flood_rows_and_the_gap_row_print_within_the_failure_lines_budget() {
        let (lines, _guard) = Lines::capture();
        let mut flood = FloodCoalescer::new(FloodClass::UnknownBind, FLOOD_IDLE_SECONDS);
        let base = at(1, 9, 0);
        for source in 0..200 {
            let peer = format!("10.0.0.{source}");
            for i in 0..=FLOOD_PASS {
                flood.keep(&unknown_bind(&format!("spray-{i}"), &peer, base));
            }
        }
        let started = flood.flush(base, false).len();
        gap_event(7);
        let printed = lines.take_loud();
        assert_eq!(
            (started, printed.len()),
            (200, BUDGET),
            "200 windows start in one pass and a gap row follows: {printed:?}"
        );
    }

    /// The loud lines so far, once `enough` says so of them or twenty seconds have passed.
    async fn lines_until(lines: &Lines, seen: &mut Vec<Line>, enough: impl Fn(&[Line]) -> bool) {
        for _ in 0..20_000 {
            seen.extend(lines.take_loud());
            if enough(seen) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    }

    #[tokio::test]
    async fn test_the_writer_says_an_outage_once_when_it_starts_and_once_when_it_ends() {
        use sea_orm::Statement;
        use tracing::Level;
        let pool = get_initialized_db().await;
        let (lines, _guard) = Lines::capture();
        let rename = |from: &str, to: &str| {
            let sql = format!("ALTER TABLE {from} RENAME TO {to}");
            Statement::from_string(DbBackend::Sqlite, sql)
        };
        pool.execute(rename("logs", "logs_away")).await.unwrap();
        let (sink, rx) = channel_sink(16);
        let task = tokio::spawn(run_writer(
            rx,
            pool.clone(),
            sink.dropped.clone(),
            LogRetention::default(),
            WriterCoalescers::new(0, FLOOD_IDLE_SECONDS),
            Duration::from_millis(1),
        ));
        let mut seen = Vec::new();
        for actor in ["bob", "carol", "dave"] {
            sink.record(event(LogKind::UserCreate, actor, 0));
            tokio::time::sleep(LINGER * 2).await;
            seen.extend(lines.take_loud());
        }
        pool.execute(rename("logs_away", "logs")).await.unwrap();
        sink.record(event(LogKind::UserCreate, "erin", 0));
        let stored_again = |seen: &[Line]| seen.iter().any(|l| l.level == Level::INFO);
        lines_until(&lines, &mut seen, stored_again).await;
        drop(sink);
        task.await.unwrap();
        let gaps = rows(&pool)
            .await
            .into_iter()
            .filter(|row| row.kind == "log_gap");
        let gaps: Vec<_> = gaps.map(|row| row.detail).collect();
        assert_eq!(
            gaps,
            vec![Some("dropped events: 3".to_owned())],
            "the three lost events are said by one row, though a gap row failed with them"
        );
        let own = seen.iter().filter(|l| l.target != "logs");
        let own: Vec<_> = own.map(|l| (l.level, l.text.as_str())).collect();
        let levels: Vec<_> = own.iter().map(|(level, _)| *level).collect();
        assert_eq!(
            levels,
            vec![Level::WARN, Level::INFO],
            "three failed passes, then a good one: {own:?}"
        );
        let (started, ended) = (own[0].1, own[1].1);
        assert!(
            started.starts_with("Log events are not being stored (") && ended.ends_with(": 3 lost"),
            "{own:?}"
        );
    }

    #[test]
    fn test_dropped_events_are_said_at_once_then_once_a_window_and_all_when_the_writer_stops() {
        let rows = [
            ("nothing dropped", 0, 0, false, None),
            ("the first drops are said at once", 5, 0, false, Some(5)),
            ("drops inside the window wait", 7, 3, false, None),
            ("and more of them", 2, GAP_WINDOW_SECONDS - 1, false, None),
            (
                "the window's end says them together",
                1,
                GAP_WINDOW_SECONDS,
                false,
                Some(10),
            ),
            (
                "a new window holds again",
                4,
                GAP_WINDOW_SECONDS + 1,
                false,
                None,
            ),
            (
                "a stopping writer says what is left",
                0,
                GAP_WINDOW_SECONDS + 2,
                true,
                Some(4),
            ),
            ("and nothing twice", 0, GAP_WINDOW_SECONDS + 3, true, None),
        ];
        let mut gaps = Gaps::default();
        for (label, lost, now, stopping, said) in rows {
            assert_eq!(gaps.due(lost, now, stopping), said, "{label}");
        }
    }
}
