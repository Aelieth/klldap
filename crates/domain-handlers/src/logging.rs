use lldap_domain::types::{GroupId, UserId};
use std::fmt;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, RwLock};
use tracing::{debug, info, warn};

const MAX_NAME_LEN: usize = 255;
const MAX_DETAIL_LEN: usize = 512;
const WARN_WINDOW_SECS: u64 = 10;
const WARN_BUDGET: u32 = 64;

#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    PartialEq,
    Eq,
    Hash,
    strum::Display,
    strum::EnumString,
    strum::IntoStaticStr,
    strum::EnumIter,
)]
#[strum(serialize_all = "snake_case")]
pub enum Protocol {
    Ldap,
    Http,
    Graphql,
    #[default]
    System,
}

// Stored as text and append-only; the computer/keytab feature adds its kinds here.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    strum::Display,
    strum::EnumString,
    strum::IntoStaticStr,
    strum::EnumIter,
)]
#[strum(serialize_all = "snake_case")]
pub enum LogKind {
    Bind,
    Login,
    Logout,
    TokenRefresh,
    PasswordResetRequest,
    PasswordResetComplete,
    PasswordChange,
    UserCreate,
    UserUpdate,
    UserDelete,
    GroupCreate,
    GroupUpdate,
    GroupDelete,
    MembershipAdd,
    MembershipRemove,
    SchemaChange,
    SystemConfigChange,
    PosixChange,
    KerberosSync,
    KeytabExport,
    KeycloakChange,
    AccessDenied,
    ServerStart,
    AdminBootstrap,
    LogGap,
    BindFlood,
    AccessDeniedFlood,
    MfaEnroll,
    MfaReset,
    PolicyChange,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RequestMeta {
    pub actor: Option<UserId>,
    pub protocol: Protocol,
    pub peer: Option<IpAddr>,
    pub forwarded_for: Option<String>,
}

impl RequestMeta {
    pub fn http(peer: Option<IpAddr>, forwarded_for: Option<String>) -> Self {
        Self {
            actor: None,
            protocol: Protocol::Http,
            peer,
            forwarded_for,
        }
    }

    pub fn ldap(actor: Option<UserId>, peer: Option<IpAddr>) -> Self {
        Self {
            actor,
            protocol: Protocol::Ldap,
            peer,
            forwarded_for: None,
        }
    }

    pub fn with_actor(mut self, actor: Option<UserId>) -> Self {
        self.actor = actor;
        self
    }

    pub fn with_protocol(mut self, protocol: Protocol) -> Self {
        self.protocol = protocol;
        self
    }
}

tokio::task_local! {
    static REQUEST: RequestMeta;
}

pub async fn with_request<F: Future>(meta: RequestMeta, f: F) -> F::Output {
    REQUEST.scope(meta, f).await
}

pub async fn with_actor<F: Future>(actor: Option<UserId>, f: F) -> F::Output {
    with_request(current_request().with_actor(actor), f).await
}

pub fn current_request() -> RequestMeta {
    REQUEST.try_with(Clone::clone).unwrap_or_default()
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogEvent {
    pub timestamp: chrono::NaiveDateTime,
    pub kind: LogKind,
    pub success: bool,
    pub protocol: Protocol,
    pub actor: Option<String>,
    pub target: Option<String>,
    pub peer: Option<String>,
    pub forwarded_for: Option<String>,
    pub detail: Option<String>,
}

impl fmt::Display for LogEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {}",
            if self.success { "✅" } else { "❌" },
            self.kind
        )?;
        if let Some(target) = &self.target {
            write!(f, " {target}")?;
        }
        if let Some(actor) = &self.actor {
            write!(f, " by {actor}")?;
        }
        write!(f, " ({}", self.protocol)?;
        if let Some(peer) = &self.peer {
            write!(f, " {peer}")?;
        }
        f.write_str(")")?;
        if let Some(detail) = &self.detail {
            write!(f, ": {detail}")?;
        }
        Ok(())
    }
}

/// The kinds a lockout counts: the ones that check a password.
pub const LOGIN_KINDS: &[LogKind] = &[LogKind::Bind, LogKind::Login];

/// Every field narrows; `kinds` empty means any; `member_of*` restrict the actor to the
/// current members of a group.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LogFilter {
    pub actor: Option<UserId>,
    pub target: Option<String>,
    pub kinds: Vec<LogKind>,
    pub success: Option<bool>,
    pub protocol: Option<Protocol>,
    pub peer: Option<String>,
    pub since: Option<chrono::NaiveDateTime>,
    pub until: Option<chrono::NaiveDateTime>,
    pub member_of: Option<String>,
    pub member_of_id: Option<GroupId>,
}

/// `Newest` and `Before` page newest first; `After` pages forward, oldest first.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum LogCursor {
    #[default]
    Newest,
    Before(i64),
    After(i64),
}

#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    strum::Display,
    strum::EnumString,
    strum::IntoStaticStr,
    strum::EnumIter,
)]
#[strum(serialize_all = "snake_case")]
pub enum LogDimension {
    Actor,
    Target,
    Kind,
    Protocol,
    Peer,
    Success,
    Day,
    Hour,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogRecord {
    pub id: i64,
    pub event: LogEvent,
}

/// One row of a grouped count; only the grouped dimensions are set (`day` is
/// `YYYY-MM-DD`, `hour` 0-23, both UTC).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogBucket {
    pub actor: Option<String>,
    pub target: Option<String>,
    pub kind: Option<LogKind>,
    pub protocol: Option<Protocol>,
    pub peer: Option<String>,
    pub success: Option<bool>,
    pub day: Option<String>,
    pub hour: Option<u32>,
    pub count: u64,
    pub first: chrono::NaiveDateTime,
    pub last: chrono::NaiveDateTime,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogActivity {
    pub actor: UserId,
    pub last_success: Option<LogRecord>,
    pub last_failure: Option<LogRecord>,
    pub failures_since_last_success: u64,
}

pub trait LogSink: Send + Sync {
    fn record(&self, event: LogEvent);
}

pub struct NoopLogSink;

impl LogSink for NoopLogSink {
    fn record(&self, _: LogEvent) {}
}

// Process-global like the Kerberos backend, so call sites stay one-liners; tests that
// install a recorder must be #[serial] and restore the default on drop.
static SINK: LazyLock<RwLock<Arc<dyn LogSink>>> =
    LazyLock::new(|| RwLock::new(Arc::new(NoopLogSink)));

pub fn log_sink() -> Arc<dyn LogSink> {
    SINK.read().expect("log sink").clone()
}

pub fn set_log_sink(sink: Arc<dyn LogSink>) {
    *SINK.write().expect("log sink") = sink;
}

pub fn record(kind: LogKind, target: Option<&str>, detail: Option<&str>) {
    record_outcome(kind, target, true, detail);
}

pub fn record_failure(kind: LogKind, target: Option<&str>, detail: &str) {
    record_outcome(kind, target, false, Some(detail));
}

pub fn record_terminal(kind: LogKind, target: Option<&str>, detail: &str) {
    let meta = current_request();
    emit(&build(
        &meta,
        meta.actor.as_ref(),
        kind,
        target,
        false,
        Some(detail),
    ));
}

pub fn record_outcome(kind: LogKind, target: Option<&str>, success: bool, detail: Option<&str>) {
    let meta = current_request();
    record_event(build(
        &meta,
        meta.actor.as_ref(),
        kind,
        target,
        success,
        detail,
    ));
}

/// For authentication events the actor is the claimed identity, not a verified one.
pub fn record_as(
    actor: Option<&UserId>,
    kind: LogKind,
    target: Option<&str>,
    success: bool,
    detail: Option<&str>,
) {
    record_event(build(
        &current_request(),
        actor,
        kind,
        target,
        success,
        detail,
    ));
}

fn build(
    meta: &RequestMeta,
    actor: Option<&UserId>,
    kind: LogKind,
    target: Option<&str>,
    success: bool,
    detail: Option<&str>,
) -> LogEvent {
    LogEvent {
        timestamp: chrono::Utc::now().naive_utc(),
        kind,
        success,
        protocol: meta.protocol,
        actor: actor.map(|a| truncate(a.as_str(), MAX_NAME_LEN)),
        target: target.map(|t| truncate(t, MAX_NAME_LEN)),
        peer: meta.peer.map(|p| p.to_string()),
        forwarded_for: meta
            .forwarded_for
            .as_deref()
            .map(|f| truncate(f, MAX_NAME_LEN)),
        detail: detail.map(|d| truncate(d, MAX_DETAIL_LEN)),
    }
}

fn record_event(event: LogEvent) {
    emit(&event);
    log_sink().record(event);
}

enum Print {
    Yes,
    Suppressed,
    YesWithSummary(u64),
}

// One global limiter for every failure line: a flood must not fill the terminal the way it
// cannot fill the table. Counters gate output only, so Relaxed is enough; the table keeps
// every stored row either way.
struct WarnLimiter {
    window_start: AtomicU64,
    printed: AtomicU32,
    suppressed: AtomicU64,
}

impl WarnLimiter {
    const fn new() -> Self {
        Self {
            window_start: AtomicU64::new(0),
            printed: AtomicU32::new(0),
            suppressed: AtomicU64::new(0),
        }
    }

    fn should_print(&self, now: u64) -> Print {
        let start = self.window_start.load(Ordering::Relaxed);
        if (now < start || now - start >= WARN_WINDOW_SECS)
            && self
                .window_start
                .compare_exchange(start, now, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
        {
            self.printed.store(1, Ordering::Relaxed);
            let missed = self.suppressed.swap(0, Ordering::Relaxed);
            return if missed > 0 {
                Print::YesWithSummary(missed)
            } else {
                Print::Yes
            };
        }
        if self.printed.fetch_add(1, Ordering::Relaxed) < WARN_BUDGET {
            Print::Yes
        } else {
            self.suppressed.fetch_add(1, Ordering::Relaxed);
            Print::Suppressed
        }
    }

    // Claim the pending suppressed count once the window has elapsed, so an idle tick can
    // flush it. Same window-roll protocol as should_print, so the two never double-count.
    fn take_suppressed(&self, now: u64) -> Option<u64> {
        let start = self.window_start.load(Ordering::Relaxed);
        if now.saturating_sub(start) >= WARN_WINDOW_SECS
            && self
                .window_start
                .compare_exchange(start, now, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
        {
            self.printed.store(0, Ordering::Relaxed);
            let missed = self.suppressed.swap(0, Ordering::Relaxed);
            return (missed > 0).then_some(missed);
        }
        None
    }
}

static WARN_LIMITER: WarnLimiter = WarnLimiter::new();

/// Print the pending `suppressed N` summary once its window has elapsed, so a failure flood
/// that stops does not leave the terminal quiet with the count unaccounted for. Called on the
/// writer's idle tick; a no-op when nothing is pending.
pub fn flush_suppressed_warnings(now: u64) {
    if let Some(missed) = WARN_LIMITER.take_suppressed(now) {
        warn!(target: "logs", "suppressed {missed} failure lines");
    }
}

fn emit(event: &LogEvent) {
    match (event.success, event.kind) {
        (false, _) => {
            let now = chrono::Utc::now().timestamp().max(0) as u64;
            match WARN_LIMITER.should_print(now) {
                Print::Yes => warn!(target: "logs", "{event}"),
                Print::YesWithSummary(missed) => {
                    warn!(target: "logs", "suppressed {missed} failure lines");
                    warn!(target: "logs", "{event}");
                }
                Print::Suppressed => {}
            }
        }
        (true, LogKind::Bind | LogKind::Login | LogKind::TokenRefresh) => {
            debug!(target: "logs", "{event}")
        }
        (true, _) => info!(target: "logs", "{event}"),
    }
}

fn truncate(s: &str, max_chars: usize) -> String {
    let cleaned: String = s.chars().filter(|c| !c.is_control()).collect();
    match cleaned.char_indices().nth(max_chars) {
        Some((end, _)) => cleaned[..end].to_owned(),
        None => cleaned,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
    use serial_test::serial;
    use std::sync::Mutex;

    struct Recorder(Mutex<Vec<LogEvent>>);

    impl LogSink for Recorder {
        fn record(&self, event: LogEvent) {
            self.0.lock().unwrap().push(event);
        }
    }

    struct SinkGuard;
    impl Drop for SinkGuard {
        fn drop(&mut self) {
            set_log_sink(Arc::new(NoopLogSink));
        }
    }

    fn install_recorder() -> (Arc<Recorder>, SinkGuard) {
        let recorder = Arc::new(Recorder(Mutex::new(Vec::new())));
        set_log_sink(recorder.clone());
        (recorder, SinkGuard)
    }

    #[test]
    fn test_warn_limiter_budget_window_and_idle_flush() {
        let limiter = WarnLimiter::new();
        for i in 0..WARN_BUDGET {
            assert!(matches!(limiter.should_print(1000), Print::Yes), "{i}");
        }
        for _ in 0..5 {
            assert!(matches!(limiter.should_print(1000), Print::Suppressed));
        }
        assert!(matches!(limiter.should_print(1009), Print::Suppressed));
        assert!(matches!(
            limiter.should_print(1010),
            Print::YesWithSummary(6)
        ));
        assert!(matches!(limiter.should_print(1010), Print::Yes));

        let limiter = WarnLimiter::new();
        for _ in 0..WARN_BUDGET {
            limiter.should_print(1000);
        }
        for _ in 0..7 {
            assert!(matches!(limiter.should_print(1000), Print::Suppressed));
        }
        // Same window: nothing to flush yet; once elapsed the count is claimed exactly once
        // and the following failure gets the full fresh budget.
        assert_eq!(limiter.take_suppressed(1005), None);
        assert_eq!(limiter.take_suppressed(1010), Some(7));
        assert_eq!(limiter.take_suppressed(1010), None);
        assert!(matches!(limiter.should_print(1010), Print::Yes));

        let limiter = WarnLimiter::new();
        for _ in 0..WARN_BUDGET {
            limiter.should_print(1000);
        }
        assert!(matches!(limiter.should_print(1000), Print::Suppressed));
        // A quiet roll flushes the one suppressed line and the budget is fresh.
        assert!(matches!(
            limiter.should_print(2000),
            Print::YesWithSummary(1)
        ));
        for i in 0..(WARN_BUDGET - 1) {
            assert!(matches!(limiter.should_print(2000), Print::Yes), "{i}");
        }
        assert!(matches!(limiter.should_print(2000), Print::Suppressed));
        // A clock jump backwards starts a new window instead of muting forever.
        assert!(matches!(
            limiter.should_print(500),
            Print::YesWithSummary(1)
        ));
    }

    #[tokio::test]
    #[serial]
    async fn test_the_request_scope_decides_the_row_and_terminal_skips_the_sink() {
        let (recorder, _guard) = install_recorder();
        let meta = RequestMeta::ldap(
            Some(UserId::new("admin")),
            Some("10.0.0.5".parse().unwrap()),
        );
        with_request(meta, async {
            record(LogKind::UserDelete, Some("bob"), None);
        })
        .await;
        with_actor(Some(UserId::new("carol")), async {
            record_failure(LogKind::AccessDenied, None, "Unauthorized write");
        })
        .await;
        record_as(
            Some(&UserId::new("dave")),
            LogKind::Bind,
            None,
            false,
            Some("invalid credentials"),
        );
        record_terminal(LogKind::AccessDenied, None, "Invalid JWT");

        let events = recorder.0.lock().unwrap().clone();
        assert_eq!(events.len(), 3);
        assert_eq!(events[0].kind, LogKind::UserDelete);
        assert!(events[0].success);
        assert_eq!(events[0].protocol, Protocol::Ldap);
        assert_eq!(events[0].actor.as_deref(), Some("admin"));
        assert_eq!(events[0].target.as_deref(), Some("bob"));
        assert_eq!(events[0].peer.as_deref(), Some("10.0.0.5"));
        assert_eq!(
            events[0].to_string(),
            "✅ user_delete bob by admin (ldap 10.0.0.5)"
        );
        assert_eq!(events[1].protocol, Protocol::System);
        assert_eq!(events[1].actor.as_deref(), Some("carol"));
        assert!(!events[1].success);
        assert_eq!(events[1].peer, None);
        assert_eq!(
            events[2].to_string(),
            "❌ bind by dave (system): invalid credentials"
        );

        let meta = RequestMeta::http(Some("192.0.2.10".parse().unwrap()), Some("10.1.1.1".into()));
        let inner = with_request(meta.clone(), async {
            with_actor(Some(UserId::new("bob")), async { current_request() }).await
        })
        .await;
        assert_eq!(inner.actor, Some(UserId::new("bob")));
        assert_eq!(inner.protocol, Protocol::Http);
        assert_eq!(inner.peer, meta.peer);
        assert_eq!(inner.forwarded_for.as_deref(), Some("10.1.1.1"));
        assert_eq!(current_request(), RequestMeta::default());
    }

    #[test]
    fn test_build_truncates_and_strips_control_characters() {
        let long_name = "é".repeat(300);
        let long_detail = "x".repeat(600);
        let event = build(
            &RequestMeta::default(),
            Some(&UserId::new(&long_name)),
            LogKind::UserUpdate,
            Some(&long_name),
            true,
            Some(&long_detail),
        );
        assert_eq!(event.actor.as_ref().unwrap().chars().count(), MAX_NAME_LEN);
        assert_eq!(event.target.as_ref().unwrap().chars().count(), MAX_NAME_LEN);
        assert_eq!(
            event.detail.as_ref().unwrap().chars().count(),
            MAX_DETAIL_LEN
        );
        assert_eq!(truncate("short", 10), "short");

        let event = build(
            &RequestMeta {
                forwarded_for: Some("203.0.113.9\nINFO pwned".into()),
                ..RequestMeta::default()
            },
            Some(&UserId::new("adm\nin")),
            LogKind::Bind,
            Some("uid=bob\r,ou=people"),
            false,
            Some("bad\tdetail"),
        );
        assert_eq!(event.actor.as_deref(), Some("admin"));
        assert_eq!(event.target.as_deref(), Some("uid=bob,ou=people"));
        assert_eq!(event.detail.as_deref(), Some("baddetail"));
        assert_eq!(
            event.forwarded_for.as_deref(),
            Some("203.0.113.9INFO pwned")
        );
        assert!(!event.to_string().contains('\n'));
    }
}
