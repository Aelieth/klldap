//! For tests only: the lines one thread prints, counted against a budget of that thread's own.
use super::{WARN_BUDGET, count_lines_alone};
use std::sync::{Arc, LazyLock, Mutex, PoisonError};
use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id, Record};
use tracing::subscriber::{DefaultGuard, NoSubscriber};
use tracing::{Dispatch, Event, Level, Metadata, Subscriber};

/// The failure lines' budget of one window.
pub const BUDGET: usize = WARN_BUDGET as usize;

// A second subscriber that stays registered: with one alone, tracing keeps for a call site the
// answer of the thread that reaches it first, and a thread with no subscriber answers never.
static SECOND: LazyLock<Dispatch> = LazyLock::new(|| Dispatch::new(NoSubscriber::default()));

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Line {
    pub level: Level,
    pub target: String,
    pub text: String,
}

#[derive(Clone, Default)]
pub struct Lines(Arc<Mutex<Vec<Line>>>);

/// KLLDAP's lines and the KDC's; a library's own, as sqlx's one per statement, are left out.
fn ours(target: &str) -> bool {
    target == "logs" || target == "krb5_klog" || target.starts_with("lldap")
}

struct Text(String);

impl Visit for Text {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.0 = format!("{value:?}");
        }
    }
}

impl Subscriber for Lines {
    fn enabled(&self, _: &Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, _: &Attributes<'_>) -> Id {
        Id::from_u64(1)
    }
    fn record(&self, _: &Id, _: &Record<'_>) {}
    fn record_follows_from(&self, _: &Id, _: &Id) {}
    fn event(&self, event: &Event<'_>) {
        if !ours(event.metadata().target()) {
            return;
        }
        let mut text = Text(String::new());
        event.record(&mut text);
        let line = Line {
            level: *event.metadata().level(),
            target: event.metadata().target().to_owned(),
            text: text.0,
        };
        self.held().push(line);
    }
    fn enter(&self, _: &Id) {}
    fn exit(&self, _: &Id) {}
}

impl Lines {
    /// This thread's lines from here until the guard drops.
    pub fn capture() -> (Self, DefaultGuard) {
        LazyLock::force(&SECOND);
        count_lines_alone();
        let lines = Self::default();
        let guard = tracing::subscriber::set_default(lines.clone());
        (lines, guard)
    }

    fn held(&self) -> std::sync::MutexGuard<'_, Vec<Line>> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Every line so far, in order; the next call starts after them.
    pub fn take(&self) -> Vec<Line> {
        std::mem::take(&mut *self.held())
    }

    /// The lines so far at INFO, WARN and ERROR, in order; the next call starts after them.
    pub fn take_loud(&self) -> Vec<Line> {
        let loud = |line: &Line| line.level <= Level::INFO;
        self.take().into_iter().filter(loud).collect()
    }
}
