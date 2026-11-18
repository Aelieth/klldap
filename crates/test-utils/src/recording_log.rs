use lldap_domain_handlers::logging::{LogEvent, LogSink, NoopLogSink, set_log_sink};
use std::sync::{Arc, Mutex};
use std::thread::ThreadId;

pub struct RecordingLog {
    events: Mutex<Vec<LogEvent>>,
    only: Option<ThreadId>,
}

impl RecordingLog {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            events: Mutex::new(Vec::new()),
            only: None,
        })
    }

    pub fn take_events(&self) -> Vec<LogEvent> {
        self.events.lock().expect("events").drain(..).collect()
    }
}

impl LogSink for RecordingLog {
    fn record(&self, event: LogEvent) {
        if self
            .only
            .is_some_and(|id| id != std::thread::current().id())
        {
            return;
        }
        self.events.lock().expect("events").push(event);
    }
}

pub struct LogGuard {
    rec: Arc<RecordingLog>,
}

impl LogGuard {
    /// Installs the recorder as the process-global sink; the test must be `#[serial]`.
    pub fn install() -> Self {
        let rec = RecordingLog::new();
        set_log_sink(rec.clone());
        Self { rec }
    }

    /// As `install`, keeping only this thread's events: tests outside `#[serial]` log too.
    pub fn install_on_this_thread() -> Self {
        let rec = Arc::new(RecordingLog {
            events: Mutex::new(Vec::new()),
            only: Some(std::thread::current().id()),
        });
        set_log_sink(rec.clone());
        Self { rec }
    }

    pub fn recorder(&self) -> &RecordingLog {
        &self.rec
    }
}

impl Drop for LogGuard {
    fn drop(&mut self) {
        set_log_sink(Arc::new(NoopLogSink));
    }
}
