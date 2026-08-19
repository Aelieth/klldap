use lldap_domain_handlers::logging::{LogEvent, LogSink, NoopLogSink, set_log_sink};
use std::sync::{Arc, Mutex};

pub struct RecordingLog {
    events: Mutex<Vec<LogEvent>>,
}

impl RecordingLog {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            events: Mutex::new(Vec::new()),
        })
    }

    pub fn take_events(&self) -> Vec<LogEvent> {
        self.events.lock().expect("events").drain(..).collect()
    }
}

impl LogSink for RecordingLog {
    fn record(&self, event: LogEvent) {
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

    pub fn recorder(&self) -> &RecordingLog {
        &self.rec
    }
}

impl Drop for LogGuard {
    fn drop(&mut self) {
        set_log_sink(Arc::new(NoopLogSink));
    }
}
