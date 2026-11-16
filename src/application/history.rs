//! Use case: keep a trend of the audits and show it.
use crate::domain::history::{point_from, with_point, with_speed, HistoryPoint};
use crate::domain::speed_test::SpeedTestResult;
use crate::domain::model::Report;
use crate::domain::ports::HistoryStore;
use std::sync::Arc;

pub struct History {
    store: Arc<dyn HistoryStore>,
}

impl History {
    pub fn new(store: Arc<dyn HistoryStore>) -> Self {
        Self { store }
    }

    /// Oldest first.
    pub fn list(&self) -> Vec<HistoryPoint> {
        self.store.load()
    }

    /// Adds this audit to the trend. Best effort: an audit never fails because the trend could not be written.
    pub fn record(&self, report: &Report) {
        let _ = self.store.save(&with_point(self.store.load(), point_from(report)));
    }

    /// Adds the speed test figures to the audit taken at `audit_at`. Best effort, like `record`.
    pub fn record_speed(&self, audit_at: &str, result: &SpeedTestResult) {
        let _ = self.store.save(&with_speed(self.store.load(), audit_at, result));
    }

    pub fn clear(&self) -> bool {
        self.store.clear()
    }
}
