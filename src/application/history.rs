//! Use case: keep a trend of the audits and show it.
use crate::domain::history::{point_from, with_point, HistoryPoint};
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

    pub fn clear(&self) -> bool {
        self.store.clear()
    }
}
