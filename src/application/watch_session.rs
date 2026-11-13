//! Use case: watch mode. Feed it each new report; it speaks only for the baseline and for changes.
use crate::domain::model::Report;
use crate::domain::report::{describe_changes, fingerprint};
use serde::Serialize;

pub const WATCH_INTERVAL_SECS: u64 = 30 * 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum WatchKind {
    Baseline,
    Change,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WatchEvent {
    pub at: String,
    pub kind: WatchKind,
    pub lines: Vec<String>,
}

#[derive(Default)]
pub struct WatchSession {
    baseline: Option<Report>,
    pub quiet_runs: u32,
}

impl WatchSession {
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns an event for the first report and for any change; None when nothing changed.
    pub fn observe(&mut self, report: &Report) -> Option<WatchEvent> {
        let before = self.baseline.replace(report.clone());
        let Some(before) = before else {
            let score = report.score.provisional.map_or("unknown".to_string(), |s| s.to_string());
            return Some(WatchEvent {
                at: report.generated_at.clone(),
                kind: WatchKind::Baseline,
                lines: vec![format!("Score {score}, coverage {}%", report.score.coverage_percent)],
            });
        };
        if fingerprint(&before) == fingerprint(report) {
            self.quiet_runs += 1;
            return None;
        }
        self.quiet_runs = 0;
        Some(WatchEvent { at: report.generated_at.clone(), kind: WatchKind::Change, lines: describe_changes(&before, report) })
    }
}
