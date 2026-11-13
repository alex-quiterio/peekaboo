//! Use case: keep audits under a name and compare them. Saving happens only when this is called with a name.
use crate::domain::compare::{compare_reports, ReportComparison};
use crate::domain::gateway::SafetyStop;
use crate::domain::model::Report;
use crate::domain::ports::{Clock, ReportRepository, SavedReportStore};
use crate::domain::saved::*;
use std::sync::Arc;

pub const CURRENT_AUDIT: &str = "Current audit";

pub struct SavedReports {
    store: Arc<dyn SavedReportStore>,
    reports: Arc<dyn ReportRepository>,
    clock: Arc<dyn Clock>,
}

impl SavedReports {
    pub fn new(store: Arc<dyn SavedReportStore>, reports: Arc<dyn ReportRepository>, clock: Arc<dyn Clock>) -> Self {
        Self { store, reports, clock }
    }

    /// Most recently saved first.
    pub fn list(&self) -> Vec<SavedReportSummary> {
        let mut summaries: Vec<_> = self.store.list().iter().map(summarise).collect();
        summaries.sort_by(|a, b| b.saved_at.cmp(&a.saved_at));
        summaries
    }

    /// Keeps the most recent audit under `label_input`, replacing a report that already has that name.
    pub fn save_current(&self, label_input: Option<&str>) -> Result<SavedReportSummary, SafetyStop> {
        let label = parse_label(label_input)?;
        let report = self.reports.latest().ok_or_else(|| SafetyStop::new("There is no audit to save yet. Run one first."))?;
        let key = label_key(&label)?;
        let existing = self.store.list();
        let replacing = existing.iter().any(|s| label_key(&s.label).ok().as_deref() == Some(key.as_str()));
        if !replacing && existing.len() >= MAX_SAVED_REPORTS {
            return Err(SafetyStop::new(format!("You can keep up to {MAX_SAVED_REPORTS} saved reports. Delete one first.")));
        }
        let saved = SavedReport { label, saved_at: self.clock.now_iso(), report };
        self.store.save(&saved).map_err(|_| SafetyStop::new("The report could not be saved. Nothing was changed."))?;
        Ok(summarise(&saved))
    }

    pub fn remove(&self, label_input: Option<&str>) -> Result<(), SafetyStop> {
        let label = parse_label(label_input)?;
        if self.store.remove(&label) {
            Ok(())
        } else {
            Err(SafetyStop::new(format!("There is no saved report named \"{label}\".")))
        }
    }

    fn resolve(&self, label_input: Option<&str>) -> Result<(String, Report), SafetyStop> {
        match label_input {
            None | Some("") => {
                let report = self.reports.latest().ok_or_else(|| SafetyStop::new("There is no current audit yet. Run one first."))?;
                Ok((CURRENT_AUDIT.to_string(), report))
            }
            Some(input) => {
                let label = parse_label(Some(input))?;
                let saved = self.store.get(&label).ok_or_else(|| SafetyStop::new(format!("There is no saved report named \"{label}\".")))?;
                Ok((saved.label, saved.report))
            }
        }
    }

    /// An omitted side is the most recent audit. Comparing a report with itself is refused as pointless.
    pub fn compare(&self, left: Option<&str>, right: Option<&str>) -> Result<ReportComparison, SafetyStop> {
        let a = self.resolve(left)?;
        let b = self.resolve(right)?;
        if a.0 == b.0 {
            return Err(SafetyStop::new("Pick two different reports to compare."));
        }
        Ok(compare_reports((&a.0, &a.1), (&b.0, &b.1)))
    }
}
