//! Stores exactly two files: sanitized-report.json and previous-sanitized-report.json.
use crate::domain::model::Report;
use crate::domain::ports::ReportRepository;
use std::fs;
use std::path::{Path, PathBuf};

pub struct JsonReportRepository {
    latest: PathBuf,
    previous: PathBuf,
}

impl JsonReportRepository {
    pub fn new(directory: &Path) -> Self {
        Self { latest: directory.join("sanitized-report.json"), previous: directory.join("previous-sanitized-report.json") }
    }

    fn read(file: &Path) -> Option<Report> {
        serde_json::from_str(&fs::read_to_string(file).ok()?).ok()
    }
}

impl ReportRepository for JsonReportRepository {
    fn latest(&self) -> Option<Report> {
        Self::read(&self.latest)
    }

    fn previous(&self) -> Option<Report> {
        Self::read(&self.previous)
    }

    fn save(&self, report: &Report) -> Result<(), String> {
        if let Some(dir) = self.latest.parent() {
            fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        }
        if self.latest.exists() {
            let _ = fs::remove_file(&self.previous); // Windows cannot rename over an existing file
            fs::rename(&self.latest, &self.previous).map_err(|e| e.to_string())?;
        }
        let json = serde_json::to_string_pretty(report).map_err(|e| e.to_string())? + "\n";
        fs::write(&self.latest, json).map_err(|e| e.to_string())
    }
}
