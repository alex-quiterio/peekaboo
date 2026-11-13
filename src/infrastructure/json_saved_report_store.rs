//! Stores each saved report as one file under a single folder, named by the label's key. Nothing else is written.
use crate::domain::ports::SavedReportStore;
use crate::domain::saved::{label_key, parse_saved_report, SavedReport};
use regex::Regex;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

/// What `label_key` can produce. Anything else in the folder is not ours and is never read.
static FILE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[a-z0-9-]+\.json$").unwrap());

pub struct JsonSavedReportStore {
    directory: PathBuf,
}

impl JsonSavedReportStore {
    pub fn new(directory: PathBuf) -> Self {
        Self { directory }
    }

    fn file_for(&self, label: &str) -> Option<PathBuf> {
        Some(self.directory.join(format!("{}.json", label_key(label).ok()?)))
    }

    fn read(file: &Path) -> Option<SavedReport> {
        parse_saved_report(&fs::read_to_string(file).ok()?)
    }
}

impl SavedReportStore for JsonSavedReportStore {
    fn list(&self) -> Vec<SavedReport> {
        let Ok(entries) = fs::read_dir(&self.directory) else { return vec![] };
        entries
            .flatten()
            .filter(|e| e.file_name().to_str().is_some_and(|n| FILE.is_match(n)))
            .filter_map(|e| Self::read(&e.path()))
            .collect()
    }

    fn get(&self, label: &str) -> Option<SavedReport> {
        Self::read(&self.file_for(label)?)
    }

    fn save(&self, saved: &SavedReport) -> Result<(), String> {
        let file = self.file_for(&saved.label).ok_or("invalid name")?;
        fs::create_dir_all(&self.directory).map_err(|e| e.to_string())?;
        let json = serde_json::to_string_pretty(saved).map_err(|e| e.to_string())? + "\n";
        fs::write(file, json).map_err(|e| e.to_string())
    }

    fn remove(&self, label: &str) -> bool {
        self.file_for(label).is_some_and(|file| fs::remove_file(file).is_ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::model::Report;

    fn report() -> Report {
        serde_json::from_str(include_str!("../../tests/fixtures/typescript-report.json")).unwrap()
    }
    fn saved(label: &str, at: &str) -> SavedReport {
        SavedReport { label: label.into(), saved_at: at.into(), report: report() }
    }
    fn temp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("peekaboo-test-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn saves_one_file_per_name_reads_it_back_and_replaces_on_the_same_name() {
        let dir = temp("save");
        let store = JsonSavedReportStore::new(dir.join("nested"));
        store.save(&saved("Amsterdam work", "a")).unwrap();
        store.save(&saved("Home", "b")).unwrap();
        store.save(&saved("home", "c")).unwrap();
        assert_eq!(fs::read_dir(dir.join("nested")).unwrap().count(), 2);
        assert_eq!(store.get("HOME").unwrap().saved_at, "c");
        let mut labels: Vec<_> = store.list().into_iter().map(|s| s.label).collect();
        labels.sort();
        assert_eq!(labels, ["Amsterdam work", "home"]);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn writes_only_inside_its_folder_whatever_the_name() {
        let dir = temp("inside");
        let store = JsonSavedReportStore::new(dir.clone());
        store.save(&saved("a.b", "a")).unwrap();
        let names: Vec<_> = fs::read_dir(&dir).unwrap().flatten().map(|e| e.file_name().into_string().unwrap()).collect();
        assert_eq!(names, [format!("{}.json", label_key("a.b").unwrap())]);
        assert!(store.save(&saved("../x", "a")).is_err());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn ignores_files_it_did_not_write_and_files_that_are_not_saved_reports() {
        let dir = temp("ignore");
        let store = JsonSavedReportStore::new(dir.clone());
        store.save(&saved("Home", "a")).unwrap();
        fs::write(dir.join("notes.txt"), "hello").unwrap();
        fs::write(dir.join("broken-00000000.json"), "{not json").unwrap();
        fs::write(dir.join("wrong-00000000.json"), r#"{"label":"x","report":{}}"#).unwrap();
        let labels: Vec<_> = store.list().into_iter().map(|s| s.label).collect();
        assert_eq!(labels, ["Home"]);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn removing_reports_whether_anything_was_there_and_a_missing_folder_is_just_empty() {
        let dir = temp("remove");
        let store = JsonSavedReportStore::new(dir.join("none"));
        assert!(store.list().is_empty());
        assert!(store.get("Home").is_none());
        store.save(&saved("Home", "a")).unwrap();
        assert!(store.remove("Home"));
        assert!(!store.remove("Home"));
        let _ = fs::remove_dir_all(dir);
    }
}
