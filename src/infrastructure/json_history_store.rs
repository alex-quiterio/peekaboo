//! Stores the trend as one file, `history.json`. Numbers and times only.
use crate::domain::history::HistoryPoint;
use crate::domain::ports::HistoryStore;
use std::fs;
use std::path::{Path, PathBuf};

pub struct JsonHistoryStore {
    file: PathBuf,
}

impl JsonHistoryStore {
    pub fn new(directory: &Path) -> Self {
        Self { file: directory.join("history.json") }
    }
}

impl HistoryStore for JsonHistoryStore {
    fn load(&self) -> Vec<HistoryPoint> {
        fs::read_to_string(&self.file).ok().and_then(|text| serde_json::from_str(&text).ok()).unwrap_or_default()
    }

    fn save(&self, points: &[HistoryPoint]) -> Result<(), String> {
        if let Some(dir) = self.file.parent() {
            fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        }
        fs::write(&self.file, serde_json::to_string(points).map_err(|e| e.to_string())? + "\n").map_err(|e| e.to_string())
    }

    fn clear(&self) -> bool {
        fs::remove_file(&self.file).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn point(at: &str) -> HistoryPoint {
        HistoryPoint { at: at.into(), score: Some(90), coverage_percent: 59, link_rate_mbps: Some(433), signal_dbm: Some(-40), router_ms: Some(6), isp_ms: None, band: None }
    }

    #[test]
    fn saves_loads_and_clears() {
        let dir = std::env::temp_dir().join(format!("peekaboo-test-history-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let store = JsonHistoryStore::new(&dir.join("nested"));
        assert!(store.load().is_empty());
        assert!(!store.clear());
        store.save(&[point("a"), point("b")]).unwrap();
        assert_eq!(store.load(), [point("a"), point("b")]);
        assert!(store.clear());
        assert!(store.load().is_empty());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn a_damaged_file_is_an_empty_trend() {
        let dir = std::env::temp_dir().join(format!("peekaboo-test-history-bad-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("history.json"), "{not json").unwrap();
        assert!(JsonHistoryStore::new(&dir).load().is_empty());
        let _ = fs::remove_dir_all(dir);
    }
}
