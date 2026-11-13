//! Reports the user chose to keep under a name. They are the same sanitized reports the audit produces; the
//! name is the only text the user adds, so it is held to a plain, short vocabulary.
use super::gateway::SafetyStop;
use super::model::Report;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::sync::LazyLock;
use unicode_normalization::UnicodeNormalization;

pub const MAX_SAVED_REPORTS: usize = 50;
const MAX_LABEL_LENGTH: usize = 40;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SavedReport {
    pub label: String,
    pub saved_at: String,
    pub report: Report,
}

/// What the lists show, without the whole report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SavedReportSummary {
    pub label: String,
    pub saved_at: String,
    pub generated_at: String,
    pub score: Option<u32>,
    pub coverage_percent: u32,
}

static LABEL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[\p{L}\p{N}][\p{L}\p{N} _.,'()-]*$").unwrap());
static SPACES: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\s+").unwrap());

/// Letters, digits, spaces and . , ' ( ) _ - only, so a label can never be a path, markup or a command.
pub fn parse_label(input: Option<&str>) -> Result<String, SafetyStop> {
    let label = input.map(|s| SPACES.replace_all(s.nfc().collect::<String>().trim(), " ").into_owned()).unwrap_or_default();
    if label.is_empty() || label.chars().count() > MAX_LABEL_LENGTH || !LABEL.is_match(&label) {
        return Err(SafetyStop::new(format!(
            "Give the report a name of 1 to {MAX_LABEL_LENGTH} characters: letters, digits, spaces, and the characters . , ' ( ) _ -."
        )));
    }
    Ok(label)
}

/// A file-safe identity for a label. Two labels differing only in case share one key, so saving "home" replaces
/// "Home". The hash keeps keys apart when the readable part collides ("Home wifi" and "home-wifi").
/// Same keys as the TypeScript version, so files saved by either are found by both.
pub fn label_key(label: &str) -> Result<String, SafetyStop> {
    let folded = parse_label(Some(label))?.to_lowercase();
    let mut hash: u32 = 0x811c_9dc5;
    for c in folded.chars() {
        hash = (hash ^ c as u32).wrapping_mul(0x0100_0193);
    }
    let ascii: String = folded.nfkd().map(|c| if c.is_ascii_alphanumeric() { c } else { '-' }).collect();
    let readable: String = ascii.split('-').filter(|s| !s.is_empty()).collect::<Vec<_>>().join("-").chars().take(30).collect();
    let readable = readable.trim_end_matches('-');
    Ok(format!("{}-{hash:08x}", if readable.is_empty() { "report" } else { readable }))
}

pub fn summarise(saved: &SavedReport) -> SavedReportSummary {
    SavedReportSummary {
        label: saved.label.clone(),
        saved_at: saved.saved_at.clone(),
        generated_at: saved.report.generated_at.clone(),
        score: saved.report.score.provisional,
        coverage_percent: saved.report.score.coverage_percent,
    }
}

/// Saved files can be edited by hand, so anything that is not a report of the expected shape is left out.
pub fn parse_saved_report(json: &str) -> Option<SavedReport> {
    let saved: SavedReport = serde_json::from_str(json).ok()?;
    parse_label(Some(&saved.label)).ok()?;
    Some(saved)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_plain_names_trimmed_and_with_single_spaces() {
        assert_eq!(parse_label(Some("  Amsterdam   work ")).unwrap(), "Amsterdam work");
        assert_eq!(parse_label(Some("Café 2.4")).unwrap(), "Café 2.4");
        assert_eq!(parse_label(Some("home_wifi-1")).unwrap(), "home_wifi-1");
        assert_eq!(parse_label(Some("Office (Amsterdam), 3rd floor")).unwrap(), "Office (Amsterdam), 3rd floor");
        assert_eq!(parse_label(Some("Home - Living room")).unwrap(), "Home - Living room");
        assert_eq!(parse_label(Some("a\nb\t c")).unwrap(), "a b c");
    }

    #[test]
    fn refuses_anything_that_could_be_a_path_markup_or_too_long() {
        let long = "x".repeat(41);
        for bad in ["", "   ", "../etc", "a/b", "a\\b", "<b>x</b>", ".hidden", "-x", &long, "a\u{0}b", "a\u{202e}b", "a;b", "a$(x)", "a`b`", "a|b", "a&b", "a\"b"] {
            assert!(parse_label(Some(bad)).is_err(), "{bad:?}");
        }
        assert!(parse_label(None).is_err());
    }

    #[test]
    fn keys_are_file_safe_case_insensitive_and_keep_look_alike_names_apart() {
        assert_eq!(label_key("Home").unwrap(), label_key("home").unwrap());
        assert_ne!(label_key("Home wifi").unwrap(), label_key("home-wifi").unwrap());
        let key = label_key("Amsterdam work").unwrap();
        assert!(Regex::new(r"^amsterdam-work-[0-9a-f]{8}$").unwrap().is_match(&key), "{key}");
        assert!(label_key("家").unwrap().starts_with("report-"));
        for label in ["Café 2.4", "a.b", "x_y", "Office (Amsterdam)", "it's, ok"] {
            let key = label_key(label).unwrap();
            assert!(key.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'), "{key}");
        }
    }

    #[test]
    fn keys_match_the_ones_the_typescript_version_wrote() {
        // File names taken from real saved reports.
        assert_eq!(label_key("Home - Living room").unwrap(), "home-living-room-c93c0f79");
        assert_eq!(label_key("Home - Kitchen").unwrap(), "home-kitchen-9a9767a9");
        assert_eq!(label_key("Test A").unwrap(), "test-a-f341215a");
        assert_eq!(label_key("Test B").unwrap(), "test-b-f2411fc7");
    }

    #[test]
    fn a_saved_file_is_trusted_only_when_it_is_shaped_like_one() {
        assert!(parse_saved_report("{}").is_none());
        assert!(parse_saved_report("not json").is_none());
        assert!(parse_saved_report(r#"{"label":"../x","savedAt":"x","report":{}}"#).is_none());
    }
}
