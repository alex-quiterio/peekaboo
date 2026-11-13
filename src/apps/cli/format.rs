//! Terminal presentation shared by the scan, watch and reports commands.
use crate::domain::compare::{Better, ReportComparison};
use crate::domain::evidence::parse_dns;
use crate::domain::gateway::SafetyStop;
use crate::domain::history::{range, series, sparkline, HistoryPoint};
use crate::domain::model::{DnsStatus, Report};
use crate::domain::saved::{parse_label, SavedReportSummary};

pub struct ScanOptions {
    pub dns: DnsStatus,
    pub isp_latency: bool,
    pub save: Option<String>,
}

/// The only flags are --dns, --isp-latency and (for scan) --save <name>. Anything else, including any kind of
/// target, is rejected. A bad name is refused now, so it stops the run before anything is measured.
pub fn options_from_args(args: &[String], allow_save: bool) -> Result<ScanOptions, SafetyStop> {
    let refuse = || SafetyStop::new(if allow_save {
        "The only options are --dns encrypted|plaintext|unknown, --isp-latency and --save <name>."
    } else {
        "The only options are --dns encrypted|plaintext|unknown and --isp-latency."
    });
    let (mut dns, mut isp_latency, mut save) = (None, false, None);
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        let (flag, inline) = match arg.split_once('=') {
            Some((flag, value)) if arg.starts_with("--") => (flag, Some(value.to_string())),
            _ => (arg.as_str(), None),
        };
        let mut value = || inline.clone().or_else(|| args.next().cloned()).ok_or_else(refuse);
        match flag {
            "--dns" => dns = Some(value()?),
            "--save" if allow_save => save = Some(value()?),
            "--isp-latency" if inline.is_none() => isp_latency = true,
            _ => return Err(refuse()),
        }
    }
    Ok(ScanOptions {
        dns: parse_dns(dns.as_deref())?,
        isp_latency,
        save: save.map(|s| parse_label(Some(&s))).transpose()?,
    })
}

pub fn format_report(report: &Report) -> String {
    let mut findings: Vec<_> = report.findings.iter().collect();
    findings.sort_by_key(|f| f.severity.rank());
    let mut lines = vec!["Peekaboo: Home Network Privacy Check".to_string(), format!("Target: {}", report.target), String::new()];
    lines.extend(findings.iter().map(|f| format!("[{}] {}", f.severity.label(), f.message)));
    lines.push(String::new());
    lines.push(match report.score.provisional {
        None => "Provisional score: Unknown (nothing could be measured)".to_string(),
        Some(score) => format!("Provisional score: {score}/100 from {}% evidence coverage", report.score.coverage_percent),
    });
    if let Some(c) = &report.comparison {
        lines.push(format!("Before/after: {} -> {} ({}{})", c.previous_score, c.current_score, if c.delta >= 0 { "+" } else { "" }, c.delta));
    }
    if !report.top_fixes.is_empty() {
        lines.push(String::new());
        lines.push("Top fixes:".to_string());
        lines.extend(report.top_fixes.iter().enumerate().map(|(i, fix)| format!("  {}. {fix}", i + 1)));
    }
    if !report.speed_tips.is_empty() {
        lines.push(String::new());
        lines.push("Make the Wi-Fi faster:".to_string());
        lines.extend(report.speed_tips.iter().enumerate().map(|(i, tip)| format!("  {}. {tip}", i + 1)));
    }
    lines.push(String::new());
    lines.push("Saved sanitized-report.json".to_string());
    lines.join("\n")
}

/// "2026-11-13T14:05:03.924Z" as "2026-11-13 14:05 UTC".
pub fn when(iso: &str) -> String {
    format!("{} UTC", iso.get(..16).unwrap_or(iso).replace('T', " "))
}

pub fn format_saved_list(saved: &[SavedReportSummary]) -> String {
    if saved.is_empty() {
        return "No saved reports yet. Run an audit, then: peekaboo reports save \"Home\"".to_string();
    }
    let width = saved.iter().map(|s| s.label.chars().count()).max().unwrap_or(0);
    let mut lines = vec!["Saved reports".to_string(), String::new()];
    lines.extend(saved.iter().map(|s| {
        let score = s.score.map_or("unknown".to_string(), |s| s.to_string());
        format!("  {:<width$}  score {score}, {}% coverage, audited {}", s.label, s.coverage_percent, when(&s.generated_at))
    }));
    lines.join("\n")
}

/// A table with a mark beside the better value of each row.
pub fn format_comparison(c: &ReportComparison) -> String {
    let cell = |value: &Option<String>, mark: bool| format!("{}{}", value.as_deref().unwrap_or("Unknown"), if mark { " *" } else { "" });
    let mut table: Vec<[String; 3]> = vec![[String::new(), c.left.name.clone(), c.right.name.clone()]];
    table.extend(c.rows.iter().map(|r| [r.label.clone(), cell(&r.left, r.better == Some(Better::Left)), cell(&r.right, r.better == Some(Better::Right))]));
    let widths: Vec<usize> = (0..3).map(|i| table.iter().map(|r| r[i].chars().count()).max().unwrap_or(0)).collect();
    let line = |row: &[String; 3]| row.iter().enumerate().map(|(i, c)| format!("{:<w$}", c, w = widths[i])).collect::<Vec<_>>().join("   ").trim_end().to_string();

    let mut lines = vec!["Comparison".to_string(), String::new(), line(&table[0]), widths.iter().map(|w| "-".repeat(*w)).collect::<Vec<_>>().join("   ")];
    lines.extend(table[1..].iter().map(line));
    lines.push(String::new());
    lines.push(format!(
        "* = better. {} is better on {}, {} on {}. Unknown values are never marked.",
        c.left.name, c.wins.left, c.right.name, c.wins.right
    ));
    for note in &c.notes {
        lines.push(String::new());
        lines.push(format!("Note: {note}"));
    }
    for (name, only) in [(&c.left.name, &c.only_left), (&c.right.name, &c.only_right)] {
        if !only.is_empty() {
            lines.push(String::new());
            lines.push(format!("Only on {name}:"));
            lines.extend(only.iter().map(|m| format!("  - {m}")));
        }
    }
    lines.join("\n")
}

/// How many of the latest audits the sparklines and the table show.
const HISTORY_SHOWN: usize = 40;
const HISTORY_ROWS: usize = 10;

/// Sparklines for the main measures, then the latest audits one per line.
pub fn format_history(points: &[HistoryPoint]) -> String {
    if points.is_empty() {
        return "No history yet. Every audit adds a point; `peekaboo watch` adds one every 30 minutes.".to_string();
    }
    let shown = &points[points.len().saturating_sub(HISTORY_SHOWN)..];
    let mut lines = vec![
        format!("History: {} audit{}, {} to {}", points.len(), if points.len() == 1 { "" } else { "s" }, when(&points[0].at), when(&points[points.len() - 1].at)),
        String::new(),
    ];
    type Measure = (&'static str, &'static str, fn(&HistoryPoint) -> Option<f64>);
    let measures: [Measure; 5] = [
        ("Score", "", |p| p.score.map(f64::from)),
        ("Link rate", " Mbps", |p| p.link_rate_mbps.map(f64::from)),
        ("Signal", " dBm", |p| p.signal_dbm.map(f64::from)),
        ("Router delay", " ms", |p| p.router_ms.map(f64::from)),
        ("ISP delay", " ms", |p| p.isp_ms.map(f64::from)),
    ];
    for (name, unit, pick) in measures {
        let values = series(shown, pick);
        let summary = match (range(&values), values.iter().rev().flatten().next()) {
            (Some((min, max)), Some(latest)) => format!("latest {latest}{unit}  ({min} to {max})"),
            _ => "no data".to_string(),
        };
        lines.push(format!("  {name:<13} {}  {summary}", sparkline(&values)));
    }
    lines.push(String::new());
    lines.push("Latest audits:".to_string());
    for p in points.iter().rev().take(HISTORY_ROWS) {
        let cell = |v: Option<String>| v.unwrap_or_else(|| "?".to_string());
        let row = format!(
            "  {}  score {:<3}  {:<9}  {:<8}  {} / {} ms  {}",
            when(&p.at),
            cell(p.score.map(|s| s.to_string())),
            cell(p.link_rate_mbps.map(|r| format!("{r} Mbps"))),
            cell(p.signal_dbm.map(|s| format!("{s} dBm"))),
            cell(p.router_ms.map(|m| m.to_string())),
            cell(p.isp_ms.map(|m| m.to_string())),
            p.band.map_or("", |b| b.as_str()),
        );
        lines.push(row.trim_end().to_string());
    }
    lines.join("\n")
}

/// Prints a message that is safe to show.
pub fn stop_safely(error: &SafetyStop) {
    eprintln!("{error}");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn accepts_the_three_options_and_nothing_else() {
        let o = options_from_args(&args(&["--dns", "encrypted", "--isp-latency", "--save", "Amsterdam work"]), true).unwrap();
        assert_eq!((o.dns, o.isp_latency, o.save.as_deref()), (DnsStatus::Encrypted, true, Some("Amsterdam work")));
        let o = options_from_args(&args(&["--dns=plaintext", "--save=Home"]), true).unwrap();
        assert_eq!((o.dns, o.save.as_deref()), (DnsStatus::Plaintext, Some("Home")));
        let o = options_from_args(&[], true).unwrap();
        assert_eq!((o.dns, o.isp_latency, o.save), (DnsStatus::Unknown, false, None));
    }

    #[test]
    fn refuses_targets_unknown_flags_bad_values_and_bad_names() {
        for bad in [&["--target", "1.2.3.4"][..], &["192.168.1.1"], &["--dns"], &["--dns", "8.8.8.8"], &["--isp-latency=yes"], &["--save", "../x"], &["--save"]] {
            assert!(options_from_args(&args(bad), true).is_err(), "{bad:?}");
        }
        assert!(options_from_args(&args(&["--save", "Home"]), false).is_err(), "watch cannot save");
    }

    fn point(at: &str, score: u32, link: Option<u32>) -> HistoryPoint {
        HistoryPoint { at: at.into(), score: Some(score), coverage_percent: 59, link_rate_mbps: link, signal_dbm: Some(-50), router_ms: Some(5), isp_ms: None, band: None }
    }

    #[test]
    fn shows_a_trend_with_sparklines_and_the_latest_audits() {
        let points = [point("2026-11-13T10:00:00.000Z", 80, Some(100)), point("2026-11-13T11:00:00.000Z", 90, None), point("2026-11-13T12:00:00.000Z", 100, Some(300))];
        let text = format_history(&points);
        assert!(text.starts_with("History: 3 audits, 2026-11-13 10:00 UTC to 2026-11-13 12:00 UTC"));
        assert!(text.contains("Score         ▁▅█  latest 100  (80 to 100)"), "{text}");
        assert!(text.contains("Link rate     ▁·█  latest 300 Mbps  (100 to 300)"), "{text}");
        assert!(text.contains("ISP delay     ···  no data"));
        assert!(text.contains("2026-11-13 12:00 UTC  score 100  300 Mbps"));
        assert_eq!(format_history(&[]).lines().count(), 1);
    }

    #[test]
    fn formats_times_for_people() {
        assert_eq!(when("2026-11-13T14:05:03.924Z"), "2026-11-13 14:05 UTC");
        assert_eq!(when("odd"), "odd UTC");
    }
}
