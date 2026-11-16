//! Terminal presentation shared by the scan, watch and reports commands.
use crate::domain::compare::{Better, ReportComparison};
use crate::domain::evidence::parse_dns;
use crate::domain::gateway::SafetyStop;
use crate::domain::history::{range, series, sparkline, HistoryPoint};
use super::style::{wrap, Style, WIDTH};
use crate::domain::model::{DnsStatus, Report, SignalQuality, Severity, SEVERITY_ORDER};
use crate::domain::saved::{parse_label, SavedReportSummary};
use crate::domain::speed_test::{Responsiveness, SpeedTestResult};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Output {
    Default,
    Json,
}

pub struct ScanOptions {
    pub output: Output,
    pub dns: DnsStatus,
    pub isp_latency: bool,
    pub speed_test: bool,
    pub save: Option<String>,
}

/// The only flags are --dns, --isp-latency / --no-isp-latency, --output default|json and (for scan) --speed-test and --save <name>. Anything else, including any kind of
/// target, is rejected. A bad name is refused now, so it stops the run before anything is measured.
pub fn options_from_args(args: &[String], allow_save: bool) -> Result<ScanOptions, SafetyStop> {
    let refuse = || SafetyStop::new(if allow_save {
        "The only options are --dns encrypted|plaintext|unknown, --no-isp-latency, --output default|json, --speed-test and --save <name>."
    } else {
        "The only options are --dns encrypted|plaintext|unknown, --no-isp-latency and --output default|json."
    });
    // On unless the caller opts out: the delay check is the audit's one step past the router.
    let (mut dns, mut isp_latency, mut save, mut output, mut speed_test) = (None, true, None, Output::Default, false);
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        let (flag, inline) = match arg.split_once('=') {
            Some((flag, value)) if arg.starts_with("--") => (flag, Some(value.to_string())),
            _ => (arg.as_str(), None),
        };
        let mut value = || inline.clone().or_else(|| args.next().cloned()).ok_or_else(refuse);
        match flag {
            "--dns" => dns = Some(value()?),
            "--output" => output = match value()?.as_str() {
                "default" => Output::Default,
                "json" => Output::Json,
                _ => return Err(refuse()),
            },
            "--speed-test" if allow_save && inline.is_none() => speed_test = true,
            "--save" if allow_save => save = Some(value()?),
            "--isp-latency" if inline.is_none() => isp_latency = true,
            "--no-isp-latency" if inline.is_none() => isp_latency = false,
            _ => return Err(refuse()),
        }
    }
    Ok(ScanOptions {
        output,
        dns: parse_dns(dns.as_deref())?,
        isp_latency,
        speed_test,
        save: save.map(|s| parse_label(Some(&s))).transpose()?,
    })
}

const LABEL_WIDTH: usize = 16;

fn row(style: &Style, label: &str, value: impl AsRef<str>) -> String {
    format!("  {}{}", style.dim(&format!("{label:<LABEL_WIDTH$}")), value.as_ref())
}

fn summary_section(style: &Style, report: &Report) -> Vec<String> {
    let mut lines = vec![style.heading("Summary")];
    match report.score.provisional {
        None => lines.push(row(style, "Score", "Unknown (nothing could be measured)")),
        Some(score) => {
            let mut text = format!("{} {}", style.bold(&format!("{score}/100")), style.meter(score, 20));
            if let Some(c) = &report.comparison {
                text.push_str(&format!("  was {} ({}{})", c.previous_score, if c.delta >= 0 { "+" } else { "" }, c.delta));
            }
            lines.push(row(style, "Score", text));
        }
    }
    lines.push(row(style, "Coverage", format!("{}% of the score could be measured", report.score.coverage_percent)));
    let count = |s: Severity| report.findings.iter().filter(|f| f.severity == s).count();
    let counts: Vec<String> = SEVERITY_ORDER.iter().map(|s| style.severity(*s, &format!("{} {}", count(*s), s.label().to_lowercase()))).collect();
    lines.push(row(style, "Findings", counts.join("  ")));
    lines
}

/// What this device's own radio reports, as a few rows. Rows with no value are left out.
fn connection_section(style: &Style, report: &Report, test: Option<&Option<SpeedTestResult>>) -> Vec<String> {
    let wifi = &report.checks.wifi;
    let speed = &wifi.speed;
    let mut rows = Vec::new();
    if let Some(standard) = speed.standard {
        rows.push(row(style, "Standard", standard.as_str()));
    }
    let band = wifi.band.map(|b| b.as_str().replace(' ', ""));
    let detail = match (speed.channel, band, speed.channel_width_mhz) {
        (channel, band, width) if channel.is_some() || band.is_some() || width.is_some() => {
            let inner: Vec<String> = [band, width.map(|w| format!("{w}MHz"))].into_iter().flatten().collect();
            let inner = if inner.is_empty() { String::new() } else { format!(" ({})", inner.join(", ")) };
            Some(format!("{}{inner}", channel.map_or_else(String::new, |c| c.to_string())).trim().to_string())
        }
        _ => None,
    };
    if let Some(detail) = detail {
        rows.push(row(style, "Channel", detail));
    }
    if let Some(dbm) = speed.signal_dbm {
        let quality = speed.signal.map_or(String::new(), |q| {
            let word = match q {
                SignalQuality::Excellent | SignalQuality::Good => style.green(q.as_str()),
                SignalQuality::Fair => style.yellow(q.as_str()),
                SignalQuality::Weak => style.red(q.as_str()),
            };
            format!(" ({word})")
        });
        rows.push(row(style, "Signal", format!("{dbm} dBm{quality}")));
    }
    if let (Some(signal), Some(noise)) = (speed.signal_dbm, speed.noise_dbm) {
        rows.push(row(style, "SNR", format!("{} dB", signal - noise)));
    }
    if let Some(rate) = speed.link_rate_mbps {
        rows.push(row(style, "Link rate", format!("{rate} Mbps {}", style.dim("(ceiling, not throughput)"))));
    }
    let latency = &report.checks.latency;
    if let Some(ms) = latency.router_ms {
        rows.push(row(style, "Router delay", format!("{ms} ms")));
    }
    if let Some(ms) = latency.isp_ms {
        rows.push(row(style, "ISP delay", format!("{ms} ms")));
    }
    rows.extend(speed_rows(style, test));
    if rows.is_empty() {
        return Vec::new();
    }
    let mut lines = vec![style.heading("Current connection")];
    lines.extend(rows);
    lines
}

fn findings_section(style: &Style, report: &Report) -> Vec<String> {
    let mut lines = vec![style.heading("Findings")];
    let mut findings: Vec<_> = report.findings.iter().collect();
    findings.sort_by_key(|f| f.severity.rank());
    // Informational notes stay out of the summary; the JSON output has them all.
    let hidden = findings.iter().filter(|f| f.severity == Severity::Info).count();
    findings.retain(|f| f.severity != Severity::Info);
    if findings.is_empty() {
        lines.push("  Nothing to report.".to_string());
    }
    for f in findings {
        let tag = style.severity(f.severity, &format!("{:<6}", f.severity.label()));
        let text = wrap(&f.message, WIDTH - 10, 8);
        lines.push(format!("  {tag}  {}", text.join("\n  ")));
        if let Some(action) = &f.action {
            let action = wrap(&format!("→ {action}"), WIDTH - 10, 8).join("\n  ");
            lines.push(format!("  {:<6}  {}", "", style.dim(&action)));
        }
    }
    if hidden > 0 {
        lines.push(style.dim(&format!("  + {hidden} informational notes (see --output json)")));
    }
    lines
}

/// A short summary of the audit: score, what needs attention, and what to do about it.
pub fn format_report(report: &Report, style: &Style, speed: Option<&Option<SpeedTestResult>>) -> String {
    let mut lines = vec![
        format!("{}  {}", style.bold("Peekaboo"), style.dim(&format!("audited {}", when(&report.generated_at)))),
        String::new(),
    ];
    lines.extend(summary_section(style, report));
    lines.push(String::new());
    let connection = connection_section(style, report, speed);
    if !connection.is_empty() {
        lines.extend(connection);
        lines.push(String::new());
    }
    lines.extend(findings_section(style, report));
    lines.push(String::new());
    lines.push(style.dim("Full detail: --output json, or the dashboard (peekaboo web)."));
    lines.join("\n")
}

/// The report as JSON, with the opt-in speed test beside it when one was run (`null` when it could not be read).
/// The speed test is added to this output only; it is not part of the saved report.
pub fn format_report_json_with_speed(report: &Report, speed: Option<&Option<SpeedTestResult>>) -> String {
    let mut value = serde_json::to_value(report).unwrap_or_default();
    if let (Some(result), Some(object)) = (speed, value.as_object_mut()) {
        object.insert("speedTest".to_string(), serde_json::to_value(result).unwrap_or_default());
    }
    serde_json::to_string_pretty(&value).unwrap_or_else(|_| "{}".to_string())
}

/// The opt-in speed test as rows for the connection section. `Some(None)` means it was asked for but gave no reading.
fn speed_rows(style: &Style, speed: Option<&Option<SpeedTestResult>>) -> Vec<String> {
    let Some(result) = speed else { return Vec::new() };
    let Some(r) = result else {
        return vec![row(style, "Speed test", "Unknown (not available here or could not be read)")];
    };
    let mut rows = vec![row(style, "Download", style.bold(&format!("{} Mbps", r.download_mbps))), row(style, "Upload", style.bold(&format!("{} Mbps", r.upload_mbps)))];
    if let Some(ms) = r.idle_latency_ms {
        rows.push(row(style, "Idle latency", format!("{ms} ms")));
    }
    if let (Some(ms), Some(rpm)) = (r.loaded_latency_ms, r.responsiveness_rpm) {
        let word = r.responsiveness().map_or(String::new(), |q| match q {
            Responsiveness::High => style.green("high"),
            Responsiveness::Medium => style.yellow("medium"),
            Responsiveness::Low => style.red("low"),
        });
        rows.push(row(style, "Under load", format!("{ms} ms | {rpm} RPM ({word})")));
    }
    rows
}

/// The sanitized report exactly as it is saved, as JSON.
pub fn format_report_json(report: &Report) -> String {
    serde_json::to_string_pretty(report).unwrap_or_else(|_| "{}".to_string())
}

/// "2026-11-13T14:05:03.924Z" as "2026-11-13 14:05 UTC".
pub fn when(iso: &str) -> String {
    format!("{} UTC", iso.get(..16).unwrap_or(iso).replace('T', " "))
}

pub fn format_saved_list(saved: &[SavedReportSummary], style: &Style) -> String {
    if saved.is_empty() {
        return "No saved reports yet. Run an audit, then: peekaboo reports save \"Home\"".to_string();
    }
    let width = saved.iter().map(|s| s.label.chars().count()).max().unwrap_or(0).max(4);
    let mut lines = vec![style.heading("Saved reports"), style.dim(&format!("  {:<width$}  {:>5}  {:>8}  {}", "Name", "Score", "Coverage", "Audited"))];
    lines.extend(saved.iter().map(|s| {
        let score = s.score.map_or("?".to_string(), |s| s.to_string());
        format!("  {:<width$}  {:>5}  {:>7}%  {}", s.label, score, s.coverage_percent, when(&s.generated_at))
    }));
    lines.join("\n")
}

/// A table with a mark beside the better value of each row.
pub fn format_comparison(c: &ReportComparison, style: &Style) -> String {
    let cell = |value: &Option<String>, mark: bool| format!("{}{}", value.as_deref().unwrap_or("Unknown"), if mark { " *" } else { "" });
    let mut table: Vec<[String; 3]> = vec![[String::new(), c.left.name.clone(), c.right.name.clone()]];
    table.extend(c.rows.iter().map(|r| [r.label.clone(), cell(&r.left, r.better == Some(Better::Left)), cell(&r.right, r.better == Some(Better::Right))]));
    let widths: Vec<usize> = (0..3).map(|i| table.iter().map(|r| r[i].chars().count()).max().unwrap_or(0)).collect();
    let line = |row: &[String; 3]| row.iter().enumerate().map(|(i, c)| format!("{:<w$}", c, w = widths[i])).collect::<Vec<_>>().join("   ").trim_end().to_string();

    let mut lines = vec![style.heading("Comparison"), style.bold(&line(&table[0])), style.dim(&widths.iter().map(|w| "─".repeat(*w)).collect::<Vec<_>>().join("   "))];
    lines.extend(table[1..].iter().map(line));
    lines.push(String::new());
    lines.push(format!(
        "* = better. {} is better on {}, {} on {}. Unknown values are never marked.",
        c.left.name, c.wins.left, c.right.name, c.wins.right
    ));
    for note in &c.notes {
        lines.push(String::new());
        lines.push(format!("{} {note}", style.yellow("Note:")));
    }
    for (name, only) in [(&c.left.name, &c.only_left), (&c.right.name, &c.only_right)] {
        if !only.is_empty() {
            lines.push(String::new());
            lines.push(style.bold(&format!("Only on {name}:")));
            lines.extend(only.iter().map(|m| format!("  - {m}")));
        }
    }
    lines.join("\n")
}

/// How many of the latest audits the sparklines and the table show.
const HISTORY_SHOWN: usize = 40;
const HISTORY_ROWS: usize = 10;

/// Sparklines for the main measures, then the latest audits one per line.
pub fn format_history(points: &[HistoryPoint], style: &Style) -> String {
    if points.is_empty() {
        return "No history yet. Every audit adds a point; `peekaboo watch` adds one every 30 minutes.".to_string();
    }
    let shown = &points[points.len().saturating_sub(HISTORY_SHOWN)..];
    let mut lines = vec![
        style.heading("History"),
        format!("{} audit{}, {} to {}", points.len(), if points.len() == 1 { "" } else { "s" }, when(&points[0].at), when(&points[points.len() - 1].at)),
        String::new(),
    ];
    type Measure = (&'static str, &'static str, fn(&HistoryPoint) -> Option<f64>);
    let measures: [Measure; 7] = [
        ("Score", "", |p| p.score.map(f64::from)),
        ("Link rate", " Mbps", |p| p.link_rate_mbps.map(f64::from)),
        ("Signal", " dBm", |p| p.signal_dbm.map(f64::from)),
        ("Router delay", " ms", |p| p.router_ms.map(f64::from)),
        ("ISP delay", " ms", |p| p.isp_ms.map(f64::from)),
        ("Download", " Mbps", |p| p.download_mbps),
        ("Upload", " Mbps", |p| p.upload_mbps),
    ];
    for (name, unit, pick) in measures {
        let values = series(shown, pick);
        let summary = match (range(&values), values.iter().rev().flatten().next()) {
            (Some((min, max)), Some(latest)) => format!("latest {latest}{unit}  ({min} to {max})"),
            _ => "no data".to_string(),
        };
        lines.push(format!("  {name:<13} {}  {summary}", style.cyan(&sparkline(&values))));
    }
    lines.push(String::new());
    lines.push(style.bold("Latest audits"));
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
        assert_eq!((o.dns, o.isp_latency, o.save), (DnsStatus::Unknown, true, None));
        assert!(!options_from_args(&args(&["--no-isp-latency"]), true).unwrap().isp_latency);
    }

    #[test]
    fn refuses_targets_unknown_flags_bad_values_and_bad_names() {
        for bad in [&["--target", "1.2.3.4"][..], &["192.168.1.1"], &["--dns"], &["--dns", "8.8.8.8"], &["--output", "xml"], &["--output"], &["--isp-latency=yes"], &["--no-isp-latency=1"], &["--save", "../x"], &["--save"]] {
            assert!(options_from_args(&args(bad), true).is_err(), "{bad:?}");
        }
        assert!(options_from_args(&args(&["--save", "Home"]), false).is_err(), "watch cannot save");
        assert!(options_from_args(&args(&["--speed-test"]), false).is_err(), "watch cannot run a speed test");
        assert!(options_from_args(&args(&["--speed-test=1"]), true).is_err());
        assert!(options_from_args(&args(&["--speed-test"]), true).unwrap().speed_test);
        assert!(!options_from_args(&[], true).unwrap().speed_test, "off unless asked");
    }

    fn point(at: &str, score: u32, link: Option<u32>) -> HistoryPoint {
        HistoryPoint { at: at.into(), score: Some(score), coverage_percent: 59, link_rate_mbps: link, signal_dbm: Some(-50), router_ms: Some(5), isp_ms: None, band: None, download_mbps: None, upload_mbps: None }
    }

    #[test]
    fn shows_a_trend_with_sparklines_and_the_latest_audits() {
        let points = [point("2026-11-13T10:00:00.000Z", 80, Some(100)), point("2026-11-13T11:00:00.000Z", 90, None), point("2026-11-13T12:00:00.000Z", 100, Some(300))];
        let text = format_history(&points, &Style::plain());
        assert!(text.contains("3 audits, 2026-11-13 10:00 UTC to 2026-11-13 12:00 UTC"));
        assert!(text.contains("Score         ▁▅█  latest 100  (80 to 100)"), "{text}");
        assert!(text.contains("Link rate     ▁·█  latest 300 Mbps  (100 to 300)"), "{text}");
        assert!(text.contains("ISP delay     ···  no data"));
        assert!(text.contains("2026-11-13 12:00 UTC  score 100  300 Mbps"));
        assert_eq!(format_history(&[], &Style::plain()).lines().count(), 1);
    }

    fn fixture() -> Report {
        serde_json::from_str(include_str!("../../../tests/fixtures/typescript-report.json")).unwrap()
    }

    #[test]
    fn summarizes_the_report_briefly_without_colour_codes_when_plain() {
        let text = format_report(&fixture(), &Style::plain(), None);
        let at = |h: &str| text.find(&format!("\n{h}\n")).unwrap_or_else(|| panic!("missing {h}\n{text}"));
        let order = ["SUMMARY", "FINDINGS"].map(at);
        assert!(order[0] < order[1], "{text}");
        assert!(!text.contains('\x1b'));
        assert!(!text.contains("Network details") && !text.contains("Score breakdown"));
        assert!(text.lines().count() < 40, "{text}");
        assert!(text.lines().all(|l| l.chars().count() <= WIDTH + 12), "{text}");
    }

    #[test]
    fn json_output_is_the_report_itself() {
        let report = fixture();
        let value: serde_json::Value = serde_json::from_str(&format_report_json(&report)).unwrap();
        assert!(value.is_object() && value.get("score").is_some());
    }

    #[test]
    fn shows_the_speed_test_inside_the_connection_section_and_adds_it_to_json_only_when_run() {
        let result = crate::domain::speed_test::parse_speed_test(r#"{"dl_throughput":35055000,"ul_throughput":97578000,"base_rtt":11.38,"responsiveness":179}"#);
        let report = fixture();
        let text = format_report(&report, &Style::plain(), Some(&result));
        for expected in ["Download        35.055 Mbps", "Upload          97.578 Mbps", "Idle latency    11.4 ms", "Under load      335.2 ms | 179 RPM (low)"] {
            assert!(text.contains(expected), "{expected}\n{text}");
        }
        assert!(!text.contains("THROUGHPUT"), "one section, not two\n{text}");
        assert_eq!(text.matches("CURRENT CONNECTION").count(), 1);
        assert!(format_report(&report, &Style::plain(), Some(&None)).contains("Speed test"));
        assert!(!format_report(&report, &Style::plain(), None).contains("Download"));
        assert!(!format_report_json_with_speed(&report, None).contains("speedTest"));
        assert!(format_report_json_with_speed(&report, Some(&result)).contains("\"downloadMbps\": 35.055"));
        assert!(format_report_json_with_speed(&report, Some(&None)).contains("\"speedTest\": null"));
    }

    #[test]
    fn wraps_text_with_a_hanging_indent() {
        assert_eq!(wrap("one two three four", 9, 2), ["one two", "  three", "  four"]);
    }

    #[test]
    fn formats_times_for_people() {
        assert_eq!(when("2026-11-13T14:05:03.924Z"), "2026-11-13 14:05 UTC");
        assert_eq!(when("odd"), "odd UTC");
    }
}
