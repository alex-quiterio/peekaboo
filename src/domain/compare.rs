//! Puts two reports side by side and says, metric by metric, which one is better. Unknown never wins.
use super::evidence::effective_dns;
use super::model::*;
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Better {
    Left,
    Right,
    Same,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ComparisonRow {
    pub id: String,
    pub label: String,
    /// Display text; None means Unknown.
    pub left: Option<String>,
    pub right: Option<String>,
    pub better: Option<Better>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ComparedReport {
    pub name: String,
    pub generated_at: String,
    pub score: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Wins {
    pub left: usize,
    pub right: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReportComparison {
    pub left: ComparedReport,
    pub right: ComparedReport,
    pub rows: Vec<ComparisonRow>,
    /// How many metrics each side wins. Ties and unknowns count for neither.
    pub wins: Wins,
    /// Problems (LOW or worse) found on one side and not on the other.
    pub only_left: Vec<String>,
    pub only_right: Vec<String>,
    /// Cautions about reading the comparison, such as scores built on different amounts of evidence.
    pub notes: Vec<String>,
}

#[derive(Clone, Copy, PartialEq)]
enum Direction {
    Higher,
    Lower,
    None,
}

/// What a metric reads out of a report: display text, and the number the two sides are compared by.
struct Reading {
    text: Option<String>,
    n: Option<f64>,
}

const UNKNOWN: Reading = Reading { text: None, n: None };

fn amount(value: Option<i64>, unit: &str) -> Reading {
    match value {
        None => UNKNOWN,
        Some(v) => Reading { text: Some(if unit.is_empty() { v.to_string() } else { format!("{v} {unit}") }), n: Some(v as f64) },
    }
}

/// `order` runs worst to best. A value outside it is unknown.
fn ranked(value: Option<&str>, order: &[&str], text: Option<String>) -> Reading {
    match value.and_then(|v| order.iter().position(|o| *o == v)) {
        None => UNKNOWN,
        Some(i) => Reading { text: text.or_else(|| value.map(str::to_string)), n: Some(i as f64) },
    }
}

struct Metric {
    id: &'static str,
    label: &'static str,
    direction: Direction,
    read: fn(&Report) -> Reading,
}

fn i(v: Option<impl Into<i64>>) -> Option<i64> {
    v.map(Into::into)
}

// Reports saved by an earlier version have no speed or delay fields, so those read as Unknown.
const METRICS: [Metric; 19] = [
    Metric { id: "score", label: "Score", direction: Direction::Higher, read: |r| amount(i(r.score.provisional), "/ 100") },
    Metric { id: "coverage", label: "Evidence coverage", direction: Direction::None, read: |r| amount(Some(r.score.coverage_percent as i64), "%") },
    Metric { id: "link-rate", label: "Wi-Fi link rate", direction: Direction::Higher, read: |r| amount(i(r.checks.wifi.speed.link_rate_mbps), "Mbps") },
    Metric { id: "signal", label: "Wi-Fi signal", direction: Direction::Higher, read: |r| amount(i(r.checks.wifi.speed.signal_dbm), "dBm") },
    Metric { id: "noise", label: "Radio noise", direction: Direction::Lower, read: |r| amount(i(r.checks.wifi.speed.noise_dbm), "dBm") },
    Metric {
        id: "standard",
        label: "Wi-Fi standard",
        direction: Direction::Higher,
        read: |r| ranked(r.checks.wifi.speed.standard.map(|s| s.as_str()), &["Legacy", "Wi-Fi 4", "Wi-Fi 5", "Wi-Fi 6", "Wi-Fi 7"], None),
    },
    Metric { id: "band", label: "Wi-Fi band", direction: Direction::Higher, read: |r| ranked(r.checks.wifi.band.map(|b| b.as_str()), &["2.4 GHz", "5 GHz", "6 GHz"], None) },
    Metric { id: "width", label: "Channel width", direction: Direction::Higher, read: |r| amount(i(r.checks.wifi.speed.channel_width_mhz), "MHz") },
    Metric {
        id: "security",
        label: "Wi-Fi security",
        direction: Direction::Higher,
        read: |r| {
            let wifi = &r.checks.wifi;
            ranked(Some(wifi.security.as_str()), &["weak", "review", "strong"], Some(wifi.security_mode.clone().unwrap_or_else(|| wifi.security.as_str().to_string())))
        },
    },
    Metric { id: "same-channel", label: "Access points on your channel", direction: Direction::Lower, read: |r| amount(i(r.checks.wifi.same_channel_count), "") },
    Metric { id: "nearby", label: "Access points in range", direction: Direction::None, read: |r| amount(i(r.checks.wifi.nearby_count), "") },
    Metric { id: "router-delay", label: "Delay to router", direction: Direction::Lower, read: |r| amount(i(r.checks.latency.router_ms), "ms") },
    Metric { id: "isp-delay", label: "Delay to ISP", direction: Direction::Lower, read: |r| amount(i(r.checks.latency.isp_ms), "ms") },
    Metric { id: "isp-km", label: "ISP router within", direction: Direction::None, read: |r| amount(i(r.checks.latency.isp_max_km), "km at most") },
    Metric {
        id: "ports",
        label: "Router ports answering",
        direction: Direction::Lower,
        read: |r| amount(Some(r.checks.ports.iter().filter(|p| p.reachable).count() as i64), ""),
    },
    Metric {
        id: "upnp",
        label: "UPnP mappings",
        direction: Direction::Lower,
        read: |r| if r.checks.upnp.state == UpnpState::Detected { amount(i(r.checks.upnp.mapping_count), "") } else { UNKNOWN },
    },
    Metric {
        id: "dns",
        label: "DNS",
        direction: Direction::Higher,
        read: |r| match effective_dns(&r.checks) {
            DnsStatus::Unknown => UNKNOWN,
            dns => ranked(Some(dns.as_str()), &["plaintext", "encrypted"], None),
        },
    },
    Metric {
        id: "firewall",
        label: "Device firewall",
        direction: Direction::Higher,
        read: |r| match r.checks.environment.firewall {
            Firewall::Unknown => UNKNOWN,
            Firewall::On => ranked(Some("on"), &["off", "on"], None),
            Firewall::Off => ranked(Some("off"), &["off", "on"], None),
        },
    },
    Metric { id: "listeners", label: "Ports open on this device", direction: Direction::Lower, read: |r| amount(i(r.checks.environment.open_listener_count), "") },
];

fn judge(direction: Direction, left: &Reading, right: &Reading) -> Option<Better> {
    let (Some(a), Some(b)) = (left.n, right.n) else { return None };
    if direction == Direction::None {
        return None;
    }
    if a == b {
        return Some(Better::Same);
    }
    Some(if (a > b) == (direction == Direction::Higher) { Better::Left } else { Better::Right })
}

/// LOW, MEDIUM or HIGH findings, keyed by id so the same problem matches across reports.
fn problems(report: &Report) -> Vec<(&str, &str)> {
    report.findings.iter().filter(|f| f.severity != Severity::Info).map(|f| (f.id.as_str(), f.message.as_str())).collect()
}

fn describe(name: &str, report: &Report) -> ComparedReport {
    ComparedReport { name: name.to_string(), generated_at: report.generated_at.clone(), score: report.score.provisional }
}

pub fn compare_reports(left: (&str, &Report), right: (&str, &Report)) -> ReportComparison {
    let rows: Vec<ComparisonRow> = METRICS
        .iter()
        .map(|metric| {
            let a = (metric.read)(left.1);
            let b = (metric.read)(right.1);
            ComparisonRow { id: metric.id.into(), label: metric.label.into(), better: judge(metric.direction, &a, &b), left: a.text, right: b.text }
        })
        .collect();
    let a = problems(left.1);
    let b = problems(right.1);
    let only = |from: &[(&str, &str)], other: &[(&str, &str)]| -> Vec<String> {
        from.iter().filter(|(id, _)| !other.iter().any(|(o, _)| o == id)).map(|(_, m)| m.to_string()).collect()
    };
    let mut notes = Vec::new();
    let (ca, cb) = (left.1.score.coverage_percent, right.1.score.coverage_percent);
    if ca != cb {
        notes.push(format!(
            "The scores rest on different evidence: {} covers {ca}% of the checks and {} {cb}%. Compare the individual measures rather than the scores.",
            left.0, right.0
        ));
    }
    ReportComparison {
        left: describe(left.0, left.1),
        right: describe(right.0, right.1),
        wins: Wins {
            left: rows.iter().filter(|r| r.better == Some(Better::Left)).count(),
            right: rows.iter().filter(|r| r.better == Some(Better::Right)).count(),
        },
        only_left: only(&a, &b),
        only_right: only(&b, &a),
        rows,
        notes,
    }
}
