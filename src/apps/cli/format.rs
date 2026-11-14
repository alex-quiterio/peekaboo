//! Terminal presentation shared by the scan, watch and reports commands.
use crate::domain::compare::{Better, ReportComparison};
use crate::domain::evidence::parse_dns;
use crate::domain::gateway::SafetyStop;
use crate::domain::history::{range, series, sparkline, HistoryPoint};
use super::style::{wrap, Style, WIDTH};
use crate::domain::model::{DnsStatus, Finding, Firewall, Report, ResolverKind, Severity, UpnpState, SEVERITY_ORDER};
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

const LABEL_WIDTH: usize = 20;

fn row(style: &Style, label: &str, value: impl AsRef<str>) -> String {
    format!("  {}{}", style.dim(&format!("{label:<LABEL_WIDTH$}")), value.as_ref())
}

fn unknown<T>(value: Option<T>, show: impl FnOnce(T) -> String) -> String {
    value.map_or_else(|| "Unknown".to_string(), show)
}

fn yes_no(value: Option<bool>) -> String {
    unknown(value, |v| if v { "yes" } else { "no" }.to_string())
}

fn numbered(style: &Style, items: &[String]) -> Vec<String> {
    items
        .iter()
        .enumerate()
        .flat_map(|(i, item)| {
            let lead = format!("  {}  ", style.bold(&format!("{}.", i + 1)));
            wrap(item, WIDTH - 5, 5).into_iter().enumerate().map(move |(n, l)| if n == 0 { format!("{lead}{l}") } else { format!("  {l}") })
        })
        .collect()
}

fn resolver(env: &crate::domain::model::EnvironmentCheck) -> String {
    let kind = match env.resolver {
        ResolverKind::Gateway => "your router",
        ResolverKind::Private => "a device on your network",
        ResolverKind::Local => "this device",
        ResolverKind::Public => "a public provider",
        ResolverKind::Unknown => "Unknown",
    };
    match &env.resolver_provider {
        Some(provider) => format!("{kind} ({provider})"),
        None => kind.to_string(),
    }
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
            lines.push(row(style, "Score (provisional)", text));
        }
    }
    lines.push(row(style, "Evidence coverage", format!("{}% of the score could be measured", report.score.coverage_percent)));
    let count = |s: Severity| report.findings.iter().filter(|f| f.severity == s).count();
    let counts: Vec<String> = SEVERITY_ORDER.iter().map(|s| style.severity(*s, &format!("{} {}", count(*s), s.label().to_lowercase()))).collect();
    lines.push(row(style, "Findings", counts.join("  ")));
    lines
}

fn findings_section(style: &Style, report: &Report) -> Vec<String> {
    let mut lines = vec![style.heading("Findings")];
    let mut findings: Vec<_> = report.findings.iter().collect();
    findings.sort_by_key(|f| f.severity.rank());
    // Routine port results are in the ports table; here they would only repeat it.
    let routine = |f: &Finding| f.severity == Severity::Info && f.id.starts_with("port-");
    let hidden = findings.iter().filter(|f| routine(f)).count();
    findings.retain(|f| !routine(f));
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
        lines.push(style.dim(&format!("  + {hidden} routine router port results, listed under Network details")));
    }
    lines
}

fn breakdown_section(style: &Style, report: &Report) -> Vec<String> {
    let mut lines = vec![style.heading("Score breakdown")];
    let width = report.score.breakdown.iter().map(|l| l.label.chars().count()).max().unwrap_or(0);
    for line in &report.score.breakdown {
        let points = match line.earned {
            Some(earned) => {
                let text = format!("{earned:>2} / {}", line.weight);
                if earned == line.weight { style.green(&text) } else if earned == 0 { style.red(&text) } else { style.yellow(&text) }
            }
            None => style.dim(&format!("{:>2} / {}  unknown, not counted", "?", line.weight)),
        };
        lines.push(format!("  {:<width$}  {points}", line.label));
    }
    lines
}

fn details_section(style: &Style, report: &Report) -> Vec<String> {
    let checks = &report.checks;
    let mut lines = vec![style.heading("Network details")];

    lines.push(style.bold("Router ports (reachable from this network only)"));
    if checks.ports.is_empty() {
        lines.push("  Unknown".to_string());
    }
    for pair in checks.ports.chunks(2) {
        let cells: Vec<String> = pair
            .iter()
            .map(|p| {
                let state = if p.reachable { style.red("open  ") } else { style.green("closed") };
                format!("{:>5} {:<12} {state}", p.port, p.service)
            })
            .collect();
        lines.push(format!("  {}", cells.join("   ")));
    }

    lines.push(String::new());
    lines.push(style.bold("UPnP"));
    let upnp = match checks.upnp.state {
        UpnpState::Detected => "detected",
        UpnpState::Refused => "not offered (router refused)",
        UpnpState::Unknown => "Unknown",
    };
    lines.push(row(style, "State", upnp));
    lines.push(row(style, "Port mappings", unknown(checks.upnp.mapping_count, |n| n.to_string())));
    lines.push(row(style, "Remote-access", unknown(checks.upnp.sensitive_count, |n| n.to_string())));

    lines.push(String::new());
    lines.push(style.bold("Wi-Fi"));
    let wifi = &checks.wifi;
    let speed = &wifi.speed;
    lines.push(row(style, "Security", match &wifi.security_mode {
        Some(mode) => format!("{mode} ({})", wifi.security.as_str()),
        None => wifi.security.as_str().to_string(),
    }));
    lines.push(row(style, "Band", unknown(wifi.band, |b| b.as_str().to_string())));
    lines.push(row(style, "Standard", unknown(speed.standard, |s| s.as_str().to_string())));
    lines.push(row(style, "Link rate", unknown(speed.link_rate_mbps, |r| format!("{r} Mbps (a ceiling, not a speed test)"))));
    lines.push(row(style, "Signal", unknown(speed.signal_dbm, |s| match speed.signal {
        Some(q) => format!("{s} dBm ({})", q.as_str()),
        None => format!("{s} dBm"),
    })));
    lines.push(row(style, "Channel width", unknown(speed.channel_width_mhz, |w| format!("{w} MHz"))));
    lines.push(row(style, "Nearby networks", unknown(wifi.nearby_count, |n| n.to_string())));
    lines.push(row(style, "Same channel", unknown(wifi.same_channel_count, |n| n.to_string())));

    lines.push(String::new());
    lines.push(style.bold("DNS"));
    lines.push(row(style, "Encryption", checks.dns.status.as_str()));
    lines.push(row(style, "Resolver", resolver(&checks.environment)));

    lines.push(String::new());
    lines.push(style.bold("This device"));
    let env = &checks.environment;
    lines.push(row(style, "Firewall", match env.firewall {
        Firewall::On => "on",
        Firewall::Off => "off",
        Firewall::Unknown => "Unknown",
    }));
    lines.push(row(style, "Stealth mode", yes_no(env.stealth_mode)));
    lines.push(row(style, "Open listeners", unknown(env.open_listener_count, |n| format!("at least {n}"))));
    lines.push(row(style, "Global IPv6", yes_no(env.global_ipv6)));
    lines.push(row(style, "VPN or tunnel", yes_no(env.tunnel_active)));
    lines.push(row(style, "Private hardware ID", yes_no(env.private_hardware_address)));

    let latency = &checks.latency;
    lines.push(String::new());
    lines.push(style.bold("ISP delay"));
    if latency.requested {
        lines.push(row(style, "Router", unknown(latency.router_ms, |m| format!("{m} ms"))));
        lines.push(row(style, "First ISP router", unknown(latency.isp_ms, |m| format!("{m} ms"))));
        lines.push(row(style, "Own routers", unknown(latency.own_hops, |n| n.to_string())));
        lines.push(row(style, "Cable distance", unknown(latency.isp_max_km, |km| format!("no more than about {km} km"))));
        lines.push(row(style, "Carrier-grade NAT", match latency.carrier_grade_nat {
            Some(true) => "most likely".to_string(),
            Some(false) => "probably not".to_string(),
            None => "Unknown".to_string(),
        }));
    } else {
        lines.push(style.dim("  Not measured. Add --isp-latency to opt in."));
    }
    lines
}

/// The audit as sections: summary, findings, score breakdown, the details behind them, then what to do.
pub fn format_report(report: &Report, style: &Style) -> String {
    let mut lines = vec![
        format!("{}  {}", style.bold("Peekaboo"), style.dim("home network privacy check")),
        row(style, "Target", &report.target),
        row(style, "Audited", when(&report.generated_at)),
        String::new(),
    ];
    for section in [summary_section(style, report), findings_section(style, report), breakdown_section(style, report), details_section(style, report)] {
        lines.extend(section);
        lines.push(String::new());
    }
    if !report.top_fixes.is_empty() {
        lines.push(style.heading("Top fixes"));
        lines.extend(numbered(style, &report.top_fixes));
        lines.push(String::new());
    }
    if !report.speed_tips.is_empty() {
        lines.push(style.heading("Make the Wi-Fi faster"));
        lines.extend(numbered(style, &report.speed_tips));
        lines.push(String::new());
    }
    lines.push(style.dim("Saved sanitized-report.json"));
    lines.join("\n")
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
    fn organizes_the_report_into_sections_without_colour_codes_when_plain() {
        let text = format_report(&fixture(), &Style::plain());
        println!("{text}");
        let at = |h: &str| text.find(&format!("\n{h}\n")).unwrap_or_else(|| panic!("missing {h}\n{text}"));
        let order = ["Summary", "Findings", "Score breakdown", "Network details"].map(at);
        assert!(order.windows(2).all(|w| w[0] < w[1]), "{text}");
        assert!(!text.contains('\x1b'));
        assert!(text.ends_with("Saved sanitized-report.json"));
        assert!(text.lines().all(|l| l.chars().count() <= WIDTH + 12), "{text}");
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
