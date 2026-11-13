//! The report aggregate: assembled from checks, compared with its predecessor, fingerprinted for change detection.
use super::evidence::effective_dns;
use super::findings::{build_findings, top_fixes};
use super::gateway::TARGET_PLACEHOLDER;
use super::model::*;
use super::scoring::score_checks;
use super::speed::speed_tips;

pub fn compare(previous: Option<&Report>, current: &Score) -> Option<Comparison> {
    let before = previous?.score.provisional? as i64;
    let now = current.provisional? as i64;
    Some(Comparison { previous_score: before, current_score: now, delta: now - before })
}

pub fn build_report(checks: Checks, previous: Option<&Report>, generated_at: String, platform: &str) -> Report {
    let score = score_checks(&checks);
    let findings = build_findings(&checks);
    let comparison = compare(previous, &score);
    let mut privacy = vec![
        "Only the private default gateway detected by the operating system was checked, plus this device's own network settings.".to_string(),
        "No SSIDs, BSSIDs, MAC addresses, device names, UPnP descriptions or complete IP addresses are stored.".to_string(),
        "Port checks connect and close without sending data. UPnP is read-only.".to_string(),
        "Device checks read this device's own settings. They send nothing and store only yes/no answers and counts.".to_string(),
        "Wi-Fi speed is the link rate this device's own radio reports. No speed test was run and nothing was sent to measure it.".to_string(),
    ];
    if checks.latency.requested {
        privacy.push("Delay to your ISP was timed, at your request, with a few empty packets that expire at the first router past your own. No address or location was looked up or stored.".to_string());
    }
    privacy.push("WAN exposure was not tested.".to_string());
    Report {
        generated_at,
        platform: platform.to_string(),
        target: TARGET_PLACEHOLDER.to_string(),
        top_fixes: top_fixes(&findings),
        speed_tips: speed_tips(&findings),
        checks,
        score,
        findings,
        privacy,
        comparison,
    }
}

/// One comparable value: unknown, text or a number. A number never equals a text.
#[derive(Debug, Clone, PartialEq)]
enum Cell {
    Unknown,
    Text(String),
    Number(i64),
}

impl Cell {
    fn show(&self) -> String {
        match self {
            Cell::Unknown => "unknown".to_string(),
            Cell::Text(t) if t.is_empty() => "unknown".to_string(),
            Cell::Text(t) => t.clone(),
            Cell::Number(n) => n.to_string(),
        }
    }
}

fn text<T: AsRef<str>>(v: Option<T>) -> Cell {
    v.map_or(Cell::Unknown, |v| Cell::Text(v.as_ref().to_string()))
}
fn number<T: Into<i64>>(v: Option<T>) -> Cell {
    v.map_or(Cell::Unknown, |v| Cell::Number(v.into()))
}
fn yes_no(v: Option<bool>) -> Cell {
    v.map_or(Cell::Unknown, |v| Cell::Text(if v { "yes" } else { "no" }.to_string()))
}

/// The parts of a report that count as "the network changed".
fn comparable(report: &Report) -> Vec<(String, Cell)> {
    let checks = &report.checks;
    let mut flat: Vec<(String, Cell)> = Vec::new();
    for p in &checks.ports {
        flat.push((format!("Port {} ({})", p.port, p.service), Cell::Text(if p.reachable { "reachable" } else { "not reachable" }.into())));
    }
    let state = match checks.upnp.state {
        UpnpState::Detected => "detected",
        UpnpState::Refused => "refused",
        UpnpState::Unknown => "unknown",
    };
    let mut mappings: Vec<String> =
        checks.upnp.mappings.iter().map(|m| format!("{} {}->{}:{}", m.protocol, m.external_port, m.internal_host, m.internal_port)).collect();
    mappings.sort();
    flat.push(("UPnP".into(), Cell::Text(state.into())));
    flat.push(("UPnP mappings".into(), number(checks.upnp.mapping_count)));
    flat.push(("UPnP mapping list".into(), Cell::Text(mappings.join(", "))));
    flat.push(("UPnP remote-access mappings".into(), number(checks.upnp.sensitive_count)));
    flat.push((
        "Wi-Fi security".into(),
        Cell::Text(checks.wifi.security_mode.clone().unwrap_or_else(|| checks.wifi.security.as_str().to_string())),
    ));
    flat.push(("Wi-Fi band".into(), text(checks.wifi.band.map(|b| b.as_str()))));
    flat.push(("Wi-Fi standard".into(), text(checks.wifi.speed.standard.map(|s| s.as_str()))));
    flat.push(("Wi-Fi channel width".into(), number(checks.wifi.speed.channel_width_mhz)));
    flat.push(("Same-channel access points".into(), number(checks.wifi.same_channel_count)));
    flat.push(("Behind carrier-grade NAT".into(), yes_no(checks.latency.carrier_grade_nat)));
    flat.push(("DNS".into(), Cell::Text(effective_dns(checks).as_str().to_string())));
    let env = &checks.environment;
    let resolver = env.resolver_provider.clone().unwrap_or_else(|| format!("{:?}", env.resolver).to_lowercase());
    flat.push(("DNS resolver".into(), Cell::Text(resolver)));
    flat.push(("Global IPv6".into(), yes_no(env.global_ipv6)));
    flat.push(("VPN or tunnel alongside".into(), yes_no(env.tunnel_active)));
    flat.push(("Device firewall".into(), Cell::Text(format!("{:?}", env.firewall).to_lowercase())));
    flat.push(("Stealth mode".into(), yes_no(env.stealth_mode)));
    flat.push(("Ports open on this device".into(), number(env.open_listener_count)));
    flat.push(("Private Wi-Fi address".into(), yes_no(env.private_hardware_address)));
    flat.push(("IPv6 built from hardware address".into(), yes_no(env.ipv6_from_hardware_address)));
    flat.push(("Score".into(), number(report.score.provisional)));
    flat.push(("Coverage".into(), number(Some(report.score.coverage_percent))));
    flat
}

pub fn fingerprint(report: &Report) -> String {
    format!("{:?}", comparable(report))
}

pub fn describe_changes(before: &Report, after: &Report) -> Vec<String> {
    let a = comparable(before);
    comparable(after)
        .into_iter()
        .filter(|(key, value)| a.iter().find(|(k, _)| k == key).map(|(_, v)| v) != Some(value))
        .map(|(key, value)| {
            let was = a.iter().find(|(k, _)| *k == key).map_or("unknown".to_string(), |(_, v)| v.show());
            format!("{key}: {was} -> {}", value.show())
        })
        .collect()
}
