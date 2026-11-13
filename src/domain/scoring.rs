//! Scores only what is known, and reports coverage separately.
use super::evidence::effective_dns;
use super::model::*;

/// Every port the audit may touch. Weight 0 = informational: checked and reported, never scored.
pub const AUDITED_PORTS: [(u16, &str, u32); 11] = [
    (21, "ftp", 6),
    (22, "ssh", 6),
    (23, "telnet", 10),
    (53, "dns", 0),
    (80, "http", 4),
    (443, "https", 0),
    (445, "smb", 6),
    (2323, "telnet-alt", 8),
    (7547, "cwmp", 10),
    (8080, "http-alt", 3),
    (8443, "https-alt", 0),
];

const WEIGHT_UPNP: u32 = 20;
const WEIGHT_WIFI: u32 = 20;
const WEIGHT_CHANNEL: u32 = 10;
const WEIGHT_DNS: u32 = 20;

pub fn score_checks(checks: &Checks) -> Score {
    let mut breakdown: Vec<ScoreLine> = AUDITED_PORTS
        .iter()
        .filter(|(_, _, weight)| *weight > 0)
        .map(|(port, service, weight)| ScoreLine {
            id: format!("port-{port}"),
            label: format!("Port {port} ({service})"),
            weight: *weight,
            earned: checks.ports.iter().find(|p| p.port == *port).map(|p| if p.reachable { 0 } else { *weight }),
        })
        .collect();

    let upnp = &checks.upnp;
    let wifi = &checks.wifi;
    let dns = effective_dns(checks);
    let line = |id: &str, label: &str, weight: u32, earned: Option<u32>| ScoreLine { id: id.into(), label: label.into(), weight, earned };
    breakdown.push(line(
        "upnp",
        "UPnP",
        WEIGHT_UPNP,
        if upnp.state == UpnpState::Detected { Some(if upnp.mapping_count == Some(0) { 10 } else { 0 }) } else { None },
    ));
    breakdown.push(line(
        "wifi",
        "Wi-Fi security",
        WEIGHT_WIFI,
        match wifi.security {
            SecurityClass::Unknown => None,
            SecurityClass::Strong => Some(WEIGHT_WIFI),
            _ => Some(0),
        },
    ));
    breakdown.push(line(
        "channel",
        "Channel congestion",
        WEIGHT_CHANNEL,
        wifi.same_channel_count.map(|n| if n == 0 { 10 } else if n <= 2 { 5 } else { 0 }),
    ));
    breakdown.push(line(
        "dns",
        "DNS",
        WEIGHT_DNS,
        match dns {
            DnsStatus::Unknown => None,
            DnsStatus::Encrypted => Some(WEIGHT_DNS),
            DnsStatus::Plaintext => Some(0),
        },
    ));

    let total_weight: u32 = breakdown.iter().map(|l| l.weight).sum();
    let known_weight: u32 = breakdown.iter().filter(|l| l.earned.is_some()).map(|l| l.weight).sum();
    let earned_weight: u32 = breakdown.iter().filter_map(|l| l.earned).sum();
    Score {
        provisional: (known_weight != 0).then(|| (earned_weight as f64 / known_weight as f64 * 100.0).round() as u32),
        coverage_percent: (known_weight as f64 / total_weight as f64 * 100.0).round() as u32,
        earned_weight,
        known_weight,
        total_weight,
        breakdown,
    }
}
