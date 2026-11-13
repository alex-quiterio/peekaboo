//! What can be said about exposure from the internet side, without ever testing from outside. Everything here is
//! inferred from evidence the audit already holds: how the ISP's first router is addressed, UPnP port mappings,
//! this device's IPv6 address and firewall. None of it is scored, and none of it is a test.
use super::model::*;

fn finding(id: &str, severity: Severity, message: impl Into<String>, action: Option<&str>) -> Finding {
    Finding { id: id.into(), severity, message: message.into(), action: action.map(str::to_string) }
}

fn service(port: u32) -> Option<&'static str> {
    Some(match port {
        21 => "FTP",
        22 => "SSH",
        23 => "Telnet",
        80 => "HTTP",
        443 => "HTTPS",
        445 => "SMB file sharing",
        1194 => "OpenVPN",
        3389 => "Remote Desktop",
        5900 => "VNC",
        8080 => "alternate HTTP",
        25565 => "Minecraft",
        32400 => "Plex",
        51820 => "WireGuard",
        _ => return None,
    })
}

/// The external ports of the mappings, once each, with well-known services named. At most six are listed.
fn describe_ports(mappings: &[SanitizedMapping]) -> String {
    let mut ports: Vec<u32> = mappings.iter().map(|m| m.external_port).collect();
    ports.sort_unstable();
    ports.dedup();
    let named = |p: &u32| service(*p).map_or(p.to_string(), |s| format!("{p} ({s})"));
    let mut text = ports.iter().take(6).map(named).collect::<Vec<_>>().join(", ");
    if ports.len() > 6 {
        text.push_str(&format!(" and {} more", ports.len() - 6));
    }
    text
}

fn nat_finding(latency: &LatencyCheck) -> Finding {
    if !latency.requested {
        return finding(
            "wan-nat",
            Severity::Info,
            "Carrier-grade NAT: Unknown. Run the audit with the ISP delay option (--isp-latency, or the switch in the dashboard) to learn whether your ISP puts you behind carrier-grade NAT, which changes what the internet can reach.",
            None,
        );
    }
    match (latency.carrier_grade_nat, latency.own_hops) {
        (Some(true), _) => finding(
            "wan-nat",
            Severity::Info,
            "Your ISP's first router sits in the shared address range reserved for carrier-grade NAT (100.64.0.0/10), so your connection is most likely behind CGNAT. Devices on the internet generally cannot start connections to your network, which keeps most of it out of reach from the internet side. It also means port forwards and UPnP mappings on your router will not work from outside.",
            None,
        ),
        (_, Some(hops)) if hops > 1 => finding(
            "wan-nat",
            Severity::Info,
            format!("There are {hops} routers of your own between this device and your ISP, so your network is behind double NAT. A port forward or UPnP mapping on the first router reaches the internet only if each router in front of it forwards the same port."),
            None,
        ),
        (Some(false), _) => finding(
            "wan-nat",
            Severity::Info,
            "The first router past yours has an ordinary public address, so your router most likely has a public address too. Connections from the internet reach it, and what is open depends on your port forwards and UPnP mappings.",
            None,
        ),
        _ => finding(
            "wan-nat",
            Severity::Info,
            "Carrier-grade NAT: Unknown. No router past your own answered, so it could not be told whether your ISP puts you behind carrier-grade NAT.",
            None,
        ),
    }
}

fn forwards_finding(upnp: &UpnpCheck, latency: &LatencyCheck) -> Option<Finding> {
    if upnp.state != UpnpState::Detected {
        return None;
    }
    if upnp.mappings.is_empty() {
        return Some(finding("wan-forwards", Severity::Info, "UPnP holds no port mappings, so no device has asked the router to forward internet traffic to it.", None));
    }
    let ports = describe_ports(&upnp.mappings);
    let reach = match (latency.carrier_grade_nat, latency.own_hops) {
        (Some(true), _) => "Because your connection appears to be behind carrier-grade NAT, these are probably not reachable from the internet.".to_string(),
        (_, Some(h)) if h > 1 => "Behind double NAT they reach the internet only if the router in front forwards them too.".to_string(),
        (Some(false), _) => "Your router appears to have a public address, so these ports are open to anyone on the internet until the mapping is removed.".to_string(),
        _ => "If your router has a public address (it is not behind carrier-grade NAT), these ports are open to anyone on the internet until the mapping is removed.".to_string(),
    };
    Some(finding("wan-forwards", Severity::Info, format!("Devices on your network asked the router to forward internet traffic to them on: {ports}. {reach}"), None))
}

/// Only when something makes a device reachable: a global IPv6 address with an open port or no firewall.
fn ipv6_finding(environment: &EnvironmentCheck) -> Option<Finding> {
    if environment.global_ipv6 != Some(true) {
        return None;
    }
    let open = environment.open_listener_count.filter(|n| *n > 0);
    let firewall_off = environment.firewall == Firewall::Off;
    if open.is_none() && !firewall_off {
        return None;
    }
    let mut reasons = Vec::new();
    if let Some(n) = open {
        reasons.push(format!("at least {n} port{} on it accept{} connections", if n == 1 { "" } else { "s" }, if n == 1 { "s" } else { "" }));
    }
    if firewall_off {
        reasons.push("its firewall is off".to_string());
    }
    Some(finding(
        "wan-ipv6",
        if open.is_some() && firewall_off { Severity::Medium } else { Severity::Low },
        format!(
            "This device has a global IPv6 address and {}. IPv6 has no NAT, so unless your router's IPv6 firewall blocks inbound connections, this device can be reached directly from the internet.",
            reasons.join(" and ")
        ),
        Some("Check that your router's IPv6 firewall blocks inbound connections, and turn on this device's firewall."),
    ))
}

pub fn exposure_findings(checks: &Checks) -> Vec<Finding> {
    let mut findings = vec![nat_finding(&checks.latency)];
    findings.extend(forwards_finding(&checks.upnp, &checks.latency));
    findings.extend(ipv6_finding(&checks.environment));
    findings.push(finding(
        "wan-verify",
        Severity::Info,
        "To see what the internet can really reach, test from outside your network, for example from a phone on mobile data with an online port checker. Peekaboo never does this itself: it would have to send your public address to someone else.",
        None,
    ));
    findings
}
