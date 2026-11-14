//! Explains checks in plain words. A LAN-side result is never described as internet exposure.
use super::evidence::effective_dns;
use super::exposure::exposure_findings;
use super::model::*;
use super::speed::{latency_findings, speed_findings, USE_FASTER_BAND};

fn finding(id: impl Into<String>, severity: Severity, message: impl Into<String>, action: Option<&str>) -> Finding {
    Finding { id: id.into(), severity, message: message.into(), action: action.map(str::to_string) }
}

/// What to say when a port accepts connections from the LAN.
fn port_advice(port: u16) -> Option<(Severity, &'static str, Option<&'static str>)> {
    use Severity::*;
    Some(match port {
        21 => (Medium, "FTP (21) accepts connections from this network. FTP is unencrypted.", Some("Disable the router's FTP or USB file-sharing server if you do not use it.")),
        22 => (Medium, "SSH (22) accepts connections from this network.", Some("Disable SSH on the router if you do not use it.")),
        23 => (High, "Telnet (23) accepts connections from this network. Telnet is unencrypted.", Some("Disable Telnet on the router.")),
        53 => (Info, "The router answers DNS (53), so it can act as your network's resolver.", None),
        80 => (Low, "The router answers on HTTP (80) from this network, usually its admin page.", Some("Use the HTTPS admin page if your router offers one, and check WAN remote management is off.")),
        443 => (Info, "The router answers on HTTPS (443), so an encrypted admin page is likely available.", None),
        445 => (Medium, "SMB file sharing (445) accepts connections from this network.", Some("Disable the router's SMB or USB file-sharing server if you do not use it.")),
        2323 => (High, "An alternate Telnet port (2323) accepts connections from this network.", Some("Disable Telnet on the router.")),
        7547 => (Medium, "CWMP/TR-069 (7547) accepts connections from this network.", Some("If your ISP does not need remote management, disable TR-069/CWMP in the router.")),
        8080 => (Low, "An alternate HTTP port (8080) accepts connections from this network.", Some("Check what the router serves on port 8080 and switch it off if it is a second admin page.")),
        8443 => (Info, "The router answers on an alternate HTTPS port (8443).", None),
        _ => return None,
    })
}

fn port_finding(check: &PortCheck) -> Finding {
    let id = format!("port-{}", check.port);
    if check.reachable {
        if let Some((severity, message, action)) = port_advice(check.port) {
            return finding(id, severity, message, action);
        }
    }
    let message = if check.reachable {
        format!("Port {} ({}) accepts connections from this network.", check.port, check.service)
    } else {
        format!("Port {} ({}) is not reachable from this network.", check.port, check.service)
    };
    finding(id, Severity::Info, message, None)
}

fn upnp_findings(upnp: &UpnpCheck) -> Vec<Finding> {
    use Severity::*;
    match upnp.state {
        UpnpState::Refused => {
            return vec![finding("upnp", Info, "UPnP: Unknown. A UPnP device answered that is not the default gateway, so it was not queried.", None)];
        }
        UpnpState::Unknown => {
            return vec![finding("upnp", Info, "UPnP: Unknown. No gateway answered discovery; verify the setting in the router.", None)];
        }
        UpnpState::Detected => {}
    }
    let count = upnp.mapping_count.unwrap_or(0);
    if count == 0 {
        return vec![finding("upnp", Low, "UPnP is on, with no port mappings right now.", Some("Disable UPnP in the router if nothing needs it."))];
    }
    let mut findings = vec![finding(
        "upnp",
        Medium,
        format!("UPnP is on and holds {count} port mapping{} created by devices on your network.", if count == 1 { "" } else { "s" }),
        Some("Review the UPnP mappings in the router and disable UPnP if nothing needs it."),
    )];
    if let Some(sensitive) = upnp.sensitive_count.filter(|n| *n > 0) {
        findings.push(finding(
            "upnp-sensitive",
            High,
            format!(
                "{sensitive} UPnP mapping{} a remote-access port (FTP, SSH, Telnet, SMB, RDP or VNC) to a device on your network.",
                if sensitive == 1 { " forwards" } else { "s forward" }
            ),
            Some("Remove UPnP mappings for remote-access ports unless you created them on purpose."),
        ));
    }
    findings
}

const WIFI_FIX: &str = "Switch Wi-Fi security to WPA3 Personal or WPA2/WPA3 Transitional.";

fn wifi_findings(wifi: &WifiCheck) -> Vec<Finding> {
    use Severity::*;
    let mut findings = Vec::new();
    let mode = wifi.security_mode.as_deref().unwrap_or("unrecognised mode");
    findings.push(match wifi.security {
        SecurityClass::Weak => finding("wifi", High, format!("Wi-Fi security is weak ({mode})."), Some(WIFI_FIX)),
        SecurityClass::Review => finding("wifi", Medium, format!("Wi-Fi security needs a look ({mode})."), Some(WIFI_FIX)),
        SecurityClass::Strong => {
            let note = if mode == "WPA2" { " WPA3 is stronger if your router and devices support it." } else { "" };
            finding("wifi", Info, format!("Wi-Fi security is strong ({mode}).{note}"), None)
        }
        SecurityClass::Unknown => finding("wifi", Info, "Wi-Fi security: Unknown. No Wi-Fi connection could be read; verify it in the router.", None),
    });

    let nearby = wifi.nearby_count.map(|n| format!(" ({n} access points in range)")).unwrap_or_default();
    findings.push(match wifi.same_channel_count {
        None => finding(
            "channel",
            Info,
            "Channel congestion: Unknown. Your own access point could not be told apart from its neighbours. Operating systems hide Wi-Fi names from apps without Location permission.",
            Some("On macOS, allow Location Services for your terminal app (System Settings > Privacy & Security > Location Services), then run the audit again."),
        ),
        Some(0) => finding("channel", Info, format!("No other access points share your Wi-Fi channel{nearby}."), None),
        Some(n) => finding(
            "channel",
            Low,
            format!("{n} other access point{} your Wi-Fi channel{nearby}.", if n == 1 { " shares" } else { "s share" }),
            Some("Set the Wi-Fi channel to Auto in the router."),
        ),
    });

    match wifi.band {
        Some(WifiBand::Ghz2) => {
            let overlap = wifi.overlapping_count.filter(|n| *n > 0);
            let note = overlap
                .map(|n| format!(" {n} access point{} nearby use overlapping channels.", if n == 1 { "" } else { "s" }))
                .unwrap_or_default();
            findings.push(finding(
                "band",
                if overlap.is_some() { Low } else { Info },
                format!("This device is connected on the 2.4 GHz band, which is slower and more crowded.{note}"),
                overlap.map(|_| USE_FASTER_BAND),
            ));
        }
        Some(band) => findings.push(finding("band", Info, format!("This device is connected on the {} band.", band.as_str()), None)),
        None => {}
    }
    findings
}

fn environment_findings(environment: &EnvironmentCheck, checks: &Checks) -> Vec<Finding> {
    use Severity::*;
    let mut findings = Vec::new();
    let effective = effective_dns(checks);

    findings.push(if checks.dns.status == DnsStatus::Plaintext {
        finding("dns", Medium, "DNS lookups are sent in plaintext, so your ISP can read which sites you look up.", Some("Enable encrypted DNS (DoH or DoT) on the router or your devices."))
    } else if effective == DnsStatus::Encrypted {
        finding("dns", Info, "DNS is encrypted (as you reported).", None)
    } else if checks.dns.status == DnsStatus::Encrypted {
        finding(
            "dns",
            Low,
            "DNS: Unknown. You reported encrypted DNS, but a VPN or tunnel is connected alongside your normal connection. A tunnel can take over DNS and send lookups around an encrypted-DNS profile, in plaintext.",
            Some("Check your DNS with the tunnel connected, or set an encrypted resolver in the tunnel's own DNS settings."),
        )
    } else {
        finding("dns", Info, "DNS: Unknown. Tell the audit whether your DNS is encrypted to include it in the score.", None)
    });

    let provider = environment.resolver_provider.as_deref().unwrap_or("a public resolver");
    let resolver = match environment.resolver {
        ResolverKind::Gateway => "This device sends its DNS lookups to the router, which usually forwards them to your ISP's resolver. Whether that hop is encrypted depends on the router's DNS settings.".to_string(),
        ResolverKind::Private => "This device sends its DNS lookups to another device on your network (for example a local filter or resolver).".to_string(),
        ResolverKind::Local => "This device sends its DNS lookups to a resolver running on the device itself (for example a VPN or encrypted-DNS app).".to_string(),
        ResolverKind::Public if effective == DnsStatus::Encrypted => format!("This device's network settings name {provider} as the resolver. Encrypted DNS overrides that setting; if it is ever removed, lookups go to {provider} in plaintext."),
        ResolverKind::Public => format!("This device sends its DNS lookups straight to {provider} rather than to the router. Unless they are encrypted, your ISP can still read them in transit."),
        ResolverKind::Unknown => "DNS resolver: Unknown. No resolver configuration could be read from this device.".to_string(),
    };
    findings.push(finding("resolver", Info, resolver, None));

    match environment.global_ipv6 {
        Some(true) => findings.push(finding("ipv6", Info, "This device has a global IPv6 address. IPv6 devices are not hidden behind NAT, so they rely on the router's IPv6 firewall; verify it is switched on.", None)),
        Some(false) => findings.push(finding("ipv6", Info, "This device has no global IPv6 address.", None)),
        None => {}
    }
    if environment.ipv6_from_hardware_address == Some(true) {
        findings.push(finding(
            "ipv6-privacy",
            Low,
            "This device's IPv6 address is built from its hardware address, so websites can recognise the device on any network.",
            Some("Enable IPv6 privacy (temporary) addresses on this device."),
        ));
    }
    findings
}

/// Findings about this device rather than the router.
fn device_findings(checks: &Checks) -> Vec<Finding> {
    use Severity::*;
    let environment = &checks.environment;
    let mut findings = Vec::new();

    if environment.tunnel_active == Some(true) && checks.dns.status != DnsStatus::Encrypted {
        findings.push(finding(
            "tunnel",
            Info,
            "A VPN or tunnel is connected alongside your normal connection. Only traffic for the tunnel's own network goes through it; the rest stays visible to your ISP, and the tunnel may choose this device's DNS.",
            None,
        ));
    }

    let open = environment.open_listener_count;
    let listening = match open {
        None => String::new(),
        Some(0) => " No app on this device was seen accepting connections from the network.".to_string(),
        Some(n) => format!(" At least {n} port{} on this device accept{} connections from the network.", if n == 1 { "" } else { "s" }, if n == 1 { "s" } else { "" }),
    };
    match environment.firewall {
        Firewall::Off => findings.push(finding(
            "firewall",
            if open.is_some_and(|n| n > 0) { Medium } else { Low },
            format!("This device's firewall is off, so anything it runs can be reached by every device on the network.{listening}"),
            Some("Turn on this device's firewall in its network settings."),
        )),
        Firewall::On => {
            let stealth = if environment.stealth_mode == Some(false) { " Stealth mode is off; turning it on stops this device answering probes." } else { "" };
            findings.push(finding("firewall", Info, format!("This device's firewall is on.{stealth}{listening}"), None));
        }
        Firewall::Unknown => findings.push(finding("firewall", Info, format!("Device firewall: Unknown. It could not be read on this operating system.{listening}"), None)),
    }

    if checks.wifi.state != WifiState::Unknown {
        if let Some(private) = environment.private_hardware_address {
            findings.push(finding(
                "hardware-address",
                Info,
                if private {
                    "This device shows the network a private (randomised) Wi-Fi address instead of its hardware address."
                } else {
                    "This device shows the network its real hardware Wi-Fi address. A private Wi-Fi address stops networks, and a router managed by your ISP, from recognising the device."
                },
                None,
            ));
        }
    }
    findings
}

pub fn build_findings(checks: &Checks) -> Vec<Finding> {
    let mut findings: Vec<Finding> = checks.ports.iter().map(port_finding).collect();
    findings.extend(upnp_findings(&checks.upnp));
    findings.extend(wifi_findings(&checks.wifi));
    findings.extend(speed_findings(&checks.wifi));
    findings.extend(latency_findings(&checks.latency));
    findings.extend(environment_findings(&checks.environment, checks));
    findings.extend(device_findings(checks));
    findings.extend(exposure_findings(checks));
    findings.push(finding("wan", Severity::Info, "WAN exposure was not tested. Every check here was made from inside your network.", None));
    findings
}

/// At most three unique, non-INFO actions, most severe first. Speed advice is listed separately, as speed tips.
pub fn top_fixes(findings: &[Finding]) -> Vec<String> {
    let mut candidates: Vec<&Finding> =
        findings.iter().filter(|f| f.severity != Severity::Info && f.action.is_some() && !f.id.starts_with("speed-")).collect();
    candidates.sort_by_key(|f| f.severity.rank());
    let mut actions: Vec<String> = Vec::new();
    for action in candidates.iter().filter_map(|f| f.action.as_ref()) {
        if !actions.contains(action) {
            actions.push(action.clone());
        }
    }
    actions.truncate(3);
    actions
}
