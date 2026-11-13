//! Reads this device's own settings: firewall, tunnels, listening sockets, address privacy.
//! Nothing here sends a packet, and only yes/no answers and counts leave this file.
use super::route::default_route;
use super::system::{run, run_allowing_exit, COMMAND_TIMEOUT};
use crate::domain::devices::is_randomised_hardware_address;
use crate::domain::evidence::{is_hardware_derived_ipv6, DeviceObservation, FirewallObservation};
use crate::domain::gateway::is_tunnel_interface;
use if_addrs::IfAddr;
use regex::Regex;
use std::collections::BTreeSet;
use std::net::IpAddr;
use std::sync::LazyLock;

const MAC_FIREWALL_TOOL: &str = "/usr/libexec/ApplicationFirewall/socketfilterfw";

static ENABLED: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)State = [12]|\benabled\b").unwrap());
static DISABLED: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)State = 0|\bdisabled\b").unwrap());
static ON: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)\b(on|enabled)\b").unwrap());
static OFF: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)\b(off|disabled)\b").unwrap());
static LISTENER: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^n(.*):(\d+)$").unwrap());
static LOOPBACK: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^127\.|^\[::1\]$|^localhost$").unwrap());
static ETHER: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\bether ([0-9a-f]{1,2}(?::[0-9a-f]{1,2}){5})\b").unwrap());

/// Parses the macOS firewall tool's answers to --getglobalstate and --getstealthmode.
pub fn parse_mac_firewall(state: Option<&str>, stealth: Option<&str>) -> Option<FirewallObservation> {
    let state = state.filter(|s| !s.is_empty())?;
    let enabled = if ENABLED.is_match(state) {
        true
    } else if DISABLED.is_match(state) {
        false
    } else {
        return None;
    };
    let hidden = stealth.filter(|s| !s.is_empty()).and_then(|s| if ON.is_match(s) { Some(true) } else if OFF.is_match(s) { Some(false) } else { None });
    Some(FirewallObservation { enabled, stealth: hidden })
}

/// Counts distinct TCP ports listening on a non-loopback address, from `lsof -Fn` output.
/// Without administrator rights lsof shows only the user's own processes, so this is a lower bound.
pub fn count_open_listeners(lsof_fields: &str) -> u32 {
    let ports: BTreeSet<&str> = lsof_fields
        .lines()
        .filter_map(|line| LISTENER.captures(line.trim()).map(|c| (c.get(1).unwrap().as_str(), c.get(2).unwrap().as_str())))
        .filter(|(host, _)| !LOOPBACK.is_match(host))
        .map(|(_, port)| port)
        .collect();
    ports.len() as u32
}

/// The default interface's hardware address, used here only to learn whether it is randomised.
pub(crate) fn hardware_address_of(interface: &str) -> Option<String> {
    if cfg!(target_os = "linux") {
        return std::fs::read_to_string(format!("/sys/class/net/{interface}/address")).ok().map(|s| s.trim().to_string());
    }
    let output = run("ifconfig", &[interface], COMMAND_TIMEOUT)?;
    ETHER.captures(&output.to_lowercase()).map(|c| c[1].to_string())
}

pub fn read_device() -> DeviceObservation {
    let interfaces = if_addrs::get_if_addrs().unwrap_or_default();
    let mac = cfg!(target_os = "macos");
    let route = default_route();

    let global_ipv6: Vec<String> = interfaces
        .iter()
        .filter(|i| !i.is_loopback())
        .filter_map(|i| match &i.addr {
            IfAddr::V6(v6) if matches!(v6.ip.segments()[0] >> 12, 2 | 3) => Some(v6.ip.to_string()),
            _ => None,
        })
        .collect();

    let (firewall_state, firewall_stealth) = if mac {
        (run(MAC_FIREWALL_TOOL, &["--getglobalstate"], COMMAND_TIMEOUT), run(MAC_FIREWALL_TOOL, &["--getstealthmode"], COMMAND_TIMEOUT))
    } else {
        (None, None)
    };
    // lsof exits with 1 when nothing matches, which means "no listeners", not a failure.
    let listeners = if cfg!(windows) { None } else { run_allowing_exit("lsof", &["-nP", "-iTCP", "-sTCP:LISTEN", "-Fn"], Some(1), COMMAND_TIMEOUT) };

    DeviceObservation {
        // A tunnel that is up carries an IPv4 address; idle system tunnels have link-local IPv6 only.
        tunnel_active: Some(interfaces.iter().any(|i| is_tunnel_interface(&i.name) && matches!(i.ip(), IpAddr::V4(_)))),
        firewall: parse_mac_firewall(firewall_state.as_deref(), firewall_stealth.as_deref()),
        open_listener_count: listeners.as_deref().map(count_open_listeners),
        hardware_address_randomised: route.interface_name.as_deref().and_then(hardware_address_of).and_then(|a| is_randomised_hardware_address(&a)),
        ipv6_from_hardware_address: if global_ipv6.is_empty() { None } else { Some(global_ipv6.iter().any(|a| is_hardware_derived_ipv6(a))) },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn macos_firewall_state_and_stealth_mode() {
        let parse = parse_mac_firewall;
        assert_eq!(parse(Some("Firewall is disabled. (State = 0)"), Some("Firewall stealth mode is off")), Some(FirewallObservation { enabled: false, stealth: Some(false) }));
        assert_eq!(parse(Some("Firewall is enabled. (State = 1)"), Some("Firewall stealth mode is on")), Some(FirewallObservation { enabled: true, stealth: Some(true) }));
        assert_eq!(parse(Some("Firewall is enabled. (State = 2)"), None), Some(FirewallObservation { enabled: true, stealth: None }));
    }

    #[test]
    fn an_unreadable_firewall_is_unknown_never_assumed_off() {
        assert_eq!(parse_mac_firewall(None, None), None);
        assert_eq!(parse_mac_firewall(Some("something unexpected"), Some("Firewall stealth mode is on")), None);
    }

    #[test]
    fn counts_distinct_ports_open_to_the_network_and_ignores_loopback_listeners() {
        let lsof = ["p101", "f12", "n*:7000", "f13", "n*:5000", "p202", "f9", "n127.0.0.1:4173", "n[::1]:4173", "n[::]:7000", "n192.168.1.20:8000"].join("\n");
        assert_eq!(count_open_listeners(&lsof), 3);
        assert_eq!(count_open_listeners(""), 0);
        assert_eq!(count_open_listeners("p1\nf3\nn127.0.0.1:631\n"), 0);
    }
}
