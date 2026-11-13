//! Reads the operating system's default route. macOS and Linux; on other systems the route is unknown,
//! and the audit stops, because a VPN could not be ruled out.
use super::system::{run, COMMAND_TIMEOUT};
use crate::domain::gateway::DefaultRoute;
use crate::domain::ports::GatewayLocator;

/// Parses `route -n get default` (macOS).
pub fn parse_macos_route(output: &str) -> DefaultRoute {
    let field = |name: &str| {
        output.lines().find_map(|line| line.trim().strip_prefix(name).map(|v| v.trim().to_string())).filter(|v| !v.is_empty())
    };
    DefaultRoute { address: field("gateway:"), interface_name: field("interface:") }
}

/// Parses `ip -4 route show default` (Linux): "default via 192.168.1.1 dev wlan0 proto dhcp ...".
pub fn parse_linux_route(output: &str) -> DefaultRoute {
    let words: Vec<&str> = output.lines().find(|l| l.starts_with("default")).map(|l| l.split_whitespace().collect()).unwrap_or_default();
    let after = |key: &str| words.iter().position(|w| *w == key).and_then(|i| words.get(i + 1)).map(|w| w.to_string());
    DefaultRoute { address: after("via"), interface_name: after("dev") }
}

pub fn default_route() -> DefaultRoute {
    if cfg!(target_os = "macos") {
        run("route", &["-n", "get", "default"], COMMAND_TIMEOUT).map(|o| parse_macos_route(&o)).unwrap_or_default()
    } else if cfg!(target_os = "linux") {
        run("ip", &["-4", "route", "show", "default"], COMMAND_TIMEOUT).map(|o| parse_linux_route(&o)).unwrap_or_default()
    } else {
        DefaultRoute::default()
    }
}

pub struct SystemGatewayLocator;

impl GatewayLocator for SystemGatewayLocator {
    fn locate(&self) -> DefaultRoute {
        default_route()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_macos_default_route() {
        let out = "   route to: default\ndestination: default\n       mask: default\n    gateway: 192.168.1.1\n  interface: en0\n      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>\n";
        assert_eq!(parse_macos_route(out), DefaultRoute { address: Some("192.168.1.1".into()), interface_name: Some("en0".into()) });
        assert_eq!(parse_macos_route("route: writing to routing socket: not in table"), DefaultRoute::default());
    }

    #[test]
    fn reads_the_linux_default_route() {
        let out = "default via 192.168.1.1 dev wlan0 proto dhcp src 192.168.1.20 metric 600\n";
        assert_eq!(parse_linux_route(out), DefaultRoute { address: Some("192.168.1.1".into()), interface_name: Some("wlan0".into()) });
        assert_eq!(parse_linux_route(""), DefaultRoute::default());
    }
}
