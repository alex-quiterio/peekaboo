//! The audit's one target: the private default gateway. These rules decide what may be scanned and shown.
use regex::Regex;
use std::fmt;
use std::sync::LazyLock;

/// An intentional refusal, with a message that is safe to show.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SafetyStop(pub String);

impl SafetyStop {
    pub fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for SafetyStop {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for SafetyStop {}

pub const TARGET_PLACEHOLDER: &str = "<private-gateway>";

/// What the operating system reports about the default route, unvalidated.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DefaultRoute {
    pub address: Option<String>,
    pub interface_name: Option<String>,
}

/// Parses dotted-quad IPv4 text into octets, without touching the network stack.
pub fn parse_ipv4(address: &str) -> Option<[u8; 4]> {
    let mut octets = [0u8; 4];
    let mut parts = address.split('.');
    for octet in &mut octets {
        let part = parts.next()?;
        if part.is_empty() || part.len() > 3 || !part.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        *octet = part.parse::<u16>().ok().filter(|n| *n <= 255)? as u8;
    }
    parts.next().is_none().then_some(octets)
}

/// True only for RFC 1918 IPv4 addresses.
pub fn is_private_ipv4(address: &str) -> bool {
    match parse_ipv4(address) {
        Some([a, b, _, _]) => a == 10 || (a == 172 && (16..=31).contains(&b)) || (a == 192 && b == 168),
        None => false,
    }
}

static TUNNEL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)^(utun|tun|tap|wg|ppp|ipsec|gpd|tailscale|zt|nordlynx|proton)").unwrap());

/// VPN and tunnel interfaces. Their "gateway" is the VPN provider's, not the home router.
pub fn is_tunnel_interface(name: &str) -> bool {
    TUNNEL.is_match(name)
}

/// Returns the gateway address if it may be scanned; otherwise stops the audit.
pub fn require_home_gateway(route: &DefaultRoute) -> Result<String, SafetyStop> {
    if route.interface_name.as_deref().is_some_and(is_tunnel_interface) {
        return Err(SafetyStop::new(
            "The default route goes through a VPN or tunnel, so its gateway is not your home router. Nothing was scanned. Disconnect the VPN and run the audit again.",
        ));
    }
    match route.address.as_deref() {
        Some(address) if is_private_ipv4(address) => Ok(address.to_string()),
        _ => Err(SafetyStop::new("The default gateway is not a private IPv4 address, so nothing was scanned.")),
    }
}

static IPV4_IN_TEXT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3})\.\d{1,3}\b").unwrap());

/// Replaces the final octet of every IPv4 address in the text with "x".
pub fn redact_ipv4(text: &str) -> String {
    IPV4_IN_TEXT.replace_all(text, "$1.x").into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_rfc_1918_ipv4() {
        for ok in ["10.0.0.1", "172.16.0.1", "172.31.255.254", "192.168.1.1"] {
            assert!(is_private_ipv4(ok), "{ok}");
        }
        for bad in ["8.8.8.8", "172.32.0.1", "192.169.1.1", "100.64.0.1", "fe80::1", "", "192.168.1.999", "router.local", "1.2.3", "1.2.3.4.5", "+1.2.3.4", "1..2.3"] {
            assert!(!is_private_ipv4(bad), "{bad}");
        }
    }

    #[test]
    fn stops_rather_than_scan_a_non_private_gateway() {
        let route = |a: Option<&str>, i: Option<&str>| DefaultRoute { address: a.map(Into::into), interface_name: i.map(Into::into) };
        assert_eq!(require_home_gateway(&route(Some("192.168.1.1"), Some("en0"))).unwrap(), "192.168.1.1");
        assert!(require_home_gateway(&route(Some("8.8.8.8"), Some("en0"))).is_err());
        assert!(require_home_gateway(&route(None, None)).is_err());
    }

    #[test]
    fn stops_when_the_default_route_is_a_vpn_tunnel_even_with_a_private_gateway() {
        for tunnel in ["utun4", "tun0", "wg0", "ppp0", "tailscale0"] {
            let route = DefaultRoute { address: Some("10.8.0.1".into()), interface_name: Some(tunnel.into()) };
            assert!(require_home_gateway(&route).unwrap_err().0.contains("VPN or tunnel"), "{tunnel}");
        }
    }

    #[test]
    fn redacts_the_final_octet() {
        assert_eq!(redact_ipv4("192.168.1.25"), "192.168.1.x");
        assert_eq!(redact_ipv4("from 10.0.0.7 to 10.0.0.1"), "from 10.0.0.x to 10.0.0.x");
    }
}
