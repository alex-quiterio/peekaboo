//! Adapters that touch the network: the TCP connect probe and this device's resolver settings.
use super::device::read_device;
use crate::domain::evidence::EnvironmentObservation;
use crate::domain::gateway::parse_ipv4;
use crate::domain::ports::{EnvironmentInspector, PortProbe};
use if_addrs::IfAddr;
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::time::Duration;

const TCP_TIMEOUT: Duration = Duration::from_millis(800);

pub struct TcpConnectProbe;

impl PortProbe for TcpConnectProbe {
    /// Connects, then closes at once. No application data is ever sent.
    fn is_reachable(&self, host: &str, port: u16) -> bool {
        let Some([a, b, c, d]) = parse_ipv4(host) else { return false };
        let address = SocketAddr::from((Ipv4Addr::new(a, b, c, d), port));
        TcpStream::connect_timeout(&address, TCP_TIMEOUT).is_ok()
    }
}

/// Resolver addresses from resolv.conf text, in order.
pub fn parse_resolv_conf(text: &str) -> Vec<String> {
    text.lines().filter_map(|l| l.trim().strip_prefix("nameserver")).map(|v| v.trim().to_string()).filter(|v| !v.is_empty()).collect()
}

pub struct SystemEnvironmentInspector;

impl EnvironmentInspector for SystemEnvironmentInspector {
    /// Reads local configuration only. No packets are sent.
    fn inspect(&self) -> EnvironmentObservation {
        let resolvers = std::fs::read_to_string("/etc/resolv.conf").map(|t| parse_resolv_conf(&t)).unwrap_or_default();
        let global_ipv6 = if_addrs::get_if_addrs().ok().map(|interfaces| {
            interfaces.iter().filter(|i| !i.is_loopback()).any(|i| matches!(&i.addr, IfAddr::V6(v6) if matches!(v6.ip.segments()[0] >> 12, 2 | 3)))
        });
        EnvironmentObservation { device: read_device(), resolvers, global_ipv6 }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_resolvers_in_order() {
        let text = "# generated\nsearch lan\nnameserver 192.168.1.1\nnameserver 9.9.9.9\n";
        assert_eq!(parse_resolv_conf(text), ["192.168.1.1", "9.9.9.9"]);
        assert!(parse_resolv_conf("").is_empty());
    }

    #[test]
    fn a_closed_local_port_is_not_reachable_and_a_non_ip_host_is_never_tried() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        assert!(TcpConnectProbe.is_reachable("127.0.0.1", listener.local_addr().unwrap().port()));
        // A port nobody listens on: claimed and released without ever being connected to.
        let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        assert!(!TcpConnectProbe.is_reachable("127.0.0.1", closed));
        assert!(!TcpConnectProbe.is_reachable("router.local", 80));
    }
}
