//! Finds the devices on this network without probing them: it makes the operating system resolve each
//! address, reads the neighbour table, and asks the gateway for names. No ports are opened on any device.
use super::device::hardware_address_of;
use super::route::default_route;
use super::system::{run, COMMAND_TIMEOUT};
use crate::domain::devices::{NeighbourObservation, SelfObservation};
use crate::domain::gateway::parse_ipv4;
use crate::domain::ports::NeighbourDiscovery;
use if_addrs::IfAddr;
use regex::Regex;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::LazyLock;
use std::thread;
use std::time::Duration;

const DISCARD_PORT: u16 = 9;
const BATCH_SIZE: usize = 32;
const BATCH_PAUSE: Duration = Duration::from_millis(40);
const SETTLE: Duration = Duration::from_millis(1500);
const NAME_TIMEOUT: Duration = Duration::from_millis(1500);

static ARP_UNIX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)\((\d{1,3}(?:\.\d{1,3}){3})\) at ([0-9a-f]{1,2}(?::[0-9a-f]{1,2}){5})\b").unwrap());
static ARP_WINDOWS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)^\s*(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-f]{2}(?:-[0-9a-f]{2}){5})\b").unwrap());

/// Parses `arp -an` (macOS, Linux) and `arp -a` (Windows) into address and hardware-address pairs.
pub fn parse_neighbour_table(output: &str) -> Vec<(String, String)> {
    output
        .lines()
        .filter_map(|line| ARP_UNIX.captures(line).or_else(|| ARP_WINDOWS.captures(line)).map(|c| (c[1].to_string(), c[2].to_string())))
        .collect()
}

/// A PTR query for an IPv4 address, in DNS wire format.
pub fn ptr_query(address: &str, id: u16) -> Option<Vec<u8>> {
    let [a, b, c, d] = parse_ipv4(address)?;
    let mut message = vec![(id >> 8) as u8, id as u8, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in [d.to_string(), c.to_string(), b.to_string(), a.to_string(), "in-addr".into(), "arpa".into()] {
        message.push(label.len() as u8);
        message.extend_from_slice(label.as_bytes());
    }
    message.extend_from_slice(&[0, 0, 12, 0, 1]);
    Some(message)
}

/// Reads a possibly compressed name starting at `at`. Returns the name and the offset after it.
fn read_name(message: &[u8], at: usize) -> Option<(String, usize)> {
    let (mut pos, mut end, mut jumps, mut labels) = (at, None, 0, Vec::new());
    loop {
        let len = *message.get(pos)? as usize;
        if len == 0 {
            return Some((labels.join("."), end.unwrap_or(pos + 1)));
        }
        if len & 0xC0 == 0xC0 {
            jumps += 1;
            if jumps > 10 {
                return None;
            }
            end.get_or_insert(pos + 2);
            pos = ((len & 0x3F) << 8) | *message.get(pos + 1)? as usize;
        } else {
            labels.push(String::from_utf8_lossy(message.get(pos + 1..pos + 1 + len)?).into_owned());
            pos += 1 + len;
        }
    }
}

/// The first PTR name in a DNS response.
pub fn parse_ptr_response(message: &[u8]) -> Option<String> {
    if message.len() < 12 || message[3] & 0x0F != 0 {
        return None;
    }
    let (questions, answers) = (u16::from_be_bytes([message[4], message[5]]), u16::from_be_bytes([message[6], message[7]]));
    let mut pos = 12;
    for _ in 0..questions {
        pos = read_name(message, pos)?.1 + 4;
    }
    for _ in 0..answers {
        let (_, after) = read_name(message, pos)?;
        let kind = u16::from_be_bytes([*message.get(after)?, *message.get(after + 1)?]);
        let length = u16::from_be_bytes([*message.get(after + 8)?, *message.get(after + 9)?]) as usize;
        if kind == 12 {
            return read_name(message, after + 10).map(|(name, _)| name).filter(|n| !n.is_empty());
        }
        pos = after + 10 + length;
    }
    None
}

/// Names come from the gateway only, never from the system resolver, so private addresses stay on this network.
fn name_from_gateway(gateway: Ipv4Addr, address: &str, id: u16) -> Option<String> {
    let query = ptr_query(address, id)?;
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.set_read_timeout(Some(NAME_TIMEOUT)).ok()?;
    socket.send_to(&query, SocketAddr::from((gateway, 53))).ok()?;
    let mut buffer = [0u8; 1024];
    let (n, from) = socket.recv_from(&mut buffer).ok()?;
    if from.ip() != std::net::IpAddr::V4(gateway) || buffer[..2] != query[..2] {
        return None;
    }
    parse_ptr_response(&buffer[..n])
}

pub struct SystemNeighbourDiscovery;

impl SystemNeighbourDiscovery {
    /// Sends one empty datagram to the discard port of each address. Its only purpose is to make the
    /// operating system look the address up, which fills the neighbour table. No reply is read.
    fn resolve_all(addresses: &[String]) {
        if addresses.is_empty() {
            return;
        }
        let Ok(socket) = UdpSocket::bind("0.0.0.0:0") else { return };
        for batch in addresses.chunks(BATCH_SIZE) {
            for address in batch {
                if let Some([a, b, c, d]) = parse_ipv4(address) {
                    let _ = socket.send_to(&[], SocketAddr::from((Ipv4Addr::new(a, b, c, d), DISCARD_PORT)));
                }
            }
            thread::sleep(BATCH_PAUSE);
        }
        thread::sleep(SETTLE);
    }
}

impl NeighbourDiscovery for SystemNeighbourDiscovery {
    fn own(&self) -> Option<SelfObservation> {
        let interface = default_route().interface_name?;
        let address = if_addrs::get_if_addrs().ok()?.into_iter().find_map(|i| match i.addr {
            IfAddr::V4(v4) if i.name == interface && !i.is_loopback() => Some(v4.ip.to_string()),
            _ => None,
        })?;
        Some(SelfObservation { address, hardware_address: hardware_address_of(&interface)? })
    }

    fn discover(&self, addresses: &[String], gateway: &str) -> Vec<NeighbourObservation> {
        Self::resolve_all(addresses);
        let table = run("arp", &[if cfg!(windows) { "-a" } else { "-an" }], COMMAND_TIMEOUT).unwrap_or_default();
        let rows = parse_neighbour_table(&table);
        let gateway_ip = parse_ipv4(gateway).map(|[a, b, c, d]| Ipv4Addr::new(a, b, c, d));
        thread::scope(|scope| {
            let lookups: Vec<_> = rows
                .into_iter()
                .enumerate()
                .map(|(i, (address, hardware_address))| {
                    scope.spawn(move || NeighbourObservation {
                        name: gateway_ip.and_then(|g| name_from_gateway(g, &address, 0x5000 + i as u16)),
                        address,
                        hardware_address,
                    })
                })
                .collect();
            lookups.into_iter().filter_map(|l| l.join().ok()).collect()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_unix_and_windows_neighbour_tables() {
        let unix = "? (192.168.1.1) at a4:83:e7:0:0:1 on en0 ifscope [ethernet]\n? (192.168.1.40) at (incomplete) on en0 ifscope [ethernet]\nrouter.lan (192.168.1.9) at 2e:11:22:33:44:55 on en0\n";
        assert_eq!(parse_neighbour_table(unix), [("192.168.1.1".to_string(), "a4:83:e7:0:0:1".to_string()), ("192.168.1.9".into(), "2e:11:22:33:44:55".into())]);
        let windows = "  192.168.1.1           a4-83-e7-00-00-01     dynamic\n  224.0.0.22            01-00-5e-00-00-16     static\n";
        assert_eq!(parse_neighbour_table(windows).len(), 2);
    }

    #[test]
    fn builds_a_ptr_query_and_reads_the_answer() {
        let query = ptr_query("192.168.1.25", 0x1234).unwrap();
        assert_eq!(&query[..4], &[0x12, 0x34, 0x01, 0x00]);
        assert!(query.ends_with(&[0, 0, 12, 0, 1]));
        assert!(ptr_query("not an address", 1).is_none());

        // A response that repeats the question and answers with a compressed pointer to it.
        let mut response = query.clone();
        response[2..4].copy_from_slice(&[0x81, 0x80]);
        response[6..8].copy_from_slice(&[0, 1]);
        response.extend_from_slice(&[0xC0, 12, 0, 12, 0, 1, 0, 0, 0, 60, 0, 12, 6, b'l', b'a', b'p', b't', b'o', b'p', 3, b'l', b'a', b'n', 0]);
        assert_eq!(parse_ptr_response(&response).as_deref(), Some("laptop.lan"));
        // An error code, or a truncated message, is no name.
        response[3] = 0x83;
        assert_eq!(parse_ptr_response(&response), None);
        assert_eq!(parse_ptr_response(&[0; 5]), None);
    }

    #[test]
    fn a_compression_loop_does_not_hang() {
        let mut message = vec![0u8; 12];
        message[5] = 1;
        message.extend_from_slice(&[0xC0, 12]);
        assert_eq!(parse_ptr_response(&message), None);
    }
}
