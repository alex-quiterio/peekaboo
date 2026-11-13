//! The device list: what else is on the home network. Built on request for the dashboard and never
//! part of a report, so nothing here is sanitized. It must not be saved, logged or printed.
use super::gateway::is_private_ipv4;
use serde::Serialize;
use std::collections::BTreeMap;

/// One row of this device's neighbour table, plus the name the gateway gave for it, if any.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NeighbourObservation {
    pub address: String,
    pub hardware_address: String,
    pub name: Option<String>,
}

/// This device's own address on the default interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelfObservation {
    pub address: String,
    pub hardware_address: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum DeviceRole {
    Router,
    ThisDevice,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkDevice {
    pub address: String,
    pub name: Option<String>,
    pub hardware_address: String,
    pub role: DeviceRole,
    /// The device shows a private (randomised) hardware address, as phones and laptops do by default.
    pub randomised_address: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceList {
    pub listed_at: String,
    pub devices: Vec<NetworkDevice>,
}

fn network(address: &str) -> &str {
    address.rfind('.').map_or(address, |i| &address[..i])
}

fn host(address: &str) -> u32 {
    address.rfind('.').and_then(|i| address[i + 1..].parse().ok()).unwrap_or(0)
}

/// The only addresses discovery may touch: the 254 hosts of this device's own /24, and only when that is
/// the gateway's network too. Anything else yields nothing, so nothing is sent.
pub fn sweep_targets(own: &str, gateway: &str) -> Vec<String> {
    if !is_private_ipv4(own) || !is_private_ipv4(gateway) || network(own) != network(gateway) {
        return vec![];
    }
    (1..=254).map(|i| format!("{}.{i}", network(own))).filter(|a| a != own).collect()
}

/// Lower-case, zero-padded "aa:bb:cc:dd:ee:ff"; None for anything that is not one real device's address.
pub fn normalise_hardware_address(raw: &str) -> Option<String> {
    let lower = raw.trim().to_lowercase();
    let octets: Vec<&str> = lower.split([':', '-']).collect();
    if octets.len() != 6 || octets.iter().any(|o| o.is_empty() || o.len() > 2 || !o.bytes().all(|b| b.is_ascii_hexdigit())) {
        return None;
    }
    let address = octets.iter().map(|o| format!("{o:0>2}")).collect::<Vec<_>>().join(":");
    if address == "00:00:00:00:00:00" {
        return None;
    }
    // The lowest bit of the first octet marks broadcast and multicast groups, not devices.
    (u8::from_str_radix(&address[..2], 16).ok()? & 1 == 0).then_some(address)
}

/// True when the locally-administered bit is set, which is how operating systems mark a randomised address.
pub fn is_randomised_hardware_address(raw: &str) -> Option<bool> {
    let address = normalise_hardware_address(raw)?;
    Some(u8::from_str_radix(&address[..2], 16).ok()? & 2 == 2)
}

pub fn device_list_from(neighbours: &[NeighbourObservation], gateway: &str, own: Option<&SelfObservation>, listed_at: String) -> DeviceList {
    let mut devices: BTreeMap<String, NetworkDevice> = BTreeMap::new();
    let mut add = |observation: &NeighbourObservation, role: DeviceRole| {
        let Some(hardware_address) = normalise_hardware_address(&observation.hardware_address) else { return };
        let address = &observation.address;
        if !is_private_ipv4(address) || network(address) != network(gateway) {
            return;
        }
        devices.insert(
            address.clone(),
            NetworkDevice {
                address: address.clone(),
                name: observation.name.as_deref().map(str::trim).filter(|n| !n.is_empty()).map(str::to_string),
                randomised_address: is_randomised_hardware_address(&hardware_address) == Some(true),
                hardware_address,
                role,
            },
        );
    };
    for n in neighbours {
        add(n, if n.address == gateway { DeviceRole::Router } else { DeviceRole::Other });
    }
    if let Some(own) = own {
        add(&NeighbourObservation { address: own.address.clone(), hardware_address: own.hardware_address.clone(), name: None }, DeviceRole::ThisDevice);
    }
    let mut devices: Vec<NetworkDevice> = devices.into_values().collect();
    devices.sort_by_key(|d| host(&d.address));
    DeviceList { listed_at, devices }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sweeps_only_the_own_slash_24_of_the_gateway() {
        assert_eq!(sweep_targets("192.168.1.20", "192.168.1.1").len(), 253);
        assert!(!sweep_targets("192.168.1.20", "192.168.1.1").contains(&"192.168.1.20".to_string()));
        assert!(sweep_targets("192.168.1.20", "192.168.2.1").is_empty());
        assert!(sweep_targets("8.8.8.8", "8.8.8.1").is_empty());
    }

    #[test]
    fn hardware_addresses_are_normalised_and_group_addresses_refused() {
        assert_eq!(normalise_hardware_address("A:b:C:d:e:f0").as_deref(), Some("0a:0b:0c:0d:0e:f0"));
        assert_eq!(normalise_hardware_address("ff:ff:ff:ff:ff:ff"), None);
        assert_eq!(normalise_hardware_address("01:00:5e:00:00:fb"), None);
        assert_eq!(normalise_hardware_address("00:00:00:00:00:00"), None);
        assert_eq!(normalise_hardware_address("(incomplete)"), None);
        assert_eq!(is_randomised_hardware_address("2e:11:22:33:44:55"), Some(true));
        assert_eq!(is_randomised_hardware_address("a4:83:e7:22:33:44"), Some(false));
    }

    #[test]
    fn lists_devices_by_host_number_with_roles_and_drops_foreign_networks() {
        let n = |a: &str, h: &str, name: Option<&str>| NeighbourObservation { address: a.into(), hardware_address: h.into(), name: name.map(Into::into) };
        let own = SelfObservation { address: "192.168.1.20".into(), hardware_address: "2e:aa:bb:cc:dd:ee".into() };
        let list = device_list_from(
            &[n("192.168.1.40", "a4:83:e7:00:00:02", Some(" tv ")), n("192.168.1.1", "a4:83:e7:00:00:01", None), n("10.0.0.5", "a4:83:e7:00:00:03", None), n("192.168.1.9", "ff:ff:ff:ff:ff:ff", None)],
            "192.168.1.1",
            Some(&own),
            "t".into(),
        );
        let rows: Vec<_> = list.devices.iter().map(|d| (d.address.as_str(), d.role, d.name.as_deref(), d.randomised_address)).collect();
        assert_eq!(
            rows,
            [("192.168.1.1", DeviceRole::Router, None, false), ("192.168.1.20", DeviceRole::ThisDevice, None, true), ("192.168.1.40", DeviceRole::Other, Some("tv"), false)]
        );
    }
}
