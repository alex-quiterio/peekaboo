//! Reads this device's own Wi-Fi link: security, band, channel, signal, rate, width and the neighbours' channels.
//! Network names and hardware addresses are used here only to leave our own access point out of the counts;
//! they never leave this module. macOS and Linux; elsewhere Wi-Fi is Unknown.
use super::route::default_route;
use super::system::run;
use crate::domain::evidence::WifiObservation;
use crate::domain::ports::WifiInspector;
use regex::Regex;
use serde_json::Value;
use std::sync::LazyLock;
use std::time::Duration;

/// The system report takes a few seconds, because it also scans for neighbouring networks.
const REPORT_TIMEOUT: Duration = Duration::from_secs(15);

static LEADING_NUMBER: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\s*(\d+)").unwrap());
static BAND: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\(\s*(\d(?:\.\d)?)\s*GHz").unwrap());
static WIDTH: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(\d+)\s*MHz").unwrap());
static LEVELS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)(-?\d+)\s*dBm\s*/\s*(-?\d+)\s*dBm").unwrap());
static IFACE_NAME: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[A-Za-z0-9._-]{1,15}$").unwrap());

/// Counts of other access points, with our own already left out. 2.4 GHz channels are 5 MHz apart but
/// 20 MHz wide, so neighbours within 4 channels overlap.
fn congestion(channel: u32, others: &[u32]) -> (u32, u32, u32) {
    let same = others.iter().filter(|c| **c == channel).count() as u32;
    let overlapping = if channel <= 14 { others.iter().filter(|c| **c <= 14 && **c != channel && c.abs_diff(channel) <= 4).count() as u32 } else { 0 };
    (same, overlapping, others.len() as u32)
}

/// The adapter's security mode as words the evidence code understands.
pub fn mac_security_text(mode: &str) -> String {
    let m = mode.to_lowercase();
    let (wpa1, wpa2, wpa3) = (m.contains("wpa_"), m.contains("wpa2"), m.contains("wpa3"));
    if wpa3 {
        return if wpa2 || m.contains("transition") { "WPA2 WPA3" } else { "WPA3" }.to_string();
    }
    match (wpa1, wpa2) {
        (true, true) => "WPA WPA2".to_string(),
        (false, true) => "WPA2".to_string(),
        (true, false) => "WPA".to_string(),
        _ if m.contains("wep") => "WEP".to_string(),
        _ if m.ends_with("none") || m.contains("open") => "NONE".to_string(),
        _ if m.contains("owe") => "OWE".to_string(),
        _ => m.to_uppercase(),
    }
}

fn channel_of(text: &str) -> Option<u32> {
    LEADING_NUMBER.captures(text)?[1].parse().ok().filter(|c| *c > 0)
}

/// Parses `system_profiler SPAirPortDataType -json` (macOS).
pub fn parse_mac_wifi(json: &str) -> WifiObservation {
    let none = WifiObservation::default();
    let Ok(root) = serde_json::from_str::<Value>(json) else { return none };
    let interfaces = root["SPAirPortDataType"].as_array().into_iter().flatten().flat_map(|e| e["spairport_airport_interfaces"].as_array().into_iter().flatten());
    let Some(interface) = interfaces.into_iter().find(|i| i["spairport_current_network_information"]["spairport_network_channel"].is_string()) else {
        return none;
    };
    let current = &interface["spairport_current_network_information"];
    let channel_text = current["spairport_network_channel"].as_str().unwrap_or("");
    let channel = channel_of(channel_text);
    let levels = LEVELS.captures(current["spairport_signal_noise"].as_str().unwrap_or(""));
    let level = |i: usize| levels.as_ref().and_then(|c| c[i].parse::<f64>().ok());

    let mut observation = WifiObservation {
        connected: true,
        security: mac_security_text(current["spairport_security_mode"].as_str().unwrap_or("")),
        channel,
        frequency_mhz: BAND.captures(channel_text).and_then(|c| match &c[1] {
            "2" | "2.4" => Some(2437),
            "5" => Some(5500),
            "6" => Some(6500),
            _ => None,
        }),
        link_rate_mbps: current["spairport_network_rate"].as_f64(),
        signal_dbm: level(1),
        noise_dbm: level(2),
        channel_width_mhz: WIDTH.captures(channel_text).and_then(|c| c[1].parse().ok()),
        standard: current["spairport_network_phymode"].as_str().map(str::to_string),
        ..WifiObservation::default()
    };

    // macOS lists the current network apart from "other local wireless networks", so the neighbour list
    // already leaves our own access point out. Names are only a second check, and without Location
    // permission every name is "<redacted>", so then the list is counted as it is.
    let Some(channel) = channel else { return observation };
    let ssid = current["_name"].as_str().filter(|s| !s.is_empty() && !s.to_lowercase().contains("redacted"));
    let others: Vec<u32> = interface["spairport_airport_other_local_wireless_networks"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|n| ssid.is_none() || n["_name"].as_str() != ssid)
        .filter_map(|n| channel_of(n["spairport_network_channel"].as_str().unwrap_or("")))
        .collect();
    if !others.is_empty() {
        let (same, overlapping, nearby) = congestion(channel, &others);
        observation.same_channel_count = Some(same);
        observation.overlapping_count = Some(overlapping);
        observation.nearby_count = Some(nearby);
    }
    observation
}

/// Parses `nmcli -t -f ACTIVE,CHAN,SECURITY dev wifi list` (Linux). Returns our own row, and the others' channels.
pub fn parse_nmcli(output: &str) -> Option<(u32, String, Vec<u32>)> {
    let mut own = None;
    let mut others = Vec::new();
    for line in output.lines() {
        let mut fields = line.splitn(3, ':');
        let (active, channel, security) = (fields.next()?, fields.next().and_then(channel_of), fields.next().unwrap_or(""));
        match (active, channel) {
            ("yes", Some(c)) => own = Some((c, security.replace("--", "").trim().to_string())),
            (_, Some(c)) => others.push(c),
            _ => {}
        }
    }
    own.map(|(c, s)| (c, s, others))
}

/// The link details `iw dev <interface> link` reports.
#[derive(Debug, Default, PartialEq)]
pub struct IwLink {
    pub frequency_mhz: Option<u32>,
    pub signal_dbm: Option<f64>,
    pub rate_mbps: Option<f64>,
    pub width_mhz: Option<u32>,
    pub standard: Option<String>,
}

pub fn parse_iw_link(output: &str) -> Option<IwLink> {
    if !output.contains("Connected to") {
        return None;
    }
    let number = |key: &str| -> Option<f64> {
        let line = output.lines().find(|l| l.trim_start().starts_with(key))?;
        Regex::new(r"(-?\d+(?:\.\d+)?)").unwrap().captures(&line[line.find(':')? + 1..])?[1].parse().ok()
    };
    let bitrate = output.lines().find(|l| l.trim_start().starts_with("tx bitrate")).unwrap_or("");
    let standard = if bitrate.contains("EHT") {
        Some("802.11be")
    } else if bitrate.contains("HE-MCS") {
        Some("802.11ax")
    } else if bitrate.contains("VHT") {
        Some("802.11ac")
    } else if bitrate.contains("MCS") {
        Some("802.11n")
    } else {
        None
    };
    Some(IwLink {
        frequency_mhz: number("freq").map(|f| f as u32),
        signal_dbm: number("signal"),
        rate_mbps: number("tx bitrate"),
        width_mhz: WIDTH.captures(bitrate).and_then(|c| c[1].parse().ok()),
        standard: standard.map(str::to_string),
    })
}

fn inspect_linux() -> WifiObservation {
    let Some(interface) = default_route().interface_name.filter(|n| IFACE_NAME.is_match(n)) else { return WifiObservation::default() };
    let timeout = Duration::from_secs(8);
    let table = run("nmcli", &["-t", "-f", "ACTIVE,CHAN,SECURITY", "dev", "wifi", "list"], timeout).and_then(|o| parse_nmcli(&o));
    let link = run("iw", &["dev", &interface, "link"], timeout).and_then(|o| parse_iw_link(&o));
    if table.is_none() && link.is_none() {
        return WifiObservation::default();
    }
    let mut observation = WifiObservation { connected: true, ..WifiObservation::default() };
    if let Some((channel, security, others)) = table {
        let (same, overlapping, nearby) = congestion(channel, &others);
        observation.channel = Some(channel);
        observation.security = security;
        observation.same_channel_count = Some(same);
        observation.overlapping_count = Some(overlapping);
        observation.nearby_count = Some(nearby);
    }
    if let Some(link) = link {
        observation.frequency_mhz = link.frequency_mhz;
        observation.signal_dbm = link.signal_dbm;
        observation.link_rate_mbps = link.rate_mbps;
        observation.channel_width_mhz = link.width_mhz;
        observation.standard = link.standard;
    }
    observation
}

pub struct SystemWifiInspector;

impl WifiInspector for SystemWifiInspector {
    fn inspect(&self) -> WifiObservation {
        if cfg!(target_os = "macos") {
            run("/usr/sbin/system_profiler", &["SPAirPortDataType", "-json"], REPORT_TIMEOUT).map(|o| parse_mac_wifi(&o)).unwrap_or_default()
        } else if cfg!(target_os = "linux") {
            inspect_linux()
        } else {
            WifiObservation::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mac_report(name: &str, others: &str) -> String {
        format!(
            r#"{{"SPAirPortDataType":[{{"spairport_airport_interfaces":[
            {{"_name":"awdl0","spairport_current_network_information":{{"spairport_network_type":"station"}}}},
            {{"_name":"en0","spairport_airport_other_local_wireless_networks":[{others}],
              "spairport_current_network_information":{{"_name":"{name}","spairport_network_channel":"36 (5GHz, 80MHz)",
              "spairport_network_phymode":"802.11ax","spairport_network_rate":1200,"spairport_security_mode":"spairport_security_mode_wpa3_transition",
              "spairport_signal_noise":"-52 dBm / -93 dBm"}}}}]}}]}}"#
        )
    }

    #[test]
    fn reads_the_radio_figures_of_the_current_macos_connection() {
        let obs = parse_mac_wifi(&mac_report("<redacted>", ""));
        assert!(obs.connected);
        assert_eq!((obs.channel, obs.channel_width_mhz, obs.link_rate_mbps), (Some(36), Some(80), Some(1200.0)));
        assert_eq!((obs.signal_dbm, obs.noise_dbm), (Some(-52.0), Some(-93.0)));
        assert_eq!((obs.security.as_str(), obs.standard.as_deref()), ("WPA2 WPA3", Some("802.11ax")));
        // No neighbours listed, so congestion stays unknown.
        assert_eq!((obs.same_channel_count, obs.nearby_count), (None, None));
    }

    #[test]
    fn counts_the_neighbour_list_when_names_are_redacted() {
        let others = r#"{"_name":"<redacted>","spairport_network_channel":"36 (5GHz, 80MHz)"},
                        {"_name":"<redacted>","spairport_network_channel":"149 (5GHz, 80MHz)"}"#;
        let obs = parse_mac_wifi(&mac_report("<redacted>", others));
        assert_eq!((obs.same_channel_count, obs.nearby_count, obs.overlapping_count), (Some(1), Some(2), Some(0)));
    }

    #[test]
    fn counts_neighbours_only_when_our_own_access_point_can_be_told_apart() {
        let others = r#"{"_name":"Home","spairport_network_channel":"36 (5GHz, 80MHz)"},
                        {"_name":"Cafe","spairport_network_channel":"36 (5GHz, 80MHz)"},
                        {"_name":"Flat 2","spairport_network_channel":"149 (5GHz, 80MHz)"}"#;
        let obs = parse_mac_wifi(&mac_report("Home", others));
        assert_eq!((obs.same_channel_count, obs.nearby_count, obs.overlapping_count), (Some(1), Some(2), Some(0)));
    }

    #[test]
    fn nothing_connected_or_unreadable_is_unknown() {
        assert!(!parse_mac_wifi(r#"{"SPAirPortDataType":[{"spairport_airport_interfaces":[]}]}"#).connected);
        assert!(!parse_mac_wifi("not json").connected);
    }

    #[test]
    fn macos_security_modes() {
        let cases = [
            ("spairport_security_mode_wpa2_personal", "WPA2"),
            ("spairport_security_mode_wpa3_personal", "WPA3"),
            ("spairport_security_mode_wpa3_transition", "WPA2 WPA3"),
            ("spairport_security_mode_wpa_personal", "WPA"),
            ("spairport_security_mode_wpa_wpa2_personal", "WPA WPA2"),
            ("spairport_security_mode_wep", "WEP"),
            ("spairport_security_mode_none", "NONE"),
        ];
        for (mode, text) in cases {
            assert_eq!(mac_security_text(mode), text, "{mode}");
        }
    }

    #[test]
    fn congestion_on_2_4_ghz_counts_overlapping_channels() {
        assert_eq!(congestion(6, &[6, 1, 3, 9, 11, 40]), (1, 2, 6));
        assert_eq!(congestion(36, &[36, 40]), (1, 0, 2));
    }

    #[test]
    fn reads_nmcli_and_iw_output() {
        let table = "yes:36:WPA2 WPA3\nno:36:WPA2\nno:6:--\nno:11:WPA2\n";
        assert_eq!(parse_nmcli(table), Some((36, "WPA2 WPA3".into(), vec![36, 6, 11])));
        assert_eq!(parse_nmcli("no:6:WPA2\n"), None);

        let iw = "Connected to aa:bb:cc:dd:ee:ff (on wlan0)\n\tSSID: Home\n\tfreq: 5180\n\tsignal: -52 dBm\n\ttx bitrate: 866.7 MBit/s VHT-MCS 9 80MHz short GI VHT-NSS 2\n";
        assert_eq!(
            parse_iw_link(iw),
            Some(IwLink { frequency_mhz: Some(5180), signal_dbm: Some(-52.0), rate_mbps: Some(866.7), width_mhz: Some(80), standard: Some("802.11ac".into()) })
        );
        assert_eq!(parse_iw_link("Not connected.\n"), None);
    }
}
