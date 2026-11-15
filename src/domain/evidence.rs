//! Turns raw observations into sanitized checks. Raw values (addresses, adapter strings) stop here.
use super::gateway::{is_private_ipv4, parse_ipv4, redact_ipv4, SafetyStop};
use super::model::*;
use regex::Regex;
use std::sync::LazyLock;

// ---------- DNS (reported by the user) ----------

pub fn parse_dns(value: Option<&str>) -> Result<DnsStatus, SafetyStop> {
    match value {
        None | Some("") | Some("unknown") => Ok(DnsStatus::Unknown),
        Some("encrypted") => Ok(DnsStatus::Encrypted),
        Some("plaintext") => Ok(DnsStatus::Plaintext),
        Some(_) => Err(SafetyStop::new("--dns must be encrypted, plaintext, or unknown.")),
    }
}

/// The DNS status the evidence supports. A reported "encrypted" stands only while no tunnel is connected:
/// a tunnel can take over DNS and send lookups around an encrypted-DNS profile.
pub fn effective_dns(checks: &Checks) -> DnsStatus {
    if checks.dns.status == DnsStatus::Encrypted && checks.environment.tunnel_active == Some(true) {
        DnsStatus::Unknown
    } else {
        checks.dns.status
    }
}

// ---------- Wi-Fi ----------

/// What an inspector may hand over: no SSID, BSSID or other identifier.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct WifiObservation {
    pub connected: bool,
    /// The adapter's own wording, such as "WPA2" or "WPA2 WPA3". Empty when unknown.
    pub security: String,
    pub channel: Option<u32>,
    pub frequency_mhz: Option<u32>,
    pub same_channel_count: Option<u32>,
    pub overlapping_count: Option<u32>,
    pub nearby_count: Option<u32>,
    /// The negotiated link rate, as this device's radio reports it.
    pub link_rate_mbps: Option<f64>,
    pub signal_dbm: Option<f64>,
    pub noise_dbm: Option<f64>,
    pub channel_width_mhz: Option<u32>,
    /// The adapter's own description of the standard in use, such as "802.11ax".
    pub standard: Option<String>,
}

fn security_text(raw: &str) -> String {
    raw.to_uppercase().trim().to_string()
}

/// "WPA" that is not WPA2 or WPA3.
fn has_wpa1(s: &str) -> bool {
    s.match_indices("WPA").any(|(i, _)| !matches!(s[i + 3..].chars().next(), Some('2' | '3')))
}

static OPEN: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"NONE|OPEN|^-+$").unwrap());

pub fn classify_security(raw: &str) -> SecurityClass {
    let s = security_text(raw);
    if s.is_empty() {
        return SecurityClass::Unknown;
    }
    if s.contains("WEP") || s.contains("TKIP") {
        return SecurityClass::Weak;
    }
    if s.contains("WPA3") || s.contains("SAE") {
        return SecurityClass::Strong;
    }
    let wpa1 = has_wpa1(&s);
    if s.contains("WPA2") || s.contains("RSN") {
        return if wpa1 { SecurityClass::Review } else { SecurityClass::Strong };
    }
    if wpa1 {
        return SecurityClass::Weak;
    }
    if s.contains("OWE") {
        return SecurityClass::Review;
    }
    if OPEN.is_match(&s) {
        return SecurityClass::Weak;
    }
    SecurityClass::Review
}

/// A fixed vocabulary for display, so raw adapter strings never reach a report.
pub fn security_label(raw: &str) -> Option<String> {
    let s = security_text(raw);
    if s.is_empty() {
        return None;
    }
    let wpa1 = has_wpa1(&s);
    let wpa2 = s.contains("WPA2") || s.contains("RSN");
    let wpa3 = s.contains("WPA3") || s.contains("SAE");
    let label = if s.contains("WEP") {
        "WEP"
    } else if wpa3 && wpa2 {
        "WPA2/WPA3"
    } else if wpa3 {
        "WPA3"
    } else if wpa2 && wpa1 {
        "WPA/WPA2"
    } else if wpa2 {
        "WPA2"
    } else if wpa1 {
        "WPA"
    } else if s.contains("OWE") {
        "Enhanced Open"
    } else if OPEN.is_match(&s) {
        "Open"
    } else {
        "Other"
    };
    Some(label.to_string())
}

pub fn wifi_band(channel: Option<u32>, frequency_mhz: Option<u32>) -> Option<WifiBand> {
    if let Some(f) = frequency_mhz.filter(|f| *f > 0) {
        if f >= 5925 {
            return Some(WifiBand::Ghz6);
        }
        if f >= 4900 {
            return Some(WifiBand::Ghz5);
        }
        if (2400..2500).contains(&f) {
            return Some(WifiBand::Ghz2);
        }
    }
    let channel = channel?;
    Some(if channel <= 14 { WifiBand::Ghz2 } else { WifiBand::Ghz5 })
}

static STANDARD: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)802\.11\s*([a-z/]+)").unwrap());

/// The newest standard named in an adapter string such as "802.11ax" or "802.11a/n/ac".
pub fn wifi_standard(raw: Option<&str>) -> Option<WifiStandard> {
    let captures = STANDARD.captures(raw?)?;
    let modes: Vec<String> = captures[1].to_lowercase().split('/').map(str::to_string).collect();
    let has = |m: &str| modes.iter().any(|x| x == m);
    Some(if has("be") {
        WifiStandard::Wifi7
    } else if has("ax") {
        WifiStandard::Wifi6
    } else if has("ac") {
        WifiStandard::Wifi5
    } else if has("n") {
        WifiStandard::Wifi4
    } else if ["a", "b", "g"].iter().any(|m| has(m)) {
        WifiStandard::Legacy
    } else {
        return None;
    })
}

pub fn signal_quality(dbm: Option<i32>) -> Option<SignalQuality> {
    let dbm = dbm?;
    Some(if dbm >= -55 {
        SignalQuality::Excellent
    } else if dbm >= -67 {
        SignalQuality::Good
    } else if dbm >= -75 {
        SignalQuality::Fair
    } else {
        SignalQuality::Weak
    })
}

const CHANNEL_WIDTHS: [u32; 5] = [20, 40, 80, 160, 320];

/// Keeps a reading only when it is a plausible value; anything else is unknown.
fn wifi_speed_from(observation: &WifiObservation) -> WifiSpeedCheck {
    let dbm = |v: Option<f64>| v.filter(|v| v.is_finite() && *v < 0.0 && *v > -120.0).map(|v| v.round() as i32);
    let signal_dbm = dbm(observation.signal_dbm);
    WifiSpeedCheck {
        link_rate_mbps: observation.link_rate_mbps.filter(|r| r.is_finite() && *r > 0.0).map(|r| r.round() as u32),
        signal_dbm,
        noise_dbm: dbm(observation.noise_dbm),
        signal: signal_quality(signal_dbm),
        channel_width_mhz: observation.channel_width_mhz.filter(|w| CHANNEL_WIDTHS.contains(w)),
        standard: wifi_standard(observation.standard.as_deref()),
        dfs_channel: observation.channel.filter(|_| wifi_band(observation.channel, observation.frequency_mhz) == Some(WifiBand::Ghz5)).map(|c| (52..=144).contains(&c)),
    }
}

pub fn wifi_check_from(observation: &WifiObservation) -> WifiCheck {
    if !observation.connected {
        return WifiCheck {
            state: WifiState::Unknown,
            security: SecurityClass::Unknown,
            security_mode: None,
            band: None,
            same_channel_count: None,
            overlapping_count: None,
            nearby_count: None,
            speed: WifiSpeedCheck::default(),
            stability: WifiStabilityCheck::default(),
        };
    }
    let security = classify_security(&observation.security);
    let complete = security != SecurityClass::Unknown && observation.same_channel_count.is_some();
    WifiCheck {
        state: if complete { WifiState::Known } else { WifiState::Partial },
        security,
        security_mode: security_label(&observation.security),
        band: wifi_band(observation.channel, observation.frequency_mhz),
        same_channel_count: observation.same_channel_count,
        overlapping_count: observation.overlapping_count,
        nearby_count: observation.nearby_count,
        speed: wifi_speed_from(observation),
        stability: WifiStabilityCheck::default(),
    }
}

// ---------- UPnP ----------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawMapping {
    pub protocol: String,
    pub external_port: u32,
    pub internal_port: u32,
    pub internal_host: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpnpObservation {
    Detected(Vec<RawMapping>),
    Refused,
    Unknown,
}

/// Remote-access services that should not be forwarded by accident: FTP, SSH, Telnet, SMB, RDP, VNC.
const SENSITIVE_PORTS: [u32; 6] = [21, 22, 23, 445, 3389, 5900];

pub fn upnp_check_from(observation: &UpnpObservation) -> UpnpCheck {
    let mappings = match observation {
        UpnpObservation::Detected(mappings) => mappings,
        UpnpObservation::Refused => return UpnpCheck { state: UpnpState::Refused, mapping_count: None, sensitive_count: None, mappings: vec![] },
        UpnpObservation::Unknown => return UpnpCheck { state: UpnpState::Unknown, mapping_count: None, sensitive_count: None, mappings: vec![] },
    };
    let mappings: Vec<SanitizedMapping> = mappings
        .iter()
        .enumerate()
        .map(|(i, m)| SanitizedMapping {
            label: format!("<mapping-{}>", i + 1),
            protocol: if m.protocol.eq_ignore_ascii_case("udp") { "UDP" } else { "TCP" }.to_string(),
            external_port: m.external_port,
            internal_port: m.internal_port,
            internal_host: if is_private_ipv4(&m.internal_host) { redact_ipv4(&m.internal_host) } else { "<redacted>".to_string() },
            sensitive: SENSITIVE_PORTS.contains(&m.internal_port) || SENSITIVE_PORTS.contains(&m.external_port),
        })
        .collect();
    UpnpCheck {
        state: UpnpState::Detected,
        mapping_count: Some(mappings.len() as u32),
        sensitive_count: Some(mappings.iter().filter(|m| m.sensitive).count() as u32),
        mappings,
    }
}

// ---------- This device's environment ----------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FirewallObservation {
    pub enabled: bool,
    pub stealth: Option<bool>,
}

/// What this device says about itself. Booleans and counts only: no names, addresses or hardware addresses.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeviceObservation {
    pub tunnel_active: Option<bool>,
    pub firewall: Option<FirewallObservation>,
    pub open_listener_count: Option<u32>,
    pub hardware_address_randomised: Option<bool>,
    pub ipv6_from_hardware_address: Option<bool>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EnvironmentObservation {
    pub device: DeviceObservation,
    /// Resolver addresses as configured on this device. Used for classification only, never stored.
    pub resolvers: Vec<String>,
    pub global_ipv6: Option<bool>,
}

/// True when an IPv6 address embeds the hardware address (EUI-64: "ff:fe" in the middle of the interface half).
pub fn is_hardware_derived_ipv6(address: &str) -> bool {
    let address = address.split('%').next().unwrap_or("");
    let mut halves = address.split("::");
    let head = halves.next().unwrap_or("");
    let tail = halves.next();
    let left: Vec<&str> = if head.is_empty() { vec![] } else { head.split(':').collect() };
    let right: Vec<&str> = match tail {
        Some(t) if !t.is_empty() => t.split(':').collect(),
        _ => vec![],
    };
    let groups: Vec<&str> = match tail {
        None => left,
        Some(_) => {
            let zeros = 8usize.saturating_sub(left.len() + right.len());
            left.into_iter().chain(std::iter::repeat_n("0", zeros)).chain(right).collect()
        }
    };
    if groups.len() != 8 {
        return false;
    }
    let group = |i: usize| format!("{:0>4}", groups[i]).to_lowercase();
    group(5).ends_with("ff") && group(6).starts_with("fe")
}

fn public_resolver(address: &str) -> Option<&'static str> {
    Some(match address {
        "1.1.1.1" | "1.0.0.1" => "Cloudflare",
        "8.8.8.8" | "8.8.4.4" => "Google",
        "9.9.9.9" | "149.112.112.112" => "Quad9",
        "208.67.222.222" | "208.67.220.220" => "OpenDNS",
        "94.140.14.14" | "94.140.15.15" => "AdGuard",
        _ => return None,
    })
}

static LOCAL_RESOLVER: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^127\.|^::1$").unwrap());
static PRIVATE_V6: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)^(fe80|fc|fd)").unwrap());

pub fn environment_check_from(observation: &EnvironmentObservation, gateway: &str) -> EnvironmentCheck {
    let device = &observation.device;
    let mut check = EnvironmentCheck {
        resolver: ResolverKind::Unknown,
        resolver_provider: None,
        global_ipv6: observation.global_ipv6,
        tunnel_active: device.tunnel_active,
        firewall: match device.firewall {
            None => Firewall::Unknown,
            Some(f) if f.enabled => Firewall::On,
            Some(_) => Firewall::Off,
        },
        stealth_mode: device.firewall.and_then(|f| f.stealth),
        open_listener_count: device.open_listener_count,
        private_hardware_address: device.hardware_address_randomised,
        ipv6_from_hardware_address: device.ipv6_from_hardware_address,
    };
    let Some(first) = observation.resolvers.first() else { return check };
    if first == gateway {
        check.resolver = ResolverKind::Gateway;
    } else if LOCAL_RESOLVER.is_match(first) {
        check.resolver = ResolverKind::Local;
    } else if is_private_ipv4(first) || PRIVATE_V6.is_match(first) {
        check.resolver = ResolverKind::Private;
    } else {
        check.resolver = ResolverKind::Public;
        check.resolver_provider = public_resolver(first).map(str::to_string);
    }
    check
}

// ---------- Delay to the ISP (opt-in) ----------

/// The furthest a timing packet may travel. Enough for a mesh or second router in front of the ISP's.
pub const MAX_LATENCY_HOPS: u32 = 4;

/// Who answered a packet that expired after a given number of routers. The address is used for classification only.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct HopObservation {
    pub address: Option<String>,
    pub times_ms: Vec<f64>,
}

/// 100.64.0.0/10, the shared address space that ISPs use for carrier-grade NAT (RFC 6598).
pub fn is_shared_address_space(address: &str) -> bool {
    matches!(parse_ipv4(address), Some([100, b, _, _]) if (64..=127).contains(&b))
}

/// True once a hop outside the home has answered, which is where the measurement must stop.
pub fn is_beyond_home(hop: &HopObservation) -> bool {
    hop.address.as_deref().is_some_and(|a| !is_private_ipv4(a))
}

fn median(values: &[f64]) -> Option<u32> {
    let mut sorted: Vec<f64> = values.iter().copied().filter(|v| v.is_finite() && *v >= 0.0).collect();
    if sorted.is_empty() {
        return None;
    }
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let middle = sorted.len() / 2;
    let value = if sorted.len() % 2 == 1 { sorted[middle] } else { (sorted[middle - 1] + sorted[middle]) / 2.0 };
    Some(value.round() as u32)
}

/// Light covers about 200 km of fibre per millisecond, and the delay is a round trip.
const KM_PER_ROUND_TRIP_MS: u32 = 100;

/// The farthest the ISP's router can be, from the delay the line adds. None when the line adds no measurable
/// delay, because then the limit would read as "0 km", which the evidence does not support.
pub fn max_cable_km(router_ms: Option<u32>, isp_ms: Option<u32>) -> Option<u32> {
    match (router_ms, isp_ms) {
        (Some(router), Some(isp)) if isp > router => Some((isp - router) * KM_PER_ROUND_TRIP_MS),
        _ => None,
    }
}

/// `hops[0]` is the first router on the path. Unless that is the audited gateway, nothing is concluded.
pub fn latency_check_from(requested: bool, hops: &[HopObservation], gateway: &str) -> LatencyCheck {
    if !requested {
        return LatencyCheck::default();
    }
    let unknown = LatencyCheck { requested: true, ..LatencyCheck::default() };
    let Some(router) = hops.first().filter(|h| h.address.as_deref() == Some(gateway)) else { return unknown };
    let router_ms = median(&router.times_ms);
    let isp_index = hops.iter().enumerate().position(|(i, h)| i > 0 && is_beyond_home(h));
    let isp_ms = isp_index.and_then(|i| median(&hops[i].times_ms));
    LatencyCheck {
        requested: true,
        router_ms,
        isp_ms,
        own_hops: isp_ms.and(isp_index).map(|i| i as u32),
        isp_max_km: max_cable_km(router_ms, isp_ms),
        // Only the yes/no leaves here: the address itself is never kept.
        carrier_grade_nat: isp_index.and_then(|i| hops[i].address.as_deref()).map(is_shared_address_space),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_accepts_only_the_three_values() {
        assert_eq!(parse_dns(None).unwrap(), DnsStatus::Unknown);
        assert_eq!(parse_dns(Some("encrypted")).unwrap(), DnsStatus::Encrypted);
        assert_eq!(parse_dns(Some("8.8.8.8")).unwrap_err().0, "--dns must be encrypted, plaintext, or unknown.");
    }

    #[test]
    fn wifi_security_classes_and_labels() {
        let cases = [
            ("WPA3 Personal", SecurityClass::Strong, Some("WPA3")),
            ("WPA2 Personal", SecurityClass::Strong, Some("WPA2")),
            ("WPA2/WPA3 Personal", SecurityClass::Strong, Some("WPA2/WPA3")),
            ("WPA/WPA2 Personal", SecurityClass::Review, Some("WPA/WPA2")),
            ("WPA Personal", SecurityClass::Weak, Some("WPA")),
            ("WEP", SecurityClass::Weak, Some("WEP")),
            ("WPA2 TKIP", SecurityClass::Weak, Some("WPA2")),
            ("none", SecurityClass::Weak, Some("Open")),
            ("", SecurityClass::Unknown, None),
        ];
        for (raw, class, label) in cases {
            assert_eq!(classify_security(raw), class, "{raw}");
            assert_eq!(security_label(raw).as_deref(), label, "{raw}");
        }
    }

    #[test]
    fn wifi_states_and_band() {
        let seen = WifiObservation { connected: true, security: "WPA2 WPA3".into(), channel: Some(40), frequency_mhz: Some(5200), ..Default::default() };
        let known = wifi_check_from(&WifiObservation { same_channel_count: Some(1), ..seen.clone() });
        assert_eq!((known.state, known.band), (WifiState::Known, Some(WifiBand::Ghz5)));
        assert_eq!(wifi_check_from(&seen).state, WifiState::Partial);
        assert_eq!(wifi_check_from(&WifiObservation::default()).state, WifiState::Unknown);
        assert_eq!(
            [wifi_band(Some(6), None), wifi_band(Some(36), None), wifi_band(Some(37), Some(6135)), wifi_band(None, None)],
            [Some(WifiBand::Ghz2), Some(WifiBand::Ghz5), Some(WifiBand::Ghz6), None]
        );
    }

    #[test]
    fn upnp_mappings_are_sanitized_and_remote_access_forwards_are_flagged() {
        let raw = |p: &str, e, i, h: &str| RawMapping { protocol: p.into(), external_port: e, internal_port: i, internal_host: h.into() };
        let check = upnp_check_from(&UpnpObservation::Detected(vec![
            raw("tcp", 8080, 80, "192.168.1.25"),
            raw("udp", 9, 9, "my-laptop.local"),
            raw("tcp", 50022, 22, "192.168.1.30"),
        ]));
        assert_eq!((check.mapping_count, check.sensitive_count), (Some(3), Some(1)));
        let rows: Vec<_> = check.mappings.iter().map(|m| (m.label.as_str(), m.protocol.as_str(), m.internal_host.as_str(), m.sensitive)).collect();
        assert_eq!(rows, [("<mapping-1>", "TCP", "192.168.1.x", false), ("<mapping-2>", "UDP", "<redacted>", false), ("<mapping-3>", "TCP", "192.168.1.x", true)]);
        assert_eq!(upnp_check_from(&UpnpObservation::Refused).mapping_count, None);
    }

    #[test]
    fn resolver_is_classified_without_keeping_its_address() {
        let classify = |resolver: &str| {
            environment_check_from(&EnvironmentObservation { resolvers: vec![resolver.into()], global_ipv6: Some(false), ..Default::default() }, "192.168.1.1")
        };
        assert_eq!(classify("192.168.1.1").resolver, ResolverKind::Gateway);
        assert_eq!(classify("192.168.1.53").resolver, ResolverKind::Private);
        assert_eq!(classify("127.0.0.1").resolver, ResolverKind::Local);
        let quad9 = classify("9.9.9.9");
        assert_eq!((quad9.resolver, quad9.resolver_provider.as_deref()), (ResolverKind::Public, Some("Quad9")));
        assert_eq!(classify("203.0.113.9").resolver_provider, None);
        assert_eq!(environment_check_from(&EnvironmentObservation::default(), "192.168.1.1").resolver, ResolverKind::Unknown);
        assert!(!serde_json::to_string(&classify("192.168.1.53")).unwrap().contains("192.168"));
    }

    #[test]
    fn an_ipv6_address_built_from_the_hardware_address_is_flagged() {
        assert!(is_hardware_derived_ipv6("2001:db8::a683:e7ff:fe22:3344"));
        assert!(is_hardware_derived_ipv6("2001:db8:1:2:a683:e7ff:fe22:3344%en0"));
        assert!(!is_hardware_derived_ipv6("2001:db8::1c3a:9b2f:77de:41a0"));
        assert!(!is_hardware_derived_ipv6("2001:db8::1"));
        assert!(!is_hardware_derived_ipv6("not-an-address"));
    }

    #[test]
    fn standards_and_signal() {
        let standards: Vec<_> = ["802.11be", "802.11ax", "802.11a/n/ac", "802.11n", "802.11b/g", "AirPort"].map(|s| wifi_standard(Some(s))).into();
        assert_eq!(
            standards,
            [Some(WifiStandard::Wifi7), Some(WifiStandard::Wifi6), Some(WifiStandard::Wifi5), Some(WifiStandard::Wifi4), Some(WifiStandard::Legacy), None]
        );
        assert_eq!(wifi_standard(None), None);
        let graded: Vec<_> = [-40, -60, -72, -80].map(|d| signal_quality(Some(d))).into();
        assert_eq!(graded, [Some(SignalQuality::Excellent), Some(SignalQuality::Good), Some(SignalQuality::Fair), Some(SignalQuality::Weak)]);
    }

    #[test]
    fn implausible_readings_become_unknown_and_the_raw_adapter_string_is_not_kept() {
        let seen = WifiObservation {
            connected: true,
            security: "WPA3".into(),
            link_rate_mbps: Some(0.0),
            signal_dbm: Some(56.0),
            noise_dbm: Some(f64::NAN),
            channel_width_mhz: Some(33),
            standard: Some("802.11ax (secret)".into()),
            ..Default::default()
        };
        assert_eq!(
            wifi_check_from(&seen).speed,
            WifiSpeedCheck { standard: Some(WifiStandard::Wifi6), ..Default::default() }
        );
    }

    #[test]
    fn delay_is_read_from_the_first_two_hops_and_distance_is_only_an_upper_limit() {
        let hop = |a: &str, t: &[f64]| HopObservation { address: Some(a.into()), times_ms: t.to_vec() };
        let check = latency_check_from(true, &[hop("192.168.1.1", &[4.0, 2.0, 3.0]), hop("203.0.113.9", &[9.0, 12.0, 30.0])], "192.168.1.1");
        assert_eq!(check, LatencyCheck { requested: true, router_ms: Some(3), isp_ms: Some(12), own_hops: Some(1), isp_max_km: Some(900), carrier_grade_nat: Some(false) });
        // The shared range is how an ISP's carrier-grade NAT shows up; only the yes/no is kept.
        let cgnat = latency_check_from(true, &[hop("192.168.1.1", &[3.0]), hop("100.64.12.1", &[9.0])], "192.168.1.1");
        assert_eq!(cgnat.carrier_grade_nat, Some(true));
        assert_eq!(latency_check_from(true, &[hop("192.168.1.1", &[3.0])], "192.168.1.1").carrier_grade_nat, None);
        for (address, shared) in [("100.64.0.1", true), ("100.127.255.254", true), ("100.63.255.255", false), ("100.128.0.1", false), ("10.0.0.1", false), ("8.8.8.8", false), ("not-an-ip", false)] {
            assert_eq!(is_shared_address_space(address), shared, "{address}");
        }
        assert_eq!(latency_check_from(false, &[], "192.168.1.1"), LatencyCheck::default());
        // The path must start at the audited gateway.
        assert_eq!(latency_check_from(true, &[hop("10.8.0.1", &[5.0])], "192.168.1.1"), LatencyCheck { requested: true, ..Default::default() });
        // No gap, no distance.
        assert_eq!(max_cable_km(Some(9), Some(8)), None);
        assert_eq!(max_cable_km(Some(5), Some(11)), Some(600));
    }
}
