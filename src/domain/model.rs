//! The audit's vocabulary. Everything here is already sanitized: no identifiers, no full addresses.
//! The JSON shape is the same as the TypeScript version wrote, so existing reports still load.
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DnsStatus {
    Encrypted,
    Plaintext,
    Unknown,
}

impl DnsStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            DnsStatus::Encrypted => "encrypted",
            DnsStatus::Plaintext => "plaintext",
            DnsStatus::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Severity {
    High,
    Medium,
    Low,
    Info,
}

/// Most severe first.
pub const SEVERITY_ORDER: [Severity; 4] = [Severity::High, Severity::Medium, Severity::Low, Severity::Info];

impl Severity {
    pub fn label(self) -> &'static str {
        match self {
            Severity::High => "HIGH",
            Severity::Medium => "MEDIUM",
            Severity::Low => "LOW",
            Severity::Info => "INFO",
        }
    }
    pub fn rank(self) -> usize {
        SEVERITY_ORDER.iter().position(|s| *s == self).unwrap_or(3)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SecurityClass {
    Strong,
    Weak,
    Review,
    Unknown,
}

impl SecurityClass {
    pub fn as_str(self) -> &'static str {
        match self {
            SecurityClass::Strong => "strong",
            SecurityClass::Weak => "weak",
            SecurityClass::Review => "review",
            SecurityClass::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WifiBand {
    #[serde(rename = "2.4 GHz")]
    Ghz2,
    #[serde(rename = "5 GHz")]
    Ghz5,
    #[serde(rename = "6 GHz")]
    Ghz6,
}

impl WifiBand {
    pub fn as_str(self) -> &'static str {
        match self {
            WifiBand::Ghz2 => "2.4 GHz",
            WifiBand::Ghz5 => "5 GHz",
            WifiBand::Ghz6 => "6 GHz",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WifiStandard {
    #[serde(rename = "Wi-Fi 7")]
    Wifi7,
    #[serde(rename = "Wi-Fi 6")]
    Wifi6,
    #[serde(rename = "Wi-Fi 5")]
    Wifi5,
    #[serde(rename = "Wi-Fi 4")]
    Wifi4,
    #[serde(rename = "Legacy")]
    Legacy,
}

impl WifiStandard {
    pub fn as_str(self) -> &'static str {
        match self {
            WifiStandard::Wifi7 => "Wi-Fi 7",
            WifiStandard::Wifi6 => "Wi-Fi 6",
            WifiStandard::Wifi5 => "Wi-Fi 5",
            WifiStandard::Wifi4 => "Wi-Fi 4",
            WifiStandard::Legacy => "Legacy",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SignalQuality {
    Excellent,
    Good,
    Fair,
    Weak,
}

impl SignalQuality {
    pub fn as_str(self) -> &'static str {
        match self {
            SignalQuality::Excellent => "excellent",
            SignalQuality::Good => "good",
            SignalQuality::Fair => "fair",
            SignalQuality::Weak => "weak",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ResolverKind {
    Gateway,
    Private,
    Local,
    Public,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortCheck {
    pub port: u16,
    pub service: String,
    pub reachable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SanitizedMapping {
    pub label: String,
    pub protocol: String,
    pub external_port: u32,
    pub internal_port: u32,
    pub internal_host: String,
    /// Forwards to a remote-access service (SSH, Telnet, SMB, RDP, VNC, FTP).
    pub sensitive: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UpnpState {
    Detected,
    Refused,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpnpCheck {
    pub state: UpnpState,
    pub mapping_count: Option<u32>,
    pub sensitive_count: Option<u32>,
    pub mappings: Vec<SanitizedMapping>,
}

/// How fast the radio link between this device and its access point is. Read from this device; nothing is sent.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct WifiSpeedCheck {
    /// The rate the radio has negotiated. A ceiling, not a measured throughput.
    pub link_rate_mbps: Option<u32>,
    pub signal_dbm: Option<i32>,
    pub noise_dbm: Option<i32>,
    pub signal: Option<SignalQuality>,
    pub channel_width_mhz: Option<u32>,
    pub standard: Option<WifiStandard>,
    /// The 5 GHz channel is one that routers must vacate when they detect radar (channels 52 to 144).
    pub dfs_channel: Option<bool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WifiState {
    Known,
    Partial,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WifiCheck {
    pub state: WifiState,
    pub security: SecurityClass,
    pub security_mode: Option<String>,
    pub band: Option<WifiBand>,
    pub same_channel_count: Option<u32>,
    /// Access points on neighbouring, overlapping channels. Only meaningful on 2.4 GHz.
    pub overlapping_count: Option<u32>,
    pub nearby_count: Option<u32>,
    #[serde(default)]
    pub speed: WifiSpeedCheck,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Firewall {
    On,
    Off,
    Unknown,
}

/// Evidence read from this device, not from the network.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnvironmentCheck {
    pub resolver: ResolverKind,
    /// A well-known provider name, when the resolver is a recognised public one.
    pub resolver_provider: Option<String>,
    pub global_ipv6: Option<bool>,
    /// A VPN or tunnel is connected while the default route still goes through the home router.
    pub tunnel_active: Option<bool>,
    pub firewall: Firewall,
    pub stealth_mode: Option<bool>,
    /// Ports on this device that accept connections from the network. A lower bound.
    pub open_listener_count: Option<u32>,
    /// The network sees a randomised hardware address instead of the real one.
    pub private_hardware_address: Option<bool>,
    /// A global IPv6 address is built from the hardware address.
    pub ipv6_from_hardware_address: Option<bool>,
}

/// Round-trip delay to this network's own router and to the first router past it. Opt-in; no address is kept.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct LatencyCheck {
    pub requested: bool,
    pub router_ms: Option<u32>,
    pub isp_ms: Option<u32>,
    /// Routers of your own between this device and the ISP. 1 means just the default gateway.
    pub own_hops: Option<u32>,
    /// The most cable there can be between the user's router and the ISP's. An upper limit, never an estimate.
    pub isp_max_km: Option<u32>,
    /// The first router past the user's own is in the shared address range that ISPs use for carrier-grade
    /// NAT (100.64.0.0/10), so the connection is most likely behind CGNAT. None when the delay was not measured.
    pub carrier_grade_nat: Option<bool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsCheck {
    pub status: DnsStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Checks {
    pub ports: Vec<PortCheck>,
    pub upnp: UpnpCheck,
    pub wifi: WifiCheck,
    pub dns: DnsCheck,
    pub environment: EnvironmentCheck,
    #[serde(default)]
    pub latency: LatencyCheck,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScoreLine {
    pub id: String,
    pub label: String,
    pub weight: u32,
    /// None = unknown, left out of the score.
    pub earned: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Score {
    pub provisional: Option<u32>,
    pub coverage_percent: u32,
    pub earned_weight: u32,
    pub known_weight: u32,
    pub total_weight: u32,
    pub breakdown: Vec<ScoreLine>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub severity: Severity,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Comparison {
    pub previous_score: i64,
    pub current_score: i64,
    pub delta: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Report {
    pub generated_at: String,
    pub platform: String,
    pub target: String,
    pub checks: Checks,
    pub score: Score,
    pub findings: Vec<Finding>,
    pub top_fixes: Vec<String>,
    /// Ways to make the Wi-Fi faster. Kept apart from `top_fixes`, which are about privacy.
    #[serde(default)]
    pub speed_tips: Vec<String>,
    pub privacy: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comparison: Option<Comparison>,
}
