//! The opt-in speed test result. Numbers only: the tester's own output (server names, addresses, interface) is
//! reduced to these figures before it leaves the adapter. Never scored, never saved.
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SpeedTestResult {
    pub download_mbps: f64,
    pub upload_mbps: f64,
    pub idle_latency_ms: Option<f64>,
    /// Round trips per minute while the link is saturated (higher is better).
    pub responsiveness_rpm: Option<u32>,
    pub loaded_latency_ms: Option<f64>,
}

/// How responsive the link stays under load, by Apple's own bands for round trips per minute.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Responsiveness {
    High,
    Medium,
    Low,
}

impl SpeedTestResult {
    pub fn responsiveness(&self) -> Option<Responsiveness> {
        self.responsiveness_rpm.map(|rpm| match rpm {
            1000.. => Responsiveness::High,
            200..=999 => Responsiveness::Medium,
            _ => Responsiveness::Low,
        })
    }
}

fn mbps(bits_per_second: f64) -> f64 {
    (bits_per_second / 1_000.0).round() / 1_000.0
}

fn tenth(value: f64) -> f64 {
    (value * 10.0).round() / 10.0
}

/// Reads the JSON that `networkQuality -c` prints. Anything that is not a plausible reading is unknown.
pub fn parse_speed_test(json: &str) -> Option<SpeedTestResult> {
    let root: Value = serde_json::from_str(json).ok()?;
    let number = |key: &str| root[key].as_f64().filter(|v| v.is_finite() && *v > 0.0);
    let download = number("dl_throughput")?;
    let upload = number("ul_throughput")?;
    let rpm = number("responsiveness").map(|r| r.round() as u32).filter(|r| *r > 0);
    Some(SpeedTestResult {
        download_mbps: mbps(download),
        upload_mbps: mbps(upload),
        idle_latency_ms: number("base_rtt").map(tenth),
        responsiveness_rpm: rpm,
        loaded_latency_ms: rpm.map(|r| tenth(60_000.0 / f64::from(r))),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_figures_and_drops_everything_else() {
        let json = r#"{"dl_throughput":35055000,"ul_throughput":97578000,"base_rtt":11.38,"responsiveness":179,"interface_name":"en0"}"#;
        let r = parse_speed_test(json).unwrap();
        assert_eq!((r.download_mbps, r.upload_mbps, r.idle_latency_ms, r.responsiveness_rpm), (35.055, 97.578, Some(11.4), Some(179)));
        assert_eq!(r.loaded_latency_ms, Some(335.2));
        assert_eq!(r.responsiveness(), Some(Responsiveness::Low));
        assert!(!serde_json::to_string(&r).unwrap().contains("en0"));
    }

    #[test]
    fn unreadable_or_implausible_output_is_unknown() {
        for bad in ["", "not json", "{}", r#"{"dl_throughput":0,"ul_throughput":1}"#, r#"{"dl_throughput":-5,"ul_throughput":1}"#] {
            assert_eq!(parse_speed_test(bad), None, "{bad}");
        }
    }
}
