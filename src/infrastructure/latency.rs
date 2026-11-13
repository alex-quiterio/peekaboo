//! The opt-in ISP delay check. Sends packets with a very small hop limit, so they expire at a router close
//! to home and never arrive anywhere. Hop addresses are used to tell "mine" from "the ISP's" and go no further.
use super::system::run;
use crate::domain::evidence::{HopObservation, MAX_LATENCY_HOPS};
use crate::domain::ports::LatencyProbe;
use regex::Regex;
use std::sync::LazyLock;
use std::time::Duration;

/// The direction the packets are sent in, not a host that is contacted: with this hop limit they expire long
/// before arriving. Fixed, and never taken from input. A real routable address is needed because home routers
/// drop packets for reserved test addresses.
const DIRECTION: &str = "9.9.9.9";
const PROBES_PER_HOP: u32 = 3;
const WAIT_SECONDS: u32 = 1;

static ADDRESS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\b\d{1,3}(?:\.\d{1,3}){3}\b").unwrap());
static TIME: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(\d+(?:\.\d+)?)\s*ms").unwrap());

/// Reads the one hop line of traceroute output, such as " 2  * 198.51.100.1  10.2 ms  7.1 ms".
pub fn parse_hop(output: Option<&str>, hops: u32) -> Option<HopObservation> {
    let line = output?.lines().find(|l| {
        let t = l.trim_start();
        t.strip_prefix(&hops.to_string()).is_some_and(|rest| rest.starts_with(char::is_whitespace))
    })?;
    let address = ADDRESS.find_iter(line).find(|m| !line[m.end()..].trim_start().starts_with("ms")).map(|m| m.as_str().to_string());
    let times_ms: Vec<f64> = TIME.captures_iter(line).filter_map(|c| c[1].parse().ok()).collect();
    // A reply from the far end would mean the packet arrived, which is not a hop on the way.
    if address.as_deref() == Some(DIRECTION) {
        return Some(HopObservation::default());
    }
    Some(HopObservation { address, times_ms })
}

pub struct TracerouteLatencyProbe;

impl LatencyProbe for TracerouteLatencyProbe {
    fn probe(&self, hops: u32) -> Option<HopObservation> {
        if !(1..=MAX_LATENCY_HOPS).contains(&hops) || cfg!(windows) {
            return None;
        }
        let (ttl, queries, wait) = (hops.to_string(), PROBES_PER_HOP.to_string(), WAIT_SECONDS.to_string());
        // -n: no name lookups. -f/-m: exactly this hop count. -q/-w: three probes, one second each.
        let args = ["-n", "-f", &ttl, "-m", &ttl, "-q", &queries, "-w", &wait, DIRECTION];
        let timeout = Duration::from_secs(u64::from(PROBES_PER_HOP * WAIT_SECONDS + 3));
        parse_hop(run("traceroute", &args, timeout).as_deref(), hops)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_address_and_every_reply_time_with_or_without_lost_probes() {
        let hop = parse_hop(Some(" 2  198.51.100.1  10.278 ms  7.118 ms  17.345 ms\n"), 2).unwrap();
        assert_eq!((hop.address.as_deref(), hop.times_ms), (Some("198.51.100.1"), vec![10.278, 7.118, 17.345]));
        let hop = parse_hop(Some(" 1  * 192.168.1.1  33.692 ms  3.952 ms\n"), 1).unwrap();
        assert_eq!((hop.address.as_deref(), hop.times_ms), (Some("192.168.1.1"), vec![33.692, 3.952]));
    }

    #[test]
    fn a_silent_hop_has_no_address_and_missing_output_is_nothing() {
        assert_eq!(parse_hop(Some(" 3  * * *\n"), 3), Some(HopObservation::default()));
        assert_eq!(parse_hop(Some(" 3  * * *\n"), 2), None);
        assert_eq!(parse_hop(None, 1), None);
        // "10" must not be mistaken for hop 1.
        assert_eq!(parse_hop(Some("10  1.2.3.4  5 ms\n"), 1), None);
    }

    #[test]
    fn a_reply_from_the_far_end_is_not_treated_as_a_hop() {
        assert_eq!(parse_hop(Some(" 4  9.9.9.9  8.1 ms  8.0 ms  8.3 ms\n"), 4), Some(HopObservation::default()));
    }

    #[test]
    fn refuses_hop_counts_outside_the_limit_without_running_anything() {
        for hops in [0, 5, 99] {
            assert_eq!(TracerouteLatencyProbe.probe(hops), None);
        }
    }
}
