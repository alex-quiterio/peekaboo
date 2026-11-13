//! Explains how fast the Wi-Fi link is and what would make it faster. Advice only: none of this is scored.
use super::model::*;

/// Below this link rate, everyday use starts to feel slow.
const SLOW_MBPS: u32 = 100;
const FAST_MBPS: u32 = 400;

const MOVE_CLOSER: &str = "Move closer to the router, or place the router higher up and nearer the middle of your home. For rooms far from it, add a mesh node or a wired access point.";
pub const USE_FASTER_BAND: &str = "Connect on the 5 GHz or 6 GHz band where your router offers it.";

fn finding(id: &str, severity: Severity, message: impl Into<String>, action: Option<&str>) -> Finding {
    Finding { id: id.into(), severity, message: message.into(), action: action.map(str::to_string) }
}

fn link_finding(wifi: &WifiCheck) -> Finding {
    let speed = &wifi.speed;
    let Some(rate) = speed.link_rate_mbps else {
        return finding("speed-link", Severity::Info, "Wi-Fi speed: Unknown. This device did not report a link rate for its Wi-Fi connection.", None);
    };
    let pace = if rate < SLOW_MBPS { "slow" } else if rate < FAST_MBPS { "moderate" } else { "fast" };
    let details: Vec<String> = [speed.standard.map(|s| s.as_str().to_string()), speed.channel_width_mhz.map(|w| format!("{w} MHz channel"))]
        .into_iter()
        .flatten()
        .collect();
    let details = if details.is_empty() { String::new() } else { format!(" ({})", details.join(", ")) };
    finding(
        "speed-link",
        Severity::Info,
        format!("This device's Wi-Fi link rate is {rate} Mbps{details}, which is {pace}. Expect about half of that in real use. Internet speed was not measured, because that would send traffic outside your network."),
        None,
    )
}

fn signal_findings(speed: &WifiSpeedCheck) -> Vec<Finding> {
    let (Some(signal), Some(signal_dbm)) = (speed.signal, speed.signal_dbm) else { return vec![] };
    let mut findings = Vec::new();
    if matches!(signal, SignalQuality::Weak | SignalQuality::Fair) {
        findings.push(finding(
            "speed-signal",
            Severity::Low,
            format!("The Wi-Fi signal where this device sits is {} ({signal_dbm} dBm), which lowers the link rate.", signal.as_str()),
            Some(MOVE_CLOSER),
        ));
    } else {
        findings.push(finding("speed-signal", Severity::Info, format!("The Wi-Fi signal is {} ({signal_dbm} dBm).", signal.as_str()), None));
    }
    // A strong signal still performs badly when the background noise is nearly as loud.
    if let Some(noise) = speed.noise_dbm.filter(|n| *n >= -85 && signal_dbm - *n < 25) {
        findings.push(finding(
            "speed-noise",
            Severity::Low,
            format!("Radio noise is high here ({noise} dBm), leaving the Wi-Fi signal little room above it."),
            Some("Keep the router away from microwave ovens, cordless phone bases, baby monitors and USB 3 hubs."),
        ));
    }
    findings
}

fn setting_findings(wifi: &WifiCheck) -> Vec<Finding> {
    let (band, speed) = (wifi.band, &wifi.speed);
    let mut findings = Vec::new();
    let signal_holds = !matches!(speed.signal, Some(SignalQuality::Weak | SignalQuality::Fair));

    // With a weak signal, 2.4 GHz may be the only band that reaches this far, so the advice is to fix the signal first.
    if band == Some(WifiBand::Ghz2) && signal_holds && wifi.overlapping_count.unwrap_or(0) == 0 {
        findings.push(finding(
            "speed-band",
            Severity::Low,
            "The 2.4 GHz band caps the link rate well below what 5 GHz or 6 GHz reach at this distance.",
            Some(USE_FASTER_BAND),
        ));
    }

    match (band, speed.channel_width_mhz) {
        (Some(WifiBand::Ghz2), Some(width)) if width > 20 => findings.push(finding(
            "speed-width",
            Severity::Low,
            format!("The 2.4 GHz channel is {width} MHz wide. That covers most of the band, so it collides with neighbours and is often slower than 20 MHz."),
            Some("Set the 2.4 GHz channel width to 20 MHz in the router."),
        )),
        (Some(band), Some(width)) if band != WifiBand::Ghz2 && width < 80 => findings.push(finding(
            "speed-width",
            Severity::Low,
            format!("The {} channel is only {width} MHz wide. An 80 MHz channel carries two to four times as much.", band.as_str()),
            Some(&format!("Set the {} channel width to 80 MHz in the router.", band.as_str())),
        )),
        _ => {}
    }

    if matches!(speed.standard, Some(WifiStandard::Wifi4 | WifiStandard::Legacy)) {
        let name = if speed.standard == Some(WifiStandard::Legacy) { "a Wi-Fi standard older than Wi-Fi 4" } else { "Wi-Fi 4" };
        findings.push(finding(
            "speed-standard",
            Severity::Low,
            format!("This connection uses {name}. Either the router or this device supports nothing newer, or the router is set to an older mode."),
            Some("Set the router's wireless mode to allow Wi-Fi 5 and Wi-Fi 6. If it offers neither, a newer router is the biggest speed gain."),
        ));
    }
    findings
}

/// Delay on a healthy Wi-Fi link stays in single digits; above this the Wi-Fi itself is the hold-up.
const SLOW_ROUTER_MS: u32 = 20;
/// What the line between the router and the ISP may add before it is worth raising with the ISP.
const SLOW_LINE_MS: u32 = 30;

/// Empty unless the user asked for the measurement.
pub fn latency_findings(check: &LatencyCheck) -> Vec<Finding> {
    if !check.requested {
        return vec![];
    }
    let Some(router_ms) = check.router_ms else {
        return vec![finding("speed-latency", Severity::Info, "Delay to your ISP: Unknown. Your router did not answer the timing packets, so nothing was concluded.", None)];
    };
    let mut findings = Vec::new();
    if check.isp_ms.is_some_and(|isp| isp < router_ms) {
        // Traffic passing through the router is quicker than the router's own answer, so the link is not the hold-up.
        findings.push(finding(
            "speed-latency-router",
            Severity::Info,
            format!("Your own router takes about {router_ms} ms to answer timing packets, yet traffic passing through it is quicker. Routers often answer these slowly; it does not mean the link is slow."),
            None,
        ));
    } else if router_ms >= SLOW_ROUTER_MS {
        findings.push(finding(
            "speed-latency-router",
            Severity::Low,
            format!("Your own router takes about {router_ms} ms to answer. On a good link that is under 5 ms, so the delay builds up between this device and the router, not at your ISP."),
            Some(MOVE_CLOSER),
        ));
    } else {
        findings.push(finding("speed-latency-router", Severity::Info, format!("Your own router answers in about {router_ms} ms."), None));
    }

    let Some(isp_ms) = check.isp_ms else {
        findings.push(finding(
            "speed-latency",
            Severity::Info,
            "Delay to your ISP: Unknown. No router past your own answered the timing packets; many ISPs switch those answers off.",
            None,
        ));
        return findings;
    };
    let own = match check.own_hops {
        Some(hops) if hops > 1 => format!(" There are {hops} routers of your own on the way (for example a mesh or a second router behind the ISP's modem)."),
        _ => String::new(),
    };
    let added = isp_ms.saturating_sub(router_ms);
    // Most of the delay is equipment rather than distance, so this is a ceiling and is worded as one.
    let distance = match check.isp_max_km {
        None => " The delay is too small to say anything about distance.".to_string(),
        Some(km) => format!(" At the speed of light in fibre, that router is no more than about {km} km of cable away, and usually far closer: most of the delay comes from equipment, not distance."),
    };
    if added >= SLOW_LINE_MS {
        findings.push(finding(
            "speed-latency",
            Severity::Low,
            format!("The first router on your ISP's side answers in about {isp_ms} ms, so the line to your ISP adds about {added} ms.{own}{distance}"),
            Some("Ask your ISP to check the line. On DSL, ask whether a lower-delay profile (fast path) is available."),
        ));
    } else {
        findings.push(finding(
            "speed-latency",
            Severity::Info,
            format!("The first router on your ISP's side answers in about {isp_ms} ms, so the line to your ISP adds little delay.{own}{distance} Where your ISP's equipment actually sits was not looked up."),
            None,
        ));
    }
    findings
}

pub fn speed_findings(wifi: &WifiCheck) -> Vec<Finding> {
    if wifi.state == WifiState::Unknown {
        return vec![finding("speed-link", Severity::Info, "Wi-Fi speed: Unknown. No Wi-Fi connection could be read.", None)];
    }
    let mut findings = vec![link_finding(wifi)];
    findings.extend(signal_findings(&wifi.speed));
    findings.extend(setting_findings(wifi));
    findings
}

/// Every unique action that would make the Wi-Fi faster, including the crowded-channel and band advice.
pub fn speed_tips(findings: &[Finding]) -> Vec<String> {
    let mut tips: Vec<String> = Vec::new();
    for f in findings.iter().filter(|f| f.id.starts_with("speed-") || f.id == "channel" || f.id == "band") {
        if let Some(action) = &f.action {
            if !tips.contains(action) {
                tips.push(action.clone());
            }
        }
    }
    tips
}
