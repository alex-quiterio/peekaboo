//! How long this device recently went without a network address, as numbers read from its own system log.
//! Advice only: none of this is scored. The log itself never gets here: the adapter hands over numbers, and
//! nothing in this module can hold text from it.
use super::model::*;

/// How far back the log is read. Matches the interval of `peekaboo watch`.
pub const LOG_WINDOW_MINUTES: u32 = 30;

/// A wait shorter than this is the ordinary hiccup of waking from sleep; it is not worth a word.
pub const SLOW_ADDRESS_SECS: u32 = 10;

/// What the log adapter saw. Only meaningful when `read` is true.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DhcpLogObservation {
    /// True only when the log was read. A log that could not be read is Unknown, never "no trouble".
    pub read: bool,
    /// DHCP requests that the router did not answer.
    pub unanswered: u32,
    /// The longest time between losing the network address and getting one again.
    pub longest_without_address_secs: Option<u32>,
}

pub fn wifi_stability_from(observation: &DhcpLogObservation) -> WifiStabilityCheck {
    if !observation.read {
        return WifiStabilityCheck::default();
    }
    // The window is the longest a gap could be, so anything longer is a misread, not a measurement.
    let longest = observation.longest_without_address_secs.filter(|s| *s > 0 && *s <= LOG_WINDOW_MINUTES * 60);
    WifiStabilityCheck { window_minutes: LOG_WINDOW_MINUTES, dhcp_unanswered: Some(observation.unanswered), longest_without_address_secs: longest }
}

fn plural(n: u32, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

/// Nothing is said when the log could not be read, because most platforms cannot read it.
pub fn stability_findings(check: &WifiStabilityCheck) -> Vec<Finding> {
    let Some(unanswered) = check.dhcp_unanswered else { return vec![] };
    let window = check.window_minutes;
    let Some(secs) = check.longest_without_address_secs.filter(|s| *s >= SLOW_ADDRESS_SECS) else {
        return vec![Finding {
            id: "dhcp-log-clear".into(),
            severity: Severity::Info,
            message: format!("No long wait for a network address showed in this device's own log over the last {window} minutes."),
            action: None,
        }];
    };
    vec![Finding {
        id: "dhcp-log-slow".into(),
        severity: Severity::Info,
        message: format!(
            "In the last {window} minutes this device went without a network address for up to about {secs} seconds, after {} got no answer from the router. That is most likely why Wi-Fi looked connected while nothing loaded. This device cannot tell whether the router was slow to answer or the request never reached it.",
            plural(unanswered.max(1), "request", "requests")
        ),
        action: Some("Renew the DHCP lease (on macOS: System Settings, Wi-Fi, Details, TCP/IP), or turn Wi-Fi off and on.".into()),
    }]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seen(unanswered: u32, longest: Option<u32>) -> DhcpLogObservation {
        DhcpLogObservation { read: true, unanswered, longest_without_address_secs: longest }
    }

    #[test]
    fn an_unread_log_is_unknown_and_says_nothing() {
        let check = wifi_stability_from(&DhcpLogObservation::default());
        assert_eq!(check, WifiStabilityCheck::default());
        assert!(stability_findings(&check).is_empty());
    }

    #[test]
    fn a_quiet_log_and_a_short_hiccup_are_both_clear_but_not_unknown() {
        for observation in [seen(0, None), seen(2, Some(2))] {
            let findings = stability_findings(&wifi_stability_from(&observation));
            assert_eq!(findings.len(), 1);
            assert_eq!(findings[0].id, "dhcp-log-clear");
            assert!(findings[0].action.is_none());
        }
    }

    #[test]
    fn a_long_wait_is_worded_as_a_likely_cause_with_one_action() {
        let findings = stability_findings(&wifi_stability_from(&seen(2, Some(35))));
        assert_eq!(findings.len(), 1);
        let f = &findings[0];
        assert_eq!((f.id.as_str(), f.severity), ("dhcp-log-slow", Severity::Info));
        assert!(f.message.contains("most likely") && f.message.contains("about 35 seconds") && f.message.contains("2 requests"), "{}", f.message);
        assert!(f.action.is_some());
    }

    #[test]
    fn a_gap_longer_than_the_window_is_dropped_as_a_misread() {
        let check = wifi_stability_from(&seen(1, Some(LOG_WINDOW_MINUTES * 60 + 1)));
        assert_eq!(check.longest_without_address_secs, None);
        assert_eq!(stability_findings(&check)[0].id, "dhcp-log-clear");
    }
}
