//! Recent Wi-Fi join trouble, as counts read from this device's own Wi-Fi log. Advice only: none of this is scored.
//! The log itself never gets here: the adapter hands over numbers, and nothing in this module can hold text from it.
use super::model::*;

/// How far back the log is read. Matches the interval of `peekaboo watch`.
pub const LOG_WINDOW_MINUTES: u32 = 30;

/// A wait longer than a day is not a Wi-Fi retry timer; treat it as unreadable.
const MAX_PLAUSIBLE_WAIT_SECS: u32 = 86_400;

/// What the log adapter saw. Only meaningful when `read` is true.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WifiEventObservation {
    /// True only when the log was read. A log that could not be read is Unknown, never "no trouble".
    pub read: bool,
    /// Join attempts that were aborted because the Wi-Fi hardware was not ready yet.
    pub driver_not_ready: u32,
    /// The longest time the system then waited before it tried again.
    pub longest_retry_wait_secs: Option<u32>,
}

pub fn wifi_stability_from(observation: &WifiEventObservation) -> WifiStabilityCheck {
    if !observation.read {
        return WifiStabilityCheck::default();
    }
    let wait = observation.longest_retry_wait_secs.filter(|s| *s > 0 && *s <= MAX_PLAUSIBLE_WAIT_SECS && observation.driver_not_ready > 0);
    WifiStabilityCheck { window_minutes: LOG_WINDOW_MINUTES, driver_not_ready: Some(observation.driver_not_ready), longest_retry_wait_secs: wait }
}

fn plural(n: u32, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

/// Nothing is said when the log could not be read, because most platforms cannot read it.
pub fn stability_findings(check: &WifiStabilityCheck) -> Vec<Finding> {
    let Some(count) = check.driver_not_ready else { return vec![] };
    let window = check.window_minutes;
    if count == 0 {
        return vec![Finding {
            id: "wifi-log-clear".into(),
            severity: Severity::Info,
            message: format!("No Wi-Fi rejoin problems showed in this device's own Wi-Fi log over the last {window} minutes."),
            action: None,
        }];
    }
    let wait = check.longest_retry_wait_secs.map(|s| {
        let minutes = (s + 30) / 60;
        format!(" The system then waited about {} before trying again.", plural(minutes.max(1), "minute", "minutes"))
    });
    vec![Finding {
        id: "wifi-log-driver".into(),
        severity: Severity::Info,
        message: format!(
            "In the last {window} minutes this device's Wi-Fi failed to join {} while its Wi-Fi hardware was not ready, most likely right after waking from sleep.{}",
            plural(count, "time", "times"),
            wait.unwrap_or_default()
        ),
        action: Some("Turn Wi-Fi off and on to rejoin without waiting.".into()),
    }]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seen(count: u32, wait: Option<u32>) -> WifiEventObservation {
        WifiEventObservation { read: true, driver_not_ready: count, longest_retry_wait_secs: wait }
    }

    #[test]
    fn an_unread_log_is_unknown_and_says_nothing() {
        let check = wifi_stability_from(&WifiEventObservation::default());
        assert_eq!(check, WifiStabilityCheck::default());
        assert!(stability_findings(&check).is_empty());
    }

    #[test]
    fn a_log_with_no_trouble_is_not_the_same_as_an_unreadable_one() {
        let check = wifi_stability_from(&seen(0, Some(120)));
        assert_eq!((check.driver_not_ready, check.longest_retry_wait_secs), (Some(0), None));
        let findings = stability_findings(&check);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, "wifi-log-clear");
    }

    #[test]
    fn a_failed_join_is_worded_as_a_likely_cause_with_the_wait_and_one_action() {
        let findings = stability_findings(&wifi_stability_from(&seen(1, Some(121))));
        assert_eq!(findings.len(), 1);
        let f = &findings[0];
        assert_eq!(f.id, "wifi-log-driver");
        assert_eq!(f.severity, Severity::Info);
        assert!(f.message.contains("most likely") && f.message.contains("1 time ") && f.message.contains("about 2 minutes"), "{}", f.message);
        assert!(f.action.is_some());
    }

    #[test]
    fn an_implausible_wait_is_dropped() {
        assert_eq!(wifi_stability_from(&seen(2, Some(10_000_000))).longest_retry_wait_secs, None);
        let message = &stability_findings(&wifi_stability_from(&seen(2, None)))[0].message;
        assert!(message.contains("2 times") && !message.contains("waited"));
    }
}
