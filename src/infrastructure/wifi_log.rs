//! Reads this device's own Wi-Fi log for recent join trouble. macOS only; elsewhere the answer is Unknown.
//! One fixed query over a short window. The log text is read here and reduced to counts and seconds:
//! no line, network name, hardware address or user name leaves this file, and none is shown or kept.
use super::system::run;
use crate::domain::ports::WifiLogInspector;
use crate::domain::stability::{WifiEventObservation, LOG_WINDOW_MINUTES};
use regex::Regex;
use std::sync::LazyLock;
use std::time::Duration;

const LOG_TOOL: &str = "/usr/bin/log";
/// Fixed. It selects the Wi-Fi daemon's join messages only, which keeps the query to a few seconds.
const LOG_PREDICATE: &str = "process == \"airportd\" AND eventMessage CONTAINS \"AUTO-JOIN\"";
const LOG_TIMEOUT: Duration = Duration::from_secs(12);

/// Keyed on the reason word, not the error number: the same number also marks the harmless "already associated".
static DRIVER_ABORT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"Auto-join aborted .*reason=DriverUnavailable").unwrap());
static RETRY_WAIT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"Scheduling auto-join retry attempt in (\d+)ms").unwrap());

/// Counts aborted joins caused by an unready Wi-Fi driver, and the longest wait scheduled right after one.
/// Retry timers that follow other aborts are ordinary and are not counted.
pub fn parse_mac_wifi_log(text: &str) -> WifiEventObservation {
    let mut observation = WifiEventObservation { read: true, ..WifiEventObservation::default() };
    let mut waiting_for_retry = false;
    for line in text.lines() {
        if DRIVER_ABORT.is_match(line) {
            observation.driver_not_ready += 1;
            waiting_for_retry = true;
        } else if waiting_for_retry {
            if let Some(ms) = RETRY_WAIT.captures(line).and_then(|c| c[1].parse::<u64>().ok()) {
                let secs = u32::try_from(ms / 1000).ok();
                observation.longest_retry_wait_secs = observation.longest_retry_wait_secs.max(secs);
                waiting_for_retry = false;
            }
        }
    }
    observation
}

pub struct SystemWifiLogInspector;

impl WifiLogInspector for SystemWifiLogInspector {
    fn inspect(&self) -> WifiEventObservation {
        if !cfg!(target_os = "macos") {
            return WifiEventObservation::default();
        }
        let window = format!("{LOG_WINDOW_MINUTES}m");
        run(LOG_TOOL, &["show", "--last", &window, "--style", "compact", "--predicate", LOG_PREDICATE], LOG_TIMEOUT)
            .map(|text| parse_mac_wifi_log(&text))
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Shaped like real macOS lines; the network name, address and user are made up.
    const LOG: &str = "\
2026-11-15 13:43:33.120 Df airportd[465:1a90ed] [com.apple.WiFiManager:] [corewifi] AUTO-JOIN: Auto-join aborted (requeued=0, cancelled=0, error=(37 'Already associated, and network transition not permitted'), reason=AlreadyAssoc)
2026-11-15 13:43:33.120 Df airportd[465:1a90ed] [com.apple.WiFiManager:] [corewifi] AUTO-JOIN: Scheduling auto-join retry attempt in 120329ms (schedule=assoc, index=0 interval=(interval=120, count=1)
2026-11-15 13:58:46.488 Df airportd[465:1ab4fa] [com.apple.WiFiManager:] [corewifi] AUTO-JOIN: Auto-join aborted (requeued=0, cancelled=0, error=(37 'driver not available'), reason=DriverUnavailable)
2026-11-15 13:58:46.600 Df airportd[465:1ab4fa] [com.apple.WiFiManager:] AutoJoin: user: someone, network: HomeNet, bssid aa:bb:cc:dd:ee:ff
2026-11-15 13:58:46.931 Df airportd[465:1a90ed] [com.apple.WiFiManager:] [corewifi] AUTO-JOIN: Scheduling auto-join retry attempt in 120924ms (schedule=assoc, index=0 interval=(interval=120, count=1)
2026-11-15 13:58:47.280 Df airportd[465:1ab8db] [com.apple.WiFiManager:] [corewifi] AUTO-JOIN: Scheduling auto-join retry attempt in 900000ms (schedule=assoc, index=0)
";

    #[test]
    fn counts_driver_not_ready_aborts_and_the_wait_that_followed() {
        let o = parse_mac_wifi_log(LOG);
        assert_eq!((o.read, o.driver_not_ready, o.longest_retry_wait_secs), (true, 1, Some(120)));
    }

    #[test]
    fn already_associated_aborts_share_the_error_number_but_are_not_trouble() {
        let harmless = LOG.lines().take(2).collect::<Vec<_>>().join("\n");
        let o = parse_mac_wifi_log(&harmless);
        assert_eq!((o.read, o.driver_not_ready, o.longest_retry_wait_secs), (true, 0, None));
    }

    #[test]
    fn an_empty_log_was_read_and_shows_no_trouble() {
        assert_eq!(parse_mac_wifi_log("Timestamp Ty Process[PID:TID]\n"), WifiEventObservation { read: true, driver_not_ready: 0, longest_retry_wait_secs: None });
    }

    #[test]
    fn nothing_from_the_log_can_be_carried_out() {
        // The result type holds a flag and numbers only, so names, addresses and users in the text have nowhere to go.
        let o = parse_mac_wifi_log(LOG);
        let shown = format!("{o:?}");
        for secret in ["HomeNet", "aa:bb:cc", "someone", "airportd"] {
            assert!(!shown.contains(secret), "{shown}");
        }
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn other_platforms_are_unknown() {
        assert!(!SystemWifiLogInspector.inspect().read);
    }
}
