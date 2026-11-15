//! Reads this device's own DHCP client log for recent waits for a network address. macOS only; elsewhere Unknown.
//! One fixed query over a short window. The log text is read here and reduced to counts and seconds:
//! no line, address, network name or user name leaves this file, and none is shown or kept.
use super::route::default_route;
use super::system::run;
use crate::domain::ports::DhcpLogInspector;
use crate::domain::stability::{DhcpLogObservation, LOG_WINDOW_MINUTES};
use regex::Regex;
use std::sync::LazyLock;
use std::time::Duration;

const LOG_TOOL: &str = "/usr/bin/log";
/// Fixed. The messages of every interface are read; the parser keeps the default one.
const LOG_PREDICATE: &str = "process == \"configd\" AND eventMessage CONTAINS \"DHCP \"";
const LOG_TIMEOUT: Duration = Duration::from_secs(12);

static IFACE_NAME: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[A-Za-z0-9._-]{1,15}$").unwrap());

/// Seconds since an arbitrary fixed day, from the "2026-11-15 17:27:48.716" that starts each compact log line.
fn timestamp_secs(line: &str) -> Option<f64> {
    let (date, rest) = line.get(..23)?.split_once(' ')?;
    let mut d = date.splitn(3, '-').map(|p| p.parse::<i64>().ok());
    let (y, m, day) = (d.next()??, d.next()??, d.next()??);
    let mut t = rest.splitn(3, ':');
    let (hh, mm, ss) = (t.next()?.parse::<f64>().ok()?, t.next()?.parse::<f64>().ok()?, t.next()?.parse::<f64>().ok()?);
    // Days since 1970-01-01 (civil-from-days, Howard Hinnant).
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(days as f64 * 86_400.0 + hh * 3600.0 + mm * 60.0 + ss)
}

/// Counts DHCP requests that got no answer, and the longest time between the address being dropped and an
/// address coming back, for one interface. Gaps still open at the end of the text are not counted.
pub fn parse_mac_dhcp_log(text: &str, interface: &str) -> DhcpLogObservation {
    let marker = format!("DHCP {interface}: ");
    let mut observation = DhcpLogObservation { read: true, ..DhcpLogObservation::default() };
    let mut dropped_at: Option<f64> = None;
    for line in text.lines().filter(|l| l.contains(&marker)) {
        let Some(at) = timestamp_secs(line) else { continue };
        if line.contains("status = 'server not responding'") {
            observation.unanswered += 1;
        } else if line.contains(": removing ") {
            dropped_at.get_or_insert(at);
        } else if line.ends_with(": BOUND") || line.contains("publish success") || line.contains("identified lease") {
            if let Some(start) = dropped_at.take() {
                let secs = (at - start).round();
                if (0.0..=f64::from(u32::MAX)).contains(&secs) {
                    observation.longest_without_address_secs = observation.longest_without_address_secs.max(Some(secs as u32));
                }
            }
        }
    }
    observation
}

pub struct SystemDhcpLogInspector;

impl DhcpLogInspector for SystemDhcpLogInspector {
    fn inspect(&self) -> DhcpLogObservation {
        if !cfg!(target_os = "macos") {
            return DhcpLogObservation::default();
        }
        let Some(interface) = default_route().interface_name.filter(|n| IFACE_NAME.is_match(n)) else { return DhcpLogObservation::default() };
        let window = format!("{LOG_WINDOW_MINUTES}m");
        run(LOG_TOOL, &["show", "--last", &window, "--style", "compact", "--predicate", LOG_PREDICATE], LOG_TIMEOUT)
            .map(|text| parse_mac_dhcp_log(&text, &interface))
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Shaped like real macOS lines; the addresses are from the documentation ranges.
    const LOG: &str = "\
2026-11-15 17:27:40.928 Df configd[1:1] [com.apple.IPConfiguration:Server] DHCP en0: INIT-REBOOT (192.0.2.20) timed out
2026-11-15 17:27:40.928 Df configd[1:1] [com.apple.IPConfiguration:Server] DHCP en0: removing 192.0.2.20
2026-11-15 17:27:40.930 Df configd[1:1] [com.apple.IPConfiguration:Server] DHCP en0: status = 'server not responding'
2026-11-15 17:27:40.995 Df configd[1:1] [com.apple.IPConfiguration:Server] DHCP en4: status = 'server not responding'
2026-11-15 17:27:42.466 Df configd[1:1] [com.apple.IPConfiguration:Server] DHCP en0: identified lease for 192.0.2.20
2026-11-15 17:27:42.469 Df configd[1:1] [com.apple.IPConfiguration:Server] DHCP en0: publish success { IPv4, DNS, DHCP }
2026-11-15 17:27:48.716 Df configd[1:1] [com.apple.IPConfiguration:Server] DHCP en0: INIT-REBOOT (192.0.2.20) timed out
2026-11-15 17:27:48.716 Df configd[1:1] [com.apple.IPConfiguration:Server] DHCP en0: removing 192.0.2.20
2026-11-15 17:27:48.716 Df configd[1:1] [com.apple.IPConfiguration:Server] DHCP en0: status = 'server not responding'
2026-11-15 17:28:15.185 Df configd[1:1] [com.apple.IPConfiguration:Server] DHCP en0: INACTIVE
2026-11-15 17:28:24.090 Df configd[1:1] [com.apple.IPConfiguration:Server] DHCP en0: BOUND
2026-11-15 17:29:08.818 Df configd[1:1] [com.apple.IPConfiguration:Server] DHCP en0: removing 192.0.2.20
";

    #[test]
    fn counts_unanswered_requests_and_the_longest_wait_for_an_address() {
        let o = parse_mac_dhcp_log(LOG, "en0");
        // Two unanswered on en0 (the en4 one is another interface); the second drop lasted 35 seconds. The last drop is still open.
        assert_eq!((o.read, o.unanswered, o.longest_without_address_secs), (true, 2, Some(35)));
    }

    #[test]
    fn only_the_given_interface_is_read() {
        let o = parse_mac_dhcp_log(LOG, "en4");
        assert_eq!((o.unanswered, o.longest_without_address_secs), (1, None));
        let none = parse_mac_dhcp_log(LOG, "en");
        assert_eq!((none.unanswered, none.longest_without_address_secs), (0, None));
    }

    #[test]
    fn an_empty_log_was_read_and_shows_no_trouble() {
        assert_eq!(parse_mac_dhcp_log("Timestamp Ty Process[PID:TID]\n", "en0"), DhcpLogObservation { read: true, unanswered: 0, longest_without_address_secs: None });
    }

    #[test]
    fn timestamps_subtract_across_midnight_and_month_ends() {
        let a = timestamp_secs("2026-11-30 23:59:59.500 Df x").unwrap();
        let b = timestamp_secs("2026-12-01 00:00:01.000 Df x").unwrap();
        assert!((b - a - 1.5).abs() < 1e-6);
        assert_eq!(timestamp_secs("garbage"), None);
    }

    #[test]
    fn nothing_from_the_log_can_be_carried_out() {
        // The result type holds a flag and numbers only, so addresses and interface names have nowhere to go.
        let shown = format!("{:?}", parse_mac_dhcp_log(LOG, "en0"));
        for secret in ["192.0.2", "en0", "configd"] {
            assert!(!shown.contains(secret), "{shown}");
        }
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn other_platforms_are_unknown() {
        assert!(!SystemDhcpLogInspector.inspect().read);
    }
}
