//! The system clock, as ISO 8601 UTC text.
use crate::domain::ports::Clock;
use std::time::{SystemTime, UNIX_EPOCH};

pub struct SystemClock;

impl Clock for SystemClock {
    fn now_iso(&self) -> String {
        let millis = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_millis() as i64);
        iso_from_unix_millis(millis)
    }
}

/// Civil date from a day count (Howard Hinnant's algorithm), so no date library is needed.
pub fn iso_from_unix_millis(millis: i64) -> String {
    let secs = millis.div_euclid(1000);
    let (days, rest) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{:03}Z",
        rest / 3600,
        rest % 3600 / 60,
        rest % 60,
        millis.rem_euclid(1000)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_known_instants() {
        assert_eq!(iso_from_unix_millis(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(iso_from_unix_millis(1_700_000_000_000), "2023-11-14T22:13:20.000Z");
        assert_eq!(iso_from_unix_millis(951_782_400_123), "2000-02-29T00:00:00.123Z");
        assert_eq!(iso_from_unix_millis(1_794_576_303_924), "2026-11-13T13:25:03.924Z");
    }
}
