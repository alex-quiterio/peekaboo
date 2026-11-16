//! The opt-in speed test: macOS's own `networkQuality`, run once with fixed arguments. It saturates the link for
//! up to about a minute and talks to Apple's servers, so the CLI runs it only when asked (`--speed-test`).
//! Nothing here takes input, and only the parsed figures leave this module.
use super::system::run;
use crate::domain::ports::SpeedTester;
use crate::domain::speed_test::{parse_speed_test, SpeedTestResult};
use std::time::Duration;

const TOOL: &str = "/usr/bin/networkQuality";
const TIMEOUT: Duration = Duration::from_secs(90);

pub struct SystemSpeedTester;

impl SpeedTester for SystemSpeedTester {
    fn run(&self) -> Option<SpeedTestResult> {
        if !cfg!(target_os = "macos") {
            return None;
        }
        parse_speed_test(&run(TOOL, &["-c"], TIMEOUT)?)
    }
}
