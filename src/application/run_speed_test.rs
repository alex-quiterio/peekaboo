//! Use case: the opt-in speed test. It has no report repository, so the result never reaches a report. It stops where an audit
//! would (VPN or tunnel, non-private gateway), so it never measures a path that is not the home network.
use super::history::History;
use crate::domain::gateway::{require_home_gateway, SafetyStop};
use crate::domain::ports::{GatewayLocator, SpeedTester};
use crate::domain::speed_test::SpeedTestResult;
use std::sync::Arc;

pub struct RunSpeedTest {
    pub gateway: Box<dyn GatewayLocator>,
    pub tester: Box<dyn SpeedTester>,
    pub history: Arc<History>,
}

impl RunSpeedTest {
    /// Takes the time of the audit it belongs to. `None` when the tester is unavailable or its output could not be
    /// read. A reading adds its download and upload figures (numbers only) to that audit's point in the trend.
    pub fn execute(&self, audit_at: &str) -> Result<Option<SpeedTestResult>, SafetyStop> {
        require_home_gateway(&self.gateway.locate())?;
        let result = self.tester.run();
        if let Some(result) = &result {
            self.history.record_speed(audit_at, result);
        }
        Ok(result)
    }
}
