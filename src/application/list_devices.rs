//! Use case: list the devices on the home network for the dashboard. It has no repository, so it cannot save.
use crate::domain::devices::{device_list_from, sweep_targets, DeviceList};
use crate::domain::gateway::{require_home_gateway, SafetyStop};
use crate::domain::ports::{Clock, GatewayLocator, NeighbourDiscovery};
use std::sync::Arc;

pub struct ListDevices {
    pub gateway: Box<dyn GatewayLocator>,
    pub neighbours: Box<dyn NeighbourDiscovery>,
    pub clock: Arc<dyn Clock>,
}

impl ListDevices {
    /// Takes no input: the network is always this device's own, and the same safety stops apply as for an audit.
    pub fn execute(&self) -> Result<DeviceList, SafetyStop> {
        let target = require_home_gateway(&self.gateway.locate())?;
        let own = self.neighbours.own();
        let targets = own.as_ref().map(|o| sweep_targets(&o.address, &target)).unwrap_or_default();
        let seen = self.neighbours.discover(&targets, &target);
        Ok(device_list_from(&seen, &target, own.as_ref(), self.clock.now_iso()))
    }
}
