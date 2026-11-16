//! What the domain needs from the outside world. Infrastructure implements these; nothing here does I/O.
//! ("Ports" in the hexagonal sense. TCP ports live in scoring.rs.)
use super::devices::{NeighbourObservation, SelfObservation};
use super::evidence::{EnvironmentObservation, HopObservation, UpnpObservation, WifiObservation};
use super::gateway::DefaultRoute;
use super::history::HistoryPoint;
use super::model::Report;
use super::saved::SavedReport;
use super::speed_test::SpeedTestResult;
use super::stability::DhcpLogObservation;

pub trait GatewayLocator: Send + Sync {
    /// The operating system's default route, unvalidated.
    fn locate(&self) -> DefaultRoute;
}

pub trait PortProbe: Send + Sync {
    /// Connect-only: opens a TCP connection and closes it without sending data.
    fn is_reachable(&self, host: &str, port: u16) -> bool;
}

pub trait UpnpInspector: Send + Sync {
    /// Read-only. Must refuse any UPnP device that is not the given gateway.
    fn inspect(&self, gateway: &str) -> UpnpObservation;
}

pub trait WifiInspector: Send + Sync {
    fn inspect(&self) -> WifiObservation;
}

pub trait DhcpLogInspector: Send + Sync {
    /// One fixed, read-only query of this device's own system log over a short window, reduced to counts. Takes no
    /// input, sends nothing over the network, and must not return, print or store any log text.
    fn inspect(&self) -> DhcpLogObservation;
}

pub trait EnvironmentInspector: Send + Sync {
    /// Reads this device's own settings. Sends nothing over the network.
    fn inspect(&self) -> EnvironmentObservation;
}

pub trait LatencyProbe: Send + Sync {
    /// Sends a few packets that expire after `hops` routers and reports who answered and how quickly. The packets
    /// carry no data and are never meant to arrive. Must refuse more than MAX_LATENCY_HOPS, and takes no destination.
    fn probe(&self, hops: u32) -> Option<HopObservation>;
}

pub trait NeighbourDiscovery: Send + Sync {
    /// This device's own address on the default interface, or None when it cannot be read.
    fn own(&self) -> Option<SelfObservation>;
    /// Makes the operating system resolve each given address, then reads its neighbour table. Names may be
    /// asked of the gateway only. Must not connect to, probe or fingerprint any device.
    fn discover(&self, addresses: &[String], gateway: &str) -> Vec<NeighbourObservation>;
}

pub trait ReportRepository: Send + Sync {
    fn latest(&self) -> Option<Report>;
    fn previous(&self) -> Option<Report>;
    /// Stores the report as latest; the old latest becomes previous.
    fn save(&self, report: &Report) -> Result<(), String>;
}

/// Reports the user chose to keep under a name. Written only when the user asks to save.
pub trait SavedReportStore: Send + Sync {
    fn list(&self) -> Vec<SavedReport>;
    fn get(&self, label: &str) -> Option<SavedReport>;
    /// Replaces any saved report with the same label.
    fn save(&self, saved: &SavedReport) -> Result<(), String>;
    /// Returns false when there was nothing to remove.
    fn remove(&self, label: &str) -> bool;
}

/// The trend: one small point per audit. Written after each audit; the user can clear it.
pub trait HistoryStore: Send + Sync {
    fn load(&self) -> Vec<HistoryPoint>;
    fn save(&self, points: &[HistoryPoint]) -> Result<(), String>;
    /// Returns false when there was nothing to remove.
    fn clear(&self) -> bool;
}

pub trait Clock: Send + Sync {
    /// The current time as an ISO 8601 UTC string, such as "2026-11-13T14:05:03.924Z".
    fn now_iso(&self) -> String;
}

pub trait SpeedTester: Send + Sync {
    /// Saturates this device's connection to measure throughput. It sends real traffic to a third-party server the
    /// adapter fixes itself, so it is opt-in and must take no input, no address and no server name, and must return
    /// numbers only. None when it cannot run.
    fn run(&self) -> Option<SpeedTestResult>;
}
