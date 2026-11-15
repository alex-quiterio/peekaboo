//! Composition root: wires the real adapters into the use cases. Every app starts here.
use super::clock::SystemClock;
use super::json_history_store::JsonHistoryStore;
use super::json_report_repository::JsonReportRepository;
use super::json_saved_report_store::JsonSavedReportStore;
use super::latency::TracerouteLatencyProbe;
use super::neighbours::SystemNeighbourDiscovery;
use super::network::{SystemEnvironmentInspector, TcpConnectProbe};
use super::paths::data_dir;
use super::route::SystemGatewayLocator;
use super::upnp::NatUpnpInspector;
use super::wifi::SystemWifiInspector;
use super::dhcp_log::SystemDhcpLogInspector;
use crate::application::history::History;
use crate::application::list_devices::ListDevices;
use crate::application::run_audit::{AuditDependencies, RunAudit};
use crate::application::saved_reports::SavedReports;
use crate::domain::ports::{Clock, ReportRepository, SavedReportStore};
use std::path::PathBuf;
use std::sync::Arc;

pub struct App {
    pub run_audit: RunAudit,
    pub list_devices: ListDevices,
    pub saved_reports: SavedReports,
    pub history: Arc<History>,
    pub reports: Arc<dyn ReportRepository>,
    pub data_dir: PathBuf,
}

pub fn create_app() -> App {
    let data_dir = data_dir();
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let reports: Arc<dyn ReportRepository> = Arc::new(JsonReportRepository::new(&data_dir));
    let history = Arc::new(History::new(Arc::new(JsonHistoryStore::new(&data_dir))));
    let saved: Arc<dyn SavedReportStore> = Arc::new(JsonSavedReportStore::new(data_dir.join("saved-reports")));
    App {
        run_audit: RunAudit::new(AuditDependencies {
            gateway: Box::new(SystemGatewayLocator),
            ports: Box::new(TcpConnectProbe),
            upnp: Box::new(NatUpnpInspector),
            wifi: Box::new(SystemWifiInspector),
            dhcp_log: Box::new(SystemDhcpLogInspector),
            environment: Box::new(SystemEnvironmentInspector),
            latency: Box::new(TracerouteLatencyProbe),
            reports: reports.clone(),
            clock: clock.clone(),
            history: history.clone(),
            platform: std::env::consts::OS.to_string(),
        }),
        list_devices: ListDevices { gateway: Box::new(SystemGatewayLocator), neighbours: Box::new(SystemNeighbourDiscovery), clock: clock.clone() },
        saved_reports: SavedReports::new(saved, reports.clone(), clock),
        history,
        reports,
        data_dir,
    }
}
