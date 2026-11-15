//! Adapters that touch the network, this device and the disk, and `composition`, the one place they are wired together.
pub mod clock;
pub mod composition;
pub mod device;
pub mod json_history_store;
pub mod json_report_repository;
pub mod json_saved_report_store;
pub mod latency;
pub mod neighbours;
pub mod network;
pub mod paths;
pub mod route;
pub mod system;
pub mod upnp;
pub mod wifi;
pub mod wifi_log;
