//! The use cases. They depend on domain traits only, never on adapters.
pub mod history;
pub mod list_devices;
pub mod run_audit;
pub mod run_speed_test;
pub mod saved_reports;
pub mod watch_session;

#[cfg(test)]
mod tests;
