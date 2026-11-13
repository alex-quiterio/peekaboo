//! The use cases against fakes: nothing here touches the network, this device or the disk.
use super::history::History;
use super::run_audit::*;
use super::saved_reports::*;
use super::watch_session::*;
use crate::domain::compare::Better;
use crate::domain::evidence::*;
use crate::domain::gateway::DefaultRoute;
use crate::domain::history::HistoryPoint;
use crate::domain::model::Report;
use crate::domain::ports::*;
use crate::domain::saved::{label_key, SavedReport, MAX_SAVED_REPORTS};
use crate::domain::scoring::AUDITED_PORTS;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

#[derive(Default)]
struct MemoryReports(Mutex<Vec<Report>>);
impl ReportRepository for MemoryReports {
    fn latest(&self) -> Option<Report> {
        self.0.lock().unwrap().last().cloned()
    }
    fn previous(&self) -> Option<Report> {
        let all = self.0.lock().unwrap();
        all.len().checked_sub(2).map(|i| all[i].clone())
    }
    fn save(&self, report: &Report) -> Result<(), String> {
        self.0.lock().unwrap().push(report.clone());
        Ok(())
    }
}

#[derive(Default)]
struct MemorySaved(Mutex<HashMap<String, SavedReport>>);
impl SavedReportStore for MemorySaved {
    fn list(&self) -> Vec<SavedReport> {
        self.0.lock().unwrap().values().cloned().collect()
    }
    fn get(&self, label: &str) -> Option<SavedReport> {
        self.0.lock().unwrap().get(&label_key(label).ok()?).cloned()
    }
    fn save(&self, saved: &SavedReport) -> Result<(), String> {
        let key = label_key(&saved.label).map_err(|e| e.0)?;
        self.0.lock().unwrap().insert(key, saved.clone());
        Ok(())
    }
    fn remove(&self, label: &str) -> bool {
        label_key(label).ok().is_some_and(|k| self.0.lock().unwrap().remove(&k).is_some())
    }
}

struct Gateway(DefaultRoute);
impl GatewayLocator for Gateway {
    fn locate(&self) -> DefaultRoute {
        self.0.clone()
    }
}

struct Ports(Arc<Mutex<Vec<String>>>);
impl PortProbe for Ports {
    fn is_reachable(&self, host: &str, port: u16) -> bool {
        self.0.lock().unwrap().push(format!("{host}:{port}"));
        port == 80
    }
}

struct Upnp;
impl UpnpInspector for Upnp {
    fn inspect(&self, _: &str) -> UpnpObservation {
        UpnpObservation::Unknown
    }
}

struct Wifi;
impl WifiInspector for Wifi {
    fn inspect(&self) -> WifiObservation {
        WifiObservation {
            connected: true,
            security: "WPA2".into(),
            channel: Some(40),
            frequency_mhz: Some(5200),
            same_channel_count: Some(0),
            overlapping_count: Some(0),
            nearby_count: Some(9),
            link_rate_mbps: Some(866.0),
            signal_dbm: Some(-50.0),
            noise_dbm: Some(-92.0),
            channel_width_mhz: Some(80),
            standard: Some("802.11ac".into()),
        }
    }
}

struct Environment;
impl EnvironmentInspector for Environment {
    fn inspect(&self) -> EnvironmentObservation {
        EnvironmentObservation { resolvers: vec!["192.168.1.1".into()], global_ipv6: Some(false), ..Default::default() }
    }
}

struct Latency(Arc<Mutex<Vec<u32>>>, fn(u32) -> Option<HopObservation>);
impl LatencyProbe for Latency {
    fn probe(&self, hops: u32) -> Option<HopObservation> {
        self.0.lock().unwrap().push(hops);
        (self.1)(hops)
    }
}

#[derive(Default)]
struct MemoryHistory {
    points: Mutex<Vec<HistoryPoint>>,
    broken: bool,
}
impl HistoryStore for MemoryHistory {
    fn load(&self) -> Vec<HistoryPoint> {
        self.points.lock().unwrap().clone()
    }
    fn save(&self, points: &[HistoryPoint]) -> Result<(), String> {
        if self.broken {
            return Err("disk full".into());
        }
        *self.points.lock().unwrap() = points.to_vec();
        Ok(())
    }
    fn clear(&self) -> bool {
        !std::mem::take(&mut *self.points.lock().unwrap()).is_empty()
    }
}

struct FixedClock;
impl Clock for FixedClock {
    fn now_iso(&self) -> String {
        "2026-03-01T10:00:00.000Z".into()
    }
}

fn hop(address: &str, times: &[f64]) -> Option<HopObservation> {
    Some(HopObservation { address: Some(address.into()), times_ms: times.to_vec() })
}

fn home_and_isp(hops: u32) -> Option<HopObservation> {
    if hops == 1 { hop("192.168.1.1", &[4.0, 2.0, 3.0]) } else { hop("203.0.113.9", &[9.0, 12.0, 30.0]) }
}

struct Harness {
    audit: RunAudit,
    probed: Arc<Mutex<Vec<String>>>,
    traced: Arc<Mutex<Vec<u32>>>,
    reports: Arc<MemoryReports>,
    history: Arc<MemoryHistory>,
}

fn harness_with(route: DefaultRoute, latency: fn(u32) -> Option<HopObservation>) -> Harness {
    harness_full(route, latency, MemoryHistory::default())
}

fn harness_full(route: DefaultRoute, latency: fn(u32) -> Option<HopObservation>, history: MemoryHistory) -> Harness {
    let history = Arc::new(history);
    let (probed, traced) = (Arc::new(Mutex::new(vec![])), Arc::new(Mutex::new(vec![])));
    let reports = Arc::new(MemoryReports::default());
    let audit = RunAudit::new(AuditDependencies {
        gateway: Box::new(Gateway(route)),
        ports: Box::new(Ports(probed.clone())),
        upnp: Box::new(Upnp),
        wifi: Box::new(Wifi),
        environment: Box::new(Environment),
        latency: Box::new(Latency(traced.clone(), latency)),
        reports: reports.clone(),
        clock: Arc::new(FixedClock),
        history: Arc::new(History::new(history.clone())),
        platform: "test".into(),
    });
    Harness { audit, probed, traced, reports, history }
}

fn home() -> DefaultRoute {
    DefaultRoute { address: Some("192.168.1.1".into()), interface_name: Some("en0".into()) }
}

fn harness() -> Harness {
    harness_with(home(), home_and_isp)
}

const OFF: AuditOptions = AuditOptions { isp_latency: false };
const ON: AuditOptions = AuditOptions { isp_latency: true };

// ---------- RunAudit ----------

#[test]
fn probes_only_the_detected_gateway_and_only_the_audited_ports() {
    let h = harness();
    h.audit.execute(Some("unknown"), OFF).unwrap();
    let mut probed = h.probed.lock().unwrap().clone();
    probed.sort();
    let mut expected: Vec<String> = AUDITED_PORTS.iter().map(|(p, _, _)| format!("192.168.1.1:{p}")).collect();
    expected.sort();
    assert_eq!(probed, expected);
}

#[test]
fn a_vpn_default_route_stops_the_audit_before_anything_is_probed() {
    let h = harness_with(DefaultRoute { address: Some("10.8.0.1".into()), interface_name: Some("utun4".into()) }, home_and_isp);
    assert!(h.audit.execute(Some("unknown"), OFF).is_err());
    assert!(h.probed.lock().unwrap().is_empty());
}

#[test]
fn a_public_gateway_stops_the_audit_before_anything_is_probed_or_saved() {
    let h = harness_with(DefaultRoute { address: Some("203.0.113.1".into()), interface_name: Some("en0".into()) }, home_and_isp);
    assert!(h.audit.execute(Some("unknown"), OFF).is_err());
    assert!(h.probed.lock().unwrap().is_empty());
    assert!(h.reports.0.lock().unwrap().is_empty());
}

#[test]
fn an_invalid_dns_value_stops_the_audit_before_the_gateway_is_located() {
    let h = harness();
    assert_eq!(h.audit.execute(Some("1.1.1.1"), OFF).unwrap_err().0, "--dns must be encrypted, plaintext, or unknown.");
    assert!(h.probed.lock().unwrap().is_empty());
}

#[test]
fn the_saved_report_holds_no_full_address_and_compares_with_the_previous_run() {
    let h = harness();
    h.audit.execute(Some("plaintext"), OFF).unwrap();
    let second = h.audit.execute(Some("encrypted"), OFF).unwrap();
    assert!(!serde_json::to_string(&*h.reports.0.lock().unwrap()).unwrap().contains("192.168.1.1"));
    let c = second.comparison.unwrap();
    assert_eq!((c.previous_score, c.current_score, c.delta), (77, 96, 19));
}

// ---------- ISP delay ----------

#[test]
fn nothing_is_sent_past_the_router_unless_asked_for() {
    let h = harness();
    let report = h.audit.execute(Some("unknown"), OFF).unwrap();
    assert!(h.traced.lock().unwrap().is_empty());
    assert!(!report.checks.latency.requested);
}

#[test]
fn stops_at_the_first_router_outside_the_home_and_stores_times_only() {
    let h = harness();
    let report = h.audit.execute(Some("unknown"), ON).unwrap();
    assert_eq!(*h.traced.lock().unwrap(), [1, 2]);
    let l = &report.checks.latency;
    assert_eq!((l.requested, l.router_ms, l.isp_ms, l.own_hops, l.isp_max_km), (true, Some(3), Some(12), Some(1), Some(900)));
    let stored = serde_json::to_string(&*h.reports.0.lock().unwrap()).unwrap();
    assert!(!stored.contains("203.0.113") && !stored.contains("192.168.1.1"));
}

#[test]
fn stops_after_one_hop_when_the_path_does_not_start_at_the_audited_gateway() {
    let h = harness_with(home(), |_| hop("10.8.0.1", &[5.0]));
    let report = h.audit.execute(Some("unknown"), ON).unwrap();
    assert_eq!(*h.traced.lock().unwrap(), [1]);
    assert_eq!((report.checks.latency.requested, report.checks.latency.router_ms, report.checks.latency.isp_ms), (true, None, None));
}

#[test]
fn silent_hops_are_followed_no_further_than_the_limit_and_a_second_home_router_is_counted() {
    let silent = harness_with(home(), |h| if h == 1 { hop("192.168.1.1", &[2.0]) } else { None });
    let report = silent.audit.execute(Some("unknown"), ON).unwrap();
    assert_eq!(silent.traced.lock().unwrap().len(), MAX_LATENCY_HOPS as usize);
    assert_eq!((report.checks.latency.router_ms, report.checks.latency.isp_ms), (Some(2), None));
    assert!(report.findings.iter().find(|f| f.id == "speed-latency").unwrap().message.contains("Unknown"));

    let nested = harness_with(home(), |h| hop(["192.168.1.1", "192.168.0.1", "100.64.0.1"][h as usize - 1], &[f64::from(h) * 10.0]));
    let report = nested.audit.execute(Some("unknown"), ON).unwrap();
    assert_eq!(*nested.traced.lock().unwrap(), [1, 2, 3]);
    assert_eq!((report.checks.latency.isp_ms, report.checks.latency.own_hops), (Some(30), Some(2)));
}

// ---------- SavedReports ----------

struct Saved {
    audit: RunAudit,
    saved: SavedReports,
    store: Arc<MemorySaved>,
}

fn saved_setup() -> Saved {
    let h = harness();
    let store = Arc::new(MemorySaved::default());
    let saved = SavedReports::new(store.clone(), h.reports.clone(), Arc::new(FixedClock));
    Saved { audit: h.audit, saved, store }
}

#[test]
fn nothing_is_saved_by_auditing_only_by_asking() {
    let s = saved_setup();
    s.audit.execute(Some("unknown"), OFF).unwrap();
    assert!(s.store.0.lock().unwrap().is_empty());
}

#[test]
fn saves_the_latest_audit_under_a_name_and_saving_again_under_that_name_replaces_it() {
    let s = saved_setup();
    s.audit.execute(Some("unknown"), OFF).unwrap();
    assert_eq!(s.saved.save_current(Some("Home")).unwrap().label, "Home");
    s.audit.execute(Some("encrypted"), OFF).unwrap();
    s.saved.save_current(Some("home")).unwrap();
    assert_eq!(s.store.0.lock().unwrap().len(), 1);
    assert_eq!(s.saved.list()[0].label, "home");
}

#[test]
fn refuses_to_save_before_any_audit_with_a_bad_name_or_past_the_limit() {
    let s = saved_setup();
    assert!(s.saved.save_current(Some("Home")).is_err());
    s.audit.execute(Some("unknown"), OFF).unwrap();
    assert!(s.saved.save_current(Some("../x")).is_err());
    assert!(s.saved.save_current(None).is_err());
    for i in 0..MAX_SAVED_REPORTS {
        s.saved.save_current(Some(&format!("Report {i}"))).unwrap();
    }
    assert!(s.saved.save_current(Some("One too many")).is_err());
    s.saved.save_current(Some("report 3")).unwrap(); // replacing is still allowed at the limit
    assert_eq!(s.store.0.lock().unwrap().len(), MAX_SAVED_REPORTS);
}

#[test]
fn compares_the_current_audit_with_a_saved_one_or_two_saved_ones() {
    let s = saved_setup();
    s.audit.execute(Some("plaintext"), OFF).unwrap();
    s.saved.save_current(Some("Office")).unwrap();
    s.audit.execute(Some("encrypted"), OFF).unwrap();
    s.saved.save_current(Some("Home")).unwrap();

    let against = s.saved.compare(None, Some("Office")).unwrap();
    assert_eq!((against.left.name.as_str(), against.right.name.as_str()), (CURRENT_AUDIT, "Office"));
    let dns = against.rows.iter().find(|r| r.id == "dns").unwrap();
    assert_eq!((dns.left.as_deref(), dns.right.as_deref(), dns.better), (Some("encrypted"), Some("plaintext"), Some(Better::Left)));

    let two = s.saved.compare(Some("Office"), Some("Home")).unwrap();
    assert_eq!((two.left.name.as_str(), two.right.name.as_str()), ("Office", "Home"));
    assert_eq!(two.rows.iter().find(|r| r.id == "dns").unwrap().better, Some(Better::Right));
}

#[test]
fn refuses_to_compare_a_report_with_itself_or_with_one_that_does_not_exist() {
    let s = saved_setup();
    assert!(s.saved.compare(None, Some("Nope")).is_err()); // no audit yet
    s.audit.execute(Some("unknown"), OFF).unwrap();
    s.saved.save_current(Some("Home")).unwrap();
    assert!(s.saved.compare(Some("Home"), Some("home")).is_err());
    assert!(s.saved.compare(None, None).is_err());
    assert!(s.saved.compare(None, Some("Nope")).is_err());
}

#[test]
fn deleting_removes_it_and_deleting_what_is_not_there_says_so() {
    let s = saved_setup();
    s.audit.execute(Some("unknown"), OFF).unwrap();
    s.saved.save_current(Some("Home")).unwrap();
    s.saved.remove(Some("Home")).unwrap();
    assert!(s.saved.list().is_empty());
    assert!(s.saved.remove(Some("Home")).is_err());
}

// ---------- WatchSession ----------

#[test]
fn baseline_first_quiet_when_unchanged_change_lines_when_something_moves() {
    let h = harness();
    let mut session = WatchSession::new();
    assert_eq!(session.observe(&h.audit.execute(Some("unknown"), OFF).unwrap()).unwrap().kind, WatchKind::Baseline);
    assert!(session.observe(&h.audit.execute(Some("unknown"), OFF).unwrap()).is_none());
    assert_eq!(session.quiet_runs, 1);
    let event = session.observe(&h.audit.execute(Some("encrypted"), OFF).unwrap()).unwrap();
    assert_eq!(event.kind, WatchKind::Change);
    assert!(event.lines.contains(&"DNS: unknown -> encrypted".to_string()));
    assert_eq!(session.quiet_runs, 0);
}

// ---------- History ----------

#[test]
fn every_audit_adds_a_numbers_only_point_to_the_trend() {
    let h = harness();
    h.audit.execute(Some("unknown"), OFF).unwrap();
    h.audit.execute(Some("unknown"), ON).unwrap();
    let points = h.history.points.lock().unwrap().clone();
    // The fake clock gives both audits the same time, so the second replaces the first.
    assert_eq!(points.len(), 1);
    assert_eq!((points[0].link_rate_mbps, points[0].signal_dbm, points[0].router_ms, points[0].isp_ms), (Some(866), Some(-50), Some(3), Some(12)));
    let json = serde_json::to_string(&points).unwrap();
    assert!(!json.contains("192.168") && !json.contains("203.0.113"));
}

#[test]
fn a_trend_that_cannot_be_written_never_fails_the_audit() {
    let h = harness_full(home(), home_and_isp, MemoryHistory { broken: true, ..Default::default() });
    assert!(h.audit.execute(Some("unknown"), OFF).is_ok());
    assert!(h.history.points.lock().unwrap().is_empty());
}

#[test]
fn a_refused_audit_adds_nothing_to_the_trend() {
    let h = harness_with(DefaultRoute { address: Some("10.8.0.1".into()), interface_name: Some("utun4".into()) }, home_and_isp);
    assert!(h.audit.execute(Some("unknown"), OFF).is_err());
    assert!(h.history.points.lock().unwrap().is_empty());
}
