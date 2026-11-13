//! Use case: run one audit of the private default gateway and store the sanitized report.
use super::history::History;
use crate::domain::evidence::*;
use crate::domain::gateway::{require_home_gateway, SafetyStop};
use crate::domain::model::*;
use crate::domain::ports::*;
use crate::domain::report::build_report;
use crate::domain::scoring::AUDITED_PORTS;
use std::sync::Arc;
use std::thread;

pub struct AuditDependencies {
    pub gateway: Box<dyn GatewayLocator>,
    pub ports: Box<dyn PortProbe>,
    pub upnp: Box<dyn UpnpInspector>,
    pub wifi: Box<dyn WifiInspector>,
    pub environment: Box<dyn EnvironmentInspector>,
    pub latency: Box<dyn LatencyProbe>,
    pub reports: Arc<dyn ReportRepository>,
    pub clock: Arc<dyn Clock>,
    pub history: Arc<History>,
    pub platform: String,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct AuditOptions {
    /// Opt-in: time the first router past the user's own. Off unless the caller passes exactly `true`.
    pub isp_latency: bool,
}

pub struct RunAudit {
    deps: AuditDependencies,
}

impl RunAudit {
    pub fn new(deps: AuditDependencies) -> Self {
        Self { deps }
    }

    /// One hop further at a time, and no further than needed: stops when the path does not start at the audited
    /// gateway, and as soon as a router outside the home answers.
    fn trace_to_isp(&self, target: &str) -> Vec<HopObservation> {
        let mut hops = Vec::new();
        for distance in 1..=MAX_LATENCY_HOPS {
            let hop = self.deps.latency.probe(distance).unwrap_or_default();
            let stop = (distance == 1 && hop.address.as_deref() != Some(target)) || is_beyond_home(&hop);
            hops.push(hop);
            if stop {
                break;
            }
        }
        hops
    }

    /// A caller can supply the DNS status and the ISP-delay opt-in, nothing else. There is no way to pass a target.
    pub fn execute(&self, dns_input: Option<&str>, options: AuditOptions) -> Result<Report, SafetyStop> {
        let deps = &self.deps;
        let dns = parse_dns(dns_input)?;
        let target = require_home_gateway(&deps.gateway.locate())?;

        let (port_checks, upnp, wifi, environment) = thread::scope(|scope| {
            let ports = scope.spawn(|| {
                thread::scope(|inner| {
                    let probes: Vec<_> = AUDITED_PORTS
                        .iter()
                        .map(|(port, service, _)| {
                            let target = &target;
                            inner.spawn(move || PortCheck { port: *port, service: service.to_string(), reachable: deps.ports.is_reachable(target, *port) })
                        })
                        .collect();
                    probes.into_iter().map(|p| p.join().expect("port probe panicked")).collect::<Vec<_>>()
                })
            });
            let upnp = scope.spawn(|| deps.upnp.inspect(&target));
            let wifi = scope.spawn(|| deps.wifi.inspect());
            let environment = scope.spawn(|| deps.environment.inspect());
            (
                ports.join().expect("port checks panicked"),
                upnp.join().expect("upnp check panicked"),
                wifi.join().expect("wifi check panicked"),
                environment.join().expect("environment check panicked"),
            )
        });

        // Timed after the other checks: a Wi-Fi scan takes the radio off its channel and would inflate the delay.
        let hops = if options.isp_latency { self.trace_to_isp(&target) } else { vec![] };

        let report = build_report(
            Checks {
                ports: port_checks,
                upnp: upnp_check_from(&upnp),
                wifi: wifi_check_from(&wifi),
                dns: DnsCheck { status: dns },
                environment: environment_check_from(&environment, &target),
                latency: latency_check_from(options.isp_latency, &hops, &target),
            },
            deps.reports.latest().as_ref(),
            deps.clock.now_iso(),
            &deps.platform,
        );
        deps.reports.save(&report).map_err(|_| SafetyStop::new("The report could not be saved. Nothing was changed."))?;
        deps.history.record(&report);
        Ok(report)
    }
}
