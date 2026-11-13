// Use case: run one audit of the private default gateway and store the sanitized report.
import {
  environmentCheckFrom,
  isBeyondHome,
  latencyCheckFrom,
  MAX_LATENCY_HOPS,
  parseDns,
  upnpCheckFrom,
  wifiCheckFrom,
  type HopObservation,
} from "@domain/evidence.ts";
import { requireHomeGateway } from "@domain/gateway.ts";
import type { Report } from "@domain/model.ts";
import type {
  EnvironmentInspector,
  GatewayLocator,
  LatencyProbe,
  PortProbe,
  ReportRepository,
  UpnpInspector,
  WifiInspector,
} from "@domain/ports.ts";
import { buildReport } from "@domain/report.ts";
import { AUDITED_PORTS } from "@domain/scoring.ts";

export interface AuditDependencies {
  gateway: GatewayLocator;
  ports: PortProbe;
  upnp: UpnpInspector;
  wifi: WifiInspector;
  environment: EnvironmentInspector;
  latency: LatencyProbe;
  reports: ReportRepository;
  platform: string;
}

export interface AuditOptions {
  /** Opt-in: time the first router past the user's own. Off unless exactly true. */
  ispLatency?: boolean;
}

export class RunAudit {
  constructor(private readonly deps: AuditDependencies) {}

  /**
   * One hop further at a time, and no further than needed: stops when the path does not start at the audited
   * gateway, and as soon as a router outside the home answers.
   */
  private async traceToIsp(target: string): Promise<HopObservation[]> {
    const hops: HopObservation[] = [];
    for (let distance = 1; distance <= MAX_LATENCY_HOPS; distance += 1) {
      const hop = (await this.deps.latency.probe(distance)) ?? { address: null, timesMs: [] };
      hops.push(hop);
      if (distance === 1 && hop.address !== target) break;
      if (isBeyondHome(hop)) break;
    }
    return hops;
  }

  /** A caller can supply the DNS status and the ISP-delay opt-in, nothing else. There is no way to pass a target. */
  async execute(dnsInput: unknown, options: AuditOptions = {}): Promise<Report> {
    const { gateway, ports, upnp, wifi, environment, reports, platform } = this.deps;
    const dns = parseDns(dnsInput);
    const ispLatency = options.ispLatency === true;
    const target = requireHomeGateway(await gateway.locate());

    const [portChecks, upnpObservation, wifiObservation, environmentObservation] = await Promise.all([
      Promise.all(
        AUDITED_PORTS.map(async ({ port, service }) => ({
          port,
          service,
          reachable: await ports.isReachable(target, port),
        })),
      ),
      upnp.inspect(target),
      wifi.inspect(),
      environment.inspect(),
    ]);
    // Timed after the other checks: a Wi-Fi scan takes the radio off its channel and would inflate the delay.
    const hops = ispLatency ? await this.traceToIsp(target) : [];

    const report = buildReport(
      {
        ports: portChecks,
        upnp: upnpCheckFrom(upnpObservation),
        wifi: wifiCheckFrom(wifiObservation),
        dns: { status: dns },
        environment: environmentCheckFrom(environmentObservation, target),
        latency: latencyCheckFrom(ispLatency, hops, target),
      },
      await reports.latest(),
      { generatedAt: new Date(), platform },
    );
    await reports.save(report);
    return report;
  }
}
