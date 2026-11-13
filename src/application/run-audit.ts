// Use case: run one audit of the private default gateway and store the sanitized report.
import { environmentCheckFrom, parseDns, upnpCheckFrom, wifiCheckFrom } from "@domain/evidence.ts";
import { requireHomeGateway } from "@domain/gateway.ts";
import type { Report } from "@domain/model.ts";
import type {
  EnvironmentInspector,
  GatewayLocator,
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
  reports: ReportRepository;
  platform: string;
}

export class RunAudit {
  constructor(private readonly deps: AuditDependencies) {}

  /** `dnsInput` is the only thing a caller can supply. There is no way to pass a target. */
  async execute(dnsInput: unknown): Promise<Report> {
    const { gateway, ports, upnp, wifi, environment, reports, platform } = this.deps;
    const dns = parseDns(dnsInput);
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

    const report = buildReport(
      {
        ports: portChecks,
        upnp: upnpCheckFrom(upnpObservation),
        wifi: wifiCheckFrom(wifiObservation),
        dns: { status: dns },
        environment: environmentCheckFrom(environmentObservation, target),
      },
      await reports.latest(),
      { generatedAt: new Date(), platform },
    );
    await reports.save(report);
    return report;
  }
}
