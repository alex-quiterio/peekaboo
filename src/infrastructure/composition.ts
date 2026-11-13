// Composition root: wires the real adapters into the use cases. Both apps start here.
import path from "node:path";
import { ListDevices } from "@application/list-devices.ts";
import { RunAudit } from "@application/run-audit.ts";
import { SavedReports } from "@application/saved-reports.ts";
import { TracerouteLatencyProbe } from "./latency.ts";
import { JsonReportRepository } from "./json-report-repository.ts";
import { JsonSavedReportStore } from "./json-saved-report-store.ts";
import { SystemNeighbourDiscovery } from "./neighbours.ts";
import {
  NatUpnpInspector,
  SystemEnvironmentInspector,
  SystemGatewayLocator,
  SystemWifiInspector,
  TcpConnectProbe,
} from "./network.ts";

export function createAudit() {
  const root = path.resolve(import.meta.dir, "../..");
  const reports = new JsonReportRepository(root);
  const gateway = new SystemGatewayLocator();
  const runAudit = new RunAudit({
    gateway,
    ports: new TcpConnectProbe(),
    upnp: new NatUpnpInspector(),
    wifi: new SystemWifiInspector(),
    environment: new SystemEnvironmentInspector(),
    latency: new TracerouteLatencyProbe(),
    reports,
    platform: process.platform,
  });
  const listDevices = new ListDevices({ gateway, neighbours: new SystemNeighbourDiscovery() });
  const savedReports = new SavedReports({ store: new JsonSavedReportStore(path.join(root, "saved-reports")), reports });
  return { runAudit, listDevices, savedReports, reports };
}
