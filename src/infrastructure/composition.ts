// Composition root: wires the real adapters into the use cases. Both apps start here.
import path from "node:path";
import { ListDevices } from "@application/list-devices.ts";
import { RunAudit } from "@application/run-audit.ts";
import { JsonReportRepository } from "./json-report-repository.ts";
import { SystemNeighbourDiscovery } from "./neighbours.ts";
import {
  NatUpnpInspector,
  SystemEnvironmentInspector,
  SystemGatewayLocator,
  SystemWifiInspector,
  TcpConnectProbe,
} from "./network.ts";

export function createAudit() {
  const reports = new JsonReportRepository(path.resolve(import.meta.dir, "../.."));
  const gateway = new SystemGatewayLocator();
  const runAudit = new RunAudit({
    gateway,
    ports: new TcpConnectProbe(),
    upnp: new NatUpnpInspector(),
    wifi: new SystemWifiInspector(),
    environment: new SystemEnvironmentInspector(),
    reports,
    platform: process.platform,
  });
  const listDevices = new ListDevices({ gateway, neighbours: new SystemNeighbourDiscovery() });
  return { runAudit, listDevices, reports };
}
