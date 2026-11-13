// What the domain needs from the outside world. Infrastructure implements these; nothing here does I/O.
// ("Ports" in the hexagonal sense. TCP ports live in scoring.ts.)
import type { NeighbourObservation, SelfObservation } from "./devices.ts";
import type { EnvironmentObservation, UpnpObservation, WifiObservation } from "./evidence.ts";
import type { DefaultRoute } from "./gateway.ts";
import type { Report } from "./model.ts";

export interface GatewayLocator {
  /** The operating system's default route, unvalidated. */
  locate(): Promise<DefaultRoute>;
}

export interface PortProbe {
  /** Connect-only: opens a TCP connection and closes it without sending data. */
  isReachable(host: string, port: number): Promise<boolean>;
}

export interface UpnpInspector {
  /** Read-only. Must refuse any UPnP device that is not the given gateway. */
  inspect(gateway: string): Promise<UpnpObservation>;
}

export interface WifiInspector {
  inspect(): Promise<WifiObservation>;
}

export interface EnvironmentInspector {
  /** Reads this device's own settings. Sends nothing over the network. */
  inspect(): Promise<EnvironmentObservation>;
}

export interface NeighbourDiscovery {
  /** This device's own address on the default interface, or null when it cannot be read. */
  self(): Promise<SelfObservation | null>;
  /**
   * Makes the operating system resolve each given address, then reads its neighbour table. Names may be
   * asked of the gateway only. Must not connect to, probe or fingerprint any device.
   */
  discover(addresses: string[], gateway: string): Promise<NeighbourObservation[]>;
}

export interface ReportRepository {
  latest(): Promise<Report | null>;
  previous(): Promise<Report | null>;
  /** Stores the report as latest; the old latest becomes previous. */
  save(report: Report): Promise<void>;
}
