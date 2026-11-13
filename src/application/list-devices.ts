// Use case: list the devices on the home network for the dashboard. It has no repository, so it cannot save.
import { deviceListFrom, sweepTargets, type DeviceList } from "@domain/devices.ts";
import { requireHomeGateway } from "@domain/gateway.ts";
import type { GatewayLocator, NeighbourDiscovery } from "@domain/ports.ts";

export interface ListDevicesDependencies {
  gateway: GatewayLocator;
  neighbours: NeighbourDiscovery;
}

export class ListDevices {
  constructor(private readonly deps: ListDevicesDependencies) {}

  /** Takes no input: the network is always this device's own, and the same safety stops apply as for an audit. */
  async execute(): Promise<DeviceList> {
    const { gateway, neighbours } = this.deps;
    const target = requireHomeGateway(await gateway.locate());
    const self = await neighbours.self();
    const seen = await neighbours.discover(self ? sweepTargets(self.address, target) : [], target);
    return deviceListFrom(seen, target, self, new Date());
  }
}
