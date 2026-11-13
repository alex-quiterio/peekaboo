// Finds the devices on this network without probing them: it makes the operating system resolve each
// address, reads the neighbour table, and asks the gateway for names. No ports are opened on any device.
import { execFile } from "node:child_process";
import dgram from "node:dgram";
import dns from "node:dns";
import os from "node:os";
import si from "systeminformation";
import type { NeighbourObservation, SelfObservation } from "@domain/devices.ts";
import type { NeighbourDiscovery } from "@domain/ports.ts";

const DISCARD_PORT = 9;
const BATCH_SIZE = 32;
const BATCH_PAUSE_MS = 40;
const SETTLE_MS = 1500;
const COMMAND_TIMEOUT_MS = 3000;
const NAME_TIMEOUT_MS = 1500;

const pause = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

/** Parses `arp -an` (macOS, Linux) and `arp -a` (Windows) into address and hardware-address pairs. */
export function parseNeighbourTable(output: string): { address: string; hardwareAddress: string }[] {
  const rows: { address: string; hardwareAddress: string }[] = [];
  for (const line of output.split("\n")) {
    const match =
      /\((\d{1,3}(?:\.\d{1,3}){3})\) at ([0-9a-f]{1,2}(?::[0-9a-f]{1,2}){5})\b/i.exec(line) ??
      /^\s*(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-f]{2}(?:-[0-9a-f]{2}){5})\b/i.exec(line);
    if (match?.[1] && match[2]) rows.push({ address: match[1], hardwareAddress: match[2] });
  }
  return rows;
}

export class SystemNeighbourDiscovery implements NeighbourDiscovery {
  async self(): Promise<SelfObservation | null> {
    try {
      const name = await si.networkInterfaceDefault();
      const ipv4 = (os.networkInterfaces()[name] ?? []).find((a) => a.family === "IPv4" && !a.internal);
      return ipv4 ? { address: ipv4.address, hardwareAddress: ipv4.mac } : null;
    } catch {
      return null;
    }
  }

  async discover(addresses: string[], gateway: string): Promise<NeighbourObservation[]> {
    await this.resolveAll(addresses);
    const table = await new Promise<string>((resolve) => {
      execFile("arp", [process.platform === "win32" ? "-a" : "-an"], { timeout: COMMAND_TIMEOUT_MS }, (error, stdout) =>
        resolve(error ? "" : stdout),
      );
    });
    const names = this.gatewayResolver(gateway);
    return Promise.all(
      parseNeighbourTable(table).map(async (row) => ({ ...row, name: await this.nameOf(names, row.address) })),
    );
  }

  /**
   * Sends one empty datagram to the discard port of each address. Its only purpose is to make the
   * operating system look the address up, which fills the neighbour table. No reply is read.
   */
  private async resolveAll(addresses: string[]): Promise<void> {
    if (addresses.length === 0) return;
    const socket = dgram.createSocket("udp4");
    socket.on("error", () => {});
    try {
      for (let i = 0; i < addresses.length; i += BATCH_SIZE) {
        for (const address of addresses.slice(i, i + BATCH_SIZE)) socket.send(new Uint8Array(0), DISCARD_PORT, address, () => {});
        await pause(BATCH_PAUSE_MS);
      }
      await pause(SETTLE_MS);
    } finally {
      socket.close();
    }
  }

  /** Names come from the gateway only, never from the system resolver, so private addresses stay on this network. */
  private gatewayResolver(gateway: string): dns.promises.Resolver | null {
    try {
      const resolver = new dns.promises.Resolver({ timeout: NAME_TIMEOUT_MS, tries: 1 });
      resolver.setServers([gateway]);
      return resolver;
    } catch {
      return null;
    }
  }

  private async nameOf(resolver: dns.promises.Resolver | null, address: string): Promise<string | null> {
    if (!resolver) return null;
    try {
      const [name] = await Promise.race([
        resolver.reverse(address),
        pause(NAME_TIMEOUT_MS + 500).then(() => [] as string[]),
      ]);
      return name ? name.replace(/\.$/, "") : null;
    } catch {
      return null;
    }
  }
}
