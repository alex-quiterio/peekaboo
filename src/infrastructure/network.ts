// Adapters that touch the network and the operating system. The only code in the project that does.
import dns from "node:dns";
import net from "node:net";
import os from "node:os";
import si from "systeminformation";
import { Client } from "@runonflux/nat-upnp";
import { NO_WIFI, type EnvironmentObservation, type UpnpObservation, type WifiObservation } from "@domain/evidence.ts";
import type { DefaultRoute } from "@domain/gateway.ts";
import type { EnvironmentInspector, GatewayLocator, PortProbe, UpnpInspector, WifiInspector } from "@domain/ports.ts";
import { readDevice } from "./device.ts";
import { readMacWifiLink } from "./wifi-link.ts";

const TCP_TIMEOUT_MS = 800;
const UPNP_TIMEOUT_MS = 3000;

export class SystemGatewayLocator implements GatewayLocator {
  async locate(): Promise<DefaultRoute> {
    const [address, interfaceName] = await Promise.all([si.networkGatewayDefault(), si.networkInterfaceDefault()]);
    return { address: address || null, interfaceName: interfaceName || null };
  }
}

export class TcpConnectProbe implements PortProbe {
  /** Connects, then closes at once. No application data is ever sent. */
  isReachable(host: string, port: number): Promise<boolean> {
    return new Promise((resolve) => {
      const socket = net.createConnection({ host, port });
      let settled = false;
      const finish = (reachable: boolean) => {
        if (settled) return;
        settled = true;
        socket.destroy();
        resolve(reachable);
      };
      socket.setTimeout(TCP_TIMEOUT_MS);
      socket.once("connect", () => finish(true));
      socket.once("timeout", () => finish(false));
      socket.once("error", () => finish(false));
    });
  }
}

export class NatUpnpInspector implements UpnpInspector {
  /** Calls only getGateway() and getMappings(). Never creates, deletes or reconfigures anything. */
  async inspect(gateway: string): Promise<UpnpObservation> {
    const client = new Client({ timeout: UPNP_TIMEOUT_MS });
    try {
      const info = await client.getGateway();
      if (new URL(info.gateway.description).hostname !== gateway) return { state: "refused" };
      const mappings = await client.getMappings();
      return {
        state: "detected",
        mappings: mappings.map((m) => ({
          protocol: String(m.protocol),
          externalPort: Number(m.public.port),
          internalPort: Number(m.private.port),
          internalHost: String(m.private.host),
        })),
      };
    } catch {
      return { state: "unknown" };
    } finally {
      client.close();
    }
  }
}

export class SystemWifiInspector implements WifiInspector {
  /** SSIDs and BSSIDs are used here only to leave our own access point out of the counts; they never leave this method. */
  async inspect(): Promise<WifiObservation> {
    try {
      const [connections, link] = await Promise.all([si.wifiConnections(), readMacWifiLink()]);
      const connection = connections[0];
      if (!connection) return NO_WIFI;

      const channel = Number(connection.channel);
      const hasChannel = Number.isFinite(channel) && channel > 0;
      const observation: WifiObservation = {
        ...NO_WIFI,
        connected: true,
        security: connection.security,
        channel: hasChannel ? channel : null,
        frequencyMhz: Number(connection.frequency) || null,
        linkRateMbps: Number(connection.txRate) || link.linkRateMbps,
        signalDbm: Number(connection.signalLevel) || link.signalDbm,
        noiseDbm: link.noiseDbm,
        channelWidthMhz: link.channelWidthMhz,
        standard: connection.type || link.standard,
      };
      const bssid = String(connection.bssid ?? "").toLowerCase();
      // macOS hands out "<redacted>" for every network name without Location permission. A redacted
      // name identifies nothing, so our own access point could not be told apart from the neighbours.
      const ssid = /redacted/i.test(String(connection.ssid ?? "")) ? "" : String(connection.ssid ?? "");
      if ((!bssid && !ssid) || !hasChannel) return observation;

      const networks = await si.wifiNetworks().catch(() => []);
      if (networks.length === 0) return observation;

      const isSelf = (n: (typeof networks)[number]) =>
        bssid && n.bssid ? String(n.bssid).toLowerCase() === bssid : n.ssid === ssid;
      const others = networks.filter((n) => !isSelf(n)).map((n) => Number(n.channel));
      return {
        ...observation,
        nearbyCount: others.length,
        sameChannelCount: others.filter((c) => c === channel).length,
        // 2.4 GHz channels are 5 MHz apart but 20 MHz wide, so neighbours within 4 channels overlap.
        overlappingCount: channel <= 14 ? others.filter((c) => c <= 14 && c !== channel && Math.abs(c - channel) <= 4).length : 0,
      };
    } catch {
      return NO_WIFI;
    }
  }
}

export class SystemEnvironmentInspector implements EnvironmentInspector {
  /** Reads local configuration only. No packets are sent. */
  async inspect(): Promise<EnvironmentObservation> {
    let resolvers: string[] = [];
    let globalIpv6: boolean | null = null;
    try {
      resolvers = dns.getServers();
    } catch {
      // leave empty: reported as Unknown
    }
    try {
      globalIpv6 = Object.values(os.networkInterfaces())
        .flat()
        .some((a) => a !== undefined && a.family === "IPv6" && !a.internal && /^[23]/.test(a.address));
    } catch {
      // leave null: reported as Unknown
    }
    return { resolvers, globalIpv6, ...(await readDevice()) };
  }
}
