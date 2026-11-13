// Turns raw observations into sanitized checks. Raw values (addresses, adapter strings) stop here.
import { isPrivateIPv4, redactIPv4, SafetyStop } from "./gateway.ts";
import type { DnsStatus, EnvironmentCheck, SecurityClass, UpnpCheck, WifiBand, WifiCheck } from "./model.ts";

// ---------- DNS (reported by the user) ----------

export function parseDns(value: unknown): DnsStatus {
  if (value === undefined || value === null || value === "") return "unknown";
  if (value === "encrypted" || value === "plaintext" || value === "unknown") return value;
  throw new SafetyStop("--dns must be encrypted, plaintext, or unknown.");
}

// ---------- Wi-Fi ----------

/** What an inspector may hand over: no SSID, BSSID or other identifier. */
export interface WifiObservation {
  connected: boolean;
  security: unknown;
  channel: number | null;
  frequencyMhz: number | null;
  sameChannelCount: number | null;
  overlappingCount: number | null;
  nearbyCount: number | null;
}

export const NO_WIFI: WifiObservation = {
  connected: false,
  security: null,
  channel: null,
  frequencyMhz: null,
  sameChannelCount: null,
  overlappingCount: null,
  nearbyCount: null,
};

function securityText(raw: unknown): string {
  return ([] as unknown[]).concat(raw ?? []).join(" ").toUpperCase().trim();
}

export function classifySecurity(raw: unknown): SecurityClass {
  const s = securityText(raw);
  if (!s) return "unknown";
  if (/WEP|TKIP/.test(s)) return "weak";
  if (/WPA3|SAE/.test(s)) return "strong";
  const wpa1 = /WPA(?![23])/.test(s);
  if (/WPA2|RSN/.test(s)) return wpa1 ? "review" : "strong";
  if (wpa1) return "weak";
  if (/OWE/.test(s)) return "review";
  if (/NONE|OPEN|^-+$/.test(s)) return "weak";
  return "review";
}

/** A fixed vocabulary for display, so raw adapter strings never reach a report. */
export function securityLabel(raw: unknown): string | null {
  const s = securityText(raw);
  if (!s) return null;
  const wpa1 = /WPA(?![23])/.test(s);
  const wpa2 = /WPA2|RSN/.test(s);
  const wpa3 = /WPA3|SAE/.test(s);
  if (/WEP/.test(s)) return "WEP";
  if (wpa3 && wpa2) return "WPA2/WPA3";
  if (wpa3) return "WPA3";
  if (wpa2 && wpa1) return "WPA/WPA2";
  if (wpa2) return "WPA2";
  if (wpa1) return "WPA";
  if (/OWE/.test(s)) return "Enhanced Open";
  if (/NONE|OPEN|^-+$/.test(s)) return "Open";
  return "Other";
}

export function wifiBand(channel: number | null, frequencyMhz: number | null): WifiBand | null {
  if (frequencyMhz && frequencyMhz >= 5925) return "6 GHz";
  if (frequencyMhz && frequencyMhz >= 4900) return "5 GHz";
  if (frequencyMhz && frequencyMhz >= 2400 && frequencyMhz < 2500) return "2.4 GHz";
  if (channel === null) return null;
  return channel <= 14 ? "2.4 GHz" : "5 GHz";
}

export function wifiCheckFrom(observation: WifiObservation): WifiCheck {
  if (!observation.connected) {
    return {
      state: "unknown",
      security: "unknown",
      securityMode: null,
      band: null,
      sameChannelCount: null,
      overlappingCount: null,
      nearbyCount: null,
    };
  }
  const security = classifySecurity(observation.security);
  const complete = security !== "unknown" && observation.sameChannelCount !== null;
  return {
    state: complete ? "known" : "partial",
    security,
    securityMode: securityLabel(observation.security),
    band: wifiBand(observation.channel, observation.frequencyMhz),
    sameChannelCount: observation.sameChannelCount,
    overlappingCount: observation.overlappingCount,
    nearbyCount: observation.nearbyCount,
  };
}

// ---------- UPnP ----------

export interface RawMapping {
  protocol: string;
  externalPort: number;
  internalPort: number;
  internalHost: string;
}

export type UpnpObservation =
  | { state: "detected"; mappings: RawMapping[] }
  | { state: "refused" }
  | { state: "unknown" };

/** Remote-access services that should not be forwarded by accident: FTP, SSH, Telnet, SMB, RDP, VNC. */
const SENSITIVE_PORTS = new Set([21, 22, 23, 445, 3389, 5900]);

export function upnpCheckFrom(observation: UpnpObservation): UpnpCheck {
  if (observation.state !== "detected") {
    return { state: observation.state, mappingCount: null, sensitiveCount: null, mappings: [] };
  }
  const mappings = observation.mappings.map((m, i) => ({
    label: `<mapping-${i + 1}>`,
    protocol: m.protocol.toUpperCase() === "UDP" ? "UDP" : "TCP",
    externalPort: m.externalPort,
    internalPort: m.internalPort,
    internalHost: isPrivateIPv4(m.internalHost) ? redactIPv4(m.internalHost) : "<redacted>",
    sensitive: SENSITIVE_PORTS.has(m.internalPort) || SENSITIVE_PORTS.has(m.externalPort),
  }));
  return {
    state: "detected",
    mappingCount: mappings.length,
    sensitiveCount: mappings.filter((m) => m.sensitive).length,
    mappings,
  };
}

// ---------- This device's environment ----------

export interface EnvironmentObservation {
  /** Resolver addresses as configured on this device. Used for classification only, never stored. */
  resolvers: string[];
  globalIpv6: boolean | null;
}

const PUBLIC_RESOLVERS: Record<string, string> = {
  "1.1.1.1": "Cloudflare",
  "1.0.0.1": "Cloudflare",
  "8.8.8.8": "Google",
  "8.8.4.4": "Google",
  "9.9.9.9": "Quad9",
  "149.112.112.112": "Quad9",
  "208.67.222.222": "OpenDNS",
  "208.67.220.220": "OpenDNS",
  "94.140.14.14": "AdGuard",
  "94.140.15.15": "AdGuard",
};

export function environmentCheckFrom(observation: EnvironmentObservation, gateway: string): EnvironmentCheck {
  const first = observation.resolvers[0];
  const base = { resolverProvider: null, globalIpv6: observation.globalIpv6 };
  if (!first) return { ...base, resolver: "unknown" };
  if (first === gateway) return { ...base, resolver: "gateway" };
  if (/^127\.|^::1$/.test(first)) return { ...base, resolver: "local" };
  if (isPrivateIPv4(first) || /^(fe80|fc|fd)/i.test(first)) return { ...base, resolver: "private" };
  return { ...base, resolver: "public", resolverProvider: PUBLIC_RESOLVERS[first] ?? null };
}
