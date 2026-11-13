// Turns raw observations into sanitized checks. Raw values (addresses, adapter strings) stop here.
import { isPrivateIPv4, redactIPv4, SafetyStop } from "./gateway.ts";
import type {
  Checks,
  DnsStatus,
  EnvironmentCheck,
  LatencyCheck,
  SecurityClass,
  SignalQuality,
  UpnpCheck,
  WifiBand,
  WifiCheck,
  WifiSpeedCheck,
  WifiStandard,
} from "./model.ts";

// ---------- DNS (reported by the user) ----------

export function parseDns(value: unknown): DnsStatus {
  if (value === undefined || value === null || value === "") return "unknown";
  if (value === "encrypted" || value === "plaintext" || value === "unknown") return value;
  throw new SafetyStop("--dns must be encrypted, plaintext, or unknown.");
}

/**
 * The DNS status the evidence supports. A reported "encrypted" stands only while no tunnel is connected:
 * a tunnel can take over DNS and send lookups around an encrypted-DNS profile.
 */
export function effectiveDns(checks: Pick<Checks, "dns" | "environment">): DnsStatus {
  return checks.dns.status === "encrypted" && checks.environment.tunnelActive ? "unknown" : checks.dns.status;
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
  /** The negotiated link rate, as this device's radio reports it. */
  linkRateMbps: number | null;
  signalDbm: number | null;
  noiseDbm: number | null;
  channelWidthMhz: number | null;
  /** The adapter's own description of the standard in use, such as "802.11ax". */
  standard: unknown;
}

export const NO_WIFI: WifiObservation = {
  connected: false,
  security: null,
  channel: null,
  frequencyMhz: null,
  sameChannelCount: null,
  overlappingCount: null,
  nearbyCount: null,
  linkRateMbps: null,
  signalDbm: null,
  noiseDbm: null,
  channelWidthMhz: null,
  standard: null,
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

/** The newest standard named in an adapter string such as "802.11ax" or "802.11a/n/ac". */
export function wifiStandard(raw: unknown): WifiStandard | null {
  if (typeof raw !== "string") return null;
  const match = /802\.11\s*([a-z/]+)/i.exec(raw);
  if (!match) return null;
  const modes = new Set((match[1] ?? "").toLowerCase().split("/"));
  if (modes.has("be")) return "Wi-Fi 7";
  if (modes.has("ax")) return "Wi-Fi 6";
  if (modes.has("ac")) return "Wi-Fi 5";
  if (modes.has("n")) return "Wi-Fi 4";
  return ["a", "b", "g"].some((mode) => modes.has(mode)) ? "Legacy" : null;
}

export function signalQuality(dbm: number | null): SignalQuality | null {
  if (dbm === null) return null;
  return dbm >= -55 ? "excellent" : dbm >= -67 ? "good" : dbm >= -75 ? "fair" : "weak";
}

const CHANNEL_WIDTHS = [20, 40, 80, 160, 320];
const NO_SPEED: WifiSpeedCheck = {
  linkRateMbps: null,
  signalDbm: null,
  noiseDbm: null,
  signal: null,
  channelWidthMhz: null,
  standard: null,
};

/** Keeps a reading only when it is a plausible value; anything else is unknown. */
function wifiSpeedFrom(observation: WifiObservation): WifiSpeedCheck {
  const dbm = (value: number | null) =>
    value !== null && Number.isFinite(value) && value < 0 && value > -120 ? Math.round(value) : null;
  const rate = observation.linkRateMbps;
  const width = observation.channelWidthMhz;
  const signalDbm = dbm(observation.signalDbm);
  return {
    linkRateMbps: rate !== null && Number.isFinite(rate) && rate > 0 ? Math.round(rate) : null,
    signalDbm,
    noiseDbm: dbm(observation.noiseDbm),
    signal: signalQuality(signalDbm),
    channelWidthMhz: width !== null && CHANNEL_WIDTHS.includes(width) ? width : null,
    standard: wifiStandard(observation.standard),
  };
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
      speed: NO_SPEED,
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
    speed: wifiSpeedFrom(observation),
  };
}

// ---------- Delay to the ISP (opt-in) ----------

/** The furthest a timing packet may travel. Enough for a mesh or second router in front of the ISP's. */
export const MAX_LATENCY_HOPS = 4;

/** Who answered a packet that expired after a given number of routers. The address is used for classification only. */
export interface HopObservation {
  address: string | null;
  timesMs: number[];
}

/** True once a hop outside the home has answered, which is where the measurement must stop. */
export function isBeyondHome(hop: HopObservation): boolean {
  return hop.address !== null && !isPrivateIPv4(hop.address);
}

function median(values: number[]): number | null {
  const sorted = values.filter((v) => Number.isFinite(v) && v >= 0).sort((a, b) => a - b);
  if (sorted.length === 0) return null;
  const middle = Math.floor(sorted.length / 2);
  const value = sorted.length % 2 ? (sorted[middle] as number) : ((sorted[middle - 1] as number) + (sorted[middle] as number)) / 2;
  return Math.round(value);
}

export const NO_LATENCY: LatencyCheck = { requested: false, routerMs: null, ispMs: null, ownHops: null, ispMaxKm: null };

/** Light covers about 200 km of fibre per millisecond, and the delay is a round trip. */
const KM_PER_ROUND_TRIP_MS = 100;

/**
 * The farthest the ISP's router can be, from the delay the line adds. Null when the line adds no measurable
 * delay, because then the limit would read as "0 km", which the evidence does not support.
 */
export function maxCableKm(routerMs: number | null, ispMs: number | null): number | null {
  if (routerMs === null || ispMs === null || ispMs <= routerMs) return null;
  return (ispMs - routerMs) * KM_PER_ROUND_TRIP_MS;
}

/** `hops[0]` is the first router on the path. Unless that is the audited gateway, nothing is concluded. */
export function latencyCheckFrom(requested: boolean, hops: HopObservation[], gateway: string): LatencyCheck {
  if (!requested) return NO_LATENCY;
  const unknown: LatencyCheck = { ...NO_LATENCY, requested: true };
  const router = hops[0];
  if (!router || router.address !== gateway) return unknown;
  const routerMs = median(router.timesMs);
  const ispIndex = hops.findIndex((hop, i) => i > 0 && isBeyondHome(hop));
  const ispMs = ispIndex < 0 ? null : median((hops[ispIndex] as HopObservation).timesMs);
  return { requested: true, routerMs, ispMs, ownHops: ispMs === null ? null : ispIndex, ispMaxKm: maxCableKm(routerMs, ispMs) };
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

/** What this device says about itself. Booleans and counts only: no names, addresses or hardware addresses. */
export interface DeviceObservation {
  tunnelActive: boolean | null;
  firewall: { enabled: boolean; stealth: boolean | null } | null;
  openListenerCount: number | null;
  hardwareAddressRandomised: boolean | null;
  ipv6FromHardwareAddress: boolean | null;
}

export const NO_DEVICE: DeviceObservation = {
  tunnelActive: null,
  firewall: null,
  openListenerCount: null,
  hardwareAddressRandomised: null,
  ipv6FromHardwareAddress: null,
};

export interface EnvironmentObservation extends DeviceObservation {
  /** Resolver addresses as configured on this device. Used for classification only, never stored. */
  resolvers: string[];
  globalIpv6: boolean | null;
}

/** True when an IPv6 address embeds the hardware address (EUI-64: "ff:fe" in the middle of the interface half). */
export function isHardwareDerivedIPv6(address: string): boolean {
  const [head = "", tail] = (address.split("%")[0] ?? "").split("::");
  const left = head ? head.split(":") : [];
  const right = tail ? tail.split(":") : [];
  const groups =
    tail === undefined ? left : [...left, ...Array<string>(Math.max(0, 8 - left.length - right.length)).fill("0"), ...right];
  if (groups.length !== 8) return false;
  const group = (i: number) => (groups[i] ?? "").padStart(4, "0").toLowerCase();
  return group(5).endsWith("ff") && group(6).startsWith("fe");
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
  const base: Omit<EnvironmentCheck, "resolver"> = {
    resolverProvider: null,
    globalIpv6: observation.globalIpv6,
    tunnelActive: observation.tunnelActive,
    firewall: observation.firewall === null ? "unknown" : observation.firewall.enabled ? "on" : "off",
    stealthMode: observation.firewall?.stealth ?? null,
    openListenerCount: observation.openListenerCount,
    privateHardwareAddress: observation.hardwareAddressRandomised,
    ipv6FromHardwareAddress: observation.ipv6FromHardwareAddress,
  };
  if (!first) return { ...base, resolver: "unknown" };
  if (first === gateway) return { ...base, resolver: "gateway" };
  if (/^127\.|^::1$/.test(first)) return { ...base, resolver: "local" };
  if (isPrivateIPv4(first) || /^(fe80|fc|fd)/i.test(first)) return { ...base, resolver: "private" };
  return { ...base, resolver: "public", resolverProvider: PUBLIC_RESOLVERS[first] ?? null };
}
