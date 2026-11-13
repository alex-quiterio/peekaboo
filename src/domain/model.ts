// The audit's vocabulary. Everything here is already sanitized: no identifiers, no full addresses.

export type DnsStatus = "encrypted" | "plaintext" | "unknown";
export type Severity = "HIGH" | "MEDIUM" | "LOW" | "INFO";
export type SecurityClass = "strong" | "weak" | "review" | "unknown";
export type WifiBand = "2.4 GHz" | "5 GHz" | "6 GHz";
export type WifiStandard = "Wi-Fi 7" | "Wi-Fi 6" | "Wi-Fi 5" | "Wi-Fi 4" | "Legacy";
export type SignalQuality = "excellent" | "good" | "fair" | "weak";
export type ResolverKind = "gateway" | "private" | "local" | "public" | "unknown";

export interface PortCheck {
  port: number;
  service: string;
  reachable: boolean;
}

export interface SanitizedMapping {
  label: string;
  protocol: string;
  externalPort: number;
  internalPort: number;
  internalHost: string;
  /** Forwards to a remote-access service (SSH, Telnet, SMB, RDP, VNC, FTP). */
  sensitive: boolean;
}

export interface UpnpCheck {
  state: "detected" | "refused" | "unknown";
  mappingCount: number | null;
  sensitiveCount: number | null;
  mappings: SanitizedMapping[];
}

/** How fast the radio link between this device and its access point is. Read from this device; nothing is sent. */
export interface WifiSpeedCheck {
  /** The rate the radio has negotiated. A ceiling, not a measured throughput. */
  linkRateMbps: number | null;
  signalDbm: number | null;
  noiseDbm: number | null;
  signal: SignalQuality | null;
  channelWidthMhz: number | null;
  standard: WifiStandard | null;
}

export interface WifiCheck {
  state: "known" | "partial" | "unknown";
  security: SecurityClass;
  securityMode: string | null;
  band: WifiBand | null;
  sameChannelCount: number | null;
  /** Access points on neighbouring, overlapping channels. Only meaningful on 2.4 GHz. */
  overlappingCount: number | null;
  nearbyCount: number | null;
  speed: WifiSpeedCheck;
}

/** Evidence read from this device, not from the network. */
export interface EnvironmentCheck {
  resolver: ResolverKind;
  /** A well-known provider name, when the resolver is a recognised public one. */
  resolverProvider: string | null;
  globalIpv6: boolean | null;
  /** A VPN or tunnel is connected while the default route still goes through the home router. */
  tunnelActive: boolean | null;
  firewall: "on" | "off" | "unknown";
  stealthMode: boolean | null;
  /** Ports on this device that accept connections from the network. A lower bound: system services can be hidden. */
  openListenerCount: number | null;
  /** The network sees a randomised hardware address instead of the real one. */
  privateHardwareAddress: boolean | null;
  /** A global IPv6 address is built from the hardware address, which makes the device recognisable everywhere. */
  ipv6FromHardwareAddress: boolean | null;
}

/** Round-trip delay to this network's own router and to the first router past it. Opt-in; no address is kept. */
export interface LatencyCheck {
  requested: boolean;
  routerMs: number | null;
  ispMs: number | null;
  /** Routers of your own between this device and the ISP. 1 means just the default gateway. */
  ownHops: number | null;
  /** The most cable there can be between the user's router and the ISP's. An upper limit, never an estimate. */
  ispMaxKm: number | null;
}

export interface Checks {
  ports: PortCheck[];
  upnp: UpnpCheck;
  wifi: WifiCheck;
  dns: { status: DnsStatus };
  environment: EnvironmentCheck;
  latency: LatencyCheck;
}

export interface ScoreLine {
  id: string;
  label: string;
  weight: number;
  /** null = unknown, left out of the score. */
  earned: number | null;
}

export interface Score {
  provisional: number | null;
  coveragePercent: number;
  earnedWeight: number;
  knownWeight: number;
  totalWeight: number;
  breakdown: ScoreLine[];
}

export interface Finding {
  id: string;
  severity: Severity;
  message: string;
  action?: string;
}

export interface Comparison {
  previousScore: number;
  currentScore: number;
  delta: number;
}

export interface Report {
  generatedAt: string;
  platform: string;
  target: string;
  checks: Checks;
  score: Score;
  findings: Finding[];
  topFixes: string[];
  /** Ways to make the Wi-Fi faster. Kept apart from topFixes, which are about privacy. */
  speedTips: string[];
  privacy: string[];
  comparison?: Comparison;
}
