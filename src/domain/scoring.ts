// Scores only what is known, and reports coverage separately.
import type { Checks, Score, ScoreLine } from "./model.ts";

/** Every port the audit may touch. Weight 0 = informational: checked and reported, never scored. */
export const AUDITED_PORTS = [
  { port: 21, service: "ftp", weight: 6 },
  { port: 22, service: "ssh", weight: 6 },
  { port: 23, service: "telnet", weight: 10 },
  { port: 53, service: "dns", weight: 0 },
  { port: 80, service: "http", weight: 4 },
  { port: 443, service: "https", weight: 0 },
  { port: 445, service: "smb", weight: 6 },
  { port: 2323, service: "telnet-alt", weight: 8 },
  { port: 7547, service: "cwmp", weight: 10 },
  { port: 8080, service: "http-alt", weight: 3 },
  { port: 8443, service: "https-alt", weight: 0 },
] as const;

const WEIGHT = { upnp: 20, wifi: 20, channel: 10, dns: 20 } as const;

export function scoreChecks(checks: Checks): Score {
  const breakdown: ScoreLine[] = AUDITED_PORTS.filter((p) => p.weight > 0).map(({ port, service, weight }) => {
    const check = checks.ports.find((p) => p.port === port);
    return {
      id: `port-${port}`,
      label: `Port ${port} (${service})`,
      weight,
      earned: check ? (check.reachable ? 0 : weight) : null,
    };
  });

  const { upnp, wifi, dns } = checks;
  const n = wifi.sameChannelCount;
  breakdown.push(
    {
      id: "upnp",
      label: "UPnP",
      weight: WEIGHT.upnp,
      earned: upnp.state === "detected" ? (upnp.mappingCount === 0 ? 10 : 0) : null,
    },
    {
      id: "wifi",
      label: "Wi-Fi security",
      weight: WEIGHT.wifi,
      earned: wifi.security === "unknown" ? null : wifi.security === "strong" ? WEIGHT.wifi : 0,
    },
    {
      id: "channel",
      label: "Channel congestion",
      weight: WEIGHT.channel,
      earned: n === null ? null : n === 0 ? 10 : n <= 2 ? 5 : 0,
    },
    {
      id: "dns",
      label: "DNS",
      weight: WEIGHT.dns,
      earned: dns.status === "unknown" ? null : dns.status === "encrypted" ? WEIGHT.dns : 0,
    },
  );

  const known = breakdown.filter((line) => line.earned !== null);
  const totalWeight = breakdown.reduce((sum, line) => sum + line.weight, 0);
  const knownWeight = known.reduce((sum, line) => sum + line.weight, 0);
  const earnedWeight = known.reduce((sum, line) => sum + (line.earned ?? 0), 0);
  return {
    provisional: knownWeight === 0 ? null : Math.round((earnedWeight / knownWeight) * 100),
    coveragePercent: Math.round((knownWeight / totalWeight) * 100),
    earnedWeight,
    knownWeight,
    totalWeight,
    breakdown,
  };
}
