// The report aggregate: assembled from checks, compared with its predecessor, fingerprinted for change detection.
import { buildFindings, topFixes } from "./findings.ts";
import { TARGET_PLACEHOLDER } from "./gateway.ts";
import type { Checks, Comparison, Report, Score } from "./model.ts";
import { scoreChecks } from "./scoring.ts";

export function compare(previous: Report | null, current: Score): Comparison | undefined {
  const before = previous?.score?.provisional;
  if (typeof before !== "number" || current.provisional === null) return undefined;
  return { previousScore: before, currentScore: current.provisional, delta: current.provisional - before };
}

export function buildReport(
  checks: Checks,
  previous: Report | null,
  context: { generatedAt: Date; platform: string },
): Report {
  const score = scoreChecks(checks);
  const findings = buildFindings(checks);
  const comparison = compare(previous, score);
  return {
    generatedAt: context.generatedAt.toISOString(),
    platform: context.platform,
    target: TARGET_PLACEHOLDER,
    checks,
    score,
    findings,
    topFixes: topFixes(findings),
    privacy: [
      "Only the private default gateway detected by the operating system was checked, plus this device's own network settings.",
      "No SSIDs, BSSIDs, MAC addresses, device names, UPnP descriptions or complete IP addresses are stored.",
      "Port checks connect and close without sending data. UPnP is read-only.",
      "WAN exposure was not tested.",
    ],
    ...(comparison ? { comparison } : {}),
  };
}

/** The parts of a report that count as "the network changed". */
function comparable(report: Report): Record<string, string | number | null> {
  const { checks, score } = report;
  const flat: Record<string, string | number | null> = {};
  for (const p of checks.ports) flat[`Port ${p.port} (${p.service})`] = p.reachable ? "reachable" : "not reachable";
  flat["UPnP"] = checks.upnp.state;
  flat["UPnP mappings"] = checks.upnp.mappingCount;
  flat["UPnP mapping list"] = checks.upnp.mappings
    .map((m) => `${m.protocol} ${m.externalPort}->${m.internalHost}:${m.internalPort}`)
    .sort()
    .join(", ");
  flat["UPnP remote-access mappings"] = checks.upnp.sensitiveCount;
  flat["Wi-Fi security"] = checks.wifi.securityMode ?? checks.wifi.security;
  flat["Wi-Fi band"] = checks.wifi.band;
  flat["Same-channel access points"] = checks.wifi.sameChannelCount;
  flat["DNS"] = checks.dns.status;
  flat["DNS resolver"] = checks.environment.resolverProvider ?? checks.environment.resolver;
  flat["Global IPv6"] = checks.environment.globalIpv6 === null ? null : checks.environment.globalIpv6 ? "yes" : "no";
  flat["Score"] = score.provisional;
  flat["Coverage"] = score.coveragePercent;
  return flat;
}

export function fingerprint(report: Report): string {
  return JSON.stringify(comparable(report));
}

export function describeChanges(before: Report, after: Report): string[] {
  const a = comparable(before);
  const b = comparable(after);
  const show = (v: unknown) => (v === null || v === "" ? "unknown" : String(v));
  return Object.keys(b)
    .filter((key) => a[key] !== b[key])
    .map((key) => `${key}: ${show(a[key])} -> ${show(b[key])}`);
}
