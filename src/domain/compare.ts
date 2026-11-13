// Puts two reports side by side and says, metric by metric, which one is better. Unknown never wins.
import { effectiveDns } from "./evidence.ts";
import type { Report, WifiSpeedCheck } from "./model.ts";

export type Better = "left" | "right" | "same" | null;

export interface ComparisonRow {
  id: string;
  label: string;
  /** Display text; null means Unknown. */
  left: string | null;
  right: string | null;
  better: Better;
}

export interface ComparedReport {
  name: string;
  generatedAt: string;
  score: number | null;
}

export interface ReportComparison {
  left: ComparedReport;
  right: ComparedReport;
  rows: ComparisonRow[];
  /** How many metrics each side wins. Ties and unknowns count for neither. */
  wins: { left: number; right: number };
  /** Problems (LOW or worse) found on one side and not on the other. */
  onlyLeft: string[];
  onlyRight: string[];
  /** Cautions about reading the comparison, such as scores built on different amounts of evidence. */
  notes: string[];
}

interface Reading {
  text: string | null;
  /** The number the two sides are compared by. Null = cannot be compared. */
  n: number | null;
}

interface Metric {
  id: string;
  label: string;
  direction: "higher" | "lower" | "none";
  read(report: Report): Reading;
}

const UNKNOWN: Reading = { text: null, n: null };

const amount = (value: number | null | undefined, unit = ""): Reading =>
  value === null || value === undefined ? UNKNOWN : { text: `${value}${unit ? ` ${unit}` : ""}`, n: value };

/** `order` runs worst to best. A value outside it is unknown. */
const ranked = (value: string | null | undefined, order: string[], text = value): Reading => {
  const index = value ? order.indexOf(value) : -1;
  return index < 0 ? UNKNOWN : { text: text ?? value ?? null, n: index };
};

// Reports saved by an earlier version have no speed or delay fields, so those read as Unknown.
const speed = (report: Report): Partial<WifiSpeedCheck> => report.checks.wifi.speed ?? {};
const latency = (report: Report) => report.checks.latency ?? { routerMs: null, ispMs: null, ispMaxKm: null };

const METRICS: Metric[] = [
  { id: "score", label: "Score", direction: "higher", read: (r) => amount(r.score.provisional, "/ 100") },
  { id: "coverage", label: "Evidence coverage", direction: "none", read: (r) => amount(r.score.coveragePercent, "%") },
  { id: "link-rate", label: "Wi-Fi link rate", direction: "higher", read: (r) => amount(speed(r).linkRateMbps, "Mbps") },
  { id: "signal", label: "Wi-Fi signal", direction: "higher", read: (r) => amount(speed(r).signalDbm, "dBm") },
  { id: "noise", label: "Radio noise", direction: "lower", read: (r) => amount(speed(r).noiseDbm, "dBm") },
  {
    id: "standard",
    label: "Wi-Fi standard",
    direction: "higher",
    read: (r) => ranked(speed(r).standard, ["Legacy", "Wi-Fi 4", "Wi-Fi 5", "Wi-Fi 6", "Wi-Fi 7"]),
  },
  { id: "band", label: "Wi-Fi band", direction: "higher", read: (r) => ranked(r.checks.wifi.band, ["2.4 GHz", "5 GHz", "6 GHz"]) },
  { id: "width", label: "Channel width", direction: "higher", read: (r) => amount(speed(r).channelWidthMhz, "MHz") },
  {
    id: "security",
    label: "Wi-Fi security",
    direction: "higher",
    read: (r) => ranked(r.checks.wifi.security, ["weak", "review", "strong"], r.checks.wifi.securityMode ?? r.checks.wifi.security),
  },
  { id: "same-channel", label: "Access points on your channel", direction: "lower", read: (r) => amount(r.checks.wifi.sameChannelCount) },
  { id: "nearby", label: "Access points in range", direction: "none", read: (r) => amount(r.checks.wifi.nearbyCount) },
  { id: "router-delay", label: "Delay to router", direction: "lower", read: (r) => amount(latency(r).routerMs, "ms") },
  { id: "isp-delay", label: "Delay to ISP", direction: "lower", read: (r) => amount(latency(r).ispMs, "ms") },
  { id: "isp-km", label: "ISP router within", direction: "none", read: (r) => amount(latency(r).ispMaxKm, "km at most") },
  {
    id: "ports",
    label: "Router ports answering",
    direction: "lower",
    read: (r) => amount(r.checks.ports.filter((p) => p.reachable).length),
  },
  {
    id: "upnp",
    label: "UPnP mappings",
    direction: "lower",
    read: (r) => (r.checks.upnp.state === "detected" ? amount(r.checks.upnp.mappingCount) : UNKNOWN),
  },
  {
    id: "dns",
    label: "DNS",
    direction: "higher",
    read: (r) => {
      const dns = effectiveDns(r.checks);
      return dns === "unknown" ? UNKNOWN : ranked(dns, ["plaintext", "encrypted"]);
    },
  },
  {
    id: "firewall",
    label: "Device firewall",
    direction: "higher",
    read: (r) => (r.checks.environment.firewall === "unknown" ? UNKNOWN : ranked(r.checks.environment.firewall, ["off", "on"])),
  },
  { id: "listeners", label: "Ports open on this device", direction: "lower", read: (r) => amount(r.checks.environment.openListenerCount) },
];

function judge(direction: Metric["direction"], left: Reading, right: Reading): Better {
  if (direction === "none" || left.n === null || right.n === null) return null;
  if (left.n === right.n) return "same";
  return (left.n > right.n) === (direction === "higher") ? "left" : "right";
}

/** LOW, MEDIUM or HIGH findings, keyed by id so the same problem matches across reports. */
function problems(report: Report): Map<string, string> {
  return new Map(report.findings.filter((f) => f.severity !== "INFO").map((f) => [f.id, f.message]));
}

const describe = (name: string, report: Report): ComparedReport => ({
  name,
  generatedAt: report.generatedAt,
  score: report.score.provisional,
});

export function compareReports(left: { name: string; report: Report }, right: { name: string; report: Report }): ReportComparison {
  const rows: ComparisonRow[] = METRICS.map((metric) => {
    const a = metric.read(left.report);
    const b = metric.read(right.report);
    return { id: metric.id, label: metric.label, left: a.text, right: b.text, better: judge(metric.direction, a, b) };
  });
  const a = problems(left.report);
  const b = problems(right.report);
  const notes: string[] = [];
  const coverage = [left.report.score.coveragePercent, right.report.score.coveragePercent];
  if (coverage[0] !== coverage[1]) {
    notes.push(
      `The scores rest on different evidence: ${left.name} covers ${coverage[0]}% of the checks and ${right.name} ${coverage[1]}%. ` +
        "Compare the individual measures rather than the scores.",
    );
  }
  return {
    left: describe(left.name, left.report),
    right: describe(right.name, right.report),
    rows,
    wins: { left: rows.filter((r) => r.better === "left").length, right: rows.filter((r) => r.better === "right").length },
    onlyLeft: [...a].filter(([id]) => !b.has(id)).map(([, message]) => message),
    onlyRight: [...b].filter(([id]) => !a.has(id)).map(([, message]) => message),
    notes,
  };
}
