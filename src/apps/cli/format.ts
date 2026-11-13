// Terminal presentation shared by the scan and watch commands.
import { parseArgs } from "node:util";
import { parseDns } from "@domain/evidence.ts";
import { SEVERITY_ORDER } from "@domain/findings.ts";
import { SafetyStop } from "@domain/gateway.ts";
import type { ReportComparison } from "@domain/compare.ts";
import type { DnsStatus, Report } from "@domain/model.ts";
import { parseLabel, type SavedReportSummary } from "@domain/saved.ts";

/** The only flags are --dns, --isp-latency and --save <name>. Anything else, including any kind of target, is rejected. */
export function optionsFromArgs(argv: string[]): { dns: DnsStatus; ispLatency: boolean; save: string | null } {
  try {
    const { values } = parseArgs({
      args: argv,
      options: { dns: { type: "string" }, "isp-latency": { type: "boolean" }, save: { type: "string" } },
      strict: true,
    });
    // The name is checked now, so a bad one stops the run before anything is measured.
    return {
      dns: parseDns(values.dns),
      ispLatency: values["isp-latency"] === true,
      save: values.save === undefined ? null : parseLabel(values.save),
    };
  } catch (error) {
    if (error instanceof SafetyStop) throw error;
    throw new SafetyStop("The only options are --dns encrypted|plaintext|unknown, --isp-latency and --save <name>.");
  }
}

export function formatReport(report: Report): string {
  const { score, comparison } = report;
  const findings = [...report.findings].sort(
    (a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity),
  );
  const lines = [
    "Home Network Privacy Check",
    `Target: ${report.target}`,
    "",
    ...findings.map((f) => `[${f.severity}] ${f.message}`),
    "",
    score.provisional === null
      ? "Provisional score: Unknown (nothing could be measured)"
      : `Provisional score: ${score.provisional}/100 from ${score.coveragePercent}% evidence coverage`,
  ];
  if (comparison) {
    const { previousScore, currentScore, delta } = comparison;
    lines.push(`Before/after: ${previousScore} -> ${currentScore} (${delta >= 0 ? "+" : ""}${delta})`);
  }
  if (report.topFixes.length) {
    lines.push("", "Top fixes:", ...report.topFixes.map((fix, i) => `  ${i + 1}. ${fix}`));
  }
  if (report.speedTips.length) {
    lines.push("", "Make the Wi-Fi faster:", ...report.speedTips.map((tip, i) => `  ${i + 1}. ${tip}`));
  }
  lines.push("", "Saved sanitized-report.json");
  return lines.join("\n");
}

export function formatSavedList(saved: SavedReportSummary[]): string {
  if (saved.length === 0) return 'No saved reports yet. Run an audit, then: bun run cli:reports save "Home"';
  const when = (iso: string) => new Date(iso).toLocaleString([], { dateStyle: "medium", timeStyle: "short" });
  const width = Math.max(...saved.map((s) => s.label.length));
  return [
    "Saved reports",
    "",
    ...saved.map(
      (s) => `  ${s.label.padEnd(width)}  score ${s.score ?? "unknown"}, ${s.coveragePercent}% coverage, audited ${when(s.generatedAt)}`,
    ),
  ].join("\n");
}

/** A table with a mark beside the better value of each row. */
export function formatComparison({ left, right, rows, wins, onlyLeft, onlyRight, notes }: ReportComparison): string {
  const cell = (value: string | null, mark: boolean) => `${value ?? "Unknown"}${mark ? " *" : ""}`;
  const body = rows.map((row) => [row.label, cell(row.left, row.better === "left"), cell(row.right, row.better === "right")]);
  const table = [["", left.name, right.name], ...body];
  const widths = [0, 1, 2].map((i) => Math.max(...table.map((r) => (r[i] as string).length)));
  const line = (r: string[]) => r.map((c, i) => c.padEnd(widths[i] as number)).join("   ").trimEnd();
  const lines = [
    "Comparison",
    "",
    line(table[0] as string[]),
    widths.map((w) => "-".repeat(w)).join("   "),
    ...body.map(line),
    "",
    `* = better. ${left.name} is better on ${wins.left}, ${right.name} on ${wins.right}. Unknown values are never marked.`,
  ];
  for (const note of notes) lines.push("", `Note: ${note}`);
  if (onlyLeft.length) lines.push("", `Only on ${left.name}:`, ...onlyLeft.map((m) => `  - ${m}`));
  if (onlyRight.length) lines.push("", `Only on ${right.name}:`, ...onlyRight.map((m) => `  - ${m}`));
  return lines.join("\n");
}

/** Prints a message that is safe to show and marks the process as failed. */
export function stopSafely(error: unknown): void {
  console.error(error instanceof SafetyStop ? error.message : "The audit stopped safely before finishing.");
  process.exitCode = 1;
}
