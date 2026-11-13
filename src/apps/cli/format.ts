// Terminal presentation shared by the scan and watch commands.
import { parseArgs } from "node:util";
import { parseDns } from "@domain/evidence.ts";
import { SEVERITY_ORDER } from "@domain/findings.ts";
import { SafetyStop } from "@domain/gateway.ts";
import type { DnsStatus, Report } from "@domain/model.ts";

/** The only flags are --dns and --isp-latency. Anything else, including any kind of target, is rejected. */
export function optionsFromArgs(argv: string[]): { dns: DnsStatus; ispLatency: boolean } {
  try {
    const { values } = parseArgs({
      args: argv,
      options: { dns: { type: "string" }, "isp-latency": { type: "boolean" } },
      strict: true,
    });
    return { dns: parseDns(values.dns), ispLatency: values["isp-latency"] === true };
  } catch (error) {
    if (error instanceof SafetyStop) throw error;
    throw new SafetyStop("The only options are --dns encrypted|plaintext|unknown and --isp-latency.");
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

/** Prints a message that is safe to show and marks the process as failed. */
export function stopSafely(error: unknown): void {
  console.error(error instanceof SafetyStop ? error.message : "The audit stopped safely before finishing.");
  process.exitCode = 1;
}
