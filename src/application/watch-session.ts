// Use case: watch mode. Feed it each new report; it speaks only for the baseline and for changes.
import type { Report } from "@domain/model.ts";
import { describeChanges, fingerprint } from "@domain/report.ts";

export const WATCH_INTERVAL_MS = 30 * 60 * 1000;

export interface WatchEvent {
  at: string;
  kind: "baseline" | "change";
  lines: string[];
}

export class WatchSession {
  private baseline: Report | null = null;
  quietRuns = 0;
  lastCheckedAt: string | null = null;

  /** Returns an event for the first report and for any change; null when nothing changed. */
  observe(report: Report): WatchEvent | null {
    const before = this.baseline;
    this.baseline = report;
    this.lastCheckedAt = report.generatedAt;

    if (!before) {
      const { provisional, coveragePercent } = report.score;
      return {
        at: report.generatedAt,
        kind: "baseline",
        lines: [`Score ${provisional ?? "unknown"}, coverage ${coveragePercent}%`],
      };
    }
    if (fingerprint(before) === fingerprint(report)) {
      this.quietRuns += 1;
      return null;
    }
    this.quietRuns = 0;
    return { at: report.generatedAt, kind: "change", lines: describeChanges(before, report) };
  }
}
