// Use case: keep audits under a name and compare them. Saving happens only when this is called with a name.
import { compareReports, type ReportComparison } from "@domain/compare.ts";
import { SafetyStop } from "@domain/gateway.ts";
import type { Report } from "@domain/model.ts";
import type { ReportRepository, SavedReportStore } from "@domain/ports.ts";
import { labelKey, MAX_SAVED_REPORTS, parseLabel, summarise, type SavedReportSummary } from "@domain/saved.ts";

export const CURRENT_AUDIT = "Current audit";

export interface SavedReportsDependencies {
  store: SavedReportStore;
  reports: ReportRepository;
}

export class SavedReports {
  constructor(private readonly deps: SavedReportsDependencies) {}

  async list(): Promise<SavedReportSummary[]> {
    const saved = await this.deps.store.list();
    return saved.map(summarise).sort((a, b) => b.savedAt.localeCompare(a.savedAt));
  }

  /** Keeps the most recent audit under `labelInput`, replacing a report that already has that name. */
  async saveCurrent(labelInput: unknown): Promise<SavedReportSummary> {
    const label = parseLabel(labelInput);
    const report = await this.deps.reports.latest();
    if (!report) throw new SafetyStop("There is no audit to save yet. Run one first.");

    const existing = await this.deps.store.list();
    const replacing = existing.some((s) => labelKey(s.label) === labelKey(label));
    if (!replacing && existing.length >= MAX_SAVED_REPORTS) {
      throw new SafetyStop(`You can keep up to ${MAX_SAVED_REPORTS} saved reports. Delete one first.`);
    }
    const saved = { label, savedAt: new Date().toISOString(), report };
    await this.deps.store.save(saved);
    return summarise(saved);
  }

  async remove(labelInput: unknown): Promise<void> {
    const label = parseLabel(labelInput);
    if (!(await this.deps.store.remove(label))) throw new SafetyStop(`There is no saved report named "${label}".`);
  }

  private async resolve(labelInput: unknown): Promise<{ name: string; report: Report }> {
    if (labelInput === undefined || labelInput === null || labelInput === "") {
      const report = await this.deps.reports.latest();
      if (!report) throw new SafetyStop("There is no current audit yet. Run one first.");
      return { name: CURRENT_AUDIT, report };
    }
    const label = parseLabel(labelInput);
    const saved = await this.deps.store.get(label);
    if (!saved) throw new SafetyStop(`There is no saved report named "${label}".`);
    return { name: saved.label, report: saved.report };
  }

  /** An omitted side is the most recent audit. Comparing a report with itself is refused as pointless. */
  async compare(left?: unknown, right?: unknown): Promise<ReportComparison> {
    const [a, b] = await Promise.all([this.resolve(left), this.resolve(right)]);
    if (a.name === b.name) throw new SafetyStop("Pick two different reports to compare.");
    return compareReports(a, b);
  }
}
