// Stores exactly two files: sanitized-report.json and previous-sanitized-report.json.
import { exists, rename } from "node:fs/promises";
import path from "node:path";
import type { Report } from "@domain/model.ts";
import type { ReportRepository } from "@domain/ports.ts";

export class JsonReportRepository implements ReportRepository {
  private readonly latestPath: string;
  private readonly previousPath: string;

  constructor(directory: string) {
    this.latestPath = path.join(directory, "sanitized-report.json");
    this.previousPath = path.join(directory, "previous-sanitized-report.json");
  }

  latest(): Promise<Report | null> {
    return this.read(this.latestPath);
  }

  previous(): Promise<Report | null> {
    return this.read(this.previousPath);
  }

  async save(report: Report): Promise<void> {
    if (await exists(this.latestPath)) await rename(this.latestPath, this.previousPath);
    await Bun.write(this.latestPath, JSON.stringify(report, null, 2) + "\n");
  }

  private async read(file: string): Promise<Report | null> {
    try {
      return (await Bun.file(file).json()) as Report;
    } catch {
      return null;
    }
  }
}
