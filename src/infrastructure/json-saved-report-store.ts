// Stores each saved report as one file under a single folder, named by the label's key. Nothing else is written.
import { mkdir, readdir, unlink } from "node:fs/promises";
import path from "node:path";
import type { SavedReportStore } from "@domain/ports.ts";
import { isSavedReport, labelKey, type SavedReport } from "@domain/saved.ts";

/** What labelKey can produce. Anything else in the folder is not ours and is never read. */
const FILE = /^[a-z0-9-]+\.json$/;

export class JsonSavedReportStore implements SavedReportStore {
  constructor(private readonly directory: string) {}

  private fileFor(label: string): string {
    return path.join(this.directory, `${labelKey(label)}.json`);
  }

  async list(): Promise<SavedReport[]> {
    const names = await readdir(this.directory).catch(() => [] as string[]);
    const saved = await Promise.all(
      names.filter((name) => FILE.test(name)).map((name) => this.read(path.join(this.directory, name))),
    );
    return saved.filter((s): s is SavedReport => s !== null);
  }

  get(label: string): Promise<SavedReport | null> {
    return this.read(this.fileFor(label));
  }

  async save(saved: SavedReport): Promise<void> {
    await mkdir(this.directory, { recursive: true });
    await Bun.write(this.fileFor(saved.label), JSON.stringify(saved, null, 2) + "\n");
  }

  async remove(label: string): Promise<boolean> {
    try {
      await unlink(this.fileFor(label));
      return true;
    } catch {
      return false;
    }
  }

  private async read(file: string): Promise<SavedReport | null> {
    try {
      const value: unknown = await Bun.file(file).json();
      return isSavedReport(value) ? value : null;
    } catch {
      return null;
    }
  }
}
