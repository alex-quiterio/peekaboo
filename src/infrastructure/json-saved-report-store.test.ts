import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdtemp, readdir, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import type { Report } from "@domain/model.ts";
import { labelKey, type SavedReport } from "@domain/saved.ts";
import { JsonSavedReportStore } from "./json-saved-report-store.ts";

const report = {
  generatedAt: "2026-03-01T10:00:00Z",
  platform: "test",
  target: "<private-gateway>",
  checks: { ports: [], wifi: {}, upnp: {}, environment: {}, dns: { status: "unknown" } },
  score: { provisional: 90, coveragePercent: 50, breakdown: [] },
  findings: [],
  topFixes: [],
  speedTips: [],
  privacy: [],
} as unknown as Report;
const saved = (label: string): SavedReport => ({ label, savedAt: "2026-03-01T10:05:00Z", report });

let directory: string;
beforeEach(async () => {
  directory = await mkdtemp(path.join(os.tmpdir(), "saved-reports-"));
});
afterEach(() => rm(directory, { recursive: true, force: true }));

describe("JsonSavedReportStore", () => {
  test("saves one file per name, reads it back, and replaces on the same name", async () => {
    const store = new JsonSavedReportStore(path.join(directory, "nested"));
    await store.save(saved("Amsterdam work"));
    await store.save(saved("Home"));
    await store.save({ ...saved("home"), savedAt: "2026-04-01T00:00:00Z" });
    expect(await readdir(path.join(directory, "nested"))).toHaveLength(2);
    expect((await store.get("HOME"))?.savedAt).toBe("2026-04-01T00:00:00Z");
    expect((await store.list()).map((s) => s.label).sort()).toEqual(["Amsterdam work", "home"]);
  });

  test("writes only inside its folder, whatever the name", async () => {
    const store = new JsonSavedReportStore(directory);
    await store.save(saved("a.b"));
    expect(await readdir(directory)).toEqual([`${labelKey("a.b")}.json`]);
  });

  test("ignores files it did not write and files that are not saved reports", async () => {
    const store = new JsonSavedReportStore(directory);
    await store.save(saved("Home"));
    await writeFile(path.join(directory, "notes.txt"), "hello");
    await writeFile(path.join(directory, "broken-00000000.json"), "{not json");
    await writeFile(path.join(directory, "wrong-00000000.json"), JSON.stringify({ label: "x", report: {} }));
    expect((await store.list()).map((s) => s.label)).toEqual(["Home"]);
  });

  test("removing reports whether anything was there, and a missing folder is just empty", async () => {
    const store = new JsonSavedReportStore(path.join(directory, "none"));
    expect(await store.list()).toEqual([]);
    expect(await store.get("Home")).toBeNull();
    await store.save(saved("Home"));
    expect(await store.remove("Home")).toBe(true);
    expect(await store.remove("Home")).toBe(false);
  });
});
