// Reports the user chose to keep under a name. They are the same sanitized reports the audit produces; the
// name is the only text the user adds, so it is held to a plain, short vocabulary.
import { SafetyStop } from "./gateway.ts";
import type { Report } from "./model.ts";

export const MAX_SAVED_REPORTS = 50;
const MAX_LABEL_LENGTH = 40;

export interface SavedReport {
  label: string;
  savedAt: string;
  report: Report;
}

/** What the lists show, without the whole report. */
export interface SavedReportSummary {
  label: string;
  savedAt: string;
  generatedAt: string;
  score: number | null;
  coveragePercent: number;
}

/** Letters, digits, spaces and . , ' ( ) _ - only, so a label can never be a path, markup or a command. */
export function parseLabel(input: unknown): string {
  const label = typeof input === "string" ? input.normalize("NFC").trim().replace(/\s+/g, " ") : "";
  if (!label || label.length > MAX_LABEL_LENGTH || !/^[\p{L}\p{N}][\p{L}\p{N} _.,'()-]*$/u.test(label)) {
    throw new SafetyStop(
      `Give the report a name of 1 to ${MAX_LABEL_LENGTH} characters: letters, digits, spaces, and the characters . , ' ( ) _ -.`,
    );
  }
  return label;
}

/**
 * A file-safe identity for a label. Two labels differing only in case share one key, so saving "home" replaces
 * "Home". The hash keeps keys apart when the readable part collides ("Home wifi" and "home-wifi").
 */
export function labelKey(label: string): string {
  const folded = parseLabel(label).toLowerCase();
  let hash = 0x811c9dc5;
  for (const char of folded) {
    hash = Math.imul(hash ^ char.codePointAt(0)!, 0x01000193) >>> 0;
  }
  const readable = folded
    .normalize("NFKD")
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "")
    .slice(0, 30);
  return `${readable || "report"}-${hash.toString(16).padStart(8, "0")}`;
}

export function summarise({ label, savedAt, report }: SavedReport): SavedReportSummary {
  return {
    label,
    savedAt,
    generatedAt: report.generatedAt,
    score: report.score.provisional,
    coveragePercent: report.score.coveragePercent,
  };
}

/** Saved files can be edited by hand, so anything that is not a report of the expected shape is left out. */
export function isSavedReport(value: unknown): value is SavedReport {
  if (!value || typeof value !== "object") return false;
  const { label, savedAt, report } = value as Record<string, unknown>;
  try {
    parseLabel(label);
  } catch {
    return false;
  }
  if (typeof savedAt !== "string" || !report || typeof report !== "object") return false;
  const r = report as Record<string, unknown>;
  const checks = r.checks as Record<string, unknown> | undefined;
  const score = r.score as Record<string, unknown> | undefined;
  return (
    typeof r.generatedAt === "string" &&
    Array.isArray(r.findings) &&
    !!checks &&
    typeof checks === "object" &&
    Array.isArray(checks.ports) &&
    !!checks.wifi &&
    !!checks.upnp &&
    !!checks.environment &&
    !!score &&
    Array.isArray(score.breakdown)
  );
}
