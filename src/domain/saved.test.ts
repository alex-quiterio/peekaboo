import { describe, expect, test } from "bun:test";
import { compareReports } from "./compare.ts";
import { NO_LATENCY, NO_WIFI, wifiCheckFrom, type WifiObservation } from "./evidence.ts";
import { SafetyStop } from "./gateway.ts";
import type { Checks, Report } from "./model.ts";
import { buildReport } from "./report.ts";
import { AUDITED_PORTS } from "./scoring.ts";
import { isSavedReport, labelKey, parseLabel } from "./saved.ts";

const environment = {
  resolver: "gateway" as const,
  resolverProvider: null,
  globalIpv6: false,
  tunnelActive: false,
  firewall: "on" as const,
  stealthMode: null,
  openListenerCount: 2,
  privateHardwareAddress: true,
  ipv6FromHardwareAddress: null,
};

function report(wifi: Partial<WifiObservation>, over: Partial<Checks> = {}): Report {
  return buildReport(
    {
      ports: AUDITED_PORTS.map(({ port, service }) => ({ port, service, reachable: false })),
      upnp: { state: "detected", mappingCount: 0, sensitiveCount: 0, mappings: [] },
      wifi: wifiCheckFrom({
        ...NO_WIFI,
        connected: true,
        security: "WPA3",
        channel: 36,
        frequencyMhz: 5180,
        sameChannelCount: 0,
        overlappingCount: 0,
        nearbyCount: 5,
        linkRateMbps: 866,
        signalDbm: -50,
        noiseDbm: -92,
        channelWidthMhz: 80,
        standard: "802.11ac",
        ...wifi,
      }),
      dns: { status: "encrypted" },
      environment,
      latency: NO_LATENCY,
      ...over,
    },
    null,
    { generatedAt: new Date("2026-03-01T10:00:00Z"), platform: "test" },
  );
}

describe("saved report labels", () => {
  test("accepts plain names, trimmed and with single spaces", () => {
    expect(parseLabel("  Amsterdam   work ")).toBe("Amsterdam work");
    expect(parseLabel("Café 2.4")).toBe("Café 2.4");
    expect(parseLabel("home_wifi-1")).toBe("home_wifi-1");
    expect(parseLabel("Office (Amsterdam), 3rd floor")).toBe("Office (Amsterdam), 3rd floor");
    expect(parseLabel("Home - Living room")).toBe("Home - Living room");
    expect(parseLabel("a\nb\t c")).toBe("a b c");
  });

  test("refuses anything that could be a path, markup or too long", () => {
    for (const bad of ["", "   ", "../etc", "a/b", "a\\b", "<b>x</b>", ".hidden", "-x", "x".repeat(41), 7, null, undefined, "a\u0000b", "a\u202eb", "a;b", "a$(x)", "a`b`", "a|b", "a&b", "a\"b"]) {
      expect(() => parseLabel(bad)).toThrow(SafetyStop);
    }
  });

  test("keys are file-safe, case-insensitive and keep look-alike names apart", () => {
    expect(labelKey("Home")).toBe(labelKey("home"));
    expect(labelKey("Home wifi")).not.toBe(labelKey("home-wifi"));
    expect(labelKey("Amsterdam work")).toMatch(/^amsterdam-work-[0-9a-f]{8}$/);
    expect(labelKey("家")).toMatch(/^report-[0-9a-f]{8}$/);
    for (const label of ["Café 2.4", "a.b", "x_y", "Office (Amsterdam)", "it's, ok"]) expect(labelKey(label)).toMatch(/^[a-z0-9-]+$/);
  });

  test("a saved file is trusted only when it is shaped like one", () => {
    const good = { label: "Home", savedAt: "2026-03-01T10:00:00Z", report: report({}) };
    expect(isSavedReport(good)).toBe(true);
    expect(isSavedReport({ ...good, label: "../x" })).toBe(false);
    expect(isSavedReport({ ...good, report: { generatedAt: "x" } })).toBe(false);
    expect(isSavedReport(null)).toBe(false);
    expect(isSavedReport("text")).toBe(false);
  });
});

describe("comparing reports", () => {
  const home = report({});
  const office = report({ channel: 6, frequencyMhz: 2437, linkRateMbps: 65, signalDbm: -74, channelWidthMhz: 20, standard: "802.11n", sameChannelCount: 4 });
  const row = (id: string, c: ReturnType<typeof compareReports>) => c.rows.find((r) => r.id === id);

  test("says which side is better on each measure, in the right direction", () => {
    const c = compareReports({ name: "Home", report: home }, { name: "Office", report: office });
    expect(row("link-rate", c)).toMatchObject({ left: "866 Mbps", right: "65 Mbps", better: "left" });
    expect(row("signal", c)).toMatchObject({ better: "left" }); // -50 dBm is stronger than -74
    expect(row("same-channel", c)).toMatchObject({ left: "0", right: "4", better: "left" }); // fewer is better
    expect(row("band", c)).toMatchObject({ left: "5 GHz", right: "2.4 GHz", better: "left" });
    expect(row("standard", c)).toMatchObject({ left: "Wi-Fi 5", right: "Wi-Fi 4", better: "left" });
    expect(row("link-rate", compareReports({ name: "Office", report: office }, { name: "Home", report: home }))).toMatchObject({ better: "right" });
  });

  test("ties are the same, information-only rows are never judged, and unknown never wins", () => {
    const c = compareReports({ name: "Home", report: home }, { name: "Office", report: office });
    expect(row("security", c)?.better).toBe("same");
    expect(row("nearby", c)?.better).toBeNull();
    const noRadio = report({ linkRateMbps: null, signalDbm: null, noiseDbm: null, channelWidthMhz: null, standard: null });
    const unknown = compareReports({ name: "A", report: home }, { name: "B", report: noRadio });
    expect(row("link-rate", unknown)).toMatchObject({ right: null, better: null });
    expect(unknown.wins.left + unknown.wins.right).toBe(unknown.rows.filter((r) => r.better === "left" || r.better === "right").length);
  });

  test("delay is compared when both sides measured it, and lower wins", () => {
    const timed = (routerMs: number, ispMs: number) => report({}, { latency: { requested: true, routerMs, ispMs, ownHops: 1, ispMaxKm: (ispMs - routerMs) * 100 } });
    const c = compareReports({ name: "A", report: timed(3, 9) }, { name: "B", report: timed(5, 30) });
    expect(row("isp-delay", c)).toMatchObject({ left: "9 ms", right: "30 ms", better: "left" });
    expect(row("isp-km", c)?.better).toBeNull();
    expect(row("isp-delay", compareReports({ name: "A", report: timed(3, 9) }, { name: "B", report: home }))).toMatchObject({ right: null, better: null });
  });

  test("a report saved before speed existed reads as Unknown instead of failing", () => {
    const old = structuredClone(home) as unknown as { checks: { wifi: Record<string, unknown>; latency?: unknown } };
    delete old.checks.wifi.speed;
    delete old.checks.latency;
    const c = compareReports({ name: "Old", report: old as unknown as Report }, { name: "Home", report: home });
    expect(row("link-rate", c)).toMatchObject({ left: null, better: null });
    expect(row("isp-delay", c)).toMatchObject({ left: null, better: null });
  });

  test("warns when the scores rest on different amounts of evidence", () => {
    const thin = report({}, { dns: { status: "unknown" } });
    expect(compareReports({ name: "A", report: home }, { name: "B", report: thin }).notes[0]).toContain("different evidence");
    expect(compareReports({ name: "A", report: home }, { name: "B", report: home }).notes).toEqual([]);
  });

  test("lists problems that exist on one side only", () => {
    const weak = report({ security: "WEP" });
    const c = compareReports({ name: "Home", report: home }, { name: "Cafe", report: weak });
    expect(c.onlyLeft).toEqual([]);
    expect(c.onlyRight.some((m) => m.includes("Wi-Fi security is weak"))).toBe(true);
  });
});
