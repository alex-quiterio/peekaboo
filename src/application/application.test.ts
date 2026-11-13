import { describe, expect, test } from "bun:test";
import { NO_DEVICE } from "@domain/evidence.ts";
import { SafetyStop } from "@domain/gateway.ts";
import type { Report } from "@domain/model.ts";
import type { ReportRepository, SavedReportStore } from "@domain/ports.ts";
import { labelKey, MAX_SAVED_REPORTS, type SavedReport } from "@domain/saved.ts";
import { AUDITED_PORTS } from "@domain/scoring.ts";
import { RunAudit, type AuditDependencies } from "./run-audit.ts";
import { CURRENT_AUDIT, SavedReports } from "./saved-reports.ts";
import { WatchSession } from "./watch-session.ts";

class MemoryReports implements ReportRepository {
  stored: Report[] = [];
  async latest() {
    return this.stored.at(-1) ?? null;
  }
  async previous() {
    return this.stored.at(-2) ?? null;
  }
  async save(report: Report) {
    this.stored.push(report);
  }
}

function harness(over: Partial<AuditDependencies> = {}) {
  const probed: string[] = [];
  const traced: number[] = [];
  const reports = new MemoryReports();
  const audit = new RunAudit({
    gateway: { locate: async () => ({ address: "192.168.1.1", interfaceName: "en0" }) },
    ports: {
      isReachable: async (host, port) => {
        probed.push(`${host}:${port}`);
        return port === 80;
      },
    },
    upnp: { inspect: async () => ({ state: "unknown" }) },
    wifi: {
      inspect: async () => ({
        connected: true,
        security: "WPA2",
        channel: 40,
        frequencyMhz: 5200,
        sameChannelCount: 0,
        overlappingCount: 0,
        nearbyCount: 9,
        linkRateMbps: 866,
        signalDbm: -50,
        noiseDbm: -92,
        channelWidthMhz: 80,
        standard: "802.11ac",
      }),
    },
    environment: { inspect: async () => ({ ...NO_DEVICE, resolvers: ["192.168.1.1"], globalIpv6: false }) },
    latency: {
      probe: async (hops) => {
        traced.push(hops);
        return hops === 1 ? { address: "192.168.1.1", timesMs: [4, 2, 3] } : { address: "203.0.113.9", timesMs: [9, 12, 30] };
      },
    },
    reports,
    platform: "test",
    ...over,
  });
  return { audit, probed, traced, reports };
}

describe("RunAudit", () => {
  test("probes only the detected gateway, and only the audited ports", async () => {
    const { audit, probed } = harness();
    await audit.execute("unknown");
    expect(probed.sort()).toEqual(AUDITED_PORTS.map(({ port }) => `192.168.1.1:${port}`).sort());
  });

  test("a VPN default route stops the audit before anything is probed", async () => {
    const { audit, probed } = harness({
      gateway: { locate: async () => ({ address: "10.8.0.1", interfaceName: "utun4" }) },
    });
    expect(audit.execute("unknown")).rejects.toBeInstanceOf(SafetyStop);
    expect(probed).toEqual([]);
  });

  test("a public gateway stops the audit before anything is probed or saved", async () => {
    const { audit, probed, reports } = harness({ gateway: { locate: async () => ({ address: "203.0.113.1", interfaceName: "en0" }) } });
    expect(audit.execute("unknown")).rejects.toBeInstanceOf(SafetyStop);
    expect(probed).toEqual([]);
    expect(reports.stored).toEqual([]);
  });

  test("an invalid --dns value stops the audit before the gateway is located", async () => {
    let located = false;
    const { audit } = harness({
      gateway: {
        locate: async () => {
          located = true;
          return { address: "192.168.1.1", interfaceName: "en0" };
        },
      },
    });
    expect(audit.execute("1.1.1.1")).rejects.toBeInstanceOf(SafetyStop);
    expect(located).toBe(false);
  });

  test("the saved report holds no full address and compares with the previous run", async () => {
    const { audit, reports } = harness();
    await audit.execute("plaintext");
    const second = await audit.execute("encrypted");
    expect(JSON.stringify(reports.stored)).not.toContain("192.168.1.1");
    expect(second.comparison).toEqual({ previousScore: 77, currentScore: 96, delta: 19 });
  });
});

describe("ISP delay", () => {
  test("nothing is sent past the router unless asked for", async () => {
    const { audit, traced } = harness();
    const report = await audit.execute("unknown");
    expect(traced).toEqual([]);
    expect(report.checks.latency).toEqual({ requested: false, routerMs: null, ispMs: null, ownHops: null, ispMaxKm: null });
    await audit.execute("unknown", { ispLatency: "yes" as unknown as boolean });
    expect(traced).toEqual([]);
  });

  test("stops at the first router outside the home and stores times only", async () => {
    const { audit, traced, reports } = harness();
    const report = await audit.execute("unknown", { ispLatency: true });
    expect(traced).toEqual([1, 2]);
    expect(report.checks.latency).toEqual({ requested: true, routerMs: 3, ispMs: 12, ownHops: 1, ispMaxKm: 900 });
    expect(JSON.stringify(reports.stored)).not.toMatch(/203\.0\.113|192\.168\.1\.1/);
  });

  test("stops after one hop when the path does not start at the audited gateway", async () => {
    const { audit, traced } = harness({
      latency: {
        probe: async (hops) => {
          traced.push(hops);
          return { address: "10.8.0.1", timesMs: [5] };
        },
      },
    });
    const report = await audit.execute("unknown", { ispLatency: true });
    expect(traced).toEqual([1]);
    expect(report.checks.latency).toEqual({ requested: true, routerMs: null, ispMs: null, ownHops: null, ispMaxKm: null });
  });

  test("silent hops are followed no further than the limit, and a second home router is counted", async () => {
    const silent = harness({ latency: { probe: async (hops) => (hops === 1 ? { address: "192.168.1.1", timesMs: [2] } : null) } });
    const quiet = await silent.audit.execute("unknown", { ispLatency: true });
    expect(quiet.checks.latency).toEqual({ requested: true, routerMs: 2, ispMs: null, ownHops: null, ispMaxKm: null });
    expect(quiet.findings.find((f) => f.id === "speed-latency")?.message).toContain("Unknown");

    const answers = ["192.168.1.1", "192.168.0.1", "100.64.0.1"];
    const asked: number[] = [];
    const nested = harness({
      latency: {
        probe: async (hops) => {
          asked.push(hops);
          return { address: answers[hops - 1] ?? null, timesMs: [hops * 10] };
        },
      },
    });
    const report = await nested.audit.execute("unknown", { ispLatency: true });
    expect(asked).toEqual([1, 2, 3]);
    expect(report.checks.latency).toMatchObject({ ispMs: 30, ownHops: 2 });
  });
});

class MemorySaved implements SavedReportStore {
  files = new Map<string, SavedReport>();
  async list() {
    return [...this.files.values()];
  }
  async get(label: string) {
    return this.files.get(labelKey(label)) ?? null;
  }
  async save(saved: SavedReport) {
    this.files.set(labelKey(saved.label), saved);
  }
  async remove(label: string) {
    return this.files.delete(labelKey(label));
  }
}

describe("SavedReports", () => {
  function setup() {
    const { audit, reports } = harness();
    const store = new MemorySaved();
    return { audit, reports, store, saved: new SavedReports({ store, reports }) };
  }

  test("nothing is saved by auditing, only by asking", async () => {
    const { audit, store } = setup();
    await audit.execute("unknown");
    expect(store.files.size).toBe(0);
  });

  test("saves the latest audit under a name, and saving again under that name replaces it", async () => {
    const { audit, saved, store } = setup();
    await audit.execute("unknown");
    expect((await saved.saveCurrent("Home")).label).toBe("Home");
    await audit.execute("encrypted");
    await saved.saveCurrent("home");
    expect(store.files.size).toBe(1);
    expect((await saved.list())[0]?.label).toBe("home");
  });

  test("refuses to save before any audit, with a bad name, or past the limit", async () => {
    const { audit, saved, store } = setup();
    expect(saved.saveCurrent("Home")).rejects.toBeInstanceOf(SafetyStop);
    await audit.execute("unknown");
    expect(saved.saveCurrent("../x")).rejects.toBeInstanceOf(SafetyStop);
    for (let i = 0; i < MAX_SAVED_REPORTS; i += 1) await saved.saveCurrent(`Report ${i}`);
    expect(saved.saveCurrent("One too many")).rejects.toBeInstanceOf(SafetyStop);
    await saved.saveCurrent("report 3"); // replacing is still allowed at the limit
    expect(store.files.size).toBe(MAX_SAVED_REPORTS);
  });

  test("saved reports hold no full address", async () => {
    const { audit, saved, store } = setup();
    await audit.execute("unknown", { ispLatency: true });
    await saved.saveCurrent("Home");
    expect(JSON.stringify([...store.files.values()])).not.toMatch(/192\.168\.1\.1|203\.0\.113/);
  });

  test("compares the current audit with a saved one, or two saved ones", async () => {
    const { audit, saved } = setup();
    await audit.execute("plaintext");
    await saved.saveCurrent("Office");
    await audit.execute("encrypted");
    await saved.saveCurrent("Home");

    const against = await saved.compare(undefined, "Office");
    expect([against.left.name, against.right.name]).toEqual([CURRENT_AUDIT, "Office"]);
    expect(against.rows.find((r) => r.id === "dns")).toMatchObject({ left: "encrypted", right: "plaintext", better: "left" });

    const two = await saved.compare("Office", "Home");
    expect([two.left.name, two.right.name]).toEqual(["Office", "Home"]);
    expect(two.rows.find((r) => r.id === "dns")?.better).toBe("right");
  });

  test("refuses to compare a report with itself, or with one that does not exist", async () => {
    const { audit, saved } = setup();
    expect(saved.compare(undefined, "Nope")).rejects.toBeInstanceOf(SafetyStop); // no audit yet
    await audit.execute("unknown");
    await saved.saveCurrent("Home");
    expect(saved.compare("Home", "home")).rejects.toBeInstanceOf(SafetyStop);
    expect(saved.compare(undefined, undefined)).rejects.toBeInstanceOf(SafetyStop);
    expect(saved.compare(undefined, "Nope")).rejects.toBeInstanceOf(SafetyStop);
  });

  test("deleting removes it, and deleting what is not there says so", async () => {
    const { audit, saved } = setup();
    await audit.execute("unknown");
    await saved.saveCurrent("Home");
    await saved.remove("Home");
    expect(await saved.list()).toEqual([]);
    expect(saved.remove("Home")).rejects.toBeInstanceOf(SafetyStop);
  });
});

describe("WatchSession", () => {
  test("baseline first, quiet when unchanged, change lines when something moves", async () => {
    const { audit } = harness();
    const session = new WatchSession();

    expect(session.observe(await audit.execute("unknown"))?.kind).toBe("baseline");
    expect(session.observe(await audit.execute("unknown"))).toBeNull();
    expect(session.quietRuns).toBe(1);

    const event = session.observe(await audit.execute("encrypted"));
    expect(event?.kind).toBe("change");
    expect(event?.lines).toContain("DNS: unknown -> encrypted");
    expect(session.quietRuns).toBe(0);
  });
});
