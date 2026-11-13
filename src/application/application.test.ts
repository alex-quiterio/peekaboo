import { describe, expect, test } from "bun:test";
import { SafetyStop } from "@domain/gateway.ts";
import type { Report } from "@domain/model.ts";
import type { ReportRepository } from "@domain/ports.ts";
import { AUDITED_PORTS } from "@domain/scoring.ts";
import { RunAudit, type AuditDependencies } from "./run-audit.ts";
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
      }),
    },
    environment: { inspect: async () => ({ resolvers: ["192.168.1.1"], globalIpv6: false }) },
    reports,
    platform: "test",
    ...over,
  });
  return { audit, probed, reports };
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
