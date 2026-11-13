import { describe, expect, test } from "bun:test";
import {
  classifySecurity,
  environmentCheckFrom,
  NO_WIFI,
  parseDns,
  securityLabel,
  upnpCheckFrom,
  wifiBand,
  wifiCheckFrom,
} from "./evidence.ts";
import { buildFindings, topFixes } from "./findings.ts";
import { isPrivateIPv4, redactIPv4, requireHomeGateway, SafetyStop } from "./gateway.ts";
import type { Checks, WifiCheck } from "./model.ts";
import { buildReport, describeChanges, fingerprint } from "./report.ts";
import { AUDITED_PORTS, scoreChecks } from "./scoring.ts";

const context = { generatedAt: new Date("2026-01-01T00:00:00Z"), platform: "test" };

const wifi = (over: Partial<WifiCheck> = {}): WifiCheck => ({
  state: "known",
  security: "strong",
  securityMode: "WPA2",
  band: "5 GHz",
  sameChannelCount: 0,
  overlappingCount: 0,
  nearbyCount: 12,
  ...over,
});

/** Only HTTP (80) answers; everything else is unknown. Scored port weight: 49 of 53. */
const checks = (over: Partial<Checks> = {}): Checks => ({
  ports: AUDITED_PORTS.map(({ port, service }) => ({ port, service, reachable: port === 80 })),
  upnp: { state: "unknown", mappingCount: null, sensitiveCount: null, mappings: [] },
  wifi: wifiCheckFrom(NO_WIFI),
  dns: { status: "unknown" },
  environment: { resolver: "unknown", resolverProvider: null, globalIpv6: null },
  ...over,
});
const allClosed = () => checks().ports.map((p) => ({ ...p, reachable: false }));

describe("gateway safety", () => {
  test("accepts only RFC 1918 IPv4", () => {
    for (const ok of ["10.0.0.1", "172.16.0.1", "172.31.255.254", "192.168.1.1"]) expect(isPrivateIPv4(ok)).toBe(true);
    for (const bad of ["8.8.8.8", "172.32.0.1", "192.169.1.1", "100.64.0.1", "fe80::1", "", "192.168.1.999", "router.local"])
      expect(isPrivateIPv4(bad)).toBe(false);
  });

  test("stops rather than scan a non-private gateway", () => {
    expect(requireHomeGateway({ address: "192.168.1.1", interfaceName: "en0" })).toBe("192.168.1.1");
    expect(() => requireHomeGateway({ address: "8.8.8.8", interfaceName: "en0" })).toThrow(SafetyStop);
    expect(() => requireHomeGateway({ address: null, interfaceName: null })).toThrow(SafetyStop);
  });

  test("stops when the default route is a VPN tunnel, even with a private gateway", () => {
    for (const tunnel of ["utun4", "tun0", "wg0", "ppp0", "tailscale0"])
      expect(() => requireHomeGateway({ address: "10.8.0.1", interfaceName: tunnel })).toThrow(/VPN or tunnel/);
  });

  test("redacts the final octet", () => {
    expect(redactIPv4("192.168.1.25")).toBe("192.168.1.x");
    expect(redactIPv4("from 10.0.0.7 to 10.0.0.1")).toBe("from 10.0.0.x to 10.0.0.x");
  });

  test("--dns accepts only the three values", () => {
    expect(parseDns(undefined)).toBe("unknown");
    expect(parseDns("encrypted")).toBe("encrypted");
    expect(() => parseDns("8.8.8.8")).toThrow("--dns must be encrypted, plaintext, or unknown.");
  });
});

describe("evidence", () => {
  test.each([
    ["WPA3 Personal", "strong", "WPA3"],
    ["WPA2 Personal", "strong", "WPA2"],
    ["WPA2/WPA3 Personal", "strong", "WPA2/WPA3"],
    ["WPA/WPA2 Personal", "review", "WPA/WPA2"],
    ["WPA Personal", "weak", "WPA"],
    ["WEP", "weak", "WEP"],
    ["WPA2 TKIP", "weak", "WPA2"],
    ["none", "weak", "Open"],
    ["", "unknown", null],
  ] as const)("wifi %s -> %s", (raw, cls, label) => {
    expect(classifySecurity(raw)).toBe(cls);
    expect(securityLabel(raw)).toBe(label);
  });

  test("wifi states and band", () => {
    const seen = { ...NO_WIFI, connected: true, security: ["WPA2", "WPA3"], channel: 40, frequencyMhz: 5200 };
    expect(wifiCheckFrom({ ...seen, sameChannelCount: 1 })).toMatchObject({ state: "known", band: "5 GHz" });
    expect(wifiCheckFrom(seen).state).toBe("partial");
    expect(wifiCheckFrom(NO_WIFI).state).toBe("unknown");
    expect([wifiBand(6, null), wifiBand(36, null), wifiBand(37, 6135), wifiBand(null, null)]).toEqual([
      "2.4 GHz",
      "5 GHz",
      "6 GHz",
      null,
    ]);
  });

  test("UPnP mappings are sanitized and remote-access forwards are flagged", () => {
    const check = upnpCheckFrom({
      state: "detected",
      mappings: [
        { protocol: "tcp", externalPort: 8080, internalPort: 80, internalHost: "192.168.1.25" },
        { protocol: "udp", externalPort: 9, internalPort: 9, internalHost: "my-laptop.local" },
        { protocol: "tcp", externalPort: 50022, internalPort: 22, internalHost: "192.168.1.30" },
      ],
    });
    expect(check.mappingCount).toBe(3);
    expect(check.sensitiveCount).toBe(1);
    expect(check.mappings.map((m) => [m.label, m.protocol, m.internalHost, m.sensitive])).toEqual([
      ["<mapping-1>", "TCP", "192.168.1.x", false],
      ["<mapping-2>", "UDP", "<redacted>", false],
      ["<mapping-3>", "TCP", "192.168.1.x", true],
    ]);
    expect(buildFindings(checks({ upnp: check })).find((f) => f.id === "upnp-sensitive")?.severity).toBe("HIGH");
    expect(upnpCheckFrom({ state: "refused" }).mappingCount).toBeNull();
  });

  test("resolver is classified without keeping its address", () => {
    const classify = (resolver: string) =>
      environmentCheckFrom({ resolvers: [resolver], globalIpv6: false }, "192.168.1.1");
    expect(classify("192.168.1.1").resolver).toBe("gateway");
    expect(classify("192.168.1.53").resolver).toBe("private");
    expect(classify("127.0.0.1").resolver).toBe("local");
    expect(classify("9.9.9.9")).toMatchObject({ resolver: "public", resolverProvider: "Quad9" });
    expect(classify("203.0.113.9")).toMatchObject({ resolver: "public", resolverProvider: null });
    expect(environmentCheckFrom({ resolvers: [], globalIpv6: null }, "192.168.1.1").resolver).toBe("unknown");
    expect(JSON.stringify(classify("192.168.1.53"))).not.toContain("192.168");
  });
});

describe("scoring", () => {
  test("scores only known checks and reports coverage separately", () => {
    const score = scoreChecks(checks());
    expect(score.totalWeight).toBe(123);
    expect(score.knownWeight).toBe(53);
    expect(score.earnedWeight).toBe(49);
    expect(score.provisional).toBe(92);
    expect(score.coveragePercent).toBe(43);
  });

  test("informational ports are checked but never scored", () => {
    const ids = scoreChecks(checks()).breakdown.map((line) => line.id);
    expect(ids).not.toContain("port-443");
    expect(ids).not.toContain("port-53");
    const open = checks({ ports: checks().ports.map((p) => ({ ...p, reachable: p.port === 443 })) });
    expect(scoreChecks(open).provisional).toBe(100);
  });

  test("full coverage, best case", () => {
    const score = scoreChecks(
      checks({
        ports: allClosed(),
        upnp: { state: "detected", mappingCount: 0, sensitiveCount: 0, mappings: [] },
        wifi: wifi({ securityMode: "WPA3" }),
        dns: { status: "encrypted" },
      }),
    );
    expect(score.coveragePercent).toBe(100);
    expect(score.provisional).toBe(92); // UPnP being on at all earns 10 of its 20
  });

  test("channel congestion tiers", () => {
    const earned = (n: number) =>
      scoreChecks(checks({ wifi: wifi({ sameChannelCount: n }) })).breakdown.find((line) => line.id === "channel")?.earned;
    expect([earned(0), earned(2), earned(3)]).toEqual([10, 5, 0]);
  });
});

describe("report", () => {
  test("top fixes: at most three, unique, by severity, never INFO", () => {
    const report = buildReport(
      checks({
        ports: checks().ports.map((p) => ({ ...p, reachable: true })),
        wifi: wifi({ security: "weak", securityMode: "WEP", sameChannelCount: 5 }),
        dns: { status: "plaintext" },
      }),
      null,
      context,
    );
    expect(report.topFixes).toHaveLength(3);
    expect(report.topFixes[0]).toMatch(/Telnet|WPA3/);
    expect(topFixes(report.findings.filter((f) => f.severity === "INFO"))).toEqual([]);
  });

  test("never claims internet exposure and always says WAN was untested", () => {
    const report = buildReport(checks({ ports: checks().ports.map((p) => ({ ...p, reachable: true })) }), null, context);
    expect(JSON.stringify(report)).not.toMatch(/internet-exposed|exposed to the internet/i);
    expect(report.findings.some((f) => f.message.includes("WAN exposure was not tested"))).toBe(true);
    expect(report.target).toBe("<private-gateway>");
  });

  test("comparison only when the previous score is known", () => {
    const first = buildReport(checks(), null, context);
    expect(first.comparison).toBeUndefined();
    const second = buildReport(checks({ ports: allClosed() }), first, context);
    expect(second.comparison).toEqual({ previousScore: 92, currentScore: 100, delta: 8 });
  });

  test("fingerprint ignores the timestamp; changes list only what moved", () => {
    const a = buildReport(checks(), null, context);
    const b = buildReport(checks(), null, { ...context, generatedAt: new Date("2026-02-02T00:00:00Z") });
    expect(fingerprint(a)).toBe(fingerprint(b));
    const c = buildReport(checks({ dns: { status: "encrypted" } }), null, context);
    expect(describeChanges(a, c)).toEqual(["DNS: unknown -> encrypted", "Score: 92 -> 95", "Coverage: 43 -> 59"]);
  });
});
