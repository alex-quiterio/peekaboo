import { describe, expect, test } from "bun:test";
import {
  classifySecurity,
  effectiveDns,
  environmentCheckFrom,
  isHardwareDerivedIPv6,
  NO_DEVICE,
  NO_WIFI,
  parseDns,
  securityLabel,
  upnpCheckFrom,
  wifiBand,
  wifiCheckFrom,
} from "./evidence.ts";
import { buildFindings, topFixes } from "./findings.ts";
import { isPrivateIPv4, redactIPv4, requireHomeGateway, SafetyStop } from "./gateway.ts";
import type { Checks, EnvironmentCheck, WifiCheck } from "./model.ts";
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

const environment = (over: Partial<EnvironmentCheck> = {}): EnvironmentCheck => ({
  resolver: "unknown",
  resolverProvider: null,
  globalIpv6: null,
  tunnelActive: null,
  firewall: "unknown",
  stealthMode: null,
  openListenerCount: null,
  privateHardwareAddress: null,
  ipv6FromHardwareAddress: null,
  ...over,
});

/** Only HTTP (80) answers; everything else is unknown. Scored port weight: 49 of 53. */
const checks = (over: Partial<Checks> = {}): Checks => ({
  ports: AUDITED_PORTS.map(({ port, service }) => ({ port, service, reachable: port === 80 })),
  upnp: { state: "unknown", mappingCount: null, sensitiveCount: null, mappings: [] },
  wifi: wifiCheckFrom(NO_WIFI),
  dns: { status: "unknown" },
  environment: environment(),
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
      environmentCheckFrom({ ...NO_DEVICE, resolvers: [resolver], globalIpv6: false }, "192.168.1.1");
    expect(classify("192.168.1.1").resolver).toBe("gateway");
    expect(classify("192.168.1.53").resolver).toBe("private");
    expect(classify("127.0.0.1").resolver).toBe("local");
    expect(classify("9.9.9.9")).toMatchObject({ resolver: "public", resolverProvider: "Quad9" });
    expect(classify("203.0.113.9")).toMatchObject({ resolver: "public", resolverProvider: null });
    expect(environmentCheckFrom({ ...NO_DEVICE, resolvers: [], globalIpv6: null }, "192.168.1.1").resolver).toBe("unknown");
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

describe("this device", () => {
  const find = (c: Checks, id: string) => buildFindings(c).find((f) => f.id === id);
  const dnsLine = (c: Checks) => scoreChecks(c).breakdown.find((line) => line.id === "dns");

  test("a reported encrypted DNS is not trusted while a tunnel is connected", () => {
    const tunnelled = checks({ dns: { status: "encrypted" }, environment: environment({ tunnelActive: true }) });
    expect(effectiveDns(tunnelled)).toBe("unknown");
    expect(dnsLine(tunnelled)?.earned).toBeNull();
    expect(find(tunnelled, "dns")).toMatchObject({ severity: "LOW" });
    expect(find(tunnelled, "dns")?.message).toStartWith("DNS: Unknown.");
    expect(topFixes(buildFindings(tunnelled)).join(" ")).toContain("tunnel");

    const direct = checks({ dns: { status: "encrypted" }, environment: environment({ tunnelActive: false }) });
    expect(effectiveDns(direct)).toBe("encrypted");
    expect(dnsLine(direct)?.earned).toBe(20);
    expect(effectiveDns(checks({ dns: { status: "plaintext" }, environment: environment({ tunnelActive: true }) }))).toBe("plaintext");
  });

  test("a tunnel next to plaintext or unknown DNS is explained once, without an alarm", () => {
    const c = checks({ environment: environment({ tunnelActive: true }) });
    expect(find(c, "tunnel")).toMatchObject({ severity: "INFO" });
    expect(find(checks(), "tunnel")).toBeUndefined();
  });

  test("a configured public resolver does not contradict encrypted DNS", () => {
    const publicResolver = environment({ resolver: "public", resolverProvider: "OpenDNS", tunnelActive: false });
    const encrypted = find(checks({ dns: { status: "encrypted" }, environment: publicResolver }), "resolver")?.message;
    expect(encrypted).toContain("Encrypted DNS overrides that setting");
    expect(encrypted).not.toContain("your ISP can still read them");
    expect(find(checks({ environment: publicResolver }), "resolver")?.message).toContain("your ISP can still read them");
  });

  test("the firewall is rated by what it leaves reachable", () => {
    const firewall = (over: Partial<EnvironmentCheck>) => find(checks({ environment: environment(over) }), "firewall");
    expect(firewall({ firewall: "off", openListenerCount: 2 })).toMatchObject({ severity: "MEDIUM" });
    expect(firewall({ firewall: "off", openListenerCount: 2 })?.message).toContain("At least 2 ports");
    expect(firewall({ firewall: "off", openListenerCount: 0 })).toMatchObject({ severity: "LOW" });
    expect(firewall({ firewall: "off" })).toMatchObject({ severity: "LOW" });
    expect(firewall({ firewall: "on", stealthMode: false })).toMatchObject({ severity: "INFO" });
    expect(firewall({ firewall: "on", stealthMode: false })?.message).toContain("Stealth mode is off");
    expect(firewall({})?.message).toStartWith("Device firewall: Unknown.");
  });

  test("the hardware address is reported only on Wi-Fi, and never stored", () => {
    const onWifi = checks({ wifi: wifi(), environment: environment({ privateHardwareAddress: false }) });
    expect(find(onWifi, "hardware-address")?.message).toContain("real hardware Wi-Fi address");
    expect(find(checks({ environment: environment({ privateHardwareAddress: false }) }), "hardware-address")).toBeUndefined();
    const observed = environmentCheckFrom(
      { ...NO_DEVICE, resolvers: [], globalIpv6: null, hardwareAddressRandomised: true, firewall: { enabled: true, stealth: null } },
      "192.168.1.1",
    );
    expect(observed).toMatchObject({ privateHardwareAddress: true, firewall: "on", stealthMode: null });
  });

  test("an IPv6 address built from the hardware address is flagged", () => {
    expect(isHardwareDerivedIPv6("2001:db8::a683:e7ff:fe22:3344")).toBe(true);
    expect(isHardwareDerivedIPv6("2001:db8:1:2:a683:e7ff:fe22:3344%en0")).toBe(true);
    expect(isHardwareDerivedIPv6("2001:db8::1c3a:9b2f:77de:41a0")).toBe(false);
    expect(isHardwareDerivedIPv6("2001:db8::1")).toBe(false);
    expect(isHardwareDerivedIPv6("not-an-address")).toBe(false);
    const flagged = checks({ environment: environment({ globalIpv6: true, ipv6FromHardwareAddress: true }) });
    expect(find(flagged, "ipv6-privacy")).toMatchObject({ severity: "LOW" });
    expect(find(checks({ environment: environment({ globalIpv6: true, ipv6FromHardwareAddress: false }) }), "ipv6-privacy")).toBeUndefined();
  });

  test("watch mode notices device changes", () => {
    const before = buildReport(checks({ environment: environment({ firewall: "off", tunnelActive: false }) }), null, context);
    const after = buildReport(checks({ environment: environment({ firewall: "on", tunnelActive: true }) }), null, context);
    expect(fingerprint(before)).not.toBe(fingerprint(after));
    expect(describeChanges(before, after)).toEqual(["VPN or tunnel alongside: no -> yes", "Device firewall: off -> on"]);
  });
});
