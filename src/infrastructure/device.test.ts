import { describe, expect, test } from "bun:test";
import { countOpenListeners, parseMacFirewall } from "./device.ts";

describe("device evidence parsing", () => {
  test("macOS firewall state and stealth mode", () => {
    expect(parseMacFirewall("Firewall is disabled. (State = 0)", "Firewall stealth mode is off")).toEqual({
      enabled: false,
      stealth: false,
    });
    expect(parseMacFirewall("Firewall is enabled. (State = 1)", "Firewall stealth mode is on")).toEqual({
      enabled: true,
      stealth: true,
    });
    expect(parseMacFirewall("Firewall is enabled. (State = 2)", null)).toEqual({ enabled: true, stealth: null });
  });

  test("an unreadable firewall is unknown, never assumed off", () => {
    expect(parseMacFirewall(null, null)).toBeNull();
    expect(parseMacFirewall("something unexpected", "Firewall stealth mode is on")).toBeNull();
  });

  test("counts distinct ports open to the network and ignores loopback listeners", () => {
    const lsof = ["p101", "f12", "n*:7000", "f13", "n*:5000", "p202", "f9", "n127.0.0.1:4173", "n[::1]:4173", "n[::]:7000", "n192.168.1.20:8000"].join("\n");
    expect(countOpenListeners(lsof)).toBe(3);
    expect(countOpenListeners("")).toBe(0);
    expect(countOpenListeners("p1\nf3\nn127.0.0.1:631\n")).toBe(0);
  });
});
