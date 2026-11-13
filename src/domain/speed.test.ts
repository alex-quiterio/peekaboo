import { describe, expect, test } from "bun:test";
import { maxCableKm, NO_WIFI, signalQuality, wifiCheckFrom, wifiStandard, type WifiObservation } from "./evidence.ts";
import { topFixes } from "./findings.ts";
import { latencyFindings, speedFindings, speedTips } from "./speed.ts";

const seen = (over: Partial<WifiObservation> = {}) =>
  wifiCheckFrom({
    ...NO_WIFI,
    connected: true,
    security: "WPA3",
    channel: 36,
    frequencyMhz: 5180,
    sameChannelCount: 0,
    overlappingCount: 0,
    nearbyCount: 4,
    linkRateMbps: 866,
    signalDbm: -50,
    noiseDbm: -92,
    channelWidthMhz: 80,
    standard: "802.11ac",
    ...over,
  });
const ids = (wifi: ReturnType<typeof seen>) => speedFindings(wifi).map((f) => f.id);

describe("wifi speed", () => {
  test("names the newest standard in an adapter string", () => {
    expect(["802.11be", "802.11ax", "802.11a/n/ac", "802.11n", "802.11b/g", "AirPort", null].map(wifiStandard)).toEqual([
      "Wi-Fi 7",
      "Wi-Fi 6",
      "Wi-Fi 5",
      "Wi-Fi 4",
      "Legacy",
      null,
      null,
    ]);
  });

  test("grades the signal", () => {
    expect([-40, -60, -72, -80, null].map(signalQuality)).toEqual(["excellent", "good", "fair", "weak", null]);
  });

  test("implausible readings become unknown, and the raw adapter string is not kept", () => {
    const { speed } = seen({ linkRateMbps: 0, signalDbm: 56, noiseDbm: NaN, channelWidthMhz: 33, standard: "802.11ax (secret)" });
    expect(speed).toEqual({
      linkRateMbps: null,
      signalDbm: null,
      noiseDbm: null,
      signal: null,
      channelWidthMhz: null,
      standard: "Wi-Fi 6",
    });
  });

  test("a healthy link gets no tips", () => {
    const findings = speedFindings(seen());
    expect(findings.every((f) => f.severity === "INFO")).toBe(true);
    expect(findings[0]?.message).toContain("866 Mbps (Wi-Fi 5, 80 MHz channel), which is fast");
    expect(speedTips(findings)).toEqual([]);
  });

  test("an unread link is Unknown, never called slow", () => {
    expect(speedFindings(wifiCheckFrom(NO_WIFI))).toEqual([
      { id: "speed-link", severity: "INFO", message: "Wi-Fi speed: Unknown. No Wi-Fi connection could be read." },
    ]);
    const partial = speedFindings(seen({ linkRateMbps: null, signalDbm: null, noiseDbm: null, channelWidthMhz: null, standard: null }));
    expect(partial).toHaveLength(1);
    expect(partial[0]?.message).toContain("Unknown");
  });

  test("a weak signal says to fix the signal, not to change band", () => {
    const wifi = seen({ channel: 1, frequencyMhz: 2412, signalDbm: -78, linkRateMbps: 40, channelWidthMhz: 20 });
    expect(ids(wifi)).toEqual(["speed-link", "speed-signal"]);
    expect(speedFindings(wifi)[0]?.message).toContain("which is slow");
  });

  test("2.4 GHz with a good signal suggests a faster band, and a wide 2.4 GHz channel is flagged", () => {
    const wifi = seen({ channel: 6, frequencyMhz: 2437, channelWidthMhz: 40, standard: "802.11n" });
    expect(ids(wifi)).toEqual(["speed-link", "speed-signal", "speed-band", "speed-width", "speed-standard"]);
  });

  test("a narrow 5 GHz channel and loud noise are flagged", () => {
    const wifi = seen({ channelWidthMhz: 20, signalDbm: -62, noiseDbm: -80 });
    expect(ids(wifi)).toEqual(["speed-link", "speed-signal", "speed-noise", "speed-width"]);
    expect(speedFindings(wifi).at(-1)?.action).toBe("Set the 5 GHz channel width to 80 MHz in the router.");
  });

  test("speed tips stay out of the privacy top fixes, and include the crowded-channel advice once", () => {
    const findings = [
      ...speedFindings(seen({ signalDbm: -80 })),
      { id: "channel", severity: "LOW" as const, message: "busy", action: "Set the Wi-Fi channel to Auto in the router." },
    ];
    expect(topFixes(findings)).toEqual(["Set the Wi-Fi channel to Auto in the router."]);
    expect(speedTips(findings)).toHaveLength(2);
  });

  test("delay findings: silent unless requested, and a slow line or slow Wi-Fi is told apart", () => {
    const check = (routerMs: number | null, ispMs: number | null, requested = true) =>
      latencyFindings({ requested, routerMs, ispMs, ownHops: ispMs === null ? null : 1, ispMaxKm: maxCableKm(routerMs, ispMs) }).map((f) => `${f.id}:${f.severity}`);
    expect(check(null, null, false)).toEqual([]);
    expect(check(null, null)).toEqual(["speed-latency:INFO"]);
    expect(check(3, 9)).toEqual(["speed-latency-router:INFO", "speed-latency:INFO"]);
    expect(check(35, 40)).toEqual(["speed-latency-router:LOW", "speed-latency:INFO"]);
    expect(check(4, 60)).toEqual(["speed-latency-router:INFO", "speed-latency:LOW"]);
    // A router that is slow to answer for itself, while traffic through it is quick, is not a slow link.
    expect(check(99, 24)).toEqual(["speed-latency-router:INFO", "speed-latency:INFO"]);
    expect(check(30, null)).toEqual(["speed-latency-router:LOW", "speed-latency:INFO"]);
  });

  test("distance is an upper limit, and is withheld when the line adds no measurable delay", () => {
    expect([maxCableKm(5, 11), maxCableKm(99, 24), maxCableKm(5, 5), maxCableKm(null, 9), maxCableKm(5, null)]).toEqual([600, null, null, null, null]);
    const message = (routerMs: number, ispMs: number) =>
      latencyFindings({ requested: true, routerMs, ispMs, ownHops: 1, ispMaxKm: maxCableKm(routerMs, ispMs) }).at(-1)?.message;
    expect(message(5, 11)).toContain("no more than about 600 km of cable away, and usually far closer");
    expect(message(99, 24)).toContain("too small to say anything about distance");
    expect(message(99, 24)).not.toContain("km");
  });
});
