import { describe, expect, test } from "bun:test";
import { parseHop, TracerouteLatencyProbe } from "./latency.ts";

describe("traceroute hop parsing", () => {
  test("reads the address and every reply time, with or without lost probes", () => {
    expect(parseHop(" 2  198.51.100.1  10.278 ms  7.118 ms  17.345 ms\n", 2)).toEqual({
      address: "198.51.100.1",
      timesMs: [10.278, 7.118, 17.345],
    });
    expect(parseHop(" 1  * 192.168.1.1  33.692 ms  3.952 ms\n", 1)).toEqual({ address: "192.168.1.1", timesMs: [33.692, 3.952] });
  });

  test("a silent hop has no address, and missing output is nothing", () => {
    expect(parseHop(" 3  * * *\n", 3)).toEqual({ address: null, timesMs: [] });
    expect(parseHop(" 3  * * *\n", 2)).toBeNull();
    expect(parseHop(null, 1)).toBeNull();
  });

  test("a reply from the far end is not treated as a hop", () => {
    expect(parseHop(" 4  9.9.9.9  8.1 ms  8.0 ms  8.3 ms\n", 4)).toEqual({ address: null, timesMs: [] });
  });

  test("refuses hop counts outside the limit without running anything", async () => {
    const probe = new TracerouteLatencyProbe();
    expect(await probe.probe(0)).toBeNull();
    expect(await probe.probe(5)).toBeNull();
    expect(await probe.probe(1.5)).toBeNull();
  });
});
