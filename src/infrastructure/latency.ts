// The opt-in ISP delay check. Sends packets with a very small hop limit, so they expire at a router close
// to home and never arrive anywhere. Hop addresses are used to tell "mine" from "the ISP's" and go no further.
import { MAX_LATENCY_HOPS, type HopObservation } from "@domain/evidence.ts";
import type { LatencyProbe } from "@domain/ports.ts";
import { read } from "./device.ts";

/**
 * The direction the packets are sent in, not a host that is contacted: with this hop limit they expire long
 * before arriving. Fixed, and never taken from input. A real routable address is needed because home routers
 * drop packets for reserved test addresses.
 */
const DIRECTION = "9.9.9.9";
const PROBES_PER_HOP = 3;
const WAIT_SECONDS = 1;
const TIMEOUT_MS = (PROBES_PER_HOP * WAIT_SECONDS + 3) * 1000;

/** Reads the one hop line of traceroute output, such as " 2  * 198.51.100.1  10.2 ms  7.1 ms". */
export function parseHop(output: string | null, hops: number): HopObservation | null {
  if (!output) return null;
  const line = output.split("\n").find((l) => new RegExp(`^\\s*${hops}\\s`).test(l));
  if (!line) return null;
  const address = /\b(\d{1,3}(?:\.\d{1,3}){3})\b(?!\s*ms)/.exec(line)?.[1] ?? null;
  const timesMs = [...line.matchAll(/(\d+(?:\.\d+)?)\s*ms/g)].map((m) => Number(m[1]));
  // A reply from the far end would mean the packet arrived, which is not a hop on the way.
  if (address === DIRECTION) return { address: null, timesMs: [] };
  return { address, timesMs };
}

export class TracerouteLatencyProbe implements LatencyProbe {
  async probe(hops: number): Promise<HopObservation | null> {
    if (!Number.isInteger(hops) || hops < 1 || hops > MAX_LATENCY_HOPS) return null;
    if (process.platform === "win32") return null;
    const ttl = String(hops);
    // -n: no name lookups. -f/-m: exactly this hop count. -q/-w: three probes, one second each.
    const args = ["-n", "-f", ttl, "-m", ttl, "-q", String(PROBES_PER_HOP), "-w", String(WAIT_SECONDS), DIRECTION];
    return parseHop(await read("traceroute", args, undefined, TIMEOUT_MS), hops);
  }
}
