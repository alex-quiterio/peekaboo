// Explains how fast the Wi-Fi link is and what would make it faster. Advice only: none of this is scored.
import type { Finding, LatencyCheck, WifiCheck } from "./model.ts";

/** Below this link rate, everyday use starts to feel slow. */
const SLOW_MBPS = 100;
const FAST_MBPS = 400;

const MOVE_CLOSER =
  "Move closer to the router, or place the router higher up and nearer the middle of your home. For rooms far from it, add a mesh node or a wired access point.";
export const USE_FASTER_BAND = "Connect on the 5 GHz or 6 GHz band where your router offers it.";

function linkFinding({ speed }: WifiCheck): Finding {
  const rate = speed.linkRateMbps;
  if (rate === null) {
    return {
      id: "speed-link",
      severity: "INFO",
      message: "Wi-Fi speed: Unknown. This device did not report a link rate for its Wi-Fi connection.",
    };
  }
  const pace = rate < SLOW_MBPS ? "slow" : rate < FAST_MBPS ? "moderate" : "fast";
  const details = [speed.standard, speed.channelWidthMhz === null ? null : `${speed.channelWidthMhz} MHz channel`]
    .filter(Boolean)
    .join(", ");
  return {
    id: "speed-link",
    severity: "INFO",
    message:
      `This device's Wi-Fi link rate is ${rate} Mbps${details ? ` (${details})` : ""}, which is ${pace}. ` +
      "Expect about half of that in real use. Internet speed was not measured, because that would send traffic outside your network.",
  };
}

function signalFindings({ speed }: WifiCheck): Finding[] {
  const { signal, signalDbm, noiseDbm } = speed;
  if (signal === null || signalDbm === null) return [];
  const findings: Finding[] = [];
  if (signal === "weak" || signal === "fair") {
    findings.push({
      id: "speed-signal",
      severity: "LOW",
      message: `The Wi-Fi signal where this device sits is ${signal} (${signalDbm} dBm), which lowers the link rate.`,
      action: MOVE_CLOSER,
    });
  } else {
    findings.push({ id: "speed-signal", severity: "INFO", message: `The Wi-Fi signal is ${signal} (${signalDbm} dBm).` });
  }
  // A strong signal still performs badly when the background noise is nearly as loud.
  if (noiseDbm !== null && noiseDbm >= -85 && signalDbm - noiseDbm < 25) {
    findings.push({
      id: "speed-noise",
      severity: "LOW",
      message: `Radio noise is high here (${noiseDbm} dBm), leaving the Wi-Fi signal little room above it.`,
      action: "Keep the router away from microwave ovens, cordless phone bases, baby monitors and USB 3 hubs.",
    });
  }
  return findings;
}

function settingFindings(wifi: WifiCheck): Finding[] {
  const { band, speed } = wifi;
  const findings: Finding[] = [];
  const signalHolds = speed.signal !== "weak" && speed.signal !== "fair";

  // With a weak signal, 2.4 GHz may be the only band that reaches this far, so the advice is to fix the signal first.
  if (band === "2.4 GHz" && signalHolds && !wifi.overlappingCount) {
    findings.push({
      id: "speed-band",
      severity: "LOW",
      message: "The 2.4 GHz band caps the link rate well below what 5 GHz or 6 GHz reach at this distance.",
      action: USE_FASTER_BAND,
    });
  }

  const width = speed.channelWidthMhz;
  if (band === "2.4 GHz" && width !== null && width > 20) {
    findings.push({
      id: "speed-width",
      severity: "LOW",
      message: `The 2.4 GHz channel is ${width} MHz wide. That covers most of the band, so it collides with neighbours and is often slower than 20 MHz.`,
      action: "Set the 2.4 GHz channel width to 20 MHz in the router.",
    });
  } else if (band !== null && band !== "2.4 GHz" && width !== null && width < 80) {
    findings.push({
      id: "speed-width",
      severity: "LOW",
      message: `The ${band} channel is only ${width} MHz wide. An 80 MHz channel carries two to four times as much.`,
      action: `Set the ${band} channel width to 80 MHz in the router.`,
    });
  }

  if (speed.standard === "Wi-Fi 4" || speed.standard === "Legacy") {
    const name = speed.standard === "Legacy" ? "a Wi-Fi standard older than Wi-Fi 4" : "Wi-Fi 4";
    findings.push({
      id: "speed-standard",
      severity: "LOW",
      message: `This connection uses ${name}. Either the router or this device supports nothing newer, or the router is set to an older mode.`,
      action: "Set the router's wireless mode to allow Wi-Fi 5 and Wi-Fi 6. If it offers neither, a newer router is the biggest speed gain.",
    });
  }
  return findings;
}

/** Delay on a healthy Wi-Fi link stays in single digits; above this the Wi-Fi itself is the hold-up. */
const SLOW_ROUTER_MS = 20;
/** What the line between the router and the ISP may add before it is worth raising with the ISP. */
const SLOW_LINE_MS = 30;

/** Empty unless the user asked for the measurement. */
export function latencyFindings({ requested, routerMs, ispMs, ownHops, ispMaxKm }: LatencyCheck): Finding[] {
  if (!requested) return [];
  if (routerMs === null) {
    return [{
      id: "speed-latency",
      severity: "INFO",
      message: "Delay to your ISP: Unknown. Your router did not answer the timing packets, so nothing was concluded.",
    }];
  }
  const findings: Finding[] = [];
  if (ispMs !== null && ispMs < routerMs) {
    // Traffic passing through the router is quicker than the router's own answer, so the link is not the hold-up.
    findings.push({
      id: "speed-latency-router",
      severity: "INFO",
      message: `Your own router takes about ${routerMs} ms to answer timing packets, yet traffic passing through it is quicker. Routers often answer these slowly; it does not mean the link is slow.`,
    });
  } else if (routerMs >= SLOW_ROUTER_MS) {
    findings.push({
      id: "speed-latency-router",
      severity: "LOW",
      message: `Your own router takes about ${routerMs} ms to answer. On a good link that is under 5 ms, so the delay builds up between this device and the router, not at your ISP.`,
      action: MOVE_CLOSER,
    });
  } else {
    findings.push({ id: "speed-latency-router", severity: "INFO", message: `Your own router answers in about ${routerMs} ms.` });
  }

  if (ispMs === null) {
    findings.push({
      id: "speed-latency",
      severity: "INFO",
      message: "Delay to your ISP: Unknown. No router past your own answered the timing packets; many ISPs switch those answers off.",
    });
    return findings;
  }
  const own = ownHops !== null && ownHops > 1
    ? ` There are ${ownHops} routers of your own on the way (for example a mesh or a second router behind the ISP's modem).`
    : "";
  const added = Math.max(0, ispMs - routerMs);
  // Most of the delay is equipment rather than distance, so this is a ceiling and is worded as one.
  const distance = ispMaxKm === null
    ? " The delay is too small to say anything about distance."
    : ` At the speed of light in fibre, that router is no more than about ${ispMaxKm} km of cable away, and usually far closer: most of the delay comes from equipment, not distance.`;
  if (added >= SLOW_LINE_MS) {
    findings.push({
      id: "speed-latency",
      severity: "LOW",
      message: `The first router on your ISP's side answers in about ${ispMs} ms, so the line to your ISP adds about ${added} ms.${own}${distance}`,
      action: "Ask your ISP to check the line. On DSL, ask whether a lower-delay profile (fast path) is available.",
    });
  } else {
    findings.push({
      id: "speed-latency",
      severity: "INFO",
      message: `The first router on your ISP's side answers in about ${ispMs} ms, so the line to your ISP adds little delay.${own}${distance} Where your ISP's equipment actually sits was not looked up.`,
    });
  }
  return findings;
}

export function speedFindings(wifi: WifiCheck): Finding[] {
  if (wifi.state === "unknown") {
    return [{ id: "speed-link", severity: "INFO", message: "Wi-Fi speed: Unknown. No Wi-Fi connection could be read." }];
  }
  return [linkFinding(wifi), ...signalFindings(wifi), ...settingFindings(wifi)];
}

/** Every unique action that would make the Wi-Fi faster, including the crowded-channel and band advice. */
export function speedTips(findings: Finding[]): string[] {
  const actions = findings
    .filter((f) => f.action && (f.id.startsWith("speed-") || f.id === "channel" || f.id === "band"))
    .map((f) => f.action as string);
  return [...new Set(actions)];
}
