// Reads this device's own settings: firewall, tunnels, listening sockets, address privacy.
// Nothing here sends a packet, and only yes/no answers and counts leave this file.
import { execFile } from "node:child_process";
import os from "node:os";
import si from "systeminformation";
import { isRandomisedHardwareAddress } from "@domain/devices.ts";
import { isHardwareDerivedIPv6, NO_DEVICE, type DeviceObservation } from "@domain/evidence.ts";
import { isTunnelInterface } from "@domain/gateway.ts";

const COMMAND_TIMEOUT_MS = 3000;
const MAC_FIREWALL_TOOL = "/usr/libexec/ApplicationFirewall/socketfilterfw";

/** Runs a fixed, read-only command. Returns null when it is missing, fails or times out. */
export function read(
  file: string,
  args: string[],
  emptyExitCode?: number,
  timeoutMs = COMMAND_TIMEOUT_MS,
): Promise<string | null> {
  return new Promise((resolve) => {
    execFile(file, args, { timeout: timeoutMs }, (error, stdout) => {
      if (!error) return resolve(stdout);
      resolve(emptyExitCode !== undefined && error.code === emptyExitCode ? "" : null);
    });
  });
}

/** Parses the macOS firewall tool's answers to --getglobalstate and --getstealthmode. */
export function parseMacFirewall(state: string | null, stealth: string | null): DeviceObservation["firewall"] {
  if (!state) return null;
  const enabled = /State = [12]|\benabled\b/i.test(state) ? true : /State = 0|\bdisabled\b/i.test(state) ? false : null;
  if (enabled === null) return null;
  const hidden = !stealth ? null : /\b(on|enabled)\b/i.test(stealth) ? true : /\b(off|disabled)\b/i.test(stealth) ? false : null;
  return { enabled, stealth: hidden };
}

/**
 * Counts distinct TCP ports listening on a non-loopback address, from `lsof -Fn` output.
 * Without administrator rights lsof shows only the user's own processes, so this is a lower bound.
 */
export function countOpenListeners(lsofFields: string): number {
  const ports = new Set<string>();
  for (const line of lsofFields.split("\n")) {
    const match = /^n(.*):(\d+)$/.exec(line.trim());
    if (!match) continue;
    const [, host = "", port = ""] = match;
    if (/^127\.|^\[::1\]$|^localhost$/.test(host)) continue;
    ports.add(port);
  }
  return ports.size;
}

export async function readDevice(): Promise<DeviceObservation> {
  try {
    const interfaces = os.networkInterfaces();
    const addresses = Object.values(interfaces).flatMap((list) => list ?? []);
    const globalIpv6 = addresses.filter((a) => a.family === "IPv6" && !a.internal && /^[23]/.test(a.address));
    const mac = process.platform === "darwin";

    const [defaultInterface, firewallState, firewallStealth, listeners] = await Promise.all([
      si.networkInterfaceDefault().catch(() => ""),
      mac ? read(MAC_FIREWALL_TOOL, ["--getglobalstate"]) : null,
      mac ? read(MAC_FIREWALL_TOOL, ["--getstealthmode"]) : null,
      // lsof exits with 1 when nothing matches, which means "no listeners", not a failure.
      process.platform === "win32" ? null : read("lsof", ["-nP", "-iTCP", "-sTCP:LISTEN", "-Fn"], 1),
    ]);

    return {
      // A tunnel that is up carries an IPv4 address; idle system tunnels have link-local IPv6 only.
      tunnelActive: Object.entries(interfaces).some(
        ([name, list]) => isTunnelInterface(name) && (list ?? []).some((a) => a.family === "IPv4"),
      ),
      firewall: parseMacFirewall(firewallState, firewallStealth),
      openListenerCount: listeners === null ? null : countOpenListeners(listeners),
      hardwareAddressRandomised: isRandomisedHardwareAddress(interfaces[defaultInterface]?.[0]?.mac ?? ""),
      ipv6FromHardwareAddress: globalIpv6.length ? globalIpv6.some((a) => isHardwareDerivedIPv6(a.address)) : null,
    };
  } catch {
    return NO_DEVICE;
  }
}
