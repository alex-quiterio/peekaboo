// Reads the details of this device's own Wi-Fi link that the cross-platform library leaves out: channel
// width and noise. macOS only. The system report also lists network names and the hardware address;
// they are never read here, and only numbers and the standard's name leave this file.
import { read } from "./device.ts";

const REPORT_TIMEOUT_MS = 10000;

export interface WifiLink {
  linkRateMbps: number | null;
  signalDbm: number | null;
  noiseDbm: number | null;
  channelWidthMhz: number | null;
  standard: string | null;
}

export const NO_LINK: WifiLink = {
  linkRateMbps: null,
  signalDbm: null,
  noiseDbm: null,
  channelWidthMhz: null,
  standard: null,
};

/** Parses `system_profiler SPAirPortDataType -json`, keeping only the current connection's radio figures. */
export function parseMacWifiLink(json: string | null): WifiLink {
  if (!json) return NO_LINK;
  try {
    const report = JSON.parse(json) as {
      SPAirPortDataType?: { spairport_airport_interfaces?: { spairport_current_network_information?: Record<string, unknown> }[] }[];
    };
    const current = (report.SPAirPortDataType ?? [])
      .flatMap((entry) => entry.spairport_airport_interfaces ?? [])
      .map((entry) => entry.spairport_current_network_information)
      .find((info) => typeof info?.spairport_network_channel === "string");
    if (!current) return NO_LINK;

    // The channel reads like "36 (5GHz, 80MHz)"; signal and noise like "-52 dBm / -93 dBm".
    const width = /(\d+)\s*MHz/i.exec(String(current.spairport_network_channel));
    const levels = /(-?\d+)\s*dBm\s*\/\s*(-?\d+)\s*dBm/i.exec(String(current.spairport_signal_noise ?? ""));
    const phy = current.spairport_network_phymode;
    return {
      linkRateMbps: Number(current.spairport_network_rate) || null,
      signalDbm: levels ? Number(levels[1]) : null,
      noiseDbm: levels ? Number(levels[2]) : null,
      channelWidthMhz: width ? Number(width[1]) : null,
      standard: typeof phy === "string" ? phy : null,
    };
  } catch {
    return NO_LINK;
  }
}

export async function readMacWifiLink(): Promise<WifiLink> {
  if (process.platform !== "darwin") return NO_LINK;
  return parseMacWifiLink(await read("/usr/sbin/system_profiler", ["SPAirPortDataType", "-json"], undefined, REPORT_TIMEOUT_MS));
}
