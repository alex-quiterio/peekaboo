import { describe, expect, test } from "bun:test";
import { NO_LINK, parseMacWifiLink } from "./wifi-link.ts";

const report = (current: Record<string, unknown>) =>
  JSON.stringify({
    SPAirPortDataType: [
      {
        spairport_airport_interfaces: [
          { _name: "awdl0", spairport_current_network_information: { spairport_network_type: "station" } },
          { _name: "en0", spairport_wireless_mac_address: "aa:bb:cc:dd:ee:ff", spairport_current_network_information: current },
        ],
      },
    ],
  });

describe("macOS Wi-Fi link parsing", () => {
  test("keeps only the radio figures of the current connection", () => {
    const link = parseMacWifiLink(
      report({
        _name: "HomeNetwork",
        spairport_network_channel: "36 (5GHz, 80MHz)",
        spairport_network_phymode: "802.11ax",
        spairport_network_rate: 1200,
        spairport_signal_noise: "-52 dBm / -93 dBm",
      }),
    );
    expect(link).toEqual({ linkRateMbps: 1200, signalDbm: -52, noiseDbm: -93, channelWidthMhz: 80, standard: "802.11ax" });
    expect(JSON.stringify(link)).not.toMatch(/HomeNetwork|aa:bb/);
  });

  test("missing fields, no connection and unreadable output are all unknown", () => {
    expect(parseMacWifiLink(report({ spairport_network_channel: "6" }))).toEqual(NO_LINK);
    expect(parseMacWifiLink(report({}))).toEqual(NO_LINK);
    expect(parseMacWifiLink("not json")).toEqual(NO_LINK);
    expect(parseMacWifiLink(null)).toEqual(NO_LINK);
  });
});
