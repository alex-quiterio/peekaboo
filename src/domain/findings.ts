// Explains checks in plain words. A LAN-side result is never described as internet exposure.
import type { Checks, EnvironmentCheck, Finding, PortCheck, Severity, UpnpCheck, WifiCheck } from "./model.ts";

interface PortAdvice {
  severity: Severity;
  message: string;
  action?: string;
}

/** What to say when a port accepts connections from the LAN. */
const REACHABLE: Record<number, PortAdvice> = {
  21: {
    severity: "MEDIUM",
    message: "FTP (21) accepts connections from this network. FTP is unencrypted.",
    action: "Disable the router's FTP or USB file-sharing server if you do not use it.",
  },
  22: {
    severity: "MEDIUM",
    message: "SSH (22) accepts connections from this network.",
    action: "Disable SSH on the router if you do not use it.",
  },
  23: {
    severity: "HIGH",
    message: "Telnet (23) accepts connections from this network. Telnet is unencrypted.",
    action: "Disable Telnet on the router.",
  },
  53: { severity: "INFO", message: "The router answers DNS (53), so it can act as your network's resolver." },
  80: {
    severity: "LOW",
    message: "The router answers on HTTP (80) from this network, usually its admin page.",
    action: "Use the HTTPS admin page if your router offers one, and check WAN remote management is off.",
  },
  443: { severity: "INFO", message: "The router answers on HTTPS (443), so an encrypted admin page is likely available." },
  445: {
    severity: "MEDIUM",
    message: "SMB file sharing (445) accepts connections from this network.",
    action: "Disable the router's SMB or USB file-sharing server if you do not use it.",
  },
  2323: {
    severity: "HIGH",
    message: "An alternate Telnet port (2323) accepts connections from this network.",
    action: "Disable Telnet on the router.",
  },
  7547: {
    severity: "MEDIUM",
    message: "CWMP/TR-069 (7547) accepts connections from this network.",
    action: "If your ISP does not need remote management, disable TR-069/CWMP in the router.",
  },
  8080: {
    severity: "LOW",
    message: "An alternate HTTP port (8080) accepts connections from this network.",
    action: "Check what the router serves on port 8080 and switch it off if it is a second admin page.",
  },
  8443: { severity: "INFO", message: "The router answers on an alternate HTTPS port (8443)." },
};

function portFinding({ port, service, reachable }: PortCheck): Finding {
  const advice = REACHABLE[port];
  if (reachable && advice) return { id: `port-${port}`, ...advice };
  return {
    id: `port-${port}`,
    severity: "INFO",
    message: reachable
      ? `Port ${port} (${service}) accepts connections from this network.`
      : `Port ${port} (${service}) is not reachable from this network.`,
  };
}

function upnpFindings(upnp: UpnpCheck): Finding[] {
  if (upnp.state === "refused") {
    return [{ id: "upnp", severity: "INFO", message: "UPnP: Unknown. A UPnP device answered that is not the default gateway, so it was not queried." }];
  }
  if (upnp.state === "unknown") {
    return [{ id: "upnp", severity: "INFO", message: "UPnP: Unknown. No gateway answered discovery; verify the setting in the router." }];
  }
  if (!upnp.mappingCount) {
    return [{
      id: "upnp",
      severity: "LOW",
      message: "UPnP is on, with no port mappings right now.",
      action: "Disable UPnP in the router if nothing needs it.",
    }];
  }
  const findings: Finding[] = [{
    id: "upnp",
    severity: "MEDIUM",
    message: `UPnP is on and holds ${upnp.mappingCount} port mapping${upnp.mappingCount === 1 ? "" : "s"} created by devices on your network.`,
    action: "Review the UPnP mappings in the router and disable UPnP if nothing needs it.",
  }];
  if (upnp.sensitiveCount) {
    findings.push({
      id: "upnp-sensitive",
      severity: "HIGH",
      message: `${upnp.sensitiveCount} UPnP mapping${upnp.sensitiveCount === 1 ? " forwards" : "s forward"} a remote-access port (FTP, SSH, Telnet, SMB, RDP or VNC) to a device on your network.`,
      action: "Remove UPnP mappings for remote-access ports unless you created them on purpose.",
    });
  }
  return findings;
}

const WIFI_FIX = "Switch Wi-Fi security to WPA3 Personal or WPA2/WPA3 Transitional.";

function wifiFindings(wifi: WifiCheck): Finding[] {
  const findings: Finding[] = [];
  const mode = wifi.securityMode ?? "unrecognised mode";
  if (wifi.security === "weak") {
    findings.push({ id: "wifi", severity: "HIGH", message: `Wi-Fi security is weak (${mode}).`, action: WIFI_FIX });
  } else if (wifi.security === "review") {
    findings.push({ id: "wifi", severity: "MEDIUM", message: `Wi-Fi security needs a look (${mode}).`, action: WIFI_FIX });
  } else if (wifi.security === "strong") {
    const note = mode === "WPA2" ? " WPA3 is stronger if your router and devices support it." : "";
    findings.push({ id: "wifi", severity: "INFO", message: `Wi-Fi security is strong (${mode}).${note}` });
  } else {
    findings.push({
      id: "wifi",
      severity: "INFO",
      message: "Wi-Fi security: Unknown. No Wi-Fi connection could be read; verify it in the router.",
    });
  }

  const n = wifi.sameChannelCount;
  const nearby = wifi.nearbyCount === null ? "" : ` (${wifi.nearbyCount} access points in range)`;
  if (n === null) {
    findings.push({
      id: "channel",
      severity: "INFO",
      message:
        "Channel congestion: Unknown. Your own access point could not be told apart from its neighbours. Operating systems hide Wi-Fi names from apps without Location permission.",
    });
  } else if (n === 0) {
    findings.push({ id: "channel", severity: "INFO", message: `No other access points share your Wi-Fi channel${nearby}.` });
  } else {
    findings.push({
      id: "channel",
      severity: "LOW",
      message: `${n} other access point${n === 1 ? " shares" : "s share"} your Wi-Fi channel${nearby}.`,
      action: "Set the Wi-Fi channel to Auto in the router.",
    });
  }

  if (wifi.band === "2.4 GHz") {
    const overlap = wifi.overlappingCount
      ? ` ${wifi.overlappingCount} access point${wifi.overlappingCount === 1 ? "" : "s"} nearby use overlapping channels.`
      : "";
    findings.push({
      id: "band",
      severity: wifi.overlappingCount ? "LOW" : "INFO",
      message: `This device is connected on the 2.4 GHz band, which is slower and more crowded.${overlap}`,
      ...(wifi.overlappingCount ? { action: "Connect on the 5 GHz or 6 GHz band where your router offers it." } : {}),
    });
  } else if (wifi.band) {
    findings.push({ id: "band", severity: "INFO", message: `This device is connected on the ${wifi.band} band.` });
  }
  return findings;
}

function environmentFindings(environment: EnvironmentCheck, checks: Checks): Finding[] {
  const findings: Finding[] = [];

  if (checks.dns.status === "plaintext") {
    findings.push({
      id: "dns",
      severity: "MEDIUM",
      message: "DNS lookups are sent in plaintext, so your ISP can read which sites you look up.",
      action: "Enable encrypted DNS (DoH or DoT) on the router or your devices.",
    });
  } else if (checks.dns.status === "encrypted") {
    findings.push({ id: "dns", severity: "INFO", message: "DNS is encrypted (as you reported)." });
  } else {
    findings.push({
      id: "dns",
      severity: "INFO",
      message: "DNS: Unknown. Tell the audit whether your DNS is encrypted to include it in the score.",
    });
  }

  const resolver: Record<EnvironmentCheck["resolver"], string> = {
    gateway: "This device sends its DNS lookups to the router, which usually forwards them to your ISP's resolver. Whether that hop is encrypted depends on the router's DNS settings.",
    private: "This device sends its DNS lookups to another device on your network (for example a local filter or resolver).",
    local: "This device sends its DNS lookups to a resolver running on the device itself (for example a VPN or encrypted-DNS app).",
    public: `This device sends its DNS lookups straight to ${environment.resolverProvider ?? "a public resolver"} rather than to the router. Unless they are encrypted, your ISP can still read them in transit.`,
    unknown: "DNS resolver: Unknown. No resolver configuration could be read from this device.",
  };
  findings.push({ id: "resolver", severity: "INFO", message: resolver[environment.resolver] });

  if (environment.globalIpv6) {
    findings.push({
      id: "ipv6",
      severity: "INFO",
      message: "This device has a global IPv6 address. IPv6 devices are not hidden behind NAT, so they rely on the router's IPv6 firewall; verify it is switched on.",
    });
  } else if (environment.globalIpv6 === false) {
    findings.push({ id: "ipv6", severity: "INFO", message: "This device has no global IPv6 address." });
  }
  return findings;
}

export function buildFindings(checks: Checks): Finding[] {
  return [
    ...checks.ports.map(portFinding),
    ...upnpFindings(checks.upnp),
    ...wifiFindings(checks.wifi),
    ...environmentFindings(checks.environment, checks),
    {
      id: "wan",
      severity: "INFO",
      message: "WAN exposure was not tested. Every check here was made from inside your network.",
    },
  ];
}

export const SEVERITY_ORDER: Severity[] = ["HIGH", "MEDIUM", "LOW", "INFO"];

/** At most three unique, non-INFO actions, most severe first. */
export function topFixes(findings: Finding[]): string[] {
  const actions = findings
    .filter((f) => f.severity !== "INFO" && f.action)
    .sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity))
    .map((f) => f.action as string);
  return [...new Set(actions)].slice(0, 3);
}
