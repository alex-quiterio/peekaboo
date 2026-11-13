// The audit's one target: the private default gateway. These rules decide what may be scanned and shown.

/** An intentional refusal to scan, with a message that is safe to show. */
export class SafetyStop extends Error {}

export const TARGET_PLACEHOLDER = "<private-gateway>";

/** What the operating system reports about the default route, unvalidated. */
export interface DefaultRoute {
  address: string | null;
  interfaceName: string | null;
}

/** True only for RFC 1918 IPv4 addresses. */
export function isPrivateIPv4(address: string): boolean {
  const match = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(address);
  if (!match) return false;
  const octets = match.slice(1).map(Number);
  if (octets.some((o) => o > 255)) return false;
  const [a, b] = octets as [number, number, number, number];
  return a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168);
}

/** VPN and tunnel interfaces. Their "gateway" is the VPN provider's, not the home router. */
export function isTunnelInterface(name: string): boolean {
  return /^(utun|tun|tap|wg|ppp|ipsec|gpd|tailscale|zt|nordlynx|proton)/i.test(name);
}

/** Returns the gateway address if it may be scanned; otherwise stops the audit. */
export function requireHomeGateway(route: DefaultRoute): string {
  if (route.interfaceName && isTunnelInterface(route.interfaceName)) {
    throw new SafetyStop(
      "The default route goes through a VPN or tunnel, so its gateway is not your home router. Nothing was scanned. Disconnect the VPN and run the audit again.",
    );
  }
  if (!route.address || !isPrivateIPv4(route.address)) {
    throw new SafetyStop("The default gateway is not a private IPv4 address, so nothing was scanned.");
  }
  return route.address;
}

/** Replaces the final octet of every IPv4 address in the text with "x". */
export function redactIPv4(text: string): string {
  return text.replace(/\b(\d{1,3}\.\d{1,3}\.\d{1,3})\.\d{1,3}\b/g, "$1.x");
}
