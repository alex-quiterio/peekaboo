// The device list: what else is on the home network. Built on request for the dashboard and never
// part of a report, so nothing here is sanitized. It must not be saved, logged or printed.
import { isPrivateIPv4 } from "./gateway.ts";

/** One row of this device's neighbour table, plus the name the gateway gave for it, if any. */
export interface NeighbourObservation {
  address: string;
  hardwareAddress: string;
  name: string | null;
}

/** This device's own address on the default interface. */
export interface SelfObservation {
  address: string;
  hardwareAddress: string;
}

export interface NetworkDevice {
  address: string;
  name: string | null;
  hardwareAddress: string;
  role: "router" | "this-device" | "other";
  /** The device shows a private (randomised) hardware address, as phones and laptops do by default. */
  randomisedAddress: boolean;
}

export interface DeviceList {
  listedAt: string;
  devices: NetworkDevice[];
}

const network = (address: string) => address.slice(0, address.lastIndexOf("."));
const host = (address: string) => Number(address.slice(address.lastIndexOf(".") + 1));

/**
 * The only addresses discovery may touch: the 254 hosts of this device's own /24, and only when that is
 * the gateway's network too. Anything else yields nothing, so nothing is sent.
 */
export function sweepTargets(own: string, gateway: string): string[] {
  if (!isPrivateIPv4(own) || !isPrivateIPv4(gateway) || network(own) !== network(gateway)) return [];
  return Array.from({ length: 254 }, (_, i) => `${network(own)}.${i + 1}`).filter((address) => address !== own);
}

/** Lower-case, zero-padded "aa:bb:cc:dd:ee:ff"; null for anything that is not one real device's address. */
export function normaliseHardwareAddress(raw: string): string | null {
  const octets = raw.trim().toLowerCase().split(/[:-]/);
  if (octets.length !== 6 || octets.some((o) => !/^[0-9a-f]{1,2}$/.test(o))) return null;
  const address = octets.map((o) => o.padStart(2, "0")).join(":");
  if (address === "00:00:00:00:00:00") return null;
  // The lowest bit of the first octet marks broadcast and multicast groups, not devices.
  return parseInt(address.slice(0, 2), 16) & 1 ? null : address;
}

/** True when the locally-administered bit is set, which is how operating systems mark a randomised address. */
export function isRandomisedHardwareAddress(raw: string): boolean | null {
  const address = normaliseHardwareAddress(raw);
  return address === null ? null : (parseInt(address.slice(0, 2), 16) & 2) === 2;
}

export function deviceListFrom(
  neighbours: NeighbourObservation[],
  gateway: string,
  self: SelfObservation | null,
  listedAt: Date,
): DeviceList {
  const devices = new Map<string, NetworkDevice>();
  const add = (observation: NeighbourObservation, role: NetworkDevice["role"]) => {
    const hardwareAddress = normaliseHardwareAddress(observation.hardwareAddress);
    const { address } = observation;
    if (!hardwareAddress || !isPrivateIPv4(address) || network(address) !== network(gateway)) return;
    devices.set(address, {
      address,
      name: observation.name?.trim() || null,
      hardwareAddress,
      role,
      randomisedAddress: isRandomisedHardwareAddress(hardwareAddress) === true,
    });
  };
  for (const neighbour of neighbours) add(neighbour, neighbour.address === gateway ? "router" : "other");
  if (self) add({ ...self, name: null }, "this-device");
  return {
    listedAt: listedAt.toISOString(),
    devices: [...devices.values()].sort((a, b) => host(a.address) - host(b.address)),
  };
}
