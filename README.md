# isp-visibility-checker

A read-only privacy audit for a home network you own or administer. It checks your router from the inside, scores what it can measure, and tells you the three most useful things to fix. It also reports how fast your Wi-Fi link is and what would make it faster.

Run it only on your own network.

## Use it

```sh
bun install
bun run web:start                 # dashboard at http://127.0.0.1:4173
bun run cli:scan --dns unknown    # one audit in the terminal
bun run cli:watch --dns unknown   # re-audit every 30 minutes, print only changes
```

There are two options:

- `--dns encrypted|plaintext|unknown`. The audit cannot safely see whether your DNS is encrypted, so you tell it.
- `--isp-latency` also times the delay to the first router on your ISP's side. Off by default, because it is the one check that sends anything past your router. The dashboard has a checkbox for it.

An audit takes about 20 seconds.

## What it checks

| Check | How |
| --- | --- |
| Router services (FTP, SSH, Telnet, DNS, HTTP/S, SMB, TR-069) | Connects to 11 ports on the default gateway and closes at once. Sends no data. |
| UPnP | Reads the router's port mappings. Flags forwards to remote-access ports. Never changes anything. |
| Wi-Fi | Security mode, band, and how crowded your channel is. |
| Wi-Fi speed | The link rate, signal, Wi-Fi standard and channel width this device's radio reports, with tips to make the Wi-Fi faster. No speed test is run, so internet speed is not measured. Never scored. |
| Delay to your ISP (opt-in) | Sends a few empty packets with a hop limit so small that they expire at the first router past your own, and times the answers. Reports milliseconds, and the most cable there can be to that router (an upper limit from the speed of light, not an estimate). No address, no location, no lookup service. Never scored. |
| DNS | Encryption status as you report it, plus which resolver this device uses. |
| IPv6 | Whether this device has a global IPv6 address, and whether that address is built from its hardware address. |
| VPN or tunnel | Whether a tunnel is connected alongside your normal connection. If so, a reported "encrypted" DNS is treated as Unknown, because a tunnel can send lookups around encrypted DNS. |
| Device firewall | Whether this device's firewall and stealth mode are on (macOS), and how many of its ports accept connections from the network. The count is a lower bound. |
| Wi-Fi address | Whether this device shows the network a private (randomised) address or its real hardware address. |

The device checks read this device's own settings. They send nothing, and keep only yes/no answers and counts.

The score counts only checks that produced evidence. Coverage is reported next to it, so a high score on thin evidence is visible as such.

## What it does not do

- It never scans anything except your private default gateway. There is no option to give it a target. The opt-in delay check times one router past yours and connects to nothing.
- It does not look up your public IP address or where your ISP is located.
- It stops without scanning if you are on a VPN, because the gateway would not be your router.
- It does not test the internet side of your router. A port that answers here is reachable from inside your network only.
- It stores no network names, MAC addresses, device names or full IP addresses. The only files written are `sanitized-report.json` and `previous-sanitized-report.json`.

## Development

```sh
bun run check   # typecheck, lint (layer rules), tests
```

The code is layered `apps -> infrastructure -> application -> domain`; see `CLAUDE.md`.

## Licence

MIT. See `LICENSE`.
