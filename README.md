<p align="center"><img src="src/apps/web/public/logo.svg" width="112" alt="Peekaboo: an eye peeking over a router"></p>

# Peekaboo

A read-only peek at what your home router and ISP can see. It checks your router from the inside, scores what it can measure, tells you the three most useful things to fix, and reports how fast your Wi-Fi link is and what would make it faster.

One binary, two ways to run it: a command line, and a local dashboard.

Run it only on a network you own or administer.

## Install

```sh
cargo install peekaboo-net        # installs the `peekaboo` command
```

or from a checkout: `cargo build --release`, then `target/release/peekaboo`. Needs Rust 1.85 or newer.

macOS is the best supported. Linux works (Wi-Fi details come from `nmcli` and `iw`) but has had less testing. Windows is not supported yet: the audit stops there, because it cannot read the default route to rule out a VPN.

## Use it

```sh
peekaboo web                          # dashboard at http://127.0.0.1:4173
peekaboo scan --dns unknown           # one audit in the terminal
peekaboo watch --dns unknown          # re-audit every 30 minutes, print only changes
peekaboo history                      # how score, Wi-Fi speed and delay have changed
```

There are three options:

- `--dns encrypted|plaintext|unknown`. The audit cannot safely see whether your DNS is encrypted, so you tell it.
- `--isp-latency` also times the delay to the first router on your ISP's side. Off by default, because it is the one check that sends anything past your router. The dashboard has a switch for it.
- `--save <name>` (scan only) keeps the audit under a name. See below.

An audit takes about 20 seconds. `peekaboo web --port 5000` changes the dashboard's port.

## Save and compare

Keep an audit under a name, then compare it with another network, for example your home Wi-Fi with your office Wi-Fi:

```sh
peekaboo scan --save "Amsterdam work"           # audit and keep it
peekaboo reports                                # list saved reports
peekaboo reports compare "Amsterdam work"       # latest audit vs a saved one
peekaboo reports compare "Amsterdam work" Home  # two saved reports
peekaboo reports save Home                      # keep the latest audit
peekaboo reports delete Home
```

The dashboard has the same in its "Saved reports" card. The comparison puts the two reports side by side, marks the better value on each measure (higher link rate, stronger signal, fewer crowded channels, lower delay and so on), and lists problems found on only one of them. Unknown values are never marked as better or worse.

Saved reports hold the same sanitized data as the report, so no network names or addresses, plus the name you chose. Saving under a name that exists replaces it.

## Trend history

Every audit adds one small point to a history: the score, link rate, signal, delays and the time. Run `peekaboo history` to see sparklines for each measure and the latest audits, or open the "Trend" card in the dashboard. Left running, `peekaboo watch` builds a picture of how your Wi-Fi and line behave through the day, which one audit cannot show.

```sh
peekaboo history          # sparklines and the latest audits
peekaboo history clear    # start again
```

A point holds numbers only: no network names or addresses. The last 500 are kept. Audits on different networks share one history, so clear it when you move.

## Where reports are kept

In a per-user folder: `~/Library/Application Support/peekaboo` on macOS, `$XDG_DATA_HOME/peekaboo` (or `~/.local/share/peekaboo`) on Linux. Set `PEEKABOO_DATA_DIR` to use another folder. It holds `sanitized-report.json`, `previous-sanitized-report.json`, `history.json`, and the reports you saved under `saved-reports/`. Nothing else is written.

## What it checks

| Check | How |
| --- | --- |
| Router services (FTP, SSH, Telnet, DNS, HTTP/S, SMB, TR-069) | Connects to 11 ports on the default gateway and closes at once. Sends no data. |
| UPnP | Reads the router's port mappings. Flags forwards to remote-access ports. Never changes anything. |
| Wi-Fi | Security mode, band, and how crowded your channel is. |
| Wi-Fi speed | The link rate, signal, Wi-Fi standard and channel width this device's radio reports, with tips to make the Wi-Fi faster. No speed test is run, so internet speed is not measured. Never scored. |
| Delay to your ISP (opt-in) | Sends a few empty packets with a hop limit so small that they expire at the first router past your own, and times the answers. Reports milliseconds, and the most cable there can be to that router (an upper limit from the speed of light, not an estimate). No address, no location, no lookup service. Never scored. |
| Internet side (inferred) | What can be said about exposure from outside, without testing from outside: whether your ISP puts you behind carrier-grade NAT or you are behind double NAT (needs `--isp-latency`), which ports UPnP forwards to the internet, and whether a device with a global IPv6 address is reachable. It never tests from outside and never looks up your public address; it tells you how to check for yourself. Never scored. |
| DNS | Encryption status as you report it, plus which resolver this device uses. |
| IPv6 | Whether this device has a global IPv6 address, and whether that address is built from its hardware address. |
| VPN or tunnel | Whether a tunnel is connected alongside your normal connection. If so, a reported "encrypted" DNS is treated as Unknown, because a tunnel can send lookups around encrypted DNS. |
| Device firewall | Whether this device's firewall and stealth mode are on (macOS), and how many of its ports accept connections from the network. The count is a lower bound. |
| Wi-Fi address | Whether this device shows the network a private (randomised) address or its real hardware address. |

The device checks read this device's own settings. They send nothing, and keep only yes/no answers and counts.

The score counts only checks that produced evidence. Coverage is reported next to it, so a high score on thin evidence is visible as such.

## What it does not do

- It never scans anything except your private default gateway. There is no option to give it a target. The opt-in delay check times one router past yours and connects to nothing.
- It stops without scanning if you are on a VPN, because the gateway would not be your router.
- It does not test the internet side of your router. A port that answers here is reachable from inside your network only. The "Internet side" findings are inferences from what it can see, and say so.
- It does not look up your public IP address or where your ISP is located.
- It stores no network names, MAC addresses, device names or full IP addresses.

## Development

```sh
cargo test    # unit tests, architecture rules, and the web server against the real binary
```

The code is layered `apps -> infrastructure -> application -> domain`, and `tests/architecture.rs` fails if a layer reaches the wrong way or a safety rule is broken. See `CLAUDE.md`.

### Releasing

Bump `version` in `Cargo.toml`, commit, then publish a GitHub release tagged with that version and a leading `v` (for example `v0.2.0`). The workflow in `.github/workflows/release.yml` runs the tests and publishes the crate to crates.io. It needs a crates.io API token stored as the repository secret `CARGO_REGISTRY_TOKEN`. Pre-releases are not published.

## Licence

MIT. See `LICENSE`.
