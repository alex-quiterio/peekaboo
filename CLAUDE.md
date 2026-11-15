# Peekaboo

A read-only, privacy-conscious audit of a home network the user owns or administers. Rust, one binary (`peekaboo`) with a command line and a local web dashboard over the same use cases. Published to crates.io as `peekaboo-net`.

## Safety rules

- Inspect only the private default gateway that the operating system detects, plus this device's own network settings.
- Stop without scanning when the default route is a VPN or tunnel, or the gateway is not private IPv4.
- Never add a target, host, CIDR, public-IP, banner-grabbing, credential, brute-force, exploit, or remote-login option.
- TCP checks may only connect and immediately close, without sending application data. The only ports are those in `AUDITED_PORTS`.
- Device checks read this device's own settings and socket table with fixed, read-only commands. They never connect to this device's ports, and they hand over only booleans and counts: no process names, addresses or hardware addresses.
- The connection log check is the one other device read: a single fixed, read-only query of this device's own system log (macOS `/usr/bin/log show`, a constant predicate for the DHCP client's messages, a 30-minute window), with no input, no `sudo` and no debug or info levels. The adapter keeps only the lines about the default interface the operating system reports, and reduces them to counts and seconds (DHCP requests that got no answer, and the longest time without an address) before anything leaves it. No log line, IP address, hardware address, network name, interface name or user name is ever printed, saved or kept. The result is never scored and stays out of `top_fixes`, and a log that cannot be read is "Unknown".
- Wi-Fi speed is the link rate, signal and channel width this device's own radio reports. Never run a speed test or send traffic to measure throughput. Speed advice is never scored and stays out of `top_fixes`.
- The ISP delay check is on by default (the CLI passes `true` unless `--no-isp-latency` is given; the dashboard switch starts On) and can be switched off. It is the only thing that may send packets past the gateway, and only when the caller passes exactly `true`. It sends hop-limited packets one hop at a time, never beyond `MAX_LATENCY_HOPS`, and stops when the first hop is not the audited gateway or as soon as a non-private hop answers. The direction address is a fixed constant, never input. Hop addresses are used only to tell private from non-private and are never printed or saved; only milliseconds and a hop count are kept. Distance is only ever stated as an upper limit ("no more than about N km of cable"), never as an estimate or a place.
- Never look up the public IP, geolocate anything, or contact a third-party service.
- Internet-side insights (`src/domain/exposure.rs`) are inferred only from evidence the audit already holds: the range of the ISP's first router (only the yes/no `carrier_grade_nat` is kept, never the address), UPnP mappings, this device's IPv6 and firewall. They are never scored, never a test, and never worded as a measured exposure: say "most likely", "probably" or "if" where the evidence is indirect.
- UPnP code may send only an SSDP search, one GET of the gateway's device description, and `GetGenericPortMappingEntry`. It must never create or delete mappings, ask for the external address, use connection-control actions, or change router configuration. Every address it contacts must be the gateway.
- Never print or save SSIDs, BSSIDs, MAC addresses, device names, raw UPnP descriptions, raw system log lines, resolver addresses, or complete private IPs.
- Save only `sanitized-report.json`, `previous-sanitized-report.json` and `history.json`, plus named reports the user explicitly asks to keep (`--save`, `peekaboo reports save`, the dashboard's Save button) as one file each under `saved-reports/`. All of it lives in the data folder (`PEEKABOO_DATA_DIR` or the per-user default), never next to the binary or source. Nothing saves a named report on its own. A saved report is exactly the sanitized report, and its name is the only text the user adds: `parse_label` limits it to short plain text, and file names come only from `label_key`, never from the raw name. The store reads only files it could have written, and only ones shaped like a report. Comparing reads saved reports and sends nothing.
- `history.json` is the trend: after each audit one `HistoryPoint` is added (time, score, coverage, link rate, signal, delays, band: numbers only, never an address or name), capped at `MAX_HISTORY_POINTS`. Recording is best effort and never fails an audit. `peekaboo history clear` and the dashboard's Clear history button remove it.
- Never label a locally reachable router port as internet-exposed.
- Return "Unknown" when evidence is incomplete.
- The web server binds to 127.0.0.1 only and serves only the files compiled in from `src/apps/web/public` (the list in `src/apps/web/assets.rs`).

## Architecture

Dependencies point inward only: `apps -> infrastructure -> application -> domain`. `tests/architecture.rs` enforces it, and several of the safety rules above. `clippy.toml` plus the `deny` in `src/lib.rs` make `cargo clippy` fail on any disk, network, process, environment or clock use outside `infrastructure` and `apps`; CI runs it before the tests.

- `src/domain` holds the model and every rule (gateway safety, evidence sanitizing, scoring, findings, speed advice, report, comparison, saved-report names, history points). No I/O. `ports.rs` declares the traits the outside world must implement.
- `src/application` holds the use cases: `RunAudit`, `SavedReports`, `History`, `ListDevices` and `WatchSession`. Depends on domain traits only.
- `src/infrastructure` holds the adapters (network, UPnP, Wi-Fi, this device, JSON files) and `composition.rs`, the one place they are wired together.
- `src/apps/cli` and `src/apps/web` are the two entry points. They do not import each other, and reach adapters only through `composition` (and `clock`). `src/apps/mod.rs` dispatches the command.
- `src/main.rs` is only the entry point; the crate is also a library (`peekaboo`) so tests can reach it.

Tests use fakes and never touch the network, except `tests/web.rs`, which starts the real binary on a loopback port and runs no audit.

Dashboard files live in `src/apps/web/public`, one CSS file per concern; colours and fonts come only from `tokens.css`. The one exception is `logo.svg`, an image that cannot read CSS variables, so its colours mirror the tokens.

The report JSON keeps the camelCase shape the earlier TypeScript version wrote, so old reports still load. New fields get serde defaults.

## Commands

- `cargo run -- scan [--dns encrypted|plaintext|unknown] [--no-isp-latency] [--save <name>]` runs one audit (`--dns` defaults to `unknown`). About 20 seconds.
- `cargo run -- watch ...` reruns the audit every 30 minutes and prints only sanitized changes.
- `cargo run -- web [--port N]` serves the dashboard at http://127.0.0.1:4173.
- `cargo run -- reports` lists saved reports; `reports save "Home"` keeps the latest audit; `reports compare "Office"` compares the latest audit with it, and `compare "Office" "Home"` compares two saved ones; `reports delete "Home"` removes one.
- `cargo run -- history [clear]` shows or clears the trend of past audits.
- `cargo clippy` checks that `domain` and `application` do no I/O. `cargo test` runs everything. `cargo build --release` builds the binary.

## Releasing

Bump `version` in `Cargo.toml`, commit, publish a GitHub release tagged `v<version>`. `.github/workflows/release.yml` tests and publishes to crates.io using the `CARGO_REGISTRY_TOKEN` secret.
