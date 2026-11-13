# isp-visibility-checker

A read-only, privacy-conscious audit of a home network the user owns or administers. TypeScript on Bun, with a CLI and a local web dashboard over the same use cases.

## Safety rules

- Inspect only the private default gateway that the operating system detects, plus this device's own network settings.
- Stop without scanning when the default route is a VPN or tunnel, or the gateway is not private IPv4.
- Never add a target, host, CIDR, public-IP, banner-grabbing, credential, brute-force, exploit, or remote-login option.
- TCP checks may only connect and immediately close, without sending application data. The only ports are those in `AUDITED_PORTS`.
- Device checks read this device's own settings and socket table with fixed, read-only commands. They never connect to this device's ports, and they hand over only booleans and counts: no process names, addresses or hardware addresses.
- Wi-Fi speed is the link rate, signal and channel width this device's own radio reports. Never run a speed test or send traffic to measure throughput. Speed advice is never scored and stays out of `topFixes`.
- The opt-in ISP delay check (`--isp-latency`, the dashboard checkbox) is the only thing that may send packets past the gateway, and only when the caller passes exactly `true`. It sends hop-limited packets one hop at a time, never beyond `MAX_LATENCY_HOPS`, and stops when the first hop is not the audited gateway or as soon as a non-private hop answers. The direction address is a fixed constant, never input. Hop addresses are used only to tell private from non-private and are never printed or saved; only milliseconds and a hop count are kept. Distance is only ever stated as an upper limit ("no more than about N km of cable"), never as an estimate or a place.
- Never look up the public IP, geolocate anything, or contact a third-party service.
- UPnP code may call only `getGateway()` and `getMappings()`. It must never create or delete mappings, call external-IP or connection-control methods, or change router configuration.
- Never print or save SSIDs, BSSIDs, MAC addresses, device names, raw UPnP descriptions, resolver addresses, or complete private IPs.
- Save only `sanitized-report.json` and `previous-sanitized-report.json`, plus named reports the user explicitly asks to keep (`--save`, `cli:reports save`, the dashboard's Save button) as one file each under `saved-reports/`. Nothing saves a named report on its own. A saved report is exactly the sanitized report, and its name is the only text the user adds: `parseLabel` limits it to short plain text, and file names come only from `labelKey`, never from the raw name. The store reads only files it could have written, and only ones shaped like a report. Comparing reads saved reports and sends nothing.
- Never label a locally reachable router port as internet-exposed.
- Return "Unknown" when evidence is incomplete.
- The web server binds to 127.0.0.1 only and serves only the files under `src/apps/web/public`.

## Architecture

Dependencies point inward only: `apps -> infrastructure -> application -> domain`. `bun run lint` enforces it.

- `src/domain` holds the model and every rule (gateway safety, evidence sanitizing, scoring, findings, report). No I/O. `ports.ts` declares the interfaces the outside world must implement.
- `src/application` holds the use cases: `RunAudit` and `WatchSession`. Depends on domain interfaces only.
- `src/infrastructure` holds the adapters (network, this device, JSON files) and `composition.ts`, the one place they are wired together.
- `src/apps/cli` and `src/apps/web` are the two entry points. They do not import each other.

Import across folders with the aliases `@domain/*`, `@application/*`, `@infrastructure/*`, `@apps/*`. Relative imports are for the same folder only.

Dashboard CSS lives in `src/apps/web/public/styles`, one file per concern; colours and fonts come only from `tokens.css`.

## Commands

- `bun run cli:scan --dns encrypted|plaintext|unknown [--isp-latency]` runs one audit (`--dns` defaults to `unknown`). About 20 seconds.
- `bun run cli:reports` lists saved reports; `cli:reports save "Home"` keeps the latest audit under a name; `cli:reports compare "Office"` compares the latest audit with it, and `compare "Office" "Home"` compares two saved ones; `cli:reports delete "Home"` removes one. `cli:scan --save "Home"` audits and saves in one step.
- `bun run cli:watch --dns ...` reruns the audit every 30 minutes and prints only sanitized changes.
- `bun run web:start` serves the dashboard at http://127.0.0.1:4173 (`web:dev` restarts on change).
- `bun run check` runs typecheck, lint and tests. Tests use fakes and never touch the network.
