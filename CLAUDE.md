# isp-visibility-checker

A read-only, privacy-conscious audit of a home network the user owns or administers. TypeScript on Bun, with a CLI and a local web dashboard over the same use cases.

## Safety rules

- Inspect only the private default gateway that the operating system detects, plus this device's own network settings.
- Stop without scanning when the default route is a VPN or tunnel, or the gateway is not private IPv4.
- Never add a target, host, CIDR, public-IP, banner-grabbing, credential, brute-force, exploit, or remote-login option.
- TCP checks may only connect and immediately close, without sending application data. The only ports are those in `AUDITED_PORTS`.
- UPnP code may call only `getGateway()` and `getMappings()`. It must never create or delete mappings, call external-IP or connection-control methods, or change router configuration.
- Never print or save SSIDs, BSSIDs, MAC addresses, device names, raw UPnP descriptions, resolver addresses, or complete private IPs.
- Save only `sanitized-report.json` and `previous-sanitized-report.json`.
- Never label a locally reachable router port as internet-exposed.
- Return "Unknown" when evidence is incomplete.
- The web server binds to 127.0.0.1 only and serves only the files under `src/apps/web/public`.

## Architecture

Dependencies point inward only: `apps -> infrastructure -> application -> domain`. `bun run lint` enforces it.

- `src/domain` holds the model and every rule (gateway safety, evidence sanitizing, scoring, findings, report). No I/O. `ports.ts` declares the interfaces the outside world must implement.
- `src/application` holds the use cases: `RunAudit` and `WatchSession`. Depends on domain interfaces only.
- `src/infrastructure` holds the adapters (network, OS, JSON files) and `composition.ts`, the one place they are wired together.
- `src/apps/cli` and `src/apps/web` are the two entry points. They do not import each other.

Import across folders with the aliases `@domain/*`, `@application/*`, `@infrastructure/*`, `@apps/*`. Relative imports are for the same folder only.

Dashboard CSS lives in `src/apps/web/public/styles`, one file per concern; colours and fonts come only from `tokens.css`.

## Commands

- `bun run cli:scan --dns encrypted|plaintext|unknown` runs one audit (`--dns` defaults to `unknown`). About 20 seconds.
- `bun run cli:watch --dns ...` reruns the audit every 30 minutes and prints only sanitized changes.
- `bun run web:start` serves the dashboard at http://127.0.0.1:4173 (`web:dev` restarts on change).
- `bun run check` runs typecheck, lint and tests. Tests use fakes and never touch the network.
