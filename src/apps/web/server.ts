// Web app: local dashboard server. Binds to 127.0.0.1 only and accepts no scan target.
import path from "node:path";
import { WATCH_INTERVAL_MS, WatchSession, type WatchEvent } from "@application/watch-session.ts";
import { parseDns } from "@domain/evidence.ts";
import { SafetyStop } from "@domain/gateway.ts";
import type { DnsStatus, Report } from "@domain/model.ts";
import { createAudit } from "@infrastructure/composition.ts";

const PORT = Number(process.env.PORT) || 4173;
const MAX_EVENTS = 50;
const PUBLIC_DIR = path.resolve(import.meta.dir, "public");

/** The static files that may be served, listed once at startup. A request can only pick from this map. */
const assets = new Map<string, string>();
for await (const file of new Bun.Glob("**/*.{html,css,js}").scan(PUBLIC_DIR)) {
  assets.set(`/${file}`, path.join(PUBLIC_DIR, file));
}
assets.set("/", path.join(PUBLIC_DIR, "index.html"));

const { runAudit, listDevices, reports } = createAudit();

const watch = {
  session: null as WatchSession | null,
  dns: "unknown" as DnsStatus,
  timer: null as ReturnType<typeof setInterval> | null,
  nextRunAt: null as string | null,
  events: [] as WatchEvent[],
};

let running: Promise<Report> | null = null;
let lastError: string | null = null;

/** One audit at a time; concurrent callers share the run in flight. */
function scan(dns: DnsStatus): Promise<Report> {
  running ??= runAudit
    .execute(dns)
    .then((report) => {
      lastError = null;
      const event = watch.session?.observe(report);
      if (event) {
        watch.events.unshift(event);
        watch.events.length = Math.min(watch.events.length, MAX_EVENTS);
        console.log(`[watch] ${event.kind}: ${event.lines.join("; ")}`);
      }
      return report;
    })
    .catch((error: unknown) => {
      lastError =
        error instanceof SafetyStop ? error.message : "The audit stopped safely before finishing. Nothing was changed.";
      throw error;
    })
    .finally(() => {
      running = null;
    });
  return running;
}

function setWatch(enabled: boolean, dns: DnsStatus) {
  if (watch.timer) clearInterval(watch.timer);
  watch.timer = null;
  watch.session = null;
  watch.nextRunAt = null;
  if (!enabled) return;

  watch.dns = dns;
  watch.session = new WatchSession();
  const tick = () => {
    watch.nextRunAt = new Date(Date.now() + WATCH_INTERVAL_MS).toISOString();
    scan(watch.dns).catch(() => {});
  };
  watch.timer = setInterval(tick, WATCH_INTERVAL_MS);
  tick();
}

async function state() {
  return {
    report: await reports.latest(),
    scanning: running !== null,
    error: lastError,
    watch: {
      enabled: watch.session !== null,
      intervalMinutes: WATCH_INTERVAL_MS / 60000,
      nextRunAt: watch.nextRunAt,
      quietRuns: watch.session?.quietRuns ?? 0,
      events: watch.events,
    },
  };
}

/** Rejects requests that did not come from the dashboard itself (DNS rebinding, cross-site posts). */
function isTrusted(req: Request): boolean {
  const allowed = [`127.0.0.1:${PORT}`, `localhost:${PORT}`];
  if (!allowed.includes(req.headers.get("host") ?? "")) return false;
  if (req.method === "GET") return true;
  const origin = req.headers.get("origin");
  const sameOrigin = origin === null || allowed.some((host) => origin === `http://${host}`);
  return sameOrigin && (req.headers.get("content-type") ?? "").startsWith("application/json");
}

async function body(req: Request): Promise<Record<string, unknown>> {
  const parsed: unknown = await req.json().catch(() => ({}));
  return parsed && typeof parsed === "object" ? (parsed as Record<string, unknown>) : {};
}

const server = Bun.serve({
  hostname: "127.0.0.1",
  port: PORT,
  async fetch(req) {
    if (!isTrusted(req)) return new Response("Forbidden", { status: 403 });
    const { pathname } = new URL(req.url);
    const route = `${req.method} ${pathname}`;
    const asset = req.method === "GET" ? assets.get(pathname) : undefined;
    if (asset) return new Response(Bun.file(asset), { headers: { "cache-control": "no-store" } });

    try {
      if (route === "GET /api/state") return Response.json(await state());
      if (route === "POST /api/scan") {
        const dns = parseDns((await body(req)).dns);
        await scan(dns).catch(() => {});
        return Response.json(await state());
      }
      if (route === "POST /api/watch") {
        const input = await body(req);
        setWatch(input.enabled === true, parseDns(input.dns));
        return Response.json(await state());
      }
      // The device list goes to the page that asked and nowhere else: not into state, a file or the log.
      if (route === "POST /api/devices") {
        try {
          return Response.json(await listDevices.execute(), { headers: { "cache-control": "no-store" } });
        } catch (error) {
          if (error instanceof SafetyStop) throw error;
          return Response.json({ error: "The device list could not be read. Nothing was changed." }, { status: 500 });
        }
      }
      return new Response("Not found", { status: 404 });
    } catch (error) {
      const message = error instanceof SafetyStop ? error.message : "Request failed safely.";
      return Response.json({ error: message }, { status: 400 });
    }
  },
});

console.log("Home Network Privacy Check");
console.log(`Dashboard: http://127.0.0.1:${server.port}  (Control-C to stop)`);
