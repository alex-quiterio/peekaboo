// CLI: rerun the audit every 30 minutes. Prints a baseline, then only changes. Control-C to stop.
import { WATCH_INTERVAL_MS, WatchSession } from "@application/watch-session.ts";
import { createAudit } from "@infrastructure/composition.ts";
import { optionsFromArgs, formatReport, stopSafely } from "./format.ts";

try {
  const { dns, ispLatency } = optionsFromArgs(Bun.argv.slice(2));
  const { runAudit } = createAudit();
  const session = new WatchSession();

  const tick = async () => {
    try {
      const report = await runAudit.execute(dns, { ispLatency });
      const event = session.observe(report);
      if (event?.kind === "baseline") {
        console.log(formatReport(report));
        console.log(`\nWatching every ${WATCH_INTERVAL_MS / 60000} minutes. Quiet unless something changes.`);
      } else if (event) {
        console.log(`\n[${new Date(event.at).toLocaleString()}] Network changed:`);
        for (const line of event.lines) console.log(`  ${line}`);
      }
    } catch (error) {
      stopSafely(error);
      process.exitCode = 0; // keep watching; the next run may succeed
    }
  };

  await tick();
  setInterval(tick, WATCH_INTERVAL_MS);
} catch (error) {
  stopSafely(error);
}
