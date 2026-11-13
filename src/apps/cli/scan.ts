// CLI: one audit. Usage: bun scan [--dns encrypted|plaintext|unknown] [--isp-latency] [--save <name>]
import { createAudit } from "@infrastructure/composition.ts";
import { optionsFromArgs, formatReport, stopSafely } from "./format.ts";

try {
  const { runAudit, savedReports } = createAudit();
  const { dns, ispLatency, save } = optionsFromArgs(Bun.argv.slice(2));
  console.log(formatReport(await runAudit.execute(dns, { ispLatency })));
  if (save !== null) console.log(`Saved as "${(await savedReports.saveCurrent(save)).label}"`);
} catch (error) {
  stopSafely(error);
}
