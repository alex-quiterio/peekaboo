// CLI: one audit. Usage: bun scan [--dns encrypted|plaintext|unknown] [--isp-latency]
import { createAudit } from "@infrastructure/composition.ts";
import { optionsFromArgs, formatReport, stopSafely } from "./format.ts";

try {
  const { runAudit } = createAudit();
  const { dns, ispLatency } = optionsFromArgs(Bun.argv.slice(2));
  console.log(formatReport(await runAudit.execute(dns, { ispLatency })));
} catch (error) {
  stopSafely(error);
}
