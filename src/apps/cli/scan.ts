// CLI: one audit. Usage: bun scan [--dns encrypted|plaintext|unknown]
import { createAudit } from "@infrastructure/composition.ts";
import { dnsFromArgs, formatReport, stopSafely } from "./format.ts";

try {
  const { runAudit } = createAudit();
  console.log(formatReport(await runAudit.execute(dnsFromArgs(Bun.argv.slice(2)))));
} catch (error) {
  stopSafely(error);
}
