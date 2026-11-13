// CLI: keep audits under a name and compare them.
//   bun run cli:reports                              list saved reports
//   bun run cli:reports save "Home"                  keep the most recent audit as "Home"
//   bun run cli:reports compare "Home"               compare the most recent audit with "Home"
//   bun run cli:reports compare "Work" "Home"        compare two saved reports
//   bun run cli:reports delete "Home"                delete a saved report
import { SafetyStop } from "@domain/gateway.ts";
import { createAudit } from "@infrastructure/composition.ts";
import { formatComparison, formatSavedList, stopSafely } from "./format.ts";

const USAGE = 'Usage: cli:reports [save <name> | compare <name> [<other>] | delete <name>]';

try {
  const { savedReports } = createAudit();
  const [command, ...names] = Bun.argv.slice(2);
  if (names.some((name) => name.startsWith("-"))) throw new SafetyStop(USAGE);

  if (command === undefined && names.length === 0) {
    console.log(formatSavedList(await savedReports.list()));
  } else if (command === "save" && names.length === 1) {
    console.log(`Saved the most recent audit as "${(await savedReports.saveCurrent(names[0])).label}".`);
  } else if (command === "delete" && names.length === 1) {
    await savedReports.remove(names[0]);
    console.log(`Deleted "${names[0]}".`);
  } else if (command === "compare" && (names.length === 1 || names.length === 2)) {
    // One name: the most recent audit against it. Two names: the two saved reports.
    const [first, second] = names;
    console.log(formatComparison(await (second === undefined ? savedReports.compare(undefined, first) : savedReports.compare(first, second))));
  } else {
    throw new SafetyStop(USAGE);
  }
} catch (error) {
  stopSafely(error);
}
