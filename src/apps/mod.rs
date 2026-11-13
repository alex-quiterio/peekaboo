//! The entry points: the command line and the local dashboard. They do not import each other;
//! only this module knows both.
pub mod cli;
pub mod web;

const HELP: &str = "\
Peekaboo: a read-only peek at what your home router and ISP can see.
Run it only on a network you own or administer.

USAGE
  peekaboo scan [--dns encrypted|plaintext|unknown] [--isp-latency] [--save <name>]
      One audit. About 20 seconds.
  peekaboo watch [--dns ...] [--isp-latency]
      Re-audit every 30 minutes and print only what changed.
  peekaboo reports [save <name> | compare <name> [<other>] | delete <name>]
      List, keep, compare or delete saved reports.
  peekaboo web [--port <number>]
      Serve the dashboard at http://127.0.0.1:4173 (this computer only).

Reports are kept in a per-user folder; set PEEKABOO_DATA_DIR to choose another.";

/// Runs the command in `args` (the program name already removed) and returns the process exit code.
pub fn run(args: Vec<String>) -> i32 {
    let (command, rest) = match args.split_first() {
        Some((command, rest)) => (command.as_str(), rest),
        None => ("--help", &[][..]),
    };
    match command {
        "scan" => cli::scan(rest),
        "watch" => cli::watch(rest),
        "reports" => cli::reports(rest),
        "web" => web::serve(rest),
        "-h" | "--help" | "help" => {
            println!("{HELP}");
            0
        }
        "-V" | "--version" => {
            println!("peekaboo {}", env!("CARGO_PKG_VERSION"));
            0
        }
        _ => {
            eprintln!("Unknown command. Run `peekaboo --help`.");
            1
        }
    }
}
