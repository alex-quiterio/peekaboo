//! The command line: scan, watch and reports.
mod format;
mod style;

use crate::application::watch_session::{WatchKind, WatchSession, WATCH_INTERVAL_SECS};
use crate::application::run_audit::AuditOptions;
use crate::domain::gateway::SafetyStop;
use crate::infrastructure::composition::create_app;
use format::*;
use style::Style;
use std::thread;
use std::time::Duration;

const REPORTS_USAGE: &str = "Usage: peekaboo reports [save <name> | compare <name> [<other>] | delete <name>]";

fn finish(result: Result<(), SafetyStop>) -> i32 {
    match result {
        Ok(()) => 0,
        Err(error) => {
            stop_safely(&error);
            1
        }
    }
}

pub fn scan(args: &[String]) -> i32 {
    finish((|| {
        let options = options_from_args(args, true)?;
        let app = create_app();
        let report = app.run_audit.execute(Some(options.dns.as_str()), AuditOptions { isp_latency: options.isp_latency })?;
        println!("{}", format_report(&report, &Style::detect()));
        if let Some(name) = options.save {
            println!("Saved as \"{}\"", app.saved_reports.save_current(Some(&name))?.label);
        }
        Ok(())
    })())
}

pub fn watch(args: &[String]) -> i32 {
    let options = match options_from_args(args, false) {
        Ok(options) => options,
        Err(error) => return finish(Err(error)),
    };
    let app = create_app();
    let mut session = WatchSession::new();
    loop {
        match app.run_audit.execute(Some(options.dns.as_str()), AuditOptions { isp_latency: options.isp_latency }) {
            Ok(report) => match session.observe(&report) {
                Some(event) if event.kind == WatchKind::Baseline => {
                    println!("{}", format_report(&report, &Style::detect()));
                    println!("\nWatching every {} minutes. Quiet unless something changes.", WATCH_INTERVAL_SECS / 60);
                }
                Some(event) => {
                    println!("\n[{}] Network changed:", when(&event.at));
                    event.lines.iter().for_each(|line| println!("  {line}"));
                }
                None => {}
            },
            // Keep watching: the next run may succeed.
            Err(error) => stop_safely(&error),
        }
        thread::sleep(Duration::from_secs(WATCH_INTERVAL_SECS));
    }
}

pub fn history(args: &[String]) -> i32 {
    let usage = || SafetyStop::new("Usage: peekaboo history [clear]");
    finish((|| {
        let app = create_app();
        match args.first().map(String::as_str) {
            None if args.is_empty() => println!("{}", format_history(&app.history.list(), &Style::detect())),
            Some("clear") if args.len() == 1 => println!("{}", if app.history.clear() { "History cleared." } else { "There was no history to clear." }),
            _ => return Err(usage()),
        }
        Ok(())
    })())
}

pub fn reports(args: &[String]) -> i32 {
    finish((|| {
        let usage = || SafetyStop::new(REPORTS_USAGE);
        if args.iter().skip(1).any(|a| a.starts_with('-')) {
            return Err(usage());
        }
        let app = create_app();
        let saved = &app.saved_reports;
        let names: Vec<&str> = args.iter().skip(1).map(String::as_str).collect();
        match (args.first().map(String::as_str), names.as_slice()) {
            (None, []) => println!("{}", format_saved_list(&saved.list(), &Style::detect())),
            (Some("save"), [name]) => println!("Saved the most recent audit as \"{}\".", saved.save_current(Some(name))?.label),
            (Some("delete"), [name]) => {
                saved.remove(Some(name))?;
                println!("Deleted \"{name}\".");
            }
            // One name: the most recent audit against it. Two names: the two saved reports.
            (Some("compare"), [name]) => println!("{}", format_comparison(&saved.compare(None, Some(name))?, &Style::detect())),
            (Some("compare"), [first, second]) => println!("{}", format_comparison(&saved.compare(Some(first), Some(second))?, &Style::detect())),
            _ => return Err(usage()),
        }
        Ok(())
    })())
}
