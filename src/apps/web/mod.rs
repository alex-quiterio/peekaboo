//! The local dashboard server. Binds to 127.0.0.1 only, accepts no scan target, and serves only the
//! files compiled in from `assets`.
mod assets;

use crate::application::run_audit::AuditOptions;
use crate::application::watch_session::{WatchEvent, WatchSession, WATCH_INTERVAL_SECS};
use crate::domain::evidence::parse_dns;
use crate::domain::gateway::SafetyStop;
use crate::domain::model::DnsStatus;
use crate::infrastructure::clock::iso_from_unix_millis;
use crate::infrastructure::composition::{create_app, App};
use serde_json::{json, Value};
use std::io::Read;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tiny_http::{Header, Method, Request, Response, Server};

const DEFAULT_PORT: u16 = 4173;
const MAX_EVENTS: usize = 50;
const MAX_BODY_BYTES: u64 = 64 * 1024;

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

struct WatchState {
    session: Option<WatchSession>,
    dns: DnsStatus,
    isp_latency: bool,
    next_run_at: Option<String>,
    events: Vec<WatchEvent>,
    /// Bumped whenever watch is switched, so an old timer thread knows to stop.
    generation: u64,
}

struct Shared {
    app: App,
    running: Mutex<bool>,
    finished: Condvar,
    last_error: Mutex<Option<String>>,
    watch: Mutex<WatchState>,
}

impl Shared {
    /// One audit at a time; concurrent callers share the run in flight.
    fn scan(self: &Arc<Self>, dns: DnsStatus, isp_latency: bool) {
        let mut running = lock(&self.running);
        if !*running {
            *running = true;
            let shared = Arc::clone(self);
            thread::spawn(move || shared.run_scan(dns, isp_latency));
        }
        while *running {
            running = self.finished.wait(running).unwrap_or_else(PoisonError::into_inner);
        }
    }

    fn run_scan(&self, dns: DnsStatus, isp_latency: bool) {
        let outcome = catch_unwind(AssertUnwindSafe(|| self.app.run_audit.execute(Some(dns.as_str()), AuditOptions { isp_latency })));
        match outcome {
            Ok(Ok(report)) => {
                *lock(&self.last_error) = None;
                let mut watch = lock(&self.watch);
                if let Some(event) = watch.session.as_mut().and_then(|s| s.observe(&report)) {
                    println!("[watch] {:?}: {}", event.kind, event.lines.join("; "));
                    watch.events.insert(0, event);
                    watch.events.truncate(MAX_EVENTS);
                }
            }
            Ok(Err(stop)) => *lock(&self.last_error) = Some(stop.0),
            Err(_) => *lock(&self.last_error) = Some("The audit stopped safely before finishing. Nothing was changed.".into()),
        }
        *lock(&self.running) = false;
        self.finished.notify_all();
    }

    fn set_watch(self: &Arc<Self>, enabled: bool, dns: DnsStatus, isp_latency: bool) {
        let generation = {
            let mut watch = lock(&self.watch);
            watch.generation += 1;
            watch.session = None;
            watch.next_run_at = None;
            if !enabled {
                return;
            }
            watch.dns = dns;
            watch.isp_latency = isp_latency;
            watch.session = Some(WatchSession::new());
            watch.generation
        };
        let shared = Arc::clone(self);
        thread::spawn(move || 'timer: loop {
            let (dns, isp_latency) = {
                let mut watch = lock(&shared.watch);
                if watch.generation != generation {
                    break;
                }
                let next = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_millis() as i64) + (WATCH_INTERVAL_SECS * 1000) as i64;
                watch.next_run_at = Some(iso_from_unix_millis(next));
                (watch.dns, watch.isp_latency)
            };
            shared.scan(dns, isp_latency);
            for _ in 0..WATCH_INTERVAL_SECS {
                thread::sleep(Duration::from_secs(1));
                if lock(&shared.watch).generation != generation {
                    break 'timer;
                }
            }
        });
    }

    fn state(&self) -> Value {
        let watch = lock(&self.watch);
        json!({
            "report": self.app.reports.latest(),
            "scanning": *lock(&self.running),
            "error": *lock(&self.last_error),
            "watch": {
                "enabled": watch.session.is_some(),
                "intervalMinutes": WATCH_INTERVAL_SECS / 60,
                "nextRunAt": watch.next_run_at,
                "quietRuns": watch.session.as_ref().map_or(0, |s| s.quiet_runs),
                "events": watch.events,
            },
        })
    }
}

/// Rejects requests that did not come from the dashboard itself (DNS rebinding, cross-site posts).
fn is_trusted(host: Option<&str>, is_get: bool, origin: Option<&str>, content_type: Option<&str>, port: u16) -> bool {
    let allowed = [format!("127.0.0.1:{port}"), format!("localhost:{port}")];
    if !host.is_some_and(|h| allowed.iter().any(|a| a == h)) {
        return false;
    }
    if is_get {
        return true;
    }
    let same_origin = origin.is_none_or(|o| allowed.iter().any(|a| o == format!("http://{a}")));
    same_origin && content_type.is_some_and(|c| c.starts_with("application/json"))
}

fn header_of<'a>(request: &'a Request, name: &'static str) -> Option<&'a str> {
    request.headers().iter().find(|h| h.field.equiv(name)).map(|h| h.value.as_str())
}

fn header(name: &str, value: &str) -> Header {
    Header::from_bytes(name.as_bytes(), value.as_bytes()).expect("static header")
}

fn respond(request: Request, status: u16, content_type: &str, body: String) {
    let response = Response::from_string(body)
        .with_status_code(status)
        .with_header(header("Content-Type", content_type))
        .with_header(header("Cache-Control", "no-store"))
        .with_header(header("X-Content-Type-Options", "nosniff"));
    let _ = request.respond(response);
}

fn respond_json(request: Request, status: u16, value: &Value) {
    respond(request, status, "application/json", value.to_string());
}

/// The request body as a JSON object; anything else is an empty one.
fn read_body(request: &mut Request) -> Value {
    let mut text = String::new();
    let _ = request.as_reader().take(MAX_BODY_BYTES).read_to_string(&mut text);
    serde_json::from_str(&text).ok().filter(Value::is_object).unwrap_or_else(|| json!({}))
}

/// A string field, an absent one, or a refusal for any other type.
fn text_field<'a>(input: &'a Value, key: &str) -> Result<Option<&'a str>, SafetyStop> {
    match input.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Ok(Some(s)),
        Some(_) => Err(SafetyStop::new(format!("{key} must be text."))),
    }
}

fn dns_field(input: &Value) -> Result<DnsStatus, SafetyStop> {
    parse_dns(text_field(input, "dns").map_err(|_| SafetyStop::new("--dns must be encrypted, plaintext, or unknown."))?)
}

fn handle(shared: &Arc<Shared>, mut request: Request, port: u16) {
    let is_get = *request.method() == Method::Get;
    let trusted = is_trusted(header_of(&request, "Host"), is_get, header_of(&request, "Origin"), header_of(&request, "Content-Type"), port);
    if !trusted {
        return respond(request, 403, "text/plain", "Forbidden".into());
    }
    let path = request.url().split('?').next().unwrap_or("").to_string();
    if is_get {
        if let Some((kind, content)) = assets::find(&path) {
            return respond(request, 200, kind, content.to_string());
        }
    }
    let route = format!("{} {path}", request.method());
    let input = if is_get { json!({}) } else { read_body(&mut request) };

    let result: Result<Value, SafetyStop> = (|| {
        Ok(match route.as_str() {
            "GET /api/state" => shared.state(),
            "GET /api/saved" => json!(shared.app.saved_reports.list()),
            "POST /api/scan" => {
                shared.scan(dns_field(&input)?, input.get("ispLatency") == Some(&Value::Bool(true)));
                shared.state()
            }
            "POST /api/watch" => {
                shared.set_watch(input.get("enabled") == Some(&Value::Bool(true)), dns_field(&input)?, input.get("ispLatency") == Some(&Value::Bool(true)));
                shared.state()
            }
            // The device list goes to the page that asked and nowhere else: not into state, a file or the log.
            "POST /api/devices" => json!(shared.app.list_devices.execute()?),
            // Saved reports change only when the page asks: nothing here saves on its own.
            "POST /api/saved" => {
                shared.app.saved_reports.save_current(text_field(&input, "label")?)?;
                json!(shared.app.saved_reports.list())
            }
            "POST /api/saved/delete" => {
                shared.app.saved_reports.remove(text_field(&input, "label")?)?;
                json!(shared.app.saved_reports.list())
            }
            "POST /api/compare" => json!(shared.app.saved_reports.compare(text_field(&input, "left")?, text_field(&input, "right")?)?),
            _ => return Err(SafetyStop::new("\u{0}not-found")),
        })
    })();
    match result {
        Ok(value) => respond_json(request, 200, &value),
        Err(stop) if stop.0 == "\u{0}not-found" => respond(request, 404, "text/plain", "Not found".into()),
        Err(stop) => respond_json(request, 400, &json!({ "error": stop.0 })),
    }
}

fn port_from(args: &[String]) -> Result<u16, SafetyStop> {
    let refuse = || SafetyStop::new("The only option is --port <number>.");
    let mut port = std::env::var("PORT").ok().and_then(|p| p.parse().ok()).filter(|p| *p > 0).unwrap_or(DEFAULT_PORT);
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        let value = match arg.split_once('=') {
            Some(("--port", value)) => value.to_string(),
            None if arg == "--port" => args.next().cloned().ok_or_else(refuse)?,
            _ => return Err(refuse()),
        };
        port = value.parse().ok().filter(|p| *p > 0).ok_or_else(refuse)?;
    }
    Ok(port)
}

pub fn serve(args: &[String]) -> i32 {
    let port = match port_from(args) {
        Ok(port) => port,
        Err(stop) => {
            eprintln!("{stop}");
            return 1;
        }
    };
    let server = match Server::http(("127.0.0.1", port)) {
        Ok(server) => server,
        Err(error) => {
            eprintln!("Could not start the dashboard on 127.0.0.1:{port}: {error}");
            return 1;
        }
    };
    let shared = Arc::new(Shared {
        app: create_app(),
        running: Mutex::new(false),
        finished: Condvar::new(),
        last_error: Mutex::new(None),
        watch: Mutex::new(WatchState { session: None, dns: DnsStatus::Unknown, isp_latency: false, next_run_at: None, events: vec![], generation: 0 }),
    });
    println!("Peekaboo: Home Network Privacy Check");
    println!("Dashboard: http://127.0.0.1:{port}  (Control-C to stop)");
    println!("Reports are kept in {}", shared.app.data_dir.display());
    for request in server.incoming_requests() {
        let shared = Arc::clone(&shared);
        thread::spawn(move || handle(&shared, request, port));
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_requests_from_the_dashboard_itself_are_trusted() {
        let t = |host, get, origin, kind| is_trusted(host, get, origin, kind, 4173);
        assert!(t(Some("127.0.0.1:4173"), true, None, None));
        assert!(t(Some("localhost:4173"), true, None, None));
        assert!(t(Some("127.0.0.1:4173"), false, None, Some("application/json")));
        assert!(t(Some("127.0.0.1:4173"), false, Some("http://localhost:4173"), Some("application/json; charset=utf-8")));
        // DNS rebinding: the right address under somebody else's name.
        assert!(!t(Some("evil.example"), true, None, None));
        assert!(!t(Some("evil.example:4173"), true, None, None));
        assert!(!t(None, true, None, None));
        // Cross-site and form posts.
        assert!(!t(Some("127.0.0.1:4173"), false, Some("http://evil.example"), Some("application/json")));
        assert!(!t(Some("127.0.0.1:4173"), false, None, Some("text/plain")));
        assert!(!t(Some("127.0.0.1:4173"), false, None, None));
    }

    #[test]
    fn the_port_comes_from_the_flag_and_nothing_else_is_accepted() {
        let args = |list: &[&str]| list.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(port_from(&args(&["--port", "5000"])).unwrap(), 5000);
        assert_eq!(port_from(&args(&["--port=5001"])).unwrap(), 5001);
        for bad in [&["--port"][..], &["--port", "0"], &["--port", "x"], &["--host", "0.0.0.0"], &["0.0.0.0:80"]] {
            assert!(port_from(&args(bad)).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn text_fields_accept_text_or_nothing() {
        let input = json!({"a": "x", "b": null, "c": 5});
        assert_eq!(text_field(&input, "a").unwrap(), Some("x"));
        assert_eq!(text_field(&input, "b").unwrap(), None);
        assert_eq!(text_field(&input, "missing").unwrap(), None);
        assert!(text_field(&input, "c").is_err());
    }
}
