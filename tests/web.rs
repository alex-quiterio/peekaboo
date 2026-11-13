//! Starts the real binary and talks to its dashboard over a socket. No audit is run, so nothing touches the
//! network and nothing but the temporary data folder is written.
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};

struct Dashboard {
    child: Child,
    port: u16,
    dir: PathBuf,
}

impl Drop for Dashboard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn start(name: &str) -> Dashboard {
    let port = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let dir = std::env::temp_dir().join(format!("peekaboo-web-{name}-{}", std::process::id()));
    let child = Command::new(env!("CARGO_BIN_EXE_peekaboo"))
        .args(["web", "--port", &port.to_string()])
        .env("PEEKABOO_DATA_DIR", &dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let dashboard = Dashboard { child, port, dir };
    let deadline = Instant::now() + Duration::from_secs(10);
    while TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(Instant::now() < deadline, "the dashboard did not start");
        sleep(Duration::from_millis(50));
    }
    dashboard
}

struct Reply {
    status: u16,
    headers: String,
    body: String,
}

fn send(port: u16, raw: &str) -> Reply {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    stream.write_all(raw.as_bytes()).unwrap();
    let mut text = String::new();
    let _ = stream.read_to_string(&mut text);
    let (headers, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    Reply { status: headers.split_whitespace().nth(1).and_then(|s| s.parse().ok()).unwrap_or(0), headers: headers.to_lowercase(), body: body.to_string() }
}

fn get(d: &Dashboard, path: &str, host: &str) -> Reply {
    send(d.port, &format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"))
}

fn post(d: &Dashboard, path: &str, body: &str, extra: &str) -> Reply {
    send(d.port, &format!("POST {path} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n{extra}Content-Length: {}\r\nConnection: close\r\n\r\n{body}", d.port, body.len()))
}

fn json_post(d: &Dashboard, path: &str, body: &str) -> Reply {
    post(d, path, body, "Content-Type: application/json\r\n")
}

fn host(d: &Dashboard) -> String {
    format!("127.0.0.1:{}", d.port)
}

#[test]
fn serves_the_dashboard_and_nothing_else() {
    let d = start("serve");
    let page = get(&d, "/", &host(&d));
    assert_eq!(page.status, 200);
    assert!(page.headers.contains("text/html") && page.headers.contains("no-store"));
    assert!(page.body.contains("<title>Peekaboo"));
    for path in ["/styles/tokens.css", "/styles/saved.css", "/scripts/dashboard.js"] {
        assert_eq!(get(&d, path, &host(&d)).status, 200, "{path}");
    }
    assert!(get(&d, "/styles/tokens.css", &host(&d)).headers.contains("text/css"));
    for path in ["/Cargo.toml", "/src/main.rs", "/../Cargo.toml", "/%2e%2e/Cargo.toml", "/styles/", "/sanitized-report.json"] {
        assert_eq!(get(&d, path, &host(&d)).status, 404, "{path}");
    }
}

#[test]
fn reports_an_empty_state_before_any_audit() {
    let d = start("state");
    let state: serde_json::Value = serde_json::from_str(&get(&d, "/api/state", &host(&d)).body).unwrap();
    assert_eq!((state["scanning"].as_bool(), state["report"].is_null(), state["watch"]["enabled"].as_bool()), (Some(false), true, Some(false)));
    assert_eq!(get(&d, "/api/saved", &host(&d)).body, "[]");
    assert_eq!(get(&d, "/api/history", &host(&d)).body, "[]");
    assert_eq!(json_post(&d, "/api/history/clear", "{}").body, "[]");
}

#[test]
fn refuses_requests_that_did_not_come_from_the_dashboard() {
    let d = start("trust");
    assert_eq!(get(&d, "/api/state", "evil.example").status, 403);
    assert_eq!(get(&d, "/", &format!("evil.example:{}", d.port)).status, 403);
    assert_eq!(post(&d, "/api/saved", r#"{"label":"x"}"#, "").status, 403, "no JSON content type");
    assert_eq!(post(&d, "/api/saved", r#"{"label":"x"}"#, "Content-Type: application/json\r\nOrigin: http://evil.example\r\n").status, 403);
    assert_eq!(post(&d, "/api/scan", "{}", "Content-Type: text/plain\r\n").status, 403);
    assert_eq!(get(&d, "/api/history", "evil.example").status, 403);
    assert_eq!(post(&d, "/api/history/clear", "{}", "").status, 403);
}

#[test]
fn saving_and_comparing_fail_safely_without_an_audit_and_refuse_bad_input() {
    let d = start("saved");
    let bad = json_post(&d, "/api/saved", r#"{"label":"../x"}"#);
    assert_eq!(bad.status, 400);
    assert!(serde_json::from_str::<serde_json::Value>(&bad.body).unwrap()["error"].as_str().unwrap().contains("name of 1 to 40 characters"));
    assert!(json_post(&d, "/api/saved", r#"{"label":"Home"}"#).body.contains("no audit to save"));
    assert!(json_post(&d, "/api/saved", r#"{"label":7}"#).status == 400);
    assert!(json_post(&d, "/api/compare", "{}").body.contains("no current audit"));
    assert!(json_post(&d, "/api/saved/delete", r#"{"label":"Nope"}"#).body.contains("no saved report named"));
    assert_eq!(json_post(&d, "/api/scan", r#"{"dns":"1.1.1.1"}"#).status, 400, "a DNS value that is not one of the three");
    assert_eq!(json_post(&d, "/api/nope", "{}").status, 404);
    assert!(!d.dir.join("saved-reports").exists(), "nothing was saved");
}

#[test]
fn the_cli_refuses_targets_and_unknown_commands() {
    let run = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_peekaboo")).args(args).env("PEEKABOO_DATA_DIR", std::env::temp_dir().join("peekaboo-cli-refusals")).output().unwrap()
    };
    for args in [&["scan", "--target", "1.2.3.4"][..], &["scan", "192.168.1.1"], &["scan", "--dns", "8.8.8.8"], &["watch", "--save", "x"], &["reports", "bogus"], &["history", "bogus"], &["history", "clear", "extra"], &["nope"]] {
        let out = run(args);
        assert!(!out.status.success(), "{args:?}");
        assert!(out.stdout.is_empty(), "{args:?} printed to stdout");
    }
    assert!(String::from_utf8_lossy(&run(&["--help"]).stdout).contains("peekaboo scan"));
    assert!(String::from_utf8_lossy(&run(&["history"]).stdout).contains("No history yet"));
    assert!(String::from_utf8_lossy(&run(&["--version"]).stdout).starts_with("peekaboo "));
}
