//! The rules the project lives by, checked against the source. These replace a linter: if one fails, the
//! layering or a safety rule has been broken.
use std::fs;
use std::path::{Path, PathBuf};

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).unwrap().flatten() {
        let path = entry.path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// Every source file with its text, test code cut off. Paths are relative to `src/`.
fn sources() -> Vec<(String, String)> {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    rust_files(&src, &mut files);
    files
        .into_iter()
        .filter(|p| p.file_name().is_some_and(|n| n != "tests.rs"))
        .map(|p| {
            let text = fs::read_to_string(&p).unwrap();
            let code = text.split("#[cfg(test)]").next().unwrap().to_string();
            (p.strip_prefix(&src).unwrap().to_string_lossy().replace('\\', "/"), code)
        })
        .collect()
}

fn violations(layer: &str, forbidden: &[&str]) -> Vec<String> {
    sources()
        .iter()
        .filter(|(path, _)| path.starts_with(layer))
        .flat_map(|(path, code)| forbidden.iter().filter(|f| code.contains(**f)).map(move |f| format!("{path} uses {f}")))
        .collect()
}

#[test]
fn the_domain_depends_on_nothing_outside_itself_and_does_no_io() {
    let bad = violations(
        "domain/",
        &["crate::application", "crate::infrastructure", "crate::apps", "std::fs", "std::net", "std::process", "std::env", "std::thread", "std::time", "std::io"],
    );
    assert!(bad.is_empty(), "{bad:#?}");
}

#[test]
fn use_cases_depend_on_domain_interfaces_not_on_adapters_and_do_no_io() {
    let bad = violations("application/", &["crate::infrastructure", "crate::apps", "std::fs", "std::net", "std::process", "std::env"]);
    assert!(bad.is_empty(), "{bad:#?}");
}

#[test]
fn infrastructure_does_not_know_about_the_apps() {
    assert!(violations("infrastructure/", &["crate::apps"]).is_empty());
}

#[test]
fn the_two_apps_do_not_import_each_other_and_reach_adapters_only_through_the_composition_root() {
    assert!(violations("apps/cli/", &["apps::web", "super::web"]).is_empty());
    assert!(violations("apps/web/", &["apps::cli", "super::cli"]).is_empty());
    for (path, code) in sources().iter().filter(|(p, _)| p.starts_with("apps/") && p != "apps/mod.rs") {
        for line in code.lines().filter(|l| l.contains("crate::infrastructure::")) {
            let module = line.split("crate::infrastructure::").nth(1).unwrap().split([':', ';', ' ', '{']).next().unwrap();
            assert!(["composition", "clock"].contains(&module), "{path} reaches into infrastructure::{module}");
        }
    }
}

#[test]
fn upnp_may_only_read_port_mappings() {
    let (_, code) = sources().into_iter().find(|(p, _)| p == "infrastructure/upnp.rs").unwrap();
    for action in [
        "AddPortMapping", "AddAnyPortMapping", "DeletePortMapping", "DeletePortMappingRange", "GetExternalIPAddress",
        "ForceTermination", "RequestTermination", "RequestConnection", "SetConnectionType", "SetAutoDisconnectTime", "SetIdleDisconnectTime",
    ] {
        assert!(!code.contains(action), "upnp.rs mentions {action}");
    }
    assert!(code.contains("const ACTION: &str = \"GetGenericPortMappingEntry\""));
}

#[test]
fn only_the_stores_write_files() {
    for (path, code) in sources() {
        if ["json_report_repository.rs", "json_saved_report_store.rs", "json_history_store.rs"].iter().any(|f| path.ends_with(f)) {
            continue;
        }
        for call in ["fs::write", "File::create", "fs::rename", "create_dir", "fs::remove", "OpenOptions"] {
            assert!(!code.contains(call), "{path} calls {call}");
        }
    }
}

#[test]
fn the_tcp_probe_connects_and_never_sends_data() {
    let (_, code) = sources().into_iter().find(|(p, _)| p == "infrastructure/network.rs").unwrap();
    assert!(code.contains("TcpStream::connect_timeout"));
    assert!(!code.contains("write_all") && !code.contains(".write("));
}

#[test]
fn the_web_server_binds_to_loopback_only_and_has_no_target_input() {
    let (_, code) = sources().into_iter().find(|(p, _)| p == "apps/web/mod.rs").unwrap();
    assert!(code.contains("Server::http((\"127.0.0.1\", port))"));
    assert!(!code.contains("0.0.0.0"));
}

#[test]
fn the_sanitized_model_has_no_field_for_network_names() {
    let (_, code) = sources().into_iter().find(|(p, _)| p == "domain/model.rs").unwrap();
    let code = code.to_lowercase();
    assert!(!code.contains("ssid") && !code.contains("bssid"));
}

#[test]
fn no_option_names_a_scan_target() {
    for (path, code) in sources().iter().filter(|(p, _)| p.starts_with("apps/")) {
        for flag in ["\"--target\"", "\"--host\"", "\"--cidr\"", "\"--ip\"", "\"--address\"", "\"--password\"", "\"--user\""] {
            assert!(!code.contains(flag), "{path} accepts {flag}");
        }
    }
}

#[test]
fn the_dhcp_log_check_is_one_fixed_read_only_query_that_keeps_no_text() {
    let (_, code) = sources().into_iter().find(|(p, _)| p == "infrastructure/dhcp_log.rs").unwrap();
    assert!(code.contains("const LOG_TOOL: &str = \"/usr/bin/log\""));
    assert!(code.contains("const LOG_PREDICATE: &str"));
    for forbidden in ["sudo", "--info", "--debug", "--private", "println!", "eprintln!", "dbg!", "fs::", "File::", "TcpStream", "UdpSocket"] {
        assert!(!code.contains(forbidden), "dhcp_log.rs mentions {forbidden}");
    }
    // Only one command is ever run.
    assert_eq!(code.matches("run(").count(), 1);
}

#[test]
fn the_wifi_stability_model_holds_numbers_only() {
    let (_, code) = sources().into_iter().find(|(p, _)| p == "domain/model.rs").unwrap();
    let start = code.find("pub struct WifiStabilityCheck").unwrap();
    let body = &code[start..start + code[start..].find('}').unwrap()];
    assert!(!body.contains("String") && !body.contains("Vec"), "{body}");
}

#[test]
fn the_speed_test_is_one_fixed_opt_in_command_that_keeps_only_numbers() {
    let (_, code) = sources().into_iter().find(|(p, _)| p == "infrastructure/speed_test.rs").unwrap();
    assert!(code.contains("const TOOL: &str = \"/usr/bin/networkQuality\""));
    for forbidden in ["sudo", "println!", "eprintln!", "dbg!", "fs::", "File::", "TcpStream", "UdpSocket", "env::"] {
        assert!(!code.contains(forbidden), "speed_test.rs mentions {forbidden}");
    }
    assert_eq!(code.matches("run(TOOL").count(), 1);
    // Only the CLI's scan command and the dashboard's manual audit may ask for it, and the audit itself never does.
    for (path, code) in sources().iter().filter(|(p, _)| !p.starts_with("apps/cli/") && p != "apps/web/mod.rs" && p != "infrastructure/composition.rs" && p != "application/mod.rs") {
        assert!(!code.contains("run_speed_test") || path.starts_with("application/run_speed_test"), "{path} runs the speed test");
    }
}
