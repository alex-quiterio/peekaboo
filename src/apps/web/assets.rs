//! The dashboard's files, compiled into the binary. A request can only pick from this list, so the server
//! serves nothing else, whatever path is asked for.

/// (path, content type, content)
pub const ASSETS: &[(&str, &str, &str)] = &[
    ("/", HTML, include_str!("public/index.html")),
    ("/index.html", HTML, include_str!("public/index.html")),
    ("/logo.svg", SVG, include_str!("public/logo.svg")),
    ("/scripts/dashboard.js", JS, include_str!("public/scripts/dashboard.js")),
    ("/scripts/rain.js", JS, include_str!("public/scripts/rain.js")),
    ("/styles/base.css", CSS, include_str!("public/styles/base.css")),
    ("/styles/controls.css", CSS, include_str!("public/styles/controls.css")),
    ("/styles/devices.css", CSS, include_str!("public/styles/devices.css")),
    ("/styles/effects.css", CSS, include_str!("public/styles/effects.css")),
    ("/styles/findings.css", CSS, include_str!("public/styles/findings.css")),
    ("/styles/layout.css", CSS, include_str!("public/styles/layout.css")),
    ("/styles/loading.css", CSS, include_str!("public/styles/loading.css")),
    ("/styles/saved.css", CSS, include_str!("public/styles/saved.css")),
    ("/styles/score.css", CSS, include_str!("public/styles/score.css")),
    ("/styles/speed.css", CSS, include_str!("public/styles/speed.css")),
    ("/styles/tokens.css", CSS, include_str!("public/styles/tokens.css")),
];

const SVG: &str = "image/svg+xml";
const HTML: &str = "text/html; charset=utf-8";
const JS: &str = "text/javascript; charset=utf-8";
const CSS: &str = "text/css; charset=utf-8";

pub fn find(path: &str) -> Option<(&'static str, &'static str)> {
    ASSETS.iter().find(|(p, _, _)| *p == path).map(|(_, kind, content)| (*kind, *content))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::Path;

    fn files(dir: &Path, prefix: &str, out: &mut Vec<String>) {
        for entry in fs::read_dir(dir).unwrap().flatten() {
            let name = format!("{prefix}/{}", entry.file_name().to_string_lossy());
            if entry.path().is_dir() {
                files(&entry.path(), &name, out);
            } else {
                out.push(name);
            }
        }
    }

    #[test]
    fn every_dashboard_file_is_embedded_and_nothing_else_is() {
        let public = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/apps/web/public");
        let mut on_disk = Vec::new();
        files(&public, "", &mut on_disk);
        on_disk.sort();
        let mut embedded: Vec<String> = ASSETS.iter().map(|(p, _, _)| p.to_string()).filter(|p| p != "/").collect();
        embedded.sort();
        assert_eq!(embedded, on_disk);
    }

    #[test]
    fn everything_the_page_links_to_is_served() {
        let (_, html) = find("/").unwrap();
        for part in html.split(['"', '\'']).filter(|p| p.starts_with("/styles/") || p.starts_with("/scripts/")) {
            assert!(find(part).is_some(), "{part} is linked but not served");
        }
    }

    #[test]
    fn unknown_paths_and_traversal_find_nothing() {
        for path in ["/etc/passwd", "/../Cargo.toml", "/styles/", "/api/state", "//index.html", "/styles/../index.html"] {
            assert!(find(path).is_none(), "{path}");
        }
    }
}
