//! Where the reports live. The binary never writes next to its own files.
use std::env;
use std::path::PathBuf;

/// `PEEKABOO_DATA_DIR` wins. Otherwise the platform's per-user data folder.
pub fn data_dir() -> PathBuf {
    if let Some(dir) = env::var_os("PEEKABOO_DATA_DIR").filter(|d| !d.is_empty()) {
        return PathBuf::from(dir);
    }
    let home = env::var_os("HOME").map(PathBuf::from);
    if cfg!(target_os = "macos") {
        if let Some(home) = home {
            return home.join("Library").join("Application Support").join("peekaboo");
        }
    } else if cfg!(windows) {
        if let Some(appdata) = env::var_os("APPDATA") {
            return PathBuf::from(appdata).join("peekaboo");
        }
    } else if let Some(xdg) = env::var_os("XDG_DATA_HOME").filter(|d| !d.is_empty()) {
        return PathBuf::from(xdg).join("peekaboo");
    } else if let Some(home) = home {
        return home.join(".local").join("share").join("peekaboo");
    }
    PathBuf::from("peekaboo-data")
}
