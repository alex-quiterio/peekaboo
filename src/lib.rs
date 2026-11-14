//! Peekaboo: a read-only, privacy-conscious audit of a home network you own or administer.
//!
//! Dependencies point inward only: `apps -> infrastructure -> application -> domain`.
//! `tests/architecture.rs` enforces it, and `clippy.toml` (run `cargo clippy`) bans I/O outside the two
//! outer layers: the lints below are denied everywhere except on `apps` and `infrastructure`.
#![deny(clippy::disallowed_methods, clippy::disallowed_types)]

#[allow(clippy::disallowed_methods, clippy::disallowed_types)]
pub mod apps;
pub mod application;
pub mod domain;
#[allow(clippy::disallowed_methods, clippy::disallowed_types)]
pub mod infrastructure;
