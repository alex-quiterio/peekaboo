//! Peekaboo: a read-only, privacy-conscious audit of a home network you own or administer.
//!
//! Dependencies point inward only: `apps -> infrastructure -> application -> domain`.
//! `tests/layering.rs` enforces it.
pub mod apps;
pub mod application;
pub mod domain;
pub mod infrastructure;
