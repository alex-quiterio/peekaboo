//! The model and every rule. No I/O: the outside world is reached only through `ports`.
pub mod compare;
pub mod devices;
pub mod evidence;
pub mod exposure;
pub mod findings;
pub mod gateway;
pub mod history;
pub mod model;
pub mod ports;
pub mod report;
pub mod saved;
pub mod scoring;
pub mod speed;

#[cfg(test)]
mod tests;
