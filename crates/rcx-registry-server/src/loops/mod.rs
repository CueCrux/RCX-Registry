//! Background loops driven from the server entrypoint.
//!
//! `sync` runs the hourly MCP scrape; `enrich` runs the 24h publisher
//! declaration refresh. Both expose an async `run` taking a shutdown
//! signal so `tokio::select!` in `main` can cooperatively stop them.

pub mod enrich;
pub mod sync;
