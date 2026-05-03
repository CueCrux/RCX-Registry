//! RCX-Registry server crate.
//!
//! Wires the existing `rcx-registry-api` router to Postgres-backed stores,
//! a real DNS TXT resolver, a GitHub OAuth provider, and a Vault Transit
//! signer for receipt minting.

pub mod config;
pub mod db;
pub mod dns;
pub mod github_oauth;
pub mod health;
pub mod loops;
pub mod metrics;
pub mod server;
pub mod vault;
