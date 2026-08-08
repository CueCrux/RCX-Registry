//! Agent Skills ingest primitives for RCX-Registry.
//!
//! Skills are distributed as [Agent Skills](https://agentskills.io) folders — a
//! `SKILL.md` with YAML frontmatter plus optional `references/`, `scripts/` and
//! `assets/`. The format is an open standard implemented by 45+ agent clients, so
//! this crate parses it and never invents a dialect.
//!
//! Three pieces, matching the ingest path:
//!
//! - [`lock`] — the `skills-lock.json` manifest: which skill comes from which
//!   source, and the content hash it is pinned to.
//! - [`skill`] — `SKILL.md` frontmatter + body, and the tiered model the resolve
//!   surface serves (discovery / body / references).
//! - [`fetch`] — retrieve each locked skill and verify it against its pinned hash.
//!
//! What this crate deliberately does *not* do is decide whether a skill is
//! trustworthy. A verified hash proves the bytes match what the lockfile recorded;
//! it says nothing about who published them or whether they are safe. Publisher
//! binding and signing live above this layer.

mod error;
pub mod fetch;
pub mod lock;
pub mod skill;

pub use error::SkillsError;
pub use fetch::{fetch_locked, FetchOutcome, Fetched, Mismatch};
pub use lock::{LockEntry, SkillLock};
pub use skill::{SkillDocument, SkillFrontMatter};
