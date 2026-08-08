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
pub mod index;
pub mod lock;
pub mod sign;
pub mod skill;
pub mod uri;

pub use error::SkillsError;
pub use fetch::{fetch_locked, FetchOutcome, Fetched, Mismatch};
pub use index::{indexed_text, ingest_body, IngestBody, IngestChunk, IngestDocument};
pub use lock::{LockEntry, SkillLock, LOCK_VERSION, MIN_SIGNABLE_LOCK_VERSION};
pub use sign::{
    lock_merkle_root, prepare_receipt, sign_receipt, signing_preimage, verify_lock_receipt,
    ReceiptDraft,
};
pub use skill::{SkillDocument, SkillFrontMatter};
pub use uri::{
    resolution_order, resolve, resolve_by_id, uris_for, Registry, RegistryKind, Resolved, SkillUri,
    RCX_SKILL_REGISTRY_AUTHORITY,
};
