//! The `skill://` URI scheme, and resolution across federated registries.
//!
//! ```text
//! skill://registry.host/skill-id@version
//!   │        │              │        │
//!   │        │              │        └── commit id; absent means "whatever is latest"
//!   │        │              └─────────── skill id, as keyed in the lockfile
//!   │        └────────────────────────── registry authority
//!   └─────────────────────────────────── scheme
//! ```
//!
//! Implements the scheme specified — but never implemented — in the upstream
//! skills-mcp `docs/FEDERATION_DESIGN.md`, whose `skill_uri` model field exists and
//! is always empty.
//!
//! ## `@version` is a commit, not a semver
//!
//! This is the whole point of the scheme. A pinned URI names an immutable object:
//! the same `skill://host/id@<commit>` resolves to the same bytes forever, or fails.
//! A semver would not give that — publishers retag, and a mutable version in an
//! identifier that people cache and share is a supply-chain hazard rather than a
//! convenience. An **unpinned** URI is a query, not an identifier, and is explicitly
//! allowed to resolve differently over time.
//!
//! ## Publishing this scheme is a commitment
//!
//! Third parties will parse these strings. Changing the grammar later breaks them
//! silently, so the parser is strict on the way in: anything ambiguous is rejected
//! rather than guessed at.

use std::fmt;

use crate::error::SkillsError;
use crate::lock::{LockEntry, SkillLock};

/// The authority this registry publishes under.
pub const RCX_SKILL_REGISTRY_AUTHORITY: &str = "registry.rcxprotocol.org";

const SCHEME: &str = "skill://";

/// A parsed `skill://` URI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkillUri {
    pub registry: String,
    pub skill_id: String,
    /// Commit id when pinned. `None` means "latest", which is a query rather than
    /// a stable identifier.
    pub version: Option<String>,
}

impl SkillUri {
    /// Parse a `skill://` URI.
    ///
    /// Strict by design — see the module note on why the grammar cannot drift.
    pub fn parse(raw: &str) -> Result<Self, SkillsError> {
        let bad = |why: &str| SkillsError::BadSkillUri {
            uri: raw.to_string(),
            reason: why.to_string(),
        };

        let rest = raw
            .strip_prefix(SCHEME)
            .ok_or_else(|| bad("missing skill:// scheme"))?;
        let (registry, tail) = rest
            .split_once('/')
            .ok_or_else(|| bad("missing /skill-id"))?;

        if registry.is_empty() {
            return Err(bad("empty registry authority"));
        }
        if !registry
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b':')
        {
            return Err(bad("registry authority has characters outside host syntax"));
        }

        // Split on the LAST '@': a skill id may not contain one, but rejecting on
        // that basis is friendlier than silently splitting at the wrong place.
        let (skill_id, version) = match tail.rsplit_once('@') {
            Some((id, ver)) => (id, Some(ver)),
            None => (tail, None),
        };

        if skill_id.is_empty() {
            return Err(bad("empty skill id"));
        }
        // A '/' in the id would make the authority boundary ambiguous, and '..'
        // is a traversal attempt against any store that maps ids onto paths.
        if skill_id.contains('/') || skill_id.contains("..") {
            return Err(bad("skill id may not contain '/' or '..'"));
        }
        if skill_id.contains('@') {
            return Err(bad("skill id may not contain '@'"));
        }

        let version = match version {
            None => None,
            // Literal pattern rather than a guard: `""` fails `is_commit_id` anyway,
            // so a guard here reads as redundant, but the distinct message is worth
            // keeping — "empty version" and "not a commit id" are different mistakes.
            Some("") => return Err(bad("empty version after '@'")),
            Some(v) if is_commit_id(v) => Some(v.to_ascii_lowercase()),
            Some(_) => {
                return Err(bad(
                    "version must be a full 40-hex commit id — a mutable tag or semver cannot pin content",
                ))
            }
        };

        Ok(Self {
            registry: registry.to_string(),
            skill_id: skill_id.to_string(),
            version,
        })
    }

    /// True when this URI names an immutable object.
    pub fn is_pinned(&self) -> bool {
        self.version.is_some()
    }

    /// Pin an unpinned URI to a commit.
    pub fn pinned_to(&self, commit: &str) -> Self {
        Self {
            version: Some(commit.to_ascii_lowercase()),
            ..self.clone()
        }
    }
}

impl fmt::Display for SkillUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{SCHEME}{}/{}", self.registry, self.skill_id)?;
        if let Some(version) = &self.version {
            write!(f, "@{version}")?;
        }
        Ok(())
    }
}

fn is_commit_id(s: &str) -> bool {
    s.len() == 40 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// How much a registry is trusted, which is also its search precedence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RegistryKind {
    /// This node's own lockfile. Always answered first — a local pin must never be
    /// silently overridden by a remote answer.
    Local,
    /// An operator-configured peer, searched in the order configured.
    TrustedRemote,
    /// An open registry, last and disableable.
    PublicFallback,
}

/// One registry in a federation.
pub struct Registry {
    pub host: String,
    pub kind: RegistryKind,
    pub lock: SkillLock,
}

/// A resolved skill: which registry answered, and the entry it holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolved<'a> {
    pub uri: SkillUri,
    pub registry: &'a str,
    pub kind: RegistryKind,
    pub entry: &'a LockEntry,
}

/// Search precedence: local, then trusted remotes in configured order, then public.
///
/// Stable within a kind, so the operator's configured order is preserved rather
/// than re-sorted by host name.
pub fn resolution_order(registries: &[Registry]) -> Vec<&Registry> {
    let mut ordered: Vec<&Registry> = registries.iter().collect();
    ordered.sort_by_key(|r| r.kind);
    ordered
}

/// Resolve a `skill://` URI against a federation.
///
/// The URI names its registry, so precedence does not apply — only the named
/// registry may answer. Anything else would let a higher-precedence registry
/// substitute content for a URI that explicitly asked elsewhere, which is the
/// substitution attack the scheme exists to prevent.
///
/// A pinned URI additionally requires the entry's commit to match. A registry that
/// holds the skill at a *different* commit is not a match — it is a different object.
pub fn resolve<'a>(uri: &SkillUri, registries: &'a [Registry]) -> Option<Resolved<'a>> {
    let registry = registries.iter().find(|r| r.host == uri.registry)?;
    let entry = registry.lock.skills.get(&uri.skill_id)?;
    if let Some(version) = &uri.version {
        if &entry.git_ref != version {
            return None;
        }
    }
    Some(Resolved {
        uri: uri.clone(),
        registry: &registry.host,
        kind: registry.kind,
        entry,
    })
}

/// Resolve a bare skill id with no registry named, honouring precedence.
///
/// This is the search path — `skills_find_relevant` rather than a URI lookup — and
/// it is where [`resolution_order`] matters.
pub fn resolve_by_id<'a>(skill_id: &str, registries: &'a [Registry]) -> Option<Resolved<'a>> {
    for registry in resolution_order(registries) {
        if let Some(entry) = registry.lock.skills.get(skill_id) {
            let uri = SkillUri {
                registry: registry.host.clone(),
                skill_id: skill_id.to_string(),
                version: (!entry.git_ref.is_empty()).then(|| entry.git_ref.clone()),
            };
            return Some(Resolved {
                uri,
                registry: &registry.host,
                kind: registry.kind,
                entry,
            });
        }
    }
    None
}

/// Every skill in `lock`, addressed under `authority`.
///
/// Entries with no commit are emitted unpinned: a v1 lockfile can still be browsed,
/// it just cannot hand out stable identifiers.
pub fn uris_for(lock: &SkillLock, authority: &str) -> Vec<SkillUri> {
    lock.skills
        .iter()
        .map(|(name, entry)| SkillUri {
            registry: authority.to_string(),
            skill_id: name.clone(),
            version: (!entry.git_ref.is_empty()).then(|| entry.git_ref.clone()),
        })
        .collect()
}
