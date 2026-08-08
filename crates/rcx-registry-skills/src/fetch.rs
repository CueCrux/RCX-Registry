//! Retrieve locked skills and check them against their pinned hash.
//!
//! The lockfile pins **content, not a commit**: an entry records `owner/repo` and a
//! path but no ref. So a fetch resolves against the source's default branch, and a
//! digest mismatch is genuinely ambiguous — upstream may have edited the skill, or
//! the bytes may have been tampered with. This module reports the mismatch and
//! refuses the content; it does not guess which happened. Distinguishing the two
//! needs a ref in the lockfile, which is a schema change, not a fetch change.
//!
//! Verification is split from transport ([`verify_bytes`] is pure) so the
//! fails-closed behaviour is testable without a network.

use std::collections::BTreeMap;

use sha2::{Digest, Sha256};

use crate::error::SkillsError;
use crate::lock::{LockEntry, SkillLock};

/// Why an entry did not yield trusted bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mismatch {
    /// Bytes arrived but hashed to something other than the pinned digest.
    Digest {
        name: String,
        source: String,
        expected: String,
        actual: String,
    },
    /// The source could not be read at all.
    Unreachable {
        name: String,
        source: String,
        detail: String,
    },
}

impl Mismatch {
    pub fn name(&self) -> &str {
        match self {
            Self::Digest { name, .. } | Self::Unreachable { name, .. } => name,
        }
    }
}

/// Bytes that arrived for one entry, and how they compared to the pinned digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fetched {
    pub bytes: Vec<u8>,
    /// sha256 of `bytes` as actually received.
    pub digest: String,
    /// Whether `digest` equalled the lockfile's `computedHash`.
    pub matched_lock: bool,
}

/// Result of walking a lockfile.
///
/// `fetched` holds everything that came back, matching or not — the two are
/// different problems. Unmatched bytes are not trusted content, but they are the
/// only input from which a *correct* lockfile can be rebuilt, so discarding them
/// would leave no way out of an unverifiable lockfile.
#[derive(Debug, Default)]
pub struct FetchOutcome {
    pub fetched: BTreeMap<String, Fetched>,
    pub mismatches: Vec<Mismatch>,
}

impl FetchOutcome {
    /// Entries whose bytes matched their pinned digest — the only trusted content.
    pub fn verified(&self) -> impl Iterator<Item = (&String, &Fetched)> {
        self.fetched.iter().filter(|(_, f)| f.matched_lock)
    }

    pub fn verified_count(&self) -> usize {
        self.verified().count()
    }

    pub fn is_clean(&self) -> bool {
        self.mismatches.is_empty()
    }

    /// Rebuild a lockfile from what was actually fetched, pinning the digests
    /// observed rather than the ones inherited.
    ///
    /// This exists because an inherited lockfile can be unverifiable — the upstream
    /// `skills-lock.json` verified 0 of 390 on first run, its hashes produced by a
    /// process absent from that repo. Signing such a file attests nothing. Relocking
    /// against a live fetch produces hashes that are ours and checkable.
    ///
    /// Entries that could not be fetched are dropped: a lock entry with no
    /// retrievable content is a promise the registry cannot keep.
    pub fn relock(&self, previous: &SkillLock) -> SkillLock {
        let skills = self
            .fetched
            .iter()
            .filter_map(|(name, f)| {
                let prev = previous.skills.get(name)?;
                Some((
                    name.clone(),
                    LockEntry {
                        computed_hash: f.digest.clone(),
                        ..prev.clone()
                    },
                ))
            })
            .collect();
        SkillLock {
            version: previous.version,
            skills,
        }
    }
}

/// Raw-content URL for a locked entry.
///
/// `HEAD` rather than a pinned ref, because the lockfile carries none — see the
/// module note on why that makes a mismatch ambiguous.
pub fn raw_url(entry: &LockEntry) -> String {
    format!(
        "https://raw.githubusercontent.com/{}/HEAD/{}",
        entry.source, entry.skill_path
    )
}

/// Check bytes against a pinned digest. Returns the digest actually computed on
/// failure so the caller can report both sides.
///
/// Fails closed: any difference at all rejects, and the comparison is over the full
/// 32-byte digest rather than a prefix.
pub fn verify_bytes(bytes: &[u8], expected_hex: &str) -> Result<(), String> {
    let actual = hex_digest(bytes);
    if actual == expected_hex {
        Ok(())
    } else {
        Err(actual)
    }
}

fn hex_digest(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Fetch and verify every entry in `lock`.
///
/// One entry failing never aborts the walk — the point of the gate is to *name*
/// every mismatch, not to stop at the first. Callers decide what an unclean
/// outcome means.
pub fn fetch_locked(lock: &SkillLock, client: &reqwest::blocking::Client) -> FetchOutcome {
    let mut outcome = FetchOutcome::default();
    for (name, entry) in &lock.skills {
        match fetch_one(entry, client) {
            Ok(bytes) => {
                let digest = hex_digest(&bytes);
                let matched_lock = digest == entry.computed_hash;
                if !matched_lock {
                    outcome.mismatches.push(Mismatch::Digest {
                        name: name.clone(),
                        source: entry.source.clone(),
                        expected: entry.computed_hash.clone(),
                        actual: digest.clone(),
                    });
                }
                outcome.fetched.insert(
                    name.clone(),
                    Fetched {
                        bytes,
                        digest,
                        matched_lock,
                    },
                );
            }
            Err(err) => outcome.mismatches.push(Mismatch::Unreachable {
                name: name.clone(),
                source: entry.source.clone(),
                detail: err.to_string(),
            }),
        }
    }
    outcome
}

fn fetch_one(
    entry: &LockEntry,
    client: &reqwest::blocking::Client,
) -> Result<Vec<u8>, SkillsError> {
    let response = client.get(raw_url(entry)).send()?.error_for_status()?;
    Ok(response.bytes()?.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    // sha256("hello world")
    const HELLO: &str = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";

    #[test]
    fn verifies_matching_bytes() {
        assert!(verify_bytes(b"hello world", HELLO).is_ok());
    }

    #[test]
    fn corrupted_bytes_fail_closed() {
        // One flipped byte in the content.
        let err = verify_bytes(b"hello worle", HELLO).expect_err("must reject");
        assert_ne!(err, HELLO);
        assert_eq!(err.len(), 64);
    }

    #[test]
    fn corrupted_digest_fails_closed() {
        // One flipped character in the *pinned* hash — the tamper direction that
        // matters once the lockfile itself is signed.
        let mut tampered = HELLO.to_string();
        tampered.replace_range(0..1, "c");
        assert!(verify_bytes(b"hello world", &tampered).is_err());
    }

    #[test]
    fn empty_content_does_not_verify_against_a_real_hash() {
        assert!(verify_bytes(b"", HELLO).is_err());
    }

    #[test]
    fn relock_pins_observed_digests_and_drops_unfetchable() {
        let mut skills = std::collections::BTreeMap::new();
        skills.insert("kept".to_string(), entry_for("a/b", HELLO));
        skills.insert("gone".to_string(), entry_for("c/d", HELLO));
        let previous = SkillLock { version: 1, skills };

        let mut outcome = FetchOutcome::default();
        outcome.fetched.insert(
            "kept".to_string(),
            Fetched {
                bytes: b"new content".to_vec(),
                digest: hex_digest(b"new content"),
                matched_lock: false,
            },
        );

        let relocked = outcome.relock(&previous);
        assert_eq!(relocked.len(), 1, "unfetchable entries must be dropped");
        let kept = relocked.skills.get("kept").expect("kept present");
        assert_eq!(kept.computed_hash, hex_digest(b"new content"));
        assert_eq!(kept.source, "a/b", "non-hash fields carry over unchanged");
        // The whole point: the rebuilt lockfile validates and re-verifies.
        assert!(relocked.validate().is_ok());
        assert!(verify_bytes(b"new content", &kept.computed_hash).is_ok());
    }

    fn entry_for(source: &str, hash: &str) -> LockEntry {
        LockEntry {
            source: source.into(),
            source_type: "github".into(),
            skill_path: "s/SKILL.md".into(),
            computed_hash: hash.into(),
        }
    }

    #[test]
    fn raw_url_is_built_from_source_and_path() {
        let entry = LockEntry {
            source: "trailofbits/skills".into(),
            source_type: "github".into(),
            skill_path: "plugins/testing-handbook-skills/skills/address-sanitizer/SKILL.md".into(),
            computed_hash: HELLO.into(),
        };
        assert_eq!(
            raw_url(&entry),
            "https://raw.githubusercontent.com/trailofbits/skills/HEAD/plugins/testing-handbook-skills/skills/address-sanitizer/SKILL.md"
        );
    }
}
