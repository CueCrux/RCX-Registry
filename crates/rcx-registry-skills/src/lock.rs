//! The `skills-lock.json` manifest.
//!
//! One entry per skill: where it came from, which file inside that source, and the
//! sha256 of the bytes at lock time. The lockfile is the ingest contract — every
//! fetch is checked against it, and the signed snapshot in the trust layer is taken
//! over it.
//!
//! **Round-trip is byte-exact by construction.** [`SkillLock::to_json`] reproduces
//! the on-disk form (2-space indent, ASCII-sorted keys, trailing newline) so a
//! re-serialised lockfile hashes identically to the one that was read. That is not
//! cosmetic: the trust layer signs a digest over this file, so a formatting-only
//! difference would read as tampering.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::error::SkillsError;

/// Lockfile schema version written by this crate.
///
/// v1 → v2 added `ref`. v1 files still parse (the field defaults to empty and is
/// omitted on write, so a v1 file round-trips byte-identically), but they cannot be
/// signed — see [`SkillLock::signable`].
pub const LOCK_VERSION: u32 = 2;

/// Below this, a lockfile pins content but not a commit, so a digest mismatch
/// cannot distinguish an upstream edit from tampering. Signing one would attest a
/// claim nobody can check.
pub const MIN_SIGNABLE_LOCK_VERSION: u32 = 2;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkillLock {
    pub version: u32,
    /// Skill display name -> pinned source. A `BTreeMap` rather than a
    /// `serde_json::Map`: the workspace enables serde_json's `preserve_order`, so a
    /// `Map` would round-trip in *insertion* order and drift the moment an entry is
    /// added out of sequence. `BTreeMap` sorts, which is what the file already is.
    pub skills: BTreeMap<String, LockEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockEntry {
    /// Owner/repo for `sourceType = "github"`.
    pub source: String,
    #[serde(rename = "sourceType")]
    pub source_type: String,
    /// Path to the `SKILL.md` within the source.
    #[serde(rename = "skillPath")]
    pub skill_path: String,
    /// Commit the content was read at — a full 40-hex git object id, never a branch
    /// name. A branch is a moving target, so pinning one would leave the digest
    /// checkable only until the next upstream push.
    ///
    /// Empty on v1 lockfiles, which is why they are not signable. Omitted from the
    /// serialised form when empty, so a v1 file round-trips byte-identically.
    #[serde(default, rename = "ref", skip_serializing_if = "String::is_empty")]
    pub git_ref: String,
    /// sha256 of the `SKILL.md` bytes at lock time, lowercase hex.
    #[serde(rename = "computedHash")]
    pub computed_hash: String,
}

impl SkillLock {
    /// Parse and validate. Validation is not optional here — an entry whose hash is
    /// malformed can never match a real digest, so accepting it would push a
    /// guaranteed failure to fetch time and report it as a content mismatch.
    pub fn from_json(raw: &str) -> Result<Self, SkillsError> {
        let lock: Self = serde_json::from_str(raw)?;
        lock.validate()?;
        Ok(lock)
    }

    /// Serialise in the canonical on-disk form: 2-space indent, sorted keys,
    /// trailing newline.
    pub fn to_json(&self) -> Result<String, SkillsError> {
        let mut out = serde_json::to_string_pretty(self)?;
        out.push('\n');
        Ok(out)
    }

    pub fn validate(&self) -> Result<(), SkillsError> {
        for (name, entry) in &self.skills {
            if !is_sha256_hex(&entry.computed_hash) {
                return Err(SkillsError::BadHash {
                    name: name.clone(),
                    got: entry.computed_hash.clone(),
                });
            }
            if entry.source_type != "github" {
                return Err(SkillsError::UnsupportedSource {
                    name: name.clone(),
                    source_type: entry.source_type.clone(),
                });
            }
        }
        Ok(())
    }

    /// Check this lockfile may be signed, or say precisely why not.
    ///
    /// Separate from [`Self::validate`] on purpose: a v1 lockfile is a legitimate
    /// thing to parse, fetch from, and relock. It is only signing that must refuse
    /// it, because a signature over refless entries would look like a guarantee and
    /// carry none.
    pub fn signable(&self) -> Result<(), SkillsError> {
        if self.version < MIN_SIGNABLE_LOCK_VERSION {
            return Err(SkillsError::NotSignable {
                reason: format!(
                    "lockfile version {} is below the minimum signable version {MIN_SIGNABLE_LOCK_VERSION} (no `ref` field, so a digest mismatch cannot be attributed)",
                    self.version
                ),
            });
        }
        if self.skills.is_empty() {
            return Err(SkillsError::NotSignable {
                reason: "refusing to sign an empty lockfile — an empty Merkle root attests nothing"
                    .to_string(),
            });
        }
        for (name, entry) in &self.skills {
            if !is_git_sha_hex(&entry.git_ref) {
                return Err(SkillsError::NotSignable {
                    reason: format!(
                        "entry `{name}` has ref {:?}; a full 40-hex commit id is required",
                        entry.git_ref
                    ),
                });
            }
        }
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.skills.len()
    }

    pub fn is_empty(&self) -> bool {
        self.skills.is_empty()
    }
}

/// 64 lowercase hex characters. Uppercase is rejected rather than normalised — two
/// spellings of one digest would give the signed snapshot two valid forms.
fn is_sha256_hex(s: &str) -> bool {
    is_lower_hex(s, 64)
}

/// A full git object id: 40 lowercase hex characters. Abbreviated ids are rejected
/// — they are ambiguous by construction, and an ambiguous ref cannot pin content.
fn is_git_sha_hex(s: &str) -> bool {
    is_lower_hex(s, 40)
}

fn is_lower_hex(s: &str, len: usize) -> bool {
    s.len() == len
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(hash: &str) -> LockEntry {
        LockEntry {
            source: "trailofbits/skills".into(),
            source_type: "github".into(),
            skill_path: "skills/x/SKILL.md".into(),
            git_ref: String::new(),
            computed_hash: hash.into(),
        }
    }

    const GOOD: &str = "4ea04d576507f4a683e6203737c33993fb36add719f628b7200649a9cb87b5fe";

    #[test]
    fn round_trip_is_byte_exact() {
        let raw = format!(
            "{{\n  \"version\": 1,\n  \"skills\": {{\n    \"ab-testing\": {{\n      \"source\": \"trailofbits/skills\",\n      \"sourceType\": \"github\",\n      \"skillPath\": \"skills/x/SKILL.md\",\n      \"computedHash\": \"{GOOD}\"\n    }}\n  }}\n}}\n"
        );
        let lock = SkillLock::from_json(&raw).expect("parses");
        assert_eq!(lock.to_json().expect("serialises"), raw);
    }

    #[test]
    fn keys_serialise_sorted_regardless_of_insertion_order() {
        let mut skills = BTreeMap::new();
        skills.insert("zebra".to_string(), entry(GOOD));
        skills.insert("Alpha".to_string(), entry(GOOD));
        skills.insert("middle".to_string(), entry(GOOD));
        let json = SkillLock {
            version: LOCK_VERSION,
            skills,
        }
        .to_json()
        .expect("serialises");
        let a = json.find("\"Alpha\"").expect("Alpha present");
        let m = json.find("\"middle\"").expect("middle present");
        let z = json.find("\"zebra\"").expect("zebra present");
        assert!(a < m && m < z, "expected ASCII-sorted keys, got:\n{json}");
    }

    #[test]
    fn rejects_malformed_hashes() {
        for bad in [
            "",
            "deadbeef",
            &GOOD.to_uppercase(),
            &format!("{GOOD}0"),
            &"z".repeat(64),
        ] {
            let mut skills = BTreeMap::new();
            skills.insert("s".to_string(), entry(bad));
            let lock = SkillLock {
                version: LOCK_VERSION,
                skills,
            };
            assert!(
                matches!(lock.validate(), Err(SkillsError::BadHash { .. })),
                "expected {bad:?} to be rejected"
            );
        }
    }

    #[test]
    fn len_and_is_empty_agree() {
        let empty = SkillLock {
            version: LOCK_VERSION,
            skills: BTreeMap::new(),
        };
        assert!(empty.is_empty());
        assert_eq!(empty.len(), 0);

        let mut skills = BTreeMap::new();
        skills.insert("s".to_string(), entry(GOOD));
        let one = SkillLock {
            version: LOCK_VERSION,
            skills,
        };
        assert!(!one.is_empty());
        assert_eq!(one.len(), 1);
    }

    #[test]
    fn rejects_unsupported_source_type() {
        let mut skills = BTreeMap::new();
        let mut e = entry(GOOD);
        e.source_type = "s3".into();
        skills.insert("s".to_string(), e);
        let lock = SkillLock {
            version: LOCK_VERSION,
            skills,
        };
        assert!(matches!(
            lock.validate(),
            Err(SkillsError::UnsupportedSource { .. })
        ));
    }
}
