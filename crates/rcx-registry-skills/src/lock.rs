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

/// Lockfile schema version. Bumping it is a breaking ingest change.
pub const LOCK_VERSION: u32 = 1;

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
    s.len() == 64
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
