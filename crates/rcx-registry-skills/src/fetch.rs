//! Retrieve locked skills and check them against their pinned hash.
//!
//! A v2 entry pins a **commit**, so its raw URL is immutable and a digest mismatch
//! means the bytes were altered in transit or at rest — an attributable failure.
//!
//! A v1 entry pins only content, and resolves against the source's default branch.
//! There a mismatch is ambiguous: upstream may have edited the skill, or the bytes
//! may have been tampered with, and nothing here can tell the two apart. This module
//! reports the mismatch and refuses the content either way; it never guesses. That
//! ambiguity is exactly why v1 lockfiles cannot be signed — see [`SkillLock::signable`].
//!
//! [`pin_refs`] is the bridge: resolve each source once, stamp every entry, and the
//! lockfile becomes signable.
//!
//! Verification is split from transport ([`verify_bytes`] is pure) so the
//! fails-closed behaviour is testable without a network.

use std::collections::{BTreeMap, BTreeSet};

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
    /// Commit the bytes were read at; empty when fetched from an unpinned `HEAD`.
    pub git_ref: String,
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
    ///
    /// The output carries the ref each fetch actually used, so relocking after
    /// [`pin_refs`] yields a signable lockfile.
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
                        git_ref: f.git_ref.clone(),
                        ..prev.clone()
                    },
                ))
            })
            .collect();
        // Relocking always writes the current schema: the output carries whatever
        // refs the fetch used, so labelling it v1 would understate it. A relock of
        // an unpinned v1 lockfile still produces refless entries, which `signable`
        // then rejects — the version alone never implies the guarantee.
        SkillLock {
            version: crate::lock::LOCK_VERSION,
            skills,
        }
    }
}

/// Raw-content URL for a locked entry.
///
/// Uses the pinned commit when the entry has one, which makes the URL immutable and
/// the digest attributable. Falls back to `HEAD` only for v1 entries, which is
/// exactly the ambiguity described above — those lockfiles cannot be signed.
pub fn raw_url(entry: &LockEntry) -> String {
    let reference = if entry.git_ref.is_empty() {
        "HEAD"
    } else {
        &entry.git_ref
    };
    format!(
        "https://raw.githubusercontent.com/{}/{reference}/{}",
        entry.source, entry.skill_path
    )
}

/// Resolve each distinct source to the commit its default branch currently points
/// at, and stamp every entry with it.
///
/// Resolution is per **source**, not per skill: 26 sources back 390 skills in the
/// upstream lockfile, so this is 26 requests rather than 390, and it also guarantees
/// that skills from one repo are pinned to one consistent commit rather than to
/// whatever each individual request happened to race.
///
/// Honours `GITHUB_TOKEN` when set. Unauthenticated GitHub allows 60 requests an
/// hour, which covers this but leaves no headroom for a retry.
pub fn pin_refs(
    lock: &mut SkillLock,
    client: &reqwest::blocking::Client,
) -> Result<(), SkillsError> {
    let sources: BTreeSet<String> = lock.skills.values().map(|e| e.source.clone()).collect();
    let mut resolved: BTreeMap<String, String> = BTreeMap::new();
    for source in sources {
        let sha = resolve_head_commit(&source, client)?;
        resolved.insert(source, sha);
    }
    for entry in lock.skills.values_mut() {
        if let Some(sha) = resolved.get(&entry.source) {
            entry.git_ref.clone_from(sha);
        }
    }
    lock.version = crate::lock::LOCK_VERSION;
    Ok(())
}

fn resolve_head_commit(
    source: &str,
    client: &reqwest::blocking::Client,
) -> Result<String, SkillsError> {
    let url = format!("https://api.github.com/repos/{source}/commits/HEAD");
    let mut request = client
        .get(&url)
        .header("Accept", "application/vnd.github.sha");
    if let Ok(token) = std::env::var("GITHUB_TOKEN") {
        if !token.is_empty() {
            request = request.bearer_auth(token);
        }
    }
    let response = request.send().map_err(|error| SkillsError::RefResolution {
        repo: source.to_string(),
        detail: error.to_string(),
    })?;
    let status = response.status();
    let body = response.text().unwrap_or_default();
    if !status.is_success() {
        return Err(SkillsError::RefResolution {
            repo: source.to_string(),
            detail: format!(
                "HTTP {status}: {}",
                body.chars().take(120).collect::<String>()
            ),
        });
    }
    parse_commit_sha(&body).ok_or_else(|| SkillsError::RefResolution {
        repo: source.to_string(),
        detail: format!(
            "expected a 40-hex commit id, got {:?}",
            body.trim().chars().take(60).collect::<String>()
        ),
    })
}

/// Accept a GitHub `.sha` response, or reject it.
///
/// Split out of the request path so the guard is unit-testable — it is the only
/// thing standing between a surprising API response and a lockfile pinned to
/// garbage, and a network-gated test cannot exercise it.
///
/// Normalises case on the way through: GitHub returns lowercase, but an uppercase
/// id would otherwise reach `signable()` and be rejected far from its cause.
fn parse_commit_sha(body: &str) -> Option<String> {
    let sha = body.trim();
    if sha.len() != 40 || !sha.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    Some(sha.to_ascii_lowercase())
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
                // Route through `verify_bytes` rather than comparing inline: an
                // inline duplicate is a second implementation of the security
                // comparison, and it is the one no unit test covers. `cargo-mutants`
                // confirmed that — inverting the inline `==` survived the suite.
                let (digest, matched_lock) = match verify_bytes(&bytes, &entry.computed_hash) {
                    Ok(()) => (entry.computed_hash.clone(), true),
                    Err(actual) => (actual, false),
                };
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
                        git_ref: entry.git_ref.clone(),
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
                git_ref: SHA.to_string(),
                digest: hex_digest(b"new content"),
                matched_lock: false,
            },
        );

        let relocked = outcome.relock(&previous);
        assert_eq!(relocked.len(), 1, "unfetchable entries must be dropped");
        let kept = relocked.skills.get("kept").expect("kept present");
        assert_eq!(kept.computed_hash, hex_digest(b"new content"));
        assert_eq!(kept.source, "a/b", "non-hash fields carry over unchanged");
        assert_eq!(
            kept.git_ref, SHA,
            "the ref actually fetched is what gets pinned"
        );
        // The whole point: the rebuilt lockfile validates, re-verifies, and — unlike
        // the v1 input it came from — is now signable.
        assert!(relocked.validate().is_ok());
        assert!(verify_bytes(b"new content", &kept.computed_hash).is_ok());
        assert!(relocked.signable().is_ok());
    }

    #[test]
    fn relocking_an_unpinned_lockfile_stays_unsignable() {
        // Bumping the version on the way out must not manufacture a guarantee: an
        // input with no refs produces an output with no refs.
        let mut skills = std::collections::BTreeMap::new();
        skills.insert("kept".to_string(), entry_for("a/b", HELLO));
        let previous = SkillLock { version: 1, skills };

        let mut outcome = FetchOutcome::default();
        outcome.fetched.insert(
            "kept".to_string(),
            Fetched {
                bytes: b"x".to_vec(),
                git_ref: String::new(),
                digest: hex_digest(b"x"),
                matched_lock: false,
            },
        );

        let relocked = outcome.relock(&previous);
        assert_eq!(relocked.version, crate::lock::LOCK_VERSION);
        assert!(
            relocked.signable().is_err(),
            "a version bump alone must never make a refless lockfile signable"
        );
    }

    const SHA: &str = "1111111111111111111111111111111111111111";

    #[test]
    fn parse_commit_sha_accepts_a_real_response() {
        // Positive control first: a guard that only ever rejects passes its whole
        // suite while inverted.
        assert_eq!(
            parse_commit_sha("a1b2c3d4e5f60718293a4b5c6d7e8f9012345678"),
            Some("a1b2c3d4e5f60718293a4b5c6d7e8f9012345678".to_string())
        );
        // GitHub's plain-text response carries a trailing newline.
        assert_eq!(
            parse_commit_sha("a1b2c3d4e5f60718293a4b5c6d7e8f9012345678\n").as_deref(),
            Some("a1b2c3d4e5f60718293a4b5c6d7e8f9012345678")
        );
        // Case is normalised rather than rejected, so it fails near its cause.
        assert_eq!(
            parse_commit_sha("A1B2C3D4E5F60718293A4B5C6D7E8F9012345678").as_deref(),
            Some("a1b2c3d4e5f60718293a4b5c6d7e8f9012345678")
        );
    }

    #[test]
    fn parse_commit_sha_rejects_anything_else() {
        for bad in [
            "",
            "abc123",                                                 // abbreviated
            "a1b2c3d4e5f60718293a4b5c6d7e8f90123456789",              // 41 chars
            "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",               // right length, not hex
            "{\"sha\":\"a1b2c3d4e5f60718293a4b5c6d7e8f9012345678\"}", // JSON, wrong Accept honoured
            "Not Found",
        ] {
            assert_eq!(
                parse_commit_sha(bad),
                None,
                "expected {bad:?} to be refused"
            );
        }
    }

    #[test]
    fn verified_count_counts_only_matching_entries() {
        let mut outcome = FetchOutcome::default();
        assert_eq!(outcome.verified_count(), 0);
        for (name, matched) in [("ok", true), ("bad", false), ("ok2", true)] {
            outcome.fetched.insert(
                name.to_string(),
                Fetched {
                    bytes: b"x".to_vec(),
                    git_ref: SHA.to_string(),
                    digest: hex_digest(b"x"),
                    matched_lock: matched,
                },
            );
        }
        assert_eq!(
            outcome.verified_count(),
            2,
            "unmatched bytes are never counted as verified"
        );
    }

    #[test]
    fn is_clean_tracks_mismatches() {
        let mut outcome = FetchOutcome::default();
        assert!(outcome.is_clean(), "no mismatches means clean");
        outcome.mismatches.push(Mismatch::Unreachable {
            name: "n".into(),
            source: "a/b".into(),
            detail: "404".into(),
        });
        assert!(!outcome.is_clean(), "any mismatch means not clean");
    }

    fn entry_for(source: &str, hash: &str) -> LockEntry {
        LockEntry {
            source: source.into(),
            source_type: "github".into(),
            skill_path: "s/SKILL.md".into(),
            git_ref: String::new(),
            computed_hash: hash.into(),
        }
    }

    #[test]
    fn raw_url_falls_back_to_head_for_an_unpinned_entry() {
        let entry = entry_for("trailofbits/skills", HELLO);
        assert_eq!(
            raw_url(&entry),
            "https://raw.githubusercontent.com/trailofbits/skills/HEAD/s/SKILL.md"
        );
    }

    #[test]
    fn raw_url_pins_the_commit_when_the_entry_has_one() {
        let mut entry = entry_for("trailofbits/skills", HELLO);
        entry.git_ref = SHA.to_string();
        assert_eq!(
            raw_url(&entry),
            format!("https://raw.githubusercontent.com/trailofbits/skills/{SHA}/s/SKILL.md"),
            "a pinned entry must resolve to an immutable URL, never HEAD"
        );
    }
}
