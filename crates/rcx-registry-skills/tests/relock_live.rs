//! The end-to-end M2 gate, against the live network.
//!
//! `#[ignore]` by default. Run it deliberately:
//!
//! ```text
//! cargo test -p rcx-registry-skills --test relock_live -- --ignored --nocapture
//! ```
//!
//! This is the claim the whole milestone rests on: a lockfile we produced is one a
//! third party can re-derive. Pin refs, fetch, relock, sign — then fetch *again* at
//! the same pinned refs and check every digest. Anything less than 100% means the
//! signature attests bytes nobody else can reproduce, which is the exact failure
//! that made the inherited lockfile worthless.
//!
//! Scoped to a handful of sources so it stays inside GitHub's unauthenticated rate
//! limit; set `GITHUB_TOKEN` to widen it.

use ed25519_dalek::{Signer, SigningKey};
use rcx_registry_skills::{
    fetch::{fetch_locked, pin_refs},
    prepare_receipt, sign_receipt, verify_lock_receipt, ReceiptDraft, SkillLock,
};

const RAW: &str = include_str!("fixtures/skills-lock.json");

/// Sources small enough to keep the run quick and the rate limit intact.
const SOURCES: &[&str] = &["anthropics/skills", "vercel-labs/agent-skills"];

fn client() -> reqwest::blocking::Client {
    reqwest::blocking::Client::builder()
        .user_agent("rcx-registry-skills/0")
        .timeout(std::time::Duration::from_secs(20))
        .build()
        .expect("client")
}

#[test]
#[ignore = "network: GitHub API + raw content"]
fn a_relocked_lockfile_reverifies_completely() {
    let full = SkillLock::from_json(RAW).expect("fixture parses");
    let mut lock = SkillLock {
        version: full.version,
        skills: full
            .skills
            .into_iter()
            .filter(|(_, e)| SOURCES.contains(&e.source.as_str()))
            .collect(),
    };
    assert!(!lock.is_empty(), "the scoped subset must not be empty");
    println!("scoped to {} skills from {SOURCES:?}", lock.len());

    // The inherited lockfile cannot be signed: no refs.
    assert!(
        lock.signable().is_err(),
        "a v1 lockfile must refuse to sign"
    );

    // 1. Pin every source to a commit.
    let http = client();
    pin_refs(&mut lock, &http).expect("refs resolve");
    let pinned: std::collections::BTreeSet<&str> =
        lock.skills.values().map(|e| e.git_ref.as_str()).collect();
    println!("pinned to {} distinct commits", pinned.len());

    // 2. Fetch at those commits and relock onto what actually arrived.
    let first = fetch_locked(&lock, &http);
    // Every entry is expected to mismatch here: these are the inherited v1 hashes,
    // which is the 0/390 finding from M1. The point of this pass is the bytes.
    println!(
        "first pass: {} fetched, {} mismatched against the inherited hashes",
        first.fetched.len(),
        first.mismatches.len()
    );
    let relocked = first.relock(&lock);
    assert!(
        !relocked.is_empty(),
        "nothing fetched — cannot assess the gate"
    );

    // 3. The relocked file is signable, and signs.
    relocked
        .signable()
        .expect("a relocked, pinned lockfile must be signable");
    let key = SigningKey::from_bytes(&[0x13; 32]);
    let mut receipt = prepare_receipt(
        &relocked,
        ReceiptDraft {
            event_id: [7u8; 16],
            snapshot_id: [9u8; 16],
            previous_snapshot_hash: None,
            signer_kid: "test:local".to_string(),
        },
    )
    .expect("preparable");
    sign_receipt(&mut receipt, |bytes| {
        Ok::<_, std::convert::Infallible>(key.sign(bytes).to_bytes())
    })
    .expect("signs");
    verify_lock_receipt(&relocked, &receipt, &key.verifying_key().to_bytes())
        .expect("the signed relock must verify");

    // 4. The claim: a second, independent fetch at the same pinned refs reproduces
    //    every digest. This is what a third party would do.
    let second = fetch_locked(&relocked, &http);
    println!(
        "second pass: {}/{} verified, {} mismatched",
        second.verified_count(),
        relocked.len(),
        second.mismatches.len()
    );
    for m in &second.mismatches {
        println!("  MISMATCH {m:?}");
    }
    assert_eq!(
        second.verified_count(),
        relocked.len(),
        "a relocked file must re-verify at 100% against a second fetch of the same refs"
    );

    // 5. And the root is stable across that second derivation.
    let rederived = first.relock(&lock);
    assert_eq!(
        rcx_registry_skills::lock_merkle_root(&relocked).expect("root"),
        rcx_registry_skills::lock_merkle_root(&rederived).expect("root"),
        "the Merkle root must be reproducible"
    );
}
