//! Live-network half of the M1 gate: fetch every locked skill and verify its hash.
//!
//! `#[ignore]` by default — it makes 390 HTTP requests to raw.githubusercontent.com,
//! which has no place in the standard lane. Run it deliberately:
//!
//! ```text
//! cargo test -p rcx-registry-skills --test fetch_live -- --ignored --nocapture
//! ```
//!
//! Mismatches are expected over time and are not automatically a failure: the
//! lockfile pins content but not a ref, so an upstream edit and a tamper look
//! identical from here. The test's job is to *name* every one.

use rcx_registry_skills::{fetch_locked, Mismatch, SkillLock};

const RAW: &str = include_str!("fixtures/skills-lock.json");

#[test]
#[ignore = "network: 390 requests to raw.githubusercontent.com"]
fn every_locked_skill_fetches_and_verifies() {
    let lock = SkillLock::from_json(RAW).expect("parses");
    let client = reqwest::blocking::Client::builder()
        .user_agent("rcx-registry-skills/0")
        .timeout(std::time::Duration::from_secs(20))
        .build()
        .expect("client");

    let outcome = fetch_locked(&lock, &client);

    println!(
        "verified {}/{} · mismatches {}",
        outcome.verified_count(),
        lock.len(),
        outcome.mismatches.len()
    );
    for m in &outcome.mismatches {
        match m {
            Mismatch::Digest {
                name,
                source,
                expected,
                actual,
            } => {
                println!("DIGEST     {name} [{source}] expected={expected} actual={actual}");
            }
            Mismatch::Unreachable {
                name,
                source,
                detail,
            } => {
                println!("UNREACHABLE {name} [{source}] {detail}");
            }
        }
    }

    assert_eq!(
        outcome.verified_count() + outcome.mismatches.len(),
        lock.len(),
        "every entry must be accounted for, verified or named"
    );
}
