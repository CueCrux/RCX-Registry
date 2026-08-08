//! Gate tests for M1, run against the real 390-entry lockfile rather than a
//! hand-written stub — a synthetic fixture would not catch the formatting and
//! ordering details that make the round-trip byte-exact.

use rcx_registry_skills::{SkillLock, SkillsError};

const RAW: &str = include_str!("fixtures/skills-lock.json");

#[test]
fn real_lockfile_parses() {
    let lock = SkillLock::from_json(RAW).expect("the shipped lockfile must parse");
    assert_eq!(lock.version, 1);
    assert_eq!(
        lock.len(),
        390,
        "entry count changed — re-verify the fixture"
    );
}

#[test]
fn real_lockfile_round_trips_byte_identically() {
    let lock = SkillLock::from_json(RAW).expect("parses");
    let out = lock.to_json().expect("serialises");
    assert_eq!(
        out.len(),
        RAW.len(),
        "byte length differs: {} vs {}",
        out.len(),
        RAW.len()
    );
    assert!(
        out == RAW,
        "re-serialised lockfile is not byte-identical to the original"
    );
}

#[test]
fn round_trip_is_stable_across_two_passes() {
    // Idempotence, not just equality: the signed snapshot in the trust layer is
    // taken over this output, so a second pass drifting would break verification
    // on re-ingest rather than at write time.
    let once = SkillLock::from_json(RAW)
        .expect("parses")
        .to_json()
        .expect("serialises");
    let twice = SkillLock::from_json(&once)
        .expect("re-parses")
        .to_json()
        .expect("re-serialises");
    assert_eq!(once, twice);
}

#[test]
fn a_single_corrupted_hash_fails_closed() {
    // Flip one character of one entry's digest. The whole lockfile must be
    // rejected — an ingest that accepts 389 of 390 and carries on is exactly the
    // partial-trust failure this gate exists to prevent.
    let lock = SkillLock::from_json(RAW).expect("parses");
    let victim = lock.skills.keys().next().expect("non-empty").clone();
    let mut corrupted = lock.clone();
    let entry = corrupted.skills.get_mut(&victim).expect("victim present");
    entry.computed_hash.replace_range(0..1, "z");

    match corrupted.validate() {
        Err(SkillsError::BadHash { name, .. }) => assert_eq!(name, victim),
        other => panic!("expected BadHash for {victim}, got {other:?}"),
    }

    // And it must fail on the parse path too, not only when validate() is called
    // explicitly — callers should not have to remember.
    let json = serde_json::to_string(&corrupted).expect("serialises");
    assert!(matches!(
        SkillLock::from_json(&json),
        Err(SkillsError::BadHash { .. })
    ));
}

#[test]
fn every_entry_is_a_supported_source() {
    let lock = SkillLock::from_json(RAW).expect("parses");
    assert!(
        lock.validate().is_ok(),
        "fixture should contain only github sources"
    );
}
