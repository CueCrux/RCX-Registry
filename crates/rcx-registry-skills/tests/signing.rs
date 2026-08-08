//! M2 gate: signing a lockfile, and every way that must fail.
//!
//! The suite is deliberately not all-negative. An inverted comparison in a verifier
//! still rejects bad input — it only breaks *good* input — so a suite made only of
//! tamper cases passes just as happily with the guard backwards. The positive
//! round-trip below is the test that would catch that, and it comes first for that
//! reason.

use std::collections::BTreeMap;

use ed25519_dalek::{Signer, SigningKey};
use rcx_registry_skills::{
    lock_merkle_root, prepare_receipt, sign_receipt, signing_preimage, verify_lock_receipt,
    LockEntry, ReceiptDraft, SkillLock, SkillsError, LOCK_VERSION,
};

const SHA_A: &str = "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678";
const SHA_B: &str = "0fedcba98765432100112233445566778899aabb";
const HASH_A: &str = "4ea04d576507f4a683e6203737c33993fb36add719f628b7200649a9cb87b5fe";
const HASH_B: &str = "fc517263c322bfba196a3da7f3c63fa4e650edaecbe34b966438f03719d8f695";

fn entry(source: &str, git_ref: &str, hash: &str) -> LockEntry {
    LockEntry {
        source: source.into(),
        source_type: "github".into(),
        skill_path: "skills/x/SKILL.md".into(),
        git_ref: git_ref.into(),
        computed_hash: hash.into(),
    }
}

fn signable_lock() -> SkillLock {
    let mut skills = BTreeMap::new();
    skills.insert("ab-testing".to_string(), entry("a/b", SHA_A, HASH_A));
    skills.insert("ad-creative".to_string(), entry("c/d", SHA_B, HASH_B));
    SkillLock {
        version: LOCK_VERSION,
        skills,
    }
}

const SIGNED_AT: u64 = 1_786_147_200_000;

fn draft() -> ReceiptDraft {
    ReceiptDraft {
        event_id: [7u8; 16],
        snapshot_id: [9u8; 16],
        signed_at_ms: SIGNED_AT,
        previous_snapshot_hash: None,
        signer_kid: "vault:transit:rcx-registry-signing-key-1".to_string(),
    }
}

fn sign(lock: &SkillLock, key: &SigningKey) -> rcx_registry_crown::SkillSnapshotReceipt {
    let mut receipt = prepare_receipt(lock, draft()).expect("preparable");
    sign_receipt(&mut receipt, |bytes| {
        Ok::<_, std::convert::Infallible>(key.sign(bytes).to_bytes())
    })
    .expect("signing is infallible here");
    receipt
}

// ── the positive control ─────────────────────────────────────────────────────

#[test]
fn a_signed_lockfile_verifies() {
    let key = SigningKey::from_bytes(&[0x13; 32]);
    let lock = signable_lock();
    let receipt = sign(&lock, &key);

    verify_lock_receipt(&lock, &receipt, &key.verifying_key().to_bytes())
        .expect("a correctly signed lockfile must verify");
}

#[test]
fn the_signing_preimage_is_the_cbor_body_not_the_receipt_hash() {
    // Three distinct byte strings exist here and only one is signable:
    //   1. receipt_hash            — 32 bytes, blake3 over the fully-zeroed body
    //   2. the fully-zeroed CBOR   — what compute_hash() digests
    //   3. the CBOR with ONLY receipt_signature zeroed  ← the preimage
    // Signing (1) was the first implementation of this milestone and produced a
    // signature that never verified, with BadSignature as the only symptom — the
    // same error the verifier returns for a hash mismatch and for a wrong key.
    // This test pins which one is correct so the confusion cannot silently return.
    use rcx_registry_crown::ReceiptDocument;

    let lock = signable_lock();
    let receipt = prepare_receipt(&lock, draft()).expect("preparable");
    let preimage = signing_preimage(&receipt);

    assert_ne!(
        preimage,
        receipt.receipt_hash.to_vec(),
        "the preimage must not be the receipt hash"
    );
    assert_ne!(
        preimage,
        receipt.to_zeroed_canonical_cbor(),
        "the preimage must not be the fully-zeroed body — signer_kid and receipt_hash are live in it"
    );
    assert!(
        preimage.len() > 32,
        "the preimage is a CBOR document, not a digest"
    );

    // Idempotent under an already-populated signature: callers must not have to
    // remember to build it before signing.
    let key = SigningKey::from_bytes(&[0x13; 32]);
    let signed = sign(&lock, &key);
    assert_eq!(
        signing_preimage(&signed),
        preimage,
        "preimage must not depend on what the signature field currently holds"
    );
}

// ── determinism ──────────────────────────────────────────────────────────────

#[test]
fn the_root_is_reproducible_across_independent_constructions() {
    // Two lockfiles built separately, inserted in opposite orders. If the root
    // depended on anything but the content, these would differ.
    let first = signable_lock();
    let mut skills = BTreeMap::new();
    skills.insert("ad-creative".to_string(), entry("c/d", SHA_B, HASH_B));
    skills.insert("ab-testing".to_string(), entry("a/b", SHA_A, HASH_A));
    let second = SkillLock {
        version: LOCK_VERSION,
        skills,
    };

    assert_eq!(
        lock_merkle_root(&first).expect("root"),
        lock_merkle_root(&second).expect("root")
    );
}

#[test]
fn two_runs_with_the_same_inputs_are_identical() {
    // Reproducibility of the *envelope*, given the same caller-supplied event ids
    // and timestamp. Nothing is read from the clock inside the crate.
    let lock = signable_lock();
    let one = prepare_receipt(&lock, draft()).expect("preparable");
    let two = prepare_receipt(&lock, draft()).expect("preparable");
    assert_eq!(one.receipt_hash, two.receipt_hash);
    assert_eq!(one.lock_merkle_root, two.lock_merkle_root);
}

#[test]
fn the_timestamp_never_reaches_the_merkle_root() {
    // The load-bearing boundary. `signed_at_ms` must change the receipt (so it is
    // covered by the signature and cannot be back-dated) while leaving the root
    // untouched (so a third party who re-fetches the same commits still derives
    // the same value). Getting this backwards costs either auditability or
    // verifiability, and the failure is silent in both directions.
    let lock = signable_lock();
    let early = prepare_receipt(&lock, draft()).expect("preparable");
    let later = prepare_receipt(
        &lock,
        ReceiptDraft {
            signed_at_ms: SIGNED_AT + 86_400_000,
            ..draft()
        },
    )
    .expect("preparable");

    assert_eq!(
        early.lock_merkle_root, later.lock_merkle_root,
        "the timestamp must not enter the Merkle root"
    );
    assert_ne!(
        early.receipt_hash, later.receipt_hash,
        "the timestamp must be covered by the receipt hash, or it could be rewritten freely"
    );

    // And both still verify against their own signatures.
    let key = SigningKey::from_bytes(&[0x13; 32]);
    for mut receipt in [early, later] {
        sign_receipt(&mut receipt, |b| {
            Ok::<_, std::convert::Infallible>(key.sign(b).to_bytes())
        })
        .expect("signs");
        verify_lock_receipt(&lock, &receipt, &key.verifying_key().to_bytes())
            .expect("a timestamped receipt must still verify");
    }
}

#[test]
fn a_back_dated_timestamp_breaks_the_signature() {
    let key = SigningKey::from_bytes(&[0x13; 32]);
    let lock = signable_lock();
    let mut receipt = sign(&lock, &key);
    receipt.signed_at_ms -= 86_400_000;
    assert!(
        verify_lock_receipt(&lock, &receipt, &key.verifying_key().to_bytes()).is_err(),
        "rewriting signed_at_ms must invalidate the receipt"
    );
}

#[test]
fn receipt_hash_ignores_the_receipt_envelope_fields() {
    // Mirrors crown's own invariant: the hash is over the zeroed body, so the
    // signature, stored hash and key id cannot feed back into it.
    let lock = signable_lock();
    let base = prepare_receipt(&lock, draft()).expect("preparable");
    let mut variant = base.clone();
    variant.receipt_hash = [0x99; 32];
    variant.receipt_signature = [0xaa; 64];
    variant.signer_kid = "vault:transit:rotated".to_string();

    use rcx_registry_crown::ReceiptDocument;
    assert_eq!(base.compute_hash(), variant.compute_hash());
}

// ── every field must move the root ───────────────────────────────────────────

#[test]
fn every_identifying_field_changes_the_root() {
    let base = lock_merkle_root(&signable_lock()).expect("root");

    /// One named mutation of a lock entry.
    type Mutation = (&'static str, Box<dyn Fn(&mut LockEntry)>);

    let mutations: Vec<Mutation> = vec![
        (
            "source",
            Box::new(|e: &mut LockEntry| e.source = "evil/repo".into()),
        ),
        (
            "sourceType",
            Box::new(|e: &mut LockEntry| e.source_type = "gitlab".into()),
        ),
        (
            "skillPath",
            Box::new(|e: &mut LockEntry| e.skill_path = "other/SKILL.md".into()),
        ),
        (
            "ref",
            Box::new(|e: &mut LockEntry| e.git_ref = SHA_B.into()),
        ),
        (
            "computedHash",
            Box::new(|e: &mut LockEntry| e.computed_hash = HASH_B.into()),
        ),
    ];

    for (field, mutate) in mutations {
        let mut lock = signable_lock();
        mutate(lock.skills.get_mut("ab-testing").expect("present"));
        assert_ne!(
            base,
            lock_merkle_root(&lock).expect("root"),
            "changing {field} must move the Merkle root"
        );
    }

    // Renaming a skill moves it too — the name is a leaf field, not just a map key.
    let mut renamed = signable_lock();
    let e = renamed.skills.remove("ab-testing").expect("present");
    renamed.skills.insert("ab-testing-evil".to_string(), e);
    assert_ne!(base, lock_merkle_root(&renamed).expect("root"));
}

// ── tamper and substitution ──────────────────────────────────────────────────

#[test]
fn a_flipped_content_hash_fails_verification() {
    let key = SigningKey::from_bytes(&[0x13; 32]);
    let lock = signable_lock();
    let receipt = sign(&lock, &key);

    let mut tampered = lock.clone();
    tampered
        .skills
        .get_mut("ab-testing")
        .expect("present")
        .computed_hash
        .replace_range(0..1, "c");

    assert!(
        verify_lock_receipt(&tampered, &receipt, &key.verifying_key().to_bytes()).is_err(),
        "a single flipped byte in any computedHash must fail verification"
    );
}

#[test]
fn a_validly_signed_receipt_for_another_lockfile_is_rejected() {
    // The substitution a lockfile signature exists to prevent: the signature is
    // genuine, the receipt is intact, and it simply describes a different set of
    // skills. Verifying only the signature would accept this.
    let key = SigningKey::from_bytes(&[0x13; 32]);
    let signed_lock = signable_lock();
    let receipt = sign(&signed_lock, &key);

    let mut other = signable_lock();
    other
        .skills
        .insert("smuggled".to_string(), entry("evil/repo", SHA_B, HASH_B));

    let err = verify_lock_receipt(&other, &receipt, &key.verifying_key().to_bytes())
        .expect_err("must reject");
    assert!(
        format!("{err}").contains("does not match this lockfile")
            || format!("{err}").contains("does not describe this lockfile"),
        "unexpected rejection reason: {err}"
    );
}

#[test]
fn a_wrong_skill_count_alone_is_rejected() {
    // Independently from the version check. cargo-mutants showed the two were
    // `||`-joined and no test tripped only one, so flipping to `&&` survived.
    let key = SigningKey::from_bytes(&[0x13; 32]);
    let lock = signable_lock();
    let mut receipt = sign(&lock, &key);
    receipt.skill_count = lock.len() as u64 + 1;
    receipt.receipt_hash = {
        use rcx_registry_crown::ReceiptDocument;
        receipt.compute_hash()
    };
    sign_receipt(&mut receipt, |b| {
        Ok::<_, std::convert::Infallible>(key.sign(b).to_bytes())
    })
    .expect("re-sign");

    let err = verify_lock_receipt(&lock, &receipt, &key.verifying_key().to_bytes())
        .expect_err("a re-signed receipt with the wrong count must still be rejected");
    assert!(format!("{err}").contains("skills"), "got: {err}");
}

#[test]
fn a_wrong_lock_version_alone_is_rejected() {
    let key = SigningKey::from_bytes(&[0x13; 32]);
    let lock = signable_lock();
    let mut receipt = sign(&lock, &key);
    receipt.lock_version = u64::from(LOCK_VERSION) + 1;
    sign_receipt(&mut receipt, |b| {
        Ok::<_, std::convert::Infallible>(key.sign(b).to_bytes())
    })
    .expect("re-sign");

    let err = verify_lock_receipt(&lock, &receipt, &key.verifying_key().to_bytes())
        .expect_err("a re-signed receipt for another lock version must be rejected");
    assert!(format!("{err}").contains("version"), "got: {err}");
}

#[test]
fn a_receipt_signed_by_the_wrong_key_is_rejected() {
    let real = SigningKey::from_bytes(&[0x13; 32]);
    let impostor = SigningKey::from_bytes(&[0x99; 32]);
    let lock = signable_lock();
    let receipt = sign(&lock, &impostor);

    // Assert *why* it was rejected, not merely that it was. A bare `is_err()` on a
    // verify path passes just as happily when the rejection comes from somewhere
    // else entirely — a broken `signable()` would satisfy it while the signature
    // check itself was dead.
    let err = verify_lock_receipt(&lock, &receipt, &real.verifying_key().to_bytes())
        .expect_err("an impostor signature must be rejected");
    assert!(
        format!("{err}").contains("signature did not verify"),
        "expected rejection on the signature, got: {err}"
    );
}

#[test]
fn a_mutated_receipt_body_is_rejected() {
    let key = SigningKey::from_bytes(&[0x13; 32]);
    let lock = signable_lock();
    let mut receipt = sign(&lock, &key);
    receipt.skill_count += 1;

    // Mutating the body after signing must trip the *signature*, not the metadata
    // comparison further down: the receipt hash is recomputed over the body, so a
    // changed field breaks the signature before anything semantic is checked.
    // Pinning that means a reordering of the checks shows up here instead of
    // silently changing which guard is load-bearing.
    let err = verify_lock_receipt(&lock, &receipt, &key.verifying_key().to_bytes())
        .expect_err("a mutated body must be rejected");
    assert!(
        format!("{err}").contains("signature did not verify"),
        "expected rejection on the signature, got: {err}"
    );
}

// ── refusal to sign ──────────────────────────────────────────────────────────

#[test]
fn a_v1_lockfile_cannot_be_signed() {
    let mut lock = signable_lock();
    lock.version = 1;
    for e in lock.skills.values_mut() {
        e.git_ref.clear();
    }
    match lock.signable() {
        Err(SkillsError::NotSignable { reason }) => {
            assert!(
                reason.contains("below the minimum signable"),
                "got: {reason}"
            )
        }
        other => panic!("expected NotSignable, got {other:?}"),
    }
    assert!(
        lock_merkle_root(&lock).is_err(),
        "no root for an unsignable lockfile"
    );
    assert!(
        prepare_receipt(&lock, draft()).is_err(),
        "no receipt either"
    );
}

#[test]
fn an_empty_lockfile_cannot_be_signed() {
    let lock = SkillLock {
        version: LOCK_VERSION,
        skills: BTreeMap::new(),
    };
    assert!(matches!(
        lock.signable(),
        Err(SkillsError::NotSignable { .. })
    ));
}

#[test]
fn a_ref_that_is_not_a_full_commit_id_cannot_be_signed() {
    for bad in [
        "",                                         // v1 entry carried forward
        "main",                                     // a branch: a moving target
        "HEAD",                                     // likewise
        "1111111",                                  // abbreviated, ambiguous
        &SHA_A.to_uppercase(),                      // two spellings of one id
        &format!("{SHA_A}1"),                       // over-long
        "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", // right length, not hex
    ] {
        let mut lock = signable_lock();
        lock.skills.get_mut("ab-testing").expect("present").git_ref = bad.to_string();
        assert!(
            matches!(lock.signable(), Err(SkillsError::NotSignable { .. })),
            "expected ref {bad:?} to be refused"
        );
    }
}

#[test]
fn one_unpinned_entry_blocks_the_whole_lockfile() {
    // Partial pinning is the dangerous middle: a lockfile that is "mostly" signable
    // would attest a set containing an unattributable member.
    let mut lock = signable_lock();
    lock.skills
        .insert("unpinned".to_string(), entry("e/f", "", HASH_A));
    assert!(matches!(
        lock.signable(),
        Err(SkillsError::NotSignable { .. })
    ));
}
