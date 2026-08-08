//! Signing a lockfile, and checking a signature over one.
//!
//! The chain is: lockfile → Merkle root → receipt → ed25519 signature. Each step
//! reuses the construction the registry already uses for MCP server snapshots
//! (`snapshot_merkle_root`, `ReceiptDocument`, `verify_receipt_signature`), so a
//! skills receipt verifies with the same code path a server receipt does.
//!
//! ## What a signature here does and does not mean
//!
//! It attests that **the named signer published these bytes**: this set of skills,
//! at these commits, with these content hashes. Anyone can refetch the same refs and
//! recompute the same root.
//!
//! It does **not** attest that any skill is safe. A skill body joins the agent's
//! prompt and may execute code; signing a malicious skill produces a validly signed
//! malicious skill. Surfaces built on this must say "published by X" and never
//! "safe" — a signature that reads as a safety claim is worse than no signature,
//! because it is believed.

use rcx_registry_crown::{
    canonicalize_json, snapshot_merkle_root, verify_receipt_signature, CrownError, ReceiptDocument,
    SkillSnapshotReceipt, SnapshotEntry, HASH_LEN,
};
use serde_json::json;

use crate::error::SkillsError;
use crate::lock::SkillLock;

/// Project a lockfile onto the digest entries the Merkle root is taken over.
///
/// `version` in the digest is the **commit ref**, not a semver: it is what makes
/// two lockings of the same skill at different commits distinct leaves. Entries are
/// framed and sorted inside `snapshot_merkle_root`, so map iteration order here
/// cannot affect the root.
pub fn digest_entries(lock: &SkillLock) -> Vec<SnapshotEntry> {
    lock.skills
        .iter()
        .map(|(name, entry)| {
            // Every field that identifies the content enters the digest. `source`
            // and `skillPath` are included because the same bytes fetched from a
            // different repo is a different provenance claim, and the root must
            // move when provenance moves.
            let canonical = canonicalize_json(&json!({
                "source": entry.source,
                "sourceType": entry.source_type,
                "skillPath": entry.skill_path,
                "ref": entry.git_ref,
                "computedHash": entry.computed_hash,
            }));
            SnapshotEntry::new(name.clone(), entry.git_ref.clone(), canonical)
        })
        .collect()
}

/// Merkle root over a lockfile.
///
/// Refuses unsignable lockfiles rather than returning a root nobody should use —
/// a root is only meaningful if the entries under it can be re-derived.
pub fn lock_merkle_root(lock: &SkillLock) -> Result<[u8; HASH_LEN], SkillsError> {
    lock.signable()?;
    Ok(snapshot_merkle_root(&digest_entries(lock)))
}

/// Everything about a receipt except the signature, which the caller's signer
/// produces. Identifiers are caller-supplied so the reproducible part of the
/// receipt stays reproducible.
pub struct ReceiptDraft {
    pub event_id: [u8; 16],
    pub snapshot_id: [u8; 16],
    /// Unix milliseconds to stamp into the signed body. Caller-supplied rather
    /// than read from the clock here, so a test can pin it and a replay can
    /// reproduce a historical receipt exactly.
    pub signed_at_ms: u64,
    pub previous_snapshot_hash: Option<[u8; HASH_LEN]>,
    pub signer_kid: String,
}

/// Build the receipt and its hash for `lock`, leaving the signature zeroed.
///
/// Split from signing so the hash can be computed without holding a key — the
/// server signs through Vault Transit, which never exposes one.
pub fn prepare_receipt(
    lock: &SkillLock,
    draft: ReceiptDraft,
) -> Result<SkillSnapshotReceipt, SkillsError> {
    let root = lock_merkle_root(lock)?;
    let mut receipt = SkillSnapshotReceipt {
        event_id: draft.event_id,
        snapshot_id: draft.snapshot_id,
        signed_at_ms: draft.signed_at_ms,
        skill_count: lock.len() as u64,
        lock_version: u64::from(lock.version),
        lock_merkle_root: root,
        previous_snapshot_hash: draft.previous_snapshot_hash,
        receipt_hash: [0u8; HASH_LEN],
        receipt_signature: [0u8; 64],
        signer_kid: draft.signer_kid,
    };
    receipt.receipt_hash = receipt.compute_hash();
    Ok(receipt)
}

/// Exact bytes a signer must sign for `receipt`.
///
/// The preimage is the canonical CBOR of the **whole** receipt with only
/// `receipt_signature` zeroed — not the receipt hash, and not the fully-zeroed body
/// that `compute_hash` uses. Three different byte strings are in play and signing
/// the wrong one produces a signature that never verifies, with `BadSignature` as
/// the only symptom for all three.
///
/// Crown has no exported helper for this, so callers reconstruct it by knowing to
/// call `to_canonical_cbor()` *before* populating the signature field. That ordering
/// requirement is invisible at the call site and easy to get backwards. This function
/// zeroes the field itself, so it is correct whatever the receipt currently holds.
pub fn signing_preimage(receipt: &SkillSnapshotReceipt) -> Vec<u8> {
    let mut unsigned = receipt.clone();
    unsigned.receipt_signature = [0u8; 64];
    unsigned.to_canonical_cbor()
}

/// Sign `receipt` in place with a caller-supplied signer.
///
/// The closure shape matches the server's Vault Transit signer, which never exposes
/// a key — so this works for both a local test key and the production HSM path
/// without either one reimplementing the preimage rule above.
pub fn sign_receipt<E>(
    receipt: &mut SkillSnapshotReceipt,
    sign: impl FnOnce(&[u8]) -> Result<[u8; 64], E>,
) -> Result<(), E> {
    // Recompute rather than trust: a caller who mutated the body after
    // `prepare_receipt` would otherwise sign a preimage that disagrees with the
    // stored hash, and fail verification at the hash check with no clue why.
    receipt.receipt_hash = receipt.compute_hash();
    receipt.receipt_signature = sign(&signing_preimage(receipt))?;
    Ok(())
}

/// Check a receipt against a lockfile and a public key.
///
/// Both halves are required and neither implies the other: the signature proves the
/// receipt came from the signer, and the root comparison proves the receipt is about
/// *this* lockfile. Verifying only the signature would accept a validly signed
/// receipt for a different set of skills — the substitution a lockfile signature
/// exists to prevent.
pub fn verify_lock_receipt(
    lock: &SkillLock,
    receipt: &SkillSnapshotReceipt,
    public_key: &[u8],
) -> Result<(), SkillsError> {
    verify_receipt_signature(receipt, public_key).map_err(|error: CrownError| {
        SkillsError::NotSignable {
            reason: format!("receipt signature did not verify: {error}"),
        }
    })?;

    let recomputed = lock_merkle_root(lock)?;
    if recomputed != receipt.lock_merkle_root {
        return Err(SkillsError::NotSignable {
            reason: "receipt is validly signed but its Merkle root does not match this lockfile"
                .to_string(),
        });
    }

    // Split rather than `||`-joined: a combined condition is satisfied by either
    // half, so a test that trips both at once never proves the other is checked.
    // `cargo-mutants` flagged exactly that — flipping the `||` to `&&` survived the
    // whole suite, because every case that changed the count also changed the root.
    if u64::from(lock.version) != receipt.lock_version {
        return Err(SkillsError::NotSignable {
            reason: format!(
                "receipt describes lock version {} but this lockfile is version {}",
                receipt.lock_version, lock.version
            ),
        });
    }
    if lock.len() as u64 != receipt.skill_count {
        return Err(SkillsError::NotSignable {
            reason: format!(
                "receipt describes {} skills but this lockfile has {}",
                receipt.skill_count,
                lock.len()
            ),
        });
    }
    Ok(())
}
