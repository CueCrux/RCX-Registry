//! Receipt over a skills lockfile.
//!
//! Structurally the sibling of [`RegistrySnapshotReceipt`](crate::RegistrySnapshotReceipt)
//! — same canonical-CBOR encoding, same zeroed-field signing idiom — with one
//! deliberate difference: **there is no timestamp in the signed body.**
//!
//! `RegistrySnapshotReceipt` carries `scraped_at` because a mirror snapshot is a
//! statement about a moment. A skills lockfile is not: it is a statement about a
//! set of `(skill, commit, content-hash)` triples, every one of which is immutable.
//! Two people who fetch the same refs must be able to compute the same root and get
//! the same receipt hash — that is what makes the signature independently checkable
//! rather than merely present. A timestamp would make every re-derivation differ
//! and quietly reduce verification to "trust the operator's copy".
//!
//! The ULID identifiers are *not* part of that guarantee: they name this particular
//! signing event. The reproducible artefact is `lock_merkle_root`.
//!
//! A signature here attests **origin, not safety** — that these bytes are what the
//! named signer published. It says nothing about whether the skill is malicious.

use crate::canonical::CborValue;
use crate::receipt::{ReceiptDocument, HASH_LEN, SIGNATURE_LEN, ULID_LEN};

/// Minimum lockfile version that may be signed.
///
/// v1 lockfiles pin a content hash but no commit ref, so a digest mismatch cannot
/// distinguish an upstream edit from tampering — signing one would attest a claim
/// nobody can check. Enforced at the ingest boundary; restated here because this is
/// where the guarantee is made public.
pub const MIN_SIGNABLE_LOCK_VERSION: u64 = 2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkillSnapshotReceipt {
    pub event_id: [u8; ULID_LEN],
    pub snapshot_id: [u8; ULID_LEN],
    /// Number of skills in the signed lockfile.
    pub skill_count: u64,
    /// Lockfile schema version. Below [`MIN_SIGNABLE_LOCK_VERSION`] this receipt
    /// must never have been minted.
    pub lock_version: u64,
    /// blake3 Merkle root over the lock entries, per `snapshot_merkle_root`.
    pub lock_merkle_root: [u8; HASH_LEN],
    /// Hash of the previous skills snapshot receipt, chaining the history.
    pub previous_snapshot_hash: Option<[u8; HASH_LEN]>,
    pub receipt_hash: [u8; HASH_LEN],
    pub receipt_signature: [u8; SIGNATURE_LEN],
    pub signer_kid: String,
}

impl ReceiptDocument for SkillSnapshotReceipt {
    fn to_cbor_value(&self, zero_receipt: bool) -> CborValue {
        CborValue::Map(vec![
            ("event_id".into(), CborValue::Bytes(self.event_id.to_vec())),
            (
                "snapshot_id".into(),
                CborValue::Bytes(self.snapshot_id.to_vec()),
            ),
            ("skill_count".into(), CborValue::Uint(self.skill_count)),
            ("lock_version".into(), CborValue::Uint(self.lock_version)),
            (
                "lock_merkle_root".into(),
                CborValue::Bytes(self.lock_merkle_root.to_vec()),
            ),
            (
                "previous_snapshot_hash".into(),
                match self.previous_snapshot_hash {
                    Some(hash) => CborValue::Bytes(hash.to_vec()),
                    None => CborValue::Null,
                },
            ),
            (
                "receipt_hash".into(),
                CborValue::Bytes(if zero_receipt {
                    vec![0u8; HASH_LEN]
                } else {
                    self.receipt_hash.to_vec()
                }),
            ),
            (
                "receipt_signature".into(),
                CborValue::Bytes(if zero_receipt {
                    vec![0u8; SIGNATURE_LEN]
                } else {
                    self.receipt_signature.to_vec()
                }),
            ),
            (
                "signer_kid".into(),
                if zero_receipt {
                    CborValue::Null
                } else {
                    CborValue::Text(self.signer_kid.clone())
                },
            ),
        ])
    }

    fn stored_hash(&self) -> &[u8; HASH_LEN] {
        &self.receipt_hash
    }

    fn stored_signature(&self) -> &[u8; SIGNATURE_LEN] {
        &self.receipt_signature
    }
}
