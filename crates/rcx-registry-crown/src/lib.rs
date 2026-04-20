//! RCX-Registry receipt and canonicalization primitives.
//!
//! The canonical-CBOR and canonical-JSON behavior here deliberately mirrors the
//! existing RCX-Protocol implementation in the sibling `Crux` repository for the
//! overlapping type set.

mod canonical;
mod error;
mod receipt;

pub use canonical::{decode, to_canonical_json, CborValue};
pub use error::CrownError;
pub use receipt::{
    verify_receipt_signature, AttestationAcceptedReceipt, AttestationRevokedReceipt,
    EntryAutoEnrichedReceipt, EntryEnrichedReceipt, PublisherRightsVerifiedReceipt,
    ReceiptDocument, RegistrySnapshotReceipt, SnapshotChanges, HASH_LEN, SIGNATURE_LEN, ULID_LEN,
};

#[cfg(test)]
mod tests;
