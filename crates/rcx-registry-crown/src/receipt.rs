use blake3::Hasher;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};

use crate::canonical::CborValue;
use crate::error::CrownError;

pub const HASH_LEN: usize = 32;
pub const SIGNATURE_LEN: usize = 64;
pub const ULID_LEN: usize = 16;

pub trait ReceiptDocument {
    fn to_cbor_value(&self, zero_receipt: bool) -> CborValue;
    fn stored_hash(&self) -> &[u8; HASH_LEN];
    fn stored_signature(&self) -> &[u8; SIGNATURE_LEN];

    fn to_canonical_cbor(&self) -> Vec<u8> {
        self.to_cbor_value(false).encode()
    }

    fn to_zeroed_canonical_cbor(&self) -> Vec<u8> {
        self.to_cbor_value(true).encode()
    }

    fn compute_hash(&self) -> [u8; HASH_LEN] {
        let zeroed = self.to_zeroed_canonical_cbor();
        let mut hasher = Hasher::new();
        hasher.update(&zeroed);
        *hasher.finalize().as_bytes()
    }
}

pub fn verify_receipt_signature(
    document: &impl ReceiptDocument,
    public_key: &[u8],
) -> Result<(), CrownError> {
    if public_key.len() != 32 {
        return Err(CrownError::PublicKeyLength(public_key.len()));
    }

    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(public_key);

    let verifying_key = VerifyingKey::from_bytes(&key_bytes)
        .map_err(|error| CrownError::Decode(format!("bad public key: {error}")))?;
    let signature = Signature::from_bytes(document.stored_signature());
    let computed = document.compute_hash();

    if computed != *document.stored_hash() {
        return Err(CrownError::BadSignature);
    }

    let mut signing_value = document.to_cbor_value(false);
    let CborValue::Map(fields) = &mut signing_value else {
        return Err(CrownError::BadSignature);
    };
    let Some((_, signature_field)) = fields
        .iter_mut()
        .find(|(name, _)| name == "receipt_signature")
    else {
        return Err(CrownError::BadSignature);
    };
    *signature_field = CborValue::Bytes(vec![0u8; SIGNATURE_LEN]);
    let signing_bytes = signing_value.encode();

    verifying_key
        .verify(&signing_bytes, &signature)
        .map_err(|_| CrownError::BadSignature)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotChanges {
    pub added: u64,
    pub removed: u64,
    pub modified: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistrySnapshotReceipt {
    pub event_id: [u8; ULID_LEN],
    pub snapshot_id: [u8; ULID_LEN],
    pub scraped_at: u64,
    pub server_count: u64,
    pub snapshot_merkle_root: [u8; HASH_LEN],
    pub previous_snapshot_hash: Option<[u8; HASH_LEN]>,
    pub upstream_registry_uri: String,
    pub upstream_snapshot_etag: Option<String>,
    pub changes: SnapshotChanges,
    pub receipt_hash: [u8; HASH_LEN],
    pub receipt_signature: [u8; SIGNATURE_LEN],
    pub signer_kid: String,
}

impl ReceiptDocument for RegistrySnapshotReceipt {
    fn to_cbor_value(&self, zero_receipt: bool) -> CborValue {
        CborValue::Map(vec![
            ("event_id".into(), CborValue::Bytes(self.event_id.to_vec())),
            (
                "snapshot_id".into(),
                CborValue::Bytes(self.snapshot_id.to_vec()),
            ),
            ("scraped_at".into(), CborValue::Uint(self.scraped_at)),
            ("server_count".into(), CborValue::Uint(self.server_count)),
            (
                "snapshot_merkle_root".into(),
                CborValue::Bytes(self.snapshot_merkle_root.to_vec()),
            ),
            (
                "previous_snapshot_hash".into(),
                match self.previous_snapshot_hash {
                    Some(hash) => CborValue::Bytes(hash.to_vec()),
                    None => CborValue::Null,
                },
            ),
            (
                "upstream_registry_uri".into(),
                CborValue::Text(self.upstream_registry_uri.clone()),
            ),
            (
                "upstream_snapshot_etag".into(),
                match &self.upstream_snapshot_etag {
                    Some(etag) => CborValue::Text(etag.clone()),
                    None => CborValue::Null,
                },
            ),
            (
                "changes".into(),
                CborValue::Map(vec![
                    ("added".into(), CborValue::Uint(self.changes.added)),
                    ("removed".into(), CborValue::Uint(self.changes.removed)),
                    ("modified".into(), CborValue::Uint(self.changes.modified)),
                ]),
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryAutoEnrichedReceipt {
    pub event_id: [u8; ULID_LEN],
    pub server_name: String,
    pub snapshot_id: [u8; ULID_LEN],
    pub auto_enrichment_bytes: Vec<u8>,
    pub receipt_hash: [u8; HASH_LEN],
    pub receipt_signature: [u8; SIGNATURE_LEN],
    pub signer_kid: String,
}

impl ReceiptDocument for EntryAutoEnrichedReceipt {
    fn to_cbor_value(&self, zero_receipt: bool) -> CborValue {
        CborValue::Map(vec![
            ("event_id".into(), CborValue::Bytes(self.event_id.to_vec())),
            (
                "server_name".into(),
                CborValue::Text(self.server_name.clone()),
            ),
            (
                "snapshot_id".into(),
                CborValue::Bytes(self.snapshot_id.to_vec()),
            ),
            (
                "auto_enrichment_bytes".into(),
                CborValue::Bytes(self.auto_enrichment_bytes.clone()),
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryEnrichedReceipt {
    pub event_id: [u8; ULID_LEN],
    pub server_name: String,
    pub publisher_passport: String,
    pub declared_uri: String,
    pub declared_hash: [u8; HASH_LEN],
    pub enrichment_bytes: Vec<u8>,
    pub supersedes_prior: Option<[u8; HASH_LEN]>,
    pub receipt_hash: [u8; HASH_LEN],
    pub receipt_signature: [u8; SIGNATURE_LEN],
    pub signer_kid: String,
}

impl ReceiptDocument for EntryEnrichedReceipt {
    fn to_cbor_value(&self, zero_receipt: bool) -> CborValue {
        CborValue::Map(vec![
            ("event_id".into(), CborValue::Bytes(self.event_id.to_vec())),
            (
                "server_name".into(),
                CborValue::Text(self.server_name.clone()),
            ),
            (
                "publisher_passport".into(),
                CborValue::Text(self.publisher_passport.clone()),
            ),
            (
                "declared_uri".into(),
                CborValue::Text(self.declared_uri.clone()),
            ),
            (
                "declared_hash".into(),
                CborValue::Bytes(self.declared_hash.to_vec()),
            ),
            (
                "enrichment_bytes".into(),
                CborValue::Bytes(self.enrichment_bytes.clone()),
            ),
            (
                "supersedes_prior".into(),
                match self.supersedes_prior {
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestationAcceptedReceipt {
    pub event_id: [u8; ULID_LEN],
    pub attestation_id: [u8; ULID_LEN],
    pub server_name: String,
    pub issuer_passport: String,
    pub attestation_type: String,
    pub attestation_hash: [u8; HASH_LEN],
    pub attestation_bytes: Vec<u8>,
    pub receipt_hash: [u8; HASH_LEN],
    pub receipt_signature: [u8; SIGNATURE_LEN],
    pub signer_kid: String,
}

impl ReceiptDocument for AttestationAcceptedReceipt {
    fn to_cbor_value(&self, zero_receipt: bool) -> CborValue {
        CborValue::Map(vec![
            ("event_id".into(), CborValue::Bytes(self.event_id.to_vec())),
            (
                "attestation_id".into(),
                CborValue::Bytes(self.attestation_id.to_vec()),
            ),
            (
                "server_name".into(),
                CborValue::Text(self.server_name.clone()),
            ),
            (
                "issuer_passport".into(),
                CborValue::Text(self.issuer_passport.clone()),
            ),
            (
                "type".into(),
                CborValue::Text(self.attestation_type.clone()),
            ),
            (
                "attestation_hash".into(),
                CborValue::Bytes(self.attestation_hash.to_vec()),
            ),
            (
                "attestation_bytes".into(),
                CborValue::Bytes(self.attestation_bytes.clone()),
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestationRevokedReceipt {
    pub event_id: [u8; ULID_LEN],
    pub attestation_id: [u8; ULID_LEN],
    pub revoker_passport: String,
    pub reason: Option<String>,
    pub revoked_at: u64,
    pub revocation_signature: [u8; SIGNATURE_LEN],
    pub receipt_hash: [u8; HASH_LEN],
    pub receipt_signature: [u8; SIGNATURE_LEN],
    pub signer_kid: String,
}

impl ReceiptDocument for AttestationRevokedReceipt {
    fn to_cbor_value(&self, zero_receipt: bool) -> CborValue {
        CborValue::Map(vec![
            ("event_id".into(), CborValue::Bytes(self.event_id.to_vec())),
            (
                "attestation_id".into(),
                CborValue::Bytes(self.attestation_id.to_vec()),
            ),
            (
                "revoker_passport".into(),
                CborValue::Text(self.revoker_passport.clone()),
            ),
            (
                "reason".into(),
                match &self.reason {
                    Some(reason) => CborValue::Text(reason.clone()),
                    None => CborValue::Null,
                },
            ),
            ("revoked_at".into(), CborValue::Uint(self.revoked_at)),
            (
                "revocation_signature".into(),
                CborValue::Bytes(self.revocation_signature.to_vec()),
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublisherRightsVerifiedReceipt {
    pub event_id: [u8; ULID_LEN],
    pub publisher_passport: String,
    pub namespace: String,
    pub verification_method: String,
    pub verified_at: u64,
    pub receipt_hash: [u8; HASH_LEN],
    pub receipt_signature: [u8; SIGNATURE_LEN],
    pub signer_kid: String,
}

impl ReceiptDocument for PublisherRightsVerifiedReceipt {
    fn to_cbor_value(&self, zero_receipt: bool) -> CborValue {
        CborValue::Map(vec![
            ("event_id".into(), CborValue::Bytes(self.event_id.to_vec())),
            (
                "publisher_passport".into(),
                CborValue::Text(self.publisher_passport.clone()),
            ),
            ("namespace".into(), CborValue::Text(self.namespace.clone())),
            (
                "verification_method".into(),
                CborValue::Text(self.verification_method.clone()),
            ),
            ("verified_at".into(), CborValue::Uint(self.verified_at)),
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
