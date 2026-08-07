#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used)]

//! Offline verification for the RCX protocol (`rcx-spec/v1`).
//!
//! Five verbs, defined language-neutrally in [`CONTRACT.md`](../CONTRACT.md) and
//! implemented identically across the Rust/TS/Python/Go SDKs:
//!
//! | Verb | Answers |
//! |---|---|
//! | [`verify_receipt`] | is this receipt's hash and signature sound? |
//! | [`verify_snapshot`] | does this server set digest to the published root? |
//! | [`verify_publisher`] | does this declaration hash to what was published? |
//! | [`verify_namespace`] | is this namespace bound to the passport claiming it? |
//! | [`verify_history`] | is this receipt chain unbroken? |
//!
//! Every verb is offline: no socket, no DNS, no clock. Verification operates on
//! bytes the caller already holds, which is the whole point — a verifier that has
//! to ask the registry whether the registry is honest has verified nothing.

use blake3::Hasher;
use ed25519_dalek::{Signature, VerifyingKey};
use rcx_registry_crown::{
    canonicalize_json, decode, snapshot_merkle_root, CborValue, SnapshotEntry,
};
use serde_json::Value;
use thiserror::Error;

pub use rcx_registry_crown::hashing::SnapshotDigestEntry;
pub use rcx_registry_crown::SnapshotEntry as Entry;

const HASH_LEN: usize = 32;
const SIGNATURE_LEN: usize = 64;
const PUBLIC_KEY_LEN: usize = 32;

const FIELD_RECEIPT_HASH: &str = "receipt_hash";
const FIELD_RECEIPT_SIGNATURE: &str = "receipt_signature";
const FIELD_SIGNER_KID: &str = "signer_kid";
const FIELD_SNAPSHOT_ROOT: &str = "snapshot_merkle_root";
const FIELD_PREVIOUS_SNAPSHOT_HASH: &str = "previous_snapshot_hash";
const FIELD_SUPERSEDES_PRIOR: &str = "supersedes_prior";

/// Why verification failed. Codes are frozen for `rcx-verify-contract/1`
/// (CONTRACT.md §6) — they may gain detail but must not be renamed.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum VerifyError {
    /// Input decoded, but re-encoding did not reproduce it byte for byte, so it
    /// was not canonical CBOR. Rejected rather than silently normalised.
    #[error("not_canonical")]
    NotCanonical,
    #[error("missing_field: {0}")]
    MissingField(&'static str),
    #[error("hash_mismatch")]
    HashMismatch,
    #[error("bad_signature")]
    BadSignature,
    #[error("root_mismatch")]
    RootMismatch,
    #[error("declaration_hash_mismatch")]
    DeclarationHashMismatch,
    #[error("namespace_mismatch")]
    NamespaceMismatch,
    #[error("chain_broken at link {link}")]
    ChainBroken { link: usize },
    #[error("bad_public_key: length {0}")]
    BadPublicKey(usize),
    #[error("decode_error: {0}")]
    DecodeError(String),
}

impl VerifyError {
    /// The frozen wire code, without the detail suffix — what an adapter reports.
    pub fn code(&self) -> &'static str {
        match self {
            Self::NotCanonical => "not_canonical",
            Self::MissingField(_) => "missing_field",
            Self::HashMismatch => "hash_mismatch",
            Self::BadSignature => "bad_signature",
            Self::RootMismatch => "root_mismatch",
            Self::DeclarationHashMismatch => "declaration_hash_mismatch",
            Self::NamespaceMismatch => "namespace_mismatch",
            Self::ChainBroken { .. } => "chain_broken",
            Self::BadPublicKey(_) => "bad_public_key",
            Self::DecodeError(_) => "decode_error",
        }
    }
}

/// What a verified receipt tells you, so a caller can chain without re-decoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiptFacts {
    pub receipt_hash: [u8; HASH_LEN],
    pub signer_kid: String,
    /// `snapshot_merkle_root`, present only on `RegistrySnapshot` receipts —
    /// this is what a snapshot chain's next link points back to.
    pub snapshot_root: Option<[u8; HASH_LEN]>,
}

/// Which field carries the backward link, and what it points at.
///
/// Taken explicitly and never inferred: snapshot chains link root-to-root while
/// enrichment chains link receipt-to-receipt (CONTRACT.md §5), so guessing wrong
/// fails a sound chain for a reason that looks like tampering.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainKind {
    /// `previous_snapshot_hash` → prior link's `snapshot_merkle_root`.
    Snapshot,
    /// `supersedes_prior` → prior link's `receipt_hash`.
    EntryEnriched,
}

// ---------------------------------------------------------------------------
// 1. verifyReceipt
// ---------------------------------------------------------------------------

/// Verify a CROWN receipt from its canonical CBOR bytes (CONTRACT.md §1).
///
/// Generic over receipt type by construction: every step is map-level, so all six
/// receipt types verify through this one path with no typed decoding — which is
/// also why it works on bytes a third party fetched, rather than on structs only
/// this repository can build.
pub fn verify_receipt(
    signed_canonical_cbor: &[u8],
    public_key: &[u8],
) -> Result<ReceiptFacts, VerifyError> {
    if public_key.len() != PUBLIC_KEY_LEN {
        return Err(VerifyError::BadPublicKey(public_key.len()));
    }

    let value =
        decode(signed_canonical_cbor).map_err(|e| VerifyError::DecodeError(e.to_string()))?;

    // A non-canonical encoding must never verify, even if it decodes cleanly.
    // Canonical CBOR is deterministic (spec §2), so a faithful input round-trips;
    // anything else was re-sorted on the way in (OQ-6) and is rejected here
    // rather than accepted under a hash of different bytes.
    if value.encode() != signed_canonical_cbor {
        return Err(VerifyError::NotCanonical);
    }

    let CborValue::Map(fields) = &value else {
        return Err(VerifyError::DecodeError("receipt is not a CBOR map".into()));
    };

    let stored_hash = take_bytes(fields, FIELD_RECEIPT_HASH, HASH_LEN)?;
    let stored_signature = take_bytes(fields, FIELD_RECEIPT_SIGNATURE, SIGNATURE_LEN)?;
    let signer_kid = match lookup(fields, FIELD_SIGNER_KID) {
        Some(CborValue::Text(kid)) => kid.clone(),
        Some(_) => return Err(VerifyError::DecodeError("signer_kid is not text".into())),
        None => return Err(VerifyError::MissingField(FIELD_SIGNER_KID)),
    };

    // Step 3 — hash over the ZEROED-field encoding (spec §5.3).
    let zeroed = zero_fields(
        &value,
        &[
            FIELD_RECEIPT_HASH,
            FIELD_RECEIPT_SIGNATURE,
            FIELD_SIGNER_KID,
        ],
    );
    let mut hasher = Hasher::new();
    hasher.update(&zeroed.encode());
    if *hasher.finalize().as_bytes() != stored_hash[..] {
        return Err(VerifyError::HashMismatch);
    }

    // Step 4 — signature over the FULL encoding with ONLY the signature zeroed.
    // A different preimage from step 3; conflating them is the OQ-1 defect.
    let signing_preimage = zero_fields(&value, &[FIELD_RECEIPT_SIGNATURE]).encode();

    let mut key = [0u8; PUBLIC_KEY_LEN];
    key.copy_from_slice(public_key);
    let verifying_key =
        VerifyingKey::from_bytes(&key).map_err(|_| VerifyError::BadPublicKey(public_key.len()))?;
    let mut sig = [0u8; SIGNATURE_LEN];
    sig.copy_from_slice(&stored_signature);
    verifying_key
        .verify_strict(&signing_preimage, &Signature::from_bytes(&sig))
        .map_err(|_| VerifyError::BadSignature)?;

    let mut receipt_hash = [0u8; HASH_LEN];
    receipt_hash.copy_from_slice(&stored_hash);

    let snapshot_root = match lookup(fields, FIELD_SNAPSHOT_ROOT) {
        Some(CborValue::Bytes(bytes)) if bytes.len() == HASH_LEN => {
            let mut root = [0u8; HASH_LEN];
            root.copy_from_slice(bytes);
            Some(root)
        }
        _ => None,
    };

    Ok(ReceiptFacts {
        receipt_hash,
        signer_kid,
        snapshot_root,
    })
}

// ---------------------------------------------------------------------------
// 2. verifySnapshot
// ---------------------------------------------------------------------------

/// Recompute the snapshot set digest and compare to the published root (§2).
pub fn verify_snapshot<E: SnapshotDigestEntry>(
    entries: &[E],
    expected_root: &[u8; HASH_LEN],
) -> Result<(), VerifyError> {
    if snapshot_merkle_root(entries) == *expected_root {
        Ok(())
    } else {
        Err(VerifyError::RootMismatch)
    }
}

// ---------------------------------------------------------------------------
// 3. verifyPublisher
// ---------------------------------------------------------------------------

/// Recompute a publisher declaration's hash from its **raw document text** and
/// compare (§3).
///
/// Takes text, not a parsed value, and the contract requires that of every SDK:
/// `{"value":1.0}` and `{"value":1}` have different canonical forms and different
/// hashes, and a JavaScript caller's `JSON.parse` collapses both to the number
/// `1`. Accepting a parsed value across the boundary would make the verb
/// unimplementable in JS and silently wrong wherever parsers disagree. Rust's
/// `serde_json` happens to preserve the distinction — taking text anyway is what
/// keeps the four SDKs honest about the same input.
pub fn verify_publisher(
    declaration_json: &str,
    expected_declared_hash: &[u8; HASH_LEN],
) -> Result<(), VerifyError> {
    let value = parse_declaration(declaration_json)?;
    let (computed, _canonical) = rcx_registry_crown::declaration_hash(&value);
    if computed == *expected_declared_hash {
        Ok(())
    } else {
        Err(VerifyError::DeclarationHashMismatch)
    }
}

fn parse_declaration(declaration_json: &str) -> Result<Value, VerifyError> {
    serde_json::from_str(declaration_json)
        .map_err(|error| VerifyError::DecodeError(format!("declaration is not JSON: {error}")))
}

// ---------------------------------------------------------------------------
// 4. verifyNamespace
// ---------------------------------------------------------------------------

/// Verify a namespace claim: the declaration hashes as published **and** names
/// the namespace being claimed (§4).
///
/// Read §4's scope limit before relying on this. Production publishes zero
/// publisher-rights records, so this establishes internal consistency of a claim,
/// **not** operator-independent proof of ownership. Key publication (spec v1
/// §5.6.1) does not change that: what is missing is publisher-rights records,
/// not a key.
pub fn verify_namespace(
    declaration_json: &str,
    expected_declared_hash: &[u8; HASH_LEN],
    claimed_namespace: &str,
) -> Result<(), VerifyError> {
    verify_publisher(declaration_json, expected_declared_hash)?;
    let declaration = parse_declaration(declaration_json)?;
    match declaration.get("mcp_name").and_then(Value::as_str) {
        Some(name) if name == claimed_namespace => Ok(()),
        Some(_) => Err(VerifyError::NamespaceMismatch),
        None => Err(VerifyError::MissingField("mcp_name")),
    }
}

// ---------------------------------------------------------------------------
// 5. verifyHistory
// ---------------------------------------------------------------------------

/// Verify every link in a receipt chain, then that each links to its predecessor
/// by the rule for `kind` (§5).
///
/// `links` is in chain order, oldest first. The first link's backward reference is
/// absent or zero and is not a break.
pub fn verify_history(
    links: &[Vec<u8>],
    public_key: &[u8],
    kind: ChainKind,
) -> Result<(), VerifyError> {
    let mut previous: Option<ReceiptFacts> = None;

    for (index, bytes) in links.iter().enumerate() {
        let facts = verify_receipt(bytes, public_key)?;

        if let Some(prior) = &previous {
            let value = decode(bytes).map_err(|e| VerifyError::DecodeError(e.to_string()))?;
            let CborValue::Map(fields) = &value else {
                return Err(VerifyError::DecodeError("receipt is not a CBOR map".into()));
            };

            let (link_field, expected) = match kind {
                ChainKind::Snapshot => (
                    FIELD_PREVIOUS_SNAPSHOT_HASH,
                    prior
                        .snapshot_root
                        .ok_or(VerifyError::MissingField(FIELD_SNAPSHOT_ROOT))?,
                ),
                ChainKind::EntryEnriched => (FIELD_SUPERSEDES_PRIOR, prior.receipt_hash),
            };

            let actual = match lookup(fields, link_field) {
                Some(CborValue::Bytes(bytes)) if bytes.len() == HASH_LEN => bytes.clone(),
                _ => return Err(VerifyError::ChainBroken { link: index }),
            };
            if actual != expected[..] {
                return Err(VerifyError::ChainBroken { link: index });
            }
        }

        previous = Some(facts);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

fn lookup<'a>(fields: &'a [(String, CborValue)], key: &str) -> Option<&'a CborValue> {
    fields
        .iter()
        .find(|(name, _)| name == key)
        .map(|(_, value)| value)
}

fn take_bytes(
    fields: &[(String, CborValue)],
    key: &'static str,
    expected_len: usize,
) -> Result<Vec<u8>, VerifyError> {
    match lookup(fields, key) {
        Some(CborValue::Bytes(bytes)) if bytes.len() == expected_len => Ok(bytes.clone()),
        Some(CborValue::Bytes(bytes)) => Err(VerifyError::DecodeError(format!(
            "{key} is {} bytes, expected {expected_len}",
            bytes.len()
        ))),
        Some(_) => Err(VerifyError::DecodeError(format!(
            "{key} is not a byte string"
        ))),
        None => Err(VerifyError::MissingField(key)),
    }
}

/// Neutralise the named top-level fields — spec §5.3's zeroed-field encoding.
///
/// The rule is **not** uniform type-preserving zeroing, and assuming it is
/// produces a valid-looking hash over the wrong preimage:
///
/// | Field kind | Neutralised to | Why |
/// |---|---|---|
/// | byte string (`receipt_hash`, `receipt_signature`) | same length, all zero | keeps the encoding's length, so only the content changes |
/// | text (`signer_kid`) | **`Null`** — not an empty string | matches the production constructors, e.g. `PublisherRightsVerifiedReceipt::to_cbor_value` |
///
/// `signer_kid` changing CBOR *type* under zeroing is the kind of detail an
/// independent implementation gets wrong from prose alone; the `receipts.json`
/// vectors are what catch it (they caught it here).
fn zero_fields(value: &CborValue, keys: &[&str]) -> CborValue {
    let CborValue::Map(fields) = value else {
        return value.clone();
    };
    CborValue::Map(
        fields
            .iter()
            .map(|(name, field)| {
                if keys.contains(&name.as_str()) {
                    let zeroed = match field {
                        CborValue::Bytes(bytes) => CborValue::Bytes(vec![0u8; bytes.len()]),
                        CborValue::Text(_) => CborValue::Null,
                        other => other.clone(),
                    };
                    (name.clone(), zeroed)
                } else {
                    (name.clone(), field.clone())
                }
            })
            .collect(),
    )
}

/// Canonical JSON, re-exported so an SDK consumer computing a declaration hash
/// does not need the mirror crates (CONTRACT.md §3).
pub fn canonical_json(value: &Value) -> String {
    canonicalize_json(value)
}

/// Build a snapshot entry from the only three fields that enter the digest.
pub fn entry(
    name: impl Into<String>,
    version: impl Into<String>,
    canonical_json: impl Into<String>,
) -> SnapshotEntry {
    SnapshotEntry::new(name, version, canonical_json)
}

#[cfg(test)]
mod tests {
    // The crate denies expect_used because a verification library must not panic
    // on caller input. Fixtures in tests are not caller input.
    #![allow(clippy::expect_used)]

    use super::*;

    #[test]
    fn snapshot_root_mismatch_is_reported_not_panicked() {
        let entries = [entry("a/mcp", "1.0.0", "{}")];
        assert_eq!(
            verify_snapshot(&entries, &[0u8; HASH_LEN]),
            Err(VerifyError::RootMismatch)
        );
        let root = snapshot_merkle_root(&entries);
        assert_eq!(verify_snapshot(&entries, &root), Ok(()));
    }

    #[test]
    fn namespace_requires_the_declaration_to_name_it() {
        // Raw document text, as a verifier holds it (CONTRACT.md §3).
        let declaration = r#"{"mcp_name":"example.com/mcp","rcx_version":"1"}"#;
        let (hash, _) = rcx_registry_crown::declaration_hash(
            &serde_json::from_str::<Value>(declaration).expect("fixture parses"),
        );

        assert_eq!(
            verify_namespace(declaration, &hash, "example.com/mcp"),
            Ok(())
        );
        // Right hash, wrong namespace — a claim must not verify for a name it
        // does not carry.
        assert_eq!(
            verify_namespace(declaration, &hash, "attacker.com/mcp"),
            Err(VerifyError::NamespaceMismatch)
        );
    }

    #[test]
    fn integral_floats_and_integers_hash_differently() {
        // The reason the API takes text: these are distinct vectors with distinct
        // canonical forms, and a JS caller's JSON.parse renders both as `1`. If
        // this ever starts passing with a parsed value across the boundary, the
        // JS SDK has silently become wrong.
        let float_form = r#"{"value":1.0}"#;
        let int_form = r#"{"value":1}"#;

        let (float_hash, float_canonical) = rcx_registry_crown::declaration_hash(
            &serde_json::from_str::<Value>(float_form).expect("parses"),
        );
        let (int_hash, int_canonical) = rcx_registry_crown::declaration_hash(
            &serde_json::from_str::<Value>(int_form).expect("parses"),
        );

        assert_eq!(float_canonical, r#"{"value":1.0}"#);
        assert_eq!(int_canonical, r#"{"value":1}"#);
        assert_ne!(float_hash, int_hash);

        assert_eq!(verify_publisher(float_form, &float_hash), Ok(()));
        assert_eq!(
            verify_publisher(int_form, &float_hash),
            Err(VerifyError::DeclarationHashMismatch)
        );
    }

    #[test]
    fn a_short_public_key_is_rejected_before_any_parsing() {
        assert_eq!(
            verify_receipt(&[0xa0], &[0u8; 4]),
            Err(VerifyError::BadPublicKey(4))
        );
    }

    #[test]
    fn non_canonical_input_is_rejected_even_though_it_decodes() {
        // Map with keys out of canonical order. The production decoder re-sorts
        // rather than rejecting (OQ-6), so this decodes fine — and must still
        // fail, because its bytes are not what any published hash covered.
        let out_of_order = CborValue::Map(vec![
            ("b".into(), CborValue::Uint(1)),
            ("a".into(), CborValue::Uint(2)),
        ]);
        let mut bytes = Vec::new();
        bytes.push(0xa2);
        bytes.extend_from_slice(&[0x61, b'b', 0x01]);
        bytes.extend_from_slice(&[0x61, b'a', 0x02]);
        // Sanity: the canonical encoding of the same map differs from our input.
        assert_ne!(out_of_order.encode(), bytes);

        assert_eq!(
            verify_receipt(&bytes, &[0u8; PUBLIC_KEY_LEN]),
            Err(VerifyError::NotCanonical)
        );
    }

    #[test]
    fn signer_kid_zeroes_to_null_not_an_empty_string() {
        // Not cosmetic: an empty Text and a Null encode to different bytes, so
        // getting this wrong yields hash_mismatch on every real receipt. This is
        // the bug the receipts.json vectors caught during M1a.
        let value = CborValue::Map(vec![(
            "signer_kid".into(),
            CborValue::Text("vault:transit:key-1".into()),
        )]);
        let zeroed = zero_fields(&value, &["signer_kid"]);
        let CborValue::Map(fields) = &zeroed else {
            panic!("expected a map");
        };
        assert_eq!(fields[0].1, CborValue::Null);
        assert_ne!(fields[0].1, CborValue::Text(String::new()));
    }

    #[test]
    fn zeroing_preserves_byte_string_length() {
        // The zeroed-field encoding must keep the map's shape — a zeroed 32-byte
        // hash is 32 zero bytes, not an empty string, or the hash preimage
        // changes length and nothing verifies.
        let value = CborValue::Map(vec![
            ("receipt_hash".into(), CborValue::Bytes(vec![9u8; 32])),
            ("keep".into(), CborValue::Uint(7)),
        ]);
        let zeroed = zero_fields(&value, &["receipt_hash"]);
        let CborValue::Map(fields) = &zeroed else {
            panic!("expected a map");
        };
        assert_eq!(fields[0].1, CborValue::Bytes(vec![0u8; 32]));
        assert_eq!(fields[1].1, CborValue::Uint(7));
        assert_eq!(zeroed.encode().len(), value.encode().len());
    }
}
