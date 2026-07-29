//! Canonical-JSON hashing primitives — the designated hash inputs of spec v1 §3, §4 and §6.
//!
//! # Which renderer is this?
//!
//! This crate contains **two** JSON renderers and they are not interchangeable.
//! Confusing them produces a valid-looking hash over the wrong preimage, which
//! is the defect class of OQ-1 (production signed the full canonical CBOR while
//! the verifier checked the 32-byte hash — incompatible preimages, undetected
//! because no code path called the verifier).
//!
//! | Function | Purpose |
//! |---|---|
//! | [`canonicalize_json`] (this module) | **The hashing renderer.** Spec v1 §3. Every registry artifact hash — declaration hash, per-server reconciliation hash, snapshot set digest — is taken over this output. |
//! | [`crate::to_canonical_json`] | **Not a hashing renderer.** Reproduces shared RCX-Protocol session-plan fixtures only. Spec v1 §3 places it explicitly out of scope for hashing. |
//!
//! If you are computing something that will be signed, chained, or compared
//! against a published digest, it is this module.
//!
//! # Provenance
//!
//! These functions were moved verbatim from `rcx-registry-ingest` and
//! `rcx-registry-enrich` so that verification does not require those crates'
//! `reqwest`/`jsonschema` dependencies — an offline verifier must not need an
//! HTTP client. Both crates re-export from here; production call sites are
//! unchanged and the M0 conformance vectors pin the bytes.

use blake3::Hasher;
use serde_json::Value;

use crate::receipt::HASH_LEN;

/// Read access to the three fields spec v1 §6 hashes.
///
/// Exists so the digest functions work on both [`SnapshotEntry`] (what an
/// offline verifier has) and `rcx_registry_ingest::MirroredServer` (what the
/// mirror pipeline already holds) **without copying**. Projecting the mirror
/// into owned `SnapshotEntry` values would clone every server's canonical JSON
/// on every sync tick; this trait is the cheaper half of that trade and keeps
/// ingest's public signatures unchanged.
pub trait SnapshotDigestEntry {
    fn name(&self) -> &str;
    fn version(&self) -> &str;
    fn canonical_json(&self) -> &str;
}

/// Callers commonly hold `&T` (map lookups, iterator refs), so blanket-forward
/// through references rather than making every call site deref.
impl<T: SnapshotDigestEntry + ?Sized> SnapshotDigestEntry for &T {
    fn name(&self) -> &str {
        (**self).name()
    }
    fn version(&self) -> &str {
        (**self).version()
    }
    fn canonical_json(&self) -> &str {
        (**self).canonical_json()
    }
}

/// The three fields of a mirrored server that actually enter a digest.
///
/// Deliberately narrower than `rcx_registry_ingest::MirroredServer`: spec v1 §6
/// hashes only `(name, version, canonical_json)`, so `schema_uri`, `schema_date`,
/// `status`, `updated_at` and `is_latest` are absent by design. A third party
/// verifying a published root must not be asked to reconstruct mirror-only
/// bookkeeping fields that the digest never observed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotEntry {
    pub name: String,
    pub version: String,
    pub canonical_json: String,
}

impl SnapshotDigestEntry for SnapshotEntry {
    fn name(&self) -> &str {
        &self.name
    }
    fn version(&self) -> &str {
        &self.version
    }
    fn canonical_json(&self) -> &str {
        &self.canonical_json
    }
}

impl SnapshotEntry {
    pub fn new(
        name: impl Into<String>,
        version: impl Into<String>,
        canonical_json: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            version: version.into(),
            canonical_json: canonical_json.into(),
        }
    }
}

/// Render `value` as canonical JSON per spec v1 §3 — compact, key-sorted, no
/// insignificant whitespace. This is the designated hash input; see the module
/// docs before reaching for [`crate::to_canonical_json`] instead.
///
/// Object keys are sorted by Rust `String` ordering (UTF-8 code-unit order),
/// which differs from RFC 8785's UTF-16 ordering for astral-plane keys. That
/// divergence is observed, frozen, and covered by the
/// `canonical-json.json` vectors — do not "fix" it without a spec revision.
pub fn canonicalize_json(value: &Value) -> String {
    match value {
        Value::Null => "null".to_string(),
        Value::Bool(boolean) => boolean.to_string(),
        Value::Number(number) => number.to_string(),
        Value::String(text) => serde_json::to_string(text).expect("strings should serialize"),
        Value::Array(items) => {
            let rendered = items
                .iter()
                .map(canonicalize_json)
                .collect::<Vec<_>>()
                .join(",");
            format!("[{rendered}]")
        }
        Value::Object(map) => {
            let mut keys = map.keys().cloned().collect::<Vec<_>>();
            keys.sort();
            let rendered = keys
                .into_iter()
                .map(|key| {
                    let encoded_key =
                        serde_json::to_string(&key).expect("object key should serialize");
                    let encoded_value = canonicalize_json(map.get(&key).expect("key should exist"));
                    format!("{encoded_key}:{encoded_value}")
                })
                .collect::<Vec<_>>()
                .join(",");
            format!("{{{rendered}}}")
        }
    }
}

/// Compute the deterministic BLAKE3 set digest over lex-sorted entries (spec v1 §6).
///
/// Despite the historical wire field name `snapshot_merkle_root`, this is a flat
/// sequential digest over a sorted set, **not** a Merkle tree — no inclusion
/// proofs are derivable from it (OQ-4). The real tree arrives additively as
/// spec v2 / M3a.
///
/// Each entry is framed `name 0x00 version 0x00 canonical_json 0xff`. The
/// trailing `0xff` is what distinguishes this framing from
/// [`canonical_server_hash`]; the two must not be conflated.
pub fn snapshot_merkle_root<E: SnapshotDigestEntry>(entries: &[E]) -> [u8; HASH_LEN] {
    let mut ordered: Vec<&E> = entries.iter().collect();
    ordered.sort_by(|left, right| {
        left.name()
            .cmp(right.name())
            .then(left.version().cmp(right.version()))
    });

    let mut hasher = Hasher::new();
    for entry in ordered {
        hasher.update(entry.name().as_bytes());
        hasher.update(&[0]);
        hasher.update(entry.version().as_bytes());
        hasher.update(&[0]);
        hasher.update(entry.canonical_json().as_bytes());
        hasher.update(&[0xff]);
    }
    *hasher.finalize().as_bytes()
}

/// Compute the per-entry reconciliation hash (spec v1 §6.5).
///
/// Same field framing as [`snapshot_merkle_root`] but **without** the trailing
/// `0xff` separator. That one byte is the entire difference between the two
/// digests, so a copy-paste between them fails silently — the
/// `hashes.json` vectors pin both forms.
pub fn canonical_server_hash<E: SnapshotDigestEntry>(entry: &E) -> [u8; HASH_LEN] {
    let mut hasher = Hasher::new();
    hasher.update(entry.name().as_bytes());
    hasher.update(&[0]);
    hasher.update(entry.version().as_bytes());
    hasher.update(&[0]);
    hasher.update(entry.canonical_json().as_bytes());
    *hasher.finalize().as_bytes()
}

/// Hash a fetched publisher declaration document (spec v1 §4.4).
///
/// Returns the digest and the canonical JSON it was taken over, so a caller can
/// store or publish the exact preimage rather than re-deriving it.
pub fn declaration_hash(value: &Value) -> ([u8; HASH_LEN], String) {
    let canonical_json = canonicalize_json(value);
    let mut hasher = Hasher::new();
    hasher.update(canonical_json.as_bytes());
    (*hasher.finalize().as_bytes(), canonical_json)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn canonicalize_json_sorts_keys_and_strips_whitespace() {
        // Spec v1 §3.1's own worked example.
        let input = json!({"b": 2, "a": {"z": true, "m": ["x", {"k": 1, "a": 2}]}});
        assert_eq!(
            canonicalize_json(&input),
            r#"{"a":{"m":["x",{"a":2,"k":1}],"z":true},"b":2}"#
        );
    }

    #[test]
    fn entry_frame_and_reconciliation_hash_differ_by_the_trailing_separator() {
        // The single 0xff byte is the only difference between the snapshot-entry
        // frame and the reconciliation-hash input. If a refactor ever unifies
        // the two framings, this fails.
        let entry = SnapshotEntry::new("example.com/mcp", "1.0.0", r#"{"a":1}"#);

        let reconciliation = canonical_server_hash(&entry);
        let root = snapshot_merkle_root(std::slice::from_ref(&entry));
        assert_ne!(reconciliation, root);

        let mut framed = Hasher::new();
        framed.update(b"example.com/mcp");
        framed.update(&[0]);
        framed.update(b"1.0.0");
        framed.update(&[0]);
        framed.update(br#"{"a":1}"#);
        assert_eq!(*framed.finalize().as_bytes(), reconciliation);
        framed.update(&[0xff]);
        assert_eq!(*framed.finalize().as_bytes(), root);
    }

    #[test]
    fn snapshot_root_is_order_independent_but_content_sensitive() {
        let a = SnapshotEntry::new("a/mcp", "1.0.0", r#"{"x":1}"#);
        let b = SnapshotEntry::new("b/mcp", "1.0.0", r#"{"x":2}"#);

        // Sorting means input order cannot change the root...
        assert_eq!(
            snapshot_merkle_root(&[a.clone(), b.clone()]),
            snapshot_merkle_root(&[b.clone(), a.clone()])
        );
        // ...but payload content must.
        let b_mutated = SnapshotEntry::new("b/mcp", "1.0.0", r#"{"x":3}"#);
        assert_ne!(
            snapshot_merkle_root(&[a.clone(), b]),
            snapshot_merkle_root(&[a, b_mutated])
        );
    }

    #[test]
    fn empty_set_root_is_the_empty_blake3_digest() {
        assert_eq!(
            snapshot_merkle_root::<SnapshotEntry>(&[]),
            *blake3::Hasher::new().finalize().as_bytes()
        );
    }

    #[test]
    fn declaration_hash_returns_the_preimage_it_hashed() {
        let (digest, canonical) = declaration_hash(&json!({"b": 1, "a": 2}));
        assert_eq!(canonical, r#"{"a":2,"b":1}"#);
        let mut expected = Hasher::new();
        expected.update(canonical.as_bytes());
        assert_eq!(digest, *expected.finalize().as_bytes());
    }
}
