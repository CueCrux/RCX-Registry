//! CONTRACT.md §8.1 — every spec-v1 vector reproduces through the SDK, positive
//! **and** negative.
//!
//! The negative cases carry the weight. Each of these verbs can be satisfied by
//! `return valid`, so a suite that only checks positives would pass against an
//! SDK that verifies nothing. Positive counts are asserted non-zero for the same
//! reason: a glob that silently matched no cases would otherwise read as green.

use std::fs;
use std::path::PathBuf;

use rcx_verify::{
    verify_history, verify_publisher, verify_receipt, verify_snapshot, ChainKind, Entry,
    VerifyError,
};
use serde_json::Value;

fn vectors(name: &str) -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../spec/v1/vectors")
        .join(name);
    let raw = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("vector file {} unreadable: {e}", path.display()));
    serde_json::from_str(&raw).unwrap_or_else(|e| panic!("vector file {name} is not JSON: {e}"))
}

fn hex32(value: &str) -> [u8; 32] {
    let bytes = hex::decode(value).expect("vector hex should decode");
    assert_eq!(bytes.len(), 32, "expected a 32-byte digest");
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    out
}

fn test_public_key(vectors: &Value) -> Vec<u8> {
    hex::decode(
        vectors["test_key"]["public_key_hex"]
            .as_str()
            .expect("test_key.public_key_hex"),
    )
    .expect("public key hex")
}

// ---------------------------------------------------------------------------
// verifySnapshot — snapshot-merkle.json
// ---------------------------------------------------------------------------

#[test]
fn verify_snapshot_reproduces_every_root_vector() {
    let vectors = vectors("snapshot-merkle.json");
    let cases = vectors["cases"].as_array().expect("cases");
    let mut checked = 0;

    for case in cases {
        let id = case["id"].as_str().unwrap_or("<unnamed>");
        let expected = hex32(case["root_hex"].as_str().expect("root_hex"));
        let entries: Vec<Entry> = case["input_order"]
            .as_array()
            .expect("input_order")
            .iter()
            .map(|entry| {
                Entry::new(
                    entry["name"].as_str().unwrap_or_default(),
                    entry["version"].as_str().unwrap_or_default(),
                    entry["canonical_json"].as_str().unwrap_or_default(),
                )
            })
            .collect();

        assert_eq!(
            verify_snapshot(&entries, &expected),
            Ok(()),
            "case {id} should verify against its own published root"
        );

        // Negative: a root one bit different must not verify. Without this the
        // verb could `return Ok(())` and still pass every case above.
        let mut tampered = expected;
        tampered[0] ^= 0x01;
        assert_eq!(
            verify_snapshot(&entries, &tampered),
            Err(VerifyError::RootMismatch),
            "case {id} verified against a tampered root"
        );
        checked += 1;
    }
    assert!(checked > 0, "no snapshot-merkle cases ran");
}

// ---------------------------------------------------------------------------
// verifyPublisher — hashes.json declaration_hash
// ---------------------------------------------------------------------------

#[test]
fn verify_publisher_reproduces_every_declaration_hash_vector() {
    let vectors = vectors("hashes.json");
    let cases = vectors["declaration_hash"]["cases"]
        .as_array()
        .expect("declaration cases");
    let mut checked = 0;

    for case in cases {
        let id = case["id"].as_str().unwrap_or("<unnamed>");
        // The raw document text, exactly as a verifier would hold it — not a
        // parsed value. See CONTRACT.md §3.
        let input = case["input_json"].as_str().expect("input_json");
        let expected = hex32(case["digest_hex"].as_str().expect("digest_hex"));

        assert_eq!(
            verify_publisher(input, &expected),
            Ok(()),
            "declaration case {id} should verify"
        );

        let mut tampered = expected;
        tampered[31] ^= 0x01;
        assert_eq!(
            verify_publisher(input, &tampered),
            Err(VerifyError::DeclarationHashMismatch),
            "declaration case {id} verified against a tampered digest"
        );
        checked += 1;
    }
    assert!(checked > 0, "no declaration_hash cases ran");
}

// ---------------------------------------------------------------------------
// verifyReceipt — receipts.json
// ---------------------------------------------------------------------------

#[test]
fn verify_receipt_reproduces_every_receipt_vector_and_rejects_every_tamper() {
    let vectors = vectors("receipts.json");
    let public_key = test_public_key(&vectors);
    let cases = vectors["cases"].as_array().expect("cases");
    let (mut positives, mut negatives) = (0, 0);

    for case in cases {
        let id = case["id"].as_str().unwrap_or("<unnamed>");
        let signed = hex::decode(
            case["signed_canonical_cbor_hex"]
                .as_str()
                .expect("signed_canonical_cbor_hex"),
        )
        .expect("signed cbor hex");

        let facts = verify_receipt(&signed, &public_key)
            .unwrap_or_else(|e| panic!("case {id} should verify, got {e}"));
        assert_eq!(
            hex::encode(facts.receipt_hash),
            case["receipt_hash_hex"].as_str().expect("receipt_hash_hex"),
            "case {id} reported the wrong receipt hash"
        );
        positives += 1;

        for negative in case["negative_cases"].as_array().unwrap_or(&Vec::new()) {
            let neg_id = negative["id"].as_str().unwrap_or("<unnamed>");

            // Byte-tamper cases carry replacement CBOR; field-tamper cases do not.
            if let Some(tampered_hex) = negative["tampered_canonical_cbor_hex"].as_str() {
                let tampered = hex::decode(tampered_hex).expect("tampered hex");
                assert!(
                    verify_receipt(&tampered, &public_key).is_err(),
                    "case {id}/{neg_id}: tampered bytes verified"
                );
                negatives += 1;
            }
            if let Some(sig_hex) = negative["receipt_signature_hex"].as_str() {
                if let Some(body_hex) = negative["signed_canonical_cbor_hex"].as_str() {
                    let _ = sig_hex;
                    let bytes = hex::decode(body_hex).expect("negative body hex");
                    assert!(
                        verify_receipt(&bytes, &public_key).is_err(),
                        "case {id}/{neg_id}: a bad-signature vector verified"
                    );
                    negatives += 1;
                }
            }
        }

        // A valid receipt must not verify under a different key.
        let mut wrong_key = public_key.clone();
        wrong_key[0] ^= 0x01;
        assert!(
            verify_receipt(&signed, &wrong_key).is_err(),
            "case {id} verified under a tampered public key"
        );
        negatives += 1;
    }

    assert!(positives > 0, "no receipt cases ran");
    assert!(negatives > 0, "no receipt tamper cases ran");
}

// ---------------------------------------------------------------------------
// verifyHistory — chains.json, both link rules
// ---------------------------------------------------------------------------

#[test]
fn verify_history_walks_both_chain_kinds() {
    let vectors = vectors("chains.json");
    let public_key = test_public_key(&vectors);

    for (key, kind) in [
        ("snapshot_chain", ChainKind::Snapshot),
        ("entry_enriched_receipt_chain", ChainKind::EntryEnriched),
    ] {
        let links: Vec<Vec<u8>> = vectors[key]["links"]
            .as_array()
            .unwrap_or_else(|| panic!("{key}.links"))
            .iter()
            .map(|link| {
                hex::decode(
                    link["signed_canonical_cbor_hex"]
                        .as_str()
                        .expect("signed_canonical_cbor_hex"),
                )
                .expect("link hex")
            })
            .collect();
        assert!(links.len() >= 2, "{key} needs at least two links to chain");

        verify_history(&links, &public_key, kind)
            .unwrap_or_else(|e| panic!("{key} should verify as {kind:?}, got {e}"));

        // Dropping the middle link must break the chain — otherwise the link rule
        // is not actually being checked.
        let mut gapped = links.clone();
        gapped.remove(1);
        assert!(
            verify_history(&gapped, &public_key, kind).is_err(),
            "{key} verified with a link removed"
        );
    }
}

#[test]
fn the_two_chain_kinds_link_on_different_fields() {
    // Snapshot chains link root-to-root, enrichment chains receipt-to-receipt
    // (CONTRACT.md §5). Applying the wrong rule must fail, which is what makes
    // taking `kind` explicitly load-bearing rather than ceremony.
    let vectors = vectors("chains.json");
    let public_key = test_public_key(&vectors);

    let snapshot_links: Vec<Vec<u8>> = vectors["snapshot_chain"]["links"]
        .as_array()
        .expect("snapshot links")
        .iter()
        .map(|link| {
            hex::decode(
                link["signed_canonical_cbor_hex"]
                    .as_str()
                    .unwrap_or_default(),
            )
            .expect("hex")
        })
        .collect();

    assert!(
        verify_history(&snapshot_links, &public_key, ChainKind::Snapshot).is_ok(),
        "snapshot chain should verify under the snapshot rule"
    );
    assert!(
        verify_history(&snapshot_links, &public_key, ChainKind::EntryEnriched).is_err(),
        "a snapshot chain must not verify under the entry-enriched link rule — if \
         this passes, the link field is not being read at all"
    );
}
