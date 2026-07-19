use std::fs;
use std::path::{Path, PathBuf};

use ed25519_dalek::{Signer, SigningKey};

use crate::canonical::{decode, to_canonical_json, CborValue};
use crate::receipt::{
    verify_receipt_signature, PublisherRightsVerifiedReceipt, ReceiptDocument,
    RegistrySnapshotReceipt, SnapshotChanges,
};

fn cuecrux_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .expect("CueCrux root")
        .to_path_buf()
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("RCX-Registry repo root")
        .to_path_buf()
}

fn session_fixture_dirs() -> Vec<PathBuf> {
    // Prefer the live golden set from the sibling RCX-Protocol repo when this
    // repo is checked out inside the CueCrux workspace; fall back to the
    // vendored copy so the check also runs on standalone/CI checkouts.
    // Re-vendor with: cp -r CueCrux-Shared/packages/session/fixtures/* fixtures/session-goldens/
    let sibling = cuecrux_root().join("CueCrux-Shared/packages/session/fixtures");
    let fixtures_root = if sibling.is_dir() {
        sibling
    } else {
        repo_root().join("fixtures/session-goldens")
    };
    let mut dirs: Vec<PathBuf> = fs::read_dir(&fixtures_root)
        .expect("read session fixtures dir")
        .filter_map(|entry| {
            let entry = entry.ok()?;
            if entry.file_type().ok()?.is_dir() {
                Some(entry.path())
            } else {
                None
            }
        })
        .collect();
    dirs.sort();
    dirs
}

fn schema_fixture_path(name: &str) -> PathBuf {
    repo_root().join("fixtures/examples").join(name)
}

fn schema_path(name: &str) -> PathBuf {
    repo_root().join("schemas/2026-04-19").join(name)
}

fn sample_snapshot_receipt() -> RegistrySnapshotReceipt {
    RegistrySnapshotReceipt {
        event_id: [0x11; 16],
        snapshot_id: [0x22; 16],
        scraped_at: 1_776_683_200_000,
        server_count: 42,
        snapshot_merkle_root: [0x33; 32],
        previous_snapshot_hash: Some([0x44; 32]),
        upstream_registry_uri: "https://registry.modelcontextprotocol.io/v0/servers".to_string(),
        upstream_snapshot_etag: Some("\"etag-42\"".to_string()),
        changes: SnapshotChanges {
            added: 2,
            removed: 1,
            modified: 5,
        },
        receipt_hash: [0x55; 32],
        receipt_signature: [0x66; 64],
        signer_kid: "vault:transit:rcx-registry-signing-key-1".to_string(),
    }
}

fn sample_rights_receipt() -> PublisherRightsVerifiedReceipt {
    PublisherRightsVerifiedReceipt {
        event_id: [0x77; 16],
        publisher_passport: "passport:github:example-org".to_string(),
        namespace: "io.github.example-org".to_string(),
        verification_method: "github_oauth".to_string(),
        verified_at: 1_776_683_260_000,
        receipt_hash: [0u8; 32],
        receipt_signature: [0u8; 64],
        signer_kid: "vault:transit:rcx-registry-signing-key-1".to_string(),
    }
}

fn load_json(path: &Path) -> serde_json::Value {
    serde_json::from_slice(&fs::read(path).unwrap_or_else(|_| panic!("read {}", path.display())))
        .unwrap_or_else(|_| panic!("parse {}", path.display()))
}

#[test]
fn rcx_protocol_golden_fixtures_round_trip_byte_for_byte() {
    let fixture_dirs = session_fixture_dirs();
    assert!(!fixture_dirs.is_empty(), "no session fixtures found");

    for fixture_dir in fixture_dirs {
        let cbor_bytes = fs::read(fixture_dir.join("plan.cbor")).expect("read plan.cbor");
        let json_string =
            String::from_utf8(fs::read(fixture_dir.join("plan.json")).expect("read plan.json"))
                .expect("utf8");

        let decoded = decode(&cbor_bytes).expect("decode cbor fixture");
        assert_eq!(
            decoded.encode(),
            cbor_bytes,
            "cbor mismatch for {:?}",
            fixture_dir
        );
        assert_eq!(
            to_canonical_json(&decoded),
            json_string,
            "json mismatch for {:?}",
            fixture_dir
        );
    }
}

#[test]
fn zeroed_hash_ignores_signing_fields() {
    let base = sample_snapshot_receipt();
    let mut variant = base.clone();
    variant.receipt_hash = [0x99; 32];
    variant.receipt_signature = [0xaa; 64];
    variant.signer_kid = "vault:transit:rotated-kid".to_string();

    assert_eq!(base.compute_hash(), variant.compute_hash());
}

#[test]
fn verifies_signature_against_zeroed_hash() {
    let mut receipt = sample_rights_receipt();
    let signing_key = SigningKey::from_bytes(&[0x13; 32]);
    let computed_hash = receipt.compute_hash();
    let signature = signing_key.sign(&computed_hash);

    receipt.receipt_hash = computed_hash;
    receipt.receipt_signature = signature.to_bytes();

    verify_receipt_signature(&receipt, &signing_key.verifying_key().to_bytes())
        .expect("signature should verify");

    let mut tampered = receipt.clone();
    tampered.namespace = "io.github.evil-org".to_string();
    assert!(verify_receipt_signature(&tampered, &signing_key.verifying_key().to_bytes()).is_err());
}

#[test]
fn floats_encode_with_deterministic_shortest_form() {
    let encoded = CborValue::Float(1.5).encode();
    assert_eq!(encoded, vec![0xf9, 0x3e, 0x00]);
    assert_eq!(
        decode(&encoded).expect("decode float"),
        CborValue::Float(1.5)
    );
}

#[test]
fn schemas_accept_valid_examples_and_reject_invalid_examples() {
    let enrichment_schema = load_json(&schema_path("rcx-enrichment.schema.json"));
    let attestation_schema = load_json(&schema_path("attestation.schema.json"));

    let enrichment_validator =
        jsonschema::validator_for(&enrichment_schema).expect("compile enrichment schema");
    let attestation_validator =
        jsonschema::validator_for(&attestation_schema).expect("compile attestation schema");

    let valid_enrichment = load_json(&schema_fixture_path("rcx-enrichment.valid.json"));
    let invalid_enrichment = load_json(&schema_fixture_path(
        "rcx-enrichment.invalid.missing-min-tier.json",
    ));
    let valid_attestation = load_json(&schema_fixture_path("attestation.auditor.valid.json"));
    let invalid_attestation = load_json(&schema_fixture_path(
        "attestation.auditor.invalid.missing-result.json",
    ));

    if !enrichment_validator.is_valid(&valid_enrichment) {
        let errors: Vec<String> = enrichment_validator
            .iter_errors(&valid_enrichment)
            .map(|error| error.to_string())
            .collect();
        panic!("valid enrichment should pass: {errors:?}");
    }
    assert!(!enrichment_validator.is_valid(&invalid_enrichment));

    if !attestation_validator.is_valid(&valid_attestation) {
        let errors: Vec<String> = attestation_validator
            .iter_errors(&valid_attestation)
            .map(|error| error.to_string())
            .collect();
        panic!("valid attestation should pass: {errors:?}");
    }
    assert!(!attestation_validator.is_valid(&invalid_attestation));
}
