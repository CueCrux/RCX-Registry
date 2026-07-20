use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::PathBuf;

use ed25519_dalek::{Signer as _, SigningKey};
use rcx_registry_admin::{build_publisher_rights_verified_receipt, VerificationMethod};
use rcx_registry_crown::{
    decode, verify_receipt_signature, AttestationAcceptedReceipt, AttestationRevokedReceipt,
    CborValue, CrownError, ReceiptDocument, HASH_LEN, SIGNATURE_LEN,
};
use rcx_registry_enrich::{
    build_entry_auto_enriched_receipt, build_entry_enriched_receipt,
    build_publisher_enrichment_payload, declaration_hash, AutoEnrichmentPayload,
    PublisherDeclaration, PublisherEnrichmentPayload,
};
use rcx_registry_ingest::{
    build_snapshot_plan, canonical_server_hash, canonicalize_json, snapshot_merkle_root,
    MirroredServer, NoopSchemaCatalog, OfficialRegistryMeta, RegistryServerEnvelope,
    RegistryServerMeta,
};
use serde::Deserialize;
use serde_json::{json, Value};

const FORMAT_PREFIX: &str = "rcx-protocol-spec-v1";
const TEST_SEED: [u8; 32] = [0x42; 32];
const TEST_KEY_LABEL: &str = "RCX Protocol Spec v1 conformance TEST KEY - NEVER USE IN PRODUCTION";
const TEST_SIGNER_KID: &str = "test-only:rcx-spec-v1:ed25519:seed-42";
const SERVER_SCHEMA_URI: &str =
    "https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json";

#[allow(dead_code)] // Used by the example target; the integration-test target only checks.
pub fn write_vectors() -> Result<(), String> {
    let vectors = render_vectors()?;
    let vector_count = vectors.len();
    let directory = vector_directory();
    fs::create_dir_all(&directory)
        .map_err(|error| format!("create {}: {error}", directory.display()))?;

    for (name, contents) in vectors {
        let path = directory.join(name);
        fs::write(&path, contents).map_err(|error| format!("write {}: {error}", path.display()))?;
    }

    println!(
        "wrote {} RCX Protocol Spec v1 vector files to {}",
        vector_count,
        directory.display()
    );
    Ok(())
}

pub fn check_vectors() -> Result<(), String> {
    let expected = render_vectors()?;
    let directory = vector_directory();
    let mut failures = Vec::new();
    let mut checked_in_chains = None;

    for (name, expected_contents) in &expected {
        let path = directory.join(name);
        match fs::read_to_string(&path) {
            Ok(actual) => {
                if *name == "chains.json" {
                    checked_in_chains = Some(actual.clone());
                }
                if actual != *expected_contents {
                    failures.push(format!(
                        "{} differs (checked-in {} bytes, production-derived {} bytes)",
                        path.display(),
                        actual.len(),
                        expected_contents.len()
                    ));
                }
            }
            Err(error) => failures.push(format!("read {}: {error}", path.display())),
        }
    }

    if let Some(chains) = checked_in_chains {
        if let Err(error) = check_chain_receipts_from_structured_inputs(&chains) {
            failures.push(format!(
                "rebuild {}: {error}",
                directory.join("chains.json").display()
            ));
        }
    }

    let expected_names = expected.keys().copied().collect::<BTreeSet<_>>();
    match fs::read_dir(&directory) {
        Ok(entries) => {
            for entry in entries {
                let entry = entry
                    .map_err(|error| format!("read entry in {}: {error}", directory.display()))?;
                let path = entry.path();
                if path.extension().and_then(|value| value.to_str()) != Some("json") {
                    continue;
                }
                let name = entry.file_name();
                let name = name.to_string_lossy();
                if !expected_names.contains(name.as_ref()) {
                    failures.push(format!("unexpected stale vector file {}", path.display()));
                }
            }
        }
        Err(error) => failures.push(format!("read {}: {error}", directory.display())),
    }

    if failures.is_empty() {
        println!(
            "{} RCX Protocol Spec v1 vector files match production code paths",
            expected.len()
        );
        Ok(())
    } else {
        Err(format!(
            "{}\nregenerate with:\n  cargo run -p rcx-registry-server --example \
             rcx-spec-v1-vectors -- --write",
            failures.join("\n")
        ))
    }
}

fn render_vectors() -> Result<BTreeMap<&'static str, String>, String> {
    let mut vectors = BTreeMap::new();
    vectors.insert("canonical-cbor.json", render(canonical_cbor_vectors())?);
    vectors.insert("canonical-json.json", render(canonical_json_vectors()?)?);
    let chains = render(chain_vectors()?)?;
    check_chain_receipts_from_structured_inputs(&chains)?;
    vectors.insert("chains.json", chains);
    vectors.insert("hashes.json", render(hash_vectors()?)?);
    vectors.insert("receipts.json", render(receipt_vectors()?)?);
    vectors.insert("snapshot-merkle.json", render(snapshot_vectors()?)?);
    Ok(vectors)
}

fn render(value: Value) -> Result<String, String> {
    let mut rendered =
        serde_json::to_string_pretty(&value).map_err(|error| format!("render JSON: {error}"))?;
    rendered.push('\n');
    Ok(rendered)
}

fn vector_directory() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../spec/v1/vectors")
}

fn canonical_json_vectors() -> Result<Value, String> {
    let definitions = [
        (
            "object-key-ordering",
            r#"{"😀":4,"\uE000":5,"ä":3,"z":0,"aa":2,"a":1}"#,
        ),
        (
            "string-escaping",
            r#"{"text":"quote: \" backslash: \\ slash: / controls: \b\f\n\r\t nul:\u0000"}"#,
        ),
        (
            "unicode-astral-and-combining",
            r#"{"astral":"😀","combining":"e\u0301","precomposed":"é"}"#,
        ),
        (
            "integers-versus-floats",
            r#"{"integer":1,"float":1.0,"negative_integer":-1,"exponent":1e3}"#,
        ),
        (
            "negative-zero",
            r#"{"negative_zero":-0.0,"positive_zero":0.0}"#,
        ),
        (
            "nested",
            r#"{"z":[{"y":2,"x":1},[]],"a":{"d":false,"c":null,"b":[3,2,1]}}"#,
        ),
        ("empty-containers", r#"{"object":{},"array":[]}"#),
        (
            "integer-boundaries",
            r#"{"u64_max":18446744073709551615,"i64_min":-9223372036854775808}"#,
        ),
        ("duplicate-object-key-last-wins", r#"{"a":1,"a":2}"#),
    ];

    let cases = definitions
        .into_iter()
        .map(|(id, input_json)| {
            let value: Value = serde_json::from_str(input_json)
                .map_err(|error| format!("parse canonical JSON case {id}: {error}"))?;
            let canonical_json = canonicalize_json(&value);
            Ok(json!({
                "id": id,
                "input_json": input_json,
                "canonical_json": canonical_json,
                "canonical_utf8_hex": hex::encode(canonical_json.as_bytes()),
            }))
        })
        .collect::<Result<Vec<_>, String>>()?;

    Ok(json!({
        "format": format!("{FORMAT_PREFIX}/canonical-json@1"),
        "production_function": "rcx_registry_ingest::canonicalize_json",
        "notes": [
            "Objects are sorted recursively; arrays retain input order.",
            "Object keys use Rust String ordering, not RFC 8785 UTF-16 ordering.",
            "Numbers are serde_json::Number values, so integer and floating forms remain distinct.",
            "Unicode is not normalized; duplicate object keys have already collapsed in serde_json::Value."
        ],
        "cases": cases,
    }))
}

fn canonical_cbor_vectors() -> Value {
    let cases = vec![
        cbor_case(
            "unsigned-integer-boundaries",
            CborValue::Array(vec![
                CborValue::Uint(0),
                CborValue::Uint(23),
                CborValue::Uint(24),
                CborValue::Uint(255),
                CborValue::Uint(256),
                CborValue::Uint(65_535),
                CborValue::Uint(65_536),
                CborValue::Uint(u32::MAX as u64),
                CborValue::Uint(u32::MAX as u64 + 1),
                CborValue::Uint(u64::MAX),
            ]),
        ),
        cbor_case(
            "integer-versus-float",
            CborValue::Array(vec![CborValue::Uint(1), CborValue::Float(1.0)]),
        ),
        cbor_case("negative-zero", CborValue::Float(-0.0)),
        cbor_case(
            "shortest-float-widths",
            CborValue::Array(vec![
                CborValue::Float(1.5),
                CborValue::Float(100_000.0),
                CborValue::Float(1.1),
            ]),
        ),
        cbor_case(
            "map-key-ordering-by-encoded-key",
            CborValue::Map(vec![
                ("aa".into(), CborValue::Uint(2)),
                ("😀".into(), CborValue::Uint(5)),
                ("b".into(), CborValue::Uint(3)),
                ("é".into(), CborValue::Uint(4)),
                ("a".into(), CborValue::Uint(1)),
            ]),
        ),
        cbor_case(
            "text-escaping-is-raw-utf8",
            CborValue::Text("quote: \" backslash: \\ controls: \0\n\t".into()),
        ),
        cbor_case(
            "unicode-astral-and-combining",
            CborValue::Array(vec![
                CborValue::Text("😀".into()),
                CborValue::Text("e\u{0301}".into()),
                CborValue::Text("é".into()),
            ]),
        ),
        cbor_case(
            "nested",
            CborValue::Map(vec![
                (
                    "z".into(),
                    CborValue::Array(vec![
                        CborValue::Map(vec![
                            ("y".into(), CborValue::Uint(2)),
                            ("x".into(), CborValue::Uint(1)),
                        ]),
                        CborValue::Array(Vec::new()),
                    ]),
                ),
                (
                    "a".into(),
                    CborValue::Map(vec![
                        ("false".into(), CborValue::Bool(false)),
                        ("null".into(), CborValue::Null),
                    ]),
                ),
            ]),
        ),
        cbor_case(
            "empty-containers",
            CborValue::Array(vec![
                CborValue::Bytes(Vec::new()),
                CborValue::Text(String::new()),
                CborValue::Array(Vec::new()),
                CborValue::Map(Vec::new()),
            ]),
        ),
        cbor_case(
            "bytes-bools-and-null",
            CborValue::Array(vec![
                CborValue::Bytes(vec![0x00, 0x7f, 0x80, 0xff]),
                CborValue::Bool(false),
                CborValue::Bool(true),
                CborValue::Null,
            ]),
        ),
        cbor_case(
            "duplicate-map-keys-retained",
            CborValue::Map(vec![
                ("same".into(), CborValue::Uint(1)),
                ("same".into(), CborValue::Uint(2)),
            ]),
        ),
    ];

    let rejection_cases = vec![
        cbor_rejection_case(
            "non-minimal-additional-info-24",
            "1817",
            "non-minimal-integer-head",
            "non-canonical integer head",
        ),
        cbor_rejection_case(
            "non-minimal-additional-info-25",
            "1900ff",
            "non-minimal-integer-head",
            "non-canonical integer head",
        ),
        cbor_rejection_case(
            "non-minimal-additional-info-26",
            "1a0000ffff",
            "non-minimal-integer-head",
            "non-canonical integer head",
        ),
        cbor_rejection_case(
            "non-minimal-additional-info-27",
            "1b00000000ffffffff",
            "non-minimal-integer-head",
            "non-canonical integer head",
        ),
        cbor_rejection_case(
            "non-shortest-f32-representable-as-f16",
            "fa3fc00000",
            "non-shortest-float",
            "non-canonical float encoding",
        ),
        cbor_rejection_case(
            "non-shortest-f64-representable-as-f32",
            "fb40f86a0000000000",
            "non-shortest-float",
            "non-canonical float encoding",
        ),
        cbor_rejection_case(
            "trailing-top-level-item",
            "00f6",
            "trailing-bytes",
            "trailing bytes at offset 1",
        ),
        cbor_rejection_case(
            "non-text-map-key",
            "a10000",
            "non-text-map-key",
            "non-text map keys are not supported",
        ),
        cbor_rejection_case(
            "reserved-additional-info-28",
            "1c",
            "reserved-additional-info",
            "reserved info value 28 not allowed in canonical cbor",
        ),
        cbor_rejection_case(
            "reserved-additional-info-29",
            "1d",
            "reserved-additional-info",
            "reserved info value 29 not allowed in canonical cbor",
        ),
        cbor_rejection_case(
            "reserved-additional-info-30",
            "1e",
            "reserved-additional-info",
            "reserved info value 30 not allowed in canonical cbor",
        ),
        cbor_rejection_case(
            "reserved-additional-info-31",
            "1f",
            "reserved-additional-info",
            "reserved info value 31 not allowed in canonical cbor",
        ),
    ];

    json!({
        "format": format!("{FORMAT_PREFIX}/canonical-cbor@1"),
        "production_function": "rcx_registry_crown::CborValue::encode",
        "typed_value_format": {
            "uint": "decimal string",
            "float": "IEEE-754 binary64 bits as 16 lowercase hex digits",
            "bytes": "lowercase hex",
            "map": "ordered entry array so duplicate keys remain representable"
        },
        "notes": [
            "Only unsigned integers are representable by the production CborValue type.",
            "Map keys are text and sort by their complete encoded CBOR key bytes.",
            "Finite floats use the shortest exact f16, f32, or f64 encoding."
        ],
        "cases": cases,
        "decoder_rejections": {
            "production_function": "rcx_registry_crown::decode",
            "notes": [
                "Every listed input MUST be rejected.",
                "Out-of-order and duplicate map keys are intentionally absent under OQ-6."
            ],
            "cases": rejection_cases,
        },
    })
}

fn cbor_case(id: &str, value: CborValue) -> Value {
    let encoded = value.encode();
    let decoded = decode(&encoded).unwrap_or_else(|error| panic!("decode CBOR case {id}: {error}"));
    assert_eq!(
        decoded.encode(),
        encoded,
        "production CBOR round trip changed case {id}"
    );

    json!({
        "id": id,
        "input": describe_cbor(&value),
        "canonical_cbor_hex": hex::encode(&encoded),
        "decoded": describe_cbor(&decoded),
    })
}

fn cbor_rejection_case(
    id: &str,
    input_cbor_hex: &str,
    reason_code: &str,
    expected_decoder_error: &str,
) -> Value {
    let input = hex::decode(input_cbor_hex)
        .unwrap_or_else(|error| panic!("decode rejection-vector hex {id}: {error}"));
    let error = match decode(&input) {
        Ok(value) => panic!("decoder accepted rejection vector {id}: {value:?}"),
        Err(error) => error,
    };
    assert_eq!(
        error,
        CrownError::Decode(expected_decoder_error.to_string()),
        "production decoder returned an unexpected error for rejection vector {id}"
    );

    json!({
        "id": id,
        "input_cbor_hex": hex::encode(input),
        "must_reject": true,
        "reason_code": reason_code,
        "production_decoder_error": error.to_string(),
    })
}

fn describe_cbor(value: &CborValue) -> Value {
    match value {
        CborValue::Uint(number) => json!({
            "type": "uint",
            "value": number.to_string(),
        }),
        CborValue::Bytes(bytes) => json!({
            "type": "bytes",
            "hex": hex::encode(bytes),
        }),
        CborValue::Text(text) => json!({
            "type": "text",
            "value": text,
            "utf8_hex": hex::encode(text.as_bytes()),
        }),
        CborValue::Array(items) => json!({
            "type": "array",
            "items": items.iter().map(describe_cbor).collect::<Vec<_>>(),
        }),
        CborValue::Map(entries) => json!({
            "type": "map",
            "entries": entries
                .iter()
                .map(|(key, value)| json!({
                    "key": key,
                    "value": describe_cbor(value),
                }))
                .collect::<Vec<_>>(),
        }),
        CborValue::Bool(boolean) => json!({
            "type": "bool",
            "value": boolean,
        }),
        CborValue::Null => json!({"type": "null"}),
        CborValue::Float(number) => json!({
            "type": "float",
            "f64_bits_hex": format!("{:016x}", number.to_bits()),
        }),
    }
}

fn hash_vectors() -> Result<Value, String> {
    let declaration_definitions = [
        ("empty-object", r#"{}"#, Value::Null, None),
        (
            "reordered-object-a",
            r#"{"b":2,"a":{"z":0,"m":1}}"#,
            json!("reordered-object"),
            None,
        ),
        (
            "reordered-object-b",
            r#"{"a":{"m":1,"z":0},"b":2}"#,
            json!("reordered-object"),
            None,
        ),
        (
            "unicode-combining",
            r#"{"value":"e\u0301"}"#,
            Value::Null,
            Some(
                "Visually similar to unicode-precomposed; hash_input_utf8_hex is authoritative (U+0065 U+0301).",
            ),
        ),
        (
            "unicode-precomposed",
            r#"{"value":"é"}"#,
            Value::Null,
            Some(
                "Visually similar to unicode-combining; hash_input_utf8_hex is authoritative (U+00E9).",
            ),
        ),
        ("integer-one", r#"{"value":1}"#, Value::Null, None),
        ("float-one", r#"{"value":1.0}"#, Value::Null, None),
        ("negative-zero", r#"{"value":-0.0}"#, Value::Null, None),
    ];

    let declaration_cases = declaration_definitions
        .into_iter()
        .map(|(id, input_json, equivalence_group, note)| {
            let value: Value = serde_json::from_str(input_json)
                .map_err(|error| format!("parse hash case {id}: {error}"))?;
            let (digest, canonical_json) = declaration_hash(&value);
            let mut case = json!({
                "id": id,
                "input_json": input_json,
                "canonical_json": canonical_json,
                "hash_input_utf8_hex": hex::encode(canonical_json.as_bytes()),
                "digest_hex": hex::encode(digest),
                "equivalence_group": equivalence_group,
            });
            if let Some(note) = note {
                case["note"] = json!(note);
            }
            Ok(case)
        })
        .collect::<Result<Vec<_>, String>>()?;

    let server = make_server(
        "io.example/hash-input",
        "1.0.0",
        json!({"astral": "😀", "combining": "e\u{0301}"}),
    );
    let server_digest = canonical_server_hash(&server);
    let mut server_hash_input = Vec::new();
    server_hash_input.extend_from_slice(server.name.as_bytes());
    server_hash_input.push(0x00);
    server_hash_input.extend_from_slice(server.version.as_bytes());
    server_hash_input.push(0x00);
    server_hash_input.extend_from_slice(server.canonical_json.as_bytes());
    assert_eq!(
        server_digest,
        *blake3::hash(&server_hash_input).as_bytes(),
        "diagnostic canonical_server_hash preimage drifted from production"
    );
    let mut snapshot_entry_frame = server_hash_input.clone();
    snapshot_entry_frame.push(0xff);
    let server_hash_cases = vec![json!({
        "id": "canonical-server-hash",
        "name": server.name,
        "version": server.version,
        "canonical_json": server.canonical_json,
        "hash_input_hex": hex::encode(server_hash_input),
        "snapshot_entry_frame_hex": hex::encode(snapshot_entry_frame),
        "digest_hex": hex::encode(server_digest),
    })];

    Ok(json!({
        "format": format!("{FORMAT_PREFIX}/hashes@1"),
        "algorithm": "BLAKE3-256",
        "declaration_hash": {
            "production_function": "rcx_registry_enrich::declaration_hash",
            "input_rule": "UTF-8 bytes of production canonical JSON",
            "cases": declaration_cases,
        },
        "canonical_server_hash": {
            "production_function": "rcx_registry_ingest::canonical_server_hash",
            "input_rule":
                "name UTF-8 || 00 || version UTF-8 || 00 || canonical_json UTF-8 (no trailing ff)",
            "snapshot_entry_frame_rule":
                "the related snapshot_merkle_root frame appends ff; it is exposed for diagnostics but is not this digest's input",
            "cases": server_hash_cases,
        },
    }))
}

fn receipt_vectors() -> Result<Value, String> {
    let signing_key = test_signing_key();
    let public_key = signing_key.verifying_key().to_bytes();
    let mut publisher_receipt = build_publisher_rights_verified_receipt(
        [0x11; 16],
        "passport:github:example-org",
        "io.github.example-org",
        VerificationMethod::GitHubOAuth,
        1_776_683_260_000,
        TEST_SIGNER_KID,
    );

    let zeroed_cbor = publisher_receipt.to_zeroed_canonical_cbor();
    let digest = publisher_receipt.compute_hash();
    assert_eq!(publisher_receipt.receipt_hash, digest);
    let signature_preimage = publisher_receipt.to_canonical_cbor();
    validate_path_a_signature_preimage(
        "publisher-rights-production-preimage-sign-verify",
        &signature_preimage,
        &digest,
        TEST_SIGNER_KID,
    )?;
    publisher_receipt.receipt_signature = signing_key.sign(&signature_preimage).to_bytes();
    verify_receipt_signature(&publisher_receipt, &public_key)
        .map_err(|error| format!("positive receipt vector did not verify: {error}"))?;
    let signed_cbor = publisher_receipt.to_canonical_cbor();

    let mut tampered_signature = publisher_receipt.clone();
    tampered_signature.receipt_signature[0] ^= 0x01;
    let tampered_cbor = tampered_signature.to_canonical_cbor();
    let byte_differences = byte_differences(&signed_cbor, &tampered_cbor);
    if byte_differences.len() != 1 {
        return Err(format!(
            "signature tamper changed {} canonical CBOR bytes, expected 1",
            byte_differences.len()
        ));
    }
    let tampered_error = verify_receipt_signature(&tampered_signature, &public_key)
        .expect_err("one-byte signature tamper must fail")
        .to_string();

    let mut tampered_content = publisher_receipt.clone();
    tampered_content.namespace = "io.github.fxample-org".into();
    let content_error = verify_receipt_signature(&tampered_content, &public_key)
        .expect_err("content tamper must fail")
        .to_string();

    let mut hash_signed_receipt = publisher_receipt.clone();
    hash_signed_receipt.receipt_signature = signing_key.sign(&digest).to_bytes();
    let hash_signed_error = verify_receipt_signature(&hash_signed_receipt, &public_key)
        .expect_err("signature over the 32-byte receipt hash must fail")
        .to_string();

    let mut zeroed_variant = publisher_receipt.clone();
    zeroed_variant.receipt_hash = [0xa5; HASH_LEN];
    zeroed_variant.receipt_signature = [0x5a; SIGNATURE_LEN];
    zeroed_variant.signer_kid = "test-only:rotated".into();
    let zeroed_fields_are_ignored = zeroed_variant.to_zeroed_canonical_cbor() == zeroed_cbor
        && zeroed_variant.compute_hash() == digest;
    assert!(zeroed_fields_are_ignored);

    let (offset, original_byte, tampered_byte) = byte_differences[0];
    let publisher_case = json!({
        "id": "publisher-rights-production-preimage-sign-verify",
        "receipt_type": "PublisherRightsVerified",
        "production_constructor":
            "rcx_registry_admin::build_publisher_rights_verified_receipt",
        "fields_after_construction_before_signature": {
            "event_id_hex": hex::encode([0x11; 16]),
            "publisher_passport": "passport:github:example-org",
            "namespace": "io.github.example-org",
            "verification_method": "github_oauth",
            "verified_at": "1776683260000",
            "receipt_hash_hex": hex::encode(digest),
            "receipt_signature_hex": hex::encode([0u8; SIGNATURE_LEN]),
            "signer_kid": TEST_SIGNER_KID,
        },
        "zeroed_canonical_cbor_hex": hex::encode(zeroed_cbor),
        "receipt_hash_hex": hex::encode(digest),
        "signature_preimage_rule":
            "full canonical CBOR with only receipt_signature zeroed; signer_kid and the real receipt_hash remain present",
        "signature_preimage_canonical_cbor_hex": hex::encode(&signature_preimage),
        "ed25519_message_hex": hex::encode(&signature_preimage),
        "receipt_signature_hex": hex::encode(publisher_receipt.receipt_signature),
        "signed_canonical_cbor_hex": hex::encode(&signed_cbor),
        "verify_result": true,
        "zeroed_hash_ignores_receipt_hash_signature_and_signer_kid": zeroed_fields_are_ignored,
        "negative_cases": [
            {
                "id": "one-signature-byte-tampered",
                "tampered_canonical_cbor_hex": hex::encode(tampered_cbor),
                "changed_byte_offset": offset,
                "original_byte_hex": format!("{original_byte:02x}"),
                "tampered_byte_hex": format!("{tampered_byte:02x}"),
                "verify_result": false,
                "error": tampered_error,
            },
            {
                "id": "content-byte-tampered",
                "field": "namespace",
                "original": publisher_receipt.namespace,
                "tampered": tampered_content.namespace,
                "verify_result": false,
                "error": content_error,
            },
            {
                "id": "signature-over-32-byte-receipt-hash",
                "ed25519_message_hex": hex::encode(digest),
                "receipt_signature_hex": hex::encode(hash_signed_receipt.receipt_signature),
                "signed_canonical_cbor_hex":
                    hex::encode(hash_signed_receipt.to_canonical_cbor()),
                "verify_result": false,
                "error": hash_signed_error,
            }
        ],
    });

    let auto_payload = AutoEnrichmentPayload::new("2026-04-19T10:03:00Z");
    let mut auto_receipt = build_entry_auto_enriched_receipt(
        "io.example/auto-enriched",
        [0x33; 16],
        [0x22; 16],
        &auto_payload,
        TEST_SIGNER_KID,
    );
    let auto_artifacts = sign_receipt(
        "entry-auto-enriched-production-preimage-sign-verify",
        &mut auto_receipt,
        &signing_key,
        &public_key,
        |receipt, signature| receipt.receipt_signature = signature,
    )?;
    let auto_case = json!({
        "id": "entry-auto-enriched-production-preimage-sign-verify",
        "receipt_type": "EntryAutoEnriched",
        "production_constructor":
            "rcx_registry_enrich::build_entry_auto_enriched_receipt",
        "fields_after_construction_before_signature": {
            "event_id_hex": hex::encode([0x22; 16]),
            "server_name": auto_receipt.server_name,
            "snapshot_id_hex": hex::encode([0x33; 16]),
            "auto_enrichment_bytes_hex": hex::encode(&auto_receipt.auto_enrichment_bytes),
            "receipt_hash_hex": hex::encode(auto_artifacts.receipt_hash),
            "receipt_signature_hex": hex::encode([0u8; SIGNATURE_LEN]),
            "signer_kid": TEST_SIGNER_KID,
        },
        "zeroed_canonical_cbor_hex": hex::encode(auto_artifacts.zeroed_canonical_cbor),
        "receipt_hash_hex": hex::encode(auto_artifacts.receipt_hash),
        "signature_preimage_rule":
            "full canonical CBOR with only receipt_signature zeroed; signer_kid and the real receipt_hash remain present",
        "signature_preimage_canonical_cbor_hex":
            hex::encode(&auto_artifacts.signature_preimage_canonical_cbor),
        "ed25519_message_hex": hex::encode(&auto_artifacts.signature_preimage_canonical_cbor),
        "receipt_signature_hex": hex::encode(auto_artifacts.receipt_signature),
        "signed_canonical_cbor_hex": hex::encode(auto_artifacts.signed_canonical_cbor),
        "verify_result": true,
    });

    let attestation_bytes = CborValue::Map(vec![
        (
            "server_name".into(),
            CborValue::Text("io.example/attested".into()),
        ),
        ("type".into(), CborValue::Text("auditor".into())),
        ("issued_at".into(), CborValue::Uint(1_776_683_320_000)),
    ])
    .encode();
    let attestation_hash = *blake3::hash(&attestation_bytes).as_bytes();
    let mut accepted_receipt = AttestationAcceptedReceipt {
        event_id: [0x44; 16],
        attestation_id: [0x55; 16],
        server_name: "io.example/attested".into(),
        issuer_passport: "passport:auditor:example".into(),
        attestation_type: "auditor".into(),
        attestation_hash,
        attestation_bytes,
        receipt_hash: [0u8; HASH_LEN],
        receipt_signature: [0u8; SIGNATURE_LEN],
        signer_kid: TEST_SIGNER_KID.into(),
    };
    accepted_receipt.receipt_hash = accepted_receipt.compute_hash();
    let accepted_artifacts = sign_receipt(
        "attestation-accepted-production-preimage-sign-verify",
        &mut accepted_receipt,
        &signing_key,
        &public_key,
        |receipt, signature| receipt.receipt_signature = signature,
    )?;
    let accepted_case = json!({
        "id": "attestation-accepted-production-preimage-sign-verify",
        "receipt_type": "AttestationAccepted",
        "production_receipt_type": "rcx_registry_crown::AttestationAcceptedReceipt",
        "construction_note":
            "No dedicated production builder exists; the production crown struct is initialized and its ReceiptDocument::compute_hash method populates receipt_hash.",
        "fields_after_construction_before_signature": {
            "event_id_hex": hex::encode([0x44; 16]),
            "attestation_id_hex": hex::encode([0x55; 16]),
            "server_name": accepted_receipt.server_name,
            "issuer_passport": accepted_receipt.issuer_passport,
            "type": accepted_receipt.attestation_type,
            "attestation_hash_hex": hex::encode(accepted_receipt.attestation_hash),
            "attestation_bytes_hex": hex::encode(&accepted_receipt.attestation_bytes),
            "receipt_hash_hex": hex::encode(accepted_artifacts.receipt_hash),
            "receipt_signature_hex": hex::encode([0u8; SIGNATURE_LEN]),
            "signer_kid": TEST_SIGNER_KID,
        },
        "zeroed_canonical_cbor_hex": hex::encode(accepted_artifacts.zeroed_canonical_cbor),
        "receipt_hash_hex": hex::encode(accepted_artifacts.receipt_hash),
        "signature_preimage_rule":
            "full canonical CBOR with only receipt_signature zeroed; signer_kid and the real receipt_hash remain present",
        "signature_preimage_canonical_cbor_hex":
            hex::encode(&accepted_artifacts.signature_preimage_canonical_cbor),
        "ed25519_message_hex": hex::encode(&accepted_artifacts.signature_preimage_canonical_cbor),
        "receipt_signature_hex": hex::encode(accepted_artifacts.receipt_signature),
        "signed_canonical_cbor_hex": hex::encode(accepted_artifacts.signed_canonical_cbor),
        "verify_result": true,
    });

    let revocation_authorization_message =
        b"rcx-spec-v1 attestation revocation authorization:5555555555555555";
    let revocation_signature = signing_key
        .sign(revocation_authorization_message)
        .to_bytes();
    let mut revoked_receipt = AttestationRevokedReceipt {
        event_id: [0x66; 16],
        attestation_id: [0x55; 16],
        revoker_passport: "passport:auditor:example".into(),
        reason: Some("superseded by corrected audit".into()),
        revoked_at: 1_776_683_380_000,
        revocation_signature,
        receipt_hash: [0u8; HASH_LEN],
        receipt_signature: [0u8; SIGNATURE_LEN],
        signer_kid: TEST_SIGNER_KID.into(),
    };
    revoked_receipt.receipt_hash = revoked_receipt.compute_hash();

    let mut zeroed_revocation_variant = revoked_receipt.clone();
    zeroed_revocation_variant.revocation_signature = [0u8; SIGNATURE_LEN];
    let revocation_signature_is_hash_content = revoked_receipt.to_zeroed_canonical_cbor()
        != zeroed_revocation_variant.to_zeroed_canonical_cbor()
        && revoked_receipt.compute_hash() != zeroed_revocation_variant.compute_hash();
    if !revocation_signature_is_hash_content {
        return Err("revocation_signature was unexpectedly neutralized in the receipt hash".into());
    }

    let wrongly_zeroed_revocation_preimage = zeroed_revocation_variant.to_canonical_cbor();
    let wrongly_zeroed_revocation_receipt_signature = signing_key
        .sign(&wrongly_zeroed_revocation_preimage)
        .to_bytes();
    let mut wrongly_signed_revocation = revoked_receipt.clone();
    wrongly_signed_revocation.receipt_signature = wrongly_zeroed_revocation_receipt_signature;
    let wrongly_zeroed_revocation_error =
        verify_receipt_signature(&wrongly_signed_revocation, &public_key)
            .expect_err("zeroing revocation_signature in the path-A preimage must fail")
            .to_string();

    let revoked_artifacts = sign_receipt(
        "attestation-revoked-production-preimage-sign-verify",
        &mut revoked_receipt,
        &signing_key,
        &public_key,
        |receipt, signature| receipt.receipt_signature = signature,
    )?;
    let revoked_case = json!({
        "id": "attestation-revoked-production-preimage-sign-verify",
        "receipt_type": "AttestationRevoked",
        "production_receipt_type": "rcx_registry_crown::AttestationRevokedReceipt",
        "construction_note":
            "No dedicated production builder exists; the production crown struct is initialized and its ReceiptDocument::compute_hash method populates receipt_hash.",
        "fields_after_construction_before_signature": {
            "event_id_hex": hex::encode([0x66; 16]),
            "attestation_id_hex": hex::encode([0x55; 16]),
            "revoker_passport": revoked_receipt.revoker_passport,
            "reason": revoked_receipt.reason,
            "revoked_at": "1776683380000",
            "revocation_signature_hex": hex::encode(revoked_receipt.revocation_signature),
            "receipt_hash_hex": hex::encode(revoked_artifacts.receipt_hash),
            "receipt_signature_hex": hex::encode([0u8; SIGNATURE_LEN]),
            "signer_kid": TEST_SIGNER_KID,
        },
        "zeroed_canonical_cbor_hex": hex::encode(revoked_artifacts.zeroed_canonical_cbor),
        "receipt_hash_hex": hex::encode(revoked_artifacts.receipt_hash),
        "revocation_signature_preserved_in_hash_preimage": revocation_signature_is_hash_content,
        "signature_preimage_rule":
            "full canonical CBOR with only receipt_signature zeroed; revocation_signature, signer_kid, and the real receipt_hash remain present",
        "revocation_signature_preserved_in_signature_preimage": true,
        "signature_preimage_canonical_cbor_hex":
            hex::encode(&revoked_artifacts.signature_preimage_canonical_cbor),
        "ed25519_message_hex": hex::encode(&revoked_artifacts.signature_preimage_canonical_cbor),
        "receipt_signature_hex": hex::encode(revoked_artifacts.receipt_signature),
        "signed_canonical_cbor_hex": hex::encode(revoked_artifacts.signed_canonical_cbor),
        "verify_result": true,
        "negative_cases": [{
            "id": "revocation-signature-wrongly-zeroed-in-signature-preimage",
            "ed25519_message_hex": hex::encode(wrongly_zeroed_revocation_preimage),
            "receipt_signature_hex":
                hex::encode(wrongly_zeroed_revocation_receipt_signature),
            "signed_canonical_cbor_hex":
                hex::encode(wrongly_signed_revocation.to_canonical_cbor()),
            "verify_result": false,
            "error": wrongly_zeroed_revocation_error,
        }],
    });

    Ok(json!({
        "format": format!("{FORMAT_PREFIX}/receipts@1"),
        "production_functions": [
            "rcx_registry_admin::build_publisher_rights_verified_receipt",
            "rcx_registry_enrich::build_entry_auto_enriched_receipt",
            "rcx_registry_crown::ReceiptDocument::to_zeroed_canonical_cbor",
            "rcx_registry_crown::ReceiptDocument::compute_hash",
            "rcx_registry_crown::ReceiptDocument::to_canonical_cbor",
            "rcx_registry_crown::verify_receipt_signature"
        ],
        "signature_verification_rule":
            "recompute and compare receipt_hash, then verify raw Ed25519 over full canonical CBOR with only receipt_signature zeroed; signer_kid and the real receipt_hash remain present",
        "test_key": test_key_json(&signing_key),
        "cases": [publisher_case, auto_case, accepted_case, revoked_case],
    }))
}

struct SignedReceiptArtifacts {
    zeroed_canonical_cbor: Vec<u8>,
    receipt_hash: [u8; HASH_LEN],
    signature_preimage_canonical_cbor: Vec<u8>,
    receipt_signature: [u8; SIGNATURE_LEN],
    signed_canonical_cbor: Vec<u8>,
}

fn sign_receipt<T: ReceiptDocument>(
    id: &str,
    receipt: &mut T,
    signing_key: &SigningKey,
    public_key: &[u8; 32],
    set_signature: impl FnOnce(&mut T, [u8; SIGNATURE_LEN]),
) -> Result<SignedReceiptArtifacts, String> {
    let zeroed_canonical_cbor = receipt.to_zeroed_canonical_cbor();
    let receipt_hash = receipt.compute_hash();
    if receipt.stored_hash() != &receipt_hash {
        return Err(format!(
            "production constructor stored the wrong receipt hash for {id}"
        ));
    }
    if receipt.stored_signature() != &[0u8; SIGNATURE_LEN] {
        return Err(format!(
            "production constructor did not leave receipt_signature zeroed for {id}"
        ));
    }

    let signature_preimage_canonical_cbor = receipt.to_canonical_cbor();
    validate_path_a_signature_preimage(
        id,
        &signature_preimage_canonical_cbor,
        &receipt_hash,
        TEST_SIGNER_KID,
    )?;
    let receipt_signature = signing_key
        .sign(&signature_preimage_canonical_cbor)
        .to_bytes();
    set_signature(receipt, receipt_signature);
    verify_receipt_signature(receipt, public_key)
        .map_err(|error| format!("positive receipt vector {id} did not verify: {error}"))?;

    Ok(SignedReceiptArtifacts {
        zeroed_canonical_cbor,
        receipt_hash,
        signature_preimage_canonical_cbor,
        receipt_signature,
        signed_canonical_cbor: receipt.to_canonical_cbor(),
    })
}

fn validate_path_a_signature_preimage(
    id: &str,
    preimage: &[u8],
    receipt_hash: &[u8; HASH_LEN],
    signer_kid: &str,
) -> Result<(), String> {
    let value = decode(preimage)
        .map_err(|error| format!("decode path-A signature preimage for {id}: {error}"))?;
    let CborValue::Map(fields) = value else {
        return Err(format!("path-A signature preimage for {id} was not a map"));
    };

    let field = |name: &str| {
        fields
            .iter()
            .find(|(field_name, _)| field_name == name)
            .map(|(_, value)| value)
    };
    if !matches!(
        field("receipt_hash"),
        Some(CborValue::Bytes(bytes)) if bytes.as_slice() == receipt_hash
    ) {
        return Err(format!(
            "path-A signature preimage for {id} did not retain the real receipt_hash"
        ));
    }
    if !matches!(
        field("receipt_signature"),
        Some(CborValue::Bytes(bytes))
            if bytes.as_slice() == [0u8; SIGNATURE_LEN].as_slice()
    ) {
        return Err(format!(
            "path-A signature preimage for {id} did not zero receipt_signature"
        ));
    }
    if !matches!(
        field("signer_kid"),
        Some(CborValue::Text(value)) if value == signer_kid
    ) {
        return Err(format!(
            "path-A signature preimage for {id} did not retain signer_kid"
        ));
    }

    Ok(())
}

fn snapshot_vectors() -> Result<Value, String> {
    let empty = Vec::new();
    let one = vec![make_server("io.example/alpha", "1.0.0", json!({"n": 1}))];
    let two_a = vec![
        make_server("io.example/beta", "2.0.0", json!({"n": 2})),
        make_server("io.example/alpha", "1.0.0", json!({"n": 1})),
    ];
    let two_b = vec![two_a[1].clone(), two_a[0].clone()];
    let odd = vec![
        make_server("io.example/gamma", "1.0.0", json!({"n": 3})),
        make_server("io.example/alpha", "2.0.0", json!({"n": 2})),
        make_server("io.example/alpha", "10.0.0", json!({"n": 10})),
    ];
    let larger = vec![
        make_server("io.example/hotel", "1.0.0", json!({"n": 8})),
        make_server("io.example/alpha", "1.0.0", json!({"n": 1})),
        make_server("io.example/golf", "1.0.0", json!({"n": 7})),
        make_server("io.example/charlie", "1.0.0", json!({"n": 3})),
        make_server("io.example/foxtrot", "1.0.0", json!({"n": 6})),
        make_server("io.example/bravo", "1.0.0", json!({"n": 2})),
        make_server("io.example/echo", "1.0.0", json!({"n": 5})),
        make_server("io.example/delta", "1.0.0", json!({"n": 4})),
    ];
    let duplicate_identical = vec![one[0].clone(), one[0].clone()];
    let duplicate_tie_a = vec![
        make_server("io.example/duplicate", "1.0.0", json!({"payload": "first"})),
        make_server(
            "io.example/duplicate",
            "1.0.0",
            json!({"payload": "second"}),
        ),
    ];
    let duplicate_tie_b = vec![duplicate_tie_a[1].clone(), duplicate_tie_a[0].clone()];

    let two_a_root = snapshot_merkle_root(&two_a);
    let two_b_root = snapshot_merkle_root(&two_b);
    if two_a_root != two_b_root {
        return Err("unique-entry permutation unexpectedly changed snapshot root".into());
    }
    let duplicate_a_root = snapshot_merkle_root(&duplicate_tie_a);
    let duplicate_b_root = snapshot_merkle_root(&duplicate_tie_b);
    if duplicate_a_root == duplicate_b_root {
        return Err("same-key differing duplicates unexpectedly produced equal roots".into());
    }

    let cases = vec![
        snapshot_case("empty-set", &empty, None),
        snapshot_case("one-element", &one, None),
        snapshot_case("two-elements-unsorted", &two_a, Some("unique-permutation")),
        snapshot_case("two-elements-permuted", &two_b, Some("unique-permutation")),
        snapshot_case("odd-three-elements", &odd, None),
        snapshot_case("larger-eight-elements", &larger, None),
        snapshot_case("duplicate-identical-retained", &duplicate_identical, None),
        snapshot_case(
            "duplicate-same-key-order-a",
            &duplicate_tie_a,
            Some("duplicate-tie-order-sensitive"),
        ),
        snapshot_case(
            "duplicate-same-key-order-b",
            &duplicate_tie_b,
            Some("duplicate-tie-order-sensitive"),
        ),
    ];

    Ok(json!({
        "format": format!("{FORMAT_PREFIX}/snapshot-merkle@1"),
        "production_function": "rcx_registry_ingest::snapshot_merkle_root",
        "observed_rules": {
            "construction": "one BLAKE3-256 stream, not a pairwise Merkle tree",
            "entry_frame": "name UTF-8 || 00 || version UTF-8 || 00 || canonical_json UTF-8 || ff",
            "ordering": "stable lexical sort by name, then version",
            "version_order": "lexical, not semantic version order",
            "duplicates": "retained; equal (name, version) ties preserve input order",
            "empty_set": "BLAKE3-256 of the empty byte string"
        },
        "invariants": {
            "unique_permutation_roots_equal": hex::encode(two_a_root) == hex::encode(two_b_root),
            "same_key_different_payload_permutations_differ":
                hex::encode(duplicate_a_root) != hex::encode(duplicate_b_root),
        },
        "cases": cases,
    }))
}

fn snapshot_case(id: &str, entries: &[MirroredServer], equivalence_group: Option<&str>) -> Value {
    json!({
        "id": id,
        "input_order": entries.iter().map(describe_server).collect::<Vec<_>>(),
        "server_count": entries.len(),
        "root_hex": hex::encode(snapshot_merkle_root(entries)),
        "equivalence_group": equivalence_group,
    })
}

fn chain_vectors() -> Result<Value, String> {
    let signing_key = test_signing_key();
    let public_key = signing_key.verifying_key().to_bytes();
    let snapshot_chain = snapshot_chain(&signing_key, &public_key)?;
    let enrichment_chain = enrichment_receipt_chain(&signing_key, &public_key)?;

    Ok(json!({
        "format": format!("{FORMAT_PREFIX}/chains@1"),
        "test_key": test_key_json(&signing_key),
        "snapshot_chain": snapshot_chain,
        "entry_enriched_receipt_chain": enrichment_chain,
    }))
}

#[derive(Debug, Deserialize)]
struct StructuredChainVectors {
    test_key: StructuredChainTestKey,
    snapshot_chain: StructuredChain<StructuredSnapshotLink>,
    entry_enriched_receipt_chain: StructuredChain<StructuredEnrichmentLink>,
}

#[derive(Debug, Deserialize)]
struct StructuredChainTestKey {
    seed_hex: String,
    public_key_hex: String,
    signer_kid: String,
}

#[derive(Debug, Deserialize)]
struct StructuredChain<T> {
    links: Vec<T>,
}

#[derive(Debug, Deserialize)]
struct StructuredServerInput {
    name: String,
    version: String,
    canonical_json: String,
}

#[derive(Debug, Deserialize)]
struct StructuredSnapshotChanges {
    added: u64,
    removed: u64,
    modified: u64,
}

#[derive(Debug, Deserialize)]
struct StructuredSnapshotLink {
    link: usize,
    event_id_hex: String,
    snapshot_id_hex: String,
    scraped_at_unix_ms: u64,
    servers: Vec<StructuredServerInput>,
    previous_servers: Vec<StructuredServerInput>,
    previous_snapshot_hash_hex: Option<String>,
    upstream_registry_uri: String,
    upstream_snapshot_etag: Option<String>,
    signer_kid: String,
    snapshot_merkle_root_hex: String,
    server_count: u64,
    changes: StructuredSnapshotChanges,
    zeroed_canonical_cbor_hex: String,
    receipt_hash_hex: String,
    signature_preimage_canonical_cbor_hex: String,
    receipt_signature_hex: String,
    signed_canonical_cbor_hex: String,
}

#[derive(Debug, Deserialize)]
struct StructuredEnrichmentLink {
    link: usize,
    event_id_hex: String,
    server_name: String,
    declaration: PublisherDeclaration,
    canonical_declaration_json: String,
    declared_uri: String,
    declared_hash_hex: String,
    enrichment_payload: PublisherEnrichmentPayload,
    signer_kid: String,
    supersedes_prior_receipt_hash_hex: Option<String>,
    zeroed_canonical_cbor_hex: String,
    receipt_hash_hex: String,
    signature_preimage_canonical_cbor_hex: String,
    receipt_signature_hex: String,
    signed_canonical_cbor_hex: String,
}

fn check_chain_receipts_from_structured_inputs(contents: &str) -> Result<(), String> {
    let vectors = serde_json::from_str::<StructuredChainVectors>(contents)
        .map_err(|error| format!("parse structured chain inputs: {error}"))?;
    let seed = decode_fixed_hex::<32>("test_key.seed_hex", &vectors.test_key.seed_hex)?;
    let expected_public_key =
        decode_fixed_hex::<32>("test_key.public_key_hex", &vectors.test_key.public_key_hex)?;
    let signing_key = SigningKey::from_bytes(&seed);
    let public_key = signing_key.verifying_key().to_bytes();
    if public_key != expected_public_key {
        return Err("test_key.public_key_hex does not match test_key.seed_hex".into());
    }

    let mut previous_snapshot_root = None;
    for (index, link) in vectors.snapshot_chain.links.iter().enumerate() {
        let expected_link = index + 1;
        if link.link != expected_link {
            return Err(format!(
                "snapshot link order mismatch: expected {expected_link}, found {}",
                link.link
            ));
        }
        if link.signer_kid != vectors.test_key.signer_kid {
            return Err(format!(
                "snapshot link {} signer_kid does not match test_key.signer_kid",
                link.link
            ));
        }
        previous_snapshot_root = Some(check_structured_snapshot_link(
            link,
            previous_snapshot_root,
            &signing_key,
            &public_key,
        )?);
    }

    let mut previous_enrichment_receipt_hash = None;
    for (index, link) in vectors
        .entry_enriched_receipt_chain
        .links
        .iter()
        .enumerate()
    {
        let expected_link = index + 1;
        if link.link != expected_link {
            return Err(format!(
                "entry enrichment link order mismatch: expected {expected_link}, found {}",
                link.link
            ));
        }
        if link.signer_kid != vectors.test_key.signer_kid {
            return Err(format!(
                "entry enrichment link {} signer_kid does not match test_key.signer_kid",
                link.link
            ));
        }
        previous_enrichment_receipt_hash = Some(check_structured_enrichment_link(
            link,
            previous_enrichment_receipt_hash,
            &signing_key,
            &public_key,
        )?);
    }

    Ok(())
}

fn check_structured_snapshot_link(
    link: &StructuredSnapshotLink,
    expected_previous_root: Option<[u8; HASH_LEN]>,
    signing_key: &SigningKey,
    public_key: &[u8; 32],
) -> Result<[u8; HASH_LEN], String> {
    let context = format!("snapshot link {}", link.link);
    let event_id = decode_fixed_hex::<16>(&format!("{context} event_id_hex"), &link.event_id_hex)?;
    let snapshot_id =
        decode_fixed_hex::<16>(&format!("{context} snapshot_id_hex"), &link.snapshot_id_hex)?;
    let previous_snapshot_hash = decode_optional_fixed_hex::<HASH_LEN>(
        &format!("{context} previous_snapshot_hash_hex"),
        link.previous_snapshot_hash_hex.as_deref(),
    )?;
    if previous_snapshot_hash != expected_previous_root {
        return Err(format!(
            "{context} previous_snapshot_hash_hex does not link to the prior snapshot root"
        ));
    }

    let current = mirrored_servers_from_structured_inputs(&link.servers, &context)?;
    let previous = mirrored_servers_from_structured_inputs(
        &link.previous_servers,
        &format!("{context} previous_servers"),
    )?;
    let plan = build_snapshot_plan(
        &current,
        &previous,
        event_id,
        snapshot_id,
        link.scraped_at_unix_ms,
        previous_snapshot_hash,
        link.upstream_snapshot_etag.as_deref(),
        &link.signer_kid,
    );
    let mut receipt = plan.snapshot_receipt;

    let expected_root = decode_fixed_hex::<HASH_LEN>(
        &format!("{context} snapshot_merkle_root_hex"),
        &link.snapshot_merkle_root_hex,
    )?;
    if receipt.snapshot_merkle_root != expected_root {
        return Err(format!("{context} snapshot_merkle_root_hex mismatch"));
    }
    if receipt.server_count != link.server_count {
        return Err(format!("{context} server_count mismatch"));
    }
    if receipt.changes.added != link.changes.added
        || receipt.changes.removed != link.changes.removed
        || receipt.changes.modified != link.changes.modified
    {
        return Err(format!("{context} changes mismatch"));
    }
    if receipt.event_id != event_id
        || receipt.snapshot_id != snapshot_id
        || receipt.scraped_at != link.scraped_at_unix_ms
        || receipt.previous_snapshot_hash != previous_snapshot_hash
        || receipt.upstream_registry_uri.as_str() != link.upstream_registry_uri.as_str()
        || receipt.upstream_snapshot_etag.as_deref() != link.upstream_snapshot_etag.as_deref()
        || receipt.signer_kid.as_str() != link.signer_kid.as_str()
    {
        return Err(format!("{context} constructor field mismatch"));
    }

    check_embedded_hex(
        &format!("{context} zeroed_canonical_cbor_hex"),
        &link.zeroed_canonical_cbor_hex,
        &receipt.to_zeroed_canonical_cbor(),
    )?;
    check_embedded_hex(
        &format!("{context} receipt_hash_hex"),
        &link.receipt_hash_hex,
        &receipt.receipt_hash,
    )?;
    let signature_preimage = receipt.to_canonical_cbor();
    check_embedded_hex(
        &format!("{context} signature_preimage_canonical_cbor_hex"),
        &link.signature_preimage_canonical_cbor_hex,
        &signature_preimage,
    )?;
    let receipt_signature = signing_key.sign(&signature_preimage).to_bytes();
    check_embedded_hex(
        &format!("{context} receipt_signature_hex"),
        &link.receipt_signature_hex,
        &receipt_signature,
    )?;
    receipt.receipt_signature = receipt_signature;
    check_embedded_hex(
        &format!("{context} signed_canonical_cbor_hex"),
        &link.signed_canonical_cbor_hex,
        &receipt.to_canonical_cbor(),
    )?;
    verify_receipt_signature(&receipt, public_key)
        .map_err(|error| format!("{context} rebuilt signature did not verify: {error}"))?;

    Ok(receipt.snapshot_merkle_root)
}

fn check_structured_enrichment_link(
    link: &StructuredEnrichmentLink,
    expected_supersedes_prior: Option<[u8; HASH_LEN]>,
    signing_key: &SigningKey,
    public_key: &[u8; 32],
) -> Result<[u8; HASH_LEN], String> {
    let context = format!("entry enrichment link {}", link.link);
    let event_id = decode_fixed_hex::<16>(&format!("{context} event_id_hex"), &link.event_id_hex)?;
    let declared_hash = decode_fixed_hex::<HASH_LEN>(
        &format!("{context} declared_hash_hex"),
        &link.declared_hash_hex,
    )?;
    let supersedes_prior = decode_optional_fixed_hex::<HASH_LEN>(
        &format!("{context} supersedes_prior_receipt_hash_hex"),
        link.supersedes_prior_receipt_hash_hex.as_deref(),
    )?;
    if supersedes_prior != expected_supersedes_prior {
        return Err(format!(
            "{context} supersedes_prior_receipt_hash_hex does not link to the prior receipt hash"
        ));
    }

    let declaration_value = serde_json::to_value(&link.declaration)
        .map_err(|error| format!("{context} serialize declaration: {error}"))?;
    let (computed_declared_hash, computed_canonical_declaration) =
        declaration_hash(&declaration_value);
    if computed_declared_hash != declared_hash {
        return Err(format!("{context} declared_hash_hex mismatch"));
    }
    if computed_canonical_declaration != link.canonical_declaration_json {
        return Err(format!("{context} canonical_declaration_json mismatch"));
    }
    let rebuilt_payload = build_publisher_enrichment_payload(
        &link.declaration,
        &link.declared_uri,
        &declared_hash,
        &link.enrichment_payload.verification_method,
        link.enrichment_payload.refresh_interval_seconds,
    );
    if rebuilt_payload != link.enrichment_payload {
        return Err(format!("{context} enrichment_payload mismatch"));
    }

    let mut receipt = build_entry_enriched_receipt(
        &link.server_name,
        &link.declaration,
        &link.declared_uri,
        declared_hash,
        &link.enrichment_payload,
        event_id,
        &link.signer_kid,
        supersedes_prior,
    )
    .map_err(|error| format!("{context} production constructor failed: {error}"))?;
    if receipt.event_id != event_id
        || receipt.server_name.as_str() != link.server_name.as_str()
        || receipt.publisher_passport.as_str() != link.declaration.publisher_passport.as_str()
        || receipt.declared_uri.as_str() != link.declared_uri.as_str()
        || receipt.declared_hash != declared_hash
        || receipt.supersedes_prior != supersedes_prior
        || receipt.signer_kid.as_str() != link.signer_kid.as_str()
    {
        return Err(format!("{context} constructor field mismatch"));
    }

    check_embedded_hex(
        &format!("{context} zeroed_canonical_cbor_hex"),
        &link.zeroed_canonical_cbor_hex,
        &receipt.to_zeroed_canonical_cbor(),
    )?;
    check_embedded_hex(
        &format!("{context} receipt_hash_hex"),
        &link.receipt_hash_hex,
        &receipt.receipt_hash,
    )?;
    let signature_preimage = receipt.to_canonical_cbor();
    check_embedded_hex(
        &format!("{context} signature_preimage_canonical_cbor_hex"),
        &link.signature_preimage_canonical_cbor_hex,
        &signature_preimage,
    )?;
    let receipt_signature = signing_key.sign(&signature_preimage).to_bytes();
    check_embedded_hex(
        &format!("{context} receipt_signature_hex"),
        &link.receipt_signature_hex,
        &receipt_signature,
    )?;
    receipt.receipt_signature = receipt_signature;
    check_embedded_hex(
        &format!("{context} signed_canonical_cbor_hex"),
        &link.signed_canonical_cbor_hex,
        &receipt.to_canonical_cbor(),
    )?;
    verify_receipt_signature(&receipt, public_key)
        .map_err(|error| format!("{context} rebuilt signature did not verify: {error}"))?;

    Ok(receipt.receipt_hash)
}

fn mirrored_servers_from_structured_inputs(
    inputs: &[StructuredServerInput],
    context: &str,
) -> Result<Vec<MirroredServer>, String> {
    inputs
        .iter()
        .enumerate()
        .map(|(index, input)| {
            let server = serde_json::from_str::<Value>(&input.canonical_json).map_err(|error| {
                format!("{context} server {index} canonical_json parse failed: {error}")
            })?;
            let envelope = RegistryServerEnvelope {
                server,
                meta: RegistryServerMeta {
                    official: OfficialRegistryMeta {
                        status: "active".into(),
                        status_changed_at: None,
                        published_at: None,
                        updated_at: None,
                        is_latest: true,
                    },
                    extra: BTreeMap::new(),
                },
            };
            let mirrored =
                MirroredServer::from_envelope(&envelope, &NoopSchemaCatalog).map_err(|error| {
                    format!("{context} server {index} reconstruction failed: {error}")
                })?;
            if mirrored.name != input.name
                || mirrored.version != input.version
                || mirrored.canonical_json != input.canonical_json
            {
                return Err(format!(
                    "{context} server {index} structured fields do not match canonical_json"
                ));
            }
            Ok(mirrored)
        })
        .collect()
}

fn decode_fixed_hex<const N: usize>(context: &str, encoded: &str) -> Result<[u8; N], String> {
    let bytes = hex::decode(encoded).map_err(|error| format!("{context}: invalid hex: {error}"))?;
    if bytes.len() != N {
        return Err(format!(
            "{context}: decoded {} bytes, expected {N}",
            bytes.len()
        ));
    }
    let mut output = [0u8; N];
    output.copy_from_slice(&bytes);
    Ok(output)
}

fn decode_optional_fixed_hex<const N: usize>(
    context: &str,
    encoded: Option<&str>,
) -> Result<Option<[u8; N]>, String> {
    encoded
        .map(|value| decode_fixed_hex::<N>(context, value))
        .transpose()
}

fn check_embedded_hex(context: &str, expected_hex: &str, actual: &[u8]) -> Result<(), String> {
    let expected =
        hex::decode(expected_hex).map_err(|error| format!("{context}: invalid hex: {error}"))?;
    if expected == actual {
        Ok(())
    } else {
        let first_difference = expected
            .iter()
            .zip(actual)
            .position(|(expected, actual)| expected != actual)
            .map_or_else(
                || format!("length {} instead of {}", actual.len(), expected.len()),
                |offset| format!("first byte difference at offset {offset}"),
            );
        Err(format!(
            "{context}: rebuilt bytes differ ({first_difference})"
        ))
    }
}

fn snapshot_chain(signing_key: &SigningKey, public_key: &[u8; 32]) -> Result<Value, String> {
    let sets = [
        vec![make_server(
            "io.example/alpha",
            "1.0.0",
            json!({"state": 1}),
        )],
        vec![
            make_server("io.example/alpha", "1.1.0", json!({"state": 2})),
            make_server("io.example/beta", "1.0.0", json!({"state": 1})),
        ],
        vec![
            make_server("io.example/alpha", "1.1.0", json!({"state": 3})),
            make_server("io.example/beta", "1.0.0", json!({"state": 2})),
            make_server("io.example/gamma", "1.0.0", json!({"state": 1})),
        ],
    ];

    let mut previous_root: Option<[u8; HASH_LEN]> = None;
    let mut links = Vec::new();
    for (index, current) in sets.into_iter().enumerate() {
        let link_number = index + 1;
        let previous = Vec::new();
        let event_id = [0x20 + link_number as u8; 16];
        let snapshot_id = [0x30 + link_number as u8; 16];
        let scraped_at_unix_ms = 1_776_683_200_000 + index as u64 * 60_000;
        let upstream_snapshot_etag: Option<&str> = None;
        let plan = build_snapshot_plan(
            &current,
            &previous,
            event_id,
            snapshot_id,
            scraped_at_unix_ms,
            previous_root,
            upstream_snapshot_etag,
            TEST_SIGNER_KID,
        );
        let receipt = plan.snapshot_receipt;
        let expected_root = snapshot_merkle_root(&current);
        assert_eq!(receipt.snapshot_merkle_root, expected_root);
        assert_eq!(receipt.previous_snapshot_hash, previous_root);

        let signature_preimage = receipt.to_canonical_cbor();
        let receipt_signature = signing_key.sign(&signature_preimage).to_bytes();
        let mut signed_receipt = receipt.clone();
        signed_receipt.receipt_signature = receipt_signature;
        verify_receipt_signature(&signed_receipt, public_key).map_err(|error| {
            format!("snapshot chain production signature {link_number} did not verify: {error}")
        })?;

        let mut hash_signed_receipt = receipt.clone();
        hash_signed_receipt.receipt_signature = signing_key.sign(&receipt.receipt_hash).to_bytes();
        let hash_signed_error = verify_receipt_signature(&hash_signed_receipt, public_key)
            .expect_err("snapshot signature over the 32-byte receipt hash must fail")
            .to_string();

        links.push(json!({
            "link": link_number,
            "event_id_hex": hex::encode(event_id),
            "snapshot_id_hex": hex::encode(snapshot_id),
            "scraped_at_unix_ms": scraped_at_unix_ms,
            "servers": current.iter().map(describe_server).collect::<Vec<_>>(),
            "previous_servers": previous.iter().map(describe_server).collect::<Vec<_>>(),
            "previous_snapshot_hash_hex": previous_root.map(hex::encode),
            "upstream_registry_uri": receipt.upstream_registry_uri,
            "upstream_snapshot_etag": upstream_snapshot_etag,
            "signer_kid": TEST_SIGNER_KID,
            "snapshot_merkle_root_hex": hex::encode(receipt.snapshot_merkle_root),
            "server_count": receipt.server_count,
            "changes": {
                "added": receipt.changes.added,
                "removed": receipt.changes.removed,
                "modified": receipt.changes.modified,
            },
            "zeroed_canonical_cbor_hex": hex::encode(receipt.to_zeroed_canonical_cbor()),
            "receipt_hash_hex": hex::encode(receipt.receipt_hash),
            "signature_preimage_canonical_cbor_hex": hex::encode(&signature_preimage),
            "receipt_signature_hex": hex::encode(receipt_signature),
            "signed_canonical_cbor_hex": hex::encode(signed_receipt.to_canonical_cbor()),
            "verify_result": true,
            "negative_cases": [{
                "id": "signature-over-32-byte-receipt-hash",
                "ed25519_message_hex": hex::encode(receipt.receipt_hash),
                "receipt_signature_hex": hex::encode(hash_signed_receipt.receipt_signature),
                "signed_canonical_cbor_hex":
                    hex::encode(hash_signed_receipt.to_canonical_cbor()),
                "verify_result": false,
                "error": hash_signed_error,
            }],
        }));

        previous_root = Some(receipt.snapshot_merkle_root);
    }

    Ok(json!({
        "production_constructor": "rcx_registry_ingest::build_snapshot_plan",
        "production_sync_link_rule":
            "previous_snapshot_hash is the prior stored snapshot_hash, which is the prior Merkle root",
        "production_sync_previous_server_set_argument":
            "empty on every link, matching the live sync build_snapshot_plan call",
        "production_sync_signing_preimage":
            "ReceiptDocument::to_canonical_cbor before receipt_signature is populated",
        "signature_preimage_rule":
            "full canonical CBOR with receipt_signature zeroed and signer_kid + receipt_hash present",
        "links": links,
    }))
}

fn enrichment_receipt_chain(
    signing_key: &SigningKey,
    public_key: &[u8; 32],
) -> Result<Value, String> {
    let mut supersedes_prior: Option<[u8; HASH_LEN]> = None;
    let mut links = Vec::new();

    for index in 0..3 {
        let link_number = index + 1;
        let declaration = PublisherDeclaration {
            schema_uri:
                "https://static.rcxprotocol.org/schemas/2026-04-19/rcx-enrichment.schema.json"
                    .into(),
            mcp_name: "io.github.example-org/document-proofer".into(),
            rcx_version: "1.0".into(),
            category: "tier_gated".into(),
            min_tier: Some(["starter", "starter", "pro"][index].into()),
            required_affinity: None,
            capability_graph: json!({
                "version": 1,
                "nodes": [{
                    "cap": "io.github.example-org.document-proofer/proof_document",
                    "revision": link_number,
                }],
                "edges": [],
            }),
            declared_at: format!("2026-04-19T10:0{index}:00Z"),
            publisher_passport: "passport:github:example-org".into(),
        };
        let raw_declaration = serde_json::to_value(&declaration)
            .map_err(|error| format!("serialize declaration link {link_number}: {error}"))?;
        let (declared_hash, canonical_declaration_json) = declaration_hash(&raw_declaration);
        let declared_uri = "https://example.org/.rcx/document-proofer.rcx.json";
        let payload = build_publisher_enrichment_payload(
            &declaration,
            declared_uri,
            &declared_hash,
            "github_oauth",
            Some(3600),
        );
        let event_id = [0x50 + link_number as u8; 16];
        let mut receipt = build_entry_enriched_receipt(
            "io.github.example-org/document-proofer",
            &declaration,
            declared_uri,
            declared_hash,
            &payload,
            event_id,
            TEST_SIGNER_KID,
            supersedes_prior,
        )
        .map_err(|error| format!("build enrichment receipt link {link_number}: {error}"))?;
        assert_eq!(receipt.supersedes_prior, supersedes_prior);

        let signature_preimage = receipt.to_canonical_cbor();
        receipt.receipt_signature = signing_key.sign(&signature_preimage).to_bytes();
        verify_receipt_signature(&receipt, public_key).map_err(|error| {
            format!("enrichment chain signature {link_number} did not verify: {error}")
        })?;

        links.push(json!({
            "link": link_number,
            "event_id_hex": hex::encode(event_id),
            "server_name": "io.github.example-org/document-proofer",
            "declaration": declaration,
            "canonical_declaration_json": canonical_declaration_json,
            "declared_uri": declared_uri,
            "declared_hash_hex": hex::encode(declared_hash),
            "enrichment_payload": payload,
            "signer_kid": TEST_SIGNER_KID,
            "supersedes_prior_receipt_hash_hex": supersedes_prior.map(hex::encode),
            "zeroed_canonical_cbor_hex": hex::encode(receipt.to_zeroed_canonical_cbor()),
            "receipt_hash_hex": hex::encode(receipt.receipt_hash),
            "signature_preimage_canonical_cbor_hex": hex::encode(signature_preimage),
            "receipt_signature_hex": hex::encode(receipt.receipt_signature),
            "signed_canonical_cbor_hex": hex::encode(receipt.to_canonical_cbor()),
            "verify_result": true,
        }));

        supersedes_prior = Some(receipt.receipt_hash);
    }

    Ok(json!({
        "production_constructor": "rcx_registry_enrich::build_entry_enriched_receipt",
        "link_field": "supersedes_prior",
        "link_target": "previous link receipt_hash",
        "signature_preimage_rule":
            "full canonical CBOR with receipt_signature zeroed and signer_kid + receipt_hash present",
        "links": links,
    }))
}

fn make_server(name: &str, version: &str, payload: Value) -> MirroredServer {
    let envelope = RegistryServerEnvelope {
        server: json!({
            "version": version,
            "payload": payload,
            "name": name,
            "$schema": SERVER_SCHEMA_URI,
        }),
        meta: RegistryServerMeta {
            official: OfficialRegistryMeta {
                status: "active".into(),
                status_changed_at: None,
                published_at: None,
                updated_at: None,
                is_latest: true,
            },
            extra: BTreeMap::new(),
        },
    };

    MirroredServer::from_envelope(&envelope, &NoopSchemaCatalog).unwrap_or_else(|error| {
        panic!("construct mirrored vector server {name}@{version}: {error}")
    })
}

fn describe_server(server: &MirroredServer) -> Value {
    json!({
        "name": server.name,
        "version": server.version,
        "canonical_json": server.canonical_json,
    })
}

fn test_signing_key() -> SigningKey {
    SigningKey::from_bytes(&TEST_SEED)
}

fn test_key_json(signing_key: &SigningKey) -> Value {
    json!({
        "label": TEST_KEY_LABEL,
        "seed_hex": hex::encode(TEST_SEED),
        "public_key_hex": hex::encode(signing_key.verifying_key().to_bytes()),
        "signer_kid": TEST_SIGNER_KID,
    })
}

fn byte_differences(left: &[u8], right: &[u8]) -> Vec<(usize, u8, u8)> {
    assert_eq!(left.len(), right.len(), "tampered vectors must keep length");
    left.iter()
        .zip(right)
        .enumerate()
        .filter_map(|(index, (left, right))| (left != right).then_some((index, *left, *right)))
        .collect()
}
