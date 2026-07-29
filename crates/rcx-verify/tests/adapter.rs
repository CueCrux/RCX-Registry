//! CONTRACT.md §7 — the adapter protocol, and §8.2 — the latency bound.
//!
//! Drives the shipped adapter binary the way the language-agnostic harness will,
//! so the protocol is exercised as a subprocess rather than as a function call. A
//! TS/Python/Go port is conformant when it answers these same lines identically.

use std::io::Write;
use std::process::{Command, Stdio};
use std::time::Instant;

use serde_json::{json, Value};

fn vectors(name: &str) -> Value {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../spec/v1/vectors")
        .join(name);
    serde_json::from_str(&std::fs::read_to_string(path).expect("vector file")).expect("json")
}

/// Send the given request lines to the adapter, return its response lines.
fn drive(requests: &[Value]) -> Vec<Value> {
    let binary = env!("CARGO_BIN_EXE_rcx-verify-adapter");
    let mut child = Command::new(binary)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("adapter should spawn");

    {
        let stdin = child.stdin.as_mut().expect("stdin");
        for request in requests {
            writeln!(stdin, "{request}").expect("write request");
        }
    }

    let output = child.wait_with_output().expect("adapter should exit");
    assert!(
        output.status.success(),
        "adapter exited {:?}; stderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );

    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("adapter emitted non-JSON"))
        .collect()
}

#[test]
fn adapter_answers_each_verb_in_order() {
    let receipts = vectors("receipts.json");
    let public_key = receipts["test_key"]["public_key_hex"]
        .as_str()
        .expect("public key");
    let case = &receipts["cases"][0];
    let signed = case["signed_canonical_cbor_hex"].as_str().expect("signed");

    let merkle = vectors("snapshot-merkle.json");
    let snapshot_case = &merkle["cases"][1];
    let entries: Vec<Value> = snapshot_case["input_order"]
        .as_array()
        .expect("input_order")
        .iter()
        .map(|entry| {
            json!({
                "name": entry["name"],
                "version": entry["version"],
                "canonicalJson": entry["canonical_json"],
            })
        })
        .collect();

    let responses = drive(&[
        json!({"verb":"verifyReceipt","signedCanonicalCborHex":signed,"publicKeyHex":public_key}),
        json!({"verb":"verifySnapshot","entries":entries,"expectedRootHex":snapshot_case["root_hex"]}),
        json!({"verb":"verifySnapshot","entries":entries,"expectedRootHex":"00".repeat(32)}),
        json!({"verb":"nonsense"}),
        json!({"not":"even a verb"}),
    ]);

    assert_eq!(responses.len(), 5, "one response per request, in order");
    assert_eq!(responses[0]["valid"], json!(true), "receipt should verify");
    assert_eq!(
        responses[0]["receiptHashHex"], case["receipt_hash_hex"],
        "adapter reported the wrong receipt hash"
    );
    assert_eq!(responses[1]["valid"], json!(true), "snapshot should verify");
    assert_eq!(responses[2]["valid"], json!(false));
    assert_eq!(responses[2]["error"], json!("root_mismatch"));

    // Malformed input is a verdict, not a crash — the harness must be able to
    // tell "this SDK says invalid" from "this SDK fell over".
    assert_eq!(responses[3]["error"], json!("decode_error"));
    assert_eq!(responses[4]["error"], json!("decode_error"));
}

#[test]
fn verifying_the_reference_receipt_stays_under_the_latency_bound() {
    let receipts = vectors("receipts.json");
    let public_key = hex::decode(
        receipts["test_key"]["public_key_hex"]
            .as_str()
            .expect("public key"),
    )
    .expect("hex");
    let signed = hex::decode(
        receipts["cases"][0]["signed_canonical_cbor_hex"]
            .as_str()
            .expect("signed"),
    )
    .expect("hex");

    // Warm once so the measurement is of the verify path, not first-touch effects.
    rcx_verify::verify_receipt(&signed, &public_key).expect("reference receipt should verify");

    let iterations = 50;
    let started = Instant::now();
    for _ in 0..iterations {
        rcx_verify::verify_receipt(&signed, &public_key).expect("should verify");
    }
    let per_call = started.elapsed() / iterations;

    // CONTRACT.md §8.2. Measured in a debug build, which is the pessimistic case;
    // release is far faster. Generous headroom is deliberate — this exists to
    // catch a structural regression (a network call, a key derivation per verify),
    // not to police microseconds on a shared CI box.
    assert!(
        per_call.as_millis() < 50,
        "verify_receipt averaged {per_call:?} per call, over the 50 ms bound"
    );
}
