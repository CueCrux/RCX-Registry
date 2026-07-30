//! The `rcx` CLI's contract is its exit codes, so that is what this pins.
//!
//! 0 verified · 1 did not verify · 2 could not run the check.
//!
//! Collapsing 1 and 2 is the mistake that makes CI green when a path was
//! mistyped, so every case here asserts the *specific* code, never merely
//! "non-zero". Driven through the real binary against the real spec-v1 vectors —
//! a unit test on the argument parser would not catch a wiring error between the
//! parser and the SDK.

use std::fs;
use std::path::PathBuf;
use std::process::Command;

use serde_json::Value;

fn vectors(name: &str) -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../spec/v1/vectors")
        .join(name);
    serde_json::from_str(&fs::read_to_string(&path).expect("vector file")).expect("vector JSON")
}

fn scratch(name: &str, contents: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("rcx-cli-test-{name}"));
    fs::write(&path, contents).expect("write fixture");
    path
}

/// Run `rcx` and return (exit code, stdout).
fn rcx(args: &[&str]) -> (i32, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_rcx"))
        .args(args)
        .output()
        .expect("rcx should run");
    (
        output.status.code().expect("process exited normally"),
        String::from_utf8_lossy(&output.stdout).to_string(),
    )
}

#[test]
fn a_valid_receipt_exits_zero_and_reports_its_hash() {
    let receipts = vectors("receipts.json");
    let case = &receipts["cases"][0];
    let receipt = scratch(
        "receipt.hex",
        case["signed_canonical_cbor_hex"].as_str().expect("hex"),
    );
    let key = scratch(
        "key.hex",
        receipts["test_key"]["public_key_hex"]
            .as_str()
            .expect("key"),
    );

    let (code, stdout) = rcx(&[
        "verify",
        "receipt",
        receipt.to_str().expect("path"),
        "--key",
        &format!("@{}", key.display()),
    ]);
    assert_eq!(code, 0, "valid receipt should exit 0; stdout: {stdout}");
    assert!(
        stdout.contains(case["receipt_hash_hex"].as_str().expect("hash")),
        "should report the receipt hash; got: {stdout}"
    );
}

#[test]
fn a_tampered_key_exits_one_not_two() {
    // The distinction under test: this is a real negative result, not a failure to
    // run. A tool that exits 2 here is indistinguishable from a typo'd path.
    let receipts = vectors("receipts.json");
    let receipt = scratch(
        "receipt-neg.hex",
        receipts["cases"][0]["signed_canonical_cbor_hex"]
            .as_str()
            .expect("hex"),
    );
    let good = receipts["test_key"]["public_key_hex"]
        .as_str()
        .expect("key");
    let tampered = format!(
        "{}{}",
        if &good[0..1] == "1" { "2" } else { "1" },
        &good[1..]
    );
    let key = scratch("key-bad.hex", &tampered);

    let (code, _) = rcx(&[
        "verify",
        "receipt",
        receipt.to_str().expect("path"),
        "--key",
        &format!("@{}", key.display()),
    ]);
    assert_eq!(code, 1, "wrong key is a negative result, so exit 1");
}

#[test]
fn a_missing_file_exits_two_not_one() {
    let (code, _) = rcx(&[
        "verify",
        "receipt",
        "/nonexistent/path/receipt.hex",
        "--key",
        &"11".repeat(32),
    ]);
    assert_eq!(
        code, 2,
        "an unreadable file is 'could not check', so exit 2"
    );
}

#[test]
fn a_snapshot_verifies_and_a_tampered_root_does_not() {
    let merkle = vectors("snapshot-merkle.json");
    let case = &merkle["cases"][1];
    let entries = scratch("entries.json", &case["input_order"].to_string());
    let root = case["root_hex"].as_str().expect("root");

    let (ok, _) = rcx(&[
        "verify",
        "snapshot",
        entries.to_str().expect("path"),
        "--root",
        root,
    ]);
    assert_eq!(ok, 0);

    let (bad, _) = rcx(&[
        "verify",
        "snapshot",
        entries.to_str().expect("path"),
        "--root",
        &"00".repeat(32),
    ]);
    assert_eq!(bad, 1);
}

#[test]
fn integral_float_and_integer_declarations_do_not_share_a_hash() {
    // The CLI reads declarations as raw text precisely so these stay distinct.
    // If this ever passes, the CLI has started round-tripping through a parser.
    let hashes = vectors("hashes.json");
    let float_case = hashes["declaration_hash"]["cases"]
        .as_array()
        .expect("cases")
        .iter()
        .find(|case| case["id"] == "float-one")
        .expect("float-one vector");
    let digest = float_case["digest_hex"].as_str().expect("digest");

    let float_form = scratch("decl-float.json", r#"{"value":1.0}"#);
    let int_form = scratch("decl-int.json", r#"{"value":1}"#);

    let (ok, _) = rcx(&[
        "verify",
        "declaration",
        float_form.to_str().expect("path"),
        "--hash",
        digest,
    ]);
    assert_eq!(ok, 0, "1.0 should hash to the float-one vector digest");

    let (bad, _) = rcx(&[
        "verify",
        "declaration",
        int_form.to_str().expect("path"),
        "--hash",
        digest,
    ]);
    assert_eq!(bad, 1, "1 must NOT hash to the same digest as 1.0");
}

#[test]
fn a_sound_chain_under_the_wrong_link_rule_exits_one() {
    let chains = vectors("chains.json");
    let links: Vec<&str> = chains["snapshot_chain"]["links"]
        .as_array()
        .expect("links")
        .iter()
        .map(|link| link["signed_canonical_cbor_hex"].as_str().expect("hex"))
        .collect();
    let chain = scratch("chain.json", &serde_json::to_string(&links).expect("json"));
    let key = scratch(
        "chainkey.hex",
        chains["test_key"]["public_key_hex"].as_str().expect("key"),
    );
    let key_arg = format!("@{}", key.display());

    let (ok, _) = rcx(&[
        "verify",
        "chain",
        chain.to_str().expect("path"),
        "--key",
        &key_arg,
        "--kind",
        "snapshot",
    ]);
    assert_eq!(ok, 0);

    let (wrong_rule, _) = rcx(&[
        "verify",
        "chain",
        chain.to_str().expect("path"),
        "--key",
        &key_arg,
        "--kind",
        "entry-enriched",
    ]);
    assert_eq!(wrong_rule, 1, "wrong link rule is a negative result");

    // An unknown kind is a usage error, not a verification result — the tool must
    // not guess which rule was meant.
    let (unknown_kind, _) = rcx(&[
        "verify",
        "chain",
        chain.to_str().expect("path"),
        "--key",
        &key_arg,
        "--kind",
        "guess",
    ]);
    assert_eq!(
        unknown_kind, 2,
        "an unknown --kind is exit 2, never inferred"
    );
}

#[test]
fn json_mode_is_parseable_on_both_outcomes() {
    let merkle = vectors("snapshot-merkle.json");
    let case = &merkle["cases"][1];
    let entries = scratch("entries-json.json", &case["input_order"].to_string());

    for (root, expected_valid, expected_code) in [
        (
            case["root_hex"].as_str().expect("root").to_string(),
            true,
            0,
        ),
        ("00".repeat(32), false, 1),
    ] {
        let (code, stdout) = rcx(&[
            "verify",
            "snapshot",
            entries.to_str().expect("path"),
            "--root",
            &root,
            "--json",
        ]);
        assert_eq!(code, expected_code);
        let parsed: Value = serde_json::from_str(stdout.trim())
            .unwrap_or_else(|error| panic!("--json output should parse: {error}; got {stdout}"));
        assert_eq!(parsed["valid"], Value::Bool(expected_valid));
    }
}

#[test]
fn namespace_output_states_what_it_does_not_prove() {
    // A green line must not read as proof of ownership (CONTRACT.md §4).
    let declaration = r#"{"mcp_name":"io.example/thing"}"#;
    let path = scratch("decl-ns.json", declaration);

    // Derive the digest with the CLI itself so the fixture cannot drift.
    let (_, listing) = rcx(&[
        "verify",
        "declaration",
        path.to_str().expect("path"),
        "--hash",
        &"00".repeat(32),
        "--json",
    ]);
    assert!(listing.contains("declaration_hash_mismatch"));

    let digest = {
        use blake3::Hasher;
        let mut hasher = Hasher::new();
        hasher.update(declaration.as_bytes());
        hex::encode(hasher.finalize().as_bytes())
    };

    let (code, stdout) = rcx(&[
        "verify",
        "namespace",
        path.to_str().expect("path"),
        "--hash",
        &digest,
        "--name",
        "io.example/thing",
    ]);
    assert_eq!(code, 0, "stdout: {stdout}");
    assert!(
        stdout.contains("not operator-independent"),
        "a verified namespace must still disclaim what it does not prove; got: {stdout}"
    );
}
