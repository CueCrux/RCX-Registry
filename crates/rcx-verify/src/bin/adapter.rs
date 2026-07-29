#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used)]

//! Conformance adapter — the only thing the language-agnostic harness knows
//! about Rust (CONTRACT.md §7).
//!
//! Newline-delimited JSON on stdin, one response per line on stdout, in order.
//! A malformed request is answered `{"valid":false,"error":"decode_error"}`; it is
//! never a crash and never a non-zero exit, so a harness distinguishes "this SDK
//! says invalid" from "this SDK fell over".

use std::io::{self, BufRead, Write};

use rcx_verify::{
    verify_history, verify_namespace, verify_publisher, verify_receipt, verify_snapshot, ChainKind,
    Entry, VerifyError,
};
use serde_json::{json, Value};

fn main() -> io::Result<()> {
    let stdin = io::stdin();
    let mut stdout = io::stdout();

    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let response = match serde_json::from_str::<Value>(&line) {
            Ok(request) => dispatch(&request),
            Err(error) => invalid("decode_error", Some(error.to_string())),
        };
        writeln!(stdout, "{response}")?;
        stdout.flush()?;
    }
    Ok(())
}

fn dispatch(request: &Value) -> Value {
    match request.get("verb").and_then(Value::as_str) {
        Some("verifyReceipt") => do_verify_receipt(request),
        Some("verifySnapshot") => do_verify_snapshot(request),
        Some("verifyPublisher") => do_verify_publisher(request),
        Some("verifyNamespace") => do_verify_namespace(request),
        Some("verifyHistory") => do_verify_history(request),
        Some(other) => invalid("decode_error", Some(format!("unknown verb: {other}"))),
        None => invalid("decode_error", Some("missing verb".into())),
    }
}

fn do_verify_receipt(request: &Value) -> Value {
    let (Some(cbor), Some(key)) = (
        hex_field(request, "signedCanonicalCborHex"),
        hex_field(request, "publicKeyHex"),
    ) else {
        return invalid("decode_error", Some("bad hex input".into()));
    };
    match verify_receipt(&cbor, &key) {
        Ok(facts) => json!({
            "valid": true,
            "receiptHashHex": hex::encode(facts.receipt_hash),
            "signerKidPresent": !facts.signer_kid.is_empty(),
            "snapshotRootHex": facts.snapshot_root.map(hex::encode),
        }),
        Err(error) => from_error(&error),
    }
}

fn do_verify_snapshot(request: &Value) -> Value {
    let Some(expected) = hash_field(request, "expectedRootHex") else {
        return invalid("decode_error", Some("bad expectedRootHex".into()));
    };
    let Some(raw) = request.get("entries").and_then(Value::as_array) else {
        return invalid("decode_error", Some("missing entries".into()));
    };
    let mut entries = Vec::with_capacity(raw.len());
    for item in raw {
        let (Some(name), Some(version), Some(canonical)) = (
            item.get("name").and_then(Value::as_str),
            item.get("version").and_then(Value::as_str),
            item.get("canonicalJson").and_then(Value::as_str),
        ) else {
            return invalid("decode_error", Some("malformed entry".into()));
        };
        entries.push(Entry::new(name, version, canonical));
    }
    match verify_snapshot(&entries, &expected) {
        Ok(()) => json!({"valid": true}),
        Err(error) => from_error(&error),
    }
}

fn do_verify_publisher(request: &Value) -> Value {
    let (Some(declaration), Some(expected)) = (
        request.get("declaration"),
        hash_field(request, "expectedDeclaredHashHex"),
    ) else {
        return invalid("decode_error", Some("missing declaration or hash".into()));
    };
    match verify_publisher(declaration, &expected) {
        Ok(()) => json!({"valid": true}),
        Err(error) => from_error(&error),
    }
}

fn do_verify_namespace(request: &Value) -> Value {
    let (Some(declaration), Some(expected), Some(namespace)) = (
        request.get("declaration"),
        hash_field(request, "expectedDeclaredHashHex"),
        request.get("claimedNamespace").and_then(Value::as_str),
    ) else {
        return invalid("decode_error", Some("missing namespace inputs".into()));
    };
    match verify_namespace(declaration, &expected, namespace) {
        Ok(()) => json!({"valid": true}),
        Err(error) => from_error(&error),
    }
}

fn do_verify_history(request: &Value) -> Value {
    let Some(key) = hex_field(request, "publicKeyHex") else {
        return invalid("decode_error", Some("bad publicKeyHex".into()));
    };
    let kind = match request.get("kind").and_then(Value::as_str) {
        Some("snapshot") => ChainKind::Snapshot,
        Some("entryEnriched") => ChainKind::EntryEnriched,
        // The kind is explicit by contract — inferring it would fail sound
        // chains in a way that looks like tampering (CONTRACT.md §5).
        _ => {
            return invalid(
                "decode_error",
                Some("kind must be snapshot|entryEnriched".into()),
            )
        }
    };
    let Some(raw) = request.get("linksHex").and_then(Value::as_array) else {
        return invalid("decode_error", Some("missing linksHex".into()));
    };
    let mut links = Vec::with_capacity(raw.len());
    for item in raw {
        match item.as_str().and_then(|hex| hex::decode(hex).ok()) {
            Some(bytes) => links.push(bytes),
            None => return invalid("decode_error", Some("malformed link hex".into())),
        }
    }
    match verify_history(&links, &key, kind) {
        Ok(()) => json!({"valid": true}),
        Err(error) => from_error(&error),
    }
}

fn hex_field(request: &Value, key: &str) -> Option<Vec<u8>> {
    request
        .get(key)
        .and_then(Value::as_str)
        .and_then(|value| hex::decode(value).ok())
}

fn hash_field(request: &Value, key: &str) -> Option<[u8; 32]> {
    let bytes = hex_field(request, key)?;
    if bytes.len() != 32 {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Some(out)
}

fn from_error(error: &VerifyError) -> Value {
    json!({"valid": false, "error": error.code(), "detail": error.to_string()})
}

fn invalid(code: &str, detail: Option<String>) -> Value {
    json!({"valid": false, "error": code, "detail": detail})
}
