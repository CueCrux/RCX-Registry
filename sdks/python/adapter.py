#!/usr/bin/env python3
"""Conformance adapter for the Python SDK — rcx-verify-contract/1 §7.

Newline-delimited JSON on stdin, one response per line on stdout, in order.
Malformed input is a verdict, never a crash and never a non-zero exit.

    ./scripts/conformance-harness.py --adapter "python3 sdks/python/adapter.py"
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from rcx_verify import (  # noqa: E402
    CHAIN_ENTRY_ENRICHED,
    CHAIN_SNAPSHOT,
    SnapshotEntry,
    VerifyError,
    verify_history,
    verify_namespace,
    verify_publisher,
    verify_receipt,
    verify_snapshot,
)


def invalid(code: str, detail: str = "") -> dict:
    return {"valid": False, "error": code, "detail": detail}


def unhex(request: dict, key: str, expected_len: int | None = None):
    raw = request.get(key)
    if not isinstance(raw, str):
        return None
    try:
        value = bytes.fromhex(raw)
    except ValueError:
        return None
    if expected_len is not None and len(value) != expected_len:
        return None
    return value


def do_verify_receipt(request: dict) -> dict:
    cbor = unhex(request, "signedCanonicalCborHex")
    key = unhex(request, "publicKeyHex")
    if cbor is None or key is None:
        return invalid("decode_error", "bad hex input")
    try:
        facts = verify_receipt(cbor, key)
    except VerifyError as exc:
        return {"valid": False, "error": exc.code, "detail": exc.detail}
    return {
        "valid": True,
        "receiptHashHex": facts.receipt_hash.hex(),
        "signerKidPresent": bool(facts.signer_kid),
        "snapshotRootHex": facts.snapshot_root.hex() if facts.snapshot_root else None,
    }


def do_verify_snapshot(request: dict) -> dict:
    expected = unhex(request, "expectedRootHex", 32)
    if expected is None:
        return invalid("decode_error", "bad expectedRootHex")
    raw_entries = request.get("entries")
    if not isinstance(raw_entries, list):
        return invalid("decode_error", "missing entries")
    entries = []
    for item in raw_entries:
        if not isinstance(item, dict):
            return invalid("decode_error", "malformed entry")
        name, version, canonical = (
            item.get("name"),
            item.get("version"),
            item.get("canonicalJson"),
        )
        if not all(isinstance(f, str) for f in (name, version, canonical)):
            return invalid("decode_error", "malformed entry")
        entries.append(SnapshotEntry(name, version, canonical))
    try:
        verify_snapshot(entries, expected)
    except VerifyError as exc:
        return {"valid": False, "error": exc.code, "detail": exc.detail}
    return {"valid": True}


def do_verify_publisher(request: dict) -> dict:
    expected = unhex(request, "expectedDeclaredHashHex", 32)
    if expected is None or "declaration" not in request:
        return invalid("decode_error", "missing declaration or hash")
    try:
        verify_publisher(request["declaration"], expected)
    except VerifyError as exc:
        return {"valid": False, "error": exc.code, "detail": exc.detail}
    return {"valid": True}


def do_verify_namespace(request: dict) -> dict:
    expected = unhex(request, "expectedDeclaredHashHex", 32)
    namespace = request.get("claimedNamespace")
    if expected is None or "declaration" not in request or not isinstance(namespace, str):
        return invalid("decode_error", "missing namespace inputs")
    try:
        verify_namespace(request["declaration"], expected, namespace)
    except VerifyError as exc:
        return {"valid": False, "error": exc.code, "detail": exc.detail}
    return {"valid": True}


def do_verify_history(request: dict) -> dict:
    key = unhex(request, "publicKeyHex")
    if key is None:
        return invalid("decode_error", "bad publicKeyHex")
    kind = request.get("kind")
    if kind not in (CHAIN_SNAPSHOT, CHAIN_ENTRY_ENRICHED):
        return invalid("decode_error", "kind must be snapshot|entryEnriched")
    raw_links = request.get("linksHex")
    if not isinstance(raw_links, list):
        return invalid("decode_error", "missing linksHex")
    links = []
    for item in raw_links:
        if not isinstance(item, str):
            return invalid("decode_error", "malformed link hex")
        try:
            links.append(bytes.fromhex(item))
        except ValueError:
            return invalid("decode_error", "malformed link hex")
    try:
        verify_history(links, key, kind)
    except VerifyError as exc:
        return {"valid": False, "error": exc.code, "detail": exc.detail}
    return {"valid": True}


DISPATCH = {
    "verifyReceipt": do_verify_receipt,
    "verifySnapshot": do_verify_snapshot,
    "verifyPublisher": do_verify_publisher,
    "verifyNamespace": do_verify_namespace,
    "verifyHistory": do_verify_history,
}


def main() -> int:
    for line in sys.stdin:
        if not line.strip():
            continue
        try:
            request = json.loads(line)
        except json.JSONDecodeError as exc:
            print(json.dumps(invalid("decode_error", str(exc))), flush=True)
            continue

        verb = request.get("verb") if isinstance(request, dict) else None
        handler = DISPATCH.get(verb)
        if handler is None:
            detail = f"unknown verb: {verb}" if verb else "missing verb"
            print(json.dumps(invalid("decode_error", detail)), flush=True)
            continue

        try:
            response = handler(request)
        except Exception as exc:  # noqa: BLE001 — a crash must still be a verdict
            response = invalid("decode_error", f"{type(exc).__name__}: {exc}")
        print(json.dumps(response), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
