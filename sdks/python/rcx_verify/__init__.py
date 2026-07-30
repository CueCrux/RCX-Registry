"""Offline verification for the RCX protocol (rcx-spec/v1).

The five verbs of ``rcx-verify-contract/1``. Same inputs, same outputs, same
failure codes as the Rust reference SDK — conformance is proven by running the
same vectors through the same harness, not by reading both implementations.

Every verb is offline: no socket, no DNS, no clock.
"""

from __future__ import annotations

import json

import blake3
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .canonical import (
    CanonicalError,
    CborBytes,
    canonicalize_json,
    decode_cbor,
    encode_cbor,
)

__all__ = [
    "verify_receipt",
    "verify_snapshot",
    "verify_publisher",
    "verify_namespace",
    "verify_history",
    "SnapshotEntry",
    "ReceiptFacts",
    "VerifyError",
    "CHAIN_SNAPSHOT",
    "CHAIN_ENTRY_ENRICHED",
]

HASH_LEN = 32
SIGNATURE_LEN = 64
PUBLIC_KEY_LEN = 32

FIELD_RECEIPT_HASH = "receipt_hash"
FIELD_RECEIPT_SIGNATURE = "receipt_signature"
FIELD_SIGNER_KID = "signer_kid"
FIELD_SNAPSHOT_ROOT = "snapshot_merkle_root"
FIELD_PREVIOUS_SNAPSHOT_HASH = "previous_snapshot_hash"
FIELD_SUPERSEDES_PRIOR = "supersedes_prior"

CHAIN_SNAPSHOT = "snapshot"
CHAIN_ENTRY_ENRICHED = "entryEnriched"


class VerifyError(Exception):
    """Verification failed. ``code`` is frozen for rcx-verify-contract/1 §6."""

    def __init__(self, code: str, detail: str = ""):
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = detail


class SnapshotEntry:
    """The three fields spec §6 hashes. Mirror-only fields are not required."""

    __slots__ = ("name", "version", "canonical_json")

    def __init__(self, name: str, version: str, canonical_json: str):
        self.name = name
        self.version = version
        self.canonical_json = canonical_json


class ReceiptFacts:
    __slots__ = ("receipt_hash", "signer_kid", "snapshot_root")

    def __init__(self, receipt_hash: bytes, signer_kid: str, snapshot_root):
        self.receipt_hash = receipt_hash
        self.signer_kid = signer_kid
        self.snapshot_root = snapshot_root


def _blake3(data: bytes) -> bytes:
    return blake3.blake3(data).digest()


# ---------------------------------------------------------------------------
# 1. verifyReceipt
# ---------------------------------------------------------------------------


def verify_receipt(signed_canonical_cbor: bytes, public_key: bytes) -> ReceiptFacts:
    """Verify a CROWN receipt from its bytes (CONTRACT.md §1).

    Map-level throughout, so all six receipt types verify through one path with
    no typed decoding.
    """
    if len(public_key) != PUBLIC_KEY_LEN:
        raise VerifyError("bad_public_key", f"length {len(public_key)}")

    try:
        value = decode_cbor(signed_canonical_cbor)
    except CanonicalError as exc:
        raise VerifyError("decode_error", str(exc)) from exc

    # Non-canonical input must never verify, even when it decodes: a hash covers
    # bytes, and these are not the bytes anybody published.
    try:
        if encode_cbor(value) != signed_canonical_cbor:
            raise VerifyError("not_canonical", "re-encoding did not reproduce the input")
    except CanonicalError as exc:
        raise VerifyError("decode_error", str(exc)) from exc

    if not hasattr(value, "items"):
        raise VerifyError("decode_error", "receipt is not a CBOR map")

    stored_hash = _take_bytes(value, FIELD_RECEIPT_HASH, HASH_LEN)
    stored_signature = _take_bytes(value, FIELD_RECEIPT_SIGNATURE, SIGNATURE_LEN)

    signer_kid = value.get(FIELD_SIGNER_KID, _MISSING)
    if signer_kid is _MISSING:
        raise VerifyError("missing_field", FIELD_SIGNER_KID)
    if not isinstance(signer_kid, str):
        raise VerifyError("decode_error", "signer_kid is not text")

    # Step 3 — hash over the zeroed-field encoding (§5.3). signer_kid becomes
    # Null, not an empty string: the zeroed form changes that field's TYPE.
    zeroed = value.replace(
        {
            FIELD_RECEIPT_HASH: CborBytes(b"\x00" * HASH_LEN),
            FIELD_RECEIPT_SIGNATURE: CborBytes(b"\x00" * SIGNATURE_LEN),
            FIELD_SIGNER_KID: None,
        }
    )
    if _blake3(encode_cbor(zeroed)) != stored_hash:
        raise VerifyError("hash_mismatch")

    # Step 4 — signature over the full encoding with ONLY the signature zeroed.
    # A different preimage from step 3; conflating them is the OQ-1 defect.
    preimage = encode_cbor(
        value.replace({FIELD_RECEIPT_SIGNATURE: CborBytes(b"\x00" * SIGNATURE_LEN)})
    )
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(stored_signature, preimage)
    except InvalidSignature as exc:
        raise VerifyError("bad_signature") from exc
    except ValueError as exc:
        raise VerifyError("bad_public_key", str(exc)) from exc

    snapshot_root = value.get(FIELD_SNAPSHOT_ROOT)
    root = (
        snapshot_root.value
        if isinstance(snapshot_root, CborBytes) and len(snapshot_root.value) == HASH_LEN
        else None
    )
    return ReceiptFacts(stored_hash, signer_kid, root)


_MISSING = object()


def _take_bytes(value, key: str, expected_len: int) -> bytes:
    item = value.get(key, _MISSING)
    if item is _MISSING:
        raise VerifyError("missing_field", key)
    if not isinstance(item, CborBytes):
        raise VerifyError("decode_error", f"{key} is not a byte string")
    if len(item.value) != expected_len:
        raise VerifyError(
            "decode_error", f"{key} is {len(item.value)} bytes, expected {expected_len}"
        )
    return item.value


# ---------------------------------------------------------------------------
# 2. verifySnapshot
# ---------------------------------------------------------------------------


def snapshot_merkle_root(entries) -> bytes:
    """Flat BLAKE3 set digest over lex-sorted entries (§6).

    Not a tree despite the name — no inclusion proof is derivable (OQ-4).
    """
    ordered = sorted(entries, key=lambda e: (e.name, e.version))
    hasher = blake3.blake3()
    for entry in ordered:
        hasher.update(entry.name.encode("utf-8"))
        hasher.update(b"\x00")
        hasher.update(entry.version.encode("utf-8"))
        hasher.update(b"\x00")
        hasher.update(entry.canonical_json.encode("utf-8"))
        hasher.update(b"\xff")
    return hasher.digest()


def verify_snapshot(entries, expected_root: bytes) -> None:
    if snapshot_merkle_root(entries) != expected_root:
        raise VerifyError("root_mismatch")


# ---------------------------------------------------------------------------
# 3. verifyPublisher
# ---------------------------------------------------------------------------


def declaration_hash(declaration_json: str):
    """Hash a declaration from its raw document text (§3, §4.4)."""
    canonical = canonicalize_json(_parse_declaration(declaration_json))
    return _blake3(canonical.encode("utf-8")), canonical


def _parse_declaration(declaration_json: str):
    if not isinstance(declaration_json, str):
        raise VerifyError("decode_error", "declaration must be raw JSON text")
    try:
        return json.loads(declaration_json)
    except json.JSONDecodeError as exc:
        raise VerifyError("decode_error", f"declaration is not JSON: {exc}") from exc


def verify_publisher(declaration_json: str, expected_declared_hash: bytes) -> None:
    """Verify a declaration hash from raw text.

    Text, not a parsed value, and the contract requires it of every SDK:
    ``{"value":1.0}`` and ``{"value":1}`` have distinct canonical forms and
    distinct hashes, and JavaScript's ``JSON.parse`` collapses both to ``1``.
    Python's ``json`` preserves the distinction — taking text anyway is what keeps
    the four SDKs honest about the same input.
    """
    computed, _ = declaration_hash(declaration_json)
    if computed != expected_declared_hash:
        raise VerifyError("declaration_hash_mismatch")


# ---------------------------------------------------------------------------
# 4. verifyNamespace
# ---------------------------------------------------------------------------


def verify_namespace(
    declaration_json: str, expected_declared_hash: bytes, claimed_namespace: str
) -> None:
    """Verify a namespace claim's internal consistency.

    Read CONTRACT.md §4's scope limit: with no published signer_kid -> public-key
    mapping (OQ-2) and no live publisher-rights records, this does NOT prove
    operator-independent ownership.
    """
    verify_publisher(declaration_json, expected_declared_hash)
    declaration = _parse_declaration(declaration_json)
    if not isinstance(declaration, dict) or "mcp_name" not in declaration:
        raise VerifyError("missing_field", "mcp_name")
    if declaration["mcp_name"] != claimed_namespace:
        raise VerifyError("namespace_mismatch")


# ---------------------------------------------------------------------------
# 5. verifyHistory
# ---------------------------------------------------------------------------


def verify_history(links, public_key: bytes, kind: str) -> None:
    """Verify each link, then the backward references (CONTRACT.md §5).

    ``kind`` is explicit and never inferred: snapshot chains link root-to-root
    while enrichment chains link receipt-to-receipt, so guessing wrong fails a
    sound chain in a way that looks like tampering.
    """
    if kind not in (CHAIN_SNAPSHOT, CHAIN_ENTRY_ENRICHED):
        raise VerifyError("decode_error", f"unknown chain kind {kind!r}")

    previous = None
    for index, raw in enumerate(links):
        facts = verify_receipt(raw, public_key)

        if previous is not None:
            value = decode_cbor(raw)
            if kind == CHAIN_SNAPSHOT:
                link_field = FIELD_PREVIOUS_SNAPSHOT_HASH
                if previous.snapshot_root is None:
                    raise VerifyError("missing_field", FIELD_SNAPSHOT_ROOT)
                expected = previous.snapshot_root
            else:
                link_field = FIELD_SUPERSEDES_PRIOR
                expected = previous.receipt_hash

            actual = value.get(link_field)
            if not isinstance(actual, CborBytes) or actual.value != expected:
                raise VerifyError("chain_broken", f"at link {index}")

        previous = facts
