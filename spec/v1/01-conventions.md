# 1. Conventions & Primitives

`rcx-spec/v1` · traces to grounding §1, §5.1.

## 1.1 Requirement keywords

**MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHOULD**, **SHOULD NOT**, **RECOMMENDED**, **MAY**, **OPTIONAL** are per RFC 2119 / RFC 8174 when, and only when, in ALL CAPS.

## 1.2 Terminology

| Term | Meaning |
|---|---|
| **Canonical CBOR** | The deterministic CBOR encoding of §2. The one hashing form for receipts. |
| **Canonical JSON** | The deterministic JSON string of §3. The one hashing form for the snapshot set and declarations. |
| **CROWN receipt** | A signed, hash-chained record of one registry state change (§5). |
| **Mirrored server** | One upstream MCP server entry as mirrored: `(name, version, canonical_json, …)`. |
| **Snapshot** | The full set of mirrored servers observed in one sync tick, summarised by a `RegistrySnapshot` receipt. |
| **`signer_kid`** | Opaque key identifier of the signer (e.g. `vault:transit:rcx-registry-signing-key-1`). NOT a public key. |
| **Zeroed-field encoding** | A receipt encoding with `receipt_hash`, `receipt_signature`, `signer_kid` neutralised, used as the hash preimage (§5.3). |

## 1.3 Byte and integer conventions

- All multi-byte integers in CBOR heads and float payloads are **big-endian** (§2.2, §2.5).
- **Hashes** are BLAKE3-256: exactly **32 bytes**.
- **Signatures** are ed25519: exactly **64 bytes** (R‖S, RFC 8032).
- **Public keys** are ed25519: exactly **32 bytes** (compressed Edwards point, RFC 8032).
- **Identifiers** (`event_id`, `snapshot_id`, `attestation_id`) are opaque **16-byte** values. An implementation MUST treat them as opaque octets and MUST NOT depend on any internal structure (they are not RFC-4122 ULIDs). (grounding §7)
- **Timestamps** on the wire are unsigned integers of **milliseconds since the Unix epoch** (UTC), unless a field explicitly states otherwise. (grounding §5.1)

## 1.4 Hex encoding

Where a hash, signature, or public key appears inside a **JSON** value (published records, `_meta` enrichment blocks, schema fields), it is **lowercase** hexadecimal, no `0x` prefix:

- 32-byte hash → 64 hex chars, optionally prefixed `blake3:` (§4.3).
- 64-byte signature → 128 hex chars (regex `^[0-9a-f]{128}$`).
- 32-byte public key → 64 hex chars (regex `^[0-9a-f]{64}$`).

Where the same value appears inside **CBOR** (inside a receipt), it is a raw CBOR **byte string** (major type 2), never hex text.

## 1.5 String encoding

All text is **UTF-8**. CBOR text strings (§2) and JSON strings (§3) both carry UTF-8; JSON strings additionally apply JSON escaping (§3.2).

## 1.6 What "reproduce identical bytes" means

A conformant encoder, given the same logical value, MUST emit the **exact same octet sequence** as the reference. Determinism is not advisory here: the hashes and signatures that make the registry verifiable are taken over these octets, so any deviation (map order, integer head width, float form, key zeroing) changes a hash and breaks verification.
