# 4. Hashing & the Per-Artifact Input Pin (OD-3)

`rcx-spec/v1` · traces to grounding §3 (the hash-input inventory).

## 4.1 Algorithm

All content hashes in RCX-Registry are **BLAKE3** in default (256-bit) mode, producing exactly **32 bytes**. Implementations **MUST** use BLAKE3 with no keying, no derive-key context, and default 32-byte output. There is no other hash function in the wire format. (grounding §3)

## 4.2 The one rule that matters — which form is hashed (OD-3)

For each hashable artifact, the hash is taken over **one designated canonical form**. Mixing forms produces a different, wrong hash. The pin, per artifact:

| Artifact / field | Hash input (designated canonical form) | Section |
|---|---|---|
| `receipt_hash` (every CROWN receipt) | **canonical CBOR** of the receipt in **zeroed-field** encoding | §5.3 |
| `snapshot_merkle_root` (snapshot-set digest) | **canonical JSON** of each server, framed & concatenated | §6 |
| per-server reconciliation hash | **canonical JSON** of the server, framed (no trailing separator) | §6.5 |
| publisher `declared_hash` | **canonical JSON** of the fetched declaration document | §4.4 |
| `auto_enrichment_bytes`, `enrichment_bytes` (embedded in a receipt) | **canonical CBOR** of the enrichment payload (opaque byte string, then folded into the receipt's own CBOR hash) | §4.5 |
| `passport_hash`, `project_hash` (published records) | **canonical CBOR** of the record — **construction defined by the producer, not by v1** | §4.6 |
| `attestation_hash` | **canonical CBOR + BLAKE3 — construction unspecified in v1** | §4.6 |

**Summary MUSTs:**
- An implementation verifying a **receipt** hash **MUST** hash **canonical CBOR** (§2), never JSON.
- An implementation verifying the **snapshot set** or a **declaration** hash **MUST** hash **canonical JSON** (§3), never CBOR.
- These two families use **different map/key orderings** (§2.4 vs §3.3). An implementation **MUST** apply the ordering that matches the designated form.

## 4.3 The `blake3:` string prefix

When a BLAKE3 hash is embedded as a **string** inside a JSON value (a `_meta` enrichment block, a published record, an attestation field), it is written as:

```
blake3:<64 lowercase hex chars>
```

The reference **always emits** the `blake3:` prefix in these positions. Consumers **MUST** accept the prefixed form; per the published JSON Schemas the prefix is syntactically optional (`^(?:blake3:)?[0-9a-f]{64}$`), so a consumer **SHOULD** also accept a bare 64-hex string and treat it as BLAKE3. When a hash appears in **CBOR** (inside a receipt), it is a raw 32-byte byte string with **no** prefix. (grounding §3, §8)

## 4.4 Publisher declaration hash (`declared_hash`)

```
declared_hash = BLAKE3( canonicalJSON(declaration_document) )      # 32 bytes
```
Computed over the **entire** fetched declaration document (§3.5). Embedded in the enrichment payload and `_meta` block as `blake3:<hex>`. (grounding §3 row 4)

## 4.5 Embedded enrichment payloads

`auto_enrichment_bytes` and `enrichment_bytes` are **canonical CBOR** encodings of their payload structs (§5.7 lists the field sets), carried inside the receipt as a CBOR **byte string**. They are not separately hashed: the receipt's own `receipt_hash` (§5.3) is taken over the receipt CBOR, which contains these byte strings verbatim. An implementer reproducing a receipt hash **MUST** first produce the byte-exact canonical CBOR of the payload, embed it as the byte-string value, then hash the whole receipt. (grounding §3 rows 5–6)

Enrichment-payload CBOR notes. Numbers inside a `capability_graph` value are converted JSON→CBOR by the reference `json_to_cbor` (`crates/rcx-registry-enrich/src/lib.rs:542-558`) with exactly this rule:

- A **non-negative integer** (a value that fits `u64`, i.e. `0 .. 2^64−1`) → CBOR **unsigned integer** (§2.1).
- A **non-integral** number (has a fractional part or exponent, of **either** sign) → CBOR **float** (§2.5, shortest form). This includes negative non-integral values such as `-1.5`, which are **not** rejected — they encode as a negative CBOR float.
- A **negative integer** → **rejected**: the reference returns a `NegativeNumber` error (`lib.rs:546-547`) and no receipt is minted. A conformant producer **MUST NOT** place a negative integer in a `capability_graph`.
- A **positive integral-form literal above `u64::MAX`** (e.g. `20000000000000000000`, which has no fractional part or exponent but exceeds `2^64−1`) → CBOR **float**. It fits neither `u64` nor `i64`, so `serde_json 1.0.139` (built here without `arbitrary_precision`) parses it as an **`f64`** at document-parse time; `json_to_cbor` then finds `as_u64()` and `as_i64()` both `None` and takes the `as_f64` branch (`lib.rs:551-552`), encoding the value as a CBOR **float** — the lossy shortest-form `binary64` approximation, exactly as for a non-integral number. (This corner is unreachable for magnitudes above `f64::MAX`: those are rejected at JSON-parse time before `json_to_cbor` runs — see [03-canonical-json.md §3.4](03-canonical-json.md) "Out-of-range literals".)

(The value model has no negative-integer CBOR variant, §2.1, which is why negative *integers* are rejected while negative *non-integers* fall through to the float branch.) Object keys inside the payload are canonically sorted by the CBOR encoder (§2.4) regardless of input order.

## 4.6 Producer-defined hashes — pinned to algorithm + form only (OQ-3 resolved)

`passport_hash`, `project_hash`, and `attestation_hash` are BLAKE3 over a **canonical CBOR** encoding by the intent documented in their JSON Schemas, but the exact field set, field ordering, and any zeroing are produced **outside this repository** (`corecruxctl publish`, and the attestation issuer). **v1 resolves OQ-3 by pinning only the *algorithm and form* (BLAKE3 over canonical CBOR) and deliberately leaving the byte construction out of scope.** The byte construction is therefore **not normative in v1**, and an independent verifier **cannot** reproduce these hashes from this document alone — it must source the field-by-field construction from the producer. The registry stores and serves these records but does not itself re-derive their hashes. (grounding §3 rows 7–9, OQ-3.)
