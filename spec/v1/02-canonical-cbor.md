# 2. Canonical CBOR

`rcx-spec/v1` · traces to grounding §1 (`crates/rcx-registry-crown/src/canonical.rs`).

Canonical CBOR is the deterministic byte encoding used for **all receipt hashing and signing** (§5) and for the embedded enrichment payloads (§4). It is a **strict subset** of RFC 8949 with RFC 8949 §4.2.1 "core deterministic" map ordering. Vectors: `vectors/cbor/*`.

## 2.1 Value model

A canonical-CBOR value is exactly one of:

| Kind | CBOR major type | Notes |
|---|---|---|
| Unsigned integer | 0 | `u64` range `0 .. 2^64−1`. |
| Byte string | 2 | Arbitrary octets. |
| Text string | 3 | UTF-8. |
| Array | 4 | Ordered list; **order preserved**, never sorted. |
| Map | 5 | Text keys only; **keys sorted** per §2.4. |
| Boolean | 7 (`0xF4`/`0xF5`) | |
| Null | 7 (`0xF6`) | |
| Float | 7 (`0xF9`/`0xFA`/`0xFB`) | Finite only; shortest form (§2.5). |

Encoders **MUST NOT** emit: negative integers (major type 1), tags (major type 6), simple values other than false/true/null, indefinite-length items, or half/single/double floats in a non-shortest form. (grounding §1.1)

## 2.2 Head (type + length/argument)

Every item begins with a head: the top 3 bits are the major type, the low 5 bits are the *additional information*. The argument (a length, or the integer value itself) uses the **shortest** form:

| Argument value `n` | Additional info | Following bytes |
|---|---|---|
| `0 ≤ n < 24` | `n` | none |
| `24 ≤ n ≤ 0xFF` | `24` | 1 byte, big-endian |
| `0x100 ≤ n ≤ 0xFFFF` | `25` | 2 bytes, big-endian |
| `0x1_0000 ≤ n ≤ 0xFFFF_FFFF` | `26` | 4 bytes, big-endian |
| `n ≥ 0x1_0000_0000` | `27` | 8 bytes, big-endian |

An encoder **MUST** use the shortest head that fits `n`. (grounding §1.2)

**Head byte = `(major << 5) | additional_info`.** Examples: `uint 5` → `0x05`; `uint 500` → `0x19 0x01 0xF4`; `text len 6` → `0x66`; `bytes len 32` → `0x58 0x20`; `map with 14 pairs` → `0xAE`; `array len 2` → `0x82`.

## 2.3 Per-type body

- **Uint(n):** head only (major 0).
- **Bytes(b):** head (major 2, len = `b.len()`) followed by the raw octets.
- **Text(s):** head (major 3, len = UTF-8 byte length) followed by the UTF-8 octets.
- **Array(items):** head (major 4, len = element count) followed by each element encoded in list order. **Array element order is significant and preserved.**
- **Map(pairs):** head (major 5, len = pair count) followed by the pairs in the canonical order of §2.4; for each pair, the key (a text string) then the value.
- **Bool:** `0xF4` for false, `0xF5` for true.
- **Null:** `0xF6`.
- **Float:** §2.5.

## 2.4 Map key ordering — length-first (RFC 8949 §4.2.1)

Map keys are **always text strings**. Keys **MUST** be sorted by the **bytewise lexicographic order of their encoded form** (the text head bytes followed by the UTF-8 content). Because the head encodes length first, this is equivalent to the operational rule:

> **Shorter keys sort before longer keys. Keys of equal length sort by unsigned bytewise (UTF-8) comparison of their content.**

This is **not** the same as sorting keys by content alone. Example (both keys < 24 bytes so single-byte heads):

| Keys | Encoded key bytes | Canonical CBOR order |
|---|---|---|
| `"b"`, `"aa"` | `61 62` vs `62 61 61` | `"b"` (len 1) **before** `"aa"` (len 2) |
| `"model"`, `"budget"` | `65 6D…` vs `66 62…` | `"model"` (len 5) **before** `"budget"` (len 6) |

A **producer MUST NOT introduce duplicate keys.** Note, however, that the reference value model can *represent* them (its map is an ordered key/value list, with no negative-integer key variant and no key-uniqueness invariant) and the encoder does **not** deduplicate: if a value does contain duplicate keys they are emitted **adjacent, in sorted position**, not rejected. Well-formed receipts never contain duplicates (they are built from fixed-key structs), so encoder conformance is defined by the §2.4 ordering above, not by dedup enforcement (vector `canonical-cbor` `duplicate-map-keys-retained`; grounding Resolutions 2026-07-19; see §2.6 / OQ-6). (grounding §1.4; contrast §3.3 — canonical JSON orders the *same* keys differently.)

## 2.5 Floats — deterministic shortest form

Non-finite floats (NaN, ±∞) **MUST NOT** be encoded (the reference panics). For a finite value `x`, the encoder **MUST** choose the shortest width that round-trips `x` exactly, in this order:

1. If `f16(x)` converts back to exactly `x`: emit `0xF9` + the 2 half-precision bytes (big-endian).
2. Else if `f32(x)` converts back to exactly `x`: emit `0xFA` + the 4 single-precision bytes (big-endian).
3. Else: emit `0xFB` + the 8 double-precision bytes (big-endian).

"Round-trips exactly" means bit-equal on conversion back to the source double. Example: `1.5` → `0xF9 0x3E 0x00`. (grounding §1.5)

Note: the registry's own receipt fields never contain floats; floats appear only inside embedded enrichment/plan payloads (§4). Implementers hashing those payloads MUST follow this rule.

## 2.6 Decoder rules

A decoder that validates canonical form **MUST** reject:
- trailing bytes after a complete top-level item;
- a non-minimal integer/length head (a value that would fit in a shorter head);
- a non-shortest float encoding (e.g. an `f32` that a half would have represented exactly);
- non-finite floats;
- non-text map keys;
- reserved additional-info values (`28`–`31`) and indefinite-length markers.

**Decoder leniency (OQ-6 — resolved for v1).** The reference decoder does **not** reject a map whose keys are out of canonical order or duplicated: it accepts them, retains duplicates, and re-sorts on re-encode. v1 resolves this as follows — a conformant **encoder MUST** emit §2.4 order and **MUST NOT** introduce duplicate keys; a conformant **decoder MAY** accept-and-normalise non-canonical input (the current behavior) and is **not required** to reject it. A decoder **SHOULD** reject out-of-order or duplicate map keys where it can, but conformance **MUST NOT** depend on that rejection. Strict decoder rejection of non-canonical ordering / duplicate keys is deferred to Spec v2. (grounding §1.6, Resolutions 2026-07-19.)

## 2.7 CBOR ⇄ JSON is not byte-preserving

Canonical CBOR and canonical JSON are **different serialisations with different map orderings** (§2.4 vs §3.3). Converting CBOR→JSON→CBOR is value-preserving but **not** a way to compute the other form's hash. Always hash the artifact's designated form (§4).
