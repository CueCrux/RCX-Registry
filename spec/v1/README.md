# RCX Protocol Specification — `rcx-spec/v1`

**Status:** Final freeze of running code (`registry.rcxprotocol.org`). All six open questions (OQ-1..OQ-6) are resolved; see "Resolved open questions" below.
**Version identifier:** `rcx-spec/v1`.
**Source of truth:** RCX-Registry `feat/spec-v1` @ `509f7b1`. Every normative statement traces to the grounding doc `PlanCrux/.agent/artifacts/rcx-spec-v1-grounding-2026-07-19.md`, which in turn cites `file:line` in this repo.

This specification defines the RCX-Registry **wire format**: the byte-exact canonical encodings, hashes, and signed receipts that make the registry independently verifiable. It is written so that an implementer who cannot read the reference Rust can reproduce identical bytes and hashes from this text plus the conformance vectors alone.

## Scope

**In scope (v1):** canonical CBOR, canonical JSON, BLAKE3 hashing rules, the CROWN receipt format and its zeroed-field signing idiom, ed25519 key/signature encodings, the snapshot-set digest ("Merkle root") construction, snapshot/receipt chaining, the `/v0` read API shape, cursor pagination, server-version selection, and the error model.

**Out of scope (deferred to v2):** SDK verify surface, inclusion/consistency proofs, transparency-log witnesses, key rotation, and any change to the bytes on the wire.

## Conformance

An implementation is **conformant** if, for every vector in [`vectors/`](vectors/), it reproduces the exact bytes/hashes specified. `vectors/` is the normative test corpus (generated separately). Where this prose and a vector disagree, **the vector is a bug report against the prose** — file it; do not silently follow one.

**Producer vs. encoder — duplicate map keys.** "No duplicate keys" is a **producer-side** rule, not an encoder-side rejection. A conformant *producer* **MUST NOT** emit a canonical-CBOR map (or a canonical-JSON object) containing duplicate keys — the registry's own artifacts, built from fixed-key structs, never do. The reference *encoder*, however, does not enforce this: if it is handed a value that already contains duplicate keys it faithfully **retains** them (canonical CBOR emits them adjacent and in stable input order, [02-canonical-cbor.md §2.4](02-canonical-cbor.md)), while a JSON *parser* collapses duplicate members last-wins before canonicalising ([03-canonical-json.md §3.1](03-canonical-json.md)). The `vectors/` corpus exercises this retained-duplicate encoder behavior (`canonical-cbor` `duplicate-map-keys-retained`) deliberately; it does not contradict the producer rule.

Requirement keywords **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, **MAY** are per [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) / [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174), interpreted only when in ALL CAPS.

## Documents

| # | File | Covers |
|---|---|---|
| 1 | [01-conventions.md](01-conventions.md) | Terminology, primitive encodings, byte/hex conventions, RFC 2119 |
| 2 | [02-canonical-cbor.md](02-canonical-cbor.md) | Deterministic CBOR: heads, types, map ordering, floats, decoder rules |
| 3 | [03-canonical-json.md](03-canonical-json.md) | Canonical JSON (the hashing form), and how it differs from canonical CBOR ordering |
| 4 | [04-hashing.md](04-hashing.md) | BLAKE3 rules, the `blake3:` prefix, and the **per-artifact hashing-input pin (OD-3)** |
| 5 | [05-receipts.md](05-receipts.md) | CROWN receipt format, zeroed-field idiom, the six receipt types, key/signature encoding |
| 6 | [06-merkle-and-snapshots.md](06-merkle-and-snapshots.md) | Snapshot-set digest, ordering, separators, empty-set rule, snapshot/receipt chaining |
| 7 | [07-api-and-errors.md](07-api-and-errors.md) | `/v0` read shape, cursor pagination, server-version selection, error model |

## Resolved open questions (freeze decisions)

The six open questions from the grounding doc §9 are resolved as follows (full rationale in the grounding doc's dated **Resolutions (2026-07-19)** section):

1. **Receipt signature preimage (OQ-1) — resolved: path A, normative.** The signature is ed25519 over the receipt's **full canonical CBOR with only `receipt_signature` zeroed** (real `receipt_hash` and real `signer_kid` present) — the message that mints every live receipt. Frozen in [05-receipts.md §5.6](05-receipts.md). The `receipt_hash` (BLAKE3, §5.3) is separately frozen. The reference crown verifier is being aligned to path A (verifier-side only, no wire change).
2. **Public-key distribution (OQ-2) — documented v1 gap.** v1 does not define how a verifier obtains the registry's ed25519 public key from `signer_kid`; without the key out of band, receipts are **hash-verifiable but not signature-verifiable from this spec alone**. Key publication is proposed for **M1a**. See [05-receipts.md §5.6.1](05-receipts.md).
3. **Producer-defined hashes (OQ-3) — resolved: form-only.** `passport_hash` / `project_hash` / `attestation_hash` are pinned to *algorithm + form* (BLAKE3 over canonical CBOR) only; their byte construction is out of scope for v1. [04-hashing.md §4.6](04-hashing.md).
4. **Snapshot root naming (OQ-4) — resolved: name retained.** `snapshot_merkle_root` keeps its historical wire name but is described honestly as a **flat set digest**; a real proof tree is deferred to **Spec v2 (M3a)**. [06-merkle-and-snapshots.md §6.1](06-merkle-and-snapshots.md).
5. **Canonical-JSON numbers (OQ-5) — resolved: implementation-pinned.** Numbers are frozen to observed `serde_json` parse→`Display` semantics. [03-canonical-json.md §3.4](03-canonical-json.md).
6. **CBOR decoder leniency (OQ-6) — resolved.** Encoders **MUST** emit canonical order and no duplicate keys; decoders **MAY** accept-and-normalise (current behavior). Strict decoder rejection is deferred to v2. [02-canonical-cbor.md §2.6](02-canonical-cbor.md).

See the grounding doc §9 plus its dated **Resolutions (2026-07-19)** section for the code-cited resolution of each.
