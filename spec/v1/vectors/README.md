# RCX Protocol Spec v1 conformance vectors

These files are generated from the Rust functions used by RCX-Registry in
production. They freeze observed bytes; the generator does not contain an
independent canonicalizer, receipt hasher, or snapshot-root implementation.

The Ed25519 seed in `receipts.json` and `chains.json` is an obvious,
deterministic **TEST KEY**. It exists only to make signatures reproducible.
Never use it outside conformance testing.
Production signing is Vault-backed, so the generator uses Ed25519-dalek with
this fixed seed while preserving the exact message bytes passed by the
production receipt and sync paths.

## Files

- `canonical-json.json` covers the canonical JSON path used before publisher
  declaration hashing, including key ordering, escaping, Unicode, numeric
  forms, negative zero, nesting, empty containers, integer boundaries, and
  duplicate-key collapse. Its private-use-BMP/astral key case distinguishes
  production Rust string ordering from RFC 8785 UTF-16 ordering.
- `canonical-cbor.json` uses typed input nodes so unsigned integers, floats,
  negative zero, byte strings, and duplicate map keys cannot be confused by a
  JSON parser. Its decoder-rejection section is checked against the production
  decoder; out-of-order and duplicate map keys are intentionally not rejection
  cases under OQ-6.
- `hashes.json` contains canonical-JSON declaration hashes and canonical server
  hashes. All digests are BLAKE3-256. The Unicode notes point to authoritative
  UTF-8 hex, and the server case exposes both the exact reconciliation-hash
  input (without `ff`) and the related snapshot entry frame (with `ff`).
- `receipts.json` contains zeroed-field canonical CBOR, receipt hashes,
  deterministic Ed25519 signatures, successful verification, and tamper
  failures. Together with `chains.json`, it covers all six receipt types.
- `snapshot-merkle.json` covers empty, one-element, two-element, odd, larger,
  reordered, and duplicate inputs.
- `chains.json` contains three-link snapshot and entry-enrichment receipt
  chains.

Every file has a versioned `format` field. Bytes, hashes, keys, and signatures
are lowercase hexadecimal. CBOR unsigned integers are decimal strings and
floats are identified by their exact 64-bit IEEE-754 bit pattern. Nullable
fields are JSON `null`.

## Regenerate and check

From the repository root:

```sh
cargo run -p rcx-registry-server --example rcx-spec-v1-vectors -- --write
cargo run -p rcx-registry-server --example rcx-spec-v1-vectors -- --check
cargo test -p rcx-registry-server --test conformance
```

`--write` replaces the six generated JSON files. `--check` re-derives them,
compares complete file bytes (including the final newline), and rejects
unexpected stale JSON vector files. The integration test performs the same
check in-process and is suitable for CI.

## SDK consumption

An SDK should treat each case as an independent assertion:

1. Check the top-level `format` value before interpreting a file.
2. Construct the typed input without numeric coercion. In particular, do not
   turn CBOR floats into integers, lose the sign of negative zero, deduplicate
   CBOR map entries, or parse values larger than the host language can represent
   exactly.
3. Run the SDK implementation and compare the emitted bytes or digest with the
   lowercase hex field byte-for-byte.
4. For receipts, hash the zeroed canonical CBOR and verify that it equals
   `receipt_hash_hex`. Then verify raw Ed25519 over the full canonical CBOR with
   only `receipt_signature` zeroed; `signer_kid` and the real `receipt_hash`
   remain present. `AttestationRevoked.revocation_signature` also remains
   present because it is signed content, not the outer receipt signature.
   Consume only the public key; the checked-in private seed is test material.
5. For snapshot roots, preserve every input entry. Sort lexically by `name` and
   then `version`; equal-key ties retain input order. The production function is
   a single framed BLAKE3 stream, despite the historical “Merkle” name.
6. Run both orders of each `equivalence_group`. Unique-entry permutations match;
   same-key, different-payload duplicates are intentionally order-sensitive.

In `chains.json`, snapshot `previous_snapshot_hash` points to the prior snapshot
Merkle root, while entry enrichment `supersedes_prior` points to the prior
receipt hash. All receipt signatures use the full canonical-CBOR preimage
described above. The snapshot chain also deliberately passes an empty previous
server set at each link because that is what the live sync call does; its change
counts therefore describe that observed behavior.
