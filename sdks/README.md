# RCX verification SDKs

Every SDK implements the same five verbs from
[`crates/rcx-verify/CONTRACT.md`](../crates/rcx-verify/CONTRACT.md), and conformance
is decided by one harness running one set of vectors against all of them.

| SDK | Location | Status |
|---|---|---|
| Rust (reference) | [`crates/rcx-verify`](../crates/rcx-verify) | conformant — 52/52 |
| Python | [`python/`](python) | conformant — 52/52 |
| TypeScript | — | not started |
| Go | — | not started |

## Running the harness

```bash
cargo build -p rcx-verify --bin rcx-verify-adapter
./scripts/conformance-harness.py --adapter "./target/debug/rcx-verify-adapter"
./scripts/conformance-harness.py --adapter "python3 sdks/python/adapter.py"
```

Exit 0 conformant, 1 not conformant, 2 the harness could not run the check —
that third case is deliberately distinct, because "we could not look" must never
be reported as "we looked and it was fine".

CI runs both on every change (`conformance` job). Cross-language reproducibility
is only a property if it is checked continuously; checked at release, it is a
coincidence.

## Adding a port

1. Implement the five verbs. Canonical JSON (§3), canonical CBOR encode **and**
   decode (§2), BLAKE3-256, Ed25519.
2. Ship an adapter executable speaking the NDJSON protocol (CONTRACT.md §7).
3. Run the harness. Iterate until 52/52.
4. Add it to the `conformance` CI job and to the table above.

### What will bite you

**The two canonical forms sort map keys by opposite rules.** Canonical CBOR is
length-first — `"b"` before `"aa"` (§2.4). Canonical JSON is plain
code-unit order — `"aa"` before `"b"` (§3.3). Same keys, same protocol, different
order.

**`signer_kid` zeroes to CBOR `Null`, not to an empty string.** The zeroed-field
encoding changes that field's *type*. Type-preserving zeroing is the intuitive
guess and yields `hash_mismatch` on every real receipt.

**The hash preimage and the signature preimage are different.** The receipt hash
covers the encoding with `receipt_hash`, `receipt_signature` *and* `signer_kid`
neutralised; the signature covers the full encoding with **only**
`receipt_signature` zeroed. Conflating them is the OQ-1 defect that already
shipped here once.

**Negative zero keeps its sign in canonical JSON.** `-0.0` renders as `-0.0`. Any
language that formats it through an integer conversion silently drops the sign —
this is what the Python port got wrong first, and the harness caught it.

**Non-canonical input must be rejected, not normalised.** Decoders re-sort
out-of-order map keys (OQ-6), so verify a re-encode round-trip against the input
bytes before trusting anything.

**Chain kind is an argument, never an inference.** Snapshot chains link
`previous_snapshot_hash` → prior `snapshot_merkle_root`; enrichment chains link
`supersedes_prior` → prior `receipt_hash`.

## Python SDK dependencies

`blake3` and `cryptography`. No HTTP client, no schema validator — verification is
offline by construction.

`sdks/python/` is a **separate implementation** from
[`spec/v1/reimpl/reimpl.py`](../spec/v1/reimpl), which stays M0's independent
cross-check. An auditor that becomes the product stops being an auditor, so the
two are deliberately not shared code.
