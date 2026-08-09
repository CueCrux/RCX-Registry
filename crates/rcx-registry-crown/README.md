# rcx-registry-crown

Canonical CBOR/JSON encoding, BLAKE3 hashing and CROWN receipt types for the
[RCX protocol](https://rcxprotocol.org/spec/v1) (`rcx-spec/v1`).

## This is a building block, not the entry point

**If you want to verify RCX artifacts, use [`rcx-verify`](https://crates.io/crates/rcx-verify)
or the [`rcx` CLI](https://crates.io/crates/rcx-cli).** They are the supported
surface, they have a frozen contract, and they are what the conformance vectors
are run against.

This crate exists on crates.io because `rcx-verify` depends on it and crates.io
does not accept path-only dependencies. It holds the canonical/hashing path in
**one place** — the alternative was copying that path into the verifier, which
would recreate the second implementation the four-SDK conformance suite exists to
catch. A naming preference is not worth a duplicated hashing path.

Use it directly only if you are implementing the protocol rather than consuming
it.

## What it contains

- **Canonical CBOR** (spec §2) — length-first map ordering, shortest-width
  floats, and a decoder that round-trips rather than normalises.
- **Canonical JSON** (spec §3) — plain byte-order key sorting, number literals
  preserved verbatim.
- **BLAKE3 hashing** (spec §4) and the snapshot set digest (spec §6).
- **CROWN receipts** (spec §5) — the six receipt types and the zeroed-field
  signing idiom.

Two hazards are documented in the module docs rather than left implicit: the
non-hashing canonical-JSON renderer sits one module away from the hashing one,
and the snapshot-entry frame differs from the reconciliation-hash input by
exactly one trailing `0xFF`.

## Stability

Published at `1.0.0` alongside `rcx-verify`. The wire formats it implements are
frozen by spec v1 and will not change; the Rust API is stable under semver from
this release.

Apache-2.0.
