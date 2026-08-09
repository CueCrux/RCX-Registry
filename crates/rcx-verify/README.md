# rcx-verify

Offline verification for the [RCX protocol](https://rcxprotocol.org/spec/v1)
(`rcx-spec/v1`). The reference implementation of `rcx-verify-contract/1`.

**Performs no network I/O.** A verifier that could fetch could be talked into
fetching from the party it is supposed to be checking. Its dependency tree
contains no HTTP client, no TLS stack, no async runtime and no JSON-schema
validator — asserted mechanically by `tests/dependency_budget.rs`, not by good
intentions.

```toml
[dependencies]
rcx-verify = "1.0"
```

Prefer the command line? [`rcx-cli`](https://crates.io/crates/rcx-cli).

## The five verbs

```rust
use rcx_verify::{verify_receipt, verify_snapshot, verify_publisher,
                 verify_namespace, verify_history, ChainKind, Entry};

let facts = verify_receipt(&signed_canonical_cbor, &public_key)?;
verify_snapshot(&entries, &expected_root)?;
verify_publisher(&declaration_text, &expected_declared_hash)?;
verify_namespace(&declaration_text, &expected_declared_hash, "io.example/thing")?;
verify_history(&links, &public_key, ChainKind::Snapshot)?;
```

Three sibling SDKs — Python, TypeScript, Go — implement the same contract with
the same frozen failure codes. Agreement is not asserted; all four are run
through one harness against one set of vectors in CI on every change. That suite
has already caught two real defects a single implementation could not have found.

## Declarations are raw text, never a parsed value

`verify_publisher` and `verify_namespace` take the document **as published**,
byte for byte. `{"value":1.0}` and `{"value":1}` have different canonical forms
and different hashes, and a parser collapses them. The contract originally took
a parsed value; Rust and Python passed only because their parsers happen to
preserve the distinction, and the TypeScript port proved it unimplementable.
Text is also the honest input — a verifier holds bytes.

## What a green result means

Verifying a snapshot receipt proves the registry signed a snapshot with that
root. Re-digesting the served entry set proves a named server was in it.

Neither proves the registry never rewrote its history: v1's `snapshot_merkle_root`
is a **flat set digest, not a Merkle tree**, so no inclusion or consistency proof
is derivable and no independent witness has co-signed anything. `verify_namespace`
likewise confirms internal consistency, not operator-independent ownership.
Closing those gaps is
[RFC-0001](https://github.com/CueCrux/RCX-Registry/blob/main/rfcs/0001-transparency-log.md).

Saying so is the point. A verifier that overstates its reach is worse than one
that admits its edges.

## Contract

[CONTRACT.md](https://github.com/CueCrux/RCX-Registry/blob/main/crates/rcx-verify/CONTRACT.md)
is normative for all four SDKs. Apache-2.0.
