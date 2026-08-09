# rcx-verify (Python)

Offline verification for the [RCX protocol](https://rcxprotocol.org/spec/v1)
(`rcx-spec/v1`). Verifies receipts, snapshot roots, publisher declarations,
namespace claims and history chains from bytes you already hold.

**Performs no network I/O.** A verifier that could fetch could be talked into
fetching from the party it is supposed to be checking.

```bash
pip install rcx-verify
```

## The five verbs

```python
from rcx_verify import (
    verify_receipt, verify_snapshot, verify_publisher,
    verify_namespace, verify_history,
)

facts = verify_receipt(signed_canonical_cbor, public_key)   # -> ReceiptFacts
verify_snapshot(entries, expected_root)
verify_publisher(declaration_json, expected_declared_hash)
verify_namespace(declaration_json, expected_declared_hash, claimed_namespace)
verify_history(links, public_key, kind)
```

Same inputs, same outputs and the same frozen failure codes as the Rust
reference SDK. That is not a claim about the code — it is checked by running all
four SDKs through one harness against one set of vectors, in CI, on every change.

## Verifying something real

```python
import json, urllib.request
from rcx_verify import SnapshotEntry, verify_receipt, verify_snapshot

BASE = "https://registry.rcxprotocol.org"
snapshot = json.load(urllib.request.urlopen(f"{BASE}/v0/snapshots/latest"))
keys = json.load(urllib.request.urlopen(f"{BASE}/.well-known/rcx-keys.json"))

# `status` is the answer, not len(keys): `unsigned` is terminal, `unavailable`
# is retryable, and an empty list means nothing on its own.
assert keys["status"] == "published"

facts = verify_receipt(
    bytes.fromhex(snapshot["receipt_cbor_hex"]),
    bytes.fromhex(keys["keys"][0]["public_key_hex"]),
)

# Trust the root inside the SIGNED bytes, not the one served beside them.
entries = json.load(urllib.request.urlopen(
    f"{BASE}/v0/snapshots/{snapshot['snapshot_id']}/entries"))
verify_snapshot(
    [SnapshotEntry(e["name"], e["version"], e["canonical_json"]) for e in entries],
    facts.snapshot_root,
)
```

The fetching is yours. The library never does it.

## Declarations are text, not parsed values

`verify_publisher` and `verify_namespace` take the **raw document text**, byte
for byte as published — never a `dict` you re-serialised. `{"value":1.0}` and
`{"value":1}` have different canonical forms and different hashes, and a parser
collapses them. This is not a Python quirk: the contract was originally written
around parsed values and the TypeScript port proved it unimplementable, which is
why all four SDKs now take text.

## What a green result does and does not mean

`verify_namespace` confirms a declaration hashes as published and claims the
namespace you named. It does **not** prove operator-independent ownership —
that needs publisher-rights records, which are a separate surface.

Verifying a snapshot receipt proves the registry signed a snapshot with that
root, and re-digesting the entry set proves your server was in it. It does not
prove the registry never rewrote its history: v1's root is a flat set digest,
not a Merkle tree, so there are no inclusion or consistency proofs and no
independent witness has co-signed anything. That is
[RFC-0001](https://github.com/CueCrux/RCX-Registry/blob/main/rfcs/0001-transparency-log.md).

## Dependencies

`blake3` and `cryptography`. No HTTP client, no schema validator.

Apache-2.0. Contract: [CONTRACT.md](https://github.com/CueCrux/RCX-Registry/blob/main/crates/rcx-verify/CONTRACT.md).
