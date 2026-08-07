# `rcx` — command-line RCX verification

Verifies RCX protocol artifacts you already hold. **Performs no network I/O**: a
verification tool that fetches could be talked into fetching from the party it is
supposed to be checking.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | verified |
| `1` | **did not** verify — a real negative result |
| `2` | could not run the check (usage, unreadable file, malformed input) |

`1` and `2` are deliberately distinct. Collapsing them is what makes a pipeline
green when someone mistypes a path — "we could not look" is not "we looked and it
was fine".

## Usage

```bash
rcx verify receipt     receipt.hex        --key @pubkey.hex
rcx verify snapshot    entries.json       --root <hex>
rcx verify declaration declaration.json   --hash <hex>
rcx verify namespace   declaration.json   --hash <hex> --name io.example/thing
rcx verify chain       chain.json         --key @pubkey.hex --kind snapshot
```

Add `--json` for machine-readable output. Try it against the checked-in examples:

```bash
rcx verify receipt examples/verify/receipt.hex --key @examples/verify/test-key.hex
rcx verify snapshot examples/verify/snapshot-entries.json \
  --root "$(cat examples/verify/snapshot-root.txt)"
```

## Input formats

| Subject | Format |
|---|---|
| `receipt`, `chain` links | canonical CBOR — raw bytes or hex text, auto-detected |
| `chain` | JSON array of hex-encoded receipts, oldest first |
| `snapshot` | JSON array of `{"name","version","canonical_json"}` |
| `declaration` | the raw JSON document, byte for byte as published |

Declarations are read as **text, never re-serialised through a parser**.
`{"value":1.0}` and `{"value":1}` have different canonical forms and different
hashes, so round-tripping through a parser would verify a different input than the
one that was published.

## `--kind` is required for chains, and never guessed

Snapshot chains link `previous_snapshot_hash` → the prior link's
`snapshot_merkle_root`. Enrichment chains link `supersedes_prior` → the prior
link's `receipt_hash`. Different fields, different targets. Guessing wrong fails a
sound chain in a way indistinguishable from tampering, so an unknown `--kind` is
exit 2 rather than an attempt.

## What `verify namespace` does not tell you

It confirms a declaration hashes as published and claims the namespace you named.
It does **not** prove operator-independent ownership — no `signer_kid` →
public-key mapping is published yet (OQ-2). The tool prints that caveat on
success, so a green line cannot be mistaken for more than it is.

## In Docker

```bash
docker build -f Dockerfile.verify -t rcx-verify .
docker run --rm -v "$PWD/examples/verify:/data:ro" rcx-verify \
  verify receipt /data/receipt.hex --key @/data/test-key.hex
```

~5 MB, runs as uid 65532, and the runtime carries no shell, package manager or
interpreter — there is nothing in it to pivot into.

## In GitHub Actions

```yaml
- uses: CueCrux/RCX-Registry@main
  with:
    subject: receipt
    file: path/to/receipt.hex
    key: '@path/to/pubkey.hex'
```

Verification failure fails the step.

## Dependencies

`hex`, `serde_json`, and `rcx-verify`. No HTTP client, no TLS stack, no async
runtime, and argument parsing is hand-rolled rather than pulling a parser crate —
a tool whose pitch is "small enough to audit" should be small enough to audit.
