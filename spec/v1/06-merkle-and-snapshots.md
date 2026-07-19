# 6. Snapshot-Set Digest & Chaining

`rcx-spec/v1` · traces to grounding §4, §6 (`crates/rcx-registry-ingest/src/lib.rs:394-460`, `crates/rcx-registry-server/src/loops/sync.rs`). Vectors: `vectors/merkle/*`.

## 6.1 Naming caveat (OQ-4 — resolved)

The wire field is named `snapshot_merkle_root`, but the construction is a **flat sequential BLAKE3 hash over the sorted entry list — not a Merkle tree.** There is no leaf-pair hashing, no tree, no odd-node duplication, and no inclusion/consistency proof capability. **v1 resolves OQ-4 by keeping the historical wire name `snapshot_merkle_root` unchanged** (renaming it would break the existing wire and stored projection) while describing it honestly as a flat set digest. Implementers **MUST** compute the digest exactly as in §6.3 and **MUST NOT** build any tree or infer proof capability from the name. A real inclusion/consistency-proof tree is deferred to **Spec v2 (M3a)**, which will add it alongside — not by redefining this field.

## 6.2 Entry inputs

Each mirrored server contributes three byte fields:
- `name` — UTF-8 bytes of the server name.
- `version` — UTF-8 bytes of the server version.
- `canonical_json` — the **canonical JSON** (§3) of the upstream **`server` object** (not the `_meta` envelope), as UTF-8 bytes.

## 6.3 Digest construction — normative

```
entries := all mirrored servers in the snapshot
sort entries by (name ascending, then version ascending)      # unsigned bytewise (UTF-8) on each
h := BLAKE3::new()
for entry in entries:
    h.update(entry.name_utf8)
    h.update(0x00)                       # field separator
    h.update(entry.version_utf8)
    h.update(0x00)                       # field separator
    h.update(entry.canonical_json_utf8)
    h.update(0xFF)                       # entry terminator
snapshot_merkle_root := h.finalize()     # 32 bytes
```

MUSTs:
- Entries **MUST** be sorted by `(name, version)`, both **unsigned bytewise ascending** (lexical, **not** semantic-version order — e.g. `10.0.0` sorts before `2.0.0`), before hashing. Across entries with **distinct** `(name, version)` the digest is therefore order-independent of the input list.
- **Duplicate `(name, version)` entries are NOT deduplicated.** They are retained and each contributes to the stream. The sort is **stable**, so entries sharing a `(name, version)` key keep their **input order**; consequently the digest is **order-sensitive** whenever two entries share a `(name, version)` key but differ in `canonical_json`. Order-independence (the previous bullet) holds **only** across distinct keys. An implementation **MUST** preserve every input entry and **MUST NOT** dedupe. (Vectors: `snapshot-merkle` `duplicate-identical-retained`, `duplicate-same-key-order-a`/`-b`; grounding Resolutions 2026-07-19, `ingest lib.rs:394-411`.)
- The three fields of each entry **MUST** be separated by a single `0x00` byte, and each entry **MUST** be terminated by a single `0xFF` byte. These separators are literal, unescaped, and are the only framing (no length prefixes).
- The hash is a **single BLAKE3 stream** updated across all entries in sorted order; do not hash entries individually and combine.

## 6.4 Empty-set rule

If there are zero entries, the loop body never runs and:
```
snapshot_merkle_root = BLAKE3("")   # empty input
                     = af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262
```
An implementation **MUST** produce the BLAKE3 empty-input digest for an empty snapshot. (The hex value above is the standard BLAKE3 empty hash; confirm against the empty-set vector.)

## 6.5 Per-server reconciliation hash (distinct — not a leaf)

Change detection between snapshots uses a **separate** per-server hash that is **NOT** part of the digest above:
```
canonical_server_hash(entry) =
    BLAKE3( entry.name_utf8 || 0x00 || entry.version_utf8 || 0x00 || entry.canonical_json_utf8 )
```
It uses the same three fields with the same `0x00` separators but **omits the trailing `0xFF`**. Two servers with the same name compare equal iff their `canonical_server_hash` matches. Implementations **MUST** keep this distinct from §6.3 and **MUST NOT** feed it into the snapshot digest. (grounding §4)

## 6.6 Snapshot chaining

Each `RegistrySnapshot` receipt (§5.5.1) references the prior snapshot:
- `previous_snapshot_hash` = the immediately prior snapshot's stored `snapshot_hash`, which **equals that snapshot's `snapshot_merkle_root`** (the set-digest root of §6.3), or CBOR `Null` for the first snapshot.
- **MUST NOT** confuse this link target with a receipt hash: `previous_snapshot_hash` links the prior snapshot's **set-digest root**, **not** the prior `RegistrySnapshot` receipt's `receipt_hash`. (Contrast §6.7, where `EntryEnriched.supersedes_prior` links the prior **`receipt_hash`**. The two chains deliberately use **different** link targets — a set-digest root for snapshots, a receipt hash for enrichment. grounding Resolutions 2026-07-19, `loops/sync.rs:162,335`.)
- The chain is over the **snapshot digest** (`snapshot_merkle_root`/`snapshot_hash`), giving a verifiable history of the full mirrored set over time.
- `scraped_at` (ms) orders snapshots; the "latest" snapshot is the one with the greatest `scraped_at`. (grounding §5.6, `db/snapshots.rs`)

The stored projection keeps `snapshot_id`, `snapshot_hash` (= digest), `server_count`, `scraped_at`, `receipt_hash`, `receipt_signature`, `signer_kid`. The full receipt body is minted but is **not** exposed by any current `/v0` route (§7); third-party retrieval of receipts is not part of the v1 read API. (grounding §5.6)

## 6.7 Enrichment supersession

An `EntryEnriched` receipt MAY carry `supersedes_prior` = the `receipt_hash` (32 bytes) of the prior `EntryEnriched` receipt it replaces, or `Null`. When a publisher's hosted declaration changes (its `declared_hash` §4.4 changes), a new `EntryEnriched` receipt is minted with `supersedes_prior` set to the previous one, forming a per-server enrichment chain. (grounding §5.5, docs/publishing.md refresh semantics)
