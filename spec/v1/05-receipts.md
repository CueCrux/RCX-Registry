# 5. CROWN Receipts

`rcx-spec/v1` · traces to grounding §5 (`crates/rcx-registry-crown/src/receipt.rs`). Vectors: `vectors/receipts/*`.

A CROWN receipt is a canonical-CBOR map recording one registry state change. Every receipt carries a self-hash (`receipt_hash`), an ed25519 signature (`receipt_signature`), and a `signer_kid`. Receipts chain via content hashes (§6.5).

## 5.1 Field-type encoding

Within a receipt's canonical CBOR map:

| Logical field kind | CBOR encoding |
|---|---|
| `event_id`, `snapshot_id`, `attestation_id` | byte string, **16 bytes** |
| hash / root (`receipt_hash`, `snapshot_merkle_root`, `declared_hash`, `attestation_hash`, `previous_snapshot_hash`, `supersedes_prior`) | byte string, **32 bytes** |
| signature (`receipt_signature`, `revocation_signature`) | byte string, **64 bytes** |
| embedded payload (`auto_enrichment_bytes`, `enrichment_bytes`, `attestation_bytes`) | byte string, arbitrary length (itself canonical CBOR, §4.5) |
| timestamp (`scraped_at`, `verified_at`, `revoked_at`) | unsigned integer, **milliseconds since Unix epoch** |
| count (`server_count`, `changes.*`) | unsigned integer |
| name / passport / URI / method / `signer_kid` | text string (UTF-8) |
| nullable field carrying no value | CBOR `Null` (`0xF6`) |

The map itself is encoded per §2, so **field/key order on the wire is length-first (§2.4), independent of the declaration order below.**

## 5.2 Map key ordering reminder

Receipt map keys are sorted length-first (§2.4). The struct field order in §5.5 is the *logical* field set; do **not** emit fields in that order. Sort the keys. Example: `RegistrySnapshot`'s keys sort as `changes`(7), `event_id`(8), `scraped_at`(10), … before longer keys — always compute via §2.4, never by hand.

## 5.3 Hashing: the zeroed-field idiom

`receipt_hash` is computed over the receipt's **zeroed-field canonical CBOR**:

1. Build the receipt map with all real values **except**:
   - `receipt_hash` → byte string of **32 zero bytes**,
   - `receipt_signature` → byte string of **64 zero bytes**,
   - `signer_kid` → CBOR **`Null`** (not an empty string).
2. Encode that map as canonical CBOR (§2).
3. `receipt_hash = BLAKE3(those bytes)` (32 bytes).

All **other** nullable fields (`previous_snapshot_hash`, `upstream_snapshot_etag`, `supersedes_prior`, `reason`, and `revocation_signature` on a revoke receipt) carry their **real** value (or `Null` if genuinely absent) in the preimage — they are part of the signed content and are **not** neutralised.

**MUST:** an implementation computing `receipt_hash` **MUST** zero exactly those three fields with exactly those types (32-byte zeros, 64-byte zeros, `Null`). Zeroing `signer_kid` to `""` instead of `Null`, or omitting the zeroed byte strings, yields a different hash. (grounding §5.2)

To **verify** `receipt_hash`: recompute per steps 1–3 from the receipt's other fields and compare for equality with the stored `receipt_hash`.

## 5.4 Key & signature encoding

- ed25519 **public key**: 32 raw bytes (RFC 8032 compressed point). In JSON records it is 64 lowercase hex chars (`public_key_hex`).
- ed25519 **signature**: 64 raw bytes (R‖S). On a receipt it is a **64-byte** CBOR byte string; in JSON records it is 128 lowercase hex chars.
- `signer_kid`: opaque UTF-8 label identifying the signing key (default `vault:transit:rcx-registry-signing-key-1`). It is **not** a public key and does **not**, by itself, let a verifier obtain one (§5.6.1 / OQ-2).
- The signature marshaling is **raw** ed25519 (R‖S). Although the signer requests Vault's `marshaling_algorithm:"asn1"`, that setting is inert for ed25519 and the on-wire signature is the raw 64-byte form. Implementations **MUST NOT** expect DER/ASN.1 wrapping. (grounding §5.4)

## 5.5 The six receipt types

Field sets below are the **logical** field set of each receipt (grounding §5.5). All are text-keyed CBOR maps; encode per §2 (keys sorted length-first). `zeroable` marks the three fields neutralised for the hash preimage (§5.3).

### 5.5.1 RegistrySnapshot
Minted once per sync tick over the full mirrored set.

| Key | Type | Notes |
|---|---|---|
| `event_id` | bytes[16] | opaque |
| `snapshot_id` | bytes[16] | opaque |
| `scraped_at` | uint | ms since epoch |
| `server_count` | uint | number of mirrored servers |
| `snapshot_merkle_root` | bytes[32] | §6 |
| `previous_snapshot_hash` | bytes[32] \| null | prior snapshot's `snapshot_hash`; null for the first (§6.5) |
| `upstream_registry_uri` | text | constant `https://registry.modelcontextprotocol.io/v0/servers` |
| `upstream_snapshot_etag` | text \| null | upstream ETag if present |
| `changes` | map | `{added: uint, removed: uint, modified: uint}` (nested map, also §2-ordered) |
| `receipt_hash` | bytes[32] | zeroable |
| `receipt_signature` | bytes[64] | zeroable |
| `signer_kid` | text | zeroable → `Null` in preimage |

**`changes` semantics — implementation quirk, NOT frozen.** The three-count
`changes` map is a byte-frozen field (nested map, keys length-first per §2.4:
`added`, `removed`, `modified`), and it **is** part of the receipt's hash and
signature preimages. Its *values*, however, are **not** a reliable inter-snapshot
diff: the live sync path builds every `RegistrySnapshot` against an **empty**
previous set, so on the wire `changes` currently always reads
`{added: server_count, removed: 0, modified: 0}` (grounding Resolutions
2026-07-19; `loops/sync.rs:170`, `ingest lib.rs:573,585-589`). This all-added
reading is an implementation artifact, not part of the frozen wire semantics. A
consumer **MUST NOT** treat `changes` as an authoritative delta; derive real
deltas from the snapshot chain (§6.6) and per-server reconciliation (§6.5). The
count *encoding* is frozen; the current count *values* are not.

### 5.5.2 EntryAutoEnriched
| Key | Type | Notes |
|---|---|---|
| `event_id` | bytes[16] | |
| `server_name` | text | |
| `snapshot_id` | bytes[16] | |
| `auto_enrichment_bytes` | bytes | canonical CBOR of the auto payload (§5.7) |
| `receipt_hash` / `receipt_signature` / `signer_kid` | | zeroable trio |

### 5.5.3 EntryEnriched
| Key | Type | Notes |
|---|---|---|
| `event_id` | bytes[16] | |
| `server_name` | text | |
| `publisher_passport` | text | e.g. `passport:github:<owner>` |
| `declared_uri` | text | publisher-hosted declaration URL |
| `declared_hash` | bytes[32] | §4.4 |
| `enrichment_bytes` | bytes | canonical CBOR of the publisher payload (§5.7) |
| `supersedes_prior` | bytes[32] \| null | prior EntryEnriched `receipt_hash`, or null |
| `receipt_hash` / `receipt_signature` / `signer_kid` | | zeroable trio |

### 5.5.4 AttestationAccepted
| Key | Type | Notes |
|---|---|---|
| `event_id` | bytes[16] | |
| `attestation_id` | bytes[16] | |
| `server_name` | text | |
| `issuer_passport` | text | |
| `type` | text | **CBOR key is `type`** (publisher/reviewer/auditor/operator) |
| `attestation_hash` | bytes[32] | producer-defined (§4.6) |
| `attestation_bytes` | bytes | the attestation document, opaque here |
| `receipt_hash` / `receipt_signature` / `signer_kid` | | zeroable trio |

### 5.5.5 AttestationRevoked
| Key | Type | Notes |
|---|---|---|
| `event_id` | bytes[16] | |
| `attestation_id` | bytes[16] | |
| `revoker_passport` | text | |
| `reason` | text \| null | |
| `revoked_at` | uint | ms since epoch |
| `revocation_signature` | bytes[64] | **NOT zeroed** — part of signed content |
| `receipt_hash` / `receipt_signature` / `signer_kid` | | zeroable trio |

### 5.5.6 PublisherRightsVerified
| Key | Type | Notes |
|---|---|---|
| `event_id` | bytes[16] | |
| `publisher_passport` | text | |
| `namespace` | text | e.g. `io.github.<owner>` |
| `verification_method` | text | one of `github_oauth`, `dns_txt`, `manual` |
| `verified_at` | uint | ms since epoch |
| `receipt_hash` / `receipt_signature` / `signer_kid` | | zeroable trio |

## 5.6 Signature — normative (OQ-1 resolved: path A)

Every signed receipt carries an ed25519 signature (`receipt_signature`) over its
**path A** preimage: the receipt's **full canonical CBOR with only the
`receipt_signature` field zeroed**. This is the message that minted every receipt
on `registry.rcxprotocol.org` (grounding §5.3 path A; `loops/sync.rs:330-331`,
`loops/enrich.rs:191-192`).

**Signing (normative):**
1. Build the receipt map with **all real values** — including the real
   `receipt_hash` (§5.3) **and** the real `signer_kid` text. This is **not** the
   zeroed-field encoding of §5.3.
2. Set **only** `receipt_signature` to a byte string of **64 zero bytes**. Every
   other field keeps its real value; on an `AttestationRevoked` receipt,
   `revocation_signature` is **not** zeroed (§5.5.5).
3. Encode that map as canonical CBOR (§2). The resulting byte string is the
   **signature preimage**.
4. `receipt_signature = ed25519_sign(private_key, preimage)` — raw 64-byte R‖S
   (§5.4).

**Verification (normative):**
1. Take the receipt as received.
2. Reconstruct the preimage: re-encode the receipt's canonical CBOR (§2) with
   `receipt_signature` set to 64 zero bytes and **every other field — including
   the real `receipt_hash` and the real `signer_kid` — at its received value**.
3. `ed25519_verify(public_key, receipt_signature, preimage)` **MUST** succeed.
4. A verifier **SHOULD** also independently recompute `receipt_hash` per §5.3
   (the *hash* preimage zeroes three fields, §5.3) and confirm it equals the
   embedded value.

Note the asymmetry between the two preimages: the **hash** preimage (§5.3) zeroes
**three** fields (`receipt_hash`, `receipt_signature`, `signer_kid`), whereas the
**signature** preimage zeroes **only** `receipt_signature` — the real
`receipt_hash` and the real `signer_kid` **are** signed. An implementation
**MUST** sign and verify over the full canonical-CBOR preimage of step 2 and
**MUST NOT** sign or verify over the bare 32-byte `receipt_hash`. (The
`chains.json` and `receipts.json` vectors carry the wrong-message case
`signature-over-32-byte-receipt-hash` as an explicit `verify_result: false`
negative.)

An all-zero `receipt_signature` (64 zero bytes) denotes an **unsigned** receipt
(keyless/local mode) and **MUST** be treated as not verifiable. (grounding §5.4)

### 5.6.1 Public-key distribution — documented v1 gap (OQ-2)

v1 does **not** define how a verifier obtains the registry's 32-byte ed25519
public key from `signer_kid`: `signer_kid` is an opaque label (§5.4), and no
wire field or endpoint in v1 serves the key. Until a publication channel is
defined (proposed for **M1a**), a receipt is **hash-verifiable but not
signature-verifiable from this specification alone**. A consumer that does not
hold the registry public key out of band **MUST** rely on `receipt_hash` (§5.3)
for content integrity and treat the signature as unverifiable rather than as
absent or invalid. (grounding §5.4, OQ-2.)

## 5.7 Embedded payload field sets

`auto_enrichment_bytes` = canonical CBOR of `{category: text, capability_graph: null, attestations_count: uint, auto_enriched_at: text}`.

`enrichment_bytes` = canonical CBOR of `{category: text, min_tier: text|null, required_affinity: text|null, capability_graph: <value>, declared_at: text, declared_uri: text, declared_hash: text("blake3:<hex>"), publisher_rights_verified: bool, verification_method: text, refresh_interval_seconds: uint|null}`.

Both are encoded per §2 (keys length-first) and embedded verbatim as the receipt's byte-string field before the receipt's own hash is taken (§4.5). (grounding §3 rows 5–6, enrich `lib.rs:96-149,247-264`.)
