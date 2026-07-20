# RCX Protocol Spec v1 — Independent Purity/Conformance Report

Implementation source: only the in-workspace `spec-v1/` prose and vectors. No reference implementation or other repository/path was consulted.

## Overall result

**292 passed, 0 failed, 292 total explicit computed-vs-expected comparisons.**

### Independently minted chain receipts

**6/6 full receipt encodings are byte-identical** when minted from structured logical inputs alone:

- `RegistrySnapshot`: 3/3.
- `EntryEnriched`: 3/3.
- Mint-stage outputs (zeroed CBOR, hash, signature preimage, deterministic signature, final CBOR, verification): 36/36.

The chain runner constructs each value model from `servers`, `previous_servers`, identifiers, timestamps, URIs/ETag, declaration, enrichment payload, predecessor, and per-link `signer_kid`; it then canonical-CBOR encodes, hashes, path-A signs, verifies, and compares raw minted bytes with the expected blob. It never decodes an expected chain receipt to obtain construction values.

- Snapshot inputs consumed: `event_id_hex`, `snapshot_id_hex`, `scraped_at_unix_ms`, `servers`, `previous_servers`, `previous_snapshot_hash_hex`, `upstream_registry_uri`, `upstream_snapshot_etag`, and per-link `signer_kid`.
- Enrichment inputs consumed: `event_id_hex`, `server_name`, structured `declaration`, `declared_uri`, structured `enrichment_payload`, `supersedes_prior_receipt_hash_hex`, and per-link `signer_kid`.

Those newly added fields are constructor inputs rather than additional expected outputs, so the ordinary comparison total remains 292; each raw signed-CBOR identity is their joint end-to-end assertion.

Additionally, 6/6 non-vector guards passed for newly clarified escaping, number presentation/domain, negative fractional capability CBOR, and NUL rejection. These guards are not included in vector-file counts.

| Vector file | Pass | Fail | Total |
|---|---:|---:|---:|
| `canonical-cbor.json` | 52 | 0 | 52 |
| `canonical-json.json` | 19 | 0 | 19 |
| `chains.json` | 104 | 0 | 104 |
| `hashes.json` | 30 | 0 | 30 |
| `receipts.json` | 66 | 0 | 66 |
| `snapshot-merkle.json` | 21 | 0 | 21 |

Counts include separate byte comparisons for canonical encodings, hash preimages, digests, deterministic test signatures, signed encodings, decoder rejection reason codes, verification verdicts, format/version guards, and chain relations. Diagnostic prose fields such as `production_function` and error-message text are not protocol computations and are not counted.

## Per-file and per-case counts

### `canonical-cbor.json`

| Case | Pass | Fail | Total |
|---|---:|---:|---:|
| `file-metadata` | 1 | 0 | 1 |
| `unsigned-integer-boundaries` | 2 | 0 | 2 |
| `integer-versus-float` | 2 | 0 | 2 |
| `negative-zero` | 2 | 0 | 2 |
| `shortest-float-widths` | 2 | 0 | 2 |
| `map-key-ordering-by-encoded-key` | 2 | 0 | 2 |
| `text-escaping-is-raw-utf8` | 3 | 0 | 3 |
| `unicode-astral-and-combining` | 5 | 0 | 5 |
| `nested` | 2 | 0 | 2 |
| `empty-containers` | 3 | 0 | 3 |
| `bytes-bools-and-null` | 2 | 0 | 2 |
| `duplicate-map-keys-retained` | 2 | 0 | 2 |
| `non-minimal-additional-info-24` | 2 | 0 | 2 |
| `non-minimal-additional-info-25` | 2 | 0 | 2 |
| `non-minimal-additional-info-26` | 2 | 0 | 2 |
| `non-minimal-additional-info-27` | 2 | 0 | 2 |
| `non-shortest-f32-representable-as-f16` | 2 | 0 | 2 |
| `non-shortest-f64-representable-as-f32` | 2 | 0 | 2 |
| `trailing-top-level-item` | 2 | 0 | 2 |
| `non-text-map-key` | 2 | 0 | 2 |
| `reserved-additional-info-28` | 2 | 0 | 2 |
| `reserved-additional-info-29` | 2 | 0 | 2 |
| `reserved-additional-info-30` | 2 | 0 | 2 |
| `reserved-additional-info-31` | 2 | 0 | 2 |

### `canonical-json.json`

| Case | Pass | Fail | Total |
|---|---:|---:|---:|
| `file-metadata` | 1 | 0 | 1 |
| `object-key-ordering` | 2 | 0 | 2 |
| `string-escaping` | 2 | 0 | 2 |
| `unicode-astral-and-combining` | 2 | 0 | 2 |
| `integers-versus-floats` | 2 | 0 | 2 |
| `negative-zero` | 2 | 0 | 2 |
| `nested` | 2 | 0 | 2 |
| `empty-containers` | 2 | 0 | 2 |
| `integer-boundaries` | 2 | 0 | 2 |
| `duplicate-object-key-last-wins` | 2 | 0 | 2 |

### `chains.json`

| Case | Pass | Fail | Total |
|---|---:|---:|---:|
| `file-metadata` | 1 | 0 | 1 |
| `test_key` | 1 | 0 | 1 |
| `snapshot_chain/link-1` | 15 | 0 | 15 |
| `snapshot_chain/link-1/signature-over-32-byte-receipt-hash` | 4 | 0 | 4 |
| `snapshot_chain/link-2` | 15 | 0 | 15 |
| `snapshot_chain/link-2/signature-over-32-byte-receipt-hash` | 4 | 0 | 4 |
| `snapshot_chain/link-3` | 15 | 0 | 15 |
| `snapshot_chain/link-3/signature-over-32-byte-receipt-hash` | 4 | 0 | 4 |
| `entry_enriched_receipt_chain/link-1` | 15 | 0 | 15 |
| `entry_enriched_receipt_chain/link-2` | 15 | 0 | 15 |
| `entry_enriched_receipt_chain/link-3` | 15 | 0 | 15 |

### `hashes.json`

| Case | Pass | Fail | Total |
|---|---:|---:|---:|
| `file-metadata` | 2 | 0 | 2 |
| `empty-object` | 3 | 0 | 3 |
| `reordered-object-a` | 3 | 0 | 3 |
| `reordered-object-b` | 3 | 0 | 3 |
| `unicode-combining` | 3 | 0 | 3 |
| `unicode-precomposed` | 3 | 0 | 3 |
| `integer-one` | 3 | 0 | 3 |
| `float-one` | 3 | 0 | 3 |
| `negative-zero` | 3 | 0 | 3 |
| `equivalence_group:reordered-object` | 1 | 0 | 1 |
| `canonical-server-hash` | 3 | 0 | 3 |

### `receipts.json`

| Case | Pass | Fail | Total |
|---|---:|---:|---:|
| `file-metadata` | 1 | 0 | 1 |
| `test_key` | 1 | 0 | 1 |
| `publisher-rights-production-preimage-sign-verify` | 12 | 0 | 12 |
| `publisher-rights-production-preimage-sign-verify/one-signature-byte-tampered` | 5 | 0 | 5 |
| `publisher-rights-production-preimage-sign-verify/content-byte-tampered` | 2 | 0 | 2 |
| `publisher-rights-production-preimage-sign-verify/signature-over-32-byte-receipt-hash` | 4 | 0 | 4 |
| `entry-auto-enriched-production-preimage-sign-verify` | 12 | 0 | 12 |
| `attestation-accepted-production-preimage-sign-verify` | 12 | 0 | 12 |
| `attestation-revoked-production-preimage-sign-verify` | 13 | 0 | 13 |
| `attestation-revoked-production-preimage-sign-verify/revocation-signature-wrongly-zeroed-in-signature-preimage` | 4 | 0 | 4 |

### `snapshot-merkle.json`

| Case | Pass | Fail | Total |
|---|---:|---:|---:|
| `file-metadata` | 1 | 0 | 1 |
| `empty-set` | 2 | 0 | 2 |
| `one-element` | 2 | 0 | 2 |
| `two-elements-unsorted` | 2 | 0 | 2 |
| `two-elements-permuted` | 2 | 0 | 2 |
| `odd-three-elements` | 2 | 0 | 2 |
| `larger-eight-elements` | 2 | 0 | 2 |
| `duplicate-identical-retained` | 2 | 0 | 2 |
| `duplicate-same-key-order-a` | 2 | 0 | 2 |
| `duplicate-same-key-order-b` | 2 | 0 | 2 |
| `invariants` | 2 | 0 | 2 |

## Normative traceability

- **CBOR value model and exclusions:** `spec-v1/02-canonical-cbor.md:9-22` — “A canonical-CBOR value is exactly one of” the listed uint/bytes/text/array/text-keyed-map/bool/null/finite-float kinds; “Encoders MUST NOT emit” negative integers, tags, other simple values, indefinite items, or non-shortest floats.

- **CBOR heads and bodies:** `spec-v1/02-canonical-cbor.md:26-46` — “The argument ... uses the shortest form”; “An encoder MUST use the shortest head that fits n”; bytes/text carry their raw/UTF-8 bodies, arrays retain list order, and maps emit key then value.

- **CBOR map ordering:** `spec-v1/02-canonical-cbor.md:53-64` — “Keys MUST be sorted by the bytewise lexicographic order of their encoded form”; “Shorter keys sort before longer keys”; the sort is stable, so represented duplicates retain input order.

- **CBOR floats:** `spec-v1/02-canonical-cbor.md:68-74` — finite floats “MUST choose the shortest width that round-trips x exactly” in f16→f32→f64 order, where exact means “bit-equal on conversion back to the source double.”

- **CBOR decoder:** `spec-v1/02-canonical-cbor.md:80-88` — a canonical validator “MUST reject” trailing bytes, non-minimal heads, non-shortest/non-finite floats, non-text map keys, and reserved/indefinite markers; v1 “MAY accept-and-normalise” out-of-order or duplicate maps.

- **Canonical JSON recursion and escaping:** `spec-v1/03-canonical-json.md:11-60` — canonicalJSON has “no whitespace between tokens,” preserves array order, collapses input duplicates last-wins, uses the exact named/lowercase-control escapes, emits raw non-ASCII and slash, and applies no Unicode normalization.

- **Canonical JSON ordering and numbers:** `spec-v1/03-canonical-json.md:62-95` — keys use “unsigned bytewise (UTF-8) comparison of the key content”; implementations “MUST NOT substitute an RFC 8785 canonicaliser”; numbers preserve integer/float distinction, cover the exact `[i64::MIN,u64::MAX]` domain plus binary64 fallback, preserve negative zero, and use the stated positional/scientific thresholds. A-04/A-05 record the remaining strict-purity edges.

- **BLAKE3 and artifact forms:** `spec-v1/04-hashing.md:7-26` — hashes use unkeyed/default BLAKE3 with 32-byte output; receipts hash canonical CBOR, while snapshots/declarations hash canonical JSON using the artifact input-pin table.

- **Hash strings, declarations, and payload bytes:** `spec-v1/04-hashing.md:30-55` — JSON hash strings are `blake3:<64 lowercase hex chars>` (bare accepted by consumers); `declared_hash = BLAKE3(canonicalJSON(declaration_document))`; canonical-CBOR enrichment payloads are embedded before receipt hashing; negative non-integral capability values are CBOR floats while negative integers are rejected.

- **Receipt shapes and field encodings:** `spec-v1/05-receipts.md:9-22,53-170,226-232` — identifiers are bytes[16], hashes bytes[32], signatures bytes[64], timestamps/counts uints, names text, nullable absence CBOR Null; §§5.5/5.7 enumerate all six exact receipt and payload field sets.

- **Receipt hash:** `spec-v1/05-receipts.md:30-43` — set `receipt_hash` to 32 zero bytes, `receipt_signature` to 64 zero bytes, and `signer_kid` to CBOR Null, retain all other real values, canonical-CBOR encode, then BLAKE3 hash.

- **Receipt signature verification:** `spec-v1/05-receipts.md:172-213` — Ed25519 signs/verifies the “full canonical CBOR with only the receipt_signature field zeroed”; real receipt hash, signer KID, and revocation signature remain; verification “MUST NOT” use only the 32-byte receipt hash, and an all-zero outer signature is unverifiable.

- **Opaque attestation bytes:** `spec-v1/05-receipts.md:127-135` — `attestation_bytes` is embedded verbatim as opaque producer input; a receipt verifier “MUST NOT” re-encode or re-canonicalise it.

- **Snapshot set digest and reconciliation hash:** `spec-v1/06-merkle-and-snapshots.md:16-67` — reject U+0000 in names/versions, stable-sort retained entries by UTF-8 `(name, version)`, hash one stream of `name || 00 || version || 00 || canonical_json || ff`; empty input hashes empty bytes; reconciliation uses the same frame without trailing `ff`.

- **Chain links:** `spec-v1/06-merkle-and-snapshots.md:69-81` — snapshot `previous_snapshot_hash` targets the prior set-digest root (not receipt hash), while `EntryEnriched.supersedes_prior` targets the prior receipt hash; first links are Null and `scraped_at` orders snapshots.

- **Structured chain constructors:** `spec-v1/vectors/README.md:45-81` — each chain link exposes the complete logical constructor input; expected counts, hashes, signatures, and CBOR are separate outputs.


## Failures

None. Every computable vector field checked by the runner matched.

## AMBIGUITY LOG

- **A-01 — resolved-by-prose.** `02-canonical-cbor.md:57-64` now says the sort is stable and byte-identical encoded keys retain input order. The equal-key bytes are therefore normatively determined.

- **A-02 — resolved-by-prose.** `03-canonical-json.md:27-37` now requires a parsed input document to collapse duplicate object names last-wins before rendering.

- **A-03 — resolved-by-prose.** `03-canonical-json.md:41-58` enumerates the seven exact named escapes, requires lowercase `\u00xx` for every other C0 control, and requires raw UTF-8 for all other characters.

- **A-04 — still-open.** The presentation thresholds and dependency versions are now pinned, but the spec-text-only digit selection remains incomplete. The insufficient sentence is: “Let `digits` be the shortest decimal significand” (`03-canonical-json.md:86`). It supplies neither a construction nor a tie-break if more than one shortest decimal round-trips. Referring to `ryu 1.0.23` is not self-contained under this purity boundary.

- **A-05 — still-open.** `03-canonical-json.md:81` now defines lossy binary64 fallback for integral tokens outside `[i64::MIN, u64::MAX]`. Overflow remains unspecified: “For a finite value `v`” and “Non-finite values do not occur” (`03-canonical-json.md:83-85`) do not say whether input such as `1e400` is rejected or mapped some other way.

- **A-06 — resolved-by-prose.** `vectors/README.md:45-81` declares and enumerates complete constructor inputs, and every link now supplies them. Combined with §§5-6, all six current receipt blobs can be minted without decoding expected CBOR. The resolution depends on the updated structured corpus as well as its describing prose.

- **A-07 — resolved-by-prose.** `05-receipts.md:15,40,145` consistently fixes `revocation_signature` as an always-present, non-nullable 64-byte string that is never zeroed.

- **A-08 — resolved-by-prose.** `05-receipts.md:17,127-135` now defines `attestation_bytes` as an opaque byte-string input embedded verbatim and forbids receipt-layer re-encoding. That determines receipt bytes; construction of the inner attestation remains intentionally outside the receipt layer.

- **A-09 — still-open.** The insufficient sentence is explicit: “v1 does **not** define a normative algorithm for deriving the true inter-snapshot delta” (`05-receipts.md:87-92`). The present chain fixtures remain computable because every `previous_servers` input is empty and lines 79-82 document the live all-added result; a non-empty prior set is not derivable.

- **A-10 — still-open.** The insufficient sentence remains: “v1 does **not** define how a verifier obtains the registry's 32-byte ed25519 public key from `signer_kid`” (`05-receipts.md:215-224`). Test vectors supply an out-of-band key.

- **A-11 — still-open.** `04-hashing.md:57-59` says the exact producer field set, ordering, and zeroing are outside v1 and that construction “is therefore **not normative in v1**.” The three producer-defined hash preimages remain uncomputable from this workspace.

- **A-12 — still-open.** `05-receipts.md:148-160` still says v1 does not define the inner `revocation_signature` preimage or revoker public-key discovery. Only the outer receipt signature is computable.

- **A-13 — resolved-by-prose.** `04-hashing.md:49-55` now partitions in-domain numbers: non-negative u64 integers become CBOR uints, non-integral values of either sign become CBOR floats, and negative integers are rejected. In particular, `-1.5` is normatively a negative CBOR float.

### New ambiguities

- **N-A-01.** `04-hashing.md:51-53` does not classify a positive integral-form `capability_graph` literal above `u64::MAX`: it does not fit the uint branch, has no fractional part or exponent for the float branch, and is not negative. `03-canonical-json.md:81` gives such tokens a binary64 fallback, but §4.5 does not say whether that parsed representation makes the capability value a float or an error.

## Prior defect disposition

- **D-01 — resolved.** Stable equal-key CBOR order is now normative (§2.4).

- **D-02 — still-open.** `README.md:44` still says encoders emit “no duplicate keys,” conflicting with `README.md:19` and §2.4's stable retention of represented duplicates.

- **D-03 — resolved.** JSON input duplicates are now normatively last-wins.

- **D-04 — resolved.** Every control escape and lowercase hex is pinned.

- **D-05 — still-open.** Version/threshold/domain text was added, but A-04 and A-05 retain the strict-purity gaps above.

- **D-06 — resolved.** Structured chain constructor inputs are now complete.

- **D-07 — resolved.** `revocation_signature` is consistently non-nullable.

- **D-08 — resolved.** `attestation_bytes` is explicitly opaque and verbatim, not canonicalised.

- **D-09 — still-open.** Intentional v1 public-key-discovery gap (A-10).

- **D-10 — still-open.** Intentional producer-defined hash gap (A-11).

- **D-11 — still-open.** Intentional inner-revocation verification gap (A-12).

- **D-12 — still-open.** No general normative `changes` derivation (A-09).

- **D-13 — resolved.** §6.2 now excludes U+0000 from name and version.

- **D-14 — resolved.** The canonical codec vector links now name real files.

- **D-15 — resolved.** The reported §4-§6 cross-references are corrected.

- **D-16 — resolved.** Negative non-integral capability values now map to floats.

## New defects found

- **N-D-01.** The new §4.5 capability-number partition omits positive integral-form values above `u64::MAX` (the byte ambiguity N-A-01).

- **N-D-02.** `03-canonical-json.md:81` cites `006-edge-large-uints`, but no such vector or case exists in the workspace.

- **N-D-03.** `07-api-and-errors.md:3` cites `vectors/api/*`, but the workspace contains no API vector directory or file.

- **N-D-04.** The normative vector corpus has no cases for several newly clarified rules (JSON presentation thresholds/wide-number fallback, alphabetic control-escape hex, negative non-integral capability floats, NUL rejection, or deliberately non-canonical opaque attestation bytes). The runner therefore includes six separate prose guards, but a 292/292 vector result alone would not detect regressions in those rules.

## Explicitly uncomputable/out-of-scope items

- `passport_hash`, `project_hash`, and `attestation_hash` preimages are withheld by §4.6; no attempt was made to invent them.
- Live receipt signatures cannot be verified from `signer_kid` alone; the vector test signatures are verified only because the vectors supply a public key.
- The inner `revocation_signature` cannot be verified because no inner message/key/algorithm construction is specified.
- The inner structure of `attestation_bytes` cannot be constructed from v1, by design; receipt bytes remain computable because the opaque input is embedded verbatim.
- A general `RegistrySnapshot.changes` algorithm for a non-empty previous server set is not normative. The current chain fixtures are computable because all previous sets are empty and the live all-added result is documented.
- Canonical-JSON overflow input behavior and a self-contained shortest-digit tie-break remain open under the strict spec-text-only boundary (A-04/A-05).

## Files read

- `reimpl.py`
- `REPORT.md`
- `spec-v1/README.md`
- `spec-v1/01-conventions.md`
- `spec-v1/02-canonical-cbor.md`
- `spec-v1/03-canonical-json.md`
- `spec-v1/04-hashing.md`
- `spec-v1/05-receipts.md`
- `spec-v1/06-merkle-and-snapshots.md`
- `spec-v1/07-api-and-errors.md`
- `spec-v1/vectors/README.md`
- `spec-v1/vectors/canonical-cbor.json`
- `spec-v1/vectors/canonical-json.json`
- `spec-v1/vectors/chains.json`
- `spec-v1/vectors/hashes.json`
- `spec-v1/vectors/receipts.json`
- `spec-v1/vectors/snapshot-merkle.json`

No file outside the workspace was consulted, and no `spec-v1/` or vector file was modified.
