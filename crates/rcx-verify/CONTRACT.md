# RCX verify contract — five verbs

`rcx-verify-contract/1` · implements `rcx-spec/v1`

This is the language-neutral surface every RCX verification SDK implements. Rust,
TypeScript, Python and Go expose the same five verbs with the same inputs,
outputs and failure codes, and all four are driven by the **same** spec-v1
conformance vectors through the adapter protocol in §7.

## 0. What this is not

This contract does **not** define wire format. Bytes, hashes, framing and
signature preimages are `rcx-spec/v1` and are frozen; nothing here may change
them. The failure codes in §6 are *contract* surface — an SDK's vocabulary for
reporting why verification failed. They are not published in receipts and carry
no wire compatibility obligation.

Every verb is **offline**. No verb performs I/O, opens a socket, resolves DNS, or
reads a clock. An implementation whose dependency tree contains an HTTP client,
a TLS stack, an async runtime or a JSON-schema validator does not conform (§8).

## 1. `verifyReceipt(signedCanonicalCbor, publicKey) -> ReceiptFacts`

Verify one CROWN receipt from its bytes.

1. Decode `signedCanonicalCbor` as canonical CBOR (spec §2). Re-encode the
   decoded value; if it does not reproduce the input **byte for byte**, fail
   `not_canonical`. This makes the round-trip assumption explicit — a
   non-canonical encoding that happened to decode must never verify.
2. Read `receipt_hash`, `receipt_signature`, `signer_kid` from the top-level map.
   Any missing → `missing_field`.
3. Recompute the hash over the **zeroed-field** encoding (spec §5.3: `receipt_hash`,
   `receipt_signature` and `signer_kid` all neutralised). Compare to the stored
   `receipt_hash`; mismatch → `hash_mismatch`.
4. Verify raw Ed25519 over the **full** canonical CBOR with **only**
   `receipt_signature` zeroed — `signer_kid` and the real `receipt_hash` remain
   present (spec §5, and `receipts.json.signature_verification_rule`). Failure →
   `bad_signature`.

Deliberately **generic over receipt type**: steps 1–4 are map-level, so all six
receipt types verify through one code path with no typed decoding. An SDK MUST
NOT require the caller to name the receipt type.

Returns `{ receiptHash, signerKid }` so a caller can chain without re-decoding.

> Note (OQ-1, spec §5.3): steps 3 and 4 hash **different** preimages. Using one
> for both is the defect that shipped in this repository once already and went
> undetected because no code path called the verifier. Conformance requires the
> positive case *and* the tamper cases.

## 2. `verifySnapshot(entries, expectedRoot) -> ()`

Recompute the snapshot set digest over `entries` (spec §6: lex-sort by
`(name, version)`, frame each as `name 0x00 version 0x00 canonicalJson 0xff`,
BLAKE3-256 the concatenation) and compare to `expectedRoot`. Mismatch →
`root_mismatch`.

`entries` carry exactly `(name, version, canonicalJson)`. Mirror-only fields
(`schema_uri`, `schema_date`, `status`, `updated_at`, `is_latest`) never enter
the digest and MUST NOT be required of a caller.

> Despite the wire field name `snapshot_merkle_root`, this is a flat digest over
> a sorted set, **not** a Merkle tree — no inclusion proof is derivable from it
> (OQ-4). Inclusion and consistency proofs are spec v2.

## 3. `verifyPublisher(declaration, expectedDeclaredHash) -> ()`

Canonicalise `declaration` as canonical JSON (spec §3) and BLAKE3-256 it
(spec §4.4). Compare to `expectedDeclaredHash`; mismatch →
`declaration_hash_mismatch`.

Canonical JSON sorts object keys by UTF-8 code-unit order, which differs from
RFC 8785's UTF-16 order for astral-plane keys. That divergence is observed and
frozen — an SDK that "corrects" it fails the `canonical-json.json` vectors.

## 4. `verifyNamespace(binding) -> ()`

Verify that a server namespace is bound to the publisher passport that claims it:
recompute the binding's declaration hash per §3 and confirm the declaration's
`mcp_name` equals the namespace being claimed. Mismatch → `namespace_mismatch`.

**Scope limit, stated plainly:** in spec v1 this is the *whole* of what a namespace
claim can be verified against offline. There is no published mapping from
`signer_kid` to a public key (OQ-2), and production currently publishes zero
passport and zero publisher-rights records — `/v0/passports` and `/v0/projects`
both return `count: 0` because unauthenticated publisher writes fail closed. So
this verb is conformant but thin until publisher rights reopen, and an SDK MUST
NOT imply it proves operator-independent namespace ownership. It does not.

## 5. `verifyHistory(chain) -> ()`

Verify each link with `verifyReceipt`, then verify the links.

**The link rule depends on chain kind, and the two are not the same field:**

| Chain kind | Link field | Links to |
|---|---|---|
| `snapshot` | `previous_snapshot_hash` | the prior link's **`snapshot_merkle_root`** |
| `entryEnriched` | `supersedes_prior` | the prior link's **`receipt_hash`** |

Snapshot chains link root-to-root; enrichment chains link receipt-to-receipt.
Applying one rule to the other kind produces a chain that fails to verify for a
reason unrelated to tampering, so an SDK MUST take the kind as an explicit
argument and MUST NOT infer it. Broken link → `chain_broken` with the index.

The first link's link-field is absent or zero and MUST NOT be treated as a break.

## 6. Failure codes (frozen for `rcx-verify-contract/1`)

`not_canonical` · `missing_field` · `hash_mismatch` · `bad_signature` ·
`root_mismatch` · `declaration_hash_mismatch` · `namespace_mismatch` ·
`chain_broken` · `bad_public_key` · `decode_error`

An SDK MAY add detail alongside a code; it MUST NOT rename or repurpose one.

## 7. Adapter protocol (how the harness drives any SDK)

Each SDK ships one executable speaking newline-delimited JSON on stdin/stdout —
one request per line, one response per line, in order. This is the only thing the
harness knows about a language.

```jsonc
→ {"verb":"verifyReceipt","signedCanonicalCborHex":"a5...","publicKeyHex":"2152..."}
← {"valid":true,"receiptHashHex":"9f...","signerKidPresent":true}

→ {"verb":"verifySnapshot","entries":[{"name":"a/mcp","version":"1.0.0","canonicalJson":"{}"}],"expectedRootHex":"ab..."}
← {"valid":false,"error":"root_mismatch"}
```

Contract: hex is lowercase and unpadded; a malformed request is a response with
`valid:false` and `error:"decode_error"`, never a crash or a non-zero exit. The
adapter exits 0 on clean EOF.

## 8. Conformance

An implementation conforms when:

1. Every spec-v1 vector reproduces through the adapter — positive **and** negative
   cases. A suite that only checks positives does not conform; every verb here
   can be trivially satisfied by `return valid`.
2. Verifying the reference receipt takes **<50 ms**.
3. Its dependency tree contains no HTTP client, TLS stack, async runtime or
   JSON-schema validator, asserted mechanically rather than by inspection.
