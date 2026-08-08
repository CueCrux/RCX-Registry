---
rfc: 0001
title: Transparency log — inclusion proofs, consistency proofs, witness co-signing, key rotation
status: Review
spec-target: rcx-spec/v2 (additive; v1 unaffected)
created: 2026-07-30
comment-period-opens: 2026-08-07
comment-period-closes: 2026-09-04
---

# RFC-0001: Transparency log

## Summary

Make RCX's snapshot history *provable* rather than merely signed. Three additive
constructions: **inclusion proofs** (this server was in snapshot N), **consistency
proofs** (snapshot N extends snapshot M without rewriting it), and **witness
co-signing** (no single operator, us included, can present a fork undetected).
Plus **key rotation and revocation** that preserves historical verifiability.

Ships as `rcx-spec/v2`, additively, behind version negotiation. Every receipt
already minted under v1 keeps verifying, unchanged, forever.

## Problem

Today RCX signs its history. It cannot prove it.

**There is no tree.** The field is called `snapshot_merkle_root`, but the
construction is a flat sequential BLAKE3 over lex-sorted `(name, version,
canonical_json)` entries framed with `0x00`/`0xFF` separators
([`rcx-registry-crown/src/hashing.rs`](../crates/rcx-registry-crown/src/hashing.rs),
`snapshot_merkle_root`; `rcx-registry-ingest` re-exports it, frozen in
[spec §6](../spec/v1/06-merkle-and-snapshots.md)). It is a **set digest**. Spec v1
says so plainly rather than hiding behind the field name, and that honesty is
what makes this RFC necessary:

- **No inclusion proof is derivable.** To convince yourself a server was in
  snapshot N you must obtain *every* entry of snapshot N and recompute the whole
  digest. For a mirror of the upstream MCP registry that is the entire corpus, to
  answer one question about one server.
- **No consistency proof is derivable.** Given snapshot roots for M and N, nothing
  demonstrates that N is an append-only extension of M. An operator could rewrite
  history between two snapshots and both would verify in isolation.
- **One signer.** Snapshots are signed by a Vault Transit ed25519 key the operator
  controls. A verifier checking that signature has confirmed the operator signed
  it — which is not the claim RCX makes. The claim is verification *without
  trusting the operator*, and a single-signer log cannot support it: the operator
  can sign two different histories and no verifier holding only one can tell.
- **Rotation is unspecified.** The registry's *current* key is published — `GET
  /.well-known/rcx-keys.json` serves it, keyed by `signer_kid` (spec v1 §5.6.1,
  Erratum E-1, 2026-08-07), so a verifier can check a signature today without
  asking the operator for anything. What does not exist is **key history**: no
  published record of which key was valid over which interval, and no revocation
  status. A receipt signed under a since-rotated key therefore has nothing to
  verify against, and rotating the key today would silently strand every
  signature made before it.

The last point is worth stating precisely, because it moved recently. Key
*publication* shipped, so spec v1 verification is complete in practice for a
receipt signed under the current key — inclusion proofs would no longer sit on
top of an unverifiable signature. Key *history across rotation* remains missing,
and that is a genuine prerequisite for the rotation half of this RFC (§5): a log
whose signatures stop verifying the moment its key changes has not solved
history, it has postponed the problem. Publication is out of scope here; history
and revocation are in.

## Proposal

### 1. Merkle tree over the entry set (`rcx-spec/v2`)

Introduce a **binary Merkle tree** per RFC 6962 §2 leaf/node hashing, over the
same lex-sorted entry sequence v1 already digests, so the ordering rule and the
canonical-JSON entry encoding are unchanged and reviewed.

- Leaf: `BLAKE3(0x00 || entry_frame)` where `entry_frame` is v1's
  `name 0x00 version 0x00 canonical_json` — **without** the trailing `0xFF`.
- Interior: `BLAKE3(0x01 || left || right)`.
- Domain separation prefixes are mandatory and exist to prevent second-preimage
  attacks that unprefixed trees admit.
- Empty tree: `BLAKE3()` of the empty input, matching v1's empty-set behaviour.

A new receipt field `snapshot_tree_root` carries it. **`snapshot_merkle_root`
retains its v1 meaning and value** — the flat set digest — because changing it
would invalidate every published snapshot. Two roots coexist; v2 clients check
both, v1 clients check the one they know. The field name remains a documented
misnomer; renaming it is not worth breaking verification over.

### 2. Inclusion proofs

`GET /v2/snapshots/{root}/inclusion?name=&version=` returns the audit path.
Verifiers recompute leaf-to-root. `verifyInclusion` joins the SDK verb surface.

### 3. Consistency proofs

`GET /v2/snapshots/consistency?from=&to=` returns an RFC 6962 §2.1.2 consistency
proof. A verifier that has previously seen root M and now sees root N MUST be able
to establish that N extends M, or reject N. This is the construction that makes
silent history rewriting detectable, and it is the reason a tree is worth the
complexity at all.

### 4. Witness co-signing

N-of-M independent witnesses observe roots and co-sign. SDKs enforce a
configurable quorum and reject below-quorum snapshots.

Witnesses see only `(root, tree_size, timestamp)` — never entry contents — so
witnessing costs a third party almost nothing and leaks nothing. Quorum values and
the initial witness set are **unresolved** (see below); they are governance
decisions, not cryptographic ones, and this RFC deliberately does not settle them
alone.

### 5. Key history, rotation, revocation

Publication of the *current* key already shipped in v1 (§5.6.1) and is not
proposed here. What follows extends it backwards in time.

- A published, signed **key history**: `signer_kid` → public key, validity
  interval, status. Served at a stable path and independently mirrorable. v1's
  `/.well-known/rcx-keys.json` answers "what is valid now"; this answers "what
  was valid then", which is the question a historical receipt asks.
- A receipt signed under a since-rotated key MUST still verify, against the key
  that was valid at its timestamp. Rotation that breaks history is not rotation,
  it is amnesia.
- Revocation produces a permanent **revocation receipt**; revocation is never
  silent and never retroactively erases what a key legitimately signed before
  compromise.

## Wire format

Deferred to the reference implementation and its vectors, per process rule 2 —
this section is what the comment period is for. What is already committed:
BLAKE3-256, 32-byte digests, ed25519 64-byte signatures, canonical CBOR for
receipts, canonical JSON for entry framing, all exactly as `rcx-spec/v1` §§1–4
define them. **No v1 byte changes.**

## Conformance vectors

Shipping with the reference implementation, extending the v1 suite's format:
inclusion proofs (valid, wrong-leaf, truncated path, forged sibling), consistency
proofs (valid extension, forked history, reordered, truncated), witness quorum
(at, below, mixed-validity signatures), key rotation (pre-rotation receipt
post-rotation, revoked-key receipt, key-history tampering).

Negative vectors are the point. All four constructions can be "implemented" by
returning success.

## Compatibility

- **v1 clients:** unaffected. New fields are additive; `snapshot_merkle_root`
  keeps its value and meaning.
- **Already-minted receipts:** keep verifying under v1 rules, permanently.
- **Negotiation:** clients advertise the max spec version they understand; the
  server serves the highest mutually understood. A v2 server MUST continue serving
  v1 verification data.

## Security considerations

**What this provides.** Detection of history rewriting (consistency proofs);
efficient proof of membership (inclusion proofs); resistance to a dishonest
operator presenting divergent histories to different verifiers (witness quorum);
continued verifiability across key changes (key history).

**What it does not.**

- It does not prevent an operator mirroring *wrong* data from upstream. RCX proves
  what it observed and when, not that upstream was honest. Nothing here changes
  that, and claiming otherwise would be the most dangerous thing this document
  could do.
- It does not prevent a **fully colluding** witness set. N-of-M assumes M
  independent operators; if we recruit all M ourselves the quorum is theatre. This
  is a governance risk, not a cryptographic one, and it is the reason M7 requires
  ≥3 *independent* witnesses before quorum is *required* rather than advisory.
- It does not protect a verifier who never persists a prior root. Consistency
  proofs need something to be consistent *with*; a client that checks only the
  latest root gains nothing from them. SDKs MUST make root persistence the
  documented default path, not an advanced option.
- It does not address availability. A witness set that goes dark can stall
  verification. Fail-open versus fail-closed on witness unavailability is
  unresolved, and it is the same question in a different costume as the ACP host
  question in M5b — an operator forced to choose between "no verification" and "no
  service" will choose service, so the protocol should not put them there.

**Second-preimage.** Domain-separation prefixes (§1) are mandatory precisely
because RFC 6962-style trees without them permit a crafted interior node to be
presented as a leaf.

## Alternatives considered

- **Do nothing; keep the flat digest.** Rejected: the CT-analogy claim is the
  product, and it is not true of a single-signer set digest. Honest alternative
  would be retracting the claim.
- **Replace the flat digest rather than adding alongside.** Rejected: invalidates
  every published snapshot. Process rule 1.
- **Adopt Trillian / Rekor wholesale.** Genuinely attractive — mature, reviewed,
  witnessed. Rejected for v2 because RCX's leaf is an MCP server envelope with its
  own canonicalisation that already ships and is frozen; adapting it into another
  log's leaf model is a larger, riskier change than adding a tree over the entry
  sequence we already order deterministically. Worth revisiting for federation
  (M8), and reviewers who think this is the wrong call should say so — it is the
  proposal's most consequential judgement.
- **Sign each entry individually instead of a tree.** Rejected: O(n) signatures
  per snapshot, no consistency property, and it answers the membership question
  while leaving the rewriting question untouched.

## Comment period

**Open 2026-08-07, closes 2026-09-04** — 28 days, the minimum this repository's
[process](README.md) requires for anything touching cryptography or wire format.
If those dates and this file's front matter ever disagree, the front matter wins.

Comment by opening an issue or a PR against this file. Disagreement with a
*rejected* alternative is as useful as disagreement with the proposal; the
"Alternatives considered" section names the judgement calls most likely to be
wrong, and the Trillian/Rekor rejection is the most consequential of them.

The reviewers this document is written for are listed in
[README § Invited reviewers](README.md#invited-reviewers): Sigstore,
Certificate Transparency, IETF SCITT, Transparency.dev.

Per process rule 3, code **may** merge during Review — but no M3a construction
lands in this repository before the period closes, because the point of the
clock is that the design can still change in response to a comment. If nobody
comments, that is an outcome and it gets recorded as one, not skipped.

## Unresolved

- **OD-1: quorum policy.** N and M values, and who the independent operators are.
  Governance, not cryptography.
- **OD-2: rotation cadence and emergency-rotation trigger authority.** Who can
  rotate under suspected compromise, and on what evidence.
- **Witness unavailability:** fail-open or fail-closed. See security
  considerations; this needs an operator decision, not a maintainer preference.
- **Proof serving cost** at mirror scale — tile-based serving (à la
  transparency.dev) may be necessary rather than optional.
- **Whether `snapshot_merkle_root` should eventually be renamed** with the old name
  retained as an alias, or left permanently misnamed for compatibility. Currently
  proposing the latter, without enthusiasm.
