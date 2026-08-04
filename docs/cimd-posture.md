# Posture: Client ID Metadata Documents

**Status:** Proposed — awaiting operator sign-off. No code, no wire change.
**Date:** 2026-08-03
**Context:** MCP revision `2026-07-28` deprecates OAuth Dynamic Client Registration in favour of
Client ID Metadata Documents.
**Recommendation:** **Attest, do not compete.**

---

## What CIMD actually is

A client's `client_id` **is** an HTTPS URL that resolves to a JSON metadata document. From the
[MCP client-registration spec](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/client-registration)
and [draft-ietf-oauth-client-id-metadata-document-00](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-00):

- The `client_id` URL **MUST** use `https` and contain a path component (`https://example.com/client.json`).
- The document **MUST** contain at least `client_id`, `client_name`, `redirect_uris`, and its
  `client_id` **MUST** match the document URL exactly.
- Authorization servers **SHOULD** fetch the document on encountering a URL-formatted `client_id`,
  **MUST** validate the self-reference and the redirect URIs, and **SHOULD** cache per HTTP cache headers.
- Client IDs are **portable across authorization servers**, because they are self-hosted URLs resolved
  on demand rather than credentials issued by one server.

Support is advertised by `client_id_metadata_document_supported: true` in Authorization Server metadata.

## Correcting an earlier reading

An earlier assessment of this revision described CIMD as "adjacent to and partly competitive with
RCX-Registry's DNS-challenge and GitHub-OAuth namespace proof." Having read the mechanism, that
framing is wrong in an important way and is corrected here:

**CIMD identifies *clients*. RCX publisher-rights identifies *server publishers*.** Different
principals, different point in the lifecycle. CIMD says "this application is who it claims to be, at
the moment of authorization." Publisher-rights says "this namespace belongs to this publisher, at the
moment of publication." They are not substitutes and CIMD does not erode publisher-rights'
differentiation.

The genuine relationship is narrower and more interesting, below.

## The gap CIMD leaves — and it is the gap we already argue about

RCX-Registry's public thesis is on the front page: *namespace ownership is solved; history isn't.*
Registries verify who a publisher is at the moment they publish, and nothing about that makes the
registry's history tamper-evident or catches a server that turns malicious after approval.

**CIMD reproduces that exact gap, one layer over, for clients — and arguably worse.**

- The metadata document is **mutable at a stable identifier**. The same `client_id` URL can serve
  different `redirect_uris`, a different `client_name`, or a different JWKS tomorrow. Nothing in the
  mechanism records that it changed.
- Freshness is governed by **HTTP cache headers**, chosen by the party being identified. The subject
  of the identity claim controls how long a verifier may hold a stale copy of it.
- The claim is **fetched, not signed**. Except for optional `private_key_jwt` with JWKS, there is no
  cryptographic binding — trust reduces to "whoever controlled that URL at fetch time, plus the
  Web PKI."
- There is **no history**. A verifier cannot ask "what did this client_id assert last month?", which
  is precisely the question that mattered in every supply-chain incident on our own front page.

A rug-pull against a CIMD is a document edit. That is a cheaper attack than the npm-published server
rug-pull we already cite (CVE-2025-54136), and it lands on the redirect URIs — the field that decides
where authorization codes go.

## Options

### A. Ignore

Do nothing. CIMD is client-side and does not touch the registry's `/v0` mirror or `rcx-spec/v1`.

**Rejected**, but honestly it is the cheapest defensible choice. It is rejected because the gap above
is not hypothetical, it is *our own stated thesis* appearing in a new place, and because the cost of
deciding now is near zero while the publisher-rights surface is still fail-closed.

### B. Compete — extend publisher-rights to cover client identity

Build an RCX-native client-identity mechanism as an alternative to CIMD.

**Rejected.** It re-solves the part the ecosystem has now standardised, invites a fragmenting second
standard, and asks clients to adopt a non-standard identifier for a problem CIMD already handles
adequately at the moment of authorization. Our differentiator has never been *establishing* identity;
it is making history over that identity verifiable.

### C. Attest — snapshot and receipt CIMDs the way we do registry entries · **RECOMMENDED**

Treat a CIMD as another artifact whose *history* deserves tamper-evidence:

- Fetch and canonicalise the metadata document, hash it per
  [`04-hashing.md`](../spec/v1/04-hashing.md), and mint a receipt over the
  `(client_id URL, document hash, observed_at)` triple.
- Include those observations in the snapshot set, so "what did this `client_id` assert, and when did
  it change?" becomes a query over receipts.
- Surface diffs on the `redirect_uris` field specifically, since that is the field a rug-pull moves.

This is additive, requires no client cooperation and no change to CIMD itself, and reuses machinery
that already exists — canonical encoding, BLAKE3 hashing, CROWN receipts, the snapshot set. It also
lands directly on the MCP flow's own extension point: the client-registration sequence diagram
already names an optional *"Domain allowed via trust policy"* validation step, which is exactly where
an authorization server would consult an attestation.

**Cost of being wrong is low**: if nobody wants it, we have published some observations nobody reads.
Nothing on the wire changes for existing verifiers.

## Why deciding now is cheap

Every publisher-rights write is still failing closed at the production edge, and complete signed
enrichment artifacts are not yet persisted or returned. There is no deployed behaviour to retrofit —
the decision shapes work that has not been built yet. Deciding after publisher-rights reopens would
mean changing something live.

## What this does *not* commit to

- No wire change. `rcx-spec/v1` is frozen and untouched by this posture.
- No RFC yet. Option C, if adopted, requires an RFC with an exact wire format, hashing inputs, and
  conformance vectors before any code, per [`rfcs/README.md`](../rfcs/README.md). This document is
  the posture, not the construction.
- No claim to be part of MCP. Attesting CIMDs is something a third party does *about* public
  documents; it needs no standing in the MCP spec.

## Open questions

1. **Fetch cadence.** Continuous polling of client-controlled URLs is a crawler with a re-identification
   footprint. On-demand-at-first-sight plus periodic re-check is probably right, but the privacy and
   load characteristics need thought before an RFC.
2. **Scope.** Every CIMD we encounter, or only those referenced by servers in the mirror? The latter
   is defensible and much smaller.
3. **Web PKI dependency.** Attesting a fetched document inherits the trust properties of the
   connection it was fetched over. A receipt says "this is what we saw", never "this is authentic" —
   the distinction must be explicit in any published artifact, or the receipt over-claims.
4. **Interaction with `private_key_jwt`.** Where a client uses JWKS-based authentication, key rotation
   is legitimate and frequent. Diffing must not present rotation as tampering.
