# Publishing to RCX-Registry

All public publisher verification and declaration writes currently fail closed at the production edge. This page records the intended contracts and the remaining gates; it is not a callable onboarding guide. Rights reads remain public.

Base URL below is the production host. For a local stack (see the [README quickstart](../README.md#quickstart)) substitute `http://127.0.0.1:3030`.

```bash
BASE=https://registry.rcxprotocol.org
```

## 0. Prerequisites

- Your server is published in the [upstream MCP registry](https://registry.modelcontextprotocol.io). RCX-Registry serves a mirrored dataset, but its current sync attempt fails at Vault signing before snapshot persistence; do not infer fresh signed evidence.
- A publisher passport identifier. Conventions: `passport:github:<owner>` for GitHub-rooted namespaces, `passport:dns:<domain>` for reverse-DNS namespaces.

## 1. Verification design (production disabled)

The production edge returns 404 for DNS challenge/verify, GitHub start/callback, and manual review. Reopening requires authenticated passport binding, server-owned audit time, complete signed-artifact persistence, and public retrieval/key discovery.

### GitHub namespaces (`io.github.*`)

The OAuth routes are implemented, but production credentials are unset. They also require server-bound state and explicit organization ownership proof before they can reopen:

```
GET $BASE/v0/publisher-rights/github/start?server_name=<name>&publisher_passport=<passport>&redirect_uri=<uri>&state=<nonce>
```

The reference callback contract compares a GitHub identity with the namespace owner. It is not a usable production proof flow today.

### Domain namespaces (reverse-DNS, e.g. `io.example.com/my-server`)

The disabled reference challenge request is:

```bash
curl -s -X POST $BASE/v0/publisher-rights/dns-challenge \
  -H 'content-type: application/json' \
  -d '{
    "server_name": "io.example.com/my-server",
    "publisher_passport": "passport:dns:example.com",
    "passport_fingerprint": "<your-passport-fingerprint>"
  }'
```

The reference response gives `record_name` (`_rcx-registry.example.com`) and `expected_value`. The latter is exactly the request's `passport_fingerprint`; publish it verbatim, with no prefix. Do not create the record today: both public DNS routes return 404 while passport-to-domain binding is redesigned. The disabled verify contract is:

```bash
curl -s -X POST $BASE/v0/publisher-rights/dns-verify \
  -H 'content-type: application/json' \
  -d '{
    "server_name": "io.example.com/my-server",
    "publisher_passport": "passport:dns:example.com",
    "passport_fingerprint": "<your-passport-fingerprint>"
  }'
```

### Anything else

Public manual review is unavailable until an authenticated, passport-attributed operator surface ships. Every publisher verification method currently returns 404 at the production edge.

Check your standing rights at any time:

```bash
curl -s $BASE/v0/publishers/passport:dns:example.com | jq
```

## 2. Prepare an enrichment declaration

Write a JSON declaration of your server's RCX capability metadata, validating against
[`rcx-enrichment.schema.json`](https://static.rcxprotocol.org/schemas/2026-04-19/rcx-enrichment.schema.json)
(also in-repo at [`schemas/2026-04-19/`](../schemas/2026-04-19/)). Hosting it at a stable HTTPS URI you control prepares it for the future authenticated submission flow, but does not publish it today.

## 3. Declaration submission is closed

`POST /v0/publishers/declare` returns 404 at the production edge and is absent from the application router. Namespace rights are not caller authentication: accepting a passport identifier in a JSON body would let another caller overwrite publisher metadata. The route will reopen only with authenticated publisher proof, real signer integration, and public receipt/key retrieval.

## 4. Inspect your rights

```bash
curl -s "$BASE/v0/publishers/passport:dns:example.com" | jq
```

## Refresh semantics

The background enrichment implementation can re-fetch already-seeded `declared_uri` values on a 24-hour cadence and invoke Vault Transit. Production currently receives 403 from Vault during snapshot sync, and storage retains receipt-hash references rather than complete signed artifacts. There is no public declaration-seeding path, live receipt retrieval, or production signing-key discovery.
