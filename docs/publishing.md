# Publishing to RCX-Registry

This is the end-to-end path from "my MCP server is in the upstream registry" to "my entry carries verified RCX enrichment". Three steps: prove you control your namespace, host a declaration, submit it.

Base URL below is the production host. For a local stack (see the [README quickstart](../README.md#quickstart)) substitute `http://127.0.0.1:3030`.

```bash
BASE=https://registry.rcxprotocol.org
```

## 0. Prerequisites

- Your server is published in the [upstream MCP registry](https://registry.modelcontextprotocol.io) — RCX-Registry mirrors it automatically; you don't re-publish here.
- A publisher passport identifier. Conventions: `passport:github:<owner>` for GitHub-rooted namespaces, `passport:dns:<domain>` for reverse-DNS namespaces.

## 1. Verify namespace rights

Pick the method that matches your server's namespace.

### GitHub namespaces (`io.github.*`)

Walk the OAuth flow in a browser:

```
GET $BASE/v0/publisher-rights/github/start?server_name=<name>&publisher_passport=<passport>&redirect_uri=<uri>&state=<nonce>
```

The callback verifies your GitHub login matches the namespace owner and records a `PublisherRightsVerified` receipt.

### Domain namespaces (reverse-DNS, e.g. `com.example/*`)

Request a challenge:

```bash
curl -s -X POST $BASE/v0/publisher-rights/dns-challenge \
  -H 'content-type: application/json' \
  -d '{
    "server_name": "com.example/my-server",
    "publisher_passport": "passport:dns:example.com",
    "passport_fingerprint": "<your-passport-fingerprint>"
  }'
```

The response gives you a `record_name` (`_rcx-registry.example.com`) and an `expected_value`. Create that TXT record, then:

```bash
curl -s -X POST $BASE/v0/publisher-rights/dns-verify \
  -H 'content-type: application/json' \
  -d '{
    "server_name": "com.example/my-server",
    "publisher_passport": "passport:dns:example.com",
    "passport_fingerprint": "<your-passport-fingerprint>"
  }'
```

### Anything else

`POST /v0/publisher-rights/manual-verify` routes to operator-mediated review.

Check your standing rights at any time:

```bash
curl -s $BASE/v0/publishers/passport:dns:example.com | jq
```

## 2. Host an enrichment declaration

Write a JSON declaration of your server's RCX capability metadata, validating against
[`rcx-enrichment.schema.json`](https://static.rcxprotocol.org/schemas/2026-04-19/rcx-enrichment.schema.json)
(also in-repo at [`schemas/2026-04-19/`](../schemas/2026-04-19/)), and host it at a stable HTTPS URI you control, e.g. `https://example.com/.well-known/rcx-enrichment.json`.

## 3. Submit the declaration

```bash
curl -s -X POST $BASE/v0/publishers/declare \
  -H 'content-type: application/json' \
  -d '{
    "server_name": "com.example/my-server",
    "declared_uri": "https://example.com/.well-known/rcx-enrichment.json",
    "declaration": { /* the declaration document itself */ }
  }'
```

The registry validates the declaration against the schema and your verified rights, hashes it, and mints a signed `EntryEnriched` receipt.

## 4. See it live

```bash
curl -s "$BASE/v0/servers?limit=100" \
  | jq '.servers[] | select(.server.name == "com.example/my-server") | ._meta["org.rcxprotocol.registry/publisher"]'
```

## Refresh semantics

The enrichment loop re-fetches every `declared_uri` on a 24-hour cadence. When the fetched document's hash changes, a superseding `EntryEnriched` receipt is minted automatically — update the hosted file and the registry follows. Each receipt is ed25519-signed; the full history stays verifiable.
