# 7. Read API, Version Selection & Errors

`rcx-spec/v1` · traces to grounding §6 (`crates/rcx-registry-api/src/lib.rs`). No conformance vectors cover this section — the read API is a JSON wire-**shape** contract (the upstream MCP `/v0` response shape plus the error model), not a byte-canonicalisation path, so it is asserted by the prose below rather than by the `vectors/` corpus.

The baseline read API is **shape-compatible with the upstream MCP registry `/v0`**; existing MCP clients work unchanged. This section freezes the wire shapes an RCX-aware client depends on.

## 7.1 API versioning

The public API version is pinned **in the URL path** (`/v0`). There is **no** content-negotiated API versioning — `Accept`-header version selection is not used, and a client **MUST NOT** rely on one. `/v0` read responses are the upstream MCP registry shape. (grounding §6.2)

## 7.2 Read endpoints

| Method & path | Purpose |
|---|---|
| `GET /v0/servers` | List mirrored servers (cursor-paginated) |
| `GET /v0/servers/{name}/versions` | List all versions of one server |
| `GET /v0/servers/{name}/versions/{version}` | Fetch one server version |

`GET /v0/servers` list response:
```json
{
  "servers": [ { "server": { … }, "_meta": { … } }, … ],
  "metadata": { "nextCursor": "<cursor|absent>", "count": <int> }
}
```
- Each element is the upstream envelope: a `server` object plus a `_meta` object. RCX enrichment, when present, is under `_meta."org.rcxprotocol.registry/publisher"` (publisher-declared) and `_meta."org.rcxprotocol.registry/auto"` (auto). (grounding §6.1, docs/publishing.md)
- `metadata.count` is the number of `servers` in **this** page (not the total).

## 7.3 Server-version selection

"Version" refers to an **MCP server version**, resolved as follows (grounding §6.2):
- On `GET /v0/servers/{name}/versions/{version}`: the literal `version` value `latest` selects the record whose `_meta` marks it latest; any other value is an **exact string match** on the server version. No match → `404 not_found`.
- On `GET /v0/servers?version=…`: `version=latest` filters to latest-marked records; `version=<v>` filters to exact matches.
- `GET /v0/servers/{name}/versions` lists that server's versions in descending version order.

A client **MUST** treat `latest` as a reserved version selector and **MUST NOT** assume any ordering semantics of version strings beyond exact match + the `latest` selector.

## 7.4 Cursor pagination

- **Cursor token format:** `"{name}:{version}"` — the name and version of the last item on the current page, joined by a single `:`. (grounding §6.3)
- **Page size:** `?limit=<n>`; the effective limit is `clamp(n, 1, 100)` with a **default of 30** when `limit` is absent.
- **Semantics:** results are ordered by `(name, version)` ascending; a supplied `?cursor=<token>` returns the items strictly **after** the record whose token equals the cursor. `metadata.nextCursor` is present **only** when a further page exists, and equals the token of the last item on the current page.
- **Invalid cursor:** a `?cursor` value that matches no record → `400 invalid_cursor` (§7.5). A client **MUST** treat a cursor as an opaque token from a prior `nextCursor` and **MUST NOT** synthesise one, except that the `name:version` structure is stable in v1. (Signed/tamper-evident cursors are gated off in v1.)

## 7.5 Error model

Errors are JSON with a stable machine code:
```json
{ "code": "<stable_string>", "message": "<human text>" }
```
The `code` values and HTTP statuses are frozen (grounding §6.4):

| HTTP status | `code` | Meaning |
|---|---|---|
| 404 | `not_found` | server / version / record not found |
| 400 | `invalid_cursor` | `?cursor` matched no record |
| 400 | `bad_request` | malformed input |
| 422 | `verification_failed` | namespace-rights verification failed (passport/DNS mismatch) |
| 501 | `unavailable` | feature not implemented in this deployment |
| 500 | `store_error` | internal storage failure |

A client **MUST** branch on `code`, not on `message` (message text is not stable). A client **SHOULD** treat any unlisted `code` as a generic failure of its HTTP status class.

## 7.6 Operator endpoints (non-API)

`GET /healthz`, `GET /readyz`, `GET /metrics` are operator/observability routes, not part of the client-facing wire contract, and **SHOULD** be network-restricted. They are out of scope for conformance. (grounding §6.1)

## 7.7 Published records & publisher flows

`GET /v0/passports`, `/v0/passports/{fpr}`, `/v0/projects`, `/v0/publishers/{passport}` and the `POST /v0/publisher-rights/*` + `POST /v0/publishers/declare` flows are RCX extensions. Their JSON shapes are governed by the date-pinned schemas (`schemas/2026-04-19/`, `schemas/2026-05-01/`). Published passport/project records carry `signature`, `signer_kid`, and `*_hash` fields whose byte construction is **producer-defined and not frozen by v1** (§4.6 / OQ-3); a client **MUST NOT** assume it can independently reproduce those hashes/signatures from v1 alone.
