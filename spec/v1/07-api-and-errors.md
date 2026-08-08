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
| `GET /.well-known/rcx-keys.json` | Signing-key discovery — the ed25519 public key(s) keyed by `signer_kid` ([05-receipts.md §5.6.1](05-receipts.md); Erratum E-1) |
| `GET /v0/snapshots` | List verifiable snapshots, newest first (Erratum E-2) |
| `GET /v0/snapshots/latest` | The most recent verifiable snapshot (Erratum E-2) |
| `GET /v0/snapshots/{snapshot_id}` | One snapshot by hex id (Erratum E-2) |
| `GET /v0/snapshots/{snapshot_id}/entries` | The entry set that snapshot's root digests (Erratum E-2) |

### 7.2.1 Snapshot artifacts (Erratum E-2)

E-1 lets a verifier check a signature. These endpoints are how it obtains the
bytes to check. Without them the specification describes a verification that
nothing in it can supply the inputs for.

A snapshot object:

```json
{
  "snapshot_id": "<hex>",
  "scraped_at": "<RFC-3339>",
  "server_count": <int>,
  "snapshot_root": "<hex>",
  "receipt_hash": "<hex>",
  "signer_kid": "<text>",
  "receipt_cbor_hex": "<hex>",
  "entries_available": <bool>
}
```

- `receipt_cbor_hex` is the **signed canonical CBOR** of the RegistrySnapshot
  receipt (§5.6) — the exact bytes `verifyReceipt` takes, signature in place.
- `snapshot_root` is the receipt's `snapshot_merkle_root`: a **flat set digest**,
  not a tree (§6.1). It is reproduced here for convenience; the authoritative
  copy is the one inside the signed bytes, and a verifier **MUST** prefer that.
- A server **MUST NOT** list or serve a snapshot it cannot supply signed bytes
  for. A snapshot whose bytes were never retained has no verifiable form, and
  offering it would hand a caller an artifact they cannot check.

`entries_available` is `false` once the entry set has passed the server's
retention window. The receipt still verifies; **membership can no longer be
recomputed** for that snapshot. The two are independent, and a client **MUST
NOT** infer one from the other.

`GET /v0/snapshots` takes `limit` (1–100, default 20) and `before`, an RFC-3339
instant returning snapshots strictly older. The response carries `next_before`,
the oldest returned `scraped_at`, so paging is a copy rather than a computation.
A malformed `before` is a **400** — never a silent restart from the newest row,
which would page a caller in a loop over the same snapshots indefinitely.

```json
{ "count": <int>, "snapshots": [ … ], "next_before": "<RFC-3339|null>" }
```

`GET /v0/snapshots/{snapshot_id}/entries` returns the `{name, version,
canonical_json}` array the root digests, in digest order-independent form —
§6.1's ordering rule is applied by the verifier, not by the wire. It is
**large** (tens of megabytes at production scale) because v1 has no inclusion
proof: establishing that one server is in a snapshot means recomputing the whole
digest (§6.1, OQ-4). `404` once the entry set has aged out.

An unknown **or malformed** `snapshot_id` is `404`, not `400`: a caller asking
about a snapshot that does not exist and one asking with a malformed id are
both asking about nothing.

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
