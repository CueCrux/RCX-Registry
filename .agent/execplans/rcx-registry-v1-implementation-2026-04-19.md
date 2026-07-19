# RCX-Registry v1.0 — Implementation ExecPlan

> Source: [RCX-Registry-Master-Plan-v1_0.md](../../../PlanCrux/docs/master-plan/RCX-Registry-Master-Plan-v1_0.md)
> Sibling spec: [VaultCrux-Session-Handshake-Master-Plan-v2_0.md](../../../PlanCrux/docs/master-plan/VaultCrux-Session-Handshake-Master-Plan-v2_0.md) (RCX-Protocol v1.0)
> Sibling ExecPlan: [vaultcrux-rcx-protocol-v2-2026-04-19.md](../../../PlanCrux/.agent/execplans/vaultcrux-rcx-protocol-v2-2026-04-19.md)
> Repo: [github.com/CueCrux/RCX-Registry](https://github.com/CueCrux/RCX-Registry) (empty at execplan creation)
> Author: Myles Bryning
> ExecPlan created: 2026-04-19
> Status: **PUBLIC REPO + M1 SOAK RUNNING 2026-07-19 (fact `gate:public-repo-and-soak`)** — operator made the repo public (dissolved the Actions billing block); PRs #1–#4 merged same night: #1 spawn_blocking panic + wget healthcheck + vendored session goldens (CI hermetic on standalone checkouts), #2 legacy upstream schema-URI date parsing + per-envelope skip (closes the `INGEST_BUG` from fact `gate:rollout-5points`), #3 professional README + `docs/publishing.md` publisher funnel, #4 connect/request timeouts on the blocking ingest/enrich HTTP clients (first tick after redeploy wedged silently on a stalled upstream response — idle socket, zero errors counted). Main redeployed to the VM via rsync + compose build (`.env` preserved — Vault signing wiring from `gate:rollout-5points` intact, no zeroed-sig warnings). Sync loop mirroring upstream with signed snapshot receipts. **Remaining gates:** trusted-cert decision (operator: repoint GoDaddy A records `registry`/`static`/apex from tailnet IP to public IP `77.42.92.157` + open 80/443, OR provide a DNS-01 token to keep tailnet-only), GitHub OAuth app + `GITHUB_OAUTH_CLIENT_{ID,SECRET}`, tailscale ACL snippet, `FEATURE_RCX_REGISTRY_PUBLISHER_DECLARATIONS=true` after a clean 24 h soak, real publisher E2E. \
> _(orig)_ In progress — M0–M4 deployable in `rcx-registry-server` binary (Postgres-backed stores, sync + enrichment loops, Vault Transit signer, hickory DNS, GitHub OAuth, ops assets). Hetzner provision + live 24h soak + real publisher E2E + Vault key + schema CDN are the remaining gates.

## Purpose

Build **RCX-Registry v1.0** — a CROWN-receipted, MCP-compatible subregistry of `registry.modelcontextprotocol.io`. The registry mirrors MCP server entries verbatim, enriches each one under a namespaced `_meta` key (`org.rcxprotocol.registry/*`), accepts signed attestations from Passport-holding principals, and republishes the whole thing via the same OpenAPI shape so existing MCP-aware clients consume it without modification.

Deliverables in dependency order:

1. **Schemas locked** — date-pinned `rcx-enrichment.schema.json` and `attestation.schema.json` published at `static.rcxprotocol.org/schemas/<date>/`. CBOR ↔ JSON round-trip golden fixtures pass.
2. **Sync pipeline** — hourly ETL from MCP registry, BLAKE3-rooted `RegistrySnapshot` CROWN receipts, full Postgres mirror, status reconciliation with 30-day soft-delete.
3. **Auto-enrichment** — every mirrored entry gets a default `org.rcxprotocol.registry/auto` block plus `EntryAutoEnriched` receipt.
4. **Publisher rights verification** — GitHub OAuth + DNS TXT flows, `PublisherRightsVerified` receipts, onboarding UI.
5. **Publisher-declared enrichment** — declaration URL discovery via `_meta.org.rcxprotocol.publisher.declaration-uri`, fetch/validate/sign, `EntryEnriched` receipts with supersession.
6. **Attestations** — submit/revoke endpoints, signature verification, evidence pointer validation, `AttestationAccepted` / `AttestationRevoked` receipts, weighting headers.
7. **Extended query API** — RCX-specific filters (`category`, `min_tier`, `affinity`, `min_attestations`, etc.), capability-graph traversal, signed cursors, rate limits.
8. **RCX-Protocol integration** — handshake's capability graph generator pulls `AttestationRef` entries from this registry for inclusion in SessionPlans.
9. **Observability + hardening** — Prometheus metrics, Grafana dashboard, load test (100 req/s sustained, 1k req/s burst), chaos test (MCP down, Postgres down, Vault Transit down).
10. **Public launch** — docs at `rcxprotocol.org/spec/rcx-registry/v1.0/`, Substack article, live `registry.rcxprotocol.org` + `static.rcxprotocol.org`, source open at this repo.

**Total budget:** ~9 engineering-weeks per master plan §12.1.

## Non-goals

- Not competing with or replacing MCP registry. RCX-Registry is a lens, never canonical for server identity.
- Not redefining CROWN signing primitives — inherited from CROWN Receipt Family v1.0 (or held in-repo and refactored when CROWN ships).
- Not redefining the capability graph schema — owned by RCX-Protocol §5.
- Not minting new server names. The MCP `name` field is authoritative.
- No paid listings, no promoted entries, no advertising surface.
- No publisher dispute adjudication. Server-name ownership disputes are MCP's to resolve.
- Not implementing v1.1 reserved features (cross-subregistry federation §13.1, third-party revocation §13.2, trust-issuer registry §13.3, real-time push §13.4, payment escrow §13.5, per-query affinity disclosure §13.6, AAIF donation protocol §13.7).
- Not building a rich human UI. v1.0 ships only the minimal `Accept: text/html` response on `GET /v0/servers` (§9.4).
- Not horizontally scaling. Single Hetzner CCX13 footprint sufficient for ~10k servers / ~1 req/s baseline (§3.3).

## Context (files / systems involved)

This repo (`RCX-Registry/`) is greenfield. Crate / package layout per master plan §3.2:

| Path | Crate / Package | Role |
|---|---|---|
| `crates/rcx-registry-ingest/` | `rcx-registry-ingest` | MCP ETL, scrape scheduler, snapshot Merkle root, `RegistrySnapshot` minting |
| `crates/rcx-registry-enrich/` | `rcx-registry-enrich` | Auto-enrichment + publisher declaration fetch/validate/sign |
| `crates/rcx-registry-attest/` | `rcx-registry-attest` | Attestation accept, signature verification, supersession + revocation |
| `crates/rcx-registry-crown/` | `rcx-registry-crown` | CROWN receipt minting (5 event types from §7.1); thin wrapper over CROWN Receipt Family or in-repo primitives until that ships |
| `crates/rcx-registry-api/` | `rcx-registry-api` | OpenAPI surface (MCP-compatible baseline + RCX extensions §8) |
| `crates/rcx-registry-admin/` | `rcx-registry-admin` | Internal moderation, publisher onboarding, issuer management |
| `migrations/` | SQL | Postgres schema for `mcp_servers`, `rcx_enrichment`, `attestations`, `snapshots`, `publisher_rights` (§4.3) |
| `schemas/` | dated JSON Schema | `rcx-enrichment.schema.json`, `attestation.schema.json` — published to `static.rcxprotocol.org/schemas/<date>/` |
| `ops/` | infra | Caddy site config, Prometheus scrape, Grafana dashboard, Tailscale ACL snippet |
| `docs/` | markdown | User-facing spec mirror, OpenAPI YAML, publisher onboarding guide |

External systems touched:

| System | Path / URL | Touchpoint |
|---|---|---|
| MCP registry (upstream) | `registry.modelcontextprotocol.io/v0/servers` | Pull only |
| CoreCrux segment log | [Crux/crates/corecrux-projections/src/events.rs](../../../Crux/crates/corecrux-projections/src/events.rs) | Add `.ccxreg` lane + 5 new event types (§7.1) |
| VaultCrux Passport service | [VaultCrux/apps/api/src/](../../../VaultCrux/apps/api/src/) | Resolve `principal_id` → public key for attestation verification |
| Vault Transit | `https://100.76.91.69:8200` (via [InfraCrux/tools/vault-proxy](../../../InfraCrux/tools/vault-proxy/proxy.py)) | ed25519 signer for receipt minting |
| RCX-Protocol crate | [Crux/crates/crux-session/src/graph.rs](../../../Crux/crates/crux-session/src/graph.rs) (→ `rcx-protocol/graph.rs`) | Capability graph schema source for publisher declarations |
| Postgres | CueCrux-Data-1 (Tailscale `100.75.64.43:5432` or new colocated DB) | Durable storage |
| Redis | new colocated instance | Query cache |

## Constraints

- **MCP-compatible surface (hard).** Every existing MCP registry client must consume `registry.rcxprotocol.org/v0/servers` by changing only the base URL — no field renames, no shape divergence, no required new headers (§1 G1, §9.2). Schema enforced by golden contract test against the official MCP OpenAPI spec.
- **Namespaced enrichment only.** All RCX data sits under `_meta.org.rcxprotocol.registry/*` or `_meta.org.rcxprotocol.publisher/*`. Never modifies upstream `name`, `description`, `version`, `packages`, or `_meta.io.modelcontextprotocol.registry/official` (§14.4).
- **MCP moderation parity.** If MCP marks an entry `deleted`, RCX-Registry mirrors that status. Additional moderation may be added but never overrides MCP (§1 G7).
- **Receipt-log primary, projections rebuildable.** Live tables are projections over the CROWN receipt log. A Postgres wipe is recoverable in hours by replaying the log (§7.2).
- **Append-only receipts.** No update or delete on receipt-log rows. Same invariant as CueCrux migration 0065.
- **CROWN canonicalisation byte-identical to RCX-Protocol's.** Same CBOR canonicalisation, same JCS JSON, same BLAKE3 zeroed-field hashing, same ed25519 via Vault Transit. Round-trip golden tests cross-check against RCX-Protocol fixtures at M0.
- **Schema URLs date-pinned and immutable.** `static.rcxprotocol.org/schemas/<YYYY-MM-DD>/<name>.schema.json` is forever-stable once published. v1.1 additions ship at a new date URL (§2.4).
- **Status reconciliation soft-deletes for 30 days.** Upstream-deleted entries remain queryable with `deleted_upstream` flag for 30 days before full eviction; receipt log retains the full history (§4.4).
- **Publisher rights verification conservative.** GitHub-named entries require GitHub OAuth control of the owner account; reverse-DNS names require `_rcx-registry.<domain>` TXT record; anonymous namespaces accepted but flagged `rights_unverified: true` (§5.3).
- **Attestation weighting consumer-side.** Registry never computes a single trust score — it surfaces issuer tier, affinity match, type, evidence verification status, and lets clients weight (§6.6).
- **Revocation by issuer only.** v1.0 disallows third-party revocation. Counter-attestations are the only way to contradict (§6.7, §13.2 deferred).
- **Rate limits enforced via token bucket.** Public reads 60/min per IP, 10k/hr per Passport. Attestations 10/hr per Passport. Publisher declarations 100/hr per publisher Passport (§8.6).
- **CBOR primary, JSON mirror.** Both content types semantically identical per CROWN canonicalisation. Default `Accept: application/cbor`; JSON on `Accept: application/json` (§8.4).
- **Signed cursors.** ed25519-signed pagination cursors; tampered cursors return `400 invalid_cursor` (§8.5).
- **Feature flags must roll back instantly.** Master `FEATURE_RCX_REGISTRY` off → all RCX-specific endpoints return `503 feature_disabled`; MCP-mirror baseline keeps serving (§12.3).
- **Chainguard base images** for all Dockerfiles per [CueCrux/CLAUDE.md §9](../../../CLAUDE.md). Map: `cgr.dev/chainguard/wolfi-base:latest` for Rust runtime, `cgr.dev/chainguard/postgres:latest` for the DB if colocated.
- **Single Hetzner CCX13 footprint for v1.0.** Postgres + Redis + API colocated. Caddy for TLS. Tailscale for admin access. Horizontal scale deferred until >100 req/s sustained (§3.3).
- **Single-domain rollout.** All public RCX-Registry surfaces live under the `rcxprotocol.org` domain family from day one: API at `registry.rcxprotocol.org`, schema CDN at `static.rcxprotocol.org`, docs/onboarding at `rcxprotocol.org`. No `cuecrux.com` launch alias or later cutover remains in scope.

## PlanCrux Notes

PlanCrux summary captured 2026-04-20 from `PlanCrux/README.md` (`README.version`: `v1.2S`; `README.mtime`: `2026-04-13 00:29:14 +0100`).

- PlanCrux is the canonical CueCrux delivery handbook; start orientation from `buildguide.md`.
- Follow `docs/handbook/process/codex-standard-dev-cycle.md` for the standard implementation loop.
- Keep repo reference logs aligned with the helper commands (`pnpm log:command`, `log:request`, `log:outcome`, `log:verify`) rather than hand-editing logs.
- Update `docs/master-plan/progress-tracker.md` and mark completed roadmap items when milestones land.
- Capture dependency and tooling changes in `docs/reference/dependency-log.md`.
- Register service ports in `docs/reference/infrastructure/Port-Registry.md` before introducing or moving services.
- For CoreCrux dataplane or `/v1/query/answer` work, validate in a GPU-side sidecar first and record the runtime envelope in the ExecPlan.
- Start long-running local services with `pnpm svc:start` and gate on `/healthz`; avoid ad-hoc backgrounding from one-shot shells.
- Run `pnpm -s exec bash scripts/guard-readme-policy.sh` before launching services to catch the known-bad backgrounding pattern.
- Keep docs tightly scoped with relative links and run `pnpm lint` before commits so markdown/reference guards stay green.

Before milestone kickoff, query (PlanCrux API on :3334):

```
GET /capabilities/analysis/gaps?system=rcx-registry          # likely empty — new system
GET /capabilities/analysis/gaps?system=vaultcrux             # Passport / signer touchpoints
GET /capabilities/analysis/gaps?system=corecrux              # segment-log touchpoints
GET /capabilities/analysis/promises?q=registry
GET /capabilities/analysis/promises?q=attestation
GET /capabilities/analysis/promises?q=mcp
GET /capabilities/analysis/coverage?system=vaultcrux
```

Paste **critical/high** gaps here at kickoff; record gap closures in Decision Log as milestones land. After M9 launch, register a new `rcx-registry` system in the Feature Registry and audit each delivered capability via `POST /capabilities/:id/audit`.

### Related existing work

- **RCX-Protocol v2 ExecPlan:** [vaultcrux-rcx-protocol-v2-2026-04-19.md](../../../PlanCrux/.agent/execplans/vaultcrux-rcx-protocol-v2-2026-04-19.md) — defines capability graph schema (§5) and `AttestationRef` shape that this registry must accept and serve.
- **Session Handshake v1.0 SHIP-REPORT:** [vaultcrux-session-handshake-SHIP-REPORT.md](../../../PlanCrux/.agent/execplans/vaultcrux-session-handshake-SHIP-REPORT.md) — proves CBOR/JSON canonicalisation, Vault Transit signer, segment-event pattern are all production-stable. Reuse byte-for-byte.
- **CROWN Receipt schema tightening:** [crown-receipt-schema-tightening-v2.md](../../../PlanCrux/.agent/execplans/crown-receipt-schema-tightening-v2.md) — coordinate signing primitives if CROWN Receipt Family v1.0 ships before this plan completes.

### Master-plan references

- **This implements:** RCX-Registry v1.0 (master plan v1.0).
- **Depends on:** RCX-Protocol v1.0 capability graph schema (Phase 4 / M4 hard dep), CROWN Receipt Family primitives (M0 dep — held in-repo if CROWN unshipped).
- **Extends:** [CoreCrux-Master-Plan-v8_0.md](../../../PlanCrux/docs/master-plan/CoreCrux-Master-Plan-v8_0.md) by adding the `.ccxreg` segment lane and 5 new event types.
- **Sibling of:** RCX-Protocol v1.0, CROWN Receipt Family v1.0, CE↔Core Migration Protocol (RCX-Protocol §9).

## Proposed design / approach

### High-level architecture

Three-layer relationship per master plan §3.1:

```
MCP Registry  ──hourly ETL──▶  RCX-Registry  ──OpenAPI──▶  Consumers
(canonical)                    (this repo)                  (RCX-Protocol, MCP clients,
                                                            downstream subregistries)
```

The registry is essentially three loops plus one HTTP surface, all writing to a CROWN-signed append-only event log. Live Postgres tables are projections over that log.

### Three loops

1. **Sync loop** (M1) — hourly: scrape MCP, diff against last snapshot, mint `RegistrySnapshot`, reconcile statuses, mint `EntryAutoEnriched` for new entries.
2. **Enrichment loop** (M4) — 24h cadence per publisher (configurable down via `_meta.org.rcxprotocol.publisher.refresh_interval_seconds`): refetch declaration URLs, validate, sign, mint `EntryEnriched` if hash changed.
3. **Verification loop** (M5 background) — async evidence-pointer fetch + BLAKE3 hash check on accepted attestations, annotate stored record with verification status.

### One HTTP surface

- **Baseline `/v0/servers`** mirrors MCP shape exactly (M1 stub, M2 with auto-enrichment, M4 with publisher enrichment surfaced, M5 with attestation counts surfaced).
- **RCX-specific filters and endpoints** (M6) layer on top.
- **Submission endpoints** for attestations (M5) and publisher declarations (M4).

### Storage model (§4.3)

Five tables: `mcp_servers`, `rcx_enrichment`, `attestations`, `snapshots`, `publisher_rights`. All five are projections rebuildable from the receipt log.

### Receipt log integration

New CoreCrux segment lane `.ccxreg` (M1 introduces, all milestones add events). Five event types per §7.1: `RegistrySnapshot`, `EntryAutoEnriched`, `EntryEnriched`, `AttestationAccepted`, `AttestationRevoked`, `PublisherRightsVerified`. (Master plan lists six in §7.1 — counting `EntryAutoEnriched` and `EntryEnriched` separately.)

### Signing

ed25519 via Vault Transit (key `vault:transit:rcx-registry-signing-key-1`, provisioned at M0). Same canonical-CBOR-with-zeroed-fields hashing as RCX-Protocol receipts. Key rotation follows CROWN Receipt Family rules; old `signer_kid` retained in receipts for verifiability.

### Failure modes (§4.2, §10.3)

- MCP unreachable → serve from last-good snapshot, alert, retry next cadence.
- Single page parse failure → log, skip entry, continue scrape.
- Schema validation failure on one entry → log, skip, continue.
- Vault Transit unreachable → halt new minting (writes block), reads continue from cache.
- Publisher declaration URL unreachable → keep prior verified enrichment, alert publisher, retry on next refresh tick.
- Postgres down → reads from Redis cache for short outages; writes block, queue in memory only briefly.

### Domain rollout (§3.4, §16 Q8)

Launch directly on the `rcxprotocol.org` domain family: API at `registry.rcxprotocol.org`, schemas at `static.rcxprotocol.org`, docs at `rcxprotocol.org`. No parallel `cuecrux.com` serving period or canonical cutover is planned.

## Milestones

Maps 1:1 to master plan §12.1 phases. Each milestone has a gate that matches the master plan's; below adds concrete sub-tasks.

### M0 — Schema lock & repo skeleton (~0.5 wk)

**Master plan gate:** schemas validate, fixtures pass, CROWN canonicalisation identical to RCX-Protocol's.

- Initialise Cargo workspace + pnpm scaffold; add `rust-toolchain.toml`, `.editorconfig`, root `Cargo.toml`, `package.json`, `tsconfig.json`, `.gitignore`, `LICENSE` (Apache-2.0 to match foundation-track readiness §1 G8), `README.md` placeholder.
- Author `schemas/2026-04-19/rcx-enrichment.schema.json` matching the example in master plan §5.2 + §18 Step 3.
- Author `schemas/2026-04-19/attestation.schema.json` matching §6.1 + §6.3 (four type-specific structured-claim shapes).
- Stand up `crates/rcx-registry-crown/` — thin wrapper over (or in-repo copy of) CROWN canonical-CBOR + JCS JSON + BLAKE3 + ed25519 verify. Cross-check fixtures against RCX-Protocol's golden fixtures byte-for-byte.
- Provision Vault Transit key `rcx-registry-signing-key-1`; document KID convention.
- Publish schemas to `static.rcxprotocol.org/schemas/2026-04-19/` (CDN deploy); record receipt of publication in commit message.
- CI: schema validation, CBOR↔JSON round-trip golden tests, BLAKE3 zeroed-field hash test.

### M1 — Sync pipeline (~1.5 wk)

**Master plan gate:** 24-hour continuous operation with zero sync failures against live MCP registry.

- Postgres migrations: `0001_mcp_servers.sql`, `0002_snapshots.sql` (per §4.3 columns).
- `crates/rcx-registry-ingest/`:
  - HTTP client with pagination (`?limit=100&cursor=…`), retry-with-backoff, ETag handling.
  - Per-entry MCP `server.schema.json` validation against the date in each entry's `$schema`.
  - BLAKE3 Merkle root computation over canonical lex-sorted entries.
  - Staging-then-swap pattern; status reconciliation per §4.4 (added / removed / unchanged / modified).
  - Burst-detection trigger (>50 changes → 15-min follow-up); 10-min hard floor between scrapes.
  - Stub for the `updated_at` delta-filter path (MCP issue #291) — flag-gated.
- `crates/rcx-registry-crown/`: implement `RegistrySnapshot` minting (§7.1).
- CoreCrux integration: register `.ccxreg` segment lane; mint receipts via Tailscale to HEL1 CoreCrux host.
- `crates/rcx-registry-api/`: stub `GET /v0/servers` and `GET /v0/servers/{name}` returning live mirror only (no enrichment yet).
- 30-day soft-delete reconciler.
- Observability: scrape duration histogram, `rcx_registry_mcp_servers_mirrored` gauge, `rcx_registry_mcp_fetch_errors_total` counter (subset of §11.1).
- 24-hour soak test against `registry.modelcontextprotocol.io`.

### M2 — Auto-enrichment (~0.5 wk)

**Master plan gate:** every mirrored server has an enrichment row; receipt count matches server count.

- Migration: `0003_rcx_enrichment.sql`.
- `crates/rcx-registry-enrich/auto.rs`: emit baseline `org.rcxprotocol.registry/auto` block per §5.1 (defaults: `category: "public"`, `capability_graph: null`, `attestations_count: 0`).
- Mint `EntryAutoEnriched` receipt per new entry.
- Surface auto-enrichment block in `GET /v0/servers` responses (under `_meta`).
- Integrity invariant test: `count(mcp_servers) == count(rcx_enrichment)` on every sync.

### M3 — Publisher rights verification (~1 wk)

**Master plan gate:** three test publishers verify rights end-to-end via all three methods.

- Migration: `0004_publisher_rights.sql`.
- GitHub OAuth flow:
  - OAuth app registration + client_id/secret in Vault.
  - Web flow: authorise → callback → resolve `<owner>` → mint `PublisherRightsVerified` receipt for namespace `io.github.<owner>`.
- DNS TXT verification:
  - `_rcx-registry.<domain>` TXT record contains Passport key fingerprint.
  - DNS resolver with negative caching; manual re-check endpoint.
  - Mint `PublisherRightsVerified` for namespace `io.<domain>`.
- Manual / admin path for edge cases (logged with reviewer Passport).
- Anonymous namespaces (`io.modelcontextprotocol.anonymous/*`) accepted but flagged `rights_unverified: true`.
- Onboarding UI: minimal HTML at `rcxprotocol.org/spec/rcx-registry/publish` (or `registry.rcxprotocol.org/publish`).
- Three end-to-end test publishers (one GitHub, one DNS, one anonymous).

### M4 — Publisher-declared enrichment (~1 wk)

**Master plan gate:** one real publisher (CueCrux network — Brian Green / Violeta Klein / Shane Grech as candidates) publishes a capability-graph declaration and sees it reflected in query responses.

> **Hard dep:** RCX-Protocol §5 capability graph schema must be stable. Coordinate with [vaultcrux-rcx-protocol-v2-2026-04-19.md](../../../PlanCrux/.agent/execplans/vaultcrux-rcx-protocol-v2-2026-04-19.md) M1 (golden re-lock) before starting.

- Discovery: parse `_meta.org.rcxprotocol.publisher.declaration-uri` from MCP entries during sync.
- Declaration fetcher: HTTP GET, BLAKE3 of canonical bytes → `declared_hash`.
- Validation pipeline:
  1. JSON Schema validate against declared `$schema`.
  2. `mcp_name` matches MCP entry `name`.
  3. `publisher_passport` has rights over namespace (lookup from M3).
  4. Capability graph nodes/edges valid per RCX-Protocol §5.
- Mint `EntryEnriched` receipt; supersede prior enrichment for that server (prior receipt retained in log).
- 24h refresh cadence; per-publisher override via `refresh_interval_seconds`.
- `POST /v0/publishers/declare` — Option B path (signed payload submission for publishers who can't modify server.json).
- Surface publisher enrichment block in `GET /v0/servers` under `_meta.org.rcxprotocol.registry/publisher`.
- E2E test: one CueCrux-network publisher publishes a real declaration, sees it surface within 1 sync cycle.

### M5 — Attestations (~2 wk)

**Master plan gate:** at least one attestation of each type (`publisher`, `reviewer`, `auditor`, `operator`) accepted; supersession + revocation flows exercised end-to-end.

- Migration: `0005_attestations.sql`.
- `crates/rcx-registry-attest/`:
  - Parse signed Attestation CBOR / JSON.
  - Verify ed25519 signature using `issuer_public_key` resolved from VaultCrux Passport service.
  - Recompute `attestation_hash` with sig + `signer_kid` zeroed; verify match.
  - Verify `server_name` exists in mirror.
  - Async evidence-pointer fetch + BLAKE3 verify (background worker; annotate record).
  - Issuer affinity match check; emit `issuer_affinity_match` flag (no blocking).
- Endpoints:
  - `POST /v0/attestations` — submit (returns `201 Created` + ULID).
  - `POST /v0/attestations/{id}/revoke` — issuer-only, signed payload.
  - `GET /v0/attestations?server=…&type=…&issuer=…` — list.
  - `GET /v0/attestations/{id}` — fetch.
- Supersession via `claim.structured.supersedes: <prior_id>` — prior marked `superseded`, both retained.
- Mint `AttestationAccepted` and `AttestationRevoked` receipts.
- Update `org.rcxprotocol.registry/attestations` block on the mirrored server entry (`count`, `by_type`, `latest_hash`).
- Rate limit: 10/hr submissions per Passport.
- One real attestation per type submitted for soak.

### M6 — Extended query API (~1 wk)

**Master plan gate:** all RCX-specific query parameters compose correctly; rate limits enforced; cursor tampering detected.

- All §8.2 query parameters: `category`, `min_tier`, `affinity`, `has_capability_graph`, `min_attestations`, `attestation_types`, `attestation_issuers`, `enriched_since`, `exclude_unverified_rights`. All composable.
- Endpoints from §8.3 not yet built:
  - `GET /v0/snapshots`, `GET /v0/snapshots/{id}`, `GET /v0/snapshots/latest`.
  - `GET /v0/capability-graphs/{server_name}` + `/edges?from=<cap>` traversal.
  - `GET /v0/publishers/{passport_id}` — list rights-verified namespaces.
  - `GET /v0/receipts/{hash}` — fetch any CROWN receipt by hash (canonical CBOR + signature).
- Signed cursors (ed25519); tampered → `400 invalid_cursor`.
- Token-bucket rate limiter: 60 req/min per IP, 10k/hr per Passport, 100/hr publisher declarations, 10/hr attestations. Burst window: 10× base for 30s.
- Response headers: `X-RCX-Snapshot-Id`, `X-RCX-Snapshot-Hash`, `X-RCX-Served-From`, `X-RCX-Upstream-Registry: registry.modelcontextprotocol.io`, `Retry-After`, `X-RateLimit-Remaining`.
- Content negotiation: CBOR default, JSON on `Accept: application/json`.
- OpenAPI YAML published at `registry.rcxprotocol.org/openapi.yaml`.

### M7 — RCX-Protocol integration (~0.5 wk)

**Master plan gate:** end-to-end — handshake issues a SessionPlan with `AttestationRef`s, agent fetches the attestation, verifies signature, confirms issuer Passport.

> **Hard dep:** RCX-Protocol v2 M6 (attestation-ref field accepting unpopulated values) must be in place. This milestone flips it from unpopulated to populated.

- VaultCrux session handshake (RCX-Protocol §5.6) extension:
  - For each capability in the generated graph, query `GET /v0/attestations?server=<server>&type=auditor&min_issuer_tier=pro`.
  - Top N (issuer tier × recency) → `AttestationRef { issuer, type, hash, uri }`.
- Agent-side verification path: fetch attestation by hash from `GET /v0/receipts/{hash}` or `GET /v0/attestations/{id}`, verify ed25519 signature, walk to issuer Passport.
- E2E happy-path test: handshake → SessionPlan with refs → agent verify → invoke.

### M8 — Observability + hardening (~1 wk)

**Master plan gate:** all metrics emit, dashboard renders, load test passes (100 req/s sustained, 1k req/s burst), failure modes degrade gracefully.

- All §11.1 Prometheus metrics complete (gaps from M1's subset filled in).
- Grafana dashboard JSON in `ops/monitoring/grafana/dashboards/rcx-registry.json` per §11.2 panel list.
- Structured-log pass: every snapshot, enrichment, attestation, revocation logs receipt hashes; no request bodies.
- Load test: `k6` script for 100 req/s sustained × 1h, 1k req/s burst × 60s. Cap p95 < 250 ms baseline, < 500 ms burst.
- Chaos drills:
  - MCP registry unreachable for 1h → serve from cache, alert, recover.
  - Postgres down for 5 min → reads from Redis, writes block then drain.
  - Vault Transit unreachable for 1 min → minting halts, reads continue.
- Backup / restore: log replay rebuilds projections from scratch in <2h for 10k servers.
- Security pass: rate-limit fuzzing, cursor tampering, signature verification fuzz inputs, SQL injection check on query parameters.
- Alertmanager rules: snapshot age > 2h, fetch error rate > 5%, Vault Transit signing latency > 1s p95, receipt log lag > 10 min.

### M9 — Public launch (~0.5 wk)

**Master plan gate:** Substack article published; external publisher onboards to production and sees enrichment flow end-to-end.

- DNS: register and serve `registry.rcxprotocol.org` plus `static.rcxprotocol.org` as the only public launch domains.
- TLS: Caddy ACME on the `rcxprotocol.org` subdomains in use.
- Docs: publish full spec at `rcxprotocol.org/spec/rcx-registry/v1.0/`.
- Open-source the repo at `github.com/CueCrux/RCX-Registry` (this repo). Apache-2.0 LICENSE, CONTRIBUTING.md, code of conduct, governance note (foundation-track readiness §1 G8).
- Substack article: "A receipted lens over the MCP registry: provenance for agentic discovery."
- External publisher onboarding test: at least one publisher outside CueCrux network completes the publish flow.

## Test plan

### Unit / property

- Schema validation: golden fixtures for valid + invalid enrichment + attestation documents (M0).
- CBOR↔JSON round-trip: 1000 random fixtures, byte-equality after canonicalisation (M0).
- BLAKE3 zeroed-field hash: matches RCX-Protocol fixtures (M0).
- Snapshot Merkle root: deterministic given lex-sorted entries (M1).
- Status reconciliation: synthesised diff fixtures cover all 4 cases (added / removed / unchanged / modified) (M1).
- Auto-enrichment defaults: every mirrored entry produces an enrichment row (M2).
- Publisher rights verification: GitHub OAuth happy + denied path; DNS TXT match + mismatch + missing record (M3).
- Declaration validation: schema-failures, namespace-mismatch, rights-not-verified, capability-graph-malformed each rejected with structured error (M4).
- Attestation signature verify: tampered signature, tampered body, wrong issuer key, expired `valid_until`, all rejected (M5).
- Supersession: prior marked `superseded`, new active, both queryable with `include_superseded=true` (M5).
- Revocation: only original issuer can revoke; third-party revocation rejected (M5).
- Cursor tampering: sign + verify; flipped bit → `400 invalid_cursor` (M6).
- Rate limiter: token bucket honours burst window; `Retry-After` populated (M6).

### Integration

- 24-hour MCP scrape soak (M1) — zero sync failures, snapshot count matches expected cadence.
- End-to-end publisher declaration: post → fetch → validate → sign → query response surfaces it (M4).
- End-to-end attestation: submit → verify → receipt → query → revoke → query again excludes (M5).
- RCX-Protocol handshake → SessionPlan with `AttestationRef` → agent fetch + verify (M7).
- Log replay: wipe Postgres, replay receipt log, projections byte-identical (M8).

### Contract

- Golden contract test against MCP registry's published OpenAPI spec — `GET /v0/servers` shape matches at every milestone (M1 onwards).
- MCP-only client (e.g., reference impl from `github.com/modelcontextprotocol/registry`) consumes RCX-Registry without code changes (M9 acceptance).

### Load / chaos

- 100 req/s sustained × 1h, p95 < 250 ms (M8).
- 1k req/s burst × 60s, no OOM, no receipt-log corruption (M8).
- MCP unreachable 1h → cache serves, alert fires, recovery clean (M8).
- Postgres down 5 min → degraded mode, no log corruption on recovery (M8).
- Vault Transit down 1 min → minting halts, reads continue, no partial receipts (M8).

### Security

- Rate-limit fuzz: per-IP, per-Passport, per-endpoint (M8).
- Signature fuzz: malformed CBOR, oversized payloads, embedded-NUL, key-confusion (M8).
- SQL injection: query-parameter fuzz on all extended filters (M8).
- Cursor signing: brute-force attempts on cursor MAC (M8).

## Rollout / rollback

### Rollout

- M0–M2 ship to `staging.registry.rcxprotocol.org` only. Master flag `FEATURE_RCX_REGISTRY=false` in production-equivalent env.
- M3–M5 stay staging-only; selected CueCrux-network publishers exercise the publish flow.
- M6 ships to staging; load tests run there.
- M7 — flip `FEATURE_RCX_V2_GRAPH` (RCX-Protocol) and `FEATURE_RCX_REGISTRY_PROTOCOL_INTEGRATION` together in staging only; verify SessionPlan refs round-trip end-to-end.
- M8 — production-equivalent infra (CCX13 in HEL1), continuous metrics + alert validation, 24h burn-in.
- M9 — `registry.rcxprotocol.org` goes live with `FEATURE_RCX_REGISTRY=true`; `static.rcxprotocol.org` serves the dated schemas; docs/onboarding routes under `rcxprotocol.org` are live at the same launch gate.

### Rollback per feature flag

- `FEATURE_RCX_REGISTRY=false` → all RCX-specific endpoints return `503 feature_disabled`. MCP-mirror baseline keeps serving.
- `FEATURE_RCX_REGISTRY_PUBLISHER_DECLARATIONS=false` → declaration fetcher idle; publisher-enriched entries fall back to auto-enrichment in responses; receipt log untouched.
- `FEATURE_RCX_REGISTRY_ATTESTATIONS=false` → submission endpoints return `503`; existing attestations remain queryable.
- `FEATURE_RCX_REGISTRY_PROTOCOL_INTEGRATION=false` → SessionPlans emit no `AttestationRef` entries (capability nodes still valid; field stays unpopulated as in v1.0).
- `FEATURE_RCX_REGISTRY_SIGNED_CURSORS=false` → cursors emit unsigned (compat fallback for the unlikely case of cursor-signing key compromise).

### Data rollback

- Append-only receipt log means there is no destructive rollback. A bad release that wrote bad receipts requires a code fix and forward repair (e.g., emit corrective receipts), never a log truncation.
- Postgres projection corruption: drop projection tables, replay receipt log. Tested at M8.

## Risks & mitigations

| # | Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|---|
| R1 | RCX-Protocol §5 capability graph schema changes after M4 | M | H | Schema is locked at RCX-Protocol v2 M1. M4 starts only after that lock; coordinate via [vaultcrux-rcx-protocol-v2-2026-04-19.md](../../../PlanCrux/.agent/execplans/vaultcrux-rcx-protocol-v2-2026-04-19.md) Decision Log. |
| R2 | MCP registry deprecates `/v0/servers` shape mid-build | L | H | Open question §16 Q7. Keep ETL versioned, contract test against MCP OpenAPI on every CI run, watch upstream issue tracker. |
| R3 | CROWN Receipt Family v1.0 ships after M0 with diverging primitives | M | M | Hold primitives in `crates/rcx-registry-crown/` until CROWN ships; refactor when stable. Cross-check fixtures against RCX-Protocol's at every CI run to catch divergence early. |
| R4 | Publisher rights verification spoofed (e.g., DNS poisoning, GitHub takeover) | L | H | Multi-source verification where possible. Rights checks re-run on cadence (24h). Suspicious changes flagged in admin dashboard. Open question §16 Q5 on publisher de-verification — partial answer via Passport revocation. |
| R5 | Attestation flooding from low-tier Passports | M | M | Weighting is tier-based, not count-based (§6.6, §10.3). Submission rate-limit 10/hr per Passport. Auditor attestations carry conventionally higher weight; consumer-side filter trivial. |
| R6 | Vault Transit signer outage halts new minting | L | M | Reads continue from cache. Alert on signing latency > 1s p95. Document recovery as an ops runbook in M8. |
| R7 | Receipt log size growth exceeds estimates | L | L | §7.3 budget is < 50 MB year one. LZ4 compression brings cold tier to ~15 MB. Trivial at v1.0 scale. Monitor `rcx_registry_receipt_log_bytes` gauge. |
| R8 | `rcxprotocol.org` DNS / TLS provisioning fault delays launch | M | M | Provision `registry.rcxprotocol.org` and `static.rcxprotocol.org` before launch week, lower TTLs ahead of cut, validate ACME issuance in staging, and keep a preflight checklist for the domain family. |
| R9 | Publisher declaration URL serves different content over time | M | L | `declared_hash` is published in receipts; mismatches trigger alerts and revert to prior verified enrichment. (§10.3 "Declaration tampering at fetch time".) |
| R10 | First external publisher unable to onboard at M9 acceptance | L | M | Three CueCrux-network publishers tested in M4 cover the failure modes. M9 onboarding kit (docs + sample server.json + example declaration) reduces friction. |
| R11 | MCP-aware client breaks when seeing `_meta.org.rcxprotocol.*` | L | H | Master plan §1 G1 hard requirement. Reference MCP client tested in M9. JSON Schema for `_meta` is open-ended in MCP per design. |
| R12 | Single CCX13 footprint insufficient | L | L | §3.3: 100 req/s threshold for horizontal scale, deferred. Monitor `rcx_registry_query_latency_seconds` p95; horizontal-scale plan documented but not built. |
| R13 | Foundation-track misalignment (AAIF donation) | L | M | §13.7 deferred to v1.1, but architecture choices in M0 (Apache-2.0, namespaced `_meta`, no MCP override, schema URL portability) are foundation-compatible from day one. |

## Progress (keep updated)

- [ ] M0 — Schema lock & repo skeleton (workspace, schemas, canonicalisation crate, fixtures, CI, and local tests landed; `static.rcxprotocol.org` publication + Vault Transit key provisioning still pending)
- [ ] M1 — Sync pipeline (24h soak gate; storage migrations, upstream page models/client hooks, schema-catalog validation interface, cadence/soft-delete logic, snapshot-receipt planning, MCP baseline API stubs, **and `rcx-registry-server` Postgres-backed scrape loop driving the cadence + soft-delete + snapshot mint with real Vault Transit signer wiring** are landed; **24h soak RUNNING since 2026-07-19** after fix PRs #2 (legacy schema-URI + per-envelope skip) and #4 (HTTP client timeouts); gate closes on a clean 24h)
- [ ] M2 — Auto-enrichment (parity invariant gate; migration, auto-enrichment payload/block helpers, receipt planning, `_meta` surfacing, and parity tests landed; full sync-loop emit-on-new-row plumbing is the remaining gap)
- [ ] M3 — Publisher rights verification (3 test publishers gate; namespace classification, GitHub-passport matching, DNS TXT challenge helpers, migration, onboarding HTML, DNS/manual verification routes, GitHub start/callback contracts, publisher-rights listing surface, **a real `hickory-resolver` DNS TXT impl, and a real `reqwest`-backed GitHub OAuth provider impl** are landed; outstanding: live GitHub OAuth app credentials, real publisher E2E, manual-review workflow)
- [ ] M4 — Publisher-declared enrichment (1 real publisher gate; declaration schema validation, discovery metadata parsing, declaration hashing/fetch helpers, `EntryEnriched` receipt planning, `POST /v0/publishers/declare`, supersession, `_meta.org.rcxprotocol.registry/publisher` response surfacing, **and the 24h refresh loop iterating mirrored rows + signing each `EntryEnriched` receipt via Vault Transit** are landed; outstanding: real publisher E2E on live infra)
- [ ] M5 — Attestations (4 types + supersede + revoke gate)
- [ ] M6 — Extended query API (composable filters + cursor tamper gate)
- [ ] M7 — RCX-Protocol integration (E2E AttestationRef gate)
- [ ] M8 — Observability + hardening (load + chaos gate; **`/metrics`, `/healthz`, `/readyz` plus the 11-series Prometheus exporter, alert rules at `ops/prometheus/rules/rcx-registry.rules.yml`, Grafana dashboard at `ops/grafana/dashboards/rcx-registry.json`, Caddy + Tailscale operator configs** landed; outstanding: load + chaos drills against the deployed host)
- [ ] M9 — Public launch (Substack + external publisher gate)

## Decision log (keep updated)

- **2026-04-19** — ExecPlan drafted from RCX-Registry-Master-Plan-v1_0.md. Mapped 10 phases (Phase 0–9) to milestones M0–M9 1:1. Created in `RCX-Registry/.agent/execplans/` (not `PlanCrux/.agent/execplans/`) per user direction "in this repo".
- **2026-04-19** — Repo skeleton: Cargo workspace + 6 crates per master plan §3.2. Apache-2.0 license chosen for foundation-track readiness (§1 G8).
- **2026-04-19** — Schema URL strategy: stay on `static.rcxprotocol.org/schemas/<date>/` forever-stable; date-pinned and immutable once published.
- **2026-04-19** — Domain rollout: all public RCX-Registry surfaces launch directly under the `rcxprotocol.org` domain family with no interim `cuecrux.com` alias.
- **2026-04-19** — CROWN signing primitives: hold in `crates/rcx-registry-crown/` until CROWN Receipt Family v1.0 ships; refactor then. Cross-check fixtures against RCX-Protocol's golden set every CI run.
- **2026-04-19** — Hard dep on RCX-Protocol v2 M1 (capability-graph schema lock) before this plan's M4 starts. Hard dep on RCX-Protocol v2 M6 (`AttestationRef` field accepting unpopulated values) before this plan's M7. Coordinate via sibling ExecPlan Decision Log.
- **2026-04-20** — Execution approved. Recorded cached `PlanCrux Notes` from `PlanCrux/README.md` v1.2 into this ExecPlan before implementation began, per repo `AGENTS.md`.
- **2026-04-20** — M0 local scaffold landed in `RCX-Registry/`: Cargo workspace, six crates, root metadata, dated schemas under `schemas/2026-04-19/`, example fixtures, and a GitHub Actions CI workflow that runs `cargo fmt --all --check` and `cargo test --workspace`.
- **2026-04-20** — `crates/rcx-registry-crown/` now carries the generic canonical-CBOR/JCS mirror, BLAKE3 zeroed-field hashing, ed25519 verification, and RCX receipt event structs. Added a regression test that round-trips the sibling RCX-Protocol golden fixtures from `CueCrux-Shared/packages/session/fixtures` byte-for-byte to hold compatibility at the canonicalisation layer.
- **2026-04-20** — Pinned Rust crate versions exactly (not caret ranges) to stay compatible with the repo’s `rust-toolchain.toml` target `1.93.0`; newer `blake3` releases currently pull transitive dependencies that require Rust 1.95+.
- **2026-04-20** — M0 remains open despite passing local tests because two milestone items are still operational, not repo-local: Vault Transit key provisioning (`rcx-registry-signing-key-1`) and schema publication to `static.rcxprotocol.org/schemas/2026-04-19/`.
- **2026-04-20** — Plan domain strategy tightened per user direction: the ExecPlan now assumes a single `rcxprotocol.org` domain family for API, schema CDN, docs, staging, and launch readiness, removing the prior `cuecrux.com` transition path.
- **2026-04-20** — Repo-local schema IDs and example fixtures were aligned to `static.rcxprotocol.org` immediately after the plan change so M0 artifacts no longer contradict the active domain strategy.
- **2026-04-20** — Started M1 with repo-local foundations: `migrations/0001_mcp_servers.sql`, `migrations/0002_snapshots.sql`, a deterministic per-entry hash helper, snapshot-Merkle-root helper, and four-state (`added` / `removed` / `modified` / `unchanged`) reconciliation tests in `crates/rcx-registry-ingest/`.
- **2026-04-20** — Verified the live upstream MCP registry shape against `https://registry.modelcontextprotocol.io/openapi.yaml` and `GET /v0/servers?limit=1`: the current API exposes `/v0/servers`, `/v0/servers/{serverName}/versions`, and `/v0/servers/{serverName}/versions/{version}` with `updated_since` query support. Treat the ExecPlan’s older `GET /v0/servers/{name}` shorthand as stale and keep the implementation aligned to the live upstream surface.
- **2026-04-20** — M1 implementation advanced materially: `crates/rcx-registry-ingest/` now includes upstream list-response models, a blocking `reqwest` fetch client with cursor/search/version/`updated_since` support plus ETag/304 handling, a date-pinned schema-catalog validation interface, canonical JSON normalisation, cadence policy, 30-day soft-delete planning, and `RegistrySnapshot` receipt planning. `crates/rcx-registry-api/` now serves MCP-shaped baseline stubs for list, version listing, and version lookup against an in-memory mirror store, with cursor/deleted/latest coverage tests.
- **2026-04-20** — M2 repo-local implementation landed: `migrations/0003_rcx_enrichment.sql`, `crates/rcx-registry-enrich/` auto-enrichment payload/block helpers, `EntryAutoEnriched` receipt planning, parity-invariant checks, and `_meta.org.rcxprotocol.registry/auto` response surfacing via extensible meta handling in the ingest/API models. One open M2 integration task remains for a later pass: wiring this into the sync loop so the parity invariant is enforced against real mirrored rows rather than helper inputs.
- **2026-04-20** — Began M3 with the local, non-provider-specific pieces: `migrations/0004_publisher_rights.sql`, namespace classification for GitHub / reverse-DNS / anonymous names, conservative `passport:github:<owner>` matching, DNS TXT challenge generation (`_rcx-registry.<domain>`), and `PublisherRightsVerified` receipt planning in `crates/rcx-registry-admin/`. The live GitHub OAuth callback flow, DNS resolver checks, manual-review workflow, and onboarding UI are still outstanding.
- **2026-04-20** — Refreshed cached `PlanCrux Notes` after detecting `PlanCrux/README.version` advanced from the previously recorded `v1.2` marker to `v1.2S`. Summary content remains valid; version metadata now matches the current handbook marker.
- **2026-04-20** — Dependency reality check: the hosted RCX-Protocol/session-v2 capability-graph code is present in VaultCrux and explicitly staged behind `FEATURE_SESSION_HANDSHAKE_V2` (`VaultCrux/apps/api/src/routes/session.ts`, `VaultCrux/feature-flags.json`), so the sibling ExecPlan header being `Draft` is not a reliable indicator of implementation absence. Treat the older `FEATURE_RCX_V2_GRAPH` name in this ExecPlan as stale nomenclature; the live gate name is `FEATURE_SESSION_HANDSHAKE_V2`. This clears the "code not present" concern for M4/M7 dependency planning, but does **not** change the RCX-Registry-side status: session capability nodes still default to empty `attestations` arrays until registry integration lands.
- **2026-04-20** — M3 repo-local API surface landed in `crates/rcx-registry-api/` and `crates/rcx-registry-admin/`: `GET /publish`, DNS challenge + verify endpoints, manual verify endpoint, GitHub OAuth start/callback contracts backed by a pluggable provider interface, publisher-rights listing, in-memory publisher-rights store / DNS resolver test doubles, and receipt-derived `PublisherRightsRecord` helpers. `cargo test --workspace` passes. Remaining M3 blockers are operational rather than structural: GitHub OAuth app credentials and redirect configuration, production DNS resolver wiring, and the human/manual review workflow.
- **2026-04-20** — M4 repo-local declaration flow landed in `crates/rcx-registry-enrich/` and `crates/rcx-registry-api/`: publisher declaration discovery metadata parsing, schema validation against `schemas/2026-04-19/rcx-enrichment.schema.json`, capability-graph edge consistency checks, declaration hashing, blocking fetch helper, `EntryEnriched` receipt planning with supersession, `POST /v0/publishers/declare`, in-memory publisher-enrichment store, and response overlay so `GET /v0/servers*` surfaces `_meta.org.rcxprotocol.registry/publisher`. `cargo test --workspace` passes. Remaining M4 blockers are execution wiring rather than local code: sync-loop discovery of declaration URIs from mirrored MCP rows, 24-hour refresh cadence in the enrichment loop, and a real publisher E2E on live infrastructure.

- **2026-05-01** — Pre-Hetzner-VM landing of `crates/rcx-registry-server/`: a deployable binary that wires the existing API router to real backends. New surface in code:
  - **Postgres** — `r2d2_postgres`-backed pool plus `PgMirrorStore`, `PgPublisherRightsStore`, `PgPublisherEnrichmentStore`, `PgSnapshotStore` impls of the api crate's traits. Embedded migration runner applies `migrations/0001`–`0004` plus a new `0005_mcp_servers_envelope.sql` (adds `envelope_json`, `version`, `is_latest`, `deleted_upstream_at`) tracked in `_rcx_registry_migrations`.
  - **Sync loop** — `loops/sync.rs` walks every MCP page, validates via `NoopSchemaCatalog`, persists each envelope, computes the canonical Merkle root, mints a `RegistrySnapshot` receipt signed by Vault Transit, soft-deletes upstream-removed rows, and evicts after the 30-day retention window. Cadence is `SyncCadencePolicy` from the ingest crate.
  - **Enrichment loop** — `loops/enrich.rs` sweeps mirrored rows on a 24h cadence, parses `_meta.org.rcxprotocol.publisher` discovery, refetches declarations, validates rights via the publisher-rights store, and signs + upserts `EntryEnriched` records when the declared hash changes.
  - **Vault Transit signer** — `vault::VaultTransitSigner` POSTs canonical CBOR bytes to `/v1/transit/sign/<key>` with `signature_algorithm: ed25519`, strips the `vault:v1:` prefix, base64-decodes, and returns the 64-byte signature. `UnsignedSigner` is the explicit fallback when `VAULT_ADDR` is unset (logs a warning and emits zeroed signatures).
  - **DNS resolver** — `dns::HickoryDnsTxtResolver` with a Cloudflare-1.1.1.1 default and a `from_system_conf` variant for Tailscale MagicDNS.
  - **GitHub OAuth provider** — `github_oauth::GitHubOAuthClient` does the canonical `authorize_url` build, `oauth/access_token` exchange, and `api.github.com/user` lookup; returns the verified login.
  - **Health, metrics, server boot** — `/healthz`, `/readyz` (verifies pool checkout), `/metrics` (hand-rolled Prometheus exposition for the 11 series enumerated in master plan §11.1), `tower-http::TraceLayer`, `tokio::signal` SIGINT/SIGTERM handler, `axum::serve(...).with_graceful_shutdown`.
  - **Feature flags** — `FEATURE_RCX_REGISTRY` (master) gates the sync loop. `FEATURE_RCX_REGISTRY_PUBLISHER_DECLARATIONS` gates the enrichment loop. Both default off.
  - **Deploy assets** — `ops/docker/{Dockerfile,docker-compose.yml,.env.example}` (Chainguard wolfi-base per CueCrux/CLAUDE.md §9), `ops/caddy/Caddyfile` (`registry.rcxprotocol.org` + `static.rcxprotocol.org` ACME), `ops/tailscale/acl-snippet.hujson` (operator-only SSH + Postgres + `/metrics`), `ops/prometheus/{prometheus.yml, rules/rcx-registry.rules.yml}` (4 alerts: snapshot staleness, fetch error burst, dead loop, enrichment error rate), `ops/grafana/dashboards/rcx-registry.json` (6 panels). `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`, and `cargo test --workspace` all green; 66 unit tests pass. Outstanding for the Hetzner provision: the operational items at the bottom of `README.md` (Vault key, schema CDN, GitHub OAuth app, DNS, real publisher E2E).

- **2026-07-19** — Repo made **public** by the operator (Apache-2.0, foundation-track). Dissolved the GitHub Actions billing block; PR #1 CI went green after one more fix: the crown golden-fixture test read from the sibling `CueCrux-Shared` checkout, absent on CI — vendored the 236K golden set under `fixtures/session-goldens/` with sibling-first fallback so local checkouts still cross-check the live set. CI must stay hermetic on standalone clones from here on.
- **2026-07-19** — **PR #2** root-caused the `INGEST_BUG` recorded in fact `gate:rollout-5points`: `schema_date_from_uri` only accepted `/schemas/<date>/…` but live upstream rows still carry legacy `/schemas/server/<date>.json`; every tick failed. Now accepts the first date-shaped path segment, and the sync loop skips-and-counts malformed envelopes (`rcx_registry_mcp_fetch_errors_total`) instead of failing the whole tick.
- **2026-07-19** — **PR #4** added connect/request timeouts (10s/60s) to the blocking reqwest clients in ingest/enrich, matching the Vault + GitHub OAuth clients — without them one stalled response hangs a loop forever with nothing counted (*silent no-sync*; the `RcxRegistrySyncDead` alert rule is the long-term guard once Prometheus scrapes prod). Post-fix measurement showed the "wedge" was partly **scale**: the upstream registry now paginates at ~1.8 s/page from this VM and is hundreds of pages deep (30 pages / 54 s only reached names starting with 'c'), so a full first tick takes tens of minutes. Follow-up candidate (not built tonight): incremental sync via the already-supported `updated_since` param after the first full walk.
- **2026-07-19** — **PR #3** shipped the adoption surface: rewritten `README.md` (verified route tables, real flag reference, crate map, honest status) + `docs/publishing.md` end-to-end publisher funnel. Redeployed main to the VM (rsync excluding `ops/docker/.env`; compose build). Peer-session state from `gate:rollout-5points` (Vault Transit signing, Caddy-over-tailnet local-CA, published schemas) verified intact post-redeploy; `/var/www/static.rcxprotocol.org/schemas/` now also carries `2026-05-01/`. M1 24h soak running. Coordination note: tonight's work interleaved with the codex session that wrote `gate:rollout-5points` — its diagnosis was consumed here, not duplicated.
