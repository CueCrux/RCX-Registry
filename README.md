# RCX-Registry

RCX-Registry is a receipted, MCP-compatible subregistry for RCX-aware discovery.

The repo is through M0–M4 local code plus a deployable
`rcx-registry-server` binary that wires real Postgres, the MCP scrape
loop, the publisher-declaration refresh loop, hickory DNS, GitHub
OAuth, and a Vault Transit ed25519 signer behind a feature-flag master
gate. See `RCX-Registry/.agent/execplans/rcx-registry-v1-implementation-2026-04-19.md`
for the canonical milestone tracker.

## Workspace

- `crates/rcx-registry-crown` — canonical CBOR/JSON, BLAKE3 hashing, ed25519 verification, and RCX receipt event types.
- `crates/rcx-registry-ingest` — sync-pipeline primitives and MCP mirror logic.
- `crates/rcx-registry-enrich` — auto and publisher-declared enrichment.
- `crates/rcx-registry-attest` — attestation acceptance and revocation.
- `crates/rcx-registry-api` — MCP-compatible HTTP surface plus RCX extensions.
- `crates/rcx-registry-admin` — moderation and publisher onboarding support.
- `crates/rcx-registry-server` — binary: axum boot, Postgres stores, sync + enrichment loops, Vault Transit signer, hickory DNS, GitHub OAuth.

Initial schema artifacts live under `schemas/2026-04-19/`.

## Surface

Publisher-rights verification:

- `GET /publish` — minimal onboarding HTML
- `POST /v0/publisher-rights/dns-challenge`
- `POST /v0/publisher-rights/dns-verify`
- `POST /v0/publisher-rights/manual-verify`
- `GET /v0/publisher-rights/github/start`
- `GET /v0/publisher-rights/github/callback`
- `GET /v0/publishers/{publisher_passport}`
- `POST /v0/publishers/declare`

MCP mirror baseline:

- `GET /v0/servers`
- `GET /v0/servers/{name}/versions`
- `GET /v0/servers/{name}/versions/{version}`

Operator surfaces (restrict via Caddy + Tailscale):

- `GET /healthz` — liveness
- `GET /readyz` — readiness (verifies Postgres pool)
- `GET /metrics` — Prometheus exposition

## Quickstart (local)

```bash
cd ops/docker
cp .env.example .env       # set POSTGRES_PASSWORD; leave VAULT_* and GITHUB_OAUTH_* empty for first boot
docker compose up -d --build
curl -s http://127.0.0.1:3030/healthz | jq
curl -s 'http://127.0.0.1:3030/v0/servers?limit=5' | jq '.metadata'
```

Boot defaults `FEATURE_RCX_REGISTRY=false` — the MCP-mirror baseline
serves but the sync loop is dormant. Flip the flag in `.env` and
restart to start scraping the upstream MCP registry on the configured
cadence.

## Hetzner deploy

See [`ops/README.md`](ops/README.md) for the per-step checklist:
provision the box, apply the Tailscale ACL snippet, install Caddy with
the bundled Caddyfile, copy `.env`, `docker compose up`, point DNS at
`registry.rcxprotocol.org`, validate `/healthz`, then flip the master
flag.

## Remaining rollout blockers

Operational, not code:

1. **Vault Transit key provisioned** at `vault:transit:rcx-registry-signing-key-1`
   — without it, receipts are minted with zeroed signatures (server logs a warning).
2. **Schemas published** to `static.rcxprotocol.org/schemas/2026-04-19/`
   for stable external references.
3. **GitHub OAuth app registered** with callback URL
   `https://registry.rcxprotocol.org/v0/publisher-rights/github/callback`
   — secrets fed via `GITHUB_OAUTH_CLIENT_{ID,SECRET}`.
4. **DNS** for `registry.rcxprotocol.org` and `static.rcxprotocol.org`
   pointed at the Hetzner CCX13.
5. **Real publisher E2E** — at least one CueCrux-network publisher
   exercises the full publish + declare flow against the live host.
