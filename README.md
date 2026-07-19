# RCX-Registry

[![CI](https://github.com/CueCrux/RCX-Registry/actions/workflows/ci.yml/badge.svg)](https://github.com/CueCrux/RCX-Registry/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

**A receipted, MCP-compatible subregistry for RCX-aware discovery.**

RCX-Registry mirrors the [official MCP registry](https://registry.modelcontextprotocol.io) and layers verifiable trust on top of it: publishers prove control of their namespace, enrich their entries with RCX capability metadata, and every state change is recorded as a signed, hash-chained CROWN receipt. Existing MCP registry clients work unchanged — the baseline read API is shape-compatible with upstream `/v0`.

## How it works

1. **Mirror** — a sync loop walks every page of the upstream MCP registry on a fixed cadence, canonicalises each server envelope, and mints a signed `RegistrySnapshot` receipt over the Merkle root of the full set. Upstream deletions are soft-deleted with a 30-day retention window.
2. **Verify** — publishers prove namespace rights via DNS TXT challenge (`_rcx-registry.<domain>`) or GitHub OAuth for `io.github.*` namespaces; manual operator review covers the rest.
3. **Enrich** — verified publishers declare RCX capability metadata for their servers. Declarations are schema-validated, hashed, refreshed on a 24 h cadence, and surfaced to clients under `_meta.org.rcxprotocol.registry/publisher` (auto-enrichment under `…/auto`).
4. **Receipt** — every mutation (snapshot, enrichment, rights verification) is an ed25519-signed CROWN receipt minted via Vault Transit, so the registry's entire history is independently verifiable.

## API surface

Baseline mirror (shape-compatible with the upstream MCP registry):

| Route | Description |
|---|---|
| `GET /v0/servers` | List servers (cursor pagination, `limit`) |
| `GET /v0/servers/{name}/versions` | List versions for a server |
| `GET /v0/servers/{name}/versions/{version}` | Fetch one version |

Publisher rights + enrichment (RCX extensions):

| Route | Description |
|---|---|
| `GET /publish` | Publisher onboarding page |
| `POST /v0/publisher-rights/dns-challenge` | Start a DNS TXT namespace challenge |
| `POST /v0/publisher-rights/dns-verify` | Verify the TXT record |
| `GET /v0/publisher-rights/github/start` · `/callback` | GitHub OAuth namespace verification |
| `POST /v0/publisher-rights/manual-verify` | Operator-mediated review |
| `GET /v0/publishers/{publisher_passport}` | Publisher rights record |
| `POST /v0/publishers/declare` | Submit an RCX enrichment declaration |

Published records:

| Route | Description |
|---|---|
| `GET /v0/passports` · `/v0/passports/{fpr}` | Published passport records |
| `GET /v0/projects` | Published project records |

Operator (restrict to your tailnet / LAN):

| Route | Description |
|---|---|
| `GET /healthz` · `/readyz` | Liveness / readiness (checks Postgres pool) |
| `GET /metrics` | Prometheus exposition (11 series + alert rules in `ops/`) |

## Quickstart

```bash
cd ops/docker
cp .env.example .env       # set POSTGRES_PASSWORD; VAULT_* and GITHUB_OAUTH_* can stay empty for a first boot
docker compose up -d --build
curl -s http://127.0.0.1:3030/healthz | jq
curl -s 'http://127.0.0.1:3030/v0/servers?limit=5' | jq '.metadata'
```

The master feature flag defaults off, so the mirror API serves but the sync loop is dormant. Set `FEATURE_RCX_REGISTRY=true` in `.env` and restart to start mirroring the upstream registry.

Without `VAULT_ADDR` configured the server falls back to an unsigned signer and logs a warning — receipts carry zeroed signatures. Fine for local development; never for a public deployment.

## Configuration

| Flag | Default | Gates |
|---|---|---|
| `FEATURE_RCX_REGISTRY` | `false` | Master switch — upstream sync loop |
| `FEATURE_RCX_REGISTRY_PUBLISHER_DECLARATIONS` | `false` | 24 h publisher-declaration refresh loop |
| `FEATURE_RCX_REGISTRY_ATTESTATIONS` | `false` | Attestation surface (in development) |
| `FEATURE_RCX_REGISTRY_SIGNED_CURSORS` | `false` | Tamper-evident pagination cursors (in development) |
| `FEATURE_RCX_REGISTRY_PROTOCOL_INTEGRATION` | `false` | RCX-Protocol `AttestationRef` integration (planned) |

Key environment: `DATABASE_URL`, `MCP_REGISTRY_BASE_URL` (defaults to the official registry), `VAULT_ADDR` + `VAULT_TRANSIT_KEY_NAME` + `RCX_REGISTRY_SIGNER_KID` for receipt signing, `GITHUB_OAUTH_CLIENT_{ID,SECRET}` for GitHub namespace verification. See `crates/rcx-registry-server/src/config.rs` for the full reference.

## Architecture

Rust workspace (toolchain pinned to 1.93.0), seven crates:

| Crate | Role |
|---|---|
| `rcx-registry-crown` | Canonical CBOR/JSON, BLAKE3 hashing, ed25519 verification, CROWN receipt types |
| `rcx-registry-ingest` | Upstream fetch client, canonicalisation, reconciliation, snapshot planning |
| `rcx-registry-enrich` | Auto and publisher-declared enrichment |
| `rcx-registry-attest` | Attestation acceptance and revocation |
| `rcx-registry-api` | Axum HTTP surface — MCP-compatible baseline + RCX extensions |
| `rcx-registry-admin` | Publisher rights: namespace classification, DNS/OAuth verification, moderation |
| `rcx-registry-server` | Deployable binary: Postgres stores, sync + enrichment loops, Vault Transit signer, hickory DNS, GitHub OAuth |

## Schemas

Date-pinned and immutable once published, served from `static.rcxprotocol.org`:

| Set | Contents |
|---|---|
| [`schemas/2026-04-19/`](schemas/2026-04-19/) | `rcx-enrichment`, `attestation` |
| [`schemas/2026-05-01/`](schemas/2026-05-01/) | `passport-publish`, `project-publish` |

## Status

Deployed and under active development. The mirror, enrichment, publisher-rights, and published-records surfaces (M0–M4 of the [v1 ExecPlan](.agent/execplans/rcx-registry-v1-implementation-2026-04-19.md)) are implemented and tested; the public host at `registry.rcxprotocol.org` is in pre-launch soak. In progress / planned: attestations (M5), extended query API (M6), RCX-Protocol integration (M7), public launch (M9).

Publisher docs: [docs/publishing.md](docs/publishing.md). Deploy/ops runbook: [ops/README.md](ops/README.md).

## License

[Apache-2.0](LICENSE)
