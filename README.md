# RCX-Registry

[![CI](https://github.com/CueCrux/RCX-Registry/actions/workflows/ci.yml/badge.svg)](https://github.com/CueCrux/RCX-Registry/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

**An MCP-compatible subregistry with a reproducible snapshot-evidence format.**

RCX-Registry serves a mirror of the [official MCP registry](https://registry.modelcontextprotocol.io) and publishes canonical receipt formats plus byte-exact conformance vectors. The baseline read API preserves the upstream `/v0` response envelope. Production currently has zero snapshots because its Vault Transit signing attempt returns 403, and all publisher verification/declaration writes fail closed while their trust model is hardened.

## How it works

1. **Mirror** — the implementation can walk every upstream page, canonicalise each envelope, and mint a `RegistrySnapshot` receipt over a flat, sorted BLAKE3 set digest (the historical field name is `snapshot_merkle_root`; it is not a Merkle tree). The hosted loop currently fails before snapshot persistence.
2. **Verify** — DNS and GitHub proof routes are implemented, but every public verification write returns 404. Reopening requires authenticated passport binding, server-owned time, OAuth state/org proof, and production credentials.
3. **Enrich** — the background implementation can validate, hash, sign, and refresh declarations. Public submission is closed, and complete signed enrichment artifacts are not persisted or returned today.
4. **Receipt** — the repository freezes Ed25519 signing semantics and test vectors. Production live signing, complete artifact storage, retrieval, and public-key discovery remain M1a work.

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
| `POST /v0/publisher-rights/dns-challenge` | Implemented contract; production edge returns 404 |
| `POST /v0/publisher-rights/dns-verify` | Implemented contract; production edge returns 404 |
| `GET /v0/publisher-rights/github/start` · `/callback` | Implemented contract; production edge returns 404 and OAuth credentials are unset |
| `GET /v0/publishers/{publisher_passport}` | Publisher rights read; production currently has zero rows |

All publisher verification and declaration writes deliberately fail closed at the production edge. `manual-verify` and `publishers/declare` are also absent from the application router.

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

The master feature flag defaults off, so the mirror API serves but the sync loop is dormant. Set `FEATURE_RCX_REGISTRY=true` in `.env` and restart to begin sync attempts; this does not guarantee a successful signed snapshot, so verify logs and persisted state.

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

Deployed and under active development. Mirror reads are live at `registry.rcxprotocol.org`; publisher-rights reads are live but currently empty. The hosted snapshot table is empty and Vault Transit calls return 403. All publisher writes are closed. Passport/project discovery uses an empty in-memory production store. Signing recovery, proof binding, complete receipt persistence/retrieval, and production-key discovery remain open before trust hardening is complete.

Publisher docs: [docs/publishing.md](docs/publishing.md). Deploy/ops runbook: [ops/README.md](ops/README.md).

## License

[Apache-2.0](LICENSE)
