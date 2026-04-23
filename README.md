# RCX-Registry

RCX-Registry is a receipted, MCP-compatible subregistry for RCX-aware discovery.

This repository is currently through milestone M4 local enrichment work from
`RCX-Registry/.agent/execplans/rcx-registry-v1-implementation-2026-04-19.md`.
The workspace contains:

- `crates/rcx-registry-crown` — canonical CBOR/JSON, BLAKE3 hashing, ed25519 verification, and RCX receipt event types.
- `crates/rcx-registry-ingest` — sync-pipeline primitives and MCP mirror logic.
- `crates/rcx-registry-enrich` — auto and publisher-declared enrichment.
- `crates/rcx-registry-attest` — attestation acceptance and revocation.
- `crates/rcx-registry-api` — MCP-compatible HTTP surface plus RCX extensions.
- `crates/rcx-registry-admin` — moderation and publisher onboarding support.

Initial schema artifacts live under `schemas/2026-04-19/`.

Publisher-rights verification now has repo-local surface area for:

- `GET /publish` — minimal onboarding HTML
- `POST /v0/publisher-rights/dns-challenge`
- `POST /v0/publisher-rights/dns-verify`
- `POST /v0/publisher-rights/manual-verify`
- `GET /v0/publisher-rights/github/start`
- `GET /v0/publisher-rights/github/callback`
- `GET /v0/publishers/{publisher_passport}`
- `POST /v0/publishers/declare` — Option B publisher declaration submission

Publisher-declared enrichment now has repo-local support for:

- declaration discovery metadata parsing from MCP `_meta`
- declaration schema validation against `schemas/2026-04-19/rcx-enrichment.schema.json`
- capability-graph edge validation and declaration hashing
- `EntryEnriched` receipt planning with supersession
- response overlay under `_meta.org.rcxprotocol.registry/publisher`

The remaining rollout blockers are operational: live GitHub OAuth app wiring, production DNS TXT lookup integration, sync-loop declaration fetch/refresh execution, and real publisher end-to-end validation.
