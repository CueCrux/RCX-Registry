# RCX-Registry

RCX-Registry is a receipted, MCP-compatible subregistry for RCX-aware discovery.

This repository is currently at milestone M0 from
`RCX-Registry/.agent/execplans/rcx-registry-v1-implementation-2026-04-19.md`.
The workspace contains:

- `crates/rcx-registry-crown` — canonical CBOR/JSON, BLAKE3 hashing, ed25519 verification, and RCX receipt event types.
- `crates/rcx-registry-ingest` — sync-pipeline primitives and MCP mirror logic.
- `crates/rcx-registry-enrich` — auto and publisher-declared enrichment.
- `crates/rcx-registry-attest` — attestation acceptance and revocation.
- `crates/rcx-registry-api` — MCP-compatible HTTP surface plus RCX extensions.
- `crates/rcx-registry-admin` — moderation and publisher onboarding support.

Initial schema artifacts live under `schemas/2026-04-19/`.

