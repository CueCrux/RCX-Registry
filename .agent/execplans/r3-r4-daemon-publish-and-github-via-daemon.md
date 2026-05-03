# RCX-Registry — R3 + R4 (Daemon publish hook + GitHub-via-daemon proof)

## Context

This plan picks up the deferred half of `cuecrux-portfolio-tier-uplift-from-coordination` (in `PlanCrux/.agent/execplans/`). R1 + R2 already shipped — schemas are at `schemas/2026-05-01/{passport,project}-publish.schema.json`, the `PublishedRecordStore` trait + in-memory impl + four lookup/list HTTP endpoints (`GET /v0/passports[/{fpr}]` + `GET /v0/projects[/{publisher}/{id}]`) are live in `crates/rcx-registry-api`.

Two pieces remain:

- **R3** — A signed publish flow so a Crux Daemon can post passport + project descriptors to the registry.
- **R4** — A new publisher-rights verification path that uses an indexed-on-daemon GitHub authorship signal (instead of/in addition to the existing OAuth flow).

Both touch the registry's signature-verification surface, which is security-sensitive — please get a security review on the verifier before deploying.

## Non-goals

- Persistent storage. The in-memory `InMemoryPublishedRecordStore` is fine for staging; production swap-in (Postgres or sled) is a separate ExecPlan owned by the registry team.
- Backwards-incompatible changes to the existing `/v0/publishers` flow.
- Sponsor-chain traversal in R3 (lookup_lineage helpers can land later).

## R3 — Daemon-driven publish flow

### Surface to add

- `POST /v0/passports` — body matches `passport-publish.schema.json`; verifies signature against `publisher_passport`'s public key over the canonical-CBOR encoding, then `upsert_passport`.
- `POST /v0/projects` — same shape for `project-publish.schema.json`.

### Verification steps (must run in this order)

1. JSON schema validation (already wired via `jsonschema` crate elsewhere in the registry — reuse).
2. Reconstruct canonical CBOR. Verify `passport_hash` / `project_hash` is `BLAKE3(canonical_cbor)`.
3. Look up `publisher_passport`'s public key. Two paths:
   - For passport-publish where `publisher_passport == passport_fpr` (a passport publishing itself), the `public_key_hex` field IS the verifier — use it.
   - For project-publish (or sponsor-different-from-self passport-publish), the publisher must already exist in the registry; reject with `412 PRECONDITION_FAILED` if absent.
4. ed25519 signature verification with the resolved public key.
5. Reject if `published_at` is more than ±5 min from server time (replay protection).

### Crux Daemon side (paired work)

Add a `corecruxctl publish passport <id>` and `corecruxctl publish project <id>` command:
- Reads the local passport/project record.
- Builds the publish envelope including a fresh signature.
- POSTs to `CORECRUXD_RCX_REGISTRY_URL` (env-configured; nothing happens if unset).
- Console UI: a "Publish to RCX Registry" button on each Passport / Project detail drawer (gated on the env being set).

### Tests

- Schema validation rejects malformed bodies.
- Hash mismatch → 400.
- Wrong-public-key signature → 401.
- Stale `published_at` → 400.
- Happy path → record stored + retrievable via `GET /v0/passports/{fpr}`.

## R4 — GitHub-via-daemon publisher-rights proof

The existing `GET /v0/publisher-rights/github/start` + `/callback` flow proves "this passport's holder controls this GitHub username/org" via OAuth. With Plan B's daemon-side GitHub indexer, an alternate proof path is possible: the publisher's daemon can sign an attestation that says "I have indexed this repo and the passport_owner authored ≥ N merged PRs against `main` in the last 90 days."

### New endpoint

- `POST /v0/publisher-rights/github-via-daemon` — body:
  - `publisher_passport`
  - `target_namespace` (e.g., `io.github.cuecrux/`)
  - `evidence`: { `repo`, `merged_pr_count`, `period_start_iso`, `period_end_iso`, `daemon_signature` over `BLAKE3(canonical(target_namespace || repo || merged_pr_count || period))` }
  - `daemon_passport_fpr`: signer of the evidence

### Verification

1. Daemon passport must have an existing passport-publish record (R3 prerequisite).
2. Verify the daemon's signature over the evidence digest.
3. Cross-check the claim by hitting `https://api.github.com/repos/{repo}/commits?author={username}&until={period_end}&since={period_start}` — must agree within ±20% on commit count.
4. Persist as a `PublisherRightsRecord` with `verification_method = "github_via_daemon"`.

### Threat model

- **Daemon lies about authorship**: mitigated by the GitHub cross-check.
- **Stolen daemon passport private key**: mitigated by the same cross-check + rate-limiting on `github-via-daemon` proofs (1 per (passport, namespace) per 24h).
- **Repo deleted/renamed between sign and verify**: API call returns 404 → reject.

### Tests

- Schema + hash + signature checks (mirror R3).
- Mock GitHub-cross-check failure → 403.
- Successful path round-trips into `PublisherRightsStore`.

## Sequencing

R3 must land before R4 (R4 depends on `PassportPublishRecord` lookups). Operator-side `corecruxctl publish` work can land in parallel with R3's server side.

## Rollout / rollback

- Feature flags: `RCX_REGISTRY_DAEMON_PUBLISH_ENABLED=1` gates `POST /v0/passports` + `POST /v0/projects`. Off by default until the verifier is reviewed.
- `RCX_REGISTRY_GITHUB_VIA_DAEMON_ENABLED=1` gates R4 similarly.
- Rollback = unset the flag + restart. Records persist (in-memory, lost on restart anyway; Postgres rollback is purely flag-based).
