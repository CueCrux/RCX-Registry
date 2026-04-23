# Docs

Repository-local documentation lives here. User-facing spec mirrors and onboarding
guides will be added in later milestones.

Current repo-local publisher onboarding surface:

- `GET /publish` for the minimal HTML onboarding page
- DNS TXT challenge + verify endpoints under `/v0/publisher-rights/*`
- Manual verification endpoint for operator-mediated review
- GitHub OAuth start/callback contracts ready for live credential wiring
- `POST /v0/publishers/declare` for Option B publisher declaration submission

Current repo-local enrichment surface:

- declaration discovery metadata parsing from mirrored MCP `_meta`
- validation against `schemas/2026-04-19/rcx-enrichment.schema.json`
- `EntryEnriched` receipt planning and supersession
- publisher enrichment overlay under `_meta.org.rcxprotocol.registry/publisher`
