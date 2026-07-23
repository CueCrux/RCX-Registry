# Docs

Repository-local documentation lives here.

- [publishing.md](publishing.md) — disabled publisher-proof contracts and the gates required before onboarding reopens.

Current repo-local publisher onboarding surface:

- `GET /publish` for the minimal HTML onboarding page
- DNS TXT and GitHub OAuth contracts exist in code, but the production edge returns 404 for all four routes
- GitHub OAuth credentials are unset; state binding and organization proof remain open
- public manual review is absent until an authenticated operator surface ships
- `POST /v0/publishers/declare` is absent until authenticated publisher proof and signing ship

Current repo-local enrichment surface:

- declaration discovery metadata parsing from mirrored MCP `_meta`
- validation against `schemas/2026-04-19/rcx-enrichment.schema.json`
- `EntryEnriched` receipt planning and supersession
- publisher enrichment overlay under `_meta.org.rcxprotocol.registry/publisher`
