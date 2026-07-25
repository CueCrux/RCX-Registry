# RCX-Registry frontdoor

Public marketing/docs site for [RCX-Registry](https://github.com/CueCrux/RCX-Registry) —
`rcxprotocol.org`. Nuxt 4 SSR, "aurora glass" theme (shared with cuecrux.com), dark by default.

Pure static-content site: **no** BFF, auth, or payments. The registry read API and publisher-status
page live on a separate host (`registry.rcxprotocol.org`) and are only linked to. Public onboarding
writes currently fail closed; the site builds and renders with the registry offline.

```bash
pnpm install
pnpm dev        # http://localhost:3200
pnpm build      # -> .output/ (node-server preset)
pnpm test       # validates the public growth-item assets
pnpm test:built # smokes built routes, client navigation, and exact vectors (Chromium required)
```

## Pages

`/` home · `/verify` verification model · `/spec/v1` normative protocol spec · `/publish` publisher onboarding ·
`/subregistry` subregistry positioning · `/badge` README badge · `/legal` terms + privacy.

`/spec/v1/*` renders the Markdown sources from `../spec/v1/` through Nuxt Content. The JSON
fixtures under `/spec/v1/vectors/` are served byte-for-byte from the repository with immutable
cache headers; the HTML vector index remains normally cacheable so site-shell updates can ship.

## Growth-item assets

`public/robots.txt`, `public/llms.txt`, `public/llms-full.txt`, `public/sitemap.xml`,
`public/.well-known/mcp.json`, `public/badge/verified.svg`. JSON-LD (Organization + DataCatalog)
is injected on the home page via `useHead`.

## Config

`NUXT_PUBLIC_SITE_URL` (default `https://rcxprotocol.org`),
`NUXT_PUBLIC_REGISTRY_API_URL` (default `https://registry.rcxprotocol.org`).

## Deploying

The host runs `.output` under `rcx-frontdoor.service` from `/srv/rcx-frontdoor`, owned by `root`
while the unit runs as the unprivileged `rcx-frontdoor` user.

**Warm the Nuxt Content database before shipping.** `pnpm build` does *not* emit
`.output/server/contents.sqlite` — the server writes it on first request from the
`__nuxt_content/*/sql_dump.txt` payloads. Because the deploy directory is root-owned, the service
user cannot create it, so a cold `.output` serves every `/spec/v1*` route as
`404 Protocol specification chapter not found` while the rest of the site looks fine.

Run the built server once locally and hit any spec route before you copy `.output` to the host:

```bash
pnpm build
node .output/server/index.mjs &        # then: curl -s localhost:3000/spec/v1 >/dev/null
ls .output/server/contents.sqlite      # must exist before deploying
```

Keep the previous directory alongside the new one — swapping it back and restarting the unit is
the whole rollback.
