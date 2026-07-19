# RCX-Registry frontdoor

Public marketing/docs site for [RCX-Registry](https://github.com/CueCrux/RCX-Registry) —
`rcxprotocol.org`. Nuxt 4 SSR, "aurora glass" theme (shared with cuecrux.com), dark by default.

Pure static-content site: **no** BFF, auth, or payments. The registry API and publisher
onboarding live on a separate host (`registry.rcxprotocol.org`) and are only linked to — the site
builds and renders with the registry offline.

```bash
pnpm install
pnpm dev        # http://localhost:3200
pnpm build      # -> .output/ (node-server preset)
pnpm test       # validates the public growth-item assets
```

## Pages

`/` home · `/verify` verification model · `/publish` publisher onboarding ·
`/subregistry` subregistry positioning · `/badge` README badge · `/legal` terms + privacy.

## Growth-item assets

`public/robots.txt`, `public/llms.txt`, `public/llms-full.txt`, `public/sitemap.xml`,
`public/.well-known/mcp.json`, `public/badge/verified.svg`. JSON-LD (Organization + DataCatalog)
is injected on the home page via `useHead`.

## Config

`NUXT_PUBLIC_SITE_URL` (default `https://rcxprotocol.org`),
`NUXT_PUBLIC_REGISTRY_API_URL` (default `https://registry.rcxprotocol.org`).
