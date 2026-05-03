# Ops

Operational assets for the RCX-Registry production deploy. The
canonical layout is a single Hetzner CCX13 host running:

- `rcx-registry-server` (this repo's binary, in a Chainguard container)
- Postgres (Chainguard image, colocated)
- Caddy (TLS + ACME, host install)
- Prometheus (host install or container — your call)
- Grafana (host install or container — your call)
- Tailscale (host install — operator access)

Files:

| Path | Purpose |
|---|---|
| `docker/Dockerfile` | Chainguard wolfi-base build + runtime image |
| `docker/docker-compose.yml` | Local + staging stack (server + Postgres) |
| `docker/.env.example` | Environment template — copy to `.env` and edit |
| `caddy/Caddyfile` | Production TLS frontend for `registry.rcxprotocol.org` and `static.rcxprotocol.org` |
| `tailscale/acl-snippet.hujson` | Tailscale ACL fragment — merge into the CueCrux tailnet policy |
| `prometheus/prometheus.yml` | Scrape config — drop-in or merge into existing CueCrux Prometheus |
| `prometheus/rules/rcx-registry.rules.yml` | Alert rules: snapshot staleness, fetch error bursts, dead loops |
| `grafana/dashboards/rcx-registry.json` | Dashboard JSON — import into Grafana |

## First-boot checklist (Hetzner CCX13)

1. Provision the box. Apply Tailscale + the ACL snippet.
2. `apt install caddy postgresql-client` (or replace Postgres host with the docker-compose Postgres if you prefer the Chainguard image).
3. Copy `ops/docker/.env.example` → `ops/docker/.env` and fill in:
   - `POSTGRES_PASSWORD`
   - `VAULT_ADDR` / `VAULT_TOKEN` (once the Vault Transit key is provisioned)
   - `GITHUB_OAUTH_CLIENT_ID` / `_SECRET` (once the GitHub OAuth app exists)
4. `cd ops/docker && docker compose up -d --build` — server boots with `FEATURE_RCX_REGISTRY=false`, serving the MCP-mirror baseline only.
5. Point `registry.rcxprotocol.org` DNS at the box, install the Caddyfile.
6. Validate `/healthz` and `/readyz` over Tailscale.
7. Flip `FEATURE_RCX_REGISTRY=true` to start the sync loop.
8. After 24h soak, flip `FEATURE_RCX_REGISTRY_PUBLISHER_DECLARATIONS=true`.

## Backout

Set `FEATURE_RCX_REGISTRY=false` and restart the container. RCX-specific
behaviour reverts to 503 stubs; the MCP-mirror baseline keeps serving.
