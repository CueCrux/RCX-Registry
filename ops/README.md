# Ops

Operational assets for the RCX-Registry production deploy. The live layout uses two hosts so a
frontdoor rollout cannot restart the registry data plane:

- API host: `rcx-registry-server`, Postgres, and the `registry.rcxprotocol.org` Caddy block
- Frontdoor host: `rcx-frontdoor` plus the apex, `www`, and static-site Caddy blocks
- Prometheus (host install or container — your call)
- Grafana (host install or container — your call)
- Tailscale (host install — operator access)

Files:

| Path | Purpose |
|---|---|
| `docker/Dockerfile` | Chainguard wolfi-base build + runtime image |
| `docker/docker-compose.yml` | Local + staging stack (server + Postgres) |
| `docker/.env.example` | Environment template — copy to `.env` and edit |
| `caddy/Caddyfile` | Combined reference config; install only the relevant site blocks on each live host |
| `systemd/rcx-frontdoor.service` | Production unit for the staged Nuxt `.output/` tree on port 3100 |
| `tailscale/acl-snippet.hujson` | Tailscale ACL fragment — merge into the CueCrux tailnet policy |
| `prometheus/prometheus.yml` | Scrape config — drop-in or merge into existing CueCrux Prometheus |
| `prometheus/rules/rcx-registry.rules.yml` | Alert rules: snapshot staleness, fetch error bursts, dead loops |
| `grafana/dashboards/rcx-registry.json` | Dashboard JSON — import into Grafana |

## First-boot checklist

1. Provision the box. Apply Tailscale + the ACL snippet.
2. `apt install caddy postgresql-client` (or replace Postgres host with the docker-compose Postgres if you prefer the Chainguard image).
3. Copy `ops/docker/.env.example` → `ops/docker/.env` and fill in:
   - `POSTGRES_PASSWORD`
   - `VAULT_ADDR` / `VAULT_TOKEN` (once the Vault Transit key is provisioned)
   - `GITHUB_OAUTH_CLIENT_ID` / `_SECRET` (once the GitHub OAuth app exists)
4. `cd ops/docker && docker compose up -d --build` — server boots with `FEATURE_RCX_REGISTRY=false`, serving the MCP-mirror baseline only.
5. Point `registry.rcxprotocol.org` DNS at the API host and install only its global/options and registry blocks. Keep the exact fail-closed matcher for manual review, DNS challenge/verify, GitHub start/callback, and publisher declaration.
6. Validate `/healthz` and `/readyz` over Tailscale.
7. Flip `FEATURE_RCX_REGISTRY=true` to start sync attempts. Accept only after logs, snapshot persistence, and signer health prove a complete cycle.
8. Keep `FEATURE_RCX_REGISTRY_PUBLISHER_DECLARATIONS=false` until authenticated declaration seeding is accepted. This flag controls only the background refresh loop; it does not authorize or gate HTTP routes.

## Backout

Retag the currently running image before each build and preserve a Postgres dump. Roll back by
repointing Compose to that immutable local tag and recreating only the registry service. Keep the
Caddy denies for all publisher verification/declaration routes across every binary rollback. Feature flags
stop background loops; they do not turn HTTP routes into 503 stubs.

## Frontdoor topology

The apex site is an SSR Nitro service, not a Caddy `file_server`. Build it with Node 22.12 or
newer, smoke the generated `.output/` with `pnpm test:built`, then stage the **contents** of that
directory under `/srv/rcx-frontdoor.release-<commit>`. Run the staged server on an alternate
loopback port and probe all baseline and `/spec/v1/*` routes before cutover. At cutover, stop only
`rcx-frontdoor.service`, move the current `/srv/rcx-frontdoor` to a timestamped rollback directory,
move the staged tree into place, and start the service. This is a controlled stop/swap/start, not an
atomic directory exchange; stopping first prevents the old Node process from lazily loading files
from the replacement tree. Probe through public Caddy immediately.

Rollback stops the service, moves the failed tree aside, restores the rollback directory, and starts
the service. The registry API and
`static.rcxprotocol.org` are separate surfaces and must not be restarted during a frontdoor rollout.

Create the non-login runtime identity once before installing the unit:

```bash
useradd --system --home-dir /nonexistent --shell /usr/sbin/nologin rcx-frontdoor
```

Keep release directories owned by `root:root`, with directories mode `0755` and files mode `0644`,
and no writable path inside the application tree. Before cutover, run the staged server as `rcx-frontdoor` on the
alternate port; this proves the read-only systemd sandbox will not hide a runtime write dependency.
