# Pointing an MCP client at RCX

Switching a client to RCX is configuration only. No client needs a patch, a
plugin, or a build — you edit one file, or in VS Code's case flip one policy.

Everything below is generated, not hand-written per server:

```bash
./scripts/rcx-client-config.py <server-name>              # every client
./scripts/rcx-client-config.py <server-name> --client cursor
```

The script resolves the server from the live registry and prints the exact block
to paste. Stdlib Python, no install step.

## Two adoption paths, and only one of them is a repoint

This distinction matters more than any config snippet, and most write-ups get it
wrong:

| | Client | What you change |
|---|---|---|
| **Gallery repoint** | VS Code | One policy value. The *whole* MCP gallery resolves through RCX — every server, no per-server entry. |
| **Resolve and paste** | Claude Desktop, Cursor, Continue, OpenCode, MCP Inspector | These have no registry-URL concept at all. RCX is where you resolve and check a server; the client still takes a per-server entry. |

If you read "point your client at RCX" and picture the VS Code behaviour for
Cursor, you will go looking for a setting that does not exist. There isn't one —
in those clients the unit of configuration is a server, not a registry.

## VS Code — repoint the gallery

VS Code exposes an enterprise policy, `McpGalleryServiceUrl`, that repoints its
entire MCP gallery at any registry serving the `/v0` read shape.

```json
{
  "McpGalleryServiceUrl": "https://registry.rcxprotocol.org"
}
```

Applied through device management. After that, servers browsed in-product come
from RCX, and nothing else needs configuring — this is the only client where
adoption is genuinely one value.

## Claude Desktop

`claude_desktop_config.json` (Settings → Developer → Edit Config).

```bash
./scripts/rcx-client-config.py io.example/thing --client claude-desktop
```

**Remote servers are bridged through `mcp-remote`, deliberately.** Claude
Desktop's `mcpServers` accepts stdio only; the native `{"url": ...}` shape is
skipped rather than rejected loudly, so a bare URL looks exactly like a broken
server. The generator never emits one.

On Windows, install the bridge globally (`npm install -g mcp-remote`) and point
`command` at `%APPDATA%\npm\mcp-remote.cmd`. Going through `npx` resolves to
`C:\Program Files\nodejs\npx.cmd`, which Claude Desktop invokes unquoted under
`cmd /C` — it dies on the space in `Program Files`.

## Cursor

`~/.cursor/mcp.json`, or `.cursor/mcp.json` to scope it to one project.

```bash
./scripts/rcx-client-config.py io.example/thing --client cursor
```

Cursor takes remote servers directly as `{"url": ...}` — no bridge needed.

## Continue

`~/.continue/config.yaml`, or a standalone file under `.continue/mcpServers/`
for one project.

```bash
./scripts/rcx-client-config.py io.example/thing --client continue
```

`mcpServers` is a YAML **list** — the leading `-` is load-bearing, and mixing
tabs with spaces breaks parsing silently. Reload the extension after editing; a
stale extension process is the usual reason a correct config appears to do
nothing.

## OpenCode

`~/.config/opencode/opencode.json` for user-wide, or `opencode.json` in the repo
root for one project.

```bash
./scripts/rcx-client-config.py io.example/thing --client opencode
```

OpenCode distinguishes `"type": "local"` from `"type": "remote"` natively, so
both kinds of server map straight across.

## MCP Inspector

Inspector takes any config file:

```bash
./scripts/rcx-client-config.py io.example/thing --client inspector > rcx-server.json
npx @modelcontextprotocol/inspector --config rcx-server.json
npx @modelcontextprotocol/inspector --cli --config rcx-server.json \
  --server io.example-thing --method tools/list
```

`--server` selects one entry from the file, and only under `--cli`.

## Migrating from the official registry

RCX mirrors the official `/v0` read surface field for field, so migration is a
URL swap, not a data migration.

1. **Repoint.** VS Code: set `McpGalleryServiceUrl`. Everything else: keep your
   existing entries and regenerate them through the script as you touch them —
   the entries are byte-identical either way, because both registries serve the
   same server records.
2. **Confirm the server resolves.**
   ```bash
   curl -fsS 'https://registry.rcxprotocol.org/v0/servers?limit=5'
   ```
3. **Check the RCX metadata.** RCX adds fields inside the existing envelope
   under `_meta`, in the reserved `org.rcxprotocol.registry` namespace. Clients
   that do not know about them ignore them, which is why the swap is safe.

Nothing about your existing config becomes invalid. If RCX is unreachable, the
official registry URL still works — that is the whole point of preserving the
read shape.

## What you can verify today, and what you cannot

Be precise about this, because the gap is real.

**You can** verify the protocol itself. The `rcx` CLI verifies receipts,
snapshot roots, declarations, namespaces and chains offline, against the
published spec-v1 conformance vectors:

```bash
rcx verify receipt examples/verify/receipt.hex --key @examples/verify/test-key.hex
```

Four independent SDKs (Rust, Python, TypeScript, Go) reproduce those vectors
byte-for-byte, checked in CI on every change.

**You cannot yet** verify a live server end-to-end. The production registry
publishes no snapshot receipt, no production snapshot root, and no signing
public key over HTTP — the only verifiable bytes published today are the
conformance vectors, which are signed with an obvious test-only key. Until those
production artifacts are served, pointing a client at RCX gets you a mirror with
a documented trust model, not an independently verified one.

That is a deliberate statement of a current limit, not an oversight to work
around. A verification story that only works against test vectors should say so.
