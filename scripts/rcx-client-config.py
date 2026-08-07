#!/usr/bin/env python3
"""Render an MCP client config entry from an RCX registry record.

    ./scripts/rcx-client-config.py ac.inference.sh/mcp
    ./scripts/rcx-client-config.py ac.inference.sh/mcp --client cursor

The point is that switching a client to RCX is *configuration only*: you resolve
a server by name and paste what comes out. Nothing here is hand-authored per
server, so "configuration-only" is demonstrated rather than asserted — if a
client ever needed a code change, it could not be a template in this file.

Stdlib only, same discipline as the conformance harness: this must run on a
clean machine with no install step, because "clean machine in under five
minutes" is a claim we make.

Exit 0 rendered · 1 the record cannot be expressed for that client · 2 could not
run (usage, network, unknown server). 1 and 2 stay distinct for the same reason
they do in `rcx`: "we could not look" must never read as "we looked and it was
fine".
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.parse
import urllib.request

DEFAULT_REGISTRY = "https://registry.rcxprotocol.org"

CLIENTS = ("claude-desktop", "cursor", "vscode", "continue", "opencode", "inspector")


class Unsupported(Exception):
    """The record is well-formed but this client cannot express it."""


def fetch(registry: str, name: str, version: str) -> dict:
    # The name contains a slash and must survive as one path segment.
    quoted = urllib.parse.quote(name, safe="")
    url = f"{registry}/v0/servers/{quoted}/versions/{urllib.parse.quote(version, safe='')}"
    try:
        with urllib.request.urlopen(url, timeout=30) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        sys.exit(f"cannot resolve {name}@{version}: HTTP {error.code} from {url}")
    except (urllib.error.URLError, TimeoutError) as error:
        sys.exit(f"cannot reach {registry}: {error}")
    except json.JSONDecodeError as error:
        sys.exit(f"{url} did not return JSON: {error}")
    # /versions/{version} returns the record; tolerate both envelope shapes.
    return payload.get("server", payload)


# ---------------------------------------------------------------------------
# record -> a neutral launch description
# ---------------------------------------------------------------------------

def stdio_command(package: dict) -> tuple[str, list[str]]:
    """Map one package entry to the command that runs it.

    Only registry types we can map exactly. A guessed runner would produce a
    config that fails at spawn time with an error pointing at the user's machine
    rather than at this table, so an unknown type is refused instead.
    """
    identifier = package.get("identifier")
    version = package.get("version")
    registry_type = package.get("registryType")
    if not identifier:
        raise Unsupported("package entry has no identifier")

    if registry_type == "npm":
        pinned = f"{identifier}@{version}" if version else identifier
        return "npx", ["-y", pinned]
    if registry_type == "pypi":
        pinned = f"{identifier}@{version}" if version else identifier
        return "uvx", [pinned]
    if registry_type == "oci":
        # OCI identifiers already carry their tag (docker.io/org/img:1.2.3), so
        # appending the version would produce an image reference nobody pushed.
        return "docker", ["run", "--rm", "-i", identifier]
    raise Unsupported(
        f"registryType {registry_type!r} has no runner mapping here — "
        "add one deliberately rather than guessing the command"
    )


def launch(record: dict) -> dict:
    """Reduce a server record to either a remote URL or a stdio command."""
    for remote in record.get("remotes") or []:
        if remote.get("url"):
            return {"kind": "remote", "url": remote["url"], "transport": remote.get("type")}
    for package in record.get("packages") or []:
        if (package.get("transport") or {}).get("type") == "stdio":
            command, args = stdio_command(package)
            return {"kind": "stdio", "command": command, "args": args, "env": env_hint(package)}
    raise Unsupported("record has neither a remote URL nor a stdio package")


def env_hint(package: dict) -> dict:
    """Environment variables the package declares, as empty placeholders.

    Values are deliberately blank: a generator that invented secret values would
    be worse than one that omits them.
    """
    return {
        variable["name"]: ""
        for variable in package.get("environmentVariables") or []
        if variable.get("name")
    }


def key_for(name: str) -> str:
    """A config key from a registry name.

    The whole name, not the last segment. Registry names routinely end in a
    generic segment (`ac.inference.sh/mcp`, `agency.goji/mcp`), so keying on the
    tail would silently overwrite an existing entry when the config already
    holds another server — the paste would appear to work and quietly remove a
    server the user still wanted.
    """
    return name.replace("/", "-")


# ---------------------------------------------------------------------------
# per-client rendering
# ---------------------------------------------------------------------------

def render_claude_desktop(name: str, run: dict) -> str:
    if run["kind"] == "remote":
        # Claude Desktop's mcpServers takes stdio only — the native
        # {"url": ...} shape is rejected outright — so a remote server is
        # bridged through mcp-remote rather than addressed directly.
        entry = {"command": "npx", "args": ["-y", "mcp-remote", run["url"]]}
    else:
        entry = {"command": run["command"], "args": run["args"]}
        if run["env"]:
            entry["env"] = run["env"]
    return json.dumps({"mcpServers": {key_for(name): entry}}, indent=2)


def render_cursor(name: str, run: dict) -> str:
    if run["kind"] == "remote":
        entry = {"url": run["url"]}
    else:
        entry = {"command": run["command"], "args": run["args"]}
        if run["env"]:
            entry["env"] = run["env"]
    return json.dumps({"mcpServers": {key_for(name): entry}}, indent=2)


def render_inspector(name: str, run: dict) -> str:
    if run["kind"] == "remote":
        entry = {"type": "http", "url": run["url"]}
    else:
        entry = {"type": "stdio", "command": run["command"], "args": run["args"]}
        if run["env"]:
            entry["env"] = run["env"]
    return json.dumps({"mcpServers": {key_for(name): entry}}, indent=2)


def render_opencode(name: str, run: dict) -> str:
    if run["kind"] == "remote":
        entry = {"type": "remote", "url": run["url"], "enabled": True}
    else:
        entry = {
            "type": "local",
            "command": [run["command"], *run["args"]],
            "enabled": True,
        }
        if run["env"]:
            entry["environment"] = run["env"]
    return json.dumps(
        {"$schema": "https://opencode.ai/config.json", "mcp": {key_for(name): entry}},
        indent=2,
    )


def render_continue(name: str, run: dict) -> str:
    """Continue takes a YAML list. Emitted by hand — no stdlib YAML writer, and
    a dependency for eight lines of output would not pay for itself."""
    if run["kind"] == "remote":
        command, args = "npx", ["-y", "mcp-remote", run["url"]]
        env = {}
    else:
        command, args, env = run["command"], run["args"], run["env"]

    lines = ["mcpServers:", f"  - name: {key_for(name)}", f"    command: {command}"]
    if args:
        lines.append("    args:")
        lines.extend(f"      - {argument}" for argument in args)
    if env:
        lines.append("    env:")
        lines.extend(f"      {variable}: ''" for variable in env)
    return "\n".join(lines)


def render_vscode(name: str, run: dict, registry: str) -> str:
    """VS Code is the one client that repoints its whole gallery, so the config
    is not per-server at all — the server below is then discoverable in-product
    with no further entry."""
    del run
    return json.dumps({"McpGalleryServiceUrl": registry}, indent=2)


def render(client: str, name: str, run: dict, registry: str) -> str:
    if client == "claude-desktop":
        return render_claude_desktop(name, run)
    if client == "cursor":
        return render_cursor(name, run)
    if client == "inspector":
        return render_inspector(name, run)
    if client == "opencode":
        return render_opencode(name, run)
    if client == "continue":
        return render_continue(name, run)
    if client == "vscode":
        return render_vscode(name, run, registry)
    raise Unsupported(f"unknown client {client!r}")


TARGET_FILE = {
    "claude-desktop": "claude_desktop_config.json",
    "cursor": "~/.cursor/mcp.json (or .cursor/mcp.json for one project)",
    "vscode": "enterprise policy — repoints the whole MCP gallery, not one server",
    "continue": "~/.continue/config.yaml",
    "opencode": "~/.config/opencode/opencode.json (or ./opencode.json)",
    "inspector": "any file, passed as --config",
}


# ---------------------------------------------------------------------------

def selftest() -> int:
    """Both record shapes the live registry actually serves, rendered for every
    client. Catches a template that stopped producing parseable config — which
    is the whole failure mode, since nobody reads these before pasting them."""
    remote = {"name": "io.example/remote", "remotes": [{"url": "https://x.example/mcp",
                                                        "type": "streamable-http"}]}
    npm = {
        "name": "io.example/pkg",
        "packages": [{"registryType": "npm", "identifier": "thing-mcp", "version": "1.2.3",
                      "transport": {"type": "stdio"},
                      "environmentVariables": [{"name": "API_KEY", "isSecret": True}]}],
    }

    for record in (remote, npm):
        run = launch(record)
        for client in CLIENTS:
            out = render(client, record["name"], run, DEFAULT_REGISTRY)
            assert out.strip(), f"{client} rendered nothing for {record['name']}"
            if client != "continue":  # the only non-JSON target
                json.loads(out)

    # A remote server must never reach Claude Desktop as a bare url — that shape
    # is silently skipped by the client, which looks like the server is broken.
    desktop = json.loads(render_claude_desktop("io.example/remote", launch(remote)))
    entry = desktop["mcpServers"]["io.example-remote"]
    assert "url" not in entry, "Claude Desktop cannot take a bare url; must bridge via mcp-remote"
    assert entry["args"][-1] == "https://x.example/mcp"

    # A declared secret must arrive empty, never invented.
    cursor = json.loads(render_cursor("io.example/pkg", launch(npm)))
    assert cursor["mcpServers"]["io.example-pkg"]["env"] == {"API_KEY": ""}

    # Two servers whose names share a tail segment must not collide — keying on
    # the last segment would have both land on "mcp" and silently overwrite.
    first = json.loads(render_cursor("ac.inference.sh/mcp", launch(remote)))
    second = json.loads(render_cursor("agency.goji/mcp", launch(remote)))
    assert set(first["mcpServers"]) != set(second["mcpServers"]), "config keys collide"

    # An unmappable package type is refused, not guessed into a broken command.
    try:
        stdio_command({"registryType": "nuget", "identifier": "x", "version": "1"})
    except Unsupported:
        pass
    else:  # pragma: no cover
        raise AssertionError("an unknown registryType must be refused, not guessed")

    print("selftest ok — 2 record shapes x 6 clients")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("name", nargs="?", help="registry server name, e.g. ac.inference.sh/mcp")
    parser.add_argument("--version", default="latest")
    parser.add_argument("--client", choices=(*CLIENTS, "all"), default="all")
    parser.add_argument("--registry", default=DEFAULT_REGISTRY)
    parser.add_argument("--from-file", help="read the record from a file instead of the network")
    parser.add_argument("--selftest", action="store_true")
    arguments = parser.parse_args()

    if arguments.selftest:
        return selftest()
    if not arguments.name:
        parser.error("a server name is required")

    if arguments.from_file:
        with open(arguments.from_file, encoding="utf-8") as handle:
            record = json.load(handle)
        record = record.get("server", record)
    else:
        record = fetch(arguments.registry, arguments.name, arguments.version)

    try:
        run = launch(record)
    except Unsupported as error:
        print(f"cannot configure {arguments.name}: {error}", file=sys.stderr)
        return 1

    targets = CLIENTS if arguments.client == "all" else (arguments.client,)
    for client in targets:
        try:
            body = render(client, arguments.name, run, arguments.registry)
        except Unsupported as error:
            print(f"# {client}: {error}", file=sys.stderr)
            return 1
        print(f"# ---- {client} — {TARGET_FILE[client]}")
        print(body)
        print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
