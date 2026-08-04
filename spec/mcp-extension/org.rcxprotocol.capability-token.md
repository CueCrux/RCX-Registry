# `org.rcxprotocol/capability-token` — an MCP extension

**Status:** Draft. Third-party extension, not an official MCP extension.
**Extension identifier:** `org.rcxprotocol/capability-token`
**Token spec:** `rcx-ct/1.0`, `rcx-ct/1.1` (delegation), `rcx-ct/1.2` (tier vocabulary)
**Minimum MCP revision:** `2026-07-28`
**Reference implementation:** [`Crux/crates/rcx-capability-token`](https://github.com/CueCrux/Crux/blob/main/crates/rcx-capability-token/src/lib.rs) (Rust, normative for wire bytes)

Requirement keywords **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, **MAY** are per
[RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) / [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174),
interpreted only when in ALL CAPS.

> **This is a draft.** It is published as a third-party extension under a vendor prefix we own.
> It has not been through the MCP SEP process and is not endorsed by the MCP maintainers. Nothing
> here should be read as claiming official status. See [§10](#10-status-and-path-to-official-status).

---

## 1. Motivation

MCP revision `2026-07-28` removed protocol-level sessions and the `initialize` handshake
([SEP-2567](https://github.com/modelcontextprotocol/modelcontextprotocol/pull/2567),
[SEP-2575](https://github.com/modelcontextprotocol/modelcontextprotocol/pull/2575)). Every request
now carries its own protocol version and client capabilities, and servers needing cross-call state
pass explicit handles as ordinary arguments.

That removes the natural home for a session-scoped credential. A server that wants to authorize
*this call* rather than *this connection* has no protocol-level place to say so, and no way to tell
a client "I require per-request capability grants" before the client sends a request that will be
refused.

This extension fills that gap. It defines how a server advertises that it requires RCX capability
tokens, how a client declares it can supply them, how the token travels, and what a refusal looks
like.

## 2. What an RCX capability token is

A short-lived, signed, scope-limited grant. It names a tenant, a set of permitted capabilities on a
named backend, permitted data-egress classes, required attestations, a validity window, and credit
terms. It is minted by an issuer the verifier trusts, and is verifiable offline against the issuer's
key.

It answers *"may this call happen?"*. It does **not** answer *"who is calling?"*.

## 3. Authorization, never authentication

> **This section is normative and is the most important rule in this document.**

A capability token is an authorization layer that sits **on top of** authentication. It **MUST NOT**
be treated as a substitute for it.

- A server **MUST NOT** grant, skip, or weaken authentication on the basis that a capability-token
  header is present.
- A server **MUST** establish the caller's identity by its own authentication mechanism first, and
  **MUST** derive the tenant/principal from that authenticated context — never from a
  client-supplied field in the request body or from the token alone.
- A server that cannot validate a presented token (for example because the feature is disabled)
  **MUST** refuse the request. It **MUST NOT** ignore the token and continue.

**Why this is stated so forcefully.** An implementation of this protocol exempted a route from
authentication whenever the capability-token header was *present* — presence, not validity — while
validating the token only under a feature flag that defaulted off. The result was an unauthenticated
cross-tenant read: the header opened the door, and with the flag off nothing stood behind it. The
three rules above each independently close that hole. Implementers **SHOULD** write a regression
test for each.

## 4. Negotiation

### 4.1 Server declaration

A server supporting this extension **MUST** advertise it in the `extensions` field of its
`ServerCapabilities`, returned from
[`server/discover`](https://modelcontextprotocol.io/specification/2026-07-28/server/discover):

```json
{
  "resultType": "complete",
  "supportedVersions": ["2026-07-28"],
  "capabilities": {
    "tools": {},
    "extensions": {
      "org.rcxprotocol/capability-token": {
        "required": true,
        "header": "x-rcx-capability-token",
        "backendId": "hosted.example.com",
        "specVersions": ["rcx-ct/1.0", "rcx-ct/1.2"],
        "issuerKeysUrl": "https://example.com/.well-known/rcx-issuer-keys"
      }
    }
  },
  "_meta": {
    "io.modelcontextprotocol/serverInfo": { "name": "ExampleServer", "version": "1.0.0" }
  },
  "ttlMs": 3600000,
  "cacheScope": "public"
}
```

### 4.2 Server settings object

| Field | Type | Required | Meaning |
|---|---|---|---|
| `required` | boolean | yes | `true`: requests without a valid token are refused. `false`: the server accepts tokens but does not demand them (observe-mode rollout). |
| `header` | string | no | Header the server reads. Defaults to `x-rcx-capability-token`. Servers **SHOULD** omit this unless they read a non-default name. |
| `backendId` | string | yes | The `backend_id` a token's `backends[]` entry **MUST** match for this server. |
| `specVersions` | string[] | yes | Accepted `spec_version` values. A client **SHOULD NOT** present a token whose version is absent from this list. |
| `issuerKeysUrl` | string | no | Where a verifier may fetch issuer public keys. Absent means keys are distributed out of band. |

`required` is the field that matters for interop: it is what lets a client know, before sending a
request, whether an absent token is fatal.

### 4.3 Client declaration

A client able to supply capability tokens **MUST** declare the extension in
`_meta["io.modelcontextprotocol/clientCapabilities"].extensions` on each request:

```json
{
  "_meta": {
    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
    "io.modelcontextprotocol/clientCapabilities": {
      "extensions": { "org.rcxprotocol/capability-token": {} }
    }
  }
}
```

The client settings object has no fields in this version; an empty object declares support.

## 5. Token carriage

The token **MUST** travel as an HTTP request header whose value is the token's wire form:
base64 of the canonical JSON encoding. Implementations **MUST** accept both standard base64 and
base64url (see [§9](#9-interoperability-notes)).

Canonical header:

```
X-Rcx-Capability-Token: <base64(JSON)>
```

Servers **MAY** additionally accept `X-Rcx-Token`. Where both are present the canonical name
**MUST** win, so a caller that has migrated is never silently served by an alias. Servers **MAY**
accept `Authorization: Bearer` **only** where no other bearer scheme is in use on the same surface;
where the surface carries session JWTs or API bearer tokens, a server **MUST NOT** accept the token
there, because the two become indistinguishable at the same header.

### 5.1 The token MUST NOT be carried via `x-mcp-header`

MCP `2026-07-28` added [`x-mcp-header`](https://modelcontextprotocol.io/specification/2026-07-28/server/tools#x-mcp-header),
which mirrors a designated tool *parameter* into an HTTP header. It **MUST NOT** be used to carry a
capability token. Three reasons, each independently sufficient:

1. The annotated value must be a tool parameter reachable from the `inputSchema` root, so the token
   becomes **model-visible and model-chosen**. A credential the model selects is not a credential.
2. Servers **MUST** reject when header and body disagree (`-32020 HeaderMismatch`), so the token
   cannot stay header-only — it is necessarily duplicated into the JSON-RPC body.
3. An omitted argument omits the header, silently downgrading a credential to an optional field.

The token is injected by the client's transport layer and **MUST NOT** appear in tool arguments.

## 6. Refusals

A server that refuses **MUST** return a RefusalReceipt rather than a bare HTTP status. A refusal is
a signed artifact: it records what was denied and why, so that "who could touch what, when" remains
answerable from receipts.

A RefusalReceipt **MUST** carry a `reason_code` from the `denied:*` vocabulary:

| Reason code | Meaning |
|---|---|
| `denied:token_missing` | Required token absent |
| `denied:token_invalid` | Malformed or unparseable |
| `denied:signature_invalid` | Signature verification failed |
| `denied:token_expired` | Outside its validity window |
| `denied:backend_not_permitted` | No `backends[]` entry matches this server's `backendId` |
| `denied:capability_not_permitted` | Capability not in the permitted set |
| `denied:egress_not_permitted` | Requested egress class exceeds the permitted set |
| `denied:attestation_missing` | A required attestation was not presented |
| `denied:insufficient_credit` | Credit terms not satisfiable |
| `denied:feature_disabled` | Server cannot validate tokens right now (see [§3](#3-authorization-never-authentication)) |

### 6.1 JSON-RPC error codes

Where a refusal surfaces as a JSON-RPC error, the code **MUST** fall within `-32000..-32019`, the
range MCP leaves implementation-defined. Implementations **MUST NOT** use `-32020..-32099`, which
`2026-07-28` reserves for the MCP specification itself (`-32020` `HeaderMismatch`, `-32021`
`MissingRequiredClientCapability`, `-32022` `UnsupportedProtocolVersion`).

The reason code, not the numeric code, is the interoperable signal.

## 7. Caching

Any result whose content depended on a capability token **MUST** be returned with
`cacheScope: "private"`. `2026-07-28` requires `ttlMs` and `cacheScope` on `tools/list`,
`prompts/list`, `resources/list`, `resources/read`, and `resources/templates/list` results.
Marking a token-scoped result `"public"` permits a shared intermediary to serve one principal's
result to another.

## 8. Graceful degradation

- A server with `required: false` **MUST** serve clients that do not declare the extension, applying
  whatever authorization it would apply in the token's absence.
- A server with `required: true` **MUST** refuse a request from a client that has not declared the
  extension, with `denied:token_missing`. It **SHOULD** do so via `server/discover` visibility rather
  than surprising the client at call time.
- A client **MUST** tolerate a server that does not declare the extension, and **MUST NOT** send the
  token header to such a server — a credential sent to a party that never asked for it is a
  credential leak.

## 9. Interoperability notes

**Base64 alphabet.** Two reference implementations differ: one mints with standard base64, another
decodes with base64url. These are distinct alphabets (`+/` versus `-_`). Interoperation currently
holds only because common runtime decoders accept either. Implementations **MUST** accept both and
**SHOULD** pin this with a test; a strict decoder on one side breaks cross-surface tokens with no
other symptom.

**Clock skew.** Verifiers **SHOULD** allow a small skew allowance when evaluating `expires_at`, and
**MUST** treat the token as expired beyond it. This extension does not define the allowance.

## 10. Status and path to official status

This is a **third-party** extension published under a vendor prefix we control, per MCP's guidance
that third parties use a reversed domain name they own. Publishing it requires no approval from the
MCP maintainers, and it carries no official standing.

Becoming an official extension would require the SEP Extensions Track: a SEP in the main MCP
repository, at least one reference implementation in an official SDK, and sponsorship by a working or
interest group, with Core Maintainers holding final authority. No such submission has been made.

Until that changes, documentation and marketing **MUST NOT** describe this as an official or adopted
MCP extension.

## 11. Versioning

Per MCP extension guidance, additive changes **SHOULD** be expressed as new optional fields in the
settings object rather than a new identifier. A breaking change — removing or renaming a field,
changing a field's type, or altering existing semantics — requires a new identifier
(`org.rcxprotocol/capability-token-v2`).

Adding an accepted header alias is **not** breaking, provided the canonical name continues to be
accepted and continues to win.
