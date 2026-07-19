# 3. Canonical JSON

`rcx-spec/v1` · traces to grounding §2 (`crates/rcx-registry-ingest/src/lib.rs:150-180`).

Canonical JSON is the deterministic JSON **string** used as the hashing input for the snapshot-set digest, the per-server reconciliation hash, and the publisher declaration hash (§4, §6). It is a compact, key-sorted rendering with no insignificant whitespace. Vectors: `vectors/json/*`.

> There are two JSON renderers in the reference. The **hashing** one is defined here (ingest `canonicalize_json`). A second renderer (crown `to_canonical_json`) exists only to reproduce shared RCX-Protocol session-plan fixtures and is **not** used to hash any registry artifact; it is described in grounding §2.1 and is **out of scope** for hashing. When this spec says "canonical JSON", it means the renderer in this section.

## 3.1 Production

`canonicalJSON(value)` produces a UTF-8 string with **no whitespace** between tokens, defined recursively over the JSON value:

| JSON value | Output |
|---|---|
| `null` | `null` |
| boolean | `true` / `false` |
| number | the number's canonical decimal text (§3.4) |
| string | a JSON-escaped, double-quoted string (§3.2) |
| array | `[` + elements joined by `,` (each recursively rendered, **order preserved**) + `]` |
| object | `{` + members joined by `,` + `}`, where each member is `<canonicalJSON(key)>:<canonicalJSON(value)>` and members are ordered by §3.3 |

There is **no space** after `:` or `,`. Object keys are themselves rendered as JSON strings (quoted + escaped).

Example (grounding §2.2):
`{"b":2,"a":{"z":true,"m":["x",{"k":1,"a":2}]}}` → `{"a":{"m":["x",{"a":2,"k":1}],"z":true},"b":2}`

## 3.2 String escaping

Strings **MUST** be escaped as standard JSON (the reference delegates to `serde_json`): `"` → `\"`, `\` → `\\`, control characters `U+0000..U+001F` via `\b \t \n \f \r` or `\u00XX`, and all other characters (including non-ASCII) emitted as their raw UTF-8. Implementations **MUST** match RFC 8259 minimal escaping; forward slash `/` is **not** escaped.

**No Unicode normalization** is applied at any point. NFC/NFD forms are preserved exactly as received, so `"é"` (`U+00E9`) and `"é"` (`U+0065 U+0301`) are **distinct** strings and produce **different** canonical bytes and hashes. An implementation **MUST NOT** normalise (NFC/NFD/NFKC/NFKD) strings or keys. (Vectors: `canonical-json` `unicode-astral-and-combining`, `hashes` `unicode-combining` vs `unicode-precomposed`; grounding Resolutions 2026-07-19.)

## 3.3 Object key ordering — content-first

Object members **MUST** be ordered by **unsigned bytewise (UTF-8) comparison of the key content** (i.e. plain lexicographic string order), applied recursively at every object depth.

This is **content-first**, and it **differs from canonical CBOR's length-first order** (§2.4). For the same two keys:

| Keys | Canonical **JSON** order (§3.3) | Canonical **CBOR** order (§2.4) |
|---|---|---|
| `"b"`, `"aa"` | `"aa"` before `"b"` (`'a' < 'b'`) | `"b"` before `"aa"` (len 1 < len 2) |
| `"budget"`, `"model"` | `"budget"` before `"model"` | `"model"` before `"budget"` (len 5 < 6) |

This ordering is the reference's **Rust `String`/`str` comparison** — equivalently, ordering by **Unicode scalar value** (for well-formed UTF-8, byte-order equals code-point order). It is **NOT** RFC 8785 / JCS ordering, which sorts by **UTF-16 code units**. The two agree across the Basic Multilingual Plane but **diverge for supplementary (astral, `≥ U+10000`) characters**: in UTF-16 an astral character is a surrogate pair whose high surrogate (`0xD800–0xDBFF`) sorts *below* BMP characters in `U+E000–U+FFFF`, so RFC 8785 would order an astral key *before* such a key while this spec orders it *after*. An implementer **MUST NOT** substitute an RFC 8785 canonicaliser. (Vector: `canonical-json` `object-key-ordering` places `😀` (`U+1F600`) **after** `""`; grounding Resolutions 2026-07-19 — ingest `lib.rs:165-166`, crown `canonical.rs:317-318`.)

An implementer **MUST NOT** reuse a single key-ordering routine for both the JSON (content-first) and CBOR (length-first, §2.4) forms.

## 3.4 Numbers

Numbers are rendered by their canonical decimal text with **no reformatting beyond parse→display**:
- Integers, including the full unsigned 64-bit range up to `18446744073709551615` (`2^64−1`), **MUST** be rendered as bare integers and **MUST** preserve full precision. An implementation **MUST NOT** coerce large integers to floating point. (Vector: `006-edge-large-uints`.)
- Non-integer numbers are rendered in the shortest decimal form that the reference (`serde_json`) produces.

**Number determinism (OQ-5 — resolved, implementation-pinned).** The snapshot set hashes **upstream** server JSON through a `serde_json` parse→`Display` re-render, so the canonical string is a function of the renderer's number formatting, not of the raw upstream bytes (e.g. `1e3` re-renders to `1000.0`, `1.0` stays `1.0`, integers stay integers). v1 **freezes** canonical-JSON numbers to exactly this parse-then-render behavior: it is normative, not provisional. An implementation **MUST** reproduce the reference `serde_json` number formatting (integer/float distinction preserved, full `u64` precision, negative zero preserved) and rely on the vectors to detect any drift. A stricter explicit number-normalisation rule is deferred to a future revision. (grounding §2.4; vectors: `canonical-json` `integers-versus-floats`, `negative-zero`, `integer-boundaries`.)

## 3.5 What canonical JSON is computed over

For a mirrored server, canonical JSON is computed over the **`server` object only** (the upstream envelope's `server` field), **not** the surrounding `_meta` envelope. (grounding §4). For a publisher declaration, it is computed over the **entire fetched declaration document**. (grounding §3 row 4)
