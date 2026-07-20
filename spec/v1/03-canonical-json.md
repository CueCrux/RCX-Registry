# 3. Canonical JSON

`rcx-spec/v1` · traces to grounding §2 (`crates/rcx-registry-ingest/src/lib.rs:150-180`).

Canonical JSON is the deterministic JSON **string** used as the hashing input for the snapshot-set digest, the per-server reconciliation hash, and the publisher declaration hash (§4, §6). It is a compact, key-sorted rendering with no insignificant whitespace. Vectors: [`vectors/canonical-json.json`](vectors/canonical-json.json).

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

**Duplicate member names on input — last-wins (parse rule).** Canonical JSON is
computed over a *parsed* JSON value, so duplicate object member names are already
resolved before rendering. The reference parser (`serde_json::Value`) keeps the
**last** occurrence of a repeated key and discards all earlier ones. An
implementation parsing a canonical-JSON *input* document that contains duplicate
member names **MUST** apply the same **last-wins** collapse before canonicalising;
the canonical output then contains the key exactly once, with the last value.
(Vector: `canonical-json` `duplicate-object-key-last-wins` renders
`{"a":1,"a":2}` → `{"a":2}`.) The output never contains duplicate keys; contrast
canonical **CBOR**, whose encoder *retains* represented duplicates in stable order
(§2.4).

## 3.2 String escaping

Strings **MUST** be escaped exactly as the reference `serde_json` serializer (pinned `serde_json 1.0.139`, `canonicalize_json` delegates every string and object key to `serde_json::to_string`, `ingest lib.rs:155,171`). The emitted forms are byte-for-byte:

- Two-character named escapes are used for exactly these seven code points — **and no others**:

  | Code point | Escape |
  |---|---|
  | `U+0008` backspace | `\b` |
  | `U+0009` tab | `\t` |
  | `U+000A` line feed | `\n` |
  | `U+000C` form feed | `\f` |
  | `U+000D` carriage return | `\r` |
  | `U+0022` quotation mark | `\"` |
  | `U+005C` reverse solidus | `\\` |

- Every **other** control character in `U+0000..U+001F` (i.e. all of `U+0000..U+001F` except the five named controls above) is escaped as `\u00XX` where `XX` is the two **lowercase**-hex digits of the code point — e.g. `U+0000` → `\u0000`, `U+000B` → `\u000b`, `U+001F` → `\u001f`. The `\u` form is **never** used for a code point that has a named escape, and the hex letters are **lowercase** (`a`–`f`), never uppercase.
- **All other characters** — including forward slash `/` (**not** escaped), `U+007F` DEL (**not** escaped), and every non-ASCII scalar — are emitted as their **raw UTF-8** bytes, never `\u`-escaped.

An implementation **MUST** reproduce these exact forms; substituting uppercase hex, `\uXXXX` for a named-escape code point, or escaping `/` produces different bytes and a different hash. (Vector: `canonical-json` `string-escaping` carries `\b\f\n\r\t`, `\u0000` (lowercase), an unescaped `/`, `\"`, and `\\`; grounding §2.2.)

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

Numbers are rendered by `serde_json`'s number formatting with **no reformatting beyond parse→display**. The behavior below is pinned to `serde_json 1.0.139` (which formats integers with `itoa 1.0.18` and floats with `ryu 1.0.23`), so an implementer can reproduce it without a Rust dependency.

**Integer domain.** A JSON numeric literal is treated as an **exact integer** iff it has no fractional part or exponent **and** its value lies in `[i64::MIN, u64::MAX]` = `[-9223372036854775808, 18446744073709551615]` (the reference parses these into `serde_json::Number`'s `i64` or `u64` slot). An exact integer **MUST** be rendered as bare decimal digits — full precision, a leading `-` only for negatives, **no** `+`, **no** leading zeros — and **MUST NOT** be coerced to floating point. (Vector: `canonical-json` `integer-boundaries` renders both `i64::MIN` and `u64::MAX` exactly.) A numeric literal whose magnitude is an integer **outside** `[i64::MIN, u64::MAX]` is not exactly representable by the reference: it is parsed as an `f64` and rendered by the **float rule** below (lossy). v1 pins this production fallback; such out-of-domain integers are outside the exact-integer domain and their rendered value is whatever the `f64` round-trip yields.

**Float rule (shortest round-trip binary64).** Every non-integer number, and any out-of-domain integer literal, is rendered by the reference `binary64` formatter (`ryu 1.0.23`, invoked via `Number::to_string`) as the **shortest decimal string that round-trips to the same IEEE-754 `binary64` value**. For a finite value `v`:

- **Sign / zero:** a leading `-` for negative values; the sign of zero is preserved, so `-0.0` renders `-0.0` and `+0.0` renders `0.0`. (Non-finite values do not occur — the reference never emits `NaN`/`Infinity` in canonical JSON; a literal whose magnitude overflows `binary64` to infinity is **rejected at JSON-parse time**, see **Out-of-range literals** below.)
- Let `digits` be the shortest decimal significand (an integer of `length` decimal digits) and `k` the power of ten with `v = ±digits × 10^k`; set `kk = length + k` (so `10^(kk−1) ≤ |v| < 10^kk`; `kk` is the number of digits left of the decimal point).
  - **Shortest-digit selection & tie-break (self-contained, no Rust dependency needed).** `digits` is the **shortest**-length decimal significand for which `±digits × 10^k` **round-trips** to the exact source `binary64` (i.e. parsing the rendered string back with round-to-nearest-even yields the identical 64-bit value). When more than one shortest-length significand round-trips, pick the one **closest** to the true real value of the `binary64`. If the true value is **exactly halfway** between the two closest shortest candidates — the discarded tail is exactly one half-ULP of the last retained digit — round to the candidate whose **last digit is even** (round-half-to-even). This is exactly the `ryu 1.0.23` rule: in `ryu-1.0.23/src/d2s.rs:253-258`, when the removed tail is exactly `5000…0` (`vr_is_trailing_zeros && last_removed_digit == 5`) the truncated value `vr` is kept iff `vr` is even (`vr % 2 == 0` forces `last_removed_digit = 4`, suppressing the increment), otherwise `vr` is incremented to its even neighbour. Non-halfway cases round to nearest by the same `last_removed_digit >= 5` test.
- **Positional** notation is used **iff `−5 < kk ≤ 16`**:
  - integer-valued in range (`k ≥ 0`): all `digits`, then `kk − length` trailing `0`s, then a **mandatory** `.0` — e.g. `1.0`, and input `1e3` → `1000.0`, `1234×10^7` → `12340000000.0`.
  - `0 < kk` with a fractional part: the decimal point falls inside `digits` — e.g. `12.34`.
  - `−5 < kk ≤ 0`: `0.`, then `−kk` leading `0`s, then `digits` — e.g. `0.001234`.
- **Scientific** notation (lowercase `e`) is used **otherwise** (`kk > 16` or `kk ≤ −5`): first digit, `.`, the remaining digits (the `.` and remainder omitted when `length == 1`), `e`, then the exponent `kk − 1` written with a `-` for negatives and **no** `+` for positives, minimum digits — e.g. `1.234e33`, `1e30`, `1.5e-8`.

An integer-valued float therefore **always** carries a trailing `.0`, preserving the integer/float distinction on the wire (`1` ≠ `1.0`).

**Out-of-range literals (overflow) — rejected, never `Infinity`.** A numeric literal whose magnitude exceeds the finite `binary64` range — an out-of-range exponent such as `1e400`, or an integer literal larger than `f64::MAX` (≈`1.8e308`) — is **not** representable and is **rejected at JSON-parse time**. `serde_json 1.0.139` returns a `NumberOutOfRange` error rather than producing `Infinity`: its `f64_from_parts` computes the value and, on `f.is_infinite()`, errors (`serde_json-1.0.139/src/de.rs:631-632` in the default build, `:663-664` under `float_roundtrip`; a wildly out-of-range exponent overflows the exponent accumulator first and errors in `parse_exponent_overflow` `:867,892-893`). Because the deserializer fails, such a literal **never reaches canonicalisation** — the whole document fails to parse and **no** canonical string, hash, or receipt is produced. This is identical for the canonical-JSON path here and for numbers inside a `capability_graph` ([04-hashing.md §4.5](04-hashing.md)), since both parse through the same `serde_json` deserializer.

**Number determinism (OQ-5 — resolved, implementation-pinned).** The snapshot set hashes **upstream** server JSON through this `serde_json` parse→render, so the canonical string is a function of the pinned renderer's number formatting, not of the raw upstream bytes (e.g. `1e3` re-renders to `1000.0`, `1.0` stays `1.0`, integers stay integers). v1 **freezes** canonical-JSON numbers to exactly this behavior — it is normative, not provisional. An implementation **MUST** reproduce the algorithm above (integer/float distinction preserved, full `[i64::MIN, u64::MAX]` precision, negative zero preserved, the `−5 < kk ≤ 16` positional/scientific threshold) and rely on the vectors to detect any drift. A stricter explicit number-normalisation rule is deferred to a future revision. (grounding §2.4; vectors: `canonical-json` `integers-versus-floats`, `negative-zero`, `integer-boundaries`; `hashes` `float-one`, `negative-zero`.)

## 3.5 What canonical JSON is computed over

For a mirrored server, canonical JSON is computed over the **`server` object only** (the upstream envelope's `server` field), **not** the surrounding `_meta` envelope. (grounding §4). For a publisher declaration, it is computed over the **entire fetched declaration document**. (grounding §3 row 4)
