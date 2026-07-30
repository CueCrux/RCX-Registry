"""Canonical JSON and canonical CBOR per rcx-spec/v1 §2 and §3.

Written from the spec text and pinned by the conformance vectors. This is a
*separate* implementation from ``spec/v1/reimpl/reimpl.py`` on purpose: that file
is M0's independent cross-check, and an auditor that becomes the product stops
being an auditor.

The one thing to hold in your head: **the two canonical forms sort map keys by
different rules.**

===============  ===================================================
Canonical CBOR   length-first — shorter keys before longer, then
(§2.4)           bytewise on content. ``"b"`` before ``"aa"``.
Canonical JSON   plain lexicographic on the key string, UTF-8
(§3.3)           code-unit order. ``"aa"`` before ``"b"``.
===============  ===================================================

Same keys, opposite order, one protocol. Getting this backwards produces bytes
that look plausible and hash to nothing anybody published.
"""

from __future__ import annotations

import json
import struct
from dataclasses import dataclass
from typing import Any, Union

__all__ = [
    "canonicalize_json",
    "encode_cbor",
    "decode_cbor",
    "CborUint",
    "CborBytes",
    "CborFloat",
    "CanonicalError",
]


class CanonicalError(Exception):
    """Malformed input, or a value the canonical form cannot represent."""


# ---------------------------------------------------------------------------
# Canonical JSON (§3)
# ---------------------------------------------------------------------------


def canonicalize_json(value: Any) -> str:
    """Render ``value`` as canonical JSON: compact, key-sorted, no whitespace.

    Object keys sort by plain code-unit order (§3.3) — *not* the length-first
    order canonical CBOR uses. This diverges from RFC 8785 for astral-plane keys,
    which is observed, frozen, and covered by the ``canonical-json`` vectors.
    """
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, (int, float)):
        return _json_number(value)
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    if isinstance(value, list):
        return "[" + ",".join(canonicalize_json(item) for item in value) + "]"
    if isinstance(value, dict):
        parts = []
        for key in sorted(value.keys()):
            if not isinstance(key, str):
                raise CanonicalError(f"object keys must be strings, got {type(key)}")
            encoded_key = json.dumps(key, ensure_ascii=False, separators=(",", ":"))
            parts.append(f"{encoded_key}:{canonicalize_json(value[key])}")
        return "{" + ",".join(parts) + "}"
    raise CanonicalError(f"cannot canonicalize {type(value)}")


def _json_number(value: Union[int, float]) -> str:
    """Match serde_json's rendering, which is what the vectors froze."""
    if isinstance(value, bool):  # bool is an int subclass; handled by caller
        raise CanonicalError("bool reached the number path")
    if isinstance(value, int):
        return str(value)
    if value != value or value in (float("inf"), float("-inf")):
        raise CanonicalError("non-finite numbers cannot be canonicalized")
    if value == int(value) and abs(value) < 1e16:
        # serde_json renders integral floats with a trailing .0 — and -0.0 keeps
        # its sign. `int(-0.0)` is `0`, so formatting through int silently drops
        # it and produces "0.0" for a value the vectors pin as "-0.0". The
        # conformance harness caught exactly this; math.copysign is how you ask
        # about the sign of a zero, because `-0.0 == 0.0` is True.
        import math

        sign = "-" if math.copysign(1.0, value) < 0 else ""
        return f"{sign}{abs(int(value))}.0"
    return repr(value)


# ---------------------------------------------------------------------------
# Canonical CBOR value model (§2.1)
# ---------------------------------------------------------------------------
#
# Python's native types cannot express the distinctions the value model needs:
# an unsigned integer is not a float, and a byte string is not text. bytes and
# str already separate cleanly, so only ints-vs-floats and explicit float width
# need wrappers.


@dataclass(frozen=True)
class CborUint:
    value: int

    def __post_init__(self):
        if self.value < 0 or self.value > 0xFFFF_FFFF_FFFF_FFFF:
            raise CanonicalError(f"uint out of range: {self.value}")


@dataclass(frozen=True)
class CborBytes:
    value: bytes


@dataclass(frozen=True)
class CborFloat:
    value: float


def encode_cbor(value: Any) -> bytes:
    out = bytearray()
    _write(value, out)
    return bytes(out)


def _write(value: Any, out: bytearray) -> None:
    if value is None:
        out.append(0xF6)
    elif value is True:
        out.append(0xF5)
    elif value is False:
        out.append(0xF4)
    elif isinstance(value, CborUint):
        _write_head(0, value.value, out)
    elif isinstance(value, int) and not isinstance(value, bool):
        # A bare int is taken as unsigned; negative integers are not in the
        # value model (§2.1 forbids major type 1).
        if value < 0:
            raise CanonicalError("negative integers are not in the canonical value model")
        _write_head(0, value, out)
    elif isinstance(value, (CborBytes, bytes, bytearray)):
        raw = value.value if isinstance(value, CborBytes) else bytes(value)
        _write_head(2, len(raw), out)
        out.extend(raw)
    elif isinstance(value, str):
        raw = value.encode("utf-8")
        _write_head(3, len(raw), out)
        out.extend(raw)
    elif isinstance(value, list):
        _write_head(4, len(value), out)
        for item in value:
            _write(item, out)
    elif isinstance(value, CborFloat) or isinstance(value, float):
        _write_float(value.value if isinstance(value, CborFloat) else value, out)
    elif isinstance(value, (dict, _OrderedMap)):
        _write_map(value, out)
    else:
        raise CanonicalError(f"cannot encode {type(value)}")


def _write_map(value: Any, out: bytearray) -> None:
    items = value.items() if isinstance(value, _OrderedMap) else list(value.items())
    pairs = []
    for key, item in items:
        if not isinstance(key, str):
            raise CanonicalError("CBOR map keys must be text strings (§2.4)")
        encoded_key = bytearray()
        raw = key.encode("utf-8")
        _write_head(3, len(raw), encoded_key)
        encoded_key.extend(raw)
        pairs.append((bytes(encoded_key), item))

    # Length-first ordering (§2.4): sorting by the *encoded* key bytes gives it
    # for free, because the head encodes length before content. Python's sort is
    # stable, which preserves input order for byte-identical (duplicate) keys as
    # §2.4 requires.
    pairs.sort(key=lambda pair: pair[0])

    _write_head(5, len(pairs), out)
    for encoded_key, item in pairs:
        out.extend(encoded_key)
        _write(item, out)


def _write_head(major: int, argument: int, out: bytearray) -> None:
    """Shortest-form head, big-endian argument (§2.2)."""
    base = major << 5
    if argument < 24:
        out.append(base | argument)
    elif argument <= 0xFF:
        out.append(base | 24)
        out.append(argument)
    elif argument <= 0xFFFF:
        out.append(base | 25)
        out.extend(struct.pack(">H", argument))
    elif argument <= 0xFFFF_FFFF:
        out.append(base | 26)
        out.extend(struct.pack(">I", argument))
    else:
        out.append(base | 27)
        out.extend(struct.pack(">Q", argument))


def _write_float(value: float, out: bytearray) -> None:
    """Shortest width that round-trips exactly (§2.5)."""
    if value != value or value in (float("inf"), float("-inf")):
        raise CanonicalError("non-finite floats MUST NOT be encoded (§2.5)")

    try:
        half = struct.pack(">e", value)
        if struct.unpack(">e", half)[0] == value and _same_sign(
            struct.unpack(">e", half)[0], value
        ):
            out.append(0xF9)
            out.extend(half)
            return
    except (OverflowError, struct.error):
        pass

    single = struct.pack(">f", value)
    if struct.unpack(">f", single)[0] == value and _same_sign(
        struct.unpack(">f", single)[0], value
    ):
        out.append(0xFA)
        out.extend(single)
        return

    out.append(0xFB)
    out.extend(struct.pack(">d", value))


def _same_sign(a: float, b: float) -> bool:
    """Distinguish -0.0 from 0.0, which ``==`` does not."""
    import math

    return math.copysign(1.0, a) == math.copysign(1.0, b)


# ---------------------------------------------------------------------------
# Decoding (§2.6)
# ---------------------------------------------------------------------------


class _OrderedMap:
    """A CBOR map as an ordered key/value list.

    Not a dict: the value model has no key-uniqueness invariant, and §2.4's
    stable tie-break for byte-identical keys only means something if duplicates
    survive decoding. A dict would silently collapse them and the re-encode
    round-trip check would then pass over bytes that differ from the input.
    """

    __slots__ = ("_pairs",)

    def __init__(self, pairs):
        self._pairs = list(pairs)

    def items(self):
        return list(self._pairs)

    def get(self, key, default=None):
        for name, value in self._pairs:
            if name == key:
                return value
        return default

    def __contains__(self, key):
        return any(name == key for name, _ in self._pairs)

    def replace(self, replacements: dict) -> "_OrderedMap":
        """Return a copy with the named keys' values replaced."""
        return _OrderedMap(
            (name, replacements[name] if name in replacements else value)
            for name, value in self._pairs
        )

    def __repr__(self):
        return f"_OrderedMap({self._pairs!r})"


def decode_cbor(data: bytes) -> Any:
    value, offset = _read(data, 0)
    if offset != len(data):
        raise CanonicalError(f"{len(data) - offset} trailing byte(s) after value")
    return value


def _read(data: bytes, offset: int):
    if offset >= len(data):
        raise CanonicalError("truncated input")
    initial = data[offset]
    major = initial >> 5
    minor = initial & 0x1F
    offset += 1

    if major == 7:
        if minor == 20:
            return False, offset
        if minor == 21:
            return True, offset
        if minor == 22:
            return None, offset
        if minor == 25:
            return CborFloat(struct.unpack(">e", data[offset : offset + 2])[0]), offset + 2
        if minor == 26:
            return CborFloat(struct.unpack(">f", data[offset : offset + 4])[0]), offset + 4
        if minor == 27:
            return CborFloat(struct.unpack(">d", data[offset : offset + 8])[0]), offset + 8
        raise CanonicalError(f"unsupported simple value {minor}")

    argument, offset = _read_argument(data, offset, minor)

    if major == 0:
        return CborUint(argument), offset
    if major == 2:
        end = offset + argument
        if end > len(data):
            raise CanonicalError("truncated byte string")
        return CborBytes(data[offset:end]), end
    if major == 3:
        end = offset + argument
        if end > len(data):
            raise CanonicalError("truncated text string")
        return data[offset:end].decode("utf-8"), end
    if major == 4:
        items = []
        for _ in range(argument):
            item, offset = _read(data, offset)
            items.append(item)
        return items, offset
    if major == 5:
        pairs = []
        for _ in range(argument):
            key, offset = _read(data, offset)
            if not isinstance(key, str):
                raise CanonicalError("CBOR map keys must be text strings")
            item, offset = _read(data, offset)
            pairs.append((key, item))
        return _OrderedMap(pairs), offset

    raise CanonicalError(f"unsupported major type {major}")


def _read_argument(data: bytes, offset: int, minor: int):
    if minor < 24:
        return minor, offset
    if minor == 24:
        return data[offset], offset + 1
    if minor == 25:
        return struct.unpack(">H", data[offset : offset + 2])[0], offset + 2
    if minor == 26:
        return struct.unpack(">I", data[offset : offset + 4])[0], offset + 4
    if minor == 27:
        return struct.unpack(">Q", data[offset : offset + 8])[0], offset + 8
    raise CanonicalError(f"indefinite-length or reserved argument {minor} is not canonical")
