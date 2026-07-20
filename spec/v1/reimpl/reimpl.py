#!/usr/bin/env python3
"""Independent RCX Protocol Spec v1 reimplementation and vector runner.

This module is intentionally derived only from the Markdown and JSON files under
``spec-v1``.  It does not use cbor2 to produce canonical bytes.  Running the
file executes every checked-in vector and rewrites ``REPORT.md``.

Runtime dependencies permitted by the exercise:
  * blake3
  * cryptography

The public helpers are usable independently of the vector runner:
  * canonical_cbor_encode / canonical_cbor_decode
  * canonical_json / parse_json
  * blake3_256 / declaration_hash / canonical_server_hash
  * receipt_hash / receipt_signature_preimage / verify_receipt
  * snapshot_set_digest / check_snapshot_chain / check_enrichment_chain
"""

from __future__ import annotations

import argparse
import json
import math
import struct
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Iterator, Sequence

from blake3 import blake3
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


ROOT = Path(__file__).resolve().parent
VECTOR_DIR = ROOT / "spec-v1" / "vectors"
ZERO_HASH = b"\x00" * 32
ZERO_SIGNATURE = b"\x00" * 64
U64_MAX = (1 << 64) - 1
I64_MIN = -(1 << 63)


class ConformanceError(ValueError):
    """The supplied value or byte string is outside the v1 canonical model."""


@dataclass(frozen=True)
class UInt:
    """An explicitly unsigned CBOR integer."""

    value: int

    def __post_init__(self) -> None:
        if isinstance(self.value, bool) or not isinstance(self.value, int):
            raise TypeError("UInt requires an int")
        if not 0 <= self.value <= U64_MAX:
            raise ConformanceError("CBOR unsigned integer is outside u64")


@dataclass(frozen=True)
class Float64:
    """A CBOR float whose logical source value is an exact IEEE-754 binary64."""

    bits: int

    def __post_init__(self) -> None:
        if not 0 <= self.bits <= U64_MAX:
            raise ConformanceError("Float64 bits are outside 64 bits")

    @classmethod
    def from_float(cls, value: float) -> "Float64":
        return cls(int.from_bytes(struct.pack(">d", value), "big"))

    @property
    def value(self) -> float:
        return struct.unpack(">d", self.bits.to_bytes(8, "big"))[0]


@dataclass(frozen=True)
class CborMap:
    """A text-keyed CBOR map represented as pairs so duplicates survive."""

    entries: tuple[tuple[str, Any], ...]

    def __init__(self, entries: Iterable[tuple[str, Any]]) -> None:
        normalized = tuple(entries)
        for key, _ in normalized:
            if not isinstance(key, str):
                raise ConformanceError("canonical CBOR map keys must be text")
        object.__setattr__(self, "entries", normalized)

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "CborMap":
        return cls(value.items())

    def replace(self, **updates: Any) -> "CborMap":
        """Replace existing unique keys, rejecting absent or duplicate targets."""

        remaining = dict(updates)
        seen: set[str] = set()
        output: list[tuple[str, Any]] = []
        for key, value in self.entries:
            if key in updates:
                if key in seen:
                    raise ConformanceError(f"cannot replace duplicate key {key!r}")
                output.append((key, updates[key]))
                seen.add(key)
                remaining.pop(key, None)
            else:
                output.append((key, value))
        if remaining:
            names = ", ".join(sorted(remaining))
            raise ConformanceError(f"map lacks required field(s): {names}")
        return CborMap(output)

    def get_unique(self, key: str) -> Any:
        values = [value for candidate, value in self.entries if candidate == key]
        if len(values) != 1:
            raise ConformanceError(
                f"expected exactly one {key!r} field, found {len(values)}"
            )
        return values[0]


def _head(major: int, argument: int) -> bytes:
    """Encode a CBOR major-type head in its shortest form (Spec v1 §2.2)."""

    if not 0 <= major <= 7:
        raise ValueError("invalid CBOR major type")
    if not 0 <= argument <= U64_MAX:
        raise ConformanceError("CBOR head argument is outside u64")
    prefix = major << 5
    if argument < 24:
        return bytes((prefix | argument,))
    if argument <= 0xFF:
        return bytes((prefix | 24, argument))
    if argument <= 0xFFFF:
        return bytes((prefix | 25,)) + argument.to_bytes(2, "big")
    if argument <= 0xFFFF_FFFF:
        return bytes((prefix | 26,)) + argument.to_bytes(4, "big")
    return bytes((prefix | 27,)) + argument.to_bytes(8, "big")


def _f64_bits(value: float) -> bytes:
    return struct.pack(">d", value)


def _roundtrips_at_format(value: float, fmt: str) -> tuple[bool, bytes]:
    try:
        payload = struct.pack(fmt, value)
    except (OverflowError, struct.error):
        return False, b""
    back = struct.unpack(fmt, payload)[0]
    return _f64_bits(back) == _f64_bits(value), payload


def _encode_float(value: float) -> bytes:
    if not math.isfinite(value):
        raise ConformanceError("non-finite CBOR float")
    exact, payload = _roundtrips_at_format(value, ">e")
    if exact:
        return b"\xf9" + payload
    exact, payload = _roundtrips_at_format(value, ">f")
    if exact:
        return b"\xfa" + payload
    return b"\xfb" + struct.pack(">d", value)


def canonical_cbor_encode(value: Any) -> bytes:
    """Encode the exact v1 CBOR value model without delegating to cbor2."""

    if isinstance(value, UInt):
        return _head(0, value.value)
    if isinstance(value, bool):
        return b"\xf5" if value else b"\xf4"
    if value is None:
        return b"\xf6"
    if isinstance(value, Float64):
        return _encode_float(value.value)
    if isinstance(value, float):
        return _encode_float(value)
    if isinstance(value, int):
        if value < 0:
            raise ConformanceError("negative integers are not in the v1 CBOR model")
        return _head(0, value)
    if isinstance(value, (bytes, bytearray, memoryview)):
        body = bytes(value)
        return _head(2, len(body)) + body
    if isinstance(value, str):
        try:
            body = value.encode("utf-8", "strict")
        except UnicodeEncodeError as exc:
            raise ConformanceError("CBOR text is not valid Unicode/UTF-8") from exc
        return _head(3, len(body)) + body
    if isinstance(value, (list, tuple)):
        return _head(4, len(value)) + b"".join(
            canonical_cbor_encode(item) for item in value
        )
    if isinstance(value, dict):
        value = CborMap.from_dict(value)
    if isinstance(value, CborMap):
        # Python's sort is stable, matching the normative equal-key tie rule in
        # §2.4: byte-identical encoded keys retain their input order.
        keyed: list[tuple[bytes, int, Any]] = []
        for index, (key, item) in enumerate(value.entries):
            encoded_key = canonical_cbor_encode(key)
            keyed.append((encoded_key, index, item))
        keyed.sort(key=lambda row: row[0])
        body = b"".join(
            encoded_key + canonical_cbor_encode(item)
            for encoded_key, _index, item in keyed
        )
        return _head(5, len(keyed)) + body
    raise ConformanceError(f"unsupported CBOR value type: {type(value).__name__}")


class _CborDecoder:
    def __init__(self, data: bytes, *, strict_map_order: bool) -> None:
        self.data = data
        self.offset = 0
        self.strict_map_order = strict_map_order

    def _take(self, size: int) -> bytes:
        end = self.offset + size
        if end > len(self.data):
            raise ConformanceError("truncated CBOR item")
        result = self.data[self.offset:end]
        self.offset = end
        return result

    def _argument(self, info: int) -> int:
        if info < 24:
            return info
        if info in (28, 29, 30, 31):
            raise ConformanceError(f"reserved additional-info value {info}")
        widths = {24: 1, 25: 2, 26: 4, 27: 8}
        if info not in widths:
            raise ConformanceError(f"unsupported additional-info value {info}")
        value = int.from_bytes(self._take(widths[info]), "big")
        minimum = {24: 24, 25: 0x100, 26: 0x1_0000, 27: 0x1_0000_0000}
        if value < minimum[info]:
            raise ConformanceError("non-minimal integer/length head")
        return value

    @staticmethod
    def _check_finite(value: float) -> None:
        if not math.isfinite(value):
            raise ConformanceError("non-finite CBOR float")

    def item(self) -> Any:
        start = self.offset
        first = self._take(1)[0]
        major, info = first >> 5, first & 0x1F
        if info in (28, 29, 30, 31):
            raise ConformanceError(f"reserved additional-info value {info}")

        if major == 7:
            if info == 20:
                return False
            if info == 21:
                return True
            if info == 22:
                return None
            if info == 25:
                value = struct.unpack(">e", self._take(2))[0]
                self._check_finite(value)
                return Float64.from_float(value)
            if info == 26:
                value = struct.unpack(">f", self._take(4))[0]
                self._check_finite(value)
                if _roundtrips_at_format(value, ">e")[0]:
                    raise ConformanceError("non-shortest float encoding")
                return Float64.from_float(value)
            if info == 27:
                value = struct.unpack(">d", self._take(8))[0]
                self._check_finite(value)
                if _roundtrips_at_format(value, ">e")[0] or _roundtrips_at_format(
                    value, ">f"
                )[0]:
                    raise ConformanceError("non-shortest float encoding")
                return Float64.from_float(value)
            raise ConformanceError("simple value is outside the v1 CBOR model")

        argument = self._argument(info)
        if major == 0:
            return UInt(argument)
        if major == 1:
            raise ConformanceError("negative integers are outside the v1 CBOR model")
        if major == 2:
            return self._take(argument)
        if major == 3:
            raw = self._take(argument)
            try:
                return raw.decode("utf-8", "strict")
            except UnicodeDecodeError as exc:
                raise ConformanceError("invalid UTF-8 CBOR text") from exc
        if major == 4:
            return [self.item() for _ in range(argument)]
        if major == 5:
            entries: list[tuple[str, Any]] = []
            prior_key_bytes: bytes | None = None
            seen: set[str] = set()
            for _ in range(argument):
                key_start = self.offset
                key = self.item()
                key_end = self.offset
                if not isinstance(key, str):
                    raise ConformanceError("non-text map key")
                encoded_key = self.data[key_start:key_end]
                if self.strict_map_order:
                    if prior_key_bytes is not None and encoded_key <= prior_key_bytes:
                        raise ConformanceError("out-of-order or duplicate map key")
                    if key in seen:
                        raise ConformanceError("duplicate map key")
                prior_key_bytes = encoded_key
                seen.add(key)
                entries.append((key, self.item()))
            return CborMap(entries)
        if major == 6:
            raise ConformanceError("CBOR tags are outside the v1 value model")
        raise ConformanceError(f"unsupported CBOR major type at offset {start}")


def canonical_cbor_decode(
    data: bytes | bytearray | memoryview, *, strict_map_order: bool = False
) -> Any:
    """Decode and validate v1 canonical CBOR.

    By default out-of-order/duplicate maps are accepted and retained, matching
    the explicitly permitted v1 accept-and-normalise behavior.  Passing
    ``strict_map_order=True`` applies the optional SHOULD-level rejection.
    """

    decoder = _CborDecoder(bytes(data), strict_map_order=strict_map_order)
    result = decoder.item()
    if decoder.offset != len(decoder.data):
        raise ConformanceError(f"trailing bytes at offset {decoder.offset}")
    return result


# ---------------------------------------------------------------------------
# Canonical JSON (Spec v1 §3)


@dataclass(frozen=True)
class JsonNumber:
    """A serde_json-like distinction between integer and binary64 numbers."""

    kind: str
    value: int | float
    source_integral_literal: bool = False

    def __post_init__(self) -> None:
        if self.kind not in {"integer", "float"}:
            raise ValueError("JsonNumber kind must be integer or float")
        if self.source_integral_literal and self.kind != "float":
            raise ValueError("only a float fallback can retain integral-token origin")


def _parse_json_integer(token: str) -> JsonNumber:
    value = int(token, 10)
    if I64_MIN <= value <= U64_MAX:
        return JsonNumber("integer", value)
    # §3.4 pins serde_json's lossy binary64 fallback for integral tokens outside
    # the exact [i64::MIN, u64::MAX] domain.
    try:
        fallback = float(token)
    except (OverflowError, ValueError) as exc:
        raise ConformanceError(
            "JSON number is outside the finite binary64 domain"
        ) from exc
    if not math.isfinite(fallback):
        raise ConformanceError("JSON number is outside the finite binary64 domain")
    return JsonNumber("float", fallback, source_integral_literal=True)


def _parse_json_float(token: str) -> JsonNumber:
    value = float(token)
    if not math.isfinite(value):
        raise ConformanceError("non-finite JSON number")
    return JsonNumber("float", value)


def _reject_json_constant(token: str) -> None:
    raise ConformanceError(f"non-standard JSON number {token!r}")


def _last_wins_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    # §3.1 normatively requires parser-level last-wins duplicate collapse.
    result: dict[str, Any] = {}
    for key, value in pairs:
        result[key] = value
    return result


def parse_json(source: str | bytes | bytearray) -> Any:
    """Parse JSON while retaining integer-vs-float and negative-zero state."""

    try:
        return json.loads(
            source,
            parse_int=_parse_json_integer,
            parse_float=_parse_json_float,
            parse_constant=_reject_json_constant,
            object_pairs_hook=_last_wins_object,
        )
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ConformanceError(f"invalid JSON: {exc}") from exc


def _json_escape(value: str) -> str:
    """Minimal serde_json-compatible escaping, with raw non-ASCII UTF-8."""

    short = {
        '"': '\\"',
        "\\": "\\\\",
        "\x08": "\\b",
        "\x09": "\\t",
        "\x0a": "\\n",
        "\x0c": "\\f",
        "\x0d": "\\r",
    }
    output = ['"']
    for character in value:
        codepoint = ord(character)
        if 0xD800 <= codepoint <= 0xDFFF:
            raise ConformanceError("JSON string contains an unpaired surrogate")
        if character in short:
            output.append(short[character])
        elif codepoint <= 0x1F:
            # §3.2 fixes \u00XX with lowercase hexadecimal for every remaining
            # U+0000..U+001F control.
            output.append(f"\\u{codepoint:04x}")
        else:
            output.append(character)
    output.append('"')
    return "".join(output)


def _json_float_text(value: float) -> str:
    """Render finite binary64 using the §3.4 positional/scientific thresholds.

    Python supplies the shortest round-tripping significand.  This function
    deliberately does not retain Python's presentation thresholds, exponent
    plus sign, or exponent zero padding; those are reconstructed from the
    normative ``digits``, ``k``, and ``kk`` rules.
    """

    if not math.isfinite(value):
        raise ConformanceError("non-finite JSON number")
    negative = math.copysign(1.0, value) < 0
    if value == 0.0:
        return "-0.0" if negative else "0.0"

    shortest = repr(abs(value)).lower()
    if "e" in shortest:
        coefficient, exponent_text = shortest.split("e", 1)
        exponent = int(exponent_text, 10)
    else:
        coefficient = shortest
        exponent = 0

    if "." in coefficient:
        whole, fraction = coefficient.split(".", 1)
    else:
        whole, fraction = coefficient, ""
    digits = (whole + fraction).lstrip("0")
    k = exponent - len(fraction)
    while len(digits) > 1 and digits.endswith("0"):
        digits = digits[:-1]
        k += 1

    length = len(digits)
    kk = length + k
    if -5 < kk <= 16:
        if k >= 0:
            body = digits + ("0" * k) + ".0"
        elif kk > 0:
            body = digits[:kk] + "." + digits[kk:]
        else:
            body = "0." + ("0" * -kk) + digits
    else:
        significand = digits[0]
        if length > 1:
            significand += "." + digits[1:]
        body = f"{significand}e{kk - 1}"
    return ("-" if negative else "") + body


def canonical_json(value: Any) -> str:
    """Render the compact, recursively UTF-8-key-sorted hashing JSON form."""

    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, JsonNumber):
        if value.kind == "integer":
            return str(value.value)
        return _json_float_text(float(value.value))
    if isinstance(value, int):
        if I64_MIN <= value <= U64_MAX:
            return str(value)
        try:
            fallback = float(value)
        except (OverflowError, ValueError) as exc:
            raise ConformanceError(
                "JSON number is outside the finite binary64 domain"
            ) from exc
        if not math.isfinite(fallback):
            raise ConformanceError("JSON number is outside the finite binary64 domain")
        return _json_float_text(fallback)
    if isinstance(value, float):
        return _json_float_text(value)
    if isinstance(value, str):
        return _json_escape(value)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(canonical_json(item) for item in value) + "]"
    if isinstance(value, dict):
        for key in value:
            if not isinstance(key, str):
                raise ConformanceError("JSON object keys must be strings")
            try:
                key.encode("utf-8", "strict")
            except UnicodeEncodeError as exc:
                raise ConformanceError("JSON key is not valid Unicode/UTF-8") from exc
        keys = sorted(value, key=lambda item: item.encode("utf-8"))
        return "{" + ",".join(
            _json_escape(key) + ":" + canonical_json(value[key]) for key in keys
        ) + "}"
    raise ConformanceError(f"unsupported JSON value type: {type(value).__name__}")


def canonicalize_json(source: str | bytes | bytearray) -> str:
    return canonical_json(parse_json(source))


def json_value_to_cbor(value: Any) -> Any:
    """Map an enrichment/capability JSON value into the v1 CBOR value model.

    Non-negative integral JSON numbers become CBOR uints.  Non-integral finite
    numbers of either sign become CBOR floats.  Only negative integers are
    rejected by §4.5.  Object member order is irrelevant because the encoder
    sorts it.
    """

    if value is None or isinstance(value, (bool, str)):
        return value
    if isinstance(value, JsonNumber):
        if value.kind == "integer":
            integer = int(value.value)
            if integer < 0:
                raise ConformanceError("negative integer in capability_graph")
            return UInt(integer)
        if value.source_integral_literal:
            raise ConformanceError(
                "integral capability number outside the specified integer domain"
            )
        floating = float(value.value)
        if not math.isfinite(floating):
            raise ConformanceError("non-finite enrichment number")
        return Float64.from_float(floating)
    if isinstance(value, int) and not isinstance(value, bool):
        if value < 0:
            raise ConformanceError("negative integer in capability_graph")
        return UInt(value)
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ConformanceError("non-finite enrichment number")
        return Float64.from_float(value)
    if isinstance(value, (list, tuple)):
        return [json_value_to_cbor(item) for item in value]
    if isinstance(value, dict):
        return CborMap((key, json_value_to_cbor(item)) for key, item in value.items())
    raise ConformanceError(
        f"unsupported enrichment JSON type: {type(value).__name__}"
    )


# ---------------------------------------------------------------------------
# Hashing, receipt verification, snapshots, and chains (Spec v1 §§4–6)


def blake3_256(data: bytes | bytearray | memoryview) -> bytes:
    return blake3(bytes(data)).digest(length=32)


def hash_json_string(digest: bytes) -> str:
    if len(digest) != 32:
        raise ConformanceError("BLAKE3 digest must be 32 bytes")
    return "blake3:" + digest.hex()


def parse_hash_json_string(value: str) -> bytes:
    text = value[7:] if value.startswith("blake3:") else value
    if len(text) != 64 or any(character not in "0123456789abcdef" for character in text):
        raise ConformanceError("hash string is not 64 lowercase hexadecimal chars")
    return bytes.fromhex(text)


def declaration_hash(document: str | bytes | bytearray | Any) -> bytes:
    if isinstance(document, (str, bytes, bytearray)):
        rendered = canonicalize_json(document)
    else:
        rendered = canonical_json(document)
    return blake3_256(rendered.encode("utf-8"))


def _utf8(text: str, field: str) -> bytes:
    if not isinstance(text, str):
        raise ConformanceError(f"{field} must be text")
    try:
        return text.encode("utf-8", "strict")
    except UnicodeEncodeError as exc:
        raise ConformanceError(f"{field} is not valid Unicode/UTF-8") from exc


def _snapshot_identifier_utf8(text: str, field: str) -> bytes:
    encoded = _utf8(text, field)
    if b"\x00" in encoded:
        raise ConformanceError(f"{field} contains U+0000 outside the v1 input domain")
    return encoded


def canonical_server_hash(name: str, version: str, canonical_server_json: str) -> bytes:
    preimage = (
        _snapshot_identifier_utf8(name, "server name")
        + b"\x00"
        + _snapshot_identifier_utf8(version, "server version")
        + b"\x00"
        + _utf8(canonical_server_json, "canonical server JSON")
    )
    return blake3_256(preimage)


def snapshot_entry_frame(name: str, version: str, canonical_server_json: str) -> bytes:
    return (
        _snapshot_identifier_utf8(name, "server name")
        + b"\x00"
        + _snapshot_identifier_utf8(version, "server version")
        + b"\x00"
        + _utf8(canonical_server_json, "canonical server JSON")
        + b"\xff"
    )


def snapshot_set_digest(entries: Iterable[dict[str, str] | tuple[str, str, str]]) -> bytes:
    normalized: list[tuple[bytes, bytes, str, str, str]] = []
    for entry in entries:
        if isinstance(entry, dict):
            name = entry["name"]
            version = entry["version"]
            canonical_server_json = entry["canonical_json"]
        else:
            name, version, canonical_server_json = entry
        normalized.append(
            (
                _snapshot_identifier_utf8(name, "server name"),
                _snapshot_identifier_utf8(version, "server version"),
                name,
                version,
                canonical_server_json,
            )
        )
    # Stable sorting preserves input order for equal (name, version) keys.
    normalized.sort(key=lambda item: (item[0], item[1]))
    hasher = blake3()
    for _name_bytes, _version_bytes, name, version, canonical_server_json in normalized:
        hasher.update(snapshot_entry_frame(name, version, canonical_server_json))
    return hasher.digest(length=32)


def _require_receipt_map(receipt: CborMap | dict[str, Any]) -> CborMap:
    if isinstance(receipt, dict):
        receipt = CborMap.from_dict(receipt)
    if not isinstance(receipt, CborMap):
        raise ConformanceError("receipt must be a text-keyed CBOR map")
    return receipt


RECEIPT_FIELD_SETS: dict[str, frozenset[str]] = {
    "RegistrySnapshot": frozenset(
        {
            "event_id",
            "snapshot_id",
            "scraped_at",
            "server_count",
            "snapshot_merkle_root",
            "previous_snapshot_hash",
            "upstream_registry_uri",
            "upstream_snapshot_etag",
            "changes",
            "receipt_hash",
            "receipt_signature",
            "signer_kid",
        }
    ),
    "EntryAutoEnriched": frozenset(
        {
            "event_id",
            "server_name",
            "snapshot_id",
            "auto_enrichment_bytes",
            "receipt_hash",
            "receipt_signature",
            "signer_kid",
        }
    ),
    "EntryEnriched": frozenset(
        {
            "event_id",
            "server_name",
            "publisher_passport",
            "declared_uri",
            "declared_hash",
            "enrichment_bytes",
            "supersedes_prior",
            "receipt_hash",
            "receipt_signature",
            "signer_kid",
        }
    ),
    "AttestationAccepted": frozenset(
        {
            "event_id",
            "attestation_id",
            "server_name",
            "issuer_passport",
            "type",
            "attestation_hash",
            "attestation_bytes",
            "receipt_hash",
            "receipt_signature",
            "signer_kid",
        }
    ),
    "AttestationRevoked": frozenset(
        {
            "event_id",
            "attestation_id",
            "revoker_passport",
            "reason",
            "revoked_at",
            "revocation_signature",
            "receipt_hash",
            "receipt_signature",
            "signer_kid",
        }
    ),
    "PublisherRightsVerified": frozenset(
        {
            "event_id",
            "publisher_passport",
            "namespace",
            "verification_method",
            "verified_at",
            "receipt_hash",
            "receipt_signature",
            "signer_kid",
        }
    ),
}


def _is_uint(value: Any) -> bool:
    if isinstance(value, UInt):
        return True
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= U64_MAX


def _expect_bytes(receipt: CborMap, name: str, size: int | None = None) -> bytes:
    value = receipt.get_unique(name)
    if not isinstance(value, bytes) or (size is not None and len(value) != size):
        suffix = "" if size is None else f"[{size}]"
        raise ConformanceError(f"receipt field {name} must be bytes{suffix}")
    return value


def _expect_text(receipt: CborMap, name: str, *, nullable: bool = False) -> None:
    value = receipt.get_unique(name)
    if nullable and value is None:
        return
    if not isinstance(value, str):
        raise ConformanceError(f"receipt field {name} must be text")


def identify_receipt_type(receipt: CborMap | dict[str, Any]) -> str:
    receipt_map = _require_receipt_map(receipt)
    keys = [key for key, _value in receipt_map.entries]
    if len(keys) != len(set(keys)):
        raise ConformanceError("well-formed receipts cannot contain duplicate keys")
    key_set = frozenset(keys)
    matches = [name for name, fields in RECEIPT_FIELD_SETS.items() if fields == key_set]
    if len(matches) != 1:
        raise ConformanceError("receipt field set does not match one v1 receipt type")
    return matches[0]


def validate_receipt(receipt: CborMap | dict[str, Any]) -> str:
    """Validate one of the six exact logical field sets and wire field types."""

    receipt_map = _require_receipt_map(receipt)
    receipt_type = identify_receipt_type(receipt_map)
    _expect_bytes(receipt_map, "event_id", 16)
    _expect_bytes(receipt_map, "receipt_hash", 32)
    _expect_bytes(receipt_map, "receipt_signature", 64)
    _expect_text(receipt_map, "signer_kid")

    if receipt_type == "RegistrySnapshot":
        _expect_bytes(receipt_map, "snapshot_id", 16)
        _expect_bytes(receipt_map, "snapshot_merkle_root", 32)
        previous = receipt_map.get_unique("previous_snapshot_hash")
        if previous is not None and (not isinstance(previous, bytes) or len(previous) != 32):
            raise ConformanceError("previous_snapshot_hash must be null or bytes[32]")
        _expect_text(receipt_map, "upstream_registry_uri")
        _expect_text(receipt_map, "upstream_snapshot_etag", nullable=True)
        for name in ("scraped_at", "server_count"):
            if not _is_uint(receipt_map.get_unique(name)):
                raise ConformanceError(f"receipt field {name} must be uint")
        changes = receipt_map.get_unique("changes")
        if isinstance(changes, dict):
            changes = CborMap.from_dict(changes)
        if not isinstance(changes, CborMap):
            raise ConformanceError("changes must be a map")
        if identify_keys := [key for key, _value in changes.entries]:
            if len(identify_keys) != len(set(identify_keys)):
                raise ConformanceError("changes cannot contain duplicate keys")
        if frozenset(key for key, _value in changes.entries) != frozenset(
            {"added", "removed", "modified"}
        ):
            raise ConformanceError("changes has the wrong field set")
        for name in ("added", "removed", "modified"):
            if not _is_uint(changes.get_unique(name)):
                raise ConformanceError(f"changes.{name} must be uint")
    elif receipt_type == "EntryAutoEnriched":
        _expect_bytes(receipt_map, "snapshot_id", 16)
        _expect_bytes(receipt_map, "auto_enrichment_bytes")
        _expect_text(receipt_map, "server_name")
    elif receipt_type == "EntryEnriched":
        _expect_bytes(receipt_map, "declared_hash", 32)
        _expect_bytes(receipt_map, "enrichment_bytes")
        prior = receipt_map.get_unique("supersedes_prior")
        if prior is not None and (not isinstance(prior, bytes) or len(prior) != 32):
            raise ConformanceError("supersedes_prior must be null or bytes[32]")
        for name in ("server_name", "publisher_passport", "declared_uri"):
            _expect_text(receipt_map, name)
    elif receipt_type == "AttestationAccepted":
        _expect_bytes(receipt_map, "attestation_id", 16)
        _expect_bytes(receipt_map, "attestation_hash", 32)
        _expect_bytes(receipt_map, "attestation_bytes")
        for name in ("server_name", "issuer_passport", "type"):
            _expect_text(receipt_map, name)
    elif receipt_type == "AttestationRevoked":
        _expect_bytes(receipt_map, "attestation_id", 16)
        _expect_bytes(receipt_map, "revocation_signature", 64)
        _expect_text(receipt_map, "revoker_passport")
        _expect_text(receipt_map, "reason", nullable=True)
        if not _is_uint(receipt_map.get_unique("revoked_at")):
            raise ConformanceError("receipt field revoked_at must be uint")
    elif receipt_type == "PublisherRightsVerified":
        for name in ("publisher_passport", "namespace", "verification_method"):
            _expect_text(receipt_map, name)
        if not _is_uint(receipt_map.get_unique("verified_at")):
            raise ConformanceError("receipt field verified_at must be uint")
    return receipt_type


def receipt_hash_preimage(receipt: CborMap | dict[str, Any]) -> bytes:
    receipt_map = _require_receipt_map(receipt)
    validate_receipt(receipt_map)
    zeroed = receipt_map.replace(
        receipt_hash=ZERO_HASH,
        receipt_signature=ZERO_SIGNATURE,
        signer_kid=None,
    )
    return canonical_cbor_encode(zeroed)


def receipt_hash(receipt: CborMap | dict[str, Any]) -> bytes:
    return blake3_256(receipt_hash_preimage(receipt))


def receipt_signature_preimage(receipt: CborMap | dict[str, Any]) -> bytes:
    receipt_map = _require_receipt_map(receipt)
    validate_receipt(receipt_map)
    return canonical_cbor_encode(receipt_map.replace(receipt_signature=ZERO_SIGNATURE))


def verify_receipt_signature(
    receipt: CborMap | dict[str, Any], public_key: bytes
) -> bool:
    receipt_map = _require_receipt_map(receipt)
    signature = receipt_map.get_unique("receipt_signature")
    if not isinstance(signature, bytes) or len(signature) != 64:
        return False
    if signature == ZERO_SIGNATURE:
        return False
    if len(public_key) != 32:
        return False
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            signature, receipt_signature_preimage(receipt_map)
        )
    except (InvalidSignature, ValueError):
        return False
    return True


def verify_receipt(receipt: CborMap | dict[str, Any], public_key: bytes) -> bool:
    """Combined vector rule: validate shape/hash, then verify path-A signature.

    §5.6 makes independent receipt-hash recomputation a SHOULD for signature-only
    verification; the vector corpus explicitly requires the combined check used
    here.  ``verify_receipt_signature`` exposes the signature-only path.
    """

    try:
        receipt_map = _require_receipt_map(receipt)
        validate_receipt(receipt_map)
        stored_hash = receipt_map.get_unique("receipt_hash")
        if not isinstance(stored_hash, bytes) or len(stored_hash) != 32:
            return False
        if receipt_hash(receipt_map) != stored_hash:
            return False
    except (ConformanceError, TypeError, ValueError):
        return False
    return verify_receipt_signature(receipt_map, public_key)


def sign_receipt(receipt: CborMap | dict[str, Any], private_key_seed: bytes) -> CborMap:
    """Deterministic Ed25519 helper used only to compare computable vectors."""

    if len(private_key_seed) != 32:
        raise ConformanceError("Ed25519 private seed must be 32 bytes")
    receipt_map = _require_receipt_map(receipt)
    signature = Ed25519PrivateKey.from_private_bytes(private_key_seed).sign(
        receipt_signature_preimage(receipt_map)
    )
    return receipt_map.replace(receipt_signature=signature)


def check_snapshot_chain(receipts: Sequence[CborMap | dict[str, Any]]) -> list[bool]:
    """Check a complete, genesis-first snapshot chain in chronological order."""

    results: list[bool] = []
    previous_root: bytes | None = None
    previous_scraped_at: int | None = None
    for index, receipt in enumerate(receipts):
        receipt_map = _require_receipt_map(receipt)
        if validate_receipt(receipt_map) != "RegistrySnapshot":
            raise ConformanceError("snapshot chain contains a non-snapshot receipt")
        link = receipt_map.get_unique("previous_snapshot_hash")
        link_valid = link is None if index == 0 else link == previous_root
        root = receipt_map.get_unique("snapshot_merkle_root")
        if not isinstance(root, bytes) or len(root) != 32:
            link_valid = False
        scraped_value = receipt_map.get_unique("scraped_at")
        scraped_at = scraped_value.value if isinstance(scraped_value, UInt) else scraped_value
        if (
            not isinstance(scraped_at, int)
            or isinstance(scraped_at, bool)
            or (previous_scraped_at is not None and scraped_at < previous_scraped_at)
        ):
            link_valid = False
        results.append(link_valid)
        previous_root = root
        previous_scraped_at = scraped_at
    return results


def check_enrichment_chain(receipts: Sequence[CborMap | dict[str, Any]]) -> list[bool]:
    """Check a complete, genesis-first EntryEnriched supersession chain."""

    results: list[bool] = []
    previous_receipt_hash: bytes | None = None
    for index, receipt in enumerate(receipts):
        receipt_map = _require_receipt_map(receipt)
        if validate_receipt(receipt_map) != "EntryEnriched":
            raise ConformanceError("enrichment chain contains a different receipt type")
        link = receipt_map.get_unique("supersedes_prior")
        results.append(link is None if index == 0 else link == previous_receipt_hash)
        current_hash = receipt_map.get_unique("receipt_hash")
        if not isinstance(current_hash, bytes) or len(current_hash) != 32:
            results[-1] = False
        previous_receipt_hash = current_hash
    return results


# ---------------------------------------------------------------------------
# Conformance-vector adapter and report generation


RULES = {
    "format": (
        "spec-v1/vectors/README.md:100-108 — “An SDK should treat each case as an "
        "independent assertion: 1. Check the top-level format value before "
        "interpreting a file.”"
    ),
    "cbor_exact": (
        "spec-v1/01-conventions.md:46 — “A conformant encoder, given the same "
        "logical value, MUST emit the exact same octet sequence as the reference.”"
    ),
    "cbor_head": (
        "spec-v1/02-canonical-cbor.md:26-36 — “The argument (a length, or the "
        "integer value itself) uses the shortest form” and “An encoder MUST use "
        "the shortest head that fits n.”"
    ),
    "cbor_map": (
        "spec-v1/02-canonical-cbor.md:53-64 — “Keys MUST be sorted by the bytewise "
        "lexicographic order of their encoded form (the text head bytes followed "
        "by the UTF-8 content)”; equal encoded keys retain stable input order."
    ),
    "cbor_float": (
        "spec-v1/02-canonical-cbor.md:68-74 — “For a finite value x, the encoder "
        "MUST choose the shortest width that round-trips x exactly” and "
        "“Round-trips exactly means bit-equal on conversion back to the source "
        "double.”"
    ),
    "cbor_decode": (
        "spec-v1/02-canonical-cbor.md:80-86 — “A decoder that validates canonical "
        "form MUST reject” trailing bytes, non-minimal heads, non-shortest or "
        "non-finite floats, non-text map keys, and reserved/indefinite markers."
    ),
    "json": (
        "spec-v1/03-canonical-json.md:11-22 — “canonicalJSON(value) produces a "
        "UTF-8 string with no whitespace between tokens,” recursively, with "
        "arrays preserved and object members ordered by §3.3."
    ),
    "json_escape": (
        "spec-v1/03-canonical-json.md:41-60 — exact named escapes and lowercase "
        "\\u00xx controls are required, with raw non-ASCII UTF-8, no escaped slash, "
        "and no Unicode normalization."
    ),
    "json_numbers": (
        "spec-v1/03-canonical-json.md:77-95 — implementations MUST preserve the "
        "integer/float distinction, exact integer domain, negative zero, shortest "
        "binary64 digits, and the stated positional/scientific thresholds."
    ),
    "blake3": (
        "spec-v1/04-hashing.md:7 — “Implementations MUST use BLAKE3 with no "
        "keying, no derive-key context, and default 32-byte output.”"
    ),
    "declaration": (
        "spec-v1/04-hashing.md:40-43 — “declared_hash = BLAKE3( "
        "canonicalJSON(declaration_document) )” computed over the entire fetched "
        "declaration document."
    ),
    "receipt_hash": (
        "spec-v1/05-receipts.md:30-41 — receipt_hash hashes canonical CBOR with "
        "receipt_hash as 32 zero bytes, receipt_signature as 64 zero bytes, and "
        "signer_kid as CBOR Null; all other fields retain their real values."
    ),
    "receipt_signature": (
        "spec-v1/05-receipts.md:172-210 — reconstruct full canonical CBOR with "
        "only receipt_signature set to 64 zero bytes, retaining the real "
        "receipt_hash and signer_kid, then ed25519_verify; MUST NOT verify over "
        "the bare 32-byte receipt_hash."
    ),
    "snapshot": (
        "spec-v1/06-merkle-and-snapshots.md:29-49 — stable-sort by UTF-8 "
        "(name, version), retain duplicates, and hash one stream of "
        "name || 00 || version || 00 || canonical_json || ff frames."
    ),
    "server_hash": (
        "spec-v1/06-merkle-and-snapshots.md:60-67 — canonical_server_hash is "
        "BLAKE3(name || 00 || version || 00 || canonical_json) and omits the "
        "trailing ff."
    ),
    "snapshot_chain": (
        "spec-v1/06-merkle-and-snapshots.md:69-75 — previous_snapshot_hash equals "
        "the immediately prior snapshot_merkle_root/snapshot_hash, not the prior "
        "receipt_hash; it is Null for the first snapshot."
    ),
    "enrichment_chain": (
        "spec-v1/06-merkle-and-snapshots.md:79-81 — supersedes_prior is the "
        "receipt_hash of the prior EntryEnriched receipt, or Null."
    ),
}


@dataclass
class Check:
    vector_file: str
    case: str
    field: str
    expected: Any
    computed: Any
    citation: str

    @property
    def passed(self) -> bool:
        return self.expected == self.computed


class Recorder:
    def __init__(self) -> None:
        self.checks: list[Check] = []
        self.prose_guards_passed = 0

    def add(
        self,
        vector_file: str,
        case: str,
        field: str,
        expected: Any,
        computed: Any,
        rule: str,
    ) -> None:
        self.checks.append(
            Check(vector_file, case, field, expected, computed, RULES[rule])
        )

    def by_file(self, vector_file: str) -> list[Check]:
        return [check for check in self.checks if check.vector_file == vector_file]


def _load_vector(name: str) -> dict[str, Any]:
    with (VECTOR_DIR / name).open("r", encoding="utf-8") as handle:
        return json.load(handle)


EXPECTED_FORMATS = {
    "canonical-cbor.json": "rcx-protocol-spec-v1/canonical-cbor@1",
    "canonical-json.json": "rcx-protocol-spec-v1/canonical-json@1",
    "chains.json": "rcx-protocol-spec-v1/chains@1",
    "hashes.json": "rcx-protocol-spec-v1/hashes@1",
    "receipts.json": "rcx-protocol-spec-v1/receipts@1",
    "snapshot-merkle.json": "rcx-protocol-spec-v1/snapshot-merkle@1",
}


def _check_format(recorder: Recorder, filename: str, data: dict[str, Any]) -> None:
    recorder.add(
        filename,
        "file-metadata",
        "format",
        EXPECTED_FORMATS[filename],
        data.get("format"),
        "format",
    )


def _decoder_reason(error: ConformanceError) -> str:
    message = str(error)
    if "non-minimal" in message:
        return "non-minimal-integer-head"
    if "non-shortest float" in message:
        return "non-shortest-float"
    if "trailing bytes" in message:
        return "trailing-bytes"
    if "non-text map key" in message:
        return "non-text-map-key"
    if "reserved additional-info" in message:
        return "reserved-additional-info"
    return "unsupported-cbor"


def _typed_to_cbor(node: dict[str, Any]) -> Any:
    kind = node["type"]
    if kind == "uint":
        return UInt(int(node["value"], 10))
    if kind == "float":
        return Float64(int(node["f64_bits_hex"], 16))
    if kind == "bytes":
        return bytes.fromhex(node["hex"])
    if kind == "text":
        return node["value"]
    if kind == "array":
        return [_typed_to_cbor(item) for item in node["items"]]
    if kind == "map":
        return CborMap(
            (entry["key"], _typed_to_cbor(entry["value"]))
            for entry in node["entries"]
        )
    if kind == "bool":
        return node["value"]
    if kind == "null":
        return None
    raise ConformanceError(f"unknown typed CBOR node {kind!r}")


def _cbor_to_typed(value: Any) -> dict[str, Any]:
    if isinstance(value, UInt):
        return {"type": "uint", "value": str(value.value)}
    if isinstance(value, Float64):
        return {"type": "float", "f64_bits_hex": f"{value.bits:016x}"}
    if isinstance(value, bytes):
        return {"type": "bytes", "hex": value.hex()}
    if isinstance(value, str):
        return {"type": "text", "value": value, "utf8_hex": value.encode().hex()}
    if isinstance(value, list):
        return {"type": "array", "items": [_cbor_to_typed(item) for item in value]}
    if isinstance(value, CborMap):
        return {
            "type": "map",
            "entries": [
                {"key": key, "value": _cbor_to_typed(item)}
                for key, item in value.entries
            ],
        }
    if isinstance(value, bool):
        return {"type": "bool", "value": value}
    if value is None:
        return {"type": "null"}
    raise ConformanceError(f"cannot convert decoded type {type(value).__name__}")


def _typed_text_nodes(node: dict[str, Any], path: str = "input") -> Iterator[tuple[str, str, str]]:
    kind = node["type"]
    if kind == "text":
        yield path, node["utf8_hex"], node["value"].encode("utf-8").hex()
    elif kind == "array":
        for index, item in enumerate(node["items"]):
            yield from _typed_text_nodes(item, f"{path}.items[{index}]")
    elif kind == "map":
        for index, entry in enumerate(node["entries"]):
            yield from _typed_text_nodes(
                entry["value"], f"{path}.entries[{index}].value"
            )


def _plain_cbor(value: Any) -> Any:
    if isinstance(value, UInt):
        return value.value
    if isinstance(value, Float64):
        return value.value
    if isinstance(value, CborMap):
        result: dict[str, Any] = {}
        for key, item in value.entries:
            result[key] = _plain_cbor(item)
        return result
    if isinstance(value, list):
        return [_plain_cbor(item) for item in value]
    return value


BYTE_FIELDS = {
    "event_id",
    "snapshot_id",
    "attestation_id",
    "receipt_hash",
    "receipt_signature",
    "snapshot_merkle_root",
    "previous_snapshot_hash",
    "declared_hash",
    "attestation_hash",
    "revocation_signature",
    "supersedes_prior",
    "auto_enrichment_bytes",
    "enrichment_bytes",
    "attestation_bytes",
}
UINT_FIELDS = {
    "scraped_at",
    "verified_at",
    "revoked_at",
    "server_count",
}


def _receipt_from_vector_fields(fields: dict[str, Any]) -> CborMap:
    output: list[tuple[str, Any]] = []
    for external_name, value in fields.items():
        if external_name.endswith("_hex"):
            name = external_name[:-4]
            if name not in BYTE_FIELDS:
                raise ConformanceError(f"unexpected receipt hex field {external_name}")
            output.append((name, bytes.fromhex(value)))
        elif external_name in UINT_FIELDS:
            output.append((external_name, UInt(int(value, 10))))
        else:
            output.append((external_name, value))
    return CborMap(output)


def _hex_or_none(value: bytes | None) -> str | None:
    return None if value is None else value.hex()


def _run_cbor_vectors(recorder: Recorder) -> None:
    filename = "canonical-cbor.json"
    data = _load_vector(filename)
    _check_format(recorder, filename, data)
    for case in data["cases"]:
        case_id = case["id"]
        logical = _typed_to_cbor(case["input"])
        for path, expected_utf8, computed_utf8 in _typed_text_nodes(case["input"]):
            recorder.add(
                filename,
                case_id,
                f"{path}.utf8_hex",
                expected_utf8,
                computed_utf8,
                "cbor_exact",
            )
        encoded = canonical_cbor_encode(logical)
        rule = "cbor_float" if "float" in json.dumps(case["input"]) else "cbor_exact"
        if case_id in {"map-key-ordering-by-encoded-key", "duplicate-map-keys-retained"}:
            rule = "cbor_map"
        recorder.add(
            filename,
            case_id,
            "canonical_cbor_hex",
            case["canonical_cbor_hex"],
            encoded.hex(),
            rule,
        )
        decoded = canonical_cbor_decode(bytes.fromhex(case["canonical_cbor_hex"]))
        recorder.add(
            filename,
            case_id,
            "decoded",
            case["decoded"],
            _cbor_to_typed(decoded),
            "cbor_decode",
        )

    for case in data["decoder_rejections"]["cases"]:
        rejected = False
        reason = "accepted"
        try:
            canonical_cbor_decode(bytes.fromhex(case["input_cbor_hex"]))
        except ConformanceError as error:
            rejected = True
            reason = _decoder_reason(error)
        recorder.add(
            filename,
            case["id"],
            "must_reject",
            case["must_reject"],
            rejected,
            "cbor_decode",
        )
        recorder.add(
            filename,
            case["id"],
            "reason_code",
            case["reason_code"],
            reason,
            "cbor_decode",
        )


def _run_json_vectors(recorder: Recorder) -> None:
    filename = "canonical-json.json"
    data = _load_vector(filename)
    _check_format(recorder, filename, data)
    for case in data["cases"]:
        rendered = canonicalize_json(case["input_json"])
        rule = "json_numbers" if case["id"] in {
            "integers-versus-floats",
            "negative-zero",
            "integer-boundaries",
        } else "json"
        if case["id"] in {"string-escaping", "unicode-astral-and-combining"}:
            rule = "json_escape"
        recorder.add(
            filename,
            case["id"],
            "canonical_json",
            case["canonical_json"],
            rendered,
            rule,
        )
        recorder.add(
            filename,
            case["id"],
            "canonical_utf8_hex",
            case["canonical_utf8_hex"],
            rendered.encode("utf-8").hex(),
            rule,
        )


def _run_hash_vectors(recorder: Recorder) -> None:
    filename = "hashes.json"
    data = _load_vector(filename)
    _check_format(recorder, filename, data)
    recorder.add(
        filename,
        "file-metadata",
        "algorithm",
        "BLAKE3-256",
        data.get("algorithm"),
        "blake3",
    )
    equivalence: dict[str, list[bytes]] = {}
    for case in data["declaration_hash"]["cases"]:
        rendered = canonicalize_json(case["input_json"])
        preimage = rendered.encode("utf-8")
        digest = blake3_256(preimage)
        recorder.add(
            filename, case["id"], "canonical_json", case["canonical_json"], rendered, "json"
        )
        recorder.add(
            filename,
            case["id"],
            "hash_input_utf8_hex",
            case["hash_input_utf8_hex"],
            preimage.hex(),
            "declaration",
        )
        recorder.add(
            filename,
            case["id"],
            "digest_hex",
            case["digest_hex"],
            digest.hex(),
            "blake3",
        )
        group = case.get("equivalence_group")
        if group is not None:
            equivalence.setdefault(group, []).append(digest)
    for group, digests in equivalence.items():
        recorder.add(
            filename,
            f"equivalence_group:{group}",
            "all_digests_equal",
            True,
            len(set(digests)) == 1,
            "declaration",
        )

    for case in data["canonical_server_hash"]["cases"]:
        base = (
            case["name"].encode()
            + b"\x00"
            + case["version"].encode()
            + b"\x00"
            + case["canonical_json"].encode()
        )
        frame = snapshot_entry_frame(
            case["name"], case["version"], case["canonical_json"]
        )
        digest = canonical_server_hash(
            case["name"], case["version"], case["canonical_json"]
        )
        recorder.add(
            filename,
            case["id"],
            "hash_input_hex",
            case["hash_input_hex"],
            base.hex(),
            "server_hash",
        )
        recorder.add(
            filename,
            case["id"],
            "snapshot_entry_frame_hex",
            case["snapshot_entry_frame_hex"],
            frame.hex(),
            "snapshot",
        )
        recorder.add(
            filename,
            case["id"],
            "digest_hex",
            case["digest_hex"],
            digest.hex(),
            "server_hash",
        )


def _run_snapshot_vectors(recorder: Recorder) -> None:
    filename = "snapshot-merkle.json"
    data = _load_vector(filename)
    _check_format(recorder, filename, data)
    by_group: dict[str, list[bytes]] = {}
    for case in data["cases"]:
        root = snapshot_set_digest(case["input_order"])
        recorder.add(
            filename,
            case["id"],
            "server_count",
            case["server_count"],
            len(case["input_order"]),
            "snapshot",
        )
        recorder.add(
            filename,
            case["id"],
            "root_hex",
            case["root_hex"],
            root.hex(),
            "snapshot",
        )
        group = case.get("equivalence_group")
        if group is not None:
            by_group.setdefault(group, []).append(root)

    unique_equal = len(set(by_group["unique-permutation"])) == 1
    duplicate_different = len(set(by_group["duplicate-tie-order-sensitive"])) > 1
    recorder.add(
        filename,
        "invariants",
        "unique_permutation_roots_equal",
        data["invariants"]["unique_permutation_roots_equal"],
        unique_equal,
        "snapshot",
    )
    recorder.add(
        filename,
        "invariants",
        "same_key_different_payload_permutations_differ",
        data["invariants"]["same_key_different_payload_permutations_differ"],
        duplicate_different,
        "snapshot",
    )


def _run_receipt_vectors(recorder: Recorder) -> None:
    filename = "receipts.json"
    data = _load_vector(filename)
    _check_format(recorder, filename, data)
    seed = bytes.fromhex(data["test_key"]["seed_hex"])
    public = bytes.fromhex(data["test_key"]["public_key_hex"])
    derived_public = Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes_raw()
    recorder.add(
        filename,
        "test_key",
        "public_key_hex",
        data["test_key"]["public_key_hex"],
        derived_public.hex(),
        "receipt_signature",
    )

    for case in data["cases"]:
        case_id = case["id"]
        receipt = _receipt_from_vector_fields(
            case["fields_after_construction_before_signature"]
        )
        recorder.add(
            filename,
            case_id,
            "receipt_type",
            case["receipt_type"],
            validate_receipt(receipt),
            "receipt_hash",
        )
        recorder.add(
            filename,
            case_id,
            "fields_after_construction_before_signature.receipt_signature_hex",
            ZERO_SIGNATURE.hex(),
            receipt.get_unique("receipt_signature").hex(),
            "receipt_signature",
        )
        recorder.add(
            filename,
            case_id,
            "fields_after_construction_before_signature.signer_kid",
            data["test_key"]["signer_kid"],
            receipt.get_unique("signer_kid"),
            "receipt_signature",
        )
        zeroed = receipt_hash_preimage(receipt)
        computed_hash = blake3_256(zeroed)
        with_hash = receipt.replace(receipt_hash=computed_hash)
        signature_preimage = receipt_signature_preimage(with_hash)
        computed_signature = Ed25519PrivateKey.from_private_bytes(seed).sign(
            signature_preimage
        )
        signed = with_hash.replace(receipt_signature=computed_signature)
        signed_bytes = canonical_cbor_encode(signed)
        received_signed = canonical_cbor_decode(
            bytes.fromhex(case["signed_canonical_cbor_hex"])
        )
        if not isinstance(received_signed, CborMap):
            raise ConformanceError("signed receipt vector is not a CBOR map")

        recorder.add(
            filename,
            case_id,
            "zeroed_canonical_cbor_hex",
            case["zeroed_canonical_cbor_hex"],
            zeroed.hex(),
            "receipt_hash",
        )
        recorder.add(
            filename,
            case_id,
            "receipt_hash_hex",
            case["receipt_hash_hex"],
            computed_hash.hex(),
            "receipt_hash",
        )
        inner_hash = case["fields_after_construction_before_signature"][
            "receipt_hash_hex"
        ]
        recorder.add(
            filename,
            case_id,
            "fields_after_construction_before_signature.receipt_hash_hex",
            inner_hash,
            computed_hash.hex(),
            "receipt_hash",
        )
        recorder.add(
            filename,
            case_id,
            "signature_preimage_canonical_cbor_hex",
            case["signature_preimage_canonical_cbor_hex"],
            signature_preimage.hex(),
            "receipt_signature",
        )
        recorder.add(
            filename,
            case_id,
            "ed25519_message_hex",
            case["ed25519_message_hex"],
            signature_preimage.hex(),
            "receipt_signature",
        )
        recorder.add(
            filename,
            case_id,
            "receipt_signature_hex",
            case["receipt_signature_hex"],
            computed_signature.hex(),
            "receipt_signature",
        )
        recorder.add(
            filename,
            case_id,
            "signed_canonical_cbor_hex",
            case["signed_canonical_cbor_hex"],
            signed_bytes.hex(),
            "cbor_exact",
        )
        recorder.add(
            filename,
            case_id,
            "verify_result",
            case["verify_result"],
            verify_receipt(received_signed, public),
            "receipt_signature",
        )

        if "zeroed_hash_ignores_receipt_hash_signature_and_signer_kid" in case:
            altered = receipt.replace(
                receipt_hash=b"\xa5" * 32,
                receipt_signature=b"\x5a" * 64,
                signer_kid="different-kid",
            )
            recorder.add(
                filename,
                case_id,
                "zeroed_hash_ignores_receipt_hash_signature_and_signer_kid",
                case["zeroed_hash_ignores_receipt_hash_signature_and_signer_kid"],
                receipt_hash_preimage(altered) == zeroed,
                "receipt_hash",
            )

        if "revocation_signature_preserved_in_hash_preimage" in case:
            decoded_zeroed = canonical_cbor_decode(zeroed)
            original_revocation = receipt.get_unique("revocation_signature")
            recorder.add(
                filename,
                case_id,
                "revocation_signature_preserved_in_hash_preimage",
                case["revocation_signature_preserved_in_hash_preimage"],
                decoded_zeroed.get_unique("revocation_signature") == original_revocation,
                "receipt_hash",
            )
            decoded_signature_preimage = canonical_cbor_decode(signature_preimage)
            recorder.add(
                filename,
                case_id,
                "revocation_signature_preserved_in_signature_preimage",
                case["revocation_signature_preserved_in_signature_preimage"],
                decoded_signature_preimage.get_unique("revocation_signature")
                == original_revocation,
                "receipt_signature",
            )

        if case["receipt_type"] == "EntryAutoEnriched":
            payload = receipt.get_unique("auto_enrichment_bytes")
            recorder.add(
                filename,
                case_id,
                "auto_enrichment_bytes_are_canonical_cbor",
                payload.hex(),
                canonical_cbor_encode(canonical_cbor_decode(payload)).hex(),
                "cbor_exact",
            )
        if case["receipt_type"] == "AttestationAccepted":
            opaque_input = bytes.fromhex(
                case["fields_after_construction_before_signature"][
                    "attestation_bytes_hex"
                ]
            )
            recorder.add(
                filename,
                case_id,
                "attestation_bytes_embedded_verbatim",
                opaque_input,
                signed.get_unique("attestation_bytes"),
                "cbor_exact",
            )

        for negative in case.get("negative_cases", []):
            negative_id = f"{case_id}/{negative['id']}"
            if "tampered_canonical_cbor_hex" in negative:
                expected_tampered = bytes.fromhex(negative["tampered_canonical_cbor_hex"])
                differences = [
                    index
                    for index, (original, changed) in enumerate(
                        zip(
                            bytes.fromhex(case["signed_canonical_cbor_hex"]),
                            expected_tampered,
                            strict=True,
                        )
                    )
                    if original != changed
                ]
                derived_offset = differences[0] if len(differences) == 1 else differences
                recorder.add(
                    filename,
                    negative_id,
                    "changed_byte_offset",
                    negative["changed_byte_offset"],
                    derived_offset,
                    "receipt_signature",
                )
                offset = negative["changed_byte_offset"]
                recorder.add(
                    filename,
                    negative_id,
                    "original_byte_hex",
                    negative["original_byte_hex"],
                    bytes.fromhex(case["signed_canonical_cbor_hex"])[
                        offset : offset + 1
                    ].hex(),
                    "receipt_signature",
                )
                recorder.add(
                    filename,
                    negative_id,
                    "tampered_byte_hex",
                    negative["tampered_byte_hex"],
                    expected_tampered[offset : offset + 1].hex(),
                    "receipt_signature",
                )
                tampered = bytearray(bytes.fromhex(case["signed_canonical_cbor_hex"]))
                tampered[offset] = int(negative["tampered_byte_hex"], 16)
                recorder.add(
                    filename,
                    negative_id,
                    "tampered_canonical_cbor_hex",
                    negative["tampered_canonical_cbor_hex"],
                    bytes(tampered).hex(),
                    "receipt_signature",
                )
                negative_receipt = canonical_cbor_decode(bytes(tampered))
            elif negative["id"] == "content-byte-tampered":
                original = received_signed.get_unique(negative["field"])
                recorder.add(
                    filename,
                    negative_id,
                    "original",
                    negative["original"],
                    original,
                    "receipt_signature",
                )
                negative_receipt = received_signed.replace(
                    **{negative["field"]: negative["tampered"]}
                )
            else:
                if negative["id"] == "signature-over-32-byte-receipt-hash":
                    wrong_message = computed_hash
                elif (
                    negative["id"]
                    == "revocation-signature-wrongly-zeroed-in-signature-preimage"
                ):
                    wrong_message = canonical_cbor_encode(
                        with_hash.replace(
                            receipt_signature=ZERO_SIGNATURE,
                            revocation_signature=ZERO_SIGNATURE,
                        )
                    )
                else:
                    raise ConformanceError(
                        f"unrecognized negative receipt case {negative['id']}"
                    )
                recorder.add(
                    filename,
                    negative_id,
                    "ed25519_message_hex",
                    negative["ed25519_message_hex"],
                    wrong_message.hex(),
                    "receipt_signature",
                )
                wrong_signature = Ed25519PrivateKey.from_private_bytes(seed).sign(
                    wrong_message
                )
                recorder.add(
                    filename,
                    negative_id,
                    "receipt_signature_hex",
                    negative["receipt_signature_hex"],
                    wrong_signature.hex(),
                    "receipt_signature",
                )
                negative_receipt = received_signed.replace(
                    receipt_signature=wrong_signature
                )
                recorder.add(
                    filename,
                    negative_id,
                    "signed_canonical_cbor_hex",
                    negative["signed_canonical_cbor_hex"],
                    canonical_cbor_encode(negative_receipt).hex(),
                    "receipt_signature",
                )
            recorder.add(
                filename,
                negative_id,
                "verify_result",
                negative["verify_result"],
                verify_receipt(negative_receipt, public),
                "receipt_signature",
            )


def _decoded_uint(receipt: CborMap, field: str) -> int:
    value = receipt.get_unique(field)
    if not isinstance(value, UInt):
        raise ConformanceError(f"{field} is not a CBOR uint")
    return value.value


@dataclass(frozen=True)
class MintedReceipt:
    """All independently derived stages of one deterministic test receipt."""

    initial: CborMap
    zeroed_cbor: bytes
    receipt_hash: bytes
    signature_preimage: bytes
    receipt_signature: bytes
    signed: CborMap
    signed_cbor: bytes


def _mint_receipt(receipt: CborMap, private_key_seed: bytes) -> MintedReceipt:
    """Hash, path-A sign, and encode a fully constructed logical receipt."""

    if len(private_key_seed) != 32:
        raise ConformanceError("Ed25519 private seed must be 32 bytes")
    validate_receipt(receipt)
    if receipt.get_unique("receipt_hash") != ZERO_HASH:
        raise ConformanceError("receipt construction must begin with a zero hash")
    if receipt.get_unique("receipt_signature") != ZERO_SIGNATURE:
        raise ConformanceError("receipt construction must begin with a zero signature")

    zeroed_cbor = receipt_hash_preimage(receipt)
    computed_hash = blake3_256(zeroed_cbor)
    with_hash = receipt.replace(receipt_hash=computed_hash)
    signature_preimage = receipt_signature_preimage(with_hash)
    signature = Ed25519PrivateKey.from_private_bytes(private_key_seed).sign(
        signature_preimage
    )
    signed = with_hash.replace(receipt_signature=signature)
    return MintedReceipt(
        initial=receipt,
        zeroed_cbor=zeroed_cbor,
        receipt_hash=computed_hash,
        signature_preimage=signature_preimage,
        receipt_signature=signature,
        signed=signed,
        signed_cbor=canonical_cbor_encode(signed),
    )


def _nullable_hash_hex(value: str | None, field: str) -> bytes | None:
    if value is None:
        return None
    try:
        decoded = bytes.fromhex(value)
    except ValueError as exc:
        raise ConformanceError(f"{field} is not hexadecimal") from exc
    if len(decoded) != 32:
        raise ConformanceError(f"{field} must encode 32 bytes")
    return decoded


def _snapshot_changes_from_inputs(
    servers: Sequence[dict[str, str]],
    previous_servers: Sequence[dict[str, str]],
) -> CborMap:
    """Reproduce the documented live empty-previous-set constructor behavior.

    v1 deliberately does not define a general non-empty inter-snapshot delta.
    Every current chain fixture supplies the empty set used by the live sync
    path, for which §5.5.1 documents the emitted all-added counts.
    """

    if previous_servers:
        raise ConformanceError(
            "v1 does not define changes for a non-empty previous server set"
        )
    return CborMap(
        (
            ("added", UInt(len(servers))),
            ("removed", UInt(0)),
            ("modified", UInt(0)),
        )
    )


PUBLISHER_ENRICHMENT_FIELDS = frozenset(
    {
        "category",
        "min_tier",
        "required_affinity",
        "capability_graph",
        "declared_at",
        "declared_uri",
        "declared_hash",
        "publisher_rights_verified",
        "verification_method",
        "refresh_interval_seconds",
    }
)


def _publisher_enrichment_payload(value: dict[str, Any]) -> CborMap:
    """Construct the exact §5.7 publisher payload from structured JSON input."""

    if frozenset(value) != PUBLISHER_ENRICHMENT_FIELDS:
        raise ConformanceError("publisher enrichment payload has the wrong field set")
    converted = json_value_to_cbor(value)
    if not isinstance(converted, CborMap):
        raise ConformanceError("publisher enrichment payload must be a map")
    return converted


def _snapshot_receipt_from_inputs(link: dict[str, Any]) -> CborMap:
    servers = link["servers"]
    root = snapshot_set_digest(servers)
    return CborMap(
        (
            ("event_id", bytes.fromhex(link["event_id_hex"])),
            ("snapshot_id", bytes.fromhex(link["snapshot_id_hex"])),
            ("scraped_at", UInt(int(link["scraped_at_unix_ms"]))),
            ("server_count", UInt(len(servers))),
            ("snapshot_merkle_root", root),
            (
                "previous_snapshot_hash",
                _nullable_hash_hex(
                    link["previous_snapshot_hash_hex"],
                    "previous_snapshot_hash_hex",
                ),
            ),
            ("upstream_registry_uri", link["upstream_registry_uri"]),
            ("upstream_snapshot_etag", link["upstream_snapshot_etag"]),
            (
                "changes",
                _snapshot_changes_from_inputs(servers, link["previous_servers"]),
            ),
            ("receipt_hash", ZERO_HASH),
            ("receipt_signature", ZERO_SIGNATURE),
            ("signer_kid", link["signer_kid"]),
        )
    )


def _entry_enriched_receipt_from_inputs(
    link: dict[str, Any],
) -> tuple[CborMap, str, bytes, CborMap]:
    declaration = link["declaration"]
    canonical_declaration = canonical_json(declaration)
    declared_digest = blake3_256(canonical_declaration.encode("utf-8"))
    payload = _publisher_enrichment_payload(link["enrichment_payload"])
    expected_declared_hash = hash_json_string(declared_digest)
    if payload.get_unique("declared_hash") != expected_declared_hash:
        raise ConformanceError(
            "enrichment_payload.declared_hash does not match the declaration"
        )
    if payload.get_unique("declared_uri") != link["declared_uri"]:
        raise ConformanceError(
            "enrichment_payload.declared_uri does not match the receipt input"
        )

    receipt = CborMap(
        (
            ("event_id", bytes.fromhex(link["event_id_hex"])),
            ("server_name", link["server_name"]),
            ("publisher_passport", declaration["publisher_passport"]),
            ("declared_uri", link["declared_uri"]),
            ("declared_hash", declared_digest),
            ("enrichment_bytes", canonical_cbor_encode(payload)),
            (
                "supersedes_prior",
                _nullable_hash_hex(
                    link["supersedes_prior_receipt_hash_hex"],
                    "supersedes_prior_receipt_hash_hex",
                ),
            ),
            ("receipt_hash", ZERO_HASH),
            ("receipt_signature", ZERO_SIGNATURE),
            ("signer_kid", link["signer_kid"]),
        )
    )
    return receipt, canonical_declaration, declared_digest, payload


def _run_updated_prose_guards() -> int:
    """Exercise clarified rules that the frozen JSON vectors do not cover."""

    checks: list[tuple[str, bool]] = [
        (
            "lowercase-control-escape",
            _json_escape("\x0b\x1f") == '"\\u000b\\u001f"',
        ),
        ("json-positional-threshold", _json_float_text(1e-5) == "0.00001"),
        ("json-scientific-no-plus", _json_float_text(1e30) == "1e30"),
        (
            "wide-integral-token-f64-fallback",
            _parse_json_integer(str(U64_MAX + 1)).kind == "float",
        ),
        (
            "negative-nonintegral-capability-float",
            canonical_cbor_encode(
                json_value_to_cbor(JsonNumber("float", -1.5))
            )
            == bytes.fromhex("f9be00"),
        ),
    ]
    nul_rejected = False
    try:
        canonical_server_hash("bad\x00name", "1.0.0", "{}")
    except ConformanceError:
        nul_rejected = True
    checks.append(("snapshot-nul-input-rejected", nul_rejected))

    failures = [name for name, passed in checks if not passed]
    if failures:
        raise ConformanceError(
            "updated-prose guard failure(s): " + ", ".join(failures)
        )
    return len(checks)


def _run_chain_vectors(recorder: Recorder) -> None:
    filename = "chains.json"
    data = _load_vector(filename)
    _check_format(recorder, filename, data)
    seed = bytes.fromhex(data["test_key"]["seed_hex"])
    public = bytes.fromhex(data["test_key"]["public_key_hex"])
    derived_public = Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes_raw()
    recorder.add(
        filename,
        "test_key",
        "public_key_hex",
        data["test_key"]["public_key_hex"],
        derived_public.hex(),
        "receipt_signature",
    )

    snapshot_receipts: list[CborMap] = []
    prior_snapshot_root: bytes | None = None
    for link in data["snapshot_chain"]["links"]:
        case_id = f"snapshot_chain/link-{link['link']}"
        constructed = _snapshot_receipt_from_inputs(link)
        minted = _mint_receipt(constructed, seed)
        receipt = minted.signed
        snapshot_receipts.append(receipt)
        root = snapshot_set_digest(link["servers"])

        recorder.add(
            filename,
            case_id,
            "minted_receipt.signer_kid",
            link["signer_kid"],
            receipt.get_unique("signer_kid"),
            "receipt_signature",
        )
        recorder.add(
            filename,
            case_id,
            "server_count",
            link["server_count"],
            len(link["servers"]),
            "snapshot",
        )
        recorder.add(
            filename,
            case_id,
            "minted_receipt.server_count",
            link["server_count"],
            _decoded_uint(receipt, "server_count"),
            "snapshot",
        )
        recorder.add(
            filename,
            case_id,
            "snapshot_merkle_root_hex",
            link["snapshot_merkle_root_hex"],
            root.hex(),
            "snapshot",
        )
        recorder.add(
            filename,
            case_id,
            "minted_receipt.snapshot_merkle_root",
            link["snapshot_merkle_root_hex"],
            receipt.get_unique("snapshot_merkle_root").hex(),
            "snapshot",
        )
        recorder.add(
            filename,
            case_id,
            "previous_snapshot_hash_hex",
            link["previous_snapshot_hash_hex"],
            _hex_or_none(prior_snapshot_root),
            "snapshot_chain",
        )
        recorder.add(
            filename,
            case_id,
            "changes",
            link["changes"],
            _plain_cbor(receipt.get_unique("changes")),
            "receipt_hash",
        )
        recorder.add(
            filename,
            case_id,
            "zeroed_canonical_cbor_hex",
            link["zeroed_canonical_cbor_hex"],
            minted.zeroed_cbor.hex(),
            "receipt_hash",
        )
        recorder.add(
            filename,
            case_id,
            "receipt_hash_hex",
            link["receipt_hash_hex"],
            minted.receipt_hash.hex(),
            "receipt_hash",
        )
        recorder.add(
            filename,
            case_id,
            "minted_receipt.receipt_hash",
            link["receipt_hash_hex"],
            receipt.get_unique("receipt_hash").hex(),
            "receipt_hash",
        )
        recorder.add(
            filename,
            case_id,
            "signature_preimage_canonical_cbor_hex",
            link["signature_preimage_canonical_cbor_hex"],
            minted.signature_preimage.hex(),
            "receipt_signature",
        )
        recorder.add(
            filename,
            case_id,
            "receipt_signature_hex",
            link["receipt_signature_hex"],
            minted.receipt_signature.hex(),
            "receipt_signature",
        )
        recorder.add(
            filename,
            case_id,
            "signed_canonical_cbor_hex",
            bytes.fromhex(link["signed_canonical_cbor_hex"]),
            minted.signed_cbor,
            "cbor_exact",
        )
        recorder.add(
            filename,
            case_id,
            "verify_result",
            link["verify_result"],
            verify_receipt(receipt, public),
            "receipt_signature",
        )

        for negative in link.get("negative_cases", []):
            negative_id = f"{case_id}/{negative['id']}"
            wrong_message = minted.receipt_hash
            wrong_signature = Ed25519PrivateKey.from_private_bytes(seed).sign(
                wrong_message
            )
            wrong_receipt = receipt.replace(receipt_signature=wrong_signature)
            recorder.add(
                filename,
                negative_id,
                "ed25519_message_hex",
                negative["ed25519_message_hex"],
                wrong_message.hex(),
                "receipt_signature",
            )
            recorder.add(
                filename,
                negative_id,
                "receipt_signature_hex",
                negative["receipt_signature_hex"],
                wrong_signature.hex(),
                "receipt_signature",
            )
            recorder.add(
                filename,
                negative_id,
                "signed_canonical_cbor_hex",
                negative["signed_canonical_cbor_hex"],
                canonical_cbor_encode(wrong_receipt).hex(),
                "receipt_signature",
            )
            recorder.add(
                filename,
                negative_id,
                "verify_result",
                negative["verify_result"],
                verify_receipt(wrong_receipt, public),
                "receipt_signature",
            )
        prior_snapshot_root = root

    for index, valid in enumerate(check_snapshot_chain(snapshot_receipts), 1):
        recorder.add(
            filename,
            f"snapshot_chain/link-{index}",
            "chain_link_valid",
            True,
            valid,
            "snapshot_chain",
        )

    enrichment_receipts: list[CborMap] = []
    prior_enrichment_hash: bytes | None = None
    for link in data["entry_enriched_receipt_chain"]["links"]:
        case_id = f"entry_enriched_receipt_chain/link-{link['link']}"
        constructed, canonical_declaration, declared_digest, payload_model = (
            _entry_enriched_receipt_from_inputs(link)
        )
        minted = _mint_receipt(constructed, seed)
        receipt = minted.signed
        enrichment_receipts.append(receipt)

        recorder.add(
            filename,
            case_id,
            "minted_receipt.signer_kid",
            link["signer_kid"],
            receipt.get_unique("signer_kid"),
            "receipt_signature",
        )
        recorder.add(
            filename,
            case_id,
            "canonical_declaration_json_is_canonical",
            link["canonical_declaration_json"],
            canonical_declaration,
            "json",
        )
        recorder.add(
            filename,
            case_id,
            "declared_hash_hex",
            link["declared_hash_hex"],
            declared_digest.hex(),
            "declaration",
        )
        recorder.add(
            filename,
            case_id,
            "minted_receipt.declared_hash",
            link["declared_hash_hex"],
            receipt.get_unique("declared_hash").hex(),
            "declaration",
        )
        recorder.add(
            filename,
            case_id,
            "supersedes_prior_receipt_hash_hex",
            link["supersedes_prior_receipt_hash_hex"],
            _hex_or_none(prior_enrichment_hash),
            "enrichment_chain",
        )
        recorder.add(
            filename,
            case_id,
            "zeroed_canonical_cbor_hex",
            link["zeroed_canonical_cbor_hex"],
            minted.zeroed_cbor.hex(),
            "receipt_hash",
        )
        recorder.add(
            filename,
            case_id,
            "receipt_hash_hex",
            link["receipt_hash_hex"],
            minted.receipt_hash.hex(),
            "receipt_hash",
        )
        recorder.add(
            filename,
            case_id,
            "minted_receipt.receipt_hash",
            link["receipt_hash_hex"],
            receipt.get_unique("receipt_hash").hex(),
            "receipt_hash",
        )
        recorder.add(
            filename,
            case_id,
            "signature_preimage_canonical_cbor_hex",
            link["signature_preimage_canonical_cbor_hex"],
            minted.signature_preimage.hex(),
            "receipt_signature",
        )
        recorder.add(
            filename,
            case_id,
            "receipt_signature_hex",
            link["receipt_signature_hex"],
            minted.receipt_signature.hex(),
            "receipt_signature",
        )
        recorder.add(
            filename,
            case_id,
            "signed_canonical_cbor_hex",
            bytes.fromhex(link["signed_canonical_cbor_hex"]),
            minted.signed_cbor,
            "cbor_exact",
        )
        recorder.add(
            filename,
            case_id,
            "verify_result",
            link["verify_result"],
            verify_receipt(receipt, public),
            "receipt_signature",
        )
        payload = receipt.get_unique("enrichment_bytes")
        recorder.add(
            filename,
            case_id,
            "enrichment_bytes_from_structured_payload",
            payload.hex(),
            canonical_cbor_encode(payload_model).hex(),
            "cbor_exact",
        )
        recorder.add(
            filename,
            case_id,
            "enrichment_bytes.declared_hash",
            hash_json_string(declared_digest),
            payload_model.get_unique("declared_hash"),
            "declaration",
        )
        prior_enrichment_hash = minted.receipt_hash

    for index, valid in enumerate(check_enrichment_chain(enrichment_receipts), 1):
        recorder.add(
            filename,
            f"entry_enriched_receipt_chain/link-{index}",
            "chain_link_valid",
            True,
            valid,
            "enrichment_chain",
        )


AMBIGUITY_DISPOSITIONS = [
    (
        "A-01",
        "resolved-by-prose",
        "`02-canonical-cbor.md:57-64` now says the sort is stable and "
        "byte-identical encoded keys retain input order. The equal-key bytes are "
        "therefore normatively determined.",
    ),
    (
        "A-02",
        "resolved-by-prose",
        "`03-canonical-json.md:27-37` now requires a parsed input document to "
        "collapse duplicate object names last-wins before rendering.",
    ),
    (
        "A-03",
        "resolved-by-prose",
        "`03-canonical-json.md:41-58` enumerates the seven exact named escapes, "
        "requires lowercase `\\u00xx` for every other C0 control, and requires "
        "raw UTF-8 for all other characters.",
    ),
    (
        "A-04",
        "still-open",
        "The presentation thresholds and dependency versions are now pinned, but "
        "the spec-text-only digit selection remains incomplete. The insufficient "
        "sentence is: “Let `digits` be the shortest decimal significand” "
        "(`03-canonical-json.md:86`). It supplies neither a construction nor a "
        "tie-break if more than one shortest decimal round-trips. Referring to "
        "`ryu 1.0.23` is not self-contained under this purity boundary.",
    ),
    (
        "A-05",
        "still-open",
        "`03-canonical-json.md:81` now defines lossy binary64 fallback for "
        "integral tokens outside `[i64::MIN, u64::MAX]`. Overflow remains "
        "unspecified: “For a finite value `v`” and “Non-finite values do not "
        "occur” (`03-canonical-json.md:83-85`) do not say whether input such as "
        "`1e400` is rejected or mapped some other way.",
    ),
    (
        "A-06",
        "resolved-by-prose",
        "`vectors/README.md:45-81` declares and enumerates complete constructor "
        "inputs, and every link now supplies them. Combined with §§5-6, all six "
        "current receipt blobs can be minted without decoding expected CBOR. "
        "The resolution depends on the updated structured corpus as well as its "
        "describing prose.",
    ),
    (
        "A-07",
        "resolved-by-prose",
        "`05-receipts.md:15,40,145` consistently fixes "
        "`revocation_signature` as an always-present, non-nullable 64-byte string "
        "that is never zeroed.",
    ),
    (
        "A-08",
        "resolved-by-prose",
        "`05-receipts.md:17,127-135` now defines `attestation_bytes` as an opaque "
        "byte-string input embedded verbatim and forbids receipt-layer "
        "re-encoding. That determines receipt bytes; construction of the inner "
        "attestation remains intentionally outside the receipt layer.",
    ),
    (
        "A-09",
        "still-open",
        "The insufficient sentence is explicit: “v1 does **not** define a "
        "normative algorithm for deriving the true inter-snapshot delta” "
        "(`05-receipts.md:87-92`). The present chain fixtures remain computable "
        "because every `previous_servers` input is empty and lines 79-82 document "
        "the live all-added result; a non-empty prior set is not derivable.",
    ),
    (
        "A-10",
        "still-open",
        "The insufficient sentence remains: “v1 does **not** define how a verifier "
        "obtains the registry's 32-byte ed25519 public key from `signer_kid`” "
        "(`05-receipts.md:215-224`). Test vectors supply an out-of-band key.",
    ),
    (
        "A-11",
        "still-open",
        "`04-hashing.md:57-59` says the exact producer field set, ordering, and "
        "zeroing are outside v1 and that construction “is therefore **not "
        "normative in v1**.” The three producer-defined hash preimages remain "
        "uncomputable from this workspace.",
    ),
    (
        "A-12",
        "still-open",
        "`05-receipts.md:148-160` still says v1 does not define the inner "
        "`revocation_signature` preimage or revoker public-key discovery. Only "
        "the outer receipt signature is computable.",
    ),
    (
        "A-13",
        "resolved-by-prose",
        "`04-hashing.md:49-55` now partitions in-domain numbers: non-negative "
        "u64 integers become CBOR uints, non-integral values of either sign become "
        "CBOR floats, and negative integers are rejected. In particular, `-1.5` "
        "is normatively a negative CBOR float.",
    ),
]


NEW_AMBIGUITIES = [
    (
        "N-A-01",
        "`04-hashing.md:51-53` does not classify a positive integral-form "
        "`capability_graph` literal above `u64::MAX`: it does not fit the uint "
        "branch, has no fractional part or exponent for the float branch, and is "
        "not negative. `03-canonical-json.md:81` gives such tokens a binary64 "
        "fallback, but §4.5 does not say whether that parsed representation makes "
        "the capability value a float or an error.",
    )
]


PRIOR_DEFECT_DISPOSITIONS = [
    ("D-01", "resolved", "Stable equal-key CBOR order is now normative (§2.4)."),
    (
        "D-02",
        "still-open",
        "`README.md:44` still says encoders emit “no duplicate keys,” conflicting "
        "with `README.md:19` and §2.4's stable retention of represented duplicates.",
    ),
    ("D-03", "resolved", "JSON input duplicates are now normatively last-wins."),
    ("D-04", "resolved", "Every control escape and lowercase hex is pinned."),
    (
        "D-05",
        "still-open",
        "Version/threshold/domain text was added, but A-04 and A-05 retain the "
        "strict-purity gaps above.",
    ),
    ("D-06", "resolved", "Structured chain constructor inputs are now complete."),
    ("D-07", "resolved", "`revocation_signature` is consistently non-nullable."),
    (
        "D-08",
        "resolved",
        "`attestation_bytes` is explicitly opaque and verbatim, not canonicalised.",
    ),
    ("D-09", "still-open", "Intentional v1 public-key-discovery gap (A-10)."),
    ("D-10", "still-open", "Intentional producer-defined hash gap (A-11)."),
    ("D-11", "still-open", "Intentional inner-revocation verification gap (A-12)."),
    ("D-12", "still-open", "No general normative `changes` derivation (A-09)."),
    ("D-13", "resolved", "§6.2 now excludes U+0000 from name and version."),
    ("D-14", "resolved", "The canonical codec vector links now name real files."),
    ("D-15", "resolved", "The reported §4-§6 cross-references are corrected."),
    ("D-16", "resolved", "Negative non-integral capability values now map to floats."),
]


NEW_DEFECTS = [
    (
        "N-D-01",
        "The new §4.5 capability-number partition omits positive integral-form "
        "values above `u64::MAX` (the byte ambiguity N-A-01).",
    ),
    (
        "N-D-02",
        "`03-canonical-json.md:81` cites `006-edge-large-uints`, but no such vector "
        "or case exists in the workspace.",
    ),
    (
        "N-D-03",
        "`07-api-and-errors.md:3` cites `vectors/api/*`, but the workspace contains "
        "no API vector directory or file.",
    ),
    (
        "N-D-04",
        "The normative vector corpus has no cases for several newly clarified "
        "rules (JSON presentation thresholds/wide-number fallback, alphabetic "
        "control-escape hex, negative non-integral capability floats, NUL "
        "rejection, or deliberately non-canonical opaque attestation bytes). The "
        "runner therefore includes six separate prose guards, but a 292/292 vector "
        "result alone would not detect regressions in those rules.",
    ),
]


TRACEABILITY = [
    (
        "CBOR value model and exclusions",
        "`spec-v1/02-canonical-cbor.md:9-22` — “A canonical-CBOR value is exactly "
        "one of” the listed uint/bytes/text/array/text-keyed-map/bool/null/finite-float "
        "kinds; “Encoders MUST NOT emit” negative integers, tags, other simple "
        "values, indefinite items, or non-shortest floats.",
    ),
    (
        "CBOR heads and bodies",
        "`spec-v1/02-canonical-cbor.md:26-46` — “The argument ... uses the "
        "shortest form”; “An encoder MUST use the shortest head that fits n”; "
        "bytes/text carry their raw/UTF-8 bodies, arrays retain list order, and maps "
        "emit key then value.",
    ),
    (
        "CBOR map ordering",
        "`spec-v1/02-canonical-cbor.md:53-64` — “Keys MUST be sorted by the bytewise "
        "lexicographic order of their encoded form”; “Shorter keys sort before longer "
        "keys”; the sort is stable, so represented duplicates retain input order.",
    ),
    (
        "CBOR floats",
        "`spec-v1/02-canonical-cbor.md:68-74` — finite floats “MUST choose the "
        "shortest width that round-trips x exactly” in f16→f32→f64 order, where exact "
        "means “bit-equal on conversion back to the source double.”",
    ),
    (
        "CBOR decoder",
        "`spec-v1/02-canonical-cbor.md:80-88` — a canonical validator “MUST reject” "
        "trailing bytes, non-minimal heads, non-shortest/non-finite floats, non-text "
        "map keys, and reserved/indefinite markers; v1 “MAY accept-and-normalise” "
        "out-of-order or duplicate maps.",
    ),
    (
        "Canonical JSON recursion and escaping",
        "`spec-v1/03-canonical-json.md:11-60` — canonicalJSON has “no whitespace "
        "between tokens,” preserves array order, collapses input duplicates "
        "last-wins, uses the exact named/lowercase-control escapes, emits raw "
        "non-ASCII and slash, and applies no Unicode normalization.",
    ),
    (
        "Canonical JSON ordering and numbers",
        "`spec-v1/03-canonical-json.md:62-95` — keys use “unsigned bytewise (UTF-8) "
        "comparison of the key content”; implementations “MUST NOT substitute an RFC "
        "8785 canonicaliser”; numbers preserve integer/float distinction, cover the "
        "exact `[i64::MIN,u64::MAX]` domain plus binary64 fallback, preserve negative "
        "zero, and use the stated positional/scientific thresholds. A-04/A-05 record "
        "the remaining strict-purity edges.",
    ),
    (
        "BLAKE3 and artifact forms",
        "`spec-v1/04-hashing.md:7-26` — hashes use unkeyed/default BLAKE3 with "
        "32-byte output; receipts hash canonical CBOR, while snapshots/declarations "
        "hash canonical JSON using the artifact input-pin table.",
    ),
    (
        "Hash strings, declarations, and payload bytes",
        "`spec-v1/04-hashing.md:30-55` — JSON hash strings are "
        "`blake3:<64 lowercase hex chars>` (bare accepted by consumers); "
        "`declared_hash = BLAKE3(canonicalJSON(declaration_document))`; canonical-CBOR "
        "enrichment payloads are embedded before receipt hashing; negative "
        "non-integral capability values are CBOR floats while negative integers are "
        "rejected.",
    ),
    (
        "Receipt shapes and field encodings",
        "`spec-v1/05-receipts.md:9-22,53-170,226-232` — identifiers are bytes[16], "
        "hashes bytes[32], signatures bytes[64], timestamps/counts uints, names text, "
        "nullable absence CBOR Null; §§5.5/5.7 enumerate all six exact receipt and "
        "payload field sets.",
    ),
    (
        "Receipt hash",
        "`spec-v1/05-receipts.md:30-43` — set `receipt_hash` to 32 zero bytes, "
        "`receipt_signature` to 64 zero bytes, and `signer_kid` to CBOR Null, retain "
        "all other real values, canonical-CBOR encode, then BLAKE3 hash.",
    ),
    (
        "Receipt signature verification",
        "`spec-v1/05-receipts.md:172-213` — Ed25519 signs/verifies the “full canonical "
        "CBOR with only the receipt_signature field zeroed”; real receipt hash, signer "
        "KID, and revocation signature remain; verification “MUST NOT” use only the "
        "32-byte receipt hash, and an all-zero outer signature is unverifiable.",
    ),
    (
        "Opaque attestation bytes",
        "`spec-v1/05-receipts.md:127-135` — `attestation_bytes` is embedded verbatim "
        "as opaque producer input; a receipt verifier “MUST NOT” re-encode or "
        "re-canonicalise it.",
    ),
    (
        "Snapshot set digest and reconciliation hash",
        "`spec-v1/06-merkle-and-snapshots.md:16-67` — reject U+0000 in names/versions, "
        "stable-sort retained entries "
        "by UTF-8 `(name, version)`, hash one stream of "
        "`name || 00 || version || 00 || canonical_json || ff`; empty input hashes "
        "empty bytes; reconciliation uses the same frame without trailing `ff`.",
    ),
    (
        "Chain links",
        "`spec-v1/06-merkle-and-snapshots.md:69-81` — snapshot "
        "`previous_snapshot_hash` targets the prior set-digest root (not receipt hash), "
        "while `EntryEnriched.supersedes_prior` targets the prior receipt hash; first "
        "links are Null and `scraped_at` orders snapshots.",
    ),
    (
        "Structured chain constructors",
        "`spec-v1/vectors/README.md:45-81` — each chain link exposes the complete "
        "logical constructor input; expected counts, hashes, signatures, and CBOR are "
        "separate outputs.",
    ),
]


FILES_READ = [
    "reimpl.py",
    "REPORT.md",
    "spec-v1/README.md",
    "spec-v1/01-conventions.md",
    "spec-v1/02-canonical-cbor.md",
    "spec-v1/03-canonical-json.md",
    "spec-v1/04-hashing.md",
    "spec-v1/05-receipts.md",
    "spec-v1/06-merkle-and-snapshots.md",
    "spec-v1/07-api-and-errors.md",
    "spec-v1/vectors/README.md",
    "spec-v1/vectors/canonical-cbor.json",
    "spec-v1/vectors/canonical-json.json",
    "spec-v1/vectors/chains.json",
    "spec-v1/vectors/hashes.json",
    "spec-v1/vectors/receipts.json",
    "spec-v1/vectors/snapshot-merkle.json",
]


def _failure_value(value: Any) -> str:
    if isinstance(value, bytes):
        return f"hex `{value.hex()}`"
    if isinstance(value, str):
        return f"`{value}` (UTF-8 hex `{value.encode('utf-8').hex()}`)"
    rendered = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return f"`{rendered}` (UTF-8 hex `{rendered.encode('utf-8').hex()}`)"


def _case_rows(checks: Sequence[Check]) -> Iterator[tuple[str, int, int]]:
    order: list[str] = []
    grouped: dict[str, list[Check]] = {}
    for check in checks:
        if check.case not in grouped:
            order.append(check.case)
            grouped[check.case] = []
        grouped[check.case].append(check)
    for case in order:
        cases = grouped[case]
        yield case, sum(item.passed for item in cases), sum(not item.passed for item in cases)


def write_report(recorder: Recorder, destination: Path) -> None:
    vector_files = [
        "canonical-cbor.json",
        "canonical-json.json",
        "chains.json",
        "hashes.json",
        "receipts.json",
        "snapshot-merkle.json",
    ]
    total_pass = sum(check.passed for check in recorder.checks)
    total_fail = sum(not check.passed for check in recorder.checks)
    primary_chain_checks = [
        check
        for check in recorder.by_file("chains.json")
        if check.case.count("/") == 1
    ]
    minted_identity_checks = [
        check
        for check in primary_chain_checks
        if check.field == "signed_canonical_cbor_hex"
    ]
    mint_stage_fields = {
        "zeroed_canonical_cbor_hex",
        "receipt_hash_hex",
        "signature_preimage_canonical_cbor_hex",
        "receipt_signature_hex",
        "signed_canonical_cbor_hex",
        "verify_result",
    }
    mint_stage_checks = [
        check for check in primary_chain_checks if check.field in mint_stage_fields
    ]
    snapshot_identities = [
        check
        for check in minted_identity_checks
        if check.case.startswith("snapshot_chain/")
    ]
    enrichment_identities = [
        check
        for check in minted_identity_checks
        if check.case.startswith("entry_enriched_receipt_chain/")
    ]
    lines = [
        "# RCX Protocol Spec v1 — Independent Purity/Conformance Report",
        "",
        "Implementation source: only the in-workspace `spec-v1/` prose and vectors. "
        "No reference implementation or other repository/path was consulted.",
        "",
        "## Overall result",
        "",
        f"**{total_pass} passed, {total_fail} failed, {len(recorder.checks)} total "
        "explicit computed-vs-expected comparisons.**",
        "",
        "### Independently minted chain receipts",
        "",
        f"**{sum(check.passed for check in minted_identity_checks)}/"
        f"{len(minted_identity_checks)} full receipt encodings are byte-identical** "
        "when minted from structured logical inputs alone:",
        "",
        f"- `RegistrySnapshot`: {sum(check.passed for check in snapshot_identities)}/"
        f"{len(snapshot_identities)}.",
        f"- `EntryEnriched`: {sum(check.passed for check in enrichment_identities)}/"
        f"{len(enrichment_identities)}.",
        f"- Mint-stage outputs (zeroed CBOR, hash, signature preimage, deterministic "
        f"signature, final CBOR, verification): "
        f"{sum(check.passed for check in mint_stage_checks)}/"
        f"{len(mint_stage_checks)}.",
        "",
        "The chain runner constructs each value model from `servers`, "
        "`previous_servers`, identifiers, timestamps, URIs/ETag, declaration, "
        "enrichment payload, predecessor, and per-link `signer_kid`; it then "
        "canonical-CBOR encodes, hashes, path-A signs, verifies, and compares raw "
        "minted bytes with the expected blob. It never decodes an expected chain "
        "receipt to obtain construction values.",
        "",
        "- Snapshot inputs consumed: `event_id_hex`, `snapshot_id_hex`, "
        "`scraped_at_unix_ms`, `servers`, `previous_servers`, "
        "`previous_snapshot_hash_hex`, `upstream_registry_uri`, "
        "`upstream_snapshot_etag`, and per-link `signer_kid`.",
        "- Enrichment inputs consumed: `event_id_hex`, `server_name`, structured "
        "`declaration`, `declared_uri`, structured `enrichment_payload`, "
        "`supersedes_prior_receipt_hash_hex`, and per-link `signer_kid`.",
        "",
        "Those newly added fields are constructor inputs rather than additional "
        "expected outputs, so the ordinary comparison total remains 292; each raw "
        "signed-CBOR identity is their joint end-to-end assertion.",
        "",
        f"Additionally, {recorder.prose_guards_passed}/"
        f"{recorder.prose_guards_passed} non-vector guards passed for newly clarified "
        "escaping, number presentation/domain, negative fractional capability CBOR, "
        "and NUL rejection. These guards are not included in vector-file counts.",
        "",
        "| Vector file | Pass | Fail | Total |",
        "|---|---:|---:|---:|",
    ]
    for filename in vector_files:
        checks = recorder.by_file(filename)
        passed = sum(check.passed for check in checks)
        failed = sum(not check.passed for check in checks)
        lines.append(f"| `{filename}` | {passed} | {failed} | {len(checks)} |")

    lines.extend(
        [
            "",
            "Counts include separate byte comparisons for canonical encodings, hash "
            "preimages, digests, deterministic test signatures, signed encodings, "
            "decoder rejection reason codes, verification verdicts, format/version "
            "guards, and chain relations. "
            "Diagnostic prose fields such as `production_function` and error-message "
            "text are not protocol computations and are not counted.",
            "",
            "## Per-file and per-case counts",
        ]
    )
    for filename in vector_files:
        lines.extend(
            [
                "",
                f"### `{filename}`",
                "",
                "| Case | Pass | Fail | Total |",
                "|---|---:|---:|---:|",
            ]
        )
        for case, passed, failed in _case_rows(recorder.by_file(filename)):
            lines.append(f"| `{case}` | {passed} | {failed} | {passed + failed} |")

    lines.extend(["", "## Normative traceability", ""])
    for title, citation in TRACEABILITY:
        lines.append(f"- **{title}:** {citation}")
        lines.append("")

    failures = [check for check in recorder.checks if not check.passed]
    lines.extend(["", "## Failures", ""])
    if not failures:
        lines.append("None. Every computable vector field checked by the runner matched.")
    else:
        for index, failure in enumerate(failures, 1):
            lines.extend(
                [
                    f"### F-{index:03d} — `{failure.vector_file}` / `{failure.case}` / `{failure.field}`",
                    "",
                    f"- Expected bytes/value: {_failure_value(failure.expected)}",
                    f"- Computed bytes/value: {_failure_value(failure.computed)}",
                    f"- Exact normative sentence followed: {failure.citation}",
                    "",
                ]
            )

    lines.extend(["", "## AMBIGUITY LOG", ""])
    for identifier, disposition, assessment in AMBIGUITY_DISPOSITIONS:
        lines.append(f"- **{identifier} — {disposition}.** {assessment}")
        lines.append("")

    lines.extend(["### New ambiguities", ""])
    for identifier, assessment in NEW_AMBIGUITIES:
        lines.append(f"- **{identifier}.** {assessment}")
        lines.append("")

    lines.extend(["## Prior defect disposition", ""])
    for identifier, disposition, assessment in PRIOR_DEFECT_DISPOSITIONS:
        lines.append(f"- **{identifier} — {disposition}.** {assessment}")
        lines.append("")

    lines.extend(["## New defects found", ""])
    for identifier, assessment in NEW_DEFECTS:
        lines.append(f"- **{identifier}.** {assessment}")
        lines.append("")

    lines.extend(
        [
            "## Explicitly uncomputable/out-of-scope items",
            "",
            "- `passport_hash`, `project_hash`, and `attestation_hash` preimages are "
            "withheld by §4.6; no attempt was made to invent them.",
            "- Live receipt signatures cannot be verified from `signer_kid` alone; the "
            "vector test signatures are verified only because the vectors supply a "
            "public key.",
            "- The inner `revocation_signature` cannot be verified because no inner "
            "message/key/algorithm construction is specified.",
            "- The inner structure of `attestation_bytes` cannot be constructed from "
            "v1, by design; receipt bytes remain computable because the opaque input "
            "is embedded verbatim.",
            "- A general `RegistrySnapshot.changes` algorithm for a non-empty previous "
            "server set is not normative. The current chain fixtures are computable "
            "because all previous sets are empty and the live all-added result is "
            "documented.",
            "- Canonical-JSON overflow input behavior and a self-contained shortest-"
            "digit tie-break remain open under the strict spec-text-only boundary "
            "(A-04/A-05).",
            "",
            "## Files read",
            "",
        ]
    )
    lines.extend(f"- `{path}`" for path in FILES_READ)
    lines.extend(
        [
            "",
            "No file outside the workspace was consulted, and no `spec-v1/` or vector "
            "file was modified.",
            "",
        ]
    )
    destination.write_text("\n".join(lines), encoding="utf-8")


def run_vectors() -> Recorder:
    recorder = Recorder()
    recorder.prose_guards_passed = _run_updated_prose_guards()
    _run_cbor_vectors(recorder)
    _run_json_vectors(recorder)
    _run_chain_vectors(recorder)
    _run_hash_vectors(recorder)
    _run_receipt_vectors(recorder)
    _run_snapshot_vectors(recorder)
    return recorder


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--report",
        type=Path,
        default=ROOT / "REPORT.md",
        help="report destination (default: workspace REPORT.md)",
    )
    parser.add_argument("--quiet", action="store_true")
    arguments = parser.parse_args(argv)
    recorder = run_vectors()
    write_report(recorder, arguments.report)
    passed = sum(check.passed for check in recorder.checks)
    failed = sum(not check.passed for check in recorder.checks)
    if not arguments.quiet:
        print(f"{passed} passed, {failed} failed; report: {arguments.report}")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
