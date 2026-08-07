// Package rcxverify implements offline verification for the RCX protocol
// (rcx-spec/v1).
//
// Canonical JSON (§3) and canonical CBOR (§2) sort map keys by OPPOSITE rules:
//
//	canonical CBOR (§2.4)  length-first — "b" before "aa"
//	canonical JSON (§3.3)  plain byte order — "aa" before "b"
//
// Same keys, same protocol, different order. Getting it backwards produces bytes
// that look plausible and hash to nothing anybody published.
//
// Go shares JavaScript's number problem: unmarshalling into any gives float64 for
// every number, so {"value":1.0} and {"value":1} — distinct vectors with distinct
// hashes — become indistinguishable. We decode with Decoder.UseNumber, which keeps
// each literal as a json.Number string, and canonicalise from that.
package rcxverify

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strings"
	"unicode/utf8"
)

// CanonicalError is malformed input, or a value the canonical form cannot hold.
type CanonicalError struct{ msg string }

func (e *CanonicalError) Error() string { return e.msg }

func canonicalErrorf(format string, args ...any) error {
	return &CanonicalError{msg: fmt.Sprintf(format, args...)}
}

// ---------------------------------------------------------------------------
// Canonical JSON (§3)
// ---------------------------------------------------------------------------

// ParseJSONPreservingNumbers decodes raw JSON text, keeping number literals
// exactly as written.
//
// Uses UseNumber so 1.0 does not become 1. Without it, §3 cannot be implemented
// correctly in Go at all — the distinction is gone before canonicalisation runs.
func ParseJSONPreservingNumbers(text string) (any, error) {
	decoder := json.NewDecoder(strings.NewReader(text))
	decoder.UseNumber()

	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, canonicalErrorf("declaration is not JSON: %v", err)
	}
	// Reject trailing content: two concatenated documents must not verify as one.
	if decoder.More() {
		return nil, canonicalErrorf("trailing content after JSON value")
	}
	return value, nil
}

// CanonicalizeJSON renders a value as canonical JSON (§3): compact, key-sorted,
// no insignificant whitespace. Keys sort by plain byte order, not the
// length-first order canonical CBOR uses.
func CanonicalizeJSON(value any) (string, error) {
	var builder strings.Builder
	if err := writeCanonicalJSON(value, &builder); err != nil {
		return "", err
	}
	return builder.String(), nil
}

func writeCanonicalJSON(value any, out *strings.Builder) error {
	switch typed := value.(type) {
	case nil:
		out.WriteString("null")
	case bool:
		if typed {
			out.WriteString("true")
		} else {
			out.WriteString("false")
		}
	case json.Number:
		// The literal, verbatim. This is the whole reason for UseNumber.
		out.WriteString(typed.String())
	case string:
		encoded, err := encodeJSONString(typed)
		if err != nil {
			return err
		}
		out.WriteString(encoded)
	case []any:
		out.WriteByte('[')
		for index, item := range typed {
			if index > 0 {
				out.WriteByte(',')
			}
			if err := writeCanonicalJSON(item, out); err != nil {
				return err
			}
		}
		out.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		// Plain byte order (§3.3). Go's string comparison is bytewise, which
		// matches Rust's String ordering — and differs from RFC 8785's UTF-16
		// order for astral-plane keys. That divergence is observed and frozen.
		sort.Strings(keys)

		out.WriteByte('{')
		for index, key := range keys {
			if index > 0 {
				out.WriteByte(',')
			}
			encoded, err := encodeJSONString(key)
			if err != nil {
				return err
			}
			out.WriteString(encoded)
			out.WriteByte(':')
			if err := writeCanonicalJSON(typed[key], out); err != nil {
				return err
			}
		}
		out.WriteByte('}')
	case float64:
		// Only reached if a caller bypassed ParseJSONPreservingNumbers. The
		// literal is already lost, so refuse rather than guess whether an
		// integral value was written 1 or 1.0 — a wrong guess is a wrong hash.
		return canonicalErrorf(
			"float64 reached canonical JSON: parse with ParseJSONPreservingNumbers so " +
				"number literals survive (1.0 and 1 have different canonical forms)")
	default:
		return canonicalErrorf("cannot canonicalize %T", value)
	}
	return nil
}

// encodeJSONString matches serde_json's escaping, which the vectors froze:
// minimal escapes, no \u for non-ASCII, invalid UTF-8 rejected.
func encodeJSONString(value string) (string, error) {
	if !utf8.ValidString(value) {
		return "", canonicalErrorf("string is not valid UTF-8")
	}
	var out strings.Builder
	out.WriteByte('"')
	for _, r := range value {
		switch r {
		case '"':
			out.WriteString(`\"`)
		case '\\':
			out.WriteString(`\\`)
		case '\n':
			out.WriteString(`\n`)
		case '\r':
			out.WriteString(`\r`)
		case '\t':
			out.WriteString(`\t`)
		case '\b':
			out.WriteString(`\b`)
		case '\f':
			out.WriteString(`\f`)
		default:
			if r < 0x20 {
				fmt.Fprintf(&out, `\u%04x`, r)
			} else {
				out.WriteRune(r)
			}
		}
	}
	out.WriteByte('"')
	return out.String(), nil
}

// ---------------------------------------------------------------------------
// Canonical CBOR value model (§2.1)
// ---------------------------------------------------------------------------

// CborUint is an unsigned integer (major type 0).
type CborUint uint64

// CborBytes is a byte string (major type 2).
type CborBytes []byte

// CborFloat is a finite float (major type 7).
type CborFloat float64

// CborMap is a CBOR map as an ordered key/value list.
//
// Not a Go map: the value model has no key-uniqueness invariant, and §2.4's
// stable tie-break for byte-identical keys only means something if duplicates
// survive decoding. A Go map would collapse them, and the re-encode round-trip
// check would then pass over bytes that differ from the input.
type CborMap struct {
	Pairs []CborPair
}

// CborPair is one map entry.
type CborPair struct {
	Key   string
	Value any
}

// Get returns the first value stored under key.
func (m *CborMap) Get(key string) (any, bool) {
	for _, pair := range m.Pairs {
		if pair.Key == key {
			return pair.Value, true
		}
	}
	return nil, false
}

// Replace returns a copy with the named keys' values replaced.
func (m *CborMap) Replace(replacements map[string]any) *CborMap {
	pairs := make([]CborPair, len(m.Pairs))
	for index, pair := range m.Pairs {
		if replacement, ok := replacements[pair.Key]; ok {
			pairs[index] = CborPair{Key: pair.Key, Value: replacement}
		} else {
			pairs[index] = pair
		}
	}
	return &CborMap{Pairs: pairs}
}

// EncodeCbor renders a value as canonical CBOR (§2).
func EncodeCbor(value any) ([]byte, error) {
	var out bytes.Buffer
	if err := writeCborValue(value, &out); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func writeCborValue(value any, out *bytes.Buffer) error {
	switch typed := value.(type) {
	case nil:
		out.WriteByte(0xf6)
	case bool:
		if typed {
			out.WriteByte(0xf5)
		} else {
			out.WriteByte(0xf4)
		}
	case CborUint:
		writeCborHead(0, uint64(typed), out)
	case CborBytes:
		writeCborHead(2, uint64(len(typed)), out)
		out.Write(typed)
	case string:
		writeCborHead(3, uint64(len(typed)), out)
		out.WriteString(typed)
	case []any:
		writeCborHead(4, uint64(len(typed)), out)
		for _, item := range typed {
			if err := writeCborValue(item, out); err != nil {
				return err
			}
		}
	case CborFloat:
		return writeCborFloat(float64(typed), out)
	case *CborMap:
		return writeCborMap(typed, out)
	default:
		return canonicalErrorf("cannot encode %T as canonical CBOR", value)
	}
	return nil
}

type encodedPair struct {
	encodedKey []byte
	value      any
}

func writeCborMap(value *CborMap, out *bytes.Buffer) error {
	pairs := make([]encodedPair, 0, len(value.Pairs))
	for _, pair := range value.Pairs {
		var head bytes.Buffer
		writeCborHead(3, uint64(len(pair.Key)), &head)
		head.WriteString(pair.Key)
		pairs = append(pairs, encodedPair{encodedKey: head.Bytes(), value: pair.Value})
	}

	// Length-first ordering (§2.4) falls out of sorting by the ENCODED key bytes,
	// because the head encodes length before content. sort.SliceStable preserves
	// input order for byte-identical keys, as §2.4 requires.
	sort.SliceStable(pairs, func(i, j int) bool {
		return bytes.Compare(pairs[i].encodedKey, pairs[j].encodedKey) < 0
	})

	writeCborHead(5, uint64(len(pairs)), out)
	for _, pair := range pairs {
		out.Write(pair.encodedKey)
		if err := writeCborValue(pair.value, out); err != nil {
			return err
		}
	}
	return nil
}

func writeCborHead(major byte, argument uint64, out *bytes.Buffer) {
	base := major << 5
	switch {
	case argument < 24:
		out.WriteByte(base | byte(argument))
	case argument <= 0xff:
		out.WriteByte(base | 24)
		out.WriteByte(byte(argument))
	case argument <= 0xffff:
		out.WriteByte(base | 25)
		out.Write(binary.BigEndian.AppendUint16(nil, uint16(argument)))
	case argument <= 0xffffffff:
		out.WriteByte(base | 26)
		out.Write(binary.BigEndian.AppendUint32(nil, uint32(argument)))
	default:
		out.WriteByte(base | 27)
		out.Write(binary.BigEndian.AppendUint64(nil, argument))
	}
}

// writeCborFloat emits the shortest width that round-trips exactly (§2.5).
func writeCborFloat(value float64, out *bytes.Buffer) error {
	if math.IsNaN(value) || math.IsInf(value, 0) {
		return canonicalErrorf("non-finite floats MUST NOT be encoded (§2.5)")
	}

	// Signbit comparison, not ==, so -0.0 is not mistaken for 0.0.
	half := float16FromFloat64(value)
	if back, ok := half.toFloat64(); ok && back == value &&
		math.Signbit(back) == math.Signbit(value) {
		out.WriteByte(0xf9)
		out.Write(binary.BigEndian.AppendUint16(nil, uint16(half)))
		return nil
	}

	single := float32(value)
	if float64(single) == value && math.Signbit(float64(single)) == math.Signbit(value) {
		out.WriteByte(0xfa)
		out.Write(binary.BigEndian.AppendUint32(nil, math.Float32bits(single)))
		return nil
	}

	out.WriteByte(0xfb)
	out.Write(binary.BigEndian.AppendUint64(nil, math.Float64bits(value)))
	return nil
}

// float16 is an IEEE 754 half-precision value. Go has no native float16, so the
// conversion is explicit.
type float16 uint16

func float16FromFloat64(value float64) float16 {
	bits := math.Float32bits(float32(value))
	sign := uint16((bits >> 16) & 0x8000)
	exponent := int32((bits>>23)&0xff) - 127
	mantissa := bits & 0x7fffff

	switch {
	case exponent > 15:
		return float16(sign | 0x7c00) // overflow to infinity; rejected by round-trip
	case exponent < -24:
		return float16(sign)
	case exponent < -14:
		shift := uint32(-exponent - 14)
		return float16(sign | uint16((mantissa|0x800000)>>(shift+13)))
	default:
		return float16(sign | uint16((uint32(exponent+15)<<10)|(mantissa>>13)))
	}
}

func (h float16) toFloat64() (float64, bool) {
	sign := uint32(h&0x8000) << 16
	exponent := uint32(h>>10) & 0x1f
	mantissa := uint32(h & 0x3ff)

	switch exponent {
	case 0x1f:
		return 0, false // Inf/NaN cannot round-trip a finite value
	case 0:
		if mantissa == 0 {
			return float64(math.Float32frombits(sign)), true
		}
		value := float64(mantissa) / 1024.0 * math.Pow(2, -14)
		if sign != 0 {
			value = -value
		}
		return value, true
	default:
		bits := sign | ((exponent + 112) << 23) | (mantissa << 13)
		return float64(math.Float32frombits(bits)), true
	}
}

// ---------------------------------------------------------------------------
// Decoding (§2.6)
// ---------------------------------------------------------------------------

// DecodeCbor parses canonical CBOR into the value model.
func DecodeCbor(data []byte) (any, error) {
	value, offset, err := readCborValue(data, 0)
	if err != nil {
		return nil, err
	}
	if offset != len(data) {
		return nil, canonicalErrorf("%d trailing byte(s) after value", len(data)-offset)
	}
	return value, nil
}

func readCborValue(data []byte, offset int) (any, int, error) {
	if offset >= len(data) {
		return nil, 0, canonicalErrorf("truncated input")
	}
	initial := data[offset]
	major := initial >> 5
	minor := initial & 0x1f
	offset++

	if major == 7 {
		switch minor {
		case 20:
			return false, offset, nil
		case 21:
			return true, offset, nil
		case 22:
			return nil, offset, nil
		case 25:
			if offset+2 > len(data) {
				return nil, 0, canonicalErrorf("truncated half float")
			}
			value, ok := float16(binary.BigEndian.Uint16(data[offset:])).toFloat64()
			if !ok {
				return nil, 0, canonicalErrorf("non-finite float is not canonical")
			}
			return CborFloat(value), offset + 2, nil
		case 26:
			if offset+4 > len(data) {
				return nil, 0, canonicalErrorf("truncated single float")
			}
			bits := binary.BigEndian.Uint32(data[offset:])
			return CborFloat(float64(math.Float32frombits(bits))), offset + 4, nil
		case 27:
			if offset+8 > len(data) {
				return nil, 0, canonicalErrorf("truncated double float")
			}
			bits := binary.BigEndian.Uint64(data[offset:])
			return CborFloat(math.Float64frombits(bits)), offset + 8, nil
		}
		return nil, 0, canonicalErrorf("unsupported simple value %d", minor)
	}

	argument, offset, err := readCborArgument(data, offset, minor)
	if err != nil {
		return nil, 0, err
	}
	length := int(argument)

	switch major {
	case 0:
		return CborUint(argument), offset, nil
	case 2:
		if offset+length > len(data) {
			return nil, 0, canonicalErrorf("truncated byte string")
		}
		out := make(CborBytes, length)
		copy(out, data[offset:offset+length])
		return out, offset + length, nil
	case 3:
		if offset+length > len(data) {
			return nil, 0, canonicalErrorf("truncated text string")
		}
		text := string(data[offset : offset+length])
		if !utf8.ValidString(text) {
			return nil, 0, canonicalErrorf("text string is not valid UTF-8")
		}
		return text, offset + length, nil
	case 4:
		items := make([]any, 0, length)
		for index := 0; index < length; index++ {
			var item any
			item, offset, err = readCborValue(data, offset)
			if err != nil {
				return nil, 0, err
			}
			items = append(items, item)
		}
		return items, offset, nil
	case 5:
		pairs := make([]CborPair, 0, length)
		for index := 0; index < length; index++ {
			var rawKey, item any
			rawKey, offset, err = readCborValue(data, offset)
			if err != nil {
				return nil, 0, err
			}
			key, ok := rawKey.(string)
			if !ok {
				return nil, 0, canonicalErrorf("CBOR map keys must be text strings")
			}
			item, offset, err = readCborValue(data, offset)
			if err != nil {
				return nil, 0, err
			}
			pairs = append(pairs, CborPair{Key: key, Value: item})
		}
		return &CborMap{Pairs: pairs}, offset, nil
	}
	return nil, 0, canonicalErrorf("unsupported major type %d", major)
}

func readCborArgument(data []byte, offset int, minor byte) (uint64, int, error) {
	switch {
	case minor < 24:
		return uint64(minor), offset, nil
	case minor == 24:
		if offset+1 > len(data) {
			return 0, 0, canonicalErrorf("truncated argument")
		}
		return uint64(data[offset]), offset + 1, nil
	case minor == 25:
		if offset+2 > len(data) {
			return 0, 0, canonicalErrorf("truncated argument")
		}
		return uint64(binary.BigEndian.Uint16(data[offset:])), offset + 2, nil
	case minor == 26:
		if offset+4 > len(data) {
			return 0, 0, canonicalErrorf("truncated argument")
		}
		return uint64(binary.BigEndian.Uint32(data[offset:])), offset + 4, nil
	case minor == 27:
		if offset+8 > len(data) {
			return 0, 0, canonicalErrorf("truncated argument")
		}
		return binary.BigEndian.Uint64(data[offset:]), offset + 8, nil
	}
	return 0, 0, canonicalErrorf("indefinite-length or reserved argument %d is not canonical", minor)
}
