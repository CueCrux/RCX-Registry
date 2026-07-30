/**
 * Canonical JSON and canonical CBOR per rcx-spec/v1 §2 and §3.
 *
 * The two canonical forms sort map keys by OPPOSITE rules:
 *
 *   canonical CBOR (§2.4)  length-first — "b" before "aa"
 *   canonical JSON (§3.3)  plain code-unit order — "aa" before "b"
 *
 * Same keys, same protocol, different order. Getting it backwards produces bytes
 * that look plausible and hash to nothing anybody published.
 *
 * JavaScript has one problem the other SDKs do not: `JSON.parse` collapses the
 * int/float distinction, so `1.0` and `1` both become the number 1 — but they are
 * distinct vectors with distinct canonical forms and distinct hashes. We therefore
 * never canonicalise a caller's parsed object. We parse the raw text ourselves
 * with JSON.parse source access, which hands us the original number literal.
 *
 * That requires Node >= 22 (or any engine with the json-parse-with-source
 * proposal). An engine without it cannot implement §3 correctly via JSON.parse at
 * all, and would need its own tokeniser.
 */

import { blake3 } from '@noble/hashes/blake3.js';

/** Marker for a number whose exact source text must survive canonicalisation. */
class RawNumber {
  constructor(source) {
    this.source = source;
  }
}

export class CanonicalError extends Error {}

/**
 * Parse raw JSON text into a value that remembers its number literals.
 *
 * @param {string} text
 */
export function parseJsonPreservingNumbers(text) {
  if (typeof text !== 'string') {
    throw new CanonicalError('declaration must be raw JSON text');
  }
  let sawSource = false;
  let parsed;
  try {
    parsed = JSON.parse(text, function reviver(_key, value, context) {
      if (context && typeof context.source === 'string') {
        sawSource = true;
        if (typeof value === 'number') {
          return new RawNumber(context.source);
        }
      }
      return value;
    });
  } catch (error) {
    throw new CanonicalError(`declaration is not JSON: ${error.message}`);
  }

  // Positive control. If the engine silently ignored the third reviver argument,
  // every number would have been coerced and `1.0` would canonicalise as `1` —
  // wrong, and wrong in a way no test on integer-only fixtures would reveal. Fail
  // loudly rather than hash the wrong bytes.
  if (!sawSource && /[-0-9]/.test(text)) {
    throw new CanonicalError(
      'this engine does not support JSON.parse source access, so canonical JSON ' +
        'cannot preserve number literals (§3.4). Node >= 22 is required.',
    );
  }
  return parsed;
}

/**
 * Render a value as canonical JSON (§3). Object keys sort by plain code-unit
 * order — not the length-first order canonical CBOR uses.
 */
export function canonicalizeJson(value) {
  if (value === null) return 'null';
  if (value === true) return 'true';
  if (value === false) return 'false';
  if (value instanceof RawNumber) return value.source;
  if (typeof value === 'number') {
    // Reached only when a caller passed an already-parsed value. The literal is
    // gone by now, so integral floats are indistinguishable from integers.
    if (!Number.isFinite(value)) {
      throw new CanonicalError('non-finite numbers cannot be canonicalized');
    }
    if (Number.isInteger(value) && !Object.is(value, -0)) return String(value);
    return String(value);
  }
  if (typeof value === 'string') return JSON.stringify(value);
  if (Array.isArray(value)) {
    return `[${value.map(canonicalizeJson).join(',')}]`;
  }
  if (typeof value === 'object') {
    const keys = Object.keys(value).sort();
    const parts = keys.map((key) => `${JSON.stringify(key)}:${canonicalizeJson(value[key])}`);
    return `{${parts.join(',')}}`;
  }
  throw new CanonicalError(`cannot canonicalize ${typeof value}`);
}

// ---------------------------------------------------------------------------
// Canonical CBOR value model (§2.1)
// ---------------------------------------------------------------------------

export class CborUint {
  constructor(value) {
    this.value = BigInt(value);
  }
}
export class CborBytes {
  constructor(value) {
    this.value = value;
  }
}
export class CborFloat {
  constructor(value) {
    this.value = value;
  }
}

/**
 * A CBOR map as an ordered key/value list.
 *
 * Not a plain object: the value model has no key-uniqueness invariant, and §2.4's
 * stable tie-break for byte-identical keys only means something if duplicates
 * survive decoding. An object would collapse them, and the re-encode round-trip
 * check would then pass over bytes that differ from the input.
 */
export class CborMap {
  constructor(pairs) {
    this.pairs = pairs;
  }
  get(key) {
    for (const [name, value] of this.pairs) if (name === key) return value;
    return undefined;
  }
  has(key) {
    return this.pairs.some(([name]) => name === key);
  }
  replace(replacements) {
    return new CborMap(
      this.pairs.map(([name, value]) =>
        Object.prototype.hasOwnProperty.call(replacements, name)
          ? [name, replacements[name]]
          : [name, value],
      ),
    );
  }
}

export function encodeCbor(value) {
  const out = [];
  writeValue(value, out);
  return Uint8Array.from(out);
}

function writeValue(value, out) {
  if (value === null) return void out.push(0xf6);
  if (value === true) return void out.push(0xf5);
  if (value === false) return void out.push(0xf4);
  if (value instanceof CborUint) return writeHead(0, value.value, out);
  if (typeof value === 'bigint') return writeHead(0, value, out);
  if (value instanceof CborBytes) {
    writeHead(2, BigInt(value.value.length), out);
    for (const byte of value.value) out.push(byte);
    return;
  }
  if (typeof value === 'string') {
    const raw = new TextEncoder().encode(value);
    writeHead(3, BigInt(raw.length), out);
    for (const byte of raw) out.push(byte);
    return;
  }
  if (Array.isArray(value)) {
    writeHead(4, BigInt(value.length), out);
    for (const item of value) writeValue(item, out);
    return;
  }
  if (value instanceof CborFloat) return writeFloat(value.value, out);
  if (value instanceof CborMap) return writeMap(value, out);
  if (typeof value === 'number') {
    if (Number.isInteger(value) && value >= 0) return writeHead(0, BigInt(value), out);
    return writeFloat(value, out);
  }
  throw new CanonicalError(`cannot encode ${typeof value}`);
}

function writeMap(map, out) {
  const encoder = new TextEncoder();
  const pairs = map.pairs.map(([key, value]) => {
    if (typeof key !== 'string') {
      throw new CanonicalError('CBOR map keys must be text strings (§2.4)');
    }
    const head = [];
    const raw = encoder.encode(key);
    writeHead(3, BigInt(raw.length), head);
    return { encoded: Uint8Array.from([...head, ...raw]), value };
  });

  // Length-first ordering (§2.4) falls out of sorting by the ENCODED key bytes,
  // because the head encodes length before content. Array.prototype.sort is
  // stable in ES2019+, which preserves input order for byte-identical keys as
  // §2.4 requires.
  pairs.sort((a, b) => compareBytes(a.encoded, b.encoded));

  writeHead(5, BigInt(pairs.length), out);
  for (const { encoded, value } of pairs) {
    for (const byte of encoded) out.push(byte);
    writeValue(value, out);
  }
}

function compareBytes(a, b) {
  const shared = Math.min(a.length, b.length);
  for (let index = 0; index < shared; index += 1) {
    if (a[index] !== b[index]) return a[index] - b[index];
  }
  return a.length - b.length;
}

function writeHead(major, argument, out) {
  const base = major << 5;
  if (argument < 24n) return void out.push(base | Number(argument));
  if (argument <= 0xffn) return void out.push(base | 24, Number(argument));
  if (argument <= 0xffffn) {
    out.push(base | 25, Number((argument >> 8n) & 0xffn), Number(argument & 0xffn));
    return;
  }
  if (argument <= 0xffffffffn) {
    out.push(base | 26);
    for (let shift = 24n; shift >= 0n; shift -= 8n) out.push(Number((argument >> shift) & 0xffn));
    return;
  }
  out.push(base | 27);
  for (let shift = 56n; shift >= 0n; shift -= 8n) out.push(Number((argument >> shift) & 0xffn));
}

function writeFloat(value, out) {
  if (!Number.isFinite(value)) {
    throw new CanonicalError('non-finite floats MUST NOT be encoded (§2.5)');
  }
  const buffer = new DataView(new ArrayBuffer(8));

  // Shortest width that round-trips exactly (§2.5). Object.is catches -0.0,
  // which `===` does not.
  buffer.setFloat16?.(0, value);
  if (buffer.setFloat16 && Object.is(buffer.getFloat16(0), value)) {
    out.push(0xf9, buffer.getUint8(0), buffer.getUint8(1));
    return;
  }
  buffer.setFloat32(0, value);
  if (Object.is(buffer.getFloat32(0), value)) {
    out.push(0xfa);
    for (let index = 0; index < 4; index += 1) out.push(buffer.getUint8(index));
    return;
  }
  buffer.setFloat64(0, value);
  out.push(0xfb);
  for (let index = 0; index < 8; index += 1) out.push(buffer.getUint8(index));
}

// ---------------------------------------------------------------------------
// Decoding (§2.6)
// ---------------------------------------------------------------------------

export function decodeCbor(data) {
  const [value, offset] = readValue(data, 0);
  if (offset !== data.length) {
    throw new CanonicalError(`${data.length - offset} trailing byte(s) after value`);
  }
  return value;
}

function readValue(data, offset) {
  if (offset >= data.length) throw new CanonicalError('truncated input');
  const initial = data[offset];
  const major = initial >> 5;
  const minor = initial & 0x1f;
  offset += 1;

  if (major === 7) {
    const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
    if (minor === 20) return [false, offset];
    if (minor === 21) return [true, offset];
    if (minor === 22) return [null, offset];
    if (minor === 25) return [new CborFloat(view.getFloat16(offset)), offset + 2];
    if (minor === 26) return [new CborFloat(view.getFloat32(offset)), offset + 4];
    if (minor === 27) return [new CborFloat(view.getFloat64(offset)), offset + 8];
    throw new CanonicalError(`unsupported simple value ${minor}`);
  }

  let argument;
  [argument, offset] = readArgument(data, offset, minor);
  const length = Number(argument);

  if (major === 0) return [new CborUint(argument), offset];
  if (major === 2) {
    if (offset + length > data.length) throw new CanonicalError('truncated byte string');
    return [new CborBytes(data.slice(offset, offset + length)), offset + length];
  }
  if (major === 3) {
    if (offset + length > data.length) throw new CanonicalError('truncated text string');
    return [new TextDecoder('utf-8', { fatal: true }).decode(data.slice(offset, offset + length)), offset + length];
  }
  if (major === 4) {
    const items = [];
    for (let index = 0; index < length; index += 1) {
      let item;
      [item, offset] = readValue(data, offset);
      items.push(item);
    }
    return [items, offset];
  }
  if (major === 5) {
    const pairs = [];
    for (let index = 0; index < length; index += 1) {
      let key;
      let item;
      [key, offset] = readValue(data, offset);
      if (typeof key !== 'string') throw new CanonicalError('CBOR map keys must be text strings');
      [item, offset] = readValue(data, offset);
      pairs.push([key, item]);
    }
    return [new CborMap(pairs), offset];
  }
  throw new CanonicalError(`unsupported major type ${major}`);
}

function readArgument(data, offset, minor) {
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  if (minor < 24) return [BigInt(minor), offset];
  if (minor === 24) return [BigInt(data[offset]), offset + 1];
  if (minor === 25) return [BigInt(view.getUint16(offset)), offset + 2];
  if (minor === 26) return [BigInt(view.getUint32(offset)), offset + 4];
  if (minor === 27) return [view.getBigUint64(offset), offset + 8];
  throw new CanonicalError(`indefinite-length or reserved argument ${minor} is not canonical`);
}

export function blake3Digest(bytes) {
  return blake3(bytes);
}
