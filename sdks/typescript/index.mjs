/**
 * Offline verification for the RCX protocol (rcx-spec/v1).
 *
 * The five verbs of rcx-verify-contract/1. Same inputs, same outputs, same
 * failure codes as the Rust reference SDK — conformance is proven by running the
 * same vectors through the same harness, not by reading both implementations.
 *
 * Offline: no socket, no DNS, no clock.
 */

import { ed25519 } from '@noble/curves/ed25519.js';

import {
  CanonicalError,
  CborBytes,
  CborMap,
  blake3Digest,
  canonicalizeJson,
  decodeCbor,
  encodeCbor,
  parseJsonPreservingNumbers,
} from './canonical.mjs';

export const HASH_LEN = 32;
export const SIGNATURE_LEN = 64;
export const PUBLIC_KEY_LEN = 32;

export const CHAIN_SNAPSHOT = 'snapshot';
export const CHAIN_ENTRY_ENRICHED = 'entryEnriched';

const FIELD_RECEIPT_HASH = 'receipt_hash';
const FIELD_RECEIPT_SIGNATURE = 'receipt_signature';
const FIELD_SIGNER_KID = 'signer_kid';
const FIELD_SNAPSHOT_ROOT = 'snapshot_merkle_root';
const FIELD_PREVIOUS_SNAPSHOT_HASH = 'previous_snapshot_hash';
const FIELD_SUPERSEDES_PRIOR = 'supersedes_prior';

/** Verification failed. `code` is frozen for rcx-verify-contract/1 §6. */
export class VerifyError extends Error {
  constructor(code, detail = '') {
    super(detail ? `${code}: ${detail}` : code);
    this.code = code;
    this.detail = detail;
  }
}

/** The three fields spec §6 hashes. Mirror-only fields are not required. */
export class SnapshotEntry {
  constructor(name, version, canonicalJson) {
    this.name = name;
    this.version = version;
    this.canonicalJson = canonicalJson;
  }
}

function equalBytes(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let index = 0; index < a.length; index += 1) diff |= a[index] ^ b[index];
  return diff === 0;
}

// ---------------------------------------------------------------------------
// 1. verifyReceipt
// ---------------------------------------------------------------------------

/**
 * Verify a CROWN receipt from its canonical CBOR bytes (CONTRACT.md §1).
 *
 * Map-level throughout, so all six receipt types verify through one path with no
 * typed decoding.
 */
export function verifyReceipt(signedCanonicalCbor, publicKey) {
  if (publicKey.length !== PUBLIC_KEY_LEN) {
    throw new VerifyError('bad_public_key', `length ${publicKey.length}`);
  }

  let value;
  try {
    value = decodeCbor(signedCanonicalCbor);
  } catch (error) {
    throw new VerifyError('decode_error', error.message);
  }

  // Non-canonical input must never verify, even when it decodes: a hash covers
  // bytes, and these are not the bytes anybody published.
  let reencoded;
  try {
    reencoded = encodeCbor(value);
  } catch (error) {
    throw new VerifyError('decode_error', error.message);
  }
  if (!equalBytes(reencoded, signedCanonicalCbor)) {
    throw new VerifyError('not_canonical', 're-encoding did not reproduce the input');
  }

  if (!(value instanceof CborMap)) {
    throw new VerifyError('decode_error', 'receipt is not a CBOR map');
  }

  const storedHash = takeBytes(value, FIELD_RECEIPT_HASH, HASH_LEN);
  const storedSignature = takeBytes(value, FIELD_RECEIPT_SIGNATURE, SIGNATURE_LEN);

  if (!value.has(FIELD_SIGNER_KID)) {
    throw new VerifyError('missing_field', FIELD_SIGNER_KID);
  }
  const signerKid = value.get(FIELD_SIGNER_KID);
  if (typeof signerKid !== 'string') {
    throw new VerifyError('decode_error', 'signer_kid is not text');
  }

  // Step 3 — hash over the zeroed-field encoding (§5.3). signer_kid becomes
  // Null, not an empty string: the zeroed form changes that field's TYPE.
  const zeroed = value.replace({
    [FIELD_RECEIPT_HASH]: new CborBytes(new Uint8Array(HASH_LEN)),
    [FIELD_RECEIPT_SIGNATURE]: new CborBytes(new Uint8Array(SIGNATURE_LEN)),
    [FIELD_SIGNER_KID]: null,
  });
  if (!equalBytes(blake3Digest(encodeCbor(zeroed)), storedHash)) {
    throw new VerifyError('hash_mismatch');
  }

  // Step 4 — signature over the full encoding with ONLY the signature zeroed. A
  // different preimage from step 3; conflating them is the OQ-1 defect.
  const preimage = encodeCbor(
    value.replace({ [FIELD_RECEIPT_SIGNATURE]: new CborBytes(new Uint8Array(SIGNATURE_LEN)) }),
  );

  let ok;
  try {
    ok = ed25519.verify(storedSignature, preimage, publicKey);
  } catch (error) {
    throw new VerifyError('bad_signature', error.message);
  }
  if (!ok) throw new VerifyError('bad_signature');

  const rootField = value.get(FIELD_SNAPSHOT_ROOT);
  const snapshotRoot =
    rootField instanceof CborBytes && rootField.value.length === HASH_LEN ? rootField.value : null;

  return { receiptHash: storedHash, signerKid, snapshotRoot };
}

function takeBytes(map, key, expectedLength) {
  if (!map.has(key)) throw new VerifyError('missing_field', key);
  const field = map.get(key);
  if (!(field instanceof CborBytes)) {
    throw new VerifyError('decode_error', `${key} is not a byte string`);
  }
  if (field.value.length !== expectedLength) {
    throw new VerifyError(
      'decode_error',
      `${key} is ${field.value.length} bytes, expected ${expectedLength}`,
    );
  }
  return field.value;
}

// ---------------------------------------------------------------------------
// 2. verifySnapshot
// ---------------------------------------------------------------------------

/** Flat BLAKE3 set digest over lex-sorted entries (§6). Not a tree (OQ-4). */
export function snapshotMerkleRoot(entries) {
  const encoder = new TextEncoder();
  const ordered = [...entries].sort((a, b) =>
    a.name === b.name ? compareStrings(a.version, b.version) : compareStrings(a.name, b.name),
  );
  const parts = [];
  for (const entry of ordered) {
    parts.push(encoder.encode(entry.name), Uint8Array.of(0));
    parts.push(encoder.encode(entry.version), Uint8Array.of(0));
    parts.push(encoder.encode(entry.canonicalJson), Uint8Array.of(0xff));
  }
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const buffer = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    buffer.set(part, offset);
    offset += part.length;
  }
  return blake3Digest(buffer);
}

/**
 * Byte-order comparison, matching Rust's `String` ordering.
 *
 * NOT `<` on JS strings: that compares UTF-16 code units, so an astral-plane name
 * sorts differently from Rust and the root would diverge on exactly the inputs
 * the vectors were built to catch.
 */
function compareStrings(a, b) {
  const encoder = new TextEncoder();
  const left = encoder.encode(a);
  const right = encoder.encode(b);
  const shared = Math.min(left.length, right.length);
  for (let index = 0; index < shared; index += 1) {
    if (left[index] !== right[index]) return left[index] - right[index];
  }
  return left.length - right.length;
}

export function verifySnapshot(entries, expectedRoot) {
  if (!equalBytes(snapshotMerkleRoot(entries), expectedRoot)) {
    throw new VerifyError('root_mismatch');
  }
}

// ---------------------------------------------------------------------------
// 3. verifyPublisher
// ---------------------------------------------------------------------------

/**
 * Hash a publisher declaration from its RAW DOCUMENT TEXT (§3, §4.4).
 *
 * Text, not a parsed object, and in JavaScript this is not a preference but a
 * correctness requirement: `{"value":1.0}` and `{"value":1}` are distinct vectors
 * with distinct hashes, and `JSON.parse` renders both as the number 1. We parse
 * the text ourselves, preserving the literal.
 */
export function declarationHash(declarationJson) {
  let parsed;
  try {
    parsed = parseJsonPreservingNumbers(declarationJson);
  } catch (error) {
    if (error instanceof CanonicalError) throw new VerifyError('decode_error', error.message);
    throw error;
  }
  const canonical = canonicalizeJson(parsed);
  return { digest: blake3Digest(new TextEncoder().encode(canonical)), canonical };
}

export function verifyPublisher(declarationJson, expectedDeclaredHash) {
  const { digest } = declarationHash(declarationJson);
  if (!equalBytes(digest, expectedDeclaredHash)) {
    throw new VerifyError('declaration_hash_mismatch');
  }
}

// ---------------------------------------------------------------------------
// 4. verifyNamespace
// ---------------------------------------------------------------------------

/**
 * Verify a namespace claim's internal consistency.
 *
 * Read CONTRACT.md §4's scope limit: with no live publisher-rights records, this
 * does NOT prove operator-independent ownership. Key publication (spec v1
 * §5.6.1) does not change that; the missing piece is publisher-rights records,
 * not a key.
 */
export function verifyNamespace(declarationJson, expectedDeclaredHash, claimedNamespace) {
  verifyPublisher(declarationJson, expectedDeclaredHash);
  const parsed = JSON.parse(declarationJson);
  if (parsed === null || typeof parsed !== 'object' || !('mcp_name' in parsed)) {
    throw new VerifyError('missing_field', 'mcp_name');
  }
  if (parsed.mcp_name !== claimedNamespace) {
    throw new VerifyError('namespace_mismatch');
  }
}

// ---------------------------------------------------------------------------
// 5. verifyHistory
// ---------------------------------------------------------------------------

/**
 * Verify each link, then the backward references (CONTRACT.md §5).
 *
 * `kind` is explicit and never inferred: snapshot chains link root-to-root while
 * enrichment chains link receipt-to-receipt, so guessing wrong fails a sound
 * chain in a way that looks like tampering.
 */
export function verifyHistory(links, publicKey, kind) {
  if (kind !== CHAIN_SNAPSHOT && kind !== CHAIN_ENTRY_ENRICHED) {
    throw new VerifyError('decode_error', `unknown chain kind ${kind}`);
  }

  let previous = null;
  for (let index = 0; index < links.length; index += 1) {
    const facts = verifyReceipt(links[index], publicKey);

    if (previous !== null) {
      const value = decodeCbor(links[index]);
      let linkField;
      let expected;
      if (kind === CHAIN_SNAPSHOT) {
        linkField = FIELD_PREVIOUS_SNAPSHOT_HASH;
        if (previous.snapshotRoot === null) {
          throw new VerifyError('missing_field', FIELD_SNAPSHOT_ROOT);
        }
        expected = previous.snapshotRoot;
      } else {
        linkField = FIELD_SUPERSEDES_PRIOR;
        expected = previous.receiptHash;
      }

      const actual = value.get(linkField);
      if (!(actual instanceof CborBytes) || !equalBytes(actual.value, expected)) {
        throw new VerifyError('chain_broken', `at link ${index}`);
      }
    }

    previous = facts;
  }
}
