#!/usr/bin/env node
/**
 * Conformance adapter for the TypeScript/JS SDK — rcx-verify-contract/1 §7.
 *
 * Newline-delimited JSON on stdin, one response per line on stdout, in order.
 * Malformed input is a verdict, never a crash and never a non-zero exit.
 *
 *   ./scripts/conformance-harness.py --adapter "node sdks/typescript/adapter.mjs"
 */

import { createInterface } from 'node:readline';

import {
  CHAIN_ENTRY_ENRICHED,
  CHAIN_SNAPSHOT,
  SnapshotEntry,
  VerifyError,
  verifyHistory,
  verifyNamespace,
  verifyPublisher,
  verifyReceipt,
  verifySnapshot,
} from './index.mjs';

const invalid = (code, detail = null) => ({ valid: false, error: code, detail });

const fromError = (error) =>
  error instanceof VerifyError
    ? { valid: false, error: error.code, detail: error.detail }
    : invalid('decode_error', `${error.name}: ${error.message}`);

function unhex(request, key, expectedLength = null) {
  const raw = request?.[key];
  if (typeof raw !== 'string' || raw.length % 2 !== 0 || /[^0-9a-fA-F]/.test(raw)) return null;
  const bytes = new Uint8Array(raw.length / 2);
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(raw.slice(index * 2, index * 2 + 2), 16);
  }
  if (expectedLength !== null && bytes.length !== expectedLength) return null;
  return bytes;
}

const toHex = (bytes) =>
  Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');

const HANDLERS = {
  verifyReceipt(request) {
    const cbor = unhex(request, 'signedCanonicalCborHex');
    const key = unhex(request, 'publicKeyHex');
    if (!cbor || !key) return invalid('decode_error', 'bad hex input');
    const facts = verifyReceipt(cbor, key);
    return {
      valid: true,
      receiptHashHex: toHex(facts.receiptHash),
      signerKidPresent: Boolean(facts.signerKid),
      snapshotRootHex: facts.snapshotRoot ? toHex(facts.snapshotRoot) : null,
    };
  },

  verifySnapshot(request) {
    const expected = unhex(request, 'expectedRootHex', 32);
    if (!expected) return invalid('decode_error', 'bad expectedRootHex');
    if (!Array.isArray(request.entries)) return invalid('decode_error', 'missing entries');
    const entries = [];
    for (const item of request.entries) {
      const { name, version, canonicalJson } = item ?? {};
      if (
        typeof name !== 'string' ||
        typeof version !== 'string' ||
        typeof canonicalJson !== 'string'
      ) {
        return invalid('decode_error', 'malformed entry');
      }
      entries.push(new SnapshotEntry(name, version, canonicalJson));
    }
    verifySnapshot(entries, expected);
    return { valid: true };
  },

  verifyPublisher(request) {
    const expected = unhex(request, 'expectedDeclaredHashHex', 32);
    const declaration = request.declarationJson;
    if (!expected || typeof declaration !== 'string') {
      return invalid('decode_error', 'missing declarationJson or hash');
    }
    verifyPublisher(declaration, expected);
    return { valid: true };
  },

  verifyNamespace(request) {
    const expected = unhex(request, 'expectedDeclaredHashHex', 32);
    const declaration = request.declarationJson;
    const namespace = request.claimedNamespace;
    if (!expected || typeof declaration !== 'string' || typeof namespace !== 'string') {
      return invalid('decode_error', 'missing namespace inputs');
    }
    verifyNamespace(declaration, expected, namespace);
    return { valid: true };
  },

  verifyHistory(request) {
    const key = unhex(request, 'publicKeyHex');
    if (!key) return invalid('decode_error', 'bad publicKeyHex');
    if (request.kind !== CHAIN_SNAPSHOT && request.kind !== CHAIN_ENTRY_ENRICHED) {
      return invalid('decode_error', 'kind must be snapshot|entryEnriched');
    }
    if (!Array.isArray(request.linksHex)) return invalid('decode_error', 'missing linksHex');
    const links = [];
    for (const item of request.linksHex) {
      const bytes = unhex({ item }, 'item');
      if (!bytes) return invalid('decode_error', 'malformed link hex');
      links.push(bytes);
    }
    verifyHistory(links, key, request.kind);
    return { valid: true };
  },
};

const readline = createInterface({ input: process.stdin, crlfDelay: Infinity });

for await (const line of readline) {
  if (!line.trim()) continue;

  let response;
  let request;
  try {
    request = JSON.parse(line);
  } catch (error) {
    process.stdout.write(`${JSON.stringify(invalid('decode_error', error.message))}\n`);
    continue;
  }

  const handler = typeof request?.verb === 'string' ? HANDLERS[request.verb] : undefined;
  if (!handler) {
    const detail = request?.verb ? `unknown verb: ${request.verb}` : 'missing verb';
    process.stdout.write(`${JSON.stringify(invalid('decode_error', detail))}\n`);
    continue;
  }

  try {
    response = handler(request);
  } catch (error) {
    // A thrown error must still be a verdict — the harness has to distinguish
    // "this SDK says invalid" from "this SDK fell over".
    response = fromError(error);
  }
  process.stdout.write(`${JSON.stringify(response)}\n`);
}
