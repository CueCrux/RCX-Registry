/** Offline verification for the RCX protocol (rcx-spec/v1). */

export declare const HASH_LEN: 32;
export declare const SIGNATURE_LEN: 64;
export declare const PUBLIC_KEY_LEN: 32;

export declare const CHAIN_SNAPSHOT: 'snapshot';
export declare const CHAIN_ENTRY_ENRICHED: 'entryEnriched';

export type ChainKind = typeof CHAIN_SNAPSHOT | typeof CHAIN_ENTRY_ENRICHED;

/** Frozen failure codes — rcx-verify-contract/1 §6. */
export type VerifyErrorCode =
  | 'not_canonical'
  | 'missing_field'
  | 'hash_mismatch'
  | 'bad_signature'
  | 'root_mismatch'
  | 'declaration_hash_mismatch'
  | 'namespace_mismatch'
  | 'chain_broken'
  | 'bad_public_key'
  | 'decode_error';

export declare class VerifyError extends Error {
  readonly code: VerifyErrorCode;
  readonly detail: string;
  constructor(code: VerifyErrorCode, detail?: string);
}

/** The three fields spec §6 hashes. Mirror-only fields are not required. */
export declare class SnapshotEntry {
  readonly name: string;
  readonly version: string;
  readonly canonicalJson: string;
  constructor(name: string, version: string, canonicalJson: string);
}

export interface ReceiptFacts {
  readonly receiptHash: Uint8Array;
  readonly signerKid: string;
  /** Present only on RegistrySnapshot receipts — what a snapshot chain links back to. */
  readonly snapshotRoot: Uint8Array | null;
}

export declare function verifyReceipt(
  signedCanonicalCbor: Uint8Array,
  publicKey: Uint8Array,
): ReceiptFacts;

export declare function verifySnapshot(
  entries: readonly SnapshotEntry[],
  expectedRoot: Uint8Array,
): void;

export declare function snapshotMerkleRoot(entries: readonly SnapshotEntry[]): Uint8Array;

/**
 * `declarationJson` is the RAW DOCUMENT TEXT, not a parsed object.
 *
 * `{"value":1.0}` and `{"value":1}` have distinct canonical forms and distinct
 * hashes; `JSON.parse` renders both as `1`. Passing a parsed object cannot be
 * canonicalised correctly.
 */
export declare function verifyPublisher(
  declarationJson: string,
  expectedDeclaredHash: Uint8Array,
): void;

export declare function declarationHash(declarationJson: string): {
  digest: Uint8Array;
  canonical: string;
};

/**
 * Verifies a namespace claim's internal consistency only. With no live
 * publisher-rights records this does NOT prove operator-independent
 * ownership — see CONTRACT.md §4. Key publication (spec v1 §5.6.1) does not
 * change that; the missing piece is publisher-rights records, not a key.
 */
export declare function verifyNamespace(
  declarationJson: string,
  expectedDeclaredHash: Uint8Array,
  claimedNamespace: string,
): void;

/** `kind` is explicit and never inferred — the two chain kinds link on different fields. */
export declare function verifyHistory(
  links: readonly Uint8Array[],
  publicKey: Uint8Array,
  kind: ChainKind,
): void;
