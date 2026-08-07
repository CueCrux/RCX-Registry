package rcxverify

// The five verbs of rcx-verify-contract/1. Same inputs, same outputs, same
// failure codes as the Rust reference SDK — conformance is proven by running the
// same vectors through the same harness, not by reading both implementations.
//
// Every verb is offline: no socket, no DNS, no clock.

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"sort"

	"github.com/zeebo/blake3"
)

const (
	HashLen      = 32
	SignatureLen = 64
	PublicKeyLen = 32
)

const (
	fieldReceiptHash          = "receipt_hash"
	fieldReceiptSignature     = "receipt_signature"
	fieldSignerKid            = "signer_kid"
	fieldSnapshotRoot         = "snapshot_merkle_root"
	fieldPreviousSnapshotHash = "previous_snapshot_hash"
	fieldSupersedesPrior      = "supersedes_prior"
)

// ChainKind selects which field carries the backward link.
//
// Taken explicitly and never inferred: snapshot chains link root-to-root while
// enrichment chains link receipt-to-receipt, so guessing wrong fails a sound
// chain for a reason that looks like tampering.
type ChainKind string

const (
	ChainSnapshot      ChainKind = "snapshot"
	ChainEntryEnriched ChainKind = "entryEnriched"
)

// VerifyError carries a frozen failure code (rcx-verify-contract/1 §6).
type VerifyError struct {
	Code   string
	Detail string
}

func (e *VerifyError) Error() string {
	if e.Detail == "" {
		return e.Code
	}
	return e.Code + ": " + e.Detail
}

func verifyErrorf(code, format string, args ...any) *VerifyError {
	return &VerifyError{Code: code, Detail: fmt.Sprintf(format, args...)}
}

// SnapshotEntry holds the three fields spec §6 hashes. Mirror-only fields
// (schema_uri, schema_date, status, updated_at, is_latest) never enter a digest
// and are deliberately absent.
type SnapshotEntry struct {
	Name          string
	Version       string
	CanonicalJSON string
}

// ReceiptFacts is what a verified receipt tells you, so a caller can chain
// without re-decoding.
type ReceiptFacts struct {
	ReceiptHash  []byte
	SignerKid    string
	SnapshotRoot []byte // nil unless this is a RegistrySnapshot receipt
}

func blake3Sum(data []byte) []byte {
	sum := blake3.Sum256(data)
	return sum[:]
}

// ---------------------------------------------------------------------------
// 1. verifyReceipt
// ---------------------------------------------------------------------------

// VerifyReceipt verifies a CROWN receipt from its canonical CBOR bytes
// (CONTRACT.md §1).
//
// Map-level throughout, so all six receipt types verify through one path with no
// typed decoding — which is what lets a third party verify bytes they fetched
// rather than structs only the registry can build.
func VerifyReceipt(signedCanonicalCbor, publicKey []byte) (*ReceiptFacts, error) {
	if len(publicKey) != PublicKeyLen {
		return nil, verifyErrorf("bad_public_key", "length %d", len(publicKey))
	}

	value, err := DecodeCbor(signedCanonicalCbor)
	if err != nil {
		return nil, &VerifyError{Code: "decode_error", Detail: err.Error()}
	}

	// Non-canonical input must never verify, even when it decodes: a hash covers
	// bytes, and these are not the bytes anybody published.
	reencoded, err := EncodeCbor(value)
	if err != nil {
		return nil, &VerifyError{Code: "decode_error", Detail: err.Error()}
	}
	if !bytes.Equal(reencoded, signedCanonicalCbor) {
		return nil, &VerifyError{
			Code:   "not_canonical",
			Detail: "re-encoding did not reproduce the input",
		}
	}

	receipt, ok := value.(*CborMap)
	if !ok {
		return nil, &VerifyError{Code: "decode_error", Detail: "receipt is not a CBOR map"}
	}

	storedHash, err := takeCborBytes(receipt, fieldReceiptHash, HashLen)
	if err != nil {
		return nil, err
	}
	storedSignature, err := takeCborBytes(receipt, fieldReceiptSignature, SignatureLen)
	if err != nil {
		return nil, err
	}

	rawKid, present := receipt.Get(fieldSignerKid)
	if !present {
		return nil, &VerifyError{Code: "missing_field", Detail: fieldSignerKid}
	}
	signerKid, ok := rawKid.(string)
	if !ok {
		return nil, &VerifyError{Code: "decode_error", Detail: "signer_kid is not text"}
	}

	// Step 3 — hash over the zeroed-field encoding (§5.3). signer_kid becomes
	// Null, not an empty string: the zeroed form changes that field's TYPE.
	zeroed := receipt.Replace(map[string]any{
		fieldReceiptHash:      make(CborBytes, HashLen),
		fieldReceiptSignature: make(CborBytes, SignatureLen),
		fieldSignerKid:        nil,
	})
	zeroedBytes, err := EncodeCbor(zeroed)
	if err != nil {
		return nil, &VerifyError{Code: "decode_error", Detail: err.Error()}
	}
	if !bytes.Equal(blake3Sum(zeroedBytes), storedHash) {
		return nil, &VerifyError{Code: "hash_mismatch"}
	}

	// Step 4 — signature over the full encoding with ONLY the signature zeroed.
	// A different preimage from step 3; conflating them is the OQ-1 defect.
	preimage, err := EncodeCbor(receipt.Replace(map[string]any{
		fieldReceiptSignature: make(CborBytes, SignatureLen),
	}))
	if err != nil {
		return nil, &VerifyError{Code: "decode_error", Detail: err.Error()}
	}
	if !ed25519.Verify(ed25519.PublicKey(publicKey), preimage, storedSignature) {
		return nil, &VerifyError{Code: "bad_signature"}
	}

	facts := &ReceiptFacts{ReceiptHash: storedHash, SignerKid: signerKid}
	if root, ok := receipt.Get(fieldSnapshotRoot); ok {
		if rootBytes, ok := root.(CborBytes); ok && len(rootBytes) == HashLen {
			facts.SnapshotRoot = rootBytes
		}
	}
	return facts, nil
}

func takeCborBytes(receipt *CborMap, key string, expectedLen int) ([]byte, error) {
	raw, present := receipt.Get(key)
	if !present {
		return nil, &VerifyError{Code: "missing_field", Detail: key}
	}
	value, ok := raw.(CborBytes)
	if !ok {
		return nil, verifyErrorf("decode_error", "%s is not a byte string", key)
	}
	if len(value) != expectedLen {
		return nil, verifyErrorf("decode_error", "%s is %d bytes, expected %d",
			key, len(value), expectedLen)
	}
	return value, nil
}

// ---------------------------------------------------------------------------
// 2. verifySnapshot
// ---------------------------------------------------------------------------

// SnapshotMerkleRoot computes the flat BLAKE3 set digest over lex-sorted entries
// (§6).
//
// Not a tree despite the wire field name — no inclusion proof is derivable from
// it (OQ-4). The real tree arrives as spec v2.
func SnapshotMerkleRoot(entries []SnapshotEntry) []byte {
	ordered := make([]SnapshotEntry, len(entries))
	copy(ordered, entries)
	// Go string comparison is bytewise, matching Rust's String ordering.
	sort.SliceStable(ordered, func(i, j int) bool {
		if ordered[i].Name != ordered[j].Name {
			return ordered[i].Name < ordered[j].Name
		}
		return ordered[i].Version < ordered[j].Version
	})

	hasher := blake3.New()
	for _, entry := range ordered {
		hasher.WriteString(entry.Name)
		hasher.Write([]byte{0})
		hasher.WriteString(entry.Version)
		hasher.Write([]byte{0})
		hasher.WriteString(entry.CanonicalJSON)
		hasher.Write([]byte{0xff})
	}
	return hasher.Sum(nil)
}

// VerifySnapshot recomputes the set digest and compares it to the published root.
func VerifySnapshot(entries []SnapshotEntry, expectedRoot []byte) error {
	if !bytes.Equal(SnapshotMerkleRoot(entries), expectedRoot) {
		return &VerifyError{Code: "root_mismatch"}
	}
	return nil
}

// ---------------------------------------------------------------------------
// 3. verifyPublisher
// ---------------------------------------------------------------------------

// DeclarationHash hashes a publisher declaration from its RAW DOCUMENT TEXT
// (§3, §4.4).
//
// Text, not a parsed value, and in Go this is a correctness requirement rather
// than a preference: unmarshalling into any gives float64 for every number, so
// {"value":1.0} and {"value":1} — distinct vectors with distinct hashes — become
// indistinguishable. Parsing here with UseNumber keeps each literal intact.
func DeclarationHash(declarationJSON string) ([]byte, string, error) {
	parsed, err := ParseJSONPreservingNumbers(declarationJSON)
	if err != nil {
		return nil, "", &VerifyError{Code: "decode_error", Detail: err.Error()}
	}
	canonical, err := CanonicalizeJSON(parsed)
	if err != nil {
		return nil, "", &VerifyError{Code: "decode_error", Detail: err.Error()}
	}
	return blake3Sum([]byte(canonical)), canonical, nil
}

// VerifyPublisher recomputes a declaration's hash from raw text and compares.
func VerifyPublisher(declarationJSON string, expectedDeclaredHash []byte) error {
	digest, _, err := DeclarationHash(declarationJSON)
	if err != nil {
		return err
	}
	if !bytes.Equal(digest, expectedDeclaredHash) {
		return &VerifyError{Code: "declaration_hash_mismatch"}
	}
	return nil
}

// ---------------------------------------------------------------------------
// 4. verifyNamespace
// ---------------------------------------------------------------------------

// VerifyNamespace verifies a namespace claim's internal consistency.
//
// Read CONTRACT.md §4's scope limit before relying on this: with no published
// signer_kid -> public-key mapping (OQ-2) and no live publisher-rights records,
// it does NOT prove operator-independent ownership.
func VerifyNamespace(declarationJSON string, expectedDeclaredHash []byte, claimedNamespace string) error {
	if err := VerifyPublisher(declarationJSON, expectedDeclaredHash); err != nil {
		return err
	}
	parsed, err := ParseJSONPreservingNumbers(declarationJSON)
	if err != nil {
		return &VerifyError{Code: "decode_error", Detail: err.Error()}
	}
	object, ok := parsed.(map[string]any)
	if !ok {
		return &VerifyError{Code: "missing_field", Detail: "mcp_name"}
	}
	rawName, present := object["mcp_name"]
	if !present {
		return &VerifyError{Code: "missing_field", Detail: "mcp_name"}
	}
	name, ok := rawName.(string)
	if !ok || name != claimedNamespace {
		return &VerifyError{Code: "namespace_mismatch"}
	}
	return nil
}

// ---------------------------------------------------------------------------
// 5. verifyHistory
// ---------------------------------------------------------------------------

// VerifyHistory verifies each link, then the backward references
// (CONTRACT.md §5).
//
// links is in chain order, oldest first. The first link's backward reference is
// absent and is not a break.
func VerifyHistory(links [][]byte, publicKey []byte, kind ChainKind) error {
	if kind != ChainSnapshot && kind != ChainEntryEnriched {
		return verifyErrorf("decode_error", "unknown chain kind %q", kind)
	}

	var previous *ReceiptFacts
	for index, raw := range links {
		facts, err := VerifyReceipt(raw, publicKey)
		if err != nil {
			return err
		}

		if previous != nil {
			value, err := DecodeCbor(raw)
			if err != nil {
				return &VerifyError{Code: "decode_error", Detail: err.Error()}
			}
			receipt, ok := value.(*CborMap)
			if !ok {
				return &VerifyError{Code: "decode_error", Detail: "receipt is not a CBOR map"}
			}

			var linkField string
			var expected []byte
			if kind == ChainSnapshot {
				linkField = fieldPreviousSnapshotHash
				if previous.SnapshotRoot == nil {
					return &VerifyError{Code: "missing_field", Detail: fieldSnapshotRoot}
				}
				expected = previous.SnapshotRoot
			} else {
				linkField = fieldSupersedesPrior
				expected = previous.ReceiptHash
			}

			rawLink, present := receipt.Get(linkField)
			if !present {
				return verifyErrorf("chain_broken", "at link %d", index)
			}
			actual, ok := rawLink.(CborBytes)
			if !ok || !bytes.Equal(actual, expected) {
				return verifyErrorf("chain_broken", "at link %d", index)
			}
		}

		previous = facts
	}
	return nil
}
