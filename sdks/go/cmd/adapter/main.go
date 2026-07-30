// Conformance adapter for the Go SDK — rcx-verify-contract/1 §7.
//
// Newline-delimited JSON on stdin, one response per line on stdout, in order.
// Malformed input is a verdict, never a crash and never a non-zero exit.
//
//	./scripts/conformance-harness.py --adapter "sdks/go/adapter-bin"
package main

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	rcxverify "github.com/CueCrux/RCX-Registry/sdks/go"
)

type request struct {
	Verb                    string         `json:"verb"`
	SignedCanonicalCborHex  string         `json:"signedCanonicalCborHex"`
	PublicKeyHex            string         `json:"publicKeyHex"`
	ExpectedRootHex         string         `json:"expectedRootHex"`
	ExpectedDeclaredHashHex string         `json:"expectedDeclaredHashHex"`
	DeclarationJSON         *string        `json:"declarationJson"`
	ClaimedNamespace        *string        `json:"claimedNamespace"`
	Kind                    string         `json:"kind"`
	LinksHex                []string       `json:"linksHex"`
	Entries                 []entryRequest `json:"entries"`
}

type entryRequest struct {
	Name          *string `json:"name"`
	Version       *string `json:"version"`
	CanonicalJSON *string `json:"canonicalJson"`
}

type response struct {
	Valid            bool    `json:"valid"`
	Error            string  `json:"error,omitempty"`
	Detail           string  `json:"detail,omitempty"`
	ReceiptHashHex   string  `json:"receiptHashHex,omitempty"`
	SignerKidPresent *bool   `json:"signerKidPresent,omitempty"`
	SnapshotRootHex  *string `json:"snapshotRootHex,omitempty"`
}

func invalid(code, detail string) response {
	return response{Valid: false, Error: code, Detail: detail}
}

func fromError(err error) response {
	var verifyError *rcxverify.VerifyError
	if errors.As(err, &verifyError) {
		return response{Valid: false, Error: verifyError.Code, Detail: verifyError.Detail}
	}
	return invalid("decode_error", err.Error())
}

func unhex(value string, expectedLen int) ([]byte, bool) {
	bytesValue, err := hex.DecodeString(value)
	if err != nil {
		return nil, false
	}
	if expectedLen > 0 && len(bytesValue) != expectedLen {
		return nil, false
	}
	return bytesValue, true
}

func doVerifyReceipt(req *request) response {
	cbor, okCbor := unhex(req.SignedCanonicalCborHex, 0)
	key, okKey := unhex(req.PublicKeyHex, 0)
	if !okCbor || !okKey {
		return invalid("decode_error", "bad hex input")
	}
	facts, err := rcxverify.VerifyReceipt(cbor, key)
	if err != nil {
		return fromError(err)
	}
	present := facts.SignerKid != ""
	out := response{
		Valid:            true,
		ReceiptHashHex:   hex.EncodeToString(facts.ReceiptHash),
		SignerKidPresent: &present,
	}
	if facts.SnapshotRoot != nil {
		encoded := hex.EncodeToString(facts.SnapshotRoot)
		out.SnapshotRootHex = &encoded
	}
	return out
}

func doVerifySnapshot(req *request) response {
	expected, ok := unhex(req.ExpectedRootHex, 32)
	if !ok {
		return invalid("decode_error", "bad expectedRootHex")
	}
	if req.Entries == nil {
		return invalid("decode_error", "missing entries")
	}
	entries := make([]rcxverify.SnapshotEntry, 0, len(req.Entries))
	for _, item := range req.Entries {
		if item.Name == nil || item.Version == nil || item.CanonicalJSON == nil {
			return invalid("decode_error", "malformed entry")
		}
		entries = append(entries, rcxverify.SnapshotEntry{
			Name:          *item.Name,
			Version:       *item.Version,
			CanonicalJSON: *item.CanonicalJSON,
		})
	}
	if err := rcxverify.VerifySnapshot(entries, expected); err != nil {
		return fromError(err)
	}
	return response{Valid: true}
}

func doVerifyPublisher(req *request) response {
	expected, ok := unhex(req.ExpectedDeclaredHashHex, 32)
	if !ok || req.DeclarationJSON == nil {
		return invalid("decode_error", "missing declarationJson or hash")
	}
	if err := rcxverify.VerifyPublisher(*req.DeclarationJSON, expected); err != nil {
		return fromError(err)
	}
	return response{Valid: true}
}

func doVerifyNamespace(req *request) response {
	expected, ok := unhex(req.ExpectedDeclaredHashHex, 32)
	if !ok || req.DeclarationJSON == nil || req.ClaimedNamespace == nil {
		return invalid("decode_error", "missing namespace inputs")
	}
	err := rcxverify.VerifyNamespace(*req.DeclarationJSON, expected, *req.ClaimedNamespace)
	if err != nil {
		return fromError(err)
	}
	return response{Valid: true}
}

func doVerifyHistory(req *request) response {
	key, ok := unhex(req.PublicKeyHex, 0)
	if !ok {
		return invalid("decode_error", "bad publicKeyHex")
	}
	kind := rcxverify.ChainKind(req.Kind)
	if kind != rcxverify.ChainSnapshot && kind != rcxverify.ChainEntryEnriched {
		return invalid("decode_error", "kind must be snapshot|entryEnriched")
	}
	if req.LinksHex == nil {
		return invalid("decode_error", "missing linksHex")
	}
	links := make([][]byte, 0, len(req.LinksHex))
	for _, item := range req.LinksHex {
		decoded, ok := unhex(item, 0)
		if !ok {
			return invalid("decode_error", "malformed link hex")
		}
		links = append(links, decoded)
	}
	if err := rcxverify.VerifyHistory(links, key, kind); err != nil {
		return fromError(err)
	}
	return response{Valid: true}
}

func dispatch(req *request) response {
	switch req.Verb {
	case "verifyReceipt":
		return doVerifyReceipt(req)
	case "verifySnapshot":
		return doVerifySnapshot(req)
	case "verifyPublisher":
		return doVerifyPublisher(req)
	case "verifyNamespace":
		return doVerifyNamespace(req)
	case "verifyHistory":
		return doVerifyHistory(req)
	case "":
		return invalid("decode_error", "missing verb")
	default:
		return invalid("decode_error", "unknown verb: "+req.Verb)
	}
}

func main() {
	scanner := bufio.NewScanner(os.Stdin)
	// Receipt and chain payloads exceed the default 64 KiB token limit.
	scanner.Buffer(make([]byte, 0, 1024*1024), 16*1024*1024)
	writer := bufio.NewWriter(os.Stdout)
	defer writer.Flush()

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var out response
		var req request
		if err := json.Unmarshal(line, &req); err != nil {
			out = invalid("decode_error", err.Error())
		} else {
			out = dispatch(&req)
		}

		encoded, err := json.Marshal(out)
		if err != nil {
			// Must still be one line per request, in order.
			encoded = []byte(`{"valid":false,"error":"decode_error"}`)
		}
		writer.Write(encoded)
		writer.WriteByte('\n')
		writer.Flush()
	}

	if err := scanner.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "adapter: stdin error:", err)
		os.Exit(1)
	}
}
