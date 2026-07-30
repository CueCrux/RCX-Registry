#!/usr/bin/env python3
"""Language-agnostic RCX verify-SDK conformance harness.

Drives any SDK that speaks the adapter protocol (CONTRACT.md §7) against the
spec-v1 conformance vectors, and reports whether it conforms.

    ./scripts/conformance-harness.py --adapter "./target/debug/rcx-verify-adapter"
    ./scripts/conformance-harness.py --adapter "python3 sdks/python/adapter.py"
    ./scripts/conformance-harness.py --adapter "node sdks/typescript/adapter.mjs"

Stdlib only, on purpose. The harness must not need the toolchain of any SDK it
tests, and it must not be able to accidentally verify anything itself — it knows
how to read vectors and compare strings, and nothing about BLAKE3, CBOR or
Ed25519. If it could hash, a bug here could mask a bug there.

Exit 0 = conformant. Exit 1 = not. Exit 2 = the harness could not run the check,
which is deliberately distinct from a failure: "we could not look" must never be
reported as "we looked and it was fine".
"""

from __future__ import annotations

import argparse
import json
import shlex
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
VECTOR_DIR = REPO_ROOT / "spec" / "v1" / "vectors"


class Check:
    """One request/expectation pair."""

    __slots__ = ("verb", "case", "request", "expect_valid", "expect_error", "expect_fields")

    def __init__(self, verb, case, request, expect_valid, expect_error=None, expect_fields=None):
        self.verb = verb
        self.case = case
        self.request = request
        self.expect_valid = expect_valid
        self.expect_error = expect_error
        self.expect_fields = expect_fields or {}


def load(name: str) -> dict:
    path = VECTOR_DIR / name
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        sys.exit(f"harness cannot run: vector file missing: {path}")
    except json.JSONDecodeError as exc:
        sys.exit(f"harness cannot run: {path} is not valid JSON: {exc}")


def build_checks() -> list[Check]:
    checks: list[Check] = []

    # --- verifySnapshot -----------------------------------------------------
    merkle = load("snapshot-merkle.json")
    for case in merkle["cases"]:
        entries = [
            {
                "name": e["name"],
                "version": e["version"],
                "canonicalJson": e["canonical_json"],
            }
            for e in case["input_order"]
        ]
        checks.append(
            Check(
                "verifySnapshot",
                case["id"],
                {
                    "verb": "verifySnapshot",
                    "entries": entries,
                    "expectedRootHex": case["root_hex"],
                },
                True,
            )
        )
        # Negative: flip one bit of the expected root. Without this, an SDK that
        # unconditionally returns valid passes every positive case above.
        flipped = flip_first_nibble(case["root_hex"])
        checks.append(
            Check(
                "verifySnapshot",
                case["id"] + "/tampered-root",
                {
                    "verb": "verifySnapshot",
                    "entries": entries,
                    "expectedRootHex": flipped,
                },
                False,
                expect_error="root_mismatch",
            )
        )

    # --- verifyPublisher ----------------------------------------------------
    hashes = load("hashes.json")
    for case in hashes["declaration_hash"]["cases"]:
        declaration = json.loads(case["input_json"])
        checks.append(
            Check(
                "verifyPublisher",
                case["id"],
                {
                    "verb": "verifyPublisher",
                    "declaration": declaration,
                    "expectedDeclaredHashHex": case["digest_hex"],
                },
                True,
            )
        )
        checks.append(
            Check(
                "verifyPublisher",
                case["id"] + "/tampered-digest",
                {
                    "verb": "verifyPublisher",
                    "declaration": declaration,
                    "expectedDeclaredHashHex": flip_first_nibble(case["digest_hex"]),
                },
                False,
                expect_error="declaration_hash_mismatch",
            )
        )

    # --- verifyReceipt ------------------------------------------------------
    receipts = load("receipts.json")
    public_key = receipts["test_key"]["public_key_hex"]
    for case in receipts["cases"]:
        checks.append(
            Check(
                "verifyReceipt",
                case["id"],
                {
                    "verb": "verifyReceipt",
                    "signedCanonicalCborHex": case["signed_canonical_cbor_hex"],
                    "publicKeyHex": public_key,
                },
                True,
                expect_fields={"receiptHashHex": case["receipt_hash_hex"]},
            )
        )
        # Wrong key must not verify.
        checks.append(
            Check(
                "verifyReceipt",
                case["id"] + "/wrong-key",
                {
                    "verb": "verifyReceipt",
                    "signedCanonicalCborHex": case["signed_canonical_cbor_hex"],
                    "publicKeyHex": flip_first_nibble(public_key),
                },
                False,
            )
        )
        for negative in case.get("negative_cases", []):
            body = negative.get("tampered_canonical_cbor_hex") or negative.get(
                "signed_canonical_cbor_hex"
            )
            if not body:
                continue
            checks.append(
                Check(
                    "verifyReceipt",
                    f"{case['id']}/{negative['id']}",
                    {
                        "verb": "verifyReceipt",
                        "signedCanonicalCborHex": body,
                        "publicKeyHex": public_key,
                    },
                    False,
                )
            )

    # --- verifyHistory ------------------------------------------------------
    chains = load("chains.json")
    chain_key = chains["test_key"]["public_key_hex"]
    for vector_key, kind in (
        ("snapshot_chain", "snapshot"),
        ("entry_enriched_receipt_chain", "entryEnriched"),
    ):
        links = [link["signed_canonical_cbor_hex"] for link in chains[vector_key]["links"]]
        checks.append(
            Check(
                "verifyHistory",
                f"{vector_key}/intact",
                {
                    "verb": "verifyHistory",
                    "linksHex": links,
                    "publicKeyHex": chain_key,
                    "kind": kind,
                },
                True,
            )
        )
        # Removing an interior link must break the chain, or the link field is
        # not being read at all.
        gapped = links[:1] + links[2:]
        checks.append(
            Check(
                "verifyHistory",
                f"{vector_key}/link-removed",
                {
                    "verb": "verifyHistory",
                    "linksHex": gapped,
                    "publicKeyHex": chain_key,
                    "kind": kind,
                },
                False,
            )
        )

    # A snapshot chain must NOT verify under the enrichment link rule. The two
    # kinds link on different fields to different targets (CONTRACT.md §5); this
    # is what proves the rule is applied rather than assumed.
    snapshot_links = [
        link["signed_canonical_cbor_hex"] for link in chains["snapshot_chain"]["links"]
    ]
    checks.append(
        Check(
            "verifyHistory",
            "snapshot_chain/under-wrong-link-rule",
            {
                "verb": "verifyHistory",
                "linksHex": snapshot_links,
                "publicKeyHex": chain_key,
                "kind": "entryEnriched",
            },
            False,
        )
    )

    # --- protocol hygiene ---------------------------------------------------
    # Malformed input is a verdict, not a crash: a harness must be able to tell
    # "this SDK says invalid" from "this SDK fell over".
    checks.append(
        Check("protocol", "unknown-verb", {"verb": "nonsense"}, False, expect_error="decode_error")
    )
    checks.append(
        Check("protocol", "no-verb", {"not": "a verb"}, False, expect_error="decode_error")
    )

    return checks


def flip_first_nibble(hex_string: str) -> str:
    """Change one hex digit, preserving length."""
    first = hex_string[0]
    replacement = "1" if first != "1" else "2"
    return replacement + hex_string[1:]


def run_adapter(command: str, checks: list[Check]) -> list[dict]:
    argv = shlex.split(command)
    payload = "".join(json.dumps(check.request) + "\n" for check in checks)

    try:
        completed = subprocess.run(
            argv,
            input=payload,
            capture_output=True,
            text=True,
            timeout=120,
        )
    except FileNotFoundError:
        sys.exit(f"harness cannot run: adapter not found: {argv[0]}")
    except subprocess.TimeoutExpired:
        sys.exit("harness cannot run: adapter did not finish within 120s")

    if completed.returncode != 0:
        sys.exit(
            "harness cannot run: adapter exited "
            f"{completed.returncode}\nstderr:\n{completed.stderr[:4000]}"
        )

    lines = [line for line in completed.stdout.splitlines() if line.strip()]
    if len(lines) != len(checks):
        sys.exit(
            "harness cannot run: adapter returned "
            f"{len(lines)} responses for {len(checks)} requests — the protocol is "
            "one response per request, in order"
        )

    responses = []
    for index, line in enumerate(lines):
        try:
            responses.append(json.loads(line))
        except json.JSONDecodeError:
            sys.exit(
                f"harness cannot run: response {index} is not JSON: {line[:200]!r}"
            )
    return responses


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--adapter", required=True, help="adapter command to run")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    checks = build_checks()

    # Positive control. If vector parsing silently produced nothing, every
    # assertion below would trivially hold and the run would report success.
    if len(checks) < 40:
        sys.exit(
            f"harness cannot run: only built {len(checks)} checks, which means "
            "vector parsing failed — a green result here would be meaningless"
        )
    verbs = {check.verb for check in checks}
    missing = {
        "verifySnapshot",
        "verifyPublisher",
        "verifyReceipt",
        "verifyHistory",
    } - verbs
    if missing:
        sys.exit(f"harness cannot run: no checks built for {sorted(missing)}")

    responses = run_adapter(args.adapter, checks)

    failures = []
    per_verb: dict[str, list[int]] = {}
    for check, response in zip(checks, responses):
        passed, reason = evaluate(check, response)
        counts = per_verb.setdefault(check.verb, [0, 0])
        counts[0 if passed else 1] += 1
        if not passed:
            failures.append((check, reason))
        elif args.verbose:
            print(f"  ok   {check.verb} {check.case}")

    print(f"\nadapter: {args.adapter}")
    print(f"checks:  {len(checks)}\n")
    for verb in sorted(per_verb):
        ok, bad = per_verb[verb]
        marker = "ok  " if bad == 0 else "FAIL"
        print(f"  {marker} {verb:<16} {ok} passed, {bad} failed")

    if failures:
        print(f"\n{len(failures)} failure(s):")
        for check, reason in failures[:25]:
            print(f"  {check.verb} {check.case}: {reason}")
        if len(failures) > 25:
            print(f"  ... and {len(failures) - 25} more")
        print("\nNOT CONFORMANT")
        return 1

    print("\nCONFORMANT")
    return 0


def evaluate(check: Check, response: dict) -> tuple[bool, str]:
    if not isinstance(response, dict) or "valid" not in response:
        return False, f"response has no 'valid' field: {response!r}"

    valid = response["valid"]
    if valid is not check.expect_valid:
        return False, f"expected valid={check.expect_valid}, got valid={valid}"

    if not check.expect_valid and check.expect_error is not None:
        actual = response.get("error")
        if actual != check.expect_error:
            return False, f"expected error={check.expect_error!r}, got {actual!r}"

    for field, expected in check.expect_fields.items():
        actual = response.get(field)
        if actual != expected:
            return False, f"{field}: expected {expected!r}, got {actual!r}"

    return True, ""


if __name__ == "__main__":
    sys.exit(main())
