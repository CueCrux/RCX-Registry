---
rfc: 0000
title: Template
status: Template
spec-target: n/a
created: 2026-07-30
comment-period-closes: n/a
---

# RFC-0000: Template

## Summary

One paragraph. What changes, for whom.

## Problem

What is wrong or missing today. Ground it: name the file, the field, the endpoint,
the vector. "Users want X" is not a problem statement; "a verifier holding a
published root cannot determine whether a given server was in it, because the
root is a flat digest ([`ingest/src/lib.rs`](../crates/rcx-registry-ingest/src/lib.rs))"
is.

State the problem before you have decided the solution. If the problem section
only makes sense once you know the proposal, it is a solution wearing a disguise.

## Proposal

The change. Normative language (MUST / SHOULD / MAY per RFC 2119) for anything
that goes on the wire.

## Wire format

Exact bytes. Encoding, field names, hash inputs, signature preimages. If this
section says "similar to §5" it is not finished — say which bytes, in which order,
hashed in which canonical form.

## Conformance vectors

What vectors ship with this RFC. A construction with no vectors is a construction
two implementations will disagree about; see the process rules.

## Compatibility

- What existing clients do when they meet this. (Answer must not be "break".)
- What already-minted receipts do. (Answer must be "keep verifying".)
- Version negotiation: how a client says it understands this.

## Security considerations

What this protects against. **What it does not.** Who has to be honest for it to
hold, and what happens when they are not — the second half is the part reviewers
need and authors skip.

## Alternatives considered

Including doing nothing. Say why each was rejected; "we preferred ours" is not a
reason.

## Unresolved

Open questions, honestly. An RFC that claims none is either trivial or hiding
something.
