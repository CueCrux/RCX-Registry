# RCX RFCs

Changes to the RCX protocol happen here, in public, before they happen in code.

`rcx-spec/v1` is frozen. Any change to what bytes go on the wire — a new receipt
type, a new hash input, a change to canonical encoding, a new proof format —
requires an accepted RFC and a spec version bump. Implementation detail, SDK
ergonomics, docs and deployment are *not* RFC matters; open a normal issue.

## Why this exists before the cryptography

RCX's claim is that you can verify the registry without trusting its operator.
An operator who designs the verification cryptography in private and ships it as
a fait accompli has not earned that claim, whatever the code does. So the process
comes first and the transparency-log constructions ([RFC-0001](0001-transparency-log.md))
go through it as the first live proposal.

We would rather find out that a proof construction is wrong from a reviewer than
from an attacker.

## Lifecycle

| Stage | What it means | Who moves it |
|---|---|---|
| **Draft** | Open PR adding `rfcs/NNNN-title.md`. Incomplete is fine; say what is unresolved. | Author |
| **Review** | Merged as Draft, comment period open. Minimum **28 days** for anything touching cryptography or wire format. | Anyone |
| **Reference implementation** | Behind a version negotiation flag, with conformance vectors. Merging code does **not** accept the RFC. | Author |
| **Accepted** | Comment period closed, blocking concerns resolved or documented as accepted risk, human gate recorded. | Maintainers |
| **Released** | Ships in a spec version. Vectors published. | Maintainers |
| **Withdrawn** / **Superseded** | Kept in place, marked, never deleted. A rejected idea is part of the record. | Either |

An RFC's status lives in its own front matter. `Draft` and `Review` RFCs are not
promises.

## Rules that are not negotiable

1. **No wire change without a released RFC.** Receipts already minted must keep
   verifying — additively, behind version negotiation, forever. A change that
   invalidates a published receipt is not a change, it is a break.
2. **Vectors ship with the proposal, not after it.** A construction described only
   in prose is a construction two implementations will disagree about. Spec v1's
   own review found 13 ambiguities and 16 defects in exactly this way, from an
   independent re-implementation working off prose alone.
3. **The comment period is real.** Code may merge during Review; the RFC is not
   Accepted until the period closes. If nobody comments, that is an outcome, not
   a formality to skip.
4. **Cryptographic RFCs get external review** before Accepted. Maintainer
   agreement is not review.

## Filing one

Copy [`0000-template.md`](0000-template.md), number it with the next free integer,
open a PR. State the problem before the solution, and list what you could not
resolve — an RFC with an honest "Unresolved" section is more useful than one that
pretends to be finished.

## Invited reviewers

The problems RCX is solving are not new, and the people who have solved adjacent
versions are explicitly invited to tell us where we are wrong:

- **[Sigstore](https://www.sigstore.dev/)** — transparency logs for software artifacts; Rekor's inclusion-proof and witness design.
- **Certificate Transparency** ([RFC 6962](https://www.rfc-editor.org/rfc/rfc6962), [RFC 9162](https://www.rfc-editor.org/rfc/rfc9162)) — the origin of the log-plus-witness model RFC-0001 borrows.
- **[IETF SCITT](https://datatracker.ietf.org/wg/scitt/about/)** — supply-chain transparency, receipt formats, registry semantics.
- **[Transparency.dev](https://transparency.dev/)** — Trillian, tile-based logs, witness protocols.

If you maintain one of these and RFC-0001 repeats a mistake your ecosystem
already made, that comment is the most valuable thing this repository could
receive.
