---
title: Privacy Notice
description: What RCX-Registry collects, why, and how little of it is personal.
lastUpdated: 2026-07-23
---

# Privacy Notice

Last updated: 23 July 2026

RCX-Registry is operated by CueCrux Limited. This notice explains what the service processes. The short version: the registry is about **public server metadata and cryptographic proofs**, not about profiling people.

## 1. What we process

**Mirrored server metadata.** Public metadata about MCP servers, mirrored from the upstream registry. This is public, third-party data, not personal data about you.

**Publisher verification data.** Public verification is currently disabled and production has no publisher-rights rows. If a reviewed flow opens in future, the notice will be updated to describe the proof data it processes before onboarding begins. GitHub OAuth is not currently configured in production.

**Enrichment declarations.** Public declaration submission is currently disabled. The implementation may process operator-seeded or already-discovered declarations, but its storage path currently retains receipt-hash references rather than complete signed artifacts.

**Operational logs.** Standard request logs (IP address, timestamp, path, user agent) kept transiently for security, abuse prevention, and reliability. These are minimised and time-boxed.

We do **not** run advertising trackers, third-party analytics, fingerprinting, or behavioural profiling.

## 2. Why we process it

- To operate the mirror and serve the read API.
- To develop and, once accepted, operate namespace verification and tamper-evident history capabilities.
- To secure the service and prevent abuse.

Lawful bases (UK/EU GDPR): performance of the service you request (verification, publishing) and legitimate interests (security, integrity, reliability).

## 3. Evidence retention

If complete signed snapshot or enrichment records are produced, later records may link to them and require an append-only history. None currently exists in hosted production. If a future record contains an account identifier and you exercise a data-protection right, we will assess the request against applicable retention and legal obligations and explain the outcome; this notice does not create a blanket exception to deletion rights.

## 4. Sharing

Mirrored metadata is **public** — that is what a registry is for. Verification state would also be public if the reviewed flow reopens and produces records; none exists today. Enrichment metadata is public only when present in a mirrored response. We do not sell data. We share nothing else except where legally required, or with infrastructure providers strictly to run the service (e.g. hosting, and HashiCorp Vault for signing-key custody).

## 5. Your rights

Under UK/EU GDPR and comparable laws you may request access to, correction of, or (subject to applicable legal retention obligations) deletion of personal data we hold about you, and you may object to certain processing. Contact us to exercise these rights.

## 6. Contact

`contact@cuecrux.com`, or open an issue at [github.com/CueCrux/RCX-Registry](https://github.com/CueCrux/RCX-Registry). If you’re in the UK/EEA and unsatisfied with our response, you may complain to your data protection authority (in the UK, the ICO).

## 7. Changes

Material changes are reflected in the “last updated” date above.
