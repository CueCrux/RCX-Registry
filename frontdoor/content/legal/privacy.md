---
title: Privacy Notice
description: What RCX-Registry collects, why, and how little of it is personal.
lastUpdated: 2026-07-19
---

# Privacy Notice

Last updated: 19 July 2026

RCX-Registry is operated by CueCrux Limited. This notice explains what the service processes. The short version: the registry is about **public server metadata and cryptographic proofs**, not about profiling people.

## 1. What we process

**Mirrored server metadata.** Public metadata about MCP servers, mirrored from the upstream registry. This is public, third-party data, not personal data about you.

**Publisher verification data.** When you claim a namespace we process what’s needed to verify it: for DNS, the domain and a one-time challenge token resolved from your TXT record; for GitHub, your GitHub account identity via OAuth (login/id and the org or user the namespace maps to). We store the verification outcome and a receipt, not your GitHub credentials.

**Enrichment declarations.** Capability metadata you submit for your servers. You author it; it is published under the `_meta.org.rcxprotocol.registry` namespace and recorded as a signed receipt attributable to your publisher identity.

**Operational logs.** Standard request logs (IP address, timestamp, path, user agent) kept transiently for security, abuse prevention, and reliability. These are minimised and time-boxed.

We do **not** run advertising trackers, third-party analytics, fingerprinting, or behavioural profiling.

## 2. Why we process it

- To operate the mirror and serve the read API.
- To verify namespace control and maintain a tamper-evident registry history.
- To secure the service and prevent abuse.

Lawful bases (UK/EU GDPR): performance of the service you request (verification, publishing) and legitimate interests (security, integrity, reliability).

## 3. Receipts are permanent by design

Verification and enrichment events are recorded as append-only, signed CROWN receipts. Their integrity is the entire point of the service, so **receipts are not deleted** — deleting one would break the verifiable history. Receipts reference a publisher identity and namespace, not sensitive personal data. Where a receipt references an account identifier and you exercise a deletion right, we restrict rather than erase, and tell you why.

## 4. Sharing

Mirrored metadata, verification state, and enrichment declarations are **public** — that is what a registry is for. We do not sell data. We share nothing else except where legally required, or with infrastructure providers strictly to run the service (e.g. hosting, and HashiCorp Vault for signing-key custody).

## 5. Your rights

Under UK/EU GDPR and comparable laws you may request access to, correction of, or (subject to the receipts exception above) deletion of personal data we hold about you, and you may object to certain processing. Contact us to exercise these rights.

## 6. Contact

`contact@cuecrux.com`, or open an issue at [github.com/CueCrux/RCX-Registry](https://github.com/CueCrux/RCX-Registry). If you’re in the UK/EEA and unsatisfied with our response, you may complain to your data protection authority (in the UK, the ICO).

## 7. Changes

Material changes are reflected in the “last updated” date above.
