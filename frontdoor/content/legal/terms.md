---
title: Terms of Use
description: The terms RCX-Registry is offered under, including disclaimers and the no-warranty basis of the service.
lastUpdated: 2026-07-23
---

# Terms of Use

Last updated: 23 July 2026

RCX-Registry is an open-source project operated by CueCrux Limited and provided under the [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0). These terms govern use of the hosted service at `rcxprotocol.org` and `registry.rcxprotocol.org`. By using the service you agree to them.

## 1. What the service is

RCX-Registry is a subregistry that serves mirrored data from the official [Model Context Protocol registry](https://registry.modelcontextprotocol.io) and publishes formats and conformance vectors for signed snapshot and enrichment evidence. Hosted production currently exposes no signed snapshot record, and publisher verification writes are unavailable. It is an independent project. It is **not** affiliated with, endorsed by, or an official service of Anthropic or the Model Context Protocol project.

## 2. Mirrored content

The registry mirrors third-party server metadata from the upstream MCP registry. That metadata originates with its publishers, not with us. We do not author it, and mirroring it is not an endorsement of any server, publisher, or the safety, security, or fitness of any listed software.

If publisher verification reopens, a valid result is intended to attest only to **namespace control**. All public verification routes currently fail closed, and production has zero rights and snapshot rows. A valid signed snapshot, when produced and made retrievable, would provide evidence about registry state. None of these records or formats certifies that a server is safe, non-malicious, bug-free, or fit for any purpose. Always evaluate a server before running it.

## 3. Acceptable use

Don’t use the service to:

- attempt to forge, tamper with, or misrepresent receipts, verification records, or registry history;
- claim or attempt to verify a namespace you do not control;
- overload, disrupt, or probe the service for vulnerabilities outside a coordinated disclosure;
- mirror or scrape the API in a way that degrades service for others (respect documented rate limits and cursors).

## 4. Publisher responsibilities

If you claim a namespace, you are responsible for maintaining control of it and for the accuracy of the proof material you provide. Public enrichment declaration submission is currently unavailable. These terms will be updated before an authenticated declaration surface is opened.

## 5. No warranty

The service is provided **“as is” and “as available”, without warranties of any kind**, express or implied, including merchantability, fitness for a particular purpose, and non-infringement. We do not warrant that the service will be uninterrupted, error-free, or that mirrored data is complete or current. This mirrors the warranty disclaimer in the Apache-2.0 licence the software is distributed under.

## 6. Limitation of liability

To the fullest extent permitted by law, CueCrux Limited is not liable for any indirect, incidental, special, consequential, or exemplary damages, or for any loss arising from your use of — or inability to use — the service or any server discovered through it.

## 7. Changes

We may update these terms or the service. Material changes will be reflected in the “last updated” date above. Continued use after a change constitutes acceptance.

## 8. Contact

Questions about these terms: open an issue at [github.com/CueCrux/RCX-Registry](https://github.com/CueCrux/RCX-Registry) or contact `contact@cuecrux.com`.
