---
title: "ADR 0004: TLS interception outside the MVP"
description: Keep initial CONNECT as a blind tunnel and require interception to arrive as one reviewed feature.
publishedAt: 2026-08-31
updatedAt: 2026-08-31
tags:
  - ADR
  - TLS
sidebar:
  order: 4
---

**Status:** Accepted

## Context

Blind CONNECT requires no local CA and preserves end-to-end TLS. Interception
introduces key custody, client trust changes, certificate generation, decrypted
payload handling, ALPN, pinning behavior, and new audit requirements.

## Decision

The headless MVP implements only blind TCP tunneling. TLS interception remains
disabled by default when added later. It may be introduced only with protected
CA inputs, SAN/SNI-correct leaves, bounded caching, explicit hostname allowlist,
HTTP/1.1 and HTTP/2 handling, pinning behavior, capture controls, and dedicated
audit events reviewed together.

## Consequences

- Initial deployments do not need to distribute a trust anchor.
- Tunnel mode remains available permanently.
- The later implementation must not become an implicit side effect of enabling
  generic inspection.
