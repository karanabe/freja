---
title: "ADR 0005: Bounded opt-in TLS interception"
description: Add hostname-allowlisted interception with protected CA material, ALPN pinning, and bounded leaves.
publishedAt: 2026-08-31
updatedAt: 2026-08-31
tags:
  - ADR
  - TLS
  - security
sidebar:
  order: 5
---

**Status:** Accepted

## Context

ADR 0004 requires interception controls to arrive together while blind CONNECT
remains the default.

## Decision

Interception compiles only with a CA certificate, protected CA private key,
non-empty hostname allowlist, and positive leaf-cache capacity. Unix key files
with group or other access are rejected. IP literal targets are never
intercepted.

Freja establishes upstream TCP before CONNECT success. It negotiates downstream
TLS first, then authenticates upstream TLS with the same `h2` or `http/1.1`
ALPN. Rcgen creates SAN-bearing leaves and an in-memory cache is bounded by
hostname and ALPN offer. Audit records hostname, cache outcome, and ALPN without
key material. Failed handshakes, including client pinning rejection, close and
audit the flow.

After both TLS handshakes, the negotiated ALPN selects a Hyper HTTP/1.1 or
HTTP/2 server/client pair. Inner requests remain pinned to the CONNECT
destination, regenerate `Host`/`:authority`, and traverse the same HTTP ACL,
inspection, typed-hook, audit, and replay pipeline as plain forwarding. Nested
CONNECT is rejected. HTTP/2 header lists and concurrent streams are explicitly
bounded.

## Consequences

- Managed clients can expose selected plaintext without globally intercepting
  CONNECT.
- Operators assume CA custody and plaintext-retention responsibilities.
- Intercepted HTTP/1.1 and HTTP/2 share semantic policy and typed mutation;
  protocol framing remains owned by Hyper.
