---
title: "ADR 0003: Hyper HTTP/1 forward-proxy engine"
description: Implement explicit HTTP/1.1 proxy semantics with Hyper instead of ProxyHttp or a custom parser.
publishedAt: 2026-08-31
updatedAt: 2026-08-31
tags:
  - ADR
  - HTTP
  - hyper
sidebar:
  order: 3
---

**Status:** Accepted

## Context

Explicit proxies receive absolute-form requests and CONNECT authority-form.
These semantics differ from an origin or reverse proxy, and malformed framing
must be handled by a maintained parser.

## Decision

Hyper 1.x owns the HTTP/1.1 connection state machine on transports supplied by
the selected listener adapter. Freja accepts absolute-form and CONNECT,
regenerates `Host`, removes hop-by-hop headers, rejects ambiguous framing,
streams bodies, and enables upgrades.

CONNECT opens and policy-checks upstream before returning success. Once
success commits, the exchange is a tunnel and cannot emit a later HTTP block or
redirect response.

Do not write an HTTP parser. Do not downgrade the `http` crate to accommodate
Pingora's high-level parser.

## Consequences

- Proxy correctness is explicit while parser state remains delegated to Hyper.
- Freja owns outbound client connections, synthetic responses, and tunnel task
  tracking.
- HTTP/2 extended CONNECT is not implied by this HTTP/1 engine.
