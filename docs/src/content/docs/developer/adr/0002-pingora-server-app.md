---
title: "ADR 0002: Pingora through ServerApp"
description: Use Pingora 0.8.1 only as a transport lifecycle adapter.
publishedAt: 2026-08-31
updatedAt: 2026-08-31
tags:
  - ADR
  - pingora
sidebar:
  order: 2
---

**Status:** Accepted

## Context

Pingora 0.8.1 is the compatibility baseline. Freja needs access to each accepted
transport without adopting reverse-proxy parsing or request lifecycle types.

## Decision

Use `pingora_core::apps::ServerApp` to receive a `Stream`. The concrete generic
adapter contains no policy logic, consumes each stream exactly once, delegates
to `PingoraConnectionHandler`, and returns `None` after the handler completes.
Do not use `pingora-proxy::ProxyHttp` for explicit forward proxying.

The all-feature gates compile Pingora and the `ServerApp` contract. The current
multi-listener CLI uses the Tokio adapter; full Pingora process wiring remains
an alternative adapter, not a domain constraint.

## Consequences

- Pingora upgrades can be isolated and compile-tested at one boundary.
- The handler must take full responsibility for protocol connection reuse and
  CONNECT upgrade ownership.
- Runtime-specific listener metadata must be translated before entering shared
  engines.
