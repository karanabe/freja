---
title: "ADR 0001: Framework-isolated runtime adapters"
description: Keep policy and protocol semantics independent from Pingora or Tokio listener ownership.
publishedAt: 2026-08-31
updatedAt: 2026-09-01
tags:
  - ADR
  - architecture
sidebar:
  order: 1
---

**Status:** Accepted

## Context

Freja needs listener lifecycle management without allowing runtime-specific I/O
types to shape domain, policy, inspection, audit, hook, or UI APIs. Pingora's
high-level reverse-proxy surface does not define the explicit forward-proxy
semantics Freja needs.

## Decision

`freja-proxy` is the framework isolation boundary. The production CLI owns
concrete Tokio accept loops and passes their streams into Freja protocol
engines. The optional Pingora module owns its separate `ServerApp` lifecycle
and delegates each supplied stream to a narrow connection handler.

Tokio and Pingora lifecycle APIs are intentionally not forced through a common
listener trait. They are not runtime-substitutable today, and an identity-only
trait would imply a capability the implementation does not provide. The shared
contract is protocol behavior and framework containment, not identical listener
or process ownership.

The production CLI selects Tokio because it coordinates HTTP, static TCP, and
SOCKS5 listeners with Freja-specific metadata and shutdown. A generic Pingora
`ServerApp` transport adapter is implemented and compile-tested independently.

## Consequences

- Facts, decisions, events, and protocol tests remain independent from runtime
  framework types.
- The CLI must provide lifecycle functions that Pingora might otherwise own.
- Choosing another process runtime requires explicit bootstrap integration; it
  is not a runtime switch behind a common trait.
- A future Pingora process integration belongs in the adapter and must not
  modify policy semantics to simplify wiring.
