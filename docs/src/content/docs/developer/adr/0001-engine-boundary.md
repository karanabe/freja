---
title: "ADR 0001: Replaceable listener engine"
description: Keep policy and protocol semantics independent from Pingora or Tokio listener ownership.
publishedAt: 2026-08-31
updatedAt: 2026-08-31
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

A narrow listener engine owns connection acceptance and passes transport
streams into Freja protocol engines. Runtime identity is represented by
`EngineKind`, not by leaking transport types across crates. A pure Tokio
listener may be selected behind this boundary.

The production CLI selects Tokio because it coordinates HTTP, static TCP, and
SOCKS5 listeners with Freja-specific metadata and shutdown. A generic Pingora
`ServerApp` transport adapter is implemented and compile-tested independently.

## Consequences

- Facts, decisions, events, and protocol tests remain reusable when runtime
  selection changes.
- The CLI must provide lifecycle functions that Pingora might otherwise own.
- A future Pingora process integration belongs in the adapter and must not
  modify policy semantics to simplify wiring.
