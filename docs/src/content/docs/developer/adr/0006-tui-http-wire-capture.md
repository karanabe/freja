---
title: "ADR 0006: TUI-only HTTP/1 wire capture"
description: Keep Hyper authoritative while a private bounded observer supplies exact Raw presentation.
publishedAt: 2026-09-02
updatedAt: 2026-09-03
tags:
  - ADR
  - TUI
  - HTTP
sidebar:
  order: 6
---

**Status:** Accepted

## Context

The traffic screen needs both a parsed Pretty view and exact Raw/Hex bytes for
plain explicit HTTP/1 requests and upstream responses. Hyper exposes semantic
messages, not the original ingress byte sequence. This presentation requirement
must not introduce a second parsing authority or couple the UI to an external
capture dependency. Freja must also preserve Hyper as the authoritative HTTP
parser and must not let presentation capture influence forwarding.

## Decision

`freja-proxy` owns a private capture-only HTTP/1 framer and asynchronous I/O
adapters. They are installed only when `UiCaptureSettings` is attached by TUI
bootstrap. The request adapter observes client ingress and correlates messages
to `TransactionId`; the response adapter observes upstream ingress. Retention
is bounded by `header_bytes + ui_content_bytes`, and correlation state is
bounded by `ui_retained_rows`.

The observer recognizes only the framing needed to delimit exact messages:
header termination, consistent Content-Length, a single chunked transfer
coding with extensions and trailers, status codes whose responses have no
body, informational responses, and close-delimited responses. Hyper still
decides whether a request is accepted and performs all forwarding. Observer
completion and failure can only attempt a non-blocking immutable UI event;
they cannot return a protocol decision or exert backpressure.

The framer remains private and is not a reusable HTTP parser API. Its state
machine has exhaustive split-boundary unit tests and is connected to the HTTP
framing fuzz target. No additional capture dependency is added.

Exact Raw initially covers plain explicit HTTP/1. Local synthetic responses,
persistent intercepted HTTP/1, and HTTP/2 report Raw unavailable while keeping
their semantic Pretty view. Supporting those cases requires a separate design
for persistent-stream transaction correlation; HTTP/2 frames must never be
presented as if they were an HTTP/1 message.

## Consequences

- Headless mode pays no wire-capture cost and retains no TUI payload snapshots.
- TUI Raw content is exact within its configured bound and is explicitly
  marked truncated or failed beyond that bound.
- TUI content is sensitive and unredacted; audit capture and redaction policies
  remain independent.
- The small private state machine becomes security-relevant observer code and
  therefore requires split-boundary, malformed-framing, fuzz, and integration
  coverage, even though failure cannot change forwarding.
