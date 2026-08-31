---
title: Typed hook design
description: Hook stages, mutation contracts, interactive flow state, and extension rules.
publishedAt: 2026-08-31
updatedAt: 2026-08-31
tags:
  - hooks
  - architecture
  - developer
sidebar:
  order: 3
---

Hooks remain in `freja-policy::hook` while the API stabilizes. They are disabled
by default and have no native dynamic-library loading path.

## Stage contracts

Automatic hooks register in-process for six distinct stages:

- HTTP request head;
- decoded HTTP request body;
- HTTP response head;
- decoded HTTP response body;
- TCP client-to-upstream chunk;
- TCP upstream-to-client chunk.

Keeping interfaces stage-specific prevents one context struct filled with
invalid `Option` combinations. Hook context contains copied identity and bounded
snapshots, never references to live network sessions.

HTTP head hooks return `HeadMutationPlan`; body hooks return
`BodyMutationPlan`; TCP hooks return bounded chunk transformations. Mutation
validation rejects hop-by-hop fields and proxy-controlled `Content-Length`.
The HTTP engine is solely responsible for wire framing and recalculates
`Content-Length` after decoded-body replacement.
Wire and decoded body representations remain separate types. Automatic and
interactive replacements larger than `limits.body_prefix_bytes` are rejected
at the shared data-plane boundary; TCP chunk replacements use the same bound.
A decoded replacement removes stale content
encoding and representation validators in preflight mode; streaming body hooks
reject content-encoded messages because their heads are already committed.

## Execution and failure

`HookRunner` applies the runtime mode, invokes a matching registered hook, and
enforces the configured timeout. A concrete `HookError` remains visible inside
the policy/proxy layers. Fail-open or fail-closed behavior is an explicit runner
choice; the CLI currently selects fail-closed.

The shipped CLI intentionally uses an empty registry. Embedders construct a
registry and pass the runner through `DataPlaneServices`; configuration does not
discover executable code.

## Interactive state

```mermaid
sequenceDiagram
    participant Flow as Network task
    participant Broker as Bounded broker
    participant TUI
    Flow->>Broker: InterceptRequest + oneshot sender
    Broker->>Broker: acquire paused-flow permit
    Broker->>TUI: bounded request
    TUI-->>Flow: InteractiveDecision via oneshot
    Flow->>Flow: validate and apply or reject
```

The queue capacity and paused-flow semaphore are independent. Saturation,
closed channels, timeout, and a dropped responder are distinct errors. The
decision is one of Continue, Reject, EditHeaders, ReplaceBody, or
CancelModification.

Manual edits are bounded and audited by action without content. Reject is legal
only before protocol commitment. An interactive TCP reject closes the flow;
after CONNECT commitment the system cannot synthesize another HTTP response.

## Extension policy

Do not load Rust dynamic libraries: Rust has no stable plugin ABI, and native
code would bypass Freja's memory and capability boundary. If an external plugin
model is introduced, design a separately reviewed WASM boundary with explicit
capabilities, time, memory, and execution budgets. Do not publish a hook SDK
until these in-process contracts stabilize.
