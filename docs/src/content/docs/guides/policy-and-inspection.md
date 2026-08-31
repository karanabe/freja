---
title: Policy and inspection
description: Build ordered ACLs, protect resolved destinations, and inspect bounded byte streams.
publishedAt: 2026-08-31
updatedAt: 2026-08-31
tags:
  - policy
  - inspection
  - security
sidebar:
  order: 4
---

Freja separates facts, findings, decisions, and enforcement. ACL and detector
results always include a `DecisionTrace`; `runtime.enforcement` decides whether
a denial is only observed or executed.

## Choose observe or enforce

```toml
[runtime]
enforcement = "observe" # or "enforce"
```

Use observe mode to validate rules against real traffic without intentionally
blocking it. Findings, decisions, and would-be actions still appear in audit
and TUI data. Move to enforce only after checking those traces.

## Ordered ACLs

Rules are evaluated in declaration order and the first match wins. If no rule
matches, `policy.default_action` applies.

```toml
[policy]
generation = 42
default_action = "allow"

[[policy.rules]]
id = "deny-example-admin"
matcher = { kind = "all", value = [
  { kind = "destination-host", value = { kind = "suffix", value = "example.com" } },
  { kind = "http-path-prefix", value = "/admin" },
] }
action = "deny"

[[policy.rules]]
id = "deny-metadata-ip"
matcher = { kind = "destination-ip", value = "169.254.0.0/16" }
action = "deny"
```

Available leaves are source CIDR, destination CIDR, exact/suffix hostname,
destination port range, protocol, HTTP method set, HTTP path prefix, and HTTP
header name with optional byte-substring matching. Compose them with `all`,
`any`, and `not`. Empty boolean expressions are invalid.
Rule IDs must be unique within the policy so traces and audit records identify
one unambiguous rule.

Increment `policy.generation` whenever policy meaning changes. The generation
is attached to decisions and audit records, making reload and replay results
identifiable.

## Destination protection

Resolved-address guards run independently of ordered ACLs. Loopback, private,
link-local, and known metadata-service addresses default to `protect`;
unspecified and multicast addresses are always rejected.

```toml
[safety]
private_destinations = "protect"
link_local_destinations = "protect"
loopback_destinations = "protect"
metadata_destinations = "protect"
```

Every DNS result is checked, not just the hostname or first answer. Set an
address class to `allow` only for a deliberate deployment requirement.

## Fixed-byte inspection

Patterns are non-empty hexadecimal byte strings. Detectors produce findings;
the separate configured action turns a matching finding into a decision.

```toml
[inspection]
mode = "streaming"

[[inspection.patterns]]
detector_id = "known-marker"
rule_id = "deny-known-marker"
pattern_hex = "deadbeef"
severity = "high"
confidence = "confirmed"
directions = ["client-to-upstream", "http-request-body"]
action = "deny"
tags = ["signature", "controlled-test"]
```

Directions are `client-to-upstream`, `upstream-to-client`,
`http-request-body`, and `http-response-body`. Matching retains only bounded
overlap, so a pattern split across read chunks is still detected. Every
pattern must fit within `limits.body_prefix_bytes`; configuration compilation
rejects a longer signature instead of silently making it unmatchable.

### Streaming versus preflight

- Both modes inspect at most the first `limits.body_prefix_bytes` in each flow
  direction. Later bytes are forwarded without detector evaluation.
- `streaming` forwards chunks while scanning. A later match can stop future
  bytes inside that prefix but cannot retract bytes already sent.
- `preflight` buffers up to `limits.body_prefix_bytes`, scans before forwarding,
  and can return an HTTP block page or close TCP before the buffered prefix
  leaves Freja. When a short TCP prefix is released on the preflight timeout,
  later bytes do not restart inspection.

Neither mode is full unbounded content scanning. Pattern matching and optional
capture remain limited by configuration. Entropy alone is not a blocking
signal.

See the [configuration reference](/reference/configuration/) for every matcher
representation and default.
