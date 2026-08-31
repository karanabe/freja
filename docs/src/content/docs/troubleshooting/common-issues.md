---
title: Common issues
description: Diagnose configuration rejection, proxy responses, TLS failures, TUI recovery, and replay errors.
publishedAt: 2026-08-31
updatedAt: 2026-08-31
tags:
  - troubleshooting
  - errors
sidebar:
  order: 1
---

Start with a configuration compile and operational logs:

```sh
freja check-config --config freja.toml
RUST_LOG=freja=debug,freja_proxy=debug freja run --config freja.toml
```

Security decisions are in the JSONL audit stream, not only in tracing output.

## Configuration is rejected

| Message or symptom | Likely cause | Resolution |
| --- | --- | --- |
| `at least one listener is required` | No `[[listeners]]` table | Add one supported listener |
| `listener ... is not loopback` | Remote bind without opt-in | Prefer loopback, or set `allow_non_loopback` and configure required authentication |
| remote HTTP/SOCKS requires authentication | Exposed proxy has no credential digest | Add the listener authentication table |
| remote static TCP unsupported | Generic TCP has no auth handshake | Keep it loopback or add a protected external transport |
| `limit ... must be non-zero` | A bounded resource was set to zero | Choose a positive operational limit |
| interactive hooks require TUI | `hooks = "interactive"` with headless UI | Set `ui = "tui"` or disable interactive hooks |
| detector has invalid hex/empty pattern | Bad `pattern_hex` | Use a non-empty even-length hexadecimal byte string |
| TLS interception requires ... | Missing CA path or allowlist | Configure all interception inputs or return to tunnel mode |

Unknown TOML keys are errors. Check table nesting carefully; a
`[listeners.authentication]` table belongs to the immediately preceding array
listener.

## A local upstream is denied

Loopback and private destinations are protected by default even when the
listener itself is local. This is intentional SSRF protection. For a deliberate
local test only:

```toml
[safety]
loopback_destinations = "allow"
```

Use the audit decision trace to confirm the matched built-in rule. Avoid
globally allowing an address class when a different network design can isolate
the required service.

## HTTP returns 403, 407, 502, or 504

- 403: inspect `acl-evaluated`, `inspection-evaluated`, and `action-executed`.
- 407: provide the exact configured HTTP Basic credential; the hash covers
  `username:password` with no newline.
- 502: confirm DNS, upstream reachability, protocol behavior, and TLS trust.
- 504: increase a timeout only after identifying a legitimately slow operation.

CONNECT also returns 403 when its port is absent from `connect_ports`.

## TLS interception fails

1. Confirm the destination hostname matches an exact/suffix allowlist entry.
2. Confirm the managed client trusts the configured CA certificate.
3. Run `chmod 0600` on the CA private key; group-readable keys are rejected.
4. Confirm the upstream certificate and DNS name validate against public roots.
5. Check whether the client uses certificate pinning. Pinned clients are
   expected to fail and cannot be bypassed safely.
6. Check ALPN: intercepted connections support `h2` and `http/1.1`.

## Audit file already exists

An exact audit file is never overwritten. Choose a new path or point
`audit.path` at an existing directory so Freja creates a unique segment.
Do not delete an existing segment until it has been retained according to your
audit policy.

## Replay rejects a segment

Replay stops before evaluating policy if sequence, previous hash, record hash,
checkpoint signature, checkpoint position, or pinned key is invalid. Make sure
the command receives one complete segment starting at sequence 1. A pinned key
also requires the segment to contain a checkpoint from that key.

## The terminal looks corrupted after TUI exit

Freja restores terminal state during normal exits and unwinding, but SIGKILL or
a terminal emulator failure prevents cleanup. Run `reset` or open a new
terminal. Prefer SIGINT/SIGTERM and investigate why graceful shutdown did not
finish.

## Reload does not apply

Only policy, destination guards, enforcement, and inspection are hot
reloadable. Listener, authentication, limit, TLS, UI/hook, capture, and audit
changes need a restart. A validation or compatibility failure leaves the old
snapshot active; inspect the tracing warning and run `check-config` on the exact
candidate file.
