---
title: Configuration reference
description: Complete TOML reference for Freja runtime, safety, limits, listeners, policy, inspection, TLS, audit, and capture.
publishedAt: 2026-08-31
updatedAt: 2026-09-03
tags:
  - configuration
  - reference
  - policy
sidebar:
  order: 2
---

Freja reads one TOML file. Unknown top-level and strict-section fields are
rejected. Omitted sections use safe defaults, but at least one listener is
required. Commandless `freja` (or `freja run` without `--config`) instead
creates a loopback-only HTTP listener at the CLI composition root and passes it
through the same compiler. Validate a file with:

```sh
freja check-config --config freja.toml
```

## Example configurations

The repository ships four standalone local-test profiles:

| Path | Runtime combination |
| --- | --- |
| `examples/config/headless/freja.toml` | Headless, enforce, disabled hooks, streaming inspection |
| `examples/config/headless/freja.enforce.toml` | Headless, enforce, preflight deny marker |
| `examples/config/tui/freja.toml` | Default TUI, enforce, interactive request decisions |
| `examples/config/tui/freja.interactive.toml` | Focused HTTP-only interactive profile with smaller bounds |

Pass a path directly to either CLI command, for example:

```sh
cargo run -p freja -- check-config --config examples/config/tui/freja.toml
cargo run -p freja -- run --config examples/config/tui/freja.toml
```

The profiles reuse the same loopback ports and are intended to run one at a
time. They allow loopback destinations for the bundled HTTP test origin; review
that weaker destination guard before adapting one for deployment. See
`examples/config/README.md` for the profile-specific checks.

## Runtime

```toml
[runtime]
ui = "tui"
enforcement = "enforce"
hooks = "interactive"
```

| Key | Values | Default | Notes |
| --- | --- | --- | --- |
| `ui` | `headless`, `tui` | `tui` | Presentation only |
| `enforcement` | `observe`, `enforce` | `enforce` | Whether deny decisions execute |
| `hooks` | `disabled`, `automatic`, `interactive` | `interactive` | Interactive requires TUI |

Omitting `[runtime]` selects that local interactive profile. The choices remain
independent: TUI does not itself imply enforcement, and observe mode does not
disable capture or audit. Interactive hooks require TUI because the decision
responder lives there. The standard headless profile explicitly selects
`headless`, `enforce`, and `disabled`; `observe` remains available for policy
evaluation scenarios that must not execute deny actions.

## Safety

```toml
[safety]
allow_non_loopback = false
private_destinations = "protect"
link_local_destinations = "protect"
loopback_destinations = "protect"
metadata_destinations = "protect"
```

Each destination control accepts `protect` or `allow`. Unspecified and
multicast IPs are always rejected. `allow_non_loopback` only permits validation
to continue: remote HTTP and SOCKS5 still require authentication, and remote
static TCP is always unsupported.

Known metadata addresses include `169.254.169.254`, `100.100.100.200`, and
`fd00:ec2::254`. Guards run after DNS against every address.

## Limits

All values must be non-zero.

| Key | Default | Meaning |
| --- | ---: | --- |
| `connections` | `1024` | Concurrent flows per listener |
| `header_bytes` | `65536` | Maximum accepted HTTP header bytes |
| `body_prefix_bytes` | `65536` | Maximum body prefix available to bounded inspection |
| `connect_timeout_ms` | `10000` | DNS resolution, upstream connect, and protocol-handshake budget where applied |
| `read_timeout_ms` | `30000` | HTTP request-header and body-frame read budget |
| `idle_timeout_ms` | `60000` | Relay read/write inactivity budget |
| `paused_flows` | `16` | Simultaneously paused interactive flows |
| `interception_timeout_ms` | `30000` | Hook/manual/TLS interception wait budget |
| `ui_event_capacity` | `1024` | Best-effort UI event queue capacity |
| `ui_content_bytes` | `65536` | Payload bytes retained for each TUI traffic side or latest repeat response |
| `ui_retained_rows` | `128` | Traffic rows and HTTP/1.1 repeat workspaces retained by the TUI |

```toml
[limits]
connections = 1024
header_bytes = 65536
body_prefix_bytes = 65536
connect_timeout_ms = 10000
read_timeout_ms = 30000
idle_timeout_ms = 60000
paused_flows = 16
interception_timeout_ms = 30000
ui_event_capacity = 1024
ui_content_bytes = 65536
ui_retained_rows = 128
```

`ui_retained_rows` must be at least `paused_flows`, so a paused request cannot
be made unreachable by row eviction. In interactive mode, `ui_content_bytes`
must be at least `body_prefix_bytes`. `header_bytes + ui_content_bytes` must fit
in `usize`; invalid combinations fail before listener startup. These TUI
retention limits do not enable payload audit capture.
`ui_retained_rows` also bounds the independent repeat request/result channels.
When the workspace limit is reached, the operator must delete a non-running
workspace; drafts are not silently evicted.

## Audit

```toml
[audit]
path = "."
channel_capacity = 1024
failure_policy = "fail-closed"
redact_query_parameters = ["access_token", "api_key", "password", "secret", "token"]
checkpoint_interval = 1000
# checkpoint_signing_key = "/etc/freja/audit-ed25519-seed.hex"
```

`failure_policy` is `fail-open` or `fail-closed`. `channel_capacity` must be
positive. When a signing key is configured, `checkpoint_interval` must also be
positive. The key file contains exactly 32 seed bytes as 64 hexadecimal
characters and, on Unix, must not be group/other accessible.

An existing directory in `path` produces a unique segment and is the default;
`.` therefore supports repeated local runs without overwriting earlier audit
data. A file path uses exclusive creation and is never overwritten. New segment
files use owner-only `0600` permissions on Unix; operators must also protect the
containing directory.

## Capture

```toml
[capture]
mode = "metadata-only"
```

Or explicitly persist a bounded plaintext prefix as hexadecimal:

```toml
[capture]
mode = "prefix"
max_bytes = 4096
```

`max_bytes` must be positive and no greater than
`limits.body_prefix_bytes`.

## Inspection

```toml
[inspection]
mode = "streaming" # or "preflight"

[[inspection.patterns]]
detector_id = "marker"
rule_id = "deny-marker"
pattern_hex = "deadbeef"
severity = "high"
confidence = "confirmed"
directions = ["client-to-upstream", "upstream-to-client"]
action = "deny"
tags = ["signature"]
```

Pattern fields:

| Key | Required | Default / values |
| --- | --- | --- |
| `detector_id` | yes | Unique non-empty identifier |
| `rule_id` | yes | Non-empty decision-trace identifier |
| `pattern_hex` | yes | Non-empty valid hexadecimal bytes, no longer than `limits.body_prefix_bytes` |
| `severity` | no | `high`; also `informational`, `low`, `medium`, `critical` |
| `confidence` | no | `confirmed`; also `heuristic`, `probable` |
| `directions` | no | all four body/stream directions |
| `action` | no | `deny`; `allow` is also valid, detour is invalid |
| `tags` | no | empty string list |

Directions are `client-to-upstream`, `upstream-to-client`,
`http-request-body`, and `http-response-body`. Detector IDs must be unique.

## TLS

Tunnel mode is the default:

```toml
[tls]
handling = "tunnel"
```

Interception requires all security inputs:

```toml
[tls]
handling = "intercept"
ca_certificate = "/etc/freja/ca.pem"
ca_private_key = "/etc/freja/ca-key.pem"
intercept_hosts = [
  { kind = "exact", value = "api.example.test" },
  { kind = "suffix", value = "example.internal" },
]
leaf_cache_entries = 256
```

`leaf_cache_entries` defaults to 256 and must be positive. `intercept_hosts`
must be non-empty. IP literals do not match hostname patterns.

## Policy

```toml
[policy]
generation = 1
default_action = "allow"
```

Generation must be non-zero. Actions are `allow`, `deny`, or a TCP detour:

```toml
action = { detour = { host = "sinkhole.example", port = 9000 } }
```

Detour cannot be the default action and is valid only for requested-stage
expressions that explicitly require protocol `tcp`.

### ACL rules

```toml
[[policy.rules]]
id = "deny-admin"
matcher = { kind = "all", value = [
  { kind = "destination-host", value = { kind = "suffix", value = "example.com" } },
  { kind = "http-method", value = ["POST", "DELETE"] },
  { kind = "http-path-prefix", value = "/admin" },
] }
action = "deny"
```

Rule IDs must be unique. Rules are declaration-ordered and first-match. Match expressions use
`{ kind = "...", value = ... }`:

| Kind | Value |
| --- | --- |
| `all` | Non-empty array; every child must match |
| `any` | Non-empty array; first matching child contributes reasons |
| `not` | One nested expression |
| `source-ip` | IPv4/IPv6 CIDR string |
| `destination-ip` | IPv4/IPv6 CIDR string; available after DNS |
| `destination-host` | `{ kind = "exact" | "suffix", value = "hostname" }` |
| `destination-port` | `{ start = 1, end = 65535 }`, inclusive |
| `protocol` | `http` or `tcp` |
| `http-method` | Array of method strings, compared case-insensitively |
| `http-path-prefix` | String prefix |
| `http-header` | `{ name = "x-name", value_contains = "optional bytes" }` |

HTTP-specific leaves do not match requested/resolved/TCP facts. Header names
are case-insensitive; `value_contains` is an optional byte substring.

## Listeners

At least one `[[listeners]]` table is required. Listen addresses must be socket
addresses such as `127.0.0.1:8080` or `[::1]:8080`.

### HTTP forward proxy

```toml
[[listeners]]
kind = "http-forward"
bind = "127.0.0.1:8080"
connect_ports = [443]
```

`connect_ports` defaults to `[443]` and cannot be empty. A remote listener also
requires:

```toml
[listeners.authentication]
realm = "Freja"
credential_sha256 = "<64 hex characters>"
```

Realm defaults to `Freja` and must be non-empty visible ASCII without quotes or
backslashes.

### Static TCP

```toml
[[listeners]]
kind = "tcp-static"
bind = "127.0.0.1:9000"
upstream = "db.example.internal:5432"
```

The upstream requires a non-zero port. Hostnames use ASCII DNS syntax. The
listener must remain loopback-bound.

### SOCKS5

```toml
[[listeners]]
kind = "socks5"
bind = "127.0.0.1:1080"
```

Remote SOCKS5 requires:

```toml
[listeners.authentication]
credential_sha256 = "<SHA-256 of exact username:password>"
```

The same digest can be used on a loopback listener when local authentication is
desired.

## Hot-reload compatibility

SIGHUP may change policy rules/generation, destination guards, enforcement,
inspection rules, and inspection mode. All other sections require restart.
Freja validates the complete candidate before comparing compatibility; a
failure leaves the old snapshot active.
