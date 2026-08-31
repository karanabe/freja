---
title: Static TCP and SOCKS5
description: Configure fixed-upstream TCP relays and SOCKS5 CONNECT listeners safely.
publishedAt: 2026-08-31
updatedAt: 2026-08-31
tags:
  - tcp
  - socks5
  - listeners
sidebar:
  order: 3
---

Freja provides two L4 entry points. A static TCP listener always selects one
configured upstream. A SOCKS5 listener receives the destination from a CONNECT
request.

## Static TCP relay

```toml
[[listeners]]
kind = "tcp-static"
bind = "127.0.0.1:9000"
upstream = "db.example.internal:5432"
```

The listener applies requested-host policy, resolves DNS, checks every resolved
address, connects with the configured timeout, and then relays both directions
with idle timeout, byte counting, inspection, hooks, and audit.

Static TCP has no protocol-level authentication handshake, so Freja rejects a
non-loopback bind even when `safety.allow_non_loopback` is true. Put another
authenticated transport in front of it instead of treating source IP as an
identity.

## SOCKS5 CONNECT

```toml
[[listeners]]
kind = "socks5"
bind = "127.0.0.1:1080"
```

Use remote DNS through the proxy with curl's `socks5h` form:

```sh
curl --proxy socks5h://127.0.0.1:1080 https://example.com/
```

Freja supports SOCKS5 CONNECT with IPv4, IPv6, and domain targets. It does not
implement UDP ASSOCIATE or BIND.

## Authenticated SOCKS5 exposure

Non-loopback SOCKS5 requires RFC 1929 username/password authentication:

```toml
[safety]
allow_non_loopback = true

[[listeners]]
kind = "socks5"
bind = "0.0.0.0:1080"

[listeners.authentication]
credential_sha256 = "<SHA-256 of exact username:password>"
```

```sh
curl --proxy socks5h://127.0.0.1:1080 --proxy-user 'username:password' https://example.com/
```

RFC 1929 credentials are cleartext on the SOCKS connection. Use the same
protected-network and rate-limit precautions as HTTP Basic authentication.
Audit events store only accepted/rejected outcomes, not identities or secrets.

## TCP detours

An ordered ACL can select a replacement upstream before any application byte
is sent:

```toml
[[policy.rules]]
id = "detour-legacy-service"
matcher = { kind = "all", value = [
  { kind = "protocol", value = "tcp" },
  { kind = "destination-port", value = { start = 9001, end = 9001 } },
] }
action = { detour = { host = "sinkhole.example.internal", port = 9002 } }
```

Detour rules must be restricted to TCP facts available before DNS. Freja runs
the selected target through requested and resolved destination policy again and
rejects a second detour as a routing loop.
