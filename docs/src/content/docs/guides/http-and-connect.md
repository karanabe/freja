---
title: HTTP forwarding and CONNECT
description: Operate the HTTP/1.1 explicit forward proxy, CONNECT tunnels, and proxy authentication.
publishedAt: 2026-08-31
updatedAt: 2026-08-31
tags:
  - http
  - connect
  - authentication
sidebar:
  order: 2
---

Freja accepts HTTP/1.1 explicit-proxy requests. Plain HTTP uses an absolute URI;
HTTPS clients normally send CONNECT authority-form and then negotiate TLS
through the resulting tunnel.

## Configure a loopback listener

```toml
[[listeners]]
kind = "http-forward"
bind = "127.0.0.1:8080"
connect_ports = [443]
```

Use it directly with curl:

```sh
curl --proxy http://127.0.0.1:8080 http://example.com/path?q=value
curl --proxy http://127.0.0.1:8080 https://example.com/
```

Applications that honor proxy environment variables can use:

```sh
export HTTP_PROXY=http://127.0.0.1:8080
export HTTPS_PROXY=http://127.0.0.1:8080
```

Check each application's proxy and `NO_PROXY` behavior; those variables are
application conventions, not Freja settings.

## Request processing

For plain HTTP, Freja:

1. parses the request with Hyper rather than a handwritten parser;
2. derives the destination and regenerates `Host` from the absolute request
   target;
3. validates framing and strips proxy credentials and hop-by-hop headers;
4. evaluates requested-target policy, resolves DNS, and evaluates every IP;
5. evaluates HTTP method, path, and header rules;
6. streams the request and response while applying configured inspection.

Malformed targets, conflicting `Transfer-Encoding` and `Content-Length`, and
oversized headers are rejected instead of forwarded.

For CONNECT, Freja checks the listener's port allowlist and destination policy,
then establishes the upstream TCP connection before returning success. After
the 200 response, the exchange is a tunnel: Freja cannot safely emit a later
HTTP block page into that committed byte stream.

## Response meanings

| Status | Meaning |
| --- | --- |
| `403 Forbidden` | Policy, destination protection, or preflight inspection denied the request |
| `407 Proxy Authentication Required` | Credentials were absent or invalid |
| `502 Bad Gateway` | The upstream could not be connected or its protocol failed |
| `504 Gateway Timeout` | A configured upstream operation timed out |

The audit trace gives the matched rule and policy generation for a policy
response.

## Expose a listener only with authentication

Non-loopback HTTP listeners require both an explicit safety opt-in and one
credential digest:

```toml
[safety]
allow_non_loopback = true

[[listeners]]
kind = "http-forward"
bind = "0.0.0.0:8080"
connect_ports = [443]

[listeners.authentication]
realm = "Freja"
credential_sha256 = "<64 hexadecimal characters>"
```

The digest is SHA-256 over the exact `username:password` bytes. Generate one
without placing the cleartext in the TOML file:

```sh
read -rsp 'username:password: ' FREJA_CREDENTIAL; echo
printf '%s' "$FREJA_CREDENTIAL" | sha256sum
unset FREJA_CREDENTIAL
```

Then authenticate a client:

```sh
curl --proxy http://127.0.0.1:8080 --proxy-user 'username:password' http://example.com/
```

:::danger
HTTP Basic proxy authentication is not encrypted by itself. Use a protected
network path, strong credentials, and external rate limiting. Freja does not
provide online guessing protection.
:::

Use [TLS interception](/guides/tls-interception/) only when managed clients
must expose tunneled plaintext to Freja. Ordinary CONNECT remains the safer
default.
