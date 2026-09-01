---
title: TLS interception
description: Opt in selected managed destinations to bounded TLS interception safely.
publishedAt: 2026-08-31
updatedAt: 2026-08-31
tags:
  - tls
  - certificates
  - security
sidebar:
  order: 6
---

CONNECT is a blind tunnel by default. TLS interception is a separate opt-in for
managed clients and explicitly allowlisted hostnames. It changes the trust and
privacy model: Freja terminates client TLS, authenticates the real upstream,
and can inspect decrypted bytes.

:::danger
Do not install the interception CA on unmanaged devices. Anyone controlling
that key can impersonate TLS destinations trusted by those devices.
:::

## Prepare a local CA

Use your organization's CA workflow when available. For an isolated test, an
OpenSSL PKCS#8 key and CA certificate can be created with:

```sh
install -d -m 0700 ./private
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
  -out ./private/freja-ca-key.pem
openssl req -x509 -new -sha256 -days 365 \
  -key ./private/freja-ca-key.pem \
  -out ./private/freja-ca.pem \
  -subj '/CN=Freja local interception CA' \
  -addext 'basicConstraints=critical,CA:TRUE' \
  -addext 'keyUsage=critical,keyCertSign,cRLSign'
chmod 0600 ./private/freja-ca-key.pem
```

Install only `freja-ca.pem` in the intentionally managed client's trust store.
Never copy the private key to clients. On Unix, Freja rejects a CA key with any
group or other permission bits.

## Configure an allowlist

```toml
[tls]
handling = "intercept"
ca_certificate = "./private/freja-ca.pem"
ca_private_key = "./private/freja-ca-key.pem"
intercept_hosts = [
  { kind = "exact", value = "api.example.test" },
  { kind = "suffix", value = "example.internal" },
]
leaf_cache_entries = 256
```

Exact and suffix matches operate on validated DNS names at label boundaries.
IP literals are never intercepted. CONNECT destinations outside this list stay
blind tunnels.

## Handshake and protocol behavior

Freja establishes the upstream TCP socket before committing CONNECT success.
For an intercepted destination it then:

1. generates or reuses a SAN-bearing leaf certificate;
2. negotiates downstream TLS and learns `h2` or `http/1.1`;
3. authenticates upstream TLS using public WebPKI roots and the same ALPN;
4. selects a Hyper HTTP/1.1 or HTTP/2 engine from ALPN;
5. runs inner exchanges through HTTP policy, bounded inspection, typed hooks,
   audit, and replay facts before forwarding them to the fixed CONNECT target.

Certificate and hostname verification are never disabled. A client that pins
the original destination certificate is expected to reject Freja's generated
leaf; Freja closes and audits that failure rather than bypassing pinning.

HTTP/1.1 and HTTP/2 are decoded by Hyper rather than a Freja wire parser. The
CONNECT authority is authoritative: Freja regenerates `Host`/`:authority`, does
not permit an inner request to select another destination, and rejects nested
CONNECT. HTTP method, path, header, request/response body inspection, and typed
HTTP mutation therefore behave consistently for plain and intercepted traffic.
The TUI shows these inner exchanges in Pretty mode. Exact Raw/Hex ingress
capture is not yet available for persistent intercepted HTTP/1 or HTTP/2 and
is reported as unavailable rather than reconstructed from semantic data.

Audit records include hostname, cache hit/miss, negotiated ALPN, and handshake
outcome, but never CA private material.
