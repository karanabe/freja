# Threat Model

Freja treats downstream requests, HTTP targets and headers, DNS answers,
upstream bytes, hook output, and replay input as untrusted. Configuration and
local key files are administrative inputs, but their cross-field invariants,
formats, and private-key permissions are still validated before listeners
start.

Primary controls include loopback-only defaults, explicit authenticated remote
HTTP/SOCKS exposure, CONNECT port allowlists, requested- and resolved-target
policy, protection for loopback/private/link-local/metadata destinations,
framing validation, hop-by-hop normalization, bounded channels and caches,
header/body/read/connect/idle/interception limits, secret redaction, and
hash-chained audit segments with optional signed checkpoints.

TLS interception is disabled by default and limited to an explicit hostname
allowlist. Certificate or ALPN failures close and audit the committed tunnel;
Freja never falls back to unauthenticated upstream TLS.

TUI traffic content is bounded but intentionally unredacted. Exact plain
HTTP/1 Raw observers are installed only in TUI mode, publish without blocking,
and cannot influence Hyper's authoritative protocol decisions. Operators must
protect terminal access and screen recordings. The HTTP/1.1 editor converts a
local text draft to bounded typed header/body changes while keeping routing and
framing validation in the data plane.

The maintained threat analysis is
[`src/content/docs/developer/threat-model.md`](src/content/docs/developer/threat-model.md).
