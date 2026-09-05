---
title: Threat model
description: Trusted inputs, attack surfaces, implemented controls, and residual operator risks.
publishedAt: 2026-08-31
updatedAt: 2026-09-05
tags:
  - security
  - threat-model
  - developer
sidebar:
  order: 4
---

Freja accepts attacker-controlled connections, protocol metadata, DNS answers,
payload bytes, and replay input. It makes security decisions and may hold a TLS
CA key. Configuration, signing keys, CA material, the binary, and the local
operating environment are trusted administrative inputs. A remote control plane
is out of scope.

## Assets and boundaries

Assets include:

- client/upstream confidentiality and integrity;
- policy identity and decision trace integrity;
- service availability and resource budgets;
- authentication material and intercepted plaintext;
- audit continuity, captured evidence, and checkpoint signing keys;
- the TLS interception CA private key.

Untrusted data crosses TCP and SOCKS handshakes, Hyper parsing, DNS, TLS
handshakes, streaming inspection, hook mutation, TUI input, audit
serialization, and replay parsing.

## Implemented controls

### Exposure and destination selection

- Listener binds are loopback-only by default. Remote HTTP/SOCKS5 requires
  explicit opt-in plus authentication; remote static TCP is rejected.
- Configuration stores only SHA-256 digests of exact `username:password`
  values. Comparison is constant-time, temporary decoded credentials are
  zeroed, credentials are stripped before forwarding, and audit stores outcomes.
- Requested hostname/port policy runs before DNS. Every resolved IP is checked
  against ACL and configurable loopback/private/link-local/metadata guards.
- CONNECT ports are allowlisted and upstream TCP must connect before 200.

### Protocol and resource safety

- Hyper handles authoritative HTTP/1 parsing and forwarding. The private TUI
  Raw framer is only a bounded observer and cannot make a protocol decision.
  Conflicting framing, excessive headers, ambiguous targets, and unsafe
  hop-by-hop forwarding are rejected by the data plane.
- Connection count, header/body/TUI content, retained TUI rows,
  DNS/connect/idle/interception timeout, leaf cache, audit/UI queues, paused
  flows, and manual edits are bounded.
- Streaming signatures retain bounded overlap; preflight holds only its prefix
  budget.
- Hooks cannot emit wire bytes or modify hop-by-hop framing. Interactive
  requests are bounded and the CLI uses fail-closed timeout behavior. The
  HTTP/1.1 editor uses `httparse` only to translate a local draft into typed
  changes; it locks routing/start-line fields, rejects protected-header edits,
  and relies on the data plane to revalidate limits and rebuild framing.
- Repeat workspaces retain bounded typed drafts rather than live connections.
  Every send receives fresh identifiers and re-enters destination checks,
  policy, inspection, hooks, authenticated TLS, audit, and replay-fact
  publication. Only listener authentication and recursive interactive pausing
  are skipped for requests originating from the local TUI.

### Audit and sensitive data

- Secret headers and configured query parameters are redacted before hashing.
  Payload capture is metadata-only by default; evidence is hashed unless prefix
  capture is explicitly enabled.
- Audit and UI use separate publishers. UI loss is counted. Audit failure
  follows an explicit policy and is not silent. The CLI monitors the writer,
  flushes after each event, and shuts down on writer failure.
- The TUI's live traffic content is intentionally unredacted and exists only in
  bounded process memory. Operators must restrict terminal access and screen
  recording. Headless mode does not install the HTTP Raw observers.
- Record/previous hashes detect internal modification and reordering. Ed25519
  checkpoints authenticate chain positions when a trusted key is pinned.
- New audit segments use owner-only `0600` permissions on Unix. Directory
  access, storage durability, rotation, and export remain operator controls.

### TLS interception and service isolation

- Interception requires explicit hostname allowlist and CA inputs. Unix CA keys
  must deny group/other permissions. Upstream certificate/name verification
  remains enabled; generated certificates contain SAN names; the cache is
  bounded by host and ALPN.
- The upstream TLS handshake uses the downstream-selected ALPN before payload
  relay. A post-CONNECT failure closes and audits the tunnel.
- The systemd unit drops capabilities, denies privilege escalation, constrains
  writable paths/address families, and applies kernel/process/syscall controls.

## Residual risks and operator responsibilities

- A compromised CA or audit signing key defeats its trust claim. Restrict
  access, rotate keys, and distribute the interception CA only to managed
  clients.
- HTTP Basic and RFC 1929 credentials are safe only on a protected path. Freja
  has no online guessing rate limit; deployments need network controls.
- Certificate-pinned applications can reject generated leaves. Freja cannot
  safely bypass pinning.
- DNS answers can change. Freja re-evaluates each resolution, but resolver
  compromise and rebinding remain environmental risks.
- Hash chains and in-segment checkpoints cannot prove deletion of an unseen
  tail or whole segment. Pin keys and export evidence to separate control.
- Prefix capture increases breach impact. Use the smallest bound and define
  access, retention, and deletion policy.
- TUI `ui_content_bytes` similarly increases live-memory and shoulder-surfing
  exposure even when audit capture remains metadata-only.
- Anyone who can operate the TUI can edit and repeat a retained request while
  preserving its original source IP as policy input. Treat terminal access as
  authority to originate those audited attempts, and delete workspaces that no
  longer need to be retained.
- Content-encoded representations are not decompressed automatically. Streaming
  body replacement rejects encoded messages; preflight replacement explicitly
  removes stale representation metadata.
- Metrics have no built-in administrative HTTP endpoint; embedders sample a
  process-local API.

Security-sensitive changes must update this page and add tests at the boundary
they alter.

## Live rule definitions

Rule inspection can expose internal hostnames and header matching values,
including configured ACL rules that did not match the selected evaluation, in the
local terminal. Definition snapshots have per-field limits and escaped terminal
controls. They are excluded from audit and serialized UI events, are not sent to
ordinary logs or external services, and are retained only within bounded UI
history and one open detail. Treat terminal access as access to these sensitive
policy values. Unavailable or truncated definitions are explicit; a current
same-ID rule cannot stand in for missing historical evidence.
