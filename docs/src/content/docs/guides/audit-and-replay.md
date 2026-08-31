---
title: Audit and offline replay
description: Retain redacted audit evidence, sign checkpoints, and evaluate it with a candidate policy.
publishedAt: 2026-08-31
updatedAt: 2026-08-31
tags:
  - audit
  - replay
  - integrity
sidebar:
  order: 7
---

Operational diagnostics use `tracing`; security events go to a separate typed
JSONL stream. The publisher is bounded and follows the configured failure
policy.

## Choose an audit path

```toml
[audit]
path = "/var/lib/freja"
channel_capacity = 1024
failure_policy = "fail-closed"
redact_query_parameters = ["access_token", "api_key", "password", "secret", "token"]
checkpoint_interval = 1000
```

If `path` is an existing directory, each start creates a unique
`freja-<unix-ms>-<pid>-<collision>.jsonl` segment. If it names a file, that file
must not already exist; Freja never silently overwrites an audit segment. On
Unix, new segments are created with owner-only `0600` permissions. Protect the
containing directory as well.

`fail-closed` waits for bounded capacity and treats a closed consumer as an
enforcement failure. `fail-open` does not wait but reports rejection and
increments `audit_rejected_events`. Use fail-open only when traffic continuity
has explicitly higher priority than audit completeness. Records are flushed
from the process buffer after each event; a writer error stops the CLI instead
of leaving a degraded proxy running.

## Capture policy

Metadata-only capture is the default:

```toml
[capture]
mode = "metadata-only"
```

Explicit prefix capture persists sensitive plaintext as hexadecimal:

```toml
[capture]
mode = "prefix"
max_bytes = 4096
```

`max_bytes` must not exceed `limits.body_prefix_bytes`. Authorization,
Proxy-Authorization, Cookie, Set-Cookie, configured query parameters, and
secret headers in replay facts are redacted before records are hashed.

## Sign periodic checkpoints

Create and protect a 32-byte Ed25519 seed:

```sh
install -d -m 0700 /etc/freja
openssl rand -hex 32 > /etc/freja/audit-ed25519-seed.hex
chmod 0600 /etc/freja/audit-ed25519-seed.hex
```

```toml
[audit]
path = "/var/lib/freja"
checkpoint_signing_key = "/etc/freja/audit-ed25519-seed.hex"
checkpoint_interval = 1000
```

Each checkpoint signs the immediately preceding sequence and record hash. Store
the public verification key in a separately controlled location; it appears in
checkpoint events but must be pinned independently to establish authenticity.

## Replay with a candidate policy

```sh
freja replay \
  --audit /var/lib/freja/freja-....jsonl \
  --config ./candidate.toml \
  --checkpoint-public-key '<64 hexadecimal characters>'
```

Replay first verifies sequence continuity, previous-hash links, record hashes,
checkpoint signatures, and each checkpoint's chain position. It accepts audit
schema version 1 and rejects unsupported versions explicitly. A pinned key
also requires at least one checkpoint from that key. Only after integrity
succeeds does Freja evaluate persisted requested/resolved/HTTP/finding facts
and rebuild direction-specific scanners for captured prefixes. Replay rejects
a JSONL line larger than 16 MiB and captured bytes larger than the candidate
`limits.body_prefix_bytes` before detector evaluation.

Without `--checkpoint-public-key`, embedded signatures prove only internal
self-consistency: an attacker able to replace the whole segment could also
replace the embedded public key. Hash chains and in-segment checkpoints also
cannot prove that an unseen tail was deleted. Export segments or checkpoints to
separately controlled storage when truncation resistance matters.

See the [audit schema reference](/reference/audit-schema/) for fields and event
types.
