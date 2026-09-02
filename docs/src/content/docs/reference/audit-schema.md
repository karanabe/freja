---
title: Audit schema
description: Version 2 JSONL fields, compatibility, event variants, redaction, hash chaining, and signed checkpoints.
publishedAt: 2026-08-31
updatedAt: 2026-09-03
tags:
  - audit
  - schema
  - reference
sidebar:
  order: 3
---

Freja writes one JSON object per line. Newly written schema version 2 records have these top-level
fields:

| Field | Type | Meaning |
| --- | --- | --- |
| `schema_version` | integer | Currently written as `2`; replay also accepts `1` |
| `sequence` | non-zero integer | Monotonic within one segment |
| `occurred_at` | integer | Unix time in milliseconds |
| `session_id` | UUID | Connection correlation ID |
| `transaction_id` | UUID, optional | HTTP exchange correlation ID |
| `policy_generation` | non-zero integer | Snapshot identity used for the event |
| `event` | tagged object | Typed event payload |
| `previous_hash` | 64-character hex, optional | Prior record hash; absent on sequence 1 |
| `record_hash` | 64-character hex | SHA-256 of all preceding record fields |

The hash covers deterministic JSON serialization including the previous link.
A sink that encounters a partial write is poisoned and refuses to continue a
potentially misleading chain.

## Event types

The `event` object contains kebab-case `event_type` and an `event` payload.
Version 2 includes:

- `connection-accepted`, `target-resolved`, `tunnel-closed`, and `flow-closed`;
- `acl-evaluated`, `inspection-evaluated`, and `action-executed` with complete
  decisions and traces;
- `http-request-observed` and `http-response-observed`;
- `proxy-authentication` with outcome only;
- `finding-detected` with hashed evidence;
- `hook-executed` and `manual-modification` without edit content;
- `http-repeat-started` with only the source session and transaction IDs;
- `tls-certificate-generated` and `tls-interception-established`;
- `replay-facts-observed` and explicitly enabled `payload-prefix-captured`;
- `signed-checkpoint`.

Version 2 adds `http-repeat-started`; all earlier event shapes remain unchanged.
Replay accepts versions 1 and 2, rejects a v2-only repeat event labeled as v1,
and rejects unknown versions rather than guessing field semantics.

## Redaction and capture

Redaction runs before hashing and serialization. It covers Authorization,
Proxy-Authorization, Cookie, Set-Cookie, configured query parameter names, URL
userinfo, and secret header values in replay facts. Authentication events contain no
username, password, or digest.

Metadata-only is the default. Prefix capture adds direction, protocol, and
bounded bytes encoded as hexadecimal. Hex encoding is not protection; treat
these events as sensitive plaintext.

## Signed checkpoints

A signed checkpoint payload contains:

| Field | Meaning |
| --- | --- |
| `covers_sequence` | Immediately preceding segment sequence |
| `record_hash` | Hash at that sequence |
| `public_key_hex` | Ed25519 verifying key |
| `signature_hex` | Signature over Freja's domain tag, sequence, and hash |

Replay verifies the signature and requires the signed position to be the
checkpoint record's actual predecessor. Pinning `public_key_hex` outside the
segment is required for authenticity against whole-segment replacement.

## Failure policy

Audit and UI publishers are separate bounded channels. `fail-closed` waits for
audit capacity and propagates a closed consumer as an enforcement failure.
`fail-open` rejects immediately, increments `audit_rejected_events`, and leaves
the caller to continue according to the explicit deployment choice. Critical
records are never silently dropped. The CLI flushes each event from its process
buffer and shuts down if the audit writer exits early or reports an error. New
segment files are created with `0600` permissions on Unix.
