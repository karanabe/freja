---
title: CLI reference
description: Freja commands, options, exit behavior, logs, and Unix signals.
publishedAt: 2026-08-31
updatedAt: 2026-08-31
tags:
  - cli
  - reference
sidebar:
  order: 1
---

The binary is named `freja`. Every command returns zero on success and a
non-zero exit status after printing a contextual error chain on failure.

```text
freja <COMMAND>

Commands:
  check-config  Parse, validate, and compile a configuration without opening listeners
  run           Run configured proxy listeners
  replay        Verify and evaluate stored facts with a candidate configuration
  help          Print help
```

## `check-config`

```sh
freja check-config --config <PATH>
```

Short option: `-c`. This follows the complete
`RawConfig -> ValidatedConfig -> CompiledConfig` path. It checks TOML keys,
endpoints, unsafe mode combinations, resource bounds, listener exposure,
credentials, required TLS configuration fields, ACL structure, and detector
definitions without binding a socket, opening the audit sink, or reading CA
material. `run` performs filesystem and certificate validation for configured
TLS interception.

Successful output reports listener count and policy generation.

## `run`

```sh
freja run --config <PATH>
```

Short option: `-c`. Freja compiles the configuration, creates bounded audit/UI
publishers, initializes optional TLS interception and TUI state, binds every
listener, and waits for shutdown or an early listener or audit-writer failure.

Set `RUST_LOG` to control operational diagnostics:

```sh
RUST_LOG=freja=debug,freja_proxy=trace freja run -c freja.toml
```

Security records are not controlled by `RUST_LOG`; they use the configured
audit JSONL sink. In TUI mode, operational lines appear in the bounded
`Operational logs` panel instead of being written directly to the raw terminal.

## `replay`

```sh
freja replay \
  --audit <JSONL-PATH> \
  --config <CANDIDATE-CONFIG> \
  [--checkpoint-public-key <64-HEX-CHARACTERS>]
```

Short options: `-a` for audit and `-c` for config. Replay validates the complete
segment before emitting candidate decisions as JSON lines to standard output.
The optional key is a 32-byte Ed25519 public key encoded as hexadecimal. When
specified, a matching valid checkpoint is mandatory. Unsupported audit schema
versions are rejected explicitly; this release accepts version 1.

Replay does not open listeners or modify the source audit segment.

## Signals

| Signal | Effect |
| --- | --- |
| SIGINT | Graceful shutdown |
| SIGTERM | Graceful shutdown |
| SIGHUP | Validate and atomically reload the compatible policy snapshot |

Signals are Unix behavior. A rejected SIGHUP candidate leaves the active
snapshot unchanged and writes an operational warning. Changes that require new
listeners, sinks, authentication, limits, TLS, capture, or UI/hook resources
require a restart.
