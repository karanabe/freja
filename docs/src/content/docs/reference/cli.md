---
title: CLI reference
description: Freja commands, options, exit behavior, logs, and Unix signals.
publishedAt: 2026-08-31
updatedAt: 2026-09-05
tags:
  - cli
  - reference
sidebar:
  order: 1
---

The binary is named `freja`. Every command returns zero on success and a
non-zero exit status after printing a contextual error chain on failure.

```text
freja [COMMAND]

Commands:
  check-config  Parse, validate, and compile a configuration without opening listeners
  run           Run proxy listeners from a file or the built-in defaults
  replay        Verify and evaluate recorded facts/captured prefixes with a candidate configuration
  help          Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version
```

Running `freja` without a command is equivalent to `freja run` without
`--config`: it starts the built-in local interactive proxy.

The coordinated release reports its workspace version directly:

```text
$ freja --version
freja 0.2.0
```

## `check-config`

```sh
freja check-config [--config <PATH>]
```

Short option: `-c`. Without a path, this validates the built-in configuration
used by config-free `run`. With a path, this follows the complete
`RawConfig -> ValidatedConfig -> CompiledConfig` path. It checks TOML keys,
endpoints, unsafe mode combinations, resource bounds, listener exposure,
credentials, required TLS configuration fields, ACL structure, and detector
definitions without binding a socket, opening the audit sink, or reading CA
material. `run` performs filesystem and certificate validation for configured
TLS interception.

Successful output reports listener count and policy generation.

## `run`

```sh
freja run [--config <PATH>]
```

The command itself may also be omitted when using built-in defaults. Short
option: `-c`. Without `--config`, Freja builds a configuration with one
HTTP forward listener on `127.0.0.1:8080`, TUI + observe + interactive runtime,
a CONNECT policy containing port 443, tunnel TLS handling, metadata-only audit
capture, and the normal protected destination classes. Observe mode records
ACL, destination-guard, inspection, and CONNECT-port deny or detour decisions
without executing them; interactive operator rejection remains effective.
Supplying a path replaces that complete configuration. Freja compiles the
selected source, creates bounded audit/UI publishers, initializes optional TLS
interception and TUI state, binds every listener, and waits for shutdown or an
early listener or audit-writer failure.

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
versions are rejected explicitly; this release accepts versions 1 and 2.

Replay does not open listeners or modify the source audit segment.

## Signals

| Signal | Effect |
| --- | --- |
| SIGINT | Graceful shutdown |
| SIGTERM | Graceful shutdown |
| SIGHUP | Reload the compatible file-backed policy snapshot; warn and ignore when built-in defaults are active |

Signals are Unix behavior. A rejected SIGHUP candidate leaves the active
snapshot unchanged and writes an operational warning. Changes that require new
listeners, sinks, authentication, limits, TLS, capture, or UI/hook resources
require a restart.
