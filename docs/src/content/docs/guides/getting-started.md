---
title: Getting started
description: Build Freja, validate a safe local configuration, and proxy your first request.
publishedAt: 2026-08-31
updatedAt: 2026-09-03
tags:
  - installation
  - quick-start
  - cli
sidebar:
  order: 1
---

This guide builds Freja from source and starts its built-in loopback-only HTTP
forward proxy. No command or configuration file is required for this local
interactive path.

## Prerequisites

- Rust 1.98 or newer with Cargo;
- a C toolchain and CMake when building the optional Pingora compatibility
  feature or running the all-feature development gates;
- curl for the request examples;
- Linux or another Unix-like system for signal and service examples.

## Build the CLI

From the repository root:

```sh title="Terminal"
cargo build --release -p freja
./target/release/freja --help
```

Keep the binary and configuration under your normal software supply-chain
controls.

## Review the built-in defaults

Commandless startup uses these choices:

- one HTTP forward listener binds to `127.0.0.1:8080`;
- the TUI presents bounded live traffic snapshots;
- enforcement executes ACL and inspection decisions;
- interactive hooks pause bounded HTTP requests for continue, reject, or edit;
- payload audit capture and TLS interception remain disabled;
- audit is written to a unique local `freja-<timestamp>-<pid>-<counter>.jsonl`
  segment on every run;
- loopback, private, link-local, and metadata destinations remain protected;
- CONNECT is limited to port 443.

## Validate before binding

With no path, `check-config` validates the same built-in configuration without
opening a socket:

```sh title="Terminal"
./target/release/freja check-config
```

Expected output includes the number of listeners and the non-zero policy
generation:

```text
configuration valid: 1 listener(s), policy generation 1
```

Unknown top-level or strict-section keys, zero limits, unsafe listener exposure,
invalid policies, and incomplete TLS interception settings make this command
fail.

## Run and send a request

```sh title="Terminal 1"
RUST_LOG=freja=info ./target/release/freja
```

In a second terminal:

```sh title="Terminal 2"
curl --proxy http://127.0.0.1:8080 http://example.com/
curl --proxy http://127.0.0.1:8080 https://example.com/
```

The first request uses HTTP absolute-form forwarding. The second establishes a
CONNECT tunnel and leaves TLS end-to-end between curl and the destination
because tunnel mode is the default. Each request waits for a TUI decision;
press `c` to continue unchanged, `r` to reject, or `e`/`i` to edit a supported
HTTP/1.1 request.

Stop Freja with Ctrl+C. SIGINT and SIGTERM stop new accepts, signal active
relays, flush the audit writer, and restore the TUI when enabled.

## Customize with a configuration file

Copy a complete example instead of editing the repository copy:

```sh title="Terminal"
cp examples/config/tui/freja.toml ./freja.toml
./target/release/freja check-config --config ./freja.toml
./target/release/freja run --config ./freja.toml
```

The TUI example adds SOCKS5 and static TCP listeners. Headless and focused
enforcement profiles also live under `examples/config/`. These local-test
profiles allow loopback destinations; remove that opt-in unless a deployment
must reach local services.

## Next steps

- Configure [HTTP and CONNECT proxying](/guides/http-and-connect/).
- Add [policy and inspection rules](/guides/policy-and-inspection/).
- Learn what is persisted in [audit and replay](/guides/audit-and-replay/).
- Read the complete [configuration reference](/reference/configuration/).
