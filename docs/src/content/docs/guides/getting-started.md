---
title: Getting started
description: Build Freja, validate a safe local configuration, and proxy your first request.
publishedAt: 2026-08-31
updatedAt: 2026-08-31
tags:
  - installation
  - quick-start
  - cli
sidebar:
  order: 1
---

This guide builds Freja from source and runs the supplied loopback-only example.
The example opens an HTTP forward proxy, a SOCKS5 listener, and a static TCP
listener. Remove listeners you do not need before using it outside a test
machine.

## Prerequisites

- Rust 1.88 or newer with Cargo;
- a C toolchain and CMake when building the optional Pingora compatibility
  feature or running the all-feature development gates;
- curl for the request examples;
- Linux or another Unix-like system for signal and service examples.

## Build the CLI

From the repository root:

```sh title="Terminal"
cargo build --release -p freja-cli
./target/release/freja --help
```

Freja is not currently distributed as a package from this repository. Keep the
binary and configuration under your normal software supply-chain controls.

## Review the example

Copy the example instead of editing the repository copy:

```sh title="Terminal"
cp examples/freja.toml ./freja.toml
```

Important defaults and explicit choices in this file are:

- all listeners bind to `127.0.0.1`;
- enforcement remains observe-only;
- hooks, payload capture, and TLS interception are disabled;
- audit is written to a unique local `freja-<timestamp>-<pid>-<counter>.jsonl`
  segment on every run;
- local upstreams are allowed so the static TCP example can reach
  `127.0.0.1:9001`;
- CONNECT is limited to port 443.

:::caution
Allowing loopback destinations is useful for local tests but weakens SSRF
protection. Remove `loopback_destinations = "allow"` unless the deployment must
reach local services.
:::

## Validate before binding

`check-config` parses, validates, and compiles the complete configuration
without opening a socket:

```sh title="Terminal"
./target/release/freja check-config --config ./freja.toml
```

Expected output includes the number of listeners and the non-zero policy
generation:

```text
configuration valid: 3 listener(s), policy generation 1
```

Unknown top-level or strict-section keys, zero limits, unsafe listener exposure,
invalid policies, and incomplete TLS interception settings make this command
fail.

## Run and send a request

```sh title="Terminal 1"
RUST_LOG=freja=info ./target/release/freja run --config ./freja.toml
```

In a second terminal:

```sh title="Terminal 2"
curl --proxy http://127.0.0.1:8080 http://example.com/
curl --proxy http://127.0.0.1:8080 https://example.com/
```

The first request uses HTTP absolute-form forwarding. The second establishes a
CONNECT tunnel and leaves TLS end-to-end between curl and the destination
because tunnel mode is the default.

Stop Freja with Ctrl+C. SIGINT and SIGTERM stop new accepts, signal active
relays, flush the audit writer, and restore the TUI when enabled.

## Next steps

- Configure [HTTP and CONNECT proxying](/guides/http-and-connect/).
- Add [policy and inspection rules](/guides/policy-and-inspection/).
- Learn what is persisted in [audit and replay](/guides/audit-and-replay/).
- Read the complete [configuration reference](/reference/configuration/).
