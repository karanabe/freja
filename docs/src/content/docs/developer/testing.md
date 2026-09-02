---
title: Development and testing
description: Workspace layout, validation gates, integration tests, fuzz targets, and documentation workflow.
publishedAt: 2026-08-31
updatedAt: 2026-09-03
tags:
  - testing
  - contributing
  - developer
sidebar:
  order: 5
---

Freja uses Rust edition 2024. The workspace's minimum declared and validated
Rust version is 1.98. Pingora compatibility is fixed at 0.8.1.

## Required gates

Run all gates before declaring a milestone complete:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
```

All-feature builds compile the Pingora adapter even though the multi-listener
CLI selects Tokio. Integration tests use local servers and observable protocol
behavior; they must not depend on public network services.

## Test ownership

- `freja-policy` unit tests cover first-match traces, destination guards,
  split-pattern detection, typed mutation, timeouts, and paused-flow bounds.
- `freja-audit` tests cover redaction-before-hash, sequence/hash chains, and
  checkpoint tamper detection.
- `freja-proxy/tests/http_forward.rs` covers absolute-form, framing limits,
  CONNECT, auth, response policy, inspection, hooks, reload, TLS interception,
  semantic intercepted HTTP/1.1/HTTP/2 forwarding, pinning failure, and exact
  TUI-only plain HTTP/1 request/response ingress capture.
- `tcp_static.rs` and `socks_forward.rs` cover relay, DNS reauthorization,
  detours, limits, inspection, and authentication.
- CLI tests cover configuration behavior, no-overwrite audit segments, and
  replay with pinned checkpoints. A Cargo-metadata integration test also locks
  the allowed workspace dependency direction and Pingora isolation boundary.
- UI tests render split and side-wide traffic plus diagnostics pages to
  ratatui's test backend, exercise pane/exit/editor key states, validate typed
  request drafts, and verify non-blocking saturation and terminal-control
  escaping. The HTTP integration suite verifies atomic manual header/body
  mutation and framing reconstruction at the upstream server.

Add a focused unit test for local logic and an integration test when externally
observable network or CLI behavior changes.

## Local HTTP test origin

The non-published `examples/http-test-server` package provides an Axum
origin for manual proxy checks without depending on a public network service.
It binds to `127.0.0.1:3001` by default and exposes request echo routes for GET,
POST, PUT, PATCH, DELETE, HEAD, OPTIONS, and arbitrary methods. It also provides
bounded status, redirect, delay, streaming, and fixed-size response routes.

With Freja using `examples/config/headless/freja.toml`, run these in separate
terminals:

```sh
cargo run --manifest-path examples/http-test-server/Cargo.toml
cargo run -p freja -- run --config examples/config/headless/freja.toml
curl --noproxy "" --proxy http://127.0.0.1:8080 \
  http://127.0.0.1:3001/get?name=freja
curl --noproxy "" --proxy http://127.0.0.1:8080 \
  http://127.0.0.1:3001/post --data 'hello through Freja'
```

`--noproxy ""` prevents environment-level loopback exclusions from bypassing
Freja. The sample configuration permits loopback destinations specifically for
local testing. The server prints each received method, URI, header set, total
body size, and at most 4 KiB of body preview to its terminal. All header values,
including credentials and cookies, are intentionally unredacted. Binary
previews are Base64 encoded, and terminal control characters are escaped. URIs,
headers, and body previews remain sensitive, so use only synthetic secrets and
payloads. Its full route table and limits are documented in
`examples/http-test-server/README.md`.

The standalone files under `examples/config/headless/` and
`examples/config/tui/` cover enforced headless operation, a focused blocking
detector, and interactive TUI runs with broad or focused bounds. The CLI
integration suite executes `check-config` against every shipped template so
schema changes cannot silently leave an example invalid.

## Fuzz targets

The nested `fuzz` workspace wires production parsers and state machines into
five targets:

```sh
cargo check --manifest-path fuzz/Cargo.toml --bins
```

Targets cover configuration parsing, target parsing, HTTP mutation plans,
binary scanning, and malformed/ambiguous HTTP framing. The framing target also
drives the private capture-only HTTP/1 message-boundary state machine. Building
targets proves they remain connected; release hardening should also run
time-bounded `cargo-fuzz` campaigns with retained corpora.

## Code constraints

- All library crates use `#![forbid(unsafe_code)]`.
- Do not use `anyhow`, `thiserror`, or equivalent erasure in library layers.
- Non-test code must not use `unwrap`, `expect`, `panic`, `todo`, or
  `unimplemented`.
- Preserve concrete sources and add context at boundaries.
- Never use unbounded channels or make UI delivery block forwarding.
- Public types and non-obvious invariants require rustdoc.

## Documentation site

The Astro site lives in `docs/` and has matching English/Japanese content.

```sh
cd docs
pnpm install --frozen-lockfile
pnpm build
```

Update both locale paths in one change. Treat code, sample configuration,
packaging, and integration tests as authoritative when a page disagrees.
