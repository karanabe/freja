---
title: Development and testing
description: Workspace layout, validation gates, integration tests, fuzz targets, and documentation workflow.
publishedAt: 2026-08-31
updatedAt: 2026-08-31
tags:
  - testing
  - contributing
  - developer
sidebar:
  order: 5
---

Freja uses Rust edition 2024. The workspace's minimum declared Rust version is
1.88, matching ratatui 0.30.2 and the resolved TLS certificate stack. Pingora
compatibility is fixed at 0.8.1.

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
  semantic intercepted HTTP/1.1/HTTP/2 forwarding, and pinning failure.
- `tcp_static.rs` and `socks_forward.rs` cover relay, DNS reauthorization,
  detours, limits, inspection, and authentication.
- CLI tests cover configuration behavior, no-overwrite audit segments, and
  replay with pinned checkpoints.
- UI tests render to ratatui's test backend and verify non-blocking saturation.

Add a focused unit test for local logic and an integration test when externally
observable network or CLI behavior changes.

## Fuzz targets

The nested `fuzz` workspace wires production parsers and state machines into
five targets:

```sh
cargo check --manifest-path fuzz/Cargo.toml --bins
```

Targets cover configuration parsing, target parsing, HTTP mutation plans,
binary scanning, and malformed/ambiguous HTTP framing. Building targets proves
they remain connected; release hardening should also run time-bounded
`cargo-fuzz` campaigns with retained corpora.

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
