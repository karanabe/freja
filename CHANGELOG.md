# Changelog

All notable changes to Freja are documented here. The seven published crates
share one version and are released together.

## 0.2.0

### Added

- Added bounded TUI traffic and diagnostics views with correlated HTTP and TCP
  flows, Pretty/Raw/Hex presentation, and non-blocking event-loss counters.
- Added bounded interactive HTTP/1.1 request editing. Freja accepts typed
  header/body changes and keeps routing, protected headers, and wire framing in
  the data plane.
- Added bounded HTTP/1.1 Repeat workspaces for plain and intercepted requests.
  Each attempt receives fresh flow identifiers and re-enters destination,
  policy, inspection, hook, TLS, audit, and replay-fact processing.
- Added a loopback Axum test origin and focused headless/TUI configuration
  profiles for local verification.
- Added audit schema version 2 and the `http-repeat-started` provenance event.
  Replay remains compatible with schema versions 1 and 2.

### Changed

- Running `freja` or `freja run` without `--config` now starts a built-in
  loopback HTTP proxy. The application default is TUI + Observe + Interactive;
  the standard unattended profile is Headless + Enforce + Disabled.
- Raised the minimum supported Rust version from 1.88 to 1.98 while retaining
  Rust edition 2024, Pingora 0.8.1, and ratatui 0.30.2 as compatibility
  baselines.
- Split configuration, policy, proxy, audit, UI, and CLI internals into focused
  ownership modules without changing the seven-crate dependency direction.
- Clarified that the shipped multi-listener CLI owns concrete Tokio listeners;
  `freja-proxy/pingora-adapter` remains an isolated compatibility boundary.

### Upgrade notes

- Pin all Freja crates to `0.2.0`; mixed `0.1.x`/`0.2.x` workspace dependency
  sets are unsupported.
- A configuration that omits `[runtime]` now selects the interactive default.
  Unattended deployments should explicitly set `ui = "headless"`,
  `enforcement = "enforce"`, and `hooks = "disabled"`.
- Audit consumers must accept newly written schema version 2 records. Freja's
  replay command continues to verify version 1 segments.
- The new `limits.ui_content_bytes` and `limits.ui_retained_rows` settings have
  bounded defaults. Interactive configurations must retain a complete bounded
  request and enough rows for every paused flow.

## 0.1.0

- Initial coordinated release of the seven Freja crates with HTTP/1.1 explicit
  forwarding, CONNECT and opt-in TLS interception, static TCP, SOCKS5 CONNECT,
  ordered ACLs, bounded inspection, typed hooks, audit/checkpoints, reload, and
  offline replay.
