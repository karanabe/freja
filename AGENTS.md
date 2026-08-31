# Freja Development Instructions

You are the lead Rust engineer for Freja.

Freja is a local-first, explainable L4/L7 inspection proxy. It supports
explicit HTTP forward proxying, CONNECT tunneling, static TCP proxying,
ACL enforcement, streaming inspection, audit logging, an optional ratatui
interface, and typed request/response transformation hooks.

## Fixed architectural decisions

1. The domain, policy, inspection, audit, hook, and UI layers must not depend
   on Pingora types.

2. Pingora is used as a server/runtime adapter through `ServerApp`.
   Do not use `pingora-proxy::ProxyHttp` for the explicit HTTP forward proxy.

3. HTTP/1 forward-proxy semantics are implemented with Hyper 1.x on top of
   the transport stream supplied by Pingora.

4. Do not implement an HTTP parser from scratch.

5. If integrating Hyper with Pingora `Box<dyn IO>` is not practical, add a
   pure Tokio listener adapter behind the same engine boundary. Do not distort
   the domain design to preserve Pingora usage.

6. Do not downgrade or pin the `http` crate solely to work around Pingora's
   absolute-form or CONNECT parsing issue. Any workaround requires an ADR and
   an isolated experimental feature.

7. The initial HTTP scope is HTTP/1.1 explicit forward proxying:
   - absolute-form requests;
   - CONNECT authority-form;
   - plain HTTP forwarding;
   - HTTPS tunneling without TLS interception.

8. The initial L4 scope is a static listener-to-upstream TCP proxy.
   SOCKS5, TPROXY, SNI routing, UDP, caching, and TLS interception are not part
   of the first milestone.

9. Headless mode is only a UI mode. Keep these concepts separate:
   - `UiMode`: Headless or Tui;
   - `EnforcementMode`: Observe or Enforce;
   - `HookMode`: Disabled, Automatic, or Interactive.

10. Hooks are disabled by default.

## Rust design rules

- Use Rust edition 2024.
- Use Tokio for asynchronous networking.
- Use Pingora 0.8.1 as the initial Pingora compatibility baseline.
- Use ratatui 0.30.2 as the initial TUI compatibility baseline.
- Do not use `anyhow`, `thiserror`, `eyre`, or equivalent error-erasure crates.
- Do not use `unsafe` in Freja crates.
- Add `#![forbid(unsafe_code)]` to Freja library crates.
- Do not use `unwrap`, `expect`, `panic`, `todo`, or `unimplemented` in
  non-test code.
- Use concrete error enums at library boundaries.
- Use a boxed `AppError` only in the CLI/bootstrap/task boundary.
- Implement `Display` and `std::error::Error` manually.
- Preserve error sources and add context wrappers.
- Do not add a blanket generic `From<E> for AppError`.
- Prefer structs and enums that represent domain concepts.
- Avoid primitive obsession where validation or invariants exist.
- Avoid a single large context struct containing many `Option` fields.
- Use typestate only where it prevents meaningful invalid transitions,
  such as configuration compilation or HTTP response commitment.
- Keep files focused on one meaningful responsibility.
- Do not create a new crate for every small concept.
- Do not allow `freja-domain` to become a miscellaneous utility crate.
- Public types and non-obvious invariants require rustdoc.

## Required workspace

Create these crates:

- `freja-domain`
- `freja-config`
- `freja-policy`
- `freja-audit`
- `freja-proxy`
- `freja-ui`
- `freja-cli`

Keep hooks under `freja-policy::hook` initially. Do not publish a separate
hook SDK until the API has stabilized.

## Data-plane rules

- Never use an unbounded channel.
- UI backpressure must never block network forwarding.
- Audit events and UI events must use separate publishers.
- UI events may be dropped with an explicit metric.
- Audit events must follow an explicit failure policy.
- Every connection has a `SessionId`.
- Every HTTP exchange has a `TransactionId`.
- Every decision records the policy generation.
- Never expose the proxy on a non-loopback address by default.
- Non-loopback binding requires explicit configuration.
- Enforce connection, header, body, capture, timeout, and paused-flow limits.
- CONNECT must establish the upstream connection before returning success.
- Restrict CONNECT destination ports through policy.
- Re-evaluate destination policy after DNS resolution.
- Evaluate every resolved address, not only the hostname.
- Protect loopback, link-local, private, and metadata-service destinations
  according to configuration.
- Re-evaluate policy for every redirect or newly selected destination.

## HTTP correctness rules

- For absolute-form requests, derive and regenerate the Host header from the
  request target.
- Remove or normalize hop-by-hop headers.
- Reject malformed or ambiguous message framing.
- Do not forward conflicting Transfer-Encoding and Content-Length values.
- Respect request and response body streaming.
- Do not buffer an entire body unless the configured capture or inspection
  mode explicitly requires it.
- A successful CONNECT switches to tunnel mode.
- After tunnel commitment, do not attempt to emit HTTP block or redirect
  responses.
- Hook mutations must be represented as typed mutation plans.
- Hooks must not directly emit arbitrary HTTP wire bytes.
- Recompute Content-Length and framing after body mutation.
- Treat wire-encoded and decoded body representations as distinct types.

## Inspection rules

- Detectors produce `Finding`; detectors do not directly block traffic.
- Policy combines facts and findings into `Decision`.
- Every decision includes a `DecisionTrace`.
- Support `Preflight` and `Streaming` inspection as distinct modes.
- Handle byte patterns split across read-buffer boundaries.
- Apply explicit memory and time budgets.
- Do not block solely on entropy without another signal.
- Payload capture is disabled by default.
- Evidence should be stored as a hash unless raw evidence is explicitly
  permitted.

## Audit rules

- Operational logs use `tracing`.
- Security audit records use typed, versioned events.
- Start with JSONL.
- Redact Authorization, Proxy-Authorization, Cookie, Set-Cookie, configured
  query parameters, and secrets.
- Include sequence number, timestamp, session ID, transaction ID when
  applicable, policy generation, event type, previous hash, and record hash.
- Never silently drop critical audit records.

## Hook rules

- Hooks are disabled by default.
- Start with in-process registered hooks.
- Do not load Rust dynamic libraries as plugins.
- If an external plugin model is introduced later, prefer sandboxed WASM with
  explicit capabilities, time limits, memory limits, and execution budgets.
- Interactive interception uses a bounded request channel and a oneshot
  response.
- Configure maximum paused flows and an interception timeout.
- Timeout behavior must be explicit: fail-open or fail-closed.

## TUI rules

- The TUI owns the terminal from a dedicated thread or isolated task.
- Use an RAII terminal guard.
- Restore the terminal after normal exit, error, and panic.
- The TUI consumes immutable UI events.
- The TUI must not hold references to live network sessions.
- Large bodies are represented by bounded snapshots or storage handles.

## Documentation

Create and maintain:

- `docs/architecture.md`
- `docs/threat-model.md`
- `docs/audit-schema.md`
- `docs/hooks.md`
- `docs/competitors.md`
- `docs/adr/0001-engine-boundary.md`
- `docs/adr/0002-pingora-server-app.md`
- `docs/adr/0003-forward-proxy-http-engine.md`
- `docs/adr/0004-tls-interception-out-of-mvp.md`

The competitor document must explicitly state that VEY, Rama, mitmproxy,
Hudsucker, and Squid exist. Freja must not claim that Rust, ACL support,
forward proxying, TLS interception, L4/L7 support, or performance alone are
unique differentiators.

Freja differentiates through explainable policy decisions, typed hooks,
shared live/headless/replay pipelines, privacy-aware audit records, and
local-first operation.

## Quality gates

Before declaring a milestone complete, run and fix all failures from:

cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features

Add integration tests for externally observable behavior.

Do not merely produce a plan. Implement the requested milestone, validate it,
and leave the repository in a compiling and tested state.

At the end, report:

1. files created and changed;
2. architectural decisions made;
3. commands executed;
4. test results;
5. remaining risks and intentionally deferred scope.
