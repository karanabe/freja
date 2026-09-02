# Freja Development Instructions

You are the lead Rust engineer for Freja.

Freja is a local-first, explainable L4/L7 inspection proxy. The current
workspace implements HTTP/1.1 explicit forward proxying, CONNECT tunneling,
hostname-allowlisted TLS interception for HTTP/1.1 and HTTP/2, static TCP
forwarding, SOCKS5 CONNECT, ordered ACLs and TCP detours, bounded inspection,
typed hooks, a ratatui interface, tamper-evident JSONL audit segments, signed
checkpoints, atomic Unix SIGHUP policy reload, and offline replay.

Treat the implementation, integration tests, `examples/config/`, and Cargo
metadata as the source of truth. Persistent documentation describes current
behavior, not an earlier milestone plan.

## Fixed architectural decisions

1. Keep security decisions and protocol-independent models free of runtime
   framework types. Pingora types must not escape `freja-proxy` or appear in
   `freja-domain`, `freja-config`, `freja-policy`, `freja-audit`, or
   `freja-ui`.

2. The shipped multi-listener CLI owns concrete Tokio listeners. The optional
   `freja-proxy/pingora-adapter` feature provides a narrow Pingora 0.8.1
   `ServerApp` compatibility boundary and is compile-tested with all features.
   Do not pretend the Tokio and Pingora process lifecycles are interchangeable.

3. Do not use `pingora-proxy::ProxyHttp` for explicit forward proxying. Hyper
   1.x is authoritative for plain HTTP/1.1 and intercepted HTTP/1.1/HTTP/2
   protocol state. Freja owns explicit-proxy target rules, policy, framing
   validation around parsed messages, upstream selection, synthetic responses,
   inspection, and mutation.

4. Do not implement another authoritative HTTP wire parser. The private
   TUI-only HTTP/1 framer may only delimit bounded ingress snapshots for
   presentation; it must remain unable to accept, reject, mutate, delay, or
   otherwise influence forwarding. The TUI request editor may parse a bounded
   local draft into typed changes, but it does not emit wire bytes.

5. Do not downgrade or pin the `http` crate solely to work around Pingora
   parsing behavior. Any such experiment requires its own ADR and isolated
   feature.

6. Preserve the configuration compiler boundary:
   `RawConfig -> ValidatedConfig -> CompiledConfig`. Translate compiled values
   into subsystem-owned settings at the `freja` composition root; do not make
   `freja-proxy` depend on `freja-config` or `freja-ui`. Commandless/config-free
   CLI startup constructs its loopback-only HTTP listener at the composition
   root and passes the built-in values through the same compiler pipeline.

7. Keep independent runtime choices independent:

   - `UiMode`: Headless or Tui;
   - `EnforcementMode`: Observe or Enforce;
   - `HookMode`: Disabled, Automatic, or Interactive;
   - `TlsHandling`: Tunnel or Intercept.

   TUI is a presentation mode, not an enforcement mode. The application
   default is Tui + Enforce + Interactive, while the standard headless profile
   is Headless + Enforce + Disabled. TLS interception, payload capture, and
   remote exposure remain separate opt-ins.

8. Hooks remain under `freja-policy::hook` while their contracts stabilize.
   They are in-process, typed, and bounded. Interactive hooks are the
   application default; the standard headless profile disables hooks. The
   shipped CLI intentionally registers no automatic hooks. Do not load Rust
   dynamic libraries or publish a separate hook SDK yet.

9. Keep runtime and data-plane delivery paths distinct. Critical audit
   publication and best-effort immutable UI/data-plane events use separate
   bounded publishers. UI loss may be counted and dropped; it must never slow
   forwarding.

10. Current protocol scope is deliberately bounded. SOCKS5 supports CONNECT,
    not BIND or UDP ASSOCIATE. Transparent proxying, TPROXY, UDP forwarding,
    caching, manual response/TCP pausing or mutation, and a remote control plane
    are not implemented. Do not advertise or incidentally add them without an
    explicit design and externally observable tests.

## Rust design rules

- Use Rust edition 2024 and preserve the workspace MSRV of Rust 1.98.
- Use Tokio for asynchronous networking.
- Keep Pingora 0.8.1 and ratatui 0.30.2 as the compatibility baselines until an
  intentional, tested upgrade changes them.
- Do not use `anyhow`, `thiserror`, `eyre`, or equivalent error-erasure crates.
- Do not use `unsafe` in Freja crates. Library crates must use
  `#![forbid(unsafe_code)]`.
- Do not use `unwrap`, `expect`, `panic`, `todo`, or `unimplemented` in non-test
  code.
- Use concrete error enums at library boundaries. Box concrete sources only in
  the CLI/bootstrap/task `AppError` boundary.
- Implement `Display` and `std::error::Error` manually, preserve error sources,
  and add context at the boundary that understands the failed operation.
- Do not add a blanket generic `From<E> for AppError`.
- Prefer validated domain types over primitive values where invariants exist.
- Avoid large context structs containing unrelated `Option` fields.
- Use typestate only when it prevents a meaningful invalid transition, such as
  configuration compilation or protocol commitment.
- Keep files and modules focused on one responsibility. Split large modules by
  ownership, not by arbitrary line count.
- Do not create a crate for every small concept or turn `freja-domain` into a
  miscellaneous utility crate.
- Public types and non-obvious lifecycle, security, and framing invariants
  require rustdoc.

## Workspace and dependency direction

Keep the seven-crate workspace and these responsibilities:

- `freja-domain`: identifiers, endpoints, facts, findings, decisions, traces,
  listener specifications, and runtime modes; no Freja crate dependencies.
- `freja-policy`: ordered ACLs, destination guards, bounded inspection, and
  typed automatic/interactive hooks; depends only on `freja-domain` among
  Freja crates.
- `freja-audit`: typed redaction, bounded publication, versioned hash-chained
  JSONL, and Ed25519 checkpoints; depends only on `freja-domain`.
- `freja-config`: raw, validated, and compiled configuration stages; may depend
  on domain, policy, and audit types.
- `freja-ui`: immutable bounded UI state, terminal ownership, and interactive
  request decisions; may depend on domain and policy, but never proxy sessions.
- `freja-proxy`: HTTP/CONNECT/TLS, TCP, SOCKS5, inspection plumbing, metrics,
  event publication, and runtime adapters; may depend on domain, policy, and
  audit, but not config or UI.
- `freja`: CLI, composition, subsystem translation, signals, reload, audit
  writer, replay, and the application error boundary; composes all crates.

The standalone, non-published `examples/http-test-server` workspace is a
development-only Axum origin for manual checks without public network services.
Keep its inputs and outputs bounded, bind it to loopback by default, and never
make it a production dependency of the seven Freja crates.

The Cargo-metadata dependency-boundary integration test is an architectural
gate. Update it only for an intentional dependency decision, never merely to
make an accidental edge pass.

## Data-plane and safety rules

- Never use an unbounded channel or collection for attacker-controlled or
  long-lived runtime data.
- Every connection has a `SessionId`; every HTTP exchange has a
  `TransactionId`; every decision records the active policy generation.
- Listeners bind to loopback by default. Non-loopback binding requires explicit
  configuration; remote HTTP and SOCKS5 also require authentication, while
  remote static TCP remains rejected.
- Enforce configured connection, header, body-prefix, TUI content/row, cache,
  timeout, channel, and paused-flow limits.
- Evaluate the requested hostname and port before DNS. After resolution,
  evaluate every returned address against ACL and loopback, private,
  link-local, metadata-service, multicast, and unspecified-address rules.
- Re-run requested and resolved checks for a TCP detour or any newly selected
  destination. Reject detour loops.
- Restrict CONNECT ports through the listener policy. Establish and authorize
  upstream TCP before committing the success response.
- Track spawned listener, tunnel, audit, reload, and TUI work so shutdown can
  signal and drain owned tasks.
- On Unix, SIGHUP may atomically replace only the compatible decision snapshot:
  ACL, destination guards, enforcement mode, inspection mode/program, and
  policy generation. Resource-owning, listener, authentication, TLS, capture,
  audit-sink, UI, hook, and limit changes require restart.

## HTTP and TLS correctness rules

- Accept absolute-form HTTP/1.1 requests and CONNECT authority-form. Regenerate
  origin-form and `Host` from the validated absolute target.
- Remove or normalize hop-by-hop headers and strip proxy credentials before
  upstream forwarding.
- Reject malformed or ambiguous targets and framing. Never forward conflicting
  `Transfer-Encoding` and `Content-Length` values.
- Stream request and response bodies. Buffer a complete body only when bounded
  preflight, interactive interception, capture, or mutation explicitly requires
  it.
- A successful CONNECT changes the protocol commitment state. After success is
  committed, do not emit an HTTP block or redirect response; later failures
  close and audit the tunnel.
- Blind CONNECT is the default. TLS interception requires configured CA
  material, a non-empty hostname allowlist, protected key permissions, and a
  bounded leaf cache. Never intercept IP literals.
- Authenticate upstream TLS and preserve the selected `h2` or `http/1.1` ALPN.
  Inner intercepted requests stay pinned to the CONNECT destination, reject
  nested CONNECT, and traverse the same policy, inspection, hook, audit, and
  replay pipeline.
- Treat wire-encoded and decoded bodies as distinct types. Hook mutations are
  typed plans; reject protected framing/hop-by-hop changes and recompute framing
  and `Content-Length` after body mutation.
- Exact Raw/Hex HTTP capture is currently limited to bounded ingress bytes for
  plain explicit HTTP/1. Local synthetic responses, intercepted persistent
  HTTP/1, and HTTP/2 retain semantic views and must report exact Raw as
  unavailable rather than fabricate it.

## Policy and inspection rules

- Declaration-ordered ACLs use first-match semantics and always produce an
  explainable `DecisionTrace`.
- Detectors produce `Finding`; they do not directly block or reroute traffic.
  Policy combines facts and findings into `Decision`.
- Keep `Preflight` and `Streaming` inspection semantically distinct. Preflight
  may deny before bytes are released; streaming cannot retract bytes already
  forwarded.
- Fixed-pattern detection must find matches split across read-buffer
  boundaries while retaining only bounded overlap.
- Apply explicit byte and time budgets. Do not add unbounded decompression or
  whole-body buffering.
- Do not block solely on entropy without another signal.
- Payload capture is metadata-only by default. Store evidence hashes unless
  raw prefixes are explicitly enabled and bounded.

## Audit and replay rules

- Operational diagnostics use `tracing`; security audit records use typed,
  versioned events.
- Redact Authorization, Proxy-Authorization, Cookie, Set-Cookie, configured
  query parameters, and known secrets before serialization and hashing.
- Records include sequence, timestamp, session ID, transaction ID when
  applicable, policy generation, event type, previous hash, and record hash.
- Never silently drop critical audit records. Honor the explicit fail-open or
  fail-closed publication policy and surface writer failure to bootstrap.
- A directory audit target receives a unique segment per start; an exact file
  path is never overwritten. Preserve owner-only `0600` segment behavior on
  Unix.
- Replay schema version 1 verifies sequence and hash-chain integrity before
  evaluating recorded facts and captured prefixes. Signed Ed25519 checkpoints
  prove authenticity only when the expected public key is pinned externally.
- New event fields or variants require schema, redaction, hash, replay,
  compatibility, and tamper tests plus synchronized audit documentation.

## Hook and interactive interception rules

- Automatic hooks have six typed stages: HTTP request head/body, HTTP response
  head/body, and TCP chunks in both directions.
- Hook contexts contain copied identifiers and bounded snapshots, never live
  network session references. Hook timeout and fail-open/fail-closed behavior
  are explicit.
- Interactive mode requires TUI. It uses a bounded request channel, an
  independent paused-flow semaphore, a oneshot response, and an explicit
  timeout; the CLI currently fails closed.
- Pause one complete bounded HTTP request at most once before upstream
  forwarding. Oversized interactive bodies receive 413. CONNECT may pause only
  before tunnel commitment with an empty body.
- Responses and TCP traffic are observable but never wait for an operator.
- The TUI editor may atomically modify textual HTTP/1.1 end-to-end headers and
  a UTF-8 body. Method, target, version, `Host`, hop-by-hop fields, and framing
  remain data-plane-owned and read-only. Revalidate typed plans in the data
  plane before forwarding.
- Audit manual actions without storing edited content.

## TUI rules

- The TUI owns the terminal on an isolated thread and uses an RAII guard to
  restore it after normal exit, error, and panic unwinding.
- Route operational tracing through bounded immutable UI events while the TUI
  owns the terminal; do not concurrently write ordinary logs to the raw
  terminal.
- The TUI consumes immutable snapshots and never retains references to live
  network sessions. Represent content as bounded snapshots or storage handles.
- UI publication is best effort and non-blocking. Count dropped events, capture
  failures, and truncations without changing the network outcome.
- Treat live TUI payloads as intentionally unredacted sensitive data. Keep them
  bounded, local to process memory, and independent from audit capture/redaction.
- Preserve flow correlation by `TransactionId` for HTTP and `SessionId` for
  TCP, and test navigation, modal editor states, rendering, terminal escaping,
  and restoration behavior.

## Documentation

- The canonical documentation site is `docs/src/content/docs/`. English pages
  are the root locale; matching Japanese pages live under `ja/` at the same
  relative path.
- Follow `docs/README.md` for the Astro Starlight workflow. Update both locales
  in one change and keep frontmatter, navigation, internal links, and anchors
  valid.
- Maintain architecture, engine boundaries, threat model, hooks, testing,
  configuration, CLI, audit schema, operator guides, troubleshooting, and ADRs
  when their contracts change. Keep same-topic legacy Markdown under `docs/`
  from contradicting the canonical site.
- ADR 0004 records TLS interception as out of the original MVP; ADR 0005 records
  the later bounded opt-in implementation. Do not erase historical decisions
  when current behavior advances beyond them.
- Competitive positioning must acknowledge VEY, Rama, mitmproxy, Hudsucker,
  and Squid. Do not claim Rust, ACLs, forward proxying, TLS interception,
  combined L4/L7 support, or performance alone as unique.
- Freja differentiates through explainable policy decisions, typed hooks,
  shared live/headless/replay pipelines, privacy-aware audit records, and
  local-first operation. Limit public claims to implemented, tested behavior.

## Quality gates

Before declaring a milestone complete, run and fix all failures from:

```console
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo check --manifest-path fuzz/Cargo.toml --bins
(cd docs && pnpm check)
```

Integration tests must cover externally observable network or CLI behavior and
must use local fixtures rather than public network services. Add focused unit
tests for local state machines and fuzz coverage for attacker-controlled parser
or framing boundaries.

Do not merely produce a plan. Implement the requested milestone, validate it,
and leave the repository compiling and tested.

At the end, report:

1. files created and changed;
2. architectural decisions made;
3. commands executed;
4. test results;
5. remaining risks and intentionally deferred scope.
