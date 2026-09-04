<br />
<h1 align="center">Freja</h1>
<h3 align="center">A local-first, explainable L4/L7 inspection proxy written in Rust.</h3>
<br />
<br />

Freja is a local-first, explainable L4/L7 inspection proxy written in Rust. It
provides HTTP/1.1 explicit forward proxying, CONNECT tunnels, opt-in TLS
interception, static TCP forwarding, SOCKS5 CONNECT, deterministic ACLs,
streaming inspection, typed hooks, a bounded ratatui traffic interface with
interactive HTTP request editing and bounded repeat workspaces, tamper-evident
audit segments, and offline policy replay.

The seven-crate workspace keeps domain, configuration, policy, inspection,
audit, hooks, and UI independent of Pingora. Hyper 1.x owns the plain HTTP/1.1
and intercepted HTTP/1.1/HTTP/2 protocol state machines. An opt-in
`freja-proxy/pingora-adapter` feature provides a small Pingora 0.8.1
`ServerApp` compatibility adapter, while the shipped multi-listener CLI
directly owns its concrete Tokio listeners. The runtime lifecycles remain
isolated rather than pretending to be interchangeable.

## Installation

Freja requires Rust 1.98 or newer. The crates.io package and installed binary
are both named `freja`:

```console
cargo install freja --locked
freja --help
```

To install the same binary directly from a source checkout:

```console
cargo install --path crates/freja --locked
```

All seven Freja crates share one version and are released together.

Version 0.2.0 raises the MSRV to Rust 1.98, makes the built-in local runtime
TUI + Observe + Interactive, writes audit schema version 2, and adds bounded
traffic views, request editing, and HTTP/1.1 Repeat workspaces. Existing
unattended configurations that omit `[runtime]` should explicitly select
Headless + Enforce + Disabled. See the
[changelog](https://github.com/karanabe/freja/blob/master/CHANGELOG.md) for the
complete release changes and upgrade notes.

## Quick start

```console
cargo run -p freja -- check-config
cargo run -p freja
curl --proxy http://127.0.0.1:8080 http://example.com/
```

With no command, Freja uses its built-in defaults and opens one explicit HTTP
proxy on `127.0.0.1:8080`; `freja run` is the explicit equivalent. HTTP
requests pause in the TUI before forwarding; press `c` to continue unchanged,
`e`/`i` to edit, or Shift+`R` to retain an HTTP/1.1 copy on the Repeat page
while continuing the original request.

Multi-listener TUI, headless, and focused enforcement profiles live under
[`examples/config/`](examples/config/).

To exercise the proxy against a local origin, start the bundled test server in
another terminal and force curl to proxy loopback traffic:

```console
cargo run --manifest-path examples/http-test-server/Cargo.toml
curl --noproxy "" --proxy http://127.0.0.1:8080 \
  http://127.0.0.1:3001/get?name=freja
```

See [`examples/http-test-server/`](examples/http-test-server/) for POST, PUT,
PATCH, DELETE, status, redirect, delay, streaming, and fixed-size responses.
It prints each received method, URI, header set, and bounded body preview to its
terminal. This development-only log intentionally includes credential and
cookie header values.

Freja's default runtime profile is local and interactive: `ui = "tui"`,
`enforcement = "observe"`, and `hooks = "interactive"`. CONNECT remains a blind
tunnel and audit capture remains metadata-only. ACL, destination-guard,
inspection, and CONNECT-port deny or detour decisions are recorded but not
executed by default; interactive operator rejection remains effective. The
headless profile explicitly selects `ui = "headless"`,
`enforcement = "enforce"`, and `hooks = "disabled"`. A
non-loopback HTTP or SOCKS5 listener requires both explicit exposure opt-in and
a SHA-256 credential digest; remote static TCP listeners are rejected because
that protocol has no authentication handshake.

The audit `path` can name a new file, which Freja never overwrites, or an
existing directory, where Freja creates a unique JSONL segment per process
start. The supplied example uses the current directory so repeated local runs
do not collide. New segments use owner-only `0600` permissions on Unix. On Unix,
`SIGHUP` atomically reloads policy, inspection, destination guards, and
enforcement mode when `--config` names a file. It is ignored with an
operational warning when built-in defaults are active. Listener,
authentication, limit, TLS, UI/hook, capture, and audit-sink changes require a
restart.

```console
cargo run -p freja -- replay --audit /path/to/segment.jsonl --config candidate.toml \
  --checkpoint-public-key '<64 hex characters>'
```

Replay accepts schema versions 1 and 2 and verifies sequence numbers, the SHA-256
chain, record hashes, and any Ed25519 checkpoints before evaluating recorded
facts and explicitly captured prefixes. Pinning the expected checkpoint public
key is optional but required for authenticity rather than self-consistency
alone.

## TUI inspection and request editing

The default runtime profile enables local interactive inspection:

```toml
[runtime]
ui = "tui"
enforcement = "observe"
hooks = "interactive"
```

The TUI correlates HTTP transactions and TCP sessions in a bounded Traffic
page, with findings, decision traces, operational logs, and counters on a
Diagnostics page. A third Repeat page retains bounded HTTP/1.1 request drafts
and each workspace's latest result. Pretty, Raw, and Hex views are available; exact Raw/Hex HTTP
bytes currently cover bounded ingress for plain explicit HTTP/1, while
intercepted HTTP/1.1 and HTTP/2 use semantic Pretty views.

Interactive mode pauses one bounded HTTP request before upstream forwarding.
The modal editor can atomically change textual HTTP/1.1 end-to-end headers and
a UTF-8 body, then submits a typed mutation plan for data-plane validation and
framing reconstruction. Method, target, version, `Host`, hop-by-hop headers,
and framing fields remain read-only. Responses and TCP traffic are observable
but never wait for an operator.

Repeat supports plain explicit and intercepted HTTP/1.1 requests, excluding
CONNECT and HTTP/2. Sending a draft creates a fresh flow, skips a second
interactive pause, and re-runs current destination checks, ACLs, inspection,
typed hooks, TLS authentication when applicable, and audit publication.

TUI payloads are intentionally unredacted and may contain secrets or personal
data. Use the interface only on a trusted local terminal. Audit redaction and
capture settings remain independent. See [TUI and typed
hooks](https://github.com/karanabe/freja/blob/master/docs/src/content/docs/guides/tui-and-hooks.md)
for controls, limits, and supported editor input.

## Workspace

- `freja-domain`: validated identifiers, endpoints, facts, findings, decisions,
  listener specifications, and independent runtime modes.
- `freja-config`: typed `RawConfig -> ValidatedConfig -> CompiledConfig`.
- `freja-policy`: ordered ACLs, destination guards, inspection, and typed hooks.
- `freja-audit`: redacted, versioned, hash-chained JSONL and signed checkpoints.
- `freja-proxy`: HTTP, CONNECT/TLS, TCP, SOCKS5, metrics, and runtime adapters.
- `freja-ui`: immutable UI events and bounded interactive TUI decisions.
- `freja`: bootstrap, replay, reload, signals, and application error boundary.

The Astro documentation site lives in
[`docs/`](https://github.com/karanabe/freja/blob/master/docs/README.md). Start
with the [operator quick
start](https://github.com/karanabe/freja/blob/master/docs/src/content/docs/guides/getting-started.md),
then use the [configuration
reference](https://github.com/karanabe/freja/blob/master/docs/src/content/docs/reference/configuration.md),
[architecture](https://github.com/karanabe/freja/blob/master/docs/src/content/docs/developer/architecture.md),
[threat
model](https://github.com/karanabe/freja/blob/master/docs/src/content/docs/developer/threat-model.md),
and [typed hook
design](https://github.com/karanabe/freja/blob/master/docs/src/content/docs/developer/hooks.md).
Matching Japanese pages live under `docs/src/content/docs/ja/`.

## Development gates

```console
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo check --manifest-path fuzz/Cargo.toml --bins
(cd docs && pnpm check)
```

### License

<sup>
Licensed under either of <a href="https://github.com/karanabe/freja/blob/master/LICENSE-APACHE">Apache License, Version 2.0</a> or <a href="https://github.com/karanabe/freja/blob/master/LICENSE-MIT">MIT license</a> at your option.
</sup>

<br>

<sub>
Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
</sub>
