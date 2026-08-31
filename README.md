# Freja

Freja is a local-first, explainable L4/L7 inspection proxy written in Rust. It
provides HTTP/1.1 explicit forward proxying, CONNECT tunnels, opt-in TLS
interception, static TCP forwarding, SOCKS5 CONNECT, deterministic ACLs,
streaming inspection, typed hooks, a ratatui interface, tamper-evident audit
segments, and offline policy replay.

The seven-crate workspace keeps domain, configuration, policy, inspection,
audit, hooks, and UI independent of Pingora. Hyper 1.x owns HTTP/1 parsing and
intercepted HTTP/2 framing. An opt-in `pingora-adapter` feature provides a small
Pingora 0.8.1 `ServerApp` adapter, while the shipped multi-listener CLI uses the
replaceable Tokio listener adapter.

## Quick start

```console
cargo run -p freja-cli -- check-config --config examples/freja.toml
cargo run -p freja-cli -- run --config examples/freja.toml
curl --proxy http://127.0.0.1:8080 http://example.com/
```

The example also opens a loopback SOCKS5 listener on port 1080 and a static TCP
listener on port 9000. Edit or remove listeners that are not needed.

Freja is conservative by default: listeners bind to loopback, enforcement is
observe-only unless configured, CONNECT is a blind tunnel, payload capture and
hooks are disabled, and sensitive destination classes are protected. A
non-loopback HTTP or SOCKS5 listener requires both explicit exposure opt-in and
a SHA-256 credential digest; remote static TCP listeners are rejected because
that protocol has no authentication handshake.

The audit `path` can name a new file, which Freja never overwrites, or an
existing directory, where Freja creates a unique JSONL segment per process
start. The supplied example uses the current directory so repeated local runs
do not collide. New segments use owner-only `0600` permissions on Unix. On Unix,
`SIGHUP` atomically reloads policy, inspection, destination guards, and
enforcement mode. Listener, authentication, limit, TLS, UI/hook, capture, and
audit-sink changes require a restart.

```console
cargo run -p freja-cli -- replay --audit /path/to/segment.jsonl --config candidate.toml \
  --checkpoint-public-key '<64 hex characters>'
```

Replay accepts schema version 1 and verifies sequence numbers, the SHA-256
chain, record hashes, and any Ed25519 checkpoints before evaluating recorded
facts and explicitly captured prefixes. Pinning the expected checkpoint public
key is optional but required for authenticity rather than self-consistency
alone.

## Workspace

- `freja-domain`: validated identifiers, endpoints, facts, findings, decisions,
  listener specifications, and independent runtime modes.
- `freja-config`: typed `RawConfig -> ValidatedConfig -> CompiledConfig`.
- `freja-policy`: ordered ACLs, destination guards, inspection, and typed hooks.
- `freja-audit`: redacted, versioned, hash-chained JSONL and signed checkpoints.
- `freja-proxy`: HTTP, CONNECT/TLS, TCP, SOCKS5, metrics, and runtime adapters.
- `freja-ui`: immutable UI events and bounded interactive TUI decisions.
- `freja-cli`: bootstrap, replay, reload, signals, and application error boundary.

The Astro documentation site lives in [`docs/`](docs/README.md). Start with the
[operator quick start](docs/src/content/docs/guides/getting-started.md), then use
the [configuration reference](docs/src/content/docs/reference/configuration.md),
[architecture](docs/src/content/docs/developer/architecture.md), [threat
model](docs/src/content/docs/developer/threat-model.md), and [typed hook
design](docs/src/content/docs/developer/hooks.md). Matching Japanese pages live
under `docs/src/content/docs/ja/`.

## Development gates

```console
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo check --manifest-path fuzz/Cargo.toml --bins
(cd docs && pnpm check)
```

## License

Freja is licensed under either the [Apache License 2.0](LICENSE-APACHE) or the
[MIT license](LICENSE-MIT), at your option. Contributions are submitted under
the same dual-license terms unless explicitly stated otherwise.
