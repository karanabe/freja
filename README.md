<p align="center">
  <img src="https://raw.githubusercontent.com/karanabe/freja/master/docs/src/assets/FrejaLogo.png" alt="Freja" width="520" />
</p>

<h1 align="center">Freja</h1>
<p align="center">A local-first, explainable L4/L7 inspection proxy written in Rust.</p>

Freja gives you a local traffic monitor with explainable policy decisions,
bounded inspection, interactive HTTP controls, privacy-aware audit records,
and offline replay. It supports HTTP/1.1 forward proxying, CONNECT tunnels,
opt-in TLS interception, static TCP forwarding, and SOCKS5 CONNECT.

Running `freja` without arguments opens the TUI monitor and starts a
loopback-only HTTP proxy on `127.0.0.1:8080`. No configuration file is needed
for this local interactive mode.

## Quick start

Freja requires Rust 1.98 or newer.

```console
cargo install freja --locked
freja
```

In another terminal, send an HTTP request through Freja:

```console
curl --proxy http://127.0.0.1:8080 http://example.com/
```

The request appears in the TUI and waits for a decision. Press `c` to continue,
`r` to reject, or `e`/`i` to edit a supported HTTP/1.1 request. Press Ctrl+C to
stop Freja.

The built-in profile is designed for local inspection: the listener is
loopback-only, policy enforcement is observe-only, HTTP decisions are
interactive, and HTTPS remains end-to-end through a blind CONNECT tunnel.
Use an explicit configuration when you need enforcement, additional listeners,
or TLS interception.

From a source checkout, start the same default mode with:

```console
cargo run -p freja
```

## Configuration

Complete local TUI, headless, and focused enforcement profiles are available
in [`examples/config/`](examples/config/).

```console
freja check-config --config ./freja.toml
freja run --config ./freja.toml
```

Validate a configuration before opening its listeners. Remote exposure, TLS
interception, and payload capture are explicit opt-ins; review their safety
requirements in the documentation before enabling them.

## Documentation

- [Getting started](docs/src/content/docs/guides/getting-started.md)
- [Use cases](docs/src/content/docs/use-cases/index.md)
- [Configuration reference](docs/src/content/docs/reference/configuration.md)
  and [CLI reference](docs/src/content/docs/reference/cli.md)
- [Architecture](docs/src/content/docs/developer/architecture.md),
  [threat model](docs/src/content/docs/developer/threat-model.md), and
  [testing](docs/src/content/docs/developer/testing.md)
- [Documentation site workflow](docs/README.md)

### License

<sup>
Licensed under either of <a href="LICENSE-APACHE">Apache License, Version 2.0</a> or <a href="LICENSE-MIT">MIT license</a> at your option.
</sup>

<br>

<sub>
Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
</sub>
