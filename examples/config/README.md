# Freja configuration examples

These standalone configurations make the main runtime combinations easy to
exercise from the repository root. They intentionally reuse the same loopback
ports, so run only one Freja configuration at a time.

| Configuration | Purpose | Listeners |
| --- | --- | --- |
| `headless/freja.toml` | Enforce policy without a terminal UI or interactive hooks | HTTP `8080`, SOCKS5 `1080`, static TCP `9000` |
| `headless/freja.enforce.toml` | Enforce a bounded preflight body detector | HTTP `8080` |
| `tui/freja.toml` | Multi-listener interactive TUI profile; enforce policy and pause HTTP requests for a decision or edit | HTTP `8080`, SOCKS5 `1080`, static TCP `9000` |
| `tui/freja.rules.toml` | Synthetic rule inspection lab: Observe, disabled hooks, compound ACL and body detector | HTTP `8080` |
| `tui/freja.interactive.toml` | Focused HTTP-only interactive profile with smaller bounds and preflight inspection | HTTP `8080` |

Validate and run any configuration by path:

```console
cargo run -p freja -- check-config --config examples/config/tui/freja.toml
cargo run -p freja -- run --config examples/config/tui/freja.toml

cargo run -p freja -- check-config --config examples/config/headless/freja.toml
cargo run -p freja -- run --config examples/config/headless/freja.toml
```

TUI profiles must run in a real terminal. Except for the rule inspection lab,
they pause each bounded HTTP request
before forwarding; use `c` to continue, `r` to reject, or `e`/`i` to open the
request editor. The headless profile also enforces ACL and inspection decisions
but disables hooks. The focused headless enforcement profile adds a preflight
body detector for an immediately testable blocking scenario.

## Test with the local HTTP origin

Start the bundled origin in another terminal:

```console
cargo run --manifest-path examples/http-test-server/Cargo.toml
```

Then force curl to use the loopback proxy:

```console
curl --noproxy "" --proxy http://127.0.0.1:8080 \
  http://127.0.0.1:3001/get?name=freja
```

With `headless/freja.enforce.toml`, an ordinary body is forwarded but the
`freja-deny` marker receives a 403 before its body is released upstream:

```console
curl --noproxy "" --proxy http://127.0.0.1:8080 \
  http://127.0.0.1:3001/post --data 'allowed'
curl --noproxy "" --proxy http://127.0.0.1:8080 \
  http://127.0.0.1:3001/post --data 'contains freja-deny marker'
```

Every example explicitly allows loopback destinations for this local workflow.
That setting weakens SSRF protection and should be removed from deployments
that do not need local upstream access. Payload audit capture remains
metadata-only; live TUI payloads are intentionally unredacted and should be
viewed only on a trusted local terminal.

## Rule inspection lab

`examples/config/tui/freja.rules.toml` uses Observe with hooks disabled so that
rule browsing can be observed while traffic continues. It retains eight rows.
The synthetic compound rule combines GET, ports 3000–3010, either `/get` or
`/anything/private`, and absence of an `x-lab-bypass` value containing `yes`.
Its configured deny is observable even when the origin returns 200. POST has a
separate allow rule; the body marker `freja-deny` selects an inspection deny.

Use Diagnostics `j/k` to select a decision, Enter to inspect the rule, Enter/q
to return, and `z` to expand the evidence pane. The bilingual documentation's
Development and testing page contains the reload and operator-observation steps.
