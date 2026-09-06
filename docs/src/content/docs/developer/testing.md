---
title: Development and testing
description: Workspace layout, validation gates, integration tests, fuzz targets, and documentation workflow.
publishedAt: 2026-08-31
updatedAt: 2026-09-06
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
cargo check --manifest-path fuzz/Cargo.toml --bins
(cd docs && pnpm check)
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
  semantic intercepted HTTP/1.1/HTTP/2 forwarding, repeat HTTP/1.1 cleartext/TLS
  execution with fresh correlation IDs and no second pause, pinning failure, and exact
  TUI-only plain HTTP/1 request/response ingress capture.
- `tcp_static.rs` and `socks_forward.rs` cover relay, DNS reauthorization,
  detours, limits, inspection, and authentication.
- CLI tests cover configuration behavior, no-overwrite audit segments, and
  replay with pinned checkpoints. A Cargo-metadata integration test also locks
  the allowed workspace dependency direction and Pingora isolation boundary.
- UI tests render split and side-wide traffic plus diagnostics pages to
  ratatui's test backend, exercise pane/exit/editor/repeat key states, validate typed
  request drafts, and verify non-blocking saturation and terminal-control
  escaping. Diagnostics tests cover request/evidence correlation for repeated
  URLs, multiple evaluations, missing/late/evicted metadata, CONNECT, partial
  targets, and long Unicode targets at minimum size and in expanded views.
  They also verify that request context remains visible while evidence scrolls
  and that TCP session correlation is preserved. Per-evaluation IPv4/IPv6 targets
  remain paired with their results through bounded retention; older UI events
  without target facts display an explicit unavailable state.
  Local CONNECT integration tests compare observer targets with the recorded
  facts actually evaluated by policy. HTTP body inspection tests verify that
  the selected connection accompanies its decision without enabling capture.
  The HTTP integration suite verifies atomic manual header/body
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

## Browser form fixture

The [HTTP/1.1 browser form lab](../../use-cases/browser-form-lab/) documents the
interactive profile, loopback proxy setup, entry-page pauses and manual evidence
to collect. `/lab` is a static same-origin page in the standalone example;
existing JSON and curl routes remain available.

The example is outside the seven-crate workspace and needs its own gates:

```sh
cargo fmt --manifest-path examples/http-test-server/Cargo.toml -- --check
cargo clippy --manifest-path examples/http-test-server/Cargo.toml --all-targets --all-features -- -D warnings
cargo test --manifest-path examples/http-test-server/Cargo.toml --all-features
```

`tests/browser_form.rs` exercises local HTTP contracts, strict bounded form
interpretation, malformed edited bytes, header/display limits and JSON route
compatibility. `tests/freja_form.rs` starts Freja against a local origin and uses
the existing typed broker to continue, edit and reject requests, expire a pause,
and run a Repeat with new transaction provenance. It checks HTTP request arrival
separately from opening an upstream TCP connection, and includes direct-access
and stopped-origin controls. It does not drive TUI keys.

With Node.js 22+ and pnpm 11+, run the browser tests:

```sh
cd examples/http-test-server
pnpm install --frozen-lockfile
pnpm exec playwright install chromium
pnpm test:browser
```

Install Chromium's required host libraries when prompted. `tests/browser.mjs`
starts a disposable local origin and checks GET/POST encoding, empty/Unicode
input, UTF-8 limits, preserved re-entry, keyboard submission, safe text output,
narrow layouts in both color modes, errors, pending/timeout state and response
bounds. Browser error/delay fixtures are controlled simulations, separate from
the Rust tests of actual Freja behavior. Neither is evidence of a maintainer
completing the browser-plus-TUI workflow. Record revision, browser/OS and proxy
setup, HTTP/1.1 and transaction correlation, origin arrivals and confusing steps
for manual cases; mark any unperformed observation explicitly.

## Browser lab visuals

The [first GET page](../../use-cases/browser-form-lab/first-get/) in both locales shares `/images/browser-form-lab/get-ready.png`, stored under
`docs/public/` and copied unchanged into the static site. Regenerate it from the
real embedded `/lab` page after changing its controls or layout. With the pinned
example Playwright dependency, Chromium and host libraries installed as above,
run these commands **from the repository root**:

```sh
cargo build --manifest-path examples/http-test-server/Cargo.toml
node docs/scripts/capture-browser-form-lab.mjs
(cd docs && pnpm check)
```

The script starts and stops its own loopback origin on an ephemeral port. It uses
a fresh Chromium context at 1100×2400 CSS pixels, device scale 1, `en-US`, light
color scheme and reduced motion. It selects GET, fills case `get-01` and message
`hello origin`, then moves keyboard focus to Send without submitting. It checks
the prepared encoding and unsent state, waits for fonts, and crops the actual
input/result sections. It does not alter the DOM or draw fictional controls;
the B1–B7 guide legend explains the real controls. No address bar, machine-specific
origin port, headers, credentials or real traffic appear in the image.

The reference capture used Linux and Chromium 153.0.8010.12 (Playwright's pinned
build 1243). OS fonts/native controls can change the pixels; review the regenerated
image, button focus and synthetic text rather than treating a hash as a portable
visual test. Keep both locales' alt text, caption and legend synchronized. This
unsent origin screenshot does not establish traversal through Freja.

The TUI ASCII map is a representative Traffic/Pretty/Split view, with empty rows
omitted and T1–T4 documentation annotations. Check it against
`crates/freja-ui/src/tui/render.rs` and the current key handling when updating it;
confirm with a local paused `/lab` request, focus Flows with `1`, select the row
and check Request/Response titles. Width and data affect wrapping and hints.
Do not turn documentation annotations into alleged UI labels or use a terminal
recording containing real traffic. Full browser-plus-TUI observation remains a
separate manual check.

## Fuzz targets

The nested `fuzz` workspace wires production parsers and state machines into
five targets, plus the development origin's bounded application form decoder:

```sh
cargo check --manifest-path fuzz/Cargo.toml --bins
```

Targets cover configuration parsing, target parsing, HTTP mutation plans,
binary scanning, and malformed/ambiguous HTTP framing. The framing target also
drives the private capture-only HTTP/1 message-boundary state machine.
`browser_form` drives the exact lab form decoder through the example's `fuzzing`
feature with at most 2 KiB input; it does not parse HTTP wire framing. Building
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
pnpm check
```

Update both locale paths in one change. Treat code, sample configuration,
packaging, and integration tests as authoritative when a page disagrees.

## Rule inspection lab

Use synthetic traffic with `examples/config/tui/freja.rules.toml`. It selects
Observe, disables interactive hooks, and retains eight rows. Start the bundled
origin in one terminal, then build Freja and run a disposable copy of the
configuration in another:

```sh
cargo run --manifest-path examples/http-test-server/Cargo.toml
```

```sh
cargo build -p freja
cp examples/config/tui/freja.rules.toml /tmp/freja-rules.toml
./target/debug/freja run --config /tmp/freja-rules.toml
```

From a third terminal, send these harmless requests through the proxy:

```sh
curl --noproxy "" -x http://127.0.0.1:8080 http://127.0.0.1:3001/get
curl --noproxy "" -x http://127.0.0.1:8080 http://127.0.0.1:3001/get
curl --noproxy "" -x http://127.0.0.1:8080 http://127.0.0.1:3001/healthz
curl --noproxy "" -x http://127.0.0.1:8080 http://127.0.0.1:3001/post --data freja-deny
curl --noproxy "" -x http://127.0.0.1:8080 --proxytunnel http://127.0.0.1:3001/healthz
```

Expected evidence: the two GET requests have different TransactionIds and a
`lab-compound` ACL denial, although Observe permits the origin's 200 response.
Its definition includes GET, ports 3000–3010 inclusive, both `/get` and
`/anything/private`, and NOT an `x-lab-bypass` header containing `yes`.
`/healthz` shows the two configured ACL rules and default allow, with no match
at the HTTP request stage; its earlier destination evaluations mark HTTP
conditions unavailable. Compare with a disposable configuration that removes both `[[policy.rules]]`
blocks and sets `rules = []` under `[policy]`: the detail explicitly reports
zero configured rules. POST has `lab-post` and
`lab-body-deny` inspection evaluations. The proxytunnel request shows the
built-in CONNECT restriction (allowed ports: 443); in Observe its denial is not
a block. For a destination guard example, start a fresh copy with
`loopback_destinations = "protect"` and `enforcement = "enforce"`; a loopback
request is rejected without contacting another host. Restore the lab settings
for the remaining checks.

Ask the operator to select an access on Traffic, enter Diagnostics with `2`,
select evaluations with `j/k`, and explain the conditions, action, recorded
reason, and generation from Enter's rule detail. Repeat with `z` expansion and
both Enter and `q` for closing. Record whether returning preserves the selected
evaluation and reading position. Keep another request arriving while the detail
is open and confirm its identity stays fixed.

For a Unix reload, keep generation 101's detail open. In the disposable config,
change generation to 102, change only `lab-compound`'s action to `allow`, and
replace its second path branch with `/anything/reloaded`. Send SIGHUP to the PID
of this lab's Freja process, then send the same `/get` request. Verify the old
detail still shows generation 101, deny, and `/anything/private`, while the new
transaction shows generation 102, allow, and `/anything/reloaded`. Do not infer a
scanner's generation from the latest global policy.

To exercise row eviction, keep a detail open and send ten additional sequential
requests (each curl process closes its connection). The lab's eight-row limit
can remove the original access. The frozen detail explains eviction; closing
must not silently select another evaluation. Return through Traffic to select a
retained access. Long definitions, per-row eviction, missing serialized
definitions, and continuous scanner reload are covered by deterministic fixtures
where a manual reproduction is impractical; record them as fixture evidence,
not observed usability.

Automated evidence is in `freja-policy/src/evidence/tests.rs`,
`freja-ui/src/tui/evidence_tests.rs`, and the proxy's HTTP Diagnostics integration
suite. These check empty versus configured ACL defaults, actual unavailable and
false expression results, first-match skips, configuration retained across
reload, complete compound definitions, source collisions, bounds and
escaping, modal navigation, same-URL correlation, old scanners across reload,
and continued forwarding with an unread bounded UI queue. Passing tests does
not establish the operator outcome. For each observed case, record the rule and
generation, external-config screen round trips, wrong selections, confusing
open/close operations, missing information, and whether the operator completed
the explanation. Mark unperformed cases **not observed**. Use no real
credentials or payloads and do not save additional traffic content.
