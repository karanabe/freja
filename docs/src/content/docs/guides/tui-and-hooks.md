---
title: TUI and typed hooks
description: Observe flows in ratatui and understand automatic or interactive hook behavior.
publishedAt: 2026-08-31
updatedAt: 2026-09-03
tags:
  - tui
  - hooks
  - interception
sidebar:
  order: 5
---

The TUI is a presentation mode, not an enforcement mode. It consumes immutable
bounded snapshots and never owns live network sessions.

## Enable the TUI

```toml
[runtime]
ui = "tui"
enforcement = "enforce"
hooks = "interactive"
```

The repository's default interactive profile can be started directly:

```sh
cargo run -p freja -- run --config examples/config/tui/freja.toml
```

`examples/config/tui/freja.interactive.toml` is a focused HTTP-only variant
with smaller bounds and preflight inspection. Run only one example profile at
a time because they share listener ports.

Run Freja in a real terminal. Traffic content in this view is intentionally
unredacted and may contain credentials, cookies, query secrets, or personal
data. Use it only on a trusted local terminal; audit redaction is unchanged.

The TUI has two pages:

- **1 Traffic** uses the top 25% for a full-width Flows list. The remaining
  area defaults to 50% Request/Client-to-Upstream and 50%
  Response/Upstream-to-Client details. One HTTP row represents a
  `TransactionId`; one TCP row represents a `SessionId`.
- **2 Diagnostics** uses its upper 45% for Findings and DecisionTrace, the
  flexible middle area for Operational logs, and the final eight rows for
  Statistics.

HTTP Pretty mode renders the parsed request/status line, headers, and bounded
body with terminal wrapping. JSON bodies are indented when valid. Raw displays
the exact retained ingress HTTP/1 bytes with terminal control bytes escaped;
Hex displays the same bytes with offsets and ASCII. Exact HTTP Raw is currently
available for plain explicit HTTP/1 forwarding. Local synthetic responses,
intercepted HTTP/1, and HTTP/2 expose the semantic Pretty view but explicitly
report Raw as unavailable. TCP Raw/Hex use bounded observed stream snapshots,
not an HTTP message capture.

Raw capture is a TUI-only, best-effort observer. It is not installed in
headless mode, cannot delay forwarding, and uses Hyper's accepted request as
the authoritative protocol result. Capture failure or truncation is shown in
Statistics instead of changing the network outcome.

Operational `tracing` lines use the same bounded presentation channel instead
of writing into the raw terminal, so they cannot displace the cursor or corrupt
the layout. If the best-effort queue fills, forwarding continues and
`event_sink_dropped_events` increases in the data-plane metrics snapshot.

The terminal is restored by an RAII guard after normal exit, errors, and panic
unwinding. If another process kills Freja without allowing cleanup, run your
shell's terminal reset command.

## Hook modes

| Mode | Behavior |
| --- | --- |
| `disabled` | No registered hook is called; selected by the headless profile |
| `automatic` | Executes registered in-process hooks with a timeout |
| `interactive` | Default; pauses each bounded HTTP request once for a TUI decision |

Interactive mode requires `ui = "tui"`; invalid combinations fail during
configuration compilation.

Automatic hooks retain six typed stages: HTTP request head/body, HTTP response
head/body, and TCP chunks in both directions. HTTP hooks return typed header or
decoded-body mutation plans. Hop-by-hop header changes are rejected, and the
HTTP engine reconstructs framing and `Content-Length` after a body replacement.
Hooks never write arbitrary HTTP wire bytes.

Interactive control is deliberately narrower. Freja collects an HTTP request
within `limits.body_prefix_bytes`, performs preflight inspection and registered
request mutations, then pauses once before upstream forwarding. Oversized
interactive request bodies receive 413. The response is displayed but never
paused. CONNECT pauses once before commitment with an empty body. TCP remains
observable and continues forwarding without an operator pause; manual TCP drop
or mutation is deferred.

:::note
The shipped CLI currently registers an empty automatic hook registry. Automatic
mode is useful to applications embedding the Freja crates and supplying
in-process hooks; configuration alone does not load hook code.
:::

## Navigation and interactive controls

| Key | Action |
| --- | --- |
| `1` / `2` | Select Traffic / Diagnostics |
| `v` | Cycle split / request-wide / response-wide detail |
| `m` | Cycle Pretty / Raw / Hex |
| `h` / `l` | Select request/client or response/upstream side |
| Ctrl+`j` / Ctrl+`k`, Tab | Move focus between vertical panes |
| `j` / `k`, arrows | Select a flow or scroll the focused pane |
| PageDown / PageUp | Scroll by ten rows |
| Enter | Expand the focused pane into a floating view |
| `q` | Close the floating view and return |
| Ctrl+C / `Q` | Quit and restore the terminal |

When a request is paused, the TUI supports:

| Key | Action |
| --- | --- |
| `c` | Continue unchanged |
| `r` | Reject before protocol commitment |
| `e` | Open the HTTP/1.1 request editor in Normal mode |
| `i` | Open the HTTP/1.1 request editor in Insert mode |
| `x` | Cancel the pending modification |

From Normal mode, use `i` to enter Insert mode, arrows or
`h`/`j`/`k`/`l` in Normal mode to move, and `s` or Ctrl+S to validate and
submit. In Insert mode, Enter inserts a newline and Esc returns to Normal mode;
`q` discards the draft only from Normal mode. Ctrl+C and `Q` still terminate
the application from either mode.

The shipped editor accepts textual HTTP/1.1 requests. It can atomically change
end-to-end headers and a UTF-8 body, including repeated headers and multiline
bodies. Method, request target, version, Host, hop-by-hop fields, and framing
headers remain read-only. Submission is parsed with `httparse`, converted to a
typed mutation plan, and checked against the configured header/body byte limits;
the proxy then reconstructs `Content-Length`. HTTP/2 and non-UTF-8 requests
remain observable but cannot be opened in the text editor.

The bounded queue, `limits.paused_flows`, and
`limits.interception_timeout_ms` prevent indefinite accumulation. The CLI uses
fail-closed behavior on timeout.

After a successful CONNECT response the connection is a tunnel, so an HTTP
reject or redirect cannot be injected. Manual actions are audited without
storing the edited content.

Developer-facing contracts are documented in [Typed hook design](/developer/hooks/).
