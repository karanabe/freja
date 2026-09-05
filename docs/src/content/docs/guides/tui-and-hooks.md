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
enforcement = "observe"
hooks = "interactive"
```

The built-in interactive profile can be started directly:

```sh
cargo run -p freja
```

`examples/config/tui/freja.toml` explicitly enables enforcement for a
multi-listener TUI profile. `examples/config/tui/freja.interactive.toml` is a
focused HTTP-only enforcement variant with smaller bounds and preflight
inspection. Run only one example profile at a time because they share listener
ports.

Run Freja in a real terminal. Traffic content in this view is intentionally
unredacted and may contain credentials, cookies, query secrets, or personal
data. Use it only on a trusted local terminal; audit redaction is unchanged.

The TUI has three pages:

- **1 Traffic** uses the top 25% for a full-width Flows list. The remaining
  area defaults to 50% Request/Client-to-Upstream and 50%
  Response/Upstream-to-Client details. One HTTP row represents a
  `TransactionId`; one TCP row represents a `SessionId`.
- **2 Diagnostics** uses its upper 45% for Findings and DecisionTrace, the
  flexible middle area for Operational logs, and the final eight rows for
  Statistics.
- **3 Repeat** uses the top 25% for retained HTTP/1.1 workspaces and splits the
  remaining area between the editable request and latest response or failure.

In Diagnostics, the Findings / DecisionTrace pane keeps the selected HTTP
transaction ID and observed request line above its scrolling evaluation rows.
Use the full transaction ID to distinguish repeated requests to the same URL.
The request summary uses at most two rows, or six when the pane is expanded
with `z`; `... [shortened]` marks omitted display text. Expansion can reveal
more of a long target while leaving the evaluation rows scrollable.

Each decision row also shows the connection facts for that evaluation:
`source IP -> requested host:port / evaluated=IP:port`. Before DNS,
`evaluated=unresolved` identifies a requested-destination check. DNS candidate
checks retain their individual IPs; HTTP body and CONNECT tunnel inspection
retain the selected connection's IP. These facts travel with the evaluation
result, so a later address or request cannot replace an earlier row's target.
An evaluated address is not proof of an established connection. Missing
evaluation facts are marked `connection: unavailable`.

CONNECT shows its observed method and authority, without an inferred URL inside
the tunnel. For origin-form or `*` targets, the summary labels the same
transaction's observed Host header separately. Missing request metadata or Host
headers are marked unavailable; session targets and other requests never fill
those gaps. Context uses bounded snapshots with terminal controls escaped and
adds no payload capture or persistence. Each Finding and DecisionTrace remains
a separate evaluation row; an Allow decision does not establish communication
success or safety.

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
configuration compilation. Continue, reject, and edit decisions remain
effective in observe mode because enforcement controls policy actions rather
than the operator response.

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


## Inspect the rule used by an evaluation

Select a transaction or TCP session in Traffic, then press `2`. In Findings /
DecisionTrace, `j`/`k` selects the next/previous **Decision**, highlighted with
`>`. `Enter` opens its read-only rule detail. Findings are observations, not
selectable decisions, even when a detector ID looks like a rule ID. Use `z` to
expand this pane; arrows and PageUp/PageDown keep evidence scrollable. Inside
rule detail, `j`/`k`, arrows, and PageUp/PageDown scroll; Home returns to the top.
`Enter` or `q` closes only the detail and returns to the previous selection and
scroll position, including when the evidence pane was expanded.

The detail identifies the transaction/session, evaluation, decision generation,
and stage. ACL details begin with the configuration used by that evaluation:
rule count, declaration order, default action, and the inputs available at that
stage. An empty ACL explicitly says that no rules were configured. Otherwise,
the view counts actual nonmatches, expressions unavailable at this stage, and
rules skipped after the first match. The ordered definitions pair each rule's
ID, conditions and action with that result. For example, a CONNECT
`ResolvedDestination` evaluation has the resolved IP but no HTTP method, path
or header inputs; a path rule is unavailable there, not evidence of a safe path.
Destination guards and payload inspection are separate checks, so an empty ACL
does not mean all protections are disabled.

The detail separates configured conditions and actions from recorded match
reasons and the policy's action category. An ACL condition is
shown as its JSON expression, including every `all`/`any` branch, `not`, inclusive
port range, hostname match kind, and header substring. A detour action includes
its destination. Results describe the whole expression as actually evaluated;
they do not identify every failed leaf or evaluate rules skipped by first-match.
Inspection definitions include the selected
pattern policy, decimal byte signature, and directions. Built-in destination
protection and CONNECT port restrictions have their own provenance; defaults
explicitly have no individual rule. No source file line or original TOML is
invented.

Enforcement mode is retained from the decision snapshot. In Observe, a policy
deny does not mean traffic was blocked. The evaluation alone does not prove the
communication outcome, and streaming cannot retract bytes already forwarded.

Diagnostics keeps its chosen access while new traffic arrives; choose another
row on Traffic to change it. Opening a detail freezes one evaluation, not the
network. Its original definition survives a same-ID reload, including a scanner
that began before reload. If the evaluation is evicted, the detail says so and
closing leaves the selection missing; `j`/`k` explicitly chooses a retained
entry. Re-enter Diagnostics from Traffic to choose another access. Missing
historical definitions stay unavailable and are never filled with a current
same-ID rule.

Definitions are sensitive, local, ephemeral data. Each conditions/action field
retains at most 16 KiB; incomplete fields display a warning before their retained
prefix. ACL context additionally retains its default action and up to the first
64 rule declarations, with the entire declaration list capped at 16 KiB. Counts
still cover the whole policy, and the selected rule's definition is retained
separately even when it lies outside that prefix. Both rule and byte omissions
are explicit. Recorded reasons retain at most 64 entries and 1 KiB per criterion/value;
the detail marks omissions. Its copied request context retains 16 KiB and marks
shortening. Existing per-row and row-count limits bound history, with only one
additional open detail. Terminal controls are escaped. Definitions are excluded
from serialized UI events and audit records; audit/replay schemas, capture,
hooks, and forwarding behavior are unchanged.

Use the [local rule inspection lab](../../developer/testing/#rule-inspection-lab)
for synthetic examples and operator observation.

## Navigation and interactive controls

| Key | Action |
| --- | --- |
| `1` / `2` / `3` | Select Traffic / Diagnostics / Repeat |
| `v` | Cycle split / request-wide / response-wide detail |
| `m` | Cycle Pretty / Raw / Hex |
| `h` / `l` | Select request/client or response/upstream side |
| Ctrl+`j` / Ctrl+`k`, Tab | Move focus between panes; Repeat cycles workspace, request, and latest result |
| `j` / `k` | Select a flow/workspace, select a Diagnostics decision, or scroll a detail |
| arrows | Scroll Diagnostics evidence or a detail; select a flow/workspace |
| PageDown / PageUp | Scroll by ten rows |
| Enter | Open the selected Diagnostics decision's rule; otherwise expand the focused pane |
| `z` in Findings / DecisionTrace | Expand the evidence pane |
| Enter / `q` in rule detail | Close only the rule detail, preserving selection, scroll, and pane expansion |
| `q` | Close the floating pane view and return |
| Ctrl+C / `Q` | Quit and restore the terminal |

When a request is paused, the TUI supports:

| Key | Action |
| --- | --- |
| `c` | Continue unchanged |
| `r` | Reject before protocol commitment |
| `e` | Open the HTTP/1.1 request editor in Normal mode |
| `i` | Open the HTTP/1.1 request editor in Insert mode |
| `x` | Cancel the pending modification |
| Shift+`R` | Continue the original unchanged and retain a copy on Repeat |

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

## Repeat workspaces

Shift+`R` is available only for a currently paused, textual HTTP/1.1 request
with an absolute `http` or `https` target. It creates a bounded independent
draft and immediately continues the original request unchanged. CONNECT and
HTTP/2 cannot enter repeat mode. HTTPS drafts are limited to hostnames already
enabled by the TLS interception allowlist; IP literals remain excluded.

Repeat workspaces remain available when `q`, `1`, or `2` returns to another
page. `ui_retained_rows` caps their count; Freja does not silently evict a
draft. Each workspace allows one in-flight attempt and retains only its latest
result. Use `j`/`k` or arrows to select a workspace. Ctrl+`j` / Ctrl+`k` or Tab
moves focus through the workspace list, editable request, and latest result;
after focusing either detail pane, `j`/`k`, arrows, and PageDown/PageUp scroll
it. Use `e`/`i` to edit and send, `s` to resend the saved draft, and `d` to
delete a workspace that is not in flight. `q` returns to the page that opened
Repeat without deleting drafts.

Every send creates fresh `SessionId` and `TransactionId` values. It preserves
the original client IP for policy facts, strips proxy credentials, regenerates
`Host` and framing, and re-runs current requested/resolved destination checks,
HTTP request and response ACLs, inspection, typed hooks, authenticated upstream
TLS, audit, and replay-fact publication. It deliberately bypasses only the
interactive broker, so a repeat never pauses itself. Proxy-listener
authentication is not repeated because the attempt originates inside the
local TUI. Response bodies are fully drained but only `ui_content_bytes` are
retained, and Raw/Hex report unavailable because repeat results are semantic
snapshots rather than ingress wire captures.

After a successful CONNECT response the connection is a tunnel, so an HTTP
reject or redirect cannot be injected. Manual actions are audited without
storing the edited content.

Developer-facing contracts are documented in [Typed hook design](/developer/hooks/).
