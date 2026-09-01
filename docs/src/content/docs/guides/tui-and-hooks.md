---
title: TUI and typed hooks
description: Observe flows in ratatui and understand automatic or interactive hook behavior.
publishedAt: 2026-08-31
updatedAt: 2026-09-01
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
hooks = "disabled"
```

Run Freja in a real terminal. The UI shows flows, HTTP metadata, bounded
hex/ASCII prefixes, findings, decision traces, operational logs, and counters.
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
| `disabled` | Default; no registered hook is called |
| `automatic` | Executes registered in-process hooks with a timeout |
| `interactive` | Pauses bounded stages for a TUI decision |

Interactive mode requires `ui = "tui"`; invalid combinations fail during
configuration compilation.

Freja defines six stages: HTTP request head/body, HTTP response head/body, and
TCP chunks in both directions. HTTP hooks return typed header or decoded-body
mutation plans. Hop-by-hop header changes are rejected, and the HTTP engine
reconstructs framing and `Content-Length` after a body replacement. Hooks never
write arbitrary HTTP wire bytes.

:::note
The shipped CLI currently registers an empty automatic hook registry. Automatic
mode is useful to applications embedding the Freja crates and supplying
in-process hooks; configuration alone does not load hook code.
:::

## Interactive controls

When a request is paused, the TUI supports:

| Key | Action |
| --- | --- |
| `c` | Continue unchanged |
| `r` | Reject before protocol commitment |
| `e` | Enter a bounded `name:value` header replacement |
| `b` | Enter a bounded replacement body |
| `x` | Cancel the pending modification |
| Enter | Submit editor input |
| Esc | Close the editor or UI |

Manual header input is capped at 8 KiB and body input at 4 KiB. The bounded
queue, `limits.paused_flows`, and `limits.interception_timeout_ms` prevent
indefinite accumulation. The CLI uses fail-closed behavior on timeout.

After a successful CONNECT response the connection is a tunnel, so an HTTP
reject or redirect cannot be injected. TCP rejection closes the flow. Manual
actions are audited without storing the edited content.

Developer-facing contracts are documented in [Typed hook design](/developer/hooks/).
