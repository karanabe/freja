# ADR 0006: TUI-only HTTP/1 Wire Capture

Status: Accepted

TUI bootstrap may install a bounded, non-blocking observer around plain
explicit HTTP/1 ingress streams. Hyper remains authoritative for parsing and
forwarding. A private capture-only framer delimits exact request and response
bytes for Raw/Hex presentation; its failure can only produce a best-effort UI
diagnostic. No `http_wire` dependency or public general-purpose parser API is
introduced.

Detailed record:
[`../src/content/docs/developer/adr/0006-tui-http-wire-capture.md`](../src/content/docs/developer/adr/0006-tui-http-wire-capture.md).
