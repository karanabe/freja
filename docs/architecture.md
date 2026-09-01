# Architecture

Freja keeps domain facts, policy, inspection, audit, typed hooks, and UI free
of Pingora types. `freja-proxy` owns wire/runtime behavior; Hyper 1.x owns the
HTTP/1 state machine and intercepted HTTP/2 framing; Pingora 0.8.1 is an
optional isolated `ServerApp` compatibility adapter; and the production CLI
owns its concrete Tokio listeners. The different runtime lifecycles are not
forced through a nominal common trait.

The configuration path is `RawConfig -> ValidatedConfig -> CompiledConfig`.
Within `freja-config`, `raw` owns TOML decoding, `validation` owns semantic and
cross-field invariants, and `compiled` freezes policy and inspection programs.
Each connection receives a `SessionId`, each HTTP exchange a `TransactionId`,
and every policy decision carries its `PolicyGeneration` and `DecisionTrace`.
Requested destinations are checked before DNS and every resolved address is
checked again before one is selected.

Data-plane events are split by reliability: the bounded audit publisher uses
an explicit fail-open or fail-closed policy, while a separate non-blocking
data-plane event sink may drop immutable snapshots and increments a drop
metric. The `freja` composition root adapts those runtime facts to the bounded
UI publisher. Payload capture, hooks, remote exposure, and TLS interception are
opt-ins.

In TUI mode, operational tracing is formatted into that bounded UI publisher
and rendered inside the terminal layout. The raw terminal has one owner; the
CLI disconnects the tracing router before joining the terminal thread.
TUI-only `UiCaptureSettings` additionally install bounded, non-blocking ingress
observers for exact plain HTTP/1 Raw display. Hyper remains the authoritative
HTTP engine; the private capture-only framer cannot affect forwarding. HTTP
interactive mode pauses one complete bounded request, while responses and TCP
traffic remain observe-only. Exact Raw for intercepted HTTP and HTTP/2 remains
explicitly unavailable.

The maintained, rendered architecture reference is
[`src/content/docs/developer/architecture.md`](src/content/docs/developer/architecture.md).
