# ADR 0001: Engine Boundary

Status: Accepted

Freja defines a transport-neutral listener engine boundary. Protocol-independent
domain, policy, inspection, audit, hook, and UI code cannot depend on Pingora.
The production Tokio listener and Pingora `ServerApp` adapter remain
replaceable without changing policy semantics.

Detailed record:
[`../src/content/docs/developer/adr/0001-engine-boundary.md`](../src/content/docs/developer/adr/0001-engine-boundary.md).
