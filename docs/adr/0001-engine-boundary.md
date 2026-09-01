# ADR 0001: Engine Boundary

Status: Accepted

`freja-proxy` is the runtime/framework isolation boundary. Domain, policy,
inspection, audit, hook, and UI code cannot depend on Pingora. The production
Tokio listeners and Pingora `ServerApp` adapter have separate lifecycle entry
points and share protocol semantics without claiming a false interchangeable
listener trait.

Detailed record:
[`../src/content/docs/developer/adr/0001-engine-boundary.md`](../src/content/docs/developer/adr/0001-engine-boundary.md).
