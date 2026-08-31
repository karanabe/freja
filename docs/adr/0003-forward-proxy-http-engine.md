# ADR 0003: Forward Proxy HTTP Engine

Status: Accepted

Hyper 1.x owns HTTP/1 parsing and connection state on the transport stream.
Freja implements absolute-form routing, origin-form regeneration, Host
regeneration, CONNECT authority handling, policy, synthetic responses, and
upgrade tracking around Hyper. CONNECT returns success only after upstream TCP
connection and switches irreversibly to tunnel mode after commitment.

Detailed record:
[`../src/content/docs/developer/adr/0003-forward-proxy-http-engine.md`](../src/content/docs/developer/adr/0003-forward-proxy-http-engine.md).
