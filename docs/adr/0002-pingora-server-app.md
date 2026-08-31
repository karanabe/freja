# ADR 0002: Pingora ServerApp

Status: Accepted

Pingora 0.8.1 is the compatibility baseline and is integrated only through
`ServerApp`. Freja does not use `pingora-proxy::ProxyHttp` for explicit forward
proxy semantics. A consumed Pingora stream is handed to a narrow connection
handler and is not returned to Pingora's reuse path.

Detailed record:
[`../src/content/docs/developer/adr/0002-pingora-server-app.md`](../src/content/docs/developer/adr/0002-pingora-server-app.md).
