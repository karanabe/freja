# Audit Schema

Freja writes one versioned JSON object per line. Every record includes schema
version, sequence, timestamp, session ID, optional transaction ID, policy
generation, typed event, optional previous hash, and record hash. Redaction is
applied before canonical hashing and persistence.

Authorization, Proxy-Authorization, Cookie, Set-Cookie, configured secret
query parameters, URL userinfo, and secret-bearing replay headers are redacted.
Payloads are metadata-only by default; explicit capture stores only a bounded prefix.
Critical events use a separate bounded publisher with an explicit failure
policy and are never silently discarded.

The maintained field and event reference is
[`src/content/docs/reference/audit-schema.md`](src/content/docs/reference/audit-schema.md).
