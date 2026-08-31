# Hooks

Hooks live under `freja-policy::hook` and are disabled by default. Separate
interfaces cover HTTP request/response heads and bodies plus both TCP chunk
directions. Hooks return typed mutation plans; they cannot emit wire bytes,
mutate hop-by-hop or proxy-controlled framing headers, or exceed the configured
HTTP/TCP replacement budget. Freja reconstructs HTTP framing after accepted
body mutation.
Decoded replacement of content-encoded messages requires preflight mode so
representation metadata can be corrected before the head is committed.

Interactive interception uses a bounded request channel, a paused-flow
semaphore, a oneshot response, and an explicit timeout policy. TUI actions are
continue, reject, edit headers, replace a bounded body, and cancel
modification. Native dynamic libraries are not loaded as plugins.

The maintained hook design is
[`src/content/docs/developer/hooks.md`](src/content/docs/developer/hooks.md).
