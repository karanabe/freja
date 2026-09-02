# Freja HTTP test server

This development-only Axum origin server makes Freja behavior testable without
depending on a public service. It binds to `127.0.0.1:3001` by default and
returns JSON describing requests received by its echo endpoints.

Start the server and Freja in separate terminals:

```console
cargo run --manifest-path examples/http-test-server/Cargo.toml
cargo run -p freja -- run --config examples/config/headless/freja.toml
```

Force curl to use Freja even when the environment excludes loopback addresses
from proxying:

```console
curl --noproxy "" --proxy http://127.0.0.1:8080 \
  "http://127.0.0.1:3001/get?name=freja" \
  -H 'X-Demo: forwarded'

curl --noproxy "" --proxy http://127.0.0.1:8080 \
  http://127.0.0.1:3001/post \
  -H 'Content-Type: application/json' \
  --data '{"message":"hello through Freja"}'
```

Every request is also written to the test server's terminal:

```text
[received] POST /post
  host: 127.0.0.1:3001
  authorization: Bearer development-token
  cookie: session=development-only
  content-type: application/json
  content-length: 33
  body: 33 bytes, utf-8 preview: {"message":"hello through Freja"}
```

The supplied `examples/config/headless/freja.toml` explicitly allows loopback
destinations for this local workflow. Production configurations should retain
the normal loopback destination protection unless local upstream access is
intentional. See `examples/config/README.md` for enforcement and TUI variants.

## Terminal request log

The log includes the method, URI, headers, total body size, and a body preview.
Text and header control characters are escaped so request data cannot emit
terminal control sequences. Binary body previews are Base64 encoded.

Body previews retain at most 4 KiB and report truncation. All incoming request
bodies are limited to 1 MiB and an oversized body receives 413 before routing.
All header values, including credentials and cookies, are intentionally shown
without redaction. URIs and body previews are also unredacted. Use only
synthetic query values, credentials, and payloads, and do not retain terminal
logs as production data.

## Endpoints

| Endpoint | Behavior |
| --- | --- |
| `GET /` | Lists the available routes. |
| `GET /healthz` | Returns `{"status":"ok"}`. |
| `/get`, `/post`, `/put`, `/patch`, `/delete` | Accept the matching method and echo method, URI, headers, and body metadata as JSON. |
| `HEAD /head`, `OPTIONS /options` | Exercise the matching HTTP methods. |
| `ANY /anything/{path}` | Echoes any method and nested path. |
| `GET /status/{code}` | Returns any final status from 200 through 599. |
| `GET /redirect/{count}` | Emits up to 10 relative temporary redirects. |
| `ANY /delay/{milliseconds}` | Delays for up to 30 seconds, then echoes the request. |
| `GET /stream/{chunks}?interval_ms=50` | Streams 1–1,000 text chunks through a capacity-one bounded channel, with at most 30 seconds of scheduled delay. |
| `GET /bytes/{size}` | Returns 0–8 MiB of deterministic `x` bytes. |

The server intentionally reflects headers and bodies, so use only synthetic
credentials and data. A non-loopback bind is rejected unless both an explicit
address and `--allow-non-loopback` are passed:

```console
cargo run --manifest-path examples/http-test-server/Cargo.toml -- \
  --bind 0.0.0.0:3001 --allow-non-loopback
```
