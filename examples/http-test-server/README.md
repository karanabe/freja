# Freja HTTP test server

This development-only Axum origin server makes Freja behavior testable without
depending on a public service. It binds to `127.0.0.1:3001` by default and
returns JSON describing requests received by its echo endpoints. `/lab` adds a
browser form for short synthetic GET queries and POST form bodies.

## Browser form lab: first GET

Use Rust 1.98+, a JavaScript-enabled browser and three terminals at the repository
root. Reserve ports 3001 (origin) and 8080 (Freja). This page is a **local
development origin fixture**, not Freja's control plane. Use synthetic data only:
origin stdout, echo and live TUI intentionally show unredacted traffic.

1. **Terminal A — origin:** start it and leave it running:

   ```sh
   cargo run --manifest-path examples/http-test-server/Cargo.toml
   ```

   Expect `freja HTTP test server listening on http://127.0.0.1:3001` and the
   `/lab` URL. In Terminal C, check readiness:

   ```sh
   curl --noproxy '*' --http1.1 -i http://127.0.0.1:3001/healthz
   ```

   Expect 200 and `{"status":"ok"}`. This is a direct readiness check, not
   evidence of proxy use.

2. **Terminal B — Freja:** validate, then run the focused interactive profile:

   ```sh
   cargo run -p freja -- check-config --config examples/config/tui/freja.interactive.toml
   cargo run -p freja -- run --config examples/config/tui/freja.interactive.toml
   ```

   Expect `configuration valid: 1 listener(s), policy generation 4`, then the
   TUI. The profile is TUI + Enforce + Interactive, explicitly permits loopback
   destinations, and has a 30-second decision timeout. Keep this terminal visible.

3. **Browser:** use a dedicated profile with HTTP proxy `127.0.0.1:8080` and
   loopback bypass removed; open `http://127.0.0.1:3001/lab`. Follow the
   [use case setup](../../docs/src/content/docs/use-cases/browser-form-lab/setup.md#quickstart)
   for copyable Chromium or Firefox setup and temporary profile explanations.
   The [lab page map](../../docs/src/content/docs/use-cases/browser-form-lab/index.md#page-map)
   leads to the first GET with its TUI map and real browser screenshot, then
   interventions, cleanup/recovery and the fixture contract.
   Browser and both processes must share the intended loopback environment.

4. **Terminal B — entry pauses:** press `1` for Traffic/Flows; select each
   `HTTP paused` row with `j`/`k` or arrows and press `c`. Handle `/lab`,
   `/lab/app.js` and `/lab/style.css` within each pause's 30-second timeout.
   The browser form becomes usable after its script continues. If an entry
   request expires, prepare the TUI and reload `/lab`.

5. **Browser → TUI → origin:** select GET, case `get-01`, message `hello origin`.
   Check `GET /lab/get?case=get-01&message=hello+origin` in Prepared encoding,
   then Send once. In Terminal B select the paused request, verify HTTP/1.1 and
   its TransactionId, and press `c`. Terminal A logs that URI; the browser
   shows matching `received.uri`, `http_version: "HTTP/1.1"` and decoded
   `interpretation.message: "hello origin"`. Only the combined TUI and origin
   observations establish this proxied round trip. Return to input does not send.

Continue with [POST and interventions](../../docs/src/content/docs/use-cases/browser-form-lab/interventions.md)
for unchanged POST, permitted header/body edits, operator reject, Repeat and a
direct control, then [cleanup and recovery](../../docs/src/content/docs/use-cases/browser-form-lab/cleanup-and-recovery.md). Each action identifies
where to look and what the evidence means. Repeat's workspace shows the source
ID; confirm the new transaction in Traffic and its response in Repeat's Latest
result. The browser response still belongs to the original submission.

Prepared input, frozen submitted bytes and the latest response are separate.
An edited body that no longer parses as a form is reported as actual received
bytes with unavailable interpretation. No automatic retry, POST navigation,
arbitrary destination, upload, history or payload storage is added. Node/pnpm is
only needed for browser development tests, not for serving these embedded assets.

## Added browser pages and HTTP endpoints

These five paths are new lab surfaces on the origin; the existing JSON APIs
are listed separately below. Router: `src/lab.rs`, merged by `src/routes.rs`.
Static assets are embedded from `src/lab/`. Open `/lab` exactly, not `/lab/`.

| Method/path | Request | Response / purpose |
| --- | --- | --- |
| `GET /lab` | No form input or required Content-Type | 200 `text/html; charset=utf-8`; browser form. |
| `GET /lab/app.js` | No form input or required Content-Type | 200 `text/javascript; charset=utf-8`; validation, encoding, bounded fetch/display and re-entry. |
| `GET /lab/style.css` | No form input or required Content-Type | 200 `text/css; charset=utf-8`; local light/dark layout. |
| `GET /lab/get` | URL-encoded `case`/`message` query; empty body; no Content-Type required | 200 `application/json` receipt for valid input; GET arrival comparison. |
| `POST /lab/post` | Empty query; URL-encoded `case`/`message` body; `application/x-www-form-urlencoded` required; no Content-Encoding | 200 `application/json` receipt for valid input; POST continue/edit/Repeat comparison. |

Receipts contain `lab`, `arrival`, `http_version`, `received` (method, URI,
header-value arrays and body byte length/UTF-8/Base64), omission flags, and
`interpretation` (decoded fields or an unavailable reason). Lab validation can
return 400, 413 or 415; serialization/output failure returns 500. Oversized or
unreadable bodies and output failures return only `{"error":"…"}` instead of a
receipt. Freja's reject/timeout/connection-error responses are separate from
these origin responses. See the complete
[Web/API contract](../../docs/src/content/docs/use-cases/browser-form-lab/http-contract.md#web-surfaces)
for error distinctions, field meanings and the HEAD/router behavior.

Limits: exactly `case` (1–32 ASCII letters/digits/`_`/`-`) and `message`
(0–256 UTF-8 bytes, empty allowed); encoded query/body each ≤2 KiB; receipt
headers ≤32 values and 1 KiB total name/value bytes; URI prefix ≤2 KiB. Omission
is explicit. Response and browser display each cap at 64 KiB; the browser waits
at most 45 seconds without retrying. Dynamic output is text with escaped controls;
lab handlers add no-store, nosniff and a same-origin CSP. The global 1 MiB body
guard and 4 KiB escaped stdout preview still apply, including to the static routes.

## JSON and curl

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

## Existing JSON and HTTP endpoints

| Endpoint | Behavior |
| --- | --- |
| `GET /` | Lists the available routes. |
| `GET /healthz` | Returns `{"status":"ok"}`. |
| `/get`, `/post`, `/put`, `/patch`, `/delete` | Accept the matching method and echo method, URI, headers, and body metadata as JSON. |
| `HEAD /head`, `OPTIONS /options` | Exercise the matching HTTP methods. |
| `ANY /anything`, `ANY /anything/{*path}` | Echoes any method and nested path. |
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

## Development checks

This package is an independent workspace, so run its checks explicitly:

```console
cargo fmt --manifest-path examples/http-test-server/Cargo.toml -- --check
cargo clippy --manifest-path examples/http-test-server/Cargo.toml --all-targets --all-features -- -D warnings
cargo test --manifest-path examples/http-test-server/Cargo.toml --all-features
```

The Rust tests use ephemeral loopback origins and the existing Freja proxy and
typed interactive broker to check pause, continue, editing, rejection, timeout,
Repeat, direct access, and origin failure. They do not operate the TUI keyboard.
The seven production crates do not depend on this fixture. The `fuzzing` feature
only exposes its bounded form decoder to the repository's `browser_form` fuzz
target; it adds no serving behavior.

For the browser's encoding, re-entry, failure, text rendering and bounds tests,
install Node.js 22 or newer, pnpm 11 or newer, and Playwright's Chromium:

```console
cd examples/http-test-server
pnpm install --frozen-lockfile
pnpm exec playwright install chromium
pnpm test:browser
```

Chromium needs the host libraries listed by Playwright's installer. The tests
start and stop their own local origin; no public service is contacted by the
test cases. Failure/pause responses in browser tests are controlled simulations;
the Rust tests separately exercise actual Freja behavior. Neither substitutes
for the maintainer's browser-plus-TUI usability observation. Record unperformed
manual cases as unobserved.
