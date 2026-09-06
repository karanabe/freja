---
title: Web/API contract
description: Look up the five local origin paths, receipt fields, errors, limits and existing JSON/curl compatibility.
publishedAt: 2026-09-06
updatedAt: 2026-09-06
tags:
  - tui
  - interception
  - testing
sidebar:
  order: 6
  label: Web/API contract
prev:
  link: /use-cases/browser-form-lab/cleanup-and-recovery/
  label: Cleanup and recovery
next:
  link: /use-cases/browser-form-lab/
  label: Return to lab overview
---

**Use this page when:** a lab request or receipt needs interpretation. It describes the fixture’s five paths, fields, errors and existing JSON/curl compatibility; it adds no walkthrough steps. Read the [overview](../) for the scenario, the [first GET](../first-get/) for proxy-path evidence, or [recovery and bounds](../cleanup-and-recovery/) for an unsuccessful attempt. These are loopback development-origin contracts; echoed headers/body can be unredacted, so use synthetic data only.

[Lab overview and page map](../#page-map)

<a id="web-surfaces"></a>

## Added Web surfaces and HTTP contract

All five paths below belong to **the development origin on port 3001**. Freja's
proxy on port 8080 forwards them like other allowed HTTP requests. There is no
browser control endpoint for continue, editing, reject, Repeat or process management.
The router is `examples/http-test-server/src/lab.rs`, merged by `src/routes.rs`;
assets are embedded from `src/lab/`.

### New page, assets and form endpoints

| Method and path | Query/body and request Content-Type | Origin response | Purpose and bounds |
| --- | --- | --- | --- |
| `GET /lab` | No form input; no request Content-Type needed | 200 `text/html; charset=utf-8` | Browser page; fixed embedded HTML. Loads the next two assets. |
| `GET /lab/app.js` | No form input; no request Content-Type needed | 200 `text/javascript; charset=utf-8` | Fixed local script for validation, encoding, bounded fetch/display and re-entry. |
| `GET /lab/style.css` | No form input; no request Content-Type needed | 200 `text/css; charset=utf-8` | Fixed local layout and light/dark styling. |
| `GET /lab/get` | URL-encoded `case` and `message` in query; empty body; no Content-Type required | 200 receipt JSON for valid input; errors below | GET input/arrival comparison. Query ≤2 KiB; [field and display limits](../cleanup-and-recovery/#bounds-and-observation-record). |
| `POST /lab/post` | Empty query; URL-encoded `case` and `message` in body; `Content-Type: application/x-www-form-urlencoded` required | 200 receipt JSON for valid input; errors below | POST continue/edit/Repeat comparison. Body ≤2 KiB; no Content-Encoding accepted. |

These are exact paths: open `/lab`, not `/lab/`. Axum's GET registrations also
provide HEAD fallback without a response body; the form operations documented
here use GET and POST. Unsupported methods on registered paths return 405;
unknown paths use the existing JSON 404 fallback. The existing global 1 MiB body
guard runs before lab handlers, including the static routes.

Lab handler responses use `Cache-Control: no-store`, `X-Content-Type-Options:
nosniff`, `Referrer-Policy: no-referrer` and CSP restricting scripts, styles and
connections to the same origin. The page displays responses with `textContent`
and escaped controls; it never interprets echoed markup as HTML. The form has no
fields for arbitrary destinations, uploads, credentials or user-defined methods/headers.

## Receipt fields and errors

GET/POST receipts are `application/json`. An excerpt from [unchanged POST](../interventions/#continue-post) is:

```json
{
  "lab": "http11-browser-form",
  "http_version": "HTTP/1.1",
  "received": {
    "method": "POST",
    "uri": "/lab/post",
    "body": { "utf8": "case=post-02&message=hello+origin" }
  },
  "interpretation": { "kind": "fields", "case": "post-02", "message": "hello origin" }
}
```

This excerpt omits other fields; the complete receipt contains:

| Field | Meaning |
| --- | --- |
| `lab` | Fixture marker `http11-browser-form`; not authenticated proxy-path evidence. |
| `arrival` | Origin receipt explanation, explicitly stating Freja traversal is unverified. |
| `http_version` | Version actually received by the HTTP/1-only origin; compare with Freja's request line. |
| `received.method`, `received.uri` | Actual method and bounded URI, including GET query. |
| `received.headers` | Map of header names to arrays of retained string values; unredacted. Non-text values use a `base64:` prefix. |
| `received.body.byte_length`, `.utf8`, `.base64` | Received body length, UTF-8 text (null for invalid UTF-8), and Base64 of the same bytes. GET normally has length 0 and empty strings. |
| `headers_omitted`, `uri_omitted` | True if that receipt surface was shortened; missing data must not be inferred. |
| `interpretation` | `kind: "fields"` plus decoded `case`/`message`, or `kind: "unavailable"` plus `reason`. It never substitutes old browser input for invalid edited bytes. |

| Origin status | Response and reason |
| --- | --- |
| 200 | Receipt with successfully interpreted fields. |
| 400 | Receipt with unavailable interpretation: missing/duplicate/unknown fields, invalid escapes/UTF-8 or field lengths, GET body, or POST query. |
| 413 | Query >2 KiB: bounded receipt with unavailable interpretation. Body >2 KiB or read failure: only `{"error":"…"}`, without receipt/body fields. Above the global 1 MiB body guard, its existing error is returned before lab routing. |
| 415 | POST has absent/unsupported Content-Type or any Content-Encoding: receipt with actual bytes and unavailable interpretation. UTF-8 decoding is fixed; a Content-Type parameter does not enable another charset. |
| 500 | Receipt serialization/total-output failure: only `{"error":"…"}`, without receipt fields. |

An earlier framing/router/proxy rejection can have a different body. In particular,
Freja's operator 403, interactive failure 504 and connection failure 502 are not
lab receipts and do not prove origin arrival. An `error`-only response has no
`lab` marker; the browser asks for terminal confirmation instead of inventing one.

## Existing JSON and curl surfaces

`GET /` remains a JSON route index (`service`, `warning`, `endpoints`); its list
now mentions the lab. `GET /healthz` remains the health response used for [origin readiness](../setup/#origin-readiness).
Existing `/get`, `/post`, `/put`, `/patch`, `/delete`, `/head`, `/options`,
`/anything` and `/anything/{*path}` retain their method/URI/header/body echo
contracts. Existing status, redirect, delay, stream and bytes routes retain
their bounds. They were not replaced with HTML and do not require lab fields.
For example, `/post` can still receive JSON; only `/lab/post` requires the lab form.
See `examples/http-test-server/README.md` for the full existing endpoint list.

With the interactive profile still running, these optional root-directory curl
commands create additional paused requests. Continue each in Terminal B. Use a
new case so they cannot be confused with the browser steps:

```sh
curl --noproxy '' --http1.1 --proxy http://127.0.0.1:8080 -i \
  'http://127.0.0.1:3001/lab/get?case=curl-get&message=hello+origin'
curl --noproxy '' --http1.1 --proxy http://127.0.0.1:8080 -i \
  http://127.0.0.1:3001/lab/post \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'case=curl-post&message=hello+origin'
```
