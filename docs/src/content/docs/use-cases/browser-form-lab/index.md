---
title: HTTP/1.1 browser form lab
description: Choose a path through the local HTTP/1.1 form lab and understand what its evidence proves.
publishedAt: 2026-09-06
updatedAt: 2026-09-06
tags:
  - tui
  - interception
  - testing
sidebar:
  order: 1
  label: Overview
prev:
  link: /use-cases/
  label: Use cases
next:
  link: /use-cases/browser-form-lab/setup/
  label: Prepare the lab
---

`examples/http-test-server` serves a browser form at `http://127.0.0.1:3001/lab`.
It is a **local development origin fixture**, not Freja's control plane. The
page sends two small fields to its own origin; operator decisions still happen
in Freja's existing TUI. Start with [setup](./setup/) and the [first GET](./first-get/) for one successful proxied request,
then continue with POST, editing, reject and Repeat. The [Web/API reference](./http-contract/#web-surfaces)
and [failure guide](./cleanup-and-recovery/#failure-and-re-entry) are separate lookup pages.

Use **synthetic data only**. Origin stdout, echo responses and the live TUI can
show unredacted headers (including Authorization/Cookie), query values and bodies.
Audit redaction is separate. A successful echo alone does not prove proxy use.

## What this lab lets you check

Send a short GET query and POST form body, then compare before/after continue,
permitted edits, rejection and a separate Repeat send. Method, target, Host and
framing remain read-only. This is an HTTP/1.1 local fixture; TLS/CA setup and
arbitrary external destinations are outside the scenario.

## Reading the evidence

Prepared encoding is the browser's intended input; Last submitted bytes freezes
what it submitted before Freja edits. Latest response shows received bytes and
the origin's interpretation. The browser cannot read Freja's TransactionId:
match the same request in the TUI and origin stdout to establish traversal.
An upstream TCP connection is not an HTTP request arrival; waiting or an absent
log line alone does not prove rejection. Check Repeat's extra arrival and new ID
separately from the original submission.

## Page map

The shortest success path is **prepare → first GET**. Continue with POST and
interventions, or use cleanup whenever you finish. Choose a page by its purpose.

| Page | Starting point and what this page completes | Next destination |
| --- | --- | --- |
| **This overview** | Understand the purpose and evidence boundaries. | [Prepare](./setup/) |
| [Prepare the lab](./setup/) | Set up tools, origin, Freja and either Chromium or Firefox; handle entry pauses. | [First GET](./first-get/) |
| [First GET](./first-get/) | With the lab running, use the TUI map and browser image to match four views. | [POST and interventions](./interventions/) or [finish](./cleanup-and-recovery/#cleanup) |
| [POST and interventions](./interventions/) | After GET success, check POST, editing, rejection, Repeat and the direct control. | [Cleanup and recovery](./cleanup-and-recovery/) |
| [Cleanup and recovery](./cleanup-and-recovery/) | Clean up your processes/profiles/audit; look up failures, bounds and observation notes. | [Web/API contract](./http-contract/) |
| [Web/API contract](./http-contract/) | Look up the lab's five paths, receipts, errors and existing JSON/curl surfaces as needed. | [Return to page map](#page-map) |

General key operations belong to the [guide](../../guides/tui-and-hooks/);
the full configuration contract belongs to [Reference](../../reference/configuration/).

## Validation coverage

Local automated checks, a narrow live-TUI check and a real unsent browser capture
are available. Firefox/macOS device checks and the maintainer's complete
browser-plus-TUI walkthrough remain **not observed**. Tests and images do not
substitute for that usage evidence. Record it using the
[observation notes](./cleanup-and-recovery/#bounds-and-observation-record).
