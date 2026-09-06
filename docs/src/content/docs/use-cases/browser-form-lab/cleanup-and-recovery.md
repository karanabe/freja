---
title: Cleanup and recovery
description: Stop only your lab processes, remove disposable profiles, recover from failures and record observations.
publishedAt: 2026-09-06
updatedAt: 2026-09-06
tags:
  - tui
  - interception
  - testing
sidebar:
  order: 5
  label: Cleanup and recovery
prev:
  link: /use-cases/browser-form-lab/interventions/
  label: POST and interventions
next:
  link: /use-cases/browser-form-lab/http-contract/
  label: Web/API contract
---

**Starting state:** you have used the lab and still have its terminals/profile variables, or an attempt needs recovery. This page covers shutdown and cleanup, and provides [failure recovery](#failure-and-re-entry), [bounds and observation notes](#bounds-and-observation-record). Finish pending work from [POST and interventions](../interventions/) before stopping processes. Retain only synthetic observations; if investigating a response, continue to the [Web/API contract](../http-contract/).

[Lab overview and page map](../#page-map)

<a id="cleanup"></a>

<a id="step-11"></a>

<a id="11-finish-and-clean-up-this-lab"></a>

## Finish and clean up this lab

**Do / look:** finish or reject your pending requests; wait for any Repeat send
to complete. Close all the dedicated browser windows you opened. In Terminal B press **Q** or
Ctrl+C; expect the ordinary terminal to be restored. In Terminal A press Ctrl+C;
expect the origin process to return to its shell. Stop only the processes you
started for this walkthrough. If you changed browser/OS proxy settings manually,
restore their previous values before ordinary browsing.

In Terminal C, inspect the disposable profile paths you created:

```sh
printf '%s\n' "${lab_proxy_profile:-}" "${lab_direct_profile:-}" "${lab_firefox_profile:-}"
```

After the corresponding browser processes have exited, optionally remove each
printed lab directory. Empty lines above just mean that option was not used.
In the same shell, choose only the commands for profiles you created; each
`${variable:?}` guard refuses an unset/empty path as explained in [dedicated browser setup](../setup/#dedicated-browser).

For Chromium (second command only if you created the direct profile in [the direct control](../interventions/#direct-control)):

```sh
rm -r -- "${lab_proxy_profile:?}"
rm -r -- "${lab_direct_profile:?}"
```

For Firefox, after its lab process has exited:

```sh
rm -r -- "${lab_firefox_profile:?}"
```

**Evidence / remaining files:** `/lab` has no fixture history or payload storage,
but a browser profile has its own files, and Freja's existing audit writer creates
`freja-<timestamp>-<pid>-<collision>.jsonl` under the sample's audit path. Review
the `audit segment created` path in operational output (Diagnostics logs while
the TUI owns the terminal). Retain or remove only this run's identified segment
according to your needs; do not broadly delete other runs' audit files. Build
artifacts remain. Avoid retaining terminal recordings with sensitive traffic.

## Failure and re-entry

For every failure, inspect the current **Last submitted bytes**, the matching
TUI transaction and Terminal A before trying again. After the request completes
or the browser stops waiting, Return to input preserves values and focuses the
case field; change the case and explicitly Send. While pending, extra sends
are disabled and the previous response is cleared. No automatic retry, POST
navigation, redirect following or history replay is performed. Aborting the
45-second browser wait cannot retract bytes already sent or prove non-arrival.

| Symptom / controlled check | Look and act | Evidence and recovery |
| --- | --- | --- |
| Invalid case or oversized input in the page | Browser validation; try 86 copies of `界` (258 UTF-8 bytes). | Send is blocked. Shorten to the byte budget; no new TUI/origin request should exist. |
| Page/controls/style missing | Terminal B: `/lab`, `/lab/app.js`, `/lab/style.css` pauses. | Continue each; after a deadline, reload the entry GET and handle new pauses. Script disabled by browser settings also prevents the form becoming usable. |
| Waiting after Send | Match the paused transaction in Traffic. | Decide within 30 seconds. Waiting alone cannot identify a pause or prove non-arrival. |
| 400 / 415 lab receipt | Browser `received` versus `interpretation.reason`. | Origin received bytes that are not an accepted form. Correct the input or edit using a new attempt. |
| Lab 413 or explicitly shortened display | Error text, omission flags, byte limits below. | Some bytes/headers may be unavailable. Reduce input; do not interpret missing data as empty. |
| Controlled decision timeout | Send a new case and deliberately make no decision for >30 seconds; watch the row and both terminals. | The sample returns 504 `interactive interception failed`; audit uses `failed`. Other broker failures share this response/action, so use the controlled wait as additional evidence. Return with a new case. |
| Origin unavailable | After completing prior attempts, stop only Terminal A with Ctrl+C and send a new case. | Usually proxy 502; startup/network errors can differ. No origin receipt is available. Restart [origin readiness](../setup/#origin-readiness), verify readiness, and send a new case after re-entry. |
| Network error or browser stops after 45 seconds | Check whether both processes are running and whether the request is still pending in Freja. | Arrival remains unknown; inspect/resolve the old transaction before sending another. |
| Echo without a matching TUI transaction | Compare [the direct control](../interventions/#direct-control) and the browser proxy setup. | Freja traversal is unverified. Restore the proxied profile and obtain a new correlated transaction. |
| `r`, `s` or navigation acts unexpectedly | Check whether the editor is in Insert mode or a pane is expanded. | Esc leaves Insert mode; `q` in Normal mode discards the editor draft. Outside it, `q` closes expansion and `1` focuses Traffic/Flows. Do not type an action into the body by mistake. |

## Bounds and observation record

| Surface | Limit |
| --- | --- |
| Fields | Exactly `case` and `message`; no duplicate/unknown/missing fields. Empty message is valid. |
| Case | 1–32 ASCII letters, digits, `_` or `-` |
| Message | 0–256 UTF-8 bytes, enforced by browser and server, not only `maxlength` |
| Encoded query or body | 2 KiB each; malformed percent encoding and non-UTF-8 fields rejected |
| Receipt headers / URI | Up to 32 header values, 1 KiB total name/value bytes; URI prefix up to 2 KiB with omission flags |
| Response / browser display | 64 KiB each; excessive response stops reading, expanded text may be explicitly shortened |
| Existing origin / interactive sample | 1 MiB body guard / 4 KiB escaped stdout body preview; 16 KiB interactive body / 30-second decision timeout |

The example remains an independent, non-published workspace outside the seven
production crates. It reuses existing echo capture and request logging. No
policy, enforcement default, TUI editing boundary or audit/replay schema changes
are part of the lab. Live output is intentionally unredacted; synthetic data is
required even when audit capture is metadata-only.

[Developer tests](../../../developer/testing/#browser-form-fixture) cover local HTTP
contracts, actual Freja interception and Chromium behavior. Browser failure/delay
simulations and typed broker decisions are automated fixtures, not maintainer
browser-plus-TUI usability observations. For each manual step record revision,
browser/OS and proxy setup, case, HTTP/1.1 evidence, original/new transaction IDs,
origin arrivals, re-entry and any confusing operation. Mark unperformed steps
**not observed**. Do not save real credentials or payloads; passing tests alone
does not establish the operator outcome or improved usability.

Firefox/macOS device checks and the maintainer’s complete browser-plus-TUI walkthrough remain **not observed**. Automated Chromium fixtures, a narrow live-TUI check and the unsent screenshot do not fill that gap.
