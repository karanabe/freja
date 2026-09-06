---
title: First GET
description: Follow one GET through the browser, Freja TUI, origin stdout and response.
publishedAt: 2026-09-06
updatedAt: 2026-09-06
tags:
  - tui
  - interception
  - testing
sidebar:
  order: 3
  label: First GET
prev:
  link: /use-cases/browser-form-lab/setup/
  label: Prepare the lab
next:
  link: /use-cases/browser-form-lab/interventions/
  label: POST and interventions
---

**Starting state:** [lab setup](../setup/) are complete, Terminal A runs the origin, Terminal B runs Freja, and the dedicated browser shows `/lab`. This page completes one correlated GET round trip. The TUI map also helps with the entry pauses during browser setup. Use only synthetic loopback traffic; stdout, echo and the TUI can expose unredacted values. After success, continue to [POST and interventions](../interventions/) or [finish the lab](../cleanup-and-recovery/#cleanup).

[Lab overview and page map](../#page-map)

<a id="tui-map"></a>

## TUI map: selected entry GET

Representative Traffic/Pretty/Split state, checked against the current renderer
and a local paused `/lab` request. Empty rows are omitted, `<TransactionId>` stands
for the real ID, and **T1–T4 are documentation annotations**, not UI labels.
Real border glyphs, wrapping and visible hints depend on width/data; the TUI
requires at least 80×24. This diagram assumes Flows has focus after pressing `1`.

```text
+[T1] Flows [1 Traffic]  mode=Pretty layout=Split  Ctrl+j/k pane | Enter expand-----------------------------------------------------------------------+
|[T2] > HTTP paused <TransactionId> GET http://127.0.0.1:3001/lab HTTP/1.1                                                                            |
|                                                                                                                                                     |
+-----------------------------------------------------------------------------------------------------------------------------------------------------+
+[T3] Request [Pretty]  m mode | v split/request/response | h/l side------+ +[T4] Response [Pretty]  m mode | v split/request/response | h/l side-----+
|GET http://127.0.0.1:3001/lab HTTP/1.1                                   | |No content observed                                                      |
|host: 127.0.0.1:3001                                                     | |                                                                         |
|                                                                         | |                                                                         |
+-------------------------------------------------------------------------+ +-------------------------------------------------------------------------+
```

1. **T1 — top Flows title:** `1` returns to Traffic and focuses Flows.
   `j/k` or arrows select rows there. `Ctrl+j/k` or Tab changes pane focus;
   Enter expands the focused pane, and `q` closes the expansion.
2. **T2 — selected row:** `>` marks selection, `paused` identifies the wait,
   and the real TransactionId binds the action to one request. Verify `/lab`,
   then `c` continues. For a selected paused request outside the editor, `e/i`
   opens editing, `r` rejects, and Shift+R continues and creates a Repeat draft.
   These are action keys, not a permanent Traffic footer shown in the diagram.
3. **T3 — Request below:** inspect HTTP/1.1, target and headers; a POST case is
   in its body. The title carries `m` (Pretty/Raw/Hex), `v` (layout) and `h/l`
   (side) hints. With detail focus, `j/k` scrolls instead of selecting a flow.
4. **T4 — Response below:** before forwarding, `No content observed` is expected;
   after `c`, check the response on this same transaction. In the editor, Insert
   mode types into the draft: Esc returns to Normal and `s` submits. Outside the
   editor, `3` opens Repeat, where `s` sends its selected draft. `Q`/Ctrl+C exits
   Freja even from the editor; check mode/focus before typing action keys.

<a id="step-5"></a>

<a id="5-send-one-get-continue-it-and-match-all-four-views"></a>

<a id="get-round-trip"></a>

## Send one GET, continue it, and match all four views

**Do — browser:** select **GET**, set **Case label** to `get-01` and **Message**
to `hello origin`. The **Prepared encoding — not sent yet** pane should show:

```text
GET /lab/get?case=get-01&message=hello+origin
(empty body)
```

<a id="browser-map"></a>

### Browser map: prepare, then press Send

![Actual local lab before sending: GET selected, case get-01, message hello origin, Send GET query focused, with Prepared encoding and the empty Last submitted bytes and Latest response areas below.](/images/browser-form-lab/get-ready.png)

*Figure B — Actual `/lab` capture, cropped to its input and result sections.
Synthetic GET values are ready; the focus outline marks **Send GET query**.
Nothing has been sent. This image is not evidence of Freja traversal; native
control appearance can differ in Firefox or another OS.*

1. **B1 — Method and input location, top selector:** choose GET here (choose POST for the [unchanged POST example](../interventions/#continue-post)).
2. **B2 — Case label, next input:** enter `get-01`; change it for each new submission.
3. **B3 — Message, textarea:** enter `hello origin`, then check Prepared encoding
   below the buttons. It shows `message=hello+origin` before any request is sent.
4. **B4 — Send GET query, filled button on the left:** press this once, or focus
   it and press Enter. Clear message to its right only empties the message.
   With POST selected the real button label is **Send POST body**.
5. **B5 — Last submitted bytes, lower section:** after Send, this freezes the
   submitted query/body before Freja edits; in the image it says No submission.
6. **B6 — Latest response, below B5:** after the decision, compare received bytes
   and decoded fields here; before sending there is no response.
7. **B7 — Return to input, bottom button:** enabled when the attempt ends;
   it focuses the case without sending. It is disabled in this unsent capture.

The existing instructions below work without the image. Capture/update conditions
are in [Developer testing](../../../developer/testing/#browser-lab-visuals).

Click **Send GET query** once. Keep the browser open and switch to Terminal B.

**Do / look — Terminal B:** press `1`, select the new paused `/lab/get` row with
`j`/`k`, and read its request line. Check **HTTP/1.1** and copy the full HTTP row's
**TransactionId**. If needed, Tab moves from Flows to the detail, `h` selects
Request, and `m` cycles Pretty/Raw/Hex; use Pretty for semantic fields. `v` cycles
split/request-wide/response-wide layouts, and Enter expands the focused pane.
`q` closes that expansion. Press `1` to focus Flows again.

**Look / evidence before continue:** the browser says it is waiting and the row
is `paused`; Terminal A has no matching `get-01` HTTP request yet. Freja can have
opened upstream TCP already; a connection is not an HTTP request arrival.
Press **`c`** on this selected request.

| View | Expected display after continue | What it establishes |
| --- | --- | --- |
| Terminal B — Traffic | Same TransactionId, request line with HTTP/1.1, and response status 200. `l` selects Response. | This request and response were observed by Freja. |
| Terminal A — origin stdout | `[received] GET /lab/get?case=get-01&message=hello+origin` | The matching HTTP request reached the origin. |
| Browser — Last submitted bytes | The original encoded query, unchanged | What this browser submission prepared before any Freja edit. |
| Browser — Latest response | `http_version: "HTTP/1.1"`, matching `received.uri`, and `interpretation` with `kind: "fields"`, `case: "get-01"`, `message: "hello origin"` | What the origin reports receiving and decoding. |

Together these observations establish this proxied HTTP/1.1 round trip. The
browser deliberately still says traversal is **unverified** until you match
Freja's TransactionId; it cannot read that ID. A case label helps you correlate
one request, but is not an identity and can be reused by Repeat.

Click **Return to input (does not send)**. Focus returns to the case field;
inputs and the last result remain. Change the case before the next explicit Send.
The result still belongs to the previous submission. **This completes the shortest
success path.** Continue to [POST and interventions](../interventions/), or go to [cleanup](../cleanup-and-recovery/#cleanup).
