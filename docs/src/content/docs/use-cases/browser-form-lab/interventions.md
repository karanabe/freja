---
title: POST and interventions
description: Compare POST continue, permitted edits, operator reject, Repeat and a direct connection.
publishedAt: 2026-09-06
updatedAt: 2026-09-06
tags:
  - tui
  - interception
  - testing
sidebar:
  order: 4
  label: POST and interventions
prev:
  link: /use-cases/browser-form-lab/first-get/
  label: First GET
next:
  link: /use-cases/browser-form-lab/cleanup-and-recovery/
  label: Cleanup and recovery
---

**Starting state:** complete the [first GET](../first-get/) and keep the same origin, Freja and proxied browser running. This page covers POST, editing, rejection, Repeat and the direct control. Use synthetic data only; output remains unredacted. Match transactions and origin arrivals as in the [GET evidence table](../first-get/#get-round-trip), then [clean up the lab](../cleanup-and-recovery/).

[Lab overview and page map](../#page-map)

<a id="post-edit-reject-and-repeat"></a>

## POST, edit and reject

Read each action before sending: the same 30-second decision timeout applies.
Send one request at a time. A POST case is in its body, so rows sharing
`POST /lab/post` must be distinguished using Request content and TransactionId.
TUI page selectors and navigation keys below apply outside the editor.

<a id="step-6"></a>

<a id="6-continue-a-post-without-changes"></a>

<a id="continue-post"></a>

### Continue a POST without changes

**Do — browser:** Return to input, select **POST**, enter case `post-02` and
message `hello origin`. Confirm the prepared content, then click **Send POST body**:

```text
POST /lab/post
Content-Type: application/x-www-form-urlencoded

case=post-02&message=hello+origin
```

**Do / look — Terminal B:** `1`, then `j`/`k` to select the paused POST. Check
HTTP/1.1, record its new TransactionId, and verify `post-02` in Request's body.
Press **`c`**.

**Look / evidence:** Terminal A logs `[received] POST /lab/post` and that exact
encoded body. Browser `received.body.utf8` equals the submitted body above;
`interpretation.message` is `hello origin`. The encoded `+` and the decoded space
have different representations of the same input. This is unchanged forwarding.

Repeat this step with a new case and an empty message, one space, and
`日本語 &=+`. Empty input produces `message=`; one space produces `message=+`.
Literal `+`, `&`, `=` become `%2B`, `%26`, `%3D`; Japanese text is UTF-8
percent-encoded. The same encoding applies to the GET query.

<a id="step-7"></a>

<a id="7-edit-a-different-post-before-it-reaches-the-origin"></a>

<a id="edit-post"></a>

### Edit a different POST before it reaches the origin

**Do — browser:** send case `edit-03`, message `before`, using POST.
**Do — Terminal B:** select that paused request, verify its body and ID, then
press **`i`** to open the editor in Insert mode. Its cursor starts at the body.

1. Use End and Backspace/Delete to replace only the message value `before`
   with `after`, leaving `case=edit-03&message=after`.
2. To also test a permitted header, move to Home at the body line and Up to the
   blank separator line. Type `X-Lab-Edit: yes`, then Enter to retain a blank
   line between the headers and body. Check the resulting header/body boundary.
3. Press Esc to enter Normal mode, then **`s`** to validate and continue.
   Ctrl+S also submits. If validation fails, read the editor error and correct
   the draft before the pause expires. `q` in Normal mode discards only the draft;
   it is not continue or reject.

**Look / evidence:** Terminal A and browser receipt contain the changed encoded
body and, when added, `received.headers["x-lab-edit"]: ["yes"]`.
`interpretation.message` is `after`, while **Last submitted bytes** still shows
`before`. This distinguishes browser input from the bytes Freja forwarded after
editing. Freja reconstructs Content-Length; do not edit method, target/query,
version, Host, hop-by-hop or framing headers. GET query editing is out of scope.

As an optional second edit, replace the entire body with `changed text`. Expect
lab HTTP 400, `received.body.utf8: "changed text"` and
`interpretation.kind: "unavailable"` with a reason. The origin received bytes,
but those bytes are not the original two-field form. Full controls are in
[TUI and typed hooks](../../../guides/tui-and-hooks/#navigation-and-interactive-controls).

<a id="step-8"></a>

<a id="8-reject-a-new-request"></a>

<a id="reject-request"></a>

### Reject a new request

**Do — browser:** send POST case `reject-04`, message `do-not-forward`.
**Do — Terminal B:** select and verify the paused body/TransactionId, then press
**`r`** outside the editor. Inspect Traffic's Response; Diagnostics (`2`) can
also show the selected request and operational context. Return with `1`.

**Look / evidence:** the browser displays the proxy's HTTP 403 response with
`rejected by operator`, without an origin lab receipt. Terminal A has no
corresponding `reject-04` body. The explicit `r` action, matching transaction
and non-arrival together establish rejection before HTTP forwarding. A missing
log line or a generic error alone is insufficient. An Observe policy deny is
not the same as a real block or an operator reject.

**Return:** click Return to input, change the case, and send only when ready.
Returning does not resend the rejected POST.

<a id="step-9"></a>

<a id="9-continue-the-original-and-send-a-repeat-draft"></a>

<a id="repeat-request"></a>

## Continue the original and send a Repeat draft

**Do — browser:** send POST case `repeat-05`, message `repeat me`.
**Do — Terminal B:** select the paused request, record its original TransactionId,
then press **Shift+R** (uppercase `R`) **instead of `c`**. This continues the
original unchanged and opens its retained draft on **3 Repeat**.

**Look before Repeat send:** Terminal A receives the original once; the browser
shows that original response. The Repeat workspace list shows the **source**
TransactionId and state `ready`. Merely creating the draft is not a second send.

**Do — Terminal B:** press `3` if necessary, use `j`/`k` or arrows to select the
workspace, then press **`s`** once. Tab or Ctrl+`j`/Ctrl+`k` cycles through
**Workspaces → Editable request → Latest result**. Use Pretty for the result;
Raw/Hex can be unavailable for these semantic snapshots. Scroll the focused
detail with `j`/`k`, arrows or PageDown/PageUp.

**Look / evidence:** the workspace moves through `sending` to `complete`;
**Latest result** shows the latest HTTP response. To read the new TransactionId,
press **`1`**, select the additional `/lab/post` row in Traffic and check its
`repeat-05` body. Its ID differs from the original ID you recorded. Press **`3`**
to return to the retained workspace and Latest result. The workspace list keeps
the **source** ID; Latest result does not itself display the new transaction ID.
Terminal A records one additional POST with the same case/body. Each Repeat has
fresh SessionId and TransactionId and **does not pause again**. The browser still shows only the
original response, not the Repeat response. `q` returns without deleting drafts;
`d` deletes the selected workspace only when no send is in flight.

<a id="step-10"></a>

<a id="10-compare-a-direct-request-then-restore-the-proxied-path"></a>

<a id="direct-control"></a>

## Compare a direct request, then restore the proxied path

Use the option matching the browser you chose in [dedicated browser setup](../setup/#dedicated-browser).

**Chromium — Terminal C:** open a second disposable profile with an explicit
direct connection. Keep this direct window separate from the proxied window:

```sh
lab_direct_profile="$(mktemp -d /tmp/freja-lab-direct.XXXXXX)"
printf '%s\n' "$lab_direct_profile"
chromium --user-data-dir="$lab_direct_profile" \
  --proxy-server="direct://" http://127.0.0.1:3001/lab &
```

**Firefox — dedicated lab window:** in the same connection settings dialog from
[dedicated browser setup](../setup/#dedicated-browser), select **No proxy** and save (`network.proxy.type` becomes `0`). Keep this
change inside the disposable lab profile; another profile is unnecessary.

**Do / look — direct browser:** send GET case `direct-control`, message `hello`.
Terminal A and this browser can show an HTTP/1.1 echo, but Terminal B has no
matching transaction. **Evidence:** origin success is possible without Freja;
traversal is unverified.

**Restore:** in Chromium, return to the original proxied window. In Firefox,
select Manual proxy configuration again, restore/verify all five preferences
from [dedicated browser setup](../setup/#dedicated-browser) (including `network.proxy.type = 1`), and save. Send a new case
`proxy-again` and repeat [the GET round trip](../first-get/#get-round-trip), including TUI selection and `c`. A new matching TransactionId
confirms the proxied path has been restored. If it cannot be matched, record the
route as unconfirmed and inspect proxy settings. Do not infer a cause solely
from an absent stdout line.
