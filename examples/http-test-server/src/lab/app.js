"use strict";

const form = document.getElementById("lab-form");
const inputs = document.getElementById("inputs");
const method = document.getElementById("method");
const caseInput = document.getElementById("case");
const message = document.getElementById("message");
const statusLine = document.getElementById("status");
const result = document.getElementById("result");
const again = document.getElementById("again");
const encoder = new TextEncoder();
const maximumResponseBytes = 64 * 1024;
let pending = false;

// Dynamic data only enters textContent. Escape directional/control characters
// as visible data too; never turn an origin or proxy response into HTML.
function visible(text) {
  return text.replace(/[\u0000-\u0008\u000b-\u001f\u007f-\u009f\u061c\u200e-\u200f\u202a-\u202e\u2066-\u2069]/g,
    character => "\\u" + character.charCodeAt(0).toString(16).padStart(4, "0"));
}

function prepared() {
  return new URLSearchParams({ case: caseInput.value, message: message.value }).toString();
}

function updatePreview() {
  const size = encoder.encode(message.value).length;
  message.setCustomValidity(size > 256 ? "Message must be at most 256 UTF-8 bytes." : "");
  document.getElementById("byte-count").textContent = `${size} / 256 UTF-8 bytes`;
  document.getElementById("validation").textContent = message.validationMessage;
  document.getElementById("send").textContent = method.value === "POST" ? "Send POST body" : "Send GET query";
  document.getElementById("preview").textContent = describe(prepared());
}

function describe(encoded) {
  return method.value === "POST"
    ? `POST /lab/post\nContent-Type: application/x-www-form-urlencoded\n\n${encoded}`
    : `GET /lab/get?${encoded}\n(empty body)`;
}

async function readBounded(response) {
  if (!response.body) return "";
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let size = 0;
  let text = "";
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) return text + decoder.decode();
      size += value.byteLength;
      if (size > maximumResponseBytes) {
        await reader.cancel();
        throw new Error("Response exceeds the 64 KiB display limit; arrival needs terminal confirmation.");
      }
      text += decoder.decode(value, { stream: true });
    }
  } finally {
    reader.releaseLock();
  }
}

form.addEventListener("input", updatePreview);
method.addEventListener("change", updatePreview);
document.getElementById("clear").addEventListener("click", () => {
  message.value = "";
  updatePreview();
  message.focus();
});
again.addEventListener("click", () => {
  caseInput.focus();
  caseInput.select();
  statusLine.textContent = "Ready to re-enter. Nothing has been sent again; the result below belongs to the last attempt.";
});
form.addEventListener("submit", async event => {
  event.preventDefault();
  if (pending) return;
  updatePreview();
  if (!form.reportValidity()) return;
  const encoded = prepared();
  if (encoder.encode(encoded).length > 2048) {
    statusLine.textContent = "Not sent: encoded input exceeds 2 KiB. Shorten the message.";
    return;
  }
  const post = method.value === "POST";
  // Both paths are fixed and relative to this page's origin. Redirects are
  // deliberately not followed and there is no general URL/method input.
  const path = post ? "/lab/post" : "/lab/get?" + encoded;
  document.getElementById("sent").textContent = describe(encoded);
  pending = true;
  inputs.disabled = true;
  again.disabled = true;
  result.textContent = "No response for this attempt yet. Previous response cleared.";
  statusLine.textContent = "Sent; waiting for a response. Check Freja for a paused HTTP/1.1 transaction, then continue, edit or reject. Origin arrival is not yet confirmed.";
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 45000);
  try {
    const response = await fetch(path, {
      method: post ? "POST" : "GET",
      headers: post ? { "Content-Type": "application/x-www-form-urlencoded" } : {},
      body: post ? encoded : undefined,
      credentials: "omit",
      cache: "no-store",
      redirect: "error",
      signal: controller.signal,
    });
    const text = await readBounded(response);
    let receipt;
    try { receipt = JSON.parse(text); } catch { /* A proxy error may be plain text. */ }
    const display = receipt === undefined ? text : JSON.stringify(receipt, null, 2);
    // Pretty-printing can expand JSON, so apply the display limit separately.
    const displayBytes = encoder.encode(visible(display));
    const omission = "\n[Display shortened to 64 KiB; suffix omitted]";
    result.textContent = displayBytes.length <= maximumResponseBytes
      ? visible(display)
      : new TextDecoder().decode(displayBytes.subarray(0, maximumResponseBytes - omission.length), { stream: true }) + omission;
    statusLine.textContent = receipt?.lab === "http11-browser-form"
      ? `Origin reports receipt (HTTP ${response.status}, ${receipt.http_version}). ${response.ok ? "Compare received bytes and interpreted fields." : "Form interpretation failed; received bytes are still the evidence."} Freja traversal remains unverified until you match its TransactionId in the TUI.`
      : `HTTP ${response.status} response received. Its status alone cannot identify reject, timeout or origin arrival. Compare Freja and origin terminals; no automatic retry.`;
  } catch (error) {
    statusLine.textContent = controller.signal.aborted
      ? "Stopped waiting after 45 seconds. Origin arrival is unknown; check both terminals before explicitly sending again. No automatic retry."
      : "Response unavailable. Origin arrival is unknown; check the proxy and origin terminals. No automatic retry.";
    result.textContent = visible(String(error)).slice(0, 1024);
  } finally {
    clearTimeout(timer);
    pending = false;
    inputs.disabled = false;
    again.disabled = false;
  }
});
inputs.disabled = false;
updatePreview();
statusLine.textContent = "Not sent. Prepare a case and check the browser proxy path in Freja.";
