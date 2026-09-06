// Real Chromium + the local Axum origin. Network failure/delay cases are
// explicitly simulated here; freja_form.rs exercises the real proxy broker.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright";

async function startOrigin() {
  const binary = fileURLToPath(new URL(`../target/debug/freja-http-test-server${process.platform === "win32" ? ".exe" : ""}`, import.meta.url));
  const child = spawn(binary, ["--bind", "127.0.0.1:0"], { stdio: ["ignore", "pipe", "pipe"] });
  let output = "";
  const address = await new Promise((resolve, reject) => {
    const timer = setTimeout(() => { child.kill(); reject(new Error("Origin startup timed out")); }, 10000);
    child.on("error", error => { clearTimeout(timer); reject(error); });
    child.on("exit", code => { clearTimeout(timer); reject(new Error(`Origin exited: ${code}`)); });
    child.stderr.on("data", data => { output = (output + data).slice(-65536); });
    child.stdout.on("data", data => {
      output = (output + data).slice(-65536);
      const match = output.match(/listening on (http:\/\/127\.0\.0\.1:\d+)/);
      if (match) { clearTimeout(timer); resolve(match[1]); }
    });
  });
  return { child, address };
}

async function completed(page) {
  await page.waitForFunction(() => !document.getElementById("again").disabled);
}
async function fill(page, method, label, message) {
  await page.locator("#method").selectOption(method);
  await page.getByLabel("Case label").fill(label);
  await page.getByLabel("Message", { exact: false }).fill(message);
}

await test("browser form lab", { timeout: 90000 }, async t => {
  const origin = await startOrigin();
  let browser;
  try {
    browser = await chromium.launch();
    async function scenario(name, run) {
      await t.test(name, async () => {
        const context = await browser.newContext();
        const page = await context.newPage();
        const errors = [];
        page.on("pageerror", error => errors.push(error.message));
        try {
          await page.goto(origin.address + "/lab");
          await page.waitForFunction(() => !document.getElementById("inputs").disabled);
          await run(page);
          assert.deepEqual(errors, []);
        } finally { await context.close(); }
      });
    }
    await scenario("GET/POST encoding, empty values and deliberate re-entry", async page => {
      for (const method of ["GET", "POST"]) {
        for (const message of ["hello", "", " ", "日本語 &=+"]) {
          await fill(page, method, "browser-01", message);
          const encoding = new URLSearchParams({ case: "browser-01", message }).toString();
          assert.ok((await page.locator("#preview").textContent()).includes(encoding));
          const requestPromise = page.waitForRequest(request => request.url().includes("/lab/" + method.toLowerCase()));
          await page.locator("#send").click();
          const request = await requestPromise;
          assert.equal(request.method(), method);
          if (method === "POST") assert.equal(request.postData(), encoding);
          else assert.equal(new URL(request.url()).search.slice(1), encoding);
          await completed(page);
          const result = JSON.parse(await page.locator("#result").textContent());
          assert.equal(result.interpretation.message, message);
          assert.equal(result.http_version, "HTTP/1.1");
          assert.match(await page.locator("#status").textContent(), /unverified/);
          assert.equal(page.url(), origin.address + "/lab");
          await page.locator("#again").click();
          assert.equal(await page.locator("#case").evaluate(element => element === document.activeElement), true);
          assert.equal(await page.locator("#message").inputValue(), message);
        }
      }
    });
    await scenario("UTF-8 byte limit blocks sending; keyboard and clear allow the next input", async page => {
      let sends = 0;
      page.on("request", request => { if (request.url().includes("/lab/get?")) sends++; });
      await fill(page, "GET", "limit", "界".repeat(86));
      await page.locator("#send").click();
      assert.equal(sends, 0);
      assert.match(await page.locator("#validation").textContent(), /256 UTF-8 bytes/);
      await page.locator("#clear").click();
      assert.equal(await page.locator("#message").inputValue(), "");
      await page.locator("#case").focus();
      await page.keyboard.press("Enter");
      await completed(page);
      assert.equal(sends, 1);
      assert.equal(JSON.parse(await page.locator("#result").textContent()).interpretation.message, "");
    });
    await scenario("markup stays text; the form fits narrow and dark views", async page => {
      let dialogs = 0;
      page.on("dialog", async dialog => { dialogs++; await dialog.dismiss(); });
      const text = '</pre><img src=x onerror=alert(1)><script>alert(2)</script>界\u001b\u061c\u200f\u202e';
      await fill(page, "POST", "markup", text);
      await page.locator("#send").click();
      await completed(page);
      assert.equal(JSON.parse(await page.locator("#result").textContent()).interpretation.message, text);
      const displayed = await page.locator("#result").textContent();
      for (const character of ["\u001b", "\u061c", "\u200f", "\u202e"]) {
        assert.equal(displayed.includes(character), false);
        assert.ok(displayed.includes("\\u" + character.charCodeAt(0).toString(16).padStart(4, "0")));
      }
      assert.equal(await page.locator("#result img, #result script").count(), 0);
      assert.equal(dialogs, 0);
      for (const colorScheme of ["light", "dark"]) {
        await page.emulateMedia({ colorScheme });
        await page.setViewportSize({ width: 390, height: 844 });
        assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth), true);
      }
    });
    await scenario("an edited non-form body shows actual bytes and an interpretation error", async page => {
      await page.route("**/lab/post", route => route.continue({ postData: "edited plain text" }));
      await fill(page, "POST", "before-edit", "original");
      await page.locator("#send").click();
      await completed(page);
      const result = JSON.parse(await page.locator("#result").textContent());
      assert.equal(result.received.body.utf8, "edited plain text");
      assert.equal(result.interpretation.kind, "unavailable");
      assert.match(await page.locator("#sent").textContent(), /original/);
      assert.match(await page.locator("#status").textContent(), /Origin reports receipt \(HTTP 400/);
    });
    await scenario("proxy-style reject is displayed safely and re-entry never retries", async page => {
      let sends = 0;
      await page.route("**/lab/post", async route => {
        sends++;
        await route.fulfill({ status: 403, contentType: "text/plain", body: "rejected by operator\n<script>bad()</script>" });
      });
      await fill(page, "POST", "reject-01", "unchanged");
      await page.locator("#send").click();
      await completed(page);
      assert.match(await page.locator("#status").textContent(), /status alone cannot identify/);
      assert.equal(await page.locator("#result script").count(), 0);
      await page.locator("#again").click();
      assert.equal(sends, 1);
      await page.unroute("**/lab/post");
      await fill(page, "POST", "after-reject", "new");
      await page.locator("#send").click();
      await completed(page);
      assert.equal(JSON.parse(await page.locator("#result").textContent()).interpretation.case, "after-reject");
    });
    await scenario("network failure preserves input and reports unknown arrival", async page => {
      let sends = 0;
      await page.route("**/lab/post", route => { sends++; return route.abort("connectionrefused"); });
      await fill(page, "POST", "network", "keep me");
      await page.locator("#send").click();
      await completed(page);
      assert.match(await page.locator("#status").textContent(), /arrival is unknown/);
      await page.locator("#again").click();
      assert.equal(await page.locator("#message").inputValue(), "keep me");
      assert.equal(sends, 1);
    });
    await scenario("pending attempt clears old evidence and wait expiry does not retry", async page => {
      await fill(page, "POST", "first", "arrived");
      await page.locator("#send").click();
      await completed(page);
      await page.clock.install();
      let sends = 0;
      await page.route("**/lab/post", () => { sends++; /* Simulated nonresponding path. */ });
      await fill(page, "POST", "pending", "wait");
      await page.locator("#send").click();
      assert.match(await page.locator("#result").textContent(), /Previous response cleared/);
      assert.equal(await page.locator("#send").isDisabled(), true);
      await page.evaluate(() => document.getElementById("lab-form").requestSubmit());
      await page.clock.fastForward(45001);
      await completed(page);
      assert.match(await page.locator("#status").textContent(), /45 seconds.*unknown/);
      assert.equal(sends, 1);
      assert.equal(await page.locator("#message").inputValue(), "wait");
    });
    await scenario("oversized response stops at the display budget", async page => {
      await page.route("**/lab/post", route => route.fulfill({ status: 200, contentType: "text/plain", body: "x".repeat(65537) }));
      await fill(page, "POST", "large-response", "x");
      await page.locator("#send").click();
      await completed(page);
      assert.match(await page.locator("#result").textContent(), /64 KiB display limit/);
      assert.match(await page.locator("#status").textContent(), /arrival is unknown/);
    });
    await scenario("JSON display expansion respects the UTF-8 byte budget", async page => {
      const body = JSON.stringify(Array(9000).fill("界"));
      assert.ok(new TextEncoder().encode(body).length < 65536);
      await page.route("**/lab/post", route => route.fulfill({ status: 200, contentType: "application/json", body }));
      await fill(page, "POST", "expanded-display", "x");
      await page.locator("#send").click();
      await completed(page);
      const displayed = await page.locator("#result").textContent();
      assert.match(displayed, /Display shortened to 64 KiB; suffix omitted/);
      assert.ok(new TextEncoder().encode(displayed).length <= 65536);
      assert.equal(displayed.includes("\ufffd"), false);
    });
  } finally {
    if (browser) await browser.close();
    const exited = new Promise(resolve => origin.child.once("exit", resolve));
    origin.child.kill();
    await exited;
  }
});
