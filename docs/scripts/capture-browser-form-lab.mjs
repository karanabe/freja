// Regenerate the shared documentation image from the actual local fixture.
// Requires the example binary and its pinned Playwright/Chromium installation.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdir } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';

const example = new URL('../../examples/http-test-server/', import.meta.url);
const { chromium } = createRequire(new URL('package.json', example))('playwright');
const binary = fileURLToPath(new URL(`target/debug/freja-http-test-server${process.platform === 'win32' ? '.exe' : ''}`, example));
const output = new URL('../public/images/browser-form-lab/get-ready.png', import.meta.url);
const origin = spawn(binary, ['--bind', '127.0.0.1:0'], { stdio: ['ignore', 'pipe', 'pipe'] });
const exited = new Promise(resolve => origin.once('close', resolve));
let browser;
try {
  const address = await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('Origin startup timed out')), 10000);
    let output = '';
    origin.once('error', error => { clearTimeout(timer); reject(error); });
    origin.once('exit', code => { clearTimeout(timer); reject(new Error(`Origin exited: ${code}`)); });
    origin.stderr.on('data', data => { output = (output + data).slice(-65536); });
    origin.stdout.on('data', data => {
      output = (output + data).slice(-65536);
      const match = output.match(/listening on (http:\/\/127\.0\.0\.1:\d+)/);
      if (match) { clearTimeout(timer); resolve(match[1]); }
    });
  });
  browser = await chromium.launch();
  const context = await browser.newContext({
    viewport: { width: 1100, height: 2400 }, deviceScaleFactor: 1,
    locale: 'en-US', colorScheme: 'light', reducedMotion: 'reduce',
  });
  await context.route('**/*', route => {
    if (new URL(route.request().url()).origin === address) return route.continue();
    return route.abort();
  });
  const page = await context.newPage();
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  await page.goto(address + '/lab');
  await page.waitForFunction(() => !document.getElementById('inputs').disabled);
  await page.locator('#method').selectOption('GET');
  await page.locator('#case').fill('get-01');
  await page.locator('#message').fill('hello origin');
  // Real keyboard focus identifies the Send button, without altering the DOM.
  await page.keyboard.press('Tab');
  assert.equal(await page.locator('#send').evaluate(el => el === document.activeElement), true);
  assert.equal(await page.locator('#sent').textContent(), 'No submission.');
  assert.match(await page.locator('#preview').textContent(), /case=get-01&message=hello\+origin/);
  await page.evaluate(() => document.fonts.ready);
  const input = await page.locator('section[aria-labelledby="input-title"]').boundingBox();
  const result = await page.locator('section[aria-labelledby="result-title"]').boundingBox();
  assert.ok(input && result);
  assert.deepEqual(errors, []);
  await mkdir(new URL('.', output), { recursive: true });
  await page.screenshot({
    path: fileURLToPath(output), animations: 'disabled',
    clip: { x: input.x, y: input.y, width: input.width, height: result.y + result.height - input.y },
  });
  console.log(`Captured actual unsent GET form with Chromium ${browser.version()}: ${fileURLToPath(output)}`);
} finally {
  await browser?.close();
  if (origin.pid !== undefined && origin.exitCode === null && origin.signalCode === null) {
    origin.kill();
    const timer = setTimeout(() => origin.kill('SIGKILL'), 5000);
    await exited;
    clearTimeout(timer);
  }
}
