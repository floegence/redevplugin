import assert from "node:assert/strict";
import { resolve } from "node:path";
import { createBrowserHarnessServer } from "./opaque-surface-server.mjs";

export async function verifyWebGL(browser) {
  const harness = createBrowserHarnessServer({
    workerPath: resolve("testdata/browser-harness/opaque-surface/generated/webgl-worker.js"),
    styleContent: "canvas{display:block;width:64px;height:64px}",
    prepareDelayMs: 0, assetDelayMs: 0,
  });
  const address = await harness.listen(0);
  const page = await browser.newPage();
  const errors = [];
  page.on("pageerror", error => errors.push(error.message));
  const snapshot = frame => frame.locator("#webgl-state").evaluate(element => JSON.parse(element.textContent));
  const ready = async () => {
    await page.waitForFunction(() => ["ready", "error"].includes(window.__redevpluginHarness.snapshot().status));
    assert.equal(await page.evaluate(() => window.__redevpluginHarness.snapshot().status), "ready", JSON.stringify(await page.evaluate(() => window.__redevpluginHarness.snapshot())));
    const iframe = page.locator("#plugin-surface-mount > iframe");
    assert.equal(await iframe.getAttribute("sandbox"), "allow-scripts");
    const frame = await (await iframe.elementHandle()).contentFrame();
    await frame.waitForFunction(() => {
      const state = JSON.parse(document.querySelector("#webgl-state")?.textContent || "{}");
      return state.failure || state.checks?.constructorHidden;
    });
    const state = await snapshot(frame);
    assert.equal(state.failure, "", JSON.stringify(state));
    for (const [name, value] of Object.entries(state.checks)) assert.equal(value, true, name);
    assert.deepEqual(state.samples.webgl.pixel, [255, 0, 0, 255]);
    assert.deepEqual(state.samples.webgl2.pixel, [0, 255, 0, 255]);
    for (const sample of Object.values(state.samples)) assert.equal(sample.error, 0);
    return frame;
  };
  try {
    await page.goto(`http://127.0.0.1:${address.port}/testdata/browser-harness/opaque-surface/index.html`);
    const frame = await ready();
    await frame.locator("#webgl2").evaluate(canvas => { canvas.style.width = "96px"; });
    await frame.waitForFunction(() => JSON.parse(document.querySelector("#webgl-state").textContent).samples.webgl2.width === 96);
    await frame.locator("#lose").click();
    await frame.waitForFunction(() => { const c = JSON.parse(document.querySelector("#webgl-state").textContent).checks; return c.webglLost && c.webgl2Lost; });
    await frame.locator("#restore").click();
    await frame.waitForFunction(() => Object.values(JSON.parse(document.querySelector("#webgl-state").textContent).samples).every(s => s.restored === 1));
    const restored = await snapshot(frame);
    assert.deepEqual(restored.samples.webgl.pixel, [255, 0, 0, 255]);
    assert.deepEqual(restored.samples.webgl2.pixel, [0, 255, 0, 255]);
    for (const type of ["hidden", "visible"]) {
      await page.locator(`#send-${type}`).click();
      await frame.waitForFunction(type => JSON.parse(document.querySelector("#webgl-state").textContent).lifecycle === type, type);
    }
    await page.evaluate(() => window.__redevpluginHarness.close());
    assert.equal(await page.locator("#plugin-surface-mount > iframe").count(), 0);
    await page.evaluate(() => window.__redevpluginHarness.open());
    await ready();
    assert.deepEqual(errors, []);
    assert.deepEqual(await page.evaluate(() => window.__redevpluginHarness.snapshot().errors), []);
    console.log("WebGL/WebGL2 rendering, budgets, recovery, and reopen regressions passed");
  } finally { await page.close(); await harness.close(); }
}
