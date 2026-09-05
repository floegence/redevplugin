import assert from "node:assert/strict";
import { resolve } from "node:path";
import { createBrowserHarnessServer } from "./opaque-surface-server.mjs";

export async function verifyCanvasResize(browser) {
  const styleContent = "body{margin:0}canvas{display:block;width:1200px;height:800px}#second{width:300px;height:200px}";
  const options = {
    workerPath: resolve("testdata/browser-harness/opaque-surface/generated/canvas-worker.js"),
    styleContent,
    prepareDelayMs: 0,
    assetDelayMs: 0,
  };
  const harness = createBrowserHarnessServer(options);
  const hiddenHarness = createBrowserHarnessServer({ ...options, styleContent: styleContent + "canvas{display:none}" });
  const address = await harness.listen(0);
  const hiddenAddress = await hiddenHarness.listen(0);
  const url = `http://127.0.0.1:${address.port}/testdata/browser-harness/opaque-surface/index.html`;
  const pages = [];
  const open = async (initiallyHidden = false) => {
    const page = await browser.newPage({ viewport: { width: 1440, height: 1000 }, deviceScaleFactor: 2 });
    pages.push(page);
    const errors = [];
    page.on("pageerror", (error) => errors.push(error.message));
    await page.goto(initiallyHidden ? url.replace(String(address.port), String(hiddenAddress.port)) : url);
    const iframe = page.locator("#plugin-surface-mount > iframe");
    await iframe.waitFor({ state: "attached" });
    await page.waitForFunction(() => window.__redevpluginHarness.snapshot().status === "ready");
    const frame = await (await iframe.elementHandle()).contentFrame();
    await frame.waitForFunction(() => document.querySelector("#canvas-state"), null, { polling: 25 });
    return { page, frame, iframe, errors };
  };
  const snapshot = (frame) => frame.locator("#canvas-state").evaluate((element) => JSON.parse(element.textContent));
  const ready = (frame, width = 1200) => frame.waitForFunction((width) => {
    const state = JSON.parse(document.querySelector("#canvas-state")?.textContent || "{}");
    return state.canvases?.first?.width === width && state.canvases?.second;
  }, width);
  const noErrors = async ({ page, frame, errors }) => {
    assert.deepEqual(errors, []);
    assert.deepEqual(await page.evaluate(() => window.__redevpluginHarness.snapshot().errors), []);
    assert.equal((await snapshot(frame)).failure, "");
  };
  const lifecycle = async (page, frame, type) => {
    await page.locator(`#send-${type}`).click();
    try {
      await frame.waitForFunction((type) => JSON.parse(document.querySelector("#canvas-state")?.textContent || "{}").lifecycle === type, type, { polling: 25, timeout: 3000 });
    } catch (error) {
      throw new Error(JSON.stringify(await page.evaluate(() => window.__redevpluginHarness.snapshot())), { cause: error });
    }
  };
  try {
    const active = await open();
    await ready(active.frame);
    const firstCanvas = await active.frame.locator("#first").elementHandle();
    const first = (await snapshot(active.frame)).canvases.first;
    assert.deepEqual({ ...first, updates: 0 }, { width: 1200, height: 800, dpr: 2, pixelsWidth: 2400, pixelsHeight: 1600, updates: 0 });
    for (let cycle = 0; cycle < 20; cycle += 1) {
      const before = await snapshot(active.frame);
      await active.page.locator("#plugin-surface-mount").evaluate((mount) => { mount.style.display = "none"; });
      await lifecycle(active.page, active.frame, "hidden");
      assert.deepEqual((await snapshot(active.frame)).canvases, before.canvases, "hidden layout cannot resize either backing store");
      await active.page.locator("#plugin-surface-mount").evaluate((mount) => { mount.style.display = ""; });
      await lifecycle(active.page, active.frame, "visible");
      await ready(active.frame);
      await noErrors(active);
    }
    assert.equal(await active.frame.locator("#first").evaluate((canvas, retained) => canvas === retained, firstCanvas), true);
    // An independently hidden canvas keeps its reservation while its sibling grows.
    await active.frame.locator("#first").evaluate((canvas) => { canvas.style.display = "none"; });
    await active.frame.locator("#second").evaluate((canvas) => { canvas.style.width = "1400px"; canvas.style.height = "900px"; });
    await active.frame.waitForFunction(() => JSON.parse(document.querySelector("#canvas-state").textContent).canvases.second.width === 1400);
    await noErrors(active);
    await active.frame.locator("#first").evaluate((canvas) => { canvas.style.display = ""; canvas.style.width = "1000px"; });
    await ready(active.frame, 1000);
    await noErrors(active);
    await active.frame.locator("#first").screenshot({ path: "dist/a2-evidence/canvas-retained.png" });

    const hidden = await open(true);
    // The fixture's RPC timeout is 1000 ms; a layout wait must survive it.
    await lifecycle(hidden.page, hidden.frame, "hidden");
    await hidden.page.waitForTimeout(1500);
    assert.deepEqual((await snapshot(hidden.frame)).canvases, {});
    await noErrors(hidden);
    await hidden.frame.locator("canvas").evaluateAll((canvases) => { for (const canvas of canvases) canvas.style.display = "block"; });
    await lifecycle(hidden.page, hidden.frame, "visible");
    await ready(hidden.frame);
    await noErrors(hidden);

    const disposed = await open(true);
    await disposed.page.evaluate(() => window.__redevpluginHarness.close());
    await disposed.page.locator("#plugin-surface-mount").evaluate((mount) => { mount.style.display = ""; });
    assert.equal(await disposed.iframe.count(), 0, "pending canvas observers cannot resurrect a disposed surface");

    for (const [width, height, expected] of [[2100, 800, "dimensions"], [2000, 2000, "pixel budget"]]) {
      const oversized = await open();
      await ready(oversized.frame);
      if (expected === "pixel budget") {
        await oversized.frame.locator("#first").evaluate((canvas) => { canvas.style.display = "none"; });
      }
      await oversized.frame.locator("#second").evaluate((canvas, { width, height }) => {
        canvas.style.width = `${width}px`;
        canvas.style.height = `${height}px`;
      }, { width, height });
      await oversized.page.waitForFunction(() => window.__redevpluginHarness.snapshot().errors.length > 0);
      const failures = await oversized.page.evaluate(() => window.__redevpluginHarness.snapshot().errors);
      assert.equal(failures.some((error) => error.message.includes(expected)), true, JSON.stringify(failures));
    }
    console.log("canvas layout/retention/budget browser regressions passed");
  } finally {
    for (const page of pages) await page.close();
    await harness.close();
    await hiddenHarness.close();
  }
}
