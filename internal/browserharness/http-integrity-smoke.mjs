import assert from "node:assert/strict";
import { networkInterfaces } from "node:os";
import { chromium } from "playwright";
import { createBrowserHarnessServer } from "./opaque-surface-server.mjs";

const network = Object.values(networkInterfaces()).flat().find((entry) => entry?.family === "IPv4" && !entry.internal);
if (!network) throw new Error("HTTP integrity smoke requires a network interface for a real insecure browser origin");
const browser = await chromium.launch({ headless: true });
try {
  for (const corruptAsset of [false, true]) {
    const harness = createBrowserHarnessServer({ corruptAsset, prepareDelayMs: 0, assetDelayMs: 50 });
    const address = await harness.listen(0, network.address);
    const page = await browser.newPage();
    const errors = [];
    page.on("pageerror", (error) => errors.push(error.message));
    page.on("console", (message) => { if (message.type() === "error") errors.push(message.text()); });
    try {
      await page.goto(`http://${network.address}:${address.port}/testdata/browser-harness/opaque-surface/index.html`, { waitUntil: "domcontentloaded" });
      assert.deepEqual(await page.evaluate(() => ({ secure: isSecureContext, subtle: typeof crypto.subtle, random: typeof crypto.getRandomValues })), { secure: false, subtle: "undefined", random: "function" });
      if (corruptAsset) {
        await page.waitForFunction(() => window.__redevpluginHarness?.snapshot().errors.length > 0);
        const errors = await page.evaluate(() => window.__redevpluginHarness.snapshot().errors);
        assert.match(JSON.stringify(errors), /renderer validation/);
      } else {
        await page.waitForFunction(() => window.__redevpluginHarness?.snapshot().status === "ready");
        const frame = await (await page.locator("#plugin-frame").elementHandle()).contentFrame();
        await frame.waitForSelector("#plugin-status");
        assert.equal(await frame.evaluate(() => typeof crypto.subtle), "undefined");
        await frame.waitForFunction(() => document.documentElement.style.getPropertyValue("--redevplugin-asset-asset_harness_lazy_1").startsWith('url("blob:'));
        const width = await frame.evaluate(async () => {
          const value = document.documentElement.style.getPropertyValue("--redevplugin-asset-asset_harness_lazy_1");
          const image = new Image();
          image.src = value.slice(5, -2);
          await image.decode();
          return image.naturalWidth;
        });
        assert.equal(width, 1);
        assert.deepEqual(await page.evaluate(() => window.__redevpluginHarness.snapshot().errors), []);
        await page.evaluate(() => window.__redevpluginHarness.close());
        assert.equal(await page.evaluate(() => window.__redevpluginHarness.snapshot().status), "disposed");
      }
      console.log(`HTTP plugin integrity passed: tampered=${corruptAsset}, origin=http://${network.address}:${address.port}`);
    } catch (error) {
      console.error(JSON.stringify({ errors, snapshot: await page.evaluate(() => window.__redevpluginHarness?.snapshot()), diagnostics: harness.diagnostics }));
      throw error;
    } finally {
      await page.close();
      await harness.close();
    }
  }
} finally {
  await browser.close();
}
