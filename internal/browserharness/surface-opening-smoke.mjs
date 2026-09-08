import assert from "node:assert/strict";
import { createBrowserHarnessServer } from "./opaque-surface-server.mjs";

// Exercise the real opaque renderer and worker; a mocked host cannot detect
// browser suppression of animation frames in retained or offscreen containers.
export async function verifySurfaceOpening(browser) {
  const harness = createBrowserHarnessServer({ prepareDelayMs: 50, assetDelayMs: 750 });
  const address = await harness.listen(0);
  const modes = ["offscreen", "visible", "hidden", "zero-size", "hide-during-open", "reveal-during-open", "blocked-raf"];
  try {
    for (const mode of modes) {
      const page = await browser.newPage();
      const errors = [];
      page.on("pageerror", (error) => errors.push(error.message));
      try {
        await page.addInitScript((mode) => {
          globalThis.__openingMessages = [];
          const send = MessagePort.prototype.postMessage;
          MessagePort.prototype.postMessage = function(message, ...args) {
            if (typeof message?.type === "string") globalThis.__openingMessages.push(message.type);
            return send.call(this, message, ...args);
          };
          if (mode === "blocked-raf" && window !== top) {
            globalThis.requestAnimationFrame = () => 1;
            globalThis.cancelAnimationFrame = () => undefined;
          }
        }, mode);
        await page.route("**/host.mjs", async (route) => {
          const response = await route.fetch();
          const setup = `
            const openingMode = ${JSON.stringify(mode)};
            const retainedContainer = surfaceMount.parentElement;
            if (openingMode === 'offscreen') retainedContainer.style.transform = 'translateY(5000px) scale(.35)';
            if (openingMode === 'hidden' || openingMode === 'reveal-during-open') retainedContainer.style.display = 'none';
            if (openingMode === 'zero-size') surfaceMount.style.cssText = 'width:0;height:0;overflow:hidden';
            if (openingMode === 'hide-during-open') setTimeout(() => retainedContainer.style.display = 'none', 10);
            if (openingMode === 'reveal-during-open') setTimeout(() => retainedContainer.style.display = '', 100);
          `;
          await route.fulfill({ response, body: (await response.text()).replace("void openSurface();", `${setup}\nvoid openSurface();`) });
        });
        await page.goto(`http://127.0.0.1:${address.port}/testdata/browser-harness/opaque-surface/index.html`);
        await page.waitForFunction(() => window.__redevpluginHarness?.snapshot().status === "ready", null, { polling: 25, timeout: 4000 });
        const iframe = page.locator("#plugin-surface-mount > iframe");
        const handle = await iframe.elementHandle();
        const frame = await handle.contentFrame();
        const messages = await frame.evaluate(() => globalThis.__openingMessages);
        assert.equal(messages.filter((type) => type === "redevplugin.surface.renderer_ready").length, 1, `${mode}: one renderer readiness`);
        assert.equal(messages.filter((type) => type === "redevplugin.surface.worker_ready").length, 1, `${mode}: one worker readiness`);
        assert.equal(messages.filter((type) => type === "redevplugin.surface.first_commit").length, 1, `${mode}: one real first commit`);
        assert.equal(messages.filter((type) => type === "redevplugin.surface.asset.read").length, 1, `${mode}: one lazy asset read`);
        assert.equal(await iframe.getAttribute("sandbox"), "allow-scripts");
        await page.evaluate(() => {
          const mount = document.querySelector("#plugin-surface-mount");
          mount.style.cssText = "";
          mount.parentElement.style.cssText = "";
        });
        await frame.waitForFunction(() => document.querySelector("#plugin-status")?.textContent === "Ready", null, { polling: 25 });
        assert.equal(await iframe.evaluate((element, original) => element === original, handle), true, `${mode}: reveal retains iframe`);
        assert.deepEqual(await page.evaluate(() => window.__redevpluginHarness.snapshot().errors), [], mode);
        assert.deepEqual(errors, [], mode);
        await page.evaluate(() => window.__redevpluginHarness.close());
        assert.equal(await iframe.count(), 0, `${mode}: close removes iframe`);
      } catch (error) {
        throw new Error(`Surface opening scenario failed: ${mode}`, { cause: error });
      } finally {
        await page.close();
      }
    }
  } finally {
    await harness.close();
  }
}

export async function verifySurfaceOpeningFailures(browser) {
  const harness = createBrowserHarnessServer({ prepareDelayMs: 0, assetDelayMs: 10 });
  const address = await harness.listen(0);
  try {
    for (const milestone of ["frame_load", "prepare", "port_ack", "token", "renderer_ready", "worker_ready", "first_commit", "invalid_initialize"]) {
      const page = await browser.newPage();
      try {
        await page.addInitScript((blocked) => {
          const send = MessagePort.prototype.postMessage;
          MessagePort.prototype.postMessage = function(message, ...args) {
            if (message?.type === `redevplugin.surface.${blocked}`) return;
            if (blocked === "invalid_initialize" && message?.type === "redevplugin.surface.initialize") {
              message = { ...message, document: null };
            }
            return send.call(this, message, ...args);
          };
          if (window !== top) return;
          const fetch = globalThis.fetch;
          globalThis.fetch = (input, init) => {
            const suffix = blocked === "prepare" ? "/prepare" : blocked === "token" ? "/bridge-token" : null;
            if (suffix && String(input).endsWith(suffix)) return new Promise((_resolve, reject) => {
              init.signal.addEventListener("abort", () => reject(new DOMException("Aborted", "AbortError")), { once: true });
            });
            return fetch(input, init);
          };
          if (blocked === "frame_load") {
            const listen = EventTarget.prototype.addEventListener;
            EventTarget.prototype.addEventListener = function(type, ...args) {
              if (this instanceof HTMLIFrameElement && type === "load") return;
              return listen.call(this, type, ...args);
            };
          }
        }, milestone);
        await page.route("**/host.mjs", async (route) => {
          const response = await route.fetch();
          await route.fulfill({ response, body: (await response.text())
            .replace("confirm: confirmDangerousAction,", "loadTimeoutMs: 800, requestTimeoutMs: 2000, confirm: confirmDangerousAction,")
            .replace("message: error.message });", "message: error.message, details: error.details });") });
        });
        await page.goto(`http://127.0.0.1:${address.port}/testdata/browser-harness/opaque-surface/index.html`);
        await page.waitForFunction(() => window.__redevpluginHarness?.snapshot().status === "error", null, { polling: 25, timeout: 4000 });
        const snapshot = await page.evaluate(() => window.__redevpluginHarness.snapshot());
        const failure = snapshot.errors[0];
        if (milestone === "invalid_initialize") {
          assert.equal(failure.error_code, "PLUGIN_BRIDGE_HANDSHAKE_FAILED");
        } else {
          assert.equal(failure.error_code, "PLUGIN_BRIDGE_TIMEOUT", milestone);
          assert.deepEqual(failure.details.pendingMilestones, [milestone], milestone);
          assert.ok(failure.details.elapsedMs >= 750, milestone);
        }
        assert.equal(await page.locator("#plugin-surface-mount > iframe").count(), 0, `${milestone}: no retired iframe`);
        const requests = await page.evaluate(async () => (await (await fetch("/__browser_harness/diagnostics")).json()));
        assert.equal(requests.requests.filter((request) => request.endsWith("/dispose")).length >= 1, true, `${milestone}: exact surface disposed`);
      } finally {
        await page.close();
      }
    }
  } finally {
    await harness.close();
  }
}
