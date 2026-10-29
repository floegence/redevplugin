import { build } from "esbuild";
import { chromium } from "playwright";
import { readFile, writeFile, mkdir } from "node:fs/promises";
import { resolve, join } from "node:path";
import assert from "node:assert/strict";
import { verifyNetworkBoundary } from "./web-network-boundary.mjs";
import { measureWebPerformance } from "./web-performance.mjs";
import { validateWebEvidence } from "../../scripts/verify_web_evidence.mjs";
const root = resolve(import.meta.dirname, "../..");
const source = resolve(root, "testdata/browser-harness/web-application");
if (process.argv[2] === "--build") {
  const files = {};
  for (const entry of ["host", "app"]) {
    const result = await build({ entryPoints: [resolve(source, entry + ".ts")], bundle: true, format: "esm", platform: "browser", target: "es2022", write: false, external: ["./chunk.js"] });
    files[entry + ".js"] = result.outputFiles[0].text;
  }
  for (const file of ["index.html", "plain.html", "chunk.js", "worker.js", "app.css"]) files[file] = await readFile(resolve(source, file), "utf8");
  files["说明.txt"] = "Unicode package resource";
  await writeFile(process.argv[3], JSON.stringify(files));
} else if (process.argv[2] === "--performance") {
  await measureWebPerformance(process.argv[3]);
} else {
  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage();
  const errors = [];
  const evidenceDir = resolve(process.env.REDEVPLUGIN_WEB_EVIDENCE_DIR || "dist/web-evidence");
  await mkdir(evidenceDir, { recursive: true });
  page.on("pageerror", e => { errors.push(e.message); console.error("pageerror", e.message); });
  page.on("console", m => { if (m.type() === "error") console.error(m.text()); });
  page.on("response", r => { if (r.status() >= 400) console.error("HTTP", r.status(), r.url()); });
  try {
    await page.goto(process.argv[3]);
    await page.waitForFunction(() => globalThis.testState?.ready || globalThis.testState?.error);
    assert.equal(await page.evaluate(() => globalThis.testState.error), "");
    const frames = page.frames().filter(f => f !== page.mainFrame());
    assert.equal(frames.length, 2);
    assert.equal(await page.evaluate(() => globalThis.testState.prepared.length), 2);
    for (const frame of frames) await frame.waitForFunction(() => globalThis.appState?.ready);
    const state = await frames[0].evaluate(() => globalThis.appState);
    assert.deepEqual(state.nativeNetwork, { uri: "/signed%2fpath?q=%2f", method: "GET" });
    assert.equal(state.firstChunk, "first"); assert.equal(state.streamCanceled, true); assert.equal(state.remoteScriptDenied, true);
    assert.equal(state.networkHeaders.challenge, null); assert.equal(state.networkHeaders.cookie, null);
    assert.ok(state.networkHeaders.csp.includes("connect-src 'self'"));
    assert.equal(state.unicode, "Unicode package resource");
    assert.equal(state.chunk, "native chunk"); assert.equal(state.worker, "native chunk worker");
    assert.deepEqual(state.pixel, [18,52,86,255]); assert.equal(state.wasm, true); assert.equal(state.webgl, true); assert.equal(state.indexedDB, true);
    assert.equal(state.parentBlocked, true); assert.equal(state.cookie, ""); assert.equal(state.storage, "isolated");
    assert.notEqual(new URL(frames[0].url()).origin, new URL(frames[1].url()).origin);
    await frames[0].locator("input").fill("中文 native selection"); await frames[0].getByRole("button", { name: "Apply", exact: true }).click();
    assert.equal(await frames[0].locator("output").textContent(), "中文 native selection");
    assert.equal(new URL(frames[0].url()).pathname, "/notes/current");
    const input = frames[0].locator("input");
    await input.fill("native"); await input.focus(); await input.press("End"); await input.pressSequentially(" editing");
    await input.press(process.platform === "darwin" ? "Meta+z" : "Control+z");
    assert.equal(await input.inputValue(), "native");
    await input.evaluate(element => element.setSelectionRange(1, 4));
    assert.deepEqual(await input.evaluate(element => [element.selectionStart, element.selectionEnd]), [1, 4]);
    await frames[0].getByRole("button", { name: "Open file", exact: true }).click();
    await frames[0].getByRole("status").filter({ hasText: /^Opened$/ }).waitFor();
    assert.equal(await frames[0].getByLabel("Selected document").inputValue(), "Existing document");
    await frames[0].getByLabel("Selected document").fill("Saved 中文 document");
    await frames[0].getByRole("button", { name: "Save file", exact: true }).click();
    await frames[0].getByRole("status").filter({ hasText: /^Saved$/ }).waitFor();
    assert.equal(await frames[1].getByLabel("Selected document").inputValue(), "");
    const originalOrigin = new URL(frames[0].url()).origin;
    await frames[0].evaluate(() => location.reload());
    await frames[0].waitForFunction(() => globalThis.appState?.ready);
    assert.equal(new URL(frames[0].url()).origin, originalOrigin);
    assert.equal(new URL(frames[0].url()).pathname, "/notes/current");
    assert.equal(await frames[0].evaluate(() => localStorage.getItem("sample")), "isolated");
    assert.equal(await page.evaluate(() => globalThis.testState.error), "");
    assert.equal(await page.evaluate(() => globalThis.testState.prepared.length), 2, "reload must retain the exact product route");
    await page.screenshot({ path: join(evidenceDir, "web-supported.png"), fullPage: true });
    const blocked = await frames[0].evaluate(async () => {
      let network = false, sw = false;
      try { await fetch("https://example.com/"); } catch { network = true; }
      try { await navigator.serviceWorker.register("/worker.js"); } catch { sw = true; }
      return { network, sw };
    });
    assert.deepEqual(blocked, { network: true, sw: true });
    assert.equal(await page.evaluate(() => globalThis.testSlots[0].requestClose()), undefined);
    assert.equal(await page.locator("iframe").count(), 2);
    await frames[0].evaluate(() => { globalThis.appState.unsaved = false; });
    const close = await page.evaluate(() => globalThis.testSlots[0].requestClose());
    assert.equal(close.quiesce.outcome, "acknowledged");
    assert.equal(await frames[1].locator("input").inputValue(), "native");
    await page.evaluate(() => globalThis.testSlots[1].close());
    await page.waitForFunction(() => globalThis.testState.released.length === 2);
    for (const mode of ["hidden", "zero-size", "offscreen", "blocked-raf"]) {
      const check = await browser.newPage();
      try {
        if (mode === "blocked-raf") await check.addInitScript(() => { if (window !== top) { requestAnimationFrame = () => 1; cancelAnimationFrame = () => {}; } });
        await check.goto(process.argv[3] + "?mode=" + mode);
        await check.waitForFunction(() => globalThis.testState?.ready || globalThis.testState?.error, null, { polling: 25, timeout: 10000 });
        assert.equal(await check.evaluate(() => globalThis.testState.error), "", mode);
        assert.equal(await check.locator("iframe").count(), 2);
        await check.evaluate(async () => { for (const slot of globalThis.testSlots) await slot.close(); });
      } finally { await check.close(); }
    }
    const plain = await browser.newPage();
    try {
      await plain.goto(process.argv[3] + "?mode=plain");
      await plain.waitForFunction(() => globalThis.testState?.ready || globalThis.testState?.error);
      assert.equal(await plain.evaluate(() => globalThis.testState.error), "");
      const application = plain.frames().find(frame => frame !== plain.mainFrame());
      await application.locator("input").fill("No application SDK required");
      assert.equal(await application.locator("output").textContent(), "No application SDK required");
      const close = await plain.evaluate(() => globalThis.testSlots[0].requestClose());
      assert.equal(close.quiesce.outcome, "acknowledged");
      await plain.evaluate(() => globalThis.testSlots[1].close());
    } finally { await plain.close(); }
    const unsupported = await browser.newPage();
    try {
      let applicationRequests = 0;
      unsupported.on("request", request => { if (new URL(request.url()).pathname === "/app.js") applicationRequests++; });
      await unsupported.route("**/*", async route => {
        const url = new URL(route.request().url());
        if (!url.hostname.endsWith(".localhost")) { await route.continue(); return; }
        const response = await route.fetch({ maxRedirects: 0 });
        const headers = { ...response.headers() }; delete headers["connection-allowlist"];
        await route.fulfill({ response, headers });
      });
      await unsupported.goto(process.argv[3]);
      await unsupported.waitForFunction(() => globalThis.testState?.error);
      assert.match(await unsupported.evaluate(() => globalThis.testState.error), /browser cannot isolate application network access/u);
      assert.equal(applicationRequests, 0);
      assert.equal(await unsupported.locator("iframe").count(), 0);
      await unsupported.screenshot({ path: join(evidenceDir, "web-unsupported.png") });
    } finally { await unsupported.close(); }
    await verifyNetworkBoundary(browser, process.argv[3]);
    const report = { schema_version: "redevplugin.web_acceptance.v1", evidence_source: "go-host-http-adapter-chromium", browser: browser.version(), checks: { origin_preparation: true, native_modules: true, dynamic_import: true, worker: true, canvas: true, webgl: true, wasm: true, indexeddb: true, native_input_undo_selection: true, independent_origins: true, parent_isolation: true, network_denied: true, receiver_network_boundary: true, service_worker_denied: true, quiesce_acknowledged: true, unsaved_close_protected: true, native_navigation: true, independent_close: true, retained_container_opening: true, unsupported_before_application: true } };
    validateWebEvidence(report);
    await writeFile(join(evidenceDir, "web-acceptance.json"), JSON.stringify(report, null, 2) + "\n");
    assert.deepEqual(errors, []);
    console.log(JSON.stringify({ browser: browser.version(), nativeApplication: state, blocked, independentClose: true }));
  } finally { await browser.close(); }
}
