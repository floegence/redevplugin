import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { inflateSync } from "node:zlib";
import { chromium } from "playwright";
import { isExpectedSandboxConsoleLine } from "./smoke-console-policy.mjs";

const baseURL = process.env.REDEVPLUGIN_EXAMPLES_URL;
if (!baseURL) throw new Error("REDEVPLUGIN_EXAMPLES_URL is required");
const evidenceDir = resolve(process.env.REDEVPLUGIN_EXAMPLES_EVIDENCE_DIR || "dist/examples-evidence");
await mkdir(evidenceDir, { recursive: true });

const browser = await chromium.launch({ headless: true });
const desktop = await browser.newPage({ viewport: { width: 1280, height: 800 }, deviceScaleFactor: 1 });
const consoleLines = [];
const pageErrors = [];
const apiFailureReads = [];
const methodCalls = [];
const methodResults = [];
desktop.on("console", (message) => consoleLines.push(`${message.type()}: ${message.text()}`));
desktop.on("pageerror", (error) => pageErrors.push(error.message));
desktop.on("request", (request) => {
  if (!request.url().includes("/_redevplugin/api/plugins/rpc")) return;
  methodCalls.push(request.postData() || "");
});
desktop.on("response", (response) => {
  if (response.url().includes("/_redevplugin/api/plugins/rpc")) {
    const method = response.request().postDataJSON()?.method;
    methodResults.push(response.json().then((body) => ({ method, body })).catch(() => ({ method, body: undefined })));
  }
  if (response.url().startsWith(baseURL) && response.status() >= 500) {
    apiFailureReads.push(response.text().then((body) => `${response.status()} ${response.url()} ${body}`).catch(() => `${response.status()} ${response.url()}`));
  }
});

try {
  await desktop.goto(baseURL, { waitUntil: "domcontentloaded" });
  assert.equal(await desktop.title(), "ReDevPlugin Examples");
  await desktop.locator(".runtime-status[data-ready=\"true\"]").waitFor({ state: "attached", timeout: 30_000 });
  assert.equal(await desktop.locator(".workspace > .surface-stage").count(), 1, "the Showcase must expose one uninterrupted app surface");
  assert.equal(await desktop.locator(".workspace > header").count(), 0, "the Showcase must not add a top-level app header");
  const showcaseIcons = await desktop.locator("#plugin-list .plugin-nav img").evaluateAll((images) => images.map((image) => ({
    src: image.getAttribute("src") || "",
    width: image.naturalWidth,
    height: image.naturalHeight,
  })));
  assert.equal(showcaseIcons.length, 3);
  for (const icon of showcaseIcons) {
    assert.match(icon.src, /-v2\.webp$/);
    assert.equal(icon.width >= 256 && icon.height >= 256, true, `consumer icon dimensions = ${JSON.stringify(icon)}`);
  }
  await assertNoHorizontalOverflow(desktop);
  await desktop.locator("#inspector-toggle").click();
  await desktop.locator('#plugin-inspector[data-open="true"]').waitFor();
  assert.equal(await desktop.locator("#plugin-inspector").getAttribute("aria-hidden"), "false");
  await desktop.locator("#inspector-close").click();
  await desktop.locator('#plugin-inspector[data-open="false"]').waitFor();
  assert.equal(await desktop.locator("#plugin-inspector").getAttribute("aria-hidden"), "true");

  let memos = await pluginFrame(desktop, "Memos");
  const explorerStyle = await waitForComputedStyles(
    memos.locator(".memos-explorer"),
    ["backgroundColor", "width"],
    (style) => style.backgroundColor === "rgb(238, 240, 243)" && style.width === "256px",
    "stable Memos explorer styles",
  );
  assert.deepEqual(explorerStyle, { backgroundColor: "rgb(238, 240, 243)", width: "256px" });
  await memos.locator(".memo-composer").waitFor();
  assert.equal(await memos.locator(".memo-feed .memo-card").count(), 0, "an empty timeline must keep the composer usable");
  const composer = memos.getByPlaceholder("What's on your mind?");
  await composer.fill("# Smoke timeline memo\n\n- [ ] verify task writeback\n\n#smoke");
  await memos.getByText("Draft pending", { exact: true }).waitFor();
  await memos.getByText("Draft protected", { exact: true }).waitFor({ timeout: 10_000 });

  await desktop.reload({ waitUntil: "domcontentloaded" });
  memos = await pluginFrame(desktop, "Memos");
  await memos.getByText("Draft protected", { exact: true }).waitFor({ timeout: 10_000 });
  assert.equal(await memos.getByPlaceholder("What's on your mind?").inputValue(), "# Smoke timeline memo\n\n- [ ] verify task writeback\n\n#smoke", "safe draft must survive a full reload");
  await memos.getByRole("button", { name: "Save", exact: true }).click();
  await memos.getByText("Memo published", { exact: true }).waitFor();
  assert.equal(await memos.getByPlaceholder("What's on your mind?").inputValue(), "", "publish trigger must clear the composer draft");
  const smokeCard = () => memos.locator(".memo-card").filter({ hasText: "Smoke timeline memo" });
  await smokeCard().waitFor();
  await smokeCard().getByRole("heading", { name: "Smoke timeline memo" }).waitFor();
  const task = smokeCard().getByRole("checkbox");
  await task.check();
  await waitFor(async () => await task.isChecked(), 5_000, "Markdown task writeback");
  const pinMemo = smokeCard().getByRole("button", { name: "Pin memo" });
  await waitFor(async () => await pinMemo.isEnabled(), 5_000, "memo actions after task update");
  await pinMemo.click();
  await smokeCard().getByRole("button", { name: "Unpin memo" }).waitFor();

  await smokeCard().getByRole("button", { name: "More memo actions" }).click();
  await smokeCard().getByRole("menuitem", { name: "Edit" }).click();
  const activeEditCard = memos.locator(".memo-card.editing");
  const editContent = activeEditCard.getByRole("textbox", { name: "Edit memo content" });
  await editContent.fill("## Edited timeline memo\n\n- [x] shipped\n\n| Area | State |\n| --- | --- |\n| Draft | Safe |\n\n<script>alert('blocked')</script>\n\n[Reference](https://example.com) #smoke");
  await activeEditCard.getByText("Unsaved", { exact: true }).waitFor();
  await activeEditCard.getByText("Saved", { exact: true }).waitFor({ timeout: 10_000 });
  await activeEditCard.getByRole("button", { name: "Done" }).click();
  const editedCard = () => memos.locator(".memo-card").filter({ hasText: "Edited timeline memo" });
  await editedCard().locator("table").waitFor();
  assert.equal(await editedCard().locator("a, img, script").count(), 0, "Markdown must not create arbitrary links, images, or raw HTML elements");
  await editedCard().getByText("<script>alert('blocked')</script>", { exact: true }).waitFor();

  const listCallsBeforeSearch = methodCalls.filter((body) => body.includes('"method":"memos.list"')).length;
  await memos.getByPlaceholder("Search memos").fill("Edited timeline");
  await waitFor(() => methodCalls.filter((body) => body.includes('"method":"memos.list"')).length > listCallsBeforeSearch, 5_000, "debounced Memos search call");
  await editedCard().waitFor();
  let releaseStaleSearch;
  const staleSearchGate = new Promise((resolveGate) => { releaseStaleSearch = resolveGate; });
  let staleSearchIntercepted = false;
  await desktop.route("**/_redevplugin/api/plugins/rpc", async (route) => {
    const requestBody = route.request().postDataJSON();
    if (requestBody?.method === "memos.list" && requestBody?.params?.query === "Stale request") {
      staleSearchIntercepted = true;
      await staleSearchGate;
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ ok: false, error_code: "PLUGIN_RUNTIME_UNAVAILABLE", error: "PLUGIN_RUNTIME_UNAVAILABLE" }),
      });
      return;
    }
    await route.continue();
  });
  await memos.getByPlaceholder("Search memos").fill("Stale request");
  await waitFor(() => staleSearchIntercepted, 5_000, "stale Memos search request");
  await memos.getByPlaceholder("Search memos").fill("Edited timeline");
  await editedCard().waitFor();
  releaseStaleSearch();
  await desktop.waitForTimeout(100);
  assert.equal(await memos.getByText("Timeline unavailable", { exact: true }).count(), 0, "a stale search failure must not replace the latest result");
  await desktop.unroute("**/_redevplugin/api/plugins/rpc");

  await memos.getByRole("button", { name: "Clear filters" }).click();
  await editedCard().waitFor();
  await editedCard().getByRole("button", { name: "#smoke" }).click();
  await memos.locator('.calendar-grid button.has-memos').first().click();
  await editedCard().waitFor();
  await memos.getByRole("button", { name: "Clear filters" }).click();

  const lifecycleComposer = memos.getByPlaceholder("What's on your mind?");
  await lifecycleComposer.fill("Lifecycle draft #later");
  await memos.getByText("Draft pending", { exact: true }).waitFor();
  const saveCallsBeforeQuiesce = methodCalls.filter((body) => body.includes('"method":"memos.draft.save"')).length;
  const weatherNavigation = desktop.locator('#plugin-list button[data-slug="weather"]');
  await weatherNavigation.click();
  await waitFor(() => methodCalls.filter((body) => body.includes('"method":"memos.draft.save"')).length > saveCallsBeforeQuiesce, 5_000, "Memos quiesce draft call");
  await pluginFrame(desktop, "Weather");
  assert.equal(await weatherNavigation.evaluate((element) => document.activeElement === element), true, "switching apps must preserve navigation focus");
  await desktop.locator('#plugin-list button[data-slug="memos"]').click();
  memos = await pluginFrame(desktop, "Memos");
  await memos.getByText("Draft protected", { exact: true }).waitFor({ timeout: 10_000 });
  assert.equal(await memos.getByPlaceholder("What's on your mind?").inputValue(), "Lifecycle draft #later", "quiesced composer draft must be restored");
  await memos.getByRole("button", { name: "Save", exact: true }).click();
  const lifecycleCard = () => memos.locator(".memo-card").filter({ hasText: "Lifecycle draft" });
  await lifecycleCard().waitFor();

  await editedCard().getByRole("button", { name: "More memo actions" }).click();
  await editedCard().getByRole("menuitem", { name: "Archive" }).click();
  await editedCard().waitFor({ state: "detached" });
  await memos.getByRole("button", { name: /^Archived/ }).click();
  await editedCard().waitFor();
  await editedCard().getByRole("button", { name: "More memo actions" }).click();
  await editedCard().getByRole("menuitem", { name: "Restore" }).click();
  await editedCard().waitFor({ state: "detached" });
  await memos.getByRole("button", { name: /^All memos/ }).click();

  await lifecycleCard().getByRole("button", { name: "More memo actions" }).click();
  const firstMenuItem = lifecycleCard().getByRole("menuitem", { name: "Edit" });
  await firstMenuItem.waitFor();
  assert.equal(await firstMenuItem.evaluate((element) => document.activeElement === element), true, "the memo menu must focus its first action");
  await firstMenuItem.press("Escape");
  await waitFor(async () => lifecycleCard().getByRole("button", { name: "More memo actions" }).evaluate((element) => document.activeElement === element), 2_000, "memo menu focus restoration");
  await lifecycleCard().getByRole("button", { name: "More memo actions" }).click();
  await lifecycleCard().getByRole("menuitem", { name: "Delete" }).click();
  const deleteMemoDialog = memos.getByRole("dialog", { name: "Delete memo" });
  await deleteMemoDialog.waitFor();
  await waitFor(async () => memos.getByRole("button", { name: "Keep memo" }).evaluate((element) => document.activeElement === element), 2_000, "delete dialog safe-action focus");
  await memos.getByRole("button", { name: "Keep memo" }).press("Shift+Tab");
  const reverseFocusState = await deleteMemoDialog.evaluate((dialog) => ({
    ariaModal: dialog.getAttribute("aria-modal"),
    activeLabel: document.activeElement?.getAttribute("aria-label") || document.activeElement?.textContent?.trim() || "",
    controls: Array.from(dialog.querySelectorAll("button")).map((button) => ({ label: button.textContent?.trim() || "", disabled: button.disabled, tabIndex: button.tabIndex, rects: button.getClientRects().length })),
  }));
  assert.equal(reverseFocusState.activeLabel, "Delete memo", `delete dialog must wrap reverse tab focus: ${JSON.stringify(reverseFocusState)}`);
  await deleteMemoDialog.getByRole("button", { name: "Delete memo" }).press("Tab");
  assert.equal(await memos.getByRole("button", { name: "Keep memo" }).evaluate((element) => document.activeElement === element), true, "delete dialog must keep forward tab focus inside the modal");
  await memos.getByRole("button", { name: "Keep memo" }).press("Escape");
  await waitFor(async () => lifecycleCard().getByRole("button", { name: "More memo actions" }).evaluate((element) => document.activeElement === element), 2_000, "delete dialog focus restoration");
  let rejectMemoDelete = true;
  await desktop.route("**/_redevplugin/api/plugins/rpc", async (route) => {
    const requestBody = route.request().postDataJSON();
    if (rejectMemoDelete && requestBody?.method === "memos.delete") {
      rejectMemoDelete = false;
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ ok: false, error_code: "PLUGIN_RUNTIME_UNAVAILABLE", error: "PLUGIN_RUNTIME_UNAVAILABLE" }),
      });
      return;
    }
    await route.continue();
  });
  await lifecycleCard().getByRole("button", { name: "More memo actions" }).click();
  await lifecycleCard().getByRole("menuitem", { name: "Delete" }).click();
  await memos.getByRole("dialog", { name: "Delete memo" }).getByRole("button", { name: "Delete memo" }).click();
  await memos.getByText("Memos could not delete this memo", { exact: true }).waitFor();
  await lifecycleCard().waitFor();
  await desktop.unroute("**/_redevplugin/api/plugins/rpc");
  await lifecycleCard().getByRole("button", { name: "More memo actions" }).click();
  await lifecycleCard().getByRole("menuitem", { name: "Delete" }).click();
  await memos.getByRole("dialog", { name: "Delete memo" }).getByRole("button", { name: "Delete memo" }).click();
  await memos.getByText("Memo deleted", { exact: true }).waitFor();
  await memos.locator(".memos-toast").waitFor({ state: "detached", timeout: 5_000 });
  await desktop.screenshot({ path: resolve(evidenceDir, "examples-memos-desktop.png"), fullPage: false });

  await desktop.locator('#plugin-list button[data-slug="weather"]').click();
  let weather = await pluginFrame(desktop, "Weather");
  await weather.getByRole("heading", { name: "Berlin" }).waitFor({ timeout: 20_000 });
  await weather.locator(".weather-story").waitFor();
  await weather.locator(".weather-glance").waitFor();
  const weatherSceneImage = await weather.locator(".weather-scene").evaluate((element) => getComputedStyle(element).backgroundImage);
  assert.match(weatherSceneImage, /^url\("blob:null\//, "the sandbox must rewrite the packaged Weather artwork to an opaque-origin blob URL");
  const currentTemperature = weather.locator(".temperature-value");
  await currentTemperature.waitFor();
  assert.match(await currentTemperature.textContent() || "", /^-?\d+°$/);
  await weather.getByRole("button", { name: "Save place", exact: true }).click();
  await weather.getByText("Berlin saved", { exact: true }).waitFor();
  await weather.getByPlaceholder("Search city or place").fill("Paris");
  await weather.getByRole("button", { name: "Search weather" }).click();
  const parisResult = weather.locator(".search-result").filter({ hasText: "France" });
  await parisResult.waitFor({ timeout: 20_000 });
  await parisResult.getByRole("button", { name: "View weather for Paris" }).click();
  await weather.getByRole("heading", { name: "Paris" }).waitFor({ timeout: 20_000 });
  await weather.getByRole("button", { name: "Save place", exact: true }).click();
  await weather.getByText("Paris saved", { exact: true }).waitFor();
  let rejectedForecasts = 1;
  const rpcPattern = "**/_redevplugin/api/plugins/rpc";
  await desktop.route(rpcPattern, async (route) => {
    const requestBody = route.request().postDataJSON();
    if (rejectedForecasts > 0 && requestBody?.method === "weather.forecast") {
      rejectedForecasts -= 1;
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ ok: false, error_code: "PLUGIN_RUNTIME_UNAVAILABLE", error: "forecast unavailable" }),
      });
      return;
    }
    await route.continue();
  });
  await weather.getByPlaceholder("Search city or place").fill("Berlin");
  await weather.getByRole("button", { name: "Search weather" }).click();
  const berlinResult = weather.locator(".search-result").filter({ hasText: "Germany" }).first();
  await berlinResult.waitFor({ timeout: 20_000 });
  await berlinResult.getByRole("button", { name: "View weather for Berlin" }).click();
  await weather.getByText("Live weather for Berlin is unavailable", { exact: true }).waitFor();
  assert.equal(await weather.getByRole("heading", { name: "Paris" }).count(), 1, "a failed forecast must preserve the previously rendered place");
  await desktop.unroute(rpcPattern);
  await weather.getByPlaceholder("Search city or place").fill("Berlin");
  await weather.getByRole("button", { name: "Search weather" }).click();
  const recoveredBerlinResult = weather.locator(".search-result").filter({ hasText: "Germany" }).first();
  await recoveredBerlinResult.waitFor({ timeout: 20_000 });
  await recoveredBerlinResult.getByRole("button", { name: "View weather for Berlin" }).click();
  await weather.getByRole("heading", { name: "Berlin" }).waitFor({ timeout: 20_000 });
  await desktop.screenshot({ path: resolve(evidenceDir, "examples-weather-desktop.png"), fullPage: false });

  await desktop.reload({ waitUntil: "domcontentloaded" });
  weather = await pluginFrame(desktop, "Weather");
  await weather.locator(".saved-strip").getByText("Paris", { exact: true }).waitFor({ timeout: 20_000 });

  const pluginSwitchSamplesMs = [];
  for (let iteration = 0; iteration < 10; iteration += 1) {
    let startedAt = performance.now();
    await desktop.locator('#plugin-list button[data-slug="memos"]').click();
    const switchedMemos = await pluginFrame(desktop, "Memos");
    await switchedMemos.locator(".memos-workspace").waitFor({ state: "visible", timeout: 10_000 });
    pluginSwitchSamplesMs.push(performance.now() - startedAt);

    startedAt = performance.now();
    await desktop.locator('#plugin-list button[data-slug="weather"]').click();
    const switchedWeather = await pluginFrame(desktop, "Weather");
    await switchedWeather.locator(".weather-app").waitFor({ state: "visible", timeout: 10_000 });
    pluginSwitchSamplesMs.push(performance.now() - startedAt);
  }
  const sortedPluginSwitchSamplesMs = [...pluginSwitchSamplesMs].sort((left, right) => left - right);
  const pluginSwitchP95Ms = sortedPluginSwitchSamplesMs[Math.ceil(sortedPluginSwitchSamplesMs.length * 0.95) - 1];
  const pluginSwitchMaxMs = sortedPluginSwitchSamplesMs.at(-1);
  assert.equal(pluginSwitchP95Ms < 1_000, true, `plugin switch p95 ${pluginSwitchP95Ms.toFixed(1)}ms exceeded 1000ms`);
  assert.equal(pluginSwitchMaxMs < 1_500, true, `plugin switch max ${pluginSwitchMaxMs.toFixed(1)}ms exceeded 1500ms`);

  await desktop.locator('#plugin-list button[data-slug="sky-strike"]').click();
  const game = await pluginFrame(desktop, "Sky Strike");
  let gameBackdropImage = "";
  await waitFor(async () => {
    gameBackdropImage = await game.locator(".canvas-stage").evaluate((element) => getComputedStyle(element).backgroundImage);
    return /^url\("blob:null\//.test(gameBackdropImage);
  }, 10_000, "sandboxed game artwork");
  assert.match(gameBackdropImage, /^url\("blob:null\//, "the sandbox must rewrite the packaged game artwork to an opaque-origin blob URL");
  const canvas = game.locator("canvas");
  await canvas.waitFor({ state: "visible", timeout: 20_000 });
  await waitFor(() => methodCalls.some((body) => body.includes("game.highScore.load")), 10_000, "high-score load call");
  const firstFrame = await waitForCanvasFrame(canvas, isRenderedGameFrame, 10_000);
  assert.equal(await canvas.getAttribute("aria-label"), "Sky Strike game canvas");
  await waitFor(async () => (await canvasAccessibleDescription(canvas)).includes("3 lives remaining"), 5_000, "canvas accessibility status");
  const firstPixels = decodePNG(firstFrame);
  assert.equal(firstPixels.uniqueSampleColors > 24, true, `game canvas color count = ${firstPixels.uniqueSampleColors}`);
  assert.equal(firstPixels.lumaRange > 40, true, `game canvas luma range = ${firstPixels.lumaRange}`);
  assert.equal(firstPixels.brightSamplePixels > 80, true, `game canvas bright pixel count = ${firstPixels.brightSamplePixels}`);
  await canvas.focus();
  await desktop.keyboard.press("Enter");
  await waitFor(async () => (await canvasAccessibleDescription(canvas)).includes("Mission running"), 5_000, "running canvas accessibility status");
  const startedFrame = await canvas.screenshot();
  assert.notEqual(sha256(startedFrame), sha256(firstFrame), "starting the mission must dismiss the launch state");
  await desktop.keyboard.down("Space");
  await new Promise((resolveDelay) => setTimeout(resolveDelay, 2_000));
  await desktop.keyboard.up("Space");
  await waitFor(async () => {
    const results = await Promise.all(methodResults);
    return results.some((result) => result.method === "game.highScore.save" && Number(result.body?.data?.data?.score ?? result.body?.data?.score ?? 0) > 0);
  }, 10_000, "high-score save response");
  const savedHighScore = Math.max(...(await Promise.all(methodResults))
    .filter((result) => result.method === "game.highScore.save")
    .map((result) => Number(result.body?.data?.data?.score ?? result.body?.data?.score ?? 0)));
  const activeFrame = await canvas.screenshot();
  assert.notEqual(sha256(activeFrame), sha256(firstFrame), "game canvas must animate after input");
  await game.locator('button[title="Play, pause, or resume"]').click();
  await new Promise((resolveDelay) => setTimeout(resolveDelay, 120));
  const pausedFrame = await canvas.screenshot();
  assert.notEqual(sha256(pausedFrame), sha256(activeFrame), "pause overlay must be visible");
  await game.locator('button[title="Restart mission"]').click();
  const restartedFrame = await canvas.screenshot();
  assert.notEqual(sha256(restartedFrame), sha256(pausedFrame), "restart must return to a fresh mission state");
  const loadResultsBeforeReload = (await Promise.all(methodResults)).filter((result) => result.method === "game.highScore.load").length;
  await desktop.reload({ waitUntil: "domcontentloaded" });
  const reloadedGame = await pluginFrame(desktop, "Sky Strike");
  await reloadedGame.locator("canvas").waitFor({ state: "visible", timeout: 20_000 });
  await waitFor(async () => {
    const results = (await Promise.all(methodResults)).filter((result) => result.method === "game.highScore.load");
    return results.length > loadResultsBeforeReload && results.some((result) => Number(result.body?.data?.data?.score ?? result.body?.data?.score ?? 0) >= savedHighScore);
  }, 10_000, "persisted high-score reload response");
  await desktop.screenshot({ path: resolve(evidenceDir, "examples-sky-strike-desktop.png"), fullPage: false });

  const mobile = await browser.newPage({ viewport: { width: 390, height: 844 }, deviceScaleFactor: 1 });
  const mobileErrors = [];
  mobile.on("pageerror", (error) => mobileErrors.push(error.message));
  await mobile.goto(baseURL, { waitUntil: "domcontentloaded" });
  const mobileMemos = await pluginFrame(mobile, "Memos");
  await assertNoHorizontalOverflow(mobile);
  const mobileFrame = mobile.frameLocator('iframe[title="Memos plugin"]');
  await assertNoHorizontalOverflow(mobileFrame);
  await mobile.locator("#mobile-inspector-toggle").click();
  await mobile.locator('#plugin-inspector[data-open="true"]').waitFor();
  await mobile.locator("#inspector-close").click();
  await mobile.locator('#plugin-inspector[data-open="false"]').waitFor();
  await waitFor(async () => await mobile.locator("#plugin-inspector").evaluate((element) => getComputedStyle(element).visibility === "hidden"), 2_000, "closed mobile app details sheet to be hidden");
  await mobileMemos.getByRole("button", { name: "Open explorer" }).click();
  await mobileMemos.locator(".memos-explorer").waitFor();
  await assertMinimumTouchSize(mobileMemos.getByRole("button", { name: "Close explorer" }), 44);
  await assertMinimumTouchSize(mobileMemos.locator(".calendar-grid button").first(), 44);
  await mobileMemos.getByRole("button", { name: "Close explorer" }).click();
  const mobileComposer = mobileMemos.getByPlaceholder("What's on your mind?");
  await mobileComposer.fill("### Mobile timeline memo\n\nCreated from the compact composer. #mobile");
  assert.equal(await mobileComposer.evaluate((element) => element.scrollWidth <= element.clientWidth), true, "mobile composer must not clip horizontally");
  await mobileMemos.getByText("Draft protected", { exact: true }).waitFor({ timeout: 10_000 });
  await mobileMemos.getByRole("button", { name: "Save", exact: true }).click();
  await mobileMemos.locator(".memo-card").filter({ hasText: "Mobile timeline memo" }).waitFor();
  await assertMinimumTouchSize(mobileMemos.locator(".memo-card").filter({ hasText: "Mobile timeline memo" }).getByRole("button", { name: "More memo actions" }), 44);
  await mobileMemos.locator(".memos-toast").waitFor({ state: "detached", timeout: 5_000 });
  await mobile.screenshot({ path: resolve(evidenceDir, "examples-memos-mobile.png"), fullPage: false });

  await mobile.locator('#mobile-plugin-list button[data-slug="weather"]').click();
  const mobileWeather = await pluginFrame(mobile, "Weather");
  await mobileWeather.getByRole("heading", { name: "Paris" }).waitFor({ timeout: 20_000 });
  await assertNoHorizontalOverflow(mobile);
  await assertNoHorizontalOverflow(mobile.frameLocator('iframe[title="Weather plugin"]'));
  await mobile.screenshot({ path: resolve(evidenceDir, "examples-weather-mobile.png"), fullPage: false });

  await mobile.locator('#mobile-plugin-list button[data-slug="sky-strike"]').click();
  const mobileGame = await pluginFrame(mobile, "Sky Strike");
  const mobileGameCanvas = mobileGame.locator("canvas");
  await mobileGameCanvas.waitFor({ state: "visible", timeout: 20_000 });
  await assertMinimumTouchSize(mobileGame.locator('button[title="Play, pause, or resume"]'), 44);
  await assertMinimumTouchSize(mobileGame.locator('button[title="Restart mission"]'), 44);
  const mobileGameFrame = await waitForCanvasFrame(mobileGameCanvas, isRenderedGameFrame, 10_000);
  await writeFile(resolve(evidenceDir, "examples-sky-strike-mobile-canvas.png"), mobileGameFrame);
  await mobile.waitForTimeout(120);
  await assertNoHorizontalOverflow(mobile);
  await assertNoHorizontalOverflow(mobile.frameLocator('iframe[title="Sky Strike plugin"]'));
  await mobile.screenshot({ path: resolve(evidenceDir, "examples-sky-strike-mobile.png"), fullPage: false });
  assert.deepEqual(mobileErrors, []);
  await mobile.close();

  const compact = await browser.newPage({ viewport: { width: 360, height: 720 }, deviceScaleFactor: 1 });
  const compactErrors = [];
  compact.on("pageerror", (error) => compactErrors.push(error.message));
  await compact.goto(`${baseURL}?plugin=memos`, { waitUntil: "domcontentloaded" });
  const compactMemos = await pluginFrame(compact, "Memos");
  await assertNoHorizontalOverflow(compact);
  await assertNoHorizontalOverflow(compact.frameLocator('iframe[title="Memos plugin"]'));
  let rejectedMemoUpdates = 2;
  await compact.route("**/_redevplugin/api/plugins/rpc", async (route) => {
    const requestBody = route.request().postDataJSON();
    if (rejectedMemoUpdates > 0 && requestBody?.method === "memos.update") {
      rejectedMemoUpdates -= 1;
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ ok: false, error_code: "PLUGIN_RUNTIME_UNAVAILABLE", error: "PLUGIN_RUNTIME_UNAVAILABLE" }),
      });
      return;
    }
    await route.continue();
  });
  const compactCard = compactMemos.locator(".memo-card").filter({ hasText: "Edited timeline memo" });
  await compactCard.getByRole("button", { name: "More memo actions" }).click();
  await compactCard.getByRole("menuitem", { name: "Edit" }).click();
  const compactEditCard = compactMemos.locator(".memo-card.editing");
  const protectedEdit = compactEditCard.getByRole("textbox", { name: "Edit memo content" });
  await protectedEdit.fill("## Protected timeline edit\n\nThis edit remains active while persistence is unavailable. #smoke");
  const protectedEditError = compactEditCard.locator(".save-state.error");
  await protectedEditError.waitFor({ state: "visible", timeout: 10_000 });
  assert.match(await protectedEditError.innerText(), /Memos could not save your changes/);
  await compactMemos.getByRole("button", { name: "Open explorer" }).click();
  await compactMemos.getByRole("button", { name: /^Archived/ }).click();
  assert.equal(await protectedEdit.inputValue(), "## Protected timeline edit\n\nThis edit remains active while persistence is unavailable. #smoke", "failed persistence must block filtering and preserve the edit");
  await compactMemos.getByRole("button", { name: "Close explorer" }).click();
  await compact.unroute("**/_redevplugin/api/plugins/rpc");
  await compactEditCard.getByRole("button", { name: "Retry" }).click();
  await compactEditCard.getByText("Saved", { exact: true }).waitFor({ timeout: 10_000 });
  await compactEditCard.getByRole("button", { name: "Done" }).click();
  await compactMemos.locator(".memo-card").filter({ hasText: "Protected timeline edit" }).waitFor();
  await compact.screenshot({ path: resolve(evidenceDir, "examples-memos-compact.png"), fullPage: false });
  await compact.goto(`${baseURL}?plugin=weather`, { waitUntil: "domcontentloaded" });
  const compactWeather = await pluginFrame(compact, "Weather");
  await compactWeather.getByRole("heading", { name: "Paris" }).waitFor({ timeout: 20_000 });
  await assertMinimumTouchSize(compactWeather.getByRole("button", { name: "Search weather" }), 44);
  await assertNoHorizontalOverflow(compact);
  await assertNoHorizontalOverflow(compact.frameLocator('iframe[title="Weather plugin"]'));
  await compact.goto(`${baseURL}?plugin=sky-strike`, { waitUntil: "domcontentloaded" });
  const compactGame = await pluginFrame(compact, "Sky Strike");
  const compactGameCanvas = compactGame.locator("canvas");
  await compactGameCanvas.waitFor({ state: "visible", timeout: 20_000 });
  await assertMinimumTouchSize(compactGame.locator('button[title="Play, pause, or resume"]'), 44);
  await assertMinimumTouchSize(compactGame.locator('button[title="Restart mission"]'), 44);
  const compactGameFrame = await waitForCanvasFrame(compactGameCanvas, isRenderedGameFrame, 10_000);
  await writeFile(resolve(evidenceDir, "examples-compact-game-canvas.png"), compactGameFrame);
  await compact.waitForTimeout(120);
  await assertNoHorizontalOverflow(compact);
  await assertNoHorizontalOverflow(compact.frameLocator('iframe[title="Sky Strike plugin"]'));
  await compact.screenshot({ path: resolve(evidenceDir, "examples-compact-mobile.png"), fullPage: false });
  assert.deepEqual(compactErrors, []);
  await compact.close();

  const unexpectedConsole = consoleLines.filter((line) => !isExpectedSandboxConsoleLine(line));
  const apiFailures = await Promise.all(apiFailureReads);
  assert.deepEqual(pageErrors, []);
  assert.deepEqual(apiFailures, []);
  assert.deepEqual(unexpectedConsole, []);
  await writeFile(resolve(evidenceDir, "examples-acceptance.json"), JSON.stringify({
    schema_version: "redevplugin.examples_acceptance.v1",
    page_title: await desktop.title(),
    plugins: ["memos", "weather", "sky-strike"],
    memos_persisted: true,
    memos_autosave_verified: true,
    memos_quiesce_save_verified: true,
    memos_delete_confirmation_verified: true,
    weather_location_persisted: true,
    weather_search_and_save_verified: true,
    plugin_switch_samples_ms: pluginSwitchSamplesMs.map((sample) => Math.round(sample * 10) / 10),
    plugin_switch_p95_ms: Math.round(pluginSwitchP95Ms * 10) / 10,
    plugin_switch_max_ms: Math.round(pluginSwitchMaxMs * 10) / 10,
    game_canvas_nonblank: true,
    game_canvas_animated: true,
    game_restart_verified: true,
    mobile_game_canvas_nonblank: true,
    compact_game_canvas_nonblank: true,
    high_score_load_called: true,
    high_score_save_and_reload_verified: true,
    premium_webp_artwork_loaded: true,
    distinct_consumer_visual_systems_verified: true,
    responsive_viewports: ["1280x800", "390x844", "360x720"],
    console_errors: unexpectedConsole,
    page_errors: pageErrors,
    api_failures: apiFailures,
  }, null, 2) + "\n");
} catch (error) {
  const diagnostics = {
    outer_status: await desktop.locator("#surface-placeholder p").textContent().catch(() => ""),
    detail_error: await desktop.locator("#detail-error").textContent().catch(() => ""),
    plugin_text: await desktop.frameLocator('iframe[title="Memos plugin"]').locator("body").innerText().catch(() => ""),
    console_lines: consoleLines,
    page_errors: pageErrors,
    api_failures: await Promise.all(apiFailureReads),
    method_calls: methodCalls,
    method_results: await Promise.all(methodResults),
  };
  throw new Error(`examples smoke failed: ${JSON.stringify(diagnostics)}`, { cause: error });
} finally {
  await desktop.close();
  await browser.close();
}

async function pluginFrame(page, name) {
  const iframe = page.locator(`iframe[title="${name} plugin"]`);
  await iframe.waitFor({ state: "visible", timeout: 30_000 });
  const frame = page.frameLocator(`iframe[title="${name} plugin"]`);
  await frame.locator("body").waitFor({ state: "visible", timeout: 30_000 });
  return frame;
}

async function assertNoHorizontalOverflow(scope) {
  const dimensions = await scope.locator("html").evaluate((element) => ({
    clientWidth: element.clientWidth,
    scrollWidth: element.scrollWidth,
  }));
  assert.equal(dimensions.scrollWidth <= dimensions.clientWidth + 1, true, `horizontal overflow: ${JSON.stringify(dimensions)}`);
}

async function assertMinimumTouchSize(locator, minimum) {
  const box = await locator.boundingBox();
  assert.notEqual(box, null, "interactive control must be visible");
  assert.equal(box.width >= minimum && box.height >= minimum, true, `touch target ${JSON.stringify(box)} is smaller than ${minimum}px`);
}

async function waitFor(predicate, timeoutMs, label) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await predicate()) return;
    await new Promise((resolveDelay) => setTimeout(resolveDelay, 50));
  }
  throw new Error(`timed out waiting for ${label}`);
}

async function waitForComputedStyles(locator, propertyNames, predicate, label, timeoutMs = 5_000) {
  let styles;
  await waitFor(async () => {
    try {
      const snapshot = await locator.evaluate((element, names) => {
        const computed = getComputedStyle(element);
        return {
          connected: element.isConnected,
          styles: Object.fromEntries(names.map((name) => [name, computed[name]])),
        };
      }, propertyNames);
      if (!snapshot.connected) return false;
      styles = snapshot.styles;
      return predicate(styles);
    } catch {
      return false;
    }
  }, timeoutMs, label);
  return styles;
}

async function canvasAccessibleDescription(canvas) {
  return canvas.evaluate((element) => {
    const descriptionID = element.getAttribute("aria-describedby");
    return descriptionID ? element.ownerDocument.getElementById(descriptionID)?.textContent ?? "" : "";
  });
}

async function waitForCanvasFrame(canvas, predicate, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  let lastFrame;
  let lastPixels;
  while (Date.now() < deadline) {
    lastFrame = await canvas.screenshot();
    lastPixels = decodePNG(lastFrame);
    if (predicate(lastPixels)) return lastFrame;
    await new Promise((resolveDelay) => setTimeout(resolveDelay, 50));
  }
  throw new Error(`timed out waiting for a rendered game frame: ${JSON.stringify(lastPixels)}`);
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function decodePNG(buffer) {
  assert.equal(buffer.subarray(0, 8).toString("hex"), "89504e470d0a1a0a", "canvas screenshot must be PNG");
  let offset = 8;
  let width = 0;
  let height = 0;
  let colorType = 0;
  const compressed = [];
  while (offset < buffer.length) {
    const length = buffer.readUInt32BE(offset);
    const type = buffer.subarray(offset + 4, offset + 8).toString("ascii");
    const data = buffer.subarray(offset + 8, offset + 8 + length);
    if (type === "IHDR") {
      width = data.readUInt32BE(0);
      height = data.readUInt32BE(4);
      assert.equal(data[8], 8, "canvas PNG must use 8-bit channels");
      colorType = data[9];
    } else if (type === "IDAT") compressed.push(data);
    else if (type === "IEND") break;
    offset += length + 12;
  }
  const bytesPerPixel = colorType === 6 ? 4 : colorType === 2 ? 3 : 0;
  assert.notEqual(bytesPerPixel, 0, `unsupported canvas PNG color type ${colorType}`);
  const inflated = inflateSync(Buffer.concat(compressed));
  const stride = width * bytesPerPixel;
  const pixels = Buffer.alloc(stride * height);
  let inputOffset = 0;
  let previous = Buffer.alloc(stride);
  for (let y = 0; y < height; y += 1) {
    const filter = inflated[inputOffset++];
    const row = pixels.subarray(y * stride, (y + 1) * stride);
    for (let x = 0; x < stride; x += 1) {
      const raw = inflated[inputOffset++];
      const left = x >= bytesPerPixel ? row[x - bytesPerPixel] : 0;
      const up = previous[x] || 0;
      const upperLeft = x >= bytesPerPixel ? previous[x - bytesPerPixel] : 0;
      row[x] = unfilter(filter, raw, left, up, upperLeft);
    }
    previous = row;
  }
  const colors = new Set();
  let minLuma = 255;
  let maxLuma = 0;
  let brightSamplePixels = 0;
  const step = Math.max(1, Math.floor((width * height) / 10_000));
  for (let pixel = 0; pixel < width * height; pixel += step) {
    const index = pixel * bytesPerPixel;
    const red = pixels[index];
    const green = pixels[index + 1];
    const blue = pixels[index + 2];
    colors.add(`${red},${green},${blue}`);
    const luma = Math.round(red * 0.2126 + green * 0.7152 + blue * 0.0722);
    minLuma = Math.min(minLuma, luma);
    maxLuma = Math.max(maxLuma, luma);
    if (luma >= 120) brightSamplePixels += 1;
  }
  return { width, height, uniqueSampleColors: colors.size, lumaRange: maxLuma - minLuma, brightSamplePixels };
}

function isRenderedGameFrame(pixels) {
  return pixels.uniqueSampleColors > 24 && pixels.lumaRange > 40 && pixels.brightSamplePixels > 80;
}

function unfilter(filter, raw, left, up, upperLeft) {
  switch (filter) {
    case 0: return raw;
    case 1: return (raw + left) & 0xff;
    case 2: return (raw + up) & 0xff;
    case 3: return (raw + Math.floor((left + up) / 2)) & 0xff;
    case 4: return (raw + paeth(left, up, upperLeft)) & 0xff;
    default: throw new Error(`unsupported PNG filter ${filter}`);
  }
}

function paeth(left, up, upperLeft) {
  const estimate = left + up - upperLeft;
  const leftDistance = Math.abs(estimate - left);
  const upDistance = Math.abs(estimate - up);
  const upperLeftDistance = Math.abs(estimate - upperLeft);
  if (leftDistance <= upDistance && leftDistance <= upperLeftDistance) return left;
  return upDistance <= upperLeftDistance ? up : upperLeft;
}
