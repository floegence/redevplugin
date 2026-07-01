import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { mkdtemp, rm } from "node:fs/promises";
import { createServer } from "node:net";
import { join } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { tmpdir } from "node:os";
import { chromium } from "playwright";

const hostPort = await getFreePort();
const pluginPort = await getFreePort(hostPort);
const generatedRoot = await mkdtemp(join(tmpdir(), "redevplugin-generated-browser-"));
const generatedPluginDir = join(generatedRoot, "plugin");
const generatedPackage = join(generatedRoot, "generated.redevplugin");
const generatedStateRoot = join(generatedRoot, "state");
await runCLI(["scaffold", "com.example.generated.browser", "Generated Browser Plugin", generatedPluginDir]);
await runCLI(["package", generatedPluginDir, generatedPackage]);
const generatedInstall = JSON.parse(await runCLI(["dev-install", generatedStateRoot, generatedPackage]));
assert.equal(generatedInstall.enable_state, "disabled");
const generatedEnable = JSON.parse(await runCLI(["dev-enable", generatedStateRoot]));
assert.equal(generatedEnable.enable_state, "enabled");
const generatedOpen = JSON.parse(
  await runCLI(["dev-open", generatedStateRoot, "com.example.generated.browser.activity", `http://127.0.0.1:${pluginPort}`]),
);
assert.equal(generatedOpen.browser_origin_count, 1);
const pluginOrigin = `http://127.0.0.1:${pluginPort}`;
const hostURL = `http://127.0.0.1:${hostPort}/demo/browser/index.html?plugin_origin=http://127.0.0.1:${pluginPort}`;
const server = spawn(process.execPath, ["demo/browser/server.mjs"], {
  cwd: new URL("../..", import.meta.url),
  env: {
    ...process.env,
    HOST_PORT: String(hostPort),
    PLUGIN_PORT: String(pluginPort),
    EXTRA_PLUGIN_ROOT: generatedPluginDir,
  },
  stdio: ["ignore", "pipe", "pipe"],
});

let serverOutput = "";
server.stdout.on("data", (chunk) => {
  serverOutput += String(chunk);
});
server.stderr.on("data", (chunk) => {
  serverOutput += String(chunk);
});

try {
  await waitForHTTP(hostURL);
  const browser = await launchBrowser();
  const page = await browser.newPage({ viewport: { width: 1280, height: 720 } });
  const consoleErrors = [];
  page.on("console", (message) => {
    if (message.type() === "error") {
      consoleErrors.push(`${message.type()}: ${message.text()}`);
    }
  });
  page.on("pageerror", (error) => {
    consoleErrors.push(`pageerror: ${error.message}`);
  });

  await page.goto(hostURL, { waitUntil: "load" });
  await expectText(page.locator("#host-status"), "listening");
  await expectText(page.locator("#handshake-count"), "1");
  await expectText(page.locator("#platform-client-status"), "settings ok");
  await expectText(page.locator("#platform-client-detail"), "revision");

  const frame = page.frameLocator("#plugin-frame");
  await expectText(frame.locator("#plugin-status"), "ready");
  await assertPluginBrowserSecurity(page, frame, pluginOrigin);

  await frame.getByRole("button", { name: "Echo" }).click();
  await expectText(frame.locator("#plugin-result"), "hello from iframe");
  await expectText(page.locator("#rpc-count"), "1");

  await frame.getByRole("button", { name: "List files" }).click();
  await expectText(frame.locator("#plugin-result"), "workspace/readme.md");
  await expectText(page.locator("#rpc-count"), "2");

  await frame.getByRole("button", { name: "Tail logs" }).click();
  await expectText(frame.locator("#plugin-result"), "demo log line 1");
  await expectText(frame.locator("#plugin-result"), "demo log line 2");
  await expectText(page.locator("#rpc-count"), "3");

  await frame.getByRole("button", { name: "Delete cache" }).click();
  await expectText(page.locator("#confirmation-method"), "demo.cache.delete");
  assert.equal(await frame.locator("#call-dangerous").getAttribute("disabled"), "");
  await page.getByRole("button", { name: "Deny" }).click();
  await expectText(frame.locator("#plugin-result"), "PLUGIN_CONFIRMATION_REJECTED");
  assert.equal(await frame.locator("#call-dangerous").getAttribute("disabled"), null);
  await expectText(page.locator("#confirmation-count"), "1");

  await frame.getByRole("button", { name: "Delete cache" }).click();
  await expectText(page.locator("#confirmation-method"), "demo.cache.delete");
  assert.equal(await frame.locator("#call-dangerous").getAttribute("disabled"), "");
  await page.getByRole("button", { name: "Approve" }).click();
  await expectText(frame.locator("#plugin-result"), "\"deleted\": true");
  assert.equal(await frame.locator("#call-dangerous").getAttribute("disabled"), null);
  await expectText(page.locator("#rpc-count"), "6");
  await expectText(page.locator("#confirmation-count"), "2");

  await page.getByRole("button", { name: "Visible" }).click();
  await expectText(frame.locator("#plugin-status"), "visible");
  await expectText(frame.locator("#plugin-result"), "\"lifecycle\": \"visible\"");

  await page.getByRole("button", { name: "Bouncer game" }).click();
  await expectText(page.locator("#handshake-count"), "1");
  const gameFrame = page.frameLocator("#plugin-frame");
  await expectText(gameFrame.locator("#plugin-status"), "ready");
  await expectText(gameFrame.locator("#level"), "1");
  await expectText(gameFrame.locator("#plugin-result"), "game.state.get");
  const firstCanvasChecksum = await canvasChecksum(gameFrame.locator("#game-canvas"));
  assert.notEqual(firstCanvasChecksum, 0, "bouncer canvas should render non-empty animation pixels");
  await delay(260);
  const secondCanvasChecksum = await canvasChecksum(gameFrame.locator("#game-canvas"));
  assert.notEqual(secondCanvasChecksum, firstCanvasChecksum, "bouncer canvas should animate across frames");
  await gameFrame.getByRole("button", { name: "Boost" }).click();
  await expectText(gameFrame.locator("#speed"), "1.2x");
  await gameFrame.getByRole("button", { name: "Power-up" }).click();
  await expectText(gameFrame.locator("#powerups"), "1");
  await expectText(gameFrame.locator("#energy"), "%");
  await expectText(gameFrame.locator("#game-event-feed"), "power-up");
  await expectText(gameFrame.locator("#mission-title"), "Break the front line");
  await gameFrame.getByRole("button", { name: "Storm challenge" }).click();
  await expectText(gameFrame.locator("#challenge-mode"), "storm");
  await expectText(gameFrame.locator("#storm-wave"), "1");
  await expectText(gameFrame.locator("#game-event-feed"), "storm challenge opened");
  await gameFrame.getByRole("button", { name: "Bank storm" }).click();
  await expectText(gameFrame.locator("#plugin-result"), "game.challenge.report");
  await expectText(gameFrame.locator("#plugin-result"), "game/challenges/history");
  await expectText(gameFrame.locator("#challenge-list"), "wave 1");
  await gameFrame.getByRole("button", { name: "Reset" }).click();
  await expectText(gameFrame.locator("#plugin-status"), "ready");
  await expectText(gameFrame.locator("#plugin-result"), "\"reset\": true");
  await gameFrame.getByRole("button", { name: "Power-up" }).click();
  await gameFrame.getByRole("button", { name: "Sync run" }).click();
  await expectText(gameFrame.locator("#plugin-result"), "game.run.sync");
  await expectText(gameFrame.locator("#plugin-result"), "game/runs/latest");
  await expectText(gameFrame.locator("#game-event-feed"), "synced");
  await gameFrame.getByRole("button", { name: "Save score" }).click();
  await expectText(gameFrame.locator("#plugin-result"), "game.score.save");
  await expectText(gameFrame.locator("#plugin-result"), "host-backed kv store");
  await expectText(gameFrame.locator("#plugin-result"), "achievements");
  await expectText(gameFrame.locator("#leaderboard"), "Latest run");
  await gameFrame.getByRole("button", { name: "Export replay" }).click();
  await expectText(gameFrame.locator("#plugin-result"), "game.replay.export");
  await expectText(gameFrame.locator("#plugin-result"), "game/replays");
  await expectText(gameFrame.locator("#replay-list"), "KiB");
  await gameFrame.getByRole("button", { name: "Save snapshot" }).click();
  await expectText(gameFrame.locator("#plugin-result"), "game.snapshot.save");
  await expectText(gameFrame.locator("#snapshot-list"), "pts");
  await gameFrame.getByRole("button", { name: "Load snapshot" }).click();
  await expectText(gameFrame.locator("#plugin-result"), "game.snapshot.load");
  await expectText(gameFrame.locator("#plugin-result"), "game/snapshots");
  await expectText(page.locator("#rpc-count"), "7");

  await page.getByRole("button", { name: "Schedule planner" }).click();
  await expectText(page.locator("#handshake-count"), "1");
  const scheduleFrame = page.frameLocator("#plugin-frame");
  await expectText(scheduleFrame.locator("#plugin-status"), "ready");
  await expectText(scheduleFrame.locator("#schedule-count"), "3");
  await expectText(scheduleFrame.locator("#schedule-open"), "2");
  await expectText(scheduleFrame.locator("#schedule-minutes"), "75");
  await expectText(scheduleFrame.locator("#schedule-storage-source"), "host storage broker");
  await expectText(scheduleFrame.locator("#schedule-storage-revision"), "rev 1");
  await expectText(scheduleFrame.locator("#schedule-storage-usage"), "KiB");
  await expectText(scheduleFrame.locator("#schedule-transaction"), "sqlite-demo");
  await expectText(scheduleFrame.locator("#schedule-sql-preview"), "SELECT * FROM schedule_items");
  await expectText(scheduleFrame.locator("#schedule-tag-cloud"), "team");
  await expectText(scheduleFrame.locator("#schedule-timeline"), "Platform standup");
  await scheduleFrame.locator("#schedule-status").selectOption("open");
  await expectText(scheduleFrame.locator("#schedule-count"), "2");
  await scheduleFrame.locator("#schedule-title").fill("Browser QA review");
  await scheduleFrame.locator("#schedule-tag").fill("qa");
  await scheduleFrame.locator("#schedule-priority").selectOption("high");
  await scheduleFrame.locator("#schedule-duration").fill("55");
  await scheduleFrame.locator("#schedule-notes").fill("Exercise notes persistence through the demo SQLite broker.");
  await scheduleFrame.getByRole("button", { name: "Add" }).click();
  await expectText(scheduleFrame.locator("#schedule-list"), "Browser QA review");
  await expectText(scheduleFrame.locator("#schedule-count"), "3");
  await expectText(scheduleFrame.locator("#schedule-minutes"), "130");
  await expectText(scheduleFrame.locator("#schedule-storage-revision"), "rev 2");
  await expectText(scheduleFrame.locator("#timeline-next"), "09:30");
  await scheduleFrame.locator("#schedule-query").fill("browser");
  await expectText(scheduleFrame.locator("#schedule-count"), "1");
  await expectText(scheduleFrame.locator("#schedule-list"), "Browser QA review");
  await scheduleFrame.locator("#schedule-list li", { hasText: "Browser QA review" }).getByRole("button", { name: "Done" }).click();
  await expectText(scheduleFrame.locator("#plugin-result"), "\"persisted\": true");
  await expectText(scheduleFrame.locator("#schedule-count"), "0");
  await scheduleFrame.locator("#schedule-status").selectOption("all");
  await scheduleFrame.locator("#schedule-query").fill("");
  await expectText(scheduleFrame.locator("#schedule-count"), "4");
  await expectText(scheduleFrame.locator("#schedule-journal"), "toggle");
  await scheduleFrame.getByRole("button", { name: "Seed week" }).click();
  await expectText(scheduleFrame.locator("#schedule-list"), "Architecture sync");
  await expectText(scheduleFrame.locator("#schedule-count"), "9");
  await expectText(scheduleFrame.locator("#schedule-journal"), "seed_week");
  await expectText(scheduleFrame.locator("#schedule-transaction-detail"), "5 rows");
  await scheduleFrame.getByRole("button", { name: "Plan sprint" }).click();
  await expectText(scheduleFrame.locator("#schedule-list"), "Plugin runtime profiling");
  await expectText(scheduleFrame.locator("#schedule-count"), "13");
  await expectText(scheduleFrame.locator("#schedule-journal"), "bulk_plan");
  await expectText(scheduleFrame.locator("#schedule-tag-cloud"), "runtime");
  await scheduleFrame.getByRole("button", { name: "Backup" }).click();
  await expectText(scheduleFrame.locator("#backup-count"), "1 snapshots");
  await expectText(scheduleFrame.locator("#backup-list"), "schedule/snapshots");
  await expectText(scheduleFrame.locator("#schedule-transaction"), "backup");
  await expectText(scheduleFrame.locator("#schedule-sql-preview"), "schedule_backups");
  await scheduleFrame.getByRole("button", { name: "Inspect DB" }).click();
  await expectText(scheduleFrame.locator("#schedule-health"), "healthy");
  await expectText(scheduleFrame.locator("#schedule-schema"), "plugin.sqlite");
  await expectText(scheduleFrame.locator("#schedule-sql-preview"), "PRAGMA table_info");
  await scheduleFrame.getByRole("button", { name: "Archive done" }).click();
  await expectText(scheduleFrame.locator("#schedule-count"), "11");
  await expectText(scheduleFrame.locator("#schedule-journal"), "archive_done");
  await scheduleFrame.getByRole("button", { name: "Restore latest" }).click();
  await expectText(scheduleFrame.locator("#schedule-count"), "13");
  await expectText(scheduleFrame.locator("#schedule-journal"), "restore_backup");
  await expectText(scheduleFrame.locator("#schedule-restores"), "1");
  await expectText(scheduleFrame.locator("#schedule-storage-revision"), "rev 8");
  await page.reload({ waitUntil: "load" });
  await expectText(page.locator("#host-status"), "listening");
  await expectText(page.locator("#handshake-count"), "1");
  const reloadedScheduleFrame = page.frameLocator("#plugin-frame");
  await expectText(reloadedScheduleFrame.locator("#plugin-status"), "ready");
  await expectText(reloadedScheduleFrame.locator("#schedule-list"), "Architecture sync");
  await expectText(reloadedScheduleFrame.locator("#schedule-list"), "Plugin runtime profiling");
  await expectText(reloadedScheduleFrame.locator("#schedule-list"), "Browser QA review");
  await expectText(reloadedScheduleFrame.locator("#schedule-count"), "13");
  await expectText(reloadedScheduleFrame.locator("#schedule-storage-source"), "host storage broker");
  await expectText(reloadedScheduleFrame.locator("#schedule-storage-revision"), "rev 8");
  await expectText(reloadedScheduleFrame.locator("#schedule-journal"), "restore_backup");

  await page.getByRole("button", { name: "Weather console" }).click();
  await expectText(page.locator("#handshake-count"), "1");
  const weatherFrame = page.frameLocator("#plugin-frame");
  await expectText(weatherFrame.locator("#plugin-status"), "ready");
  await expectText(weatherFrame.locator("#weather-place"), "San Francisco");
  await expectText(weatherFrame.locator("#saved-locations"), "Shanghai");
  await weatherFrame.getByRole("button", { name: "Detect location" }).click();
  await expectText(weatherFrame.locator("#detected-location"), "network");
  await expectText(weatherFrame.locator("#detected-confidence"), "%");
  await expectText(weatherFrame.locator("#detected-coordinates"), ".");
  await expectText(weatherFrame.locator("#network-history"), "GET /v1/geolocate");
  await weatherFrame.locator("#weather-location").fill("Shanghai");
  await weatherFrame.getByRole("button", { name: "Fetch" }).click();
  await expectText(weatherFrame.locator("#weather-place"), "Shanghai");
  await expectText(weatherFrame.locator("#weather-condition"), "Warm evening haze");
  await expectText(weatherFrame.locator("#weather-pressure"), "1009 hPa");
  await expectText(weatherFrame.locator("#weather-aqi"), "43");
  await expectText(weatherFrame.locator("#weather-aqi-category"), "good");
  await expectText(weatherFrame.locator("#network-operation"), "http GET /v1/forecast");
  await expectText(weatherFrame.locator("#network-latency"), "ms");
  await expectText(weatherFrame.locator("#network-broker"), "host http fetch");
  await expectText(weatherFrame.locator("#network-response"), "200");
  await expectText(weatherFrame.locator("#network-parser"), "json");
  await expectText(weatherFrame.locator("#raw-weather-response"), "parsed_from_raw");
  await expectText(weatherFrame.locator("#raw-weather-response"), "/demo/weather-api/v1/forecast");
  await expectText(weatherFrame.locator("#hourly"), "09:00");
  await expectText(weatherFrame.locator("#network-history"), "GET /v1/forecast");
  await expectText(weatherFrame.locator("#plugin-result"), "weather.fetch");
  await expectText(weatherFrame.locator("#plugin-result"), "api.weather.example");
  await weatherFrame.getByRole("button", { name: "Explain parser" }).click();
  await expectText(weatherFrame.locator("#parser-quality"), "valid-json");
  await expectText(weatherFrame.locator("#parser-fields"), "7");
  await expectText(weatherFrame.locator("#parser-steps"), "current.temperature_c");
  await weatherFrame.getByRole("button", { name: "Compare saved" }).click();
  await expectText(weatherFrame.locator("#weather-compare-count"), "4 locations");
  await expectText(weatherFrame.locator("#weather-compare-grid"), "San Francisco");
  await expectText(weatherFrame.locator("#weather-compare-grid"), "Shanghai");
  await expectText(weatherFrame.locator("#weather-compare-grid"), "London");
  await weatherFrame.locator("#saved-locations").getByRole("button", { name: "London" }).click();
  await expectText(weatherFrame.locator("#weather-place"), "London");
  await expectText(weatherFrame.locator("#weather-condition"), "Patchy rain windows");
  await expectText(weatherFrame.locator("#weather-alerts"), "Wind window");
  await expectText(weatherFrame.locator("#weather-alert-count"), "1");

  const generatedURL = new URL(`http://127.0.0.1:${hostPort}/demo/browser/index.html`);
  generatedURL.searchParams.set("plugin_origin", `http://127.0.0.1:${pluginPort}`);
  generatedURL.searchParams.set("plugin_path", "/generated-plugin/ui/index.html");
  generatedURL.searchParams.set("plugin_id", generatedOpen.plugin_id);
  generatedURL.searchParams.set("surface_id", generatedOpen.surface_id);
  generatedURL.searchParams.set("surface_instance_id", generatedOpen.surface_instance_id);
  generatedURL.searchParams.set("active_fingerprint", generatedOpen.active_fingerprint);
  generatedURL.searchParams.set("bridge_nonce", generatedOpen.bridge_nonce);
  await page.goto(generatedURL.href, { waitUntil: "load" });
  await expectText(page.locator("#host-status"), "listening");
  await expectText(page.locator("#handshake-count"), "1");

  const generatedFrame = page.frameLocator("#plugin-frame");
  await expectText(generatedFrame.locator("#status"), "Ready");
  await generatedFrame.getByRole("button", { name: "Invoke backend" }).click();
  await expectText(generatedFrame.locator("#status"), "Backend responded");
  await expectText(generatedFrame.locator("#result"), "generated wasm worker scaffold");
  await expectText(generatedFrame.locator("#result"), "worker.echo");
  await expectText(page.locator("#rpc-count"), "1");
  await generatedFrame.getByRole("button", { name: "Storage + network" }).click();
  await expectText(generatedFrame.locator("#status"), "Brokered backend responded");
  await expectText(generatedFrame.locator("#result"), "worker.brokerDemo");
  await expectText(generatedFrame.locator("#result"), "storage_file");
  await expectText(generatedFrame.locator("#result"), "notes/generated-broker-demo.txt");
  await expectText(generatedFrame.locator("#result"), "storage_kv");
  await expectText(generatedFrame.locator("#result"), "demo/last_broker_run");
  await expectText(generatedFrame.locator("#result"), "storage_sqlite");
  await expectText(generatedFrame.locator("#result"), "plugin.sqlite");
  await expectText(generatedFrame.locator("#result"), "network_execute");
  await expectText(generatedFrame.locator("#result"), "network_execute_websocket");
  await expectText(generatedFrame.locator("#result"), "network_execute_tcp");
  await expectText(generatedFrame.locator("#result"), "network_execute_udp");
  await expectText(generatedFrame.locator("#result"), "host-network-executor");
  await expectText(generatedFrame.locator("#result"), "\"gateway_token_visible\": false");
  await expectText(generatedFrame.locator("#result"), "\"storage_grant_visible\": false");
  await expectText(generatedFrame.locator("#result"), "\"network_grant_visible\": false");
  await expectText(page.locator("#rpc-count"), "2");

  const generatedDisable = JSON.parse(await runCLI(["dev-disable", generatedStateRoot]));
  assert.equal(generatedDisable.enable_state, "disabled");
  const generatedUninstall = JSON.parse(await runCLI(["dev-uninstall", generatedStateRoot, "--delete-data"]));
  assert.equal(generatedUninstall.retained_data_state, "deleted");
  assert.equal(generatedUninstall.package_retained, false);

  const unexpectedConsoleErrors = consoleErrors.filter((entry) => !isExpectedSandboxPermissionViolation(entry));
  assert.deepEqual(unexpectedConsoleErrors, []);
  await browser.close();
  console.log("browser demo smoke passed");
} finally {
  server.kill("SIGTERM");
  await Promise.race([once(server, "exit"), delay(1_000)]);
  await rm(generatedRoot, { recursive: true, force: true });
}

async function expectText(locator, expected, timeoutMs = 5_000) {
  const deadline = Date.now() + timeoutMs;
  let last = "";
  while (Date.now() < deadline) {
    try {
      last = (await locator.textContent()) ?? "";
      if (last.includes(expected)) {
        return;
      }
    } catch {
      // Retry until the page has finished wiring the sandbox frame.
    }
    await delay(50);
  }
  throw new Error(`expected text ${JSON.stringify(expected)} but last saw ${JSON.stringify(last)}`);
}

async function expectMissingText(locator, unexpected, timeoutMs = 1_000) {
  const deadline = Date.now() + timeoutMs;
  let last = "";
  while (Date.now() < deadline) {
    try {
      last = (await locator.textContent()) ?? "";
      if (last.includes(unexpected)) {
        throw new Error(`unexpected text ${JSON.stringify(unexpected)} still visible in ${JSON.stringify(last)}`);
      }
    } catch (error) {
      if (String(error?.message ?? "").startsWith("unexpected text")) {
        throw error;
      }
    }
    await delay(50);
  }
}

async function canvasChecksum(locator) {
  return locator.evaluate((canvas) => {
    const context = canvas.getContext("2d");
    const { data } = context.getImageData(0, 0, canvas.width, canvas.height);
    let checksum = 0;
    for (let index = 0; index < data.length; index += 97) {
      checksum = (checksum + data[index] * (index + 1)) % 1000000007;
    }
    return checksum;
  });
}

async function assertPluginBrowserSecurity(page, frame, pluginOrigin) {
  const before = await runSandboxSecurityProbe(frame, "write");
  assert.equal(before.localStorageValue, "dirty");
  assert.equal(before.indexedDBValue, "dirty");
  assert.equal(before.cacheSupported, true);
  assert.equal(before.cacheMatched, true);
  assert.equal(before.cameraAllowed, false);
  assert.equal(before.microphoneAllowed, false);
  assert.notEqual(before.mediaCapture, "allowed");

  const cdp = await page.context().newCDPSession(page);
  try {
    await cdp.send("Storage.clearDataForOrigin", {
      origin: pluginOrigin,
      storageTypes: "local_storage,indexeddb,cache_storage",
    });
  } finally {
    await cdp.detach();
  }

  const after = await runSandboxSecurityProbe(frame, "read");
  assert.equal(after.localStorageValue, null);
  assert.equal(after.indexedDBValue, null);
  assert.equal(after.cacheMatched, false);
}

async function runSandboxSecurityProbe(frame, mode) {
  return frame.locator("body").evaluate(async (_body, probeMode) => {
    const storageKey = "redevplugin-security-probe";
    const dbName = "redevplugin-security-probe-db";
    const storeName = "items";
    const cacheName = "redevplugin-security-probe-cache";
    const cacheRequest = new Request(`${window.location.origin}/demo/browser/security-probe.txt`);

    const requestToPromise = (request) =>
      new Promise((resolve, reject) => {
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error ?? new Error("indexedDB request failed"));
      });

    const deleteDatabase = () =>
      new Promise((resolve, reject) => {
        const request = indexedDB.deleteDatabase(dbName);
        request.onsuccess = () => resolve();
        request.onerror = () => reject(request.error ?? new Error("indexedDB delete failed"));
        request.onblocked = () => resolve();
      });

    const openDatabase = () =>
      new Promise((resolve, reject) => {
        const request = indexedDB.open(dbName, 1);
        request.onupgradeneeded = () => {
          request.result.createObjectStore(storeName);
        };
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error ?? new Error("indexedDB open failed"));
      });

    const writeIndexedDB = async (value) => {
      const database = await openDatabase();
      try {
        const transaction = database.transaction(storeName, "readwrite");
        transaction.objectStore(storeName).put(value, storageKey);
        await new Promise((resolve, reject) => {
          transaction.oncomplete = () => resolve();
          transaction.onerror = () => reject(transaction.error ?? new Error("indexedDB write failed"));
        });
      } finally {
        database.close();
      }
    };

    const readIndexedDB = async () => {
      let database;
      try {
        database = await openDatabase();
        if (!database.objectStoreNames.contains(storeName)) {
          return null;
        }
        const transaction = database.transaction(storeName, "readonly");
        const result = await requestToPromise(transaction.objectStore(storeName).get(storageKey));
        return result ?? null;
      } catch {
        return null;
      } finally {
        database?.close();
      }
    };

    const cacheMatched = async () => {
      if (!("caches" in window)) {
        return false;
      }
      return Boolean(await caches.match(cacheRequest));
    };

    if (probeMode === "write") {
      localStorage.setItem(storageKey, "dirty");
      await deleteDatabase();
      await writeIndexedDB("dirty");
      if ("caches" in window) {
        const cache = await caches.open(cacheName);
        await cache.put(cacheRequest, new Response("dirty", { headers: { "Content-Type": "text/plain" } }));
      }
    }

    const policy = document.permissionsPolicy ?? document.featurePolicy ?? null;
    const mediaCapture = await probeMediaCapture();
    return {
      localStorageValue: localStorage.getItem(storageKey),
      indexedDBValue: await readIndexedDB(),
      cacheSupported: "caches" in window,
      cacheMatched: await cacheMatched(),
      cameraAllowed: policy?.allowsFeature("camera") ?? null,
      microphoneAllowed: policy?.allowsFeature("microphone") ?? null,
      mediaCapture: mediaCapture.state,
      mediaCaptureError: mediaCapture.error,
    };

    async function probeMediaCapture() {
      if (!navigator.mediaDevices?.getUserMedia) {
        return { state: "api_unavailable", error: "" };
      }
      try {
        const stream = await Promise.race([
          navigator.mediaDevices.getUserMedia({ audio: true, video: true }),
          new Promise((_, reject) => setTimeout(() => reject(new Error("timeout")), 1_000)),
        ]);
        stream.getTracks().forEach((track) => track.stop());
        return { state: "allowed", error: "" };
      } catch (error) {
        return {
          state: "blocked",
          error: error instanceof Error ? error.name || error.message : String(error),
        };
      }
    }
  }, mode);
}

function isExpectedSandboxPermissionViolation(entry) {
  return /^error: Permissions policy violation: (camera|microphone) is not allowed in this document\.$/.test(entry);
}

async function waitForHTTP(url, timeoutMs = 5_000) {
  const deadline = Date.now() + timeoutMs;
  let lastError;
  while (Date.now() < deadline) {
    if (server.exitCode != null) {
      throw new Error(`demo server exited early with code ${server.exitCode}\n${serverOutput}`);
    }
    try {
      const response = await fetch(url);
      if (response.ok) {
        return;
      }
      lastError = new Error(`HTTP ${response.status}`);
    } catch (error) {
      lastError = error;
    }
    await delay(50);
  }
  throw new Error(`demo server was not ready: ${lastError?.message ?? "unknown error"}\n${serverOutput}`);
}

async function runCLI(args) {
  const command = spawn("go", ["run", "./cmd/redevplugin", ...args], {
    cwd: new URL("../..", import.meta.url),
    env: { ...process.env, GOWORK: "off" },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let output = "";
  command.stdout.on("data", (chunk) => {
    output += String(chunk);
  });
  command.stderr.on("data", (chunk) => {
    output += String(chunk);
  });
  const [code] = await once(command, "exit");
  if (code !== 0) {
    throw new Error(`redevplugin ${args.join(" ")} failed with code ${code}\n${output}`);
  }
  return output;
}

function getFreePort(except) {
  return new Promise((resolve, reject) => {
    const probe = createServer();
    probe.on("error", reject);
    probe.listen(0, "127.0.0.1", () => {
      const address = probe.address();
      if (!address || typeof address === "string") {
        reject(new Error("failed to allocate a local TCP port"));
        return;
      }
      const port = address.port;
      probe.close(() => {
        if (port === except) {
          getFreePort(except).then(resolve, reject);
          return;
        }
        resolve(port);
      });
    });
  });
}

async function launchBrowser() {
  try {
    return await chromium.launch({ headless: true });
  } catch (error) {
    if (!String(error?.message ?? error).includes("Executable doesn't exist")) {
      throw error;
    }
  }
  try {
    return await chromium.launch({ channel: "chrome", headless: true });
  } catch (error) {
    throw new Error(`failed to launch a browser for the demo smoke. Run "npx playwright install chromium" or install Google Chrome.\n${error?.message ?? error}`);
  }
}
