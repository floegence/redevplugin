import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { createServer } from "node:net";
import { setTimeout as delay } from "node:timers/promises";
import { chromium } from "playwright";

const hostPort = await getFreePort();
const pluginPort = await getFreePort(hostPort);
const hostURL = `http://127.0.0.1:${hostPort}/demo/browser/index.html?plugin_origin=http://127.0.0.1:${pluginPort}`;
const server = spawn(process.execPath, ["demo/browser/server.mjs"], {
  cwd: new URL("../..", import.meta.url),
  env: {
    ...process.env,
    HOST_PORT: String(hostPort),
    PLUGIN_PORT: String(pluginPort),
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

  const frame = page.frameLocator("#plugin-frame");
  await expectText(frame.locator("#plugin-status"), "ready");

  await frame.getByRole("button", { name: "Echo" }).click();
  await expectText(frame.locator("#plugin-result"), "hello from iframe");
  await expectText(page.locator("#rpc-count"), "1");

  await frame.getByRole("button", { name: "List files" }).click();
  await expectText(frame.locator("#plugin-result"), "workspace/readme.md");
  await expectText(page.locator("#rpc-count"), "2");

  await frame.getByRole("button", { name: "Delete cache" }).click();
  await expectText(page.locator("#confirmation-method"), "demo.cache.delete");
  await page.getByRole("button", { name: "Deny" }).click();
  await expectText(frame.locator("#plugin-result"), "PLUGIN_CONFIRMATION_REJECTED");
  await expectText(page.locator("#confirmation-count"), "1");

  await frame.getByRole("button", { name: "Delete cache" }).click();
  await expectText(page.locator("#confirmation-method"), "demo.cache.delete");
  await page.getByRole("button", { name: "Approve" }).click();
  await expectText(frame.locator("#plugin-result"), "\"deleted\": true");
  await expectText(page.locator("#rpc-count"), "5");
  await expectText(page.locator("#confirmation-count"), "2");

  await page.getByRole("button", { name: "Visible" }).click();
  await expectText(frame.locator("#plugin-status"), "visible");
  await expectText(frame.locator("#plugin-result"), "\"lifecycle\": \"visible\"");

  assert.deepEqual(consoleErrors, []);
  await browser.close();
  console.log("browser demo smoke passed");
} finally {
  server.kill("SIGTERM");
  await Promise.race([once(server, "exit"), delay(1_000)]);
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
