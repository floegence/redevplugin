import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { mkdtemp, rm } from "node:fs/promises";
import { createServer } from "node:net";
import { join } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { tmpdir } from "node:os";
import { chromium } from "playwright";

const toolEnv = withUserToolchainPath(process.env);
const hostPort = await getFreePort();
const pluginPort = await getFreePort(hostPort);
const stateRoot = await mkdtemp(join(tmpdir(), "redevplugin-real-runtime-demo-"));
const binRoot = await mkdtemp(join(tmpdir(), "redevplugin-real-runtime-bin-"));
const runtimePath = await buildRuntime();
const cliPath = await buildCLI(binRoot);
const hostName = "app.redevplugin.localhost";
const sandboxHost = "plg-real.redevplugin.localhost";
const server = spawn(cliPath, ["demo-real-server", stateRoot, runtimePath], {
  cwd: new URL("../..", import.meta.url),
  env: {
    ...process.env,
    GOWORK: "off",
    REAL_DEMO_HOST_PORT: String(hostPort),
    REAL_DEMO_PLUGIN_PORT: String(pluginPort),
    REAL_DEMO_HOST_NAME: hostName,
    REAL_DEMO_SANDBOX_HOST: sandboxHost,
  },
  stdio: ["ignore", "pipe", "pipe"],
});

let serverOutput = "";
let browser;
server.stdout.on("data", (chunk) => {
  serverOutput += String(chunk);
});
server.stderr.on("data", (chunk) => {
  serverOutput += String(chunk);
});

try {
  const hostURL = `http://${hostName}:${hostPort}/demo/real/index.html`;
  const sandboxOrigin = `http://${sandboxHost}:${pluginPort}`;
  await waitForHTTP(hostURL);
  const assetBeforeBootstrap = await fetch(`${sandboxOrigin}/_redevplugin/assets/ui/index.html`);
  assert.equal(assetBeforeBootstrap.status, 403);
  const sandboxManagementProbe = await fetch(`${sandboxOrigin}/_redevplugin/api/plugins/install`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: "{}",
  });
  assert.equal(sandboxManagementProbe.status, 404);
  browser = await launchBrowser();
  const page = await browser.newPage({ viewport: { width: 1280, height: 720 } });
  const consoleErrors = [];
  const requestedURLs = [];
  const responseHeaders = new Map();
  const responseHeaderReads = [];
  page.on("request", (request) => {
    requestedURLs.push(request.url());
  });
  page.on("response", (response) => {
    const url = response.url();
    if (url.includes("/_redevplugin/bootstrap") || url.includes("/_redevplugin/assets/ui/index.html")) {
      responseHeaderReads.push(response.allHeaders().then((headers) => {
        responseHeaders.set(url, headers);
      }));
    }
  });
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
  await expectText(page.locator("#runtime-ready"), "1");
  await Promise.all(responseHeaderReads);
  const iframeSrc = await page.locator("#plugin-frame").getAttribute("src");
  assert.ok(iframeSrc?.startsWith(`${sandboxOrigin}/_redevplugin/assets/ui/index.html?`), iframeSrc ?? "");
  assert.equal(new URL(iframeSrc).searchParams.has("asset_ticket"), false);
  assert.ok(requestedURLs.some((url) => url === `${sandboxOrigin}/_redevplugin/bootstrap`));
  assert.ok(requestedURLs.some((url) => url.startsWith(`${sandboxOrigin}/_redevplugin/assets/ui/index.html?`)));
  assert.equal(requestedURLs.some((url) => url.startsWith(`${sandboxOrigin}/ui/index.html`)), false);
  const bootstrapHeaders = headerEntry(responseHeaders, `${sandboxOrigin}/_redevplugin/bootstrap`);
  const setCookie = bootstrapHeaders["set-cookie"] ?? "";
  assert.match(setCookie, /__Host-redevplugin-asset-session=/);
  assert.match(setCookie, /HttpOnly/i);
  assert.match(setCookie, /Secure/i);
  assert.match(setCookie, /SameSite=Strict/i);
  assert.match(setCookie, /Path=\//i);
  assert.equal(/Domain=/i.test(setCookie), false);
  const assetHeaders = headerEntry(responseHeaders, `${sandboxOrigin}/_redevplugin/assets/ui/index.html`);
  assert.equal(assetHeaders["x-content-type-options"], "nosniff");

  const frame = page.frameLocator("#plugin-frame");
  await expectText(frame.locator("#status"), "Ready");
  await frame.getByRole("button", { name: "Invoke backend" }).click();
  await expectText(frame.locator("#status"), "Backend responded");
  await expectText(frame.locator("#result"), "rust runtime ipc");
  await expectText(frame.locator("#result"), "\"worker_id\": \"backend\"");
  await expectText(page.locator("#rpc-count"), "1");

  await frame.getByRole("button", { name: "Dangerous action" }).click();
  await expectText(page.locator("#confirmation-method"), "danger.run");
  await page.getByRole("button", { name: "Deny" }).click();
  await expectText(frame.locator("#status"), "Dangerous action blocked");
  await expectText(frame.locator("#result"), "PLUGIN_CONFIRMATION_REJECTED");
  await expectText(page.locator("#rpc-count"), "2");

  await frame.getByRole("button", { name: "Dangerous action" }).click();
  await expectText(page.locator("#confirmation-method"), "danger.run");
  await page.getByRole("button", { name: "Approve" }).click();
  await expectText(frame.locator("#status"), "Dangerous action confirmed");
  await expectText(frame.locator("#result"), "real http adapter confirmation");
  await expectText(frame.locator("#result"), "\"asset_ticket_visible\": false");
  await expectText(frame.locator("#result"), "\"gateway_token_visible\": false");
  await expectText(frame.locator("#result"), "\"confirmation_token_visible\": false");
  await expectText(page.locator("#rpc-count"), "4");

  const sandbox = await page.locator("#plugin-frame").getAttribute("sandbox");
  assert.equal(sandbox, "allow-scripts allow-same-origin");
  assert.deepEqual(consoleErrors.filter((entry) => !entry.includes("409 (Conflict)")), []);
  console.log("real runtime browser smoke passed");
} finally {
  await browser?.close();
  await stopServer();
  await rm(stateRoot, { recursive: true, force: true });
  await rm(binRoot, { recursive: true, force: true });
}

async function buildRuntime() {
  const command = spawn("cargo", ["build", "-p", "redevplugin-runtime"], {
    cwd: new URL("../..", import.meta.url),
    env: { ...toolEnv, CARGO_TERM_COLOR: "never" },
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
    throw new Error(`cargo build -p redevplugin-runtime failed with code ${code}\n${output}`);
  }
  return new URL("../../target/debug/redevplugin-runtime", import.meta.url).pathname;
}

async function buildCLI(outDir) {
  const filename = join(outDir, process.platform === "win32" ? "redevplugin.exe" : "redevplugin");
  const command = spawn("go", ["build", "-o", filename, "./cmd/redevplugin"], {
    cwd: new URL("../..", import.meta.url),
    env: { ...toolEnv, GOWORK: "off" },
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
    throw new Error(`go build ./cmd/redevplugin failed with code ${code}\n${output}`);
  }
  return filename;
}

async function stopServer() {
  if (server.exitCode != null) {
    return;
  }
  server.kill("SIGTERM");
  const timeout = delay(1_000).then(() => "timeout");
  const exited = once(server, "exit").then(() => "exit");
  if ((await Promise.race([exited, timeout])) === "timeout") {
    server.kill("SIGKILL");
    await Promise.race([once(server, "exit"), delay(1_000)]);
  }
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
      // Retry until the host page and sandbox frame finish wiring.
    }
    await delay(50);
  }
  throw new Error(`expected text ${JSON.stringify(expected)} but last saw ${JSON.stringify(last)}`);
}

async function waitForHTTP(url, timeoutMs = 10_000) {
  const deadline = Date.now() + timeoutMs;
  let lastError;
  while (Date.now() < deadline) {
    if (server.exitCode != null) {
      throw new Error(`real demo server exited early with code ${server.exitCode}\n${serverOutput}`);
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
  throw new Error(`real demo server was not ready: ${lastError?.message ?? "unknown error"}\n${serverOutput}`);
}

function headerEntry(headersByURL, urlPrefix) {
  for (const [url, headers] of headersByURL.entries()) {
    if (url.startsWith(urlPrefix)) {
      return headers;
    }
  }
  throw new Error(`missing response headers for ${urlPrefix}`);
}

async function getFreePort(excluding) {
  for (;;) {
    const port = await new Promise((resolve, reject) => {
      const server = createServer();
      server.listen(0, "127.0.0.1", () => {
        const address = server.address();
        server.close(() => {
          if (address && typeof address === "object") {
            resolve(address.port);
            return;
          }
          reject(new Error("no TCP port allocated"));
        });
      });
      server.on("error", reject);
    });
    if (port !== excluding) {
      return port;
    }
  }
}

async function launchBrowser() {
  try {
    return await chromium.launch({ channel: "chrome", headless: true });
  } catch {
    try {
      return await chromium.launch({ channel: "msedge", headless: true });
    } catch {
      return chromium.launch({ headless: true });
    }
  }
}

function withUserToolchainPath(env) {
  const home = env.HOME;
  if (!home) {
    return { ...env };
  }
  const cargoBin = join(home, ".cargo", "bin");
  const pathValue = env.PATH ?? "";
  if (pathValue.split(":").includes(cargoBin)) {
    return { ...env };
  }
  return { ...env, PATH: `${cargoBin}:${pathValue}` };
}
