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
const server = spawn(cliPath, ["demo-real-server", stateRoot, runtimePath], {
  cwd: new URL("../..", import.meta.url),
  env: {
    ...process.env,
    GOWORK: "off",
    REAL_DEMO_HOST_PORT: String(hostPort),
    REAL_DEMO_PLUGIN_PORT: String(pluginPort),
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
  const hostURL = `http://127.0.0.1:${hostPort}/demo/real/index.html`;
  await waitForHTTP(hostURL);
  browser = await launchBrowser();
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
  await expectText(page.locator("#runtime-ready"), "1");

  const frame = page.frameLocator("#plugin-frame");
  await expectText(frame.locator("#status"), "Ready");
  await frame.getByRole("button", { name: "Invoke backend" }).click();
  await expectText(frame.locator("#status"), "Backend responded");
  await expectText(frame.locator("#result"), "rust runtime ipc");
  await expectText(frame.locator("#result"), "\"worker_id\": \"backend\"");
  await expectText(page.locator("#rpc-count"), "1");

  const sandbox = await page.locator("#plugin-frame").getAttribute("sandbox");
  assert.equal(sandbox, "allow-scripts allow-same-origin");
  assert.deepEqual(consoleErrors, []);
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
