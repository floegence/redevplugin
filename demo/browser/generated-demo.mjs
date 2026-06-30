import { spawn } from "node:child_process";
import { once } from "node:events";
import { mkdtemp, rm } from "node:fs/promises";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { setTimeout as delay } from "node:timers/promises";

const repoRoot = new URL("../..", import.meta.url);
const hostPort = Number(process.env.HOST_PORT || (await getFreePort()));
const pluginPort = Number(process.env.PLUGIN_PORT || (await getFreePort(hostPort)));
const generatedRoot = await mkdtemp(join(tmpdir(), "redevplugin-generated-demo-"));
const generatedPluginDir = join(generatedRoot, "plugin");
const generatedPackage = join(generatedRoot, "generated.redevplugin");
const generatedStateRoot = join(generatedRoot, "state");
let server;
let cleanupStarted = false;

try {
  await runCLI(["scaffold", "com.example.generated.demo", "Generated Demo Plugin", generatedPluginDir]);
  await runCLI(["package", generatedPluginDir, generatedPackage]);
  await runCLI(["dev-install", generatedStateRoot, generatedPackage]);
  await runCLI(["dev-enable", generatedStateRoot]);
  const openSummary = JSON.parse(
    await runCLI(["dev-open", generatedStateRoot, "com.example.generated.demo.activity", `http://127.0.0.1:${pluginPort}`]),
  );

  server = spawn(process.execPath, ["demo/browser/server.mjs"], {
    cwd: repoRoot,
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
    process.stdout.write(chunk);
  });
  server.stderr.on("data", (chunk) => {
    serverOutput += String(chunk);
    process.stderr.write(chunk);
  });

  server.on("exit", (code) => {
    if (!cleanupStarted) {
      void cleanup().then(() => {
        process.exit(code ?? 1);
      });
    }
  });

  const generatedURL = buildGeneratedURL(openSummary);
  await waitForHTTP(generatedURL.href, () => serverOutput);

  console.log("");
  console.log("ReDevPlugin generated plugin demo is ready.");
  console.log(`Open: ${generatedURL.href}`);
  console.log(`State root: ${generatedStateRoot}`);
  console.log("Press Ctrl+C to disable, uninstall, delete plugin data, and remove the temporary demo directory.");

  process.on("SIGINT", () => {
    void cleanup().then(() => process.exit(0));
  });
  process.on("SIGTERM", () => {
    void cleanup().then(() => process.exit(0));
  });

  await new Promise(() => {});
} catch (error) {
  await cleanup();
  throw error;
}

function buildGeneratedURL(openSummary) {
  const url = new URL(`http://127.0.0.1:${hostPort}/demo/browser/index.html`);
  url.searchParams.set("plugin_origin", `http://127.0.0.1:${pluginPort}`);
  url.searchParams.set("plugin_path", "/generated-plugin/ui/index.html");
  url.searchParams.set("plugin_id", openSummary.plugin_id);
  url.searchParams.set("surface_id", openSummary.surface_id);
  url.searchParams.set("surface_instance_id", openSummary.surface_instance_id);
  url.searchParams.set("active_fingerprint", openSummary.active_fingerprint);
  url.searchParams.set("bridge_nonce", openSummary.bridge_nonce);
  return url;
}

async function cleanup() {
  if (cleanupStarted) {
    return;
  }
  cleanupStarted = true;
  if (server && server.exitCode == null) {
    server.kill("SIGTERM");
    await Promise.race([once(server, "exit"), delay(1_000)]);
  }
  await runCLI(["dev-disable", generatedStateRoot], { allowFailure: true });
  await runCLI(["dev-uninstall", generatedStateRoot, "--delete-data"], { allowFailure: true });
  await rm(generatedRoot, { recursive: true, force: true });
}

async function waitForHTTP(url, outputProvider, timeoutMs = 5_000) {
  const deadline = Date.now() + timeoutMs;
  let lastError;
  while (Date.now() < deadline) {
    if (server?.exitCode != null) {
      throw new Error(`demo server exited early with code ${server.exitCode}\n${outputProvider()}`);
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
  throw new Error(`demo server was not ready: ${lastError?.message ?? "unknown error"}\n${outputProvider()}`);
}

async function runCLI(args, options = {}) {
  const command = spawn("go", ["run", "./cmd/redevplugin", ...args], {
    cwd: repoRoot,
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
  if (code !== 0 && !options.allowFailure) {
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
