import { spawn } from "node:child_process";
import { once } from "node:events";
import { mkdtemp, rm } from "node:fs/promises";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { setTimeout as delay } from "node:timers/promises";

const repoRoot = new URL("../..", import.meta.url);
const toolEnv = withUserToolchainPath(process.env);
const hostPort = Number(process.env.REAL_DEMO_HOST_PORT || (await getFreePort()));
const pluginPort = Number(process.env.REAL_DEMO_PLUGIN_PORT || (await getFreePort(hostPort)));
const hostName = process.env.REAL_DEMO_HOST_NAME || "app.redevplugin.localhost";
const sandboxHost = process.env.REAL_DEMO_SANDBOX_HOST || "plg-real.redevplugin.localhost";
const stateRoot = await mkdtemp(join(tmpdir(), "redevplugin-real-demo-"));
const binRoot = await mkdtemp(join(tmpdir(), "redevplugin-real-demo-bin-"));
let server;
let cleanupStarted = false;

try {
  const runtimePath = await buildRuntime();
  const cliPath = await buildCLI(binRoot);
  server = spawn(cliPath, ["demo-real-server", stateRoot, runtimePath], {
    cwd: repoRoot,
    env: {
      ...toolEnv,
      GOWORK: "off",
      REAL_DEMO_HOST_PORT: String(hostPort),
      REAL_DEMO_PLUGIN_PORT: String(pluginPort),
      REAL_DEMO_HOST_NAME: hostName,
      REAL_DEMO_SANDBOX_HOST: sandboxHost,
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
      void cleanup().then(() => process.exit(code ?? 1));
    }
  });

  const hostURL = `http://${hostName}:${hostPort}/demo/real/index.html`;
  await waitForHTTP(hostURL, () => serverOutput);

  console.log("");
  console.log("ReDevPlugin real runtime demo is ready.");
  console.log(`Open: ${hostURL}`);
  console.log(`State root: ${stateRoot}`);
  console.log(`Sandbox origin: http://${sandboxHost}:${pluginPort}`);
  console.log("Press Ctrl+C to stop the demo server and delete the temporary demo state.");

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

async function buildRuntime() {
  const command = spawn("cargo", ["build", "-p", "redevplugin-runtime"], {
    cwd: repoRoot,
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
    cwd: repoRoot,
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

async function cleanup() {
  if (cleanupStarted) {
    return;
  }
  cleanupStarted = true;
  if (server && server.exitCode == null) {
    server.kill("SIGTERM");
    await Promise.race([once(server, "exit"), delay(1_000)]);
  }
  await rm(stateRoot, { recursive: true, force: true });
  await rm(binRoot, { recursive: true, force: true });
}

async function waitForHTTP(url, outputProvider, timeoutMs = 10_000) {
  const deadline = Date.now() + timeoutMs;
  let lastError;
  while (Date.now() < deadline) {
    if (server?.exitCode != null) {
      throw new Error(`real demo server exited early with code ${server.exitCode}\n${outputProvider()}`);
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
  throw new Error(`real demo server was not ready: ${lastError?.message ?? "unknown error"}\n${outputProvider()}`);
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
