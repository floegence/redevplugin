#!/usr/bin/env node

import { existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { pathToFileURL } from "node:url";

const modulePath = "github.com/floegence/redevplugin";
const defaultRetryDelaysMs = Object.freeze([0, 1_000, 2_000, 4_000, 8_000, 15_000, 30_000, 30_000]);

export async function verifyGoModuleReadback({
  version,
  expectedSourceCommit,
  outputPath,
  env = process.env,
  platform = process.platform,
  retryDelaysMs = defaultRetryDelaysMs,
  sleep = sleepFor,
  logger = console.error,
} = {}) {
  assertInputs(version, expectedSourceCommit, outputPath);
  const moduleVersion = `v${version}`;
  const goRoot = run("go", ["env", "GOROOT"], env, "resolve Go toolchain").trim();
  const goBinary = join(goRoot, "bin", platform === "win32" ? "go.exe" : "go");
  if (!existsSync(goBinary)) {
    throw new Error(`resolved Go binary does not exist: ${goBinary}`);
  }

  const tempRoot = mkdtempSync(join(tmpdir(), "redevplugin-go-readback-"));
  try {
    const direct = await downloadModule({
      goBinary,
      moduleVersion,
      proxy: "direct",
      sumdb: "off",
      moduleCache: join(tempRoot, "direct"),
      env,
      retryDelaysMs,
      sleep,
      logger,
    });
    validateModuleIdentity(direct, "direct", moduleVersion);
    if (direct.Origin?.Hash !== expectedSourceCommit || direct.Origin?.Ref !== `refs/tags/${moduleVersion}`) {
      throw new Error(`direct module origin does not match ${moduleVersion}@${expectedSourceCommit}`);
    }

    const proxy = await downloadModule({
      goBinary,
      moduleVersion,
      proxy: "https://proxy.golang.org",
      sumdb: "sum.golang.org",
      moduleCache: join(tempRoot, "proxy"),
      env,
      retryDelaysMs,
      sleep,
      logger,
      allowPropagationDelay: true,
    });
    validateModuleIdentity(proxy, "proxy", moduleVersion);
    if (direct.Sum !== proxy.Sum || direct.GoModSum !== proxy.GoModSum) {
      throw new Error(`Go proxy module identity mismatch: direct ${direct.Sum}/${direct.GoModSum}, proxy ${proxy.Sum}/${proxy.GoModSum}`);
    }

    const result = {
      module: modulePath,
      version: moduleVersion,
      h1: proxy.Sum,
      go_mod_h1: proxy.GoModSum,
      source_commit: expectedSourceCommit,
    };
    if (outputPath) {
      writeFileSync(outputPath, `${JSON.stringify(result, null, 2)}\n`, { flag: "wx" });
    }
    return result;
  } finally {
    rmSync(tempRoot, { recursive: true, force: true });
  }
}

export async function retryGoModuleReadback({
  label,
  attemptDownload,
  allowPropagationDelay = false,
  retryDelaysMs = defaultRetryDelaysMs,
  sleep = sleepFor,
  logger = console.error,
}) {
  if (typeof label !== "string" || label.length === 0 || typeof attemptDownload !== "function") {
    throw new Error("Go module readback retry configuration is invalid");
  }
  if (!Array.isArray(retryDelaysMs) || retryDelaysMs.length === 0
      || retryDelaysMs.some((delay) => !Number.isSafeInteger(delay) || delay < 0)) {
    throw new Error("Go module readback retry delays are invalid");
  }

  let lastFailure;
  for (let attempt = 0; attempt < retryDelaysMs.length; attempt += 1) {
    const delay = retryDelaysMs[attempt];
    if (delay > 0) await sleep(delay);
    try {
      return await attemptDownload();
    } catch (error) {
      if (!isTransientGoModuleReadbackFailure(error, { allowPropagationDelay })) throw error;
      lastFailure = error;
      const nextDelay = retryDelaysMs[attempt + 1];
      if (nextDelay !== undefined) {
        logger(`${label} temporarily unavailable; retrying in ${nextDelay}ms (${attempt + 1}/${retryDelaysMs.length})`);
      }
    }
  }
  throw new Error(`${label} remained unavailable after ${retryDelaysMs.length} bounded attempts`, {
    cause: lastFailure,
  });
}

export function isTransientGoModuleReadbackFailure(error, { allowPropagationDelay = false } = {}) {
  const message = error instanceof Error ? error.message : String(error);
  if (/checksum mismatch|security error|module declares its path|malformed module path|invalid module path/i.test(message)) {
    return false;
  }
  if (/(?:HTTP(?: response)?(?: status)?[ :=]*)?(?:408|425|429|5\d\d)\b/i.test(message)) return true;
  if (/connection (?:reset|refused|closed)|context deadline exceeded|dial tcp|i\/o timeout|TLS handshake timeout|temporary failure in name resolution|no such host|network is unreachable|proxyconnect tcp|server misbehaving|unexpected EOF|\bEOF\b|ETIMEDOUT|ECONNRESET|ECONNREFUSED|EAI_AGAIN|ENETUNREACH|RPC failed|remote end hung up unexpectedly|HTTP\/2 stream .* not closed cleanly/i.test(message)) {
    return true;
  }
  return allowPropagationDelay && /(?:HTTP(?: response)?(?: status)?[ :=]*)?(?:404|410)\b|not found|unknown revision/i.test(message);
}

export function validateModuleIdentity(result, label, moduleVersion) {
  if (result.Path !== modulePath || result.Version !== moduleVersion) {
    throw new Error(`${label} module identity mismatch: ${result.Path}@${result.Version}`);
  }
  for (const [name, value] of [["Sum", result.Sum], ["GoModSum", result.GoModSum]]) {
    if (typeof value !== "string" || !/^h1:[A-Za-z0-9+/]+={0,2}$/.test(value)) {
      throw new Error(`${label} ${name} is invalid`);
    }
  }
}

async function downloadModule({
  goBinary,
  moduleVersion,
  proxy,
  sumdb,
  moduleCache,
  env,
  retryDelaysMs,
  sleep,
  logger,
  allowPropagationDelay = false,
}) {
  const goFlags = [env.GOFLAGS, "-modcacherw"].filter(Boolean).join(" ");
  const label = `download ${moduleVersion} from ${proxy}`;
  return retryGoModuleReadback({
    label,
    allowPropagationDelay,
    retryDelaysMs,
    sleep,
    logger,
    attemptDownload: () => runGoModuleDownload(goBinary, moduleVersion, {
      ...env,
      GOFLAGS: goFlags,
      GOMODCACHE: moduleCache,
      GOPROXY: proxy,
      GOSUMDB: sumdb,
      GOTOOLCHAIN: "local",
      GOWORK: "off",
    }, label),
  });
}

function runGoModuleDownload(goBinary, moduleVersion, env, label) {
  const result = spawnSync(goBinary, ["mod", "download", "-json", `${modulePath}@${moduleVersion}`], {
    encoding: "utf8",
    env,
    maxBuffer: 4 * 1024 * 1024,
    timeout: 30_000,
  });
  let parsed;
  if (result.stdout?.trim()) {
    try {
      parsed = JSON.parse(result.stdout);
    } catch (error) {
      throw new Error(`${label} returned invalid JSON: ${error instanceof Error ? error.message : String(error)}`);
    }
  }
  if (result.status !== 0 || result.error || (typeof parsed?.Error === "string" && parsed.Error.length > 0)) {
    const diagnostics = [parsed?.Error, result.stderr?.trim(), result.error?.message]
      .filter((value) => typeof value === "string" && value.length > 0)
      .join("; ");
    throw new Error(`${label} failed: ${diagnostics || `exit status ${result.status}`}`);
  }
  if (!parsed) throw new Error(`${label} returned empty output`);
  return parsed;
}

function assertInputs(version, expectedSourceCommit, outputPath) {
  if (!/^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/.test(version ?? "")) {
    throw new Error("Go module readback version is invalid");
  }
  if (!/^[0-9a-f]{40}$/.test(expectedSourceCommit ?? "")) {
    throw new Error("Go module readback source commit is invalid");
  }
  if (outputPath !== undefined && (typeof outputPath !== "string" || outputPath.length === 0)) {
    throw new Error("Go module readback output path is invalid");
  }
}

function run(command, args, env, label) {
  const result = spawnSync(command, args, { encoding: "utf8", env, maxBuffer: 4 * 1024 * 1024 });
  if (result.status !== 0) {
    throw new Error(`${label} failed: ${result.stderr || result.stdout || result.error}`);
  }
  return result.stdout;
}

function sleepFor(delayMs) {
  return new Promise((resolve) => setTimeout(resolve, delayMs));
}

async function main() {
  const [version, expectedSourceCommit, outputPath] = process.argv.slice(2);
  if (!version || !expectedSourceCommit || process.argv.length < 4 || process.argv.length > 5) {
    console.error("usage: verify_go_module_readback.mjs <version> <source-commit> [output-json]");
    process.exit(2);
  }
  const result = await verifyGoModuleReadback({ version, expectedSourceCommit, outputPath });
  console.log(`Go module ${result.module}@${result.version} verified at ${result.source_commit} (${result.h1})`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await main();
}
