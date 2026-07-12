#!/usr/bin/env node

import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";

const [version, expectedSourceCommit] = process.argv.slice(2);
if (!/^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/.test(version ?? "") || !/^[0-9a-f]{40}$/.test(expectedSourceCommit ?? "")) {
  console.error("usage: verify_go_module_readback.mjs <version> <source-commit>");
  process.exit(2);
}

const modulePath = "github.com/floegence/redevplugin";
const moduleVersion = `v${version}`;
const goRoot = run("go", ["env", "GOROOT"], process.env, "resolve Go toolchain").trim();
const goBinary = join(goRoot, "bin", process.platform === "win32" ? "go.exe" : "go");
if (!existsSync(goBinary)) {
  throw new Error(`resolved Go binary does not exist: ${goBinary}`);
}

const tempRoot = mkdtempSync(join(tmpdir(), "redevplugin-go-readback-"));
try {
  const direct = downloadModule("direct", "off", join(tempRoot, "direct"));
  const proxy = downloadModule("https://proxy.golang.org", "sum.golang.org", join(tempRoot, "proxy"));
  validateModuleIdentity(direct, "direct");
  validateModuleIdentity(proxy, "proxy");
  if (direct.Origin?.Hash !== expectedSourceCommit || direct.Origin?.Ref !== `refs/tags/${moduleVersion}`) {
    throw new Error(`direct module origin does not match ${moduleVersion}@${expectedSourceCommit}`);
  }
  if (direct.Sum !== proxy.Sum || direct.GoModSum !== proxy.GoModSum) {
    throw new Error(`Go proxy module identity mismatch: direct ${direct.Sum}/${direct.GoModSum}, proxy ${proxy.Sum}/${proxy.GoModSum}`);
  }
  console.log(`Go module ${modulePath}@${moduleVersion} verified at ${expectedSourceCommit} (${proxy.Sum})`);
} finally {
  rmSync(tempRoot, { recursive: true, force: true });
}

function downloadModule(proxy, sumdb, moduleCache) {
  const goFlags = [process.env.GOFLAGS, "-modcacherw"].filter(Boolean).join(" ");
  const output = run(goBinary, ["mod", "download", "-json", `${modulePath}@${moduleVersion}`], {
    ...process.env,
    GOFLAGS: goFlags,
    GOMODCACHE: moduleCache,
    GOPROXY: proxy,
    GOSUMDB: sumdb,
    GOTOOLCHAIN: "local",
    GOWORK: "off",
  }, `download ${moduleVersion} from ${proxy}`);
  const result = JSON.parse(output);
  if (typeof result.Error === "string" && result.Error.length > 0) {
    throw new Error(`${proxy} returned module error: ${result.Error}`);
  }
  return result;
}

function validateModuleIdentity(result, label) {
  if (result.Path !== modulePath || result.Version !== moduleVersion) {
    throw new Error(`${label} module identity mismatch: ${result.Path}@${result.Version}`);
  }
  for (const [name, value] of [["Sum", result.Sum], ["GoModSum", result.GoModSum]]) {
    if (typeof value !== "string" || !/^h1:[A-Za-z0-9+/]+={0,2}$/.test(value)) {
      throw new Error(`${label} ${name} is invalid`);
    }
  }
}

function run(command, args, env, label) {
  const result = spawnSync(command, args, { encoding: "utf8", env, maxBuffer: 4 * 1024 * 1024 });
  if (result.status !== 0) {
    throw new Error(`${label} failed: ${result.stderr || result.stdout || result.error}`);
  }
  return result.stdout;
}
