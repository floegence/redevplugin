import { createHash } from "node:crypto";
import { readFile, realpath, writeFile } from "node:fs/promises";
import { basename, dirname, isAbsolute, relative, resolve, sep } from "node:path";

const root = resolve(import.meta.dirname, "..");
const canonicalContractPaths = Object.freeze([
  "internal/runtime-wire-fixtures.json",
  "internal/runtime-wire.schema.json",
  "openapi/plugin-platform.yaml",
  "platform-release-manifest.schema.json",
  "plugin/bridge.schema.json",
  "plugin/error-codes.schema.json",
  "plugin/external-signer-request-v1.schema.json",
  "plugin/external-signer-response-v1.schema.json",
  "plugin/host-capability-contract-v1.schema.json",
  "plugin/host-capability-pin-v1.schema.json",
  "plugin/manifest-v9.schema.json",
  "plugin/network-grant-v2.schema.json",
  "plugin/opaque-surface-document-v3.schema.json",
  "plugin/opaque-surface-transport-v6.schema.json",
  "plugin/package-signature-v1.schema.json",
  "plugin/plugin-api.json",
  "plugin/presentation-icon-evidence-v1.schema.json",
  "plugin/presentation-locale-fixtures-v1.json",
  "plugin/process-containment-v1.schema.json",
  "plugin/publisher-release-ref-v1.schema.json",
  "plugin/quarantine-cleanup-v1.schema.json",
  "plugin/release-metadata.schema.json",
  "plugin/release-publisher-config-v1.schema.json",
  "plugin/release-revocation-pointer-v2.schema.json",
  "plugin/release-revocation-v3.schema.json",
  "plugin/release-root-delegation-v1.schema.json",
  "plugin/release-source-policy-pointer-v2.schema.json",
  "plugin/release-source-policy-v3.schema.json",
  "plugin/resource-scope-v1.schema.json",
  "plugin/runtime-admission-v1.schema.json",
  "plugin/runtime-exec-journal-v1.schema.json",
  "plugin/session-scope-v1.schema.json",
  "plugin/target-classifier-v2.json",
  "plugin/token-ticket-v4.schema.json",
  "plugin/wasm-abi.json",
  "plugin/worker-invocation.schema.json",
]);

export async function listCanonicalContractArtifacts() {
  const specRoot = resolve(root, "spec");
  return canonicalContractPaths.map((path) => ({
    name: `contract:${path}`,
    path: resolve(specRoot, path),
  }));
}

export async function generatePlatformReleaseManifest({ artifacts, output }) {
  if (!Array.isArray(artifacts) || artifacts.length === 0) {
    throw new Error("at least one --artifact name=path is required");
  }
  if (typeof output !== "string" || output.length === 0) {
    throw new Error("--output must name an external release-staging file");
  }

  const requestedOutputPath = resolve(output);
  if (isWithin(root, requestedOutputPath)) {
    throw new Error("release manifest output must be outside the repository to avoid package hash cycles");
  }
  const outputPath = resolve(await realpath(dirname(requestedOutputPath)), basename(requestedOutputPath));
  if (isWithin(root, outputPath)) {
    throw new Error("release manifest output must be outside the repository to avoid package hash cycles");
  }

  const platformVersion = (await readFile(resolve(root, "VERSION"), "utf8")).trim();
  if (!/^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/.test(platformVersion)) {
    throw new Error(`VERSION is not a release SemVer: ${JSON.stringify(platformVersion)}`);
  }
  const pluginAPI = JSON.parse(await readFile(resolve(root, "spec/plugin/plugin-api.json"), "utf8"));
  if (!Number.isSafeInteger(pluginAPI.plugin_api) || pluginAPI.plugin_api < 1 || Object.keys(pluginAPI).length !== 1) {
    throw new Error("spec/plugin/plugin-api.json must contain only a positive integer plugin_api");
  }
  const runtimeWire = JSON.parse(await readFile(resolve(root, "spec/internal/runtime-wire.schema.json"), "utf8"));
  if (!Number.isSafeInteger(runtimeWire.internal_wire) || runtimeWire.internal_wire < 1) {
    throw new Error("spec/internal/runtime-wire.schema.json must define a positive integer internal_wire");
  }

  const names = new Set();
  const entries = [];
  for (const artifact of artifacts) {
    if (!artifact || typeof artifact.name !== "string" || !/^(go|npm|crate|contract):[^\s=]+$/.test(artifact.name)) {
      throw new Error(`invalid artifact name: ${JSON.stringify(artifact?.name)}`);
    }
    if (artifact.name === "contract:platform-release-manifest") {
      throw new Error("the platform release manifest cannot list itself as an artifact");
    }
    if (names.has(artifact.name)) {
      throw new Error(`duplicate artifact name: ${artifact.name}`);
    }
    names.add(artifact.name);
    const hasPath = typeof artifact.path === "string" && artifact.path.length > 0;
    const hasDigest = typeof artifact.sha256 === "string" && artifact.sha256.length > 0;
    if (hasPath === hasDigest) {
      throw new Error(`artifact ${artifact.name} must provide exactly one of path or sha256`);
    }
    let sha256 = artifact.sha256;
    if (hasPath) {
      const artifactPath = await realpath(resolve(artifact.path));
      if (artifactPath === outputPath) {
        throw new Error("the platform release manifest cannot hash its own output");
      }
      const bytes = await readFile(artifactPath);
      sha256 = createHash("sha256").update(bytes).digest("hex");
    } else if (!/^[0-9a-f]{64}$/.test(sha256)) {
      throw new Error(`invalid artifact sha256 for ${artifact.name}`);
    }
    entries.push({
      name: artifact.name,
      sha256,
    });
  }
  entries.sort((left, right) => left.name < right.name ? -1 : left.name > right.name ? 1 : 0);

  const manifest = {
    platform_version: platformVersion,
    plugin_api: pluginAPI.plugin_api,
    internal_wire: runtimeWire.internal_wire,
    artifacts: entries,
  };
  const canonical = `${JSON.stringify(manifest, null, 2)}\n`;
  await writeFile(outputPath, canonical, { flag: "w", mode: 0o644 });
  return canonical;
}

function isWithin(parent, child) {
  const path = relative(parent, child);
  return path === "" || (!path.startsWith(`..${sep}`) && path !== "..");
}

function parseArgs(argv) {
  const artifacts = [];
  let output = "";
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === "--output") {
      output = argv[++index] ?? "";
      continue;
    }
    if (argument === "--artifact-file" || argument === "--artifact-sha256") {
      const coordinate = argv[++index] ?? "";
      const separator = coordinate.indexOf("=");
      if (separator <= 0 || separator === coordinate.length - 1) {
        throw new Error(`${argument} must use name=value`);
      }
      const value = coordinate.slice(separator + 1);
      if (argument === "--artifact-file" && !isAbsolute(value)) {
        throw new Error(`artifact path must be absolute: ${value}`);
      }
      artifacts.push(argument === "--artifact-file"
        ? { name: coordinate.slice(0, separator), path: value }
        : { name: coordinate.slice(0, separator), sha256: value });
      continue;
    }
    throw new Error(`unknown argument: ${argument}`);
  }
  return { artifacts, output };
}

const invokedPath = process.argv[1] ? await realpath(process.argv[1]) : "";
if (invokedPath === await realpath(new URL(import.meta.url))) {
  try {
    await generatePlatformReleaseManifest(parseArgs(process.argv.slice(2)));
  } catch (error) {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  }
}
