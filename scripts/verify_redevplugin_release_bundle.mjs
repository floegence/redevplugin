#!/usr/bin/env node
import { createHash, createPublicKey, generateKeyPairSync, verify as verifySignature } from "node:crypto";
import { execFileSync } from "node:child_process";
import { cpSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, relative, resolve, sep } from "node:path";

const args = process.argv.slice(2);
const structuralOnly = args.includes("--structural-only");
const positional = args.filter((arg) => arg !== "--structural-only");
const [rawBundleDir, rawExpectedVersion] = positional;
const exactStableSemanticVersionPattern = /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/;

if (!rawBundleDir || positional.length > 2) {
  console.error("usage: verify_redevplugin_release_bundle.mjs [--structural-only] <bundle-dir> [expected-version]");
  process.exit(2);
}

const bundleDir = resolve(rawBundleDir);
const releaseManifestPath = join(bundleDir, "release-manifest.json");
const sha256SumsPath = join(bundleDir, "SHA256SUMS");
const manifest = readJSON(releaseManifestPath);
const expectedVersion = rawExpectedVersion || manifest.version;

verifyReleaseManifestShape(manifest, expectedVersion);
verifyManifestFiles(bundleDir, manifest);
verifyRequiredArtifacts(bundleDir);
verifyExecutableTargets(bundleDir, manifest.runtime_target);
verifyCompatibility(bundleDir, expectedVersion, manifest, structuralOnly);
verifyRuntimeHello(bundleDir, expectedVersion, structuralOnly);
await verifyNpmTarball(bundleDir, expectedVersion, manifest);
verifyNoticeEvidence(bundleDir);
verifyHostCapabilitySample(bundleDir, manifest, structuralOnly);

console.log(`release bundle verified: ${bundleDir}`);

function verifyReleaseManifestShape(manifest, expectedVersion) {
  assertObject(manifest, "release-manifest.json");
  assertExactKeys(manifest, [
    "schema_version",
    "version",
    "source_commit",
    "runtime_target",
    "generated_at",
    "compatibility_sha256",
    "npm_package",
    "files",
  ], "release manifest");
  assertEqual(manifest.schema_version, "redevplugin.release_manifest.v2", "release manifest schema_version");
  assertEqual(manifest.version, expectedVersion, "release manifest version");
  assertGitCommit(manifest.source_commit, "release manifest source_commit");
  if (manifest.runtime_target !== null && typeof manifest.runtime_target !== "string") {
    fail("release manifest runtime_target must be a string or null");
  }
  if (!Number.isFinite(Date.parse(manifest.generated_at))) {
    fail("release manifest generated_at must be an ISO date-time string");
  }
  assertHexSHA256(manifest.compatibility_sha256, "release manifest compatibility_sha256");
  verifyNpmManifestEntry(manifest.npm_package, expectedVersion);
  if (!Array.isArray(manifest.files) || manifest.files.length === 0) {
    fail("release manifest files must be a non-empty array");
  }
  const seen = new Set();
  for (const [index, file] of manifest.files.entries()) {
    assertObject(file, `release manifest files[${index}]`);
    assertBundlePath(file.path, `release manifest files[${index}].path`);
    assertHexSHA256(file.sha256, `release manifest files[${index}].sha256`);
    if (!Number.isSafeInteger(file.size) || file.size < 0) {
      fail(`release manifest files[${index}].size must be a non-negative safe integer`);
    }
    if (seen.has(file.path)) {
      fail(`release manifest contains duplicate file path ${file.path}`);
    }
    seen.add(file.path);
  }
}

function verifyManifestFiles(bundleDir, manifest) {
  const actualFiles = listBundleFiles(bundleDir);
  const manifestFiles = manifest.files.map((file) => ({
    path: file.path,
    sha256: file.sha256,
    size: file.size,
  }));
  manifestFiles.sort((a, b) => a.path.localeCompare(b.path));
  assertDeepEqual(manifestFiles, actualFiles, "release manifest file list");

  const expectedSums = manifestFiles.map((file) => `${file.sha256}  ${file.path}`).join("\n") + "\n";
  const actualSums = readFileSync(sha256SumsPath, "utf8");
  assertEqual(actualSums, expectedSums, "SHA256SUMS content");
}

function verifyRequiredArtifacts(bundleDir) {
  const requiredFiles = [
    "AGENTS.md",
    "CHANGELOG.md",
    "docs/release/a2-tdd-evidence.md",
    "docs/release/a3-tdd-evidence.md",
    "LICENSE",
    "README.md",
    "THIRD_PARTY_NOTICES.md",
    "bin/redevplugin",
    "bin/redevplugin-runtime",
    "compatibility.json",
    "contracts/spec/openapi/plugin-platform-v2.yaml",
    "contracts/spec/plugin/bridge-v2.schema.json",
    "contracts/spec/plugin/compatibility-manifest-v2.schema.json",
    "contracts/spec/plugin/error-codes-v1.schema.json",
    "contracts/spec/plugin/host-capability-contract-v1.schema.json",
    "contracts/spec/plugin/host-capability-pin-v1.schema.json",
    "contracts/spec/plugin/host-capability-manifest-v1.schema.json",
    "contracts/spec/plugin/host-capability-compatibility-v1.schema.json",
    "contracts/spec/plugin/host-capability-signature-v1.schema.json",
    "contracts/spec/plugin/host-capability-notices-v1.schema.json",
    "contracts/spec/plugin/ipc-v1.schema.json",
    "contracts/spec/plugin/manifest-v2.schema.json",
    "contracts/spec/plugin/opaque-surface-document-v1.schema.json",
    "contracts/spec/plugin/opaque-surface-transport-v1.schema.json",
    "contracts/spec/plugin/release-metadata-v2.schema.json",
    "contracts/spec/plugin/release-manifest-v2.schema.json",
    "contracts/spec/plugin/source-policy-v1.schema.json",
    "contracts/spec/plugin/source-revocations-v1.schema.json",
    "contracts/spec/plugin/token-ticket-v2.schema.json",
    "contracts/spec/plugin/worker-invocation-v1.schema.json",
    "examples/host-capability/sample-documents-v1/example-documents.public.json",
    "examples/host-capability/sample-documents-v1/host-capability.pin.json",
    "examples/host-capability/sample-documents-v1/plugin-consumer.ts",
    "examples/host-capability/sample-documents-v1/capabilities/example.documents/v1.0.0/example.documents.v1.client.ts",
    "examples/host-capability/sample-documents-v1/capabilities/example.documents/v1.0.0/example.documents.v1.compatibility.json",
    "examples/host-capability/sample-documents-v1/capabilities/example.documents/v1.0.0/example.documents.v1.manifest.json",
    "examples/host-capability/sample-documents-v1/capabilities/example.documents/v1.0.0/example.documents.v1.notices.json",
    "examples/host-capability/sample-documents-v1/capabilities/example.documents/v1.0.0/example.documents.v1.schema.json",
    "examples/host-capability/sample-documents-v1/capabilities/example.documents/v1.0.0/example.documents.v1.sig",
    "notices/Cargo.lock",
    "notices/THIRD_PARTY_LICENSES.json",
    "notices/go.sum",
    "notices/package-lock.json",
  ];
  for (const path of requiredFiles) {
    assertFile(join(bundleDir, path), path);
  }
  assertExecutable(join(bundleDir, "bin/redevplugin"), "bin/redevplugin");
  assertExecutable(join(bundleDir, "bin/redevplugin-runtime"), "bin/redevplugin-runtime");
}

function verifyCompatibility(bundleDir, expectedVersion, manifest, skipExecution) {
  const compatibilityPath = join(bundleDir, "compatibility.json");
  const compatibilityBytes = readFileSync(compatibilityPath);
  assertEqual(
    createHash("sha256").update(compatibilityBytes).digest("hex"),
    manifest.compatibility_sha256,
    "compatibility manifest sha256",
  );
  const compatibility = readJSON(compatibilityPath);
  assertObject(compatibility, "compatibility.json");
  assertExactKeys(compatibility, ["schema_version", "matrix", "contracts"], "compatibility manifest");
  assertEqual(compatibility.schema_version, "redevplugin.compatibility.v2", "compatibility schema_version");
  assertObject(compatibility.matrix, "compatibility matrix");
  for (const key of ["redevplugin_go_version", "redevplugin_ui_version", "redevplugin_runtime_version"]) {
    assertEqual(compatibility.matrix?.[key], expectedVersion, `compatibility matrix ${key}`);
  }
  if (!Array.isArray(compatibility.contracts) || compatibility.contracts.length === 0) {
    fail("compatibility contracts must be a non-empty array");
  }
  const contractIDs = new Set();
  const contractPaths = new Set();
  for (const [index, contract] of compatibility.contracts.entries()) {
    assertObject(contract, `compatibility contracts[${index}]`);
    assertExactKeys(contract, ["id", "path", "version", "sha256"], `compatibility contracts[${index}]`);
    if (typeof contract.id !== "string" || !/^[a-z][a-z0-9-]+$/.test(contract.id) || contractIDs.has(contract.id)) {
      fail(`compatibility contracts[${index}].id is invalid or duplicated`);
    }
    assertBundlePath(contract.path, `compatibility contracts[${index}].path`);
    if (!contract.path.startsWith("spec/") || contractPaths.has(contract.path)) {
      fail(`compatibility contracts[${index}].path is invalid or duplicated`);
    }
    if (typeof contract.version !== "string" || contract.version.length === 0) {
      fail(`compatibility contracts[${index}].version must be non-empty`);
    }
    assertHexSHA256(contract.sha256, `compatibility contracts[${index}].sha256`);
    const contractPath = join(bundleDir, "contracts", contract.path);
    assertFile(contractPath, `contracts/${contract.path}`);
    assertEqual(
      createHash("sha256").update(readFileSync(contractPath)).digest("hex"),
      contract.sha256,
      `compatibility contract ${contract.id} sha256`,
    );
    contractIDs.add(contract.id);
    contractPaths.add(contract.path);
  }
  if (skipExecution) return;
  const verifyOutput = execFileSync(
    join(bundleDir, "bin/redevplugin"),
    ["verify-compatibility", compatibilityPath, join(bundleDir, "contracts")],
    { encoding: "utf8" },
  );
  const summary = JSON.parse(verifyOutput);
  assertEqual(summary.ok, true, "verify-compatibility summary");
}

function verifyRuntimeHello(bundleDir, expectedVersion, skipExecution) {
  if (skipExecution || process.env.REDEVPLUGIN_SKIP_RUNTIME_EXEC === "1") {
    return;
  }
  const channelNonce = "release_bundle_nonce_1";
  const { publicKey } = generateKeyPairSync("ed25519");
  const publicJWK = publicKey.export({ format: "jwk" });
  if (typeof publicJWK.x !== "string") {
    fail("release verifier could not export the runtime lease public key");
  }
  const hello =
    JSON.stringify({
      ipc_version: "rust-ipc-v1",
      frame_type: "hello",
      request_id: "hello-1",
      runtime_generation_id: "gen-1",
      payload: {
        channel_nonce: channelNonce,
        runtime_lease_public_keys: [
          {
            algorithm: "ed25519",
            key_id: "release_verifier_ephemeral_1",
            public_key_base64: Buffer.from(publicJWK.x, "base64url").toString("base64"),
          },
        ],
      },
    }) + "\n";
  const output = execFileSync(join(bundleDir, "bin/redevplugin-runtime"), {
    input: hello,
    encoding: "utf8",
  }).trim().split("\n")[0];
  const ack = JSON.parse(output);
  assertEqual(ack.frame_type, "hello_ack", "runtime hello frame_type");
  assertEqual(ack.payload?.runtime_version, expectedVersion, "runtime hello version");
  assertEqual(ack.payload?.rust_ipc_version, "rust-ipc-v1", "runtime hello rust_ipc_version");
  assertEqual(ack.payload?.wasm_abi_version, "redevplugin-wasm-worker-v1", "runtime hello wasm_abi_version");
  assertEqual(ack.payload?.channel_nonce, channelNonce, "runtime hello channel_nonce");
}

function verifyExecutableTargets(bundleDir, runtimeTarget) {
  if (runtimeTarget === null) return;
  const targets = {
    "x86_64-unknown-linux-gnu": { format: "elf", machine: 62 },
    "aarch64-unknown-linux-gnu": { format: "elf", machine: 183 },
    "x86_64-apple-darwin": { format: "macho", machine: 0x01000007 },
    "aarch64-apple-darwin": { format: "macho", machine: 0x0100000c },
  };
  const expected = targets[runtimeTarget];
  if (!expected) fail(`unsupported runtime_target ${runtimeTarget}`);
  for (const relativePath of ["bin/redevplugin", "bin/redevplugin-runtime"]) {
    const bytes = readFileSync(join(bundleDir, relativePath));
    if (bytes.length < 32) fail(`${relativePath} is too small to be a supported executable`);
    if (expected.format === "elf") {
      if (bytes.subarray(0, 4).toString("hex") !== "7f454c46" || bytes[4] !== 2 || bytes[5] !== 1) {
        fail(`${relativePath} is not a 64-bit little-endian ELF executable`);
      }
      assertEqual(bytes.readUInt16LE(18), expected.machine, `${relativePath} ELF machine`);
      continue;
    }
    if (bytes.subarray(0, 4).toString("hex") !== "cffaedfe") {
      fail(`${relativePath} is not a 64-bit little-endian Mach-O executable`);
    }
    assertEqual(bytes.readUInt32LE(4), expected.machine, `${relativePath} Mach-O CPU type`);
  }
}

function verifyNpmManifestEntry(npmPackage, expectedVersion) {
  assertObject(npmPackage, "release manifest npm_package");
  assertExactKeys(npmPackage, ["name", "version", "path", "sha256", "integrity", "size"], "release manifest npm_package");
  assertEqual(npmPackage.name, "@floegence/redevplugin-ui", "release manifest npm package name");
  assertEqual(npmPackage.version, expectedVersion, "release manifest npm package version");
  if (typeof npmPackage.path !== "string" || !/^npm\/floegence-redevplugin-ui-[A-Za-z0-9._+-]+\.tgz$/.test(npmPackage.path)) {
    fail("release manifest npm package path is invalid");
  }
  assertHexSHA256(npmPackage.sha256, "release manifest npm package sha256");
  if (typeof npmPackage.integrity !== "string" || !/^sha512-[A-Za-z0-9+/]+={0,2}$/.test(npmPackage.integrity)) {
    fail("release manifest npm package integrity must be sha512 SRI");
  }
  if (!Number.isSafeInteger(npmPackage.size) || npmPackage.size < 1) {
    fail("release manifest npm package size must be a positive safe integer");
  }
}

async function verifyNpmTarball(bundleDir, expectedVersion, manifest) {
  const npmPath = join(bundleDir, manifest.npm_package.path);
  const npmBytes = readFileSync(npmPath);
  assertEqual(createHash("sha256").update(npmBytes).digest("hex"), manifest.npm_package.sha256, "npm tarball sha256");
  assertEqual(`sha512-${createHash("sha512").update(npmBytes).digest("base64")}`, manifest.npm_package.integrity, "npm tarball integrity");
  assertEqual(npmBytes.length, manifest.npm_package.size, "npm tarball size");
  const tmp = mkdtempSync(join(tmpdir(), "redevplugin-npm-"));
  try {
    const archiveEntries = execFileSync("tar", ["-tzf", npmPath], { encoding: "utf8" }).trim().split("\n").filter(Boolean);
    if (archiveEntries.length === 0) fail("npm tarball must contain package files");
    for (const entry of archiveEntries) {
      if (!entry.startsWith("package/") || entry.includes("\\") || entry.split("/").includes("..")) {
        fail(`npm tarball contains unsafe path ${entry}`);
      }
    }
    execFileSync("tar", ["-xzf", npmPath, "-C", tmp]);
    const packageDir = join(tmp, "package");
    const pkg = readJSON(join(packageDir, "package.json"));
    assertEqual(pkg.name, "@floegence/redevplugin-ui", "npm package name");
    assertEqual(pkg.version, expectedVersion, "npm package version");
    assertEqual(pkg.license, "MIT", "npm package license");
    assertFile(join(packageDir, "LICENSE"), "npm package LICENSE");
    assertEqual(readFileSync(join(packageDir, "LICENSE"), "utf8"), readFileSync(join(bundleDir, "LICENSE"), "utf8"), "npm package LICENSE content");
    assertObject(pkg.exports, "npm package exports");
    const exportSpecifiers = [];
    for (const [subpath, target] of Object.entries(pkg.exports)) {
      if (subpath !== "." && !/^\.\/[A-Za-z0-9._/-]+$/.test(subpath)) {
        fail(`npm package export subpath is invalid: ${subpath}`);
      }
      assertObject(target, `npm package export ${subpath}`);
      assertExactKeys(target, ["types", "default"], `npm package export ${subpath}`);
      for (const condition of ["types", "default"]) {
        const relativeTarget = target[condition];
        if (typeof relativeTarget !== "string" || !relativeTarget.startsWith("./")) {
          fail(`npm package export ${subpath}.${condition} must be a package-relative path`);
        }
        assertBundlePath(relativeTarget.slice(2), `npm package export ${subpath}.${condition}`);
        const absoluteTarget = resolve(packageDir, relativeTarget);
        if (!absoluteTarget.startsWith(packageDir + sep)) {
          fail(`npm package export ${subpath}.${condition} escapes the package`);
        }
        assertFile(absoluteTarget, `npm package export ${subpath}.${condition}`);
        if (lstatSync(absoluteTarget).isSymbolicLink()) {
          fail(`npm package export ${subpath}.${condition} must not be a symlink`);
        }
      }
      exportSpecifiers.push(subpath === "." ? pkg.name : pkg.name + subpath.slice(1));
    }
    assertDeepEqual(exportSpecifiers.sort(), [
      "@floegence/redevplugin-ui",
      "@floegence/redevplugin-ui/local-import",
      "@floegence/redevplugin-ui/plugin",
      "@floegence/redevplugin-ui/trusted-parent",
    ], "npm package export specifiers");
    execFileSync(
      process.execPath,
      ["--input-type=module", "--eval", `
        for (const specifier of ${JSON.stringify(exportSpecifiers)}) await import(specifier);
        const plugin = await import("@floegence/redevplugin-ui/plugin");
        const pluginKeys = Object.keys(plugin).sort();
        const expectedPluginKeys = [
          "PluginBridgeClient",
          "PluginBridgeError",
          "callCapabilityOperation",
          "callCapabilityStream",
          "callCapabilitySync",
          "isCapabilityBusinessError",
        ];
        if (JSON.stringify(pluginKeys) !== JSON.stringify(expectedPluginKeys)) {
          throw new Error("plugin entrypoint runtime exports are not closed: " + JSON.stringify(pluginKeys));
        }
        const trusted = await import("@floegence/redevplugin-ui/trusted-parent");
        for (const forbidden of ["PluginBridgeClient", "createOpaquePluginBootstrapHTML"]) {
          if (forbidden in trusted) throw new Error("trusted-parent entrypoint exposes forbidden export " + forbidden);
        }
      `],
      { cwd: packageDir, encoding: "utf8" },
    );
    const pluginTypes = readFileSync(join(packageDir, "dist/plugin.d.ts"), "utf8");
    for (const forbidden of [
      "PluginPlatformClient",
      "PluginSurfaceHost",
      "PluginTrustedMethodResult",
      "ReDevPluginSurfaceTransport",
      "createOpaquePluginBootstrapHTML",
      "stream_ticket",
    ]) {
      if (pluginTypes.includes(forbidden)) fail(`plugin entrypoint types expose ${forbidden}`);
    }
    for (const entrypoint of ["index.d.ts", "trusted-parent.d.ts"]) {
      if (readFileSync(join(packageDir, "dist", entrypoint), "utf8").includes("createOpaquePluginBootstrapHTML")) {
        fail(`${entrypoint} exposes the internal opaque bootstrap HTML factory`);
      }
    }
    verifyPackedTypeScriptConsumer(bundleDir, npmPath, tmp);
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
}

function verifyPackedTypeScriptConsumer(bundleDir, npmPath, tmp) {
  const consumerRoot = join(tmp, "standalone-consumer");
  const sourceRoot = join(consumerRoot, "src");
  const typescriptToolchain = readBundledTypeScriptToolchain(bundleDir);
  mkdirSync(consumerRoot, { recursive: true });
  writeFileSync(join(consumerRoot, "package.json"), JSON.stringify({ private: true, type: "module" }) + "\n");
  execFileSync(
    "npm",
    [
      "install",
      "--ignore-scripts",
      "--no-audit",
      "--no-fund",
      "--registry=https://registry.npmjs.org",
      npmPath,
      `typescript@${typescriptToolchain.version}`,
    ],
    { cwd: consumerRoot, encoding: "utf8" },
  );
  cpSync(join(bundleDir, "examples/host-capability/sample-documents-v1"), sourceRoot, { recursive: true });
  writeFileSync(join(consumerRoot, "tsconfig.json"), JSON.stringify({
    compilerOptions: {
      target: "ES2022",
      module: "NodeNext",
      moduleResolution: "NodeNext",
      strict: true,
      skipLibCheck: false,
      noEmit: true,
    },
    include: ["src/**/*.ts"],
  }, null, 2) + "\n");
  const consumerLock = readJSON(join(consumerRoot, "package-lock.json"));
  assertObject(consumerLock.packages, "standalone consumer package-lock packages");
  const installedToolchain = consumerLock.packages["node_modules/typescript"];
  assertObject(installedToolchain, "standalone consumer TypeScript lock entry");
  for (const key of ["version", "resolved", "integrity"]) {
    assertEqual(installedToolchain[key], typescriptToolchain[key], `standalone consumer TypeScript ${key}`);
  }
  const installedTypeScript = readJSON(join(consumerRoot, "node_modules/typescript/package.json"));
  assertEqual(installedTypeScript.version, typescriptToolchain.version, "standalone consumer TypeScript package version");
  const tsc = join(consumerRoot, "node_modules/typescript/bin/tsc");
  assertFile(tsc, "release verifier TypeScript compiler");
  execFileSync(process.execPath, [tsc, "--project", join(consumerRoot, "tsconfig.json")], {
    cwd: consumerRoot,
    encoding: "utf8",
  });
}

function readBundledTypeScriptToolchain(bundleDir) {
  const lock = readJSON(join(bundleDir, "notices/package-lock.json"));
  assertObject(lock.packages, "bundled package-lock packages");
  const typescript = lock.packages["node_modules/typescript"];
  assertObject(typescript, "bundled package-lock TypeScript entry");
  if (typeof typescript.version !== "string" || !exactStableSemanticVersionPattern.test(typescript.version)) {
    fail("bundled package-lock TypeScript version must be exact stable semantic version text");
  }
  const expectedResolved = `https://registry.npmjs.org/typescript/-/typescript-${typescript.version}.tgz`;
  if (typescript.resolved !== expectedResolved) {
    fail(`bundled package-lock TypeScript resolved URL must be ${expectedResolved}`);
  }
  if (!isCanonicalSHA512SRI(typescript.integrity)) {
    fail("bundled package-lock TypeScript integrity must be sha512 SRI");
  }
  return {
    version: typescript.version,
    resolved: typescript.resolved,
    integrity: typescript.integrity,
  };
}

function isCanonicalSHA512SRI(value) {
  if (typeof value !== "string" || !/^sha512-[A-Za-z0-9+/]+={0,2}$/.test(value)) {
    return false;
  }
  const encoded = value.slice("sha512-".length);
  const decoded = Buffer.from(encoded, "base64");
  return decoded.length === 64 && decoded.toString("base64") === encoded;
}

function verifyHostCapabilitySample(bundleDir, releaseManifest, skipExecution) {
  const sampleRoot = join(bundleDir, "examples/host-capability/sample-documents-v1");
  const pinPath = join(sampleRoot, "host-capability.pin.json");
  const publicPath = join(sampleRoot, "example-documents.public.json");
  const pin = readJSON(pinPath);
  const publicDocument = readJSON(publicPath);
  assertObject(pin, "host capability sample pin");
  assertObject(publicDocument, "host capability sample public key");
  assertEqual(pin.publisher_id, "example.publisher", "host capability sample publisher_id");
  assertEqual(pin.contract_id, "example.documents.v1", "host capability sample contract_id");
  assertEqual(pin.contract_version, "1.0.0", "host capability sample contract_version");
  assertEqual(publicDocument.algorithm, "ed25519", "host capability sample public key algorithm");
  assertEqual(publicDocument.key_id, pin.signature_key_id, "host capability sample public key key_id");

  const entries = [
    ["artifact_ref", "artifact_sha256"],
    ["manifest_ref", "manifest_sha256"],
    ["signature_ref", "signature_sha256"],
    ["compatibility_ref", "compatibility_sha256"],
    ["generated_client_ref", "generated_client_sha256"],
    ["notices_ref", "notices_sha256"],
  ];
  for (const [refKey, hashKey] of entries) {
    assertBundlePath(pin[refKey], `host capability sample ${refKey}`);
    assertHexSHA256(pin[hashKey], `host capability sample ${hashKey}`);
    const bytes = readFileSync(join(sampleRoot, pin[refKey]));
    assertEqual(createHash("sha256").update(bytes).digest("hex"), pin[hashKey], `host capability sample ${refKey} hash`);
  }

  const manifestBytes = readFileSync(join(sampleRoot, pin.manifest_ref));
  const sampleManifest = JSON.parse(manifestBytes.toString("utf8"));
  assertEqual(sampleManifest.publisher_id, pin.publisher_id, "host capability sample manifest publisher_id");
  assertEqual(sampleManifest.contract_id, pin.contract_id, "host capability sample manifest contract_id");
  assertEqual(sampleManifest.contract_version, pin.contract_version, "host capability sample manifest contract_version");
  assertEqual(sampleManifest.source_commit, releaseManifest.source_commit, "host capability sample source_commit");
  assertEqual(sampleManifest.generated_at, releaseManifest.generated_at, "host capability sample generated_at");
  if (!Array.isArray(sampleManifest.entries) || sampleManifest.entries.length !== 4) {
    fail("host capability sample manifest must contain exactly four signed entries");
  }

  const compatibility = readJSON(join(sampleRoot, pin.compatibility_ref));
  assertEqual(compatibility.min_redevplugin_version, releaseManifest.version, "host capability sample minimum ReDevPlugin version");

  const signature = readJSON(join(sampleRoot, pin.signature_ref));
  assertEqual(signature.algorithm, "ed25519", "host capability sample signature algorithm");
  assertEqual(signature.key_id, pin.signature_key_id, "host capability sample signature key_id");
  assertEqual(signature.manifest_sha256, pin.manifest_sha256, "host capability sample signature manifest hash");
  const rawPublicKey = Buffer.from(publicDocument.public_key, "base64");
  if (rawPublicKey.length !== 32) fail("host capability sample public key must contain 32 raw Ed25519 bytes");
  const publicKey = createPublicKey({
    key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), rawPublicKey]),
    format: "der",
    type: "spki",
  });
  if (!verifySignature(null, manifestBytes, publicKey, Buffer.from(signature.signature_base64, "base64"))) {
    fail("host capability sample signature verification failed");
  }

  const sampleText = entries.map(([refKey]) => readFileSync(join(sampleRoot, pin[refKey]), "utf8")).join("\n").toLowerCase();
  for (const forbidden of ["docker", "podman", "containers", "env app", "local ui", "desktop", "workbench"]) {
    if (sampleText.includes(forbidden)) fail(`host capability sample contains forbidden host-product term ${forbidden}`);
  }

  const consumer = readFileSync(join(sampleRoot, "plugin-consumer.ts"), "utf8");
  for (const required of ["ExampleDocumentsClient", "isExampleDocumentsBusinessError", "for await", "archive.cancel"]) {
    if (!consumer.includes(required)) fail(`host capability sample consumer must demonstrate ${required}`);
  }
  for (const forbidden of ["trusted-parent", "PluginSurfaceHost", "/_redevplugin/api/", "stream_ticket", "gateway_token"]) {
    if (consumer.includes(forbidden)) fail(`host capability sample consumer contains forbidden platform access ${forbidden}`);
  }

  if (skipExecution) return;
  execFileSync(join(bundleDir, "bin/redevplugin"), ["host-capability", "verify", sampleRoot, pinPath, publicPath], { encoding: "utf8" });
  execFileSync(join(bundleDir, "bin/redevplugin"), [
    "host-capability",
    "generate-client",
    sampleRoot,
    pinPath,
    publicPath,
    join(sampleRoot, pin.generated_client_ref),
    "--check",
  ], { encoding: "utf8" });
}

function verifyNoticeEvidence(bundleDir) {
  const notice = readFileSync(join(bundleDir, "THIRD_PARTY_NOTICES.md"), "utf8");
  for (const expected of [
    "scripts/generate_third_party_notices.mjs",
    "notices/go.sum",
    "notices/package-lock.json",
    "notices/Cargo.lock",
    "notices/THIRD_PARTY_LICENSES.json",
    "cargo deny check",
    "## Rust Crates",
    "## npm Packages",
    "## Go Modules",
    "| wasmi |",
    "| typescript |",
    "| modernc.org/sqlite |",
    "Apache-2.0",
    "MIT",
  ]) {
    if (!notice.includes(expected)) {
      fail(`THIRD_PARTY_NOTICES.md must mention ${expected}`);
    }
  }
  if (notice.includes("UNKNOWN")) {
    fail("THIRD_PARTY_NOTICES.md must not contain UNKNOWN license evidence");
  }
  const cargoLock = readFileSync(join(bundleDir, "notices/Cargo.lock"), "utf8");
  for (const crate of ["wasmi", "redevplugin-runtime", "redevplugin-ipc"]) {
    if (!cargoLock.includes(`name = "${crate}"`)) {
      fail(`notices/Cargo.lock must include ${crate}`);
    }
  }

	const licenseManifest = readJSON(join(bundleDir, "notices/THIRD_PARTY_LICENSES.json"));
	assertObject(licenseManifest, "third-party license manifest");
	assertExactKeys(licenseManifest, ["schema_version", "packages"], "third-party license manifest");
	assertEqual(licenseManifest.schema_version, "redevplugin.third_party_licenses.v1", "third-party license manifest schema_version");
	if (!Array.isArray(licenseManifest.packages) || licenseManifest.packages.length === 0) {
		fail("third-party license manifest packages must be a non-empty array");
	}
	const referencedFiles = new Set();
	const packageIDs = new Set();
	for (const [index, pkg] of licenseManifest.packages.entries()) {
		assertObject(pkg, `third-party license packages[${index}]`);
		assertExactKeys(pkg, ["ecosystem", "name", "version", "license", "files"], `third-party license packages[${index}]`);
		if (!["go", "npm", "rust"].includes(pkg.ecosystem) || typeof pkg.name !== "string" || pkg.name.length === 0 || typeof pkg.version !== "string" || pkg.version.length === 0) {
			fail(`third-party license packages[${index}] has invalid identity`);
		}
		if (typeof pkg.license !== "string" || pkg.license.length === 0 || pkg.license === "UNKNOWN") {
			fail(`third-party license packages[${index}] has invalid license metadata`);
		}
		const packageID = `${pkg.ecosystem}:${pkg.name}@${pkg.version}`;
		if (packageIDs.has(packageID)) fail(`third-party license manifest duplicates ${packageID}`);
		packageIDs.add(packageID);
		if (!Array.isArray(pkg.files) || pkg.files.length === 0) {
			fail(`third-party license package ${packageID} has no redistributed legal text`);
		}
		for (const [fileIndex, file] of pkg.files.entries()) {
			assertObject(file, `third-party license package ${packageID} files[${fileIndex}]`);
			assertExactKeys(file, ["path", "sha256"], `third-party license package ${packageID} files[${fileIndex}]`);
			if (typeof file.path !== "string" || !file.path.startsWith("notices/licenses/") || referencedFiles.has(file.path)) {
				fail(`third-party license package ${packageID} has invalid or duplicated legal-text path`);
			}
			assertHexSHA256(file.sha256, `third-party license package ${packageID} legal-text sha256`);
			const legalPath = join(bundleDir, file.path);
			assertFile(legalPath, file.path);
			const bytes = readFileSync(legalPath);
			if (bytes.length === 0) fail(`third-party legal text is empty: ${file.path}`);
			assertEqual(createHash("sha256").update(bytes).digest("hex"), file.sha256, `${file.path} sha256`);
			referencedFiles.add(file.path);
		}
	}
	for (const requiredPackage of ["rust:wasmi@", "npm:typescript@", "go:modernc.org/sqlite@"]) {
		if (![...packageIDs].some((packageID) => packageID.startsWith(requiredPackage))) {
			fail(`third-party license manifest must include ${requiredPackage}`);
		}
	}
	const actualLegalFiles = listBundleFiles(join(bundleDir, "notices", "licenses")).map((file) => `notices/licenses/${file.path}`);
	assertDeepEqual([...referencedFiles].sort(), actualLegalFiles.sort(), "third-party legal-text file set");
}

function listBundleFiles(root) {
  const files = [];
  walk(root);
  files.sort((a, b) => a.path.localeCompare(b.path));
  return files;

  function walk(dir) {
    for (const entry of readdirSync(dir)) {
      const path = join(dir, entry);
      const rel = relative(root, path).replaceAll("\\", "/");
      if (rel === "release-manifest.json" || rel === "SHA256SUMS") {
        continue;
      }
      const linkStat = lstatSync(path);
      if (linkStat.isSymbolicLink()) {
        fail(`release bundle must not contain symlink ${rel}`);
      }
      const stat = statSync(path);
      if (stat.isDirectory()) {
        walk(path);
        continue;
      }
      if (!stat.isFile()) {
        fail(`release bundle entry must be a regular file: ${rel}`);
      }
      files.push({
        path: rel,
        sha256: createHash("sha256").update(readFileSync(path)).digest("hex"),
        size: stat.size,
      });
    }
  }
}

function readJSON(path) {
  return JSON.parse(readFileSync(path, "utf8"));
}

function assertFile(path, label) {
  if (!existsSync(path) || !statSync(path).isFile()) {
    fail(`required release artifact missing: ${label}`);
  }
}

function assertExecutable(path, label) {
  assertFile(path, label);
  if (process.platform !== "win32" && (statSync(path).mode & 0o111) === 0) {
    fail(`required release artifact is not executable: ${label}`);
  }
}

function assertBundlePath(value, label) {
  if (typeof value !== "string" || value.length === 0) {
    fail(`${label} must be a non-empty string`);
  }
  if (value.startsWith("/") || value.includes("\\") || value.split("/").includes("..") || /\s/.test(value)) {
    fail(`${label} must be a relative POSIX path without traversal or whitespace: ${value}`);
  }
}

function assertHexSHA256(value, label) {
  if (typeof value !== "string" || !/^[0-9a-f]{64}$/.test(value)) {
    fail(`${label} must be a lowercase hex sha256`);
  }
}

function assertGitCommit(value, label) {
  if (typeof value !== "string" || !/^[0-9a-f]{40}$/.test(value)) {
    fail(`${label} must be a full lowercase Git commit`);
  }
}

function assertObject(value, label) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    fail(`${label} must be an object`);
  }
}

function assertExactKeys(value, expected, label) {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  assertDeepEqual(actual, wanted, `${label} keys`);
}

function assertEqual(actual, expected, label) {
  if (actual !== expected) {
    fail(`${label} mismatch: got ${JSON.stringify(actual)}, want ${JSON.stringify(expected)}`);
  }
}

function assertDeepEqual(actual, expected, label) {
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    fail(`${label} mismatch:\nactual=${JSON.stringify(actual, null, 2)}\nexpected=${JSON.stringify(expected, null, 2)}`);
  }
}

function fail(message) {
  console.error(`release bundle verification failed: ${message}`);
  process.exit(1);
}
