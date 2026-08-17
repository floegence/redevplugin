import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, readdir, readFile, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";
import { spawnSync } from "node:child_process";
import Ajv2020 from "ajv/dist/2020.js";
import {
  generatePlatformReleaseManifest,
  listCanonicalContractArtifacts,
} from "./generate_platform_release_manifest.mjs";

const root = resolve(import.meta.dirname, "..");

test("manifest module can be imported from a stdin Node program", () => {
  const result = spawnSync(process.execPath, ["--input-type=module", "-"], {
    cwd: root,
    input: "import { listCanonicalContractArtifacts } from './scripts/generate_platform_release_manifest.mjs';\nprocess.stdout.write(String((await listCanonicalContractArtifacts()).length));\n",
    encoding: "utf8",
  });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout, String(expectedCanonicalContracts.length));
});

const expectedCanonicalContracts = [
  "contract:internal/runtime-wire-fixtures.json",
  "contract:internal/runtime-wire.schema.json",
  "contract:openapi/plugin-platform.yaml",
  "contract:platform-release-manifest.schema.json",
  "contract:plugin/bridge.schema.json",
  "contract:plugin/error-codes.schema.json",
  "contract:plugin/external-signer-request-v1.schema.json",
  "contract:plugin/external-signer-response-v1.schema.json",
  "contract:plugin/host-capability-contract-v1.schema.json",
  "contract:plugin/host-capability-pin-v1.schema.json",
  "contract:plugin/manifest-v9.schema.json",
  "contract:plugin/network-grant-v2.schema.json",
  "contract:plugin/opaque-surface-document-v3.schema.json",
  "contract:plugin/opaque-surface-transport-v6.schema.json",
  "contract:plugin/package-signature-v1.schema.json",
  "contract:plugin/plugin-api.json",
  "contract:plugin/presentation-icon-evidence-v1.schema.json",
  "contract:plugin/presentation-locale-fixtures-v1.json",
  "contract:plugin/process-containment-v1.schema.json",
  "contract:plugin/publisher-release-ref-v1.schema.json",
  "contract:plugin/quarantine-cleanup-v1.schema.json",
  "contract:plugin/release-metadata.schema.json",
  "contract:plugin/release-publisher-config-v1.schema.json",
  "contract:plugin/release-revocation-pointer-v2.schema.json",
  "contract:plugin/release-revocation-v3.schema.json",
  "contract:plugin/release-root-delegation-v1.schema.json",
  "contract:plugin/release-source-policy-pointer-v2.schema.json",
  "contract:plugin/release-source-policy-v3.schema.json",
  "contract:plugin/resource-scope-v1.schema.json",
  "contract:plugin/runtime-admission-v1.schema.json",
  "contract:plugin/runtime-exec-journal-v1.schema.json",
  "contract:plugin/session-scope-v1.schema.json",
  "contract:plugin/target-classifier-v2.json",
  "contract:plugin/token-ticket-v4.schema.json",
  "contract:plugin/wasm-abi.json",
  "contract:plugin/worker-invocation.schema.json",
];

test("release manifest is canonical, sorted, and derived from VERSION", async () => {
  const staging = await mkdtemp(join(tmpdir(), "redevplugin-release-manifest-"));
  const npm = join(staging, "ui.tgz");
  await writeFile(npm, "npm artifact");
  const version = (await readFile(join(root, "VERSION"), "utf8")).trim();

  const first = join(staging, "first.json");
  const second = join(staging, "second.json");
  const artifacts = [
    { name: "npm:@floegence/redevplugin-ui", path: npm },
    {
      name: "go:github.com/floegence/redevplugin/v3",
      sha256: createHash("sha256").update("go artifact").digest("hex"),
    },
  ];
  await generatePlatformReleaseManifest({ artifacts, output: first });
  await generatePlatformReleaseManifest({ artifacts: artifacts.toReversed(), output: second });

  const [firstBytes, secondBytes, schemaBytes] = await Promise.all([
    readFile(first, "utf8"),
    readFile(second, "utf8"),
    readFile(join(root, "spec/platform-release-manifest.schema.json"), "utf8"),
  ]);
  assert.equal(firstBytes, secondBytes);
  assert.equal(firstBytes.endsWith("\n"), true);
  const manifest = JSON.parse(firstBytes);
  assert.deepEqual(manifest, {
    platform_version: version,
    plugin_api: 1,
    internal_wire: 1,
    artifacts: [
      {
        name: "go:github.com/floegence/redevplugin/v3",
        sha256: createHash("sha256").update("go artifact").digest("hex"),
      },
      {
        name: "npm:@floegence/redevplugin-ui",
        sha256: createHash("sha256").update("npm artifact").digest("hex"),
      },
    ],
  });
  const validate = new Ajv2020({ strict: true }).compile(JSON.parse(schemaBytes));
  assert.equal(validate(manifest), true, JSON.stringify(validate.errors));
  assert.equal("version" in manifest.artifacts[0], false);
});

test("release manifest rejects duplicate coordinates and repository output", async () => {
  const staging = await mkdtemp(join(tmpdir(), "redevplugin-release-manifest-"));
  const artifact = join(staging, "artifact.tgz");
  await writeFile(artifact, "artifact");
  const duplicate = [
    { name: "npm:@floegence/redevplugin-ui", path: artifact },
    { name: "npm:@floegence/redevplugin-ui", path: artifact },
  ];
  await assert.rejects(
    generatePlatformReleaseManifest({ artifacts: duplicate, output: join(staging, "release.json") }),
    /duplicate artifact name/,
  );
  await assert.rejects(
    generatePlatformReleaseManifest({
      artifacts: duplicate.slice(0, 1),
      output: join(root, "dist/platform-release-manifest.json"),
    }),
    /outside the repository/,
  );
  await assert.rejects(
    generatePlatformReleaseManifest({
      artifacts: [{ name: "contract:platform-release-manifest", path: artifact }],
      output: join(staging, "release.json"),
    }),
    /cannot list itself/,
  );
  await assert.rejects(
    generatePlatformReleaseManifest({
      artifacts: [{
        name: "npm:@floegence/redevplugin-ui",
        path: artifact,
        sha256: "0".repeat(64),
      }],
      output: join(staging, "ambiguous.json"),
    }),
    /exactly one of path or sha256/,
  );
  await assert.rejects(
    generatePlatformReleaseManifest({
      artifacts: [{ name: "crate:redevplugin-runtime", sha256: "not-a-digest" }],
      output: join(staging, "invalid-digest.json"),
    }),
    /invalid artifact sha256/,
  );
});

test("canonical contract artifacts are one explicit exact release set", async () => {
  const artifacts = await listCanonicalContractArtifacts();
  assert.deepEqual(artifacts.map(({ name }) => name), expectedCanonicalContracts);
  assert.deepEqual(await listSpecContractNames(join(root, "spec")), expectedCanonicalContracts);
  await assert.rejects(stat(join(root, "spec/plugin/platform-version.json")), { code: "ENOENT" });
});

async function listSpecContractNames(specRoot, directory = specRoot) {
  const names = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) {
      names.push(...await listSpecContractNames(specRoot, path));
    } else if (entry.isFile()) {
      names.push(`contract:${path.slice(specRoot.length + 1).split("\\").join("/")}`);
    }
  }
  return names.toSorted();
}
