import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { execFileSync } from "node:child_process";
const root = resolve(import.meta.dirname, "..");
const temporary = mkdtempSync(join(tmpdir(), "redevplugin-ui-consumer-"));
const version = readFileSync(join(root, "VERSION"), "utf8").trim();
const run = (command, args, cwd = root) => execFileSync(command, args, { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
try {
  const files = [];
  for (const name of ["contracts", "ui"]) {
    const tarball = run(process.execPath, ["scripts/build_redevplugin_" + name + "_package.mjs", version, temporary]).trim();
    assert.doesNotMatch(run("tar", ["-tzf", tarball]), /jsx(?:-dev)?-runtime|opaque-surface|ui-reconciler|ui-patch-validator|surface-integrity/);
    files.push(tarball);
  }
  writeFileSync(join(temporary, "package.json"), JSON.stringify({ private: true, type: "module" }));
  run("npm", ["install", "--ignore-scripts", "--no-audit", "--no-fund", "--package-lock=false", ...files], temporary);
  writeFileSync(join(temporary, "verify.mjs"), [
    "import assert from 'node:assert/strict';",
    "import * as parent from '@floegence/redevplugin-ui/trusted-parent';",
    "import * as root from '@floegence/redevplugin-ui';",
    "import * as plugin from '@floegence/redevplugin-ui/plugin';",
    "import * as testing from '@floegence/redevplugin-ui/testing';",
    "import * as local from '@floegence/redevplugin-ui/local-import';",
    "assert.deepEqual(Object.keys(root), Object.keys(parent));",
    "assert.deepEqual(Object.keys(plugin), ['PluginBridgeClient','PluginBridgeError','callCapabilityOperation','callCapabilityStream','callCapabilitySync','createPluginProcessClient','isCapabilityBusinessError','pluginAPIMajor']);",
    "assert.deepEqual(Object.keys(testing), ['createPluginTestClock','createPluginTestContext','createPluginTestHarness']);",
    "assert.ok(local.PluginLocalImportClient);",
    "for (const name of ['jsx-runtime','jsx-dev-runtime']) await assert.rejects(import('@floegence/redevplugin-ui/' + name), { code: 'ERR_PACKAGE_PATH_NOT_EXPORTED' });",
    "const fixture = testing.createPluginTestHarness({call: () => ({data: 'verified'})});",
    "const client = new fixture.BridgeClient(); await client.ready(); assert.deepEqual(await client.call('notes.read'), {data:'verified'}); fixture.dispose();",
  ].join("\n"));
  run(process.execPath, ["verify.mjs"], temporary);
  writeFileSync(join(temporary, "consumer.ts"), [
    "import {PluginBridgeClient} from '@floegence/redevplugin-ui/plugin';",
    "import {PluginPlatformClient,PluginSurfaceSlot} from '@floegence/redevplugin-ui';",
    "import {createPluginTestClock} from '@floegence/redevplugin-ui/testing';",
    "const client = new PluginBridgeClient({clock:createPluginTestClock().clock});",
    "client.onBeforeClose(async () => false);",
    "declare const slot: PluginSurfaceSlot;",
    "void slot.requestClose(); void new PluginPlatformClient();",
    "// @ts-expect-error plugin code must not import host management",
    "import {PluginPlatformClient as Invalid} from '@floegence/redevplugin-ui/plugin';",
    "void Invalid;",
    "// @ts-expect-error retired render contract is not exported",
    "import {jsx} from '@floegence/redevplugin-ui/jsx-runtime';",
    "void jsx;",
  ].join("\n"));
  run(process.execPath, [join(root, "node_modules/typescript/bin/tsc"), "--noEmit", "--strict", "--module", "NodeNext", "--moduleResolution", "NodeNext", "--target", "ES2022", "consumer.ts"], temporary);
  process.stdout.write("Packed SDK entrypoints and standalone declarations passed\n");
} finally { rmSync(temporary, {recursive:true, force:true}); }
