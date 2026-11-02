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
    "assert.deepEqual(Object.keys(plugin).sort(), ['PluginBridgeClient','PluginBridgeError','PluginFileHandle','PluginFileWriteError','PluginFilesClient','callCapabilityOperation','callCapabilityStream','callCapabilitySync','createPluginProcessClient','isCapabilityBusinessError','openPluginConnection','pluginAPIMajor','PluginResourceError','callPluginActionOperation','callPluginActionStream','callPluginActionSync','describePluginResources','observePluginActionEvents','observePluginExecution','openPluginWebSocket','pluginDatabase','pluginFiles','pluginKV','pluginSettings'].sort());",
    "assert.deepEqual(Object.keys(testing), ['createPluginTestClock','createPluginTestContext','createPluginTestHarness']);",
    "assert.ok(local.PluginLocalImportClient);",
    "for (const name of ['jsx-runtime','jsx-dev-runtime']) await assert.rejects(import('@floegence/redevplugin-ui/' + name), { code: 'ERR_PACKAGE_PATH_NOT_EXPORTED' });",
    "const fixture = testing.createPluginTestHarness({call: () => ({data: 'verified'})});",
    "const client = new fixture.BridgeClient(); await client.ready(); assert.deepEqual(await client.call('notes.read'), {data:'verified'}); fixture.dispose();",
  ].join("\n"));
  run(process.execPath, ["verify.mjs"], temporary);
  writeFileSync(join(temporary, "consumer.ts"), [
    "import {PluginBridgeClient,PluginFileHandle,PluginFileWriteError,PluginFilesClient,openPluginConnection,type PluginWebConnection,type PluginFileResource,type PluginFileStat} from '@floegence/redevplugin-ui/plugin';",
    "import {PluginPlatformClient,PluginSurfaceSlot} from '@floegence/redevplugin-ui';",
    "import {createPluginTestClock} from '@floegence/redevplugin-ui/testing';",
    "import {pluginKV,pluginFiles,pluginDatabase,pluginSettings,describePluginResources,openPluginWebSocket,callPluginActionSync,callPluginActionOperation,callPluginActionStream,observePluginActionEvents,observePluginExecution,type PluginResourceDescription,type PluginSocket} from '@floegence/redevplugin-ui/plugin';",
    "const resources: PluginResourceDescription = await describePluginResources(); void resources.limits.stream_timeout_ms;",
    "const saved = await pluginKV<{title:string}>('documents').put('draft', {title:'Hello'}, {expectedETag:''}); void saved.etag;",
    "await pluginDatabase('index').transaction([{sql:'CREATE TABLE notes (title TEXT)'},{sql:'INSERT INTO notes VALUES (?)',args:['Hello']}]);",
    "const privateFiles = pluginFiles('files'); const bytes: number = await privateFiles.writeFrom('note.txt',new Blob(['Hello'])); void bytes;",
    "const stream: ReadableStream<Uint8Array> = await privateFiles.readable('note.txt'); void stream;",
    "const settings = pluginSettings<{theme:string}>(); const snapshot = await settings.get(); await settings.patch(snapshot.values_revision,{theme:'dark'});",
    "const socket: PluginSocket = await openPluginWebSocket('events','/'); await socket.send('snapshot'); socket.close();",
    "const client = new PluginBridgeClient({clock:createPluginTestClock().clock});",
    "const data: {title:string} = await callPluginActionSync(client,{method:'document.read',execution:'sync',cancelable:false},{}); void data;",
    "const operation = await callPluginActionOperation(client,{method:'document.write',execution:'operation',cancelable:true},{}); await operation.cancel();",
    "const events = await callPluginActionStream(client,{method:'document.events',execution:'subscription',cancelable:true},{}); await events.read();",
    "void observePluginActionEvents(client,operation.execution_id); void observePluginExecution(client,operation.execution_id);",
    "client.onBeforeClose(async () => false);",
    "const connection: PluginWebConnection = await openPluginConnection('api'); void connection.baseURL;",
    "const files: PluginFilesClient = client.files;",
    "declare const resource: PluginFileResource;",
    "const file: PluginFileHandle = await files.open(resource.uri, {read:true,write:true});",
    "const offset: bigint = await file.seek(0n);",
    "const stat: PluginFileStat = await files.stat(resource.uri);",
    "const size: bigint = stat.size; void offset; void size;",
    "try { await file.write(new Uint8Array([1])); } catch (error) { if (!(error instanceof PluginFileWriteError)) throw error; }",
    "await file.sync(); await file.close();",
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
