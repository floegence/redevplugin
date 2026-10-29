import assert from "node:assert/strict";
import { mkdtemp, readFile, writeFile, rm, copyFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { resolve, join } from "node:path";
import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { chromium } from "playwright";
import Ajv2020 from "ajv/dist/2020.js";

const root = resolve(import.meta.dirname, "..");
const cli = resolve(root, process.argv[2] ?? "dist/author-cli");
const runtime = resolve(root, process.argv[3] ?? "target/debug/redevplugin-runtime");
// The test builds this exact runtime itself; this digest is test evidence only.
const digest = createHash("sha256").update(await readFile(runtime)).digest("hex");
const directory = await mkdtemp(join(tmpdir(), "redevplugin-author-smoke-"));
let child;
let browser;
let exited;
try {
const project = join(directory, "source");
const initialized = spawnSync(cli, ["init", "dev.example.author", "Author Preview", project], { encoding: "utf8" });
assert.equal(initialized.status, 0, initialized.stderr);
await copyFile(join(project, "dist/ui/assets/app.js"), join(project, "ui/source.js"));
await writeFile(join(project, "scripts/smoke-build.mjs"), 'import {copyFile,readFile} from "node:fs/promises";\nawait copyFile("ui/source.js","dist/ui/assets/app.js");\n');
await writeFile(join(project, "scripts/smoke-test.mjs"), 'import assert from "node:assert/strict"; import {readFile} from "node:fs/promises"; assert.match(await readFile("ui/source.js","utf8"),/worker.echo/u);\n');
await writeFile(join(project, "redevplugin.project.json"), JSON.stringify({schema_version:"redevplugin.project.v1",output:"dist",build:["node","scripts/smoke-build.mjs"],test:["node","scripts/smoke-test.mjs"],watch:["ui","scripts","manifest.json"]}));
const test = spawnSync(cli, ["test",project,"--runtime",runtime,"--runtime-sha256",digest,"--surface","dev.example.author.view","--method","worker.echo","--params",JSON.stringify({message:"author-real-runtime"})],{encoding:"utf8",timeout:45000});
assert.equal(test.status,0,test.stdout+test.stderr);
const report=JSON.parse(test.stdout);
const validate = new Ajv2020().compile(JSON.parse(await readFile(join(root,"spec/plugin/author-test-v1.schema.json"),"utf8")));
assert.equal(validate(report),true,JSON.stringify(validate.errors));
assert.equal(report.runtime_result.data.message,"author-real-runtime");
const rejected=spawnSync(cli,["test",project,"--runtime",runtime,"--runtime-sha256",digest],{encoding:"utf8",timeout:45000});
assert.equal(rejected.status,1);const rejectedReport=JSON.parse(rejected.stdout);assert.equal(rejectedReport.ok,false);assert.equal(validate(rejectedReport),true,JSON.stringify(validate.errors));
child = spawn(cli,["dev",project,"--runtime",runtime,"--runtime-sha256",digest],{stdio:["ignore","pipe","pipe"]});
let logs="";child.stdout.on("data",value=>{logs+=value});child.stderr.on("data",value=>{logs+=value});
exited = new Promise(resolveExit=>child.once("exit",(code,signal)=>resolveExit({code,signal})));
browser=await chromium.launch({headless:true});
try{
 let preview;
 for(let attempt=0;attempt<100;attempt++){preview=logs.match(/Preview: (http:\/\/127\.0\.0\.1:\d+\/#[a-f0-9]+)/u)?.[1];if(preview)break;await new Promise(resolveWait=>setTimeout(resolveWait,100))}
 assert.ok(preview,logs);const origin=new URL(preview).origin;
 assert.equal((await fetch(origin+"/dev/status")).status,403);
 assert.equal((await fetch(origin+"/manifest.json")).status,404);
 const page=await browser.newPage();await page.goto(preview);
 const frame=page.frameLocator("#stage > iframe");await frame.getByRole("heading",{name:"Author Preview"}).waitFor({timeout:30000});
 await frame.getByLabel("Message",{exact:true}).fill("Browser worker acceptance");await frame.getByRole("button",{name:"Send to worker"}).click();await frame.getByText("Browser worker acceptance",{exact:true}).waitFor({timeout:15000});
 await page.locator("#confirmation").evaluate(dialog=>dialog.showModal());
 await page.getByRole("button",{name:"Cancel",exact:true}).waitFor();
 assert.equal(await page.getByRole("button",{name:"Cancel",exact:true}).evaluate(button=>button===document.activeElement),true);
 await page.keyboard.press("Escape");assert.equal(await page.locator("#confirmation").evaluate(dialog=>dialog.open),false);
 const iframe=await page.locator("#stage > iframe").elementHandle();
 await writeFile(join(project,"scripts/smoke-build.mjs"),'throw new Error("intentional author build failure");\n');
 await page.getByText("Build failed. Showing the last valid preview.",{exact:true}).waitFor({timeout:10000});
 assert.equal(await iframe.evaluate(element=>element.isConnected),true);
 await frame.getByText("Browser worker acceptance",{exact:true}).waitFor();
 const source=await readFile(join(project,"ui/source.js"),"utf8");await writeFile(join(project,"ui/source.js"),source.replaceAll("Author Preview","Author Reloaded"));
 await writeFile(join(project,"scripts/smoke-build.mjs"),'import {copyFile} from "node:fs/promises"; await copyFile("ui/source.js","dist/ui/assets/app.js");\n');
 await frame.getByRole("heading",{name:"Author Reloaded"}).waitFor({timeout:15000});
 assert.equal(await iframe.evaluate(element=>element.isConnected),false);
 await page.setViewportSize({width:700,height:900});assert.ok((await page.locator("#stage").boundingBox()).height>=360);
 const current=await page.locator("#stage > iframe").elementHandle();
 await writeFile(join(project,"redevplugin.project.json"),(await readFile(join(project,"redevplugin.project.json"),"utf8"))+" ");
 await page.getByText("project configuration changed; restart the developer preview to apply it",{exact:true}).waitFor({timeout:10000});
 assert.equal(await current.evaluate(element=>element.isConnected),true);
 console.log("Author workflow passed: real WASM call, opaque preview, failed-build retention, fresh reload generation, responsive layout, private API.");
}catch(error){throw new Error(String(error)+"\n"+logs,{cause:error})}
} finally {
 try {
  if (browser) await browser.close();
  if (child && child.exitCode === null && child.signalCode === null) {
   child.kill("SIGINT");
   let deadline;
   try { await Promise.race([exited, new Promise((_, reject) => { deadline = setTimeout(() => reject(new Error("author process failed to stop")), 10000); })]); }
   finally { clearTimeout(deadline); if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL"); }
  }
 } finally { await rm(directory, {recursive:true, force:true}); }
}
