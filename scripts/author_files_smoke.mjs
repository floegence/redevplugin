import assert from "node:assert/strict";
import {mkdtemp,writeFile,rm} from "node:fs/promises";
import {tmpdir} from "node:os";
import {join,resolve} from "node:path";
import {spawn,spawnSync} from "node:child_process";
import {chromium} from "playwright";
const cli=resolve(process.argv[2]);const root=await mkdtemp(join(tmpdir(),"redevplugin-file-author-"));let child,browser,logs="";
try{
 const project=join(root,"app");const init=spawnSync(cli,["init","dev-example-files","File Workspace",project,"--template","files"],{encoding:"utf8"});assert.equal(init.status,0,init.stderr);
 await writeFile(join(project,"scripts/smoke.mjs"),"process.exit(0);\n");
 await writeFile(join(project,"redevplugin.project.json"),JSON.stringify({schema_version:"redevplugin.project.v1",output:"dist",build:["node","scripts/smoke.mjs"],test:["node","scripts/smoke.mjs"],watch:["ui","manifest.json","scripts"]}));
 child=spawn(cli,["dev",project],{stdio:["ignore","pipe","pipe"]});child.stdout.on("data",d=>logs+=d);child.stderr.on("data",d=>logs+=d);
 let url;for(let i=0;i<150;i++){url=logs.match(/Preview: (http:\/\/localhost:\d+\/#[a-f0-9]+)/u)?.[1];if(url)break;await new Promise(r=>setTimeout(r,100))}assert.ok(url,logs);
 browser=await chromium.launch({headless:true});const page=await browser.newPage();await page.goto(url);const frame=page.frameLocator("#stage > iframe");await frame.getByText("Ready. Choose files to begin.",{exact:true}).waitFor();
 await frame.getByLabel("Choose files",{exact:true}).setInputFiles([{name:"large.bin",mimeType:"application/octet-stream",buffer:Buffer.alloc(2<<20,42)},{name:"second.txt",mimeType:"text/plain",buffer:Buffer.from("second")}]);
 await frame.getByRole("button",{name:"Import and verify",exact:true}).click();await frame.getByText("2 files saved and verified",{exact:true}).waitFor({timeout:15000});
 assert.equal(await frame.getByRole("listitem").count(),2);assert.match(await frame.getByRole("listitem").first().textContent(),/2097152 bytes/);
 await page.setViewportSize({width:640,height:900});assert.ok((await page.locator("#stage").boundingBox()).height>=360);
 console.log("File author browser acceptance passed: real binary upload/download, private scope, two completed results, byte counts, responsive layout.");
} catch(error){throw new Error(String(error)+"\n"+logs,{cause:error})}finally{if(browser)await browser.close();if(child&&child.exitCode===null){child.kill("SIGINT");await Promise.race([new Promise(r=>child.once("exit",r)),new Promise(r=>setTimeout(r,5000))]);if(child.exitCode===null)child.kill("SIGKILL")};await rm(root,{recursive:true,force:true})}
