import assert from "node:assert/strict";
import {mkdtemp,writeFile,rm} from "node:fs/promises";
import {tmpdir} from "node:os";
import {join,resolve} from "node:path";
import {spawn,spawnSync} from "node:child_process";
import {chromium} from "playwright";
const cli=resolve(process.argv[2]??"dist/author-cli");
const root=await mkdtemp(join(tmpdir(),"redevplugin-data-"));let child,browser;let logs="";
try{
 const app=join(root,"app");let result=spawnSync(cli,["init","dev.example.data","Document Workspace",app,"--template","data"],{encoding:"utf8"});assert.equal(result.status,0,result.stderr);
 // Use the generated packaged assets; dependency/build compilation has its own gate.
 await writeFile(join(app,"scripts/smoke.mjs"),'process.exit(0);\n');
 await writeFile(join(app,"redevplugin.project.json"),JSON.stringify({schema_version:"redevplugin.project.v1",output:"dist",build:["node","scripts/smoke.mjs"],test:["node","scripts/smoke.mjs"],watch:["ui","manifest.json","scripts"]}));
 for(const command of ["doctor","check"]){result=spawnSync(cli,[command,app],{encoding:"utf8"});assert.equal(result.status,0,result.stdout+result.stderr);assert.equal(JSON.parse(result.stdout).runtime_required,false)}
 child=spawn(cli,["dev",app],{stdio:["ignore","pipe","pipe"]});child.stdout.on("data",data=>logs+=data);child.stderr.on("data",data=>logs+=data);
 let url;for(let i=0;i<150;i++){url=logs.match(/Preview: (http:\/\/localhost:\d+\/#[a-f0-9]+)/u)?.[1];if(url)break;await new Promise(resolve=>setTimeout(resolve,100))}assert.ok(url,logs);
 browser=await chromium.launch({headless:true});const context=await browser.newContext();const first=await context.newPage();await first.goto(url);
 const a=first.frameLocator("#stage > iframe");await a.getByRole("heading",{name:"Document Workspace"}).waitFor();await a.getByText("Ready",{exact:true}).waitFor();
 const second=await context.newPage();await second.goto(new URL(url).origin);const b=second.frameLocator("#stage > iframe");await b.getByText("Ready",{exact:true}).waitFor();
 await b.getByLabel("Document",{exact:true}).fill("unsaved second window");
 await a.getByLabel("Document",{exact:true}).fill("saved first window");await a.getByRole("button",{name:"Save",exact:true}).click();await a.getByText("Saved",{exact:true}).waitFor();
 await b.getByText("A newer saved version is available. Your unsaved changes are kept here.",{exact:true}).waitFor({timeout:10000});
 assert.equal(await b.getByLabel("Document",{exact:true}).inputValue(),"unsaved second window");
 await b.getByRole("button",{name:"Save",exact:true}).click();await b.getByText("Another window saved a newer version. Your changes are kept here. Reload when you are ready to replace them.",{exact:true}).waitFor();
 assert.equal(await b.getByLabel("Document",{exact:true}).inputValue(),"unsaved second window");
 await b.getByRole("button",{name:"Reload saved version",exact:true}).click();await b.getByRole("button",{name:"Confirm reload — replace unsaved changes",exact:true}).click();await b.getByText("Ready",{exact:true}).waitFor();assert.equal(await b.getByLabel("Document",{exact:true}).inputValue(),"saved first window");
 await first.close();await b.getByLabel("Document",{exact:true}).fill("sibling survives");await b.getByRole("button",{name:"Save",exact:true}).click();await b.getByText("Saved",{exact:true}).waitFor();
 await second.reload();await b.getByText("Ready",{exact:true}).waitFor();assert.equal(await b.getByLabel("Document",{exact:true}).inputValue(),"sibling survives");
 const invoke=async(intent_id,params)=>await second.evaluate(async input=>{const state=await(await fetch("/dev/status")).json();const response=await fetch("/_redevplugin/api/plugins/intents/invoke",{method:"POST",headers:{"Content-Type":"application/json","X-ReDevPlugin-CSRF":state.csrf},body:JSON.stringify({plugin_instance_id:state.plugin_instance_id,surface_instance_id:document.querySelector("#stage").dataset.surfaceInstance,...input})});return {status:response.status,body:await response.json()};},{intent_id,params});
 const initial=await invoke("application.read",{});assert.equal(initial.status,200,JSON.stringify(initial));const revision=initial.body.data.data.revision;
 const replaced=await invoke("document.replace",{expected_revision:revision,message:"Agent draft"});assert.equal(replaced.status,200,JSON.stringify(replaced));assert.equal(replaced.body.data.data.applied,true);
 assert.equal(await b.getByLabel("Document",{exact:true}).inputValue(),"Agent draft");
 const stale=await invoke("document.replace",{expected_revision:revision,message:"stale overwrite"});assert.equal(stale.body.data.data.applied,false);
 await b.getByRole("button",{name:"Undo last action",exact:true}).click();assert.equal(await b.getByLabel("Document",{exact:true}).inputValue(),"sibling survives");
 console.log("Data author acceptance passed: no runtime, independent windows, snapshots, CAS conflict retention, explicit reload, sibling isolation, reopen persistence, doctor and check.");
} catch(error){throw new Error(String(error)+"\n"+logs,{cause:error})}finally{
 if(browser)await browser.close();if(child&&child.exitCode===null){child.kill("SIGINT");await Promise.race([new Promise(resolve=>child.once("exit",resolve)),new Promise(resolve=>setTimeout(resolve,5000))]);if(child.exitCode===null)child.kill("SIGKILL")};await rm(root,{recursive:true,force:true});
}
