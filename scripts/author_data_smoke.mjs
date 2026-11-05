import assert from "node:assert/strict";
import {mkdtemp,readFile,writeFile,rm} from "node:fs/promises";
import {tmpdir} from "node:os";
import {join,resolve} from "node:path";
import {spawn,spawnSync} from "node:child_process";
import {chromium} from "playwright";
const cli=resolve(process.argv[2]??"dist/author-cli");
const root=await mkdtemp(join(tmpdir(),"redevplugin-data-"));let child,browser;let logs="";
try{
 const app=join(root,"app");let result=spawnSync(cli,["init","dev.example.data","Document Workspace",app,"--template","data"],{encoding:"utf8"});assert.equal(result.status,0,result.stderr);
 for(const name of ["manifest.json","dist/manifest.json"]){const path=join(app,name),manifest=JSON.parse(await readFile(path,"utf8"));manifest.surfaces.push({...manifest.surfaces[0],surface_id:"dev.example.data.other",label:"Other window"});await writeFile(path,JSON.stringify(manifest));}
 result=spawnSync(cli,["generate",join(app,"manifest.json"),join(app,"generated")],{encoding:"utf8"});assert.equal(result.status,0,result.stdout+result.stderr);
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
 await second.getByRole("button",{name:"Close preview",exact:true}).click();
 await second.getByRole("button",{name:"Cancel",exact:true}).click();
 assert.equal(await b.getByLabel("Document",{exact:true}).inputValue(),"unsaved second window");
 await second.getByLabel("Preview surface").waitFor({state:"visible"});await second.waitForFunction(()=>!document.querySelector("#surfaces").disabled);
 await second.getByLabel("Preview surface").selectOption("dev.example.data.other");
 await second.getByRole("button",{name:"Cancel",exact:true}).click();
 await second.waitForFunction(()=>!document.querySelector("#surfaces").disabled);
 assert.equal(await second.getByLabel("Preview surface").inputValue(),"dev.example.data.view");
 assert.equal(await b.getByLabel("Document",{exact:true}).inputValue(),"unsaved second window");
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
 // Exercise the preview controls, including requests whose response arrives late or is lost.
 await second.locator("#action-tools > summary").click();
 await second.getByLabel("Application action",{exact:true}).selectOption("document.replace");
 assert.equal(await second.locator("#action-fields input").count(),2);
 await second.locator("#action-fields input").first().fill("3");
 await second.locator("#action-fields input").last().fill("reviewed action draft");
 const draftParams=await second.getByLabel("JSON parameters",{exact:true}).inputValue();
 const refreshState=async()=>{await second.getByRole("button",{name:"Refresh state",exact:true}).click();await second.waitForFunction(()=>!document.querySelector("#refresh-state").disabled);};
 await refreshState();
 assert.equal(await second.getByLabel("Application action",{exact:true}).inputValue(),"document.replace");
 assert.equal(await second.locator("#action-fields input").count(),2);
 assert.equal(await second.locator("#action-fields input").last().inputValue(),"reviewed action draft");
 assert.equal(await second.getByLabel("JSON parameters",{exact:true}).inputValue(),draftParams);
 await second.getByLabel("JSON parameters",{exact:true}).fill('{"message":');
 await refreshState();assert.equal(await second.getByLabel("JSON parameters",{exact:true}).inputValue(),'{"message":');
 await second.getByLabel("JSON parameters",{exact:true}).fill(draftParams);
 await second.getByLabel("Application action",{exact:true}).selectOption("application.read");
 let resolveHeld,received=0,settled=0;const held=new Promise(resolve=>resolveHeld=resolve);
 await second.route("**/_redevplugin/api/plugins/intents/invoke",async route=>{received++;const response=await route.fetch();await held;await route.fulfill({response});settled++;});
 try {
  await second.getByRole("button",{name:"Run action",exact:true}).click();
  for(let i=0;i<100&&received===0;i++)await second.waitForTimeout(20);
  assert.equal(received,1);
  await refreshState();assert.equal(await second.getByRole("button",{name:"Run action",exact:true}).isDisabled(),true);
  assert.equal(await second.getByLabel("Application action",{exact:true}).isDisabled(),true);
  await second.evaluate(()=>document.querySelector("#action-run").click());assert.equal(received,1);
 } finally {resolveHeld();for(let i=0;i<100&&settled===0;i++)await second.waitForTimeout(20);await second.unrouteAll({behavior:"wait"});}
 await second.waitForFunction(()=>!document.querySelector("#action-run").disabled);
 const currentAction=await invoke("application.read",{});
 await second.getByLabel("Application action",{exact:true}).selectOption("document.replace");
 await second.getByLabel("JSON parameters",{exact:true}).fill(JSON.stringify({expected_revision:currentAction.body.data.data.revision,message:"panel action"}));
 await second.getByRole("button",{name:"Run action",exact:true}).click();
 await second.waitForFunction(()=>document.querySelector("#action-result").textContent.includes('"applied": true'));
 assert.equal(await b.getByLabel("Document",{exact:true}).inputValue(),"panel action");
 const nextAction=await invoke("application.read",{});
 await second.getByLabel("JSON parameters",{exact:true}).fill(JSON.stringify({expected_revision:nextAction.body.data.data.revision,message:"committed action with lost response"}));
 let lostAction;
 await second.route("**/_redevplugin/api/plugins/intents/invoke",async route=>{const response=await route.fetch();lostAction=await response.json();await route.abort("failed");});
 await second.getByRole("button",{name:"Run action",exact:true}).click();
 await second.waitForFunction(()=>document.querySelector("#action-result").textContent.includes("result is unknown"));
 assert.equal(lostAction.data.data.applied,true);assert.equal(await b.getByLabel("Document",{exact:true}).inputValue(),"committed action with lost response");
 await second.unrouteAll({behavior:"wait"});
 await refreshState();assert.equal(await second.getByRole("button",{name:"Run action",exact:true}).isDisabled(),true);
 const recovery=second.getByRole("button",{name:"Review uncertain result",exact:true});
 await recovery.click();assert.equal(await second.locator("#confirmation-details").textContent(),"Submitted request");assert.equal(await second.locator("#confirmation-method").textContent(),"document.replace");await second.keyboard.press("Escape");
 assert.equal(await second.getByRole("button",{name:"Run action",exact:true}).isDisabled(),true);
 assert.equal(await recovery.evaluate(element=>element===document.activeElement),true);
 const requestsAfterUnknown=[];const observe=request=>{if(new URL(request.url()).pathname.endsWith("/intents/invoke"))requestsAfterUnknown.push(request.url());};second.on("request",observe);
 await recovery.click();await second.getByRole("button",{name:"Allow another action",exact:true}).click();
 await second.waitForFunction(()=>!document.querySelector("#action-run").disabled);
 assert.equal(requestsAfterUnknown.length,0,"acknowledgement must not replay an action");second.off("request",observe);
 assert.equal(await second.getByLabel("JSON parameters",{exact:true}).evaluate(element=>element===document.activeElement),true);
 await b.getByLabel("Document",{exact:true}).fill("save response lost");
 // Pause the browser's actual response so Origin and Fetch Metadata remain browser-owned.
 const frame=second.frames().find(frame=>frame.parentFrame()===second.mainFrame());
 assert.ok(frame,"application frame exists");
 const network=await context.newCDPSession(frame);
 let lostWrites=0,lostSave,interceptionError;
 network.on("Fetch.requestPaused",event=>{void(async()=>{
  let body;try{body=JSON.parse(event.request.postData??"null")}catch{body=null}
  if(body?.resource==="storage.kv"&&body?.arguments?.operation==="put") {
   lostWrites++;
   const response=await network.send("Fetch.getResponseBody",{requestId:event.requestId});
   lostSave={status:event.responseStatusCode,body:response.base64Encoded?Buffer.from(response.body,"base64").toString():response.body};
   await network.send("Fetch.failRequest",{requestId:event.requestId,errorReason:"Failed"});
  } else await network.send("Fetch.continueRequest",{requestId:event.requestId});
 })().catch(error=>{interceptionError=error;});});
 await network.send("Fetch.enable",{patterns:[{urlPattern:"*/_redevplugin_web/resource",requestStage:"Response"}]});
 await b.getByRole("button",{name:"Save",exact:true}).click();
 await b.getByText("The save result is unknown. Your changes are kept here. Reload the saved version before saving again.",{exact:true}).waitFor();
 assert.equal(await b.getByLabel("Document",{exact:true}).inputValue(),"save response lost");
 assert.equal(await b.getByRole("button",{name:"Save",exact:true}).isDisabled(),true);assert.equal(lostWrites,1);assert.ifError(interceptionError);assert.equal(lostSave.status,200,JSON.stringify(lostSave));assert.equal(JSON.parse(lostSave.body).ok,true);
 await network.send("Fetch.disable");await network.detach();
 await b.getByRole("button",{name:"Reload saved version",exact:true}).click();await b.getByRole("button",{name:"Confirm reload — replace unsaved changes",exact:true}).click();await b.getByText("Ready",{exact:true}).waitFor();
 assert.equal(await b.getByLabel("Document",{exact:true}).inputValue(),"save response lost");
 console.log("Data author acceptance passed: no runtime, close cancellation, independent windows, CAS conflict, committed response loss, explicit uncertain-action review, single-flight actions, draft form refresh, sibling isolation and persistent data.");
} catch(error){throw new Error(String(error)+"\n"+logs,{cause:error})}finally{
 if(browser)await browser.close();if(child&&child.exitCode===null){child.kill("SIGINT");await Promise.race([new Promise(resolve=>child.once("exit",resolve)),new Promise(resolve=>setTimeout(resolve,5000))]);if(child.exitCode===null)child.kill("SIGKILL")};await rm(root,{recursive:true,force:true});
}
