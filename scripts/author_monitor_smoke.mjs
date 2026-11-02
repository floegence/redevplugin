import assert from "node:assert/strict";
import {chromium} from "playwright";
const browser=await chromium.launch({headless:true});
try{
 const page=await browser.newPage();const errors=[];page.on("console",message=>{if(message.type()==="error")errors.push(message.text())});
 await page.goto(process.argv[2]);const frame=page.frameLocator("#stage > iframe");
 await page.locator("#resources > summary").click();
 await page.getByLabel("Destination for events").fill(process.argv[3]);
 await page.getByLabel("Allow loopback destination on this computer").check();
 await page.getByRole("button",{name:"Review connection",exact:true}).click();
 await page.getByRole("button",{name:"Approve action",exact:true}).click();
 await page.getByText("events · active",{exact:true}).waitFor();
 await frame.getByRole("button",{name:"Connect",exact:true}).click();
 try{await frame.getByText("Live · snapshot 1",{exact:true}).waitFor({timeout:10000})}catch(error){throw new Error(String(error)+"\n"+errors.join("\n")+"\n"+await frame.locator("body").textContent())}
 assert.equal(await frame.getByLabel("Current snapshot").textContent(),"fixture snapshot");
 await frame.getByRole("button",{name:"Disconnect",exact:true}).click();await frame.getByText("Disconnected. Last snapshot retained.",{exact:true}).waitFor();
 assert.equal(await frame.getByLabel("Current snapshot").textContent(),"fixture snapshot");
 await frame.getByRole("button",{name:"Connect",exact:true}).click();await frame.getByText("Live · snapshot 2",{exact:true}).waitFor();
 await page.locator("#observations > summary").click();await page.getByRole("button",{name:"Refresh observations"}).click();
 await page.waitForFunction(()=>document.querySelector("#observations-result")?.textContent.includes('"tasks"'));
 const result=JSON.parse(await page.locator("#observations-result").textContent());assert.ok(Array.isArray(result.tasks.executions));assert.ok(result.diagnostics);
 await page.getByRole("button",{name:"Revoke network.client",exact:true}).click();
 console.log("Authenticated monitor acceptance passed: real Surface, CSP, discovery, upgrade, live snapshot, explicit reconnect, retained snapshot, permission revocation and observations.");
}finally{await browser.close()}
