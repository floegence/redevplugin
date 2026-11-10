import assert from "node:assert/strict";
import { test } from "node:test";
import { pluginKV, pluginFiles, pluginDatabase, PluginResourceError } from "../src/resources.js";

test("storage lists accept broker usage identities and validate each required counter", async () => {
 const originalFetch = globalThis.fetch;
 const originalLocation = Object.getOwnPropertyDescriptor(globalThis, "location");
 Object.defineProperty(globalThis, "location", { configurable: true, value: { origin: "https://data.example.test" } });
 const usage = { plugin_instance_id: "plugin_fixture", store_id: "notes", usage_bytes: 12, quota_bytes: 4096, usage_files: 1, quota_files: 100 };
 try {
  for (const entries of [[], [{ key: "habit:reading", size_bytes: 12, updated_at: "2026-11-10T00:00:00Z" }]]) {
   const page = { entries, usage, next_cursor: "" };
   globalThis.fetch = async () => Response.json({ ok: true, data: page });
   assert.deepEqual(await pluginKV("notes").list(), page);
  }
  const files = { entries: [{ path: "notes.txt", dir: false, size_bytes: 12, updated_at: "2026-11-10T00:00:00Z" }], usage };
  globalThis.fetch = async () => Response.json({ ok: true, data: files });
  assert.deepEqual(await pluginFiles("notes").list(), files);
  for (const field of ["usage_bytes", "quota_bytes", "usage_files", "quota_files"]) {
   for (const invalid of [undefined, null, "0", -1, 0.5, Number.MAX_SAFE_INTEGER + 1]) {
    globalThis.fetch = async () => Response.json({ ok: true, data: { entries: [], usage: { ...usage, [field]: invalid } } });
    await assert.rejects(pluginKV("notes").list(), e => e instanceof PluginResourceError && e.code === "INVALID_RESPONSE" && e.mutationOutcome === "not_committed", `${field}: ${String(invalid)}`);
   }
  }
 } finally {
  globalThis.fetch = originalFetch;
  if (originalLocation) Object.defineProperty(globalThis, "location", originalLocation); else Reflect.deleteProperty(globalThis, "location");
 }
});

test("private resources preserve CAS, exact origin, and unknown mutation outcomes", async () => {
 const originalFetch = globalThis.fetch;
 const originalLocation = Object.getOwnPropertyDescriptor(globalThis, "location");
 Object.defineProperty(globalThis,"location",{configurable:true,value:{origin:"https://data.example.test"}});
 let calls=0;
 let operation="";
 globalThis.fetch=async (url,options)=>{
  calls++;
  assert.equal(String(url),"https://data.example.test/_redevplugin_web/resource");
  assert.equal(options?.credentials,"same-origin");assert.equal(options?.redirect,"error");
  const input=JSON.parse(String(options?.body));operation=input.arguments.operation;
  if(operation==="put") {assert.equal(input.arguments.expected_etag,"");return Response.json({ok:true,data:{etag:"revision"}});}
  if(operation==="get") return Response.json({ok:true,data:{value_base64:btoa(JSON.stringify({text:"saved"})),etag:"revision"}});
  return Response.json({ok:false,error:{code:"CONFLICT",retryable:false,mutation_outcome:"not_committed"}},{status:400});
 };
 try {
  const kv=pluginKV<{text:string}>("notes");
  assert.deepEqual(await kv.put("draft",{text:"saved"},{expectedETag:""}),{etag:"revision"});
  assert.deepEqual(await kv.read("draft"),{value:{text:"saved"},etag:"revision"});
  await assert.rejects(kv.delete("draft",{expectedETag:"stale"}),e=>e instanceof PluginResourceError && e.code==="CONFLICT" && e.mutationOutcome==="not_committed");
  const before=calls;
  await assert.rejects(pluginDatabase("notes").exec("SELECT ?",[Number.MAX_SAFE_INTEGER+1]));
  assert.equal(calls,before);
  globalThis.fetch=async ()=>{calls++;throw new Error("lost reply");};
  await assert.rejects(kv.put("draft",{text:"uncertain"}),e=>e instanceof PluginResourceError && e.mutationOutcome==="unknown");
  assert.equal(calls,before+1);
  const controller=new AbortController();controller.abort();
  await assert.rejects(kv.put("draft",{text:"never sent"},{signal:controller.signal}));
  assert.equal(calls,before+1);
 } finally {
  globalThis.fetch=originalFetch;
  if(originalLocation) Object.defineProperty(globalThis,"location",originalLocation);else Reflect.deleteProperty(globalThis,"location");
 }
});

test("private binary uploads preserve explicit rollback and unknown outcomes",async()=>{
 const {pluginFiles}=await import("../src/resources.js");const original=globalThis.fetch;const location=Object.getOwnPropertyDescriptor(globalThis,"location");
 Object.defineProperty(globalThis,"location",{configurable:true,value:{origin:"https://surface.example"}});let calls=0;
 try{
  globalThis.fetch=async(url,init)=>{calls++;assert.equal(new URL(String(url)).pathname,"/_redevplugin_web/private-file-transfer");assert.equal(init?.body instanceof Blob,true);return Response.json({ok:false,error:{code:"RESOURCE_LIMIT",retryable:false,mutation_outcome:"not_committed"}},{status:400})};
  await assert.rejects(pluginFiles("files").writeFrom("large.bin",new Blob(["hello"])),e=>e instanceof PluginResourceError&&e.mutationOutcome==="not_committed");assert.equal(calls,1);
  globalThis.fetch=async()=>{calls++;throw new Error("lost")};await assert.rejects(pluginFiles("files").writeFrom("large.bin",new Blob(["hello"])),e=>e instanceof PluginResourceError&&e.mutationOutcome==="unknown");assert.equal(calls,2);
 }finally{globalThis.fetch=original;if(location)Object.defineProperty(globalThis,"location",location);else Reflect.deleteProperty(globalThis,"location")}
});

test("control responses reject malformed data and bound decoded bytes", async () => {
 const original=globalThis.fetch; const location=Object.getOwnPropertyDescriptor(globalThis,"location");
 Object.defineProperty(globalThis,"location",{configurable:true,value:{origin:"https://surface.example"}});
 try {
  globalThis.fetch=async()=>Response.json({ok:true,data:{etag:32}});
  await assert.rejects(pluginKV("notes").put("draft",{}),e=>e instanceof PluginResourceError && e.code==="INVALID_RESPONSE" && e.mutationOutcome==="unknown");
  globalThis.fetch=async()=>Response.json({ok:true,data:{value_base64:"e30=",etag:32}});
  await assert.rejects(pluginKV("notes").read("draft"),e=>e instanceof PluginResourceError && e.code==="INVALID_RESPONSE");
  let cancelled=false;
  globalThis.fetch=async()=>new Response(new ReadableStream<Uint8Array>({pull(controller){controller.enqueue(new Uint8Array(128*1024).fill(32));},cancel(){cancelled=true;}}));
  await assert.rejects(pluginKV("notes").read("draft"),e=>e instanceof PluginResourceError && e.code==="INVALID_RESPONSE");assert.equal(cancelled,true);
 } finally {globalThis.fetch=original;if(location)Object.defineProperty(globalThis,"location",location);else Reflect.deleteProperty(globalThis,"location");}
});
