import assert from "node:assert/strict";
import { test } from "node:test";
import { openPluginConnection } from "../src/connections.js";

test("connection discovery preserves native fetch and binds exact child origin", async () => {
 const originalFetch = globalThis.fetch;
 const originalLocation = Object.getOwnPropertyDescriptor(globalThis, "location");
 Object.defineProperty(globalThis, "location", { configurable:true, value:{origin:"https://plugin.example.com"} });
 const controller = new AbortController();
 let calls = 0;
 const response = {connector_id:"api", connection_id:"fixed-0",base_path:"/_redevplugin_web/connections/api/fixed-0/",http_methods:["GET"]};
 const transport: typeof fetch = async (url, options) => {
  calls++;
  assert.equal(String(url), "https://plugin.example.com/_redevplugin_web/connection?connector_id=api&destination_index=0");
  assert.equal(options?.credentials,"same-origin"); assert.equal(options?.redirect,"error"); assert.equal(options?.cache,"no-store"); assert.equal(options?.signal,controller.signal);
  return Response.json(response);
 };
 globalThis.fetch = transport;
 try {
  const result = await openPluginConnection("api",{signal:controller.signal});
  assert.equal(globalThis.fetch,transport);
  assert.equal(result.baseURL,"https://plugin.example.com/_redevplugin_web/connections/api/fixed-0/");
  assert.equal(Object.isFrozen(result),true); assert.equal(Object.isFrozen(result.httpMethods),true);
  for (const id of ["../outside","api/path","api?query","a".repeat(129),"中"]) await assert.rejects(openPluginConnection(id));
  for (const index of [-1,1.5,NaN]) await assert.rejects(openPluginConnection("api",{destinationIndex:index}));
  assert.equal(calls,1);
  response.base_path="https://outside.example.com/";
  await assert.rejects(openPluginConnection("api",{signal:controller.signal}));
  globalThis.fetch = async () => {calls++; throw new Error("unknown outcome");};
  const before = calls;
  await assert.rejects(openPluginConnection("api")); assert.equal(calls,before+1);
 } finally {
  globalThis.fetch=originalFetch;
  if (originalLocation) Object.defineProperty(globalThis,"location",originalLocation);
  else Reflect.deleteProperty(globalThis,"location");
 }
});
