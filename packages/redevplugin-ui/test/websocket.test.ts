import assert from "node:assert/strict";
import { test } from "node:test";
import {openPluginWebSocket} from "../src/websocket.js";
test("controlled socket bounds messages, closes explicitly, and never reconnects",async()=>{
 const original={fetch:globalThis.fetch,socket:globalThis.WebSocket,location:Object.getOwnPropertyDescriptor(globalThis,"location")};
 let created=0;const instances:FakeSocket[]=[];
 class FakeSocket extends EventTarget {
  protocol="test";binaryType="";bufferedAmount=0;sent:unknown[]=[];
  constructor(readonly url:URL){super();created++;instances.push(this);queueMicrotask(()=>this.dispatchEvent(new Event("open")));}
  send(data:unknown){this.sent.push(data)}
  close(code=1000){queueMicrotask(()=>this.dispatchEvent(Object.assign(new Event("close"),{code})))}
 }
 Object.defineProperty(globalThis,"location",{configurable:true,value:{origin:"https://surface.example"}});
 globalThis.WebSocket=FakeSocket as unknown as typeof WebSocket;
 globalThis.fetch=async()=>Response.json({connection_id:"fixed-0"});
 try{
  const socket=await openPluginWebSocket("events");assert.equal(instances.at(-1)!.url.origin,"wss://surface.example");
  await socket.send("hello");assert.deepEqual(instances.at(-1)!.sent,["hello"]);
  await assert.rejects(socket.send(new Uint8Array(1048577)),error=>error instanceof RangeError);
  for(let i=0;i<33;i++)instances.at(-1)!.dispatchEvent(Object.assign(new Event("message"),{data:"x"}));
  await assert.rejects(socket[Symbol.asyncIterator]().next(),error=>error instanceof Error && /overflow/.test(error.message));assert.equal(created,1);
  const second=await openPluginWebSocket("events");second.close();await Promise.resolve();assert.equal((await second[Symbol.asyncIterator]().next()).done,true);assert.equal(created,2);
 }finally{globalThis.fetch=original.fetch;globalThis.WebSocket=original.socket;if(original.location)Object.defineProperty(globalThis,"location",original.location);else Reflect.deleteProperty(globalThis,"location")}
});
