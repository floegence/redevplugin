import { PluginBridgeClient } from "../../../packages/redevplugin-ui/src/plugin.js";
const bridge = new PluginBridgeClient();
await bridge.ready();
const unicode = await (await fetch("/说明.txt")).text();
const chunk = await import("./chunk.js");
const worker = new Worker(new URL("./worker.js", import.meta.url), { type: "module" });
const workerValue = await new Promise(resolve => { worker.onmessage = event => resolve(event.data); });
worker.terminate();
const canvas = document.querySelector<HTMLCanvasElement>("canvas")!;
const context = canvas.getContext("2d")!;
context.fillStyle = "#123456"; context.fillRect(0, 0, 2, 2);
const wasm = await WebAssembly.instantiate(new Uint8Array([0,97,115,109,1,0,0,0]));
let parentBlocked = false;
try { void parent.document.body; } catch { parentBlocked = true; }
localStorage.setItem("sample", "isolated");
const gl = document.createElement("canvas").getContext("webgl2");
const nativeStorage = await new Promise<boolean>((resolve, reject) => {
 const opening = indexedDB.open("native-application", 1);
 opening.onupgradeneeded = () => opening.result.createObjectStore("records");
 opening.onerror = () => reject(opening.error);
 opening.onsuccess = () => { const db = opening.result; const transaction = db.transaction("records", "readwrite"); transaction.objectStore("records").put("value", "key"); transaction.oncomplete = () => { db.close(); resolve(true); }; transaction.onerror = () => reject(transaction.error); };
});
bridge.onLifecycle(async event => { if (event.type === "dispose") await new Promise(resolve => setTimeout(resolve, 20)); });
const state = { unicode, unsaved: true, webgl: !!gl, indexedDB: nativeStorage, ready: true, chunk: chunk.value, worker: workerValue, pixel: [...context.getImageData(0,0,1,1).data], wasm: !!wasm.instance,
  parentBlocked, cookie: document.cookie, storage: localStorage.getItem("sample") };
bridge.onBeforeClose(() => !state.unsaved);
Object.assign(globalThis, { appState: state });
document.querySelector("button")!.addEventListener("click", () => {
  const input = document.querySelector<HTMLInputElement>("input")!;
  document.querySelector("output")!.textContent = input.value;
  history.pushState(null, "", "/notes/current");
});

const editor = document.createElement("textarea"); editor.setAttribute("aria-label", "Selected document");
const openFile = document.createElement("button"); openFile.textContent = "Open file";
const saveFile = document.createElement("button"); saveFile.textContent = "Save file"; saveFile.disabled = true;
const fileStatus = document.createElement("p"); fileStatus.setAttribute("role", "status");
document.body.append(editor, openFile, saveFile, fileStatus);
let selectedURI = "";
openFile.addEventListener("click", () => { void (async () => {
  try {
    const resource = await bridge.files.select({ kind: "file", writable: true });
    if (!resource) return;
    selectedURI = resource.uri;
    const file = await bridge.files.open(selectedURI);
    try { editor.value = new TextDecoder().decode((await file.read()).bytes); }
    finally { await file.close(); }
    saveFile.disabled = false; fileStatus.textContent = "Opened";
  } catch (error) { fileStatus.textContent = String(error); }
})(); });
saveFile.addEventListener("click", () => { void (async () => {
  try {
    const file = await bridge.files.open(selectedURI, { write: true, truncate: true });
    try { await file.write(new TextEncoder().encode(editor.value)); await file.sync(); }
    finally { await file.close(); }
    fileStatus.textContent = "Saved";
  } catch (error) { fileStatus.textContent = String(error); }
})(); });
