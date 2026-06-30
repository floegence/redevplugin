import { decodePluginStreamText, PluginBridgeClient, PluginBridgeError, readPluginStream } from "../../packages/redevplugin-ui/dist/index.js";
import { demoBootstrap, formatJSON } from "./demo-platform.mjs";

const status = document.querySelector("#plugin-status");
const result = document.querySelector("#plugin-result");
const echoButton = document.querySelector("#call-echo");
const listButton = document.querySelector("#call-list");
const streamButton = document.querySelector("#call-stream");
const dangerousButton = document.querySelector("#call-dangerous");
const actionButtons = [echoButton, listButton, streamButton, dangerousButton];

const parentOrigin = new URLSearchParams(window.location.search).get("parent_origin");
if (!parentOrigin || parentOrigin === "*") {
  throw new Error("parent_origin query parameter must be an exact origin");
}

const client = new PluginBridgeClient({
  pluginId: demoBootstrap.pluginId,
  surfaceId: demoBootstrap.surfaceId,
  surfaceInstanceId: demoBootstrap.surfaceInstanceId,
  activeFingerprint: demoBootstrap.activeFingerprint,
  bridgeNonce: demoBootstrap.bridgeNonce,
  parentOrigin,
});

client.onLifecycle((event) => {
  status.textContent = event.type;
  appendResult({ lifecycle: event.type });
});

echoButton.addEventListener("click", () => {
  void callPlugin("demo.echo", { message: "hello from iframe" });
});

listButton.addEventListener("click", () => {
  void callPlugin("demo.storage.list", { path: "workspace" });
});

streamButton.addEventListener("click", () => {
  void tailLogs();
});

dangerousButton.addEventListener("click", () => {
  void callPlugin("demo.cache.delete", { path: "workspace/cache/index.sqlite" });
});

client.handshake();

async function callPlugin(method, params) {
  status.textContent = "calling";
  setActionBusy(true);
  try {
    const response = await client.call(method, params);
    status.textContent = "ready";
    appendResult({ method, response });
  } catch (error) {
    status.textContent = "error";
    if (error instanceof PluginBridgeError) {
      appendResult({ method, error_code: error.errorCode, error: error.message });
      return;
    }
    appendResult({ method, error: String(error) });
  } finally {
    setActionBusy(false);
  }
}

async function tailLogs() {
  status.textContent = "streaming";
  setActionBusy(true);
  try {
    const response = await client.call("demo.logs.tail", { source: "demo" });
    const events = await readPluginStream({
      result: response,
      apiBaseURL: new URL(parentOrigin).origin,
    });
    status.textContent = "ready";
    appendResult({
      method: "demo.logs.tail",
      response,
      stream: events.map((event) => ({
        sequence: event.sequence,
        kind: event.kind,
        text: decodePluginStreamText(event),
      })),
    });
  } catch (error) {
    status.textContent = "error";
    if (error instanceof PluginBridgeError) {
      appendResult({ method: "demo.logs.tail", error_code: error.errorCode, error: error.message });
      return;
    }
    appendResult({ method: "demo.logs.tail", error: String(error) });
  } finally {
    setActionBusy(false);
  }
}

function appendResult(value) {
  result.textContent = formatJSON(value);
}

function setActionBusy(busy) {
  for (const button of actionButtons) {
    button.disabled = busy;
  }
}
