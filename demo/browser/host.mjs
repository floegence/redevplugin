import { PluginSurfaceHost } from "../../packages/redevplugin-ui/dist/index.js";
import { createDemoBootstrap, createDemoPlatformFetch } from "./demo-platform.mjs";

const iframe = document.querySelector("#plugin-frame");
const status = document.querySelector("#host-status");
const log = document.querySelector("#event-log");
const handshakeCount = document.querySelector("#handshake-count");
const rpcCount = document.querySelector("#rpc-count");
const confirmationCount = document.querySelector("#confirmation-count");
const confirmationPanel = document.querySelector("#confirmation-panel");
const confirmationMethod = document.querySelector("#confirmation-method");
const confirmationHash = document.querySelector("#confirmation-hash");
const approveConfirmation = document.querySelector("#approve-confirmation");
const denyConfirmation = document.querySelector("#deny-confirmation");
const sendVisible = document.querySelector("#send-visible");

const params = new URLSearchParams(window.location.search);
const pluginOrigin = params.get("plugin_origin") ?? "http://127.0.0.1:4174";
const pluginPath = params.get("plugin_path") ?? "/demo/browser/plugin.html";
const pluginID = params.get("plugin_id");
const surfaceID = params.get("surface_id");
const surfaceInstanceID = params.get("surface_instance_id");
const activeFingerprint = params.get("active_fingerprint");
const bridgeNonce = params.get("bridge_nonce");
const demoBootstrap = createDemoBootstrap({
  pluginId: pluginID,
  surfaceId: surfaceID,
  surfaceInstanceId: surfaceInstanceID,
  activeFingerprint,
  bridgeNonce,
});
const pluginURL = new URL(pluginPath, pluginOrigin);
pluginURL.searchParams.set("parent_origin", window.location.origin);
pluginURL.searchParams.set("plugin_id", demoBootstrap.pluginId);
pluginURL.searchParams.set("surface_id", demoBootstrap.surfaceId);
pluginURL.searchParams.set("surface_instance_id", demoBootstrap.surfaceInstanceId);
pluginURL.searchParams.set("active_fingerprint", demoBootstrap.activeFingerprint);
pluginURL.searchParams.set("bridge_nonce", demoBootstrap.bridgeNonce);
iframe.src = pluginURL.href;

let handshakes = 0;
let rpcCalls = 0;
let confirmations = 0;
let pendingConfirmation = null;

const platform = createDemoPlatformFetch({
  bootstrap: demoBootstrap,
  onCall(path, body) {
    if (path.endsWith("/bridge-token")) {
      handshakes += 1;
      handshakeCount.textContent = String(handshakes);
      addLog("bridge-token", { surface_instance_id: body.handshake?.surface_instance_id });
    }
    if (path.endsWith("/rpc")) {
      rpcCalls += 1;
      rpcCount.textContent = String(rpcCalls);
      addLog("rpc", { method: body.method, confirmed: Boolean(body.confirmation_token) });
    }
    if (path.endsWith("/confirm")) {
      addLog("confirmation-intent", { method: body.method });
    }
  },
});

const surfaceHost = new PluginSurfaceHost({
  bootstrap: demoBootstrap,
  iframeOrigin: pluginURL.origin,
  iframeWindow: iframe.contentWindow,
  parentWindow: window,
  apiBaseURL: "",
  fetch: platform.fetch,
  confirm: confirmDangerousCall,
  onError(error) {
    status.textContent = "error";
    addLog("host-error", { error_code: error.errorCode, message: error.message });
  },
});

sendVisible.addEventListener("click", () => {
  surfaceHost.sendLifecycle({ type: "visible" });
  addLog("lifecycle", { type: "visible" });
});

approveConfirmation.addEventListener("click", () => {
  resolvePendingConfirmation(true);
});

denyConfirmation.addEventListener("click", () => {
  resolvePendingConfirmation(false);
});

window.addEventListener("beforeunload", () => {
  surfaceHost.dispose();
});

status.textContent = "listening";
addLog("host-ready", { host_origin: window.location.origin, plugin_origin: pluginURL.origin });

function confirmDangerousCall(intent) {
  confirmations += 1;
  confirmationCount.textContent = String(confirmations);
  confirmationMethod.textContent = intent.method;
  confirmationHash.textContent = intent.requestHash;
  confirmationPanel.hidden = false;
  addLog("confirmation-required", {
    method: intent.method,
    confirmation_token_id: intent.confirmationTokenId,
  });
  return new Promise((resolve) => {
    pendingConfirmation = resolve;
  });
}

function resolvePendingConfirmation(confirmed) {
  if (!pendingConfirmation) {
    return;
  }
  confirmationPanel.hidden = true;
  pendingConfirmation({ confirmed });
  pendingConfirmation = null;
  addLog("confirmation-decision", { confirmed });
}

function addLog(type, detail) {
  const item = document.createElement("li");
  item.textContent = `${new Date().toLocaleTimeString()} ${type} ${JSON.stringify(detail)}`;
  log.prepend(item);
  while (log.children.length > 20) {
    log.lastElementChild?.remove();
  }
}
