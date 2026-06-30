import { PluginPlatformClient, PluginSurfaceHost } from "../../packages/redevplugin-ui/dist/index.js";
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
const picker = document.querySelector("#demo-picker");
const platformClientStatus = document.querySelector("#platform-client-status");
const platformClientDetail = document.querySelector("#platform-client-detail");

const builtinPlugins = [
  {
    key: "workspace",
    label: "Workspace tools",
    path: "/demo/browser/plugin.html",
    pluginId: "dev.redevplugin.workspace.demo",
  },
  {
    key: "bouncer",
    label: "Bouncer game",
    path: "/demo/browser/plugins/bouncer.html",
    pluginId: "dev.redevplugin.bouncer.demo",
  },
  {
    key: "schedule",
    label: "Schedule planner",
    path: "/demo/browser/plugins/schedule.html",
    pluginId: "dev.redevplugin.schedule.demo",
  },
  {
    key: "weather",
    label: "Weather console",
    path: "/demo/browser/plugins/weather.html",
    pluginId: "dev.redevplugin.weather.demo",
  },
];

const params = new URLSearchParams(window.location.search);
const pluginOrigin = params.get("plugin_origin") ?? "http://127.0.0.1:4174";
const requestedPluginPath = params.get("plugin_path");
const requestedPluginID = params.get("plugin_id");
const requestedSurfaceID = params.get("surface_id");
const requestedSurfaceInstanceID = params.get("surface_instance_id");
const requestedActiveFingerprint = params.get("active_fingerprint");
const requestedBridgeNonce = params.get("bridge_nonce");
const selectionStorageKey = "redevplugin.demo.selected_plugin";

let surfaceHost = null;
let platform = null;
let handshakes = 0;
let rpcCalls = 0;
let confirmations = 0;
let pendingConfirmation = null;

for (const plugin of builtinPlugins) {
  const button = document.createElement("button");
  button.type = "button";
  button.className = "plugin-choice";
  button.dataset.pluginKey = plugin.key;
  button.textContent = plugin.label;
  button.addEventListener("click", () => openBuiltinPlugin(plugin));
  picker?.append(button);
}

sendVisible.addEventListener("click", () => {
  surfaceHost?.sendLifecycle({ type: "visible" });
  addLog("lifecycle", { type: "visible" });
});

approveConfirmation.addEventListener("click", () => {
  resolvePendingConfirmation(true);
});

denyConfirmation.addEventListener("click", () => {
  resolvePendingConfirmation(false);
});

window.addEventListener("beforeunload", () => {
  surfaceHost?.dispose();
});

if (requestedPluginPath) {
  openPlugin({
    key: "custom",
    label: requestedPluginID ?? "Custom plugin",
    path: requestedPluginPath,
    pluginId: requestedPluginID,
    surfaceId: requestedSurfaceID,
    surfaceInstanceId: requestedSurfaceInstanceID,
    activeFingerprint: requestedActiveFingerprint,
    bridgeNonce: requestedBridgeNonce,
  });
} else {
  openBuiltinPlugin(findInitialBuiltinPlugin());
}

function openBuiltinPlugin(plugin) {
  saveSelectedBuiltinPlugin(plugin.key);
  const token = crypto.randomUUID().replaceAll("-", "");
  openPlugin({
    ...plugin,
    surfaceId: `${plugin.pluginId}.activity`,
    surfaceInstanceId: `surface_${plugin.key}_${token.slice(0, 16)}`,
    activeFingerprint: `sha256:${plugin.key}_${token}`,
    bridgeNonce: `bridge_nonce_${plugin.key}_${token}`,
  });
}

function findInitialBuiltinPlugin() {
  const savedKey = loadSelectedBuiltinPlugin();
  return builtinPlugins.find((plugin) => plugin.key === savedKey) ?? builtinPlugins[0];
}

function loadSelectedBuiltinPlugin() {
  try {
    return window.localStorage.getItem(selectionStorageKey);
  } catch {
    return "";
  }
}

function saveSelectedBuiltinPlugin(key) {
  try {
    window.localStorage.setItem(selectionStorageKey, key);
  } catch {
    // Ignore storage failures; the demo can still open the selected plugin.
  }
}

function openPlugin(plugin) {
  surfaceHost?.dispose();
  surfaceHost = null;
  pendingConfirmation = null;
  confirmationPanel.hidden = true;
  status.textContent = "starting";
  handshakes = 0;
  rpcCalls = 0;
  confirmations = 0;
  handshakeCount.textContent = "0";
  rpcCount.textContent = "0";
  confirmationCount.textContent = "0";
  setSelectedPlugin(plugin.key);

  const demoBootstrap = createDemoBootstrap({
    pluginId: plugin.pluginId,
    surfaceId: plugin.surfaceId,
    surfaceInstanceId: plugin.surfaceInstanceId,
    activeFingerprint: plugin.activeFingerprint,
    bridgeNonce: plugin.bridgeNonce,
  });
  const pluginURL = new URL(plugin.path, pluginOrigin);
  pluginURL.searchParams.set("parent_origin", window.location.origin);
  pluginURL.searchParams.set("plugin_id", demoBootstrap.pluginId);
  pluginURL.searchParams.set("surface_id", demoBootstrap.surfaceId);
  pluginURL.searchParams.set("surface_instance_id", demoBootstrap.surfaceInstanceId);
  pluginURL.searchParams.set("active_fingerprint", demoBootstrap.activeFingerprint);
  pluginURL.searchParams.set("bridge_nonce", demoBootstrap.bridgeNonce);

  platform = createDemoPlatformFetch({
    bootstrap: demoBootstrap,
    onCall(path, body) {
      if (path.endsWith("/settings/schema") || path.endsWith("/settings")) {
        addLog("platform-client", { path, keys: Object.keys(body ?? {}) });
      }
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

  surfaceHost = new PluginSurfaceHost({
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

  iframe.src = pluginURL.href;
  status.textContent = "listening";
  addLog("host-ready", {
    plugin: plugin.label,
    host_origin: window.location.origin,
    plugin_origin: pluginURL.origin,
  });
  void refreshPlatformClientState(demoBootstrap);
}

async function refreshPlatformClientState(bootstrap) {
  platformClientStatus.textContent = "loading";
  platformClientDetail.textContent = "reading schema";
  const client = new PluginPlatformClient({
    fetch: platform.fetch,
    ownerSessionHashHeader: bootstrap.ownerSessionHash,
  });
  try {
    const schema = await client.getSettingsSchema(bootstrap.pluginInstanceId);
    const current = await client.getSettings(bootstrap.pluginInstanceId);
    const nextAccent = current.values?.accent_mode === "teal" ? "indigo" : "teal";
    const patched = await client.patchSettings(bootstrap.pluginInstanceId, { accent_mode: nextAccent });
    platformClientStatus.textContent = "settings ok";
    platformClientDetail.textContent = `${schema.fields.length} fields, revision ${patched.settings_revision}, accent ${patched.values.accent_mode}`;
    addLog("settings-client", {
      plugin_instance_id: patched.plugin_instance_id,
      settings_revision: patched.settings_revision,
      accent_mode: patched.values.accent_mode,
    });
  } catch (error) {
    platformClientStatus.textContent = "settings error";
    platformClientDetail.textContent = error instanceof Error ? error.message : String(error);
    addLog("settings-client-error", { error: platformClientDetail.textContent });
  }
}

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

function setSelectedPlugin(key) {
  for (const button of picker?.querySelectorAll(".plugin-choice") ?? []) {
    button.classList.toggle("selected", button.dataset.pluginKey === key);
  }
}

function addLog(type, detail) {
  const item = document.createElement("li");
  item.textContent = `${new Date().toLocaleTimeString()} ${type} ${JSON.stringify(detail)}`;
  log.prepend(item);
  while (log.children.length > 20) {
    log.lastElementChild?.remove();
  }
}
