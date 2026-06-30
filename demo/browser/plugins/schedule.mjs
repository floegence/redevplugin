import { PluginBridgeClient, PluginBridgeError } from "../../../packages/redevplugin-ui/dist/index.js";
import { createDemoBootstrap, formatJSON } from "../demo-platform.mjs";

const params = new URLSearchParams(window.location.search);
const parentOrigin = params.get("parent_origin");
if (!parentOrigin || parentOrigin === "*") {
  throw new Error("parent_origin query parameter must be an exact origin");
}

const bootstrap = createDemoBootstrap({
  pluginId: params.get("plugin_id"),
  surfaceId: params.get("surface_id"),
  surfaceInstanceId: params.get("surface_instance_id"),
  activeFingerprint: params.get("active_fingerprint"),
  bridgeNonce: params.get("bridge_nonce"),
});
const client = new PluginBridgeClient({ ...bootstrap, parentOrigin });

const status = document.querySelector("#plugin-status");
const addButton = document.querySelector("#schedule-add");
const titleInput = document.querySelector("#schedule-title");
const dateInput = document.querySelector("#schedule-date");
const timeInput = document.querySelector("#schedule-time");
const tagInput = document.querySelector("#schedule-tag");
const list = document.querySelector("#schedule-list");
const count = document.querySelector("#schedule-count");
const result = document.querySelector("#plugin-result");

client.onLifecycle((event) => {
  status.textContent = event.type;
  writeResult({ lifecycle: event.type });
  if (event.type === "ready") {
    void refreshItems();
  }
});
client.handshake();

addButton.addEventListener("click", async () => {
  await callPlugin("schedule.item.add", {
    title: titleInput.value,
    date: dateInput.value,
    time: timeInput.value,
    tag: tagInput.value || "focus",
    notes: "Created from the sandboxed schedule plugin UI.",
  });
  titleInput.value = "";
  tagInput.value = "";
});

async function refreshItems() {
  await callPlugin("schedule.items.list", {});
}

async function callPlugin(method, payload) {
  status.textContent = "syncing";
  try {
    const response = await client.call(method, payload);
    const data = response?.data ?? response;
    if (Array.isArray(data?.items)) {
      renderItems(data.items);
    }
    status.textContent = "ready";
    writeResult({ method, response });
  } catch (error) {
    status.textContent = "error";
    if (error instanceof PluginBridgeError) {
      writeResult({ method, error_code: error.errorCode, error: error.message });
      return;
    }
    writeResult({ method, error: String(error) });
  }
}

function renderItems(items) {
  count.textContent = String(items.length);
  list.replaceChildren(...items.map((item) => {
    const row = document.createElement("li");
    row.className = item.done ? "done" : "";
    const content = document.createElement("div");
    content.innerHTML = `<strong>${escapeHTML(item.title)}</strong><span>${escapeHTML(item.date)} · ${escapeHTML(item.time)} · ${escapeHTML(item.tag)}</span><p>${escapeHTML(item.notes || "")}</p>`;
    const actions = document.createElement("div");
    actions.className = "button-row";
    const toggle = document.createElement("button");
    toggle.type = "button";
    toggle.className = "secondary-button";
    toggle.textContent = item.done ? "Reopen" : "Done";
    toggle.addEventListener("click", () => callPlugin("schedule.item.toggle", { id: item.id }));
    const remove = document.createElement("button");
    remove.type = "button";
    remove.className = "ghost-button";
    remove.textContent = "Remove";
    remove.addEventListener("click", () => callPlugin("schedule.item.delete", { id: item.id }));
    actions.append(toggle, remove);
    row.append(content, actions);
    return row;
  }));
}

function writeResult(value) {
  result.textContent = formatJSON(value);
}

function escapeHTML(value) {
  return String(value).replace(/[&<>"']/g, (char) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    "\"": "&quot;",
    "'": "&#39;",
  })[char]);
}
