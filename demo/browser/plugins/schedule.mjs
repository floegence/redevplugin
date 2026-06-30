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
const refreshButton = document.querySelector("#schedule-refresh");
const seedWeekButton = document.querySelector("#schedule-seed-week");
const archiveDoneButton = document.querySelector("#schedule-archive-done");
const titleInput = document.querySelector("#schedule-title");
const dateInput = document.querySelector("#schedule-date");
const timeInput = document.querySelector("#schedule-time");
const tagInput = document.querySelector("#schedule-tag");
const priorityInput = document.querySelector("#schedule-priority");
const durationInput = document.querySelector("#schedule-duration");
const queryInput = document.querySelector("#schedule-query");
const statusInput = document.querySelector("#schedule-status");
const list = document.querySelector("#schedule-list");
const count = document.querySelector("#schedule-count");
const openCount = document.querySelector("#schedule-open");
const doneCount = document.querySelector("#schedule-done");
const minuteCount = document.querySelector("#schedule-minutes");
const storageSource = document.querySelector("#schedule-storage-source");
const storageRevision = document.querySelector("#schedule-storage-revision");
const storageUsage = document.querySelector("#schedule-storage-usage");
const persistedAt = document.querySelector("#schedule-persisted-at");
const timelineNext = document.querySelector("#timeline-next");
const timeline = document.querySelector("#schedule-timeline");
const journalCount = document.querySelector("#journal-count");
const journal = document.querySelector("#schedule-journal");
const result = document.querySelector("#plugin-result");

dateInput.value = new Date().toISOString().slice(0, 10);

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
    priority: priorityInput.value,
    duration_minutes: durationInput.value,
    notes: "Created from the sandboxed schedule plugin UI.",
    view: currentView(),
  });
  titleInput.value = "";
  tagInput.value = "";
});

refreshButton.addEventListener("click", refreshItems);
seedWeekButton.addEventListener("click", () => callPlugin("schedule.items.seedWeek", { view: currentView() }));
archiveDoneButton.addEventListener("click", () => callPlugin("schedule.items.archiveDone", { view: currentView() }));
statusInput.addEventListener("change", refreshItems);
queryInput.addEventListener("input", debounce(refreshItems, 180));

async function refreshItems() {
  await callPlugin("schedule.items.list", currentView());
}

async function callPlugin(method, payload) {
  status.textContent = "syncing";
  try {
    const response = await client.call(method, payload);
    const data = response?.data ?? response;
    if (Array.isArray(data?.items)) {
      renderItems(data.items);
    }
    if (data?.stats) {
      renderStats(data.stats, data.items ?? []);
    }
    if (Array.isArray(data?.timeline)) {
      renderTimeline(data.timeline, data.stats);
    }
    if (Array.isArray(data?.journal)) {
      renderJournal(data.journal);
    }
    if (data?.source || data?.persisted_at) {
      renderStorageState(data);
    }
    status.textContent = "ready";
    writeResult({ method, response });
    return response;
  } catch (error) {
    status.textContent = "error";
    if (error instanceof PluginBridgeError) {
      writeResult({ method, error_code: error.errorCode, error: error.message });
      return null;
    }
    writeResult({ method, error: String(error) });
    return null;
  }
}

function renderItems(items) {
  count.textContent = String(items.length);
  list.replaceChildren(...items.map((item) => {
    const row = document.createElement("li");
    row.className = item.done ? "done" : "";
    const content = document.createElement("div");
    content.innerHTML = `<strong>${escapeHTML(item.title)}</strong><span>${escapeHTML(item.date)} · ${escapeHTML(item.time)} · ${escapeHTML(item.tag)} · ${escapeHTML(item.priority || "medium")} · ${Number(item.duration_minutes ?? 0)}m</span><p>${escapeHTML(item.notes || "")}</p>`;
    const actions = document.createElement("div");
    actions.className = "button-row";
    const toggle = document.createElement("button");
    toggle.type = "button";
    toggle.className = "secondary-button";
    toggle.textContent = item.done ? "Reopen" : "Done";
    toggle.addEventListener("click", () => callPlugin("schedule.item.toggle", { id: item.id, view: currentView() }));
    const remove = document.createElement("button");
    remove.type = "button";
    remove.className = "ghost-button";
    remove.textContent = "Remove";
    remove.addEventListener("click", () => callPlugin("schedule.item.delete", { id: item.id, view: currentView() }));
    actions.append(toggle, remove);
    row.append(content, actions);
    return row;
  }));
}

function renderStats(stats) {
  openCount.textContent = String(stats.open ?? 0);
  doneCount.textContent = String(stats.done ?? 0);
  minuteCount.textContent = String(stats.planned_minutes ?? 0);
  timelineNext.textContent = stats.next ? `${stats.next.time} · ${stats.next.title}` : "No upcoming item";
}

function renderStorageState(data) {
  storageSource.textContent = data.source ?? "host storage broker";
  if (data.storage) {
    storageRevision.textContent = `rev ${Number(data.storage.revision ?? 0)}`;
    storageUsage.textContent = `${formatBytes(data.storage.used_bytes)} / ${formatBytes(data.storage.quota_bytes)}`;
  }
  persistedAt.textContent = formatTime(data.persisted_at);
}

function renderTimeline(items) {
  timeline.replaceChildren(...items.slice(0, 8).map((item) => {
    const node = document.createElement("div");
    node.className = `timeline-item priority-${escapeClass(item.priority)}${item.done ? " done" : ""}`;
    node.style.setProperty("--lane", String(Number(item.lane ?? 0)));
    node.innerHTML = `<strong>${escapeHTML(item.slot)}</strong><span>${escapeHTML(item.label)}</span><small>${escapeHTML(item.tag)}</small>`;
    return node;
  }));
}

function renderJournal(entries) {
  journalCount.textContent = `${entries.length} entries`;
  journal.replaceChildren(...entries.slice(0, 8).map((entry) => {
    const row = document.createElement("li");
    row.innerHTML = `<strong>${escapeHTML(entry.action)}</strong><span>rev ${Number(entry.revision ?? 0)} · ${formatTime(entry.at)}</span><p>${escapeHTML(entry.detail)}</p>`;
    return row;
  }));
}

function currentView() {
  return {
    status: statusInput.value,
    query: queryInput.value,
  };
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

function formatTime(value) {
  if (!value) {
    return "--";
  }
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return String(value);
  }
  return date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

function formatBytes(value) {
  const bytes = Number(value ?? 0);
  if (!Number.isFinite(bytes) || bytes <= 0) {
    return "0 B";
  }
  if (bytes < 1024) {
    return `${Math.round(bytes)} B`;
  }
  return `${(bytes / 1024).toFixed(1)} KiB`;
}

function escapeClass(value) {
  return String(value || "medium").replace(/[^a-z0-9_-]/gi, "").toLowerCase() || "medium";
}

function debounce(fn, delayMs) {
  let timer = 0;
  return () => {
    clearTimeout(timer);
    timer = setTimeout(fn, delayMs);
  };
}
