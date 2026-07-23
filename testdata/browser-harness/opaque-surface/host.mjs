import {
  PluginPlatformClient,
  PluginSurfaceSlot,
  createReDevPluginSurfaceTransport,
  createPluginSurfaceScope,
} from "../../../packages/redevplugin-ui/dist/trusted-parent.js";

const surfaceMount = document.querySelector("#plugin-surface-mount");
const hostStatus = document.querySelector("#host-status");
const sandboxMode = document.querySelector("#sandbox-mode");
const credentiallessMode = document.querySelector("#credentialless-mode");
const openingProgress = document.querySelector("#opening-progress");
const confirmationCount = document.querySelector("#confirmation-count");
const confirmationPanel = document.querySelector("#confirmation-panel");
const confirmationMethod = document.querySelector("#confirmation-method");
const confirmationHash = document.querySelector("#confirmation-hash");
const approveConfirmation = document.querySelector("#approve-confirmation");
const denyConfirmation = document.querySelector("#deny-confirmation");
const eventLog = document.querySelector("#event-log");
const sendVisible = document.querySelector("#send-visible");
const sendHidden = document.querySelector("#send-hidden");
const disposeSurface = document.querySelector("#dispose-surface");
const reopenSurface = document.querySelector("#reopen-surface");

const credentiallessScenario = new URLSearchParams(location.search).get("credentialless") === "unsupported"
  ? "unsupported"
  : "supported";
const surfaceScope = createPluginSurfaceScope();
const hostTransport = createReDevPluginSurfaceTransport();
const platformClient = new PluginPlatformClient({ surfaceScope, surfaceTransport: hostTransport });
const surfaceSlot = PluginSurfaceSlot.create({ stage: surfaceMount });
const state = {
  surfaceHost: null,
  pendingConfirmation: null,
  confirmations: 0,
  progressEvents: [],
  openedAt: 0,
  disposedAt: 0,
  interactions: [],
  errors: [],
};

document.cookie = "redevplugin_host_harness_secret=parent-only; SameSite=Strict";
credentiallessMode.textContent = credentiallessScenario;

sendVisible.addEventListener("click", () => sendLifecycle("visible"));
sendHidden.addEventListener("click", () => sendLifecycle("hidden"));
disposeSurface.addEventListener("click", () => void closeSurface());
reopenSurface.addEventListener("click", () => void openSurface());
approveConfirmation.addEventListener("click", () => resolveConfirmation(true));
denyConfirmation.addEventListener("click", () => resolveConfirmation(false));
addEventListener("beforeunload", () => void surfaceSlot.dispose());

window.__redevpluginHarness = Object.freeze({
  open: openSurface,
  close: closeSurface,
  snapshot: () => ({
    status: hostStatus.dataset.state,
    credentiallessScenario,
    confirmations: state.confirmations,
    progressEvents: [...state.progressEvents],
    openedAt: state.openedAt,
    disposedAt: state.disposedAt,
    interactions: [...state.interactions],
    errors: [...state.errors],
    iframeSrcdocEmpty: !state.surfaceHost || state.surfaceHost.element.srcdoc === "",
  }),
});

void openSurface();

async function openSurface() {
  state.surfaceHost = null;
  state.pendingConfirmation = null;
  state.progressEvents = [];
  state.openedAt = 0;
  state.disposedAt = 0;
  state.interactions = [];
  confirmationPanel.hidden = true;
  openingProgress.textContent = "0";
  setStatus("opening");
  addLog("surface-open-start", { credentialless: credentiallessScenario });
  try {
    const surfaceHost = await platformClient.openSurfaceInSlot(surfaceSlot, {
      plugin_instance_id: "plugin_browser_harness_1",
      surface_id: "dev.redevplugin.opaque-browser.view",
      expected_management_revision: 1,
    }, {
      confirm: confirmDangerousAction,
      onOpeningProgress(progress) {
        state.progressEvents.push(progress.elapsedMs);
        openingProgress.textContent = String(state.progressEvents.length);
        addLog("surface-opening-progress", { elapsed_ms: progress.elapsedMs });
      },
      onInteraction(event) {
        state.interactions.push({
          kind: event.kind,
          sequence: event.sequence,
          localScroll: event.localScroll,
        });
        if (state.interactions.length > 32) state.interactions.shift();
      },
      onError(error) {
        state.errors.push({ error_code: error.errorCode, message: error.message });
        addLog("surface-error", { error_code: error.errorCode, message: error.message });
      },
    });
    const iframe = surfaceHost.element;
    iframe.id = "plugin-frame";
    iframe.title = "Opaque ReDevPlugin surface";
    state.surfaceHost = surfaceHost;
    if (state.surfaceHost !== surfaceHost) return;
    state.openedAt = Date.now();
    sandboxMode.textContent = iframe.getAttribute("sandbox") || "missing";
    credentiallessMode.textContent = "credentialless" in iframe && iframe.credentialless
      ? "enabled"
      : "unsupported-safe";
    setStatus("ready");
    addLog("surface-ready", {
      sandbox: iframe.getAttribute("sandbox"),
      credentialless: credentiallessMode.textContent,
    });
  } catch (error) {
    const failure = normalizeError(error);
    state.errors.push(failure);
    setStatus("error");
    addLog("surface-open-failed", failure);
  }
}

async function closeSurface() {
  const surfaceHost = state.surfaceHost;
  state.surfaceHost = null;
  if (!surfaceHost) return;
  const iframe = surfaceHost.element;
  try {
    await surfaceSlot.close();
    state.disposedAt = Date.now();
    setStatus("disposed");
    addLog("surface-disposed", { iframe_srcdoc_empty: iframe.srcdoc === "" });
  } catch (error) {
    const failure = normalizeError(error);
    state.errors.push(failure);
    setStatus("error");
    addLog("surface-dispose-failed", failure);
  }
}

function sendLifecycle(type) {
  try {
    state.surfaceHost?.sendLifecycle({ type });
    addLog("surface-lifecycle", { type });
  } catch (error) {
    addLog("surface-lifecycle-failed", normalizeError(error));
  }
}

function confirmDangerousAction(intent) {
  state.confirmations += 1;
  confirmationCount.textContent = String(state.confirmations);
  confirmationMethod.textContent = intent.method;
  confirmationHash.textContent = intent.requestHash;
  confirmationPanel.hidden = false;
  addLog("confirmation-requested", {
    method: intent.method,
    request_hash: intent.requestHash,
    plan_hash: intent.planHash,
  });
  return new Promise((resolve) => {
    const pending = { resolve };
    state.pendingConfirmation = pending;
    intent.signal.addEventListener("abort", () => {
      if (state.pendingConfirmation !== pending) return;
      state.pendingConfirmation = null;
      confirmationPanel.hidden = true;
      resolve({ confirmed: false });
      addLog("confirmation-aborted", { method: intent.method });
    }, { once: true });
  });
}

function resolveConfirmation(confirmed) {
  if (!state.pendingConfirmation) return;
  const pending = state.pendingConfirmation;
  state.pendingConfirmation = null;
  confirmationPanel.hidden = true;
  pending.resolve({ confirmed });
  addLog("confirmation-decided", { confirmed });
}

function setStatus(value) {
  hostStatus.textContent = value;
  hostStatus.dataset.state = value;
}

function addLog(type, detail) {
  const item = document.createElement("li");
  item.textContent = `${type} ${JSON.stringify(detail)}`;
  eventLog.prepend(item);
  while (eventLog.children.length > 24) eventLog.lastElementChild?.remove();
}

function normalizeError(error) {
  return {
    error_code: error?.errorCode || "PLUGIN_PLATFORM_REQUEST_FAILED",
    message: String(error?.message || error),
  };
}
