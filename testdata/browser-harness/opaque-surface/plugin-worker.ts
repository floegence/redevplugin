import {
  PluginBridgeClient,
  type PluginCanvasWheelEvent,
  type PluginMethodResult,
  type PluginUIVNode,
} from "../../../packages/redevplugin-ui/src/plugin.js";
import { runWorkerSecurityProbe, type WorkerSecurityProbe } from "./worker-security-probe.js";

type HarnessExecutionEvent = {
  kind: "progress" | "data" | "diagnostic" | "terminal";
  payload?: { data_base64?: string };
};

function decodeExecutionText(event: HarnessExecutionEvent): string {
  if (!event.payload?.data_base64) return "";
  const binary = atob(event.payload.data_base64);
  return new TextDecoder().decode(Uint8Array.from(binary, (character) => character.charCodeAt(0)));
}

const bridge = new PluginBridgeClient({ timeoutMs: 8_000 });
const state = {
  status: "Starting isolated worker...",
  result: "Waiting for the trusted parent.",
  busy: false,
  security: {} as WorkerSecurityProbe,
  canvasWheel: null as PluginCanvasWheelEvent | null,
};

bridge.onAction("call-host", () => void callHost());
bridge.onAction("read-execution-events", () => void readExecutionEvents());
bridge.onAction("dangerous-action", () => void runDangerousAction());
bridge.onAction("observe-execution", () => void observeExecution());
bridge.onCanvasInput("wheel-probe", (event) => {
  if (event.type !== "wheel") return;
  state.canvasWheel = event;
  void render();
});
bridge.onLifecycle(async (event) => {
  if (event.type === "visible" || event.type === "hidden") {
    state.status = `Lifecycle: ${event.type}`;
    await render();
    await bridge.call("harness.echo", { message: `Lifecycle render committed: ${event.type}` });
  }
});

void initialize();

async function initialize(): Promise<void> {
  state.security = await runWorkerSecurityProbe();
  await bridge.ready();
  state.status = "Ready";
  await render();
  await bridge.openCanvas("wheel-probe");
}

async function callHost(): Promise<void> {
  await runAction("Calling harness.echo...", "Host responded", async () => {
    const response = await bridge.call("harness.echo", { message: "Hello from the opaque plugin worker" });
    return { method: "harness.echo", response };
  });
}

async function readExecutionEvents(): Promise<void> {
  await runAction("Opening Host-owned execution...", "Execution events received", async () => {
    const response = await bridge.call<PluginMethodResult>("harness.logs", { lines: 2 });
    if (!response.execution_id) throw new Error("host response omitted execution_id");
    const events = await readExecutionEventsToTerminal(response.execution_id);
    return {
      method: "harness.logs",
      events,
      text: events.map((event) => decodeExecutionText(event)).join(""),
      parent_execution_credential_visible: JSON.stringify(response).includes("ticket"),
    };
  });
}

async function readExecutionEventsToTerminal(executionID: string): Promise<HarnessExecutionEvent[]> {
  const events: HarnessExecutionEvent[] = [];
  let cursor = 0;
  let recoveredResponseLoss = false;
  while (true) {
    let batch;
    try {
      batch = await bridge.executionEvents(executionID, cursor);
    } catch (error) {
      if (recoveredResponseLoss) throw error;
      recoveredResponseLoss = true;
      continue;
    }
    events.push(...batch.events as HarnessExecutionEvent[]);
    cursor = batch.cursor;
    if (batch.events.some((event) => event.kind === "terminal")) return events;
  }
}

async function runDangerousAction(): Promise<void> {
  await runAction("Waiting for confirmation...", "Dangerous action confirmed", async () => ({
    method: "danger.run",
    response: await bridge.call("danger.run", { target: "harness-resource" }),
  }));
}

async function observeExecution(): Promise<void> {
  await runAction("Testing execution observation cancellation...", "Execution observation recovered", async () => {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 50);
    let firstErrorCode = "";
    try {
      await bridge.executionSnapshot("execution_harness_1", { signal: controller.signal });
    } catch (error) {
      firstErrorCode = (error as { errorCode?: string }).errorCode ?? "";
    } finally {
      clearTimeout(timer);
    }
    if (firstErrorCode !== "PLUGIN_BRIDGE_CANCELLED") {
      throw new Error(`first execution observation was not cancelled: ${firstErrorCode}`);
    }
    const snapshot = await bridge.executionSnapshot("execution_harness_1");
    return { first_cancelled: true, retry_status: snapshot.status };
  });
}

async function runAction(starting: string, complete: string, action: () => Promise<unknown>): Promise<void> {
  if (state.busy) return;
  state.busy = true;
  state.status = starting;
  await render();
  try {
    state.result = JSON.stringify(await action(), null, 2);
    state.status = complete;
  } catch (error) {
    const failure = error as Error & { errorCode?: string };
    state.result = JSON.stringify({ error: failure.message, error_code: failure.errorCode }, null, 2);
    state.status = "Action failed";
  } finally {
    state.busy = false;
    await render();
  }
}

function button(label: string, action: string): PluginUIVNode {
  return {
    type: "element",
    key: `action-${action}`,
    tag: "button",
    attributes: {
      type: "button",
      disabled: state.busy,
      "data-redevplugin-action": action,
    },
    children: [text(`action-${action}-label`, label)],
  };
}

function text(key: string, value: string): PluginUIVNode {
  return { type: "text", key, text: value };
}

function render(): Promise<void> {
  return bridge.render({
    type: "element",
    key: "harness-root",
    tag: "main",
    attributes: { class: "plugin-surface" },
    children: [
      { type: "element", key: "harness-eyebrow", tag: "p", attributes: { class: "eyebrow" }, children: [text("harness-eyebrow-text", "Opaque worker surface")] },
      { type: "element", key: "harness-title", tag: "h1", children: [text("harness-title-text", "Plugin isolation lab")] },
      { type: "element", key: "harness-status", tag: "p", attributes: { id: "plugin-status", class: "status", role: "status" }, children: [text("harness-status-text", state.status)] },
      {
        type: "element",
        key: "wheel-probe",
        tag: "canvas",
        attributes: {
          width: 320,
          height: 120,
          "aria-label": "Canvas wheel input probe",
          "data-redevplugin-canvas": "wheel-probe",
        },
        children: [],
      },
      {
        type: "element",
        key: "canvas-wheel",
        tag: "pre",
        attributes: { id: "canvas-wheel", "aria-label": "Latest canvas wheel input" },
        children: [text("canvas-wheel-text", state.canvasWheel ? JSON.stringify(state.canvasWheel) : "Waiting for canvas wheel input")],
      },
      {
        type: "element",
        key: "harness-actions",
        tag: "div",
        attributes: { class: "button-row" },
        children: [
          button("Call host", "call-host"),
          button("Read execution events", "read-execution-events"),
          button("Dangerous action", "dangerous-action"),
          button("Observe execution", "observe-execution"),
        ],
      },
      { type: "element", key: "security-title", tag: "h2", children: [text("security-title-text", "Worker security probe")] },
      {
        type: "element",
        key: "security-probe",
        tag: "pre",
        attributes: { id: "security-probe", "aria-label": "Worker security probe" },
        children: [text("security-probe-text", JSON.stringify(state.security, null, 2))],
      },
      { type: "element", key: "result-title", tag: "h2", children: [text("result-title-text", "Latest result")] },
      {
        type: "element",
        key: "plugin-result",
        tag: "pre",
        attributes: { id: "plugin-result", "aria-label": "Latest result" },
        children: [text("plugin-result-text", state.result)],
      },
    ],
  });
}
