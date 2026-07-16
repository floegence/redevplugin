import {
  PluginBridgeClient,
  type PluginMethodResult,
  type PluginUIVNode,
} from "../../../packages/redevplugin-ui/src/plugin.js";
import { runWorkerSecurityProbe, type WorkerSecurityProbe } from "./worker-security-probe.js";

type HarnessStreamEvent = {
  data?: string;
};

function decodePluginStreamText(event: HarnessStreamEvent): string {
  if (!event.data) return "";
  const binary = atob(event.data);
  return new TextDecoder().decode(Uint8Array.from(binary, (character) => character.charCodeAt(0)));
}

const bridge = new PluginBridgeClient({ timeoutMs: 8_000 });
const state = {
  status: "Starting isolated worker...",
  result: "Waiting for the trusted parent.",
  busy: false,
  security: {} as WorkerSecurityProbe,
};

bridge.onAction("call-host", () => void callHost());
bridge.onAction("read-stream", () => void readStream());
bridge.onAction("dangerous-action", () => void runDangerousAction());
bridge.onLifecycle((event) => {
  if (event.type === "visible" || event.type === "hidden") {
    state.status = `Lifecycle: ${event.type}`;
    void render();
  }
});

void initialize();

async function initialize(): Promise<void> {
  state.security = await runWorkerSecurityProbe();
  await bridge.ready();
  state.status = "Ready";
  await render();
}

async function callHost(): Promise<void> {
  await runAction("Calling harness.echo...", "Host responded", async () => {
    const response = await bridge.call("harness.echo", { message: "Hello from the opaque plugin worker" });
    return { method: "harness.echo", response };
  });
}

async function readStream(): Promise<void> {
  await runAction("Opening parent-owned stream...", "Stream received", async () => {
    const response = await bridge.call<PluginMethodResult>("harness.logs", { lines: 2 });
    if (!response.stream_handle) throw new Error("host response omitted stream_handle");
    const events = await readStreamToEnd(response.stream_handle);
    return {
      method: "harness.logs",
      events,
      text: events.map((event) => decodePluginStreamText(event)).join(""),
      parent_stream_credential_visible: JSON.stringify(response).includes(["stream", "ticket"].join("_")),
    };
  });
}

async function readStreamToEnd(streamHandle: string): Promise<HarnessStreamEvent[]> {
  const events: HarnessStreamEvent[] = [];
  while (true) {
    const batch = await bridge.readStream(streamHandle);
    events.push(...batch.events);
    if (batch.done) return events;
    if (batch.events.length === 0 && batch.retry_after_ms > 0) {
      await new Promise((resolve) => setTimeout(resolve, batch.retry_after_ms));
    }
  }
}

async function runDangerousAction(): Promise<void> {
  await runAction("Waiting for confirmation...", "Dangerous action confirmed", async () => ({
    method: "danger.run",
    response: await bridge.call("danger.run", { target: "harness-resource" }),
  }));
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
    children: [label],
  };
}

function render(): Promise<void> {
  return bridge.render({
    type: "element",
    key: "harness-root",
    tag: "main",
    attributes: { class: "plugin-surface" },
    children: [
      { type: "element", key: "harness-eyebrow", tag: "p", attributes: { class: "eyebrow" }, children: ["Opaque worker surface"] },
      { type: "element", key: "harness-title", tag: "h1", children: ["Plugin isolation lab"] },
      { type: "element", key: "harness-status", tag: "p", attributes: { id: "plugin-status", class: "status", role: "status" }, children: [state.status] },
      {
        type: "element",
        key: "harness-actions",
        tag: "div",
        attributes: { class: "button-row" },
        children: [
          button("Call host", "call-host"),
          button("Read stream", "read-stream"),
          button("Dangerous action", "dangerous-action"),
        ],
      },
      { type: "element", key: "security-title", tag: "h2", children: ["Worker security probe"] },
      {
        type: "element",
        key: "security-probe",
        tag: "pre",
        attributes: { id: "security-probe", "aria-label": "Worker security probe" },
        children: [JSON.stringify(state.security, null, 2)],
      },
      { type: "element", key: "result-title", tag: "h2", children: ["Latest result"] },
      {
        type: "element",
        key: "plugin-result",
        tag: "pre",
        attributes: { id: "plugin-result", "aria-label": "Latest result" },
        children: [state.result],
      },
    ],
  });
}
