import {
  PluginBridgeClient,
  PluginBridgeError,
  type PluginMethodResult,
  type PluginUIActionEvent,
  type PluginUIVNode,
} from "@floegence/redevplugin-ui/plugin";

type EchoResult = {
  backend: string;
  transport: string;
  method: string;
  worker_id: string;
  wasm_abi: string;
  message: string;
};

const bridge = new PluginBridgeClient({ timeoutMs: 20_000 });
const state = {
  message: "Hello from the generated plugin",
  response: "Your WASM worker response will appear here.",
  status: "Connecting...",
  busy: false,
  error: false,
};
let disposed = false;

bridge.onAction("echo-message", (event) => void echoMessage(event));
bridge.onLifecycle((event) => {
  if (event.type === "dispose") disposed = true;
});

void initialize().catch(reportUnhandledFailure);

async function initialize(): Promise<void> {
  await bridge.ready();
  state.status = "Ready";
  await render();
}

async function echoMessage(event: PluginUIActionEvent): Promise<void> {
  if (state.busy) return;
  const message = String(event.form_data?.message ?? "").trim();
  if (!message) {
    state.status = "Enter a message first";
    state.error = true;
    await render();
    return;
  }
  state.message = message;
  state.busy = true;
  state.error = false;
  state.status = "Calling the sandboxed worker...";
  await render();
  try {
    const response = await bridge.call<PluginMethodResult<EchoResult>>("worker.echo", { message });
    state.response = response.data.message;
    state.status = `Answered by ${response.data.worker_id}`;
  } catch (error) {
    state.response = error instanceof Error ? error.message : "The worker call failed.";
    state.status = "Worker unavailable";
    state.error = true;
  } finally {
    state.busy = false;
    await render();
  }
}

function text(key: string, value: string): PluginUIVNode {
  return { type: "text", key, text: value };
}

function render(): Promise<void> {
  if (disposed) return Promise.resolve();
  return bridge.render({
    type: "element",
    key: "plugin-root",
    tag: "main",
    attributes: { class: "plugin-surface" },
    children: [
      { type: "element", key: "plugin-eyebrow", tag: "p", attributes: { class: "eyebrow" }, children: [text("plugin-eyebrow-copy", "Sandboxed plugin")] },
      { type: "element", key: "plugin-title", tag: "h1", children: [text("plugin-title-copy", "__REDEVPLUGIN_DISPLAY_NAME__")] },
      { type: "element", key: "plugin-intro", tag: "p", attributes: { class: "intro" }, children: [text("plugin-intro-copy", "A minimal editable plugin with a TypeScript surface and Rust WASM worker.")] },
      {
        type: "element",
        key: "echo-form",
        tag: "form",
        attributes: { class: "echo-form", "data-redevplugin-action": "echo-message" },
        children: [
          { type: "element", key: "message-label", tag: "label", attributes: { for: "message" }, children: [text("message-label-copy", "Message")] },
          { type: "element", key: "message-input", tag: "input", attributes: { id: "message", name: "message", value: state.message, maxlength: 4096, disabled: state.busy, autocomplete: "off" } },
          { type: "element", key: "message-submit", tag: "button", attributes: { type: "submit", disabled: state.busy }, children: [text("message-submit-copy", state.busy ? "Sending..." : "Send to worker")] },
        ],
      },
      { type: "element", key: "plugin-status", tag: "p", attributes: { class: state.error ? "status error" : "status", role: "status" }, children: [text("plugin-status-copy", state.status)] },
      { type: "element", key: "worker-response", tag: "section", attributes: { class: "response", "aria-label": "Worker response" }, children: [
        { type: "element", key: "worker-response-label", tag: "span", children: [text("worker-response-label-copy", "Response")] },
        { type: "element", key: "worker-response-value", tag: "strong", children: [text("worker-response-value-copy", state.response)] },
      ] },
    ],
  });
}

function reportUnhandledFailure(error: unknown): void {
  if (disposed && error instanceof PluginBridgeError && error.errorCode === "PLUGIN_BRIDGE_DISPOSED") return;
  queueMicrotask(() => { throw error; });
}
