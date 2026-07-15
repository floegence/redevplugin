import {
  PluginBridgeClient,
  type PluginMethodResult,
  type PluginUIActionEvent,
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

bridge.onAction("echo-message", (event) => void echoMessage(event));

void initialize();

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

function render(): Promise<void> {
  return bridge.render({
    type: "element",
    tag: "main",
    attributes: { class: "plugin-surface" },
    children: [
      { type: "element", tag: "p", attributes: { class: "eyebrow" }, children: ["Sandboxed plugin"] },
      { type: "element", tag: "h1", children: ["__REDEVPLUGIN_DISPLAY_NAME__"] },
      { type: "element", tag: "p", attributes: { class: "intro" }, children: ["A minimal editable plugin with a TypeScript surface and Rust WASM worker."] },
      {
        type: "element",
        tag: "form",
        attributes: { class: "echo-form", "data-redevplugin-action": "echo-message" },
        children: [
          { type: "element", tag: "label", attributes: { for: "message" }, children: ["Message"] },
          { type: "element", tag: "input", attributes: { id: "message", name: "message", value: state.message, maxlength: 4096, disabled: state.busy, autocomplete: "off" } },
          { type: "element", tag: "button", attributes: { type: "submit", disabled: state.busy }, children: [state.busy ? "Sending..." : "Send to worker"] },
        ],
      },
      { type: "element", tag: "p", attributes: { class: state.error ? "status error" : "status", role: "status" }, children: [state.status] },
      { type: "element", tag: "section", attributes: { class: "response", "aria-label": "Worker response" }, children: [
        { type: "element", tag: "span", children: ["Response"] },
        { type: "element", tag: "strong", children: [state.response] },
      ] },
    ],
  });
}
