import { PluginBridgeClient, type PluginUIVNode } from "../../packages/redevplugin-ui/src/plugin.js";

const bridge = new PluginBridgeClient({ timeoutMs: 30_000 });
const state = {
  status: "Starting isolated worker...",
  result: "Waiting for the trusted parent.",
  busy: false,
};

bridge.onAction("invoke-worker", () => void invoke("worker.echo", { message: "Hello from the generated plugin" }, "Backend responded"));
bridge.onAction("invoke-broker", () => void invoke("worker.brokerDemo", { note: "Generated plugin storage and network sample" }, "Brokered backend responded"));

void initialize();

async function initialize(): Promise<void> {
  await bridge.ready();
  state.status = "Ready";
  await render();
}

async function invoke(method: string, params: Record<string, unknown>, complete: string): Promise<void> {
  if (state.busy) return;
  state.busy = true;
  state.status = `Calling ${method}...`;
  await render();
  try {
    const response = await bridge.call(method, params);
    state.result = JSON.stringify({ method, response, token_leak_check: tokenLeakCheck(response) }, null, 2);
    state.status = complete;
  } catch (error) {
    const failure = error as Error & { errorCode?: string };
    state.result = JSON.stringify({ method, error: failure.message, error_code: failure.errorCode }, null, 2);
    state.status = "Backend call failed";
  } finally {
    state.busy = false;
    await render();
  }
}

function tokenLeakCheck(value: unknown): Record<string, boolean> {
  const raw = JSON.stringify(value ?? {});
  return {
    gateway_credential_visible: raw.includes(["gateway", "token"].join("_")),
    storage_credential_visible: raw.includes(["handle", "grant", "token"].join("_")),
    network_credential_visible: raw.includes(["connection", "grant", "token"].join("_")),
  };
}

function button(label: string, action: string): PluginUIVNode {
  return {
    type: "element",
    tag: "button",
    attributes: { type: "button", disabled: state.busy, "data-redevplugin-action": action },
    children: [label],
  };
}

function render(): Promise<void> {
  return bridge.render({
    type: "element",
    tag: "main",
    attributes: { class: "plugin-surface" },
    children: [
      { type: "element", tag: "p", attributes: { class: "eyebrow" }, children: ["Opaque plugin surface"] },
      { type: "element", tag: "h1", children: ["Generated Plugin"] },
      { type: "element", tag: "p", attributes: { id: "status", class: "status", role: "status" }, children: [state.status] },
      {
        type: "element",
        tag: "div",
        attributes: { class: "button-row" },
        children: [
          button("Invoke backend", "invoke-worker"),
          button("Storage + network", "invoke-broker"),
        ],
      },
      { type: "element", tag: "pre", attributes: { id: "result", "aria-label": "Latest result" }, children: [state.result] },
    ],
  });
}
