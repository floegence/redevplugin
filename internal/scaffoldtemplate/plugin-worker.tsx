import {
  PluginBridgeClient,
  PluginBridgeError,
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

function render(): Promise<void> {
  if (disposed) return Promise.resolve();
  return bridge.render(
    <main key="plugin-root" className="plugin-surface">
      <p key="plugin-eyebrow" className="eyebrow">Sandboxed plugin</p>
      <h1 key="plugin-title">{"__REDEVPLUGIN_DISPLAY_NAME__"}</h1>
      <p key="plugin-intro" className="intro">A minimal editable plugin with a TypeScript surface and Rust WASM worker.</p>
      <form key="echo-form" className="echo-form" data-redevplugin-action="echo-message">
        <label key="message-label" htmlFor="message">Message</label>
        <input key="message-input" id="message" name="message" value={state.message} maxLength={4096} disabled={state.busy} autoComplete="off" />
        <button key="message-submit" type="submit" disabled={state.busy}>{state.busy ? "Sending..." : "Send to worker"}</button>
      </form>
      <p key="plugin-status" className={state.error ? "status error" : "status"} role="status">{state.status}</p>
      <section key="worker-response" className="response" aria-label="Worker response">
        <span key="worker-response-label">Response</span>
        <strong key="worker-response-value">{state.response}</strong>
      </section>
    </main>,
  );
}

function reportUnhandledFailure(error: unknown): void {
  if (disposed && error instanceof PluginBridgeError && error.errorCode === "PLUGIN_BRIDGE_DISPOSED") return;
  queueMicrotask(() => { throw error; });
}
