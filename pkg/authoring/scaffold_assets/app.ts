import { PluginBridgeClient, type PluginMethodResult } from "@floegence/redevplugin-ui/plugin";

type EchoResult = { worker_id: string; message: string };
const bridge = new PluginBridgeClient({ timeoutMs: 20_000 });
bridge.onContext((context) => {
  const root = document.documentElement;
  root.classList.toggle("dark", context.appearance.color_scheme === "dark");
  root.classList.toggle("light", context.appearance.color_scheme === "light");
  root.style.colorScheme = context.appearance.color_scheme;
  root.lang = context.locale.language_tag;
  root.dir = context.locale.direction;
});
const root = document.createElement("main");
root.className = "plugin-surface";
root.dataset.floeSurface = "raised";
root.innerHTML = `<p class="eyebrow">Your application</p><h1></h1>
<p class="intro">A regular Web application with a sandboxed Rust worker.</p>
<form class="echo-form"><label for="message">Message</label>
<input data-floe-surface="inset" id="message" name="message" maxlength="4096" autocomplete="off" value="Hello from the generated plugin">
<button data-floe-surface="raised" type="submit" disabled>Send to worker</button></form>
<p class="status" role="status">Connecting...</p>
<section class="response" aria-label="Worker response"><span>Response</span><strong>Your worker response will appear here.</strong></section>`;
root.querySelector("h1")!.textContent = "__REDEVPLUGIN_DISPLAY_NAME__";
document.body.replaceChildren(root);
const form = root.querySelector("form")!;
const input = root.querySelector("input")!;
const button = root.querySelector("button")!;
const status = root.querySelector(".status")!;
const response = root.querySelector(".response strong")!;
let busy = false;
let disposed = false;
bridge.onLifecycle((event) => { if (event.type === "dispose") { disposed = true; button.disabled = true; } });
form.addEventListener("submit", (event) => { event.preventDefault(); void echo(); });
void bridge.registerMethod("application.read", (_params, { signal }) => { signal.throwIfAborted(); return { message: input.value }; }).then(() => { if (!disposed) { status.textContent = "Ready"; button.disabled = false; } }).catch(reportError);

async function echo(): Promise<void> {
  if (busy || disposed) return;
  const message = input.value.trim();
  if (!message) { input.focus(); status.textContent = "Enter a message first"; return; }
  busy = true;
  button.disabled = true;
  status.textContent = "Sending...";
  status.classList.remove("error");
  try {
    const result = await bridge.call<PluginMethodResult<EchoResult>>("worker.echo", { message });
    if (disposed) return;
    response.textContent = result.data.message;
    status.textContent = `Answered by ${result.data.worker_id}`;
  } catch (error) { reportError(error); }
  finally { busy = false; button.disabled = disposed; }
}

function reportError(error: unknown): void {
  if (disposed) return;
  status.classList.add("error");
  status.textContent = error instanceof Error ? error.message : "The worker is unavailable. Try again.";
}
