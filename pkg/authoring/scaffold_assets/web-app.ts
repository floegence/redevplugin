import { PluginBridgeClient } from "@floegence/redevplugin-ui/plugin";

const bridge = new PluginBridgeClient();
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
<p class="intro">Build your application with ordinary Web code.</p>
<form class="echo-form"><label for="message">Message</label>
<input data-floe-surface="inset" id="message" name="message" maxlength="4096" autocomplete="off" value="Hello from your application">
<button data-floe-surface="raised" type="submit">Preview</button></form>
<p class="status" role="status">Connecting...</p>
<section class="response" aria-label="Preview"><span>Preview</span><strong>Your message will appear here.</strong></section>`;
root.querySelector("h1")!.textContent = "__REDEVPLUGIN_DISPLAY_NAME__";
document.body.replaceChildren(root);
const input = root.querySelector("input")!;
const status = root.querySelector(".status")!;
const response = root.querySelector(".response strong")!;
let disposed = false;
root.querySelector("form")!.addEventListener("submit", (event) => {
  event.preventDefault();
  if (!disposed) response.textContent = input.value;
});
bridge.onLifecycle((event) => {
  if (event.type === "dispose") { disposed = true; root.querySelector("button")!.disabled = true; }
});
void bridge.registerMethod("application.read", (_params, { signal }) => {
  signal.throwIfAborted();
  return { message: input.value };
}).then(() => { if (!disposed) status.textContent = "Ready"; }).catch((error: unknown) => {
  if (disposed) return;
  status.classList.add("error");
  status.textContent = error instanceof Error ? error.message : "Application connection unavailable";
});
