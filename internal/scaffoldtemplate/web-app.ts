import { PluginBridgeClient } from "@floegence/redevplugin-ui/plugin";

const bridge = new PluginBridgeClient();
bridge.onContext((context) => {
  const root = document.documentElement;
  root.classList.toggle("dark", context.appearance.color_scheme === "dark");
  root.classList.toggle("light", context.appearance.color_scheme === "light");
  root.style.colorScheme = context.appearance.color_scheme;
  const colors = { canvas: "background", surface: "card", surface_elevated: "popover", text: "foreground", text_muted: "muted-foreground", border: "border", accent: "primary", accent_text: "primary-foreground", success: "success", warning: "warning", danger: "error", focus: "ring" } as const;
  for (const [name, token] of Object.entries(colors)) {
    root.style.setProperty(`--${token}`, context.appearance.colors[name as keyof typeof colors]);
  }
  root.lang = context.locale.language_tag;
  root.dir = context.locale.direction;
});
const root = document.createElement("main");
root.className = "plugin-surface";
root.innerHTML = `<h1></h1>
<p class="intro">Build your application with ordinary Web code.</p>
<form class="echo-form"><label for="message">Message</label>
<input data-floe-surface="inset" id="message" name="message" maxlength="4096" autocomplete="off" value="Hello from your application">
<button class="primary" type="submit">Preview</button></form>
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
void bridge.ready().then(() => { if (!disposed) status.textContent = "Ready"; }).catch((error: unknown) => {
  if (disposed) return;
  status.classList.add("error");
  status.textContent = error instanceof Error ? error.message : "Application connection unavailable";
});
