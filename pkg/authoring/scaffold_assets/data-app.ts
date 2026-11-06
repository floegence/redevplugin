import { PluginBridgeClient, pluginKV, PluginResourceError } from "@floegence/redevplugin-ui/plugin";

const bridge = new PluginBridgeClient();
const notes = pluginKV<{ message: string }>("documents");
const root = document.createElement("main");
root.className = "plugin-surface";
root.innerHTML = `<h1></h1>
<p class="intro">Your document stays available across windows.</p>
<form class="echo-form"><label for="message">Document</label>
<textarea id="message" rows="8" maxlength="24000" data-floe-surface="inset"></textarea>
<div class="actions"><button class="primary" type="submit" disabled>Save</button> <button type="button" id="undo" disabled>Undo last action</button> <button type="button" id="reload" disabled>Reload saved version</button></div></form>
<p class="status" role="status" aria-live="polite">Connecting...</p>`;
root.querySelector("h1")!.textContent = "__REDEVPLUGIN_DISPLAY_NAME__";
document.body.replaceChildren(root);
const editor = root.querySelector("textarea")!;
const save = root.querySelector<HTMLButtonElement>("button[type=submit]")!;
const reload = root.querySelector<HTMLButtonElement>("#reload")!;
const undo = root.querySelector<HTMLButtonElement>("#undo")!;
const status = root.querySelector(".status")!;
const lifetime = new AbortController();
let etag = "";
let dirty = false;
let pending = false;
let reloadConfirmed = false;
let uncertain = false;
let watching = false;
let revision = 0;
let beforeAction: string | undefined;
function controls() { save.disabled = pending || !dirty || uncertain || lifetime.signal.aborted; reload.disabled = pending || lifetime.signal.aborted; undo.disabled = pending || beforeAction === undefined || lifetime.signal.aborted; }
function failure(error: unknown) {
  if (lifetime.signal.aborted) return;
  status.classList.add("error");
  if (error instanceof PluginResourceError && error.code === "CONFLICT") status.textContent = "Another window saved a newer version. Your changes are kept here. Reload when you are ready to replace them.";
  else if (error instanceof PluginResourceError && error.mutationOutcome === "unknown") { uncertain = true; status.textContent = "The save result is unknown. Your changes are kept here. Reload the saved version before saving again."; }
  else status.textContent = error instanceof Error ? error.message : "Document unavailable";
}
async function load() {
  pending = true; controls();
  try {
    const current = await notes.read("draft", { signal: lifetime.signal });
    if (lifetime.signal.aborted) return;
    editor.value = current?.value.message ?? ""; etag = current?.etag ?? ""; dirty = false; uncertain = false; revision++; beforeAction = undefined;
    status.classList.remove("error"); status.textContent = "Ready";
  } catch (error) { failure(error); } finally { pending = false; controls(); }
}
editor.addEventListener("input", () => { revision++; beforeAction = undefined; dirty = true; reloadConfirmed = false; reload.textContent = "Reload saved version"; controls(); });
undo.addEventListener("click", () => { if (undo.disabled || beforeAction === undefined) return; editor.value = beforeAction; beforeAction = undefined; revision++; dirty = true; status.textContent = "Action undone. Save when ready."; controls(); });
reload.addEventListener("click", () => {
  if (dirty && !reloadConfirmed) { reloadConfirmed = true; reload.textContent = "Confirm reload — replace unsaved changes"; return; }
  reloadConfirmed = false; reload.textContent = "Reload saved version";
  void load();
});
root.querySelector("form")!.addEventListener("submit", event => {
  event.preventDefault();
  if (save.disabled) return;
  const message = editor.value;
  pending = true; controls(); status.textContent = "Saving...";
  void notes.put("draft", { message }, { expectedETag: etag, signal: lifetime.signal }).then(saved => {
    if (lifetime.signal.aborted) return;
    etag = saved.etag; dirty = editor.value !== message; status.classList.remove("error"); status.textContent = dirty ? "Saved. New edits are not saved yet." : "Saved";
  }).catch(failure).finally(() => { pending = false; controls(); });
});
bridge.onContext(context => {
  document.documentElement.classList.toggle("dark", context.appearance.color_scheme === "dark");
  document.documentElement.classList.toggle("light", context.appearance.color_scheme === "light");
  document.documentElement.style.colorScheme = context.appearance.color_scheme;
  const colors = { canvas: "background", surface: "card", surface_elevated: "popover", text: "foreground", text_muted: "muted-foreground", border: "border", accent: "primary", accent_text: "primary-foreground", success: "success", warning: "warning", danger: "error", focus: "ring" } as const;
  for (const [name, token] of Object.entries(colors)) {
    document.documentElement.style.setProperty(`--${token}`, context.appearance.colors[name as keyof typeof colors]);
  }
  document.documentElement.lang = context.locale.language_tag;
  document.documentElement.dir = context.locale.direction;
});
bridge.onLifecycle(event => { if (event.type === "dispose") { lifetime.abort(); controls(); } });
bridge.onBeforeClose(() => !dirty && !pending && !uncertain);
async function watch() {
  if (watching) return;
  watching = true;
  try {
    for await (const change of notes.watch("draft", { cursor: etag, signal: lifetime.signal })) {
      if (change.cursor === etag) continue;
      if (dirty || pending || uncertain) {
        status.textContent = "A newer saved version is available. Your unsaved changes are kept here.";
        continue;
      }
      editor.value = change.value?.message ?? ""; etag = change.cursor; revision++; beforeAction = undefined; controls();
      status.textContent = "Updated from another window";
    }
  } catch (error) { failure(error); }
}
void Promise.all([
  bridge.registerMethod("application.read", (_params, { signal }) => { signal.throwIfAborted(); return { message: editor.value, revision }; }),
  bridge.registerMethod("document.replace", (params, { signal }) => {
    signal.throwIfAborted();
    if (pending || uncertain || params.expected_revision !== revision) return { applied: false, revision };
    if (typeof params.message !== "string" || params.message.length > 24000) throw new Error("Invalid document text");
    beforeAction = editor.value; editor.value = params.message; revision++; dirty = true;
    status.textContent = "Action applied to your draft. Review, undo, or save."; controls();
    return { applied: true, revision };
  }),
]).then(async () => { await load(); void watch(); }).catch(failure);
