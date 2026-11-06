import { PluginBridgeClient, PluginResourceError, pluginFiles } from "@floegence/redevplugin-ui/plugin";

const bridge = new PluginBridgeClient(); const files = pluginFiles("imports");
const root = document.createElement("main"); root.className = "plugin-surface"; root.innerHTML = `<h1></h1><p class="intro">Import files into private plugin storage. Completed files remain available if you cancel.</p><label for="files">Choose files</label><input id="files" type="file" multiple><div class="actions"><button class="primary" id="start" disabled>Import and verify</button> <button id="cancel" disabled>Cancel</button></div><progress max="1" value="0" aria-label="Import progress"></progress><p class="status" role="status" aria-live="polite">Connecting…</p><ul aria-label="File results"></ul>`;
root.querySelector("h1")!.textContent = "__REDEVPLUGIN_DISPLAY_NAME__"; document.body.replaceChildren(root);
const input = root.querySelector<HTMLInputElement>("input")!; const start = root.querySelector<HTMLButtonElement>("#start")!; const cancel = root.querySelector<HTMLButtonElement>("#cancel")!;
const progress = root.querySelector("progress")!; const status = root.querySelector(".status")!; const results = root.querySelector("ul")!;
const lifetime = new AbortController(); let task: AbortController | undefined; let ready = false; let summary = "No imports yet";
function controls() { input.disabled = !!task; start.disabled = !ready || !!task || !input.files?.length || lifetime.signal.aborted; cancel.disabled = !task; }
input.onchange = controls; cancel.onclick = () => task?.abort();
start.onclick = () => { void (async () => {
  const selected = Array.from(input.files ?? []); if (!selected.length || task) return;
  task = new AbortController(); const signal = AbortSignal.any([task.signal, lifetime.signal]); controls(); results.replaceChildren(); progress.max = selected.length; progress.value = 0;
  const batch = crypto.randomUUID(); let completed = 0;
  try {
    for (const [index, file] of selected.entries()) {
      signal.throwIfAborted(); const row = document.createElement("li"); row.textContent = file.name + " · importing"; results.append(row);
      const path = batch + "/" + index + ".bin"; let committed = false;
      try {
        status.textContent = "Importing " + file.name; const written = await files.writeFrom(path, file, { signal }); committed = true;
        const stream = await files.readable(path, { signal }); const reader = stream.getReader(); let size = 0;
        try { while (true) { const chunk = await reader.read(); if (chunk.done) break; size += chunk.value.byteLength; } } finally { await reader.cancel(); reader.releaseLock(); }
        if (written !== file.size || size !== file.size) throw new Error("Verification size mismatch");
        completed++; progress.value = completed; row.textContent = file.name + " · saved and verified · " + size + " bytes · " + path;
      } catch (error) {
        row.textContent = file.name + (committed ? " · saved; verification interrupted" : error instanceof PluginResourceError && error.mutationOutcome === "unknown" ? " · save outcome unknown; inspect storage before retrying" : " · not saved");
        throw error;
      }
    }
    summary = completed + " files saved and verified"; status.textContent = summary;
  } catch (error) {
    summary = completed + " files verified. " + (signal.aborted ? "Canceled. Completed files are kept." : error instanceof Error ? error.message : "Import stopped"); status.textContent = summary;
  } finally { task = undefined; controls(); }
})(); };
bridge.onContext(context => { document.documentElement.classList.toggle("dark", context.appearance.color_scheme === "dark");
  document.documentElement.classList.toggle("light", context.appearance.color_scheme === "light");
  document.documentElement.style.colorScheme = context.appearance.color_scheme;
  const colors = { canvas: "background", surface: "card", surface_elevated: "popover", text: "foreground", text_muted: "muted-foreground", border: "border", accent: "primary", accent_text: "primary-foreground", success: "success", warning: "warning", danger: "error", focus: "ring" } as const;
  for (const [name, token] of Object.entries(colors)) {
    document.documentElement.style.setProperty(`--${token}`, context.appearance.colors[name as keyof typeof colors]);
  } document.documentElement.lang = context.locale.language_tag; document.documentElement.dir = context.locale.direction; });
bridge.onLifecycle(event => { if (event.type === "dispose") { lifetime.abort(); task?.abort(); controls(); } });
void bridge.registerMethod("application.read", () => ({ message: summary })).then(() => { ready = true; status.textContent = "Ready. Choose files to begin."; controls(); });
