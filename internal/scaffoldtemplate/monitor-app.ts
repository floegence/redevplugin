import { PluginBridgeClient, openPluginWebSocket, type PluginSocket } from "@floegence/redevplugin-ui/plugin";

const bridge = new PluginBridgeClient();
const root = document.createElement("main"); root.className = "plugin-surface"; root.innerHTML = `<h1></h1><p class="intro">Connect to your configured events service. Each message replaces the current snapshot.</p><div class="actions"><button class="primary" id="connect" disabled>Connect</button> <button id="disconnect" disabled>Disconnect</button></div><p class="status" role="status" aria-live="polite">Connecting to host…</p><pre aria-label="Current snapshot">No snapshot yet</pre>`;
root.querySelector("h1")!.textContent = "__REDEVPLUGIN_DISPLAY_NAME__"; document.body.replaceChildren(root);
const connect = root.querySelector<HTMLButtonElement>("#connect")!; const disconnect = root.querySelector<HTMLButtonElement>("#disconnect")!;
const status = root.querySelector(".status")!; const output = root.querySelector("pre")!;
const lifetime = new AbortController(); let connection: AbortController | undefined; let socket: PluginSocket | undefined; let snapshot = ""; let count = 0;
function stop() { connection?.abort(); socket?.close(); }
connect.onclick = () => { void (async () => {
  connect.disabled = true; disconnect.disabled = false; connection = new AbortController();
  const signal = AbortSignal.any([lifetime.signal, connection.signal]); status.textContent = "Opening configured connection…";
  try {
    socket = await openPluginWebSocket("events", "/", { signal });
    status.textContent = "Connected · waiting for a fresh snapshot";
    for await (const message of socket) {
      snapshot = typeof message === "string" ? message : new TextDecoder("utf-8", { fatal: true }).decode(message);
      count++; output.textContent = snapshot; status.textContent = "Live · snapshot " + count;
    }
    status.textContent = "Disconnected. Reconnect to receive a fresh snapshot.";
  } catch (error) {
    status.textContent = signal.aborted ? "Disconnected. Last snapshot retained." : (error instanceof Error ? error.message : "Connection unavailable") + ". Configure the events connection and grant network access, then reconnect.";
  } finally { socket?.close(); socket = undefined; disconnect.disabled = true; connect.disabled = lifetime.signal.aborted; }
})(); };
disconnect.onclick = stop;
bridge.onContext(context => { document.documentElement.classList.toggle("dark", context.appearance.color_scheme === "dark");
  document.documentElement.classList.toggle("light", context.appearance.color_scheme === "light");
  document.documentElement.style.colorScheme = context.appearance.color_scheme;
  const colors = { canvas: "background", surface: "card", surface_elevated: "popover", text: "foreground", text_muted: "muted-foreground", border: "border", accent: "primary", accent_text: "primary-foreground", success: "success", warning: "warning", danger: "error", focus: "ring" } as const;
  for (const [name, token] of Object.entries(colors)) {
    document.documentElement.style.setProperty(`--${token}`, context.appearance.colors[name as keyof typeof colors]);
  } document.documentElement.lang = context.locale.language_tag; document.documentElement.dir = context.locale.direction; });
bridge.onLifecycle(event => { if (event.type === "dispose") { lifetime.abort(); stop(); connect.disabled = true; disconnect.disabled = true; } });
void bridge.registerMethod("application.read", () => ({ message: snapshot })).then(() => { connect.disabled = false; status.textContent = "Ready. Configure the events connection in your host, then connect."; });
