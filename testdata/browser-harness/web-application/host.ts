import { PluginPlatformClient, PluginSurfaceSlot } from "../../../packages/redevplugin-ui/src/trusted-parent.js";
const response = await fetch("/fixture");
const fixture = await response.json();
const mode = new URL(location.href).searchParams.get("mode");
const slots = [0, 1].map(() => PluginSurfaceSlot.create({ stage: document.createElement("section") }));
const client = new PluginPlatformClient();
const state = { ready: false, error: "", interactions: [] as string[], prepared: [] as string[], targets: [] as string[], released: [] as string[] };
Object.assign(globalThis, { testState: state, testSlots: slots });
for (const slot of slots) {
  document.body.append(slot.element);
  slot.element.style.cssText = "display:block;width:500px;height:400px";
  if (mode === "hidden") slot.element.style.display = "none";
  if (mode === "zero-size") slot.element.style.cssText = "width:0;height:0;overflow:hidden";
  if (mode === "offscreen") slot.element.style.transform = "translateY(5000px)";
}
try {
  for (const slot of slots) await client.openSurfaceInSlot(slot, {
    plugin_instance_id: fixture.plugin_instance_id, surface_id: mode === "plain" ? "plain.view" : "http.view", expected_management_revision: fixture.management_revision,
  }, { prepareWebOrigin: async ({ signal, ...route }) => {
    const response = await fetch("/fixture/routes", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(route), signal });
    if (!response.ok) throw new Error("Application route preparation failed");
    state.prepared.push(route.origin); state.targets.push(route.surfaceInstanceId);
    const release = () => { void fetch("/fixture/routes", { method: "DELETE", headers: { "Content-Type": "application/json" }, body: JSON.stringify(route) })
      .then(response => { if (response.ok) state.released.push(route.origin); }).catch(() => undefined); };
    signal.addEventListener("abort", release, { once: true });
    if (signal.aborted) release();
  }, confirmFileAccess: async review => review.name === "selected.txt" && review.writable, onInteraction: event => state.interactions.push(event.kind), onError: error => { state.error = error.message; } });
  state.ready = true;
} catch (error) { state.error = String(error); }

Object.assign(globalThis, { invokeDocument: async (index: number | undefined, method: string, params: Record<string, unknown> = {}) => client.invokeIntent({ plugin_instance_id: fixture.plugin_instance_id, surface_instance_id: index === undefined ? undefined : state.targets[index], intent_id: method, params }) });
