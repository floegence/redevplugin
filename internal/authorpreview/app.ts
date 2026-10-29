import { PluginPlatformClient, PluginSurfaceSlot, createPluginSurfaceScope, createReDevPluginSurfaceTransport, getPluginSurfaceActionState, type FetchLike, type PluginCatalogRecord, type PluginConfirmationIntent } from "../../packages/redevplugin-ui/src/trusted-parent.js";

function element<T extends HTMLElement>(id: string): T { const value = document.getElementById(id); if (!value) throw new Error("Missing preview element: " + id); return value as T; }
const status = element("status"), error = element("error"), output = element("output"), permissions = element("permissions");
const surfaces = element<HTMLSelectElement>("surfaces"), reload = element<HTMLButtonElement>("reload");
const scope = createPluginSurfaceScope();
const slot = PluginSurfaceSlot.create({ stage: element("stage") });
let csrf = "", generation = 0, record: PluginCatalogRecord | undefined, opening = false, stopped = false;
let buildError = "", surfaceError = "";
const authenticatedFetch: FetchLike = (input, init) => fetch(input, { ...init, headers: { ...init.headers, "X-ReDevPlugin-CSRF": csrf } });
const client = new PluginPlatformClient({ fetch: authenticatedFetch, surfaceScope: scope, surfaceTransport: createReDevPluginSurfaceTransport({ fetch: authenticatedFetch }) });
type State = { restart_required: boolean; generation: number; building: boolean; error: string; output: string; plugin_instance_id: string; csrf: string; mode: string };

reload.onclick = () => { void refreshCatalog(true).catch(showError); };
surfaces.onchange = () => { void openSelected().catch(showError); };
addEventListener("beforeunload", () => { stopped = true; void slot.dispose(); });
void initialize().catch(showError);

async function initialize(): Promise<void> {
  const token = location.hash.slice(1); history.replaceState(null, "", location.pathname);
  if (token) { const response = await fetch("/dev/session", { method: "POST", body: token }); if (!response.ok) throw new Error("Developer session was rejected. Open the preview URL printed by the CLI."); }
  await poll();
}
function renderError(): void { error.textContent = [buildError, surfaceError].filter(Boolean).join("\n\n"); }
function showError(value: unknown): void { surfaceError = value instanceof Error ? value.message : String(value); renderError(); }
async function poll(): Promise<void> {
  if (stopped) return;
  try {
    const response = await fetch("/dev/status"); if (!response.ok) throw new Error("Developer session expired. Open the current CLI preview URL.");
    const state = await response.json() as State; csrf = state.csrf;
    status.textContent = state.restart_required ? "Preview paused. Restart the command to reconcile package state." : state.building ? "Building… Your current preview remains available." : state.error ? "Build failed. Showing the last valid preview." : "Ready · real runtime";
    output.textContent = state.output; buildError = state.error; renderError();
    if (state.restart_required) { await slot.close(); reload.disabled = true; surfaces.disabled = true; return; }
    if (state.generation > generation) { await refreshCatalog(true); generation = state.generation; }
  } catch (failure) { showError(failure); }
  if (!stopped) setTimeout(() => { void poll(); }, 500);
}
async function refreshCatalog(open: boolean): Promise<void> {
  const catalog = await client.catalog(); record = catalog.plugins[0]; if (!record) { await slot.close(); return; }
  const selected = surfaces.value; surfaces.replaceChildren();
  for (const surface of record.manifest.surfaces ?? []) { if (surface.kind !== "view") continue; const option = document.createElement("option"); option.value = surface.surface_id; const availability = getPluginSurfaceActionState(record, surface.surface_id); option.textContent = surface.label + (availability.can_open ? "" : " · " + availability.blocked_reason); surfaces.append(option); }
  if (Array.from(surfaces.options).some(option => option.value === selected)) surfaces.value = selected;
  await renderPermissions(record); if (open) await openSelected();
}
async function renderPermissions(current: PluginCatalogRecord): Promise<void> {
  const [requirements, grants] = await Promise.all([client.getPermissionRequirements({ plugin_instance_id: current.plugin_instance_id }), client.listPermissions({ plugin_instance_id: current.plugin_instance_id, active_only: true })]);
  permissions.replaceChildren();
  for (const permission of requirements.required_permissions) {
    const granted = grants.permissions.some(grant => grant.permission_id === permission && grant.effect === "grant");
    const button = document.createElement("button"); button.type = "button"; button.textContent = (granted ? "Revoke " : "Allow ") + permission;
    button.onclick = () => { void (async () => {
      button.disabled = true;
      const request = { plugin_instance_id: current.plugin_instance_id, permission_id: permission, expected_policy_revision: current.policy_revision, expected_management_revision: current.management_revision, expected_revoke_epoch: current.revoke_epoch };
      try { if (granted) await client.revokePermission({ ...request, reason: "developer-preview" }); else await client.grantPermission(request); await refreshCatalog(true); } finally { button.disabled = false; }
    })().catch(showError); };
    permissions.append(button);
  }
}
async function openSelected(): Promise<void> {
  if (!record || !surfaces.value || opening) return;
  const available = getPluginSurfaceActionState(record, surfaces.value);
  if (!available.can_open) { await slot.close(); showError("This surface requires attention: " + available.blocked_reason); return; }
  opening = true; reload.disabled = true; surfaces.disabled = true;
  surfaceError = ""; renderError();
  try {
    await client.openSurfaceInSlot(slot, { plugin_instance_id: record.plugin_instance_id, surface_id: surfaces.value, expected_management_revision: record.management_revision }, { confirm: confirmAction, onError: showError });
  } finally { opening = false; reload.disabled = false; surfaces.disabled = false; }
}

function confirmAction(intent: PluginConfirmationIntent): Promise<boolean> {
  const dialog = element<HTMLDialogElement>("confirmation");
  if (intent.signal.aborted || dialog.open) return Promise.resolve(false);
  const previous = document.activeElement;
  element("confirmation-method").textContent = intent.method;
  element("confirmation-plan").textContent = JSON.stringify(intent.plan ?? {}, null, 2);
  dialog.returnValue = "cancel";
  return new Promise(resolve => {
    const abort = (): void => { dialog.close("cancel"); };
    dialog.addEventListener("close", () => {
      intent.signal.removeEventListener("abort", abort);
      if (previous instanceof HTMLElement && previous.isConnected) previous.focus();
      resolve(!intent.signal.aborted && dialog.returnValue === "confirm");
    }, { once: true });
    intent.signal.addEventListener("abort", abort, { once: true });
    dialog.showModal();
  });
}
