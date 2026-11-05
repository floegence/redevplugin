import { PluginPlatformClient, PluginSurfaceSlot, PluginBridgeError, PluginPlatformRequestError, pluginMutationOutcome, createPluginSurfaceScope, createReDevPluginSurfaceTransport, getPluginSurfaceActionState, type FetchLike, type PluginCatalogRecord, type PluginIntentInvokeRequest, type PluginConfirmationIntent } from "../../packages/redevplugin-ui/src/trusted-parent.js";

function element<T extends HTMLElement>(id: string): T { const value = document.getElementById(id); if (!value) throw new Error("Missing preview element: " + id); return value as T; }
const status = element("status"), error = element("error"), output = element("output"), permissions = element("permissions");
const surfaces = element<HTMLSelectElement>("surfaces"), reload = element<HTMLButtonElement>("reload");
const apply = element<HTMLButtonElement>("apply");
let applying = false, candidateSource = "";
let csrf = "", generation = 0, record: PluginCatalogRecord | undefined, opening = false, closing = false, stopped = false;
let buildError = "", surfaceError = "", activeSurface = "", activeSurfaceId = "";
let actionUncertain = false;
const scope = createPluginSurfaceScope();
const slot = PluginSurfaceSlot.create({ stage: element("stage"), onStateChange: state => {
  element("stage").setAttribute("aria-busy", String(state === "opening"));
  if (state !== "ready") { activeSurface = ""; activeSurfaceId = ""; delete element("stage").dataset.surfaceInstance; }
  element("surface-status").textContent = state === "ready" ? "Application connected" : state === "opening" ? "Opening application…" : "Preview closed. Reopen when ready.";
} });
const authenticatedFetch: FetchLike = (input, init) => fetch(input, { ...init, headers: { ...init.headers, "X-ReDevPlugin-CSRF": csrf } });
const client = new PluginPlatformClient({ fetch: authenticatedFetch, surfaceScope: scope, surfaceTransport: createReDevPluginSurfaceTransport({ fetch: authenticatedFetch }) });
type State = { candidate?: boolean; manual?: boolean; persistent?: boolean; source_hash?: string; package_hash?: string; stages?: {name: string; status: string; duration_ms: number}[]; restart_required: boolean; generation: number; building: boolean; error: string; output: string; plugin_instance_id: string; csrf: string; mode: string };

apply.onclick = () => { void (async () => {
  const reviewedSource = candidateSource;
  if (applying || !await confirmReview("Apply candidate update", {effect: "Open a fresh application frame. Save any unsaved drafts first."})) return;
  applying = true; apply.disabled = true;
  try { const response = await fetch("/dev/apply", {method: "POST", headers: {"X-ReDevPlugin-CSRF": csrf, "Content-Type": "application/json"}, body: JSON.stringify({source_hash:reviewedSource})}); if (!response.ok) throw new Error(await response.text()); } finally { applying = false; }
})().catch(showError); };
const reset = element<HTMLButtonElement>("reset");
reset.onclick = () => { void (async () => {
  if (reset.disabled) return;
  const reviewedGeneration = generation;
  if (!await confirmReview("Reset development data", {effect: "Uninstall the current preview, delete its development data and grants, then install a fresh instance."})) return;
  reset.disabled = true;
  const response = await fetch("/dev/reset",{method:"POST",headers:{"X-ReDevPlugin-CSRF":csrf,"Content-Type":"application/json"},body:JSON.stringify({generation:reviewedGeneration})});
  if (!response.ok) throw new Error(await response.text());
})().catch(showError).finally(() => { reset.disabled = false; }); };
reload.onclick = () => { void (async () => {
  if (activeSurface && !await requestClose()) return;
  await refreshCatalog(true);
})().catch(showError); };
element<HTMLButtonElement>("close-preview").onclick = () => { void requestClose().catch(showError); };
element<HTMLButtonElement>("refresh-state").onclick = () => { void (async () => {
  const selectedAction = element<HTMLSelectElement>("actions").value;
  const params = element<HTMLTextAreaElement>("action-params").value;
  await refreshCatalog(false);
  if (Array.from(element<HTMLSelectElement>("actions").options).some(option => option.value === selectedAction)) {
    element<HTMLSelectElement>("actions").value = selectedAction;
    element<HTMLTextAreaElement>("action-params").value = params;
  }
  actionUncertain = false;
  element<HTMLButtonElement>("action-run").disabled = !element<HTMLSelectElement>("actions").options.length;
})().catch(showError); };
surfaces.onchange = () => { void (async () => {
  const selected = surfaces.value;
  if (activeSurface && !await requestClose()) {
    if (record) {
      const current = record.manifest.surfaces.find(surface => surface.surface_id === activeSurfaceId);
      if (current) surfaces.value = current.surface_id;
    }
    return;
  }
  surfaces.value = selected;
  await openSelected();
})().catch(showError); };
addEventListener("beforeunload", () => { stopped = true; void slot.dispose(); });
void initialize().catch(showError);

async function requestClose(): Promise<boolean> {
  if (closing) return false;
  closing = true; reload.disabled = true; surfaces.disabled = true;
  element<HTMLButtonElement>("close-preview").disabled = true;
  try { return Boolean(await slot.requestClose()); }
  finally { closing = false; reload.disabled = false; surfaces.disabled = false; element<HTMLButtonElement>("close-preview").disabled = false; }
}
async function initialize(): Promise<void> {
  const token = location.hash.slice(1); history.replaceState(null, "", location.pathname);
  if (token) { const response = await fetch("/dev/session", { method: "POST", body: token }); if (!response.ok) throw new Error("Developer session was rejected. Open the preview URL printed by the CLI."); }
  await poll();
}
function renderError(): void { error.textContent = [buildError, surfaceError].filter(Boolean).join("\n\n"); }
function failureMessage(value: unknown): string {
  const message = value instanceof Error ? value.message : String(value);
  const code = value instanceof PluginBridgeError || value instanceof PluginPlatformRequestError ? value.errorCode : "";
  if (pluginMutationOutcome(value) === "unknown") return message + "\nThe result is unknown. Keep your input, refresh observations and inspect the application before deciding whether to run it again.";
  if (code === "PLUGIN_PERMISSION_DENIED") return message + "\nReview the permissions below, then reopen the preview after approval.";
  if (code === "PLUGIN_CONNECTION_UNAVAILABLE") return message + "\nOpen Resources and connections to review and approve the destination.";
  if (code === "PLUGIN_RUNTIME_UNAVAILABLE") return message + "\nPrepare the verified runtime and restart dev with the runtime evidence shown by runtime prepare.";
  if (code === "PLUGIN_SESSION_REVOKED") return message + "\nRestart dev and open the new preview URL to establish a new session.";
  if (code.endsWith("_REVISION_MISMATCH") || code.endsWith("_CONFLICT")) return message + "\nRefresh state and review the current version before submitting another change. Your input has been kept.";
  return message;
}
function showError(value: unknown): void { surfaceError = failureMessage(value); renderError(); }
async function poll(): Promise<void> {
  if (stopped) return;
  try {
    const response = await fetch("/dev/status"); if (!response.ok) throw new Error("Developer session expired. Open the current CLI preview URL.");
    const state = await response.json() as State; csrf = state.csrf;
    status.textContent = state.restart_required ? "Preview paused. Restart the command to reconcile package state." : state.building ? "Building… Your current preview remains available." : state.error ? "Build failed. Showing the last valid preview." : state.candidate ? "Update ready. Save drafts, then apply when ready." : state.mode === "web" ? "Ready · Web application" : "Ready · real runtime";
    candidateSource = state.source_hash ?? "";
    apply.hidden = !state.candidate; apply.disabled = applying || state.building || state.restart_required;
    element("data-mode").textContent = state.persistent ? "Persistent environment · application data survives a command restart. Sessions and surface authority are renewed each time." : "Temporary environment · stopping this command removes its data. Use --state with a dedicated directory to keep data between sessions.";
    element("build-identity").textContent = (state.manual ? "Manual updates" : "Automatic updates") + (state.package_hash ? " · package " + state.package_hash.slice(0, 12) : "");
    element("build-stages").replaceChildren(...(state.stages ?? []).map(stage => { const item = document.createElement("li"); item.textContent = stage.name + " · " + stage.status + " · " + stage.duration_ms + " ms"; return item; }));
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
  renderInspector(record);
  await renderPermissions(record); await renderConnections(record); if (open) await openSelected();
}
async function renderPermissions(current: PluginCatalogRecord): Promise<void> {
  const [requirements, grants] = await Promise.all([client.getPermissionRequirements({ plugin_instance_id: current.plugin_instance_id }), client.listPermissions({ plugin_instance_id: current.plugin_instance_id, active_only: true })]);
  permissions.replaceChildren();
  for (const permission of new Set([...(current.manifest.permissions ?? []), ...requirements.required_permissions])) {
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
  activeSurface = ""; delete element("stage").dataset.surfaceInstance;
  opening = true; reload.disabled = true; surfaces.disabled = true;
  surfaceError = ""; renderError();
  try {
    const opened = await client.openSurfaceInSlot(slot, { plugin_instance_id: record.plugin_instance_id, surface_id: surfaces.value, expected_management_revision: record.management_revision }, {
      confirm: confirmAction, onError: showError,
      confirmClose: ({ reason, signal }) => confirmReview("Close preview", { effect: reason === "unsaved" ? "Discard unsaved application changes." : "The application is not responding. Closing may discard unsaved changes." }, signal),
      onOpeningProgress: progress => {
        const labels = { preparing: "Preparing isolated application", connecting: "Connecting application", authorizing: "Authorizing application", initializing: "Waiting for application readiness" };
        element("surface-status").textContent = labels[progress.stage] + " · " + (progress.elapsedMs / 1000).toFixed(1) + " s";
      },
    });
    activeSurface = opened.surfaceInstanceId; activeSurfaceId = surfaces.value; element("stage").dataset.surfaceInstance = activeSurface;
  } finally { opening = false; reload.disabled = false; surfaces.disabled = false; }
}

function confirmReview(method: string, plan: unknown, signal = new AbortController().signal): Promise<boolean> {
  return confirmAction({method, plan, signal} as PluginConfirmationIntent);
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

function renderInspector(current: PluginCatalogRecord): void {
  const manifest = current.manifest;
  element("contract").textContent = JSON.stringify({ surfaces: manifest.surfaces, storage: manifest.storage, network: manifest.network_access, workers: manifest.workers }, null, 2);
  const actions = element<HTMLSelectElement>("actions"); actions.replaceChildren();
  for (const intent of manifest.intents ?? []) {
    const method = manifest.methods?.find(item => item.method === intent.method);
    if (!method || (method.effect !== "read" && method.route.kind !== "surface")) continue;
    const option = document.createElement("option"); option.value = intent.intent_id; option.textContent = intent.intent_id + " · " + method.effect; actions.append(option);
  }
  element("action-tools").hidden = !actions.options.length;
  element("resources").hidden = !hasDeclaredResources(manifest);
  const fields = element("action-fields"), json = element<HTMLTextAreaElement>("action-params");
  const renderFields = (): void => {
    fields.replaceChildren();
    const intent = manifest.intents?.find(item => item.intent_id === actions.value);
    const schema = intent?.payload_schema as {properties?: Record<string, {type?: string; default?: unknown; description?: string}>} | undefined;
    const values: Record<string, unknown> = {};
    for (const [key, property] of Object.entries(schema?.properties ?? {})) {
      if (!["string", "number", "integer", "boolean"].includes(property.type ?? "")) continue;
      const label = document.createElement("label"); label.textContent = key;
      const input = document.createElement("input"); input.type = property.type === "boolean" ? "checkbox" : property.type === "string" ? "text" : "number";
      if (property.type === "integer") input.step = "1";
      if (property.default !== undefined) { input.value = String(property.default); input.checked = property.default === true; values[key] = property.default; }
      input.title = property.description ?? key;
      input.oninput = () => { values[key] = input.type === "checkbox" ? input.checked : input.type === "number" ? Number(input.value) : input.value; json.value = JSON.stringify(values, null, 2); };
      label.append(input); fields.append(label);
    }
    json.value = JSON.stringify(values, null, 2);
  };
  actions.onchange = renderFields; renderFields();
  const button = element<HTMLButtonElement>("action-run"); button.disabled = actionUncertain || !actions.options.length;
  button.onclick = () => { void (async () => {
    button.disabled = true;
    try {
      const params: unknown = JSON.parse(element<HTMLTextAreaElement>("action-params").value);
      if (!params || typeof params !== "object" || Array.isArray(params)) throw new Error("Parameters must be a JSON object");
      const intent = current.manifest.intents?.find(item => item.intent_id === actions.value);
      const method = current.manifest.methods?.find(item => item.method === intent?.method);
      if (method?.route.kind === "surface" && !activeSurface) throw new Error("Open the target Surface before invoking its action");
      const request: PluginIntentInvokeRequest = { plugin_instance_id: current.plugin_instance_id, intent_id: actions.value, ...(method?.route.kind === "surface" ? { surface_instance_id: activeSurface } : {}), params: params as Record<string, never> };
      if (method?.effect !== "read" && method?.confirmation?.mode !== "none") {
        const prepared = await client.prepareIntentConfirmation(request);
        if (!await confirmReview(method?.method ?? actions.value, prepared.plan)) return;
        request.confirmation_id = prepared.confirmation_id;
      }
      const result = await client.invokeIntent(request);
      element("action-result").textContent = JSON.stringify(result, null, 2);
    } catch (error) { actionUncertain = pluginMutationOutcome(error) === "unknown"; element("action-result").textContent = failureMessage(error); }
    finally { button.disabled = actionUncertain || !actions.options.length; }
  })(); };
}

function hasDeclaredResources(manifest: PluginCatalogRecord["manifest"]): boolean {
  return Boolean(manifest.storage?.stores?.length || manifest.settings?.fields?.length || manifest.network_access?.connectors?.length || manifest.workers?.length || manifest.surfaces.some(surface => surface.web?.storage?.length || surface.web?.settings?.length || surface.web?.network?.length));
}

const observations = element<HTMLButtonElement>("observations-refresh");
observations.onclick = () => { void (async () => {
  if (!record) return;
  observations.disabled = true;
  try {
    const query = { plugin_instance_id: record.plugin_instance_id, limit: 25 };
    const [tasks, diagnostics] = await Promise.all([client.listExecutions(query), client.listDiagnosticEvents(query)]);
    element("observations-result").textContent = JSON.stringify({tasks, diagnostics}, null, 2);
    const list = element("execution-list"); list.replaceChildren();
    for (const task of tasks.executions) {
      const row = document.createElement("div"); row.className = "resource-card";
      const description = document.createElement("p"); description.textContent = task.execution_id + " · " + task.status;
      const inspect = document.createElement("button"); inspect.textContent = "Inspect events";
      inspect.onclick = () => { void client.listExecutionEvents(task.execution_id, {after_cursor: 0, limit: 100}).then(events => { element("observations-result").textContent = JSON.stringify(events, null, 2); }).catch(showError); };
      row.append(description, inspect);
      if (task.cancelable && task.status === "running") {
        const cancel = document.createElement("button"); cancel.textContent = "Cancel task";
        cancel.onclick = () => { void (async () => { if (!await confirmReview("Cancel task", {execution_id: task.execution_id})) return; cancel.disabled = true; try { const result = await client.cancelExecution(task.execution_id, "developer-preview"); description.textContent = task.execution_id + " · " + result.status; } finally { observations.click(); } })().catch(showError); }; row.append(cancel);
      }
      list.append(row);
    }
  } catch (error) { element("observations-result").textContent = error instanceof Error ? error.message : String(error); }
  finally { observations.disabled = false; }
})(); };

async function renderConnections(current: PluginCatalogRecord): Promise<void> {
  const container = element("connections"); container.replaceChildren();
  element("resource-contract").textContent = JSON.stringify({storage: current.manifest.storage, surfaces: current.manifest.surfaces.map(surface => ({surface_id: surface.surface_id, resources: surface.web}))}, null, 2);
  if (!current.manifest.network_access?.connectors?.length) return;
  const inventory = await client.listConnections({plugin_instance_id: current.plugin_instance_id});
  for (const declaration of current.manifest.network_access.connectors) {
    const connection = inventory.connections.find(item => item.connector_id === declaration.connector_id);
    const card = document.createElement("div"); card.className = "resource-card";
    const title = document.createElement("p"); title.textContent = declaration.connector_id + " · " + (connection?.status ?? "unconfigured"); card.append(title);
    if (declaration.configurable) {
      const label = document.createElement("label"); label.textContent = "Destination for " + declaration.connector_id;
      const input = document.createElement("input"); input.type = "url"; input.placeholder = declaration.transport === "websocket" ? "wss://events.example.com" : "https://api.example.com"; input.value = connection?.destination ?? ""; label.append(input); card.append(label);
      const privateLabel = document.createElement("label"); privateLabel.textContent = "Allow loopback destination on this computer";
      const privateInput = document.createElement("input"); privateInput.type = "checkbox"; privateInput.checked = Boolean(connection?.private_prefixes?.length); privateLabel.append(privateInput); card.append(privateLabel);
      const button = document.createElement("button"); button.textContent = "Review connection";
      button.onclick = () => { void (async () => {
        button.disabled = true;
        try {
          const methods = current.manifest.surfaces.flatMap(surface => surface.web?.network ?? []).filter(item => item.connector_id === declaration.connector_id).flatMap(item => item.http_methods ?? []);
          const privatePrefixes = privateInput.checked ? ["127.0.0.0/8", "::1/128"] : undefined;
          const result = await client.reviewConnection({private_prefixes: privatePrefixes,plugin_instance_id: current.plugin_instance_id, connector_id: declaration.connector_id, destination: input.value.trim(), expected_revision: connection?.revision ?? 0, ...(declaration.transport === "http" ? {http_methods: [...new Set(methods)]} : {})});
          const reference = {plugin_instance_id: current.plugin_instance_id, review_id: result.review.review_id};
          if (await confirmReview("Approve connection", result.review)) await client.approveConnection(reference);
          else await client.cancelConnectionReview(reference);
          await renderConnections(current);
        } catch (error) { showError(error); await renderConnections(current); }
        finally { button.disabled = false; }
      })().catch(showError); }; card.append(button);
    }
    if (connection?.status === "active") {
      const revoke = document.createElement("button"); revoke.textContent = "Revoke connection";
      revoke.onclick = () => { void (async () => { if (!await confirmReview("Revoke connection", {connector_id: declaration.connector_id, destination: connection.destination})) return; revoke.disabled = true; try { await client.revokeConnection({plugin_instance_id: current.plugin_instance_id, connector_id: declaration.connector_id, expected_revision: connection.revision}); } finally { await renderConnections(current); } })().catch(showError); }; card.append(revoke);
    }
    container.append(card);
  }
}
