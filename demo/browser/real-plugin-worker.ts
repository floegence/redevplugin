import {
  PluginBridgeClient,
  type PluginMethodResult,
  type PluginStreamEvent,
  type PluginUIVNode,
} from "../../packages/redevplugin-ui/src/plugin.js";
import { runWorkerSecurityProbe, type WorkerSecurityProbe } from "./worker-security-probe.js";

type ScheduleRow = {
  title: string;
  starts_at: string;
  location: string;
  source: string;
  database: string;
};

const bridge = new PluginBridgeClient({ timeoutMs: 30_000 });
const state = {
  status: "Starting isolated worker...",
  result: "Waiting for the trusted parent.",
  scheduleRows: [] as ScheduleRow[],
  busy: false,
  security: {} as WorkerSecurityProbe,
};

for (const [action, handler] of Object.entries({
  "invoke-worker": invokeWorker,
  "invoke-broker": invokeBroker,
  "invoke-schedule": invokeSchedule,
  "invoke-network-matrix": invokeNetworkMatrix,
  "invoke-stream": invokeStream,
  "invoke-danger": invokeDangerous,
})) {
  bridge.onAction(action, () => void handler());
}

void initialize();

async function initialize(): Promise<void> {
  state.security = await runWorkerSecurityProbe();
  await bridge.ready();
  state.status = "Ready";
  await render();
}

async function invokeStream(): Promise<void> {
  await runAction("Opening runtime stream...", "Runtime stream received", async () => {
    const response = await bridge.call<PluginMethodResult>("worker.httpStream");
    if (!response.stream_handle) throw new Error("runtime response omitted stream_handle");
    const events = await readStreamToEnd(response.stream_handle);
    return {
      method: "worker.httpStream",
      events,
      text: events.map((event) => decodePluginStreamText(event)).join(""),
      parent_stream_credential_visible: JSON.stringify(response).includes(["stream", "ticket"].join("_")),
      token_leak_check: tokenLeakCheck(response),
    };
  });
}

async function readStreamToEnd(streamHandle: string): Promise<PluginStreamEvent[]> {
  const events: PluginStreamEvent[] = [];
  while (true) {
    const batch = await bridge.readStream(streamHandle);
    events.push(...batch.events);
    if (batch.done) return events;
    if (batch.events.length === 0 && batch.retry_after_ms > 0) {
      await new Promise((resolve) => setTimeout(resolve, batch.retry_after_ms));
    }
  }
}

async function invokeWorker(): Promise<void> {
  await runAction("Calling worker.echo...", "Backend responded", async () => {
    const response = await bridge.call("worker.echo", { message: "Hello from real runtime demo" });
    return { method: "worker.echo", response, token_leak_check: tokenLeakCheck(response) };
  });
}

async function invokeBroker(): Promise<void> {
  await runAction("Calling worker.brokerDemo...", "Brokered backend responded", async () => {
    const response = await bridge.call("worker.brokerDemo", { note: "Hello from the isolated plugin worker" });
    return {
      method: "worker.brokerDemo",
      response,
      parsed_network_body: parseNetworkBody(response),
      token_leak_check: tokenLeakCheck(response),
    };
  });
}

async function invokeSchedule(): Promise<void> {
  await runAction("Planning schedule...", "Schedule saved", async () => {
    const response = await bridge.call("worker.schedulePlan", {
      title: "Design plugin rollout",
      starts_at: "2026-07-03T09:30:00+08:00",
      location: "Focus Room A",
    });
    state.scheduleRows = parseScheduleRows(response);
    return {
      method: "worker.schedulePlan",
      response,
      parsed_schedule_rows: state.scheduleRows,
      token_leak_check: tokenLeakCheck(response),
    };
  });
}

async function invokeNetworkMatrix(): Promise<void> {
  await runAction("Calling network matrix...", "Network matrix completed", async () => {
    const methods = [
      ["http", "worker.networkHTTP"],
      ["websocket", "worker.networkWebSocket"],
      ["tcp", "worker.networkTCP"],
      ["udp", "worker.networkUDP"],
    ] as const;
    const results: Record<string, unknown> = {};
    for (const [transport, method] of methods) {
      const response = await bridge.call(method);
      results[transport] = {
        method,
        response,
        parsed_body: parseNetworkBody(response),
        parsed_payload: parseNetworkPayload(response),
      };
    }
    return { method: "network.matrix", results, token_leak_check: tokenLeakCheck(results) };
  });
}

async function invokeDangerous(): Promise<void> {
  await runAction("Waiting for confirmation...", "Dangerous action confirmed", async () => {
    const response = await bridge.call("danger.run", { target: "demo-database" });
    return { method: "danger.run", response, token_leak_check: tokenLeakCheck(response) };
  }, "Dangerous action blocked");
}

async function runAction(
  starting: string,
  complete: string,
  action: () => Promise<unknown>,
  failed = "Backend call failed",
): Promise<void> {
  if (state.busy) return;
  state.busy = true;
  state.status = starting;
  await render();
  try {
    state.result = JSON.stringify(await action(), null, 2);
    state.status = complete;
  } catch (error) {
    const failure = error as Error & { errorCode?: string };
    state.result = JSON.stringify({ error: failure.message, error_code: failure.errorCode }, null, 2);
    state.status = failed;
  } finally {
    state.busy = false;
    await render();
  }
}

function parseNetworkBody(value: unknown): unknown {
  const record = value as { data?: { network_execute?: { body_base64?: string } }; network_execute?: { body_base64?: string } };
  const encoded = record?.data?.network_execute?.body_base64 ?? record?.network_execute?.body_base64;
  if (!encoded) return null;
  try {
    return JSON.parse(atob(encoded));
  } catch (error) {
    return { parse_error: String(error) };
  }
}

function parseNetworkPayload(value: unknown): unknown {
  const record = value as { data?: { network_execute?: { payload_base64?: string } }; network_execute?: { payload_base64?: string } };
  const encoded = record?.data?.network_execute?.payload_base64 ?? record?.network_execute?.payload_base64;
  if (!encoded) return null;
  try {
    return atob(encoded);
  } catch (error) {
    return `parse_error: ${String(error)}`;
  }
}

function parseScheduleRows(value: unknown): ScheduleRow[] {
  const record = value as { data?: { storage_sqlite?: unknown }; storage_sqlite?: unknown };
  const sqlite = (record?.data?.storage_sqlite ?? record?.storage_sqlite) as {
    rows?: Array<Array<Record<string, unknown>>>;
    database?: string;
  } | undefined;
  return (sqlite?.rows ?? []).map((row) => ({
    title: sqliteValueText(row?.[0]),
    starts_at: sqliteValueText(row?.[1]),
    location: sqliteValueText(row?.[2]),
    source: sqliteValueText(row?.[3]),
    database: sqlite?.database ?? "plugin.sqlite",
  })).filter((item) => item.title.length > 0);
}

function sqliteValueText(value: Record<string, unknown> | undefined): string {
  if (!value) return "";
  if (typeof value.text === "string") return value.text;
  if (typeof value.int === "number") return String(value.int);
  if (typeof value.float === "number") return String(value.float);
  return value.null ? "" : JSON.stringify(value);
}

function tokenLeakCheck(value: unknown): Record<string, boolean> {
  const serialized = JSON.stringify(value);
  return {
    parent_asset_credential_visible: false,
    gateway_credential_visible: serialized.includes(["plugin", "gateway", "token"].join("_")) || serialized.includes(["gateway", "token"].join("_")),
    confirmation_credential_visible: serialized.includes(["confirmation", "token"].join("_")) || serialized.includes(["confirmation", "secret"].join("_")),
    storage_credential_visible: serialized.includes(["storage", "handle", "grant", "token"].join("_")) || serialized.includes(["handle", "grant", "token"].join("_")),
    network_credential_visible: serialized.includes(["connection", "grant", "token"].join("_")) || serialized.includes(["network", "grant", "token"].join("_")),
  };
}

function decodePluginStreamText(event: { data?: string }): string {
  if (!event.data) return "";
  const binary = atob(event.data);
  return new TextDecoder().decode(Uint8Array.from(binary, (character) => character.charCodeAt(0)));
}

function button(label: string, action: string): PluginUIVNode {
  return {
    type: "element",
    tag: "button",
    attributes: { type: "button", disabled: state.busy, "data-redevplugin-action": action },
    children: [label],
  };
}

function scheduleList(): PluginUIVNode {
  return {
    type: "element",
    tag: "ul",
    attributes: { id: "schedule-list", class: "schedule-list", "aria-label": "Persisted schedule" },
    children: state.scheduleRows.map((item) => ({
      type: "element",
      tag: "li",
      children: [
        { type: "element", tag: "strong", children: [item.title] },
        { type: "element", tag: "span", children: [`${item.starts_at} - ${item.location} - ${item.source}`] },
      ],
    })),
  };
}

function render(): Promise<void> {
  const scheduleMeta = state.scheduleRows.length > 0
    ? `Persisted ${state.scheduleRows.length} item in ${state.scheduleRows[0].database}`
    : "No persisted schedule yet";
  return bridge.render({
    type: "element",
    tag: "main",
    attributes: { class: "plugin-surface" },
    children: [
      { type: "element", tag: "p", attributes: { class: "eyebrow" }, children: ["Opaque plugin surface"] },
      { type: "element", tag: "h1", children: ["Real Runtime Demo Plugin"] },
      {
        type: "element",
        tag: "section",
        attributes: { class: "planner-panel", "aria-label": "Schedule planner" },
        children: [
          { type: "element", tag: "h2", children: ["Today at a glance"] },
          { type: "element", tag: "p", attributes: { id: "schedule-meta", class: "status" }, children: [scheduleMeta] },
          button("Plan schedule", "invoke-schedule"),
          scheduleList(),
        ],
      },
      { type: "element", tag: "p", attributes: { id: "status", class: "status", role: "status" }, children: [state.status] },
      {
        type: "element",
        tag: "div",
        attributes: { class: "button-row" },
        children: [
          button("Invoke backend", "invoke-worker"),
          button("Storage + network", "invoke-broker"),
          button("Network matrix", "invoke-network-matrix"),
          button("Read stream", "invoke-stream"),
          button("Dangerous action", "invoke-danger"),
        ],
      },
      { type: "element", tag: "h2", children: ["Worker security probe"] },
      {
        type: "element",
        tag: "pre",
        attributes: { id: "security-probe", "aria-label": "Worker security probe" },
        children: [JSON.stringify(state.security, null, 2)],
      },
      { type: "element", tag: "pre", attributes: { id: "result", "aria-label": "Latest result" }, children: [state.result] },
    ],
  });
}
