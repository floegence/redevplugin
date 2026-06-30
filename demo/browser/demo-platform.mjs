const defaultDemoBootstrap = Object.freeze({
  pluginId: "dev.redevplugin.demo",
  pluginInstanceId: "plugini_demo_1",
  surfaceId: "demo.activity",
  surfaceInstanceId: "surface_demo_1",
  activeFingerprint: "sha256:demo",
  bridgeNonce: "bridge_nonce_demo",
  ownerSessionHash: "owner_session_demo",
  ownerUserHash: "owner_user_demo",
  sessionChannelIdHash: "session_channel_demo",
});

export const demoBootstrap = createDemoBootstrap();

export function createDemoBootstrap(overrides = {}) {
  return Object.freeze({
    ...defaultDemoBootstrap,
    ...Object.fromEntries(Object.entries(overrides).filter(([, value]) => value != null && value !== "")),
  });
}

export function createDemoPlatformFetch(options = {}) {
  const bootstrap = options.bootstrap ?? demoBootstrap;
  const calls = [];
  const persistence = createDemoPersistence(bootstrap, options.persistence);
  const networkFetch = options.networkFetch ?? (typeof globalThis.fetch === "function" ? globalThis.fetch.bind(globalThis) : null);
  const networkBaseURL = options.networkBaseURL ?? "";
  const state = createDefaultDemoState();
  applyPersistedState(state, persistence.load());

  function persistState() {
    persistence.save({
      gameBestScore: state.gameBestScore,
      gameLastRun: state.gameLastRun,
      gameSaves: state.gameSaves,
      gameSnapshots: state.gameSnapshots,
      scheduleItems: state.scheduleItems,
      scheduleJournal: state.scheduleJournal,
      scheduleRevision: state.scheduleRevision,
      weatherLocation: state.weatherLocation,
      weatherSavedLocations: state.weatherSavedLocations,
      weatherNetworkEvents: state.weatherNetworkEvents,
      hostSettings: state.hostSettings,
      settingsRevision: state.settingsRevision,
      settingsUpdatedAt: state.settingsUpdatedAt,
    });
  }

  Object.assign(state, {
    bridgeTokenIssued: false,
    confirmationToken: "",
    confirmedDeletes: 0,
    streamTickets: 0,
  });

  async function fetch(input, init) {
    const url = new URL(String(input), "http://demo.local");
    const method = String(init?.method ?? "GET").toUpperCase();
    const body = init?.body ? JSON.parse(String(init.body)) : {};
    calls.push({ path: url.pathname, body });
    options.onCall?.(url.pathname, body);

    if (url.pathname.endsWith("/settings/schema") && method === "GET") {
      return jsonResponse({
        ok: true,
        data: demoSettingsSchema(bootstrap.pluginInstanceId, state.settingsRevision),
      });
    }

    if (url.pathname.endsWith("/settings") && method === "GET") {
      return jsonResponse({
        ok: true,
        data: demoSettingsSnapshot(bootstrap.pluginInstanceId, state),
      });
    }

    if (url.pathname.endsWith("/settings") && method === "PATCH") {
      const values = isRecord(body.values) ? body.values : {};
      state.hostSettings = normalizeDemoSettings({ ...state.hostSettings, ...values });
      state.settingsRevision += 1;
      state.settingsUpdatedAt = new Date().toISOString();
      persistState();
      return jsonResponse({
        ok: true,
        data: demoSettingsSnapshot(bootstrap.pluginInstanceId, state),
      });
    }

    if (url.pathname.endsWith(`/surfaces/${bootstrap.surfaceInstanceId}/bridge-token`)) {
      state.bridgeTokenIssued = true;
      return jsonResponse({
        ok: true,
        data: {
          plugin_gateway_token: "gateway_token_parent_only_demo",
          plugin_gateway_token_id: "gateway_token_demo_1",
          issued_at: "2026-06-30T00:00:00Z",
          expires_at: "2026-06-30T00:05:00Z",
        },
      });
    }

    if (url.pathname.endsWith("/confirm")) {
      state.confirmationToken = `confirmation_token_${body.method ?? "unknown"}`;
      return jsonResponse({
        ok: true,
        data: {
          confirmation_token: state.confirmationToken,
          confirmation_token_id: "confirmation_demo_1",
          request_hash: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          expires_at: "2026-06-30T00:01:00Z",
        },
      });
    }

    if (url.pathname.endsWith("/rpc")) {
      if (!state.bridgeTokenIssued || body.plugin_gateway_token !== "gateway_token_parent_only_demo") {
        return jsonResponse({ ok: false, error_code: "PLUGIN_BRIDGE_HANDSHAKE_REQUIRED", error: "bridge token is missing" }, 403);
      }
      switch (body.method) {
        case "demo.echo":
          return jsonResponse({
            ok: true,
            data: {
              data: {
                echoed: body.params?.message ?? "hello",
                transport: "MessageChannel bridge",
                time: "2026-06-30T00:00:05Z",
              },
            },
          });
        case "worker.echo":
          return jsonResponse({
            ok: true,
            data: {
              data: {
                method: "worker.echo",
                echoed: body.params?.message ?? "hello from generated scaffold",
                backend: "generated wasm worker scaffold",
                transport: "MessageChannel bridge",
              },
            },
          });
        case "worker.brokerDemo":
          return jsonResponse({
            ok: true,
            data: {
              data: {
                method: "worker.brokerDemo",
                backend: "generated wasm worker scaffold",
                transport: "MessageChannel bridge",
                storage_file: {
                  ok: true,
                  handle_id: "storage:workspace",
                  method: "storage.files",
                  operation: "write",
                  store_id: "workspace",
                  path: "notes/generated-broker-demo.txt",
                  bytes_written: 51,
                  executor: "host storage broker",
                },
                storage_kv: {
                  ok: true,
                  handle_id: "storage:settings",
                  method: "storage.kv",
                  operation: "put",
                  store_id: "settings",
                  key: "demo/last_broker_run",
                  size_bytes: 35,
                  executor: "host storage broker",
                },
                network_execute: {
                  ok: true,
                  connector_id: "api",
                  transport: "http",
                  destination: "https://api.example.com",
                  method: "POST",
                  path: "/v1/worker",
                  response_status: 200,
                  executor: "host-network-executor",
                  body_base64: "Z2VuZXJhdGVkIGJyb2tlcmVkIGh0dHAgcmVzcG9uc2U=",
                },
              },
            },
          });
        case "demo.storage.list":
          return jsonResponse({
            ok: true,
            data: {
              data: {
                files: [
                  { path: "workspace/readme.md", size_bytes: 2048 },
                  { path: "workspace/cache/index.sqlite", size_bytes: 8192 },
                ],
              },
            },
          });
        case "demo.logs.tail":
          state.streamTickets += 1;
          return jsonResponse({
            ok: true,
            data: {
              data: {
                started: true,
                source: body.params?.source ?? "demo",
              },
              stream_id: "demo_stream_logs",
              stream_ticket: `demo_stream_ticket_${state.streamTickets}`,
              stream_ticket_id: `demo_stream_ticket_id_${state.streamTickets}`,
            },
          });
        case "demo.cache.delete":
          if (body.confirmation_token !== state.confirmationToken) {
            return jsonResponse({ ok: false, error_code: "PLUGIN_CONFIRMATION_REQUIRED", error: "confirmation required" }, 409);
          }
          state.confirmedDeletes += 1;
          return jsonResponse({
            ok: true,
            data: {
              data: {
                deleted: true,
                deleted_paths: ["workspace/cache/index.sqlite"],
                confirmed_deletes: state.confirmedDeletes,
              },
            },
          });
        case "game.score.save":
          state.gameSaves += 1;
          state.gameLastRun = normalizeGameRun(body.params);
          state.gameBestScore = Math.max(state.gameBestScore, state.gameLastRun.score);
          persistState();
          return jsonResponse({
            ok: true,
            data: {
              data: {
                saved: true,
                best_score: state.gameBestScore,
                last_run: state.gameLastRun,
                saves: state.gameSaves,
                achievements: gameAchievements(state.gameLastRun),
                leaderboard: gameLeaderboard(state),
                storage: "host-backed kv store",
              },
            },
          });
        case "game.state.get":
          return jsonResponse({
            ok: true,
            data: {
              data: {
                best_score: state.gameBestScore,
                last_run: state.gameLastRun,
                saves: state.gameSaves,
                achievements: state.gameLastRun ? gameAchievements(state.gameLastRun) : [],
                leaderboard: gameLeaderboard(state),
                snapshots: state.gameSnapshots,
                storage: "host-backed kv store",
              },
            },
          });
        case "game.snapshot.save": {
          const snapshot = normalizeGameSnapshot(body.params);
          state.gameSnapshots = [snapshot, ...state.gameSnapshots].slice(0, 5);
          persistState();
          return jsonResponse({
            ok: true,
            data: {
              data: {
                saved: true,
                snapshot,
                snapshots: state.gameSnapshots,
                storage: "host-backed kv store",
                storage_key: "game/snapshots",
              },
            },
          });
        }
        case "game.snapshot.load":
          return jsonResponse({
            ok: true,
            data: {
              data: {
                snapshot: state.gameSnapshots[0] ?? null,
                snapshots: state.gameSnapshots,
                storage: "host-backed kv store",
                storage_key: "game/snapshots",
              },
            },
          });
        case "schedule.items.list":
          return jsonResponse({
            ok: true,
            data: {
              data: {
                items: filterScheduleItems(state.scheduleItems, body.params),
                stats: scheduleStats(state.scheduleItems),
                timeline: scheduleTimeline(state.scheduleItems),
                storage: scheduleStorageMetadata(state),
                journal: state.scheduleJournal,
                source: "host storage broker",
                persisted_at: new Date().toISOString(),
              },
            },
          });
        case "schedule.item.add": {
          const item = normalizeScheduleItem(body.params);
          state.scheduleItems = [...state.scheduleItems, item].sort(compareScheduleItems);
          state.scheduleRevision += 1;
          appendScheduleJournal(state, "add", item.title);
          persistState();
          return jsonResponse({
            ok: true,
            data: {
              data: {
                item,
                items: filterScheduleItems(state.scheduleItems, body.params?.view),
                stats: scheduleStats(state.scheduleItems),
                timeline: scheduleTimeline(state.scheduleItems),
                storage: scheduleStorageMetadata(state),
                journal: state.scheduleJournal,
                source: "host storage broker",
                persisted: true,
                persisted_at: new Date().toISOString(),
              },
            },
          });
        }
        case "schedule.item.toggle": {
          const id = String(body.params?.id ?? "");
          state.scheduleItems = state.scheduleItems.map((item) => item.id === id ? { ...item, done: !item.done } : item);
          state.scheduleRevision += 1;
          appendScheduleJournal(state, "toggle", id);
          persistState();
          return jsonResponse({
            ok: true,
            data: {
              data: {
                items: filterScheduleItems(state.scheduleItems, body.params?.view),
                stats: scheduleStats(state.scheduleItems),
                timeline: scheduleTimeline(state.scheduleItems),
                storage: scheduleStorageMetadata(state),
                journal: state.scheduleJournal,
                source: "host storage broker",
                persisted: true,
                persisted_at: new Date().toISOString(),
              },
            },
          });
        }
        case "schedule.item.delete": {
          const id = String(body.params?.id ?? "");
          state.scheduleItems = state.scheduleItems.filter((item) => item.id !== id);
          state.scheduleRevision += 1;
          appendScheduleJournal(state, "delete", id);
          persistState();
          return jsonResponse({
            ok: true,
            data: {
              data: {
                items: filterScheduleItems(state.scheduleItems, body.params?.view),
                stats: scheduleStats(state.scheduleItems),
                timeline: scheduleTimeline(state.scheduleItems),
                storage: scheduleStorageMetadata(state),
                journal: state.scheduleJournal,
                source: "host storage broker",
                persisted: true,
                persisted_at: new Date().toISOString(),
              },
            },
          });
        }
        case "schedule.items.seedWeek": {
          const seeded = createSeedScheduleItems(state.scheduleRevision);
          state.scheduleItems = [...state.scheduleItems, ...seeded].sort(compareScheduleItems);
          state.scheduleRevision += 1;
          appendScheduleJournal(state, "seed_week", `${seeded.length} items`);
          persistState();
          return jsonResponse({
            ok: true,
            data: {
              data: {
                added: seeded.length,
                items: filterScheduleItems(state.scheduleItems, body.params?.view),
                stats: scheduleStats(state.scheduleItems),
                timeline: scheduleTimeline(state.scheduleItems),
                storage: scheduleStorageMetadata(state),
                journal: state.scheduleJournal,
                source: "host storage broker",
                persisted: true,
                persisted_at: new Date().toISOString(),
              },
            },
          });
        }
        case "schedule.items.archiveDone": {
          const before = state.scheduleItems.length;
          state.scheduleItems = state.scheduleItems.filter((item) => !item.done);
          const archived = before - state.scheduleItems.length;
          state.scheduleRevision += 1;
          appendScheduleJournal(state, "archive_done", `${archived} items`);
          persistState();
          return jsonResponse({
            ok: true,
            data: {
              data: {
                archived,
                items: filterScheduleItems(state.scheduleItems, body.params?.view),
                stats: scheduleStats(state.scheduleItems),
                timeline: scheduleTimeline(state.scheduleItems),
                storage: scheduleStorageMetadata(state),
                journal: state.scheduleJournal,
                source: "host storage broker",
                persisted: true,
                persisted_at: new Date().toISOString(),
              },
            },
          });
        }
        case "weather.location.get":
          return jsonResponse({
            ok: true,
            data: {
              data: {
                location: state.weatherLocation,
                saved_locations: state.weatherSavedLocations,
                source: "plugin settings storage",
              },
            },
          });
        case "weather.location.save":
          state.weatherLocation = normalizeLocation(body.params?.location);
          state.weatherSavedLocations = rememberLocation(state.weatherSavedLocations, state.weatherLocation);
          persistState();
          return jsonResponse({
            ok: true,
            data: {
              data: {
                location: state.weatherLocation,
                saved_locations: state.weatherSavedLocations,
                source: "plugin settings storage",
                saved: true,
              },
            },
          });
        case "weather.fetch": {
          const location = normalizeLocation(body.params?.location ?? state.weatherLocation);
          state.weatherLocation = location;
          state.weatherSavedLocations = rememberLocation(state.weatherSavedLocations, location);
          state.weatherFetches += 1;
          const payload = await fetchWeatherPayload(location, state.weatherFetches, { networkBaseURL, networkFetch });
          state.weatherNetworkEvents = rememberWeatherNetworkEvent(state.weatherNetworkEvents, payload.network);
          payload.network_history = state.weatherNetworkEvents;
          persistState();
          return jsonResponse({
            ok: true,
            data: {
              data: payload,
            },
          });
        }
        default:
          return jsonResponse({ ok: false, error_code: "PLUGIN_METHOD_NOT_FOUND", error: `unknown method ${body.method}` }, 404);
      }
    }

    return jsonResponse({ ok: false, error_code: "PLUGIN_NOT_FOUND", error: `unknown demo endpoint ${url.pathname}` }, 404);
  }

  return { fetch, calls, state };
}

function createDefaultDemoState() {
  return {
    gameBestScore: 0,
    gameLastRun: null,
    gameSaves: 0,
    gameSnapshots: [],
    scheduleRevision: 1,
    scheduleJournal: [
      { action: "init", detail: "seed fixture", revision: 1, at: "2026-06-30T00:00:00Z" },
    ],
    scheduleItems: [
      {
        id: "sched-standup",
        title: "Platform standup",
        date: "2026-06-30",
        time: "09:30",
        tag: "team",
        priority: "high",
        duration_minutes: 30,
        notes: "Review bridge lifecycle and demo coverage.",
        done: false,
      },
      {
        id: "sched-design",
        title: "Plugin UX review",
        date: "2026-06-30",
        time: "14:00",
        tag: "design",
        priority: "medium",
        duration_minutes: 45,
        notes: "Check sandbox UI, storage broker, and weather flow.",
        done: false,
      },
      {
        id: "sched-release",
        title: "Runtime smoke",
        date: "2026-07-01",
        time: "10:15",
        tag: "qa",
        priority: "low",
        duration_minutes: 20,
        notes: "Run browser demo and real Rust runtime checks.",
        done: true,
      },
    ],
    weatherLocation: "San Francisco",
    weatherSavedLocations: ["San Francisco", "Shanghai", "London"],
    weatherNetworkEvents: [],
    weatherFetches: 0,
    hostSettings: { accent_mode: "teal", telemetry_enabled: false },
    settingsRevision: 1,
    settingsUpdatedAt: "2026-06-30T00:00:00Z",
  };
}

function demoSettingsSchema(pluginInstanceID, settingsRevision) {
  return {
    plugin_instance_id: pluginInstanceID,
    schema_version: 1,
    migration: {
      from_version: 1,
      to_version: 1,
      reversible: true,
      requires_worker: false,
      estimated_bytes: 0,
      max_duration_ms: 0,
      data_loss_risk: false,
      steps_hash: "sha256:demo-settings",
    },
    fields: [
      { key: "accent_mode", type: "select", label: "Accent mode", scope: "user", default: "teal", options: ["teal", "indigo", "amber"] },
      { key: "telemetry_enabled", type: "boolean", label: "Telemetry enabled", scope: "user", default: false },
    ],
    settings_revision: settingsRevision,
  };
}

function demoSettingsSnapshot(pluginInstanceID, state) {
  return {
    plugin_instance_id: pluginInstanceID,
    schema_version: 1,
    settings_revision: state.settingsRevision,
    values: { ...state.hostSettings },
    updated_at: state.settingsUpdatedAt,
  };
}

function createDemoPersistence(bootstrap, override) {
  if (override) {
    return normalizePersistenceAdapter(override);
  }
  if (typeof globalThis.localStorage !== "undefined") {
    const key = `redevplugin.demo.storage.${bootstrap.pluginId}`;
    return {
      load() {
        const raw = globalThis.localStorage.getItem(key);
        return raw ? JSON.parse(raw) : {};
      },
      save(value) {
        globalThis.localStorage.setItem(key, JSON.stringify(value));
      },
      clear() {
        globalThis.localStorage.removeItem(key);
      },
    };
  }
  return createMemoryPersistence();
}

export function createMemoryPersistence(initial = {}) {
  let current = structuredCloneSafe(initial);
  return {
    load() {
      return structuredCloneSafe(current);
    },
    save(value) {
      current = structuredCloneSafe(value);
    },
    clear() {
      current = {};
    },
  };
}

function normalizePersistenceAdapter(adapter) {
  return {
    load: typeof adapter.load === "function" ? adapter.load.bind(adapter) : () => ({}),
    save: typeof adapter.save === "function" ? adapter.save.bind(adapter) : () => {},
    clear: typeof adapter.clear === "function" ? adapter.clear.bind(adapter) : () => {},
  };
}

function applyPersistedState(state, persisted = {}) {
  if (typeof persisted !== "object" || persisted === null) {
    return;
  }
  if (Number.isFinite(Number(persisted.gameBestScore))) {
    state.gameBestScore = Math.max(0, Math.round(Number(persisted.gameBestScore)));
  }
  if (persisted.gameLastRun && typeof persisted.gameLastRun === "object") {
    state.gameLastRun = normalizeGameRun(persisted.gameLastRun);
  }
  if (Number.isFinite(Number(persisted.gameSaves))) {
    state.gameSaves = Math.max(0, Math.round(Number(persisted.gameSaves)));
  }
  if (Array.isArray(persisted.gameSnapshots)) {
    state.gameSnapshots = persisted.gameSnapshots.map(normalizeGameSnapshot).slice(0, 5);
  }
  if (Array.isArray(persisted.scheduleItems)) {
    state.scheduleItems = persisted.scheduleItems.map(normalizePersistedScheduleItem).sort(compareScheduleItems);
  }
  if (Array.isArray(persisted.scheduleJournal)) {
    state.scheduleJournal = persisted.scheduleJournal.map(normalizeJournalEntry).slice(0, 8);
  }
  if (Number.isFinite(Number(persisted.scheduleRevision))) {
    state.scheduleRevision = Math.max(1, Math.round(Number(persisted.scheduleRevision)));
  }
  if (typeof persisted.weatherLocation === "string") {
    state.weatherLocation = normalizeLocation(persisted.weatherLocation);
  }
  if (Array.isArray(persisted.weatherSavedLocations)) {
    state.weatherSavedLocations = persisted.weatherSavedLocations.map(normalizeLocation).slice(0, 6);
  }
  if (Array.isArray(persisted.weatherNetworkEvents)) {
    state.weatherNetworkEvents = persisted.weatherNetworkEvents.map(normalizeWeatherNetworkEvent).slice(0, 6);
  }
  if (isRecord(persisted.hostSettings)) {
    state.hostSettings = normalizeDemoSettings(persisted.hostSettings);
  }
  if (Number.isFinite(Number(persisted.settingsRevision))) {
    state.settingsRevision = Math.max(1, Math.round(Number(persisted.settingsRevision)));
  }
  if (typeof persisted.settingsUpdatedAt === "string") {
    state.settingsUpdatedAt = persisted.settingsUpdatedAt;
  }
}

function normalizeDemoSettings(values = {}) {
  const accent = String(values.accent_mode ?? "teal");
  return {
    accent_mode: ["teal", "indigo", "amber"].includes(accent) ? accent : "teal",
    telemetry_enabled: Boolean(values.telemetry_enabled),
  };
}

function normalizePersistedScheduleItem(item = {}) {
  return {
    id: String(item.id || `sched-${Date.now().toString(36)}`).slice(0, 80),
    title: String(item.title || "Untitled event").trim().slice(0, 80),
    date: String(item.date || "2026-06-30"),
    time: String(item.time || "09:00"),
    tag: String(item.tag || "focus").trim().slice(0, 24),
    priority: normalizePriority(item.priority),
    duration_minutes: normalizeDuration(item.duration_minutes),
    notes: String(item.notes || "").trim().slice(0, 180),
    done: Boolean(item.done),
  };
}

function structuredCloneSafe(value) {
  return JSON.parse(JSON.stringify(value ?? {}));
}

function isRecord(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function normalizeScheduleItem(params = {}) {
  const now = Date.now().toString(36);
  return {
    id: `sched-${now}`,
    title: String(params.title || "Untitled event").trim().slice(0, 80),
    date: String(params.date || "2026-06-30"),
    time: String(params.time || "09:00"),
    tag: String(params.tag || "focus").trim().slice(0, 24),
    priority: normalizePriority(params.priority),
    duration_minutes: normalizeDuration(params.duration_minutes),
    notes: String(params.notes || "").trim().slice(0, 180),
    done: false,
  };
}

function createSeedScheduleItems(revision) {
  const base = [
    ["Mon", "Architecture sync", "10:00", "platform", "high", 40],
    ["Tue", "Storage migration review", "13:30", "storage", "medium", 50],
    ["Wed", "Weather connector test", "15:00", "network", "medium", 35],
    ["Thu", "Sandbox UI polish", "11:20", "design", "low", 45],
    ["Fri", "Browser smoke rehearsal", "16:00", "qa", "high", 30],
  ];
  return base.map(([day, title, time, tag, priority, duration], index) => ({
    id: `sched-seed-${revision}-${index}`,
    title: `${day} · ${title}`,
    date: `2026-07-${String(index + 6).padStart(2, "0")}`,
    time,
    tag,
    priority,
    duration_minutes: duration,
    notes: "Generated by a backend storage operation in the demo host.",
    done: false,
  }));
}

function compareScheduleItems(a, b) {
  return `${a.date}T${a.time}`.localeCompare(`${b.date}T${b.time}`);
}

function normalizePriority(value) {
  const priority = String(value || "medium").trim().toLowerCase();
  return ["low", "medium", "high"].includes(priority) ? priority : "medium";
}

function normalizeDuration(value) {
  const minutes = Number(value ?? 30);
  if (!Number.isFinite(minutes)) {
    return 30;
  }
  return Math.max(5, Math.min(240, Math.round(minutes)));
}

function filterScheduleItems(items, params = {}) {
  const view = typeof params === "string" ? { view: params } : (params ?? {});
  const status = String(view.status || "all");
  const query = String(view.query || "").trim().toLowerCase();
  const tag = String(view.tag || "").trim().toLowerCase();
  return items
    .filter((item) => status === "all" || (status === "open" && !item.done) || (status === "done" && item.done))
    .filter((item) => query === "" || item.title.toLowerCase().includes(query) || item.notes.toLowerCase().includes(query))
    .filter((item) => tag === "" || item.tag.toLowerCase() === tag)
    .sort(compareScheduleItems);
}

function scheduleStats(items) {
  const open = items.filter((item) => !item.done);
  const done = items.length - open.length;
  const minutes = open.reduce((sum, item) => sum + Number(item.duration_minutes ?? 0), 0);
  const tags = [...new Set(items.map((item) => item.tag).filter(Boolean))].sort();
  const next = open.slice().sort(compareScheduleItems)[0] ?? null;
  return {
    total: items.length,
    open: open.length,
    done,
    planned_minutes: minutes,
    tags,
    next,
  };
}

function normalizeGameRun(params = {}) {
  const score = Math.max(0, Math.round(Number(params.score ?? 0)));
  return {
    score,
    level: Math.max(1, Math.round(Number(params.level ?? 1))),
    combo: Math.max(0, Math.round(Number(params.combo ?? 0))),
    bricks_cleared: Math.max(0, Math.round(Number(params.bricks_cleared ?? 0))),
    powerups_collected: Math.max(0, Math.round(Number(params.powerups_collected ?? 0))),
    peak_speed: Math.max(1, Number(params.peak_speed ?? 1)),
    duration_ms: Math.max(0, Math.round(Number(params.duration_ms ?? 0))),
    saved_at: "2026-06-30T00:00:09Z",
  };
}

function normalizeGameSnapshot(params = {}) {
  return {
    id: String(params.id || `snapshot-${Date.now().toString(36)}`).slice(0, 80),
    score: Math.max(0, Math.round(Number(params.score ?? 0))),
    level: Math.max(1, Math.round(Number(params.level ?? 1))),
    combo: Math.max(0, Math.round(Number(params.combo ?? 0))),
    bricks_cleared: Math.max(0, Math.round(Number(params.bricks_cleared ?? 0))),
    powerups_collected: Math.max(0, Math.round(Number(params.powerups_collected ?? 0))),
    lives: Math.max(0, Math.round(Number(params.lives ?? 3))),
    energy: Math.max(0, Math.min(100, Math.round(Number(params.energy ?? 100)))),
    speed: Math.max(1, Number(params.speed ?? 1)),
    saved_at: typeof params.saved_at === "string" ? params.saved_at : new Date().toISOString(),
  };
}

function gameAchievements(run) {
  const achievements = [];
  if (run.score >= 50) {
    achievements.push("score-sprinter");
  }
  if (run.combo >= 4) {
    achievements.push("combo-streak");
  }
  if (run.bricks_cleared >= 12) {
    achievements.push("brick-sweeper");
  }
  if (run.powerups_collected >= 2) {
    achievements.push("power-collector");
  }
  return achievements;
}

function gameLeaderboard(state) {
  const lastScore = Number(state.gameLastRun?.score ?? 0);
  return [
    { rank: 1, name: "Best sandbox run", score: state.gameBestScore },
    { rank: 2, name: "Latest run", score: lastScore },
    { rank: 3, name: "Demo target", score: 120 },
  ].sort((a, b) => b.score - a.score).map((entry, index) => ({ ...entry, rank: index + 1 }));
}

function scheduleStorageMetadata(state) {
  return {
    engine: "sqlite-demo",
    namespace: "plugini_demo_1/schedule",
    revision: state.scheduleRevision,
    records: state.scheduleItems.length,
    journal_entries: state.scheduleJournal.length,
    quota_bytes: 1048576,
    used_bytes: 4096 + state.scheduleItems.length * 384 + state.scheduleJournal.length * 128,
  };
}

function appendScheduleJournal(state, action, detail) {
  state.scheduleJournal = [
    {
      action,
      detail: String(detail || "").slice(0, 80),
      revision: state.scheduleRevision,
      at: new Date().toISOString(),
    },
    ...state.scheduleJournal,
  ].slice(0, 8);
}

function normalizeJournalEntry(entry = {}) {
  return {
    action: String(entry.action || "unknown").slice(0, 40),
    detail: String(entry.detail || "").slice(0, 80),
    revision: Math.max(1, Math.round(Number(entry.revision ?? 1))),
    at: typeof entry.at === "string" ? entry.at : "2026-06-30T00:00:00Z",
  };
}

function scheduleTimeline(items) {
  return items
    .slice()
    .sort(compareScheduleItems)
    .map((item, index) => ({
      slot: `${item.date} ${item.time}`,
      label: item.title,
      tag: item.tag,
      priority: item.priority,
      done: item.done,
      lane: index % 3,
    }));
}

function normalizeLocation(value) {
  const location = String(value || "San Francisco").trim();
  return location === "" ? "San Francisco" : location.slice(0, 80);
}

function rememberLocation(locations, location) {
  const next = [location, ...locations.filter((candidate) => candidate.toLowerCase() !== location.toLowerCase())];
  return next.slice(0, 6);
}

async function fetchWeatherPayload(location, fetchCount = 1, options = {}) {
  if (typeof options.networkFetch !== "function" || !options.networkBaseURL) {
    return createWeatherPayload(location, fetchCount);
  }
  const upstreamURL = new URL("/demo/weather-api/v1/forecast", options.networkBaseURL);
  upstreamURL.searchParams.set("location", location);
  upstreamURL.searchParams.set("fetch_count", String(fetchCount));

  const startedAt = Date.now();
  const response = await options.networkFetch(upstreamURL.href, {
    method: "GET",
    headers: {
      accept: "application/json",
      "x-redevplugin-connector": "weather_api",
    },
  });
  const rawResponseBody = await response.text();
  let rawPayload;
  try {
    rawPayload = JSON.parse(rawResponseBody);
  } catch {
    rawPayload = createWeatherAPIPayload(location);
  }
  return createWeatherPayloadFromRaw(location, rawPayload, rawResponseBody, {
    brokerEndpoint: upstreamURL.href,
    fetchCount,
    latencyMs: Math.max(1, Date.now() - startedAt),
    responseHeaders: headersToObject(response.headers),
    responseStatus: response.status,
    upstreamMode: "host http fetch",
  });
}

function createWeatherPayload(location, fetchCount = 1) {
  const rawPayload = createWeatherAPIPayload(location);
  const rawResponseBody = JSON.stringify(rawPayload);
  return createWeatherPayloadFromRaw(location, rawPayload, rawResponseBody, {
    fetchCount,
    latencyMs: 42 + fetchCount,
    responseHeaders: {
      "content-type": "application/json",
      "x-demo-cache": fetchCount % 2 === 0 ? "hit" : "miss",
    },
    responseStatus: 200,
    upstreamMode: "in-memory fixture",
  });
}

export function createWeatherAPIPayload(location) {
  const key = location.toLowerCase();
  const presets = {
    "san francisco": { temp: 17, condition: "Pacific fog clearing", wind: 18, humidity: 72, pressure: 1015, uv: 4, accent: "marine layer" },
    "shanghai": { temp: 29, condition: "Warm evening haze", wind: 11, humidity: 78, pressure: 1009, uv: 7, accent: "river breeze" },
    "beijing": { temp: 31, condition: "Dry and bright", wind: 9, humidity: 38, pressure: 1012, uv: 8, accent: "clear north sky" },
    "london": { temp: 19, condition: "Patchy rain windows", wind: 16, humidity: 81, pressure: 1006, uv: 3, accent: "soft drizzle" },
    "tokyo": { temp: 28, condition: "Humid cloud breaks", wind: 12, humidity: 74, pressure: 1008, uv: 6, accent: "neon rain" },
  };
  const weather = presets[key] ?? {
    temp: 22 + (location.length % 9),
    condition: "Synthetic forecast sample",
    wind: 8 + (location.length % 12),
    humidity: 48 + (location.length % 35),
    pressure: 1004 + (location.length % 14),
    uv: 2 + (location.length % 7),
    accent: "demo network response",
  };
  const hourly = [0, 3, 6, 9].map((offset) => ({
    hour: `${String((9 + offset) % 24).padStart(2, "0")}:00`,
    temperature_c: weather.temp + (offset % 6) - 2,
    condition: offset === 0 ? weather.condition : "Cloud pattern drift",
    wind_kph: weather.wind + offset,
  }));
  const forecast = [0, 1, 2, 3, 4].map((offset) => ({
    day: `D+${offset}`,
    high_c: weather.temp + 2 + offset,
    low_c: weather.temp - 4 + (offset % 2),
    condition: offset % 2 === 0 ? weather.condition : "Light cloud shifts",
    precipitation_percent: Math.min(95, Math.max(5, weather.humidity - 32 + offset * 4)),
  }));
  const rawPayload = {
    location,
    observed_at: "2026-06-30T08:00:00Z",
    source_station: `${location.toLowerCase().replaceAll(" ", "-")}-demo-station`,
    current: {
      temperature_c: weather.temp,
      condition: weather.condition,
      wind_kph: weather.wind,
      humidity_percent: weather.humidity,
      pressure_hpa: weather.pressure,
      uv_index: weather.uv,
      accent: weather.accent,
    },
    air_quality: {
      aqi: 35 + (location.length % 58),
      dominant_pollutant: location.length % 2 === 0 ? "pm2.5" : "ozone",
      category: location.length % 3 === 0 ? "moderate" : "good",
    },
    alerts: weather.wind > 15 ? [
      {
        severity: "advisory",
        title: "Wind window",
        detail: "Outdoor setup should account for gusts during the afternoon slot.",
      },
    ] : [],
    hourly,
    forecast,
  };
  return rawPayload;
}

function createWeatherPayloadFromRaw(location, rawPayload, rawResponseBody, network) {
  const current = rawPayload.current ?? {};
  const hourly = Array.isArray(rawPayload.hourly) ? rawPayload.hourly : [];
  const forecast = Array.isArray(rawPayload.forecast) ? rawPayload.forecast : [];
  const alerts = Array.isArray(rawPayload.alerts) ? rawPayload.alerts : [];
  return {
    location,
    current,
    hourly,
    forecast,
    alerts,
    air_quality: rawPayload.air_quality ?? null,
    network: {
      connector_id: "weather_api",
      transport: "http",
      operation: `GET /v1/forecast?location=${encodeURIComponent(location)}`,
      destination: "https://api.weather.example",
      broker_endpoint: network.brokerEndpoint ?? "in-memory://weather-api/v1/forecast",
      request_headers: {
        accept: "application/json",
        "x-redevplugin-connector": "weather_api",
      },
      response_status: network.responseStatus ?? 200,
      response_headers: network.responseHeaders ?? {},
      latency_ms: network.latencyMs ?? 0,
      bytes_received: rawResponseBody.length,
      parsed: false,
      upstream_mode: network.upstreamMode ?? "unknown",
    },
    raw_response_body: rawResponseBody,
    parser: {
      format: "json",
      fields: ["current.temperature_c", "current.condition", "air_quality", "alerts[]", "forecast[]", "hourly[]"],
    },
    parsed_summary: `${current.condition ?? "Unknown"}; ${current.wind_kph ?? "--"} kph wind; ${current.humidity_percent ?? "--"}% humidity`,
  };
}

function rememberWeatherNetworkEvent(events, network = {}) {
  return [
    normalizeWeatherNetworkEvent({
      operation: network.operation,
      response_status: network.response_status,
      latency_ms: network.latency_ms,
      bytes_received: network.bytes_received,
      upstream_mode: network.upstream_mode,
      at: new Date().toISOString(),
    }),
    ...events,
  ].slice(0, 6);
}

function normalizeWeatherNetworkEvent(event = {}) {
  return {
    operation: String(event.operation || "GET /v1/forecast").slice(0, 120),
    response_status: Math.round(Number(event.response_status ?? 200)),
    latency_ms: Math.max(0, Math.round(Number(event.latency_ms ?? 0))),
    bytes_received: Math.max(0, Math.round(Number(event.bytes_received ?? 0))),
    upstream_mode: String(event.upstream_mode || "unknown").slice(0, 80),
    at: typeof event.at === "string" ? event.at : "2026-06-30T00:00:00Z",
  };
}

function headersToObject(headers) {
  const output = {};
  if (headers && typeof headers.forEach === "function") {
    headers.forEach((value, key) => {
      output[String(key).toLowerCase()] = String(value);
    });
  }
  return output;
}

export function jsonResponse(body, status = 200) {
  return {
    ok: status >= 200 && status < 300,
    status,
    async json() {
      return body;
    },
  };
}

export function formatJSON(value) {
  return JSON.stringify(value, null, 2);
}
