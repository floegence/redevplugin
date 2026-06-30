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
  const state = {
    bridgeTokenIssued: false,
    confirmationToken: "",
    confirmedDeletes: 0,
    streamTickets: 0,
    gameBestScore: 0,
    gameLastRun: null,
    gameSaves: 0,
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
    weatherFetches: 0,
  };

  async function fetch(input, init) {
    const url = new URL(String(input), "http://demo.local");
    const body = init?.body ? JSON.parse(String(init.body)) : {};
    calls.push({ path: url.pathname, body });
    options.onCall?.(url.pathname, body);

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
          return jsonResponse({
            ok: true,
            data: {
              data: {
                saved: true,
                best_score: state.gameBestScore,
                last_run: state.gameLastRun,
                saves: state.gameSaves,
                achievements: gameAchievements(state.gameLastRun),
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
                storage: "host-backed kv store",
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
                source: "host storage broker",
                persisted_at: "2026-06-30T00:00:05Z",
              },
            },
          });
        case "schedule.item.add": {
          const item = normalizeScheduleItem(body.params);
          state.scheduleItems = [...state.scheduleItems, item].sort(compareScheduleItems);
          return jsonResponse({
            ok: true,
            data: {
              data: {
                item,
                items: filterScheduleItems(state.scheduleItems, body.params?.view),
                stats: scheduleStats(state.scheduleItems),
                persisted: true,
                persisted_at: "2026-06-30T00:00:06Z",
              },
            },
          });
        }
        case "schedule.item.toggle": {
          const id = String(body.params?.id ?? "");
          state.scheduleItems = state.scheduleItems.map((item) => item.id === id ? { ...item, done: !item.done } : item);
          return jsonResponse({
            ok: true,
            data: {
              data: {
                items: filterScheduleItems(state.scheduleItems, body.params?.view),
                stats: scheduleStats(state.scheduleItems),
                persisted: true,
                persisted_at: "2026-06-30T00:00:07Z",
              },
            },
          });
        }
        case "schedule.item.delete": {
          const id = String(body.params?.id ?? "");
          state.scheduleItems = state.scheduleItems.filter((item) => item.id !== id);
          return jsonResponse({
            ok: true,
            data: {
              data: {
                items: filterScheduleItems(state.scheduleItems, body.params?.view),
                stats: scheduleStats(state.scheduleItems),
                persisted: true,
                persisted_at: "2026-06-30T00:00:08Z",
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
          return jsonResponse({
            ok: true,
            data: {
              data: {
                location: state.weatherLocation,
                saved_locations: state.weatherSavedLocations,
                saved: true,
              },
            },
          });
        case "weather.fetch": {
          const location = normalizeLocation(body.params?.location ?? state.weatherLocation);
          state.weatherLocation = location;
          state.weatherSavedLocations = rememberLocation(state.weatherSavedLocations, location);
          state.weatherFetches += 1;
          return jsonResponse({
            ok: true,
            data: {
              data: createWeatherPayload(location, state.weatherFetches),
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
    duration_ms: Math.max(0, Math.round(Number(params.duration_ms ?? 0))),
    saved_at: "2026-06-30T00:00:09Z",
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
  return achievements;
}

function normalizeLocation(value) {
  const location = String(value || "San Francisco").trim();
  return location === "" ? "San Francisco" : location.slice(0, 80);
}

function rememberLocation(locations, location) {
  const next = [location, ...locations.filter((candidate) => candidate.toLowerCase() !== location.toLowerCase())];
  return next.slice(0, 6);
}

function createWeatherPayload(location, fetchCount = 1) {
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
  return {
    location,
    current: {
      temperature_c: weather.temp,
      condition: weather.condition,
      wind_kph: weather.wind,
      humidity_percent: weather.humidity,
      pressure_hpa: weather.pressure,
      uv_index: weather.uv,
      accent: weather.accent,
    },
    forecast: [0, 1, 2, 3, 4].map((offset) => ({
      day: `D+${offset}`,
      high_c: weather.temp + 2 + offset,
      low_c: weather.temp - 4 + (offset % 2),
      condition: offset % 2 === 0 ? weather.condition : "Light cloud shifts",
      precipitation_percent: Math.min(95, Math.max(5, weather.humidity - 32 + offset * 4)),
    })),
    network: {
      connector_id: "weather_api",
      transport: "http",
      operation: "GET /v1/forecast",
      destination: "https://api.weather.example",
      latency_ms: 42 + fetchCount,
      bytes_received: 1320 + location.length * 11,
      parsed: true,
    },
    parsed_summary: `${weather.condition}; ${weather.wind} kph wind; ${weather.humidity}% humidity`,
  };
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
