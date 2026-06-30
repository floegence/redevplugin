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
    scheduleItems: [
      {
        id: "sched-standup",
        title: "Platform standup",
        date: "2026-06-30",
        time: "09:30",
        tag: "team",
        notes: "Review bridge lifecycle and demo coverage.",
        done: false,
      },
      {
        id: "sched-design",
        title: "Plugin UX review",
        date: "2026-06-30",
        time: "14:00",
        tag: "design",
        notes: "Check sandbox UI, storage broker, and weather flow.",
        done: false,
      },
      {
        id: "sched-release",
        title: "Runtime smoke",
        date: "2026-07-01",
        time: "10:15",
        tag: "qa",
        notes: "Run browser demo and real Rust runtime checks.",
        done: true,
      },
    ],
    weatherLocation: "San Francisco",
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
          state.gameBestScore = Math.max(state.gameBestScore, Number(body.params?.score ?? 0));
          return jsonResponse({
            ok: true,
            data: {
              data: {
                saved: true,
                best_score: state.gameBestScore,
                storage: "host-backed kv store",
              },
            },
          });
        case "schedule.items.list":
          return jsonResponse({
            ok: true,
            data: {
              data: {
                items: state.scheduleItems,
                source: "host storage broker",
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
                items: state.scheduleItems,
                persisted: true,
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
                items: state.scheduleItems,
                persisted: true,
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
                items: state.scheduleItems,
                persisted: true,
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
                source: "plugin settings storage",
              },
            },
          });
        case "weather.location.save":
          state.weatherLocation = normalizeLocation(body.params?.location);
          return jsonResponse({
            ok: true,
            data: {
              data: {
                location: state.weatherLocation,
                saved: true,
              },
            },
          });
        case "weather.fetch": {
          const location = normalizeLocation(body.params?.location ?? state.weatherLocation);
          state.weatherLocation = location;
          return jsonResponse({
            ok: true,
            data: {
              data: createWeatherPayload(location),
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
    notes: String(params.notes || "").trim().slice(0, 180),
    done: false,
  };
}

function compareScheduleItems(a, b) {
  return `${a.date}T${a.time}`.localeCompare(`${b.date}T${b.time}`);
}

function normalizeLocation(value) {
  const location = String(value || "San Francisco").trim();
  return location === "" ? "San Francisco" : location.slice(0, 80);
}

function createWeatherPayload(location) {
  const key = location.toLowerCase();
  const presets = {
    "san francisco": { temp: 17, condition: "Pacific fog clearing", wind: 18, humidity: 72, accent: "marine layer" },
    "shanghai": { temp: 29, condition: "Warm evening haze", wind: 11, humidity: 78, accent: "river breeze" },
    "beijing": { temp: 31, condition: "Dry and bright", wind: 9, humidity: 38, accent: "clear north sky" },
    "london": { temp: 19, condition: "Patchy rain windows", wind: 16, humidity: 81, accent: "soft drizzle" },
    "tokyo": { temp: 28, condition: "Humid cloud breaks", wind: 12, humidity: 74, accent: "neon rain" },
  };
  const weather = presets[key] ?? {
    temp: 22 + (location.length % 9),
    condition: "Synthetic forecast sample",
    wind: 8 + (location.length % 12),
    humidity: 48 + (location.length % 35),
    accent: "demo network response",
  };
  return {
    location,
    current: {
      temperature_c: weather.temp,
      condition: weather.condition,
      wind_kph: weather.wind,
      humidity_percent: weather.humidity,
      accent: weather.accent,
    },
    forecast: [0, 1, 2, 3, 4].map((offset) => ({
      day: `D+${offset}`,
      high_c: weather.temp + 2 + offset,
      low_c: weather.temp - 4 + (offset % 2),
      condition: offset % 2 === 0 ? weather.condition : "Light cloud shifts",
    })),
    network: {
      connector_id: "weather_api",
      transport: "http",
      destination: "https://api.weather.example",
      parsed: true,
    },
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
