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

resetDemoDocumentScroll();

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
      gameEvents: state.gameEvents,
      gameSaves: state.gameSaves,
      gameSnapshots: state.gameSnapshots,
      gameChallenges: state.gameChallenges,
      gameReplayExports: state.gameReplayExports,
      scheduleItems: state.scheduleItems,
      scheduleJournal: state.scheduleJournal,
      scheduleBackups: state.scheduleBackups,
      scheduleRevision: state.scheduleRevision,
      scheduleRestoreCount: state.scheduleRestoreCount,
      weatherLocation: state.weatherLocation,
      weatherSavedLocations: state.weatherSavedLocations,
      weatherDetectedLocations: state.weatherDetectedLocations,
      weatherNetworkEvents: state.weatherNetworkEvents,
      weatherParserRuns: state.weatherParserRuns,
      weatherLastPayload: state.weatherLastPayload,
      hostSettings: state.hostSettings,
      settingsRevision: state.settingsRevision,
      settingsUpdatedAt: state.settingsUpdatedAt,
    });
  }

  Object.assign(state, {
    bridgeTokenIssued: false,
    confirmationID: "",
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
      state.confirmationID = `confirmation_intent_${body.method ?? "unknown"}`;
      return jsonResponse({
        ok: true,
        data: {
          confirmation_id: state.confirmationID,
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
                storage_sqlite: {
                  ok: true,
                  handle_id: "storage:db",
                  method: "storage.sqlite",
                  operation: "exec",
                  store_id: "db",
                  database: "plugin.sqlite",
                  rows_affected: 0,
                  executor: "host sqlite storage broker",
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
                network_execute_websocket: {
                  ok: true,
                  connector_id: "stream",
                  transport: "websocket",
                  destination: "wss://stream.example.com",
                  message_type: "text",
                  executor: "host-network-executor",
                  payload_base64: "d2Vic29ja2V0OmdlbmVyYXRlZCB3ZWJzb2NrZXQgcm91bmQgdHJpcA==",
                },
                network_execute_tcp: {
                  ok: true,
                  connector_id: "mysql",
                  transport: "tcp",
                  destination: "tcp://db.example.com:3306",
                  executor: "host-network-executor",
                  payload_base64: "dGNwOmdlbmVyYXRlZCB0Y3Agcm91bmQgdHJpcA==",
                },
                network_execute_udp: {
                  ok: true,
                  connector_id: "metrics",
                  transport: "udp",
                  destination: "udp://metrics.example.com:8125",
                  executor: "host-network-executor",
                  payload_base64: "dWRwOmdlbmVyYXRlZCB1ZHAgcm91bmQgdHJpcA==",
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
          if (!state.confirmationID || body.confirmation_id !== state.confirmationID) {
            return jsonResponse({ ok: false, error_code: "PLUGIN_CONFIRMATION_REQUIRED", error: "confirmation required" }, 409);
          }
          state.confirmationID = "";
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
                events: state.gameEvents,
                leaderboard: gameLeaderboard(state),
                mission: gameMission(state.gameLastRun),
                challenge_history: state.gameChallenges,
                replay_exports: state.gameReplayExports,
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
                events: state.gameEvents,
                leaderboard: gameLeaderboard(state),
                mission: gameMission(state.gameLastRun),
                snapshots: state.gameSnapshots,
                challenge_history: state.gameChallenges,
                replay_exports: state.gameReplayExports,
                storage: "host-backed kv store",
              },
            },
          });
        case "game.run.sync": {
          const run = normalizeGameRun(body.params?.run ?? {});
          const telemetry = normalizeGameTelemetry(body.params?.telemetry ?? {});
          state.gameLastRun = run;
          state.gameBestScore = Math.max(state.gameBestScore, run.score);
          state.gameEvents = [
            {
              label: `synced ${telemetry.events.length} runtime events`,
              tone: "green",
              score: run.score,
              level: run.level,
              combo: run.combo,
              at: new Date().toISOString(),
            },
            ...telemetry.events,
            ...state.gameEvents,
          ].map(normalizeGameEvent).slice(0, 8);
          persistState();
          return jsonResponse({
            ok: true,
            data: {
              data: {
                synced: true,
                run,
                telemetry,
                best_score: state.gameBestScore,
                events: state.gameEvents,
                mission: gameMission(run),
                challenge_history: state.gameChallenges,
                replay_exports: state.gameReplayExports,
                storage: "host-backed kv store",
                storage_key: "game/runs/latest",
              },
            },
          });
        }
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
        case "game.replay.export": {
          const replay = createGameReplayExport(state, body.params);
          state.gameReplayExports = [replay, ...state.gameReplayExports].slice(0, 4);
          state.gameEvents = [
            normalizeGameEvent({
              label: `exported replay ${replay.frame_count}f`,
              tone: "blue",
              score: replay.score,
              level: replay.level,
              combo: replay.max_combo,
              at: replay.created_at,
            }),
            ...state.gameEvents,
          ].slice(0, 8);
          persistState();
          return jsonResponse({
            ok: true,
            data: {
              data: {
                exported: true,
                replay,
                replay_exports: state.gameReplayExports,
                events: state.gameEvents,
                storage: "host files broker + kv replay index",
                storage_key: "game/replays",
                runtime_actor: "wasm-game-loop-demo",
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
        case "game.challenge.report": {
          const challenge = normalizeGameChallenge(body.params);
          state.gameChallenges = [challenge, ...state.gameChallenges].slice(0, 5);
          state.gameEvents = [
            normalizeGameEvent({
              label: `storm wave ${challenge.waves_survived} banked`,
              tone: challenge.completed ? "violet" : "blue",
              score: challenge.score,
              level: challenge.storm_level,
              combo: challenge.max_combo,
              at: challenge.saved_at,
            }),
            ...state.gameEvents,
          ].slice(0, 8);
          state.gameBestScore = Math.max(state.gameBestScore, challenge.score);
          persistState();
          return jsonResponse({
            ok: true,
            data: {
              data: {
                reported: true,
                challenge,
                challenge_history: state.gameChallenges,
                best_score: state.gameBestScore,
                events: state.gameEvents,
                achievements: gameAchievements(challenge),
                mission: gameMission(challenge),
                replay_exports: state.gameReplayExports,
                storage: "host-backed kv store",
                storage_key: "game/challenges/history",
                runtime_actor: "wasm-game-loop-demo",
              },
            },
          });
        }
        case "schedule.items.list":
          return jsonResponse({
            ok: true,
            data: {
              data: {
                items: filterScheduleItems(state.scheduleItems, body.params),
                stats: scheduleStats(state.scheduleItems),
                timeline: scheduleTimeline(state.scheduleItems),
                storage: scheduleStorageMetadata(state),
                transaction: scheduleTransaction("read", state, 0),
                backups: state.scheduleBackups,
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
                transaction: scheduleTransaction("insert", state, 1),
                backups: state.scheduleBackups,
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
                transaction: scheduleTransaction("update", state, 1),
                backups: state.scheduleBackups,
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
                transaction: scheduleTransaction("delete", state, 1),
                backups: state.scheduleBackups,
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
                transaction: scheduleTransaction("bulk_insert", state, seeded.length),
                backups: state.scheduleBackups,
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
                transaction: scheduleTransaction("bulk_delete", state, archived),
                backups: state.scheduleBackups,
                journal: state.scheduleJournal,
                source: "host storage broker",
                persisted: true,
                persisted_at: new Date().toISOString(),
              },
            },
          });
        }
        case "schedule.items.bulkPlan": {
          const planned = createSprintPlanItems(state.scheduleRevision);
          state.scheduleItems = [...state.scheduleItems, ...planned].sort(compareScheduleItems);
          state.scheduleRevision += 1;
          appendScheduleJournal(state, "bulk_plan", `${planned.length} sprint items`);
          persistState();
          return jsonResponse({
            ok: true,
            data: {
              data: {
                added: planned.length,
                items: filterScheduleItems(state.scheduleItems, body.params?.view),
                stats: scheduleStats(state.scheduleItems),
                timeline: scheduleTimeline(state.scheduleItems),
                storage: scheduleStorageMetadata(state),
                transaction: scheduleTransaction("bulk_insert", state, planned.length),
                backups: state.scheduleBackups,
                journal: state.scheduleJournal,
                source: "host storage broker",
                persisted: true,
                persisted_at: new Date().toISOString(),
              },
            },
          });
        }
        case "schedule.storage.backup": {
          const backup = createScheduleBackup(state);
          state.scheduleBackups = [backup, ...state.scheduleBackups].slice(0, 5);
          state.scheduleRevision += 1;
          appendScheduleJournal(state, "backup", backup.filename);
          persistState();
          return jsonResponse({
            ok: true,
            data: {
              data: {
                backup,
                backups: state.scheduleBackups,
                items: filterScheduleItems(state.scheduleItems, body.params?.view),
                stats: scheduleStats(state.scheduleItems),
                timeline: scheduleTimeline(state.scheduleItems),
                storage: scheduleStorageMetadata(state),
                transaction: scheduleTransaction("backup", state, state.scheduleItems.length),
                journal: state.scheduleJournal,
                source: "host files broker + sqlite snapshot",
                persisted: true,
                persisted_at: new Date().toISOString(),
              },
            },
          });
        }
        case "schedule.storage.inspect":
          return jsonResponse({
            ok: true,
            data: {
              data: {
                items: filterScheduleItems(state.scheduleItems, body.params?.view),
                stats: scheduleStats(state.scheduleItems),
                timeline: scheduleTimeline(state.scheduleItems),
                storage: scheduleStorageMetadata(state),
                transaction: scheduleTransaction("inspect", state, 0),
                backups: state.scheduleBackups,
                journal: state.scheduleJournal,
                source: "host sqlite storage broker",
                health: scheduleStorageHealth(state),
                schema: scheduleSchemaSummary(),
                persisted_at: new Date().toISOString(),
              },
            },
          });
        case "schedule.storage.restoreLatest": {
          const latest = state.scheduleBackups[0] ?? null;
          const restoredItems = Array.isArray(latest?.item_snapshot) ? latest.item_snapshot.map(normalizePersistedScheduleItem) : null;
          if (restoredItems) {
            state.scheduleItems = restoredItems.sort(compareScheduleItems);
            state.scheduleRevision += 1;
            state.scheduleRestoreCount += 1;
            appendScheduleJournal(state, "restore_backup", latest.filename);
            persistState();
          }
          return jsonResponse({
            ok: true,
            data: {
              data: {
                restored: Boolean(restoredItems),
                restored_from: latest?.filename ?? null,
                restore_count: state.scheduleRestoreCount,
                items: filterScheduleItems(state.scheduleItems, body.params?.view),
                stats: scheduleStats(state.scheduleItems),
                timeline: scheduleTimeline(state.scheduleItems),
                storage: scheduleStorageMetadata(state),
                transaction: scheduleTransaction("restore", state, restoredItems?.length ?? 0),
                backups: state.scheduleBackups,
                journal: state.scheduleJournal,
                source: "host files broker + sqlite restore",
                health: scheduleStorageHealth(state),
                schema: scheduleSchemaSummary(),
                persisted: Boolean(restoredItems),
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
                detected_locations: state.weatherDetectedLocations,
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
                detected_locations: state.weatherDetectedLocations,
                source: "plugin settings storage",
                saved: true,
              },
            },
          });
        case "weather.location.detect": {
          const detected = await fetchDetectedLocationPayload(state.weatherFetches + 1, { networkBaseURL, networkFetch });
          state.weatherLocation = normalizeLocation(detected.location);
          state.weatherSavedLocations = rememberLocation(state.weatherSavedLocations, state.weatherLocation);
          state.weatherDetectedLocations = rememberDetectedLocation(state.weatherDetectedLocations, detected);
          state.weatherNetworkEvents = rememberWeatherNetworkEvent(state.weatherNetworkEvents, detected.network);
          persistState();
          return jsonResponse({
            ok: true,
            data: {
              data: {
                ...detected,
                saved_locations: state.weatherSavedLocations,
                detected_locations: state.weatherDetectedLocations,
                network_history: state.weatherNetworkEvents,
                source: "host network broker",
              },
            },
          });
        }
        case "weather.fetch": {
          const location = normalizeLocation(body.params?.location ?? state.weatherLocation);
          state.weatherLocation = location;
          state.weatherSavedLocations = rememberLocation(state.weatherSavedLocations, location);
          state.weatherFetches += 1;
          const payload = await fetchWeatherPayload(location, state.weatherFetches, { networkBaseURL, networkFetch });
          state.weatherNetworkEvents = rememberWeatherNetworkEvent(state.weatherNetworkEvents, payload.network);
          state.weatherLastPayload = payload;
          payload.network_history = state.weatherNetworkEvents;
          payload.saved_locations = state.weatherSavedLocations;
          payload.detected_locations = state.weatherDetectedLocations;
          persistState();
          return jsonResponse({
            ok: true,
            data: {
              data: payload,
            },
          });
        }
        case "weather.parser.explain": {
          const location = normalizeLocation(body.params?.location ?? state.weatherLocation);
          state.weatherLocation = location;
          state.weatherSavedLocations = rememberLocation(state.weatherSavedLocations, location);
          state.weatherFetches += 1;
          state.weatherParserRuns += 1;
          const payload = await fetchWeatherPayload(location, state.weatherFetches, { networkBaseURL, networkFetch });
          state.weatherLastPayload = payload;
          state.weatherNetworkEvents = rememberWeatherNetworkEvent(state.weatherNetworkEvents, payload.network);
          const explanation = createWeatherParserExplanation(payload, state.weatherParserRuns);
          payload.network_history = state.weatherNetworkEvents;
          payload.saved_locations = state.weatherSavedLocations;
          payload.detected_locations = state.weatherDetectedLocations;
          persistState();
          return jsonResponse({
            ok: true,
            data: {
              data: {
                ...payload,
                parser_explanation: explanation,
                source: "host network broker + sandbox JSON parser",
              },
            },
          });
        }
        case "weather.saved.compare": {
          const locations = state.weatherSavedLocations.slice(0, 4);
          const comparisons = [];
          for (const location of locations) {
            state.weatherFetches += 1;
            const payload = await fetchWeatherPayload(location, state.weatherFetches, { networkBaseURL, networkFetch });
            state.weatherNetworkEvents = rememberWeatherNetworkEvent(state.weatherNetworkEvents, payload.network);
            comparisons.push(payload);
          }
          persistState();
          return jsonResponse({
            ok: true,
            data: {
              data: {
                comparisons,
                saved_locations: state.weatherSavedLocations,
                detected_locations: state.weatherDetectedLocations,
                network_history: state.weatherNetworkEvents,
                source: "host network broker",
              },
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
    gameEvents: [],
    gameLastRun: null,
    gameSaves: 0,
    gameSnapshots: [],
    gameChallenges: [],
    gameReplayExports: [],
    scheduleRevision: 1,
    scheduleRestoreCount: 0,
    scheduleJournal: [
      { action: "init", detail: "seed fixture", revision: 1, at: "2026-06-30T00:00:00Z" },
    ],
    scheduleBackups: [],
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
    weatherDetectedLocations: [],
    weatherNetworkEvents: [],
    weatherFetches: 0,
    weatherParserRuns: 0,
    weatherLastPayload: null,
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
  if (Array.isArray(persisted.gameEvents)) {
    state.gameEvents = persisted.gameEvents.map(normalizeGameEvent).slice(0, 8);
  }
  if (Number.isFinite(Number(persisted.gameSaves))) {
    state.gameSaves = Math.max(0, Math.round(Number(persisted.gameSaves)));
  }
  if (Array.isArray(persisted.gameSnapshots)) {
    state.gameSnapshots = persisted.gameSnapshots.map(normalizeGameSnapshot).slice(0, 5);
  }
  if (Array.isArray(persisted.gameChallenges)) {
    state.gameChallenges = persisted.gameChallenges.map(normalizeGameChallenge).slice(0, 5);
  }
  if (Array.isArray(persisted.gameReplayExports)) {
    state.gameReplayExports = persisted.gameReplayExports.map(normalizeGameReplayExport).slice(0, 4);
  }
  if (Array.isArray(persisted.scheduleItems)) {
    state.scheduleItems = persisted.scheduleItems.map(normalizePersistedScheduleItem).sort(compareScheduleItems);
  }
  if (Array.isArray(persisted.scheduleJournal)) {
    state.scheduleJournal = persisted.scheduleJournal.map(normalizeJournalEntry).slice(0, 8);
  }
  if (Array.isArray(persisted.scheduleBackups)) {
    state.scheduleBackups = persisted.scheduleBackups.map(normalizeScheduleBackup).slice(0, 5);
  }
  if (Number.isFinite(Number(persisted.scheduleRevision))) {
    state.scheduleRevision = Math.max(1, Math.round(Number(persisted.scheduleRevision)));
  }
  if (Number.isFinite(Number(persisted.scheduleRestoreCount))) {
    state.scheduleRestoreCount = Math.max(0, Math.round(Number(persisted.scheduleRestoreCount)));
  }
  if (typeof persisted.weatherLocation === "string") {
    state.weatherLocation = normalizeLocation(persisted.weatherLocation);
  }
  if (Array.isArray(persisted.weatherSavedLocations)) {
    state.weatherSavedLocations = persisted.weatherSavedLocations.map(normalizeLocation).slice(0, 6);
  }
  if (Array.isArray(persisted.weatherDetectedLocations)) {
    state.weatherDetectedLocations = persisted.weatherDetectedLocations.map(normalizeDetectedLocation).slice(0, 5);
  }
  if (Array.isArray(persisted.weatherNetworkEvents)) {
    state.weatherNetworkEvents = persisted.weatherNetworkEvents.map(normalizeWeatherNetworkEvent).slice(0, 6);
  }
  if (Number.isFinite(Number(persisted.weatherParserRuns))) {
    state.weatherParserRuns = Math.max(0, Math.round(Number(persisted.weatherParserRuns)));
  }
  if (isRecord(persisted.weatherLastPayload)) {
    state.weatherLastPayload = persisted.weatherLastPayload;
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

function createSprintPlanItems(revision) {
  const base = [
    ["2026-07-13", "09:40", "Plugin runtime profiling", "runtime", "high", 45],
    ["2026-07-13", "13:10", "Storage broker quota drill", "storage", "high", 50],
    ["2026-07-14", "11:00", "Network connector fixture replay", "network", "medium", 35],
    ["2026-07-15", "15:30", "Sandbox iframe accessibility pass", "ui", "medium", 40],
  ];
  return base.map(([date, time, title, tag, priority, duration], index) => ({
    id: `sched-sprint-${revision}-${index}`,
    title,
    date,
    time,
    tag,
    priority,
    duration_minutes: duration,
    notes: "Inserted by one simulated SQLite transaction from the backend worker path.",
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
  const tagLoad = items.reduce((acc, item) => {
    acc[item.tag] = (acc[item.tag] ?? 0) + 1;
    return acc;
  }, {});
  const next = open.slice().sort(compareScheduleItems)[0] ?? null;
  return {
    total: items.length,
    open: open.length,
    done,
    planned_minutes: minutes,
    tags,
    tag_load: tagLoad,
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

function normalizeGameChallenge(params = {}) {
  return {
    id: String(params.id || `challenge-${Date.now().toString(36)}`).slice(0, 80),
    score: Math.max(0, Math.round(Number(params.score ?? 0))),
    storm_level: Math.max(1, Math.round(Number(params.storm_level ?? params.level ?? 1))),
    waves_survived: Math.max(0, Math.round(Number(params.waves_survived ?? 0))),
    max_combo: Math.max(0, Math.round(Number(params.max_combo ?? params.combo ?? 0))),
    bricks_cleared: Math.max(0, Math.round(Number(params.bricks_cleared ?? 0))),
    powerups_collected: Math.max(0, Math.round(Number(params.powerups_collected ?? 0))),
    peak_speed: Math.max(1, Number(params.peak_speed ?? 1)),
    duration_ms: Math.max(0, Math.round(Number(params.duration_ms ?? 0))),
    completed: Boolean(params.completed),
    saved_at: typeof params.saved_at === "string" ? params.saved_at : new Date().toISOString(),
  };
}

function normalizeGameTelemetry(params = {}) {
  return {
    events: Array.isArray(params.events) ? params.events.map(normalizeGameEvent).slice(0, 8) : [],
    peak_speed: Math.max(1, Number(params.peak_speed ?? 1)),
    duration_ms: Math.max(0, Math.round(Number(params.duration_ms ?? 0))),
    canvas_size: String(params.canvas_size || "860x420").slice(0, 24),
  };
}

function normalizeGameReplayExport(params = {}) {
  return {
    id: String(params.id || `replay-${Date.now().toString(36)}`).slice(0, 80),
    filename: String(params.filename || "game/replays/latest.replay.json").slice(0, 140),
    score: Math.max(0, Math.round(Number(params.score ?? 0))),
    level: Math.max(1, Math.round(Number(params.level ?? 1))),
    frame_count: Math.max(1, Math.round(Number(params.frame_count ?? 1))),
    max_combo: Math.max(0, Math.round(Number(params.max_combo ?? params.combo ?? 0))),
    size_bytes: Math.max(128, Math.round(Number(params.size_bytes ?? 128))),
    checksum: String(params.checksum || "sha256:game-replay-demo").slice(0, 96),
    created_at: typeof params.created_at === "string" ? params.created_at : new Date().toISOString(),
  };
}

function createGameReplayExport(state, params = {}) {
  const run = normalizeGameRun(params?.run ?? state.gameLastRun ?? params ?? {});
  const frameCount = Math.max(90, Math.round(Number(params.frame_count ?? run.duration_ms / 16.6 ?? 180)));
  return normalizeGameReplayExport({
    id: `replay-${Date.now().toString(36)}`,
    filename: `game/replays/run-${String(state.gameReplayExports.length + 1).padStart(2, "0")}.replay.json`,
    score: run.score,
    level: run.level,
    frame_count: frameCount,
    max_combo: run.combo,
    size_bytes: 768 + frameCount * 18,
    checksum: `sha256:replay${String(run.score).padStart(4, "0")}${String(frameCount).padStart(4, "0")}`,
    created_at: new Date().toISOString(),
  });
}

function normalizeGameEvent(event = {}) {
  return {
    label: String(event.label || "runtime event").slice(0, 80),
    tone: String(event.tone || "default").slice(0, 24),
    score: Math.max(0, Math.round(Number(event.score ?? 0))),
    level: Math.max(1, Math.round(Number(event.level ?? 1))),
    combo: Math.max(0, Math.round(Number(event.combo ?? 0))),
    at: typeof event.at === "string" ? event.at : "2026-06-30T00:00:00Z",
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
  if (Number(run.waves_survived ?? 0) >= 3) {
    achievements.push("storm-runner");
  }
  return achievements;
}

function gameMission(run) {
  if (!run || run.bricks_cleared < 8) {
    return {
      key: "clear",
      title: "Break the front line",
      detail: "Clear eight bricks before syncing the run.",
    };
  }
  if (run.combo < 6) {
    return {
      key: "combo",
      title: "Build combo heat",
      detail: "Keep rebounds alive until combo reaches six.",
    };
  }
  return {
    key: "sync",
    title: "Bank the run",
    detail: "Sync the current run to host-backed plugin storage.",
  };
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

function scheduleTransaction(mode, state, rowsChanged) {
  const rows = Math.max(0, Math.round(Number(rowsChanged ?? 0)));
  const table = ["backup", "restore"].includes(mode) ? "schedule_backups" : "schedule_items";
  const sqlByMode = {
    read: "SELECT * FROM schedule_items ORDER BY date, time",
    insert: "INSERT INTO schedule_items (...) VALUES (...)",
    update: "UPDATE schedule_items SET done = ? WHERE id = ?",
    delete: "DELETE FROM schedule_items WHERE id = ?",
    bulk_insert: "INSERT INTO schedule_items SELECT * FROM json_each(?)",
    bulk_delete: "DELETE FROM schedule_items WHERE done = true",
    backup: "INSERT INTO schedule_backups (...) VALUES (...)",
    inspect: "PRAGMA table_info(schedule_items); SELECT count(*) FROM schedule_items",
    restore: "BEGIN IMMEDIATE; DELETE FROM schedule_items; INSERT INTO schedule_items SELECT * FROM json_each(?); COMMIT",
  };
  return {
    engine: "sqlite-demo",
    mode,
    table,
    sql_preview: sqlByMode[mode] ?? "BEGIN IMMEDIATE; COMMIT;",
    revision: state.scheduleRevision,
    rows_changed: rows,
    bytes_written: rows === 0 ? 0 : 512 + rows * 192,
    journal_mode: "wal",
    committed_at: new Date().toISOString(),
  };
}

function createScheduleBackup(state) {
  const backup = {
    id: `backup-${state.scheduleRevision}-${Date.now().toString(36)}`,
    filename: `schedule/snapshots/rev-${state.scheduleRevision}.json`,
    item_count: state.scheduleItems.length,
    journal_count: state.scheduleJournal.length,
    size_bytes: 640 + state.scheduleItems.length * 284 + state.scheduleJournal.length * 96,
    checksum: `sha256:${String(state.scheduleRevision).padStart(2, "0")}demo${String(state.scheduleItems.length).padStart(2, "0")}`,
    created_at: new Date().toISOString(),
    item_snapshot: state.scheduleItems.map(normalizePersistedScheduleItem),
  };
  return normalizeScheduleBackup(backup);
}

function normalizeScheduleBackup(backup = {}) {
  return {
    id: String(backup.id || `backup-${Date.now().toString(36)}`).slice(0, 80),
    filename: String(backup.filename || "schedule/snapshots/latest.json").slice(0, 140),
    item_count: Math.max(0, Math.round(Number(backup.item_count ?? 0))),
    journal_count: Math.max(0, Math.round(Number(backup.journal_count ?? 0))),
    size_bytes: Math.max(0, Math.round(Number(backup.size_bytes ?? 0))),
    checksum: String(backup.checksum || "sha256:demo").slice(0, 96),
    created_at: typeof backup.created_at === "string" ? backup.created_at : "2026-06-30T00:00:00Z",
    item_snapshot: Array.isArray(backup.item_snapshot) ? backup.item_snapshot.map(normalizePersistedScheduleItem).slice(0, 200) : [],
  };
}

function scheduleStorageHealth(state) {
  const storage = scheduleStorageMetadata(state);
  const usageRatio = storage.quota_bytes > 0 ? storage.used_bytes / storage.quota_bytes : 0;
  return {
    status: usageRatio > 0.9 ? "quota-warning" : "healthy",
    wal_checkpoint: "clean",
    restores: state.scheduleRestoreCount,
    last_backup: state.scheduleBackups[0]?.filename ?? null,
    quota_percent: Math.round(usageRatio * 100),
  };
}

function scheduleSchemaSummary() {
  return {
    database: "plugin.sqlite",
    tables: [
      { name: "schedule_items", columns: 9, indexes: ["idx_schedule_time", "idx_schedule_tag"] },
      { name: "schedule_journal", columns: 4, indexes: ["idx_schedule_journal_revision"] },
      { name: "schedule_backups", columns: 6, indexes: ["idx_schedule_backup_created"] },
    ],
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

function rememberDetectedLocation(locations, detected) {
  const normalized = normalizeDetectedLocation(detected);
  const next = [
    normalized,
    ...locations.filter((candidate) => candidate.location.toLowerCase() !== normalized.location.toLowerCase()),
  ];
  return next.slice(0, 5);
}

function normalizeDetectedLocation(value = {}) {
  return {
    location: normalizeLocation(value.location),
    confidence: Math.max(0, Math.min(1, Number(value.confidence ?? 0.92))),
    source: String(value.source || "network geolocation broker").slice(0, 80),
    latitude: Number(value.latitude ?? 37.7749),
    longitude: Number(value.longitude ?? -122.4194),
    detected_at: typeof value.detected_at === "string" ? value.detected_at : "2026-06-30T00:00:00Z",
  };
}

async function fetchDetectedLocationPayload(fetchCount = 1, options = {}) {
  if (typeof options.networkFetch !== "function" || !options.networkBaseURL) {
    return createDetectedLocationPayload(fetchCount);
  }
  const upstreamURL = new URL("/demo/weather-api/v1/geolocate", options.networkBaseURL);
  upstreamURL.searchParams.set("fetch_count", String(fetchCount));

  const startedAt = Date.now();
  const response = await options.networkFetch(upstreamURL.href, {
    method: "GET",
    headers: {
      accept: "application/json",
      "x-redevplugin-connector": "weather_geolocation",
    },
  });
  const rawResponseBody = await response.text();
  let rawPayload;
  try {
    rawPayload = JSON.parse(rawResponseBody);
  } catch {
    rawPayload = createWeatherGeolocationPayload(fetchCount);
  }
  return createDetectedLocationPayloadFromRaw(rawPayload, rawResponseBody, {
    brokerEndpoint: upstreamURL.href,
    latencyMs: Math.max(1, Date.now() - startedAt),
    responseHeaders: headersToObject(response.headers),
    responseStatus: response.status,
    upstreamMode: "host http fetch",
  });
}

function createDetectedLocationPayload(fetchCount = 1) {
  const rawPayload = createWeatherGeolocationPayload(fetchCount);
  return createDetectedLocationPayloadFromRaw(rawPayload, JSON.stringify(rawPayload), {
    latencyMs: 30 + fetchCount,
    responseHeaders: { "content-type": "application/json" },
    responseStatus: 200,
    upstreamMode: "in-memory fixture",
  });
}

export function createWeatherGeolocationPayload(fetchCount = 1) {
  const candidates = [
    { location: "San Francisco", latitude: 37.7749, longitude: -122.4194, confidence: 0.94, source: "demo network geoip" },
    { location: "Tokyo", latitude: 35.6762, longitude: 139.6503, confidence: 0.88, source: "demo network browser hint" },
    { location: "London", latitude: 51.5072, longitude: -0.1276, confidence: 0.91, source: "demo network region" },
  ];
  return {
    ...candidates[Math.max(0, fetchCount - 1) % candidates.length],
    detected_at: "2026-06-30T08:00:03Z",
  };
}

function createDetectedLocationPayloadFromRaw(rawPayload, rawResponseBody, network) {
  const normalized = normalizeDetectedLocation(rawPayload);
  return {
    ...normalized,
    network: {
      connector_id: "weather_geolocation",
      transport: "http",
      operation: "GET /v1/geolocate",
      destination: "https://geo.weather.example",
      broker_endpoint: network.brokerEndpoint ?? "in-memory://weather-api/v1/geolocate",
      request_headers: {
        accept: "application/json",
        "x-redevplugin-connector": "weather_geolocation",
      },
      response_status: network.responseStatus ?? 200,
      response_headers: network.responseHeaders ?? {},
      latency_ms: network.latencyMs ?? 0,
      bytes_received: rawResponseBody.length,
      parsed: true,
      upstream_mode: network.upstreamMode ?? "unknown",
    },
    raw_response_body: rawResponseBody,
    parser: {
      format: "json",
      fields: ["location", "latitude", "longitude", "confidence", "source"],
    },
  };
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

function createWeatherParserExplanation(payload, run) {
  const parsed = safeParseJSON(payload.raw_response_body);
  const fields = [
    ["current.temperature_c", "raw.current.temperature_c", parsed.current?.temperature_c],
    ["current.condition", "raw.current.condition", parsed.current?.condition],
    ["current.wind_kph", "raw.current.wind_kph", parsed.current?.wind_kph],
    ["current.humidity_percent", "raw.current.humidity_percent", parsed.current?.humidity_percent],
    ["air_quality.aqi", "raw.air_quality.aqi", parsed.air_quality?.aqi],
    ["forecast[]", "raw.forecast", Array.isArray(parsed.forecast) ? `${parsed.forecast.length} days` : "missing"],
    ["hourly[]", "raw.hourly", Array.isArray(parsed.hourly) ? `${parsed.hourly.length} points` : "missing"],
  ];
  return {
    run,
    quality: fields.every(([, , value]) => value !== undefined && value !== "missing") ? "valid-json" : "partial-json",
    field_count: fields.length,
    steps: fields.map(([field, source, value]) => ({
      field,
      source,
      value: String(value ?? "null"),
    })),
  };
}

function safeParseJSON(raw) {
  try {
    return JSON.parse(String(raw ?? "{}"));
  } catch {
    return {};
  }
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

function resetDemoDocumentScroll() {
  if (typeof window === "undefined" || typeof window.scrollTo !== "function") {
    return;
  }
  requestAnimationFrame(() => {
    window.scrollTo(0, 0);
  });
}
