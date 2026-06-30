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
        default:
          return jsonResponse({ ok: false, error_code: "PLUGIN_METHOD_NOT_FOUND", error: `unknown method ${body.method}` }, 404);
      }
    }

    return jsonResponse({ ok: false, error_code: "PLUGIN_NOT_FOUND", error: `unknown demo endpoint ${url.pathname}` }, 404);
  }

  return { fetch, calls, state };
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
