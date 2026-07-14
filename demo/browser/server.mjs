import { createHash } from "node:crypto";
import { createReadStream, existsSync, readFileSync, statSync } from "node:fs";
import { createServer } from "node:http";
import { extname, normalize, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(fileURLToPath(new URL("../..", import.meta.url)));
const generatedWorkerPath = resolve(root, "demo/browser/generated/opaque-plugin-worker.js");
const lazyAssetBytes = Buffer.concat([
  Buffer.from("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=", "base64"),
  Buffer.alloc(384 * 1024),
]);
const lazyAssetBase64 = lazyAssetBytes.toString("base64");
const entrySHA256 = digest("opaque-browser-entry-v1");
const workerSHA256 = digestBytes(readFileSync(generatedWorkerPath));
const styleContent = `
:root { color: #15232a; background: #ffffff; font-family: Inter, ui-sans-serif, system-ui, sans-serif; }
* { box-sizing: border-box; }
body { margin: 0; min-height: 100vh; }
.plugin-surface { display: grid; gap: 14px; min-height: 100vh; align-content: start; padding: 24px; }
.eyebrow { margin: 0; color: #597078; font-size: 11px; font-weight: 700; text-transform: uppercase; }
h1, h2 { margin: 0; letter-spacing: 0; }
h1 { font-size: 25px; }
h2 { margin-top: 8px; font-size: 15px; }
.status { margin: 0; color: #1d5e55; font-weight: 650; }
.button-row { display: flex; flex-wrap: wrap; gap: 9px; }
button { min-height: 36px; border: 1px solid #1d5e55; border-radius: 6px; padding: 0 13px; color: #fff; background: #1d5e55; font: inherit; cursor: pointer; }
button:disabled { cursor: not-allowed; opacity: .55; }
pre { max-width: 100%; margin: 0; padding: 13px; overflow: auto; border: 1px solid #d9dfe2; background: #f6f8f9; font-size: 11px; line-height: 1.5; white-space: pre-wrap; }
/* ${"x".repeat(384 * 1024)} */`;
const styleSHA256 = digestBytes(Buffer.from(styleContent));
const assetSHA256 = digestBytes(lazyAssetBytes);

const contentTypes = new Map([
  [".html", "text/html; charset=utf-8"],
  [".css", "text/css; charset=utf-8"],
  [".js", "text/javascript; charset=utf-8"],
  [".mjs", "text/javascript; charset=utf-8"],
  [".json", "application/json; charset=utf-8"],
]);

export function createBrowserDemoServer(options = {}) {
  const prepareDelayMs = options.prepareDelayMs ?? 420;
  const assetDelayMs = options.assetDelayMs ?? 750;
  const surfaces = new Map();
  const diagnostics = {
    requests: [],
    latest_surface_id: "",
    prepare_started_at: 0,
    prepare_completed_at: 0,
    asset_started_at: 0,
    asset_completed_at: 0,
    dispose_completed_at: 0,
  };
  let sequence = 0;

  const server = createServer(async (request, response) => {
    const requestURL = new URL(request.url ?? "/", `http://${request.headers.host ?? "127.0.0.1"}`);
    diagnostics.requests.push(`${request.method ?? "GET"} ${requestURL.pathname}`);
    if (diagnostics.requests.length > 80) diagnostics.requests.shift();
    try {
      if (requestURL.pathname === "/demo/browser/diagnostics" && request.method === "GET") {
        writeJSON(response, diagnostics);
        return;
      }
      if (requestURL.pathname === "/_redevplugin/api/plugins/surfaces/open" && request.method === "POST") {
        await readJSONBody(request);
        sequence += 1;
        const surfaceID = `surface_browser_${String(sequence).padStart(4, "0")}`;
        const surface = {
          id: surfaceID,
          assetTicket: `parent_asset_ticket_${sequence}`,
          assetSession: `parent_asset_session_${sequence}`,
          assetSessionID: `asset_session_id_${sequence}`,
          assetSessionNonce: `asset_session_nonce_${sequence}`,
          bridgeNonce: `bridge_nonce_${sequence}`,
          gatewayToken: "",
          gatewayTokenID: "",
          leaseVersion: 0,
          streamTicket: `parent_stream_ticket_${sequence}`,
          streamReadCount: 0,
          confirmationID: `confirmation_${sequence}`,
          disposed: false,
        };
        surfaces.set(surfaceID, surface);
        diagnostics.latest_surface_id = surfaceID;
        diagnostics.prepare_started_at = 0;
        diagnostics.prepare_completed_at = 0;
        diagnostics.asset_started_at = 0;
        diagnostics.asset_completed_at = 0;
        diagnostics.dispose_completed_at = 0;
        writeEnvelope(response, {
          plugin_id: "dev.redevplugin.opaque-browser",
          plugin_instance_id: "plugin_browser_demo_1",
          plugin_version: "0.2.0",
          surface_id: "dev.redevplugin.opaque-browser.view",
          surface_instance_id: surfaceID,
          active_fingerprint: digest(`active-${sequence}`),
          entry_path: "ui/index.html",
          entry_sha256: entrySHA256,
          asset_session_nonce: surface.assetSessionNonce,
          plugin_state_version: 1,
          revoke_epoch: 1,
          runtime_generation_id: "runtime_browser_demo_1",
          asset_ticket: surface.assetTicket,
          asset_ticket_id: `asset_ticket_id_${sequence}`,
          bridge_nonce: surface.bridgeNonce,
          issued_at: new Date().toISOString(),
          expires_at: new Date(Date.now() + 15_000).toISOString(),
        });
        return;
      }

      const surfaceRoute = matchSurfaceRoute(requestURL.pathname);
      if (surfaceRoute) {
        const surface = surfaces.get(surfaceRoute.surfaceID);
        if (!surface || surface.disposed) {
          writeError(response, 410, "PLUGIN_GATEWAY_TOKEN_INVALID", "surface is unavailable");
          return;
        }
        const body = await readJSONBody(request);
        if (surfaceRoute.action === "prepare" && request.method === "POST") {
          if (body.asset_ticket !== surface.assetTicket) {
            writeError(response, 403, "PLUGIN_ASSET_TICKET_INVALID", "asset ticket is invalid");
            return;
          }
          diagnostics.prepare_started_at = Date.now();
          await delay(prepareDelayMs);
          diagnostics.prepare_completed_at = Date.now();
          const workerContent = readFileSync(generatedWorkerPath, "utf8");
          const issuedAt = new Date();
          writeEnvelope(response, {
            asset_session: surface.assetSession,
            asset_session_id: surface.assetSessionID,
            asset_session_nonce: surface.assetSessionNonce,
            entry_path: "ui/index.html",
            entry_sha256: entrySHA256,
            plugin_state_version: 1,
            revoke_epoch: 1,
            issued_at: issuedAt.toISOString(),
            expires_at: new Date(issuedAt.getTime() + 10 * 60_000).toISOString(),
            document: {
              schema_version: "redevplugin.opaque_surface_document.v1",
              entry_path: "ui/index.html",
              entry_sha256: entrySHA256,
              title: "Opaque browser demo",
              language: "en",
              direction: "ltr",
              body_html: '<main class="plugin-surface"><p id="critical-paint" class="status">Critical document painted</p><img alt="Lazy asset" data-redevplugin-asset-binding="asset_demo_lazy_1" data-redevplugin-asset-attr="src"></main>',
              styles: [{ path: "ui/styles.css", sha256: styleSHA256, content: styleContent }],
              worker: { path: "ui/worker.js", sha256: workerSHA256, type: "classic", content: workerContent },
              assets: [{ binding_id: "asset_demo_lazy_1", path: "ui/lazy.png", sha256: assetSHA256, size: lazyAssetBytes.length, content_type: "image/png" }],
              critical_bytes: Buffer.byteLength(workerContent) + Buffer.byteLength(styleContent) + 240,
            },
          });
          return;
        }
        if (surfaceRoute.action === "bridge-token" && request.method === "POST") {
          if (body.handshake?.surface_instance_id !== surface.id || body.handshake?.bridge_nonce !== surface.bridgeNonce) {
            writeError(response, 403, "PLUGIN_BRIDGE_HANDSHAKE_FAILED", "bridge handshake is invalid");
            return;
          }
          if ((surface.leaseVersion === 0 && body.previous_plugin_gateway_token) ||
              (surface.leaseVersion > 0 && body.previous_plugin_gateway_token !== surface.gatewayToken)) {
            writeError(response, 403, "PLUGIN_GATEWAY_TOKEN_INVALID", "previous gateway token is invalid");
            return;
          }
          surface.leaseVersion += 1;
          surface.gatewayToken = `parent_gateway_token_${sequence}_${surface.leaseVersion}`;
          surface.gatewayTokenID = `gateway_token_id_${sequence}_${surface.leaseVersion}`;
          surface.assetSession = `parent_asset_session_${sequence}_${surface.leaseVersion}`;
          surface.assetSessionID = `asset_session_id_${sequence}_${surface.leaseVersion}`;
          const issuedAt = new Date();
          writeEnvelope(response, {
            plugin_gateway_token: surface.gatewayToken,
            plugin_gateway_token_id: surface.gatewayTokenID,
            asset_session: surface.assetSession,
            asset_session_id: surface.assetSessionID,
            issued_at: issuedAt.toISOString(),
            expires_at: new Date(issuedAt.getTime() + 10 * 60_000).toISOString(),
          });
          return;
        }
        if (surfaceRoute.action === "assets/read" && request.method === "POST") {
          if (body.asset_session !== surface.assetSession || body.asset_session_id !== surface.assetSessionID || body.binding_id !== "asset_demo_lazy_1") {
            writeError(response, 403, "PLUGIN_ASSET_SESSION_INVALID", "asset session is invalid");
            return;
          }
          diagnostics.asset_started_at = Date.now();
          await delay(assetDelayMs);
          diagnostics.asset_completed_at = Date.now();
          writeEnvelope(response, {
            path: "ui/lazy.png",
            sha256: assetSHA256,
            content_type: "image/png",
            content_base64: lazyAssetBase64,
          });
          return;
        }
        if (surfaceRoute.action === "streams/read" && request.method === "POST") {
          if (body.stream_id !== "stream_demo_logs" || body.stream_ticket !== surface.streamTicket) {
            writeError(response, 403, "PLUGIN_STREAM_TICKET_INVALID", "stream credential is invalid");
            return;
          }
          if (surface.streamReadCount === 0) {
            surface.streamReadCount = 1;
            surface.streamTicket = `parent_stream_ticket_${sequence}_2`;
            writeEnvelope(response, {
              events: [
                { stream_id: "stream_demo_logs", sequence: 1, kind: "data", data: Buffer.from("opaque log line 1\n").toString("base64"), at: "2026-07-12T00:00:01Z" },
              ],
              done: false,
              next_stream_ticket: surface.streamTicket,
              next_stream_ticket_id: "stream_ticket_id_parent_only_2",
              next_stream_expires_at: new Date(Date.now() + 60_000).toISOString(),
            });
            return;
          }
          surface.streamReadCount = 2;
          writeEnvelope(response, {
            events: [
              { stream_id: "stream_demo_logs", sequence: 2, kind: "data", data: Buffer.from("opaque log line 2\n").toString("base64"), at: "2026-07-12T00:00:02Z" },
              { stream_id: "stream_demo_logs", sequence: 3, kind: "end", at: "2026-07-12T00:00:03Z" },
            ],
            done: true,
            terminal_status: "closed",
          });
          return;
        }
        if (surfaceRoute.action === "dispose" && request.method === "POST") {
          if (body.bridge_nonce !== surface.bridgeNonce) {
            writeError(response, 403, "PLUGIN_GATEWAY_TOKEN_INVALID", "surface generation is invalid");
            return;
          }
          surface.disposed = true;
          diagnostics.dispose_completed_at = Date.now();
          writeEnvelope(response, { disposed: true });
          return;
        }
      }

      if (requestURL.pathname === "/_redevplugin/api/plugins/rpc" && request.method === "POST") {
        const body = await readJSONBody(request);
        const surface = surfaces.get(body.surface_instance_id);
        if (!surface || surface.disposed || body.plugin_gateway_token !== surface.gatewayToken) {
          writeError(response, 403, "PLUGIN_GATEWAY_TOKEN_INVALID", "plugin gateway token is invalid");
          return;
        }
        if (body.method === "demo.echo") {
          writeEnvelope(response, { data: { echoed: body.params?.message ?? "", transport: "typed MessagePort" } });
          return;
        }
        if (body.method === "demo.logs") {
          surface.streamReadCount = 0;
          surface.streamTicket = `parent_stream_ticket_${sequence}_1`;
          writeEnvelope(response, {
            data: { started: true },
            operation_id: "operation_demo_logs",
            stream_id: "stream_demo_logs",
            stream_ticket: surface.streamTicket,
            stream_ticket_id: "stream_ticket_id_parent_only",
            stream_expires_at: new Date(Date.now() + 60_000).toISOString(),
          });
          return;
        }
        if (body.method === "danger.run") {
          if (body.confirmation_id !== surface.confirmationID) {
            writeError(response, 409, "PLUGIN_CONFIRMATION_REQUIRED", "confirmation is required");
            return;
          }
          writeEnvelope(response, { data: { confirmed: true, target: body.params?.target ?? "" }, operation_id: "operation_demo_1" });
          return;
        }
        writeError(response, 404, "PLUGIN_INVALID_REQUEST", "unknown demo method");
        return;
      }

      if (requestURL.pathname === "/_redevplugin/api/plugins/confirm" && request.method === "POST") {
        const body = await readJSONBody(request);
        const surface = surfaces.get(body.surface_instance_id);
        if (!surface || body.plugin_gateway_token !== surface.gatewayToken || body.method !== "danger.run") {
          writeError(response, 403, "PLUGIN_CONFIRMATION_INVALID", "confirmation request is invalid");
          return;
        }
        writeEnvelope(response, {
          confirmation_id: surface.confirmationID,
          confirmation_token_id: "confirmation_token_id_parent_only",
          request_hash: digest("confirmation-request"),
          plan_hash: digest("confirmation-plan"),
          plan: {
            schema_version: "redevplugin.capability.risk_plan.v1",
            summary: "Run the demo dangerous action",
            risk_flags: [{ id: "demo-write", severity: "medium", summary: "Writes demo state", requires_confirmation: true }],
            requires_confirmation: true,
          },
          expires_at: "2026-07-12T00:05:00Z",
        });
        return;
      }

      serveStatic(requestURL.pathname, response);
    } catch (error) {
      writeError(response, 500, "PLUGIN_RUNTIME_UNAVAILABLE", String(error?.message || error));
    }
  });

  return {
    server,
    diagnostics,
    listen(port = 0, host = "127.0.0.1") {
      return new Promise((resolveListen, reject) => {
        server.once("error", reject);
        server.listen(port, host, () => {
          server.removeListener("error", reject);
          resolveListen(server.address());
        });
      });
    },
    close() {
      return new Promise((resolveClose, reject) => server.close((error) => error ? reject(error) : resolveClose()));
    },
  };
}

function matchSurfaceRoute(pathname) {
  const match = pathname.match(/^\/_redevplugin\/api\/plugins\/surfaces\/([^/]+)\/(prepare|bridge-token|assets\/read|streams\/read|dispose)$/);
  return match ? { surfaceID: decodeURIComponent(match[1]), action: match[2] } : null;
}

function serveStatic(rawPathname, response) {
  let pathname = decodeURIComponent(rawPathname);
  if (pathname === "/") pathname = "/demo/browser/index.html";
  const filename = resolve(root, normalize(pathname).replace(/^[/\\]+/, ""));
  if (filename !== root && !filename.startsWith(root + sep)) {
    response.writeHead(403, { "Cache-Control": "no-store" });
    response.end("forbidden");
    return;
  }
  if (!existsSync(filename) || !statSync(filename).isFile()) {
    response.writeHead(404, { "Cache-Control": "no-store" });
    response.end("not found");
    return;
  }
  response.writeHead(200, {
    "Cache-Control": "no-store",
    "Content-Type": contentTypes.get(extname(filename)) ?? "application/octet-stream",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), display-capture=(), usb=(), serial=()",
    "X-Content-Type-Options": "nosniff",
  });
  createReadStream(filename).pipe(response);
}

async function readJSONBody(request) {
  const chunks = [];
  let size = 0;
  for await (const chunk of request) {
    size += chunk.length;
    if (size > 1 << 20) throw new Error("request body exceeds 1 MiB");
    chunks.push(chunk);
  }
  if (chunks.length === 0) return {};
  return JSON.parse(Buffer.concat(chunks).toString("utf8"));
}

function writeEnvelope(response, data, status = 200) {
  writeJSON(response, { ok: true, data }, status);
}

function writeError(response, status, errorCode, error) {
  writeJSON(response, { ok: false, error_code: errorCode, error }, status);
}

function writeJSON(response, value, status = 200) {
  response.writeHead(status, {
    "Cache-Control": "no-store",
    "Content-Type": "application/json; charset=utf-8",
    "X-Content-Type-Options": "nosniff",
  });
  response.end(JSON.stringify(value));
}

function digest(value) {
  return digestBytes(Buffer.from(value));
}

function digestBytes(value) {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function delay(ms) {
  return new Promise((resolveDelay) => setTimeout(resolveDelay, ms));
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const port = Number(process.env.HOST_PORT || process.env.PORT || 4173);
  const demo = createBrowserDemoServer();
  await demo.listen(port);
  console.log(`ReDevPlugin opaque browser demo: http://127.0.0.1:${port}/demo/browser/index.html`);
  const shutdown = () => void demo.close().finally(() => process.exit(0));
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}
