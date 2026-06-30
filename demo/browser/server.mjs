import { createReadStream, existsSync, statSync } from "node:fs";
import { createServer } from "node:http";
import { extname, normalize, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { createWeatherAPIPayload } from "./demo-platform.mjs";

const root = resolve(fileURLToPath(new URL("../..", import.meta.url)));
const extraPluginRoot = process.env.EXTRA_PLUGIN_ROOT ? resolve(process.env.EXTRA_PLUGIN_ROOT) : "";
const hostPort = Number(process.env.HOST_PORT || process.env.PORT || 4173);
const pluginPort = Number(process.env.PLUGIN_PORT || hostPort + 1);

const contentTypes = new Map([
  [".html", "text/html; charset=utf-8"],
  [".css", "text/css; charset=utf-8"],
  [".js", "text/javascript; charset=utf-8"],
  [".mjs", "text/javascript; charset=utf-8"],
  [".json", "application/json; charset=utf-8"],
]);

function createDemoServer(label) {
  return createServer((request, response) => {
    serveStatic(label, request, response);
  });
}

function serveStatic(label, request, response) {
  const requestURL = new URL(request.url ?? "/", `http://${request.headers.host ?? "127.0.0.1"}`);
  if (requestURL.pathname === "/_redevplugin/stream/demo_stream_logs") {
    serveDemoStream(request, requestURL, response);
    return;
  }
  if (requestURL.pathname === "/demo/weather-api/v1/forecast") {
    serveWeatherAPI(requestURL, response);
    return;
  }
  let pathname = decodeURIComponent(requestURL.pathname);
  if (pathname === "/") {
    pathname = "/demo/browser/index.html";
  }
  if (extraPluginRoot && pathname.startsWith("/generated-plugin/")) {
    const rel = normalize(pathname.slice("/generated-plugin/".length)).replace(/^[/\\]+/, "");
    const filename = resolve(extraPluginRoot, rel);
    if (filename !== extraPluginRoot && !filename.startsWith(extraPluginRoot + sep)) {
      response.writeHead(403);
      response.end("forbidden");
      return;
    }
    serveFile(filename, label, response);
    return;
  }
  const filename = resolve(root, normalize(pathname).replace(/^[/\\]+/, ""));
  if (!filename.startsWith(root + sep)) {
    response.writeHead(403);
    response.end("forbidden");
    return;
  }
  serveFile(filename, label, response);
}

function serveFile(filename, label, response) {
  if (!existsSync(filename) || !statSync(filename).isFile()) {
    response.writeHead(404);
    response.end("not found");
    return;
  }
  response.writeHead(200, {
    "Cache-Control": "no-store",
    "Content-Type": contentTypes.get(extname(filename)) ?? "application/octet-stream",
    "X-ReDevPlugin-Demo-Origin": label,
  });
  createReadStream(filename).pipe(response);
}

function serveDemoStream(request, requestURL, response) {
  const ticket = requestURL.searchParams.get("ticket") ?? "";
  const origin = request.headers.origin ?? "";
  const corsHeaders = origin === `http://127.0.0.1:${pluginPort}` ? {
    "Access-Control-Allow-Origin": origin,
    "Vary": "Origin",
  } : {};
  if (!ticket.startsWith("demo_stream_ticket_")) {
    response.writeHead(403, {
      "Cache-Control": "no-store",
      "Content-Type": "application/json; charset=utf-8",
      ...corsHeaders,
    });
    response.end(JSON.stringify({ ok: false, error_code: "PLUGIN_PERMISSION_DENIED", error: "stream ticket is required" }));
    return;
  }
  response.writeHead(200, {
    "Cache-Control": "no-store",
    "Content-Type": "application/x-ndjson",
    "X-ReDevPlugin-Demo-Origin": "host",
    ...corsHeaders,
  });
  const events = [
    {
      stream_id: "demo_stream_logs",
      sequence: 1,
      kind: "data",
      data: Buffer.from("demo log line 1").toString("base64"),
      at: "2026-06-30T00:00:10Z",
    },
    {
      stream_id: "demo_stream_logs",
      sequence: 2,
      kind: "data",
      data: Buffer.from("demo log line 2").toString("base64"),
      at: "2026-06-30T00:00:11Z",
    },
  ];
  response.end(events.map((event) => JSON.stringify(event)).join("\n") + "\n");
}

function serveWeatherAPI(requestURL, response) {
  const location = requestURL.searchParams.get("location") ?? "San Francisco";
  const fetchCount = Number(requestURL.searchParams.get("fetch_count") ?? 1);
  const payload = createWeatherAPIPayload(location);
  response.writeHead(200, {
    "Cache-Control": "no-store",
    "Content-Type": "application/json; charset=utf-8",
    "X-Demo-Weather-Fetch": Number.isFinite(fetchCount) && fetchCount % 2 === 0 ? "hit" : "miss",
    "X-ReDevPlugin-Demo-Origin": "host-network-broker",
  });
  response.end(JSON.stringify(payload));
}

const hostServer = createDemoServer("host");
const pluginServer = createDemoServer("plugin");

hostServer.listen(hostPort, "127.0.0.1", () => {
  console.log(`ReDevPlugin browser demo host: http://127.0.0.1:${hostPort}/demo/browser/index.html?plugin_origin=http://127.0.0.1:${pluginPort}`);
});

pluginServer.listen(pluginPort, "127.0.0.1", () => {
  console.log(`ReDevPlugin browser demo plugin sandbox: http://127.0.0.1:${pluginPort}/demo/browser/plugin.html`);
});

function shutdown() {
  hostServer.close();
  pluginServer.close();
}

process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);
