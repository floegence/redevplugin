import { createReadStream, existsSync, statSync } from "node:fs";
import { createServer } from "node:http";
import { extname, normalize, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

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
