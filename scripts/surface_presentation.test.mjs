import assert from "node:assert/strict";
import http from "node:http";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import test from "node:test";
import { build } from "esbuild";
import { chromium } from "playwright";
import { solidPlugin } from "./solid_build.mjs";

// The real bootstrap and example UI with a held business response. This isolates
// presentation from Worker latency; the Go Host browser suite owns containment.
const root = resolve(import.meta.dirname, "..");
const context = { schema_version: "redevplugin.surface_context.v1", revision: 1,
  appearance: { color_scheme: "dark", colors: { canvas: "#171b22", surface: "#20262f", surface_elevated: "#29313c", text: "#f3f4f6", text_muted: "#a8b0bd", border: "#59616e", accent: "#f3f4f6", accent_text: "#171b22", success: "#5db98b", warning: "#d8aa55", danger: "#e77676", focus: "#82aef0" } },
  locale: { language_tag: "en-US", direction: "ltr" } };

for (const fails of [false, true]) test(`Memos reveals a stable restored or failure view with the current theme (failure: ${fails})`, async () => {
  const bootstrap = await readFile(resolve(root, "pkg/httpadapter/web_surface_bootstrap.js"), "utf8");
  const bundle = await build({ entryPoints: [resolve(root, "examples/plugin-ui/memos.tsx")], plugins: [solidPlugin], conditions: ["browser"], bundle: true, format: "esm", platform: "browser", write: false });
  const html = await readFile(resolve(root, "examples/plugins/memos/ui/index.html"));
  const css = await readFile(resolve(root, "examples/plugins/memos/ui/assets/styles.css"));
  let parentOrigin, childOrigin;
  const server = http.createServer((req, res) => {
    const pathname = new URL(req.url, "http://localhost").pathname;
    if (pathname === "/parent") {
      res.setHeader("Content-Type", "text/html");
      res.end(`<!doctype html><style>html,body{margin:0;background:#171b22}iframe{width:1000px;height:740px;border:0;opacity:0}</style><script>
        window.events=[];addEventListener('message',event=>{
          if(event.origin!==${JSON.stringify(childOrigin)}||event.data.type!=='redevplugin.surface.entry_ready')return;
          const channel=new MessageChannel();window.bridge=channel.port1;
          bridge.onmessage=event=>{const data=event.data;events.push(data);
            if(data.type==='redevplugin.surface.port_ack'){
              bridge.postMessage({type:'redevplugin.surface.initialize',frame_generation_id:'frame_12345678',surface_handle:'surface_12345678',entry_path:'/index.html',context:${JSON.stringify(context)}});
              bridge.postMessage({type:'redevplugin.bridge.lifecycle',event:{type:'ready'}});
            }
            if(data.type==='redevplugin.surface.app_ready'){window.appReady=true;document.querySelector('iframe').style.opacity='1';}
            if(data.type==='redevplugin.bridge.call')window.pendingCall=data.request;
          };bridge.start();event.source.postMessage({type:'redevplugin.surface.port',frame_generation_id:'frame_12345678',document_id:event.data.document_id},event.origin,[channel.port2]);
        });</script><iframe src="${childOrigin}/_redevplugin_web/bootstrap#${"a".repeat(64)}"></iframe>`);
    } else if (pathname === "/_redevplugin_web/bootstrap") { res.setHeader("Content-Type", "text/html"); res.end("<!doctype html><body><script>" + bootstrap + "</script></body>"); }
    else if (pathname === "/_redevplugin_web/enter") { res.setHeader("Content-Type", "application/json"); res.end(JSON.stringify({ parent_origin: parentOrigin, entry_path: "/index.html" })); }
    else if (pathname === "/_redevplugin_web/probe") res.end("redevplugin-web-boundary");
    else if (pathname === "/_redevplugin_web/probe-redirect") req.socket.destroy();
    else if (pathname === "/_redevplugin_web/document") { res.setHeader("Content-Type", "text/html"); res.end(html); }
    else if (pathname === "/assets/app.js") { res.setHeader("Content-Type", "text/javascript"); res.end(bundle.outputFiles[0].text); }
    else if (pathname === "/assets/styles.css") { res.setHeader("Content-Type", "text/css"); res.end(css); }
    else { res.statusCode = 404; res.end(); }
  });
  await new Promise(resolve => server.listen(0, "0.0.0.0", resolve));
  parentOrigin = `http://127.0.0.1:${server.address().port}`; childOrigin = `http://localhost:${server.address().port}`;
  let browser;
  try {
    browser = await chromium.launch({ headless: true });
    const page = await browser.newPage({ viewport: { width: 1000, height: 740 } });
    const errors = []; page.on("pageerror", error => errors.push(error.message));
    await page.goto(parentOrigin + "/parent");
    await page.waitForFunction(() => window.pendingCall, null, { timeout: 5000 });
    const frame = page.frames().find(frame => frame.url().startsWith(childOrigin));
    assert.equal(await page.evaluate(() => pendingCall.method), "memos.bootstrap");
    // Flush browser tasks while the authoritative result is held; no duration
    // threshold or source-pattern assertion can substitute for concealed pixels.
    await frame.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));
    assert.equal(await page.evaluate(() => Boolean(window.appReady)), false, "unrestored application must stay concealed");
    assert.equal(await page.locator("iframe").evaluate(node => getComputedStyle(node).opacity), "0");
    await page.evaluate(context => bridge.postMessage({ type: "redevplugin.surface.context", frame_generation_id: "frame_12345678", surface_handle: "surface_12345678", context }), { ...context, revision: 2, appearance: { ...context.appearance, color_scheme: "light" } });
    if (fails) await page.evaluate(() => bridge.postMessage({ type: "redevplugin.bridge.response", id: pendingCall.id, ok: false, error_code: "PLUGIN_INTERNAL_ERROR", error: "Saved memos unavailable" }));
    else await page.evaluate(() => bridge.postMessage({ type: "redevplugin.bridge.response", id: pendingCall.id, ok: true, data: { data: {
      memos: [{ id: "memo_fixture", content: "Previously saved memo", created_at: "2026-11-16T12:00:00Z", updated_at: "2026-11-16T12:00:00Z", pinned: false, archived: false, tags: [] }], next_cursor: null,
      facets: { month: "2026-11", tags: [], days: [], all_total: 1, pinned_total: 0, archived_total: 0 }, draft: { content: "Previously saved draft", updated_at: "2026-11-16T12:00:00Z" },
    } } }));
    await page.waitForFunction(() => window.appReady, null, { timeout: 5000 });
    const snapshot = () => frame.evaluate(() => ({ theme: document.documentElement.className, draft: document.querySelector("textarea").value, rows: document.querySelector("textarea").rows, empty: document.body.innerText.includes("A little space for your thoughts"), failure: document.body.innerText.includes("Timeline unavailable"), top: [...document.querySelectorAll("h1,h2,h3")].find(node => node.textContent === "Timeline").getBoundingClientRect().top }));
    const first = await snapshot();
    assert.equal(first.theme, "light"); assert.equal(first.draft, fails ? "" : "Previously saved draft"); assert.equal(first.rows, fails ? 2 : 7); assert.equal(first.empty, false); assert.equal(first.failure, fails);
    for (let index = 0; index < 8; index++) { await frame.evaluate(() => new Promise(requestAnimationFrame)); assert.deepEqual(await snapshot(), first); }
    assert.deepEqual(errors, []);
  } finally { await browser?.close(); await new Promise(resolve => server.close(resolve)); }
});
