import assert from "node:assert/strict";
import http from "node:http";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import test from "node:test";
import { build } from "esbuild";
import { chromium } from "playwright";

const root = resolve(import.meta.dirname, "..");
const context = { schema_version: "redevplugin.surface_context.v1", revision: 1,
  appearance: { color_scheme: "dark", colors: { canvas: "#171b22", surface: "#20262f", surface_elevated: "#29313c", text: "#f3f4f6", text_muted: "#a8b0bd", border: "#59616e", accent: "#f3f4f6", accent_text: "#171b22", success: "#5db98b", warning: "#d8aa55", danger: "#e77676", focus: "#82aef0" } },
  locale: { language_tag: "en-US", direction: "ltr" } };

// Capture the actual computed styles at the child readiness boundary, before
// browser automation latency can accidentally hide a transient white frame.
const instrument = `window.samples=[];const post=MessagePort.prototype.postMessage;
  MessagePort.prototype.postMessage=function(value,...args){
    if(value?.type==='redevplugin.surface.app_ready')samples.push(snapshot());
    return post.call(this,value,...args);
  };
  window.snapshot=()=>({transitions:document.getAnimations().filter(a=>a instanceof CSSTransition&&a.playState==='running').length,color:getComputedStyle(document.querySelector('input')).backgroundColor,
    opacity:getComputedStyle(document.querySelector('main')).opacity,
    pseudo:getComputedStyle(document.querySelector('main'),'::before').opacity,
    cssRunning:document.getAnimations().filter(a=>a instanceof CSSAnimation&&a.animationName==='entrance'&&a.playState==='running').length,
    spinner:document.getAnimations().find(a=>a instanceof CSSAnimation&&a.animationName==='spin')?.playState,
    script:window.scriptAnimation.playState});`;

for (const mode of ["implicit", "explicit", "no-sdk", "newer-context"]) test(`first presentation settles finite CSS motion and preserves later motion (${mode})`, async () => {
  const bootstrap = await readFile(resolve(root, "pkg/httpadapter/web_surface_bootstrap.js"), "utf8");
  const bundle = await build({ stdin: { contents: `import {PluginBridgeClient} from './packages/redevplugin-ui/src/surface.ts';
    const input=document.querySelector('input');
    window.scriptAnimation=document.querySelector('aside').animate([{opacity:.2},{opacity:1}],{duration:10000});
    // Commit the light starting style while concealed to reproduce the initial
    // context-triggered transition deterministically without a timer or RAF.
    getComputedStyle(input).backgroundColor;
    ${mode === "no-sdk" ? "document.documentElement.className='dark';" : `const bridge=new PluginBridgeClient(${mode === "explicit" ? '{presentation:"explicit"}' : ''});
    bridge.onContext(context=>{document.documentElement.className=context.appearance.color_scheme;});
    await bridge.ready();${mode === "explicit" ? 'bridge.present();' : ''}`}
    input.addEventListener('click',()=>{input.classList.toggle('active');const item=document.createElement('section');item.id='later';item.style.animation='entrance 1s both';document.body.append(item);});`, resolveDir: root }, bundle: true, format: "esm", platform: "browser", write: false });
  const html = `<!doctype html><html class="light"><style>
    input{background:white;transition:background-color 150ms ease 80ms}.dark input{background:rgb(23,23,23)}input.active{background:rgb(100,150,200)}
    main{animation:entrance 280ms both}main::before{content:'decorative';animation:entrance 700ms 50ms both}
    footer{animation:spin 1s infinite} @keyframes entrance{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:translateY(0)}}
    @keyframes spin{from{transform:rotate(0deg)}to{transform:rotate(360deg)}}
    </style><body><input aria-label="Search"><main>Restored content</main><footer>Busy</footer><aside>Script</aside><script type="module" src="/app.js"></script></body></html>`;
  let parentOrigin, childOrigin;
  const server = http.createServer((req, res) => {
    const pathname = new URL(req.url, "http://localhost").pathname;
    if (pathname === "/parent") {
      res.setHeader("Content-Type", "text/html");
      res.end(`<!doctype html><script>window.events=[];window.readyCount=0;addEventListener('message',e=>{
        if(e.origin!==${JSON.stringify(childOrigin)}||e.data.type!=='redevplugin.surface.entry_ready')return;
        const c=new MessageChannel();window.bridge=c.port1;bridge.onmessage=e=>{const d=e.data;events.push(d);
          if(d.type==='redevplugin.surface.port_ack'){
            bridge.postMessage({type:'redevplugin.surface.initialize',frame_generation_id:'frame_12345678',surface_handle:'surface_12345678',entry_path:'/index.html',context:${JSON.stringify(context)}});
            bridge.postMessage({type:'redevplugin.bridge.lifecycle',event:{type:'ready'}});
          }
          if(d.type==='redevplugin.surface.app_ready'){
            if(${JSON.stringify(mode)}==='newer-context'&&++readyCount===1){
              bridge.postMessage({type:'redevplugin.surface.presented',frame_generation_id:'frame_wrong123',context_revision:d.context_revision});
              bridge.postMessage({type:'redevplugin.surface.context',context:${JSON.stringify({...context,revision:2,appearance:{...context.appearance,color_scheme:'light'}})}});return;
            }
            window.appReady=true;document.querySelector('iframe').style.opacity='1';
            bridge.postMessage({type:'redevplugin.surface.presented',frame_generation_id:d.frame_generation_id,context_revision:d.context_revision});}
        };bridge.start();e.source.postMessage({type:'redevplugin.surface.port',frame_generation_id:'frame_12345678',document_id:e.data.document_id},e.origin,[c.port2]);
      });</script><iframe style="opacity:0" src="${childOrigin}/_redevplugin_web/bootstrap#${"a".repeat(64)}"></iframe>`);
    } else if (pathname === "/_redevplugin_web/bootstrap") { res.setHeader("Content-Type", "text/html"); res.end("<!doctype html><body><script>" + instrument + bootstrap + "</script></body>"); }
    else if (pathname === "/_redevplugin_web/enter") { res.setHeader("Content-Type", "application/json"); res.end(JSON.stringify({ parent_origin: parentOrigin, entry_path: "/index.html" })); }
    else if (pathname === "/_redevplugin_web/probe") res.end("redevplugin-web-boundary");
    else if (pathname === "/_redevplugin_web/probe-redirect") req.socket.destroy();
    else if (pathname === "/_redevplugin_web/document") { res.setHeader("Content-Type", "text/html"); res.end(html); }
    else if (pathname === "/app.js") { res.setHeader("Content-Type", "text/javascript"); res.end(bundle.outputFiles[0].text); }
    else { res.statusCode = 404; res.end(); }
  });
  await new Promise(resolve => server.listen(0, "0.0.0.0", resolve));
  parentOrigin = `http://127.0.0.1:${server.address().port}`; childOrigin = `http://localhost:${server.address().port}`;
  let browser;
  try {
    browser = await chromium.launch({ headless: true });
    const page = await browser.newPage();
    const errors = []; page.on("pageerror", error => errors.push(error.message));
    await page.goto(parentOrigin + "/parent");
    await page.waitForFunction(() => window.appReady, null, { timeout: 5000 });
    const frame = page.frames().find(frame => frame.url().startsWith(childOrigin));
    const first = await frame.evaluate(() => samples[0]);
    assert.equal(first.color, "rgb(23, 23, 23)", "theme transition must finish before reveal");
    assert.equal(first.transitions, 0);
    assert.equal(first.opacity, "1", "initial entrance must finish before reveal");
    assert.equal(first.pseudo, "1", "delayed pseudo-element entrance must finish before reveal");
    assert.equal(first.cssRunning, 0);
    assert.equal(first.spinner, "running", "infinite CSS animation must keep running");
    assert.equal(first.script, "running", "application JavaScript animation must keep running");
    if (mode === "newer-context") {
      const current = await frame.evaluate(() => samples[1]);
      assert.equal(current.color, "rgb(255, 255, 255)");
      assert.equal(current.transitions, 0, "newer opening context must settle before acknowledgement");
    }
    const later = await frame.evaluate(() => {
      document.querySelector('input').click();
      return { transition:document.querySelector('input').getAnimations().some(a=>a instanceof CSSTransition&&a.playState==='running'),
        opacity:getComputedStyle(document.querySelector('#later')).opacity };
    });
    assert.equal(later.transition, true, "interaction transitions remain enabled");
    assert.equal(later.opacity, "0", "new runtime entrance animations remain enabled");
    await page.evaluate(context => bridge.postMessage({type:'redevplugin.surface.context',context}), {...context,revision:3,appearance:{...context.appearance,color_scheme:'light'}});
    await frame.waitForFunction(count => samples.length === count, mode === "newer-context" ? 3 : 2);
    const updated = await frame.evaluate(() => ({ snapshot:samples.at(-1),later:document.querySelector('#later').getAnimations()[0]?.playState }));
    assert.equal(updated.later, "running", "later contexts cannot finish runtime animations");
    assert.deepEqual(errors, []);
  } finally { await browser?.close(); await new Promise(resolve => server.close(resolve)); }
});
