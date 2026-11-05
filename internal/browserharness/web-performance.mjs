import assert from 'node:assert/strict';
import { appendFile, readFile, writeFile } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import os from 'node:os';
import { chromium } from 'playwright';

// Measure the shipped loader and native DOM inside the real Go HTTP fixture.
// These scenarios replace measurements of the removed platform VNode renderer.
export async function measureWebPerformance(url) {
  const output = process.env.REDEVPLUGIN_WEB_PERFORMANCE_OUTPUT;
  const gate = process.env.REDEVPLUGIN_WEB_PERFORMANCE_GATE;
  if (!output || !['smoke', 'full', 'release'].includes(gate)) throw new Error('Web performance output and gate are required');
  const contract = JSON.parse(await readFile(new URL('../../testdata/quality/performance.json', import.meta.url), 'utf8'));
  const specifications = contract.scenarios.filter(item => item.id.startsWith('ui.'));
  const samples = new Map(specifications.map(item => [item.id, []]));
  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage({ viewport: { width: 1440, height: 900 } });
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  try {
    const count = specifications.find(item => item.id === 'ui.web-opening').sample_count;
    for (let index = 0; index < count; index++) {
      const started = performance.now();
      await page.goto(url, { waitUntil: 'domcontentloaded' });
      await page.waitForFunction(() => globalThis.testState?.ready || globalThis.testState?.error, null, { polling: 10 });
      assert.equal(await page.evaluate(() => globalThis.testState.error), '');
      for (const frame of page.frames().filter(frame => frame !== page.mainFrame())) {
        await frame.waitForFunction(() => globalThis.appState?.ready, null, { polling: 10 });
      }
      samples.get('ui.web-opening').push(performance.now() - started);
      if (index < count - 1) await page.evaluate(async () => { for (const slot of globalThis.testSlots) await slot.close(); });
    }
    const frame = page.frames().find(frame => frame !== page.mainFrame());
    assert.ok(frame, 'native application frame is required');
    const measurements = await frame.evaluate(async () => {
      const root = document.createElement('section');
      const nodes = Array.from({ length: 4095 }, (_, index) => {
        const node = document.createElement('p'); node.textContent = 'Row ' + index; return node;
      });
      root.append(...nodes); document.body.append(root);
      const nextFrame = () => new Promise(resolve => requestAnimationFrame(resolve));
      await nextFrame();
      const leaf = [];
      for (let index = 0; index < 45; index++) {
        await nextFrame();
        const started = performance.now();
        nodes[2048].textContent = 'Updated row ' + index;
        void root.offsetHeight;
        if (index >= 5) leaf.push(performance.now() - started);
      }
      root.replaceChildren(...nodes.slice(0, 1000));
      const reorder = [];
      for (let index = 0; index < 35; index++) {
        await nextFrame();
        const children = [...root.children];
        const started = performance.now();
        for (let position = children.length - 1; position >= 0; position--) root.append(children[position]);
        void root.offsetHeight;
        if (index >= 5) reorder.push(performance.now() - started);
        if (root.firstChild !== children.at(-1) || root.lastChild !== children[0]) throw new Error('native reordering failed');
      }
      root.remove();
      return { leaf, reorder };
    });
    samples.set('ui.native-leaf-update', measurements.leaf);
    samples.set('ui.native-reordering', measurements.reorder);
    await page.evaluate(async () => { for (const slot of globalThis.testSlots) await slot.close(); });
    const plainPage = await browser.newPage({ viewport: { width: 1440, height: 900 } });
    const traffic = { startup: {}, idle: {}, interaction: {}, closing: {}, sibling: {} };
    let phase = 'startup';
    plainPage.on('pageerror', error => errors.push(error.message));
    plainPage.on('request', request => {
      const path = new URL(request.url()).pathname;
      const kind = path.endsWith('/surfaces/methods') ? 'methods'
        : path.endsWith('/bridge-token') ? 'authority'
        : path.startsWith('/_redevplugin_web/') ? 'web-control-or-resource'
        : path.startsWith('/_redevplugin/api/') ? 'lifecycle' : 'document-or-asset';
      traffic[phase][kind] = (traffic[phase][kind] ?? 0) + 1;
    });
    const plainStarted = performance.now();
    await plainPage.goto(url + '?mode=plain', { waitUntil: 'domcontentloaded' });
    await plainPage.waitForFunction(() => globalThis.testState?.ready || globalThis.testState?.error, null, { polling: 10 });
    assert.equal(await plainPage.evaluate(() => globalThis.testState.error), '');
    const plainFrames = plainPage.frames().filter(frame => frame !== plainPage.mainFrame());
    const plainHostReadyMs = performance.now() - plainStarted;
    assert.equal(plainFrames.length, 2);
    assert.notEqual(new URL(plainFrames[0].url()).origin, new URL(plainFrames[1].url()).origin);
    await plainFrames[0].locator('input').fill('ready for local input');
    assert.equal(await plainFrames[0].locator('output').textContent(), 'ready for local input');
    const plainInteractiveMs = performance.now() - plainStarted;
    assert.equal(traffic.startup.methods ?? 0, 0, 'plain startup must not register a method receiver');
    for (const current of ['idle', 'interaction', 'sibling']) {
      if (current === 'sibling') { phase = 'closing'; await plainPage.evaluate(() => globalThis.testSlots[0].close()); }
      phase = current;
      if (current !== 'idle') {
        const target = plainFrames[current === 'sibling' ? 1 : 0];
        await target.locator('input').fill(current + ' remains local');
        assert.equal(await target.locator('output').textContent(), current + ' remains local');
      }
      await plainPage.waitForTimeout(1500);
      samples.get('ui.web-surface-idle-method-requests').push(traffic[current].methods ?? 0);
    }
    assert.equal(await plainPage.locator('iframe').count(), 1);
    assert.equal(await plainPage.evaluate(() => globalThis.testState.error), '');
    const diagnostic = {
      schema_version: 'redevplugin.web-performance-diagnostic.v1',
      source_commit: execFileSync('git', ['rev-parse', 'HEAD'], { encoding: 'utf8' }).trim(),
      source_diff_sha256: createHash('sha256').update(execFileSync('git', ['diff', 'HEAD', '--'])).digest('hex'),
      platform_version: (await readFile(new URL('../../VERSION', import.meta.url), 'utf8')).trim(),
      generated_at: new Date().toISOString(), gate,
      environment: { os: os.platform(), arch: os.arch(), node: process.version, chromium: browser.version() },
      web_traffic: traffic, observation_ms_per_phase: 1500, initial_surface_count: 2, final_surface_count: 1,
      plain_opening_ms: { host_ready: plainHostReadyMs, first_verified_input: plainInteractiveMs },
      raw_gate_samples: Object.fromEntries(samples), profiles: [],
    };
    await plainPage.evaluate(async () => { for (const slot of globalThis.testSlots) await slot.close(); });
    await plainPage.close();
    for (const requestDelayMs of [0, 40]) diagnostic.profiles.push(await observeApplicationCosts(browser, url, requestDelayMs));
    assert.deepEqual(errors, []);
    for (const specification of specifications) {
      const values = [...samples.get(specification.id)].sort((left, right) => left - right);
      assert.equal(values.length, specification.sample_count);
      const metrics = specification.metrics.map(metric => ({ ...metric, observed: metric.name === 'max' ? values.at(-1) : values[Math.ceil(values.length * .95) - 1] }));
      for (const metric of metrics) {
        assert.ok(Number.isFinite(metric.observed) && metric.observed >= 0);
        if (gate !== 'smoke') assert.ok(metric.observed <= metric.limit, specification.id + ' ' + metric.name + ' exceeded ' + metric.limit + ': ' + metric.observed);
      }
      await appendFile(output, JSON.stringify({ id: specification.id, gate, status: 'pass', sample_count: values.length, metrics }) + '\n', { mode: 0o600 });
    }
    const diagnosticPath = process.env.REDEVPLUGIN_WEB_PERFORMANCE_DIAGNOSTIC || output + '.web-diagnostic.json';
    await writeFile(diagnosticPath, JSON.stringify(diagnostic, null, 2) + '\n', { mode: 0o600 });
    console.log(JSON.stringify({ web_performance_diagnostic: diagnosticPath, profiles: diagnostic.profiles.map(profile => ({ request_delay_ms: profile.request_delay_ms, method_samples: profile.method_roundtrip_ms.length, resource_samples: profile.resource_roundtrip_ms.length, closed_surface_count: profile.closed_surface_count })) }));
  } finally { await page.close(); await browser.close(); }
}

// Supplemental baselines retain raw samples without inventing a latency/RSS
// threshold. The complete runner binds this file to the exact tested source.
async function observeApplicationCosts(browser, url, requestDelayMs) {
  const context = await browser.newContext({ viewport: { width: 1440, height: 900 } });
  const page = await context.newPage();
  const errors = []; page.on('pageerror', error => errors.push(error.message));
  const traffic = { startup: {}, idle: {}, methods: {}, resources: {}, cancellation: {}, closing: {} };
  let phase = 'startup';
  page.on('request', request => {
    const path = new URL(request.url()).pathname;
    const kind = path.endsWith('/surfaces/methods') ? 'methods' : path.endsWith('/bridge-token') ? 'authority'
      : path.startsWith('/_redevplugin_web/resource') ? 'resource' : path.startsWith('/_redevplugin_web/') ? 'web-control'
      : path.startsWith('/_redevplugin/api/') ? 'lifecycle' : 'document-or-asset';
    traffic[phase][kind] = (traffic[phase][kind] ?? 0) + 1;
  });
  if (requestDelayMs) await context.route('**/*', async route => {
    await new Promise(resolve => setTimeout(resolve, requestDelayMs));
    await route.continue();
  });
  try {
    const cdp = await context.newCDPSession(page);
    await cdp.send('Performance.enable');
    const memory = async () => {
      const { metrics } = await cdp.send('Performance.getMetrics');
      const values = Object.fromEntries(metrics.map(item => [item.name, item.value]));
      return { parent_target_js_heap_used_bytes: values.JSHeapUsedSize, ...(await cdp.send('Memory.getDOMCounters')) };
    };
    const before = await memory();
    const started = performance.now();
    await page.goto(url, { waitUntil: 'domcontentloaded' });
    await page.waitForFunction(() => globalThis.testState?.ready || globalThis.testState?.error, null, { polling: 10 });
    assert.equal(await page.evaluate(() => globalThis.testState.error), '');
    const hostReadyMs = performance.now() - started;
    const frames = page.frames().filter(frame => frame.parentFrame() === page.mainFrame());
    assert.equal(frames.length, 2);
    for (const frame of frames) await frame.waitForFunction(() => globalThis.appState?.methodsReady, null, { polling: 10 });
    const methodsReadyMs = performance.now() - started;
    await frames[0].evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));
    const renderedMs = performance.now() - started;
    const loaded = await memory();
    phase = 'idle'; await page.waitForTimeout(1500);
    const methodTimes = [], resourceTimes = [], cancellationTimes = [];
    phase = 'methods';
    for (let index = 0; index < 20; index++) {
      const timing = await page.evaluate(async () => {
        const started = performance.now(); const result = await globalThis.invokeDocument(0, 'document.read');
        if (!Number.isInteger(result.data.revision)) throw new Error('Method response is invalid');
        return performance.now() - started;
      });
      methodTimes.push(timing);
    }
    phase = 'resources';
    for (let index = 0; index < 20; index++) resourceTimes.push(await frames[0].evaluate(async index => {
      const started = performance.now(); await globalThis.performanceResource(index); return performance.now() - started;
    }, index));
    assert.equal(traffic.resources.resource, 40, 'each resource roundtrip must perform exactly one write and one read');
    phase = 'cancellation';
    for (let index = 0; index < 5; index++) {
      await frames[0].evaluate(() => { globalThis.appState.canceled = false; globalThis.appState.waiting = false; });
      await page.evaluate(() => {
        globalThis.pendingDocument = globalThis.invokeDocument(0, 'document.wait').then(() => ({ unexpected_success: true }), () => ({ canceled: true }));
      });
      await frames[0].waitForFunction(() => globalThis.appState.waiting, null, { polling: 10 });
      const canceledAt = performance.now();
      await page.evaluate(() => globalThis.cancelWaitingDocument());
      await frames[0].waitForFunction(() => globalThis.appState.canceled, null, { polling: 10 });
      assert.deepEqual(await page.evaluate(() => globalThis.pendingDocument), { canceled: true });
      cancellationTimes.push(performance.now() - canceledAt);
    }
    phase = 'closing';
    const closeAt = performance.now();
    await page.evaluate(async () => { for (const slot of globalThis.testSlots) await slot.close(); });
    await page.waitForFunction(() => globalThis.testState.released.length === 2);
    const closeMs = performance.now() - closeAt;
    assert.equal(await page.locator('iframe').count(), 0);
    assert.deepEqual(errors, []);
    return { request_delay_ms: requestDelayMs, cache: 'fresh browser context; delayed profile intercepts each request and disables HTTP cache',
      opening_ms: { host_ready: hostReadyMs, methods_ready: methodsReadyMs, after_two_animation_frames: renderedMs },
      method_roundtrip_ms: methodTimes, resource_roundtrip_ms: resourceTimes, cancellation_observed_ms: cancellationTimes,
      idle_observation_ms: 1500, traffic, close_ms: closeMs, closed_surface_count: 2,
      memory: { before, loaded, closed: await memory(), scope: 'parent CDP target only; excludes isolated child processes, total browser RSS and Worker runtime RSS; no forced GC' } };
  } finally { await context.close(); }
}
