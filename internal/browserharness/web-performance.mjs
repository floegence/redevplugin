import assert from 'node:assert/strict';
import { appendFile, readFile } from 'node:fs/promises';
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
    assert.deepEqual(errors, []);
    for (const specification of specifications) {
      const values = samples.get(specification.id).sort((left, right) => left - right);
      assert.equal(values.length, specification.sample_count);
      const metrics = specification.metrics.map(metric => ({ ...metric, observed: metric.name === 'max' ? values.at(-1) : values[Math.ceil(values.length * .95) - 1] }));
      for (const metric of metrics) {
        assert.ok(Number.isFinite(metric.observed) && metric.observed >= 0);
        if (gate !== 'smoke') assert.ok(metric.observed <= metric.limit, specification.id + ' ' + metric.name + ' exceeded ' + metric.limit + ': ' + metric.observed);
      }
      await appendFile(output, JSON.stringify({ id: specification.id, gate, status: 'pass', sample_count: values.length, metrics }) + '\n', { mode: 0o600 });
    }
  } finally { await page.close(); await browser.close(); }
}
