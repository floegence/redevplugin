import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { createSocket } from 'node:dgram';

// Receiver evidence covers APIs that connect-src alone does not confine.
export async function verifyNetworkBoundary(browser, applicationURL) {
  const requests = [];
  const packets = [];
  const server = createServer((request, response) => {
    if (request.url !== '/') requests.push(request.url);
    response.setHeader('Content-Type', 'text/html');
    response.end('<!doctype html><title>Network control</title>');
  });
  server.on('upgrade', (request, socket) => { requests.push(request.url); socket.destroy(); });
  const udp = createSocket('udp4');
  udp.on('message', data => packets.push(data.length));
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  await new Promise(resolve => udp.bind(0, '127.0.0.1', resolve));
  const sink = 'http://127.0.0.1:' + server.address().port;
  const input = { sink, stunPort: udp.address().port };
  const control = await browser.newPage();
  const isolated = await browser.newPage();
  try {
    await control.goto(sink);
    await control.evaluate(probe, input);
    await control.evaluate(url => { location.href = url + '/navigation'; }, sink);
    await control.waitForURL(sink + '/navigation');
    assert.ok(packets.length > 0, 'STUN control must reach the UDP receiver');
    for (const route of ['/fetch', '/worker', '/shared-worker', '/websocket', '/navigation']) assert.ok(requests.includes(route), 'receiver control missing ' + route);
    requests.length = 0; packets.length = 0;

    await isolated.goto(applicationURL);
    await isolated.waitForFunction(() => globalThis.testState?.ready || globalThis.testState?.error);
    assert.equal(await isolated.evaluate(() => globalThis.testState.error), '');
    const frame = isolated.frames().find(item => item !== isolated.mainFrame());
    await frame.waitForFunction(() => globalThis.appState?.ready);
    await frame.evaluate(probe, input);
    await frame.evaluate(url => { location.href = url + '/navigation'; }, sink).catch(() => undefined);
    await isolated.waitForTimeout(300);
    assert.deepEqual(requests, [], 'isolated application must not reach any external HTTP/WebSocket receiver');
    assert.deepEqual(packets, [], 'isolated application must not reach the STUN receiver');
    await isolated.evaluate(async () => { for (const slot of globalThis.testSlots) await slot.close(); });
  } finally {
    await control.close(); await isolated.close();
    await new Promise(resolve => server.close(resolve));
    udp.close();
  }
}

async function probe({ sink, stunPort }) {
  await fetch(sink + '/fetch').catch(() => undefined);
  const script = new Blob(['fetch(' + JSON.stringify(sink + '/worker') + ').catch(() => {}).finally(() => postMessage("done"))'], { type: 'text/javascript' });
  const blobURL = URL.createObjectURL(script);
  const worker = new Worker(blobURL);
  await new Promise((resolve, reject) => {
    const deadline = setTimeout(() => reject(new Error('network Worker did not finish')), 3000);
    worker.onmessage = () => { clearTimeout(deadline); resolve(); };
    worker.onerror = () => { clearTimeout(deadline); reject(new Error('network Worker failed')); };
  });
  worker.terminate(); URL.revokeObjectURL(blobURL);
  const sharedScript = new Blob(['onconnect = event => { const port = event.ports[0]; fetch(' + JSON.stringify(sink + '/shared-worker') + ').catch(() => {}).finally(() => { port.postMessage("done"); close(); }); }'], { type: 'text/javascript' });
  const sharedURL = URL.createObjectURL(sharedScript);
  const shared = new SharedWorker(sharedURL);
  try {
    await new Promise((resolve, reject) => {
      const deadline = setTimeout(() => reject(new Error('network SharedWorker did not finish')), 3000);
      shared.port.onmessage = () => { clearTimeout(deadline); resolve(); };
      shared.onerror = () => { clearTimeout(deadline); reject(new Error('network SharedWorker failed')); };
      shared.port.start();
    });
  } finally { shared.port.close(); URL.revokeObjectURL(sharedURL); }
  await new Promise(resolve => {
    let socket;
    const deadline = setTimeout(() => { socket?.close(); resolve(); }, 300);
    try {
      socket = new WebSocket(sink.replace('http:', 'ws:') + '/websocket');
      socket.onerror = () => { clearTimeout(deadline); resolve(); };
    } catch { clearTimeout(deadline); resolve(); }
  });
  const connection = new RTCPeerConnection({ iceServers: [{ urls: 'stun:127.0.0.1:' + stunPort }] });
  try {
    connection.createDataChannel('network-test');
    await connection.setLocalDescription(await connection.createOffer());
    await new Promise(resolve => setTimeout(resolve, 1200));
  } finally { connection.close(); }
}
