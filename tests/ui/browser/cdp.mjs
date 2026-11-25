// Minimal dependency-free Chrome DevTools Protocol driver (Node >= 22, global WebSocket/fetch).
import { spawn } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

export const CHROME = process.env.CHROME_BIN || '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';

export async function launch({ port = 0, headed = false } = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'ot-chrome-'));
  const args = [...(headed ? [] : ['--headless=new']), '--disable-gpu', '--no-first-run', '--no-default-browser-check',
    '--hide-scrollbars', `--user-data-dir=${dir}`, '--remote-debugging-port=' + port, 'about:blank'];
  const proc = spawn(CHROME, args, { stdio: ['ignore', 'ignore', 'pipe'] });
  const wsUrl = await new Promise((resolve, reject) => {
    let buf = '';
    const t = setTimeout(() => reject(new Error('chrome did not start')), 20000);
    proc.stderr.on('data', (d) => {
      buf += d;
      const m = buf.match(/DevTools listening on (ws:\/\/\S+)/);
      if (m) { clearTimeout(t); resolve(m[1]); }
    });
    proc.on('exit', () => reject(new Error('chrome exited')));
  });
  const browser = await connect(wsUrl);
  const close = async () => { try { browser.close(); } catch {} proc.kill('SIGKILL'); try { rmSync(dir, { recursive: true, force: true }); } catch {} };
  return { browser, close, proc, dir };
}

export function connect(url) {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(url);
    let id = 0; const pending = new Map(); const listeners = [];
    ws.onopen = () => resolve({
      send(method, params = {}, sessionId) {
        const msg = { id: ++id, method, params }; if (sessionId) msg.sessionId = sessionId;
        ws.send(JSON.stringify(msg));
        return new Promise((res, rej) => pending.set(msg.id, { res, rej, method }));
      },
      on(fn) { listeners.push(fn); },
      close() { ws.close(); },
    });
    ws.onerror = (e) => reject(e);
    ws.onmessage = (ev) => {
      const m = JSON.parse(ev.data);
      if (m.id && pending.has(m.id)) {
        const p = pending.get(m.id); pending.delete(m.id);
        m.error ? p.rej(new Error(p.method + ': ' + m.error.message)) : p.res(m.result);
      } else if (m.method) listeners.forEach((fn) => fn(m));
    };
  });
}

// A page = a target session with convenience helpers and passive request/console/exception logs.
export async function newPage(browser, { width, height, mobile = false, scale = 1 }) {
  const { targetId } = await browser.send('Target.createTarget', { url: 'about:blank' });
  const { sessionId } = await browser.send('Target.attachToTarget', { targetId, flatten: true });
  const s = (m, p) => browser.send(m, p, sessionId);
  const log = { requests: [], console: [], exceptions: [], failed: [], responses: [] };
  browser.on((m) => {
    if (m.sessionId !== sessionId) return;
    const p = m.params;
    if (m.method === 'Network.requestWillBeSent') log.requests.push({ url: p.request.url, method: p.request.method, type: p.type });
    else if (m.method === 'Network.responseReceived') log.responses.push({ url: p.response.url, status: p.response.status, headers: p.response.headers });
    else if (m.method === 'Network.loadingFailed') log.failed.push({ id: p.requestId, error: p.errorText, canceled: p.canceled });
    else if (m.method === 'Runtime.consoleAPICalled') log.console.push({ type: p.type, text: p.args.map((a) => a.value ?? a.description ?? '').join(' ') });
    else if (m.method === 'Runtime.exceptionThrown') log.exceptions.push(p.exceptionDetails.exception?.description || p.exceptionDetails.text);
    else if (m.method === 'Log.entryAdded') log.console.push({ type: p.entry.level, text: p.entry.text + ' ' + (p.entry.url || '') });
  });
  await s('Page.enable'); await s('Runtime.enable'); await s('Network.enable'); await s('Log.enable');
  await s('Emulation.setDeviceMetricsOverride', { width, height, deviceScaleFactor: scale, mobile });
  const page = {
    log, sessionId, targetId, width, height,
    send: s,
    async goto(url) {
      const loaded = new Promise((r) => { const h = (m) => { if (m.sessionId === sessionId && m.method === 'Page.loadEventFired') r(); }; browser.on(h); });
      await s('Page.navigate', { url }); await loaded;
    },
    async eval(expr) {
      const r = await s('Runtime.evaluate', { expression: expr, awaitPromise: true, returnByValue: true });
      if (r.exceptionDetails) throw new Error('eval: ' + (r.exceptionDetails.exception?.description || r.exceptionDetails.text));
      return r.result.value;
    },
    async waitFor(expr, timeout = 15000, label = expr) {
      const t0 = Date.now();
      while (Date.now() - t0 < timeout) { if (await page.eval(`!!(${expr})`)) return true; await new Promise((r) => setTimeout(r, 50)); }
      throw new Error('timeout waiting for: ' + label);
    },
    async click(selector) {
      const pt = await page.eval(`(()=>{const e=document.querySelector(${JSON.stringify(selector)}); if(!e) return null; e.scrollIntoView({block:'center',inline:'center',behavior:'instant'}); const r=e.getBoundingClientRect(); return {x:r.x+r.width/2,y:r.y+r.height/2,w:r.width,h:r.height};})()`);
      if (!pt) throw new Error('click: no element ' + selector);
      await s('Input.dispatchMouseEvent', { type: 'mouseMoved', x: pt.x, y: pt.y });
      await s('Input.dispatchMouseEvent', { type: 'mousePressed', x: pt.x, y: pt.y, button: 'left', clickCount: 1 });
      await s('Input.dispatchMouseEvent', { type: 'mouseReleased', x: pt.x, y: pt.y, button: 'left', clickCount: 1 });
    },
    async type(selector, text) {
      await page.eval(`(()=>{const e=document.querySelector(${JSON.stringify(selector)}); e.focus(); e.select&&e.select();})()`);
      await s('Input.insertText', { text });
    },
    async key(key, code = key, extra = {}) {
      const vk = { Enter: 13, Escape: 27, Tab: 9, ArrowDown: 40, ArrowUp: 38, ArrowLeft: 37, ArrowRight: 39, ' ': 32 }[key] || 0;
      const base = { key, code, windowsVirtualKeyCode: vk, nativeVirtualKeyCode: vk, ...extra };
      await s('Input.dispatchKeyEvent', { type: 'keyDown', text: key.length === 1 ? key : (key === 'Enter' ? '\r' : undefined), ...base });
      await s('Input.dispatchKeyEvent', { type: 'keyUp', ...base });
    },
    async screenshot(path, { fullPage = false } = {}) {
      const r = await s('Page.captureScreenshot', { format: 'png', captureBeyondViewport: fullPage });
      writeFileSync(path, Buffer.from(r.data, 'base64'));
    },
    async close() { await browser.send('Target.closeTarget', { targetId }); },
  };
  return page;
}
