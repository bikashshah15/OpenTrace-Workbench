// UIP-03-IR-05 real-browser checks: a status-read failure after a successful start is never hidden behind the last "running" claim.
// A LOCAL stub service (no scan, no Docker, no network) serves src/ui and canned frozen fixtures; the status endpoint misbehaves on demand.
// Usage: node tests/ui/browser/run_scan_poll_checks.mjs
import http from 'node:http';
import { readFileSync, existsSync } from 'node:fs';
import { join, resolve, dirname, extname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { launch, newPage } from './cdp.mjs';

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), '../../..');
const UI = join(REPO, 'src/ui');
const RUNNING = JSON.parse(readFileSync(join(REPO, 'evidence/uip/fixtures/scan-status-matrix-synthetic/scan-03-sbom-running.json'), 'utf8'));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const results = [];
const check = (id, ok, detail = '') => { results.push({ id, ok: !!ok }); console.log(`${ok ? 'PASS' : 'FAIL'} ${id}${detail ? ' — ' + String(detail).slice(0, 200) : ''}`); };
const TYPES = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.svg': 'image/svg+xml', '.json': 'application/json', '.png': 'image/png' };
const CONFIG = { live: { enabled: true, isolation: { available: true, description: 'a Docker worker container with no network' }, policy: { effective: 'bounded' }, advisories: { enabled: false } } };

// mode: 'ok' | 'network' | '500' | '404' | '409' | 'slow' (answers 'ok' after delayMs)
function stub() {
  const state = { mode: 'ok', delayMs: 0, seq: RUNNING.job.seq, statusCalls: 0, scanCalls: 0, ended: false };
  const doc = () => ({ ...JSON.parse(JSON.stringify(RUNNING)), job: { ...RUNNING.job, seq: ++state.seq } });
  const srv = http.createServer(async (req, res) => {
    const u = new URL(req.url, 'http://x');
    const send = (code, body, type = 'application/json', h = {}) => { res.writeHead(code, { 'content-type': type, 'cache-control': 'no-store', ...h }); res.end(body); };
    if (u.pathname === '/api/config') return send(200, JSON.stringify(CONFIG));
    if (u.pathname === '/api/session') return send(201, '{"status":"active","generation":0}', 'application/json', { 'set-cookie': 'ot_session=a.b; Path=/api' });
    if (u.pathname === '/api/session/end') { state.ended = true; return send(200, '{"state":"deleted_verified"}'); }
    if (u.pathname === '/api/scan') { state.scanCalls++; return send(202, JSON.stringify({ schema: 'opentrace.scan_job_response/1', status: doc(), result: null })); }
    if (u.pathname === '/api/scan/status') {
      state.statusCalls++;
      if (state.mode === 'network') return req.socket.destroy();
      if (state.mode === '500') return send(500, '{"error":"internal_error"}');
      if (state.mode === '404') return send(404, '{"error":"job_not_found"}');
      if (state.mode === '409') return send(409, '{"error":"stale_generation"}');
      if (state.delayMs) await sleep(state.delayMs);
      return send(200, JSON.stringify({ schema: 'opentrace.scan_job_response/1', status: doc(), result: null }));
    }
    if (u.pathname.startsWith('/api/')) return send(404, '{"error":"not_found"}');
    const rel = u.pathname === '/' ? 'index.html' : u.pathname.startsWith('/static/') ? u.pathname.slice('/static/'.length) : null;
    const file = rel && resolve(UI, rel);
    if (!file || !file.startsWith(UI) || !existsSync(file)) return send(404, 'not found', 'text/plain');
    send(200, readFileSync(file), TYPES[extname(file)] || 'application/octet-stream');
  });
  return new Promise((r) => srv.listen(0, '127.0.0.1', () => r({ base: `http://127.0.0.1:${srv.address().port}/`, state, close: () => srv.close() })));
}

const { browser, close } = await launch();
const txt = (pg, sel) => pg.eval(`(document.querySelector(${JSON.stringify(sel)})?.innerText||'')`);
const exists = (pg, sel) => pg.eval(`!!document.querySelector(${JSON.stringify(sel)})`);
const store = (pg) => pg.eval('JSON.parse(JSON.stringify(window.__otStore.get()))');

async function begin(mode) {
  const svc = await stub(); svc.state.mode = 'ok';
  const pg = await newPage(browser, { width: 1366, height: 900 });
  await pg.goto(svc.base);
  await pg.waitFor(`document.getElementById('ot-scan') && !document.getElementById('ot-scan').disabled`, 15000);
  await pg.type('#ot-url', 'https://github.com/example-org/sample-web');
  await pg.click('#ot-scan');
  await pg.waitFor(`document.getElementById('ot-scan-status') && window.__otStore.get().scan.status`, 15000);
  svc.state.mode = mode;
  return { svc, pg };
}
// Count the page's own fetches (Network.requestWillBeSent), not server hits: Chrome silently re-sends a GET whose reused keep-alive socket was reset.
const statusFetches = (pg) => pg.log.requests.filter((r) => /\/api\/scan\/status/.test(r.url)).length;
const staleShown = (pg) => pg.waitFor(`document.getElementById('ot-scan-stale')`, 30000, 'stale banner');

async function failureScenario(mode, label, transient) {
  const { svc, pg } = await begin(mode);
  try {
    await staleShown(pg);
    const html = await txt(pg, '#ot-scan-status');
    const calls = statusFetches(pg);
    check(`[${label}] the error is visible next to the last known status (status exists)`, /Status updates stopped/.test(html) && /Resolve and pin/.test(html) && (await pg.eval(`document.getElementById('ot-scan-status').dataset.stale`)) === 'true', html.replace(/\n+/g, ' ').slice(0, 160));
    check(`[${label}] no fresh running claim: no 'Scanning…' headline, no busy indicator, no Cancel`, !/Scanning…/.test(html) && !(await exists(pg, '.ot-scan-indeterminate')) && !(await exists(pg, '#ot-scan-cancel')) && /Current status unknown/.test(html));
    check(`[${label}] nothing is claimed about the server work`, /may still be running on the service/.test(html) && !/stopped running|has stopped working|was cancelled/.test(html));
    check(`[${label}] End session is available in the panel`, await exists(pg, '#ot-scan-end'));
    check(`[${label}] ${transient ? 'a recovery action is offered' : 'no futile retry is offered for a lost job'}`, (await exists(pg, '#ot-scan-recheck')) === transient);
    check(`[${label}] polling is bounded: ${transient ? 'initial read plus exactly 3 automatic retries' : 'a lost job is not retried'}`, calls === (transient ? 4 : 1), `status fetches ${calls}`);
    await sleep(3500);
    check(`[${label}] polling has stopped (no further reads)`, statusFetches(pg) === calls, `${calls} -> ${statusFetches(pg)}`);
    check(`[${label}] Scan stays disabled (a scan may still be running) and the panel is one announced status region`, (await pg.eval(`document.getElementById('ot-scan').disabled`)) && (await pg.eval(`document.getElementById('ot-scan-status').getAttribute('role')`)) === 'status');
    if (transient) {
      svc.state.mode = 'ok';
      await pg.click('#ot-scan-recheck');
      await pg.waitFor(`!document.getElementById('ot-scan-stale') && document.getElementById('ot-scan-status').dataset.stale==='false'`, 15000, 'recovered');
      check(`[${label}] Check again recovers: the error clears and live status resumes (generation and job unchanged)`, (await exists(pg, '#ot-scan-cancel')) && (await store(pg)).scan.job === RUNNING.job.job_id && (await store(pg)).scan.error === null);
      const n = statusFetches(pg); await sleep(2500);
      check(`[${label}] polling resumed after recovery`, statusFetches(pg) > n, `${n} -> ${statusFetches(pg)}`);
    }
    check(`[${label}] no page errors`, pg.log.exceptions.length === 0, pg.log.exceptions.join('|'));
  } finally { await pg.close().catch(() => {}); svc.close(); }
}

try {
  // The two transient scenarios take ~16 s each (2 s + 4 s + 8 s of bounded retries); the definitive ones are immediate.
  await Promise.all([failureScenario('network', 'network failure', true), failureScenario('500', 'HTTP 500', true)]);
  await failureScenario('404', 'HTTP 404 job_not_found', false);
  await failureScenario('409', 'HTTP 409 stale_generation', false);

  // ---- End session from the stale panel stops everything and clears the job
  {
    const { svc, pg } = await begin('404');
    try {
      await staleShown(pg);
      await pg.click('#ot-scan-end');
      await pg.waitFor(`document.getElementById('ot-ended-note')`, 15000);
      const s = await store(pg);
      check('[end] End session from the stale panel clears the scan job and revokes the page state', s.scan.job === null && s.scan.status === null && s.analysis === null && svc.state.ended);
    } finally { await pg.close().catch(() => {}); svc.close(); }
  }

  // ---- a late response (answered after End session) is rejected
  {
    const { svc, pg } = await begin('ok');
    try {
      svc.state.delayMs = 4000;                    // the next poll is in flight when the session ends
      await sleep(1500);
      const before = svc.state.statusCalls;
      await pg.click('#ot-top-end');
      await pg.waitFor(`document.getElementById('ot-ended-note')`, 15000);
      await sleep(5000);                            // the delayed (otherwise valid) response arrives after the session ended
      const s = await store(pg);
      check('[late] a status response that arrives after End session cannot repopulate the ended session', s.scan.job === null && s.scan.status === null && s.analysis === null && s.destination === 'analyze', `calls ${before}->${svc.state.statusCalls}`);
      const n = svc.state.statusCalls; await sleep(3500);
      check('[late] no polling continues after End session', svc.state.statusCalls === n);
    } finally { await pg.close().catch(() => {}); svc.close(); }
  }

  // ---- focus: moved once to the status region on start; later polls do not steal it
  {
    const svc = await stub();
    const pg = await newPage(browser, { width: 1366, height: 900 });
    try {
      await pg.goto(svc.base);
      await pg.waitFor(`document.getElementById('ot-scan') && !document.getElementById('ot-scan').disabled`, 15000);
      await pg.type('#ot-url', 'https://github.com/example-org/sample-web');
      await pg.click('#ot-scan');
      await pg.waitFor(`document.getElementById('ot-scan-status')`, 15000);
      await sleep(200);
      check('[focus] starting a scan moves focus to the status region (once)', await pg.eval(`document.activeElement && document.activeElement.id==='ot-scan-status'`));
      const seq0 = (await store(pg)).scan.lastSeq;
      await pg.eval(`document.getElementById('ot-url').focus()`);
      await pg.waitFor(`window.__otStore.get().scan.lastSeq > ${seq0}`, 15000, 'a later poll was applied');
      await sleep(300);
      check('[focus] a later poll repaint does not steal focus from where the user moved it', await pg.eval(`document.activeElement && document.activeElement.id==='ot-url'`), await pg.eval(`document.activeElement && document.activeElement.id`));
      await pg.eval(`document.getElementById('ot-scan-status').focus()`);
      const seq1 = (await store(pg)).scan.lastSeq;
      await pg.waitFor(`window.__otStore.get().scan.lastSeq > ${seq1}`, 15000, 'another poll was applied');
      await sleep(300);
      check('[focus] a focused status region keeps focus across the repaint', await pg.eval(`document.activeElement && document.activeElement.id==='ot-scan-status'`));
    } finally { await pg.close().catch(() => {}); svc.close(); }
  }
} catch (e) { check('run completed', false, e.stack || e.message); }
await close();
const failed = results.filter((r) => !r.ok);
console.log(`\n${results.length - failed.length}/${results.length} checks passed`);
process.exit(failed.length ? 1 : 0);
