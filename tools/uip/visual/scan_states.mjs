// UIP-03 visual states (C5; corrected in UIP-03 correction 01 for UIP-03-IR-06): deterministic Scan states rendered by the REAL UI against a LOCAL
// STUB service. No scan, no Docker, no network, no provider.
//
//   PYTHON=<python with requirements-dev> node tools/uip/visual/scan_states.mjs capture  --out DIR [--viewports 1366,1920,390] [--themes light,dark]
//   PYTHON=... node tools/uip/visual/scan_states.mjs variance --out DIR [--repeats 10]      (writes variance.json and thresholds.json; thresholds never raised)
//
// Every status/envelope the stub serves is validated with the REAL frozen scan_status/1 validator and the real scan_job_response/1 transport rules
// (tools/uip/validate_scan_envelopes.py) BEFORE any capture and again on what was actually served; one violation aborts the run before a manifest is
// written. Ready states carry a valid result. The stub answers every poll (nothing is stalled to substitute another workflow); the only held things are
// (a) the start request for the "starting" state and (b) the 1 s poll TIMER for the labelled transient terminal panels, whose envelopes stay valid.
// Handoff states use the real UI handoff into the compact Workbench: a local demo service (the captured sample analysis, offline) supplies the valid
// result and the Workbench views, and the stub's status binding is derived from that result's identity. Application-only: the reference prototype
// defines none of these states, so there is no reference image and no parity claim.
import http from 'node:http';
import { execFileSync, spawn } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync, existsSync, renameSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve, dirname, extname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { launch, newPage } from '../../../tests/ui/browser/cdp.mjs';
import { VIEWPORTS, THEMES, SETTINGS, MAX_PAGE_HEIGHT, isLoopbackUrl, sha256, decodePng, diffStats, summarize, thresholdFor } from './lib.mjs';

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), '../../..');
const UI = join(REPO, 'src/ui');
const FIXTURES = join(REPO, 'evidence/uip/fixtures/scan-status-matrix-synthetic');
const PYTHON = process.env.PYTHON || 'python3';
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const args = process.argv.slice(2); const cmd = args[0];
const opt = (k, d) => { const i = args.indexOf('--' + k); return i >= 0 ? args[i + 1] : d; };
const OUT = resolve(opt('out', join(REPO, 'evidence/uip/visual/uip-03')));
const vpIds = opt('viewports', '1366,1920,390').split(',');
const themes = opt('themes', THEMES.join(',')).split(',');
const viewports = VIEWPORTS.filter((v) => vpIds.includes(v.id));
const only = opt('only', '');                      // development aid: a comma list of state ids (never used for the committed evidence)
const git = (...a) => { try { return execFileSync('git', a, { cwd: REPO, encoding: 'utf8' }).trim(); } catch { return 'unknown'; } };
const COMMIT = git('rev-parse', 'HEAD');
const pyEnv = { ...process.env, PYTHONPATH: join(REPO, 'src/core'), PYTHONDONTWRITEBYTECODE: '1' };

// ---------------------------------------------------------------- demo service (the valid result and the Workbench views for handoff states)
let demo = null;
async function startDemo() {
  const root = mkdtempSync(join(tmpdir(), 'ot-visual-demo-'));
  const proc = spawn(PYTHON, ['-m', 'opentrace_core.app', '--port', '0', '--session-root', root], { cwd: REPO, env: pyEnv, stdio: ['ignore', 'pipe', 'pipe'] });
  const port = await new Promise((res, rej) => { let b = ''; const t = setTimeout(() => rej(new Error('demo service did not start: ' + b)), 40000);
    proc.stdout.on('data', (d) => { b += d; const m = b.match(/listening on 127\.0\.0\.1:(\d+)/); if (m) { clearTimeout(t); res(Number(m[1])); } }); proc.stderr.on('data', (d) => { b += d; }); });
  demo = { port, stop: () => { proc.kill('SIGTERM'); rmSync(root, { recursive: true, force: true }); } };
}
function call(method, path, body, cookie, port = demo.port) {
  return new Promise((res, rej) => {
    const data = body == null ? '' : typeof body === 'string' ? body : JSON.stringify(body);
    const r = http.request({ host: '127.0.0.1', port, method, path, headers: { host: `127.0.0.1:${port}`, 'content-type': 'application/json', 'content-length': Buffer.byteLength(data), ...(cookie ? { cookie } : {}) } }, (resp) => {
      const chunks = []; resp.on('data', (c) => chunks.push(c)); resp.on('end', () => res({ status: resp.statusCode, headers: resp.headers, body: Buffer.concat(chunks) }));
    });
    r.on('error', rej); r.end(data);
  });
}

// ---------------------------------------------------------------- fixtures
const fx = (n) => JSON.parse(readFileSync(join(FIXTURES, n + '.json'), 'utf8'));
const clone = (x) => JSON.parse(JSON.stringify(x));
const SHARED_NOTE = 'SBOM and CBOM are produced in one isolated worker phase; per-scanner progress is not available.';
const SCANNER_NOTE = 'The scanner reported warnings; they are kept in the scan record.';
const stageOf = (d, id) => d.stages.find((x) => x.stage_id === id);
const patchStage = (d, id, p) => { Object.assign(stageOf(d, id), p); return d; };
const FAILED_NEXT = { blocked_reason: 'The scan did not complete.' };

function sharedPhase() {
  const d = clone(fx('scan-04-completed'));
  for (const s of d.stages) {
    if (s.stage_id === 'sbom' || s.stage_id === 'cbom') Object.assign(s, { state: 'running', finished_at: null, outputs: [], warnings: [SHARED_NOTE], started_at: '2026-01-01T00:00:05Z', updated_at: '2026-01-01T00:00:05Z' });
    if (s.stage_id === 'evidence_projection' || s.stage_id === 'workbench_ready') Object.assign(s, { state: 'queued', started_at: null, finished_at: null });
  }
  d.job.state = 'running'; d.job.elapsed_ms = 7000; d.job.updated_at = '2026-01-01T00:00:07Z'; d.handoff = { ready: false, blocked_reason: 'The scan has not finished.' };
  return d;
}
// running with the advisory stage: the scanners are done and the advisory lookup is the running stage
function runningAdvisory() {
  const d = clone(fx('scan-04-completed'));
  patchStage(d, 'advisory_lookup', { state: 'running', reason_code: null, started_at: '2026-01-01T00:00:09Z', finished_at: null, updated_at: '2026-01-01T00:00:09Z', outputs: [], warnings: [] });
  for (const id of ['source_checks', 'evidence_projection', 'workbench_ready']) patchStage(d, id, { state: 'queued', reason_code: null, started_at: null, finished_at: null, outputs: [], warnings: [] });
  Object.assign(d.job, { state: 'running', elapsed_ms: 9500, updated_at: '2026-01-01T00:00:09Z' }); d.handoff = { ready: false, blocked_reason: 'The scan has not finished.' }; d.cleanup = { state: 'pending' };
  return d;
}
function withWarnings() { const d = clone(fx('scan-04-completed')); patchStage(d, 'sbom', { warnings: [SCANNER_NOTE] }); patchStage(d, 'cbom', { warnings: [SCANNER_NOTE] }); return d; }
function unsupportedStage() { const d = clone(fx('scan-04-completed')); patchStage(d, 'aibom', { state: 'unsupported', reason_code: 'unsupported_ecosystem', finished_at: '2026-01-01T00:00:08Z' }); d.job.state = 'partial'; return d; }
function failedResolution(reason, note) { const d = clone(fx('scan-07-failed-resolution')); patchStage(d, 'resolve_revision', { reason_code: reason, warnings: note ? [note] : [] }); return d; }
function failedSbom() { const d = clone(fx('scan-08-failed-scan')); patchStage(d, 'sbom', { state: 'failed', reason_code: 'scanner_failed', outputs: [] }); return d; }
function failedCleanup() { const d = clone(fx('scan-08-failed-scan')); patchStage(d, 'cbom', { state: 'failed', reason_code: 'cleanup_unverified' }); d.cleanup = { state: 'unverified' }; return d; }
// A ready status for the handoff flows: the base fixture with its binding/identity taken from the result the demo service returned, so status and result agree.
function readyFor(base, result) {
  const d = clone(fx(base)); const id = result.identity; const [, , host, owner, name] = new URL(id.repository).href.split('/');
  const repository = { canonical_url: id.repository, host, name, owner };
  d.generation = result.generation;
  d.binding = { analysis_digest: id.analysis_digest, repository, commit_sha: id.commit, requested_ref: { kind: id.requested.kind, text: id.requested.text }, generation: result.generation, mode: d.mode, assessment: null };
  const ident = clone(fx(base).identity);
  d.identity = { ...ident, analysis_digest: id.analysis_digest, repository, requested: { ...ident.requested, kind: id.requested.kind, text: id.requested.text }, resolved: { ...ident.resolved, commit_sha: id.commit }, session: { generation: result.generation } };
  return d;
}

const CONFIGS = {
  A: { live: { enabled: true, isolation: { available: true, description: 'a Docker worker container with no network', name: 'docker-worker' }, policy: { effective: 'bounded' }, advisories: { enabled: false } } },
  'A-advisory': { live: { enabled: true, isolation: { available: true, description: 'a Docker worker container with no network' }, policy: { effective: 'bounded' }, advisories: { enabled: true, host: 'api.osv.dev', sends: 'package ecosystem, name and version' } } },
  B: { live: { enabled: true, isolation: { available: true, description: 'the local macOS sandbox' }, policy: { effective: 'allowlist' }, advisories: { enabled: false } } },
  C: { live: { enabled: true, isolation: { available: false, reason: 'no isolation provider is available' }, policy: { effective: 'allowlist' }, advisories: { enabled: false } } },
  D: { live: { enabled: false } },
};
// flow: idle (homepage) | starting (the start request is in flight) | panel (the panel stays; every poll is answered) | transient (a VALID ready envelope; only the
// 1 s poll timer is held so the terminal panel can be photographed before the handoff; labelled) | handoff (the real handoff into the Workbench) | end (End session during a run)
const ST = (id, config, flow, doc, extra = {}) => ({ id, config, flow, doc, ...extra });
const STATES = [
  ST('home-variant-A', 'A', 'idle'), ST('home-variant-A-advisory', 'A-advisory', 'idle'), ST('home-variant-B', 'B', 'idle'), ST('home-variant-C', 'C', 'idle'), ST('home-variant-D', 'D', 'idle'),
  ST('home-config-unknown', 'unknown', 'idle'), ST('home-config-failed', 'failed', 'idle'),
  ST('scan-starting', 'A', 'starting'),
  ST('scan-resolving', 'A', 'panel', () => fx('scan-01-resolving')), ST('scan-acquiring', 'A', 'panel', () => fx('scan-02-acquiring')),
  ST('scan-sbom-running', 'A', 'panel', () => fx('scan-03-sbom-running')), ST('scan-shared-worker-phase', 'A', 'panel', sharedPhase),
  ST('scan-running-advisory-lookup', 'A-advisory', 'panel', runningAdvisory),
  ST('scan-completed-transient-panel', 'A', 'transient', () => fx('scan-04-completed'), { ready: 'scan-04-completed' }),
  ST('scan-completed-empty-cbom-transient-panel', 'A', 'transient', () => fx('scan-05-completed-empty-cbom'), { ready: 'scan-05-completed-empty-cbom' }),
  ST('scan-completed-with-warnings-transient-panel', 'A', 'transient', withWarnings, { ready: 'scan-04-completed', mutate: withWarnings }),
  ST('scan-partial-transient-panel', 'A', 'transient', () => fx('scan-06-partial'), { ready: 'scan-06-partial' }),
  ST('scan-unsupported-transient-panel', 'A', 'transient', unsupportedStage, { ready: 'scan-04-completed', mutate: unsupportedStage }),
  ST('handoff-workbench-completed', 'A', 'handoff', () => fx('scan-04-completed'), { ready: 'scan-04-completed' }),
  ST('handoff-workbench-partial', 'A', 'handoff', () => fx('scan-06-partial'), { ready: 'scan-06-partial' }),
  ST('scan-failed-invalid-revision', 'A', 'panel', () => fx('scan-07-failed-resolution')),
  ST('scan-failed-policy-refused', 'A', 'panel', () => failedResolution('policy_refused', 'This repository is not on the live-scan pilot list.')),
  ST('scan-failed-isolation-unavailable', 'A', 'panel', () => failedResolution('scanner_unavailable', 'No isolation boundary could be verified, so nothing was scanned.')),
  ST('scan-failed-rate-limited', 'A', 'panel', () => failedResolution('rate_limited', 'Revision lookup exceeded its request limit; try a simpler link.')),
  ST('scan-failed-cbom', 'A', 'panel', () => fx('scan-08-failed-scan')), ST('scan-failed-sbom-unavailable', 'A', 'panel', failedSbom),
  ST('scan-failed-cleanup-unverified', 'A', 'panel', failedCleanup),
  ST('scan-cancelled', 'A', 'panel', () => fx('scan-09-cancelled-cleanup-verified')), ST('scan-cancelled-cleanup-unverified', 'A', 'panel', () => fx('scan-10-cancelled-cleanup-unverified')),
  ST('scan-end-session-during-run', 'A', 'end', () => fx('scan-03-sbom-running')),
].filter((st) => !only || only.split(',').includes(st.id));

// ---------------------------------------------------------------- validation (the real validators, before AND after capture)
function validateEnvelopes(map, label) {
  const file = join(mkdtempSync(join(tmpdir(), 'ot-visual-env-')), 'envelopes.json');
  writeFileSync(file, JSON.stringify(map));
  let out;
  try { out = execFileSync(PYTHON, [join(REPO, 'tools/uip/validate_scan_envelopes.py'), file], { cwd: REPO, env: pyEnv, encoding: 'utf8' }); }
  catch (e) { console.error(`fixture validation FAILED (${label}):\n` + (e.stdout || e.message)); process.exit(4); }
  const rep = JSON.parse(out); console.log(`fixture validation (${label}): ${rep.checked} envelopes valid (frozen scan_status/1 validator + scan_job_response/1 rules)`); return rep;
}
// The expected result of the demo service is only known at run time; a probe session supplies it for the pre-capture validation.
async function probeResult() {
  const sess = await call('POST', '/api/session', {}); const cookie = String(sess.headers['set-cookie']).split(';')[0];
  const res = JSON.parse((await call('POST', '/api/analysis/demo', {}, cookie)).body.toString());
  await call('POST', '/api/session/end', {}, cookie); return res;
}
const docFor = (st, result) => (st.flow === 'handoff' || st.flow === 'transient') ? (st.mutate ? (() => { const d = readyFor(st.ready, result); const m = st.mutate(); for (const k of ['stages', 'job']) d[k] = m[k]; return d; })() : readyFor(st.ready, result)) : st.doc();
async function preValidate() {
  const result = await probeResult(); const map = {};
  for (const st of STATES) if (st.doc) map[st.id] = { status: docFor(st, result), result: (st.flow === 'handoff' || st.flow === 'transient') ? result : null };
  validateEnvelopes(map, 'before capture');
}

// ---------------------------------------------------------------- stub service
const TYPES = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.svg': 'image/svg+xml', '.json': 'application/json', '.png': 'image/png', '.ico': 'image/x-icon' };
const readBody = (req) => new Promise((r) => { const c = []; req.on('data', (d) => c.push(d)); req.on('end', () => r(Buffer.concat(c).toString())); });
function stub(st, served) {
  const state = { cookie: null, result: null };
  const proxied = st.flow === 'handoff' || st.flow === 'transient';
  const env = () => ({ schema: 'opentrace.scan_job_response/1', status: docFor(st, state.result), result: proxied ? state.result : null });
  const srv = http.createServer(async (req, res) => {
    const u = new URL(req.url, 'http://x'); const send = (code, body, type = 'application/json', h = {}) => { res.writeHead(code, { 'content-type': type, 'cache-control': 'no-store', ...h }); res.end(body); };
    if (u.pathname === '/api/config') {
      if (st.config === 'failed') return send(500, '{"error":"x"}');
      if (st.config === 'unknown') return; // never answered: the UI must not guess a variant
      return send(200, JSON.stringify(CONFIGS[st.config]));
    }
    if (u.pathname === '/api/session' && req.method === 'POST') {
      if (!proxied) return send(201, '{"status":"active","generation":0}', 'application/json', { 'set-cookie': 'ot_session=a.b; Path=/api' });
      const r = await call('POST', '/api/session', {}); state.cookie = String(r.headers['set-cookie']).split(';')[0];
      state.result = JSON.parse((await call('POST', '/api/analysis/demo', {}, state.cookie)).body.toString());
      return send(201, r.body, 'application/json', { 'set-cookie': r.headers['set-cookie'] });
    }
    if (u.pathname === '/api/session/end') { if (proxied) { const r = await call('POST', '/api/session/end', {}, state.cookie); return send(r.status, r.body, 'application/json', r.headers['set-cookie'] ? { 'set-cookie': r.headers['set-cookie'] } : {}); } return send(200, '{"state":"deleted_verified"}', 'application/json', { 'set-cookie': 'ot_session=; Path=/api; Max-Age=0' }); }
    if (u.pathname === '/api/scan' || u.pathname === '/api/scan/status') {
      if (st.flow === 'starting') return;                         // the start request itself is in flight (the "starting" state)
      if (!st.doc) return send(404, '{"error":"job_not_found"}');
      const e = env(); served.set(st.id, { status: e.status, result: e.result });
      return send(u.pathname === '/api/scan' ? 202 : 200, JSON.stringify(e));
    }
    if (u.pathname.startsWith('/api/')) {
      if (!proxied) return send(404, '{"error":"not_found"}');    // the Workbench views come from the demo service for handoff flows only
      const body = req.method === 'POST' ? await readBody(req) : null;
      const r = await call(req.method, req.url, body, state.cookie);
      return send(r.status, r.body, r.headers['content-type'] || 'application/json', Object.fromEntries(['x-artifact-sha256', 'x-artifact-kind'].filter((h) => r.headers[h]).map((h) => [h, r.headers[h]])));
    }
    const rel = u.pathname === '/' ? 'index.html' : u.pathname.startsWith('/static/') ? u.pathname.slice('/static/'.length) : null;   // the same two static routes as the real service
    if (rel === null) return send(404, 'not found', 'text/plain');
    const file = resolve(UI, rel);
    if (!file.startsWith(UI) || !existsSync(file)) return send(404, 'not found', 'text/plain');
    send(200, readFileSync(file), TYPES[extname(file)] || 'application/octet-stream');
  });
  return new Promise((res) => srv.listen(0, '127.0.0.1', () => res({ base: `http://127.0.0.1:${srv.address().port}/`, close: () => srv.close() })));
}

// ---------------------------------------------------------------- capture
const blocked = [];
async function openPage(browser, vp, theme, holdPoll) {
  const pg = await newPage(browser, { width: vp.width, height: vp.height, mobile: !!vp.mobile, scale: SETTINGS.deviceScaleFactor });
  await pg.send('Fetch.enable', { patterns: [{ urlPattern: '*' }] });
  browser.on((m) => { if (m.sessionId !== pg.sessionId || m.method !== 'Fetch.requestPaused') return; const url = m.params.request.url;
    if (isLoopbackUrl(url)) pg.send('Fetch.continueRequest', { requestId: m.params.requestId }).catch(() => {}); else { blocked.push(url); pg.send('Fetch.failRequest', { requestId: m.params.requestId, errorReason: 'BlockedByClient' }).catch(() => {}); } });
  // Animations, transitions, smooth scrolling and the caret are disabled by an injected style (contract section 6).
  await pg.send('Page.addScriptToEvaluateOnNewDocument', { source: "document.addEventListener('DOMContentLoaded',()=>{const s=document.createElement('style');s.textContent='*,*::before,*::after{animation:none!important;transition:none!important;scroll-behavior:auto!important;caret-color:transparent!important}html{scroll-behavior:auto!important}';document.head.appendChild(s)})" });
  // Labelled transient panels only: the application's 1 s status-poll TIMER is held (the network and the envelope are untouched).
  if (holdPoll) await pg.send('Page.addScriptToEvaluateOnNewDocument', { source: "(()=>{const st=window.setTimeout;window.setTimeout=function(fn,ms,...a){return ms===1000?0:st.call(window,fn,ms,...a)}})()" });
  await pg.send('Emulation.setEmulatedMedia', { features: [{ name: 'prefers-reduced-motion', value: 'reduce' }, { name: 'prefers-color-scheme', value: theme }] });
  await pg.send('Emulation.setTimezoneOverride', { timezoneId: 'UTC' }).catch(() => {}); await pg.send('Emulation.setLocaleOverride', { locale: 'en-US' }).catch(() => {});
  return pg;
}
async function shot(pg) {
  await pg.eval(`document.activeElement&&document.activeElement.blur&&document.activeElement.blur()`); await pg.eval(`document.fonts.ready.then(()=>true)`);
  const height = Math.min(MAX_PAGE_HEIGHT, await pg.eval('Math.max(document.documentElement.scrollHeight, innerHeight)'));
  const grab = async () => Buffer.from((await pg.send('Page.captureScreenshot', { format: 'png', captureBeyondViewport: true, clip: { x: 0, y: 0, width: pg.width, height, scale: 1 } })).data, 'base64');
  let prev = await grab();
  for (let i = 0; i < 25; i++) { await sleep(200); const cur = await grab(); if (cur.equals(prev)) return cur; prev = cur; }
  if (process.env.SCAN_STATES_DEBUG) { mkdirSync(process.env.SCAN_STATES_DEBUG, { recursive: true }); writeFileSync(join(process.env.SCAN_STATES_DEBUG, 'prev.png'), prev); writeFileSync(join(process.env.SCAN_STATES_DEBUG, 'cur.png'), await grab()); }
  throw new Error('readiness failed: the page did not stabilise within 5 s');
}
async function setTheme(pg, theme) { await pg.eval(`window.__otStore.dispatch({type:'THEME',value:${JSON.stringify(theme)}})`); await sleep(120); if ((await pg.eval(`document.documentElement.dataset.theme||'light'`)) !== theme) throw new Error('theme not applied'); }
const snap = (pg) => pg.eval(`(()=>{const s=window.__otStore.get();return {destination:s.destination,tab:s.workbench&&s.workbench.tab,selection:(s.workbench&&s.workbench.perTab&&s.workbench.perTab.contexts&&s.workbench.perTab.contexts.selection)||null,contexts:document.querySelectorAll('#ot-tabpanel [data-ctx]').length,jobState:s.scan.status&&s.scan.status.job.state,scanJob:s.scan.job,analysisMode:s.analysis&&s.analysis.identity&&s.analysis.identity.mode,ended:s.ended,busy:s.busy,config:s.config.state}})()`);
const asserts = (st, got) => {
  const fail = (why) => { throw new Error(`${st.id}: ${why} (${JSON.stringify(got)})`); };
  if (st.flow === 'handoff') { if (got.destination !== 'workbench' || got.tab !== 'contexts' || !got.analysisMode || !got.contexts || !['completed', 'partial'].includes(got.jobState)) fail('the handoff did not land on the Workbench Repository contexts'); }
  else if (st.flow === 'transient') { if (got.destination !== 'analyze' || !['completed', 'partial'].includes(got.jobState)) fail('the transient panel is not the terminal ready panel on the homepage'); }
  else if (st.flow === 'panel') { if (got.destination !== 'analyze' || !got.jobState) fail('the status panel is not shown on the homepage'); }
  else if (st.flow === 'end') { if (got.ended !== 'deleted_verified' || got.scanJob !== null) fail('the session did not end cleanly'); }
  else if (st.flow === 'starting') { if (got.scanJob !== null || got.busy !== 'analysis') fail('the start request is not in flight'); }
  return got;
};

async function captureState(browser, st, vp, theme, served) {
  const svc = await stub(st, served);
  const pg = await openPage(browser, vp, theme, st.flow === 'transient');
  try {
    await pg.goto(svc.base); await sleep(400); await setTheme(pg, theme);
    const expect = (js, what) => pg.waitFor(js, 20000, what);
    if (st.config === 'unknown') { await sleep(600); if (!(await pg.eval(`document.getElementById('ot-scan').disabled && !document.getElementById('ot-disclosure')`))) throw new Error('unknown config must disable Scan and show no disclosure'); }
    else if (st.config === 'failed') { await expect(`document.getElementById('ot-scan-reason') && /could not be loaded/.test(document.getElementById('ot-scan-reason').innerText)`, 'failed config message'); }
    else await expect(`window.__otStore.get().config.state==='loaded'`, 'config loaded');
    if (st.flow !== 'idle') {
      await pg.eval(`(()=>{const e=document.getElementById('ot-url');e.value='https://github.com/example-org/sample-web';e.dispatchEvent(new Event('input',{bubbles:true}))})()`);
      await expect(`!document.getElementById('ot-scan').disabled`, 'Scan enabled'); await pg.click('#ot-scan');
      if (st.flow === 'starting') await expect(`window.__otStore.get().busy==='analysis'`, 'start request in flight');
      else if (st.flow === 'handoff') await expect(`window.__otStore.get().destination==='workbench' && window.__otStore.get().workbench.tab==='contexts' && document.querySelector('#ot-tabpanel [data-ctx]')`, 'Workbench handoff (Repository contexts)');
      else if (st.flow === 'transient') await expect(`document.getElementById('ot-scan-status') && window.__otStore.get().scan.status && window.__otStore.get().scan.result`, 'terminal panel with its result');
      else { await expect(`document.getElementById('ot-scan-status') && window.__otStore.get().scan.status`, 'scan panel'); await sleep(1600); }    // let the first status read settle (it returns the same document)
      if (st.flow === 'end') {
        if (vp.mobile) { await pg.eval(`document.querySelector('[data-nav=analyze]')?.click()`); await sleep(200); await pg.eval(`document.getElementById('ot-end-session').click()`); } else await pg.click('#ot-top-end');
        await expect(`document.getElementById('ot-ended-note')`, 'ended note');
      }
    } else if (st.config !== 'unknown' && st.config !== 'failed') {
      const variant = st.config.startsWith('A') ? 'A' : st.config; await expect(`document.getElementById('ot-disclosure') && document.getElementById('ot-disclosure').dataset.variant==='${variant}'`, 'disclosure variant');
    }
    await setTheme(pg, theme); await pg.eval('window.scrollTo(0,0)'); await sleep(300);
    const observed = asserts(st, await snap(pg));
    const png = await shot(pg);
    const fonts = await pg.eval(`(()=>({loaded:[...new Set([...document.fonts].filter(x=>x.status==='loaded').map(x=>x.family))].sort(),body:getComputedStyle(document.body).fontFamily}))()`);
    return { png, fonts, observed };
  } finally { await pg.close().catch(() => {}); svc.close(); }
}

const name = (st, vp, theme) => `${st.id}_${vp.id}_${theme}.png`;
const LABEL = {
  idle: 'homepage idle', starting: 'start request in flight (POST /api/scan held open)', panel: 'status panel from a valid envelope; every poll answered with the same valid document',
  transient: 'TRANSIENT terminal panel: a valid ready envelope with its result; only the 1 s poll timer is held so the panel can be photographed before the handoff',
  handoff: 'real UI handoff into the compact Workbench (Repository contexts); result and views supplied by a local demo service; status binding derived from the result', end: 'End session clicked during a running scan',
};
async function capture(browser) {
  await startDemo(); await preValidate();
  mkdirSync(join(OUT, 'app'), { recursive: true });
  const stage = join(OUT, '.staging'); rmSync(stage, { recursive: true, force: true }); mkdirSync(stage, { recursive: true });
  const records = []; const info = await browser.send('Browser.getVersion'); const served = new Map();
  for (const st of STATES) for (const vp of viewports) for (const theme of themes) {
    const { png, fonts, observed } = await captureState(browser, st, vp, theme, served);
    writeFileSync(join(stage, name(st, vp, theme)), png);
    records.push({ state: st.id, config_variant: st.config, flow: st.flow, flow_note: LABEL[st.flow], fixture: st.ready || (st.doc ? 'derived-or-frozen scan_status fixture' : null), viewport: vp.id, theme, file: 'app/' + name(st, vp, theme), sha256: sha256(png), bytes: png.length,
      observed, browser: info.product, device_scale_factor: SETTINGS.deviceScaleFactor, fonts: JSON.stringify(fonts), readiness: 'two consecutive byte-identical screenshots 200 ms apart', tested_commit: COMMIT, reference_hash: null, reference_note: 'application-only: the reference defines no Scan states' });
    console.log('captured', name(st, vp, theme));
  }
  if (blocked.length) { console.error('blocked non-loopback requests:', blocked); process.exit(3); }
  validateEnvelopes(Object.fromEntries(served), 'as served during capture');          // the envelopes the UI actually received
  for (const r of records) renameSync(join(stage, r.file.slice(4)), join(OUT, r.file));
  rmSync(stage, { recursive: true, force: true });
  writeFileSync(join(OUT, 'manifest.json'), JSON.stringify({ schema: 'opentrace.uip.visual.manifest/1', increment: 'UIP-03', correction: 'UIP-03 correction 01', tested_commit: COMMIT, viewports: viewports.map((v) => v.id), themes, states: STATES.map((s) => ({ id: s.id, config: s.config, flow: s.flow, note: LABEL[s.flow] })), records }, null, 2) + '\n');
  console.log(`${records.length} captures, manifest written`);
}

async function variance(browser) {
  await startDemo(); await preValidate();
  const repeats = Number(opt('repeats', String(SETTINGS.repeats))); const series = []; const served = new Map();
  for (const st of STATES) for (const vp of viewports) for (const theme of themes) {
    const base = await captureState(browser, st, vp, theme, served); const a = decodePng(base.png); const ratios = [];
    for (let i = 1; i < repeats; i++) { const next = await captureState(browser, st, vp, theme, served); ratios.push(diffStats(a, decodePng(next.png)).ratio); }
    const sum = summarize(ratios); series.push({ state: st.id, viewport: vp.id, theme, repeats, max_ratio: sum.max, threshold: thresholdFor(sum.max) });
    console.log('variance', st.id, vp.id, theme, sum.max);
  }
  validateEnvelopes(Object.fromEntries(served), 'as served during variance');
  mkdirSync(OUT, { recursive: true });
  const body = { schema: 'opentrace.uip.visual.variance/1', increment: 'UIP-03', tested_commit: COMMIT, repeats, metric: 'differing-pixel ratio vs repeat 1; threshold = 2 x max rounded up to 1e-6; never raised', series };
  writeFileSync(join(OUT, 'variance.json'), JSON.stringify(body, null, 2) + '\n');
  writeFileSync(join(OUT, 'thresholds.json'), JSON.stringify({ schema: 'opentrace.uip.visual.thresholds/1', increment: 'UIP-03', thresholds: Object.fromEntries(series.map((s) => [`${s.state}|${s.viewport}|${s.theme}`, s.threshold])) }, null, 2) + '\n');
  console.log(`${series.length} series; max threshold ${Math.max(...series.map((s) => s.threshold))}`);
}

const { browser, close } = await launch();
try { if (cmd === 'capture') await capture(browser); else if (cmd === 'variance') await variance(browser); else { console.error('usage: scan_states.mjs capture|variance'); process.exit(2); } }
finally { await close(); if (demo) demo.stop(); }
