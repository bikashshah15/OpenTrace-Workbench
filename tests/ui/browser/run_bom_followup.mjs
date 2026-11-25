// UIP-08 narrow follow-up browser invocation (BR-01, BR-02, BR-D01, harness repairs, outside-filter path). ONE invocation, executor evidence only.
// Limits: 1 server, 1 Chrome, 2 pages (1366x900 light, 390x844 dark), <= 10 minutes including cleanup, no retry.
//
// Usage (from the worktree root):
//   PYTHON=<python> TMPDIR=<scratch> node tests/ui/browser/run_bom_followup.mjs EVIDENCE_DIR
//
// Limits enforced here: at most one new loopback app-server process and one hermetic headless Chrome; two application viewport
// pages (1366x900 light, 390x844 dark); offline captured Demo only; live scan, advisory lookup and AI phase off; a
// credential-free child environment; every non-loopback request is blocked (browser DNS is also mapped to NOTFOUND) and logged;
// no retry; exact-PID cleanup with try/finally plus an independent shell watchdog; hard stop well inside 15 minutes.
// Real controls and DOM events drive every interaction under test; the store is only read to observe results.
import { spawn, execFileSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync, existsSync, appendFileSync, truncateSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { createHash } from 'node:crypto';
import net from 'node:net';
import { join, resolve, dirname, basename } from 'node:path';
import { fileURLToPath } from 'node:url';
import { connect, newPage, CHROME } from './cdp.mjs';

const T0 = Date.now();
const REPO = resolve(dirname(fileURLToPath(import.meta.url)), '../../..');
const OUT = resolve(process.argv[2] || join(REPO, '.context/logs/UIP-08_BROWSER_CORRECTION_2026-11-15_evidence/browser'));
const PYTHON = process.env.PYTHON || 'python3';
const HARD_STOP_MS = 6 * 60 * 1000;           // no new scenario starts after this
const WATCHDOG_SECONDS = 9 * 60;               // independent shell watchdog (the whole campaign including cleanup is capped at 15 min)
const REFERENCE_SHA = 'd5bc14fabff29dc42a53dab1f91ae88a6165d70aee808f17e76d066901b3a148';
const sha = (p) => createHash('sha256').update(readFileSync(p)).digest('hex');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const now = () => Date.now() - T0;
const git = (...a) => execFileSync('git', ['-C', REPO, ...a], { encoding: 'utf8' }).trim();

// ---------- result bookkeeping ----------
const results = []; const uncovered = []; const scenarios = []; const notes = [];
function check(id, name, ok, detail = '') {
  results.push({ id, name, ok: !!ok, detail: typeof detail === 'string' ? detail : JSON.stringify(detail), t_ms: now() });
  console.log(`${ok ? 'PASS' : 'FAIL'} [${id}] ${name}${detail && !ok ? ': ' + (typeof detail === 'string' ? detail : JSON.stringify(detail)).slice(0, 400) : ''}`);
}
function cover(id, reason) { uncovered.push({ id, reason }); console.log(`UNCOVERED [${id}] ${reason}`); }

// ---------- source pins (before anything is created or started) ----------
const pins = (() => {
  const dirty = git('status', '--porcelain', '--', 'src', 'tests', 'tools', 'evidence');
  return {
    git_head: git('rev-parse', 'HEAD'), tree_src: git('rev-parse', 'HEAD:src'), tree_tests_ui_browser: git('rev-parse', 'HEAD:tests/ui/browser'),
    tree_tests: git('rev-parse', 'HEAD:tests'), tracked_source_dirty: dirty || null,
    harness_sha256: sha(fileURLToPath(import.meta.url)), cdp_sha256: sha(join(REPO, 'tests/ui/browser/cdp.mjs')),
    reference_sha256: sha(join(REPO, '.context/references/prototypes/OpenTrace-UI-Update-9-Combined.html')), reference_expected: REFERENCE_SHA,
    node: process.version, python: PYTHON, chrome: CHROME,
  };
})();
if (pins.tracked_source_dirty) throw new Error('tracked source is dirty; pin would be meaningless: ' + pins.tracked_source_dirty);
if (pins.reference_sha256 !== REFERENCE_SHA) throw new Error('reference hash changed');
mkdirSync(OUT, { recursive: true });

// ---------- process ownership, cleanup and watchdog ----------
const WORK = mkdtempSync(join(tmpdir(), 'uip08-camp-'));
const TOKEN = basename(WORK);                    // appears in the server --session-root and the Chrome --user-data-dir
mkdirSync(join(WORK, 'home'), { recursive: true });
const PIDFILE = join(WORK, 'owned.pids');
writeFileSync(PIDFILE, '');
const psAll = () => execFileSync('/bin/ps', ['-axo', 'pid=,ppid=,command='], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 }).split('\n')
  .map((l) => { const m = l.match(/^\s*(\d+)\s+(\d+)\s+(.*)$/); return m ? { pid: +m[1], ppid: +m[2], cmd: m[3] } : null; }).filter(Boolean);
const procs = { server: null, chrome: null, watchdog: null, seen: new Map() };     // seen: pid -> cmd captured while alive (exact identity)
function descendants(rootPid, all) { const out = new Set(); let frontier = [rootPid]; while (frontier.length) { const next = []; for (const p of all) if (frontier.includes(p.ppid) && !out.has(p.pid)) { out.add(p.pid); next.push(p.pid); } frontier = next; } return out; }
function refreshOwned() {
  const all = psAll(); const mine = new Set();
  for (const p of all) if (p.pid !== process.pid && p.pid !== procs.watchdog && p.cmd.includes(TOKEN)) mine.add(p.pid);
  for (const root of [procs.server, procs.chrome]) if (root) { mine.add(root); for (const d of descendants(root, all)) mine.add(d); }
  for (const p of all) if (mine.has(p.pid) && p.pid !== procs.watchdog) procs.seen.set(p.pid, p.cmd);
  writeFileSync(PIDFILE, [...procs.seen.entries()].filter(([pid]) => mine.has(pid)).map(([pid]) => `${pid} ${TOKEN}`).join('\n') + '\n');
  return all;
}
const alive = (pid) => { try { process.kill(pid, 0); return true; } catch { return false; } };
const WD = `P=$1; LIMIT=$2; FILE=$3; i=0
while kill -0 "$P" 2>/dev/null && [ "$i" -lt "$LIMIT" ]; do sleep 1; i=$((i+1)); done
if [ -s "$FILE" ]; then while read -r pid token; do [ -n "$pid" ] || continue
  if /bin/ps -p "$pid" -o command= 2>/dev/null | /usr/bin/grep -qF -- "$token"; then kill -9 "$pid" 2>/dev/null; fi; done < "$FILE"; fi`;
const wd = spawn('/bin/sh', ['-c', WD, 'wd', String(process.pid), String(WATCHDOG_SECONDS), PIDFILE], { detached: true, stdio: 'ignore' });
wd.unref(); procs.watchdog = wd.pid;

const accounting = { started: new Date(T0).toISOString(), work_dir_token: TOKEN, server_pid: null, chrome_pid: null, watchdog_pid: procs.watchdog, owned_peak: [], port: null, cleanup: null };
let browserConn = null; let chromeProc = null; let serverProc = null; let cleaned = false; const pagesOpen = [];

async function cleanup(reason) {
  if (cleaned) return accounting.cleanup; cleaned = true;
  const log = { reason, steps: [], t_ms_start: now() };
  const step = (s) => log.steps.push(`${now()}ms ${s}`);
  try { for (const p of pagesOpen.splice(0)) await Promise.race([p.close(), sleep(1500)]).catch(() => {}); } catch { /* best effort */ }
  try { browserConn?.close(); } catch { /* ignore */ }
  let all = []; try { all = refreshOwned(); } catch (e) { step('refreshOwned failed ' + e.message); }
  const targets = [...procs.seen.entries()].filter(([pid]) => alive(pid));
  step(`owned processes alive before stop: ${targets.length}`);
  // Exact PIDs only; TERM first, then KILL after a short grace. The identity (captured command) is re-checked before every signal.
  const same = (pid, cmd) => { try { return psAll().some((p) => p.pid === pid && p.cmd === cmd); } catch { return false; } };
  for (const sig of ['SIGTERM', 'SIGKILL']) {
    for (const [pid, cmd] of targets) if (alive(pid) && same(pid, cmd)) { try { process.kill(pid, sig); } catch { /* gone */ } }
    for (let i = 0; i < 30 && targets.some(([pid]) => alive(pid)); i++) await sleep(100);
    if (!targets.some(([pid]) => alive(pid))) break;
  }
  const leftover = targets.filter(([pid]) => alive(pid) && same(pid, procs.seen.get(pid))).map(([pid]) => pid);
  step(`leftover after stop: ${JSON.stringify(leftover)}`);
  let portFree = null;
  if (accounting.port) portFree = await new Promise((res) => { const s = net.connect({ host: '127.0.0.1', port: accounting.port }); s.on('connect', () => { s.destroy(); res(false); }); s.on('error', () => res(true)); setTimeout(() => { s.destroy(); res(null); }, 1500); });
  step(`port ${accounting.port} released: ${portFree}`);
  const stray = (() => { try { return psAll().filter((p) => p.pid !== process.pid && p.pid !== procs.watchdog && p.cmd.includes(TOKEN)).map((p) => p.pid); } catch { return ['ps failed']; } })();
  step(`processes still carrying the campaign token: ${JSON.stringify(stray)}`);
  try { truncateSync(PIDFILE, 0); } catch { /* ignore */ }
  try { if (procs.watchdog && alive(procs.watchdog)) process.kill(procs.watchdog, 'SIGKILL'); } catch { /* ignore */ }
  await sleep(100); step(`watchdog ${procs.watchdog} alive after stop: ${alive(procs.watchdog)}`);
  log.owned_total = targets.length; log.leftover = leftover; log.port_released = portFree; log.stray_token_pids = stray; log.watchdog_alive = alive(procs.watchdog); log.t_ms_end = now();
  accounting.cleanup = log; return log;
}
for (const sig of ['SIGINT', 'SIGTERM']) process.on(sig, () => { cleanup('signal ' + sig).finally(() => process.exit(130)); });
process.on('exit', () => { try { for (const pid of procs.seen.keys()) if (alive(pid) && !cleaned) process.kill(pid, 'SIGKILL'); } catch { /* ignore */ } });

// ---------- network control: block non-loopback, log everything, optionally hold chosen real requests ----------
const netLog = []; let BASE = null;
async function attachNet(pg, label) {
  const rules = [];
  const ctl = {
    rules, label,
    hold(name, match, limit = 1) { const r = { name, match, limit, taken: 0, held: [] }; rules.push(r); return r; },
    async waitHeld(r, n = 1, timeout = 15000) { const t = Date.now(); while (Date.now() - t < timeout) { if (r.held.length >= n) return true; await sleep(30); } throw new Error(`timeout waiting for ${n} held ${r.name} request(s); have ${r.held.length}`); },
    async release(r) { const items = r.held.splice(0); for (const h of items) { h.released_ms = now(); await pg.send('Fetch.continueRequest', { requestId: h.requestId }).catch((e) => { h.release_error = String(e.message || e); }); } return items; },
    async releaseAll() { for (const r of rules) await ctl.release(r); rules.length = 0; },
    since(t0, filter = () => true) { return netLog.filter((e) => e.page === label && e.t_ms > t0 && filter(e)); },
  };
  browserConn.on((m) => {
    if (m.sessionId !== pg.sessionId || m.method !== 'Fetch.requestPaused') return;
    const { requestId, request } = m.params; const url = request.url;
    let u = null; try { u = new URL(url); } catch { /* opaque */ }
    const loopback = !!BASE && url.startsWith(BASE.replace(/\/$/, '') + '/');
    const entry = { t_ms: now(), page: label, method: request.method, url, path: u ? u.pathname : null, decision: null };
    if (!loopback && /^(https?|wss?|ftp):/i.test(url)) { entry.decision = 'BLOCKED_NON_LOOPBACK'; netLog.push(entry); pg.send('Fetch.failRequest', { requestId, errorReason: 'BlockedByClient' }).catch(() => {}); return; }
    const rule = rules.find((r) => r.taken < r.limit && r.match(u, request));
    if (rule) { rule.taken++; entry.decision = 'held:' + rule.name; entry.held_ms = now(); rule.held.push({ requestId, url, held_ms: now() }); netLog.push(entry); return; }
    entry.decision = 'continued'; netLog.push(entry);
    pg.send('Fetch.continueRequest', { requestId }).catch(() => {});
  });
  await pg.send('Fetch.enable', { patterns: [{ urlPattern: '*' }] });
  return ctl;
}
const isPath = (suffix) => (u) => !!u && u.pathname.endsWith(suffix);
const isQueue = (u) => isPath('/bom-candidates')(u);
const isGraphFocused = (u) => isPath('/bom-graph')(u) && u.searchParams.get('scope_kind') === 'focused_candidate';
const isRelated = (u) => isPath('/bom-related-checks')(u);

// ---------- in-page observation helpers (read only) ----------
const SNAP = `(()=>{const s=window.__otStore.get(),b=s.bom8;return {tab:s.workbench.tab,view:b.view,filter:b.filter,q:b.q,offset:b.offset,selected:b.selected,selectedRecord:b.selectedRecord,pin:b.pin?b.pin.item_id:null,popup:b.popup,
graphKind:b.graph?b.graph.scope.kind:null,graphCand:b.graph?(b.graph.scope.candidate_id||null):null,graphNodeIds:b.graph?b.graph.nodes.map(n=>n.node_id):[],relatedSubject:b.related?b.related.subject.id:null,relatedRes:b.related?b.related.resolution:null,
relatedTotal:b.related?b.related.related_total:null,relatedOffset:b.related?b.related.page.offset:null,queueIds:b.queue?b.queue.items.map(x=>x.item_id):null,filtered:b.queue?b.queue.counts.filtered_total:null,
reqQ:!!b.req.queue,reqG:!!b.req.graph,reqR:!!b.req.related,error:b.error,drawer:b.drawer,tlife:b.tlife,plife:b.plife,group:b.group,fullQ:b.fullQ||''}})()`;
const snap = (pg) => pg.eval(SNAP);
const waitSnap = (pg, fn, timeout = 20000, label) => pg.waitFor(`(${fn})(${SNAP})`, timeout, label || fn);
const probe = (pg, path, params) => pg.eval(`(async()=>{const g=window.__otStore.get().analysis.generation;const u=new URLSearchParams({generation:String(g),...${JSON.stringify(params)}});
const r=await fetch('/api/workbench/v1/${path}?'+u,{credentials:'same-origin'});let body=null;try{body=await r.json()}catch(e){};return {status:r.status,body}})()`);
const probeAll = async (pg, extra = {}) => { const items = []; for (let off = 0; off < 400; off += 25) { const r = await probe(pg, 'bom-candidates', { offset: String(off), size: '25', ...extra }); if (r.status !== 200) throw new Error('queue probe ' + r.status); items.push(...r.body.items); if (!r.body.page.has_more) break; } return items; };
const sel = (action, id) => `[data-action="${action}"][data-id=${JSON.stringify(id)}]`;
const inspectorText = (pg) => pg.eval(`(document.querySelector('.ot-bom8-inspector .ot-bom8-drawer-body')||{}).innerText||''`);
const inspectorH3 = (pg) => pg.eval(`(document.querySelector('.ot-bom8-inspector .ot-bom8-drawer-body h3')||{}).textContent||''`);
const overflow = (pg) => pg.eval('document.documentElement.scrollWidth>innerWidth');

// ---------- page lifecycle ----------
async function startDemo(pg, { dark = false } = {}) {
  await pg.send('Network.clearBrowserCookies');
  await pg.goto(BASE);
  await pg.waitFor(`document.querySelector('#ot-demo')`, 30000);
  if (dark && (await pg.eval('document.documentElement.dataset.theme')) !== 'dark') await pg.click('#ot-theme');
  await pg.click('#ot-demo'); await pg.waitFor(`document.querySelector('#ot-tab-bom')`, 30000);
  await pg.click('#ot-tab-bom');
  await waitSnap(pg, `s=>s.tab==='bom'&&s.queueIds&&s.queueIds.length>0&&!s.reqQ`, 30000, 'queue loaded');
  await waitSnap(pg, `s=>s.selected&&s.graphCand===s.selected&&!s.reqG`, 30000, 'focused graph loaded');
  await pg.waitFor(`document.querySelector('[data-bom-cy="inline"]')?._cy?.nodes().length>0`, 30000);
  await sleep(300);
}
async function relatedKinds(pg, nodeIds, cap = 14) {
  const multi = []; const single = [];
  for (const id of nodeIds.slice(0, cap)) {
    const r = await probe(pg, 'bom-related-checks', { subject_kind: 'record', subject_id: id, size: '20' });
    if (r.status !== 200) continue;
    (r.body.resolution === 'multiple' ? multi : r.body.resolution === 'single' ? single : []).push({ id, total: r.body.related_total });
  }
  return { multi, single };
}
async function openChooser(pg, recId) {
  await pg.click(`.ot-bom8-main ${sel('bom-record', recId)}`);
  await waitSnap(pg, `s=>s.popup==='chooser'&&s.relatedSubject===${JSON.stringify(recId)}`, 20000, 'chooser open');
}

// ---------- follow-up scenarios ----------
const ctx = { net: null };
const pageLogs = []; const flows = []; const diagAll = [];
const collectLogs = (pg) => pageLogs.push({ label: pg.label, exceptions: pg.log.exceptions, console_errors_and_warnings: pg.log.console.filter((c) => c.type === 'error' || c.type === 'warning' || c.type === 'warn'), failed_loads: pg.log.failed });
async function scenario(id, fn) {
  if (now() > HARD_STOP_MS) { cover(id, 'not run: hard-stop time reached'); scenarios.push({ id, status: 'not_run', ms: 0 }); return; }
  const t = now(); let status = 'ok';
  try { await fn(); } catch (e) { status = 'scenario_error'; check(id + '.completed', `${id} ran to completion`, false, String(e.stack || e).slice(0, 900)); }
  finally { try { await ctx.net?.releaseAll(); } catch { /* ignore */ } scenarios.push({ id, status, ms: now() - t }); try { refreshOwned(); } catch { /* ignore */ } }
}
// Test-scoped Cytoscape diagnostics (BR-D01): installed before any app script; every event is timestamped and tagged with the running scenario.
// The wrapper records and RE-THROWS: it neither suppresses nor alters application behavior.
const DIAG = `(() => {
  const D = window.__diag = { events: [] }; window.__scn = 'document-start';
  const rec = (kind, o) => D.events.push({ t: Math.round(performance.now()), scenario: window.__scn, kind, ...o });
  addEventListener('error', (e) => rec('window.error', { message: e.message, stack: e.error && e.error.stack }));
  addEventListener('unhandledrejection', (e) => rec('unhandledrejection', { message: String(e.reason), stack: e.reason && e.reason.stack }));
  const ce = console.error; console.error = function (...a) { rec('console.error', { text: a.map((x) => (x && x.stack) ? x.stack : String(x)).join(' ').slice(0, 1800) }); return ce.apply(this, a); };
  let real = null;
  const wrap = function (opts, ...rest) {
    const c = opts && opts.container; let info = { headless: !c };
    if (c) { const r = c.getBoundingClientRect(), cs = getComputedStyle(c); info = { host: (c.dataset && (c.dataset.bomCy || c.dataset.keep)) || c.id || c.className, connected: c.isConnected, clientW: c.clientWidth, clientH: c.clientHeight, rectW: Math.round(r.width), rectH: Math.round(r.height), padL: cs.getPropertyValue('padding-left'), display: cs.display, hostHasCy: !!c._cy }; }
    rec('cytoscape.construct', info);
    try { const cy = real.apply(this, [opts, ...rest]); rec('cytoscape.constructed', { host: info.host, connected: c ? c.isConnected : null }); return cy; }
    catch (e) { rec('cytoscape.construct.error', { ...info, message: e.message, stack: e.stack }); throw e; }
  };
  Object.defineProperty(window, 'cytoscape', { configurable: true, get() { return real ? wrap : undefined; }, set(v) { real = v; Object.keys(v || {}).forEach((k) => { wrap[k] = v[k]; }); } });
  new MutationObserver((ms) => { for (const m of ms) for (const n of m.removedNodes) { if (n.nodeType !== 1) continue; const hs = (n.matches && n.matches('[data-bom-cy]')) ? [n] : (n.querySelectorAll ? [...n.querySelectorAll('[data-bom-cy]')] : []); for (const h of hs) rec('host.removed', { host: h.dataset.bomCy, hadCy: !!h._cy }); } }).observe(document, { childList: true, subtree: true });
})();`;
const DIAG_ERR = new Set(['window.error', 'unhandledrejection', 'console.error', 'cytoscape.construct.error']);
const scn = (pg, name) => pg.eval(`window.__scn=${JSON.stringify(name)}`);
const harvest = async (pg, label) => { try { const ev = await pg.eval(`window.__diag?window.__diag.events:[]`); if (ev.length) diagAll.push({ page: pg.label, document: label, events: ev }); return ev; } catch { return []; } };
const diagSince = async (pg, from) => (await pg.eval(`window.__diag?window.__diag.events:[]`)).filter((e) => e.t >= from);
const tNow = (pg) => pg.eval('Math.round(performance.now())');
async function diagCheck(pg, id, label, t0) {
  const ev = await diagSince(pg, t0); const errs = ev.filter((e) => DIAG_ERR.has(e.kind)); const cons = ev.filter((e) => e.kind === 'cytoscape.construct');
  check(`${id}.no-graph-error`, `${label}: no Cytoscape/page error recorded by the timestamped diagnostics`, errs.length === 0, errs.slice(0, 3));
  check(`${id}.hosts-connected`, `${label}: every Cytoscape construction happened on a connected host`, cons.every((e) => e.connected === true), cons.map((e) => ({ t: e.t, host: e.host, connected: e.connected, clientW: e.clientW })));
  return { constructs: cons.length, errors: errs.length };
}
const graphOk = (pg, kind = 'inline') => pg.waitFor(`document.querySelector('[data-bom-cy="${kind}"]')?._cy?.nodes().length>0`, 25000);
const luminance = `(c)=>{const m=c.match(/[\\d.]+/g).slice(0,3).map(Number).map((v)=>{v/=255;return v<=0.03928?v/12.92:Math.pow((v+0.055)/1.055,2.4)});return 0.2126*m[0]+0.7152*m[1]+0.0722*m[2]}`;
const askLimits = async (pg) => {
  await pg.click('[data-action="bom-ask"]'); await waitSnapAssistant(pg);
  const t0 = now(); await pg.click('[data-action="a-ask"][data-q="limits"]'); await sleep(300);
  const turn = await pg.eval(`(()=>{const t=window.__otStore.get().assistant.turns;return t[t.length-1]||null})()`);
  return { turn, requests: ctx.net.since(t0, (e) => /^\/api\//.test(e.path || '')).map((e) => e.path) };
};
const waitSnapAssistant = (pg) => pg.waitFor(`window.__otStore.get().assistant.open===true&&document.querySelector('[data-action="a-ask"][data-q="limits"]')`, 10000);
const resetAssistant = (pg) => pg.eval(`window.__otStore.dispatch({type:'ASSISTANT',patch:{open:false,turns:[]}})`);
const fresh = async (pg, name) => { await harvest(pg, name + ':prev'); await startDemo(pg); await scn(pg, name); };

async function main() {
  // ---- server (one process, loopback, ephemeral port, credential-free env) ----
  const env = { PATH: '/usr/bin:/bin', HOME: join(WORK, 'home'), LANG: 'en_US.UTF-8', TMPDIR: WORK, PYTHONPATH: join(REPO, 'src/core'), PYTHONDONTWRITEBYTECODE: '1',
    OPENTRACE_LIVE_SCAN: '0', OPENTRACE_LIVE_ADVISORIES: '0', OPENTRACE_LIVE_AIBOM: '0' };
  accounting.server_env_keys = Object.keys(env).sort(); accounting.server_env_flags = { OPENTRACE_LIVE_SCAN: '0', OPENTRACE_LIVE_ADVISORIES: '0', OPENTRACE_LIVE_AIBOM: '0' };
  check('setup.env', 'child environment is credential-free', !Object.keys(env).some((k) => /KEY|TOKEN|SECRET|PASS|OPENAI|ANTHROPIC|GITHUB|CREDENTIAL/i.test(k)), accounting.server_env_keys.join(','));
  serverProc = spawn(PYTHON, ['-m', 'opentrace_core.app', '--port', '0', '--session-root', join(WORK, 's')], { cwd: REPO, env, stdio: ['ignore', 'pipe', 'pipe'] });
  procs.server = serverProc.pid; accounting.server_pid = serverProc.pid; refreshOwned();
  let serverLog = ''; serverProc.stderr.on('data', (d) => { serverLog += d; });
  BASE = await new Promise((res, rej) => { let buf = ''; const t = setTimeout(() => rej(new Error('local service failed to start within 30 s')), 30000);
    serverProc.stdout.on('data', (d) => { buf += d; serverLog += d; const m = buf.match(/http:\/\/127\.0\.0\.1:\d+\//); if (m) { clearTimeout(t); res(m[0]); } });
    serverProc.on('exit', (c) => { clearTimeout(t); rej(new Error('local service exited before start: ' + c)); }); });
  accounting.port = Number(new URL(BASE).port); accounting.base = BASE; accounting.t_server_ready_ms = now();
  console.log('server', BASE, 'pid', serverProc.pid);

  // ---- browser (one hermetic headless Chrome) ----
  const chromeDir = join(WORK, 'chrome'); mkdirSync(chromeDir, { recursive: true });
  const cargs = ['--headless=new', '--disable-gpu', '--no-first-run', '--no-default-browser-check', '--hide-scrollbars', `--user-data-dir=${chromeDir}`, '--remote-debugging-port=0',
    '--disable-background-networking', '--disable-component-update', '--disable-sync', '--disable-default-apps', '--no-pings', '--disable-domain-reliability', '--disable-client-side-phishing-detection',
    '--metrics-recording-only', '--password-store=basic', '--use-mock-keychain', '--host-resolver-rules=MAP * ~NOTFOUND , EXCLUDE 127.0.0.1', 'about:blank'];
  chromeProc = spawn(CHROME, cargs, { stdio: ['ignore', 'ignore', 'pipe'], env: { PATH: '/usr/bin:/bin', HOME: join(WORK, 'home'), TMPDIR: WORK } });
  procs.chrome = chromeProc.pid; accounting.chrome_pid = chromeProc.pid; accounting.chrome_args = cargs.filter((a) => !a.startsWith('--user-data-dir')); refreshOwned();
  const wsUrl = await new Promise((resolveWs, rej) => { let buf = ''; const t = setTimeout(() => rej(new Error('chrome did not start within 20 s')), 20000);
    chromeProc.stderr.on('data', (d) => { buf += d; const m = buf.match(/DevTools listening on (ws:\/\/\S+)/); if (m) { clearTimeout(t); resolveWs(m[1]); } });
    chromeProc.on('exit', (c) => { clearTimeout(t); rej(new Error('chrome exited: ' + c)); }); });
  browserConn = await connect(wsUrl); accounting.t_browser_ready_ms = now(); refreshOwned();
  const dtPort = Number(new URL(wsUrl).port); accounting.devtools_port = dtPort;

  const open = async (label, w, h, mobile = false) => { const pg = await newPage(browserConn, { width: w, height: h, mobile }); pg.label = label; pagesOpen.push(pg); const net = await attachNet(pg, label); ctx.net = net; ctx.pg = pg; refreshOwned(); return { pg, net }; };

  
  // ===================== PAGE 1: 1366x900 light =====================
  const { pg, net } = await open('1366x900-light', 1366, 900);
  await pg.send('Page.addScriptToEvaluateOnNewDocument', { source: DIAG });

  // -- C0: cold start (libraries not yet loaded while the BOM workspace repaints) --
  await scenario('C0-cold-start', async () => {
    await pg.send('Network.clearBrowserCookies'); await pg.goto(BASE); await scn(pg, 'C0-cold-start'); const t0 = await tNow(pg);
    await pg.waitFor(`document.querySelector('#ot-demo')`, 30000); await pg.click('#ot-demo'); await pg.waitFor(`document.querySelector('#ot-tab-bom')`, 30000); await pg.click('#ot-tab-bom');
    await waitSnap(pg, `s=>s.tab==='bom'&&s.queueIds&&s.queueIds.length>0&&!s.reqQ`, 30000); await waitSnap(pg, `s=>s.selected&&s.graphCand===s.selected&&!s.reqG`, 30000); await graphOk(pg); await sleep(500);
    const r = await diagCheck(pg, 'C0', 'cold start to first BOM graph', t0); notes.push({ C0: r });
    check('C0.graph-recovered', 'the first BOM graph is live after a cold start', await pg.eval(`document.querySelector('[data-bom-cy="inline"]')._cy.nodes().length>0`));
  });
  // -- C1/C2/C3: the transitions implicated by the diagnosis --
  await scenario('C1-tab-leave-return', async () => {
    await scn(pg, 'C1-tab-leave-return'); const t0 = await tNow(pg);
    await pg.click('#ot-tab-dependencies'); await waitSnap(pg, `s=>s.tab==='dependencies'`); await sleep(900);
    await pg.click('#ot-tab-bom'); await waitSnap(pg, `s=>s.tab==='bom'&&!s.reqQ`, 25000); await graphOk(pg); await sleep(400);
    const r = await diagCheck(pg, 'C1', 'tab leave/return', t0); check('C1.graph-recovered', 'the graph is live again after leaving and returning', true, r);
  });
  await scenario('C2-popup-close-reopen', async () => {
    await scn(pg, 'C2-popup-close-reopen'); const t0 = await tNow(pg);
    await pg.click('[data-action="bom-expand"]'); await waitSnap(pg, `s=>s.popup==='graph'`); await graphOk(pg, 'popup');
    await pg.click('.ot-bom8-overlay [data-action="bom-close"]'); await waitSnap(pg, `s=>s.popup===null`);
    await pg.click('[data-action="bom-expand"]'); await waitSnap(pg, `s=>s.popup==='graph'`); await graphOk(pg, 'popup'); await sleep(400);
    const r = await diagCheck(pg, 'C2', 'expanded popup close/reopen', t0);
    check('C2.popup-graph-live', 'the reopened expanded graph is live', await pg.eval(`document.querySelector('[data-bom-cy="popup"]')._cy.nodes().length>0`), r);
    await pg.key('Escape'); await waitSnap(pg, `s=>s.popup===null`);
  });
  await scenario('C3-zero-result-restore', async () => {
    await scn(pg, 'C3-zero-result-restore'); const t0 = await tNow(pg);
    await pg.type('#ot-bom8-q', 'zzq'); await waitSnap(pg, `s=>s.q==='zzq'&&s.queueIds&&s.queueIds.length===0&&!s.reqQ`, 20000); await sleep(300);
    check('C3.graph-removed', 'zero results remove the graph host', await pg.eval(`!document.querySelector('[data-bom-cy]')`));
    await pg.eval(`(()=>{const e=document.querySelector('#ot-bom8-q');e.value='';e.dispatchEvent(new Event('input',{bubbles:true}))})()`);
    notes.push({ C3_clear_search: 'HARNESS: the search field was emptied programmatically with a real input event' });
    await waitSnap(pg, `s=>s.q===''&&s.queueIds&&s.queueIds.length>0&&!s.reqQ`, 20000); await waitSnap(pg, `s=>s.selected&&s.graphCand===s.selected&&!s.reqG`, 20000); await graphOk(pg); await sleep(400);
    await pg.click('[data-action="bom-filter"][data-filter="represented"]'); await waitSnap(pg, `s=>s.filter==='represented'&&s.queueIds&&s.queueIds.length===0&&!s.reqQ`, 20000);
    await pg.click('[data-action="bom-filter"][data-filter="all"]'); await waitSnap(pg, `s=>s.filter==='all'&&s.queueIds&&s.queueIds.length>0&&!s.reqQ`, 20000); await waitSnap(pg, `s=>s.selected&&s.graphCand===s.selected&&!s.reqG`, 20000); await graphOk(pg); await sleep(400);
    const r = await diagCheck(pg, 'C3', 'zero-result graph removal and restoration (search and filter)', t0);
    check('C3.graph-restored', 'the graph is restored after zero-result states', true, r);
  });
  await scenario('C4-rapid-churn', async () => {
    await scn(pg, 'C4-rapid-churn'); const t0 = await tNow(pg);
    for (const v of ['software', 'full', 'gaps', 'crypto', 'gaps']) { await pg.click(`[data-action="bom-view"][data-view="${v}"]`); await sleep(40); }
    await pg.click('#ot-tab-ai'); await sleep(30); await pg.click('#ot-tab-bom');
    await waitSnap(pg, `s=>s.tab==='bom'&&s.view==='gaps'&&s.queueIds&&s.queueIds.length>0&&!s.reqQ`, 25000); await waitSnap(pg, `s=>s.selected&&s.graphCand===s.selected&&!s.reqG`, 25000); await graphOk(pg); await sleep(600);
    const r = await diagCheck(pg, 'C4', 'rapid view/tab churn', t0); check('C4.graph-recovered', 'the graph recovers after rapid view and tab churn', true, r);
  });
  // -- R1: the dependencies request the application itself sends --
  await scenario('R1-dependencies-request', async () => {
    await fresh(pg, 'R1'); const t0 = now(); await pg.click('#ot-tab-dependencies'); await sleep(1500);
    const mine = pg.log.responses.filter((r) => r.url.includes('/dependencies'));
    const reqs = net.since(t0, (e) => (e.path || '').includes('dependencies'));
    writeFileSync(join(OUT, 'dependencies_request.json'), JSON.stringify({ app_requests: reqs.map((e) => ({ method: e.method, url: e.url })), responses: mine.map((r) => ({ url: r.url, status: r.status })) }, null, 2) + '\n');
    check('R1.dependencies', 'the Dependencies tab issues its own request(s) and every one answers 200 (the earlier 400 came from the harness probe shape)', reqs.length > 0 && mine.length > 0 && mine.every((r) => r.status === 200), { reqs: reqs.map((e) => e.url), statuses: mine.map((r) => r.status) });
    await pg.click('#ot-tab-bom'); await waitSnap(pg, `s=>s.tab==='bom'`);
  });
  // -- A1: Ask about this for an ordinary candidate (candidate deliberately selected, no record) --
  await scenario('A1-ask-ordinary', async () => {
    await fresh(pg, 'A1'); await pg.click('.ot-bom8-rows [data-action="bom-select"]:nth-child(2)'); await waitSnap(pg, `s=>s.selected===s.queueIds[1]&&s.graphCand===s.selected&&!s.reqG&&s.selectedRecord===null`, 20000);
    const s0 = await snap(pg); const item = (await probeAll(pg)).find((x) => x.item_id === s0.selected);
    check('A1.inspector', 'the candidate inspector and its Ask control exist for the selected candidate', await pg.eval(`!!document.querySelector('[data-action="bom-ask"]')`));
    const { turn, requests } = await askLimits(pg);
    check('A1.limits', 'ordinary candidate: the guide gives the existing recorded-scope limitation, cited with the exact candidate/assertion/rule/inventory IDs', !!turn && /does not establish installation, runtime use or completeness beyond its recorded scope/.test(turn.text) && turn.cite.includes(s0.selected) && turn.cite.includes(item.assertion_id) && (!item.rule_id || turn.cite.includes(item.rule_id)), { turn, expected_ids: [s0.selected, item.assertion_id, item.rule_id] });
    check('A1.no-request', 'asking issued no request (no model, no network submission, nothing auto-submitted)', requests.length === 0 && (await pg.eval(`window.__otStore.get().assistant.turns.length`)) === 1, requests);
    await resetAssistant(pg);
  });
  // -- A2: Ask about this for a pinned, rule-backed, out-of-list candidate (BR-02) --
  await scenario('A2-ask-pinned', async () => {
    await fresh(pg, 'A2'); const s0 = await snap(pg); const kinds = await relatedKinds(pg, s0.graphNodeIds);
    if (!kinds.multi.length) { cover('A2', 'no multi-check record in the focused graph'); return; }
    const rec = kinds.multi.sort((a, b) => b.total - a.total)[0].id; const full = await probeAll(pg); const pos = new Map(full.map((x, i) => [x.item_id, i])); const byId = new Map(full.map((x) => [x.item_id, x]));
    await openChooser(pg, rec); await pg.click('.ot-bom8-chooser [data-action="bom-chooser-page"][data-dir="1"]'); await waitSnap(pg, `s=>s.popup==='chooser'&&s.relatedOffset===20`);
    const items = await pg.eval(`window.__otStore.get().bom8.related.items.map(x=>({item_id:x.item_id,display_name:x.display_name,state:x.state}))`);
    const pick = items.find((x) => (pos.get(x.item_id) ?? -1) >= 25 && byId.get(x.item_id)?.rule_id && byId.get(x.item_id)?.assertion_id);
    if (!pick) { cover('A2', 'chooser page 2 offered no rule-backed check beyond queue page 1'); return; }
    const indep = byId.get(pick.item_id);
    await pg.click(`.ot-bom8-chooser ${sel('bom-related', pick.item_id)}`); await waitSnap(pg, `s=>s.graphCand===${JSON.stringify(pick.item_id)}&&!s.reqG&&!s.reqQ&&s.selectedRecord===null`, 25000); await sleep(300);
    const { turn, requests } = await askLimits(pg);
    check('A2.pinned-limits', 'pinned out-of-list rule-backed candidate: the guide states the recorded verdict and which details are not loaded, never "no rule verdict"', !!turn && !/no rule verdict/i.test(turn.text) && new RegExp(indep.state.replaceAll('_', ' ')).test(turn.text) && /not loaded/i.test(turn.text) && /does not establish installation, runtime use or completeness/.test(turn.text), { text: turn?.text, state: indep.state });
    check('A2.pinned-citations', 'citations are the exact candidate and assertion IDs; no rule ID or inventory is invented', !!turn && JSON.stringify(turn.cite) === JSON.stringify([pick.item_id, indep.assertion_id]), { cite: turn?.cite, expected: [pick.item_id, indep.assertion_id], independent_rule: indep.rule_id });
    check('A2.no-request', 'asking issued no request and nothing was auto-submitted', requests.length === 0, requests);
    await pg.screenshot(join(OUT, '1366-light-ask-pinned.png')); flows.push({ id: 'A2', chosen: { ...pick, queue_position: pos.get(pick.item_id), assertion_id: indep.assertion_id, rule_id: indep.rule_id }, turn });
    await resetAssistant(pg);
  });
  // -- O1: outside-filter navigation through Full evidence graph (existing-data route) --
  await scenario('O1-outside-filter', async () => {
    await fresh(pg, 'O1'); const attempt = [];
    await pg.click('[data-action="bom-filter"][data-filter="unknown"]'); await waitSnap(pg, `s=>s.filter==='unknown'&&s.queueIds&&s.queueIds.length>0&&!s.reqQ`, 20000); attempt.push('Coverage unknown filter active');
    const unknown = (await probeAll(pg, { filter_group: 'unknown' })); const unknownIds = new Set(unknown.map((x) => x.item_id));
    await pg.click('[data-action="bom-view"][data-view="full"]'); await waitSnap(pg, `s=>s.view==='full'&&s.graphKind==='full_view'&&!s.reqG`, 25000); attempt.push('Full evidence graph opened');
    await pg.click('[data-action="bom-group"][data-group="all"]'); await waitSnap(pg, `s=>s.group==='all'&&!s.reqG&&s.graphKind==='full_view'`, 25000); attempt.push('All recorded evidence');
    check('O1.filter-retained', 'the Coverage-unknown filter stays active in the Full evidence graph route', (await snap(pg)).filter === 'unknown');
    let target = null; const pattern = /curated-source-reading/;
    await pg.type('#ot-bom8-full-q', 'curated-source-reading'); await sleep(700); await waitSnap(pg, `s=>s.fullQ==='curated-source-reading'&&!s.reqG`, 25000); attempt.push('bounded graph search "curated-source-reading"');
    let ids = (await snap(pg)).graphNodeIds.filter((i) => pattern.test(i)); let kinds = ids.length ? await relatedKinds(pg, ids, 60) : { multi: [], single: [] };
    if (!kinds.multi.length) {                           // bounded paging fallback with an empty search
      await pg.eval(`(()=>{const e=document.querySelector('#ot-bom8-full-q');e.value='';e.dispatchEvent(new Event('input',{bubbles:true}))})()`); await sleep(700); await waitSnap(pg, `s=>s.fullQ===''&&!s.reqG`, 25000);
      for (let p = 0; p < 6 && !kinds.multi.length; p++) { ids = (await snap(pg)).graphNodeIds.filter((i) => pattern.test(i)); attempt.push(`page ${p}: ${ids.length} matching record(s)`); if (ids.length) kinds = await relatedKinds(pg, ids, 60); if (kinds.multi.length) break;
        const more = await pg.eval(`!document.querySelector('[data-action="bom-full-page"][data-dir="1"]').disabled`); if (!more) break; await pg.click('[data-action="bom-full-page"][data-dir="1"]'); await sleep(500); await waitSnap(pg, `s=>!s.reqG`, 25000); }
    }
    attempt.push(`records with several related checks: ${JSON.stringify(kinds.multi)}`);
    if (!kinds.multi.length) { writeFileSync(join(OUT, 'outside_filter_attempt.json'), JSON.stringify({ reachable: false, attempt }, null, 2) + '\n'); cover('O1', 'the shared inventory record was not reachable through bounded search/paging: ' + attempt.join(' > ')); return; }
    target = kinds.multi.sort((a, b) => b.total - a.total)[0].id;
    await pg.click(sel('bom-record', target)); await waitSnap(pg, `s=>s.popup==='chooser'&&s.relatedSubject===${JSON.stringify(target)}`, 20000); attempt.push('related-check chooser opened');
    const full = await probeAll(pg); const byId = new Map(full.map((x) => [x.item_id, x]));
    const items = await pg.eval(`window.__otStore.get().bom8.related.items.map(x=>({item_id:x.item_id,display_name:x.display_name,state:x.state}))`);
    const pick = items.find((x) => !unknownIds.has(x.item_id) && byId.get(x.item_id)?.rule_id && byId.get(x.item_id)?.assertion_id);
    if (!pick) { writeFileSync(join(OUT, 'outside_filter_attempt.json'), JSON.stringify({ reachable: true, chooser_opened: true, attempt, chooser_items: items.length }, null, 2) + '\n'); cover('O1', 'the chooser offered no rule-backed check outside the active filter'); return; }
    const indep = byId.get(pick.item_id); const queueBefore = (await snap(pg)).queueIds;
    await pg.click(`.ot-bom8-chooser ${sel('bom-related', pick.item_id)}`); await waitSnap(pg, `s=>s.graphCand===${JSON.stringify(pick.item_id)}&&!s.reqG&&!s.reqQ`, 25000); await sleep(400);
    const s1 = await snap(pg); const h3 = await inspectorH3(pg); const text = await inspectorText(pg);
    writeFileSync(join(OUT, 'outside_filter_attempt.json'), JSON.stringify({ reachable: true, attempt, record: target, chosen: { ...pick, assertion_id: indep.assertion_id, rule_id: indep.rule_id }, outside_filter: !unknownIds.has(pick.item_id) }, null, 2) + '\n');
    check('O1.selected', 'outside-filter choice via Full evidence graph: exact selected ID and pin', s1.selected === pick.item_id && s1.pin === pick.item_id && s1.view === 'gaps', { selected: s1.selected, view: s1.view });
    check('O1.graph', 'returned graph is the chosen check\'s and contains its recorded assertion node', s1.graphKind === 'focused_candidate' && s1.graphCand === pick.item_id && s1.graphNodeIds.includes('assertion:' + indep.assertion_id), { graphCand: s1.graphCand });
    check('O1.inspector', 'inspector shows the chosen check and truthfully says details are not loaded', h3.trim() === pick.display_name.trim() && /Not loaded for this list/.test(text) && text.includes(pick.item_id), { h3 });
    check('O1.filter-kept', 'the Coverage-unknown queue is unchanged and does not list the chosen check', s1.filter === 'unknown' && JSON.stringify(s1.queueIds) === JSON.stringify(queueBefore) && !s1.queueIds.includes(pick.item_id), { filter: s1.filter, queueLen: s1.queueIds.length });
    check('O1.rule-backed', 'the chosen check has a real recorded assertion and rule', !!indep.assertion_id && !!indep.rule_id, { assertion: indep.assertion_id, rule: indep.rule_id });
    flows.push({ id: 'O1', attempt, chosen: pick });
  });
  collectLogs(pg); await harvest(pg, 'final'); await pg.close(); pagesOpen.splice(pagesOpen.indexOf(pg), 1);

  // ===================== PAGE 2: 390x844 dark (then light, same page) =====================
  const m = await open('390x844-dark', 390, 844, true); const mp = m.pg;
  await mp.send('Page.addScriptToEvaluateOnNewDocument', { source: DIAG });
  const measure = (p) => p.eval(`(()=>{const b=document.querySelector('[data-action="bom-drawer"]');const cs=getComputedStyle(b);const lum=${luminance};
    const bg=cs.backgroundColor, fg=cs.color;const L1=lum(fg),L2=lum(bg);const ratio=(Math.max(L1,L2)+0.05)/(Math.min(L1,L2)+0.05);
    return {text:b.textContent.trim(),expanded:b.getAttribute('aria-expanded'),color:fg,background:bg,border:cs.borderTopWidth+' '+cs.borderTopStyle+' '+cs.borderTopColor,ratio:Math.round(ratio*100)/100,display:cs.display,w:Math.round(b.getBoundingClientRect().width),h:Math.round(b.getBoundingClientRect().height),theme:document.documentElement.dataset.theme}})()`);
  const toggleChecks = async (p, mode) => {
    const closedM = await measure(p);
    check(`BR01.${mode}.readable`, `${mode} mobile: the Details toggle's text meets 4.5:1 contrast against its own background`, closedM.ratio >= 4.5 && closedM.text.length > 0, closedM);
    check(`BR01.${mode}.label`, `${mode} mobile: label preserved ("Open details"/"Close details")`, /^(Open|Close) details$/.test(closedM.text), closedM.text);
    await p.click('[data-action="bom-drawer"]'); const openM = await measure(p);
    check(`BR01.${mode}.open-close`, `${mode} mobile: the toggle opens then closes the drawer and updates its label/aria-expanded`, openM.expanded === 'true' && /^Close details$/.test(openM.text) && await p.eval(`document.querySelector('.ot-bom8-inspector').classList.contains('open')`), openM);
    check(`BR01.${mode}.open-readable`, `${mode} mobile: the open-state "Close details" text is readable`, openM.ratio >= 4.5, openM);
    await p.key('Shift'); await p.eval(`document.querySelector('[data-action="bom-drawer"]').focus()`); await sleep(120);
    const f = await p.eval(`(()=>{const b=document.querySelector('[data-action="bom-drawer"]');const cs=getComputedStyle(b);return {active:document.activeElement===b,focusVisible:b.matches(':focus-visible'),outlineStyle:cs.outlineStyle,outlineWidth:cs.outlineWidth,outlineColor:cs.outlineColor}})()`);
    check(`BR01.${mode}.focus`, `${mode} mobile: keyboard focus is visible on the toggle (outline preserved)`, f.active && f.focusVisible && f.outlineStyle !== 'none' && parseFloat(f.outlineWidth) > 0, f);
    await p.screenshot(join(OUT, `390-${mode}-details-toggle-open.png`));
    await p.click('[data-action="bom-drawer"]'); const closedAgain = await measure(p);
    check(`BR01.${mode}.closes`, `${mode} mobile: the toggle closes the drawer again`, closedAgain.expanded === 'false' && /^Open details$/.test(closedAgain.text) && await p.eval(`!document.querySelector('.ot-bom8-inspector').classList.contains('open')`), closedAgain);
    flows.push({ id: 'BR01-' + mode, closedM, openM, focus: f });
  };
  await scenario('M1-details-toggle', async () => {
    await startDemo(mp, { dark: true }); await scn(mp, 'M1');
    check('BR01.theme', 'the mobile page is dark', (await mp.eval(`document.documentElement.dataset.theme`)) === 'dark');
    await toggleChecks(mp, 'dark');
    await mp.click('#ot-theme'); await sleep(400);
    check('BR01.theme-light', 'switched to light theme on the same page', (await mp.eval(`document.documentElement.dataset.theme`)) !== 'dark');
    await toggleChecks(mp, 'light');
    check('M1.no-overflow', 'no horizontal overflow at 390 px', !(await overflow(mp)));
  });
  collectLogs(mp); await harvest(mp, 'final'); await mp.close(); pagesOpen.splice(pagesOpen.indexOf(mp), 1);
}

let fatal = null;
try { await main(); } catch (e) { fatal = String(e.stack || e); console.error('FATAL', fatal); }
finally {
  const allLogs = [];
  try { /* page logs are collected from pages still open only; closed pages already released their handlers */ } catch { /* ignore */ }
  // cleanup first so that nothing keeps running while the evidence is written
  await cleanup(fatal ? 'fatal error' : 'normal end');
}
// network-attempt accounting
const blocked = netLog.filter((e) => e.decision === 'BLOCKED_NON_LOOPBACK');
const nonLoop = netLog.filter((e) => !(BASE && e.url.startsWith(BASE.replace(/\/$/, '') + '/')) && /^(https?|wss?):/i.test(e.url));
check('NET.no-external', 'no non-loopback request was attempted by the page (blocked attempts recorded separately)', blocked.length === 0 && nonLoop.length === 0, { blocked: blocked.length, nonLoopbackSeen: nonLoop.length });
const exc = pageLogs.flatMap((l) => l.exceptions.map((x) => l.label + ': ' + x));
const cerr = pageLogs.flatMap((l) => l.console_errors_and_warnings.filter((c) => !/Failed to load resource.*(404|409)/.test(c.text)).map((c) => l.label + ': ' + c.text));
check('CONSOLE.no-exceptions', 'no uncaught page exception in any viewport', exc.length === 0, exc.slice(0, 5));
check('CONSOLE.no-errors', 'no unexpected console error/warning (the deliberate scan-status 404 probe is excluded)', cerr.length === 0, cerr.slice(0, 5));
writeFileSync(join(OUT, 'console.json'), JSON.stringify({ schema: 'opentrace.uip08.console/1', pages: pageLogs }, null, 2) + '\n');
const posts = [...new Set(netLog.filter((e) => e.method === 'POST').map((e) => e.path))];
check('NET.no-scan-ai-post', 'no scan, live-analysis, intake-preview or AI request was issued (POSTs: ' + posts.join(', ') + ')', !posts.some((p) => ['/api/scan', '/api/analysis/live', '/api/intake/preview'].includes(p)), posts);
const cl = accounting.cleanup || {};
check('CLEAN.processes', 'every owned server/browser process is gone and the selected port is released', !!cl.leftover && cl.leftover.length === 0 && cl.stray_token_pids?.length === 0 && cl.port_released === true && cl.watchdog_alive === false, cl);
const counts = { total: results.length, passed: results.filter((r) => r.ok).length, failed: results.filter((r) => !r.ok).length, uncovered: uncovered.length, scenario_errors: scenarios.filter((s) => s.status === 'scenario_error').length };
accounting.finished = new Date().toISOString(); accounting.total_ms = now(); accounting.scenarios = scenarios;
writeFileSync(join(OUT, 'result.json'), JSON.stringify({ schema: 'opentrace.uip08.browser_followup/1', fixture: 'offline captured Demo, loopback app, live scan/advisories/AI phase off, credential-free child environment', viewports: ['1366x900 light', '390x844 dark (+ light on the same page)'], executor_evidence_awaiting_independent_review: true, counts, fatal, uncovered, notes, results }, null, 2) + '\n');
writeFileSync(join(OUT, 'flows.json'), JSON.stringify({ schema: 'opentrace.uip08.followup_flows/1', flows }, null, 2) + '\n');
writeFileSync(join(OUT, 'network_attempts.json'), JSON.stringify({ schema: 'opentrace.uip08.network_attempts/1', base: BASE, blocked_non_loopback: blocked, total_requests: netLog.length, held_requests: netLog.filter((e) => String(e.decision).startsWith('held:')), all: netLog }, null, 2) + '\n');
writeFileSync(join(OUT, 'process_accounting.json'), JSON.stringify(accounting, null, 2) + '\n');
writeFileSync(join(OUT, 'graph_diagnostics.json'), JSON.stringify({ schema: 'opentrace.uip08.graph_diagnostics/1', note: 'Test-scoped timestamped events (performance.now per document); scenario tags; construction wrapper re-throws', documents: diagAll }, null, 2) + '\n');
writeFileSync(join(OUT, 'source_pins.json'), JSON.stringify(pins, null, 2) + '\n');
try { rmSync(WORK, { recursive: true, force: true }); } catch { /* ignore */ }
console.log(JSON.stringify(counts), 'elapsed_ms', now());
process.exitCode = counts.failed || counts.scenario_errors || fatal ? 1 : 0;
