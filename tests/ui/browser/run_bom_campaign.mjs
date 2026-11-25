// UIP-08 bounded offline browser/server campaign (merged, corrected source). ONE invocation, executor evidence only.
//
// Usage (from the worktree root):
//   PYTHON=<python> TMPDIR=<scratch> node tests/ui/browser/run_bom_campaign.mjs EVIDENCE_DIR
//
// Limits enforced here: at most one new loopback app-server process and one hermetic headless Chrome; three application viewport
// pages (1366x900 light, 1600x900 light, 390x844 dark); offline captured Demo only; live scan, advisory lookup and AI phase off; a
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
const OUT = resolve(process.argv[2] || join(REPO, '.context/logs/UIP-08_BROWSER_VALIDATION_2026-11-15_evidence'));
const PYTHON = process.env.PYTHON || 'python3';
const HARD_STOP_MS = 9.5 * 60 * 1000;           // no new scenario starts after this
const WATCHDOG_SECONDS = 13 * 60;               // independent shell watchdog (the whole campaign including cleanup is capped at 15 min)
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

// ---------- scenarios ----------
const ctx = { pages: {}, nets: {} };
const pageLogs = [];
const collectLogs = (pg) => pageLogs.push({ label: pg.label, exceptions: pg.log.exceptions, console_errors_and_warnings: pg.log.console.filter((c) => c.type === 'error' || c.type === 'warning' || c.type === 'warn'), failed_loads: pg.log.failed });
const pins01 = [];                      // per-flow evidence for IR-01
async function scenario(id, fn) {
  if (now() > HARD_STOP_MS) { cover(id, 'not run: campaign hard-stop time reached'); scenarios.push({ id, status: 'not_run', ms: 0 }); return; }
  const t = now(); let status = 'ok';
  try { await fn(); } catch (e) { status = 'scenario_error'; check(id + '.completed', `${id} ran to completion`, false, String(e.stack || e).slice(0, 900)); }
  finally { try { await ctx.net?.releaseAll(); } catch { /* ignore */ } scenarios.push({ id, status, ms: now() - t }); try { refreshOwned(); } catch { /* ignore */ } }
}

// IR-01 flow: choose a real related check that lies outside the queue page / filter / search, with a chosen delivery order.
async function ir01Flow(pg, net, { id, context, order, shots = false }) {
  const label = `${id}`;
  await startDemo(pg);
  let queueBefore = null; let outside = null; let contextNote = '';
  if (context === 'search') {
    await pg.type('#ot-bom8-q', 'aiofiles'); await waitSnap(pg, `s=>s.q==='aiofiles'&&s.queueIds&&s.queueIds.length===1&&!s.reqQ`, 20000, 'search results');
    await waitSnap(pg, `s=>s.selected&&s.graphCand===s.selected&&!s.reqG`, 20000, 'graph for search result'); await sleep(250);
    outside = new Set((await probeAll(pg, { query: 'aiofiles' })).map((x) => x.item_id)); contextNote = 'search "aiofiles" (1 match)';
  } else if (context === 'filter') {
    await pg.click('[data-action="bom-filter"][data-filter="unknown"]'); await waitSnap(pg, `s=>s.filter==='unknown'&&s.queueIds&&s.queueIds.length>0&&!s.reqQ`, 20000, 'filter results');
    await waitSnap(pg, `s=>s.selected&&s.graphCand===s.selected&&!s.reqG`, 20000, 'graph for filtered result'); await sleep(250);
    outside = new Set((await probeAll(pg, { filter_group: 'unknown' })).map((x) => x.item_id)); contextNote = 'filter "Coverage unknown"';
  } else contextNote = 'queue page 1 of 25 (chosen candidate lies beyond it)';
  const s0 = await snap(pg); queueBefore = s0.queueIds;
  const kinds = await relatedKinds(pg, s0.graphNodeIds);
  if (!kinds.multi.length) { cover(`${id}`, `no record with several related checks in the focused graph (${contextNote}); not substituted`); return; }
  const rec = kinds.multi.sort((a, b) => b.total - a.total)[0];
  const full = await probeAll(pg); const pos = new Map(full.map((x, i) => [x.item_id, i])); const byId = new Map(full.map((x) => [x.item_id, x]));
  await openChooser(pg, rec.id);
  let items = (await snap(pg)).relatedTotal;
  if (context === 'page2') { await pg.click('.ot-bom8-chooser [data-action="bom-chooser-page"][data-dir="1"]'); await waitSnap(pg, `s=>s.popup==='chooser'&&s.relatedOffset===20&&s.relatedSubject===${JSON.stringify(rec.id)}`, 20000, 'chooser page 2'); }
  const chooserItems = await pg.eval(`window.__otStore.get().bom8.related.items.map(x=>({item_id:x.item_id,display_name:x.display_name,assertion_id:x.assertion_id,state:x.state}))`);
  const candidate = chooserItems.find((x) => context === 'page2' ? (pos.get(x.item_id) ?? -1) >= 25 : !outside.has(x.item_id));
  if (!candidate) { cover(`${id}`, `chooser offered no check outside the ${contextNote}`); return; }
  const indep = byId.get(candidate.item_id);
  const chosen = { item_id: candidate.item_id, display_name: candidate.display_name, queue_position: pos.get(candidate.item_id), assertion_id: indep?.assertion_id || null, rule_id: indep?.rule_id || indep?.finding?.rule_id || null, independent_title: indep?.display?.raw_title || null, record: rec.id, record_related_total: rec.total };
  check(`${id}.fixture`, `${id}: chosen check is a real recorded check outside the ${contextNote}`, !!indep && !!chosen.assertion_id && (context === 'page2' ? chosen.queue_position >= 25 : !outside.has(chosen.item_id)), chosen);
  if (shots) await pg.screenshot(join(OUT, `1366-light-chooser-${context}.png`));
  let hold = null; const t0 = now();
  if (order === 'graph-first') hold = net.hold('queue', (u) => isQueue(u), 1);
  if (order === 'queue-first') hold = net.hold('graph', (u) => isGraphFocused(u), 1);
  await pg.click(`.ot-bom8-chooser ${sel('bom-related', chosen.item_id)}`);
  const phases = {};
  if (order === 'graph-first') {
    await net.waitHeld(hold, 1);
    await waitSnap(pg, `s=>s.graphCand===${JSON.stringify(chosen.item_id)}&&!s.reqG`, 20000, 'graph delivered while queue held');
    const mid = await snap(pg); phases.graph_first = { selected: mid.selected, graphCand: mid.graphCand, queue_pending: mid.reqQ };
    check(`${id}.graph-first`, `${id}: graph delivered first (queue still pending) selects the chosen check`, mid.reqQ && mid.selected === chosen.item_id && mid.graphCand === chosen.item_id, phases.graph_first);
    await net.release(hold); await waitSnap(pg, `s=>!s.reqQ`, 20000, 'queue delivered after');
  } else if (order === 'queue-first') {
    await net.waitHeld(hold, 1);
    await waitSnap(pg, `s=>!s.reqQ&&s.queueIds&&s.queueIds.length>0`, 20000, 'queue delivered while first graph held');
    const mid = await snap(pg); phases.queue_first = { selected: mid.selected, queue_first_id: mid.queueIds[0], first_graph_still_held: hold.held.length === 1 };
    check(`${id}.queue-first`, `${id}: queue delivered first (graph held) does not replace the chosen check`, mid.selected === chosen.item_id && mid.queueIds[0] !== chosen.item_id && hold.held.length === 1, phases.queue_first);
    await waitSnap(pg, `s=>s.graphCand===${JSON.stringify(chosen.item_id)}&&!s.reqG`, 20000, 'follow-up graph delivered');
    const before = await snap(pg); await net.release(hold); await sleep(600); const after = await snap(pg);
    check(`${id}.late-graph`, `${id}: the older held graph response changes nothing when released`, JSON.stringify([before.selected, before.graphCand, before.pin]) === JSON.stringify([after.selected, after.graphCand, after.pin]), { before: [before.selected, before.graphCand], after: [after.selected, after.graphCand] });
  } else await waitSnap(pg, `s=>s.graphCand===${JSON.stringify(chosen.item_id)}&&!s.reqG&&!s.reqQ`, 20000, 'natural delivery');
  await sleep(350);
  const s1 = await snap(pg); const h3 = await inspectorH3(pg); const text = await inspectorText(pg);
  const graphHasAssertion = chosen.assertion_id ? s1.graphNodeIds.includes('assertion:' + chosen.assertion_id) : false;
  const cyHas = chosen.assertion_id ? await pg.eval(`document.querySelector('[data-bom-cy="inline"]')?._cy?.getElementById(${JSON.stringify('assertion:' + chosen.assertion_id)}).length===1`) : false;
  check(`${id}.selected`, `${id}: selected ID is the chosen check`, s1.selected === chosen.item_id && s1.pin === chosen.item_id, { selected: s1.selected, pin: s1.pin });
  check(`${id}.graph`, `${id}: returned graph candidate ID and rendered graph are the chosen check's`, s1.graphKind === 'focused_candidate' && s1.graphCand === chosen.item_id && graphHasAssertion && cyHas, { graphCand: s1.graphCand, has_assertion_node: graphHasAssertion, cytoscape_has_assertion: cyHas });
  check(`${id}.inspector`, `${id}: inspector shows the chosen check and its canonical ID`, h3.trim() === chosen.display_name.trim() && text.includes(chosen.item_id), { h3, expected: chosen.display_name });
  check(`${id}.unloaded`, `${id}: out-of-list inspector truthfully says inventory/rule details are not loaded`, /Not loaded for this list/.test(text) && /outside the current list/.test(text), text.slice(0, 500));
  check(`${id}.not-substituted`, `${id}: the first queue row was not substituted for the chosen check`, s1.selected !== (s1.queueIds || [])[0] && !(s1.queueIds || []).includes(chosen.item_id), { queueFirst: (s1.queueIds || [])[0], queueLen: (s1.queueIds || []).length });
  if (context !== 'page2') check(`${id}.queue-context-kept`, `${id}: the search/filter queue was not replaced`, JSON.stringify(s1.queueIds) === JSON.stringify(queueBefore), { before: queueBefore.length, after: (s1.queueIds || []).length });
  if (shots) { await pg.eval(`document.querySelector('.ot-bom8')?.scrollIntoView({block:'start'})`); await sleep(150); await pg.screenshot(join(OUT, `1366-light-pinned-${context}-${order}.png`)); }
  pins01.push({ id, context, order, phases, chosen, final: { selected: s1.selected, graphCand: s1.graphCand, pin: s1.pin, queue_len: (s1.queueIds || []).length } });
}

// ---------- the campaign ----------
const BOM_TAB_ORDER = ['Repository contexts', 'Dependencies', 'Cryptography', 'AI models', 'BOM connections'];
const INNER = ['Software · SBOM', 'Cryptography · CBOM', 'AI models · AI-BOM', 'Full evidence graph', 'Focused gaps'];

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
  // -- S1: home / intake copy before any analysis (AI disclosure inspection only) --
  await scenario('S1-ai-copy', async () => {
    await pg.goto(BASE); await pg.waitFor(`document.querySelector('#ot-demo')`, 30000); await sleep(600);
    const cfg = await pg.eval(`fetch('/api/config',{credentials:'same-origin'}).then(r=>r.json().then(j=>({status:r.status,body:j})))`);
    const disclosure = await pg.eval(`(()=>{const d=document.querySelector('#ot-disclosure');return d?{variant:d.dataset.variant,text:d.innerText}:null})()`);
    const body = await pg.eval(`document.body.innerText.slice(0,2500)`);
    writeFileSync(join(OUT, 'ai_copy.json'), JSON.stringify({ schema: 'opentrace.uip08.ai_copy_inspection/1', note: 'Offline Demo service with live scan, advisories and AI phase disabled: only inspected, nothing started. Flag-on AI disclosure wording is NOT exercised here.', config: cfg, disclosure, home_text_excerpt: body }, null, 2) + '\n');
    check('S1.config', 'GET /api/config answers 200 with live scanning disabled', cfg.status === 200 && cfg.body?.live?.enabled === false, cfg);
    check('S1.no-ai-block', 'the disabled service publishes no ai_bom/AI-availability block (no AI claim possible offline)', !('ai_bom' in (cfg.body?.live || {})), cfg.body);
    check('S1.copy', 'the intake page shows the disabled-service copy (no scan, no AI step wording) or no disclosure block', disclosure === null || (disclosure.variant === 'D' && !/AI inventory step/i.test(disclosure.text)), disclosure || 'no #ot-disclosure rendered');
  });

  // -- S2: combined application, outer tabs, five inner views, coexisting routes --
  await scenario('S2-combined', async () => {
    await startDemo(pg);
    const tabs = await pg.eval(`[...document.querySelectorAll('.ot-tabs [role=tab]')].map(b=>b.textContent.trim())`);
    check('S2.outer-tabs', 'outer tabs in order: Repository contexts, Dependencies, Cryptography, AI models, BOM connections', JSON.stringify(tabs) === JSON.stringify(BOM_TAB_ORDER), tabs);
    const inner = await pg.eval(`[...document.querySelectorAll('.ot-bom8-tabs button')].map(b=>b.textContent.trim())`);
    check('S2.inner-tabs', 'five inner BOM views in the contract order', JSON.stringify(inner) === JSON.stringify(INNER), inner);
    const s0 = await snap(pg);
    check('S2.default-gaps', 'BOM connections defaults to Focused gaps with a selected check and its real graph', s0.view === 'gaps' && !!s0.selected && s0.graphCand === s0.selected, { view: s0.view, selected: s0.selected });
    // five inner views, real clicks
    const seen = [];
    for (const [key, label] of [['software', INNER[0]], ['crypto', INNER[1]], ['ai', INNER[2]], ['full', INNER[3]], ['gaps', INNER[4]]]) {
      await pg.click(`[data-action="bom-view"][data-view="${key}"]`);
      await waitSnap(pg, `s=>s.view===${JSON.stringify(key)}&&!s.reqQ&&s.queueIds!==null`, 25000, 'view ' + key);
      if (key === 'full') await waitSnap(pg, `s=>s.graphKind==='full_view'&&!s.reqG`, 25000, 'full graph');
      await sleep(250);
      const st = await snap(pg); const status = await pg.eval(`[...document.querySelectorAll('.ot-bom8 > .ot-prompt')].map(x=>x.innerText).join(' | ')`);
      seen.push({ view: key, queue_len: st.queueIds.length, filtered: st.filtered, status });
      check(`S2.view-${key}`, `inner view "${label}" renders from real data`, st.view === key && !st.error && (key === 'full' ? st.graphKind === 'full_view' : st.queueIds.length >= 0), { queue_len: st.queueIds.length, filtered: st.filtered, status });
    }
    notes.push({ inner_views: seen });
    // full evidence graph interactions: group cards, node search, exact <scan-root> record
    await pg.click('[data-action="bom-view"][data-view="full"]'); await waitSnap(pg, `s=>s.graphKind==='full_view'&&!s.reqG`);
    for (const g of ['software', 'cryptography', 'ai_model', 'other', 'all']) { await pg.click(`[data-action="bom-group"][data-group="${g}"]`); await waitSnap(pg, `s=>s.group===${JSON.stringify(g)}&&!s.reqG&&s.graphKind==='full_view'`, 25000, 'group ' + g); }
    check('S2.full-groups', 'full-graph family cards switch scope and keep a full_view graph', (await snap(pg)).group === 'all');
    await pg.type('#ot-bom8-full-q', 'scan-root'); await sleep(600); await waitSnap(pg, `s=>s.fullQ==='scan-root'&&!s.reqG`, 25000, 'full search');
    await sleep(300);
    const rec = await pg.eval(`(()=>{const nodes=window.__otStore.get().bom8.graph.nodes.map(n=>n.node_id).filter(id=>id.includes('<scan-root>'));return nodes[0]||null})()`);
    if (!rec) cover('S2.scan-root', 'search for "scan-root" returned no recorded node with the literal <scan-root> segment in this fixture page');
    else {
      const dom = await pg.eval(`(()=>{const b=[...document.querySelectorAll('[data-action="bom-record"]')].find(x=>x.dataset.id===${JSON.stringify(rec)});return {found:!!b,datasetExact:b?b.dataset.id===${JSON.stringify(rec)}:false,text:b?b.textContent:'',injected:!!document.querySelector('scan-root'),anyUnknownEl:[...document.querySelectorAll('.ot-bom8 *')].some(e=>e.tagName.toLowerCase().includes('scan-root'))}})()`);
      check('S2.escaped-id', 'recorded ID with literal <scan-root> is escaped (exact in data-id, no injected element)', dom.found && dom.datasetExact && !dom.injected && !dom.anyUnknownEl, dom);
      await pg.click(sel('bom-record', rec));
      await waitSnap(pg, `s=>s.relatedSubject===${JSON.stringify(rec)}`, 20000, 'related for scan-root record');
      const st = await snap(pg); check('S2.scan-root-lookup', 'the exact <scan-root> ID round-trips through the related-checks route (AM-01)', st.relatedSubject === rec, { subject: st.relatedSubject, resolution: st.relatedRes });
      if (st.popup === 'chooser') { await pg.key('Escape'); await waitSnap(pg, `s=>s.popup===null`); }
    }
    await pg.click('[data-action="bom-view"][data-view="gaps"]'); await waitSnap(pg, `s=>s.view==='gaps'&&!s.reqQ&&s.queueIds&&s.queueIds.length>0`, 25000);
    // coexisting routes in the same running server (read-only probes)
    const routes = [];
    for (const [name, path] of [['bom-candidates', 'bom-candidates?size=25&offset=0'], ['bom-graph', 'bom-graph?scope_kind=full_view&group=all&offset=0'], ['bom-related-checks', null], ['ai-assets', 'ai-assets'], ['crypto-assets', 'crypto-assets'], ['dependencies', 'dependencies'], ['contexts', 'contexts']]) {
      if (!path) continue;
      const r = await pg.eval(`(async()=>{const g=window.__otStore.get().analysis.generation;const sep=${JSON.stringify(path)}.includes('?')?'&':'?';const r=await fetch('/api/workbench/v1/${path}'+sep+'generation='+g,{credentials:'same-origin'});let j=null;try{j=await r.json()}catch(e){};return {status:r.status,schema:j&&(j.schema||j.schema_version)||null,keys:j?Object.keys(j).slice(0,6):null}})()`);
      routes.push({ name, ...r });
    }
    const cfgR = await pg.eval(`fetch('/api/config',{credentials:'same-origin'}).then(r=>({status:r.status}))`); routes.push({ name: 'config', ...cfgR });
    const stR = await pg.eval(`fetch('/api/scan/status?job=job:000000000000000000000000&generation=1',{credentials:'same-origin'}).then(async r=>({status:r.status,body:await r.json().catch(()=>null)}))`); routes.push({ name: 'scan-status(no job)', ...stR });
    const viewAi = await pg.eval(`fetch('/api/view/ai?generation='+window.__otStore.get().analysis.generation,{credentials:'same-origin'}).then(r=>({status:r.status}))`); routes.push({ name: 'view/ai', ...viewAi });
    writeFileSync(join(OUT, 'routes.json'), JSON.stringify({ schema: 'opentrace.uip08.route_coexistence/1', routes }, null, 2) + '\n');
    check('S2.routes-coexist', 'BOM v1 routes and the Cisco-facing read-only config/presentation routes (config, ai-assets, scan-status) answer from the same running server', routes.filter((r) => ['bom-candidates', 'bom-graph', 'ai-assets', 'config'].includes(r.name)).every((r) => r.status === 200) && routes.find((r) => r.name === 'scan-status(no job)').status === 404, routes.map((r) => `${r.name}:${r.status}`).join(' '));
    check('S2.routes-other', 'the other read-only presentation routes also answer 200 (informational; default parameters)', routes.filter((r) => ['crypto-assets', 'dependencies', 'contexts', 'view/ai'].includes(r.name)).every((r) => r.status === 200), routes.map((r) => `${r.name}:${r.status}`).join(' '));
    // other outer tabs render real panels; capture the AI models copy without starting anything
    const panels = {};
    for (const t of ['crypto', 'ai', 'dependencies', 'contexts']) { await pg.click(`#ot-tab-${t}`); await sleep(900); panels[t] = await pg.eval(`document.querySelector('#ot-tabpanel').innerText.slice(0,1800)`); }
    writeFileSync(join(OUT, 'ai_copy.json'), JSON.stringify({ ...JSON.parse(readFileSync(join(OUT, 'ai_copy.json'), 'utf8')), ai_models_panel_excerpt: panels.ai, other_panel_excerpts: { crypto: panels.crypto, dependencies: panels.dependencies, contexts: panels.contexts } }, null, 2) + '\n');
    check('S2.other-tabs', 'Repository contexts, Dependencies, Cryptography and AI models panels render alongside BOM connections', Object.values(panels).every((t) => t.length > 40), Object.fromEntries(Object.entries(panels).map(([k, v]) => [k, v.length])));
    await pg.click('#ot-tab-bom'); await waitSnap(pg, `s=>s.tab==='bom'&&!s.reqQ&&s.queueIds!==null`, 25000);
  });

  // -- S3..S6: IR-01 exact chooser navigation --
  await scenario('S3-ir01-page2-graph-first', () => ir01Flow(pg, net, { id: 'IR01-A', context: 'page2', order: 'graph-first', shots: true }));
  await scenario('S4-ir01-page2-queue-first', () => ir01Flow(pg, net, { id: 'IR01-B', context: 'page2', order: 'queue-first' }));
  await scenario('S5-ir01-outside-search', () => ir01Flow(pg, net, { id: 'IR01-C', context: 'search', order: 'graph-first' }));
  await scenario('S6-ir01-outside-filter', () => ir01Flow(pg, net, { id: 'IR01-D', context: 'filter', order: 'queue-first' }));

  // -- S7: IR-02 search changes, zero match, delayed earlier response, recovery --
  await scenario('S7-ir02-search', async () => {
    await startDemo(pg);
    await pg.click('.ot-bom8-rows [data-action="bom-select"]:nth-child(2)'); await waitSnap(pg, `s=>s.selected&&s.graphCand===s.selected&&!s.reqG`, 20000); await sleep(250);
    const s0 = await snap(pg); const kinds = await relatedKinds(pg, s0.graphNodeIds);
    const recId = (kinds.single[0] || kinds.multi[0] || {}).id;
    if (!recId) { cover('IR02-search', 'no recorded graph record available to select'); return; }
    await pg.click(`.ot-bom8-main ${sel('bom-record', recId)}`); await waitSnap(pg, `s=>s.selectedRecord===${JSON.stringify(recId)}&&(s.relatedSubject===${JSON.stringify(recId)})`, 20000);
    if ((await snap(pg)).popup === 'chooser') { await pg.key('Escape'); await waitSnap(pg, `s=>s.popup===null`); }
    const sel0 = await snap(pg);
    check('IR02-search.setup', 'a candidate, its graph and a graph record are selected through the UI', !!sel0.selected && !!sel0.selectedRecord && sel0.graphCand === sel0.selected, { selected: sel0.selected, record: sel0.selectedRecord });
    const early = net.hold('earlier-search', (u) => isQueue(u) && (u.searchParams.get('query') || '') === 'memray', 1);
    await pg.type('#ot-bom8-q', 'memray'); await net.waitHeld(early, 1);
    await pg.type('#ot-bom8-q', 'zzz-no-such-check'); await waitSnap(pg, `s=>s.q==='zzz-no-such-check'&&s.queueIds&&s.queueIds.length===0&&!s.reqQ`, 20000, 'zero-match queue'); await sleep(300);
    const z = await snap(pg); const dom = await pg.eval(`({cy:!!document.querySelector('[data-bom-cy]'),records:document.querySelectorAll('.ot-bom8-record').length,rows:document.querySelectorAll('.ot-bom8-row').length,inspector:document.querySelector('.ot-bom8-inspector .ot-bom8-drawer-body').innerText,rowsText:document.querySelector('.ot-bom8-rows').innerText})`);
    check('IR02-search.cleared', 'zero-match search clears the incompatible candidate, graph, record, related and pin state', z.selected === null && z.selectedRecord === null && z.relatedSubject === null && z.graphKind === null && z.pin === null, z);
    check('IR02-search.dom', 'zero-match search shows no old graph, records or inspector; says no candidates match', !dom.cy && dom.records === 0 && dom.rows === 0 && /Select a candidate or recorded item/.test(dom.inspector) && /No candidates match/.test(dom.rowsText), dom);
    await net.release(early); await sleep(700);
    const z2 = await snap(pg);
    check('IR02-search.late-response', 'a delayed earlier (memray) response released afterwards restores nothing', z2.queueIds.length === 0 && z2.selected === null && z2.graphKind === null && z2.selectedRecord === null && z2.q === 'zzz-no-such-check', z2);
    // clearing the search restores normal navigation (real Backspace presses; fallback is labeled)
    await pg.eval(`(()=>{const e=document.querySelector('#ot-bom8-q');e.focus();e.setSelectionRange(e.value.length,e.value.length)})()`);
    for (let i = 0; i < 17; i++) await pg.send('Input.dispatchKeyEvent', { type: 'rawKeyDown', key: 'Backspace', code: 'Backspace', windowsVirtualKeyCode: 8, nativeVirtualKeyCode: 8 }).then(() => pg.send('Input.dispatchKeyEvent', { type: 'keyUp', key: 'Backspace', code: 'Backspace', windowsVirtualKeyCode: 8, nativeVirtualKeyCode: 8 }));
    let cleared = (await snap(pg)).q === '';
    if (!cleared) { notes.push({ IR02_clear_search: 'HARNESS FALLBACK: Backspace key events did not edit the field; value cleared programmatically with a real input event' }); await pg.eval(`(()=>{const e=document.querySelector('#ot-bom8-q');e.value='';e.dispatchEvent(new Event('input',{bubbles:true}))})()`); }
    await waitSnap(pg, `s=>s.q===''&&s.queueIds&&s.queueIds.length>0&&!s.reqQ`, 20000, 'queue restored');
    await waitSnap(pg, `s=>s.selected&&s.graphCand===s.selected&&!s.reqG`, 20000, 'graph restored by auto-selection'); await sleep(200);
    await pg.click('.ot-bom8-rows [data-action="bom-select"]:nth-child(3)'); await waitSnap(pg, `s=>s.selected===s.queueIds[2]&&s.graphCand===s.selected&&!s.reqG`, 20000);
    check('IR02-search.recovers', 'clearing the search restores the queue and normal selection/graph navigation', (await snap(pg)).graphCand === (await snap(pg)).queueIds[2], { backspace_used: cleared });
  });

  // -- S8: IR-02 filter changes (non-empty and zero-match) --
  await scenario('S8-ir02-filter', async () => {
    await startDemo(pg);
    await pg.click('.ot-bom8-rows [data-action="bom-select"]:nth-child(2)'); await waitSnap(pg, `s=>s.selected&&s.graphCand===s.selected&&!s.reqG`, 20000); await sleep(250);
    const s0 = await snap(pg); const kinds = await relatedKinds(pg, s0.graphNodeIds); const recId = (kinds.single[0] || kinds.multi[0] || {}).id;
    if (recId) { await pg.click(`.ot-bom8-main ${sel('bom-record', recId)}`); await waitSnap(pg, `s=>s.selectedRecord===${JSON.stringify(recId)}`, 20000); await sleep(300); if ((await snap(pg)).popup === 'chooser') { await pg.key('Escape'); await waitSnap(pg, `s=>s.popup===null`); } }
    const old = await snap(pg);
    await pg.click('[data-action="bom-filter"][data-filter="unknown"]');
    await waitSnap(pg, `s=>s.filter==='unknown'&&s.queueIds&&s.queueIds.length>0&&!s.reqQ`, 20000); await waitSnap(pg, `s=>s.selected&&s.graphCand===s.selected&&!s.reqG`, 20000); await sleep(250);
    const f1 = await snap(pg);
    check('IR02-filter.nonempty', 'changing to a non-empty filter clears the old record/related state and shows the new first candidate and its own graph', f1.selectedRecord === null && f1.relatedSubject === null && f1.selected === f1.queueIds[0] && f1.selected !== old.selected && f1.graphCand === f1.selected, { old: old.selected, now: f1.selected });
    await pg.click('[data-action="bom-filter"][data-filter="represented"]'); await waitSnap(pg, `s=>s.filter==='represented'&&s.queueIds&&s.queueIds.length===0&&!s.reqQ`, 20000); await sleep(300);
    const f2 = await snap(pg); const dom = await pg.eval(`({cy:!!document.querySelector('[data-bom-cy]'),records:document.querySelectorAll('.ot-bom8-record').length,inspector:document.querySelector('.ot-bom8-inspector .ot-bom8-drawer-body').innerText})`);
    check('IR02-filter.zero', 'a zero-match filter clears candidate, graph, record, related and inspector', f2.selected === null && f2.graphKind === null && f2.relatedSubject === null && !dom.cy && dom.records === 0 && /Select a candidate or recorded item/.test(dom.inspector), { f2, dom });
    await pg.click('[data-action="bom-filter"][data-filter="all"]'); await waitSnap(pg, `s=>s.filter==='all'&&s.queueIds&&s.queueIds.length>0&&!s.reqQ`, 20000); await waitSnap(pg, `s=>s.selected&&s.graphCand===s.selected&&!s.reqG`, 20000);
    await pg.click('.ot-bom8-rows [data-action="bom-select"]:nth-child(2)'); await waitSnap(pg, `s=>s.selected===s.queueIds[1]&&s.graphCand===s.selected&&!s.reqG`, 20000);
    check('IR02-filter.recovers', 'returning to All allows normal selection/graph navigation', true);
  });

  // -- S9/S10: IR-03 tab and popup lifetimes --
  await scenario('S9-ir03-tab-and-popup', async () => {
    await startDemo(pg);
    const s0 = await snap(pg); const kinds = await relatedKinds(pg, s0.graphNodeIds);
    if (!kinds.multi.length) { cover('IR03', 'no record with several related checks (needed so a stale response would open the chooser)'); return; }
    const rec = kinds.multi[0].id;
    // (a) delayed related response, leave BOM and return before releasing
    const held = net.hold('related-a', isRelated, 1);
    await pg.click(`.ot-bom8-main ${sel('bom-record', rec)}`); await net.waitHeld(held, 1);
    check('IR03-a.pending', 'the related-check request is genuinely delayed before leaving BOM', (await snap(pg)).selectedRecord === rec && (await snap(pg)).popup === null);
    await pg.click('#ot-tab-dependencies'); await waitSnap(pg, `s=>s.tab==='dependencies'`); await sleep(1200);
    await pg.click('#ot-tab-bom'); await waitSnap(pg, `s=>s.tab==='bom'&&!s.reqQ&&s.queueIds&&s.queueIds.length>0`, 25000); await sleep(500);
    const before = await snap(pg); const tRel = now(); const hdl = await net.release(held); await sleep(900);
    const after = await snap(pg); const follow = net.since(tRel, (e) => /^\/api\//.test(e.path || ''));
    check('IR03-a.no-reopen', 'the old response cannot reopen the chooser or update current details after a tab round trip', after.popup === null && after.relatedSubject === null && !(await pg.eval(`!!document.querySelector('.ot-bom8-overlay')`)) && after.tlife === before.tlife, { before: [before.popup, before.relatedSubject], after: [after.popup, after.relatedSubject], released: hdl.length });
    check('IR03-a.no-followup', 'the stale response triggered no follow-up requests', follow.length === 0, follow.map((e) => e.path));
    await pg.click(`.ot-bom8-main ${sel('bom-record', rec)}`); await waitSnap(pg, `s=>s.popup==='chooser'&&s.relatedSubject===${JSON.stringify(rec)}`, 20000);
    check('IR03-a.current-succeeds', 'a current related-check request still succeeds and opens the chooser', true);
    await pg.key('Escape'); await waitSnap(pg, `s=>s.popup===null`);
    // (b) expanded graph: select record, close popup, reopen, then release the older response
    await pg.click('[data-action="bom-expand"]'); await waitSnap(pg, `s=>s.popup==='graph'`); await pg.waitFor(`document.querySelector('[data-bom-cy="popup"]')?._cy?.nodes().length>0`, 25000);
    const held2 = net.hold('related-b', isRelated, 1);
    await pg.click(`.ot-bom8-overlay ${sel('bom-record', rec)}`); await net.waitHeld(held2, 1);
    await pg.click('.ot-bom8-overlay [data-action="bom-close"]'); await waitSnap(pg, `s=>s.popup===null`);
    await pg.click('[data-action="bom-expand"]'); await waitSnap(pg, `s=>s.popup==='graph'`); await pg.waitFor(`document.querySelector('[data-bom-cy="popup"]')?._cy?.nodes().length>0`, 25000); await sleep(300);
    const b0 = await snap(pg); const tRel2 = now(); await net.release(held2); await sleep(900);
    const b1 = await snap(pg); const follow2 = net.since(tRel2, (e) => /^\/api\//.test(e.path || ''));
    check('IR03-b.no-chooser', 'after select/close/reopen the older response neither opens the chooser nor updates current details', b1.popup === 'graph' && b1.relatedSubject === null && b1.plife === b0.plife && !(await pg.eval(`!!document.querySelector('[aria-label="Related checks"]')`)), { b0: [b0.popup, b0.relatedSubject, b0.plife], b1: [b1.popup, b1.relatedSubject, b1.plife] });
    check('IR03-b.no-followup', 'the stale popup response triggered no follow-up requests', follow2.length === 0, follow2.map((e) => e.path));
    await pg.click(`.ot-bom8-overlay ${sel('bom-record', rec)}`); await waitSnap(pg, `s=>s.popup==='chooser'&&s.relatedSubject===${JSON.stringify(rec)}`, 20000);
    check('IR03-b.current-succeeds', 'a current request from the reopened popup still succeeds', true);
    await pg.key('Escape'); await waitSnap(pg, `s=>s.popup===null`);
  });

  // -- S11: layout, accessibility, focus/cursor, scroll, focus restoration at 1366 --
  await scenario('S11-layout-a11y', async () => {
    await startDemo(pg);
    check('A11Y.desktop-overflow', '1366 px: no horizontal overflow', !(await overflow(pg)));
    const geo = await pg.eval(`(()=>{const r=(q)=>{const x=document.querySelector(q);if(!x)return null;const b=x.getBoundingClientRect();return {x:Math.round(b.x),w:Math.round(b.width)}};return {layout:getComputedStyle(document.querySelector('.ot-bom8-layout')).display,cols:getComputedStyle(document.querySelector('.ot-bom8-layout')).gridTemplateColumns,queue:r('.ot-bom8-queue'),main:r('.ot-bom8-main'),inspector:r('.ot-bom8-inspector')}})()`);
    check('A11Y.three-columns', '1366 px: queue, graph and details are three columns', geo.layout === 'grid' && geo.queue.x < geo.main.x && geo.main.x < geo.inspector.x, geo);
    await pg.eval(`document.querySelector('.ot-bom8')?.scrollIntoView({block:'start'})`); await sleep(200); await pg.screenshot(join(OUT, '1366-light-focused.png'));
    // multi-character typing keeps focus and caret through re-renders
    await pg.click('#ot-bom8-q');
    for (const ch of 'zzq') { await pg.key(ch); await sleep(45); }
    await sleep(700);
    const t1 = await pg.eval(`({id:document.activeElement.id,val:document.activeElement.value,pos:document.activeElement.selectionStart})`);
    check('A11Y.typing-focus', 'multi-character search typing keeps the field focused with the caret at the end across re-renders', t1.id === 'ot-bom8-q' && t1.val === 'zzq' && t1.pos === 3, t1);
    await pg.eval(`document.querySelector('#ot-bom8-q').setSelectionRange(1,1)`); await pg.key('X'); await sleep(700);
    const t2 = await pg.eval(`({id:document.activeElement.id,val:document.activeElement.value,pos:document.activeElement.selectionStart})`);
    check('A11Y.typing-caret', 'typing mid-text keeps the caret where it was after the re-render', t2.id === 'ot-bom8-q' && t2.val === 'zXzq' && t2.pos === 2, t2);
    await pg.eval(`(()=>{const e=document.querySelector('#ot-bom8-q');e.value='';e.dispatchEvent(new Event('input',{bubbles:true}))})()`);
    notes.push({ A11Y_clear_search: 'HARNESS: the search field was emptied programmatically (with a real input event) after the typing assertions, only to restore the queue' });
    await waitSnap(pg, `s=>s.q===''&&s.queueIds&&s.queueIds.length>0&&!s.reqQ`, 20000); await waitSnap(pg, `s=>s.selected&&s.graphCand===s.selected&&!s.reqG`, 20000);
    // ordinary selection preserves queue scroll
    await pg.eval(`document.querySelector('.ot-bom8-rows').scrollIntoView({block:'start'})`);
    const sc = await pg.eval(`(()=>{const c=document.querySelector('.ot-bom8-rows');c.scrollTop=420;return {top:c.scrollTop,max:c.scrollHeight-c.clientHeight}})()`);
    await sleep(120);
    const target = await pg.eval(`(()=>{const c=document.querySelector('.ot-bom8-rows'),cr=c.getBoundingClientRect();const rows=[...c.querySelectorAll('[data-action="bom-select"]')];const r=rows.find(x=>{const b=x.getBoundingClientRect();return b.top>=cr.top+4&&b.bottom<=Math.min(cr.bottom,innerHeight)-4&&x.getAttribute('aria-pressed')!=='true'});if(!r)return null;const b=r.getBoundingClientRect();return {id:r.dataset.id,x:b.x+b.width/2,y:b.y+b.height/2}})()`);
    if (!target || sc.top < 100) cover('A11Y.queue-scroll', `queue not scrollable/visible enough to test (scrollTop ${sc.top}, max ${sc.max})`);
    else {
      await pg.send('Input.dispatchMouseEvent', { type: 'mouseMoved', x: target.x, y: target.y }); await pg.send('Input.dispatchMouseEvent', { type: 'mousePressed', x: target.x, y: target.y, button: 'left', clickCount: 1 }); await pg.send('Input.dispatchMouseEvent', { type: 'mouseReleased', x: target.x, y: target.y, button: 'left', clickCount: 1 });
      await waitSnap(pg, `s=>s.selected===${JSON.stringify(target.id)}&&s.graphCand===s.selected&&!s.reqG`, 20000); await sleep(300);
      const after = await pg.eval(`document.querySelector('.ot-bom8-rows').scrollTop`);
      check('A11Y.queue-scroll', 'ordinary queue selection preserves the queue scroll position', Math.abs(after - sc.top) <= 2, { before: sc.top, after, selected: target.id });
    }
    // popup Close / Escape focus restoration (expanded graph and chooser)
    await pg.click('[data-action="bom-expand"]'); await waitSnap(pg, `s=>s.popup==='graph'`); await sleep(300);
    await pg.screenshot(join(OUT, '1366-light-expanded.png'));
    await pg.key('Escape'); await waitSnap(pg, `s=>s.popup===null`);
    check('A11Y.escape-graph', 'Escape closes the expanded graph and returns focus to its opener', await pg.eval(`document.activeElement?.dataset.action==='bom-expand'`));
    await pg.click('[data-action="bom-expand"]'); await waitSnap(pg, `s=>s.popup==='graph'`); await pg.click('.ot-bom8-overlay [data-action="bom-close"]'); await waitSnap(pg, `s=>s.popup===null`);
    check('A11Y.close-graph', 'Close closes the expanded graph and returns focus to its opener', await pg.eval(`document.activeElement?.dataset.action==='bom-expand'`));
    const s1 = await snap(pg); const kinds = await relatedKinds(pg, s1.graphNodeIds);
    if (kinds.multi.length) {
      const rec = kinds.multi[0].id; await openChooser(pg, rec); await pg.key('Escape'); await waitSnap(pg, `s=>s.popup===null`);
      check('A11Y.escape-chooser', 'Escape closes the chooser and returns focus to the recorded item', await pg.eval(`document.activeElement?.dataset.id===${JSON.stringify(rec)}`));
      await openChooser(pg, rec); await pg.click('.ot-bom8-chooser [data-action="bom-close"]'); await waitSnap(pg, `s=>s.popup===null`);
      check('A11Y.close-chooser', 'Close closes the chooser and returns focus to the recorded item', await pg.eval(`document.activeElement?.dataset.id===${JSON.stringify(rec)}`));
    } else cover('A11Y.chooser-focus', 'no multi-check record in the focused graph');
    // Ask about this: opens the existing draft panel only; no request, no provider
    const tAsk = now(); await pg.click('[data-action="bom-ask"]'); await sleep(500);
    const askReq = net.since(tAsk, (e) => /^\/api\//.test(e.path || ''));
    check('A11Y.ask-draft-only', '"Ask about this" opens the local assistant draft and issues no request', askReq.length === 0 && (await pg.eval(`window.__otStore.get().assistant.open===true`)), askReq.map((e) => e.path));
    await pg.eval(`document.querySelector('[data-action="a-close"]')?.click()`);
  });
  collectLogs(pg); await pg.close(); pagesOpen.splice(pagesOpen.indexOf(pg), 1);

  // ===================== PAGE 2: 1600x900 light =====================
  const w = await open('1600x900-light', 1600, 900);
  await scenario('S12-wide', async () => {
    await startDemo(w.pg);
    const g = await w.pg.eval(`({cols:getComputedStyle(document.querySelector('.ot-bom8-layout')).gridTemplateColumns,overflow:document.documentElement.scrollWidth>innerWidth,cy:document.querySelector('[data-bom-cy="inline"]')?._cy?.nodes().length})`);
    check('WIDE.layout', '1600 px: real graph, three columns, no horizontal overflow', !g.overflow && g.cy > 0 && g.cols.split(' ').length >= 3, g);
    await w.pg.eval(`document.querySelector('.ot-bom8')?.scrollIntoView({block:'start'})`); await sleep(200); await w.pg.screenshot(join(OUT, '1600-light-focused.png'));
  });
  collectLogs(w.pg); await w.pg.close(); pagesOpen.splice(pagesOpen.indexOf(w.pg), 1);

  // ===================== PAGE 3: 390x844 dark =====================
  const m = await open('390x844-dark', 390, 844, true);
  await scenario('S13-mobile', async () => {
    const mp = m.pg;
    await startDemo(mp, { dark: true });
    const st = await mp.eval(`({display:getComputedStyle(document.querySelector('.ot-bom8-layout')).display,drawer:document.querySelector('.ot-bom8-inspector').classList.contains('open'),overflow:document.documentElement.scrollWidth>innerWidth,theme:document.documentElement.dataset.theme,cy:document.querySelector('[data-bom-cy="inline"]')?._cy?.nodes().length})`);
    check('MOBILE.layout', '390 px dark: stacked layout, drawer closed, live graph, no horizontal overflow', st.display === 'block' && !st.drawer && !st.overflow && st.cy > 0 && st.theme === 'dark', st);
    await mp.screenshot(join(OUT, '390-dark-collapsed.png'));
    await mp.click('[data-action="bom-drawer"]');
    check('MOBILE.drawer-open', 'the Details drawer opens', await mp.eval(`document.querySelector('.ot-bom8-inspector').classList.contains('open')&&document.querySelector('[data-action="bom-drawer"]').getAttribute('aria-expanded')==='true'`));
    check('MOBILE.drawer-overflow', 'no horizontal overflow with the drawer open', !(await overflow(mp)));
    await mp.click('[data-action="bom-drawer"]'); check('MOBILE.drawer-close', 'Close details closes the drawer', await mp.eval(`!document.querySelector('.ot-bom8-inspector').classList.contains('open')`));
    // popups on mobile
    await mp.click('[data-action="bom-expand"]'); await waitSnap(mp, `s=>s.popup==='graph'`); await mp.key('Escape'); await waitSnap(mp, `s=>s.popup===null`);
    check('MOBILE.escape-graph', 'mobile: Escape closes the expanded graph and restores focus', await mp.eval(`document.activeElement?.dataset.action==='bom-expand'&&document.documentElement.scrollWidth<=innerWidth`));
    // out-of-list chooser selection at mobile width; capture the Details drawer
    const s0 = await snap(mp); const kinds = await relatedKinds(mp, s0.graphNodeIds);
    if (!kinds.multi.length) { cover('MOBILE.pinned-details', 'no multi-check record at mobile width'); return; }
    const rec = kinds.multi[0].id; const full = await probeAll(mp); const pos = new Map(full.map((x, i) => [x.item_id, i]));
    await openChooser(mp, rec); await mp.click('.ot-bom8-chooser [data-action="bom-chooser-page"][data-dir="1"]'); await waitSnap(mp, `s=>s.popup==='chooser'&&s.relatedOffset===20`);
    const items = await mp.eval(`window.__otStore.get().bom8.related.items.map(x=>({item_id:x.item_id,display_name:x.display_name}))`);
    const pick = items.find((x) => (pos.get(x.item_id) ?? -1) >= 25);
    if (!pick) { cover('MOBILE.pinned-details', 'chooser page 2 offered no check beyond queue page 1'); return; }
    check('MOBILE.chooser-no-overflow', 'mobile chooser has no horizontal overflow', !(await overflow(mp)));
    await mp.click(`.ot-bom8-chooser ${sel('bom-related', pick.item_id)}`); await waitSnap(mp, `s=>s.graphCand===${JSON.stringify(pick.item_id)}&&!s.reqG&&!s.reqQ`, 25000); await sleep(400);
    if (!(await snap(mp)).drawer) await mp.click('[data-action="bom-drawer"]');
    await sleep(250);
    const txt = await inspectorText(mp); const h3 = await inspectorH3(mp);
    check('MOBILE.pinned-details', 'mobile Details drawer shows the chosen out-of-list check and says its details are not loaded', h3.trim() === pick.display_name.trim() && /Not loaded for this list/.test(txt) && (await snap(mp)).selected === pick.item_id, { h3, selected: (await snap(mp)).selected });
    await mp.screenshot(join(OUT, '390-dark-details-out-of-list.png'));
    check('MOBILE.final-overflow', 'no horizontal overflow at the end of the mobile run', !(await overflow(mp)));
  });
  collectLogs(m.pg); await m.pg.close(); pagesOpen.splice(pagesOpen.indexOf(m.pg), 1);
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
writeFileSync(join(OUT, 'result.json'), JSON.stringify({ schema: 'opentrace.uip08.browser_validation/1', fixture: 'offline captured Demo, loopback app, live scan/advisories/AI phase off, credential-free child environment', viewports: ['1366x900 light', '1600x900 light', '390x844 dark'], executor_evidence_awaiting_independent_review: true, counts, fatal, uncovered, notes, results }, null, 2) + '\n');
writeFileSync(join(OUT, 'ir01_flows.json'), JSON.stringify({ schema: 'opentrace.uip08.ir01_flows/1', flows: pins01 }, null, 2) + '\n');
writeFileSync(join(OUT, 'network_attempts.json'), JSON.stringify({ schema: 'opentrace.uip08.network_attempts/1', base: BASE, blocked_non_loopback: blocked, total_requests: netLog.length, held_requests: netLog.filter((e) => String(e.decision).startsWith('held:')), all: netLog }, null, 2) + '\n');
writeFileSync(join(OUT, 'process_accounting.json'), JSON.stringify(accounting, null, 2) + '\n');
writeFileSync(join(OUT, 'source_pins.json'), JSON.stringify(pins, null, 2) + '\n');
try { rmSync(WORK, { recursive: true, force: true }); } catch { /* ignore */ }
console.log(JSON.stringify(counts), 'elapsed_ms', now());
process.exitCode = counts.failed || counts.scenario_errors || fatal ? 1 : 0;
