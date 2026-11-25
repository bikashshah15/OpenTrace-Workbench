// UIP-10 F1/F3 follow-up (test harness; the earlier run_uip10_f1f3.mjs, its probe and its 141/151 evidence are kept unchanged).
// One fixture service + one headless Chrome per invocation. Usage:
//   PYTHON=... OT_DEADLINE_MS=<epoch ms> node run_uip10_followup.mjs <A|B> <outDir>
// A = followupA service: widget (partial, populated) -> F3 visible-content probe, sensitivity controls, drawer/focus, desktop baseline; gadget (partial, zero);
//     okrepo (compared) -> Full graph loads, request counts, transitions.
// B = followupB service: nodeonly (unsupported), failrepo (failed by marker injection) -> zero graph requests; okrepo (compared) after not-compared.
import { spawn, execFileSync } from 'node:child_process';
import { appendFileSync, copyFileSync, mkdirSync, writeFileSync } from 'node:fs';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { launch, newPage } from './cdp.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = resolve(HERE, '../../..');
const [PAIR, OUTARG] = process.argv.slice(2);
const OUT = resolve(OUTARG); mkdirSync(OUT, { recursive: true });
const DEADLINE = Number(process.env.OT_DEADLINE_MS || 0);
const PIDS = process.env.OT_PIDS_FILE;
const results = [], evidence = {}, unfinished = [];
const check = (id, ok, detail = '') => { results.push({ id, ok: !!ok, detail: String(detail).slice(0, 600) }); console.log(`${ok ? 'PASS' : 'FAIL'} ${id}${detail ? ' — ' + String(detail).slice(0, 220) : ''}`); };
const guard = () => { if (DEADLINE && Date.now() > DEADLINE) throw new Error('DEADLINE'); };
const save = (name, obj) => writeFileSync(join(OUT, name), JSON.stringify(obj, null, 1));

function service() {
  const proc = spawn(process.env.PYTHON || 'python3', [join(HERE, 'uip10_coverage_service.py'), '--case', PAIR === 'A' ? 'followupA' : 'followupB', '--marker', process.env.OT_MARKER || ''], { cwd: REPO, env: { ...process.env, PYTHONPATH: `${REPO}:${join(REPO, 'src/core')}` }, stdio: ['ignore', 'pipe', 'pipe'] });
  if (PIDS) appendFileSync(PIDS, proc.pid + '\n');
  return new Promise((res, rej) => { let b = ''; const t = setTimeout(() => rej(new Error('service did not start: ' + b)), 40000);
    proc.stdout.on('data', (d) => { b += d; const m = b.match(/http:\/\/127\.0\.0\.1:(\d+)\//); if (m) { clearTimeout(t); res({ base: m[0], stop: () => proc.kill('SIGTERM') }); } });
    proc.stderr.on('data', (d) => { b += d; }); });
}
const txt = (pg, sel) => pg.eval(`(document.querySelector(${JSON.stringify(sel)})?.innerText||'').replace(/\\s+/g,' ')`);
const state = (pg) => pg.eval('JSON.parse(JSON.stringify(window.__otStore.get()))');
const api = (pg, path) => pg.eval(`fetch(${JSON.stringify(path)}, { credentials: 'same-origin' }).then((r) => r.json())`);
const setUrl = async (pg, url) => { await pg.eval(`(()=>{const e=document.getElementById('ot-url');e.value='';e.dispatchEvent(new Event('input',{bubbles:true}))})()`); await pg.type('#ot-url', url); };
const frames = (pg) => pg.eval('new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(() => r(true))))');
const viewport = async (pg, narrow) => {
  await pg.send('Emulation.setDeviceMetricsOverride', narrow ? { width: 390, height: 844, deviceScaleFactor: 1, mobile: true } : { width: 1366, height: 900, deviceScaleFactor: 1, mobile: false });
  await pg.waitFor(`innerWidth===${narrow ? 390 : 1366} && window.__otStore.get().narrow===${narrow}`, 8000); await frames(pg);
};
const graphReqs = (pg) => pg.log.requests.filter((r) => r.url.includes('/bom-graph')).length;
const queueReqs = (pg) => pg.log.requests.filter((r) => r.url.includes('/bom-candidates')).length;
const settled = (pg, v) => pg.waitFor(`(()=>{const b=window.__otStore.get().bom8; return b.view===${JSON.stringify(v)} && b.queue && !b.req.queue && !b.req.graph && (${v === 'full'} ? (b.queue.mode!=='discovery_compared' || !!b.graph || !!b.error) : true)})()`, 30000);
const scanRepo = async (pg, repo) => {
  guard();
  await pg.waitFor(`document.getElementById('ot-scan') && !document.getElementById('ot-scan').disabled`, 20000);
  await setUrl(pg, 'https://github.com/acme/' + repo); await pg.click('#ot-scan');
  await pg.waitFor(`window.__otStore.get().destination === 'workbench' || window.__otStore.get().scan?.status?.job?.state === 'failed'`, 90000);
  await pg.click('#ot-tab-bom'); await pg.waitFor(`window.__otStore.get().bom8.queue`, 30000);
  await pg.waitFor(`(()=>{const b=window.__otStore.get().bom8; return b.queue && !b.req.queue && !b.req.graph})()`, 30000);
};
const endSession = async (pg) => { await viewport(pg, false); await pg.click('#ot-top-end'); await pg.waitFor(`document.getElementById('ot-ended-note')`, 20000); };
const caps = async (pg) => { const g = (await state(pg)).analysis.generation; const p = await api(pg, `/api/workbench/v1/bom-candidates?schema_version=1&generation=${g}`); return { mode: p.mode, software: (p.capabilities || []).find((c) => c.family === 'software'), total: p.counts?.candidates_total }; };
const toView = async (pg, v) => { await pg.click(`[data-action=bom-view][data-view=${v}]`); await settled(pg, v); };

// ---- page-side probe library (visible-content assessment) ----
const LIB = `window.__p = (() => {
  const L = () => document.getElementById('ot-assistant-launch');
  const inter = (a, b) => { const left = Math.max(a.left, b.left), top = Math.max(a.top, b.top), right = Math.min(a.right, b.right), bottom = Math.min(a.bottom, b.bottom); return right - left > 1 && bottom - top > 1 ? { left, top, right, bottom } : null; };
  const boxes = (e) => { if (/^(BUTTON|INPUT|SUMMARY|A)$/.test(e.tagName)) return [e.getBoundingClientRect()]; const g = document.createRange(); g.selectNodeContents(e); return [...g.getClientRects()].filter((r) => r.width > 1 && r.height > 1); };
  const SELS = ['.ot-bom8-coverage', '.ot-bom8 .ot-prompt', '.ot-bom8 .ot-help', '.ot-bom8-filters button', '#ot-bom8-q', '.ot-bom8-row', '.ot-bom8-tabs button', '.ot-pager button', '.ot-bom8-queue h3', '.ot-bom8-main h3', '.ot-bom8-cards button', '.ot-bom8-drawer-head h3', '.ot-bom8-drawer-head button'];
  // Content VISIBLE without the launcher (elementFromPoint ignores visibility:hidden) that the launcher's box covers. Content already hidden beneath the opaque dock is not counted.
  const obstructed = (sels = SELS) => {
    const l = L(), lr = l.getBoundingClientRect(), prev = l.style.visibility; l.style.visibility = 'hidden'; const out = [];
    try { for (const q of sels) for (const e of document.querySelectorAll(q)) for (const r of boxes(e)) {
      const o = inter(r, lr); if (!o) continue;
      const pts = [[(o.left + o.right) / 2, (o.top + o.bottom) / 2], [o.left + 1, o.top + 1], [o.right - 1, o.bottom - 1], [o.left + 1, o.bottom - 1], [o.right - 1, o.top + 1]];
      let vis = 0; for (const [x, y] of pts) { const t = document.elementFromPoint(x, y); if (t && (t === e || e.contains(t))) vis++; }
      if (vis) out.push({ q, text: (e.innerText || e.value || '').slice(0, 30), visiblePoints: vis, overlap: { w: Math.round(o.right - o.left), h: Math.round(o.bottom - o.top) } });
    } } finally { l.style.visibility = prev; }
    return out;
  };
  // Raw rectangle intersections (the earlier probe's measure), kept only to show how many of them are content hidden beneath the dock.
  const rawHits = (sels = SELS) => { const lr = L().getBoundingClientRect(); let n = 0; for (const q of sels) for (const e of document.querySelectorAll(q)) for (const r of boxes(e)) if (inter(r, lr)) n++; return n; };
  const cs = () => { const s = getComputedStyle(L()); return { position: s.position, top: s.top, bottom: s.bottom, left: s.left, right: s.right, transform: s.transform, zIndex: s.zIndex, width: s.width, height: s.height }; };
  const geo = () => { const r = L().getBoundingClientRect(), d = document.querySelector('.ot-bom8-inspector'), dr = d && d.getBoundingClientRect(); return { rect: { l: +r.left.toFixed(1), t: +r.top.toFixed(1), r: +r.right.toFixed(1), b: +r.bottom.toFixed(1) }, computed: cs(), dock: dr ? { l: dr.left, t: dr.top, r: dr.right, b: dr.bottom, open: d.classList.contains('open') } : null, vw: innerWidth, vh: innerHeight, scrollY: Math.round(scrollY) }; };
  const noticeBox = () => { const n = document.querySelector('.ot-bom8-coverage'); if (!n) return null; const r = n.getBoundingClientRect(); return { l: r.left, t: r.top, r: r.right, b: r.bottom, cy: (r.top + r.bottom) / 2 }; };
  const scrollNoticeCenterTo = (y) => { const n = noticeBox(); if (!n) return null; window.scrollBy({ top: n.cy - y, left: 0, behavior: 'instant' }); return noticeBox(); };
  // Every line box of the notice is visible (not covered by the launcher OR the dock) at the current scroll position.
  const readable = (sel = '.ot-bom8-coverage') => { const e = document.querySelector(sel); if (!e) return { lines: 0, visible: 0 }; const ls = boxes(e); let v = 0; for (const r of ls) { const t = document.elementFromPoint((r.left + r.right) / 2, (r.top + r.bottom) / 2); if (t && (t === e || e.contains(t))) v++; } return { lines: ls.length, visible: v }; };
  const textLine = () => { const e = document.querySelector('.ot-bom8-coverage'); const r = boxes(e)[0]; return { l: r.left, t: r.top, r: r.right, b: r.bottom }; };
  const set = (o) => { const l = L(); for (const [k, v] of Object.entries(o)) l.style.setProperty(k, v, 'important'); };
  const clear = (keys) => { const l = L(); for (const k of keys) l.style.removeProperty(k); };
  return { obstructed, rawHits, cs, geo, noticeBox, scrollNoticeCenterTo, readable, textLine, set, clear, SELS };
})()`;
const ensureLib = async (pg) => { if (!(await pg.eval('!!window.__p'))) await pg.eval(`${LIB}; true`); };
const P = (pg, expr) => pg.eval(`window.__p.${expr}`);

async function f3Block(pg, label) {
  await viewport(pg, true); await toView(pg, 'software');
  const base = await P(pg, 'geo()'); evidence[`${label}_baseline_geometry`] = base;
  const notice0 = await P(pg, 'noticeBox()'); check(`${label} F3: the notice is present for the probe`, !!notice0);
  // 1. the previous placement, applied through CSSOM and VERIFIED (computed style + rect), gives the former crossing positions
  await P(pg, `set({ bottom: '62px', right: '12px', left: 'auto', top: 'auto', transform: 'none' })`);
  const old = await P(pg, 'geo()'); evidence[`${label}_old_placement_geometry`] = old;
  check(`${label} control: the old placement took effect (computed bottom 62px, right 12px) and the launcher rect moved`, old.computed.bottom === '62px' && old.computed.right === '12px' && (old.rect.t !== base.rect.t || old.rect.l !== base.rect.l), JSON.stringify({ base: base.rect, old: old.rect }));
  const oldCy = (old.rect.t + old.rect.b) / 2;
  await P(pg, `clear(['bottom','right','left','top','transform'])`);
  const restored1 = await P(pg, 'geo()');
  check(`${label} control: removing the old placement restores the corrected computed style and geometry exactly`, JSON.stringify(restored1.rect) === JSON.stringify(base.rect) && restored1.computed.bottom === base.computed.bottom && restored1.computed.left === base.computed.left && restored1.computed.transform === base.computed.transform, JSON.stringify({ base: base.rect, restored: restored1.rect }));
  const positions = [['at', 0], ['above', -45], ['below', 45]].map(([n, dy]) => ({ n, y: oldCy + dy }));
  const rows = [];
  for (const pos of positions) {
    guard();
    await P(pg, `scrollNoticeCenterTo(${pos.y})`); await frames(pg);
    const nb = await P(pg, 'noticeBox()');
    const reached = nb && Math.abs(nb.cy - pos.y) < 3;
    // corrected launcher
    const corrected = { obstructed: await P(pg, 'obstructed()'), raw: await P(pg, 'rawHits()'), geo: await P(pg, 'geo()'), notice: nb };
    await pg.screenshot(join(OUT, `${label}_crossing_${pos.n}_corrected_390.png`));
    // old placement (control A): the same probe must see the launcher over visible notice text
    await P(pg, `set({ bottom: '62px', right: '12px', left: 'auto', top: 'auto', transform: 'none' })`); await frames(pg);
    const oldRes = { obstructed: await P(pg, 'obstructed()'), geo: await P(pg, 'geo()') };
    await pg.screenshot(join(OUT, `${label}_crossing_${pos.n}_oldplacement_390.png`));
    await P(pg, `clear(['bottom','right','left','top','transform'])`); await frames(pg);
    rows.push({ position: pos, reachedTarget: reached, corrected, oldPlacement: oldRes });
  }
  evidence[`${label}_crossing_rows`] = rows;
  check(`${label} F3: the notice was scrolled to ${rows.length} former crossing positions (centre at the old launcher's centre and +/-45 px)`, rows.every((r) => r.reachedTarget), JSON.stringify(rows.map((r) => [r.position.n, r.reachedTarget, r.corrected.notice && Math.round(r.corrected.notice.cy)])));
  check(`${label} F3: with the corrected launcher NO visible content (notice, prompts, filters, rows, tabs, drawer controls) is obstructed at any former crossing position`, rows.every((r) => r.corrected.obstructed.length === 0), JSON.stringify(rows.map((r) => r.corrected.obstructed)).slice(0, 400));
  check(`${label} F3: the corrected launcher stays inside the closed dock area`, rows.every((r) => r.corrected.geo.dock && r.corrected.geo.rect.l >= r.corrected.geo.dock.l && r.corrected.geo.rect.r <= r.corrected.geo.dock.r && r.corrected.geo.rect.t >= r.corrected.geo.dock.t && r.corrected.geo.rect.b <= r.corrected.geo.dock.b), JSON.stringify(rows[0].corrected.geo.rect) + JSON.stringify(rows[0].corrected.geo.dock));
  check(`${label} control A: the SAME probe detects the old placement over visible notice text at one or more of those positions (sensitivity)`, rows.some((r) => r.oldPlacement.obstructed.some((o) => o.q === '.ot-bom8-coverage')), JSON.stringify(rows.map((r) => r.oldPlacement.obstructed.map((o) => o.q + ':' + o.visiblePoints))).slice(0, 400));
  evidence[`${label}_raw_vs_visible`] = rows.map((r) => ({ at: r.position.n, rawRectHitsWithCorrected: r.corrected.raw, visibleObstructionsWithCorrected: r.corrected.obstructed.length }));
  // 2. control B: deliberately overlapping placement over the first notice text line
  await P(pg, `scrollNoticeCenterTo(400)`); await frames(pg);
  const line = await P(pg, 'textLine()');
  await P(pg, `set({ position: 'fixed', left: '${Math.round(line.l + 6)}px', top: '${Math.round(line.t)}px', bottom: 'auto', right: 'auto', transform: 'none' })`); await frames(pg);
  const over = await P(pg, 'geo()'); const overObs = await P(pg, 'obstructed()');
  check(`${label} control B: the deliberate placement took effect (computed top/left set, rect moved onto the notice text)`, over.computed.top === `${Math.round(line.t)}px` && over.rect.t !== base.rect.t, JSON.stringify({ line, over: over.rect }));
  check(`${label} control B: the same probe reports the launcher over visible notice text`, overObs.some((o) => o.q === '.ot-bom8-coverage'), JSON.stringify(overObs).slice(0, 300));
  await pg.screenshot(join(OUT, `${label}_control_B_overlap_390.png`));
  await P(pg, `clear(['position','left','top','bottom','right','transform'])`); await frames(pg);
  const restored2 = await P(pg, 'geo()'); const after = await P(pg, 'obstructed()');
  check(`${label} control B: after removing the override the launcher geometry is restored and the probe is quiet again`, restored2.rect.l === base.rect.l && restored2.rect.b === base.rect.b && restored2.computed.position === base.computed.position && after.length === 0, JSON.stringify({ base: base.rect, restored: restored2.rect, after }));
  // 3. content can be scrolled to a readable position (notice fully visible, unobscured by launcher or dock)
  await P(pg, `scrollNoticeCenterTo(300)`); await frames(pg);
  const rd = await P(pg, 'readable()');
  check(`${label} F3: the notice can be scrolled into a fully readable position (all line boxes visible with the launcher present)`, rd.lines > 0 && rd.lines === rd.visible, JSON.stringify(rd));
  await pg.screenshot(join(OUT, `${label}_readable_390.png`));
  // 4. keyboard focus and drawer
  await pg.eval(`document.getElementById('ot-assistant-launch').focus()`);
  const f = await pg.eval(`(()=>{const L=document.getElementById('ot-assistant-launch'); const r=L.getBoundingClientRect(); return {focused:document.activeElement===L,top:document.elementFromPoint((r.left+r.right)/2,(r.top+r.bottom)/2)===L,inViewport:r.bottom<=innerHeight&&r.top>=0&&r.left>=0&&r.right<=innerWidth}})()`);
  check(`${label} F3: keyboard focus reaches the launcher; it is topmost and inside the viewport`, f.focused && f.top && f.inViewport, JSON.stringify(f));
  await pg.eval(`document.querySelector('[data-action=bom-drawer]').click()`); await pg.waitFor(`document.querySelector('.ot-bom8-inspector.open')`, 5000); await frames(pg);
  const dg = await P(pg, 'geo()');
  const dc = await pg.eval(`(()=>{const b=document.querySelector('[data-action=bom-drawer]'); const r=b.getBoundingClientRect(); const L=document.getElementById('ot-assistant-launch').getBoundingClientRect(); const hit=document.elementFromPoint((r.left+r.right)/2,(r.top+r.bottom)/2)===b; const lo=!(Math.min(r.right,L.right)-Math.max(r.left,L.left)>1&&Math.min(r.bottom,L.bottom)-Math.max(r.top,L.top)>1); return {closeControlReachable:hit,launcherClearOfClose:lo,btn:[r.left,r.top,r.right,r.bottom].map(Math.round)}})()`);
  check(`${label} F3: with the drawer open the launcher is above it and the close control is reachable and not covered`, dg.dock && dg.dock.open && dg.rect.b <= dg.dock.t + 1 && dc.closeControlReachable && dc.launcherClearOfClose, JSON.stringify({ launcher: dg.rect, dock: dg.dock, dc }));
  evidence[`${label}_drawer_open`] = { geo: dg, close: dc }; await pg.screenshot(join(OUT, `${label}_drawer_open_390.png`));
  await pg.eval(`document.querySelector('[data-action=bom-drawer]').click()`); await pg.waitFor(`!document.querySelector('.ot-bom8-inspector.open')`, 5000);
}

async function desktopBaseline(browser, pg) {
  // Pre-correction baseline: the PREVIOUS app.css (6a94f7b) in a bare page vs the current app.css, and the live page, all at 1366 px.
  const old = execFileSync('git', ['show', '6a94f7b2e81ca6fb7d302fc1bf5b1704ba7dc443:src/ui/styles/app.css'], { cwd: REPO, maxBuffer: 1 << 26 });
  writeFileSync(join(OUT, 'baseline_old_app.css'), old); copyFileSync(join(REPO, 'src/ui/styles/app.css'), join(OUT, 'baseline_new_app.css')); copyFileSync(join(REPO, 'src/ui/styles/prototype.css'), join(OUT, 'baseline_prototype.css'));
  for (const v of ['old', 'new']) writeFileSync(join(OUT, `baseline_${v}.html`), `<!doctype html><meta charset=utf-8><link rel=stylesheet href="baseline_prototype.css"><link rel=stylesheet href="baseline_${v}_app.css"><body><div class="ot-bom8"><div class="ot-bom8-inspector"></div></div><button type="button" class="assistant-launch" id="ot-assistant-launch">Lab assistant ↗</button></body>`);
  const out = {};
  for (const v of ['old', 'new']) for (const w of [1366, 390]) {
    const bp = await newPage(browser, { width: w, height: w === 390 ? 844 : 900, mobile: w === 390 });
    await bp.goto(pathToFileURL(join(OUT, `baseline_${v}.html`)).href);
    out[`${v}_${w}`] = await bp.eval(`(()=>{const L=document.getElementById('ot-assistant-launch'); const s=getComputedStyle(L); const r=L.getBoundingClientRect(); return {position:s.position,bottom:s.bottom,right:s.right,left:s.left,rect:[r.left,r.top,r.right,r.bottom].map((x)=>+x.toFixed(1))}})()`);
    await bp.close();
  }
  evidence.desktop_baseline = out;
  const live = await P(pg, 'geo()');
  check('desktop: the corrected CSS places the launcher exactly where the pre-correction CSS did at 1366 px (computed values and rectangle)', JSON.stringify(out.old_1366) === JSON.stringify(out.new_1366), JSON.stringify({ old: out.old_1366, new: out.new_1366 }));
  check('desktop: the live Workbench launcher matches the pre-correction baseline computed bottom/right', live.computed.bottom === out.old_1366.bottom && live.computed.right === out.old_1366.right, JSON.stringify({ live: live.computed, baseline: out.old_1366 }));
  check('390 px reference: the old CSS put the launcher at bottom 62px; the corrected CSS differs (the intended change)', out.old_390.bottom === '62px' && out.new_390.bottom !== '62px', JSON.stringify({ old: out.old_390, new: out.new_390 }));
}

async function f1Counts(pg, label, notCompared) {
  const rows = [];
  for (const vp of ['1366', '390']) {
    await viewport(pg, vp === '390');
    for (const round of [1, 2]) {
      guard();
      await toView(pg, 'software');
      const g0 = graphReqs(pg), q0 = queueReqs(pg);
      await pg.click('[data-action=bom-view][data-view=full]'); await settled(pg, 'full');
      const g1 = graphReqs(pg), q1 = queueReqs(pg); const b = (await state(pg)).bom8;
      rows.push({ vp, round, graphBefore: g0, graphAfter: g1, queueBefore: q0, queueAfter: q1, error: b.error, graph: !!b.graph, mode: b.queue.mode });
      await pg.screenshot(join(OUT, `${label}_full_${vp}_r${round}.png`));
    }
  }
  evidence[`${label}_graph_request_counts`] = rows;
  if (notCompared) {
    check(`${label} F1: entering Full evidence graph sends ZERO graph requests at 1366 and 390 px (2 entries each); the queue is requested each time (>= 1)`, rows.every((r) => r.graphAfter === r.graphBefore && r.queueAfter >= r.queueBefore + 1 && !r.error && !r.graph), JSON.stringify(rows.map((r) => [r.vp, r.graphBefore, r.graphAfter])));
    const body = await txt(pg, '.ot-bom8');
    check(`${label} F1: the reason stays visible in Full evidence graph and there is no endpoint banner`, /Not compared\./.test(body) && /There is no bound comparison graph/.test(body) && !/endpoint is unavailable/.test(body), body.slice(0, 240));
  } else {
    check(`${label} F1: compared - each Full-view entry sends exactly one graph request after its queue and the graph loads without error`, rows.every((r) => r.graphAfter === r.graphBefore + 1 && r.queueAfter >= r.queueBefore + 1 && r.graph && !r.error), JSON.stringify(rows.map((r) => [r.vp, r.graphBefore, r.graphAfter, r.graph, r.error])));
  }
}

const { browser, close, proc } = await launch();
if (PIDS) appendFileSync(PIDS, proc.pid + '\n');
let svc;
try {
  svc = await service();
  const pg = await newPage(browser, { width: 1366, height: 900 });
  await pg.goto(svc.base); await pg.eval(`${LIB}; true`);
  const plan = PAIR === 'A' ? [['widget', 'partial'], ['gadget', 'partial0'], ['okrepo', 'compared']] : [['nodeonly', 'unsupported'], ['failrepo', 'failed'], ['okrepo', 'compared']];
  for (const [i, [repo, label]] of plan.entries()) {
    try {
      guard(); if (i > 0) await endSession(pg);
      await scanRepo(pg, repo); await viewport(pg, false); await ensureLib(pg);
      const c = await caps(pg); evidence[`${label}_caps`] = c;
      const want = { partial: ['partial', 'discovery_compared'], partial0: ['partial', 'discovery_compared'], compared: ['completed', 'discovery_compared'], unsupported: ['unsupported', 'not_compared'], failed: ['failed', 'not_compared'] }[label];
      check(`${PIDS ? '' : ''}${label}: API state is software ${want[0]} on a ${want[1]} page`, c.software.state === want[0] && c.mode === want[1], JSON.stringify(c));
      if (label === 'partial') { await f3Block(pg, label); await viewport(pg, false); await desktopBaseline(browser, pg); }
      if (label === 'partial0') { await viewport(pg, true); await toView(pg, 'software'); const o = await P(pg, 'obstructed()'); check('partial0 F3: zero-total partial page - launcher obstructs no visible content at 390 px', o.length === 0, JSON.stringify(o)); await pg.screenshot(join(OUT, 'partial0_software_390.png')); }
      if (label === 'compared') { await f1Counts(pg, label, false); }
      if (label === 'unsupported' || label === 'failed') { await f1Counts(pg, label, true); }
      if (label === 'compared' && PAIR === 'B') {
        const b = (await state(pg)).bom8; check('B transition: a compared analysis after not-compared ones shows no stale error and its graph', !b.error && !!b.graph && b.graph.scope.kind === 'full_view', JSON.stringify({ error: b.error, graph: !!b.graph }));
      }
    } catch (e) { if (e.message === 'DEADLINE') { unfinished.push(`${label}: deadline`); check(`${label}: finished before the deadline`, false, 'deadline'); break; } check(`${label}: state run completed`, false, e.stack || e.message); try { await pg.screenshot(join(OUT, `${PAIR}_${label}_failure.png`)); } catch {} }
  }
  check(`${PAIR}: no page errors`, pg.log.exceptions.length === 0, pg.log.exceptions.join('|'));
} catch (e) { check(`${PAIR}: run completed`, false, e.stack || e.message); }
finally { try { svc && svc.stop(); } catch {} await close(); }
save(`${PAIR}_results.json`, { pair: PAIR, results, evidence, unfinished });
const failed = results.filter((r) => !r.ok).length;
console.log(`${results.length - failed}/${results.length} checks passed`);
process.exit(failed ? 1 : 0);
