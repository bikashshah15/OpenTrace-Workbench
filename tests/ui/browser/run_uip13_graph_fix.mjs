// UIP-13 graph-renderer correction: PRODUCT acceptance battery (test harness only; no product change). ONE fixture service + ONE Chrome per invocation.
// The SAME battery runs against the starting source (before) and the corrected source (after); the passive hooks are installed identically both times, so any destroy
// the hooks cause would appear in the corrected run too. Every fixture is SYNTHETIC (uip13_followup_service.py): no network, Docker, scanner, provider or Cisco.
// Paint is verified as canvas alpha>0 ink per node + edge-midpoint ink + a compositor screenshot of the host region, with REAL mouse events.
// Usage: OT_LABEL=<baseline|corrected> [OT_HEADLESS=1] OT_DEADLINE_MS=<epoch ms> OT_PIDS_FILE=<file> PYTHON=<venv python> node run_uip13_graph_fix.mjs <outDir> | --selftest
import { spawn } from 'node:child_process';
import { appendFileSync, writeFileSync } from 'node:fs';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { launch, newPage } from './cdp.mjs';
import { harness, sleep, state, apiJson, settled, setUrl } from './uip12_lib.mjs';
import { HOOK, SUMMARY, SAMPLE, ANALYZE, selftest, launchHeaded } from './uip13_graph_probe.mjs';

if (process.argv[2] === '--selftest') { const e = selftest(); console.log(e ? 'SELFTEST FAIL ' + e : 'SELFTEST OK (in-page scripts parse)'); process.exit(e ? 1 : 0); }
const HERE = dirname(fileURLToPath(import.meta.url)); const REPO = resolve(HERE, '../../..');
const LABEL = process.env.OT_LABEL || 'unlabelled'; const HEADLESS = process.env.OT_HEADLESS === '1';
const H = harness({ out: process.argv[2], label: `uip13_graph_fix_${LABEL}`, synthetic: true });
const { check, guard, evidence, OUT } = H;
const T0 = Date.now(); const rec = { label: LABEL, counters: { serviceLaunches: 0, chromeLaunches: 0 }, phases: {} }; evidence.rec = rec;
const stamp = () => ({ wall: new Date().toISOString(), sinceStartS: Math.round((Date.now() - T0) / 100) / 10 });
const pid = (p) => { if (process.env.OT_PIDS_FILE && p) appendFileSync(process.env.OT_PIDS_FILE, p + '\n'); };
const endSession = async (pg) => { await pg.click('#ot-top-end'); await pg.waitFor(`document.getElementById('ot-ended-note')`, 30000); };

function service() {
  rec.counters.serviceLaunches++; rec.serviceStart = stamp();
  const proc = spawn(process.env.PYTHON || 'python3', [join(HERE, 'uip13_followup_service.py')], { cwd: REPO, env: { ...process.env, PYTHONPATH: `${REPO}:${join(REPO, 'src/core')}` }, stdio: ['ignore', 'pipe', 'pipe'] }); pid(proc.pid);
  return new Promise((res, rej) => { let b = ''; const t = setTimeout(() => rej(new Error('service did not start: ' + b)), 40000);
    proc.stdout.on('data', (d) => { b += d; const m = b.match(/http:\/\/127\.0\.0\.1:(\d+)\//); if (m) { clearTimeout(t); res({ base: m[0], stop: () => proc.kill('SIGTERM') }); } });
    proc.stderr.on('data', (d) => { b += d; try { appendFileSync(join(OUT, 'service_stderr.log'), d); } catch {} }); });
}

const SEL = '[data-bom-cy=inline]'; const POP = '[data-bom-cy=popup]';
const sample = (pg, sel = SEL, ink = true) => pg.eval(`${SAMPLE}(${JSON.stringify(sel)},${ink})`);
const summary = (pg) => pg.eval(SUMMARY);
const derive = (s) => { const c = s.cy; if (!c) return { layout: false, alive: false, inkOk: false, painted: false };
  const layout = c.nodes > 0 && c.nodes === c.expectedNodes && c.edges === c.expectedEdges && !!c.finite && (c.nodes < 2 || c.distinct === c.nodes);
  const alive = c.rendererDestroyed === false && c.destroyed === false && c.container === true;
  const inkOk = s.ink !== undefined && s.ink >= 300 * c.nodes && s.edgesWithInk >= Math.ceil(0.8 * c.edges);
  return { layout, alive, inkOk, painted: layout && alive && inkOk }; };
const slim = (s) => ({ host: s.host && { id: s.host.id, rect: s.host.rect }, cy: s.cy && { id: s.cy.id, rd: s.cy.rendererDestroyed, nodes: s.cy.nodes, edges: s.cy.edges, zoom: s.cy.zoom && +s.cy.zoom.toFixed ? +s.cy.zoom.toFixed(4) : s.cy.zoom, sel: s.cy.selected }, ink: s.ink, edgesWithInk: s.edgesWithInk, canv: s.canvases && s.canvases[0], raf: s.raf });
async function painted(pg, sel, ms = 5000) { const t0 = Date.now(); let s, d;
  for (;;) { guard(); s = await sample(pg, sel, true); d = derive(s); if (d.painted) return { ok: true, ms: Date.now() - t0, s, d }; if (Date.now() - t0 > ms) return { ok: false, ms: Date.now() - t0, s, d }; await sleep(120); } }
async function region(pg, name, sel = SEL) {
  const s0 = await sample(pg, sel, false); if (!s0.host) return { err: 'no host' }; const sc = await pg.eval('({x:scrollX,y:scrollY})'); const h = s0.host;
  const clip = { x: Math.max(0, h.rect[0] + sc.x), y: Math.max(0, h.rect[1] + sc.y), width: Math.max(1, Math.min(h.rect[2], 1700)), height: Math.max(1, Math.min(h.rect[3], 1200)), scale: 1 };
  const r = await pg.send('Page.captureScreenshot', { format: 'png', clip, captureBeyondViewport: true }); writeFileSync(join(OUT, name.replace(/[^\w.-]+/g, '_') + '_graph_region.png'), Buffer.from(r.data, 'base64'));
  return { ...(await pg.eval(ANALYZE(r.data))), clip };
}
const compOk = (r) => r && r.nonDominantShare > 0.03 && r.distinctColours > 20;   // painted reference build: share 0.0933 / 139 colours; blank: 0.0081 / 8 (page text only)
const rowSel = (id) => `[data-action=bom-select][data-id=${JSON.stringify(id)}]`;
const gen = async (pg) => (await state(pg)).analysis.generation;
const queue = async (pg, family) => (await apiJson(pg, `/api/workbench/v1/bom-candidates?schema_version=1&generation=${await gen(pg)}&family=${family}`)).body?.items || [];
async function scanTo(pg, repo, first, view) {
  guard(); if (!first) { await dismiss(pg); await endSession(pg); }
  await pg.waitFor(`document.getElementById('ot-scan') && !document.getElementById('ot-scan').disabled`, 20000);
  await setUrl(pg, 'https://github.com/acme/' + repo); await pg.click('#ot-scan');
  await pg.waitFor(`window.__otStore.get().destination === 'workbench' || window.__otStore.get().scan?.status?.job?.state === 'failed'`, 90000);
  const st = await state(pg); if (st.destination !== 'workbench') throw new Error('scan did not reach the workbench: ' + JSON.stringify(st.scan?.status?.job).slice(0, 400));
  await pg.click('#ot-tab-bom'); await pg.waitFor(`window.__otStore.get().bom8.queue`, 30000);
  await pg.waitFor(`(()=>{const b=window.__otStore.get().bom8; return b.queue && !b.req.queue && !b.req.graph && !b.req.detail})()`, 30000);
  await pg.click(`[data-action=bom-view][data-view=${view}]`); await settled(pg, view);
}
// A node click can open the modal 'Related checks' chooser (bom_flow.js: related.resolution==='multiple' -> popup 'chooser'). Real users dismiss it with Escape; so does the harness.
async function dismiss(pg) {
  await pg.waitFor(`!window.__otStore.get().bom8.req.related`, 6000).catch(() => {});
  const pop = await pg.eval(`window.__otStore.get().bom8.popup`);
  if (pop === 'chooser') { await pg.key('Escape', 'Escape'); await pg.waitFor(`!window.__otStore.get().bom8.popup`, 4000).catch(() => {}); rec.chooserDismissed = (rec.chooserDismissed || 0) + 1; }
}
const selectCandidate = async (pg, id) => { await dismiss(pg);  await pg.click(rowSel(id)); await pg.waitFor(`window.__otStore.get().bom8.selected===${JSON.stringify(id)} && window.__otStore.get().bom8.graph?.scope?.candidate_id===${JSON.stringify(id)}`, 20000); };
async function nodeClickPoint(pg, id, sel = SEL) {
  await pg.eval(`document.querySelector(${JSON.stringify(sel)}).scrollIntoView({block:'center',behavior:'instant'})`); await sleep(120);
  return pg.eval(`(()=>{const h=document.querySelector(${JSON.stringify(sel)}); const n=h._cy.getElementById(${JSON.stringify(id)}); const r=h.getBoundingClientRect(); const q=n.renderedPosition(); return {x:r.x+q.x,y:r.y+q.y,inside:q.x>5&&q.y>5&&q.x<r.width-5&&q.y<r.height-5}})()`);
}
const mouse = async (pg, pt) => { await pg.send('Input.dispatchMouseEvent', { type: 'mouseMoved', x: pt.x, y: pt.y }); await pg.send('Input.dispatchMouseEvent', { type: 'mousePressed', x: pt.x, y: pt.y, button: 'left', clickCount: 1 }); await pg.send('Input.dispatchMouseEvent', { type: 'mouseReleased', x: pt.x, y: pt.y, button: 'left', clickCount: 1 }); };
const realClickNode = async (pg, id, sel = SEL) => { const pt = await nodeClickPoint(pg, id, sel); await mouse(pg, pt); await dismiss(pg); return pt; };
async function emptyPoint(pg, sel = SEL) {   // a host point outside every element's rendered bounding box (labels included); the camera is shifted aside temporarily when the graph fills the container
  await pg.eval(`document.querySelector(${JSON.stringify(sel)}).scrollIntoView({block:'center',behavior:'instant'})`); await sleep(120);
  const find = `(()=>{const h=document.querySelector(${JSON.stringify(sel)}); const cy=h._cy; const r=h.getBoundingClientRect(); const bbs=cy.elements().map(e=>e.renderedBoundingBox({includeLabels:true,includeOverlays:false})); let best=null;
    for(let x=15;x<r.width-15;x+=15) for(let y=15;y<r.height-15;y+=15){ const d=Math.min(...bbs.map(b=>Math.max(b.x1-x,x-b.x2,b.y1-y,y-b.y2))); if(!best||d>best.d) best={d,x,y}; } return best&&best.d>=8?{x:r.x+best.x,y:r.y+best.y,d:Math.round(best.d)}:null})()`;
  let pt = await pg.eval(find); let restore = null;
  if (!pt) { restore = await pg.eval(`(()=>{const cy=document.querySelector(${JSON.stringify(sel)})._cy; const p={...cy.pan()}; cy.pan({x:p.x-cy.width()*0.55,y:p.y}); return p})()`); pt = await pg.eval(find); }
  return { pt, restore };
}
async function setSize(pg, ctx, w, h) {
  if (HEADLESS) { await pg.send('Emulation.setDeviceMetricsOverride', { width: w, height: h, deviceScaleFactor: 1, mobile: false }); await pg.waitFor(`innerWidth===${w}`, 8000); return; }
  const { windowId } = await ctx.browser.send('Browser.getWindowForTarget', { targetId: pg.targetId }); await ctx.browser.send('Browser.setWindowBounds', { windowId, bounds: { windowState: 'normal', width: w, height: h } });
  await pg.waitFor(`Math.abs(outerWidth-${w})<=2`, 8000).catch(() => {}); await sleep(250);
}
const camEq = (a, b) => a && b && Math.abs(a.zoom - b.zoom) < 1e-6 && Math.abs(a.pan.x - b.pan.x) < 0.01 && Math.abs(a.pan.y - b.pan.y) < 0.01;
const unintentional = async (pg) => (await summary(pg)).unintentionalDestroys;

// Selection / camera / repaint battery on the currently selected candidate (graph exists in SEL).
async function interact(pg, P, { deep }) {
  const s0 = (await painted(pg, SEL, 5000)); const id0 = s0.s.cy?.id;
  const ids = s0.s.cy?.nodeIds || []; if (ids.length < 2) { check(`${P}: >=2 nodes to interact with`, false, JSON.stringify(slim(s0.s))); return; }
  // real click on a node: selects the record, store and cy agree, same instance, still painted
  const pickInside = async (skip = []) => { for (const id of ids) { if (skip.includes(id)) continue; const pt = await nodeClickPoint(pg, id); if (pt.inside) return id; } return ids.find((x) => !skip.includes(x)); };
  const A = await pickInside(); await realClickNode(pg, A);
  await pg.waitFor(`window.__otStore.get().bom8.selectedRecord===${JSON.stringify(A)}`, 4000).catch(() => {});
  const a = await painted(pg, SEL, 5000); const stA = (await state(pg)).bom8.selectedRecord;
  evidence[`${P}_clickA`] = { A, selectedRecord: stA, ...slim(a.s) };
  check(`${P}: a REAL mouse click on node selects that record (store + Cytoscape) and the graph stays painted`, stA === A && a.s.cy?.selected?.includes(A) && a.d.painted, JSON.stringify(evidence[`${P}_clickA`]).slice(0, 380));
  check(`${P}: the click did not replace or destroy the graph instance`, a.s.cy?.id === id0 && a.d.alive, JSON.stringify({ before: id0, after: a.s.cy?.id, alive: a.d.alive }));
  // camera: set zoom/pan like a user, then surrounding repaints (node selections) must keep it
  await pg.eval(`(()=>{const cy=document.querySelector(${JSON.stringify(SEL)})._cy; cy.zoom({level:Math.min(2.4,cy.zoom()*1.15),renderedPosition:{x:cy.width()/2,y:cy.height()/2}}); cy.pan({x:cy.pan().x+14,y:cy.pan().y+9});})()`);
  const camBefore = await pg.eval(`(()=>{const cy=document.querySelector(${JSON.stringify(SEL)})._cy; return {zoom:cy.zoom(),pan:{...cy.pan()}}})()`);
  const B = await pickInside([A]); await realClickNode(pg, B); await pg.waitFor(`window.__otStore.get().bom8.selectedRecord===${JSON.stringify(B)}`, 4000).catch(() => {});
  const b = await painted(pg, SEL, 5000); const camAfter = await pg.eval(`(()=>{const cy=document.querySelector(${JSON.stringify(SEL)})._cy; return {zoom:cy.zoom(),pan:{...cy.pan()}}})()`);
  check(`${P}: a surrounding repaint (selection change) keeps the same instance, camera (zoom+pan) and paint`, b.s.cy?.id === id0 && camEq(camBefore, camAfter) && b.d.painted && b.s.cy.selected.join() === B, JSON.stringify({ camBefore, camAfter, id: b.s.cy?.id, id0, sel: b.s.cy?.selected, B }));
  evidence[`${P}_membership`] = { before: ids, after: b.s.cy?.nodeIds };
  check(`${P}: graph membership (node ids) is unchanged by repaints`, JSON.stringify(ids) === JSON.stringify(b.s.cy?.nodeIds), JSON.stringify(evidence[`${P}_membership`]).slice(0, 300));
  if (deep) {
    const { pt: bg, restore } = await emptyPoint(pg); if (bg) { await mouse(pg, bg); await pg.waitFor(`window.__otStore.get().bom8.selectedRecord==null`, 4000).catch(() => {}); if (restore) await pg.eval(`document.querySelector(${JSON.stringify(SEL)})._cy.pan(${JSON.stringify(restore)})`); const c = await painted(pg, SEL, 5000); const sr = (await state(pg)).bom8.selectedRecord;
      check(`${P}: a real click on empty canvas clears the selection and the graph stays painted`, sr == null && c.d.painted && c.s.cy.id === id0, JSON.stringify({ sr, id: c.s.cy?.id, painted: c.d.painted })); } else evidence[`${P}_emptyPoint`] = 'no empty point even after shifting the camera (not exercised)';
    // repeated surrounding repaints with handler/observer accounting
    const s1 = await summary(pg); const seq = []; for (let i = 0; i < 4; i++) { const t = ids[(i + 1) % ids.length]; await realClickNode(pg, t); await sleep(120); const q = await painted(pg, SEL, 4000); seq.push({ t, ok: q.d.painted, id: q.s.cy?.id }); }
    const s2 = await summary(pg); const me = s2.insts.find((i) => i.id === id0); const me1 = s1.insts.find((i) => i.id === id0);
    evidence[`${P}_burst`] = { seq, obsBefore: s1.obs, obsAfter: s2.obs, on: me?.on, coreListenersBefore: me1?.listeners, coreListenersAfter: me?.listeners, mounts: me?.mounts };
    check(`${P}: four more surrounding repaints: same instance every time and painted every time`, seq.every((x) => x.ok && x.id === id0), JSON.stringify(seq));
    check(`${P}: no duplicate event handlers (tap registrations per instance exactly: node tap 1, background tap 1), no growth in the Core's listener count, and no growth in live observers over the repaints`, me && me.on['tap:node'] === 1 && me.on['tap'] === 1 && s2.obs.hostObs === s1.obs.hostObs && s2.obs.parentObs === s1.obs.parentObs && s2.obs.docEl === s1.obs.docEl && me1 && me.listeners === me1.listeners, JSON.stringify(evidence[`${P}_burst`]));
  }
  const reg = await region(pg, `${P}_after_repaints`); evidence[`${P}_compositor`] = reg;
  check(`${P}: COMPOSITOR output of the graph region shows nodes and edges after interaction (screenshot analysis)`, compOk(reg), JSON.stringify(reg));
  check(`${P}: no renderer was destroyed outside an intentional teardown call (cumulative, whole page so far)`, (await unintentional(pg)) === 0, JSON.stringify((await summary(pg)).insts.map((i) => ({ id: i.id, u: i.destroys.filter((d) => !d.viaCyCall).length })).filter((x) => x.u)));
}

async function resizeFit(pg, ctx, P, sizes) {
  for (const [w, h] of sizes) {
    await setSize(pg, ctx, w, h); await pg.waitFor(`(()=>{const h=document.querySelector(${JSON.stringify(SEL)}); const c=h&&h.querySelector('canvas'); return c&&Math.abs(c.clientWidth-h.getBoundingClientRect().width)<=4})()`, 4000).catch(() => {}); const q = await painted(pg, SEL, 5000); const hostW = q.s.host?.rect[2]; const c0 = q.s.canvases?.[0]; const reg = await region(pg, `${P}_resize_${w}`);
    evidence[`${P}_resize_${w}`] = { ...slim(q.s), inner: q.s.inner, hostW, reg };
    check(`${P}: resize to ${w}x${h}: canvases follow the host width, graph painted, compositor shows content`, q.d.painted && c0 && Math.abs(c0[2] - hostW) <= 4 && compOk(reg), JSON.stringify(evidence[`${P}_resize_${w}`]).slice(0, 420));
    await dismiss(pg); await pg.click('[data-action=bom-fit]'); const f = await painted(pg, SEL, 4000); const fr = await region(pg, `${P}_fit_${w}`);
    check(`${P}: Fit after ${w}x${h}: graph painted and inside the container`, f.d.painted && f.s.cy.inside === f.s.cy.nodes && compOk(fr), JSON.stringify({ ...slim(f.s), inside: f.s.cy?.inside, fr }).slice(0, 380));
  }
}

async function buildCase(pg, ctx, P, repo, family, view, first, { deep, sizes, popup }) {
  rec.phases[P] = { start: stamp() };
  await scanTo(pg, repo, first, view); const items = await queue(pg, family); check(`${P}: at least one ${family} candidate queued`, items.length >= 1, JSON.stringify(items.map((i) => [i.item_id, i.state])));
  const sup = items.find((i) => i.state === 'supported') || items[0]; const other = items.find((i) => i !== sup);
  await selectCandidate(pg, sup.item_id); const q = await painted(pg, SEL, 6000);
  const reg = await region(pg, `${P}_first_paint`); const sm = await summary(pg); const first_ = sm.insts.find((i) => i.id === q.s.cy?.id);
  evidence[`${P}_first`] = { items: items.map((i) => [i.item_id, i.state]), timeToPaintMs: q.ms, ...slim(q.s), reg, destroys: first_?.destroys };
  check(`${P}: selecting the ${sup.state} candidate paints the graph (layout complete, live renderer, ink per node/edge) within 6 s`, q.ok, JSON.stringify(evidence[`${P}_first`]).slice(0, 420));
  check(`${P}: the first paint is visible in the compositor (screenshot analysis)`, compOk(reg), JSON.stringify(reg));
  await interact(pg, P + '/supported', { deep });
  if (other) {   // inconclusive/other candidate on the same case, then back
    await selectCandidate(pg, other.item_id); const o = await painted(pg, SEL, 6000); const ro = await region(pg, `${P}_other_first_paint`);
    check(`${P}: selecting the ${other.state} candidate paints the graph (live renderer, ink)`, o.ok && compOk(ro), JSON.stringify({ ...slim(o.s), ro }).slice(0, 380));
    await interact(pg, P + '/' + other.state, { deep: false });
    await selectCandidate(pg, sup.item_id); const bk = await painted(pg, SEL, 6000); check(`${P}: reselecting the supported candidate paints again`, bk.ok, JSON.stringify(slim(bk.s)).slice(0, 300));
  }
  if (sizes) await resizeFit(pg, ctx, P, sizes);
  if (popup) {
    const idBefore = (await sample(pg, SEL, false)).cy?.id; await pg.click('[data-action=bom-expand]'); await pg.waitFor(`document.querySelector(${JSON.stringify(POP)})`, 8000).catch(() => {});
    const pp = await painted(pg, POP, 6000); const rp = await region(pg, `${P}_popup`, POP);
    check(`${P}: expanded (popup) graph paints on first open`, pp.ok && compOk(rp), JSON.stringify({ ...slim(pp.s), rp }).slice(0, 380));
    await pg.click('[data-action=bom-close]'); await sleep(200); const after = await painted(pg, SEL, 6000);
    check(`${P}: closing the popup leaves the inline graph on the SAME instance, live and painted`, after.s.cy?.id === idBefore && after.d.painted, JSON.stringify({ idBefore, after: slim(after.s) }));
    await pg.click('[data-action=bom-expand]'); await pg.waitFor(`document.querySelector(${JSON.stringify(POP)})`, 8000).catch(() => {}); const pp2 = await painted(pg, POP, 6000);
    check(`${P}: reopening the expanded graph paints again`, pp2.ok, JSON.stringify(slim(pp2.s)).slice(0, 300)); await pg.click('[data-action=bom-close]'); await sleep(200);
  }
  rec.phases[P].end = stamp(); return { items, sup, other };
}

async function navigation(pg, P, other, sup) {
  await dismiss(pg); const live0 = await summary(pg);
  await pg.click('[data-nav=evidence]'); await pg.waitFor(`window.__otStore.get().destination==='evidence'`, 8000);
  const away = await summary(pg); evidence[`${P}_navAway`] = { liveBefore: live0.liveCount, liveAfter: away.liveCount, liveDetached: away.liveDetached, obs: away.obs };
  check(`${P}: navigating away retires every graph instance (none live, no leaked renderer/host observers)`, away.liveCount === 0 && away.liveDetached === 0 && away.obs.hostObs === 0 && away.obs.parentObs === 0, JSON.stringify(evidence[`${P}_navAway`]));
  await pg.click('[data-nav=workbench]'); await pg.waitFor(`window.__otStore.get().destination==='workbench'`, 8000); await pg.waitFor(`document.querySelector(${JSON.stringify(SEL)})`, 8000).catch(() => {});
  const back = await painted(pg, SEL, 6000); const rb = await region(pg, `${P}_nav_back`);
  check(`${P}: navigating back reopens the graph on a NEW live instance, painted`, back.ok && compOk(rb), JSON.stringify({ ...slim(back.s), rb }).slice(0, 380));
  const sb = await summary(pg); check(`${P}: after navigating back exactly one live instance exists for the one visible graph (no stale second instance)`, sb.liveCount === 1 && sb.liveDetached === 0, JSON.stringify({ live: sb.liveCount, detached: sb.liveDetached }));
  // stale layout race (best effort and non-deterministic by nature; the deterministic proof is the unit test): change the graph and leave in the same breath, then return and reselect
  if (other) { const ex0 = pg.log.exceptions.length; await pg.click(rowSel(other.item_id)); await pg.click('[data-nav=evidence]'); await pg.waitFor(`window.__otStore.get().destination==='evidence'`, 8000);
    const mid = await summary(pg); await pg.click('[data-nav=workbench]'); await pg.waitFor(`window.__otStore.get().destination==='workbench'`, 8000); await selectCandidate(pg, sup.item_id); const r = await painted(pg, SEL, 6000); const sr = await summary(pg);
    evidence[`${P}_raceNav`] = { midLive: mid.liveCount, midDetached: mid.liveDetached, newExceptions: pg.log.exceptions.slice(ex0), ...slim(r.s), liveAfter: sr.liveCount, detachedAfter: sr.liveDetached };
    check(`${P}: replace-then-navigate race: nothing left live while away, no exception, and the returned graph paints on one live instance`, mid.liveCount === 0 && pg.log.exceptions.length === ex0 && r.ok && sr.liveCount === 1 && sr.liveDetached === 0, JSON.stringify(evidence[`${P}_raceNav`]).slice(0, 420)); }
}

// Destroy-trigger evidence: all lifecycle events (stacks kept for destroy/cy-* calls) and a classification of every renderer destroy that was NOT made through a cy call.
async function dumpHooks(pg) {
  const ev = await pg.eval(`window.__gl.ev.map((e)=>e)`); evidence.hookEvents = ev;
  const bySeq = [...ev].sort((a, b) => a.seq - b.seq); const out = [];
  for (const d of bySeq.filter((e) => e.k === 'renderer-destroy' && !e.viaCyCall)) {
    const before = bySeq.filter((e) => e.seq < d.seq);
    const rem = bySeq.find((e) => e.k === 'observed-parent-removal' && e.inst === d.inst && Math.abs(e.seq - d.seq) <= 2);   // the probe observer is created after Cytoscape's own, so its record follows the destroy in the same microtask
    const rep = [...before].reverse().find((e) => e.k === 'keep-reparent' && e.host === d.host);
    const created = before.find((e) => e.k === 'cy-create' && e.inst === d.inst);
    const paints = before.filter((e) => e.k === 'root-innerHTML' && (!created || e.seq > created.seq)).length;
    out.push({ destroySeq: d.seq, inst: d.inst, host: d.host, t: d.t, createdSeq: created?.seq, createdT: created?.t, msAfterCreate: created ? +(d.t - created.t).toFixed(1) : null, hostConnected: d.hostConnected, coreDestroyed: d.coreDestroyed,
      hostParentIsObservedParent: d.hostParent === d.observedParent, observedParentRemovalRecordedWithDestroy: !!rem, removalSeq: rem?.seq, keepReparentSeq: rep?.seq, keepReparentOldParent: rep?.oldParent, keepReparentBeforeDestroy: !!(rep && rep.seq < d.seq), paintsSinceCreate: paints, stack: d.stack });
  }
  const unintentional = out.length; evidence.trigger = { unintentionalDestroys: unintentional, first: out[0] || null, all: out.slice(0, 12),
    summaryByReason: { observerDestroyAfterKeepReparent: out.filter((x) => x.observedParentRemovalRecordedWithDestroy && x.keepReparentBeforeDestroy).length, observerDestroyNoKeepReparent: out.filter((x) => x.observedParentRemovalRecordedWithDestroy && !x.keepReparentBeforeDestroy).length, noObserverRecord: out.filter((x) => !x.observedParentRemovalRecordedWithDestroy).length } };
}

async function launchChrome() {
  rec.counters.chromeLaunches++; rec.chromeStart = stamp();
  if (HEADLESS) { const c = await launch(); pid(c.proc.pid); rec.flags = ['--headless=new', '--disable-gpu', '--no-first-run', '--no-default-browser-check', '--hide-scrollbars', '--user-data-dir=<fresh>', '--remote-debugging-port=0', '+ Emulation 1366x900']; return c; }
  const c = await launchHeaded({ onPid: pid }); rec.flags = c.flags; return c;
}

let svc, chrome, pgRef;
try {
  svc = await service(); chrome = await launchChrome();
  const pg = await newPage(chrome.browser, { width: 1366, height: 900 }); if (!HEADLESS) await pg.send('Emulation.clearDeviceMetricsOverride');
  pgRef = pg; const ctx = { browser: chrome.browser };
  await pg.send('Page.addScriptToEvaluateOnNewDocument', { source: HOOK });
  await pg.goto(svc.base); await pg.waitFor(`document.getElementById('ot-url') && window.__gl`, 30000);
  if (!HEADLESS) { await pg.send('Target.activateTarget', { targetId: pg.targetId }).catch(() => {}); await pg.send('Page.bringToFront'); }
  rec.env = await pg.eval(`({ua:navigator.userAgent,screen:[screen.width,screen.height],dpr:devicePixelRatio,inner:[innerWidth,innerHeight],outer:[outerWidth,outerHeight],vs:document.visibilityState,focus:document.hasFocus()})`);
  rec.version = await chrome.browser.send('Browser.getVersion').catch(() => null);
  const f0 = await pg.eval('window.__gl.raf'); await sleep(1000); const f1 = await pg.eval('window.__gl.raf'); rec.idleFramesFirstSecond = f1 - f0; await sleep(1500); const r0 = await pg.eval('window.__gl.raf'); await sleep(1000); const r1 = await pg.eval('window.__gl.raf'); rec.idleFramesPer1s = r1 - r0;
  check('control: foreground page is visible, focused and producing animation frames (1 s window 2.5 s after activation; the first-second count is recorded separately)', rec.env.vs === 'visible' && rec.idleFramesPer1s >= 20, JSON.stringify({ vs: rec.env.vs, focus: rec.env.focus, frames1s: rec.idleFramesPer1s, firstSecond: rec.idleFramesFirstSecond }));
  const sizes = [[1100, 800], [1600, 900], [1366, 900]];
  const step = async (name, fn) => { try { return await fn(); } catch (e) { H.unfinished.push(`${name} stopped: ` + (e.stack || e.message).slice(0, 300)); check(`${name}: phase completed`, false, e.message); try { await dismiss(pg); } catch {} return null; } };
  const c1 = await step('stage3-modelsupp', () => buildCase(pg, ctx, 'stage3-modelsupp', 'modelsupp', 'ai_model', 'ai', true, { deep: true, sizes, popup: true }));
  if (c1) await step('stage3-modelsupp/navigation', () => navigation(pg, 'stage3-modelsupp', c1.other, c1.sup));
  await step('stage3-modeloutside', () => buildCase(pg, ctx, 'stage3-modeloutside', 'modeloutside', 'ai_model', 'ai', false, { deep: false, sizes: null, popup: false }));
  await step('stage2-crypto', () => buildCase(pg, ctx, 'stage2-crypto', 'cryptosupp', 'cryptography', 'crypto', false, { deep: true, sizes: [[1100, 800], [1366, 900]], popup: false }));
  // session retirement through the real UI: every instance retired, no live detached instance, no leaked observers
  await dismiss(pg); await endSession(pg); const fin = await summary(pg);
  evidence.final = { liveCount: fin.liveCount, liveDetached: fin.liveDetached, unintentionalDestroys: fin.unintentionalDestroys, obs: fin.obs, instances: fin.insts.length };
  check('session retirement: no graph instance remains live (all retired) and no observer is leaked', fin.liveCount === 0 && fin.obs.hostObs === 0 && fin.obs.parentObs === 0, JSON.stringify(evidence.final));
  check('whole run: zero renderer destroys outside intentional teardown calls', fin.unintentionalDestroys === 0, JSON.stringify(fin.insts.filter((i) => i.destroys.some((d) => !d.viaCyCall)).map((i) => ({ id: i.id, destroys: i.destroys })).slice(0, 6)));
  check('whole run: no page exceptions, hook errors or console errors', pg.log.exceptions.length === 0 && fin.hookErrors.length === 0 && pg.log.console.filter((c) => c.type === 'error').length === 0, JSON.stringify({ ex: pg.log.exceptions.slice(0, 3), hook: fin.hookErrors, errs: pg.log.console.filter((c) => c.type === 'error').slice(0, 3) }));
  rec.pageExceptions = pg.log.exceptions.slice(0, 10); rec.consoleErrors = pg.log.console.filter((c) => c.type === 'error').slice(0, 10);
} catch (e) { H.unfinished.push('driver stopped: ' + (e.stack || e.message).slice(0, 500)); check('run completed', false, e.stack || e.message); }
finally {
  try { if (pgRef) await dumpHooks(pgRef); } catch (e) { evidence.hookDumpError = String(e.message).slice(0, 200); }
  rec.end = stamp(); H.save(); try { svc && svc.stop(); } catch {} if (chrome) await chrome.close();
}
const failed = H.results.filter((r) => !r.ok).length; console.log(`${H.results.length - failed}/${H.results.length} checks passed; unfinished: ${H.unfinished.length}; launches: service ${rec.counters.serviceLaunches}, chrome ${rec.counters.chromeLaunches}`);
