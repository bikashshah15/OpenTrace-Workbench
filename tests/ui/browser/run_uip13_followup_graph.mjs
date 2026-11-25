// UIP-13 follow-up (test harness only; no product change): desktop verification that the focused BOM graph VISIBLY renders (canvas ink, not just a populated list or a
// computed layout), plus the late live-scan banner and occurrence-label wording, through the real UI. LOCAL SYNTHETIC fixtures only (uip13_followup_service.py).
// One fixture service + one headless Chrome per invocation. No retries. Usage:
//   OT_DEADLINE_MS=<epoch ms> OT_PIDS_FILE=<file> node run_uip13_followup_graph.mjs <outDir>
import { spawn } from 'node:child_process';
import { appendFileSync, writeFileSync } from 'node:fs';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { launch, newPage } from './cdp.mjs';
import { harness, sleep, txt, state, apiJson, settled, setUrl, inspectorContent, endSession } from './uip12_lib.mjs';

const HERE = dirname(fileURLToPath(import.meta.url)); const REPO = resolve(HERE, '../../..');
const H = harness({ out: process.argv[2], label: 'uip13_followup_graph', synthetic: true });
const { check, guard, evidence, OUT } = H;
const BANNER_AI = 'no advisory matching or inventory checks (the AI-BOM was produced separately by Cisco AI-BOM and is compared with static model references in the BOM view).';
const BANNER_NOAI = 'no advisory matching, AI-BOM or inventory checks.';

function service() {
  const proc = spawn(process.env.PYTHON || 'python3', [join(HERE, 'uip13_followup_service.py')], { cwd: REPO, env: { ...process.env, PYTHONPATH: `${REPO}:${join(REPO, 'src/core')}` }, stdio: ['ignore', 'pipe', 'pipe'] });
  if (process.env.OT_PIDS_FILE) appendFileSync(process.env.OT_PIDS_FILE, proc.pid + '\n');
  return new Promise((res, rej) => { let b = ''; const t = setTimeout(() => rej(new Error('service did not start: ' + b)), 40000);
    proc.stdout.on('data', (d) => { b += d; const m = b.match(/http:\/\/127\.0\.0\.1:(\d+)\//); if (m) { clearTimeout(t); res({ base: m[0], stop: () => proc.kill('SIGTERM') }); } });
    proc.stderr.on('data', (d) => { b += d; try { appendFileSync(join(OUT, 'service_stderr.log'), d); } catch {} }); });
}
const scanRepo = async (pg, repo, first) => {
  guard(); if (!first) await endSession(pg);
  await pg.waitFor(`document.getElementById('ot-scan') && !document.getElementById('ot-scan').disabled`, 20000);
  await setUrl(pg, 'https://github.com/acme/' + repo); await pg.click('#ot-scan');
  await pg.waitFor(`window.__otStore.get().destination === 'workbench' || window.__otStore.get().scan?.status?.job?.state === 'failed'`, 90000);
  const st = await state(pg);
  if (st.destination !== 'workbench') throw new Error('scan did not reach the workbench: ' + JSON.stringify(st.scan?.status?.job).slice(0, 800));
  await pg.click('#ot-tab-bom'); await pg.waitFor(`window.__otStore.get().bom8.queue`, 30000);
  await pg.waitFor(`(()=>{const b=window.__otStore.get().bom8; return b.queue && !b.req.queue && !b.req.graph && !b.req.detail})()`, 30000);
};
const gen = async (pg) => (await state(pg)).analysis.generation;
const queue = async (pg, family) => { const r = await apiJson(pg, `/api/workbench/v1/bom-candidates?schema_version=1&generation=${await gen(pg)}&family=${family}`); return { items: r.body?.items || [], caps: r.body?.capabilities || [] }; };
const rowSel = (id) => `[data-action=bom-select][data-id=${JSON.stringify(id)}]`;
const openView = async (pg, v) => { await pg.click(`[data-action=bom-view][data-view=${v}]`); await settled(pg, v); };

// In-page probe of the REAL rendered graph: Cytoscape state + the pixels actually painted on its canvas layers.
const PROBE = `(()=>{
  const host=document.querySelector('[data-bom-cy=inline]'); if(!host) return {host:false};
  host.scrollIntoView({block:'center',behavior:'instant'}); const r=host.getBoundingClientRect(); const cy=host._cy; const canv=[...host.querySelectorAll('canvas')];
  const out={host:true, scroll:{x:scrollX,y:scrollY}, rect:{x:r.x,y:r.y,w:r.width,h:r.height}, hostVisible:r.width>50&&r.height>50&&getComputedStyle(host).visibility!=='hidden'&&getComputedStyle(host).display!=='none',
    canvases:canv.map(c=>({w:c.width,h:c.height,cw:c.clientWidth,ch:c.clientHeight})), cy:!!cy, expectedNodes:(window.__otStore.get().bom8.graph?.nodes||[]).length, expectedEdges:(window.__otStore.get().bom8.graph?.edges||[]).length};
  if(!cy) return out;
  const nodes=cy.nodes().map(n=>{const p=n.position(), q=n.renderedPosition(); return {id:n.id(),x:p.x,y:p.y,rx:q.x,ry:q.y};});
  out.nodes=nodes.length; out.edges=cy.edges().length; out.zoom=cy.zoom(); out.selected=cy.$(':selected').map(n=>n.id());
  out.finite=nodes.every(n=>[n.x,n.y,n.rx,n.ry].every(Number.isFinite));
  out.distinct=new Set(nodes.map(n=>Math.round(n.x)+','+Math.round(n.y))).size;
  out.insideContainer=nodes.filter(n=>n.rx>=0&&n.rx<=r.width&&n.ry>=0&&n.ry<=r.height).length;
  out.nodePositions=nodes.slice(0,12);
  // ink: painted (alpha>0) pixels over all canvas layers of the host
  let ink=0,total=0; const pr=window.devicePixelRatio||1;
  const layers=canv.map(c=>{try{const d=c.getContext('2d').getImageData(0,0,c.width,c.height).data; let k=0; for(let i=3;i<d.length;i+=4) if(d[i]>0) k++; ink+=k; total+=c.width*c.height; return {ink:k,px:c.width*c.height};}catch(e){return {err:String(e)}}});
  out.layers=layers; out.inkPixels=ink; out.canvasPixels=total;
  // edge evidence: painted pixels around every edge midpoint on any layer
  let edgeInk=0; const em=cy.edges().map(e=>e.renderedMidpoint());
  out.edgeMidpoints=em.length;
  for(const m of em){ let hit=false; for(const c of canv){ try{ const x=Math.max(0,Math.round(m.x*pr)-4), y=Math.max(0,Math.round(m.y*pr)-4); const d=c.getContext('2d').getImageData(x,y,9,9).data; for(let i=3;i<d.length;i+=4) if(d[i]>0){hit=true;break;} }catch{} if(hit)break;} if(hit) edgeInk++; }
  out.edgesWithInk=edgeInk;
  const cx=r.x+r.width/2, cyy=r.y+r.height/2; const top=document.elementFromPoint(Math.min(innerWidth-1,Math.max(0,cx)),Math.min(innerHeight-1,Math.max(0,cyy)));
  out.topElementInsideHost=!!top&&host.contains(top);
  return out;})()`;
const probe = (pg) => pg.eval(PROBE);
const rendered = (p, minNodes = 1) => p.host && p.hostVisible && p.cy && p.nodes >= minNodes && p.nodes === p.expectedNodes && p.edges === p.expectedEdges && p.finite
  && (p.nodes < 2 || p.distinct === p.nodes) && p.insideContainer === p.nodes && p.inkPixels >= 300 * p.nodes && p.topElementInsideHost;

// Wait (bounded) for REAL layout completion + meaningful node positions + painted ink; records how long it took and what the earlier states looked like.
async function waitRendered(pg, label, ms = 12000) {
  const t0 = Date.now(); let first = null, last = null, early = null;
  while (Date.now() - t0 < ms) {
    guard(); last = await probe(pg);
    if (last.cy && first === null) { first = Date.now() - t0; if (!(last.nodes > 1 ? last.distinct === last.nodes : true)) early = { atMs: first, nodes: last.nodes, distinct: last.distinct, ink: last.inkPixels }; }
    if (rendered(last)) return { ok: true, ms: Date.now() - t0, firstCyMs: first, early, probe: last };
    await sleep(100);
  }
  return { ok: false, ms: Date.now() - t0, firstCyMs: first, early, probe: last };
}
// Screenshot of the host region (compositor output, not the canvas buffer), analysed in the page: share of pixels that differ from the dominant (background) colour.
async function shot(pg, name) {
  const p = await probe(pg); const file = join(OUT, name + '.png');
  await pg.screenshot(file);
  const clip = p.host ? { x: Math.max(0, p.rect.x + p.scroll.x), y: Math.max(0, p.rect.y + p.scroll.y), width: Math.max(1, Math.min(p.rect.w, 1700)), height: Math.max(1, Math.min(p.rect.h, 1200)), scale: 1 } : null;
  let ratio = null;
  if (clip) {
    const r = await pg.send('Page.captureScreenshot', { format: 'png', clip, captureBeyondViewport: true });
    writeFileSync(join(OUT, name + '_graph_region.png'), Buffer.from(r.data, 'base64'));
    ratio = await pg.eval(`new Promise((res)=>{const im=new Image(); im.onload=()=>{const c=document.createElement('canvas'); c.width=im.width; c.height=im.height; const g=c.getContext('2d'); g.drawImage(im,0,0); const d=g.getImageData(0,0,c.width,c.height).data; const m=new Map(); for(let i=0;i<d.length;i+=4){const k=(d[i]>>3)+','+(d[i+1]>>3)+','+(d[i+2]>>3); m.set(k,(m.get(k)||0)+1);} let best=0; for(const v of m.values()) if(v>best) best=v; const px=d.length/4; res({w:c.width,h:c.height,distinctColours:m.size,nonDominantShare:Number(((px-best)/px).toFixed(4))});}; im.onerror=()=>res({err:'decode'}); im.src='data:image/png;base64,${r.data}';})`);
  }
  return { file, region: ratio, probe: p };
}
async function savePng(pg, name) {   // Cytoscape's own export of the drawn graph, independent of screen compositing
  const b64 = await pg.eval(`(()=>{const h=document.querySelector('[data-bom-cy=inline]'); return h&&h._cy ? h._cy.png({output:'base64', full:true, scale:1, bg:'#ffffff'}) : null})()`);
  if (b64) writeFileSync(join(OUT, name + '_cy_export.png'), Buffer.from(b64, 'base64')); return b64 ? b64.length : 0;
}
const clickNode = async (pg, id) => {   // a REAL mouse click at the node's rendered position
  await pg.eval(`document.querySelector('[data-bom-cy=inline]').scrollIntoView({block:'center',behavior:'instant'})`); await sleep(150);
  const pt = await pg.eval(`(()=>{const h=document.querySelector('[data-bom-cy=inline]'); const n=h._cy.getElementById(${JSON.stringify(id)}); const r=h.getBoundingClientRect(); const q=n.renderedPosition(); return {x:r.x+q.x,y:r.y+q.y}})()`);
  await pg.send('Input.dispatchMouseEvent', { type: 'mouseMoved', x: pt.x, y: pt.y });
  await pg.send('Input.dispatchMouseEvent', { type: 'mousePressed', x: pt.x, y: pt.y, button: 'left', clickCount: 1 });
  await pg.send('Input.dispatchMouseEvent', { type: 'mouseReleased', x: pt.x, y: pt.y, button: 'left', clickCount: 1 });
};
const setSize = async (pg, w, h) => { await pg.send('Emulation.setDeviceMetricsOverride', { width: w, height: h, deviceScaleFactor: 1, mobile: false }); await pg.waitFor(`innerWidth===${w}`, 8000); };

async function graphChecks(pg, label, family, view, first) {
  await scanRepo(pg, label, first); await openView(pg, view);
  const q = await queue(pg, family); evidence[`${label}_queue`] = q.items.map((i) => ({ id: i.item_id, state: i.state, path: i.location?.path }));
  check(`${label}: at least one ${family} candidate is queued`, q.items.length >= 1, JSON.stringify(evidence[`${label}_queue`]));
  return q;
}

async function main(pg) {
  // ---- Stage 3 (models) -------------------------------------------------------------------------------------------------------------------------------
  let q = await graphChecks(pg, 'modelsupp', 'ai_model', 'ai', true);
  // banner (late change R3-03): checked against the cards the page itself holds
  const st = await state(pg); const cards = (st.analysis?.summary?.cards || []).map((c) => c.kind);
  const bar = await pg.eval(`(()=>{const e=document.getElementById('ot-bar-text'); const r=e&&e.getBoundingClientRect(); return {text:(e?.innerText||'').replace(/\\s+/g,' '), visible:!!r&&r.width>0&&r.height>0&&r.bottom>0&&r.top<innerHeight}})()`);
  evidence.banner = { cards, ...bar };
  const wantAi = cards.includes('aibom');
  check('banner: visible in the live UI', bar.visible, bar.text.slice(0, 200), { actions: ['scan modelsupp'] });
  check(`banner: states what the scan ran, consistent with the cards present (${cards.join(',')})`, wantAi ? bar.text.includes(BANNER_AI) && !bar.text.includes(BANNER_NOAI) : bar.text.includes(BANNER_NOAI), bar.text);
  check('banner: an AI-BOM card exists in this fixture, so the banner must not say "no AI-BOM"', !wantAi || !/No AI-BOM|AI-BOM or inventory checks/.test(bar.text), bar.text);
  await pg.screenshot(join(OUT, 'banner_modelsupp_1366.png'));
  // occurrence label (late change R3-04) in every model candidate's inspector
  for (const it of q.items) {
    await pg.click(rowSel(it.item_id)); await pg.waitFor(`document.querySelector('[data-evidence-for=${JSON.stringify(it.item_id)}] .ot-gap-inspector')`, 20000);
    const t = await inspectorContent(pg); evidence[`label_${it.state}`] = t.slice(0, 1500);
    check(`occurrence label (${it.state}): "not compared for another reason (see the reason code)" is shown`, /Occurrences:/.test(t) && t.includes('not compared for another reason (see the reason code)'), t.slice(0, 300));
    check(`occurrence label (${it.state}): the old "blocked by a digest or binding check" wording is gone`, !t.includes('blocked by a digest or binding check'), t.slice(0, 200));
  }
  // focused graph: select the supported candidate, wait for real layout, verify painted nodes/edges
  const sup = q.items.find((i) => i.state === 'supported'), unv = q.items.find((i) => i.state !== 'supported');
  check('modelsupp: a supported and a second candidate exist for reselection', !!sup && !!unv, JSON.stringify(evidence.modelsupp_queue));
  await pg.click(rowSel(sup.item_id)); await pg.waitFor(`window.__otStore.get().bom8.selected===${JSON.stringify(sup.item_id)} && window.__otStore.get().bom8.graph?.scope?.candidate_id===${JSON.stringify(sup.item_id)}`, 20000);
  const w1 = await waitRendered(pg, 'modelsupp-initial'); evidence.modelsupp_initial = { ms: w1.ms, firstCyMs: w1.firstCyMs, early: w1.early };
  check('modelsupp graph: layout completes with distinct finite node positions inside the container, within 12 s', w1.ok, JSON.stringify(w1.probe).slice(0, 400), { routes: ['/api/workbench/v1/bom-graph'], actions: ['select supported candidate'] });
  const s1 = await shot(pg, 'modelsupp_initial_1366'); evidence.modelsupp_initial_shot = s1;
  check('modelsupp graph: the canvas has painted ink for every node (>= 300 px per node)', s1.probe.inkPixels >= 300 * s1.probe.nodes, `ink=${s1.probe.inkPixels} nodes=${s1.probe.nodes}`);
  check('modelsupp graph: every edge midpoint carries painted ink (edges visible)', s1.probe.edges >= 1 && s1.probe.edgesWithInk >= Math.ceil(0.8 * s1.probe.edges), `${s1.probe.edgesWithInk}/${s1.probe.edges}`);
  check('modelsupp graph: the screenshot region (compositor output) is not blank', !!s1.region && s1.region.nonDominantShare > 0.01 && s1.region.distinctColours > 4, JSON.stringify(s1.region));
  check('modelsupp graph: the graph list shows the same node count the canvas draws', (await pg.eval(`document.querySelectorAll('.ot-bom8-records [data-action=bom-record]').length`)) === s1.probe.nodes, '');
  evidence.modelsupp_export_bytes = await savePng(pg, 'modelsupp_initial');
  // node selection by real click, then reselection of candidates
  const target = s1.probe.nodePositions.find((n) => !s1.probe.selected.includes(n.id)) || s1.probe.nodePositions[0];
  await clickNode(pg, target.id); await pg.waitFor(`window.__otStore.get().bom8.selectedRecord===${JSON.stringify(target.id)}`, 8000).catch(() => {});
  await sleep(300); const w2 = await probe(pg); const sel = (await state(pg)).bom8.selectedRecord;
  check('modelsupp graph: a real click on a drawn node selects that record and the graph stays painted', sel === target.id && w2.selected.includes(target.id) && rendered(w2), JSON.stringify({ sel, want: target.id, selected: w2.selected, ink: w2.inkPixels }));
  await shot(pg, 'modelsupp_node_selected_1366');
  for (const [lab, it] of [['unverifiable', unv], ['supported again', sup], ['unverifiable again', unv]]) {
    await pg.click(rowSel(it.item_id)); await pg.waitFor(`window.__otStore.get().bom8.selected===${JSON.stringify(it.item_id)} && window.__otStore.get().bom8.graph?.scope?.candidate_id===${JSON.stringify(it.item_id)}`, 20000);
    const w = await waitRendered(pg, lab); const s = await shot(pg, 'modelsupp_reselect_' + lab.replace(/\W+/g, '_'));
    check(`reselect (${lab}): graph is laid out and painted within 12 s, no blank canvas`, w.ok && s.region?.nonDominantShare > 0.01, JSON.stringify({ ms: w.ms, ink: s.probe.inkPixels, nodes: s.probe.nodes, region: s.region }));
  }
  await pg.click(rowSel(sup.item_id)); await waitRendered(pg, 'before-resize');
  for (const [w, h] of [[1100, 800], [1600, 900], [1366, 900]]) {
    await setSize(pg, w, h); await sleep(1500); const p = await probe(pg); const s = await shot(pg, `modelsupp_resize_${w}`);
    evidence[`resize_${w}`] = { rect: p.rect, canvases: p.canvases, ink: p.inkPixels, nodes: p.nodes, inside: p.insideContainer, region: s.region };
    check(`resize ${w}x${h}: graph still painted within 1.5 s without user action`, rendered(p) && s.region?.nonDominantShare > 0.01, JSON.stringify(evidence[`resize_${w}`]).slice(0, 400));
    if (!(rendered(p) && s.region?.nonDominantShare > 0.01)) { await pg.click('[data-action=bom-fit]'); await sleep(500); const pf = await probe(pg); evidence[`resize_${w}_after_fit`] = { ink: pf.inkPixels, rendered: rendered(pf) }; }
  }
  // outside-scope model reference: label wording with a non-zero outside count
  q = await graphChecks(pg, 'modeloutside', 'ai_model', 'ai', false);
  if (q.items[0]) { await pg.click(rowSel(q.items[0].item_id)); await pg.waitFor(`document.querySelector('[data-evidence-for=${JSON.stringify(q.items[0].item_id)}] .ot-gap-inspector')`, 20000);
    const t = await inspectorContent(pg); evidence.label_outside = t.slice(0, 1500);
    check('occurrence label (outside scope): counts line uses the corrected wording with a non-zero outside count', /[1-9]\d* outside the AI-BOM scope/.test(t) && t.includes('not compared for another reason (see the reason code)'), t.slice(0, 300));
    const w = await waitRendered(pg, 'modeloutside'); await shot(pg, 'modeloutside_1366'); check('modeloutside graph: painted', w.ok, JSON.stringify(w.probe).slice(0, 300)); }
  // ---- Stage 2 representative (crypto) ----------------------------------------------------------------------------------------------------------------
  q = await graphChecks(pg, 'cryptosupp', 'cryptography', 'crypto', false);
  const c0 = q.items[0];
  if (c0) {
    await pg.click(rowSel(c0.item_id)); await pg.waitFor(`window.__otStore.get().bom8.selected===${JSON.stringify(c0.item_id)} && window.__otStore.get().bom8.graph?.scope?.candidate_id===${JSON.stringify(c0.item_id)}`, 20000);
    const w = await waitRendered(pg, 'cryptosupp'); const s = await shot(pg, 'cryptosupp_initial_1366'); await savePng(pg, 'cryptosupp_initial');
    evidence.cryptosupp = { ms: w.ms, early: w.early, ink: s.probe.inkPixels, nodes: s.probe.nodes, edges: s.probe.edges, edgesWithInk: s.probe.edgesWithInk, region: s.region };
    check('Stage 2 crypto graph: layout completes with distinct finite positions inside the container', w.ok, JSON.stringify(w.probe).slice(0, 400));
    check('Stage 2 crypto graph: nodes and edges are painted and the screenshot region is not blank', s.probe.inkPixels >= 300 * s.probe.nodes && s.probe.edgesWithInk >= Math.ceil(0.8 * s.probe.edges) && s.region?.nonDominantShare > 0.01, JSON.stringify(evidence.cryptosupp));
    await setSize(pg, 1100, 800); await sleep(1500); const p = await probe(pg); const s2 = await shot(pg, 'cryptosupp_resize_1100');
    check('Stage 2 crypto graph: still painted after a resize', rendered(p) && s2.region?.nonDominantShare > 0.01, JSON.stringify({ ink: p.inkPixels, region: s2.region }));
    await setSize(pg, 1366, 900);
  }
  check('no page exceptions', pg.log.exceptions.length === 0, pg.log.exceptions.join(' | ').slice(0, 300));
  evidence.console_errors = pg.log.console.filter((c) => c.type === 'error').slice(0, 10);
}

let svc, chrome;
try {
  svc = await service(); chrome = await launch(); if (process.env.OT_PIDS_FILE) appendFileSync(process.env.OT_PIDS_FILE, chrome.proc.pid + '\n');
  const pg = await newPage(chrome.browser, { width: 1366, height: 900 }); await pg.goto(svc.base);
  await pg.waitFor(`document.getElementById('ot-url')`, 30000);
  await main(pg);
} catch (e) { H.unfinished.push('driver stopped: ' + (e.stack || e.message).slice(0, 400)); check('run completed', false, e.stack || e.message); }
finally { H.save(); try { svc && svc.stop(); } catch {} if (chrome) await chrome.close(); }
const failed = H.results.filter((r) => !r.ok).length; console.log(`${H.results.length - failed}/${H.results.length} checks passed; unfinished: ${H.unfinished.length}`);
