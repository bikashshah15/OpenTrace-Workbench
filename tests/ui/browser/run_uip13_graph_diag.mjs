// UIP-13 follow-up graph DIAGNOSTIC (test harness only; no product change). Separates three things that the first desktop run conflated:
//   LAYOUT (Cytoscape node positions/viewport fit)  vs  CANVAS PAINT (alpha>0 pixels on the canvas layers)  vs  COMPOSITOR OUTPUT (screenshot of the host region).
// It also records page visibility/focus, requestAnimationFrame progress, Cytoscape renderer state (unavailable fields are reported as unknown/<absent>, never as false/0),
// the actual connected host/canvas identity and dimensions, worker activity and page errors. Every fixture is SYNTHETIC (uip13_followup_service.py): no network, Docker, scanner, provider.
//
// ONE fixture service for the whole run; Chrome launch 1 = the original headless configuration (cdp.mjs launch(), unchanged) with instrumentation;
// Chrome launch 2 (only if launch 1 leaves any check unsatisfied) = a visible, foreground, headed Chrome with normal rendering flags, same service, fresh profile (cookie isolation).
// No retries. Usage:  OT_DEADLINE_MS=<epoch ms> OT_PIDS_FILE=<file> node run_uip13_graph_diag.mjs <outDir>      |      node run_uip13_graph_diag.mjs --selftest
import { spawn } from 'node:child_process';
import { appendFileSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { launch, newPage, connect, CHROME } from './cdp.mjs';
import { harness, sleep, state, apiJson, settled, setUrl } from './uip12_lib.mjs';
// End the fixture-owned session through the real UI WITHOUT re-applying a viewport override (keeps the headed control free of emulation).
const endSession = async (pg) => { await pg.click('#ot-top-end'); await pg.waitFor(`document.getElementById('ot-ended-note')`, 30000); };

const HERE = dirname(fileURLToPath(import.meta.url)); const REPO = resolve(HERE, '../../..');

// ---- in-page scripts (strings) --------------------------------------------------------------------------------------------------------------------------
// Installed BEFORE navigation with Page.addScriptToEvaluateOnNewDocument. A cheap perpetual rAF counter (so frame production is measured by a separate observer, independent of
// Cytoscape), visibility/focus event log, Worker creation/message/error log, window errors. The Worker subclass only adds listeners; it does not change behaviour.
export const DIAG = `(()=>{ if(window.__diag) return; const D=window.__diag={raf:{n:0,last:0,ts:[]},events:[],workers:[],errors:[],io:null,ioHost:null,ids:0};
 const tick=()=>{D.raf.n++;D.raf.last=performance.now(); const a=D.raf.ts; a.push(Math.round(performance.now())); if(a.length>4000) a.shift(); requestAnimationFrame(tick)}; requestAnimationFrame(tick);
 const ev=(k)=>D.events.push({k,t:Math.round(performance.now()),vs:document.visibilityState,focus:document.hasFocus()});
 ev('init'); document.addEventListener('visibilitychange',()=>ev('visibilitychange')); window.addEventListener('focus',()=>ev('focus')); window.addEventListener('blur',()=>ev('blur'));
 window.addEventListener('error',(e)=>D.errors.push({k:'error',m:String(e.message||e.type).slice(0,200),src:String(e.filename||'').slice(-60)}));
 window.addEventListener('unhandledrejection',(e)=>D.errors.push({k:'rejection',m:String((e.reason&&e.reason.message)||e.reason).slice(0,200)}));
 const W=window.Worker; if(W){ window.Worker=class extends W{ constructor(u,o){ super(u,o); const w={url:String(u).slice(-60),created:Math.round(performance.now()),msgs:0,errors:[]}; D.workers.push(w);
   this.addEventListener('message',()=>{w.msgs++;}); this.addEventListener('error',(e)=>w.errors.push(String(e.message||'error').slice(0,160))); this.addEventListener('messageerror',()=>w.errors.push('messageerror')); } }; }
 D.mark=(n)=>D.events.push({k:'mark:'+n,t:Math.round(performance.now()),vs:document.visibilityState,focus:document.hasFocus()});
})()`;

// One sample of the page + graph. withInk reads the canvas pixels (alpha>0) on every layer; deep adds the ancestor chain and renderer key list.
export const SAMPLE = `((withInk, deep)=>{
 const P=performance.now(); const D=window.__diag||{raf:{n:0,last:0,ts:[]},events:[],workers:[],errors:[],ids:0}; const tr=(f)=>{try{return f();}catch(e){return 'ERR:'+String(e).slice(0,60);}};
 const o={t:Math.round(P),vs:document.visibilityState,hidden:document.hidden,focus:document.hasFocus(),dpr:devicePixelRatio,inner:[innerWidth,innerHeight]};
 const ts=D.raf.ts.filter((x)=>x>=P-1000); let mg=0; for(let i=1;i<ts.length;i++) mg=Math.max(mg,ts[i]-ts[i-1]);
 o.raf={n:D.raf.n,lastAgoMs:D.raf.last?Math.round(P-D.raf.last):null,last1s:ts.length,maxGap1s:mg,io:D.io||null}; o.nEvents=D.events.length; o.nWorkers=D.workers.length; o.nErrors=D.errors.length;
 const hosts=[...document.querySelectorAll('[data-bom-cy=inline]')]; o.hostCount=hosts.length; const host=hosts[0];
 if(!host){ o.host=null; o.cost=Math.round(performance.now()-P); return o; }
 host.__dg=host.__dg||('h'+(++D.ids)); const r=host.getBoundingClientRect(); const cs=getComputedStyle(host);
 o.host={id:host.__dg,connected:host.isConnected,keep:host.getAttribute('data-keep'),rect:[Math.round(r.x),Math.round(r.y),Math.round(r.width),Math.round(r.height)],display:cs.display,visibility:cs.visibility,opacity:cs.opacity,
   offset:[host.offsetWidth,host.offsetHeight],client:[host.clientWidth,host.clientHeight],inViewport:r.bottom>0&&r.top<innerHeight&&r.right>0&&r.left<innerWidth,scrollY:Math.round(scrollY)};
 if(D.ioHost!==host){ D.ioHost=host; try{ new IntersectionObserver((es)=>{const e=es[es.length-1]; D.io={isIntersecting:e.isIntersecting,ratio:+e.intersectionRatio.toFixed(3),t:Math.round(performance.now())};}).observe(host);}catch(e){} }
 if(deep){ const anc=[]; let e=host.parentElement; for(let i=0;e&&i<12;i++,e=e.parentElement){ const c=getComputedStyle(e),b=e.getBoundingClientRect();
   anc.push([e.tagName.toLowerCase()+(e.id?'#'+e.id:'')+((typeof e.className==='string'&&e.className)?'.'+e.className.split(' ')[0]:''),c.display,c.visibility,c.opacity,c.overflow,c.contentVisibility||'',c.transform==='none'?'':'transform',Math.round(b.width)+'x'+Math.round(b.height)].join('|')); } o.ancestors=anc; }
 const cv=[...host.querySelectorAll('canvas')];
 o.canvases=cv.map((c)=>{ c.__dg=c.__dg||('c'+(++D.ids)); const q=getComputedStyle(c); return {id:c.__dg,connected:c.isConnected,w:c.width,h:c.height,cw:c.clientWidth,ch:c.clientHeight,display:q.display,visibility:q.visibility,z:q.zIndex}; });
 const cy=host._cy; o.cy=!!cy; if(!cy){ o.cost=Math.round(performance.now()-P); return o; }
 o.cyInfo={container:tr(()=>cy.container()===host),destroyed:tr(()=>cy.destroyed()),batching:tr(()=>cy.batching()),forceRenderType:typeof cy.forceRender,pan:tr(()=>cy.pan()),zoom:tr(()=>cy.zoom()),size:tr(()=>[cy.width(),cy.height()])};
 const ns=cy.nodes(); const pos=ns.map((n)=>n.position()); const rp=ns.map((n)=>n.renderedPosition()); const st=window.__otStore.get().bom8.graph||{};
 o.nodes=ns.length; o.edges=cy.edges().length; o.expectedNodes=(st.nodes||[]).length; o.expectedEdges=(st.edges||[]).length;
 o.finite=pos.every((p)=>Number.isFinite(p.x)&&Number.isFinite(p.y))&&rp.every((p)=>Number.isFinite(p.x)&&Number.isFinite(p.y));
 o.distinct=new Set(pos.map((p)=>Math.round(p.x)+','+Math.round(p.y))).size; o.insideContainer=rp.filter((p)=>p.x>=0&&p.x<=r.width&&p.y>=0&&p.y<=r.height).length;
 o.positions=pos.slice(0,8).map((p)=>[Math.round(p.x),Math.round(p.y)]);
 if(rp.length){ o.renderedBBox=[Math.round(Math.min(...rp.map((p)=>p.x))),Math.round(Math.min(...rp.map((p)=>p.y))),Math.round(Math.max(...rp.map((p)=>p.x))),Math.round(Math.max(...rp.map((p)=>p.y)))]; }
 const R=tr(()=>cy.renderer()); const K=['renderLoopStarted','destroyed','requestedFrame','skipFrame','redrawCount','lastDrawTime','averageRedrawTime','lastRedrawTime'];
 o.renderer=(R&&typeof R==='object'&&!String(R).startsWith('ERR'))?Object.fromEntries(K.map((k)=>[k,(k in R)?R[k]:'<absent>'])):'unavailable';
 if(deep&&R&&typeof R==='object') o.rendererKeys=Object.keys(R).slice(0,100);
 if(withInk){ let ink=0,total=0; const pr=devicePixelRatio||1;
   o.layers=cv.map((c)=>{ try{ const d=c.getContext('2d').getImageData(0,0,c.width,c.height).data; let k=0; for(let i=3;i<d.length;i+=4) if(d[i]>0) k++; ink+=k; total+=c.width*c.height; return {ink:k,px:c.width*c.height}; }catch(e){ return {err:String(e).slice(0,80)}; } });
   o.inkPixels=ink; o.canvasPixels=total; let edgeInk=0; const em=cy.edges().map((e)=>e.renderedMidpoint()); o.edgeMidpoints=em.length;
   for(const m of em){ let hit=false; for(const c of cv){ try{ const x=Math.max(0,Math.round(m.x*pr)-4),y=Math.max(0,Math.round(m.y*pr)-4); const d=c.getContext('2d').getImageData(x,y,9,9).data; for(let i=3;i<d.length;i+=4) if(d[i]>0){hit=true;break;} }catch{} if(hit) break; } if(hit) edgeInk++; }
   o.edgesWithInk=edgeInk; }
 o.cost=Math.round(performance.now()-P); return o; })`;

// forceRender step: ink before, call, then renderer/ink immediately (synchronously) so that "immediate" is not confused with "after the next frame".
export const FORCE = `(()=>{ const host=document.querySelector('[data-bom-cy=inline]'); const cy=host&&host._cy; if(!cy) return {cy:false}; const tr=(f)=>{try{return f();}catch(e){return 'ERR:'+String(e).slice(0,80);}};
 const ink=()=>{ let k=0; for(const c of host.querySelectorAll('canvas')){ try{ const d=c.getContext('2d').getImageData(0,0,c.width,c.height).data; for(let i=3;i<d.length;i+=4) if(d[i]>0) k++; }catch{} } return k; };
 const R=tr(()=>cy.renderer()); const f=()=>R&&typeof R==='object'?{requestedFrame:('requestedFrame' in R)?R.requestedFrame:'<absent>',redrawCount:('redrawCount' in R)?R.redrawCount:'<absent>',lastDrawTime:('lastDrawTime' in R)?R.lastDrawTime:'<absent>'}:'unavailable';
 const before={ink:ink(),r:f(),rafN:window.__diag?window.__diag.raf.n:null}; const type=typeof cy.forceRender; let err=null; if(type==='function'){ try{ cy.forceRender(); }catch(e){ err=String(e).slice(0,120); } }
 const after={ink:ink(),r:f(),rafN:window.__diag?window.__diag.raf.n:null}; return {cy:true,forceRenderType:type,err,before,afterSync:after}; })()`;

const CALLEE = (s) => `(${s})`;
export const selftest = () => { for (const [n, s] of [['DIAG', DIAG], ['SAMPLE', SAMPLE], ['FORCE', FORCE]]) { try { new Function('return ' + (n === 'SAMPLE' ? s : s)); } catch (e) { return `${n}: ${e.message}`; } } return null; };
if (process.argv[2] === '--selftest') { const e = selftest(); console.log(e ? 'SELFTEST FAIL ' + e : 'SELFTEST OK (in-page scripts parse)'); process.exit(e ? 1 : 0); }

// ---- harness -------------------------------------------------------------------------------------------------------------------------------------------
const H = harness({ out: process.argv[2], label: 'uip13_graph_diag', synthetic: true });
const { check, guard, evidence, OUT } = H;
const T0 = Date.now(); const DEADLINE = Number(process.env.OT_DEADLINE_MS || 0);
const rec = { counters: { serviceLaunches: 0, chromeLaunches: 0 }, timeoutEvents: [], phases: {} }; evidence.rec = rec;
const stamp = () => ({ wall: new Date().toISOString(), sinceFirstLaunchS: Math.round((Date.now() - T0) / 100) / 10 });
const pidAppend = (pid) => { if (process.env.OT_PIDS_FILE && pid) appendFileSync(process.env.OT_PIDS_FILE, pid + '\n'); };

function service() {
  rec.counters.serviceLaunches++; rec.serviceStart = stamp();
  const proc = spawn(process.env.PYTHON || 'python3', [join(HERE, 'uip13_followup_service.py')], { cwd: REPO, env: { ...process.env, PYTHONPATH: `${REPO}:${join(REPO, 'src/core')}` }, stdio: ['ignore', 'pipe', 'pipe'] });
  pidAppend(proc.pid);
  return new Promise((res, rej) => { let b = ''; const t = setTimeout(() => rej(new Error('service did not start: ' + b)), 40000);
    proc.stdout.on('data', (d) => { b += d; const m = b.match(/http:\/\/127\.0\.0\.1:(\d+)\//); if (m) { clearTimeout(t); res({ base: m[0], stop: () => proc.kill('SIGTERM') }); } });
    proc.stderr.on('data', (d) => { b += d; try { appendFileSync(join(OUT, 'service_stderr.log'), d); } catch {} }); });
}
async function launchHeaded() {          // visible, foreground desktop Chrome: normal rendering (no --headless, no --disable-gpu), fresh profile = cookie isolation
  const dir = mkdtempSync(join(tmpdir(), 'ot-chrome-headed-'));
  const args = [`--user-data-dir=${dir}`, '--no-first-run', '--no-default-browser-check', '--remote-debugging-port=0', '--window-size=1366,900', '--window-position=40,40', 'about:blank'];
  rec.headedFlags = args.map((a) => a.replace(dir, '<fresh-profile-dir>'));
  const proc = spawn(CHROME, args, { stdio: ['ignore', 'ignore', 'pipe'] }); pidAppend(proc.pid);
  const wsUrl = await new Promise((resolve, reject) => { let buf = ''; const t = setTimeout(() => reject(new Error('chrome did not start')), 25000);
    proc.stderr.on('data', (d) => { buf += d; const m = buf.match(/DevTools listening on (ws:\/\/\S+)/); if (m) { clearTimeout(t); resolve(m[1]); } }); proc.on('exit', () => reject(new Error('chrome exited'))); });
  const browser = await connect(wsUrl);
  const close = async () => { try { browser.close(); } catch {} proc.kill('SIGKILL'); try { rmSync(dir, { recursive: true, force: true }); } catch {} };
  return { browser, close, proc, dir };
}

const sample = (pg, ink = true, deep = false) => pg.eval(`${SAMPLE}(${ink},${deep})`);
const derive = (s, region = null) => ({
  layout: !!s.cy && s.nodes > 0 && s.nodes === s.expectedNodes && s.edges === s.expectedEdges && !!s.finite && (s.nodes < 2 || s.distinct === s.nodes) && s.insideContainer === s.nodes,
  canvasInk: s.inkPixels === undefined ? null : (s.nodes > 0 && s.inkPixels >= 300 * s.nodes && s.edgesWithInk >= Math.ceil(0.8 * s.edges)),
  compositor: region ? (region.nonDominantShare > 0.01 && region.distinctColours > 4) : null });
const slim = (s) => ({ t: s.t, vs: s.vs, focus: s.focus, raf: s.raf && { n: s.raf.n, last1s: s.raf.last1s, maxGap1s: s.raf.maxGap1s, lastAgoMs: s.raf.lastAgoMs }, host: s.host && { id: s.host.id, rect: s.host.rect, vis: s.host.visibility, disp: s.host.display, inVp: s.host.inViewport },
  nodes: s.nodes, edges: s.edges, distinct: s.distinct, inside: s.insideContainer, renderer: s.renderer, batching: s.cyInfo?.batching, destroyed: s.cyInfo?.destroyed, zoom: s.cyInfo?.zoom, ink: s.inkPixels, edgesWithInk: s.edgesWithInk, cost: s.cost });
const rowSel = (id) => `[data-action=bom-select][data-id=${JSON.stringify(id)}]`;
const gen = async (pg) => (await state(pg)).analysis.generation;
const queue = async (pg, family) => { const r = await apiJson(pg, `/api/workbench/v1/bom-candidates?schema_version=1&generation=${await gen(pg)}&family=${family}`); return r.body?.items || []; };

async function scanTo(pg, repo, first, view) {
  guard(); if (!first) await endSession(pg);
  await pg.waitFor(`document.getElementById('ot-scan') && !document.getElementById('ot-scan').disabled`, 20000);
  await setUrl(pg, 'https://github.com/acme/' + repo); await pg.click('#ot-scan');
  await pg.waitFor(`window.__otStore.get().destination === 'workbench' || window.__otStore.get().scan?.status?.job?.state === 'failed'`, 90000);
  const st = await state(pg); if (st.destination !== 'workbench') throw new Error('scan did not reach the workbench: ' + JSON.stringify(st.scan?.status?.job).slice(0, 500));
  await pg.click('#ot-tab-bom'); await pg.waitFor(`window.__otStore.get().bom8.queue`, 30000);
  await pg.waitFor(`(()=>{const b=window.__otStore.get().bom8; return b.queue && !b.req.queue && !b.req.graph && !b.req.detail})()`, 30000);
  await pg.click(`[data-action=bom-view][data-view=${view}]`); await settled(pg, view);
}
const selectCandidate = async (pg, id) => { await pg.click(rowSel(id)); await pg.waitFor(`window.__otStore.get().bom8.selected===${JSON.stringify(id)} && window.__otStore.get().bom8.graph?.scope?.candidate_id===${JSON.stringify(id)}`, 20000); };

// Compositor output: screenshot clip of the host region, analysed for the share of pixels that differ from the dominant colour. Records rAF counter around the capture (a capture can itself produce a frame).
async function region(pg, name) {
  const s0 = await sample(pg, false); if (!s0.host) return { err: 'no host' };
  const h = s0.host; const sc = await pg.eval('({x:scrollX,y:scrollY})');
  const clip = { x: Math.max(0, h.rect[0] + sc.x), y: Math.max(0, h.rect[1] + sc.y), width: Math.max(1, Math.min(h.rect[2], 1700)), height: Math.max(1, Math.min(h.rect[3], 1200)), scale: 1 };
  const r = await pg.send('Page.captureScreenshot', { format: 'png', clip, captureBeyondViewport: true }); writeFileSync(join(OUT, name + '_graph_region.png'), Buffer.from(r.data, 'base64'));
  await pg.screenshot(join(OUT, name + '_full.png'));
  const stats = await pg.eval(`new Promise((res)=>{const im=new Image(); im.onload=()=>{const c=document.createElement('canvas'); c.width=im.width; c.height=im.height; const g=c.getContext('2d'); g.drawImage(im,0,0); const d=g.getImageData(0,0,c.width,c.height).data; const m=new Map(); for(let i=0;i<d.length;i+=4){const k=(d[i]>>3)+','+(d[i+1]>>3)+','+(d[i+2]>>3); m.set(k,(m.get(k)||0)+1);} let best=0; for(const v of m.values()) if(v>best) best=v; const px=d.length/4; res({w:c.width,h:c.height,distinctColours:m.size,nonDominantShare:Number(((px-best)/px).toFixed(4))});}; im.onerror=()=>res({err:'decode'}); im.src='data:image/png;base64,${r.data}';})`);
  const s1 = await sample(pg, false); return { ...stats, rafBefore: s0.raf?.n, rafAfter: s1.raf?.n };
}
async function timeline(pg, label, ms, every = 250, ink = true) {      // bounded observation; the sample cost is recorded so a probe-induced stall would show as a long cost/gap
  const out = []; const t0 = Date.now();
  while (Date.now() - t0 < ms) { guard(); out.push(slim(await sample(pg, ink))); await sleep(every); }
  evidence['timeline_' + label] = out; return out;
}
const rafProgress = (tl) => { const a = tl[0]?.raf?.n, b = tl[tl.length - 1]?.raf?.n; return a == null || b == null ? null : b - a; };

async function realClick(pg, id) {
  await pg.eval(`document.querySelector('[data-bom-cy=inline]').scrollIntoView({block:'center',behavior:'instant'})`); await sleep(150);
  const pt = await pg.eval(`(()=>{const h=document.querySelector('[data-bom-cy=inline]'); const n=h._cy.getElementById(${JSON.stringify(id)}); const r=h.getBoundingClientRect(); const q=n.renderedPosition(); return {x:r.x+q.x,y:r.y+q.y}})()`);
  await pg.send('Input.dispatchMouseEvent', { type: 'mouseMoved', x: pt.x, y: pt.y });
  await pg.send('Input.dispatchMouseEvent', { type: 'mousePressed', x: pt.x, y: pt.y, button: 'left', clickCount: 1 });
  await pg.send('Input.dispatchMouseEvent', { type: 'mouseReleased', x: pt.x, y: pt.y, button: 'left', clickCount: 1 });
}
async function setSize(pg, ctx, w, h) {
  if (ctx.headed) { const { windowId } = await ctx.browser.send('Browser.getWindowForTarget', { targetId: pg.targetId }); await ctx.browser.send('Browser.setWindowBounds', { windowId, bounds: { windowState: 'normal', width: w, height: h } }); await sleep(400); }
  else { await pg.send('Emulation.setDeviceMetricsOverride', { width: w, height: h, deviceScaleFactor: 1, mobile: false }); await pg.waitFor(`innerWidth===${w}`, 8000); }
}

// One graph build = scan + select + un-intervened bounded observation (no screenshot, no forceRender) + compositor analysis. Returns the pieces for the interpretation.
async function observeBuild(pg, P, repo, family, view, first, tag, { obsMs = 2500 } = {}) {
  await scanTo(pg, repo, first, view); const items = await queue(pg, family); check(`${P}/${tag}: at least one ${family} candidate queued`, items.length >= 1, JSON.stringify(items.map((i) => i.item_id)));
  const sup = items.find((i) => i.state === 'supported') || items[0];
  await pg.eval(`window.__diag&&window.__diag.mark(${JSON.stringify('select-' + tag)})`); const tSel = Date.now();
  await selectCandidate(pg, sup.item_id);
  const tl = await timeline(pg, `${P}_${tag}`, obsMs); const last = tl[tl.length - 1];
  const pre = await sample(pg, true, true); evidence[`pre_${P}_${tag}`] = pre;                       // full sample incl. ancestors + renderer keys, BEFORE any screenshot/forceRender
  const d = derive(pre); const rp = rafProgress(tl);
  evidence[`build_${P}_${tag}`] = { items: items.map((i) => ({ id: i.item_id, state: i.state })), selectedMs: Date.now() - tSel, rafFramesDuringObservation: rp, derivedPreScreenshot: d, vs: pre.vs, focus: pre.focus, hostRect: pre.host?.rect, canvases: pre.canvases };
  check(`${P}/${tag}: LAYOUT complete (positions distinct/finite/inside container) before any screenshot or forceRender`, d.layout, JSON.stringify(slim(pre)).slice(0, 400));
  check(`${P}/${tag}: CANVAS PAINT: alpha>0 pixels for every node and most edges before any screenshot or forceRender`, d.canvasInk === true, `ink=${pre.inkPixels} nodes=${pre.nodes} edgesWithInk=${pre.edgesWithInk}/${pre.edges} rafFrames=${rp}`);
  return { items, sup, tl, pre, d };
}

async function battery(pg, ctx, P, items) {                          // selection / reselection / resize / Fit, each with layout vs paint vs compositor kept apart
  const sup = items.find((i) => i.state === 'supported') || items[0]; const unv = items.find((i) => i !== sup);
  let s = await sample(pg, true); const reg0 = await region(pg, `${P}_battery_pre`); const d0 = derive(await sample(pg, true), reg0);
  evidence[`${P}_battery_pre`] = { derived: d0, region: reg0 };
  check(`${P}: COMPOSITOR output of the graph region shows content (screenshot analysis)`, d0.compositor === true, JSON.stringify(reg0));
  const target = (s.positions || []).length ? (await pg.eval(`(()=>{const h=document.querySelector('[data-bom-cy=inline]'); const sel=h._cy.$(':selected').map(n=>n.id()); const n=h._cy.nodes().filter(x=>!sel.includes(x.id()))[0]; return n?n.id():null})()`)) : null;
  if (target) {
    await realClick(pg, target); await sleep(500); const after = await sample(pg, true); const rec2 = (await state(pg)).bom8.selectedRecord;
    const cySel = await pg.eval(`document.querySelector('[data-bom-cy=inline]')._cy.$(':selected').map(n=>n.id())`);
    evidence[`${P}_click`] = { target, selectedRecord: rec2, cySelected: cySel, derived: derive(after), rafN: after.raf?.n };
    check(`${P}: a real mouse click on a node selects that record`, rec2 === target && cySel.includes(target), JSON.stringify(evidence[`${P}_click`]));
    await region(pg, `${P}_node_selected`);
  } else check(`${P}: a node to click exists`, false, 'no nodes');
  for (const [lab, it] of [['other', unv], ['back', sup]].filter(([, it]) => it)) {
    await selectCandidate(pg, it.item_id); const tl = await timeline(pg, `${P}_reselect_${lab}`, 1500, 500); const reg = await region(pg, `${P}_reselect_${lab}`); const d = derive(await sample(pg, true), reg);
    evidence[`${P}_reselect_${lab}`] = { derived: d, region: reg, rafFrames: rafProgress(tl) };
    check(`${P}: reselect (${lab}): LAYOUT ok, CANVAS PAINT ok, COMPOSITOR ok`, d.layout && d.canvasInk === true && d.compositor === true, JSON.stringify(evidence[`${P}_reselect_${lab}`]));
  }
  for (const [w, h] of [[1100, 800], [1600, 900], [1366, 900]]) {
    await setSize(pg, ctx, w, h); const tl = await timeline(pg, `${P}_resize_${w}`, 1500, 500); const reg = await region(pg, `${P}_resize_${w}`); const sm = await sample(pg, true); const d = derive(sm, reg);
    evidence[`${P}_resize_${w}`] = { derived: d, region: reg, inner: sm.inner, hostRect: sm.host?.rect, canvases: sm.canvases, rafFrames: rafProgress(tl) };
    check(`${P}: resize toward ${w}x${h}: LAYOUT ok, CANVAS PAINT ok, COMPOSITOR ok without user action (inner ${sm.inner})`, d.layout && d.canvasInk === true && d.compositor === true, JSON.stringify(evidence[`${P}_resize_${w}`]).slice(0, 500));
    if (!(d.canvasInk === true && d.compositor === true)) {
      await pg.click('[data-action=bom-fit]'); await sleep(100); const f0 = await sample(pg, true); await sleep(700); const f1 = await sample(pg, true); const regF = await region(pg, `${P}_resize_${w}_after_fit`);
      evidence[`${P}_resize_${w}_after_fit`] = { immediate: derive(f0), later: derive(f1, regF), region: regF, zoom: [f0.cyInfo?.zoom, f1.cyInfo?.zoom] };
      check(`${P}: Fit after resize ${w}: graph painted (LAYOUT/CANVAS/COMPOSITOR)`, derive(f1, regF).canvasInk === true && derive(f1, regF).compositor === true, JSON.stringify(evidence[`${P}_resize_${w}_after_fit`]).slice(0, 400));
    }
  }
  await pg.click('[data-action=bom-fit]'); await sleep(100); const g0 = await sample(pg, true); await sleep(600); const g1 = await sample(pg, true); const regG = await region(pg, `${P}_fit_final`);
  evidence[`${P}_fit_final`] = { immediate: derive(g0), later: derive(g1, regG), region: regG, zoom: [g0.cyInfo?.zoom, g1.cyInfo?.zoom] };
  check(`${P}: Fit button leaves the graph fitted and painted (LAYOUT/CANVAS/COMPOSITOR)`, derive(g1, regG).layout && derive(g1, regG).canvasInk === true && derive(g1, regG).compositor === true, JSON.stringify(evidence[`${P}_fit_final`]).slice(0, 400));
}

async function phase(P, ctx, { forceStep }) {
  rec.phases[P] = { start: stamp() }; const { pg } = ctx;
  await pg.send('Page.addScriptToEvaluateOnNewDocument', { source: DIAG });
  await pg.goto(ctx.base); await pg.waitFor(`document.getElementById('ot-url')`, 30000);
  const env = await pg.eval(`({ua:navigator.userAgent,screen:[screen.width,screen.height,screen.availWidth,screen.availHeight],dpr:devicePixelRatio,inner:[innerWidth,innerHeight],outer:[outerWidth,outerHeight],vs:document.visibilityState,focus:document.hasFocus(),reducedMotion:matchMedia('(prefers-reduced-motion: reduce)').matches,hwConcurrency:navigator.hardwareConcurrency})`);
  rec.phases[P].env = env; rec.phases[P].version = await ctx.browser.send('Browser.getVersion').catch(() => null);
  rec.phases[P].cookiesAtStart = (await pg.send('Network.getCookies', { urls: [ctx.base] }).catch(() => ({ cookies: [] }))).cookies.map((c) => c.name);
  if (ctx.headed) { await pg.send('Target.activateTarget', { targetId: pg.targetId }).catch(() => {}); await ctx.browser.send('Target.activateTarget', { targetId: pg.targetId }).catch(() => {}); await pg.send('Page.bringToFront'); }
  // control: frame production of the idle app page (before any graph exists), measured by the independent rAF counter
  const ctl = await timeline(pg, `${P}_control_idle`, 1000, 250, false); rec.phases[P].controlIdleRaf = { framesPer1s: rafProgress(ctl), vs: ctl[0].vs, focus: ctl[0].focus };
  check(`${P}: control: the idle page produces animation frames (independent rAF counter)`, (rafProgress(ctl) || 0) >= 5, JSON.stringify(rec.phases[P].controlIdleRaf));

  // build 1 (modelsupp): un-intervened observation, then (headless phase only) the forceRender step + conditional front/focus step
  const b1 = await observeBuild(pg, P, 'modelsupp', 'ai_model', 'ai', true, 'modelsupp');
  const noFrames = (rafProgress(b1.tl) ?? 0) < 5; evidence[`${P}_noFramesDuringObservation`] = noFrames;
  if (forceStep || !(b1.d.canvasInk === true)) {
    const f = await pg.eval(FORCE); await sleep(0); const seq = [];
    for (const ms of [0, 100, 250, 500, 1000, 2000]) { await sleep(ms === 0 ? 0 : ms - (seq.length ? seq[seq.length - 1].ms : 0)); seq.push({ ms, ...slim(await sample(pg, true)) }); }
    evidence[`${P}_forceRender`] = { reason: forceStep ? 'planned (headless launch)' : 'headed control was blank', ...f, subsequent: seq };
    check(`${P}: forceRender: cy.forceRender exists on the instance`, f.forceRenderType === 'function', JSON.stringify(f).slice(0, 300));
    check(`${P}: forceRender: canvas ink > 0 after forceRender (immediate or within 2 s)`, (f.afterSync?.ink || 0) > 0 || seq.some((x) => (x.ink || 0) > 0), JSON.stringify({ afterSync: f.afterSync, ink: seq.map((x) => x.ink) }));
    if (noFrames) {
      await pg.send('Emulation.setFocusEmulationEnabled', { enabled: true }); await pg.send('Page.bringToFront'); await pg.eval(`window.__diag.mark('bringToFront+focusEmulation')`);
      const tl2 = await timeline(pg, `${P}_after_front_focus`, 2500); evidence[`${P}_front_focus`] = { rafFrames: rafProgress(tl2), last: tl2[tl2.length - 1] };
      check(`${P}: after bringToFront + focus emulation, animation frames are produced`, (rafProgress(tl2) || 0) >= 5, JSON.stringify(evidence[`${P}_front_focus`]).slice(0, 300));
    }
  }
  await battery(pg, ctx, P, b1.items);
  // builds 2 and 3, un-intervened (no forceRender): reproduction rate of the blank canvas with instrumentation
  const b2 = await observeBuild(pg, P, 'modeloutside', 'ai_model', 'ai', false, 'modeloutside'); const r2 = await region(pg, `${P}_modeloutside`);
  evidence[`${P}_modeloutside_region`] = r2; check(`${P}/modeloutside: COMPOSITOR output shows content`, derive(b2.pre, r2).compositor === true, JSON.stringify(r2));
  const b3 = await observeBuild(pg, P, 'cryptosupp', 'cryptography', 'crypto', false, 'cryptosupp'); const r3 = await region(pg, `${P}_cryptosupp`);
  evidence[`${P}_cryptosupp_region`] = r3; check(`${P}/cryptosupp (Stage 2): COMPOSITOR output shows content`, derive(b3.pre, r3).compositor === true, JSON.stringify(r3));
  if (b3.items[0]) { const tg = await pg.eval(`(()=>{const h=document.querySelector('[data-bom-cy=inline]'); return h&&h._cy&&h._cy.nodes()[0]?h._cy.nodes()[0].id():null})()`);
    if (tg) { await realClick(pg, tg); await sleep(500); const sr = (await state(pg)).bom8.selectedRecord; check(`${P}/cryptosupp (Stage 2): a real click on a node selects that record`, sr === tg, JSON.stringify({ sr, tg })); } }
  const dg = await pg.eval(`({events:window.__diag.events,workers:window.__diag.workers,errors:window.__diag.errors,io:window.__diag.io,rafTotal:window.__diag.raf.n})`);
  rec.phases[P].diag = dg; rec.phases[P].pageExceptions = pg.log.exceptions.slice(0, 10); rec.phases[P].consoleErrors = pg.log.console.filter((c) => c.type === 'error').slice(0, 10); rec.phases[P].failedRequests = pg.log.failed.slice(0, 10);
  check(`${P}: no page exceptions, no worker errors, no window errors`, pg.log.exceptions.length === 0 && dg.workers.every((w) => w.errors.length === 0) && dg.errors.length === 0, JSON.stringify({ ex: pg.log.exceptions.slice(0, 3), werr: dg.workers.map((w) => w.errors), errs: dg.errors.slice(0, 3) }));
  rec.phases[P].end = stamp();
}

let svc, chrome, chromeB; let needB = false; const failedBefore = () => H.results.filter((r) => !r.ok).length;
try {
  svc = await service(); rec.counters.chromeLaunches++; rec.chromeAStart = stamp();
  chrome = await launch(); pidAppend(chrome.proc.pid);
  rec.headlessFlags = ['--headless=new', '--disable-gpu', '--no-first-run', '--no-default-browser-check', '--hide-scrollbars', '--user-data-dir=<fresh-profile-dir>', '--remote-debugging-port=0', 'about:blank', '+ CDP Emulation.setDeviceMetricsOverride 1366x900 dpr1 mobile=false (cdp.mjs newPage)'];
  const pgA = await newPage(chrome.browser, { width: 1366, height: 900 });
  try { await phase('A_headless', { pg: pgA, browser: chrome.browser, base: svc.base, headed: false }, { forceStep: true }); }
  catch (e) { H.unfinished.push('launch A stopped: ' + (e.stack || e.message).slice(0, 400)); check('A_headless: run completed', false, e.stack || e.message); if (/timeout/i.test(e.message)) rec.timeoutEvents.push({ phase: 'A_headless', msg: e.message.slice(0, 200), ...stamp() }); }
  try { await endSession(pgA); } catch (e) { rec.sessionEndA = 'not ended: ' + String(e.message).slice(0, 100); }
  H.save(); await chrome.close(); chrome = null; rec.chromeAEnd = stamp();
  needB = failedBefore() > 0;                              // pre-declared rule: launch 2 only if launch 1 left any check unsatisfied
  rec.launch2Decision = { needed: needB, failedChecksInLaunch1: failedBefore(), elapsedS: Math.round((Date.now() - T0) / 1000), deadlineLeftS: DEADLINE ? Math.round((DEADLINE - Date.now()) / 1000) : null };
  if (needB && (!DEADLINE || DEADLINE - Date.now() > 6 * 60 * 1000)) {
    rec.counters.chromeLaunches++; rec.chromeBStart = stamp(); chromeB = await launchHeaded();
    const pgB = await newPage(chromeB.browser, { width: 1366, height: 900 }); await pgB.send('Emulation.clearDeviceMetricsOverride');
    try { await phase('B_headed', { pg: pgB, browser: chromeB.browser, base: svc.base, headed: true }, { forceStep: false }); }
    catch (e) { H.unfinished.push('launch B stopped: ' + (e.stack || e.message).slice(0, 400)); check('B_headed: run completed', false, e.stack || e.message); if (/timeout/i.test(e.message)) rec.timeoutEvents.push({ phase: 'B_headed', msg: e.message.slice(0, 200), ...stamp() }); }
    try { await endSession(pgB); } catch (e) { rec.sessionEndB = 'not ended: ' + String(e.message).slice(0, 100); }
    rec.chromeBEnd = stamp();
  } else if (needB) rec.launch2Decision.skipped = 'insufficient time left for a second launch';
} catch (e) { H.unfinished.push('driver stopped: ' + (e.stack || e.message).slice(0, 400)); check('run completed', false, e.stack || e.message); }
finally { rec.end = stamp(); H.save(); try { svc && svc.stop(); } catch {} if (chrome) await chrome.close(); if (chromeB) await chromeB.close(); }
const failed = H.results.filter((r) => !r.ok).length; console.log(`${H.results.length - failed}/${H.results.length} checks passed; unfinished: ${H.unfinished.length}; launches: service ${rec.counters.serviceLaunches}, chrome ${rec.counters.chromeLaunches}`);
