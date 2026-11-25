// UIP-13 graph correction: LIBRARY-LEVEL smoke (test harness only). No fixture service, no product code, no network: a static page loads the vendored Cytoscape and
// reproduces a paint()-style keeper re-parent (ph.replaceWith(host)) so that (1) the passive hooks are validated, (2) the library behaviour is measured without any OpenTrace code,
// and (3) the proposed re-attach (cy.mount on the same instance) is measured for paint, camera, selection, handler and observer effects. It is NOT product evidence.
// Usage: OT_DEADLINE_MS=<epoch ms> OT_PIDS_FILE=<file> node run_uip13_graph_smoke.mjs <outDir> | --selftest
import { appendFileSync, writeFileSync } from 'node:fs';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { newPage } from './cdp.mjs';
import { HOOK, SUMMARY, selftest, launchHeaded } from './uip13_graph_probe.mjs';

const HERE = dirname(fileURLToPath(import.meta.url)); const REPO = resolve(HERE, '../../..'); const OUT = resolve(process.argv[2] === '--selftest' ? '.' : process.argv[2]);
const results = []; const check = (id, ok, detail = '') => { results.push({ id, ok: !!ok, detail: String(detail).slice(0, 400) }); console.log(`${ok ? 'PASS' : 'FAIL'} ${id}${ok ? '' : ' — ' + String(detail).slice(0, 240)}`); };
const pid = (p) => { if (process.env.OT_PIDS_FILE && p) appendFileSync(process.env.OT_PIDS_FILE, p + '\n'); };
const DEADLINE = Number(process.env.OT_DEADLINE_MS || 0);

const PAGE = `<!doctype html><meta charset=utf-8><title>uip13 smoke</title><body style="margin:0"><div id="root"></div><script src="${pathToFileURL(join(REPO, 'src/ui/vendor/cytoscape.min.js')).href}"></script>`;
const RUN = `(async()=>{ const G=window.__gl; const root=document.getElementById('root'); const out={};
 const frames=(n)=>new Promise((r)=>{ let i=0; const f=()=>(++i>=n?r():requestAnimationFrame(f)); requestAnimationFrame(f); });
 const mkPh=()=>{ root.innerHTML='<div class="wrap"><div data-ph></div></div>'; return root.querySelector('[data-ph]'); };
 const mkHost=(k)=>{ const h=document.createElement('div'); h.setAttribute('data-keep',k); h.style.cssText='width:600px;height:400px;position:relative'; return h; };
 const els=()=>[{data:{id:'a'},position:{x:100,y:100}},{data:{id:'b'},position:{x:300,y:100}},{data:{id:'c'},position:{x:200,y:250}},{data:{id:'e1',source:'a',target:'b'}},{data:{id:'e2',source:'b',target:'c'}}];
 const style=[{selector:'node',style:{width:80,height:40,shape:'round-rectangle','background-color':'#334','border-width':2,'border-color':'#99a',label:'data(id)'}},{selector:'edge',style:{width:3,'line-color':'#c33','target-arrow-color':'#c33','target-arrow-shape':'triangle','curve-style':'bezier'}},{selector:'node:selected',style:{'border-color':'#0a0','border-width':4}}];
 const ink=(h)=>{ let k=0; for(const c of h.querySelectorAll('canvas')){ const d=c.getContext('2d').getImageData(0,0,c.width,c.height).data; for(let i=3;i<d.length;i+=4) if(d[i]>0) k++; } return k; };
 const mk=(key)=>{ const h=mkHost(key); const ph=mkPh(); ph.replaceWith(h); const cy=window.cytoscape({container:h,elements:els(),style,layout:{name:'preset'}}); cy.fit(undefined,20); return {h,cy}; };
 const repaint=(h,mount)=>{ const ph=mkPh(); ph.replaceWith(h); if(mount) { const st=h._cy.style().json(); h._cy.mount(h); h._cy.style(st); h._cy.resize(); } };
 // 1. control: undisturbed
 { const {h,cy}=mk('ctl'); h._cy=cy; await frames(6); out.control={ink:ink(h),rendererDestroyed:!!cy.renderer().destroyed}; }
 // 2. paint-style re-parent, NO re-attach (what the product does on the starting source)
 { const {h,cy}=mk('noremount'); h._cy=cy; await frames(4); const ink0=ink(h); repaint(h,false); const sync=!!cy.renderer().destroyed; await Promise.resolve(); const micro=!!cy.renderer().destroyed; await frames(6);
   out.reparent={ink0,destroyedSync:sync,destroyedAfterMicrotask:micro,destroyedAfterFrames:!!cy.renderer().destroyed,coreDestroyed:cy.destroyed(),inkAfter:ink(h)};
   cy.zoom(1.2); out.reparent.forceRenderInk=(()=>{ cy.forceRender(); return ink(h); })();
   // recovery by the same-instance re-attach, camera/selection kept
   cy.$('#a').select(); const cam={z:cy.zoom(),p:cy.pan()}; const st=cy.style().json(); cy.mount(h); cy.style(st); cy.resize(); await frames(6);
   out.recoverByMount={destroyed:!!cy.renderer().destroyed,ink:ink(h),zoomKept:Math.abs(cy.zoom()-cam.z)<1e-9,panKept:Math.abs(cy.pan().x-cam.p.x)<1e-9&&Math.abs(cy.pan().y-cam.p.y)<1e-9,selected:cy.$(':selected').map((n)=>n.id())}; }
 // 3. paint-style re-parent WITH immediate same-instance re-attach, repeated
 { const {h,cy}=mk('remount'); h._cy=cy; let taps=0,bg=0; cy.on('tap','node',()=>taps++); cy.on('tap',(e)=>{ if(e.target===cy) bg++; }); await frames(4); cy.zoom(0.9); cy.pan({x:30,y:20}); cy.$('#b').select(); const cam={z:cy.zoom(),p:{...cy.pan()}};
   const s0=window.eval(${JSON.stringify(SUMMARY)}); const reps=[];
   for(let i=0;i<4;i++){ repaint(h,true); await Promise.resolve(); const m1=!!cy.renderer().destroyed; await frames(5); reps.push({i,destroyedAfterMicrotask:m1,destroyedAfterFrames:!!cy.renderer().destroyed,ink:ink(h)}); }
   cy.$('#c').emit('tap'); const s1=window.eval(${JSON.stringify(SUMMARY)}); const inst=s1.insts.find((x)=>x.id===cy.__gid);
   out.remount={reps,zoomKept:Math.abs(cy.zoom()-cam.z)<1e-9,panKept:Math.abs(cy.pan().x-cam.p.x)<1e-9&&Math.abs(cy.pan().y-cam.p.y)<1e-9,selected:cy.$(':selected').map((n)=>n.id()),tapsAfterOneEmit:taps,onCalls:inst.on,mounts:inst.mounts,
     unintentionalDestroys:inst.destroys.filter((d)=>!d.viaCyCall).length,observersBefore:s0.obs,observersAfter:s1.obs,hostParentObsDelta:s1.obs.parentObs-s0.obs.parentObs,hostObsDelta:s1.obs.hostObs-s0.obs.hostObs}; }
 out.summary=window.eval(${JSON.stringify(SUMMARY)}); out.events=window.__gl.ev.slice(-60).map((e)=>({seq:e.seq,k:e.k,inst:e.inst,host:e.host,viaCyCall:e.viaCyCall,hostConnected:e.hostConnected,stack:e.stack?String(e.stack).slice(0,260):undefined}));
 return out; })()`;

if (process.argv[2] === '--selftest') { let e = selftest(); try { new Function('return ' + RUN); new Function('return ' + PAGE.length); } catch (x) { e = e || 'RUN: ' + x.message; } console.log(e ? 'SELFTEST FAIL ' + e : 'SELFTEST OK (in-page scripts parse)'); process.exit(e ? 1 : 0); }
const chrome = await launchHeaded({ onPid: pid });
let out = null;
try {
  const pg = await newPage(chrome.browser, { width: 1366, height: 900 }); await pg.send('Emulation.clearDeviceMetricsOverride'); await pg.send('Page.bringToFront');
  await pg.send('Page.addScriptToEvaluateOnNewDocument', { source: HOOK });
  const tmp = join(OUT, 'smoke_page.html'); const { mkdirSync } = await import('node:fs'); mkdirSync(OUT, { recursive: true }); writeFileSync(tmp, PAGE);
  await pg.goto(pathToFileURL(tmp).href); await pg.waitFor(`typeof window.cytoscape==='function' && window.__gl`, 15000);
  const env = await pg.eval(`({vs:document.visibilityState,focus:document.hasFocus(),inner:[innerWidth,innerHeight],dpr:devicePixelRatio,ua:navigator.userAgent})`);
  out = await pg.eval(RUN); out.env = env; out.chromeFlags = chrome.flags;
  check('hooks installed before cytoscape (window.cytoscape wrapped, instances recorded)', out.summary.insts.length >= 3 && out.summary.hookErrors.length === 0, JSON.stringify(out.summary.hookErrors));
  check('control: undisturbed instance paints (ink>0) with a live renderer', out.control.ink > 0 && out.control.rendererDestroyed === false, JSON.stringify(out.control));
  check('MEASURED: paint-style re-parent destroys the renderer while the Core stays alive', out.reparent.destroyedAfterMicrotask === true && out.reparent.coreDestroyed === false, JSON.stringify(out.reparent));
  check('MEASURED: the destroy is delivered after the synchronous re-parent (observer microtask), not during it', out.reparent.destroyedSync === false && out.reparent.destroyedAfterMicrotask === true, JSON.stringify({ sync: out.reparent.destroyedSync, micro: out.reparent.destroyedAfterMicrotask }));
  check('MEASURED: forceRender does not recover a destroyed renderer', out.reparent.forceRenderInk === 0 || out.reparent.forceRenderInk === out.reparent.inkAfter, JSON.stringify({ forceRenderInk: out.reparent.forceRenderInk, inkAfter: out.reparent.inkAfter }));
  check('same-instance cy.mount recovers paint with camera and selection kept', out.recoverByMount.destroyed === false && out.recoverByMount.ink > 0 && out.recoverByMount.zoomKept && out.recoverByMount.panKept && out.recoverByMount.selected.join() === 'a', JSON.stringify(out.recoverByMount));
  const rm = out.remount;
  check('immediate re-attach on every re-parent keeps the renderer alive (4 repaints) and painted', rm.reps.every((r) => r.destroyedAfterMicrotask === false && r.destroyedAfterFrames === false && r.ink > 0), JSON.stringify(rm.reps));
  check('re-attach keeps camera and selection; handlers not duplicated (one tap => one callback); no unintentional destroys', rm.zoomKept && rm.panKept && rm.selected.join() === 'c' && rm.tapsAfterOneEmit === 1 && rm.unintentionalDestroys === 0, JSON.stringify({ z: rm.zoomKept, p: rm.panKept, sel: rm.selected, taps: rm.tapsAfterOneEmit, unint: rm.unintentionalDestroys }));
  check('re-attach does not accumulate observers (live parent/host observer counts unchanged over 4 repaints)', rm.hostParentObsDelta === 0 && rm.hostObsDelta === 0, JSON.stringify({ before: rm.observersBefore, after: rm.observersAfter }));
} catch (e) { check('smoke completed', false, e.stack || e.message); }
finally { writeFileSync(join(OUT, 'uip13_graph_smoke_results.json'), JSON.stringify({ label: 'uip13_graph_smoke', libraryLevelOnly: true, results, out }, null, 1)); await chrome.close(); }
const failed = results.filter((r) => !r.ok).length; console.log(`${results.length - failed}/${results.length} checks passed`);
