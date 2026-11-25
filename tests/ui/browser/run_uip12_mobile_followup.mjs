// UIP-12 mobile follow-up (test harness only; no product change). SYNTHETIC fixture (uip12_crypto_service.py --case interact), real active BOM inspector.
// Corrects the earlier T4 gap: the mobile scroll container is .ot-bom8-inspector (fixed, max-height:45vh, overflow:auto), not .ot-bom8-drawer-body.
// Usage: OT_DEADLINE_MS=<epoch ms> OT_PIDS_FILE=<file> node run_uip12_mobile_followup.mjs <outDir>
import { spawn } from 'node:child_process';
import { appendFileSync } from 'node:fs';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { launch, newPage } from './cdp.mjs';
import { harness, sleep, state, frames, viewport, setUrl, endSession } from './uip12_lib.mjs';

const HERE = dirname(fileURLToPath(import.meta.url)); const REPO = resolve(HERE, '../../..');
const H = harness({ out: process.argv[2], label: 'mobile_followup', synthetic: true });
const { check, guard, evidence, OUT } = H;
const TAGS = { routes: ['/api/workbench/v1/bom-candidates', '/api/view/gap'], actions: ['select candidate at 390 px'] };

function service() {
  const proc = spawn(process.env.PYTHON || 'python3', [join(HERE, 'uip12_crypto_service.py'), '--case', 'interact'], { cwd: REPO, env: { ...process.env, PYTHONPATH: `${REPO}:${join(REPO, 'src/core')}` }, stdio: ['ignore', 'pipe', 'pipe'] });
  if (process.env.OT_PIDS_FILE) appendFileSync(process.env.OT_PIDS_FILE, proc.pid + '\n');
  return new Promise((res, rej) => { let b = ''; const t = setTimeout(() => rej(new Error('service did not start: ' + b)), 40000);
    proc.stdout.on('data', (d) => { b += d; const m = b.match(/http:\/\/127\.0\.0\.1:(\d+)\//); if (m) { clearTimeout(t); res({ base: m[0], stop: () => proc.kill('SIGTERM') }); } });
    proc.stderr.on('data', (d) => { b += d; }); });
}

// In-page geometry helpers, installed once. visibleRect(el) = element rect clipped by every ancestor that clips (overflow != visible) and by the viewport.
const INSTALL = `(()=>{
  const clip=(r,c)=>({l:Math.max(r.l,c.l),t:Math.max(r.t,c.t),r:Math.min(r.r,c.r),b:Math.min(r.b,c.b)});
  const R=(e)=>{const b=e.getBoundingClientRect();return {l:b.left,t:b.top,r:b.right,b:b.bottom}};
  const area=(r)=>Math.max(0,r.r-r.l)*Math.max(0,r.b-r.t);
  const visibleRect=(el)=>{let r=R(el); for(let p=el.parentElement;p;p=p.parentElement){const cs=getComputedStyle(p); if(cs.overflowX!=='visible'||cs.overflowY!=='visible'){ r=clip(r,R(p)); }} return clip(r,{l:0,t:0,r:innerWidth,b:innerHeight});};
  const round=(r)=>({l:Math.round(r.l),t:Math.round(r.t),r:Math.round(r.r),b:Math.round(r.b)});
  const scroller=()=>{const ev=document.querySelector('.ot-bom8-evidence'); const chain=[]; let found=null;
    for(let p=ev;p&&p!==document.documentElement;p=p.parentElement){const cs=getComputedStyle(p); const o={sel:p.tagName.toLowerCase()+(p.className&&typeof p.className==='string'?'.'+p.className.trim().split(/\\s+/).join('.'):''),overflowY:cs.overflowY,position:cs.position,scrollTop:Math.round(p.scrollTop),clientHeight:p.clientHeight,scrollHeight:p.scrollHeight,scrollable:(cs.overflowY==='auto'||cs.overflowY==='scroll')&&p.scrollHeight>p.clientHeight+1};chain.push(o); if(!found&&o.scrollable) found=p;}
    return {el:found,chain};};
  // Readability of one element: visible fraction after clipping, and topmost-element occlusion at a 5x3 sample grid inside the visible part.
  const read=(el)=>{const full=R(el); const v=visibleRect(el); const fa=area(full), va=area(v); let hits=0,total=0,blockers={};
    if(va>0){for(let i=0;i<5;i++)for(let j=0;j<3;j++){const x=v.l+(v.r-v.l)*(i+.5)/5, y=v.t+(v.b-v.t)*(j+.5)/3; total++; const h=document.elementFromPoint(x,y); if(h&&(el.contains(h)||h.contains(el)&&h===el)) hits++; else {const k=h?(h.id||h.className||h.tagName):'none'; blockers[String(k).slice(0,60)]=(blockers[String(k).slice(0,60)]||0)+1;}}}
    return {rect:round(full),visible:round(v),visibleFraction:fa?+(va/fa).toFixed(3):0,unoccludedSamples:hits+'/'+total,blockers};};
  const overlapWith=(el,over)=>{const v=visibleRect(el); const o=clip(v,over); return {w:Math.round(Math.max(0,o.r-o.l)),h:Math.round(Math.max(0,o.b-o.t)),area:Math.round(area(o))};};
  window.__u12={clip,R,area,visibleRect,round,scroller,read,overlapWith};
  return true;})()`;

const probe = (pg, js) => pg.eval(`(()=>{const U=window.__u12; ${js}})()`);
const setScroll = async (pg, top) => { await probe(pg, `const s=U.scroller().el; if(s) s.scrollTop=${JSON.stringify(top)};`); await frames(pg); await sleep(60); };
// Bring a target element into the scroller's client region (top-aligned with 6 px margin) by scrolling the REAL container.
const bringIntoView = async (pg, sel, which) => { await probe(pg, `const s=U.scroller().el; const el=${which === 'last' ? `[...document.querySelectorAll('.ot-bom8-evidence > *')].pop()` : `document.querySelector(${JSON.stringify(sel)})`}; if(s&&el){const sr=s.getBoundingClientRect(), er=el.getBoundingClientRect(); s.scrollTop += (er.top - sr.top) - 6;}`); await frames(pg); await sleep(60); };
const launcherVsInspector = (pg) => probe(pg, `const L=document.getElementById('ot-assistant-launch'); const I=document.querySelector('.ot-bom8-inspector'); const lr=U.round(U.R(L)); const ir=U.round(U.visibleRect(I)); const ov=U.overlapWith(L, U.R(I)); return {launcher:lr, inspectorVisible:ir, launcherOverlapsInspector:ov.area>0, overlap:ov, launcherHitAtItsCenter:(document.elementFromPoint((lr.l+lr.r)/2,(lr.t+lr.b)/2)||{}).id||null};`);
const evidenceParts = (pg) => probe(pg, `const ev=document.querySelector('.ot-bom8-evidence'); const parts=[]; const raw=ev.querySelector('.ot-raw'); if(raw) parts.push(['excerpt', raw]); const last=[...ev.children].pop(); parts.push(['final', last]);
  return parts.map(([name,el])=>({name, tag:el.tagName.toLowerCase()+'.'+(el.className||''), text:(el.innerText||'').replace(/\\s+/g,' ').slice(0,140), ...U.read(el), launcher:(()=>{const L=document.getElementById('ot-assistant-launch'); return U.overlapWith(el, U.R(L)); })()}));`);

async function scanMulti(pg) {
  await pg.waitFor(`document.getElementById('ot-scan') && !document.getElementById('ot-scan').disabled`, 20000);
  await setUrl(pg, 'https://github.com/acme/multi'); await pg.click('#ot-scan');
  await pg.waitFor(`window.__otStore.get().destination === 'workbench'`, 90000);
  await pg.click('#ot-tab-bom'); await pg.waitFor(`window.__otStore.get().bom8.queue`, 30000);
  await pg.waitFor(`(()=>{const b=window.__otStore.get().bom8; return b.queue && !b.req.queue && !b.req.graph && !b.req.detail})()`, 30000);
  await pg.click('[data-action=bom-view][data-view=crypto]');
  await pg.waitFor(`(()=>{const b=window.__otStore.get().bom8; return b.view==='crypto' && b.queue && !b.req.queue && !b.req.graph && !b.req.detail})()`, 30000);
}

async function runViewport(pg, w, h, primary) {
  const tag = `${w}x${h}`;
  await pg.send('Emulation.setDeviceMetricsOverride', { width: w, height: h, deviceScaleFactor: 1, mobile: true });
  await pg.waitFor(`innerWidth===${w} && window.__otStore.get().narrow===true`, 8000); await frames(pg);
  const ids = await pg.eval(`[...document.querySelectorAll('[data-action=bom-select]')].map((e)=>e.dataset.id)`);
  evidence[`${tag}_candidates`] = ids.length; let best = null;
  for (const id of ids) {
    guard(); await pg.click(`[data-action=bom-select][data-id=${JSON.stringify(id)}]`);
    await pg.waitFor(`document.querySelector('[data-evidence-for=${JSON.stringify(id)}] .ot-gap-inspector')`, 20000); await frames(pg); await pg.eval(INSTALL);
    const sc = await probe(pg, `const s=U.scroller(); return {chain:s.chain.slice(0,6), found:s.el?s.el.tagName.toLowerCase()+'.'+s.el.className:null, st:s.el?s.el.scrollTop:null, ch:s.el?s.el.clientHeight:null, sh:s.el?s.el.scrollHeight:null}`);
    evidence[`${tag}_${id}_scroller`] = sc;
    if (!best || (sc.sh || 0) > (best.sc.sh || 0)) best = { id, sc };
  }
  // Use the candidate whose evidence is longest (most demanding); record all.
  const id = best.id; await pg.click(`[data-action=bom-select][data-id=${JSON.stringify(id)}]`);
  await pg.waitFor(`document.querySelector('[data-evidence-for=${JSON.stringify(id)}] .ot-gap-inspector')`, 20000); await frames(pg); await pg.eval(INSTALL);
  const drawer = await probe(pg, `const I=document.querySelector('.ot-bom8-inspector'); return {open:I.classList.contains('open'), pos:getComputedStyle(I).position, maxH:getComputedStyle(I).maxHeight, overflowY:getComputedStyle(I).overflowY, rect:U.round(U.R(I)), bodyOverflowY:getComputedStyle(document.querySelector('.ot-bom8-drawer-body')).overflowY, bodyScrollableByItself: document.querySelector('.ot-bom8-drawer-body').scrollHeight>document.querySelector('.ot-bom8-drawer-body').clientHeight+1}`);
  evidence[`${tag}_drawer`] = drawer;
  const sc = best.sc; const tc = `${tag} ${id.slice(0, 12)}`;
  check(`${tag}: the actual scroll container is .ot-bom8-inspector (fixed, overflow:auto) and the nested .ot-bom8-drawer-body is not the scroller`, drawer.open && drawer.pos === 'fixed' && /ot-bom8-inspector/.test(sc.found || '') && drawer.bodyOverflowY === 'visible' && drawer.bodyScrollableByItself === false, JSON.stringify({ found: sc.found, drawer }), TAGS);
  const scrollable = sc.sh > sc.ch + 1;
  check(`${tag}: the container's evidence overflows (scrollHeight > clientHeight), so scrolling is required and measurable`, scrollable, `scrollTop=${sc.st} clientHeight=${sc.ch} scrollHeight=${sc.sh}`, TAGS);
  // Representative scroll positions (real container): top, 25/50/75%, bottom. Record before/after and visibility of excerpt + final part, launcher vs inspector.
  const maxTop = sc.sh - sc.ch; const positions = [0, 0.25, 0.5, 0.75, 1].map((f) => Math.round(maxTop * f));
  const rows = [];
  for (const p of positions) {
    guard(); const before = await probe(pg, `const s=U.scroller().el; return {scrollTop:Math.round(s.scrollTop), clientHeight:s.clientHeight, scrollHeight:s.scrollHeight}`);
    await setScroll(pg, p); const after = await probe(pg, `const s=U.scroller().el; return {scrollTop:Math.round(s.scrollTop), clientHeight:s.clientHeight, scrollHeight:s.scrollHeight}`);
    rows.push({ target: p, before, after, parts: await evidenceParts(pg), launcher: await launcherVsInspector(pg) });
  }
  evidence[`${tag}_positions`] = rows;
  check(`${tag}: scrolling the real container changes scrollTop (before/after recorded) and reaches the maximum`, scrollable && rows[0].after.scrollTop === 0 && rows[4].after.scrollTop >= maxTop - 2 && rows[4].after.scrollTop > rows[0].after.scrollTop && rows.every((r, i) => i === 0 || r.after.scrollTop >= rows[i - 1].after.scrollTop), JSON.stringify(rows.map((r) => [r.before.scrollTop, r.after.scrollTop])), TAGS);
  check(`${tag}: at every sampled position the launcher does not intersect the inspector's visible region (so it cannot cover visible evidence)`, rows.every((r) => !r.launcher.launcherOverlapsInspector), JSON.stringify(rows.map((r) => r.launcher.overlap.area)), TAGS);
  check(`${tag}: at every sampled position no visible evidence part is overlapped by the launcher`, rows.every((r) => r.parts.every((q) => q.launcher.area === 0)), JSON.stringify(rows.map((r) => r.parts.map((q) => q.launcher.area))), TAGS);
  // Excerpt: scroll so it is inside the visible inspector region, unclipped, not occluded.
  await setScroll(pg, 0); await bringIntoView(pg, '.ot-bom8-evidence .ot-raw');
  const exPart = (await evidenceParts(pg)).find((q) => q.name === 'excerpt'); const exL = await launcherVsInspector(pg);
  evidence[`${tag}_excerpt_visible`] = { exPart, exL, scroll: await probe(pg, `const s=U.scroller().el; return s.scrollTop`) };
  check(`${tag}: the source excerpt can be brought fully into the visible, unclipped inspector region and is readable (not occluded)`, !!exPart && exPart.visibleFraction >= 0.99 && /^(\d+)\/(\d+)$/.test(exPart.unoccludedSamples) && exPart.unoccludedSamples.split('/')[0] === exPart.unoccludedSamples.split('/')[1] && exPart.text.length > 5, JSON.stringify(exPart), TAGS);
  check(`${tag}: launcher check while the excerpt is visible: no overlap with the excerpt or the inspector`, exPart && exPart.launcher.area === 0 && !exL.launcherOverlapsInspector, JSON.stringify({ excerptLauncher: exPart?.launcher, exL }), TAGS);
  if (primary) await pg.screenshot(join(OUT, `excerpt_readable_${tag}.png`));
  // Final evidence section.
  await bringIntoView(pg, null, 'last'); await sleep(30);
  let fin = (await evidenceParts(pg)).find((q) => q.name === 'final'); const atMax = await probe(pg, `const s=U.scroller().el; return {top:Math.round(s.scrollTop), max:s.scrollHeight-s.clientHeight}`);
  evidence[`${tag}_final_visible`] = { fin, atMax };
  const finFull = fin && fin.visibleFraction >= 0.99;
  const finRow = rows[4].parts.find((q) => q.name === 'final');
  check(`${tag}: the final evidence section can be reached (scrolled to maximum) and is visible, unclipped and not occluded`, !!finRow && finRow.visibleFraction >= 0.99 && finRow.unoccludedSamples.split('/')[0] === finRow.unoccludedSamples.split('/')[1], JSON.stringify(finRow), TAGS);
  evidence[`${tag}_final_aligned_note`] = { finFull, fin };
  await setScroll(pg, 1e6); if (primary) await pg.screenshot(join(OUT, `final_section_reachable_${tag}.png`));
  // Drawer controls: reachable by scroll and by keyboard; focus behaves.
  await setScroll(pg, 0);
  const ctl = await probe(pg, `const b=document.querySelector('[data-action=bom-drawer]'); const r=U.read(b); return {btn:r, label:(b.innerText||'').trim().slice(0,30), expanded:b.getAttribute('aria-expanded'), hitIsButton:(document.elementFromPoint((r.visible.l+r.visible.r)/2,(r.visible.t+r.visible.b)/2)||{}).closest?.('[data-action=bom-drawer]')===b, w:Math.round(b.getBoundingClientRect().width), h:Math.round(b.getBoundingClientRect().height)}`);
  evidence[`${tag}_drawer_button_top`] = ctl;
  check(`${tag}: drawer toggle is visible, unoccluded and hit-testable at the top of the inspector`, ctl.btn.visibleFraction >= 0.99 && ctl.hitIsButton, JSON.stringify(ctl), TAGS);
  await setScroll(pg, 1e6); const ctlMax = await probe(pg, `const b=document.querySelector('[data-action=bom-drawer]'); return U.read(b)`);
  evidence[`${tag}_drawer_button_at_max_scroll`] = ctlMax; // observation (not asserted): the header scrolls with the content
  await pg.eval(`document.querySelector('[data-action=bom-drawer]').focus()`); await frames(pg);
  const afterFocus = await probe(pg, `const b=document.querySelector('[data-action=bom-drawer]'); const s=U.scroller().el; return {scrollTop:Math.round(s.scrollTop), vis:U.read(b).visibleFraction, active:document.activeElement===b}`);
  evidence[`${tag}_focus_from_bottom`] = afterFocus;
  check(`${tag}: from the bottom of the evidence, keyboard focus on the drawer toggle brings it back into view`, afterFocus.active && afterFocus.vis >= 0.99, JSON.stringify({ ctlMaxVisible: ctlMax.visibleFraction, afterFocus }), TAGS);
  const keyState = async () => probe(pg, `const I=document.querySelector('.ot-bom8-inspector'); const a=document.activeElement; return {open:I.classList.contains('open'), active:a&&(a.dataset&&a.dataset.action||a.id||a.tagName), isToggle:!!(a&&a.matches&&a.matches('[data-action=bom-drawer]')), expanded:document.querySelector('[data-action=bom-drawer]')?.getAttribute('aria-expanded')}`);
  const s0 = await keyState(); await pg.key('Enter'); await frames(pg); const s1 = await keyState();
  await pg.eval(`document.querySelector('[data-action=bom-drawer]').focus()`); await pg.key('Enter'); await frames(pg); const s2 = await keyState();
  evidence[`${tag}_keyboard`] = { s0, s1, s2 };
  check(`${tag}: Enter on the drawer toggle closes then reopens the drawer`, s0.open && !s1.open && s2.open, JSON.stringify({ s0, s1, s2 }), { routes: [], actions: ['focus toggle', 'Enter', 'Enter'] });
  check(`${tag}: focus stays on the drawer toggle after a keyboard toggle (or is explicitly re-placed on it)`, s1.isToggle && s2.isToggle, JSON.stringify({ s1: s1.active, s2: s2.active }), { routes: [], actions: ['Enter'] });
  const sp = await (async () => { await pg.eval(`document.querySelector('[data-action=bom-drawer]').focus()`); await pg.key(' ', 'Space'); await frames(pg); const a = await keyState(); await pg.eval(`document.querySelector('[data-action=bom-drawer]').focus()`); await pg.key(' ', 'Space'); await frames(pg); return [a, await keyState()]; })();
  evidence[`${tag}_keyboard_space`] = sp;
  check(`${tag}: Space on the drawer toggle also closes then reopens (native button behaviour)`, !sp[0].open && sp[1].open, JSON.stringify(sp), { routes: [], actions: ['Space', 'Space'] });
  // Sensitivity control: deliberate visible overlap of the launcher on the visible excerpt; detect; restore exactly.
  await setScroll(pg, 0); await bringIntoView(pg, '.ot-bom8-evidence .ot-raw');
  const orig = await probe(pg, `const L=document.getElementById('ot-assistant-launch'); const cs=getComputedStyle(L); return {styleAttr:L.getAttribute('style'), rect:U.round(U.R(L)), computed:{left:cs.left,right:cs.right,top:cs.top,bottom:cs.bottom,transform:cs.transform,position:cs.position,zIndex:cs.zIndex}}`);
  const injected = await probe(pg, `const L=document.getElementById('ot-assistant-launch'); const ex=document.querySelector('.ot-bom8-evidence .ot-raw'); const v=U.visibleRect(ex); const lw=L.getBoundingClientRect().width, lh=L.getBoundingClientRect().height;
    L.style.setProperty('position','fixed','important'); L.style.setProperty('right','auto','important'); L.style.setProperty('bottom','auto','important'); L.style.setProperty('transform','none','important'); L.style.setProperty('left',Math.round(v.l+4)+'px','important'); L.style.setProperty('top',Math.round(v.t+2)+'px','important');
    const exPartNow=U.read(ex); const ov=U.overlapWith(ex,U.R(L)); const hit=document.elementFromPoint(v.l+8, v.t+6); return {styleAttr:L.getAttribute('style'), rect:U.round(U.R(L)), overlap:ov, hitId:hit&&(hit.id||hit.className||hit.tagName), exUnoccluded:exPartNow.unoccludedSamples, launcherSize:[lw,lh]};`);
  await frames(pg); if (primary) await pg.screenshot(join(OUT, `overlap_sensitivity_control_${tag}.png`));
  const detected = await probe(pg, `const L=document.getElementById('ot-assistant-launch'); const ex=document.querySelector('.ot-bom8-evidence .ot-raw'); const ov=U.overlapWith(ex,U.R(L)); const r=U.read(ex); const lv=U.overlapWith(document.querySelector('.ot-bom8-inspector'),U.R(L)); return {excerptOverlapArea:ov.area, unoccluded:r.unoccludedSamples, blockers:r.blockers, inspectorOverlapArea:lv.area}`);
  evidence[`${tag}_sensitivity`] = { orig, injected, detected };
  check(`${tag}: SENSITIVITY CONTROL: a deliberate visible overlap IS detected (excerpt overlap area > 0, occlusion samples reduced)`, detected.excerptOverlapArea > 0 && detected.inspectorOverlapArea > 0 && detected.unoccluded.split('/')[0] !== detected.unoccluded.split('/')[1], JSON.stringify(detected), { routes: [], actions: ['inject launcher style over the visible excerpt'] });
  await probe(pg, `const L=document.getElementById('ot-assistant-launch'); const o=${JSON.stringify(orig.styleAttr)}; if(o===null) L.removeAttribute('style'); else L.setAttribute('style', o);`); await frames(pg);
  const restored = await probe(pg, `const L=document.getElementById('ot-assistant-launch'); const cs=getComputedStyle(L); const ex=document.querySelector('.ot-bom8-evidence .ot-raw'); return {styleAttr:L.getAttribute('style'), rect:U.round(U.R(L)), computed:{left:cs.left,right:cs.right,top:cs.top,bottom:cs.bottom,transform:cs.transform,position:cs.position,zIndex:cs.zIndex}, excerptOverlapArea:U.overlapWith(ex,U.R(L)).area, exRead:U.read(ex)}`);
  evidence[`${tag}_restored`] = restored;
  check(`${tag}: SENSITIVITY CONTROL: the exact original inline style, rect and computed placement are restored; no overlap remains`, restored.styleAttr === orig.styleAttr && JSON.stringify(restored.rect) === JSON.stringify(orig.rect) && JSON.stringify(restored.computed) === JSON.stringify(orig.computed) && restored.excerptOverlapArea === 0, JSON.stringify({ orig: orig.rect, restored: restored.rect, styleOrig: orig.styleAttr, styleRestored: restored.styleAttr }), { routes: [], actions: ['restore launcher style'] });
  if (primary) await pg.screenshot(join(OUT, `overlap_restored_${tag}.png`));
}

let svc, chrome;
try {
  svc = await service(); chrome = await launch(); if (process.env.OT_PIDS_FILE) appendFileSync(process.env.OT_PIDS_FILE, chrome.proc.pid + '\n');
  const pg = await newPage(chrome.browser, { width: 1366, height: 900 }); await pg.goto(svc.base);
  await pg.waitFor(`document.getElementById('ot-url')`, 30000);
  await scanMulti(pg);
  await viewport(pg, true);
  await runViewport(pg, 390, 844, true);
  guard(); await runViewport(pg, 390, 568, false); // supplementary short phone viewport (same session)
  check('followup: no page exceptions', pg.log.exceptions.length === 0, pg.log.exceptions.join(' | ').slice(0, 300));
} catch (e) { if (e.message === 'DEADLINE') H.unfinished.push('deadline reached'); check('followup: run completed', false, e.stack || e.message); }
finally { H.save(); try { svc && svc.stop(); } catch {} if (chrome) await chrome.close(); }
const failed = H.results.filter((r) => !r.ok).length; console.log(`${H.results.length - failed}/${H.results.length} checks passed; unfinished: ${H.unfinished.length}`);
