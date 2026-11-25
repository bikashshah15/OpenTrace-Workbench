// UIP-12 validation helpers (test harness only; no product behaviour). Shared by run_uip12_v3.mjs and run_uip12_inspector.mjs.
// Every check records which routes and UI actions it exercised. Records are labelled SYNTHETIC when the data came from a local fixture.
import { appendFileSync, mkdirSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

export function harness({ out, label, synthetic }) {
  const OUT = resolve(out); mkdirSync(OUT, { recursive: true });
  const DEADLINE = Number(process.env.OT_DEADLINE_MS || 0);
  const results = [], evidence = {}, unfinished = [];
  const guard = () => { if (DEADLINE && Date.now() > DEADLINE) throw new Error('DEADLINE'); };
  const check = (id, ok, detail = '', tags = {}) => {
    results.push({ id, ok: !!ok, detail: String(detail).slice(0, 500), synthetic: !!synthetic, routes: tags.routes || [], actions: tags.actions || [] });
    console.log(`${ok ? 'PASS' : 'FAIL'} ${id}${ok ? '' : ' — ' + String(detail).slice(0, 240)}`);
  };
  const save = () => writeFileSync(join(OUT, `${label}_results.json`), JSON.stringify({ label, synthetic: !!synthetic, results, unfinished, evidence }, null, 1));
  return { OUT, guard, check, results, evidence, unfinished, save };
}
export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
export const txt = (pg, sel) => pg.eval(`(document.querySelector(${JSON.stringify(sel)})?.innerText||'').replace(/\\s+/g,' ')`);
export const state = (pg) => pg.eval('JSON.parse(JSON.stringify(window.__otStore.get()))');
export const api = (pg, path) => pg.eval(`fetch(${JSON.stringify(path)}, { credentials: 'same-origin' }).then(async (r) => ({ status: r.status, body: await r.text() }))`);
export const apiJson = async (pg, path) => { const r = await api(pg, path); let b = null; try { b = JSON.parse(r.body); } catch {} return { status: r.status, body: b, raw: r.body }; };
export const frames = (pg) => pg.eval('new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(() => r(true))))');
export const viewport = async (pg, narrow) => {
  await pg.send('Emulation.setDeviceMetricsOverride', narrow ? { width: 390, height: 844, deviceScaleFactor: 1, mobile: true } : { width: 1366, height: 900, deviceScaleFactor: 1, mobile: false });
  await pg.waitFor(`innerWidth===${narrow ? 390 : 1366} && window.__otStore.get().narrow===${narrow}`, 8000); await frames(pg);
};
export const settled = (pg, v) => pg.waitFor(`(()=>{const b=window.__otStore.get().bom8; return b.view===${JSON.stringify(v)} && b.queue && !b.req.queue && !b.req.graph && !b.req.detail})()`, 30000);
export const setUrl = async (pg, url) => { await pg.eval(`(()=>{const e=document.getElementById('ot-url');e.value='';e.dispatchEvent(new Event('input',{bubbles:true}))})()`); await pg.type('#ot-url', url); };
export const detailRequests = (pg) => pg.log.requests.filter((r) => r.url.includes('/api/view/gap?id='));
export const inspectorHtml = (pg) => pg.eval(`(document.querySelector('.ot-bom8-drawer-body')||{}).innerHTML||''`);
export const inspectorText = (pg) => pg.eval(`(document.querySelector('.ot-bom8-drawer-body')?.innerText||'').replace(/\\s+/g,' ')`);
// Geometry of the active inspector: no page-level horizontal scroll, evidence inside the viewport width, excerpt scrollable or fitting, drawer state, scrollability.
export const layoutProbe = (pg) => pg.eval(`(()=>{const d=document.documentElement; const ev=document.querySelector('.ot-bom8-evidence'); const raw=[...document.querySelectorAll('.ot-bom8-evidence .ot-raw')];
  const er=ev&&ev.getBoundingClientRect(); const body=document.querySelector('.ot-bom8-drawer-body'); const dock=document.querySelector('.ot-bom8-inspector');
  return {vw:innerWidth, hscroll:d.scrollWidth>innerWidth+1, evidence:!!ev, evRight:er?Math.round(er.right):null, evInside:!!er&&er.right<=innerWidth+1&&er.left>=-1,
   rawOverflow:raw.map((p)=>({fits:p.scrollWidth<=p.clientWidth+1, ox:getComputedStyle(p).overflowX})), drawerOpen:!!dock&&dock.classList.contains('open'),
   bodyScrollable:!!body&&body.scrollHeight>body.clientHeight+1, bodyOverflowY:body?getComputedStyle(body).overflowY:null, activeId:document.activeElement?.id||document.activeElement?.dataset?.action||document.activeElement?.tagName}})()`);
export const endSession = async (pg) => { await viewport(pg, false); await pg.click('#ot-top-end'); await pg.waitFor(`document.getElementById('ot-ended-note')`, 30000); };
export const inspectorContent = (pg) => pg.eval(`(document.querySelector('.ot-bom8-drawer-body')?.textContent||'').replace(/\\s+/g,' ')`);
