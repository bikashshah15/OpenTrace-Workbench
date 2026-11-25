// UI-POLISH-01 bounded desktop browser closeout: ONE deterministic fixture service (stage4_completion_service.py: SYNTHETIC repositories, fake scanners,
// no network/Docker/provider/credential) and ONE headed Chrome, both launched AND cleaned up by this single driver. No attach mode, no relaunch.
//   PYTHON=<python> node tests/ui/browser/run_ui_polish_checks.mjs <outDir>   # pass 1 at once; then waits for <outDir>/next (re-run ONLY the blocks that failed, same processes) or <outDir>/done
//   node tests/ui/browser/run_ui_polish_checks.mjs --dry                      # offline preflight: parse + sequencing + failure-isolation against a stub page (no service, no Chrome)
// Every scenario block is isolated: a thrown error is recorded as a failed check and the run continues with the next block. Desktop only (1440 and 1100).
import { spawn } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url)); const REPO = resolve(HERE, '../../..');
const DRY = process.argv.includes('--dry');
const OUT = resolve(process.argv.find((a, i) => i >= 2 && !a.startsWith('--')) || join(REPO, 'evidence/ui-polish-01'));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const T0 = Date.now(); const DEADLINE_MS = Number(process.env.DEADLINE_MS || 9.5 * 60 * 1000); const SHA = process.env.TESTED_SHA || 'unset';
let pass = 0; let block = ''; const results = []; const steps = [];
const ok = (name, good, detail = '') => { results.push({ pass, block, name, ok: !!good, detail: String(detail).slice(0, 360) }); console.log(`${good ? 'PASS' : 'FAIL'} [p${pass}/${block}] ${name}${good ? '' : ' :: ' + String(detail).slice(0, 360)}`); };
const step_ = (name) => steps.push(`p${pass} ${name}`);

// ---------------------------------------------------------------- in-page probes (strings; they return plain data)
const COLOR = `const P=(c)=>{const m=String(c).match(/rgba?\\(([^)]+)\\)/); if(!m) return null; const a=m[1].split(/[ ,\\/]+/).filter(Boolean).map(Number); return {r:a[0],g:a[1],b:a[2],a:a.length>3?a[3]:1}};
const L=(c)=>{const f=(v)=>{v/=255; return v<=0.03928? v/12.92 : Math.pow((v+0.055)/1.055,2.4)}; return 0.2126*f(c.r)+0.7152*f(c.g)+0.0722*f(c.b)};
const R=(a,b)=>{if(!a||!b) return null; const x=L(a),y=L(b); return Math.round(((Math.max(x,y)+0.05)/(Math.min(x,y)+0.05))*100)/100};
const bgOf=(el)=>{let e=el; while(e){const c=P(getComputedStyle(e).backgroundColor); if(c&&c.a>0.5) return c; e=e.parentElement;} return {r:255,g:255,b:255,a:1}};
const tok=(n)=>{const s=document.createElement('span'); s.style.color='var('+n+')'; document.body.appendChild(s); const c=getComputedStyle(s).color; s.remove(); return c};`;
const FIELD = (sel) => `(()=>{ ${COLOR} const e=document.querySelector(${JSON.stringify(sel)}); if(!e) return null; const cs=getComputedStyle(e); const ph=P(getComputedStyle(e,'::placeholder').color);
  return { color: cs.color, bg: cs.backgroundColor, border: cs.borderTopColor, ratio: R(P(cs.color),P(cs.backgroundColor)), phRatio: R(ph,P(cs.backgroundColor)),
    outline: cs.outlineStyle+' '+cs.outlineWidth+' '+cs.outlineColor, outlineVisible: cs.outlineStyle!=='none' && parseFloat(cs.outlineWidth)>0, borderRatio: R(P(cs.borderTopColor), bgOf(e.parentElement)) } })()`;
const DISABLED_PROBE = (sel) => `(()=>{ ${COLOR} const e=document.querySelector(${JSON.stringify(sel)}); if(!e) return null; const was=e.disabled; e.disabled=true; const cs=getComputedStyle(e); const out={color:cs.color,bg:cs.backgroundColor,ratio:R(P(cs.color),P(cs.backgroundColor)),cursor:cs.cursor}; e.disabled=was; return out })()`;
const CLUSTER = (c) => `(()=>{ const root=document.querySelector(${JSON.stringify(c.cluster)}); if(!root) return null;
  const rr=root.getBoundingClientRect(); const sr=root.parentElement.getBoundingClientRect();
  const kinds=[...root.children].map((e)=>{ const r=e.getBoundingClientRect(); const k = e.matches(${JSON.stringify(c.percent)}) ? 'percent' : e.matches(${JSON.stringify(c.minus)}) ? 'minus' : e.matches(${JSON.stringify(c.plus)}) ? 'plus' : e.matches(${JSON.stringify(c.fit)}) ? 'fit' : (e.textContent.trim()==='Fit all') ? 'fitall' : 'other:'+e.tagName; return {k, left: Math.round(r.left), right: Math.round(r.right), text: e.textContent.trim(), clipped: r.right>rr.right+1||r.left<rr.left-1}; });
  return { dom: kinds.map((x)=>x.k), visual: [...kinds].sort((a,b)=>a.left-b.left).map((x)=>x.k), texts: kinds.map((x)=>x.text), anyClipped: kinds.some((x)=>x.clipped), insideStage: rr.left>=sr.left-1 && rr.right<=sr.right+1 && rr.top>=sr.top-1 && rr.bottom<=sr.bottom+1,
    pageOverflow: document.documentElement.scrollWidth>innerWidth+1, expand: ${c.expand ? `(()=>{const b=document.querySelector(${JSON.stringify(c.expand)}); return b? {text:b.textContent.trim(), expanded:b.getAttribute('aria-expanded')}:null})()` : 'null'} } })()`;
const GRAPHS = [
  { tab: 'contexts', cluster: '.ot4-controls', percentSel: '#ot4-zoom', percent: '#ot4-zoom', minus: '[data-ctx-zoom="1.25"]', plus: '[data-ctx-zoom="0.8"]', fit: '[data-ctx-fit]', expand: null },
  { tab: 'dependencies', cluster: '#ot5-stage .ot-zoom', percentSel: '#ot5-zoom-label', percent: '#ot5-zoom-label', minus: '[data-ot5-zoom="0.8"]', plus: '[data-ot5-zoom="1.25"]', fit: '[data-ot5-fit]', expand: '#ot5-expand', expanded: '#ot5-expanded' },
  { tab: 'crypto', cluster: '.otc-zoomctl', percentSel: '#otc-zoom', percent: '#otc-zoom', minus: '[data-otc-zoom="0.8333"]', plus: '[data-otc-zoom="1.2"]', fit: '[data-otc-fit]', expand: '#otc-expand', expanded: '#otc-expanded' },
  { tab: 'ai', cluster: '.otai-zoomctl', percentSel: '#otai-zoom', percent: '#otai-zoom', minus: '[data-otai-zoom="0.8333333333333334"]', plus: '[data-otai-zoom="1.2"]', fit: '#otai-fit', expand: '#otai-expand', expanded: '#otai-expanded' },
];
const BOM_PROBE = `(()=>{ ${COLOR}
  const tabs=[...document.querySelectorAll('.ot-bom8-tabs button')].map((b)=>({text:b.textContent.trim(), icons:b.querySelectorAll('svg').length, hidden:[...b.querySelectorAll('svg')].every((s)=>s.getAttribute('aria-hidden')==='true'), current:b.getAttribute('aria-current'), svg:b.querySelector('svg')?.innerHTML.length||0}));
  const nav=document.querySelector('.ot-bom8-tabs'); const navClipped = nav ? nav.scrollWidth>nav.clientWidth+1 : null;
  const rows=[...document.querySelectorAll('.ot-bom8-row')]; const px=(el)=>el? parseFloat(getComputedStyle(el).fontSize):null; const col=(el)=>el?getComputedStyle(el).color:null;
  const row=(r)=>{ if(!r) return null; const cs=getComputedStyle(r); const chip=r.querySelector('.ot-bom8-chip'); const chipSpan=chip&&chip.querySelector(':scope > span'); const name=r.querySelector('.ot-bom8-name'); const sm=r.querySelector('.ot-bom8-selmark'); const smSpan=sm&&sm.querySelector('span'); const loc=r.querySelector('.ot-bom8-meta > span:not(.ot-bom8-chip)');
    return { selected:r.classList.contains('selected'), pressed:r.getAttribute('aria-pressed'), bg:cs.backgroundColor, shadow:cs.boxShadow, rowColor:cs.color, rowFont:cs.fontSize,
      name:name?.textContent.trim(), nameSize:px(name), nameColor:col(name), nameWeight:name?getComputedStyle(name).fontWeight:null, nameRatio:name?R(P(col(name)),bgOf(r)):null,
      familyIcon: !!r.querySelector('.ot-bom8-family'), family: r.querySelector('.ot-bom8-family-label')?.textContent, famSize:px(r.querySelector('.ot-bom8-family-label')),
      chip: chip?.textContent.trim(), chipIcon: !!chip?.querySelector('svg[aria-hidden=true]'), chipColor:col(chip), chipTextColor:col(chipSpan), chipTextSize:px(chipSpan), chipRatio: chipSpan? R(P(col(chipSpan)), bgOf(r)):null, chipTone:chip?[...chip.classList].find((c)=>['warn','ok','unavailable','muted'].includes(c)):null,
      selmark: sm?.textContent.trim()||null, selSize:px(smSpan), selColor:col(smSpan), selRatio: smSpan?R(P(col(smSpan)),bgOf(r)):null, locSize:px(loc), locColor:col(loc) }; };
  return { tabs, navClipped, rowCount: rows.length, rows: rows.slice(0,8).map(row), depSelected: tok('--dep-selected'), muted: tok('--muted'), ink: tok('--ink'), svgsHidden:[...document.querySelectorAll('.ot-bom8 svg')].every((s)=>s.getAttribute('aria-hidden')==='true'), pageOverflow: document.documentElement.scrollWidth>innerWidth+1 } })()`;

const ev = async (pg, expr) => (await pg.eval(expr)) ?? {};

// ---------------------------------------------------------------- blocks
async function homepageBlock(pg, env, theme) {
  step_(`homepage ${theme}`);
  await pg.goto(env.base); await env.ready(); await env.setTheme(theme); await sleep(400);   // navigate + readiness BEFORE any theme/state access
  const light = theme === 'light';
  const probeUrl = await ev(pg, FIELD('#ot-url'));
  await pg.type('#ot-url', 'https://github.com/acme/widget'); await sleep(150);
  const typed = await ev(pg, FIELD('#ot-url')); const value = await ev(pg, `document.getElementById('ot-url').value`);
  ok(`${theme}: typed URL text readable (>= 4.5)`, typed.ratio >= 4.5, JSON.stringify({ c: typed.color, bg: typed.bg, r: typed.ratio }));
  ok(`${theme}: URL value preserved`, value === 'https://github.com/acme/widget', value);
  await pg.eval(`(()=>{const e=document.getElementById('ot-url');e.value='';e.dispatchEvent(new Event('input',{bubbles:true})); e.blur()})()`); await sleep(120);
  const empty = await ev(pg, FIELD('#ot-url'));
  ok(`${theme}: URL placeholder readable (>= 4.5)`, empty.phRatio >= 4.5, JSON.stringify({ ph: empty.phRatio, bg: empty.bg }));
  ok(`${theme}: URL border distinguishable from card (>= 3:1)`, empty.borderRatio >= 3, String(empty.borderRatio));
  await pg.eval(`document.getElementById('ot-url').focus()`); await sleep(120);
  const focus = await ev(pg, FIELD('#ot-url')); ok(`${theme}: URL focus indicator visible`, focus.outlineVisible, focus.outline);
  const dis = await ev(pg, DISABLED_PROBE('#ot-url'));
  ok(`${theme}: disabled URL input (CSS-state probe) muted text >= 3 and not a white field in dark`, dis.ratio >= 3 && (light || !/^rgb\(255, 255, 255\)/.test(dis.bg || '')), JSON.stringify(dis));
  await pg.eval(`document.getElementById('ot-url').blur()`);
  // Advanced reveals the commit field (existing UI; toggled back afterwards)
  await pg.eval(`(()=>{const a=document.getElementById('ot-advanced'); if(a && !a.checked) a.click()})()`); await sleep(400);
  const hasCommit = await pg.eval(`!!document.getElementById('ot-commit')`);
  if (hasCommit) {
    const ce = await ev(pg, FIELD('#ot-commit'));
    ok(`${theme}: commit placeholder readable (>= 4.5)`, ce.phRatio >= 4.5, JSON.stringify(ce));
    await pg.type('#ot-commit', 'abc1234'); await sleep(120); const ct = await ev(pg, FIELD('#ot-commit'));
    ok(`${theme}: typed commit text readable (>= 4.5)`, ct.ratio >= 4.5, JSON.stringify({ c: ct.color, bg: ct.bg, r: ct.ratio }));
    ok(`${theme}: commit focus indicator visible`, ct.outlineVisible, ct.outline);
    await pg.eval(`(()=>{const e=document.getElementById('ot-commit'); e.value=''; e.dispatchEvent(new Event('input',{bubbles:true})); e.blur()})()`);
    const cd = await ev(pg, DISABLED_PROBE('#ot-commit')); ok(`${theme}: disabled commit input (CSS-state probe) text >= 3`, cd.ratio >= 3, JSON.stringify(cd));
  } else ok(`${theme}: commit field available under Advanced`, false, 'not rendered');
  await pg.eval(`(()=>{const a=document.getElementById('ot-advanced'); if(a && a.checked) a.click()})()`); await sleep(300);
  const sample = await ev(pg, FIELD('#nh-sample'));
  ok(`${theme}: sample button text readable (>= 4.5)`, sample.ratio >= 4.5, JSON.stringify({ c: sample.color, bg: sample.bg, r: sample.ratio }));
  ok(`${theme}: sample button border distinguishable (>= 3:1)`, sample.borderRatio >= 3, String(sample.borderRatio));
  await pg.eval(`document.getElementById('nh-sample').focus()`); await sleep(100); const sf = await ev(pg, FIELD('#nh-sample')); ok(`${theme}: sample button focus visible`, sf.outlineVisible, sf.outline); await pg.eval(`document.getElementById('nh-sample').blur()`);
  const sdis = await ev(pg, DISABLED_PROBE('#nh-sample')); ok(`${theme}: sample button disabled (CSS-state probe) text >= 3`, sdis.ratio >= 3, JSON.stringify(sdis));
  const sc = await ev(pg, `(()=>{ ${COLOR} const b=document.getElementById('ot-scan'); const cs=getComputedStyle(b); return {ratio:R(P(cs.color),P(cs.backgroundColor)), bg:cs.backgroundColor, color:cs.color} })()`);
  ok(`${theme}: Scan (enabled) readable (>= 4.5)`, sc.ratio >= 4.5, JSON.stringify(sc));
  const scd = await ev(pg, DISABLED_PROBE('#ot-scan')); ok(`${theme}: Scan disabled (CSS-state probe) text >= 3`, scd.ratio >= 3, JSON.stringify(scd));
  if (light) ok('light: input and sample button keep the original white fill', /255, 255, 255/.test(probeUrl.bg || '') && /255, 255, 255/.test(sample.bg || ''), JSON.stringify({ u: probeUrl.bg, s: sample.bg }));
  await env.shot(`home-${theme}-1440`);
}
async function openWorkbench(pg, env) {
  step_('scan fixture repository'); await pg.goto(env.base); await env.ready(); await env.setTheme('light'); await env.setWidth(1440, 900);
  await pg.eval(`(()=>{const e=document.getElementById('ot-url');e.value='';e.dispatchEvent(new Event('input',{bubbles:true}))})()`); await pg.type('#ot-url', 'https://github.com/acme/aicrypto'); await pg.click('#ot-scan');
  await pg.waitFor(`window.__otStore.get().destination === 'workbench'`, 90000);
  ok('fixture repository opened in the Workbench', true);
}
async function bomBlock(pg, env, theme, w, h) {
  step_(`bom ${theme} ${w}`); await env.setWidth(w, h); await env.setTheme(theme); await sleep(400); await env.normalize();
  await pg.eval(`document.getElementById('ot-tab-bom').click()`); await pg.waitFor(`window.__otStore.get().bom8.queue`, 30000); await sleep(700);
  const p0 = await ev(pg, BOM_PROBE); const tag = `${theme}/${w}`;
  ok(`${tag}: five BOM view labels, one decorative icon each, labels kept`, p0.tabs?.length === 5 && p0.tabs.every((t) => t.icons === 1 && t.hidden && t.text), JSON.stringify(p0.tabs));
  ok(`${tag}: five different icons`, new Set((p0.tabs || []).map((t) => t.svg)).size === 5, JSON.stringify((p0.tabs || []).map((t) => t.svg)));
  ok(`${tag}: aria-current kept (exactly one page)`, (p0.tabs || []).filter((t) => t.current === 'page').length === 1, '');
  const rows = p0.rows || [];
  ok(`${tag}: rows show family icon, family label and chip with icon`, rows.length > 0 && rows.every((r) => r.familyIcon && r.family && r.chip && r.chipIcon), JSON.stringify(rows.slice(0, 2)));
  ok(`${tag}: UPR-01 row name is full size (>= 13px) and ink, not 11px muted`, rows.length > 0 && rows.every((r) => r.nameSize >= 13 && r.nameColor === p0.ink && r.nameColor !== p0.muted), JSON.stringify(rows.slice(0, 3).map((r) => [r.nameSize, r.nameColor])) + ' ink=' + p0.ink + ' muted=' + p0.muted);
  ok(`${tag}: UPR-01 chip text keeps the chip tone colour, 11px, contrast >= 4.5`, rows.length > 0 && rows.every((r) => r.chipTextColor === r.chipColor && r.chipTextSize === 11 && r.chipRatio >= 4.5), JSON.stringify(rows.map((r) => [r.chipTone, r.chipColor, r.chipTextColor, r.chipTextSize, r.chipRatio])));
  ok(`${tag}: family label is 11px`, rows.length > 0 && rows.every((r) => r.famSize === 11), JSON.stringify(rows.map((r) => r.famSize)));
  ok(`${tag}: no horizontal page overflow; nav not clipped; all BOM svgs aria-hidden`, !p0.pageOverflow && p0.navClipped === false && p0.svgsHidden, JSON.stringify({ x: p0.pageOverflow, nav: p0.navClipped, h: p0.svgsHidden }));
  await pg.eval(`document.querySelectorAll('.ot-bom8-row')[0].click()`); await sleep(900);
  const pt = await pg.eval(`(()=>{const r=document.querySelectorAll('.ot-bom8-row')[1]; if(!r) return null; r.scrollIntoView({block:'center'}); const b=r.getBoundingClientRect(); return {x:Math.round(b.left+b.width/2), y:Math.round(b.top+b.height/2)}})()`);
  if (pt) await pg.send('Input.dispatchMouseEvent', { type: 'mouseMoved', x: pt.x, y: pt.y }); await sleep(250);
  const p1 = await ev(pg, BOM_PROBE); const sel = (p1.rows || []).find((r) => r.selected); const hov = (p1.rows || [])[1];
  const hovered = await pg.eval(`document.querySelectorAll('.ot-bom8-row')[1]?.matches(':hover')`);
  ok(`${tag}: one row selected with visible "Selected" mark and aria-pressed=true`, (p1.rows || []).filter((r) => r.selected).length === 1 && sel?.selmark === 'Selected' && sel?.pressed === 'true', JSON.stringify(sel));
  ok(`${tag}: UPR-01 "Selected" is --dep-selected, 11px, contrast >= 4.5`, sel && sel.selColor === p1.depSelected && sel.selSize === 11 && sel.selRatio >= 4.5, JSON.stringify({ c: sel?.selColor, want: p1.depSelected, s: sel?.selSize, r: sel?.selRatio }));
  ok(`${tag}: selected row name is full size and bold`, sel && sel.nameSize >= 13 && Number(sel.nameWeight) >= 700, JSON.stringify({ s: sel?.nameSize, w: sel?.nameWeight }));
  ok(`${tag}: pointer really hovers a non-selected row`, hovered === true && hov && !hov.selected, String(hovered));
  ok(`${tag}: selected has a leading bar that hover lacks (not colour alone)`, sel && hov && /inset/.test(sel.shadow) && !/inset/.test(hov.shadow), JSON.stringify({ sel: sel?.shadow, hov: hov?.shadow }));
  ok(`${tag}: hover fill differs from selected fill`, sel && hov && sel.bg !== hov.bg, JSON.stringify({ sel: sel?.bg, hov: hov?.bg }));
  await env.shot(`bom-${theme}-${w}`);
  for (const view of ['crypto', 'ai']) {
    await pg.eval(`document.querySelector('.ot-bom8-tabs [data-view=${view}]').click()`); await sleep(900);
    const pv = await ev(pg, BOM_PROBE); const cur = (pv.tabs || []).findIndex((t) => t.current === 'page');
    ok(`${tag}: ${view} view marked current, icons intact`, cur === (view === 'crypto' ? 1 : 2) && (pv.tabs || []).every((t) => t.icons === 1), JSON.stringify((pv.tabs || []).map((t) => t.current)));
  }
  await pg.eval(`document.querySelector('.ot-bom8-tabs [data-view=gaps]').click()`);
}
async function graphBlock(pg, env, theme, w, h, g) {
  step_(`graph ${g.tab} ${theme} ${w}`); await env.setWidth(w, h); await env.setTheme(theme); await sleep(300); await env.normalize();
  await pg.eval(`document.getElementById('ot-tab-${g.tab}').click()`);
  await pg.waitFor(`document.querySelector(${JSON.stringify(g.cluster)})`, 30000, `controls of ${g.tab}`); await sleep(900);
  const tag = `${theme}/${w} ${g.tab}`; const want = ['minus', 'percent', 'plus', 'fit'];
  const c = await ev(pg, CLUSTER(g));
  ok(`${tag}: DOM order minus, percentage, plus, Fit`, JSON.stringify((c.dom || []).slice(0, 4)) === JSON.stringify(want), JSON.stringify(c.dom));
  ok(`${tag}: visual left-to-right order matches`, JSON.stringify((c.visual || []).slice(0, 4)) === JSON.stringify(want), JSON.stringify(c.visual));
  ok(`${tag}: Fit all (if present) comes after Fit; nothing unexpected`, (c.dom || []).length === 4 || ((c.dom || []).length === 5 && c.dom[4] === 'fitall'), JSON.stringify(c.dom));
  ok(`${tag}: controls inside the stage, not clipped, no page overflow`, c.insideStage && !c.anyClipped && !c.pageOverflow, JSON.stringify({ in: c.insideStage, clip: c.anyClipped, x: c.pageOverflow }));
  if (c.expand) ok(`${tag}: expand control reads "Expand"`, c.expand.text === 'Expand' && c.expand.expanded === 'false', JSON.stringify(c.expand));
  const pct = async () => parseInt((await ev(pg, `document.querySelector(${JSON.stringify(g.percentSel)})?.textContent`)) || '', 10);
  if (w === 1440) {
    const p0 = await pct(); await pg.click(g.minus); await sleep(250); const p1 = await pct(); await pg.click(g.plus); await sleep(250); await pg.click(g.plus); await sleep(250); const p2 = await pct();
    await pg.click(g.fit); await sleep(350); const p3 = await pct();
    ok(`${tag}: minus lowers, plus raises, Fit restores the initial fit`, p1 < p0 && p2 > p1 && p3 === p0, JSON.stringify({ p0, p1, p2, p3 }));
    const fa = await pg.eval(`!![...document.querySelectorAll(${JSON.stringify(g.cluster + ' button')})].find((b)=>b.textContent.trim()==='Fit all')`);
    if (fa) { const before = await pct(); await pg.eval(`[...document.querySelectorAll(${JSON.stringify(g.cluster + ' button')})].find((b)=>b.textContent.trim()==='Fit all').click()`); await sleep(350); const after = await pct(); ok(`${tag}: existing Fit all still operates`, after > 0, `${before} -> ${after}`); }
  }
  if (c.expand) {
    await pg.click(g.expand); await sleep(700);
    const open = await ev(pg, `({frame: !!document.querySelector(${JSON.stringify(g.expanded)}), label: document.querySelector(${JSON.stringify(g.expand)})?.textContent.trim(), ex: document.querySelector(${JSON.stringify(g.expand)})?.getAttribute('aria-expanded')})`);
    const co = await ev(pg, CLUSTER(g));
    ok(`${tag}: Expand -> "Close expanded view", frame open, same control order, controls unclipped`, open.frame && open.label === 'Close expanded view' && open.ex === 'true' && JSON.stringify((co.dom || []).slice(0, 4)) === JSON.stringify(want) && !co.anyClipped && !co.pageOverflow, JSON.stringify({ open, dom: co.dom, clip: co.anyClipped, x: co.pageOverflow }));
    await env.shot(`graph-${g.tab}-expanded-${theme}-${w}`);
    await pg.click(g.expand); await sleep(600);
    const closed = await ev(pg, `({frame: !!document.querySelector(${JSON.stringify(g.expanded)}), label: document.querySelector(${JSON.stringify(g.expand)})?.textContent.trim()})`);
    ok(`${tag}: closing restores "Expand" and removes the frame`, !closed.frame && closed.label === 'Expand', JSON.stringify(closed));
  }
  await env.shot(`graph-${g.tab}-${theme}-${w}`);
}

// Ordered block list. A failed block never aborts the run.
const BLOCKS = (pg, env) => [
  { name: 'home-light', home: true, run: () => homepageBlock(pg, env, 'light') },
  { name: 'home-dark', home: true, run: () => homepageBlock(pg, env, 'dark') },
  { name: 'open-workbench', setup: true, run: () => openWorkbench(pg, env) },
  { name: 'bom-light-1440', run: () => bomBlock(pg, env, 'light', 1440, 900) },
  ...GRAPHS.map((g) => ({ name: `graph-${g.tab}-light-1440`, run: () => graphBlock(pg, env, 'light', 1440, 900, g) })),
  { name: 'bom-dark-1440', run: () => bomBlock(pg, env, 'dark', 1440, 900) },
  ...GRAPHS.map((g) => ({ name: `graph-${g.tab}-dark-1440`, run: () => graphBlock(pg, env, 'dark', 1440, 900, g) })),
  { name: 'bom-dark-1100', run: () => bomBlock(pg, env, 'dark', 1100, 800) },
  ...GRAPHS.map((g) => ({ name: `graph-${g.tab}-dark-1100`, run: () => graphBlock(pg, env, 'dark', 1100, 800, g) })),
  { name: 'bom-light-1100', run: () => bomBlock(pg, env, 'light', 1100, 800) },
];
const failedBlocks = new Set();
async function runBlocks(pg, env, only) {
  const list = BLOCKS(pg, env); const needsWb = only ? list.some((b) => only.has(b.name) && !b.home && !b.setup) : true;
  for (const b of list) {
    if (only && !only.has(b.name) && !(b.setup && needsWb)) continue;
    block = b.name; const before = results.length;
    try { await b.run(); } catch (e) { ok(`block "${b.name}" completed`, false, e.message); }
    if (results.slice(before).some((r) => !r.ok)) failedBlocks.add(b.name); else failedBlocks.delete(b.name);
  }
  block = 'final'; try { await pg.eval(`fetch('/api/session/end',{method:'POST'}).then(()=>true).catch(()=>true)`); } catch {}
  ok('no page exceptions', (pg.log?.exceptions || []).length === 0, (pg.log?.exceptions || []).join(' | '));
  ok('no external network request', (pg.log?.requests || []).every((r) => r.url.startsWith(env.base.slice(0, -1)) || r.url.startsWith('data:') || r.url.startsWith('about:')), '');
}
const writeResults = (extra = {}) => { try { mkdirSync(OUT, { recursive: true }); writeFileSync(join(OUT, 'results.json'), JSON.stringify({ tested_sha: SHA, elapsed_seconds: Math.round((Date.now() - T0) / 1000), passes: pass, headed: true, relaunch: false, services: 1, chrome: 1, failed_blocks: [...failedBlocks], results, steps, ...extra }, null, 1)); } catch {} };

// ---------------------------------------------------------------- dry run: parsing, sequencing, failure isolation
if (DRY) {
  let thrown = 0;
  const stub = { log: { requests: [], exceptions: [] }, eval: async () => null, send: async () => ({}), click: async () => {}, type: async () => {}, goto: async () => {}, screenshot: async () => {}, close: async () => {},
    waitFor: async (expr) => { if (!thrown && String(expr).includes('bom8.queue')) { thrown = 1; throw new Error('INJECTED failure in the first BOM block'); } return true; } };
  const noop = async () => {};
  const probes = [['FIELD', FIELD('#ot-url')], ['DISABLED', DISABLED_PROBE('#nh-sample')], ['BOM', BOM_PROBE], ...GRAPHS.map((g) => ['CLUSTER ' + g.tab, CLUSTER(g)])];
  for (const [name, expr] of probes) { try { new Function('return ' + expr); } catch (e) { console.log('PARSE FAIL', name, e.message); process.exit(2); } }
  pass = 1; await runBlocks(stub, { ready: noop, shot: noop, setTheme: noop, setWidth: noop, normalize: noop, base: 'http://127.0.0.1:0/' });
  const injected = results.find((r) => /block "bom-light-1440" completed/.test(r.name) && !r.ok);
  console.log('DRY blocks defined: ' + BLOCKS(stub, {}).length + '; steps run (' + steps.length + '):\n  ' + steps.join('\n  '));
  const laterRan = steps.some((s) => /graph contexts light 1440/.test(s)) && steps.some((s) => /bom light 1100/.test(s));
  console.log('failure isolation: injected failure recorded=' + !!injected + ', later blocks still ran=' + laterRan + ', failed_blocks include bom-light-1440=' + failedBlocks.has('bom-light-1440'));
  process.exit(injected && laterRan ? 0 : 2);
}

// ---------------------------------------------------------------- real run (this process owns launch AND cleanup)
const { connect, newPage, CHROME } = await import('./cdp.mjs');
let svc = null; let chrome = null; let browser = null; let dir = null; let cleaned = false; const pids = [];
const cleanup = async () => {
  if (cleaned) return; cleaned = true;
  try { browser && browser.close(); } catch {}
  for (const p of [chrome, svc]) { try { p && p.pid && p.kill('SIGTERM'); } catch {} }
  await sleep(1000);
  for (const p of [chrome, svc]) { try { p && p.exitCode === null && p.kill('SIGKILL'); } catch {} }
  try { dir && rmSync(dir, { recursive: true, force: true }); } catch {}
  const alive = pids.filter((pid) => { try { process.kill(pid, 0); return true; } catch { return false; } });
  console.log('CLEANUP started=' + JSON.stringify(pids) + ' still_alive=' + JSON.stringify(alive)); globalThis.__alive = alive;
};
const timer = setTimeout(async () => { block = 'deadline'; ok('deadline: finished within the time limit', false, 'deadline reached'); writeResults({ deadline_hit: true }); await cleanup(); process.exit(3); }, DEADLINE_MS);
process.on('SIGINT', async () => { writeResults({ interrupted: true }); await cleanup(); process.exit(130); });
mkdirSync(OUT, { recursive: true });
try {
  svc = spawn(process.env.PYTHON || 'python3', [join(HERE, 'stage4_completion_service.py')], { cwd: REPO, env: { ...process.env, PYTHONPATH: REPO + ':' + join(REPO, 'src/core') + ':' + join(REPO, 'src/agents/investigator') }, stdio: ['ignore', 'pipe', 'pipe'] }); if (svc.pid) pids.push(svc.pid);
  const base = await new Promise((res, rej) => { let b = ''; const t = setTimeout(() => rej(new Error('service did not start: ' + b)), 40000); svc.stdout.on('data', (d) => { b += d; const m = b.match(/http:\/\/127\.0\.0\.1:(\d+)\//); if (m) { clearTimeout(t); res(m[0]); } }); svc.stderr.on('data', (d) => { b += d; }); });
  dir = mkdtempSync(join(tmpdir(), 'ot-polish-chrome-'));
  chrome = spawn(CHROME, ['--no-first-run', '--no-default-browser-check', `--user-data-dir=${dir}`, '--remote-debugging-port=0', '--window-size=1500,1000', 'about:blank'], { stdio: ['ignore', 'ignore', 'pipe'] }); if (chrome.pid) pids.push(chrome.pid);
  const wsUrl = await new Promise((res, rej) => { let b = ''; const t = setTimeout(() => rej(new Error('chrome did not start')), 30000); chrome.stderr.on('data', (d) => { b += d; const m = b.match(/DevTools listening on (ws:\/\/\S+)/); if (m) { clearTimeout(t); res(m[1]); } }); chrome.on('exit', () => rej(new Error('chrome exited'))); });
  browser = await connect(wsUrl);
  const pg = await newPage(browser, { width: 1440, height: 900 });
  const env = { base,
    ready: () => pg.waitFor(`document.getElementById('ot-scan') && !document.getElementById('ot-scan').disabled`, 30000),
    shot: (name) => pg.screenshot(join(OUT, `p${pass}_${name}.png`)),
    // theme/state are only touched on a loaded page: every block navigates and waits for readiness first (homepage) or runs after the Workbench opened.
    setTheme: (t) => pg.eval(`(()=>{ if(!window.__otStore) throw new Error('app not ready'); window.__otStore.dispatch({type:'THEME', value:'${t}'}); return true })()`),
    setWidth: (w, h) => pg.send('Emulation.setDeviceMetricsOverride', { width: w, height: h, deviceScaleFactor: 1, mobile: false }),
    normalize: async () => { if (await pg.eval(`!!document.querySelector('.ot5-expanded,.otc-expanded,.otai-expanded')`)) { await pg.key('Escape'); await sleep(400); } } };
  for (;;) {
    pass += 1; await runBlocks(pg, env, pass === 1 ? null : new Set(failedBlocks)); writeResults();
    const mine = results.filter((r) => r.pass === pass); const bad = mine.filter((r) => !r.ok).length; console.log(`pass ${pass}: ${mine.length - bad}/${mine.length} passed; failed blocks: ${[...failedBlocks].join(', ') || 'none'}`);
    if (pass >= 2) break;
    console.log(`WAITING for ${OUT}/next (one targeted correction pass: re-runs only the failed blocks, same processes) or ${OUT}/done`);
    let go = null; while (!go) { if (existsSync(join(OUT, 'done'))) go = 'done'; else if (existsSync(join(OUT, 'next'))) go = 'next'; else await sleep(1000); }
    if (go === 'done') break;
  }
} catch (e) { block = 'driver'; ok('driver completed', false, e.stack || e.message); } finally { clearTimeout(timer); writeResults(); await cleanup(); writeResults({ cleanup_alive: globalThis.__alive || [] }); }
const bad = results.filter((r) => !r.ok); console.log(`\n${results.length - bad.length}/${results.length} passed in ${Math.round((Date.now() - T0) / 1000)} s`); process.exit(bad.length ? 1 : 0);
