// UIP-10 F1-F3 local fixture validation (test harness; supersedes nothing: the earlier run_uip10_coverage.mjs and its evidence are kept).
// One fixture service + one headless Chrome per invocation; several fixture repositories (states) may be exercised inside one pair.
// Usage: PYTHON=<python with requirements-dev> OT_DEADLINE_MS=<epoch ms> node run_uip10_f1f3.mjs <case: partial|completed|unsupported|failed> <outDir>
// States per case: partial -> partial (widget: populated; gadget: zero total); completed -> completed (okrepo) + completed_empty (plain); unsupported; failed.
import { spawn } from 'node:child_process';
import { appendFileSync, mkdirSync, writeFileSync } from 'node:fs';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { launch, newPage } from './cdp.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = resolve(HERE, '../../..');
const [CASE, OUTARG] = process.argv.slice(2);
const OUT = resolve(OUTARG); mkdirSync(OUT, { recursive: true });
const DEADLINE = Number(process.env.OT_DEADLINE_MS || 0);
const PIDS = process.env.OT_PIDS_FILE;
const results = [], evidence = {}, unfinished = [];
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const guard = () => { if (DEADLINE && Date.now() > DEADLINE) throw new Error('DEADLINE'); };
const check = (id, ok, detail = '') => { results.push({ id, ok: !!ok, detail: String(detail).slice(0, 400) }); console.log(`${ok ? 'PASS' : 'FAIL'} ${id}${detail ? ' — ' + String(detail).slice(0, 200) : ''}`); };

function service() {
  const proc = spawn(process.env.PYTHON || 'python3', [join(HERE, 'uip10_coverage_service.py'), '--case', CASE, '--marker', process.env.OT_MARKER || ''], { cwd: REPO, env: { ...process.env, PYTHONPATH: `${REPO}:${join(REPO, 'src/core')}` }, stdio: ['ignore', 'pipe', 'pipe'] });
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
// A condition wait (not a sleep): the override is applied, the page has seen the new width and the UI has switched its narrow flag.
const viewport = async (pg, narrow) => {
  await pg.send('Emulation.setDeviceMetricsOverride', narrow ? { width: 390, height: 844, deviceScaleFactor: 1, mobile: true } : { width: 1366, height: 900, deviceScaleFactor: 1, mobile: false });
  await pg.waitFor(`innerWidth===${narrow ? 390 : 1366} && window.__otStore.get().narrow===${narrow}`, 8000); await frames(pg);
};
const settled = (pg, v) => pg.waitFor(`(()=>{const b=window.__otStore.get().bom8; return b.view===${JSON.stringify(v)} && b.queue && !b.req.queue && !b.req.graph})()`, 30000);
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
const noticeLayout = (pg) => pg.eval(`(()=>{const n=document.querySelector('.ot-bom8-coverage'); const d=document.documentElement; const base={hscroll:d.scrollWidth>innerWidth+1}; if(!n) return {...base,present:false}; const r=n.getBoundingClientRect(); return {...base,present:true,clipX:r.left<-0.5||r.right>innerWidth+0.5,textFits:n.scrollHeight<=n.clientHeight+1}})()`);
// Geometric probe: the FIXED launcher against every relevant element currently in the viewport, plus its position relative to the fixed details dock.
const PROBE = `(()=>{const L=document.getElementById('ot-assistant-launch'); if(!L) return {err:'no launcher'}; const lr=L.getBoundingClientRect();
  const x=(r)=>{const w=Math.min(r.right,lr.right)-Math.max(r.left,lr.left), h=Math.min(r.bottom,lr.bottom)-Math.max(r.top,lr.top); return w>1&&h>1?{w:Math.round(w),h:Math.round(h)}:null};
  const sels=['.ot-bom8-coverage','.ot-bom8 .ot-prompt','.ot-bom8 .ot-help','.ot-bom8-filters button','#ot-bom8-q','.ot-bom8-row','.ot-bom8-tabs button','.ot-bom8-record','.ot-pager button','.ot-bom8-queue h3','.ot-bom8-main h3','.ot-bom8-cards button'];
  const hits=[]; for(const q of sels) for(const e of document.querySelectorAll(q)){const r=e.getBoundingClientRect(); if(!r.width||!r.height||r.bottom<0||r.top>innerHeight) continue; const o=x(r); if(o) hits.push({q,...o,text:(e.innerText||'').slice(0,28)})}
  const dock=document.querySelector('.ot-bom8-inspector'); const dr=dock&&dock.getBoundingClientRect(); const open=!!dock&&dock.classList.contains('open');
  const dockCtl=[]; if(dock) for(const e of dock.querySelectorAll('.ot-bom8-drawer-head h3,.ot-bom8-drawer-head button')){const o=x(e.getBoundingClientRect()); if(o) dockCtl.push({text:(e.innerText||'').slice(0,20),...o})}
  const cx=(lr.left+lr.right)/2, cy=(lr.top+lr.bottom)/2;
  return {launcher:{l:Math.round(lr.left),t:Math.round(lr.top),r:Math.round(lr.right),b:Math.round(lr.bottom)},vw:innerWidth,vh:innerHeight,hits,dockOpen:open,insideDock:!!dr&&!open&&lr.left>=dr.left&&lr.right<=dr.right&&lr.top>=dr.top&&lr.bottom<=dr.bottom,aboveOpenDrawer:!!dr&&open&&lr.bottom<=dr.top+1,dockCtl,onTop:document.elementFromPoint(cx,cy)===L,inViewport:lr.left>=0&&lr.right<=innerWidth&&lr.top>=0&&lr.bottom<=innerHeight,css:{bottom:getComputedStyle(L).bottom,right:getComputedStyle(L).right}}})()`;
const SCROLLS = ['start', 'center', 'end'];
async function overlapSweep(pg, label, noticeSel) {
  const rows = [];
  for (const pos of SCROLLS) for (const d of [-120, -60, 0, 60, 120]) {
    guard();
    await pg.eval(`(()=>{const n=document.querySelector(${JSON.stringify(noticeSel)})||document.querySelector('.ot-bom8 .ot-prompt'); n&&n.scrollIntoView({block:${JSON.stringify(pos)}}); window.scrollBy(0,${d});})()`);
    await frames(pg);
    const r = await pg.eval(PROBE); rows.push({ pos, d, hits: r.hits, insideDock: r.insideDock, dockCtl: r.dockCtl, onTop: r.onTop, inViewport: r.inViewport });
  }
  evidence[label] = rows;
  return rows;
}
const wordingCheck = async (pg, st, view, vp) => {
  const body = await txt(pg, '.ot-bom8');
  const id = `${st} ${view} ${vp}`;
  check(`${id}: no "endpoint unavailable" banner`, !/endpoint is unavailable/.test(body));
  const w = {
    partial: [/Partial coverage\./],
    completed: [/produced no candidates/, /no count of them is shown/],
    completed_empty: [/No requirement declarations were found/],
    unsupported: [/Not compared\./, /Only declaration files|formats or ecosystems this build does not read|nothing was compared/i],
    failed: [/Not compared\./, /directory listing failed/],
  }[st];
  return { id, body, ok: w ? w.every((re) => re.test(body)) : true };
};

async function exerciseState(pg, st, label) {
  // Called with the analysis for state `st` open on the BOM tab. Checks software, focused gaps and Full evidence graph at desktop and 390 px.
  const c = await caps(pg); evidence[`${label}_caps`] = c;
  const want = { partial: ['partial', 'discovery_compared'], completed: ['completed', 'discovery_compared'], completed_empty: ['completed_empty', 'discovery_compared'], unsupported: ['unsupported', 'not_compared'], failed: ['failed', 'not_compared'] }[st];
  check(`${label}: API state is software ${want[0]} on a ${want[1]} page`, c.software.state === want[0] && c.mode === want[1], JSON.stringify(c));
  const notCompared = want[1] === 'not_compared';
  for (const vp of ['1366', '390']) {
    await viewport(pg, vp === '390');
    for (const v of ['software', 'gaps', 'full']) {
      guard();
      const before = pg.log.requests.filter((r) => r.url.includes('/bom-graph')).length;
      await pg.click(`[data-action=bom-view][data-view=${v}]`); await settled(pg, v);
      const id = `${label} ${v} ${vp}`;
      const nl = await noticeLayout(pg);
      check(`${id}: partial notice ${st === 'partial' ? 'present' : 'absent'}`, nl.present === (st === 'partial') && !nl.hscroll && !nl.clipX && (nl.textFits !== false), JSON.stringify(nl));
      const wc = await wordingCheck(pg, st, v, vp);
      if (v === 'software' || notCompared) check(`${id}: states its situation in words`, wc.ok, wc.body.slice(0, 260));
      if (!notCompared && c.total === 0 && v === 'software') {
        check(`${id}: zero-total wording is state-specific`, st === 'partial' ? /coverage was partial/.test(wc.body) && !/comparison completed/i.test(wc.body) : true && /This assessment has no candidates/.test(wc.body), wc.body.slice(0, 200));
        check(`${id}: not described as a filtered-empty list`, !/No candidates match this filter/.test(wc.body));
      }
      if (notCompared && v === 'full') {
        const after = pg.log.requests.filter((r) => r.url.includes('/bom-graph')).length;
        check(`${id}: no graph request was made for a not-compared analysis`, after === before, `${before}->${after}`);
        check(`${id}: reason is still visible in Full evidence graph`, /Not compared\./.test(wc.body) && /There is no bound comparison graph/.test(wc.body), wc.body.slice(0, 200));
        check(`${id}: no leaked exception text or path`, !/injected|PermissionError|\/tmp\/|\/private\//.test(wc.body));
      }
      if (!notCompared && v === 'full') check(`${id}: Full evidence graph shows its graph area without an error`, !(await state(pg)).bom8.error);
      await pg.screenshot(join(OUT, `${label}_${v}_${vp}.png`));
    }
  }
}

async function f3Checks(pg, st, label) {
  // 390 px: the fixed launcher against the notice/lists at realistic scroll positions, the details dock, keyboard focus, the open drawer; desktop keeps its CSS position.
  await viewport(pg, true);
  await pg.click(`[data-action=bom-view][data-view=software]`); await settled(pg, 'software');
  const rows = await overlapSweep(pg, `${label}_overlap390`, '.ot-bom8-coverage');
  const bad = rows.filter((r) => r.hits.length || !r.insideDock || r.dockCtl.length || !r.onTop || !r.inViewport);
  check(`${label} F3: at 390 px the launcher never intersects notice/prompt/list/filter/tab elements, sits inside the dock clear of its controls, is on top and in the viewport at ${rows.length} scroll positions`, bad.length === 0, JSON.stringify(bad[0] || {}));
  await pg.eval(`document.getElementById('ot-assistant-launch').focus()`);
  const f = await pg.eval(`(()=>{const L=document.getElementById('ot-assistant-launch'); const r=L.getBoundingClientRect(); return {focused:document.activeElement===L,top:document.elementFromPoint((r.left+r.right)/2,(r.top+r.bottom)/2)===L,vis:r.bottom<=innerHeight&&r.top>=0}})()`);
  check(`${label} F3: keyboard focus lands on the launcher and it is visible and unobscured`, f.focused && f.top && f.vis, JSON.stringify(f));
  await pg.eval(`document.querySelector('[data-action=bom-drawer]').click()`); await pg.waitFor(`document.querySelector('.ot-bom8-inspector.open')`, 5000);
  const o = await pg.eval(PROBE);
  const ctl = await pg.eval(`(()=>{const b=document.querySelector('[data-action=bom-drawer]'); const r=b.getBoundingClientRect(); return {top:document.elementFromPoint((r.left+r.right)/2,(r.top+r.bottom)/2)===b}})()`);
  check(`${label} F3: with the details drawer open the launcher stays above it and the drawer's close control is not covered`, o.aboveOpenDrawer && o.onTop && ctl.top && o.dockCtl.length === 0, JSON.stringify({ above: o.aboveOpenDrawer, top: o.onTop, ctl: ctl.top, dockCtl: o.dockCtl }));
  await pg.screenshot(join(OUT, `${label}_f3_drawer_open_390.png`));
  await pg.eval(`document.querySelector('[data-action=bom-drawer]').click()`); await pg.waitFor(`!document.querySelector('.ot-bom8-inspector.open')`, 5000);
  await pg.eval(`window.scrollTo(0,0)`);
  await pg.screenshot(join(OUT, `${label}_f3_top_390.png`));
  await viewport(pg, false);
  const d = await pg.eval(PROBE);
  check(`${label} F3: desktop keeps the launcher's original position (bottom 22px, right 24px)`, d.css.bottom === '22px' && d.css.right === '24px', JSON.stringify(d.css));
}

const { browser, close, proc } = await launch();
if (PIDS) appendFileSync(PIDS, proc.pid + '\n');
let svc;
try {
  svc = await service();
  const pg = await newPage(browser, { width: 1366, height: 900 });
  await pg.goto(svc.base);
  const plan = { partial: [['widget', 'partial', 'partial_populated'], ['gadget', 'partial', 'partial_zero']], completed: [['okrepo', 'completed', 'completed'], ['plain', 'completed_empty', 'completed_empty']], unsupported: [['nodeonly', 'unsupported', 'unsupported']], failed: [['widget', 'failed', 'failed']] }[CASE];
  for (const [i, [repo, st, label]] of plan.entries()) {
    try {
      guard(); if (i > 0) await endSession(pg);
      await scanRepo(pg, repo); await viewport(pg, false);
      if (st === 'partial' && label === 'partial_populated') {
        const c0 = await caps(pg); check('partial_populated: one candidate', c0.total === 1, JSON.stringify(c0));
        await pg.click('[data-action=bom-view][data-view=software]'); await settled(pg, 'software');
        check('partial_populated: candidate row listed beside the notice', await pg.eval(`!!document.querySelector('.ot-bom8-row')`) && (await noticeLayout(pg)).present);
        await pg.click('[data-action=bom-filter][data-filter=represented]'); await pg.waitFor(`window.__otStore.get().bom8.filter==='represented' && !window.__otStore.get().bom8.req.queue`, 15000);
        const ef = await txt(pg, '.ot-bom8'); const cf = await caps(pg);
        check('partial_populated: empty-by-filter - no rows, filtered-empty wording (not zero-total), notice stays, API still partial', !(await pg.eval(`!!document.querySelector('.ot-bom8-row')`)) && /No candidates match this filter/.test(ef) && !/This assessment has no candidates/.test(ef) && (await noticeLayout(pg)).present && cf.software.state === 'partial', ef.slice(0, 200));
        await pg.screenshot(join(OUT, 'partial_populated_empty_by_filter_1366.png'));
        await pg.click('[data-action=bom-filter][data-filter=all]'); await pg.waitFor(`window.__otStore.get().bom8.filter==='all' && !window.__otStore.get().bom8.req.queue`, 15000);
        await pg.eval(`(()=>{const e=document.getElementById('ot-bom8-q');e.focus();e.value='zzzz-no-match';e.dispatchEvent(new Event('input',{bubbles:true}))})()`);
        await pg.waitFor(`window.__otStore.get().bom8.q==='zzzz-no-match' && !window.__otStore.get().bom8.req.queue && (window.__otStore.get().bom8.queue?.counts?.filtered_total===0)`, 15000);
        const es = await txt(pg, '.ot-bom8');
        check('partial_populated: empty-by-search - no rows, filtered-empty wording, notice stays', !(await pg.eval(`!!document.querySelector('.ot-bom8-row')`)) && /No candidates match this filter/.test(es) && (await noticeLayout(pg)).present, es.slice(0, 200));
        await pg.screenshot(join(OUT, 'partial_populated_empty_by_search_1366.png'));
        await pg.eval(`(()=>{const e=document.getElementById('ot-bom8-q');e.value='';e.dispatchEvent(new Event('input',{bubbles:true}))})()`);
        await pg.waitFor(`window.__otStore.get().bom8.q==='' && !window.__otStore.get().bom8.req.queue`, 15000);
      }
      await exerciseState(pg, st, label);
      if (label === 'partial_populated' || label === 'unsupported' || label === 'completed') await f3Checks(pg, st, label);
      if (label === 'partial_populated') {
        // Sensitivity control: re-apply the PREVIOUS launcher rule and show the same probe detects the floating overlap at some scroll position.
        await viewport(pg, true);
        await pg.eval(`(()=>{const s=document.createElement('style'); s.id='ot-prev-rule'; s.textContent='@media(max-width:700px){body:has(.ot-bom8) .assistant-launch{bottom:62px!important;right:12px!important;left:auto!important;transform:none!important}}'; document.head.appendChild(s)})()`);
        await pg.click(`[data-action=bom-view][data-view=software]`); await settled(pg, 'software');
        const ctrl = await overlapSweep(pg, 'control_previous_rule_overlap390', '.ot-bom8-coverage');
        check('F3 control: with the previous launcher rule re-applied the same probe DOES detect overlap (probe is sensitive)', ctrl.some((r) => r.hits.length > 0), JSON.stringify(ctrl.find((r) => r.hits.length) || {}));
        await pg.screenshot(join(OUT, 'control_previous_rule_390.png'));
        await pg.eval(`document.getElementById('ot-prev-rule').remove()`);
      }
    } catch (e) { if (e.message === 'DEADLINE') { unfinished.push(`${label}: deadline`); check(`${label}: finished before the deadline`, false, 'deadline'); break; } check(`${label}: state run completed`, false, e.stack || e.message); try { await pg.screenshot(join(OUT, `${label}_failure.png`)); } catch {} }
  }
  check(`${CASE}: no page errors`, pg.log.exceptions.length === 0, pg.log.exceptions.join('|'));
} catch (e) { check(`${CASE}: run completed`, false, e.stack || e.message); }
finally { try { svc && svc.stop(); } catch {} await close(); }
writeFileSync(join(OUT, `${CASE}_results.json`), JSON.stringify({ case: CASE, results, evidence, unfinished }, null, 1));
const failed = results.filter((r) => !r.ok).length;
console.log(`${results.length - failed}/${results.length} checks passed`);
process.exit(failed ? 1 : 0);
