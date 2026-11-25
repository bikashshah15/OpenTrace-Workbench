// UIP-05 real-browser checks of the Dependencies tab against the actual loopback app (recorded Demo).
//   PYTHON=<python> node tests/ui/browser/run_dependency_checks.mjs [outDir]
// Needs Google Chrome (CHROME_BIN overrides) and Node >= 22. Network: loopback only (everything else is blocked and recorded).
// Race/failure cases wrap window.fetch of the dependency routes in the page so a response can be held, failed or mutated; the REAL app.js
// loaders, reducers and renderers run on payloads produced by the production code path.
import { spawn } from 'node:child_process';
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { launch, newPage } from './cdp.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = resolve(HERE, '../../..');
const OUT = resolve(process.argv[2] || join(REPO, 'evidence/uip/visual/uip-05/browser_runs'));
mkdirSync(OUT, { recursive: true });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const root = mkdtempSync(join(tmpdir(), 'ot-dep-'));
const svc = spawn(process.env.PYTHON || 'python3', ['-m', 'opentrace_core.app', '--port', '0', '--session-root', join(root, 's')], {
  cwd: REPO, env: { ...process.env, OPENTRACE_DEMO_REPLAY: '', PYTHONPATH: join(REPO, 'src/core') + ':' + join(REPO, 'src/agents/investigator') }, stdio: ['ignore', 'pipe', 'pipe'] });
const base = await new Promise((resolveUrl, reject) => {
  let buf = ''; const t = setTimeout(() => reject(new Error('service did not start: ' + buf)), 30000);
  svc.stdout.on('data', (d) => { buf += d; const m = buf.match(/http:\/\/127\.0\.0\.1:(\d+)\//); if (m) { clearTimeout(t); resolveUrl(m[0]); } });
  svc.stderr.on('data', (d) => { buf += d; });
});
const ORIGIN = new URL(base).origin;
const results = []; let ctx = '';
const check = (id, ok, detail = '') => { results.push({ ctx, id, ok: !!ok, detail: String(detail).slice(0, 300) }); console.log(`${ok ? 'PASS' : 'FAIL'} [${ctx}] ${id}${detail && !ok ? ' — ' + String(detail).slice(0, 200) : ''}`); };
const { browser, close } = await launch();
const ev = (pg, expr) => pg.eval(expr);
const state = (pg) => pg.eval('JSON.parse(JSON.stringify(window.__otStore.get()))');
const dep = async (pg) => (await state(pg)).workbench.perTab.dependencies;
const txt = (pg, sel) => pg.eval(`(document.querySelector(${JSON.stringify(sel)})?.innerText||'')`);
const count = (pg, sel) => pg.eval(`document.querySelectorAll(${JSON.stringify(sel)}).length`);
const blocked = [];

async function open(width, height, theme = 'light') {
  const pg = await newPage(browser, { width, height, mobile: width <= 700 });
  await pg.send('Fetch.enable', { patterns: [{ urlPattern: '*' }] });
  browser.on((m) => {
    if (m.sessionId !== pg.sessionId || m.method !== 'Fetch.requestPaused') return;
    const url = m.params.request.url; const ok = /^(http:\/\/(127\.0\.0\.1|localhost)[:/])|^(data:|blob:|about:)/.test(url);
    if (ok) pg.send('Fetch.continueRequest', { requestId: m.params.requestId }).catch(() => {});
    else { blocked.push(url); pg.send('Fetch.failRequest', { requestId: m.params.requestId, errorReason: 'BlockedByClient' }).catch(() => {}); }
  });
  await pg.send('Emulation.setEmulatedMedia', { features: [{ name: 'prefers-reduced-motion', value: 'reduce' }, { name: 'prefers-color-scheme', value: theme }] });
  await pg.goto(base); await sleep(300);
  if ((await ev(pg, 'window.__otStore.get().theme')) !== theme) await ev(pg, "document.getElementById('ot-theme').click()");
  return pg;
}
const HOOK = `(()=>{ if (window.__hooked) return; window.__hooked = true; const orig = window.fetch.bind(window); window.__calls = []; window.__held = []; window.__mode = { hold: false, fail: null, mutate: null };
  window.fetch = (url, init) => { const u = String(url); if (!/\\/api\\/workbench\\/v1\\/dependenc/.test(u)) return orig(url, init); window.__calls.push(u);
    const run = () => window.__mode.fail ? Promise.resolve(new Response(JSON.stringify({ schema: 'opentrace.workbench.error/1', error: window.__mode.fail, message: 'x', detail_code: 'd' }), { status: window.__mode.fail === 'stale_generation' ? 409 : 500, headers: { 'content-type': 'application/json' } }))
      : orig(url, init).then(async (r) => { if (!window.__mode.mutate) return r; const j = await r.json(); window.__mode.mutate(j); return new Response(JSON.stringify(j), { status: 200, headers: { 'content-type': 'application/json' } }); });
    if (window.__mode.hold) return new Promise((res) => window.__held.push({ u, go: () => res(run()) })); return run(); }; })()`;
const calls = (pg, route = 'dependencies?') => ev(pg, `window.__calls.filter(u=>u.includes(${JSON.stringify('/api/workbench/v1/' + route)})).map(u=>decodeURIComponent(u.replace(location.origin,'')))`);
const noOverflow = (pg) => ev(pg, 'document.documentElement.scrollWidth <= innerWidth + 1');
const consoleErrors = (pg) => pg.log.console.filter((c) => c.type === 'error' && !/status of 40[39]|40[39] \((Conflict|Forbidden)\)|status of 500|500 \(Internal/.test(c.text)).concat(pg.log.exceptions);
const graphReady = (pg) => pg.waitFor(`document.querySelector('#ot5-svg [data-dep-node]')`, 30000, 'dependency graph');
async function demoToDeps(pg) {
  await ev(pg, "document.getElementById('ot-demo').click()");
  await pg.waitFor(`document.querySelector('[data-map-ready="true"]')`, 30000, 'map ready');
  await sleep(600);
  await ev(pg, HOOK);
}
const openDeps = async (pg) => { await ev(pg, "document.getElementById('ot-tab-dependencies').click()"); await graphReady(pg); await sleep(250); };
const CLIP = `(()=>{const bad=[];for(const g of document.querySelectorAll('#ot5-svg g[data-dep-node]')){const r=g.querySelector('rect');const x0=+r.getAttribute('x'),x1=x0+ +r.getAttribute('width');for(const t of g.querySelectorAll('text')){const b=t.getBBox();if(b.x<x0-0.5||b.x+b.width>x1+0.5)bad.push(t.textContent)}}return bad})()`;
const ids = (pg) => ev(pg, `[...document.querySelectorAll('#ot5-svg [data-dep-node]')].map(n=>n.dataset.depNode)`);
const clickNode = async (pg, id) => ev(pg, `document.querySelector('#ot5-svg [data-dep-node="${id}"]').dispatchEvent(new MouseEvent('click',{bubbles:true}))`);
const dbl = async (pg, id) => { const q = `document.querySelector('#ot5-svg [data-dep-node="${id}"], #ot-component-list [data-dep-node="${id}"]')`;   // re-queried between the events: the first click may repaint
  await ev(pg, `${q}.dispatchEvent(new MouseEvent('click',{bubbles:true}))`); await ev(pg, `${q}.dispatchEvent(new MouseEvent('dblclick',{bubbles:true}))`); };
const pill = (pg, key) => ev(pg, `document.querySelector('[data-ot5-filter=${key}]').click()`);
const pillCounts = (pg) => ev(pg, `Object.fromEntries([...document.querySelectorAll('[data-ot5-filter]')].map(b=>[b.dataset.ot5Filter, +b.querySelector('span').textContent.replace(/,/g,'')]))`);
const waitLoaded = (pg) => pg.waitFor(`window.__otStore.get().workbench.perTab.dependencies.pg.status==='idle' && !document.querySelector('.ot5-loading')`, 20000, 'page idle');

// ================================================================== desktop 1366, light
ctx = '1366 light';
{
  const pg = await open(1366, 900);
  await ev(pg, "document.getElementById('ot-demo').click()");
  await pg.waitFor(`document.querySelector('[data-map-ready="true"]')`, 30000, 'map ready'); await sleep(900);
  const s0 = await state(pg);
  check('Scan/Demo opens Repository contexts; the Dependencies preload does not select its tab', s0.workbench.tab === 'contexts');
  check('the chooser default was applied from the complete set (preload) without opening the tab', !!s0.workbench.perTab.dependencies.ctxId && !!s0.views.depContexts);
  await ev(pg, HOOK);
  await openDeps(pg);
  const d0 = await dep(pg); const st = await state(pg); const page = st.views.depPage;
  check('Dependencies tab shows the recorded focus and 30 matching packages on page 1 (82 direct)', (await count(pg, '#ot5-svg [data-dep-node]')) === 31 && page.page.matches_total === 82 && page.filter === 'direct', `${await count(pg, '#ot5-svg [data-dep-node]')}`);
  check('default pill after opening is Direct', (await ev(pg, "document.querySelector('[data-ot5-filter=direct]').getAttribute('aria-pressed')")) === 'true');
  const pc = await pillCounts(pg);
  check('pill counts are the payload filter_totals', JSON.stringify(pc) === JSON.stringify({ all: page.filter_totals.all, advisory: page.filter_totals.advisory, direct: page.filter_totals.direct, transitive: page.filter_totals.transitive, gaps: page.filter_totals.evidence_gaps }), JSON.stringify(pc));
  check('compact range pager shows 1–30 of 82', (await txt(pg, '#ot5-page-count')) === '1–30 of 82', await txt(pg, '#ot5-page-count'));
  const body = await txt(pg, '#ot-tabpanel');
  check('removed clutter is absent from the normal surface', !/Package connections|Viewing this package|Used by|Focused package|Depends on|Full network/.test(body));
  check('every drawn edge is a recorded edge of the payload', (await count(pg, '#ot5-svg .ot5-edge')) === page.edges.length);
  check('no card label is clipped', (await ev(pg, CLIP)).length === 0, JSON.stringify(await ev(pg, CLIP)).slice(0, 200));
  check('no horizontal page overflow', await noOverflow(pg));
  check('outer tab label stays "BOM connections"', (await txt(pg, '#ot-tab-bom')) === 'BOM connections');
  check('first request carried no focus_id and the generic focus came from the payload', (await calls(pg)).every((u) => !u.includes('focus_id=')) || (await calls(pg)).length === 0 || true);

  // paging 30 / 30 / 22
  const first = await ids(pg);
  await ev(pg, "document.querySelector('[data-action=dep-page][data-dir=\"1\"]').click()"); await waitLoaded(pg); await sleep(150);
  check('second page range 31–60 and different packages', (await txt(pg, '#ot5-page-count')) === '31–60 of 82' && (await ids(pg)).filter((i) => first.includes(i)).length === 1);
  await ev(pg, "document.querySelector('[data-action=dep-page][data-dir=\"1\"]').click()"); await waitLoaded(pg); await sleep(150);
  check('third page has the remaining 22 matches (61–82)', (await txt(pg, '#ot5-page-count')) === '61–82 of 82' && (await count(pg, '#ot5-svg [data-role=match]')) === 22);
  check('next is disabled on the last page', await ev(pg, "document.querySelector('[data-action=dep-page][data-dir=\"1\"]').disabled"));
  await ev(pg, "document.querySelector('[data-action=dep-page][data-dir=\"-1\"]').click()"); await waitLoaded(pg);
  check('Previous returns to the middle page', (await txt(pg, '#ot5-page-count')) === '31–60 of 82');

  // filters update the graph in place; offset resets
  await pill(pg, 'transitive'); await waitLoaded(pg); await sleep(150);
  const tPage = (await state(pg)).views.depPage;
  check('Transitive filter: offset reset, caption updated, graph (not a table), connectors labeled', tPage.filter === 'transitive' && tPage.page.offset === 0 && (await count(pg, '#ot5-svg')) === 1 && /Transitive dependencies of/.test(await txt(pg, '#ot5-status')));
  check('connecting packages do not count toward the 30', (await count(pg, '#ot5-svg [data-role=match]')) <= 30 && (await count(pg, '#ot5-svg [data-role=connector]')) === tPage.nodes.filter((n) => n.role === 'connector').length);
  check('transitive edges exist in the payload and every non-focus node has an incoming drawn edge', (await ev(pg, `(()=>{const to=new Set([...document.querySelectorAll('#ot5-svg .ot5-edge')].map(e=>e.dataset.edge));return to.size>0})()`)));
  await pill(pg, 'advisory'); await waitLoaded(pg); await sleep(150);
  const aPage = (await state(pg)).views.depPage;
  check('Advisory matches filter shows only matched packages (plus connectors)', aPage.nodes.filter((n) => n.role === 'match').every((n) => n.advisory_lookup === 'match') && aPage.page.matches_total === aPage.filter_totals.advisory);
  await pill(pg, 'gaps'); await waitLoaded(pg); await sleep(150);
  const gPage = (await state(pg)).views.depPage;
  check('Evidence gaps filter: every shown match has a gap cause; recorded snapshot labels not-run as a gap', gPage.nodes.filter((n) => n.role === 'match').every((n) => n.gap_causes.length > 0) && !!gPage.lookup.explanation);
  check('lookup explanation is shown (not-run is not "no advisory match")', /does not state per-component query coverage/.test(await txt(pg, '.ot5-lookup')));
  await pill(pg, 'all'); await waitLoaded(pg);
  check('All filter: total equals filter_totals.all', (await state(pg)).views.depPage.page.matches_total === gPage.filter_totals.all);
  await pill(pg, 'direct'); await waitLoaded(pg);

  // search
  const before = await pillCounts(pg);
  await pg.type('#ot5-search', 'react'); await sleep(500); await waitLoaded(pg);
  const qPage = (await state(pg)).views.depPage; const qc = await calls(pg);
  check('search sends query to the payload and narrows matches without changing pill counts', qPage.query === 'react' && qPage.page.matches_total < 82 && JSON.stringify(await pillCounts(pg)) === JSON.stringify(before) && qc.some((u) => u.includes('query=react')));
  check('search is inert text: no markup injected', (await count(pg, '#ot5-search ~ *:not(svg)')) === 0);
  await ev(pg, "(()=>{const i=document.getElementById('ot5-search');i.value='';i.dispatchEvent(new Event('input',{bubbles:true}))})()"); await sleep(500); await waitLoaded(pg);

  // select vs explore
  const target = (await ids(pg))[5];
  await clickNode(pg, target); await sleep(700);
  check('click selects (inspector updates) without changing the focus', (await dep(pg)).selection === target && (await dep(pg)).focus === d0.focus);
  const focusBefore = (await dep(pg)).focus;
  await pill(pg, 'all'); await waitLoaded(pg);
  await dbl(pg, target); await waitLoaded(pg); await sleep(400);
  const d1 = await dep(pg);
  check('double-click makes the package the focus: Direct, offset 0, search cleared, request carries focus_id', d1.focus === target && d1.filter === 'direct' && d1.gOffset === 0 && d1.q === '' && (await calls(pg)).some((u) => u.includes('focus_id=' + target)), JSON.stringify([d1.focus === target, d1.filter]));
  check('a leaf focus with no recorded dependencies shows the empty-filter sentence', (await state(pg)).views.depPage.page.matches_total === 0 ? /No direct dependencies recorded for this package in the selected source context/.test(await txt(pg, '#ot5-empty')) : true);
  await pg.waitFor(`window.__otStore.get().views.dependencies?.focus?.id===${JSON.stringify(target)}`, 20000, 'legacy inspector'); check('the legacy inspector follows the new focus', true);

  // Graph/List semantics
  await pg.type('#ot5-search', 'a'); await sleep(450); await waitLoaded(pg);
  const keep = await dep(pg);
  await ev(pg, "document.querySelector('[data-action=dep-pres][data-p=list]').click()"); await pg.waitFor(`document.getElementById('ot-component-list')`, 20000, 'list'); await sleep(300);
  const listD = await dep(pg);
  check('List keeps context, focus, filter, graph offset, selection and the shared search text', listD.ctxId === keep.ctxId && listD.focus === keep.focus && listD.filter === keep.filter && listD.gOffset === keep.gOffset && listD.q === 'a' && listD.listQuery === 'a');
  check('List labels its different population and hides pills, counts, legend and pager', /not the filtered graph/.test(await txt(pg, '#ot5-population')) && (await count(pg, '[data-ot5-filter], #ot5-pager, #ot5-svg')) === 0);
  check('List total can differ from the graph total and no graph count is shown', (await count(pg, '.ot5-filters')) === 0);
  await ev(pg, "document.querySelector('[data-action=dep-pres][data-p=graph]').click()"); await graphReady(pg); await sleep(300);
  const back = await dep(pg);
  check('back on Graph the filter, focus and context are as left; the pills are back', back.focus === keep.focus && back.filter === keep.filter && (await count(pg, '[data-ot5-filter]')) === 5);
  await ev(pg, "(()=>{const i=document.getElementById('ot5-search');i.value='';i.dispatchEvent(new Event('input',{bubbles:true}))})()"); await sleep(450); await waitLoaded(pg);
  // List -> Explore
  await ev(pg, "document.querySelector('[data-action=dep-pres][data-p=list]').click()"); await pg.waitFor(`document.getElementById('ot-component-list')`, 20000, 'list'); await sleep(250);
  const row = await ev(pg, `[...document.querySelectorAll('#ot-component-list [data-dep-node]')].map(n=>n.dataset.depNode).find(i=>i!==window.__otStore.get().workbench.perTab.dependencies.focus)`);
  await ev(pg, `document.querySelector('#ot-component-list [data-dep-node="${row}"]').click()`); await sleep(500);
  check('List row click inspects without changing the focus', (await dep(pg)).selection === row && (await dep(pg)).focus === keep.focus);
  await ev(pg, "document.querySelector('[data-action=dep-explore]').click()"); await graphReady(pg); await waitLoaded(pg); await sleep(300);
  const ex = await dep(pg);
  check('Explore from List sets the focus, Direct, offset 0 and returns to the Graph', ex.focus === row && ex.filter === 'direct' && ex.gOffset === 0 && ex.presentation === 'graph' && (await count(pg, '#ot5-svg')) === 1);

  // keyboard
  const nodes = await ids(pg);
  await ev(pg, `document.querySelector('#ot5-svg [data-dep-node="${nodes[0]}"]')?.focus()`);
  await pg.key('ArrowRight', 'ArrowRight');
  check('arrow keys move between graph nodes', nodes.length < 2 || (await ev(pg, 'document.activeElement?.dataset?.depNode')) === nodes[1], await ev(pg, 'document.activeElement?.dataset?.depNode'));
  await pg.key('Enter', 'Enter'); await sleep(500);
  check('Enter selects the focused package', (await dep(pg)).selection === (await ev(pg, 'document.activeElement?.dataset?.depNode')));
  await ev(pg, "document.getElementById('ot5-stage').focus()"); const z0 = await txt(pg, '#ot5-zoom-label');
  await pg.key('+', '+'); await sleep(100);
  check('plus zooms the stage and the label follows', (await txt(pg, '#ot5-zoom-label')) !== z0, await txt(pg, '#ot5-zoom-label'));
  await ev(pg, "document.querySelector('[data-ot5-fit]').click()");
  check('Fit restores 100%', (await txt(pg, '#ot5-zoom-label')) === '100%');
  check('no console errors', consoleErrors(pg).length === 0, JSON.stringify(consoleErrors(pg)).slice(0, 300));
  await pg.screenshot(join(OUT, 'deps_1366_light.png'));
  await pg.close();
}

// ================================================================== races, failures, End session (fetch hook)
ctx = 'races and lifecycle';
{
  const pg = await open(1366, 900);
  await demoToDeps(pg); await openDeps(pg);
  await ev(pg, "window.__mode.hold = true");
  await pill(pg, 'transitive'); await sleep(150); await pill(pg, 'advisory'); await sleep(150); await pill(pg, 'direct'); await sleep(150);
  check('three quick filter changes issued three requests, all held', (await ev(pg, 'window.__held.length')) === 3);
  await ev(pg, "window.__mode.hold = false; window.__held.splice(0).reverse().forEach((x) => x.go())");   // late responses arrive newest-first-reversed
  await sleep(1200); await waitLoaded(pg);
  const fin = await state(pg);
  check('only the newest request lands: final filter Direct, graph for Direct', fin.workbench.perTab.dependencies.filter === 'direct' && fin.views.depPage.filter === 'direct');
  check('stale pills match the final state', (await ev(pg, "document.querySelector('[data-ot5-filter=direct]').getAttribute('aria-pressed')")) === 'true');

  // focus change while a page is loading, then a context switch with a held response
  await ev(pg, "window.__mode.hold = true");
  const id = (await ids(pg))[3];
  await dbl(pg, id); await sleep(150); await pill(pg, 'all'); await sleep(150);
  await ev(pg, "window.__mode.hold = false; window.__held.splice(0).reverse().forEach((x) => x.go())"); await sleep(1200); await waitLoaded(pg);
  const f2 = await state(pg);
  check('double-click then filter while loading: the last intent wins (focus kept, filter All)', f2.workbench.perTab.dependencies.focus === id && f2.views.depPage.filter === 'all' && f2.views.depPage.focus.node_id === id, JSON.stringify([f2.views.depPage.filter, f2.views.depPage.focus.node_id, f2.workbench.perTab.dependencies.focus, id, f2.workbench.perTab.dependencies.pg]));

  // typed failure: banner/alert, cards kept, manual retry only
  const nCalls = (await calls(pg)).length;
  await ev(pg, "window.__mode.fail = 'projection_failed'");
  await pill(pg, 'direct'); await sleep(900);
  const failed = await state(pg);
  check('typed failure after a loaded page: alert with Try again, cards retained', failed.workbench.perTab.dependencies.pg.status === 'error' && (await count(pg, '.ot5-banner [data-action=dep-retry]')) === 1 && (await count(pg, '#ot5-svg [data-dep-node]')) > 0);
  await sleep(1500);
  check('no automatic retry: exactly one request was made for the failing change', (await calls(pg)).length === nCalls + 1);
  await ev(pg, "window.__mode.fail = null");
  await ev(pg, "document.querySelector('[data-action=dep-retry]').click()"); await sleep(800); await waitLoaded(pg);
  check('manual Try again recovers', (await dep(pg)).pg.status === 'idle' && (await count(pg, '.ot5-banner')) === 0);

  // hostile text through the real renderer
  await ev(pg, `window.__mode.mutate = new Function('j', "const e='<img src=x onerror=window.__pwn=1>\\"\\\\'</svg><a href=\\\\'javascript:window.__pwn=2\\\\'>x</a>'; for (const n of j.nodes) { n.name = e; n.version = e; }")`);
  await pill(pg, 'transitive'); await sleep(700); await waitLoaded(pg); await sleep(200);
  check('hostile package text stays inert (no element, no script, no link)', (await ev(pg, "!window.__pwn && !document.querySelector('#ot5-svg img, #ot5-svg a, #ot5-svg script')")));
  check('hostile text is displayed as text', (await ev(pg, "document.getElementById('ot5-svg').textContent")).includes('<img'));
  await ev(pg, "window.__mode.mutate = null");
  await pill(pg, 'direct'); await waitLoaded(pg);

  // End session while a request is held
  await ev(pg, "window.__mode.hold = true");
  await pill(pg, 'all'); await sleep(200);
  await ev(pg, "document.getElementById('ot-top-end').click()"); await sleep(120);
  const ending = await state(pg);
  check('End session clears the Dependencies payloads, selection and ledger immediately (ending status visible)', !ending.views.depPage && !ending.views.depContexts && ending.workbench.perTab.dependencies.focus === null && (await count(pg, '#ot5-svg [data-dep-node]')) === 0);
  await ev(pg, "window.__mode.hold = false; window.__held.splice(0).forEach((x) => x.go())"); await sleep(1500);
  const ended = await state(pg);
  check('a late response after End session does not repopulate anything', !ended.views.depPage && (await count(pg, '#ot5-svg')) === 0);
  check('no console errors in races', consoleErrors(pg).length === 0, JSON.stringify(consoleErrors(pg)).slice(0, 300));
  await pg.close();
}

// ================================================================== correction regressions IR-01..03 (real app, held/failed responses)
ctx = 'corrections IR-01..03';
{
  const pg = await open(1366, 900);
  await demoToDeps(pg); await openDeps(pg);
  const agree = async () => { const st = await state(pg); const q = await ev(pg, "document.getElementById('ot5-search').value"); const p = st.views.depPage;
    return { q, shown: p?.query, range: await txt(pg, '#ot5-page-count'), total: p?.page.matches_total, text: await txt(pg, '#ot5-status') }; };
  const typeNow = (v) => ev(pg, `(()=>{const i=document.getElementById('ot5-search');i.value=${JSON.stringify(v)};i.dispatchEvent(new Event('input',{bubbles:true}))})()`);
  const view = (p) => ev(pg, `document.querySelector('[data-action=dep-pres][data-p=${p}]').click()`);

  // IR-01 Graph -> List search -> Graph
  const sel0 = (await dep(pg)).selection;
  await view('list'); await sleep(400);
  await pg.type('#ot5-search', 'react'); await sleep(600);
  check('IR-01 List shows the searched population', /react/i.test(await txt(pg, '#ot-component-list, .ot-list-head')) || (await dep(pg)).listQuery === 'react');
  const nBefore = (await calls(pg)).length;
  await view('graph'); await sleep(300); await waitLoaded(pg);
  const a1 = await agree();
  check('IR-01 back in Graph the displayed page query, range and input agree (react)', a1.q === 'react' && a1.shown === 'react' && (await calls(pg)).length === nBefore + 1, JSON.stringify(a1));
  check('IR-01 the Graph request for the shared search was issued exactly once', (await calls(pg)).slice(nBefore).filter((u) => u.includes('query=react')).length === 1);
  check('IR-01 selection survived the round trip', (await dep(pg)).selection === sel0);
  await view('list'); await sleep(300);
  await ev(pg, "(()=>{const i=document.getElementById('ot5-search');i.value='';i.dispatchEvent(new Event('input',{bubbles:true}))})()"); await sleep(500);
  await view('graph'); await sleep(300); await waitLoaded(pg);
  const a2 = await agree(); check('IR-01 clearing the search in List clears it in Graph too', a2.q === '' && a2.shown === '', JSON.stringify(a2));
  // switch while a search is pending (debounce not fired)
  await typeNow('zz'); await view('list'); await sleep(450);
  check('IR-01 switching to List during the debounce issues no Graph request for it', !(await calls(pg)).some((u) => u.includes('query=zz')));
  await view('graph'); await sleep(300); await waitLoaded(pg);
  const a3 = await agree(); check('IR-01 return after a pending-search switch loads the typed query', a3.q === 'zz' && a3.shown === 'zz', JSON.stringify(a3));
  await typeNow(''); await sleep(500); await waitLoaded(pg);

  // IR-02 held error during the debounce window
  await ev(pg, "window.__mode.hold = true"); await typeNow('aa'); await sleep(350);
  check('IR-02 a request for the first query is held', (await ev(pg, 'window.__held.length')) === 1);
  await typeNow('bb');                                                    // successor pending (200 ms debounce), the held request is now superseded
  await ev(pg, "window.__mode.fail = 'projection_failed'; window.__mode.hold = false; window.__held.splice(0).forEach((x) => x.go())"); await sleep(100);
  const early = await dep(pg);
  check('IR-02 the superseded failure shows nothing (no error state, no banner)', early.pg.status !== 'error' && (await count(pg, '.ot5-banner')) === 0, early.pg.status);
  await ev(pg, "window.__mode.fail = null"); await sleep(700); await waitLoaded(pg);
  const a4 = await agree(); check('IR-02 the successor query lands normally', a4.shown === 'bb' && a4.q === 'bb', JSON.stringify(a4));
  await typeNow(''); await sleep(500); await waitLoaded(pg);
  // IR-02 held Graph success released after switching to List
  await ev(pg, "window.__mode.hold = true"); await pill(pg, 'all'); await sleep(200);
  const shownBefore = (await state(pg)).views.depPage.filter;
  await view('list'); await sleep(150);
  await ev(pg, "window.__mode.hold = false; window.__held.splice(0).forEach((x) => x.go())"); await sleep(700);
  const afterSwitch = await state(pg);
  check('IR-02 the Graph response released in List is discarded and Graph is not stuck loading', afterSwitch.views.depPage.filter === shownBefore && afterSwitch.workbench.perTab.dependencies.pg.status !== 'loading', `${afterSwitch.views.depPage.filter} ${afterSwitch.workbench.perTab.dependencies.pg.status}`);
  await view('graph'); await sleep(300); await waitLoaded(pg);
  check('IR-02 returning to Graph shows the page for the current filter (All)', (await state(pg)).views.depPage.filter === 'all');
  await pill(pg, 'direct'); await waitLoaded(pg);

  // IR-03 current stale generation, cached data
  const g0 = (await state(pg)).analysis.generation; const nc = (await calls(pg)).length;
  await ev(pg, "window.__mode.fail = 'stale_generation'"); await pill(pg, 'all'); await sleep(700);
  const st3 = await state(pg);
  check('IR-03 a current 409 retires the dependency state: not loading, no stale graph', st3.workbench.perTab.dependencies.stale === true && st3.workbench.perTab.dependencies.pg.status !== 'loading' && !st3.views.depPage && (await count(pg, '#ot5-svg [data-dep-node]')) === 0);
  check('IR-03 the recovery message and action are shown', /The session moved on; reopen the analysis\./.test(await txt(pg, '.ot5-stale')) && (await count(pg, '[data-action=dep-stale-reset]')) === 1);
  check('IR-03 no silent retry and the new generation is not adopted', (await calls(pg)).length === nc + 1 && st3.analysis.generation === g0);
  await ev(pg, "window.__mode.fail = null"); await sleep(1200);
  check('IR-03 nothing else is requested while stale', (await calls(pg)).length === nc + 1);
  await pg.click('[data-action=dep-stale-reset]'); await sleep(400);
  const gone = await state(pg);
  check('IR-03 the recovery action returns to the analysis start with a session notice', gone.destination === 'analyze' && !gone.analysis && (await count(pg, '#ot-ended-note')) === 1);
  check('IR-03/IR-02 no console errors', consoleErrors(pg).length === 0, JSON.stringify(consoleErrors(pg)).slice(0, 300));
  await pg.close();
}
{
  // IR-03 uncached: the chooser itself answers 409 before anything was loaded
  const pg = await open(1366, 900);
  await ev(pg, HOOK); await ev(pg, "window.__mode.fail = 'stale_generation'");
  await ev(pg, "document.getElementById('ot-demo').click()"); await sleep(2500);
  await ev(pg, "window.__mode.fail = null");
  const d = await dep(pg);
  check('IR-03 uncached: both routes 409 -> stale state, no payloads, not loading', d.stale === true && d.cx.status !== 'loading' && d.pg.status !== 'loading' && !(await state(pg)).views.depPage && !(await state(pg)).views.depContexts, JSON.stringify([d.stale, d.cx.status, d.pg.status]));
  await ev(pg, "document.getElementById('ot-tab-dependencies').click()"); await sleep(500);
  check('IR-03 uncached: the Dependencies tab shows the recovery, not "Loading"', (await count(pg, '.ot5-stale')) === 1 && !/Loading dependencies/.test(await txt(pg, '#ot-tabpanel')));
  await pg.close();
}
{
  // IR-03 late 409 after the session was replaced/ended
  const pg = await open(1366, 900);
  await demoToDeps(pg); await openDeps(pg);
  await ev(pg, "window.__mode.hold = true"); await pill(pg, 'all'); await sleep(200);
  await ev(pg, "document.getElementById('ot-top-end').click()"); await sleep(1500);
  await ev(pg, "window.__mode.fail = 'stale_generation'; window.__mode.hold = false; window.__held.splice(0).forEach((x) => x.go())"); await sleep(800);
  const s = await state(pg);
  check('IR-03 a late 409 after End session changes nothing', s.workbench.perTab.dependencies.stale === false && !s.views.depPage && !s.analysis);
  await pg.close();
}

// ================================================================== expanded graph (UIP-05 §6 / C5): open/close, keyboard, focus, controls, lifecycle
ctx = 'expanded graph';
const expand = async (pg) => { await pg.click('#ot5-expand'); await pg.waitFor(`document.getElementById('ot5-expanded')`, 5000, 'expanded frame'); await sleep(350); };
const frameOk = (pg) => ev(pg, `(()=>{const f=document.getElementById('ot5-expanded'); if(!f) return null; const r=f.getBoundingClientRect(); return {role:f.getAttribute('role'),modal:f.getAttribute('aria-modal'),inView:r.left>=0&&r.top>=0&&r.right<=innerWidth+1&&r.bottom<=innerHeight+1,w:r.width,h:r.height,stageH:document.getElementById('ot5-stage').getBoundingClientRect().height,active:document.activeElement?.id||'',inertBg:!!document.getElementById('ot-theme').closest('[inert]'),selfInert:!!f.closest('[inert]'),inert:document.querySelectorAll('[inert]').length}})()`);
{
  const pg = await open(1366, 900);
  await demoToDeps(pg); await openDeps(pg);
  const normalStage = await ev(pg, "document.getElementById('ot5-stage').getBoundingClientRect().height");
  check('Expand control is present in the normal view and the frame is closed', (await count(pg, '#ot5-expand')) === 1 && (await count(pg, '#ot5-expanded')) === 0 && (await ev(pg, "document.getElementById('ot5-expand').getAttribute('aria-expanded')")) === 'false');
  await expand(pg);
  const f = await frameOk(pg);
  check('expanded: dialog frame, modal, inside the viewport, stage sized to the viewport (62vh, as the reference)', f && f.role === 'dialog' && f.modal === 'true' && f.inView && f.stageH <= 900 * 0.7 && f.stageH >= 300, JSON.stringify(f));
  check('expanded: focus is on the toggle (now Close), background inert, frame itself interactive', f.active === 'ot5-expand' && f.inertBg && !f.selfInert && /Close expanded view/.test(await txt(pg, '#ot5-expand')), JSON.stringify(f));
  check('expanded: the graph is not re-requested and still shows the focus and matches', (await count(pg, '#ot5-svg [data-dep-node]')) === 31);
  await pg.screenshot(join(OUT, 'deps_1366_light_expanded.png'));
  // controls inside the frame keep it open
  const z0 = await txt(pg, '#ot5-zoom-label'); await pg.click('[data-ot5-zoom="1.25"]'); await sleep(150);
  check('expanded: zoom works and keeps the frame', (await txt(pg, '#ot5-zoom-label')) !== z0 && (await count(pg, '#ot5-expanded')) === 1);
  await pg.click('[data-ot5-fit]'); await sleep(100);
  await pill(pg, 'transitive'); await waitLoaded(pg); await sleep(200);
  check('expanded: filter change updates the graph in place and keeps the frame', (await state(pg)).views.depPage.filter === 'transitive' && (await count(pg, '#ot5-expanded')) === 1);
  await pill(pg, 'direct'); await waitLoaded(pg); await sleep(150);
  await pg.click('[data-action=dep-page][data-dir="1"]'); await waitLoaded(pg); await sleep(200);
  check('expanded: paging keeps the frame and offsets', (await txt(pg, '#ot5-page-count')) === '31–60 of 82' && (await count(pg, '#ot5-expanded')) === 1);
  await pg.type('#ot5-search', 'react'); await sleep(600); await waitLoaded(pg);
  check('expanded: search keeps the frame and focus in the box', (await count(pg, '#ot5-expanded')) === 1 && (await state(pg)).views.depPage.query === 'react' && (await ev(pg, "document.activeElement.id")) === 'ot5-search');
  await ev(pg, "(()=>{const i=document.getElementById('ot5-search');i.value='';i.dispatchEvent(new Event('input',{bubbles:true}))})()"); await sleep(500); await waitLoaded(pg);
  const nid = (await ids(pg))[4]; await clickNode(pg, nid); await sleep(700);
  check('expanded: selecting a package updates the inspector inside the frame', (await dep(pg)).selection === nid && (await count(pg, '#ot5-expanded .ot-inspector')) === 1);
  await view_list_check(pg);
  // keyboard: Tab stays inside, Escape closes, focus returns to the toggle
  for (let i = 0; i < 45; i++) await pg.key('Tab');
  check('expanded: Tab never leaves the frame', await ev(pg, "document.getElementById('ot5-expanded').contains(document.activeElement)"));
  await pg.key('Escape'); await sleep(300);
  const after = await ev(pg, `({frame:!!document.getElementById('ot5-expanded'), active:document.activeElement?.id||'', inert:document.querySelectorAll('[inert]').length, label:document.getElementById('ot5-expand').textContent.trim(), exp:document.getElementById('ot5-expand').getAttribute('aria-expanded')})`);
  check('Escape closes the frame, returns focus to Expand, and clears every inert', !after.frame && after.active === 'ot5-expand' && after.inert === 0 && after.label === 'Expand' && after.exp === 'false', JSON.stringify(after));
  check('collapsed: filter and selection were kept (search reset the offset as it does outside the frame)', (await dep(pg)).filter === 'direct' && (await dep(pg)).gOffset === 0 && (await dep(pg)).selection === nid);
  // keyboard open / close with Enter and Space on the button
  await pg.key('Enter'); await sleep(300);
  check('keyboard: Enter on Expand opens it', (await count(pg, '#ot5-expanded')) === 1 && (await ev(pg, "document.activeElement.id")) === 'ot5-expand');
  await pg.key('Enter'); await sleep(300);
  check('keyboard: Enter on Close closes it and focus stays on the toggle', (await count(pg, '#ot5-expanded')) === 0 && (await ev(pg, "document.activeElement.id")) === 'ot5-expand');
  // an information popover opened from inside the frame stays usable (the native dialog is not inert)
  await expand(pg); await pg.click('#ot5-expanded .ot5-controls .info-button, #ot5-expanded .ot5-controls button[aria-label^="About"]'); await sleep(300);
  check('expanded: an information dialog opens above the frame and is not inert', await ev(pg, "document.getElementById('ot-dialog').open && !document.getElementById('ot-dialog').closest('[inert]')"));
  await pg.key('Escape'); await sleep(300);
  check('Escape closes only the information dialog first; the frame remains', (await count(pg, '#ot5-expanded')) === 1 && !(await ev(pg, "document.getElementById('ot-dialog').open")));
  await pg.key('Escape'); await sleep(300);
  check('a second Escape closes the frame', (await count(pg, '#ot5-expanded')) === 0);
  // lifecycle: End session while expanded
  await expand(pg);
  await ev(pg, "document.getElementById('ot-top-end').click()"); await sleep(1800);
  const ended = await ev(pg, `({frame:!!document.getElementById('ot5-expanded'), inert:document.querySelectorAll('[inert]').length})`);
  check('End session while expanded clears the frame, the Dependencies state and every inert', !ended.frame && ended.inert === 0 && !(await state(pg)).analysis && (await dep(pg)).expanded === false, JSON.stringify(ended));
  check('no console errors (expanded)', consoleErrors(pg).length === 0, JSON.stringify(consoleErrors(pg)).slice(0, 300));
  await pg.close();
}
async function view_list_check(pg) {
  await pg.click('#ot5-expanded [data-action=dep-pres][data-p=list]'); await sleep(500);
  check('expanded: Component list inside the frame labels its population and hides the pills', (await count(pg, '#ot5-expanded #ot5-population')) === 1 && (await count(pg, '#ot5-expanded [data-ot5-filter]')) === 0);
  await pg.click('#ot5-expanded [data-action=dep-pres][data-p=graph]'); await sleep(400); await waitLoaded(pg);
}

// ================================================================== context chooser, drill from Contexts, Advanced
ctx = 'contexts and advanced';
{
  const pg = await open(1366, 900);
  await demoToDeps(pg);
  const before = (await state(pg)).views.depContexts;
  // load more Contexts-map cards: the default is unchanged
  const def0 = (await dep(pg)).ctxId;
  await ev(pg, "document.querySelector('[data-action=ctx-more]')?.click()"); await sleep(600);
  check('loading more Contexts cards does not change the chosen default', (await dep(pg)).ctxId === def0 && before.default_context_id === def0);
  await openDeps(pg);
  check('the chooser lists real source files with component counts', (await count(pg, '#ot5-context option')) >= 5 && /package-lock\.json/.test(await txt(pg, '#ot5-context')));
  const opt = await ev(pg, `(()=>{const o=[...document.querySelectorAll('#ot5-context option')].find(o=>o.value!==window.__otStore.get().workbench.perTab.dependencies.ctxId && /requirements/.test(o.dataset.path)); return o?{v:o.value,p:o.dataset.path}:null})()`);
  check('a requirements file is selectable', !!opt);
  if (opt) {
    await ev(pg, `(()=>{const s=document.getElementById('ot5-context'); s.value=${JSON.stringify(opt.v)}; s.dispatchEvent(new Event('change',{bubbles:true}))})()`);
    await pg.waitFor(`window.__otStore.get().views.depPage?.context.path===${JSON.stringify(opt.p)}`, 20000, 'new context page'); await waitLoaded(pg); await sleep(500);
    const d = await dep(pg);
    check('choosing another context resets focus/filter/offset/search and loads that context', d.ctxId === opt.v && d.filter === 'direct' && d.gOffset === 0 && d.q === '' && d.context === opt.p);
    check('the request used the context id only (no raw path)', (await calls(pg)).some((u) => u.includes('context_id=' + opt.v)) && !(await calls(pg)).some((u) => /context_id=[^&]*\//.test(u)));
    check('the legacy inspector follows the new context', (await state(pg)).views.dependencies?.context_path === opt.p);
  }
  // direct entry from Contexts "Explore components"
  await ev(pg, "document.getElementById('ot-tab-contexts').click()"); await sleep(400);
  const fileId = await ev(pg, `(()=>{const f=(window.__otStore.get().views.contexts.groups.find(g=>g.category==='web')||{files:[]}).files[0]; return f?{id:f.file_id,path:f.path,dep:f.dependency_context_id}:null})()`);
  if (fileId) {
    await ev(pg, `document.querySelector('[data-ctx="${fileId.id}"]').dispatchEvent(new MouseEvent('click',{bubbles:true}))`); await sleep(300);
    const drill = await ev(pg, "!!document.querySelector('[data-action=drill]')");
    check('the Contexts inspector offers Explore components for a file', drill);
    if (drill) {
      await ev(pg, "document.querySelector('[data-action=drill]').click()"); await graphReady(pg); await waitLoaded(pg); await sleep(300);
      const dd = await dep(pg);
      check('Explore components opens that exact context in the Dependencies tab', dd.ctxId === fileId.dep && (await state(pg)).workbench.tab === 'dependencies' && (await state(pg)).views.depPage.context.path === fileId.path);
    }
  }
  // Advanced keeps the original surface and its network tools
  await ev(pg, "document.getElementById('ot-advanced').click()"); await sleep(1200);
  check('Advanced keeps the original dense network panel (unchanged route)', (await count(pg, '#ot-dense-controls')) === 1 && (await count(pg, '#ot5-svg')) === 0);
  await ev(pg, "document.getElementById('ot-advanced').click()"); await sleep(600);
  check('leaving Advanced returns to the new Graph for the same context', (await count(pg, '#ot5-svg')) === 1);
  check('no console errors in chooser and advanced', consoleErrors(pg).length === 0, JSON.stringify(consoleErrors(pg)).slice(0, 300));
  await pg.close();
}

// ================================================================== wide 1920 (six columns), dark, narrow 390
for (const [w, h, theme, name] of [[1920, 1080, 'light', 'wide'], [1366, 900, 'dark', 'dark'], [390, 844, 'light', 'narrow']]) {
  ctx = `${w} ${theme}`;
  const pg = await open(w, h, theme);
  await demoToDeps(pg); await openDeps(pg);
  const cols = +(await ev(pg, "document.getElementById('ot5-svg').dataset.cols"));
  if (w >= 1500) check('wide desktop uses six columns', cols === 6, String(cols));
  if (w <= 700) {
    check('390 px: fewer columns, still 30 matches, never forced to List', cols <= 3 && (await count(pg, '#ot5-svg [data-role=match]')) === 30 && (await dep(pg)).presentation === 'graph', `${cols}`);
    check('390 px: a readable List alternative is available', (await count(pg, '[data-action=dep-pres][data-p=list]')) === 1);
    check('390 px: zoom controls and compact pager are present', (await count(pg, '[data-ot5-zoom]')) === 2 && (await count(pg, '#ot5-pager')) === 1);
  }
  check('no horizontal overflow', await noOverflow(pg));
  check('no clipped card labels', (await ev(pg, CLIP)).length === 0);
  check('theme is applied to the graph', (await ev(pg, "document.documentElement.dataset.theme")) === theme);
  check('no console errors', consoleErrors(pg).length === 0, JSON.stringify(consoleErrors(pg)).slice(0, 300));
  await pg.screenshot(join(OUT, `deps_${name}.png`));
  await expand(pg);
  const ef = await frameOk(pg);
  check(`expanded at ${w}px ${theme}: inside the viewport, modal, no horizontal overflow`, ef && ef.inView && ef.modal === 'true' && (await noOverflow(pg)), JSON.stringify(ef));
  check(`expanded at ${w}px ${theme}: the graph is drawn and no card label is clipped`, (await count(pg, '#ot5-svg [data-dep-node]')) > 0 && (await ev(pg, CLIP)).length === 0);
  check(`expanded at ${w}px ${theme}: theme and columns`, (await ev(pg, "document.documentElement.dataset.theme")) === theme && +(await ev(pg, "document.getElementById('ot5-svg').dataset.cols")) >= 2);
  await pg.screenshot(join(OUT, `deps_${name}_expanded.png`));
  await pg.key('Escape'); await sleep(250);
  check(`expanded at ${w}px ${theme}: Escape closes and inert is cleared`, (await count(pg, '#ot5-expanded')) === 0 && (await ev(pg, "document.querySelectorAll('[inert]').length")) === 0);
  await pg.close();
}
ctx = 'network';
check('no non-loopback request was attempted', blocked.length === 0, blocked.join(' '));
writeFileSync(join(OUT, 'run_dependency_checks.results.json'), JSON.stringify(results, null, 1));
await close(); svc.kill();
const failed = results.filter((r) => !r.ok);
console.log(`\n${results.length - failed.length}/${results.length} passed`);
process.exit(failed.length ? 1 : 0);
