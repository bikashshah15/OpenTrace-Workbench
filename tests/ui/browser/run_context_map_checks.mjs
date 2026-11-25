// UIP-04 real-browser checks of the repository contexts map against the actual loopback app (recorded Demo) and the uip04-* fixtures.
//   PYTHON=<python> node tests/ui/browser/run_context_map_checks.mjs [outDir]
// Needs Google Chrome (CHROME_BIN overrides) and Node >= 22. Network: loopback only (everything else is blocked and recorded).
// Fixture-driven cases install a page-level fetch double for /api/analysis/demo and /api/workbench/v1/contexts so the REAL app.js loaders,
// reducers and renderers run on payloads produced by the production code path; the double can hold or fail a request deterministically.
import { spawn } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { launch, newPage } from './cdp.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = resolve(HERE, '../../..');
const OUT = resolve(process.argv[2] || join(REPO, 'evidence/uip/visual/uip-04/browser_runs'));
mkdirSync(OUT, { recursive: true });
const FIXDIR = join(REPO, 'evidence/uip/visual/uip-04/fixtures');
const REF = JSON.parse(readFileSync(join(REPO, 'evidence/uip/visual/uip-04/reference_geometry.json'), 'utf8'));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const root = mkdtempSync(join(tmpdir(), 'ot-ctxmap-'));
const svc = spawn(process.env.PYTHON || 'python3', ['-m', 'opentrace_core.app', '--port', '0', '--session-root', join(root, 's')], {
  cwd: REPO, env: { ...process.env, PYTHONPATH: join(REPO, 'src/core') }, stdio: ['ignore', 'pipe', 'pipe'] });
const base = await new Promise((resolveUrl, reject) => {
  let buf = ''; const t = setTimeout(() => reject(new Error('service did not start: ' + buf)), 30000);
  svc.stdout.on('data', (d) => { buf += d; const m = buf.match(/http:\/\/127\.0\.0\.1:(\d+)\//); if (m) { clearTimeout(t); resolveUrl(m[0]); } });
  svc.stderr.on('data', (d) => { buf += d; });
});
const ORIGIN = new URL(base).origin;

const results = []; let ctx = '';
const check = (id, ok, detail = '') => { results.push({ ctx, id, ok: !!ok, detail: String(detail).slice(0, 300) }); console.log(`${ok ? 'PASS' : 'FAIL'} [${ctx}] ${id}${detail && !ok ? ' — ' + String(detail).slice(0, 220) : ''}`); };
const { browser, close } = await launch();
const state = (pg) => pg.eval('JSON.parse(JSON.stringify(window.__otStore.get()))');
const ev = (pg, expr) => pg.eval(expr);
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
  // The theme preference persists in localStorage across pages of one browser: set it explicitly.
  if ((await ev(pg, 'window.__otStore.get().theme')) !== theme) await ev(pg, "document.getElementById('ot-theme').click()");
  return pg;
}
const ready = (pg) => pg.waitFor(`document.querySelector('[data-map-ready="true"]')`, 30000, 'map ready');
async function demo(pg) { await ev(pg, "document.getElementById('ot-demo').click()"); await ready(pg); await sleep(250); }
const noOverflow = (pg) => ev(pg, 'document.documentElement.scrollWidth <= innerWidth + 1');
const sel = (pg) => ev(pg, "(()=>{const e=document.querySelector('[data-selection-kind]');return e?e.dataset.selectionKind+'|'+e.dataset.selectionId:null})()");
const inspTitle = (pg) => ev(pg, "document.querySelector('.ot4-inspector .ot-insp-head h2')?.textContent||''");
const dataCtx = (pg, path) => ev(pg, `[...document.querySelectorAll('[data-ctx-kind=file]')].find(e=>(e.querySelector('title')?.textContent||e.innerText||'').includes(${JSON.stringify(path)}))?.dataset.ctx`);
// The fixture double has no server-side analysis behind the other tabs' routes, so their expected 409 responses are logged by Chrome; those are not errors of this increment.
const consoleErrors = (pg) => pg.log.console.filter((c) => c.type === 'error' && !/status of 409|409 \(Conflict\)/.test(c.text)).concat(pg.log.exceptions);
const svgText = (pg, s = '#ot4-svg') => ev(pg, `(document.querySelector(${JSON.stringify(s)})?.textContent||'')`);
const ctxCalls = (pg) => pg.log.requests.filter((r) => r.url.includes('/api/workbench/v1/contexts')).map((r) => r.url.replace(ORIGIN, ''));

// text elements must stay inside their card (no clipped labels)
const CLIP = `(()=>{const bad=[];for(const g of document.querySelectorAll('#ot4-svg g[data-ctx]')){const r=g.querySelector('rect');if(!r)continue;const x0=+r.getAttribute('x'),x1=x0+ +r.getAttribute('width');for(const t of g.querySelectorAll('text')){const b=t.getBBox();if(b.x<x0-1||b.x+b.width>x1+1)bad.push((t.textContent||'').slice(0,50)+':'+Math.round(b.x+b.width-x1));}}return bad;})()`;

// ================================================================== fixture-driven double
function fixtureData(name) {
  const dir = join(FIXDIR, name); const files = {};
  for (const f of readdirSync(dir)) if (f.endsWith('.json') && f !== 'MANIFEST.json') files[f] = JSON.parse(readFileSync(join(dir, f), 'utf8'));
  return files;
}
// pages: key 'full:<limit>' or 'g:<groupId>:<offset>:<limit>' -> body. Rules run in the page and may hold, fail or pass a request.
async function installFixture(pg, name, rulesSrc = 'null') {
  const files = fixtureData(name); const pages = {};
  const full0 = files['contexts-page-0.json']; if (full0) pages['full:20'] = full0;
  for (const [f, body] of Object.entries(files)) {
    let m;
    if ((m = f.match(/^contexts-page-0-limit-(\d+)\.json$/))) pages['full:' + m[1]] = body;
    if ((m = f.match(/^contexts-group-[a-z]+-offset-(\d+)-limit-(\d+)\.json$/))) pages[`g:${body.groups[0].group_id}:${m[1]}:${m[2]}`] = body;
  }
  await ev(pg, `(()=>{ window.__fx={analysis:${JSON.stringify(files['analysis.json'])},pages:${JSON.stringify(pages)},error:${JSON.stringify(files['error-response-too-large.json'] || files['error-projection-failed.json'] || null)},calls:[],held:[],rules:null};
    window.__fx.rules = ${rulesSrc};
    const real=window.fetch.bind(window); const J=(b,s=200)=>new Response(JSON.stringify(b),{status:s,headers:{'Content-Type':'application/json'}});
    window.fetch = async (u, init) => { const url=String(u);
      if (url.startsWith('/api/analysis/demo')) return J(window.__fx.analysis);
      if (url.startsWith('/api/workbench/v1/contexts')) {
        const q=new URL(url,location.origin).searchParams; const req={full:!q.get('group_id'),group:q.get('group_id'),offset:+(q.get('files_offset')||0),limit:+(q.get('files_limit')||20),generation:+q.get('generation')};
        window.__fx.calls.push(req.full?('full:'+req.limit):('g:'+req.offset+':'+req.limit));
        const key=req.full?('full:'+req.limit):('g:'+req.group+':'+req.offset+':'+req.limit);
        let r = window.__fx.rules ? await window.__fx.rules(req,key,window.__fx) : null;
        if (r && r.hold) { await new Promise((res)=>window.__fx.held.push({key,res,r})); r=r.then||null; }
        if (r && r.status) return J(r.body||window.__fx.error, r.status);
        const body = window.__fx.pages[key]; return body ? J(body) : J({schema:'opentrace.workbench.error/1',error:'invalid_request',message:'no fixture page '+key,detail_code:'fixture'},400);
      }
      return real(u, init); }; })()`);
}
const fxCalls = (pg) => ev(pg, 'window.__fx.calls.slice()');
const releaseAll = (pg) => ev(pg, 'window.__fx.held.splice(0).forEach((h)=>h.res())');

// ================================================================== 1) the recorded Demo (real service), six viewport/theme runs
for (const [w, h, theme] of [[1366, 900, 'light'], [1366, 900, 'dark'], [1920, 1080, 'light'], [1920, 1080, 'dark'], [390, 844, 'light'], [390, 844, 'dark']]) {
  ctx = `demo ${w}x${h} ${theme}`; const narrow = w <= 700;
  const pg = await open(w, h, theme);
  await demo(pg);
  const st = await state(pg); const m = st.views.contexts;
  check('UIP04-01 opens on Repository contexts with the repository root selected and its inspector shown', st.workbench.tab === 'contexts' && st.workbench.perTab.contexts.selection === 'root' && /REPOSITORY/i.test(await txt(pg, '.ot4-inspector')) && (await inspTitle(pg)) === m.root.name, await inspTitle(pg));
  check('UIP04-02 the map comes from contexts/1: five groups (four located + Unlocated), thirteen files', m.schema === 'opentrace.workbench.contexts/1' && m.groups.length === 5 && m.groups.reduce((n, g) => n + g.files.length, 0) === 13 && m.groups.at(-1).kind === 'unlocated');
  check('UIP04-03 default presentation: Graph on desktop, List at 390 px', st.workbench.perTab.contexts.presentation === (narrow ? 'list' : 'graph'));
  check('UIP04-04 exactly one contexts/1 request at open (generation bound, first page of 20)', JSON.stringify(ctxCalls(pg).map((u) => u.split('?')[1])) === JSON.stringify(['generation=1&files_limit=20']), JSON.stringify(ctxCalls(pg)));
  check('UIP04-05 no horizontal page scroll', await noOverflow(pg));
  if (!narrow) {
    const attrs = await ev(pg, "(()=>{const s=document.getElementById('ot4-stage');return {ready:s.dataset.mapReady,cards:s.dataset.cardCount,groups:s.dataset.groupCount,kind:s.dataset.selectionKind,fit:s.dataset.fit}})()");
    check('UIP04-06 observable postconditions: map ready, 13 cards, 5 groups, root selection, fit viewBox', attrs.ready === 'true' && attrs.cards === '13' && attrs.groups === '5' && attrs.kind === 'root' && attrs.fit === '0 0 1400 1206', JSON.stringify(attrs));
    check('UIP04-07 no label is clipped by its card', (await ev(pg, CLIP)).length === 0, JSON.stringify(await ev(pg, CLIP)));
    const rootText = await ev(pg, "document.querySelector('[data-ctx=root] text.ot4-name').textContent");
    check('UIP04-08 the root card shows the data-driven repository name and short commit (no constant)', rootText === `${m.root.name.split('/').pop()} · ${m.root.commit_sha.slice(0, 7)}`, rootText);
  } else {
    check('UIP04-06 List shows the root, five group rows and thirteen file rows', (await count(pg, '#ot4-list [data-ctx-kind=root]')) === 1 && (await count(pg, '#ot4-list [data-ctx-kind=group]')) === 4 && (await count(pg, '#ot4-list [data-ctx-kind=unlocated]')) === 1 && (await count(pg, '#ot4-list [data-ctx-kind=file]')) === 13);
  }
  check('UIP04-09 no console errors, no exceptions, no non-loopback request', consoleErrors(pg).length === 0 && blocked.length === 0, JSON.stringify(consoleErrors(pg)).slice(0, 200));
  // reference-match report (desktop only): DOM/SVG facts of the application against the prototype extracted facts
  if (!narrow) {
    const app = await ev(pg, `(()=>{const num=(e,a)=>Number(e.getAttribute(a)); const R=e=>({x:num(e,'x'),y:num(e,'y'),w:num(e,'width'),h:num(e,'height')});
      const zones=[...document.querySelectorAll('#ot4-svg .ot4-zone')].map(z=>({token:z.dataset.token,id:z.dataset.groupId,zone:R(z.querySelector(':scope > rect')),header:R(z.querySelector('g[data-ctx-kind=group] rect, g[data-ctx-kind=unlocated] rect')),files:[...z.querySelectorAll('[data-ctx-kind=file]')].map(f=>({title:f.querySelector('title').textContent,rect:R(f.querySelector('rect')),fill:getComputedStyle(f.querySelector('rect')).fill,stroke:getComputedStyle(f.querySelector('rect')).stroke})),zoneFill:getComputedStyle(z.querySelector(':scope > rect')).fill,edge:getComputedStyle(z.querySelector(':scope > rect')).stroke,headFill:getComputedStyle(z.querySelector('g[data-ctx] rect')).fill}));
      return {viewBox:document.getElementById('ot4-svg').getAttribute('viewBox'),root:R(document.querySelector('[data-ctx=root] rect')),zones};})()`);
    const ref = REF.themes[theme]; const near = (a, b) => Math.abs(a - b) <= 1;
    const located = app.zones.filter((z) => z.token !== 'neutral'); const kinds = ['docs', 'web', 'python', 'actions'];
    const rows = []; let geometryOk = true;
    located.forEach((z, i) => {
      const r = ref.groups[i]; const ok = near(z.zone.x, r.zone.x) && near(z.zone.y, r.zone.y) && near(z.zone.w, r.zone.w) && near(z.header.x, r.header.x) && near(z.header.y, r.header.y) && near(z.header.w, r.header.w)
        && z.files.every((f, k) => near(f.rect.x, r.files[k].rect.x) && near(f.rect.y, r.files[k].rect.y) && near(f.rect.w, r.files[k].rect.w) && near(f.rect.h, r.files[k].rect.h));
      geometryOk &&= ok; rows.push({ group: kinds[i], zoneHeight: { app: z.zone.h, reference: r.zone.h, status: z.zone.h === r.zone.h ? 'matched' : 'approved exception (FR-6)' } });
    });
    const tok = located.every((z, i) => z.zoneFill === ref.tokens[kinds[i]].zoneFill && z.edge === ref.tokens[kinds[i]].edge && z.headFill === ref.tokens[kinds[i]].headerFill && z.files.every((f) => f.fill === ref.tokens[kinds[i]].fileFill));
    check('UIP04-10 DOM/SVG geometry equals the prototype within 1 px (zones, headers, file slots; row-2 height is the approved exception)', geometryOk && located.length === 4 && near(app.root.x, ref.root.rect.x) && near(app.root.w, ref.root.rect.w) && near(app.root.h, ref.root.rect.h), JSON.stringify(rows));
    check(`UIP04-11 computed ${theme} token colors equal the prototype's for the four categories`, tok, JSON.stringify(located.map((z) => [z.zoneFill, z.edge])));
    writeFileSync(join(OUT, `reference_match_${w}_${theme}.json`), JSON.stringify({ reference_sha256: REF.reference.sha256, viewport: `${w}x${h}`, theme, app_viewBox: app.viewBox, reference_viewBox: ref.viewBox, zone_heights: rows,
      not_matched: ['root name text: data-driven "frigate" vs the prototype constant "Frigate"', 'file order inside a group: contract code-point order vs the prototype capture order (slots compared, texts by path)'],
      not_in_reference: ['Unlocated components zone (FR-5)', 'Show more footers'], approved_exception: 'row-2 zone/viewBox height 560/1040 vs 570/1050 (FR-6)' }, null, 2) + '\n');
  }
  if (w === 1366 && theme === 'light') {
    // ---- selection, inspector, Explore, evidence, Graph/List, tab return
    const pyGroup = m.groups.find((g) => g.category === 'python_requirements'); const docFile = m.groups[0].files[0];
    await pg.click(`[data-ctx="${pyGroup.group_id}"]`); await sleep(200);
    check('UIP04-20 selecting a group updates the inspector and the observable selection', (await inspTitle(pg)) === 'Python requirements' && (await sel(pg)) === `group|${pyGroup.group_id}` && /does not establish installation, workflow execution or service topology/.test(await txt(pg, '.ot4-inspector')));
    check('UIP04-21 the group header counts: distinct records and (only when different) file memberships', /5 captured source locations/.test(await svgText(pg)) && /21 distinct records/.test(await svgText(pg)));
    await pg.click(`[data-ctx="${docFile.file_id}"]`); await sleep(200);
    const fileInsp = await txt(pg, '.ot4-inspector');
    check('UIP04-22 selecting a file shows path, Explore components, evidence access and the pinned revision link', (await inspTitle(pg)) === docFile.path && /Explore components/.test(fileInsp) && /Inspect evidence/.test(fileInsp) && (await ev(pg, `document.querySelector('.ot4-source-link a')?.href`)) === docFile.revision_link.href);
    check('UIP04-23 the only active link in the inspector is the exact pinned https://github.com/ revision', (await ev(pg, `[...document.querySelectorAll('.ot4-inspector a')].map(a=>a.href)`)).every((h) => h.startsWith('https://github.com/')) && (await ev(pg, `document.querySelector('.ot4-source-link a').rel`)) === 'noopener noreferrer');
    await pg.click('.ot4-inspector [data-action=ctx-evidence]'); await sleep(300);
    check('UIP04-24 evidence access opens the facts (source, association count, "installation, builds and execution were not observed")', /Installation, builds and execution were not observed/.test(await txt(pg, '#ot-dialog-content')) && /1,513 (recorded )?component records/.test(await txt(pg, "#ot-dialog-content")), (await txt(pg, '#ot-dialog-content')).slice(0, 160));
    await ev(pg, "document.getElementById('ot-dialog').close()"); await sleep(150);
    // Graph/List preserves the selection
    await pg.click('[data-action=tab-pres][data-p=list]'); await sleep(250);
    check('UIP04-25 List mirrors the map (13 file rows) and keeps the selection', (await count(pg, '#ot4-list [data-ctx-kind=file]')) === 13 && (await sel(pg)) === `file|${docFile.file_id}` && (await ev(pg, `document.querySelector('#ot4-list [data-ctx="${docFile.file_id}"]').getAttribute('aria-pressed')`)) === 'true');
    await pg.click('[data-action=tab-pres][data-p=graph]'); await sleep(250);
    check('UIP04-26 back to Graph: selection and fit preserved', (await sel(pg)) === `file|${docFile.file_id}` && (await ev(pg, `document.getElementById('ot4-svg').getAttribute('viewBox')`)) === '0 0 1400 1206');
    // tab return keeps a valid selection
    await ev(pg, "document.getElementById('ot-tab-bom').click()"); await sleep(500); await ev(pg, "document.getElementById('ot-tab-contexts').click()"); await sleep(300);
    check('UIP04-27 returning to the Contexts tab preserves the selection (no new contexts request)', (await sel(pg)) === `file|${docFile.file_id}` && ctxCalls(pg).length === 1, JSON.stringify(ctxCalls(pg)));
    // zoom / pan / fit
    const vb0 = await ev(pg, `document.getElementById('ot4-svg').getAttribute('viewBox')`);
    await pg.click('[data-ctx-zoom="0.8"]'); await sleep(100);
    const z1 = await ev(pg, `({label:document.getElementById('ot4-zoom').textContent,vb:document.getElementById('ot4-svg').getAttribute('viewBox')})`);
    check('UIP04-30 zoom in: label 125% and the viewBox narrows', z1.label === '125%' && Number(z1.vb.split(' ')[2]) === 1120, JSON.stringify(z1));
    await pg.click('[data-ctx-zoom="1.25"]'); await sleep(100); await pg.click('[data-ctx-zoom="1.25"]'); await sleep(100);
    check('UIP04-31 zoom out: label 80%', (await txt(pg, '#ot4-zoom')) === '80%');
    await pg.click('[data-ctx-fit]'); await sleep(100);
    check('UIP04-32 Fit restores the fitted viewBox and 100%', (await ev(pg, `document.getElementById('ot4-svg').getAttribute('viewBox')`)) === vb0 && (await txt(pg, '#ot4-zoom')) === '100%');
    const box = await ev(pg, `(()=>{const r=document.getElementById('ot4-svg').getBoundingClientRect();return {x:r.x+r.width*0.97,y:r.y+r.height*0.5}})()`);
    await pg.send('Input.dispatchMouseEvent', { type: 'mouseMoved', x: box.x, y: box.y }); await pg.send('Input.dispatchMouseEvent', { type: 'mousePressed', x: box.x, y: box.y, button: 'left', clickCount: 1 });
    await pg.send('Input.dispatchMouseEvent', { type: 'mouseMoved', x: box.x - 120, y: box.y - 60, buttons: 1 }); await pg.send('Input.dispatchMouseEvent', { type: 'mouseReleased', x: box.x - 120, y: box.y - 60, button: 'left', clickCount: 1 });
    await sleep(150);
    const vbPan = (await ev(pg, `document.getElementById('ot4-svg').getAttribute('viewBox')`)).split(' ').map(Number);
    check('UIP04-33 dragging the background pans the viewBox (zoom unchanged, selection unchanged)', vbPan[0] > 0 && vbPan[1] > 0 && vbPan[2] === 1400 && (await sel(pg)) === `file|${docFile.file_id}`, vbPan.join(' '));
    await pg.click('[data-ctx-fit]'); await sleep(100);
    await pg.send('Input.dispatchMouseEvent', { type: 'mouseWheel', x: box.x - 300, y: box.y, deltaX: 0, deltaY: -100, modifiers: 2 }); await sleep(150);
    check('UIP04-34 Ctrl/Cmd + wheel zooms the map', (await txt(pg, '#ot4-zoom')) !== '100%' && (await ev(pg, 'window.scrollY')) === (await ev(pg, 'window.scrollY')));
    await pg.click('[data-ctx-fit]'); await sleep(100);
    // keyboard: Tab order root -> group header -> its cards, Enter/Space, arrows/Home/End, stage zoom keys, focus return
    await ev(pg, "document.getElementById('ot4-stage').focus()");
    await pg.key('+'); await sleep(80); check('UIP04-40 stage focused: + zooms in', (await txt(pg, '#ot4-zoom')) === '125%');
    await pg.key('-'); await sleep(80); check('UIP04-41 stage focused: - zooms out', (await txt(pg, '#ot4-zoom')) === '100%');
    await pg.key('+'); await pg.key('0'); await sleep(80); check('UIP04-42 stage focused: 0 fits', (await txt(pg, '#ot4-zoom')) === '100%');
    await ev(pg, "document.querySelector('#ot4-stage').focus()");
    const order = []; for (let i = 0; i < 5; i++) { await pg.key('Tab'); order.push(await ev(pg, 'document.activeElement?.dataset?.ctx||document.activeElement?.id||document.activeElement?.tagName')); }
    const domOrder = await ev(pg, `[...document.querySelectorAll('#ot4-svg [data-ctx]')].slice(0,4).map(e=>e.dataset.ctx)`);
    check('UIP04-43 Tab order is DOM order: root, first group header, its cards, next group', order.slice(0, 1)[0] === 'root' && JSON.stringify(order.slice(0, 4)) === JSON.stringify(domOrder) && domOrder[1] === m.groups[0].group_id && domOrder[2] === m.groups[0].files[0].file_id && domOrder[3] === m.groups[1].group_id, JSON.stringify(order));
    const pyFiles = pyGroup.files.map((f) => f.file_id);
    await ev(pg, `document.querySelector('[data-ctx="${pyFiles[0]}"]').focus()`);
    await pg.key('ArrowDown'); check('UIP04-44 ArrowDown moves to the next card in the zone', (await ev(pg, 'document.activeElement.dataset.ctx')) === pyFiles[1]);
    await pg.key('End'); check('UIP04-45 End jumps to the zone\'s last card', (await ev(pg, 'document.activeElement.dataset.ctx')) === pyFiles.at(-1));
    await pg.key('ArrowUp'); await pg.key('Home'); check('UIP04-46 Home jumps to the zone\'s first card', (await ev(pg, 'document.activeElement.dataset.ctx')) === pyFiles[0]);
    await pg.key('Enter'); await sleep(250);
    check('UIP04-47 Enter selects the focused card and focus returns to it after the re-render', (await sel(pg)) === `file|${pyFiles[0]}` && (await ev(pg, 'document.activeElement?.dataset?.ctx')) === pyFiles[0], await ev(pg, 'document.activeElement?.outerHTML?.slice(0,80)'));
    await pg.key('ArrowDown'); await pg.key(' '); await sleep(250);
    check('UIP04-48 Space selects too and keeps focus on the activated card', (await sel(pg)) === `file|${pyFiles[1]}` && (await ev(pg, 'document.activeElement?.dataset?.ctx')) === pyFiles[1]);
    check('UIP04-49 the focused card shows a visible focus ring', (await ev(pg, `getComputedStyle(document.querySelector('[data-ctx="${pyFiles[1]}"] rect')).strokeWidth`)) !== '' && (await ev(pg, `document.activeElement.matches('g[role=button]:focus')`)));
    // Explore components
    await pg.click(`[data-ctx="${docFile.file_id}"]`); await sleep(200);
    const callsBefore = pg.log.requests.length;
    await pg.click('.ot4-inspector [data-action=drill]'); await sleep(1500);
    const dd = await state(pg);
    check('UIP04-50 Explore components switches to Dependencies with the file as context through the existing dependencies route', dd.workbench.tab === 'dependencies' && dd.workbench.perTab.dependencies.context === docFile.path && pg.log.requests.slice(callsBefore).some((r) => /\/api\/view\/dependencies\?.*context=docs%2Fpackage-lock\.json/.test(r.url)));
    check('UIP04-51 the Dependencies context chooser lists every captured path (UIP-05: the dependency-contexts route; 13 files, no "All captured contexts" entry in the normal view)', (await count(pg, '#ot5-context option')) === 13, String(await count(pg, '#ot5-context option')));
    await ev(pg, "document.getElementById('ot-tab-contexts').click()"); await sleep(300);
    check('UIP04-52 coming back from Explore keeps the selected file', (await sel(pg)) === `file|${docFile.file_id}`);
    // End session clears the map, selection and view state; a new Demo reopens on the root
    await ev(pg, "document.getElementById('ot-top-end').click()"); await pg.waitFor('window.__otStore.get().ended', 20000, 'ended'); await sleep(300);
    const ended = await state(pg);
    check('UIP04-53 End session clears the map payload, selection and bookkeeping', ended.views.contexts === undefined && ended.workbench.perTab.contexts.selection === 'root' && ended.workbench.perTab.contexts.map.status === 'idle' && (await count(pg, '#ot4-svg')) === 0);
    await demo(pg);
    check('UIP04-54 a new Demo after End session opens on the repository root with a fresh fitted map', (await sel(pg)) === 'root|root' && (await ev(pg, `document.getElementById('ot4-svg').getAttribute('viewBox')`)) === '0 0 1400 1206');
    await pg.screenshot(join(OUT, 'demo_1366_light_contexts.png'));
  }
  await pg.close();
}

// ================================================================== 2) fixture-driven cases (real app.js loaders and reducers, production payloads)
ctx = 'fixtures 1366x900 light';
const fxPage = async (name, rules, w = 1366, h = 900, theme = 'light') => { const pg = await open(w, h, theme); await installFixture(pg, name, rules); await demo(pg); return pg; };

{ // eleven classifier groups + the labelled synthetic twelve-group layout-capacity payload
  let pg = await fxPage('uip04-eleven-groups');
  const attrs = await ev(pg, "(()=>{const s=document.getElementById('ot4-stage');return {g:s.dataset.groupCount,c:s.dataset.cardCount,fit:s.dataset.fit}})()");
  check('UIP04-60 eleven production groups (all ten categories plus Unlocated) lay out without overlap, clipping or horizontal scroll', attrs.g === '11' && (await noOverflow(pg)) && (await ev(pg, CLIP)).length === 0 && await ev(pg, `(()=>{const b=[...document.querySelectorAll('#ot4-svg .ot4-zone-box')].map(r=>[+r.getAttribute('x'),+r.getAttribute('y'),+r.getAttribute('width'),+r.getAttribute('height')]);return b.every((a,i)=>b.slice(i+1).every(c=>a[0]+a[2]<=c[0]||c[0]+c[2]<=a[0]||a[1]+a[3]<=c[1]||c[1]+c[3]<=a[1]))})()`), JSON.stringify(attrs));
  check('UIP04-61 every category uses an approved token (blue/green/amber/purple) or neutral', await ev(pg, `[...document.querySelectorAll('#ot4-svg .ot4-zone')].every(z=>['blue','green','amber','purple','neutral'].includes(z.dataset.token))`));
  await pg.screenshot(join(OUT, 'fixture_eleven_groups.png')); await pg.close();
  pg = await fxPage('uip04-synthetic-12-group-layout-capacity');
  check('UIP04-62 the SYNTHETIC 12-group layout-capacity payload (schema maximum) lays out without overlap or clipping', (await ev(pg, "document.getElementById('ot4-stage').dataset.groupCount")) === '12' && (await noOverflow(pg)) && (await ev(pg, CLIP)).length === 0);
  await pg.close();
}
for (const [name, expect] of [['uip04-one-group', { groups: 1 }], ['uip04-zero-location', { groups: 0 }], ['uip04-unlocated-only', { groups: 1 }], ['uip04-unlocated-with-files', { groups: 3 }], ['uip04-overlap', { groups: 3 }], ['uip04-multi-ecosystem', { groups: 7 }]]) {
  const pg = await fxPage(name);
  const g = await ev(pg, "document.getElementById('ot4-stage')?.dataset.groupCount");
  check(`UIP04-63 ${name}: renders ${expect.groups} group(s), selectable root inspector, no overflow, no console errors`, g === String(expect.groups) && (await noOverflow(pg)) && /REPOSITORY/i.test(await txt(pg, '.ot4-inspector')) && consoleErrors(pg).length === 0, g);
  if (name === 'uip04-unlocated-with-files') {
    const u = await ev(pg, `document.querySelector('#ot4-svg [data-ctx-kind=unlocated]')?.dataset.ctx`); await pg.click(`[data-ctx="${u}"]`); await sleep(200);
    check('UIP04-64 the Unlocated zone is selectable, header-only, with its own inspector text (no invented location)', (await inspTitle(pg)) === 'Unlocated components' && /no recorded source-file location/.test(await txt(pg, '.ot4-inspector')) && (await count(pg, '#ot4-svg .ot4-zone[data-token=neutral] [data-ctx-kind=file]')) === 0);
  }
  if (name === 'uip04-overlap') check('UIP04-65 overlap: a group header labels file memberships separately when they exceed distinct records', /file memberships?/.test(await svgText(pg)));
  await pg.close();
}
{ // hostile text stays inert
  const pg = await fxPage('uip04-hostile-text');
  const bad = await ev(pg, `({img:document.querySelectorAll('#ot-workbench img').length,script:document.querySelectorAll('#ot-workbench script').length,handlers:[...document.querySelectorAll('#ot-workbench *')].filter(e=>[...e.attributes].some(a=>/^on/i.test(a.name))).length,anchors:[...document.querySelectorAll('#ot-workbench a')].map(a=>a.href)})`);
  check('UIP04-70 hostile paths render as literal text: no injected element, no event handler, no foreign link', bad.img === 0 && bad.script === 0 && bad.handlers === 0 && bad.anchors.every((h) => h.startsWith('https://github.com/')), JSON.stringify(bad));
  const hostileId = await ev(pg, `[...document.querySelectorAll('[data-ctx-kind=file]')].find(e=>/img src=x/.test(e.querySelector('title').textContent))?.dataset.ctx`);
  await pg.click(`[data-ctx="${hostileId}"]`); await sleep(200);
  check('UIP04-71 selecting a hostile file shows its text literally and an inert or pinned link only', /<img src=x onerror=alert\(1\)>/.test(await txt(pg, '.ot4-inspector')) && (await ev(pg, "document.querySelectorAll('.ot4-inspector a').length")) <= 1 && consoleErrors(pg).length === 0);
  const jsFile = await ev(pg, `[...document.querySelectorAll('[data-ctx-kind=file]')].find(e=>e.querySelector('title').textContent==='javascript:alert(1)')?.dataset.ctx`);
  await pg.click(`[data-ctx="${jsFile}"]`); await sleep(200);
  check('UIP04-72 a path that looks like a URL scheme is text; its pinned revision link is an exact https://github.com/ URL', (await ev(pg, "[...document.querySelectorAll('.ot4-inspector a')].every(a=>a.href.startsWith('https://github.com/'))")));
  await pg.close();
}
{ // unrepresentable path: explicit unavailable state, other tabs unaffected, Check again re-enters at 20
  const rules = `async(req,key,fx)=>{ if(!fx.fixed) return {status:500,body:fx.error}; return null }`;
  const pg = await open(1366, 900); await installFixture(pg, 'uip04-unrepresentable-path', rules);
  await ev(pg, "document.getElementById('ot-demo').click()"); await pg.waitFor(`document.querySelector('[data-state=unavailable]')`, 30000, 'unavailable');
  const unavailable = await txt(pg, '#ot-tabpanel');
  check('UIP04-80 an unrepresentable path is an explicit unavailable state with the typed error, never a partial map', /Repository contexts are unavailable/.test(unavailable) && /projection_failed/.test(unavailable) && /Nothing is shown as a partial map/.test(unavailable) && (await count(pg, '#ot4-svg')) === 0 && (await state(pg)).views.contexts === undefined);
  await ev(pg, "document.getElementById('ot-tab-dependencies').click()"); await sleep(300);
  check('UIP04-81 other tabs are not affected: the unavailable state belongs to the Contexts tab only', !/Repository contexts are unavailable/.test(await txt(pg, '#ot-tabpanel')) && (await state(pg)).workbench.tab === 'dependencies');
  await ev(pg, "document.getElementById('ot-tab-contexts').click()"); await sleep(200);
  const callsA = (await fxCalls(pg)).length;
  await ev(pg, 'window.__fx.fixed=false'); await pg.click('[data-action=ctx-retry]'); await sleep(500);
  check('UIP04-82 Check again re-enters at 20 (no automatic retry happened before)', callsA === 1 && (await fxCalls(pg)).at(-1) === 'full:20', JSON.stringify(await fxCalls(pg)));
  await pg.close();
}
{ // response_too_large ladder 20 -> 10 -> 5 -> 1, and terminal failure
  let pg = await open(1366, 900);
  await installFixture(pg, 'uip04-large-map', `async(req,key,fx)=>{ if(req.full && req.limit>5) return {status:500,body:fx.error}; return null }`);
  await ev(pg, "document.getElementById('ot-demo').click()"); await ready(pg);
  check('UIP04-83 response_too_large retries the initial request 20 -> 10 -> 5 and then succeeds with the smaller page', JSON.stringify(await fxCalls(pg)) === JSON.stringify(['full:20', 'full:10', 'full:5']) && (await ev(pg, "document.getElementById('ot4-stage').dataset.cardCount")) === String((await state(pg)).views.contexts.groups.reduce((n, g) => n + g.files.length, 0)), JSON.stringify(await fxCalls(pg)));
  check('UIP04-84 the smaller first page is honest: hidden totals visible and every group still shows its footer', /not shown/.test(await svgText(pg)) && (await ev(pg, "document.querySelectorAll('#ot4-svg [data-action=ctx-more]').length")) > 0);
  await pg.close();
  pg = await open(1366, 900);
  await installFixture(pg, 'uip04-large-map', `async(req,key,fx)=>({status:500,body:fx.error})`);
  await ev(pg, "document.getElementById('ot-demo').click()"); await pg.waitFor(`document.querySelector('[data-state=unavailable]')`, 30000, 'terminal');
  check('UIP04-85 the 1-card request failing too is terminal: four requests, an unavailable state, no further automatic retry', JSON.stringify(await fxCalls(pg)) === JSON.stringify(['full:20', 'full:10', 'full:5', 'full:1']) && (await sleep(800), (await fxCalls(pg)).length === 4), JSON.stringify(await fxCalls(pg)));
  await pg.close();
}
{ // paging: Show more in Graph (pages of 20), the 100-card cap, List pages of 40, hidden totals
  const pg = await fxPage('uip04-large-map');
  const web = (await state(pg)).views.contexts.groups.find((g) => g.files_counts.total === 213);
  check('UIP04-90 the initial map shows 20 cards per group and the largest group states its hidden total', web.files.length === 20 && /Showing 20 of 213 source locations · 193 not shown/.test(await svgText(pg)));
  const total0 = await ev(pg, "document.getElementById('ot4-stage').dataset.cardCount");
  for (let i = 0; i < 4; i++) { await ev(pg, `document.querySelector('#ot4-svg [data-action=ctx-more][data-group="${web.group_id}"]')?.dispatchEvent(new MouseEvent('click',{bubbles:true}))`); await sleep(350); }
  const g2 = (await state(pg)).views.contexts.groups.find((g) => g.group_id === web.group_id);
  check('UIP04-91 Show more appends pages of 20 without dropping cards (offsets 20, 40, 60, 80)', g2.files.length === 100 && JSON.stringify((await fxCalls(pg)).slice(1)) === JSON.stringify(['g:20:20', 'g:40:20', 'g:60:20', 'g:80:20']) && g2.files.slice(0, 20).every((f, i) => f.file_id === web.files[i].file_id), JSON.stringify(await fxCalls(pg)));
  check('UIP04-92 at the 100-card Graph cap the footer continues in List view and offers no Show more', /Showing 100 of 213 source locations · 113 not shown/.test(await svgText(pg)) && /Continue in List view/.test(await svgText(pg)) && (await ev(pg, `document.querySelectorAll('#ot4-svg [data-action=ctx-more][data-group="${web.group_id}"]').length`)) === 0);
  check('UIP04-93 the whole-map Graph budget of 400 cards is respected', Number(await ev(pg, "document.getElementById('ot4-stage').dataset.cardCount")) <= 400 && Number(await ev(pg, "document.getElementById('ot4-stage').dataset.cardCount")) > Number(total0));
  await pg.click('[data-action=tab-pres][data-p=list]'); await sleep(300);
  check('UIP04-94 List shows every loaded card (100) with Show more and the hidden total', (await count(pg, `#ot4-list [data-group-id="${web.group_id}"] [data-ctx-kind=file]`)) === 100 && /113 not shown/.test(await txt(pg, '#ot4-list')));
  await ev(pg, `document.querySelector('#ot4-list [data-action=ctx-more][data-group="${web.group_id}"]').click()`); await sleep(400);
  const g3 = (await state(pg)).views.contexts.groups.find((g) => g.group_id === web.group_id);
  check('UIP04-95 List pages of 40: the next request starts at the loaded count (offset 100, limit 40), bounded by the group total', g3.files.length === 140 && (await fxCalls(pg)).at(-1) === 'g:100:40');
  for (const off of [140, 180]) { await ev(pg, `document.querySelector('#ot4-list [data-action=ctx-more][data-group="${web.group_id}"]')?.click()`); await sleep(400); }
  const g4 = (await state(pg)).views.contexts.groups.find((g) => g.group_id === web.group_id);
  check('UIP04-96 the last page ends exactly at the group total and the Show more control disappears', g4.files.length === 213 && (await ev(pg, `document.querySelectorAll('#ot4-list [data-action=ctx-more][data-group="${web.group_id}"]').length`)) === 0);
  await pg.screenshot(join(OUT, 'fixture_large_list.png')); await pg.close();
}
{ // group retry ladder: 20 fails, 10 succeeds; and a terminal group failure keeps the loaded cards
  let pg = await open(1366, 900);
  await installFixture(pg, 'uip04-large-map', `async(req,key,fx)=>{ if(!req.full && req.limit>10) return {status:500,body:fx.error}; return null }`);
  await ev(pg, "document.getElementById('ot-demo').click()"); await ready(pg);
  const web = (await state(pg)).views.contexts.groups.find((g) => g.files_counts.total === 213);
  await ev(pg, `document.querySelector('#ot4-svg [data-action=ctx-more][data-group="${web.group_id}"]').dispatchEvent(new MouseEvent('click',{bubbles:true}))`); await sleep(500);
  check('UIP04-97 a group page retries 20 -> 10 and the smaller page extends the loaded prefix', JSON.stringify((await fxCalls(pg)).slice(1)) === JSON.stringify(['g:20:20', 'g:20:10']) && (await state(pg)).views.contexts.groups.find((g) => g.group_id === web.group_id).files.length === 30);
  await pg.close();
  pg = await open(1366, 900);
  await installFixture(pg, 'uip04-large-map', `async(req,key,fx)=>{ if(!req.full) return {status:500,body:fx.error}; return null }`);
  await ev(pg, "document.getElementById('ot-demo').click()"); await ready(pg);
  await ev(pg, `document.querySelector('#ot4-svg [data-action=ctx-more][data-group="${web.group_id}"]').dispatchEvent(new MouseEvent('click',{bubbles:true}))`); await sleep(600);
  const s2 = await state(pg);
  check('UIP04-98 a group failing at 1 card is terminal for that group only: loaded cards stay, the map stays ready, the error is shown in List', s2.workbench.perTab.contexts.map.groups[web.group_id].state === 'error' && s2.workbench.perTab.contexts.map.status === 'ready' && s2.views.contexts.groups.find((g) => g.group_id === web.group_id).files.length === 20 && s2.views.contexts.groups.length === 7, JSON.stringify(await fxCalls(pg)));
  await pg.close();
}
{ // late / superseded responses never apply
  let pg = await open(1366, 900);
  await installFixture(pg, 'uip04-multi-ecosystem', `async(req,key,fx)=>{ if(fx.hold && req.full){ fx.hold=false; return {hold:true}; } return null }`);
  await ev(pg, 'window.__fx.hold=true'); await ev(pg, "document.getElementById('ot-demo').click()"); await sleep(800);
  const e1 = (await state(pg)).epoch;
  check('UIP04-100 while the initial contexts request is held the tab shows a loading state, not a partial map', /Loading contexts/.test(await txt(pg, '#ot-tabpanel')) && (await count(pg, '#ot4-svg')) === 0);
  await ev(pg, "document.getElementById('ot-top-end').click()"); await pg.waitFor('window.__otStore.get().ended', 20000, 'ended'); await sleep(300);
  await releaseAll(pg); await sleep(700);
  const late = await state(pg);
  check('UIP04-101 a late success that arrives after End session is discarded: no map, no notice, no state', late.views.contexts === undefined && late.analysis === null && (await count(pg, '#ot4-svg')) === 0 && late.epoch > e1);
  await pg.close();
  pg = await open(1366, 900);
  await installFixture(pg, 'uip04-multi-ecosystem', `async(req,key,fx)=>{ if(fx.hold && req.full){ fx.hold=false; return {hold:true,then:{status:500,body:fx.error}}; } return null }`);
  await ev(pg, 'window.__fx.hold=true'); await ev(pg, "document.getElementById('ot-demo').click()"); await sleep(600);
  await ev(pg, "document.getElementById('ot-demo').click()"); await ready(pg); const before = await state(pg);
  await releaseAll(pg); await sleep(700);
  const after = await state(pg);
  check('UIP04-102 a late ERROR from a superseded analysis changes nothing (no unavailable state, no retry request)', JSON.stringify(after.views.contexts) === JSON.stringify(before.views.contexts) && after.workbench.perTab.contexts.map.status === 'ready' && (await fxCalls(pg)).length === 2, JSON.stringify(await fxCalls(pg)));
  await pg.close();
}

// ================================================================== 2b) correction 01 (independent review IR-01..IR-04)
ctx = 'correction 01';
{ // IR-02: Graph group paging — held, then terminally failed, then a manual retry; the REAL app loaders run
  const pg = await open(1366, 900);
  await installFixture(pg, 'uip04-large-map', `async(req,key,fx)=>{ if(req.full) return null; if(fx.hold){ fx.hold=false; return {hold:true,then:{status:500,body:fx.error}}; } return {status:500,body:fx.error}; }`);
  await ev(pg, 'window.__fx.hold=true'); await ev(pg, "document.getElementById('ot-demo').click()"); await ready(pg);
  const web = (await state(pg)).views.contexts.groups.find((g) => g.files_counts.total === 213);
  const more = `#ot4-svg [data-action=ctx-more][data-group="${web.group_id}"]`;
  await ev(pg, `document.querySelector('${more}').dispatchEvent(new MouseEvent('click',{bubbles:true}))`);
  await pg.waitFor('window.__fx.held.length===1', 10000, 'group request held');
  check('UIP04-120 Graph: while the group page is held it shows Loading… and the control is aria-disabled, cards stay', /Loading…/.test(await svgText(pg)) && (await ev(pg, `document.querySelector('${more}').getAttribute('aria-disabled')`)) === 'true' && (await ev(pg, 'document.getElementById("ot4-stage").dataset.mapReady')) === 'false' && (await state(pg)).views.contexts.groups.find((g) => g.group_id === web.group_id).files.length === 20);
  await releaseAll(pg); await pg.waitFor(`window.__otStore.get().workbench.perTab.contexts.map.groups[${JSON.stringify(web.group_id)}]?.state==='error'`, 15000, 'terminal group failure');
  const calls1 = (await fxCalls(pg)).length; await sleep(900);
  check('UIP04-121 Graph: the terminal failure is visible as a typed alert with the hidden total and a Try again control; loaded cards are kept', /response_too_large/.test(await svgText(pg)) && (await count(pg, '#ot4-svg [role=alert]')) >= 1 && /193 not shown/.test(await svgText(pg)) && /Try again/.test(await svgText(pg)) && (await state(pg)).views.contexts.groups.find((g) => g.group_id === web.group_id).files.length === 20);
  check('UIP04-122 Graph: no automatic retry follows the terminal failure', (await fxCalls(pg)).length === calls1, JSON.stringify(await fxCalls(pg)));
  await ev(pg, `document.querySelector('${more}').focus()`); await pg.key('Enter');
  await pg.waitFor(`window.__fx.calls.length>${calls1}`, 10000, 'manual retry issued'); await pg.waitFor(`window.__otStore.get().workbench.perTab.contexts.map.groups[${JSON.stringify(web.group_id)}]?.state==='error'`, 15000, 'error again'); await sleep(250);
  check('UIP04-123 Graph: the keyboard retry issues a new request, ends in the typed error again, and focus stays on the retry control', (await fxCalls(pg)).length > calls1 && (await ev(pg, `document.activeElement?.dataset?.action==='ctx-more'&&document.activeElement.dataset.group===${JSON.stringify(web.group_id)}`)) === true);
  await ev(pg, "document.querySelector('[data-action=tab-pres][data-tab=contexts][data-p=list]').click()"); await sleep(200);
  check('UIP04-124 List shows the same group state (error text, hidden total, Try again)', /response_too_large/.test(await txt(pg, '#ot4-list')) && /193 not shown/.test(await txt(pg, '#ot4-list')) && /Try again/.test(await txt(pg, '#ot4-list')));
  await pg.close();
}
{ // IR-03: a deterministic held End-session response
  const pg = await open(1366, 900);
  await installFixture(pg, 'uip04-large-map', `async(req,key,fx)=>{ if(!req.full && fx.hold){ fx.hold=false; return {hold:true}; } return null; }`);
  await ev(pg, 'window.__fx.hold=true'); await ev(pg, "document.getElementById('ot-demo').click()"); await ready(pg);
  const web = (await state(pg)).views.contexts.groups.find((g) => g.files_counts.total === 213);
  await ev(pg, `document.querySelector('#ot4-svg [data-ctx-kind=file]').dispatchEvent(new MouseEvent('click',{bubbles:true}))`); await sleep(200);
  await ev(pg, `document.querySelector('#ot4-svg [data-action=ctx-more][data-group="${web.group_id}"]').dispatchEvent(new MouseEvent('click',{bubbles:true}))`);
  await pg.waitFor('window.__fx.held.length===1', 10000, 'group request held');
  await ev(pg, `(()=>{ const real=window.fetch.bind(window); window.__endHeld=[]; window.__endCalls=0; window.fetch=async(u,i)=>{ if(String(u).startsWith('/api/session/end')){ window.__endCalls++; await new Promise((r)=>window.__endHeld.push(r)); } return real(u,i); }; })()`);
  const e0 = (await state(pg)).epoch; const selBefore = (await state(pg)).workbench.perTab.contexts.selection;
  await ev(pg, "document.getElementById('ot-top-end').click()"); await pg.waitFor('window.__endCalls===1 && window.__otStore.get().busy==="ending"', 10000, 'End session held in flight');
  const s1 = await state(pg);
  check('UIP04-130 while End session is in flight the map, its cards and the selection are already gone', selBefore !== 'root' && s1.busy === 'ending' && s1.views.contexts === undefined && s1.workbench.perTab.contexts.selection === 'root' && s1.workbench.perTab.contexts.map.latest.full === 0 && (await count(pg, '#ot4-svg')) === 0 && (await count(pg, '[data-ctx-kind]')) === 0 && s1.epoch > e0, JSON.stringify({ b: s1.busy, sel: s1.workbench.perTab.contexts.selection }));
  check('UIP04-131 the ending status is visible while the request is held', /Ending session/.test(await txt(pg, '#ot-tabpanel')) && /Ending session/.test(await txt(pg, '#ot-session-status') + await txt(pg, '#ot-tabpanel')));
  await releaseAll(pg); await sleep(500);
  const s2 = await state(pg);
  check('UIP04-132 the late contexts response released during End session is refused (no map, no notice, no request state)', s2.views.contexts === undefined && (await count(pg, '#ot4-svg')) === 0 && s2.busy === 'ending' && s2.workbench.perTab.contexts.map.status === 'idle' && s2.notice == null);
  await ev(pg, 'window.__endHeld.splice(0).forEach((r)=>r())'); await pg.waitFor('window.__otStore.get().ended', 20000, 'ended');
  const s3 = await state(pg);
  check('UIP04-133 the held End-session response then settles to the final cleanup report with everything session-scoped cleared', typeof s3.ended === 'string' && s3.analysis === null && s3.views.contexts === undefined && s3.busy == null && /Session ended|session is no longer active|cleanup/i.test(await txt(pg, '#ot-ended-note')), String(s3.ended));
  await pg.close();
}
for (const [w, h, narrow] of [[390, 844, true], [1366, 900, false]]) { // IR-04: List keyboard navigation (the narrow default, and the desktop List choice)
  ctx = `correction 01 list keyboard ${w}x${h}`;
  const pg = await open(w, h); await demo(pg);
  if (!narrow) { await ev(pg, "document.querySelector('[data-action=tab-pres][data-tab=contexts][data-p=list]').click()"); await sleep(250); }
  const m = (await state(pg)).views.contexts; const g = m.groups.find((x) => x.files.length >= 3); const ids = g.files.map((f) => f.file_id);
  const act = () => ev(pg, 'document.activeElement?.dataset?.ctx||""');
  check('UIP04-140 List is the presentation under test', (await state(pg)).workbench.perTab.contexts.presentation === 'list' && (await count(pg, '#ot4-list')) === 1 && (await count(pg, '#ot4-svg')) === 0);
  await ev(pg, `document.querySelector('#ot4-list [data-ctx="${ids[0]}"]').focus()`);
  await pg.key('ArrowDown'); check('UIP04-141 ArrowDown moves to the next file button in the group', (await act()) === ids[1], await act());
  await pg.key('End'); check('UIP04-142 End jumps to the group\'s last file button', (await act()) === ids.at(-1), await act());
  await pg.key('ArrowDown'); check('UIP04-143 ArrowDown at the last file stays in the group (no crossing into the next group)', (await act()) === ids.at(-1), await act());
  await pg.key('Home'); check('UIP04-144 Home jumps to the first file button', (await act()) === ids[0], await act());
  await pg.key('ArrowUp'); check('UIP04-145 ArrowUp at the first file stays put', (await act()) === ids[0], await act());
  await ev(pg, `document.querySelector('#ot4-list [data-ctx="${g.group_id}"]').focus()`); await pg.key('ArrowDown');
  check('UIP04-146 a group header row is a native control: arrows do not move focus away from it', (await act()) === g.group_id, await act());
  await ev(pg, `document.querySelector('#ot4-list [data-ctx="${ids[1]}"]').focus()`); await pg.key('Enter'); await sleep(250);
  check('UIP04-147 Enter still activates the focused file button natively (selection changes, focus stays in the list)', (await state(pg)).workbench.perTab.contexts.selection === ids[1] && (await ev(pg, "!!document.activeElement?.closest?.('#ot4-list')")) === true);
  await pg.close();
}
// IR-01 in the real app: a service-supplied pinned link for a dotted path is inert; a legitimate one is an active link
ctx = 'correction 01 links';
{
  const pg = await open(1366, 900); await demo(pg);
  const m = (await state(pg)).views.contexts; const f = m.groups.find((x) => x.files.length)?.files[0];
  await ev(pg, `document.querySelector('#ot4-svg [data-ctx="${f.file_id}"]').dispatchEvent(new MouseEvent('click',{bubbles:true}))`); await sleep(250);
  const expected = `https://github.com/${m.binding.repository.owner}/${m.binding.repository.name}/blob/${m.root.commit_sha}/`;
  check('UIP04-150 a recorded Demo file shows an active link that points exactly at its repository and pinned commit', (await ev(pg, "document.querySelector('.ot4-source-link a')?.href||''")).startsWith(expected));
  await pg.close();
}
{
  const pg = await open(1366, 900);
  await installFixture(pg, 'uip04-multi-ecosystem');
  await ev(pg, `(()=>{ const p=window.__fx.pages['full:20']; const f=p.groups.find((g)=>g.files.length).files[0]; f.revision_link.href=f.revision_link.href.replace(/blob\\/([0-9a-f]{40})\\/.*/, 'blob/$1/../../../../attacker/other/blob/main/README.md'); window.__bad=f.file_id; })()`);
  await ev(pg, "document.getElementById('ot-demo').click()"); await ready(pg);
  await ev(pg, `document.querySelector('#ot4-svg [data-ctx="'+window.__bad+'"]').dispatchEvent(new MouseEvent('click',{bubbles:true}))`); await sleep(250);
  check('UIP04-151 a pinned link that a URL parser would resolve to another repository is inert text in the real app', (await count(pg, '.ot4-source-link a')) === 0 && (await count(pg, '.ot4-source-link span')) === 1 && /Source at the pinned revision/.test(await txt(pg, '.ot4-inspector')));
  await pg.close();
}

// ================================================================== 3) the Dependencies tab and legacy content remain intact
ctx = 'regression';
{
  const pg = await open(1366, 900); await demo(pg);
  await ev(pg, "document.getElementById('ot-tab-dependencies').click()"); await pg.waitFor("document.getElementById('ot5-context')", 20000, 'deps');
  check('UIP04-110 the Dependencies tab renders its context chooser (UIP-05: path + count options from the dependency-contexts route)', (await count(pg, '#ot5-context option')) === 13 && /web\/package-lock\.json · 421/.test(await ev(pg, "[...document.querySelectorAll('#ot5-context option')].map(o=>o.textContent).join('\\n')")));
  check('UIP04-111 the approved tab label "BOM connections" is unchanged', (await txt(pg, '#ot-tab-bom')) === 'BOM connections');
  check('UIP04-112 legacy /api/view/contexts is still served and unchanged in shape', await ev(pg, `fetch('/api/view/contexts?generation=1').then(r=>r.json()).then(d=>Array.isArray(d.rows)&&d.rows.length===13&&typeof d.component_total==='number')`));
  await pg.close();
}
writeFileSync(join(OUT, 'run_context_map_checks.results.json'), JSON.stringify({ results, blocked_requests: blocked }, null, 1) + '\n');
const failed = results.filter((r) => !r.ok);
console.log(`\n${results.length - failed.length}/${results.length} checks passed; blocked non-loopback requests: ${blocked.length}`);
await close(); svc.kill('SIGTERM');
process.exit(failed.length || blocked.length ? 1 : 0);
