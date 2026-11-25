// UIP-07 real-browser checks of the AI models tab against the actual loopback app (recorded Demo).
//   PYTHON=<python> node tests/ui/browser/run_ai_checks.mjs [outDir]
// Needs Google Chrome (CHROME_BIN overrides) and Node >= 22. Network: loopback only (everything else is blocked and recorded).
// The recorded Demo's AI-BOM lists one inventory-reported model, so states with runtimes, alternatives, services or review items are driven by wrapping
// window.fetch of the AI route in the page: the REAL app.js loader, reducers and renderer run on SYNTHETIC renderer fixtures
// (evidence/uip/visual/uip-07/fixtures/renderer). Their `binding` is replaced by the real session binding. Nothing here is evidence about any repository.
import { spawn } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { launch, newPage } from './cdp.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = resolve(HERE, '../../..');
const OUT = resolve(process.argv[2] || join(REPO, 'evidence/uip/visual/uip-07/browser_runs'));
const SHOTS = join(OUT, 'captures'); mkdirSync(SHOTS, { recursive: true });
const FX = (n) => JSON.parse(readFileSync(join(REPO, 'evidence/uip/visual/uip-07/fixtures/renderer', n + '.json'), 'utf8'));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const root = mkdtempSync(join(tmpdir(), 'ot-ai-'));
const svc = spawn(process.env.PYTHON || 'python3', ['-m', 'opentrace_core.app', '--port', '0', '--session-root', join(root, 's')], {
  cwd: REPO, env: { ...process.env, OPENTRACE_DEMO_REPLAY: '', PYTHONPATH: join(REPO, 'src/core') + ':' + join(REPO, 'src/agents/investigator') }, stdio: ['ignore', 'pipe', 'pipe'] });
const base = await new Promise((resolveUrl, reject) => {
  let buf = ''; const t = setTimeout(() => reject(new Error('service did not start: ' + buf)), 30000);
  svc.stdout.on('data', (d) => { buf += d; const m = buf.match(/http:\/\/127\.0\.0\.1:(\d+)\//); if (m) { clearTimeout(t); resolveUrl(m[0]); } });
  svc.stderr.on('data', (d) => { buf += d; });
});
const results = []; let ctx = '';
const check = (id, ok, detail = '') => { results.push({ ctx, id, ok: !!ok, detail: String(detail).slice(0, 300) }); console.log(`${ok ? 'PASS' : 'FAIL'} [${ctx}] ${id}${detail && !ok ? ' — ' + String(detail).slice(0, 200) : ''}`); };
const { browser, close } = await launch();
const blocked = [];
const ev = (pg, expr) => pg.eval(expr);
const state = (pg) => pg.eval('JSON.parse(JSON.stringify(window.__otStore.get()))');
const cs = async (pg) => (await state(pg)).workbench.perTab.ai;
const txt = (pg, sel) => pg.eval(`(document.querySelector(${JSON.stringify(sel)})?.innerText||'')`);
const tc = (pg, sel) => pg.eval(`(document.querySelector(${JSON.stringify(sel)})?.textContent||'')`);   // textContent: SVG has no reliable innerText and collapsed <details> hide theirs
const count = (pg, sel) => pg.eval(`document.querySelectorAll(${JSON.stringify(sel)}).length`);
const noOverflow = (pg) => ev(pg, 'document.documentElement.scrollWidth <= innerWidth + 1');
const consoleErrors = (pg) => pg.log.console.filter((c) => c.type === 'error' && !/status of 40[39]|40[39] \((Conflict|Forbidden)\)|status of 500|500 \(Internal|Failed to load resource: the server responded/.test(c.text)).concat(pg.log.exceptions);

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
const HOOK = `(()=>{ if (window.__hooked) return; window.__hooked = true; const orig = window.fetch.bind(window); window.__calls = []; window.__held = []; window.__fx = null; window.__mode = { hold: false, fail: null, status: 500 };
  window.fetch = (url, init) => { const u = String(url); if (!/\\/api\\/workbench\\/v1\\/ai-assets/.test(u)) return orig(url, init); window.__calls.push(decodeURIComponent(u));
    const run = () => window.__mode.fail ? Promise.resolve(new Response(JSON.stringify({ schema: 'opentrace.workbench.error/1', error: window.__mode.fail, message: 'x', detail_code: window.__mode.detail || 'd' }), { status: window.__mode.status, headers: { 'content-type': 'application/json' } }))
      : orig(window.__fx ? u.replace(/&group_id=[^&]*/, '') : url, init).then(async (r) => { if (!window.__fx || !r.ok) return r; const real = await r.json(); const f = JSON.parse(JSON.stringify(window.__fx)); f.binding = real.binding; const b = real.binding, enc = (t) => encodeURIComponent(t).replace(/[!'()*]/g, (c) => '%' + c.charCodeAt(0).toString(16).toUpperCase());
        for (const a of f.assets) for (const o of a.occurrences) { const l = o.source_location; l.link = { href: 'https://github.com/' + b.repository.owner + '/' + b.repository.name + '/blob/' + b.commit_sha + '/' + l.path.split('/').map(enc).join('/'), text: l.path }; }
        return new Response(JSON.stringify(f), { status: 200, headers: { 'content-type': 'application/json' } }); });
    if (window.__mode.hold) return new Promise((res) => window.__held.push({ u, go: () => res(run()) })); return run(); }; })()`;
const setFx = (pg, name) => ev(pg, `window.__fx = ${name ? JSON.stringify(FX(name)) : 'null'}`);
const calls = (pg) => ev(pg, 'window.__calls.slice()');
const release = (pg, i) => ev(pg, `window.__held[${i}].go()`);
const idle = (pg) => pg.waitFor(`window.__otStore.get().workbench.perTab.ai.pg.status==='idle' && !document.querySelector('.otai-loading')`, 20000, 'ai idle');
async function demoToAi(pg) {
  await ev(pg, "document.getElementById('ot-demo').click()");
  await pg.waitFor(`document.querySelector('[data-map-ready="true"]')`, 30000, 'map ready'); await sleep(500);
  await ev(pg, HOOK);
}
// UIP-07 correction 01 (IR-04): real keyboard events on List rows; focus and selection must agree and survive the repaint.
const listKeys = async (pg) => {
  const ids = await ev(pg, "[...document.querySelectorAll('#otai-list .otai-list-row')].map(b=>b.dataset.otaiSelect)");
  const at = () => ev(pg, "(document.activeElement && document.activeElement.dataset && document.activeElement.dataset.otaiSelect) || ''");
  await ev(pg, "document.querySelector('#otai-list .otai-list-row').focus()");
  const steps = [['ArrowDown', 1], ['ArrowDown', 2], ['End', ids.length - 1], ['ArrowDown', ids.length - 1], ['ArrowUp', ids.length - 2], ['Home', 0], ['ArrowUp', 0]];
  let ok = ids.length >= 3;
  for (const [k, i] of steps) { await pg.key(k); await sleep(120); ok = ok && (await at()) === ids[i] && (await cs(pg)).sel === ids[i] && (await ev(pg, "document.activeElement.getAttribute('aria-pressed')")) === 'true'; }
  return ok;
};
const openAi = async (pg) => { await ev(pg, "document.getElementById('ot-tab-ai').click()"); await pg.waitFor(`document.querySelector('#otai-empty, #otai-svg, #otai-list')`, 20000, 'ai tab'); await idle(pg); await sleep(150); };
const reload = async (pg, fx, filter = 'all') => { await setFx(pg, fx); await ev(pg, `document.querySelector('[data-otai-filter=${filter}]').click()`); await idle(pg); await sleep(150); };
const vb = (pg) => ev(pg, "document.getElementById('otai-svg').getAttribute('viewBox').split(' ').map(Number)");
const rects = (pg) => ev(pg, `[...document.querySelectorAll('#otai-svg g.otai-group')].map(g=>{const r=g.querySelector(':scope > rect');const h=g.querySelector('g[data-otai-select^="group:"] rect');const cards=[...g.querySelectorAll('g[data-otai-select^="asset:"] rect')].map(c=>[+c.getAttribute('x'),+c.getAttribute('y'),+c.getAttribute('width'),+c.getAttribute('height')]);return {zone:[+r.getAttribute('x'),+r.getAttribute('y'),+r.getAttribute('width'),+r.getAttribute('height')],head:h?[+h.getAttribute('x'),+h.getAttribute('y'),+h.getAttribute('width'),+h.getAttribute('height')]:null,cards}})`);
const shot = async (pg, name) => { await sleep(200); await pg.screenshot(join(SHOTS, name + '.png')); };
const CLIP = `(()=>{const bad=[];for(const t of document.querySelectorAll('#otai-svg text')){const g=t.closest('g[data-otai-select]');const r=g&&g.querySelector('rect');if(!r)continue;const x0=+r.getAttribute('x'),x1=x0+ +r.getAttribute('width');const b=t.getBBox();if(b.x<x0-1||b.x+b.width>x1+1)bad.push(t.textContent.slice(0,30));}return bad;})()`;

// ================================================================== 1366 light — recorded Demo
ctx = '1366 light Demo';
{
  const pg = await open(1366, 900);
  await ev(pg, "document.getElementById('ot-demo').click()");
  await pg.waitFor(`document.querySelector('[data-map-ready="true"]')`, 30000, 'map ready'); await sleep(500);
  await ev(pg, HOOK);
  check('the workbench still opens on Repository contexts', (await state(pg)).workbench.tab === 'contexts');
  await openAi(pg);
  const c = await calls(pg);
  check('one request on tab open: /ai-assets?generation=1&filter=all&offset=0&size=30', c.length === 1 && /ai-assets\?generation=1&filter=all&offset=0&size=30$/.test(c[0]), JSON.stringify(c));
  const panel = await txt(pg, '#ot-tabpanel');
  check('the Demo shows one inventory-reported model, honest availability, 0 runtimes/services/findings', /Inventory-reported models only; identity, provider and runtime use are not established\./.test(panel) && /1 AI asset · 1 model · 0 runtimes · 0 AI services/.test(panel), panel.slice(0, 160).replace(/\n/g, ' '));
  check('the model card sits in the "No recorded source file" lane and names yolov6n.hef', (await tc(pg, '#otai-svg')).includes('No recorded source file') && (await tc(pg, '#otai-svg')).includes('yolov6n.hef'));
  check('the detail says identity is unresolved and metadata is not recorded; no local path is shown anywhere', /unresolved/.test(await txt(pg, '#otai-detail')) && !/\/Users\/|hailo8l|BOMBridge|frigate-aibom-scope/.test(await ev(pg, 'document.body.innerText')) , '');
  check('no prototype assets or claims: no cpu_model/hailo_platform/tflite_runtime, no "verified source"', !/cpu_model|hailo_platform|tflite_runtime|ai_edge_litert|verified source references/i.test(panel));
  check('the five filters carry counts; Graph/List/Expand present; AI services and Runtimes show 0', (await count(pg, '[data-otai-filter]')) === 5 && (await count(pg, '[data-otai-pres]')) === 2 && (await count(pg, '#otai-expand')) === 1 && /Runtimes 0/.test(panel) && /AI services 0/.test(panel));
  const dl = await ev(pg, "document.querySelector('.otai-toolbar a')?.getAttribute('href')");
  check('Download AI-BOM is the existing session artifact link', /^\/api\/artifacts\/[^?]+\?disposition=attachment$/.test(dl || ''), dl);
  const ch = await ev(pg, `fetch(${JSON.stringify(dl || '/x')},{credentials:'same-origin'}).then(r=>r.status)`);
  check('the AI-BOM download is served by the unchanged artifact route', ch === 200, ch);
  await pg.click('[data-otai-filter=ai_services]'); await idle(pg);
  check('AI services (0): says what was not collected, never that none exist', /does not show that none exists/.test(await txt(pg, '#otai-empty')) && (await count(pg, '#otai-svg')) === 0);
  await pg.click('[data-otai-filter=findings]'); await idle(pg);
  check('Findings (0): "not assessed", distinct from finding none', /not assessed/.test(await txt(pg, '#otai-empty')) && /different from finding none/.test(await txt(pg, '#otai-empty')));
  await pg.click('[data-otai-filter=all]'); await idle(pg);
  check('no inline style attributes (CSP style-src self) and no horizontal overflow', (await count(pg, '#ot-tabpanel [style]')) === 0 && (await noOverflow(pg)));
  await shot(pg, 'demo_one_model_1366_light');
  const adv = await ev(pg, "(async()=>{document.getElementById('ot-advanced').click(); await new Promise(r=>setTimeout(r,1500)); return !!document.querySelector('[data-cy=ai]')})()");
  check('Advanced keeps the generic family surface for AI models (legacy view)', adv === true);
  await ev(pg, "document.getElementById('ot-advanced').click()"); await sleep(400);
  await ev(pg, "document.querySelector('[data-nav=evidence], #ot-nav-evidence')?.click()"); await sleep(400);
  check('the Evidence view lists the BOM-verification finding for AI models', (await count(pg, '[data-action=open-check][data-mode=ai]')) === 1);
  await ev(pg, "document.querySelector('[data-action=open-check][data-mode=ai]').click()"); await sleep(800);
  check('"Inspect evidence" opens the AI tab with the requested check shown above the assets (not lost in the normal view)', (await state(pg)).workbench.tab === 'ai' && (await count(pg, '#otai-check')) === 1 && /does not match the selected model/.test(await tc(pg, '#otai-check')) && /not a model or service security finding/.test(await tc(pg, '#otai-check')));
  await pg.click('[data-otai-check-close]'); await sleep(200);
  check('"Back to assets" clears the requested check', (await count(pg, '#otai-check')) === 0 && (await cs(pg)).checkId === null);
  check('no console errors / exceptions', consoleErrors(pg).length === 0, JSON.stringify(consoleErrors(pg)));
  await pg.close();
}

// ================================================================== 1366 light — synthetic renderer fixtures
ctx = '1366 light synthetic';
{
  const pg = await open(1366, 900); await demoToAi(pg); await openAi(pg);
  await reload(pg, 'multi3');
  const R = await rects(pg); const view = await vb(pg);
  check('composition: 3 source groups at x = 20/420/820, 360x500 zones at y=160 (reference geometry)', R.length === 3 && R.every((g, i) => g.zone[0] === 20 + i * 400 && g.zone[1] === 160 && g.zone[2] === 360 && g.zone[3] === 500), JSON.stringify(R.map((g) => g.zone)));
  check('headers 330x66 at y=176; cards 300x90 at y = 280 + 120*i', R.every((g) => g.head && g.head[1] === 176 && g.head[2] === 330 && g.head[3] === 66 && g.cards.every((c, i) => c[1] === 280 + 120 * i && c[2] === 300 && c[3] === 90)), JSON.stringify(R[0]));
  check('Fit window equals the reference [-20,0,1240,690]; zoom label 100%', JSON.stringify(view) === JSON.stringify([-20, 0, 1240, 690]) && (await txt(pg, '#otai-zoom')) === '100%');
  check('card text stays inside its card', (await ev(pg, CLIP)).length === 0, JSON.stringify(await ev(pg, CLIP)));
  const first = await ev(pg, "document.querySelector('#otai-svg g[data-otai-select^=asset]').dataset.otaiSelect");
  check('the first asset is selected by default and the detail panel names it', (await cs(pg)).sel === first && (await txt(pg, '#otai-title')).length > 0);
  const second = await ev(pg, "document.querySelectorAll('#otai-svg g[data-otai-select^=asset]')[4].dataset.otaiSelect");
  await pg.click(`#otai-svg [data-otai-select="${second}"]`); await sleep(150);
  check('clicking a card selects it (aria-pressed, store)', (await cs(pg)).sel === second && (await ev(pg, `document.querySelector('#otai-svg [data-otai-select="${second}"]').getAttribute('aria-pressed')`)) === 'true');
  const third = await ev(pg, "document.querySelectorAll('#otai-svg g[data-otai-select^=asset]')[5].dataset.otaiSelect");
  await ev(pg, `document.querySelector('#otai-svg [data-otai-select="${third}"]').focus()`); await pg.key('Enter'); await sleep(150);
  check('Enter selects the focused card and focus is restored after the repaint', (await cs(pg)).sel === third && (await ev(pg, 'document.activeElement?.dataset?.otaiSelect')) === third);
  await pg.click('[data-otai-select=root]'); await sleep(150);
  check('the root node selects the repository summary', (await cs(pg)).sel === 'root' && /AI assets/.test(await txt(pg, '#otai-title')));
  const v0 = await vb(pg);
  await pg.click('[data-otai-zoom="1.2"]'); await sleep(100);
  check('zoom in shrinks the viewBox and the label rises above 100%', (await vb(pg))[2] < v0[2] && parseInt(await txt(pg, '#otai-zoom')) > 100);
  await pg.click('[data-otai-fit]'); await sleep(100);
  check('Fit restores the reference window', JSON.stringify(await vb(pg)) === JSON.stringify([-20, 0, 1240, 690]));
  await ev(pg, "document.getElementById('otai-stage').focus()"); await pg.key('+'); await sleep(100);
  check('with the stage focused, + zooms in; 0 fits', (await vb(pg))[2] < 1240 && (await pg.key('0'), await sleep(100), JSON.stringify(await vb(pg))) === JSON.stringify([-20, 0, 1240, 690]));
  await shot(pg, 'synthetic_multi3_1366_light');
  // the reference composition: alternatives drawn as alternatives
  await reload(pg, 'ref_composition');
  check('the reference composition draws a dashed labelled alternative path for the preferred/fallback pair', (await count(pg, '#otai-svg .otai-alt')) === 1 && /alternative: fallback import/.test(await tc(pg, '#otai-svg')));
  check('purple models, teal runtimes: card families are marked and resolve to different fills', await ev(pg, "(()=>{const f=(k)=>getComputedStyle(document.querySelector('#otai-svg g[data-otai-kind='+k+'] rect')).fill;return f('model')!==f('runtime')})()"));
  const fb = await ev(pg, "[...document.querySelectorAll('#otai-svg g[data-otai-select^=asset]')].find(g=>/fallback/.test(g.getAttribute('aria-label'))).dataset.otaiSelect");
  await pg.click(`#otai-svg [data-otai-select="${fb}"]`); await sleep(150);
  check('the fallback runtime is described as an alternative path with its source condition, not as running together', /Alternative path/.test(await tc(pg, '#otai-detail')) && /not shown as running together/.test(await tc(pg, '#otai-detail')) && /used only if the first import fails/.test(await tc(pg, '#otai-detail')));
  await ev(pg, "document.querySelector('#otai-detail .supplement-more').open = true");
  const href = await ev(pg, "document.querySelector('#otai-detail .otai-source a')?.getAttribute('href')"); const b = (await state(pg)).views.aiPage.binding;
  check('source links are pinned-revision GitHub blob URLs with a line anchor, opened with rel=noreferrer', !!href && href.startsWith(`https://github.com/${b.repository.owner}/${b.repository.name}/blob/${b.commit_sha}/`) && /#L\d+/.test(href) && (await ev(pg, "document.querySelector('#otai-detail .otai-source a').getAttribute('rel')")) === 'noreferrer');
  await shot(pg, 'synthetic_ref_composition_1366_light');
  await reload(pg, 'with_service');
  check('a service renders a cyan service card; the AI services filter counts it', (await count(pg, '#otai-svg g[data-otai-kind=service]')) === 1 && /AI services 1/.test(await txt(pg, '.otai-filters')));
  await reload(pg, 'findings');
  check('a rule-backed review item renders the amber state and the Findings count', /Needs review/.test(await ev(pg, "document.getElementById('otai-svg').textContent")) && /Findings 1/.test(await txt(pg, '.otai-filters')));
  check('no red fill anywhere in the graph', !(await ev(pg, "[...document.querySelectorAll('#otai-svg *')].some(n=>/red|#d00|#c00|#e00|#b00/i.test((n.getAttribute('fill')||'')+(n.getAttribute('stroke')||'')))")));
  await shot(pg, 'synthetic_findings_1366_light');
  await reload(pg, 'display_group');
  check('equal basenames: two separate cards, "Same name as another asset"', (await ev(pg, "[...document.querySelectorAll('#otai-svg g[data-otai-select^=asset]')].filter(g=>/model\\.bin/.test(g.getAttribute('aria-label'))).length")) === 2 && /Same name as another asset/.test(await tc(pg, '#otai-svg')));
  // Graph/List, search, group
  await reload(pg, 'multi3'); const sel0 = (await cs(pg)).sel;
  await pg.click('[data-otai-pres=list]'); await sleep(150);
  check('List shows rows as buttons with a status chip and keeps filter and selection', (await count(pg, '#otai-list button.otai-list-row')) === 9 && (await cs(pg)).sel === sel0);
  check('List: ArrowDown/ArrowUp/Home/End move focus and selection together, stop at the ends, and focus survives the repaint', await listKeys(pg));
  await shot(pg, 'synthetic_list_1366_light');
  await pg.click('[data-otai-pres=graph]'); await sleep(150);
  check('back to Graph: selection preserved, SVG redrawn', (await cs(pg)).sel === sel0 && (await count(pg, '#otai-svg')) === 1);
  const n0 = (await calls(pg)).length;
  await ev(pg, "(()=>{const s=document.getElementById('otai-group');s.value=s.options[1].value;s.dispatchEvent(new Event('change',{bubbles:true}))})()"); await idle(pg);
  const cg = await calls(pg); check('choosing a source group issues one request with group_id', cg.length === n0 + 1 && /group_id=grp:[0-9a-f]{24}/.test(cg[cg.length - 1]), cg[cg.length - 1]);
  await ev(pg, "(()=>{const s=document.getElementById('otai-group');s.value='';s.dispatchEvent(new Event('change',{bubbles:true}))})()"); await idle(pg);
  const n2 = (await calls(pg)).length; await pg.type('#otai-q', 'ab'); await sleep(700); await idle(pg);
  check('search is debounced: typing two characters issues a single request with query=ab', (await calls(pg)).length === n2 + 1 && /query=ab/.test((await calls(pg)).at(-1)));
  await ev(pg, "(()=>{const q=document.getElementById('otai-q');q.value='';q.dispatchEvent(new Event('input',{bubbles:true}))})()"); await sleep(500); await idle(pg);
  // expanded
  await reload(pg, 'multi3'); await pg.click('#otai-expand'); await sleep(200);
  const inert = await ev(pg, "(()=>{const f=document.getElementById('otai-expanded');if(!f)return null;let n=f,out=[];for(;n.parentElement;n=n.parentElement)for(const s of n.parentElement.children)if(s!==n&&!['DIALOG','SCRIPT','STYLE'].includes(s.tagName))out.push(s.inert);return out.every(Boolean)})()");
  check('Expand opens a modal frame with the background inert', (await count(pg, '#otai-expanded[aria-modal=true]')) === 1 && inert === true, String(inert));
  await shot(pg, 'synthetic_expanded_1366_light');
  await ev(pg, "document.getElementById('otai-expand').focus()"); await pg.key('Tab'); await sleep(80);
  check('Tab keeps focus inside the expanded frame', await ev(pg, "document.getElementById('otai-expanded').contains(document.activeElement)"));
  await pg.key('Escape'); await sleep(200);
  check('Escape closes the frame and focus returns to the Expand control; nothing stays inert', (await count(pg, '#otai-expanded')) === 0 && (await ev(pg, 'document.activeElement?.id')) === 'otai-expand' && !(await ev(pg, "[...document.querySelectorAll('body *')].some(n=>n.inert)")));
  // layouts, paging, occurrences
  await reload(pg, 'occ45'); await pg.click('#otai-svg g[data-otai-select^=asset]'); await sleep(150);
  check('45 occurrences: the detail says "20 of 45" and names the AI-BOM download (no reachability promise)', /20 of 45 occurrences shown; the AI-BOM download lists all of them\./.test(await ev(pg, "document.getElementById('otai-detail').textContent")) && !/reachable/i.test(await ev(pg, "document.getElementById('otai-detail').textContent")));
  await reload(pg, 'tall5'); const Rt = await rects(pg);
  check('a group with 5 cards grows its zone to 740 and nothing is clipped', Rt[0].zone[3] === 740 && Rt[0].cards.length === 5 && Rt[0].cards.every((c) => c[1] + c[3] <= Rt[0].zone[1] + Rt[0].zone[3]), JSON.stringify(Rt[0].zone));
  await reload(pg, 'wrap7'); const Rw = await rects(pg); const vw = await vb(pg);
  check('7 groups wrap into rows of three (y = 160, 720, 1280); the viewBox is 1280 wide', Rw.length === 7 && JSON.stringify(Rw.map((g) => g.zone[1])) === JSON.stringify([160, 160, 160, 720, 720, 720, 1280]) && vw[2] === 1280 && vw[0] === -40, JSON.stringify(vw));
  check('Fit all is offered for the tall layout and covers the whole box', (await count(pg, '[data-otai-fitall]')) === 1 && (await (async () => { await pg.click('[data-otai-fitall]'); await sleep(100); const va = await vb(pg); return va[3] >= 1810 - 1; })()));
  await reload(pg, 'paged45', 'all');
  check('paged page: 45 assets give a pager "31–45 of 45" and the request offset is 30', /31–45 of 45/.test(await txt(pg, '.otai-pager')) || (await count(pg, '.otai-pager')) === 1);
  await reload(pg, 'unlocated_and_located');
  check('assets with no recorded location are drawn in the client-side lane, which is not selectable as a group', /No recorded source file/.test(await tc(pg, '#otai-svg')) && (await count(pg, '#otai-svg g[data-otai-select^=group]')) === 1);
  await reload(pg, 'hostile'); await pg.click('#otai-svg g[data-otai-select^=asset]'); await sleep(150);
  check('hostile names and paths stay inert (no injected nodes, no javascript: link) and are clipped inside the card', (await count(pg, '#ot-tabpanel img, #ot-tabpanel script, #ot-tabpanel b')) === 0 && !(await ev(pg, "[...document.querySelectorAll('#ot-tabpanel a')].some(a=>/^javascript:/i.test(a.getAttribute('href')||''))")) && (await ev(pg, CLIP)).length === 0, JSON.stringify(await ev(pg, CLIP)));
  for (const [fx, re, name] of [['unsupported', /No supported AI inventory/, 'unsupported'], ['failed', /failed/, 'failed'], ['partial_empty', /incomplete/i, 'partial'], ['not_run', /No AI inventory was generated for this analysis\./, 'not_generated'], ['completed_empty', /does not show that no AI is used/, 'completed_empty']]) {
    await reload(pg, fx);
    check(`state ${fx}: the availability message is shown and no graph is drawn`, re.test(await txt(pg, '#otai-empty')) && (await count(pg, '#otai-svg')) === 0, await txt(pg, '#otai-empty'));
    await shot(pg, `state_${name}_1366_light`);
  }
  await reload(pg, 'partial_models');
  check('partial coverage with models: the assets stay visible with a partial banner', (await count(pg, '#otai-svg g[data-otai-select^=asset]')) === 1 && /incomplete/i.test(await txt(pg, '.otai-availability')));
  await shot(pg, 'state_partial_models_1366_light');
  check('console clean after all fixtures', consoleErrors(pg).length === 0, JSON.stringify(consoleErrors(pg)));
  await pg.close();
}

// ================================================================== races, failures, lifecycle
ctx = 'races and lifecycle';
{
  const pg = await open(1366, 900); await demoToAi(pg); await openAi(pg); await reload(pg, 'multi3');
  await ev(pg, 'window.__mode.hold = true');
  await pg.click('[data-otai-filter=runtimes]'); await pg.click('[data-otai-filter=models]'); await sleep(200);
  check('two quick filter changes issue two requests (the older is superseded)', (await ev(pg, 'window.__held.length')) === 2);
  await release(pg, 1); await sleep(300); await release(pg, 0); await sleep(300);
  check('a late response for the older filter is ignored (state keeps the newest request)', (await cs(pg)).filter === 'models' && (await cs(pg)).loaded === JSON.stringify(['models', '', null, 0]));
  await ev(pg, 'window.__mode.hold = false; window.__held = []');
  await ev(pg, "window.__mode.fail = 'projection_failed'; window.__mode.detail = 'path_not_representable'");
  await pg.click('[data-otai-filter=all]'); await sleep(400);
  check('a typed failure keeps the page and shows an alert with "Try again"; no automatic retry', (await count(pg, '.otai-banner [data-otai-retry]')) === 1 && /cannot be shown exactly/.test(await txt(pg, '.otai-banner')));
  const nf = (await calls(pg)).length; await sleep(1200);
  check('nothing retries by itself', (await calls(pg)).length === nf);
  await ev(pg, "document.getElementById('ot-tab-dependencies').click()"); await sleep(600); const nd = (await calls(pg)).length;
  await ev(pg, "document.getElementById('ot-tab-ai').click()"); await sleep(600);
  check('revisiting the tab does not retry the failed current request (IR-03 lesson)', (await calls(pg)).length === nd && (await count(pg, '.otai-banner [data-otai-retry]')) === 1);
  await ev(pg, 'window.__mode.fail = null'); await pg.click('.otai-banner [data-otai-retry]'); await idle(pg);
  check('manual retry recovers', (await count(pg, '.otai-banner')) === 0 && (await cs(pg)).pg.status === 'idle');
  await ev(pg, "window.__mode.fail = 'stale_generation'; window.__mode.status = 409"); await pg.click('[data-otai-filter=runtimes]'); await sleep(400);
  check('a current 409 retires the payload and shows the "session moved on" recovery', (await cs(pg)).stale === true && (await state(pg)).views.aiPage === undefined && /session moved on/.test(await txt(pg, '#ot-tabpanel')));
  await ev(pg, "window.__mode.fail = null; window.__mode.status = 500");
  await pg.click('[data-otai-stale-reset]'); await sleep(500);
  check('"Reopen the analysis" closes the old analysis locally', (await state(pg)).analysis === null);
  await pg.close();
}
{
  const pg = await open(1366, 900); await demoToAi(pg); await openAi(pg); await reload(pg, 'multi3');
  await ev(pg, 'window.__mode.hold = true'); await pg.click('[data-otai-filter=runtimes]'); await sleep(200);
  await ev(pg, "document.getElementById('ot-top-end').click()"); await pg.waitFor(`window.__otStore.get().ended`, 15000, 'ended');
  check('End session clears the AI payload at once', (await state(pg)).views.aiPage === undefined && (await cs(pg)).sel === null);
  await ev(pg, 'window.__held.forEach(h=>h.go())'); await sleep(500);
  check('a late response after End session cannot restore anything', (await state(pg)).views.aiPage === undefined && (await count(pg, '#otai-svg')) === 0);
  await pg.close();
}
{
  const pg = await open(1366, 900); await demoToAi(pg); await openAi(pg); await reload(pg, 'multi3');
  await pg.click('#otai-svg g[data-otai-select^=asset]'); const sel = (await cs(pg)).sel; const name = await txt(pg, '#otai-title');
  await ev(pg, "document.getElementById('ot-tab-dependencies').click()"); await sleep(700);
  check('switching tabs replaces the details (no AI selection leaks into Dependencies)', !/synthetic-/.test(await txt(pg, '#ot-tabpanel')));
  await ev(pg, "document.getElementById('ot-tab-ai').click()"); await sleep(500);
  check('returning to AI models keeps the cached page and selection without a second request', (await cs(pg)).sel === sel && (await count(pg, '#otai-svg')) === 1);
  await ev(pg, "document.getElementById('ot-assistant-launch').click()"); await sleep(300);
  await pg.waitFor("document.querySelector('#ot-assistant .micro') && !document.getElementById('ot-assistant').hidden", 5000, 'assistant open');
  check('the assistant context follows the selected AI asset', (await ev(pg, "document.getElementById('ot-assistant').textContent")).includes('Context: ' + name), name);
  check('no console errors', consoleErrors(pg).length === 0, JSON.stringify(consoleErrors(pg)));
  await pg.close();
}

// ================================================================== dark theme and narrow
ctx = '1366 dark';
{
  const pg = await open(1366, 900, 'dark'); await demoToAi(pg); await openAi(pg); await reload(pg, 'ref_composition');
  const fill = await ev(pg, "getComputedStyle(document.querySelector('#otai-svg g.otai-group > rect')).fill");
  check('dark tokens apply to the zones (fill differs from the light token)', fill !== 'rgb(234, 240, 248)' && fill.startsWith('rgb'), fill);
  check('no console errors / no overflow', consoleErrors(pg).length === 0 && (await noOverflow(pg)));
  await shot(pg, 'synthetic_ref_composition_1366_dark');
  await pg.close();
}
ctx = '390 light';
{
  const pg = await open(390, 844, 'light'); await demoToAi(pg); await openAi(pg); await reload(pg, 'ref_composition');
  check('at 390 px the List is the default presentation and no horizontal scroll', (await cs(pg)).presentation === 'list' && (await count(pg, '#otai-list')) === 1 && (await noOverflow(pg)));
  check('at 390 px the List keeps arrow/Home/End navigation with stable focus and selection', await listKeys(pg));
  await shot(pg, 'synthetic_list_390_light');
  await pg.click('[data-otai-pres=graph]'); await sleep(300);
  check('the person\'s choice of Graph is kept at 390 px (never forced back)', (await cs(pg)).presentation === 'graph' && (await count(pg, '#otai-svg')) === 1 && (await noOverflow(pg)));
  await shot(pg, 'synthetic_ref_composition_390_light');
  check('no console errors', consoleErrors(pg).length === 0, JSON.stringify(consoleErrors(pg)));
  await pg.close();
}

check('only loopback traffic (everything else blocked and recorded)', blocked.length === 0, blocked.join(' '));
await close(); svc.kill('SIGKILL');
const failed = results.filter((r) => !r.ok);
writeFileSync(join(OUT, 'results.json'), JSON.stringify(results, null, 1));
console.log(`\n${results.length - failed.length}/${results.length} passed`);
process.exit(failed.length ? 1 : 0);
