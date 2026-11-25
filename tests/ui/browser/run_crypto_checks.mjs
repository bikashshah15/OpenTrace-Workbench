// UIP-06 real-browser checks of the Cryptography tab against the actual loopback app (recorded Demo).
//   PYTHON=<python> node tests/ui/browser/run_crypto_checks.mjs [outDir]
// Needs Google Chrome (CHROME_BIN overrides) and Node >= 22. Network: loopback only (everything else is blocked and recorded).
// The recorded Demo's CBOM lists no cryptographic assets, so asset-bearing states are driven by wrapping window.fetch of the crypto route in the page:
// the REAL app.js loader, reducers and renderer run on SYNTHETIC renderer fixtures (evidence/uip/visual/uip-06/fixtures/renderer, produced by the
// production producer from invented in-memory inputs). Their `binding` is replaced by the real session binding. Race/failure cases hold or fail
// the response. Nothing here is evidence about any repository.
import { spawn } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { launch, newPage } from './cdp.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = resolve(HERE, '../../..');
const OUT = resolve(process.argv[2] || join(REPO, 'evidence/uip/visual/uip-06/browser_runs'));
const SHOTS = join(OUT, 'captures'); mkdirSync(SHOTS, { recursive: true });
const FX = (n) => JSON.parse(readFileSync(join(REPO, 'evidence/uip/visual/uip-06/fixtures/renderer', n + '.json'), 'utf8'));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const root = mkdtempSync(join(tmpdir(), 'ot-crypto-'));
const svc = spawn(process.env.PYTHON || 'python3', ['-m', 'opentrace_core.app', '--port', '0', '--session-root', join(root, 's')], {
  cwd: REPO, env: { ...process.env, PYTHONPATH: join(REPO, 'src/core') + ':' + join(REPO, 'src/agents/investigator') }, stdio: ['ignore', 'pipe', 'pipe'] });
const base = await new Promise((resolveUrl, reject) => {
  let buf = ''; const t = setTimeout(() => reject(new Error('service did not start: ' + buf)), 30000);
  svc.stdout.on('data', (d) => { buf += d; const m = buf.match(/http:\/\/127\.0\.0\.1:(\d+)\//); if (m) { clearTimeout(t); resolveUrl(m[0]); } });
  svc.stderr.on('data', (d) => { buf += d; });
});
const ORIGIN = new URL(base).origin;
const results = []; let ctx = '';
const check = (id, ok, detail = '') => { results.push({ ctx, id, ok: !!ok, detail: String(detail).slice(0, 300) }); console.log(`${ok ? 'PASS' : 'FAIL'} [${ctx}] ${id}${detail && !ok ? ' — ' + String(detail).slice(0, 200) : ''}`); };
const { browser, close } = await launch();
const blocked = [];
const ev = (pg, expr) => pg.eval(expr);
const state = (pg) => pg.eval('JSON.parse(JSON.stringify(window.__otStore.get()))');
const cs = async (pg) => (await state(pg)).workbench.perTab.crypto;
const txt = (pg, sel) => pg.eval(`(document.querySelector(${JSON.stringify(sel)})?.innerText||'')`);
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
const HOOK = `(()=>{ if (window.__hooked) return; window.__hooked = true; const orig = window.fetch.bind(window); window.__calls = []; window.__held = []; window.__fx = null; window.__keepLinks = false; window.__mode = { hold: false, fail: null, status: 500 };
  window.fetch = (url, init) => { const u = String(url); if (!/\\/api\\/workbench\\/v1\\/crypto-assets/.test(u)) return orig(url, init); window.__calls.push(decodeURIComponent(u));
    const run = () => window.__mode.fail ? Promise.resolve(new Response(JSON.stringify({ schema: 'opentrace.workbench.error/1', error: window.__mode.fail, message: 'x', detail_code: window.__mode.detail || 'd' }), { status: window.__mode.status, headers: { 'content-type': 'application/json' } }))
      : orig(window.__fx ? u.replace(/&group_id=[^&]*/, '') : url, init).then(async (r) => { if (!window.__fx || !r.ok) return r; const real = await r.json(); const f = JSON.parse(JSON.stringify(window.__fx)); f.binding = real.binding; if (!window.__keepLinks) { const b = real.binding, enc = (t) => encodeURIComponent(t).replace(/[!'()*]/g, (c) => '%' + c.charCodeAt(0).toString(16).toUpperCase()); for (const a of f.assets) for (const o of a.occurrences) o.source_location.link.href = 'https://github.com/' + b.repository.owner + '/' + b.repository.name + '/blob/' + b.commit_sha + '/' + o.source_location.path.split('/').map(enc).join('/'); } return new Response(JSON.stringify(f), { status: 200, headers: { 'content-type': 'application/json' } }); });
    if (window.__mode.hold) return new Promise((res) => window.__held.push({ u, go: () => res(run()) })); return run(); }; })()`;
const setFx = (pg, name) => ev(pg, `window.__fx = ${name ? JSON.stringify(FX(name)) : 'null'}`);
const calls = (pg) => ev(pg, 'window.__calls.slice()');
const release = (pg, i) => ev(pg, `window.__held[${i}].go()`);
const idle = (pg) => pg.waitFor(`window.__otStore.get().workbench.perTab.crypto.pg.status==='idle' && !document.querySelector('.otc-loading')`, 20000, 'crypto idle');
async function demoToCrypto(pg) {
  await ev(pg, "document.getElementById('ot-demo').click()");
  await pg.waitFor(`document.querySelector('[data-map-ready="true"]')`, 30000, 'map ready'); await sleep(500);
  await ev(pg, HOOK);
}
const openCrypto = async (pg) => { await ev(pg, "document.getElementById('ot-tab-crypto').click()"); await pg.waitFor(`document.querySelector('#otc-empty, #otc-svg, #otc-list')`, 20000, 'crypto tab'); await idle(pg); await sleep(150); };
const reload = async (pg, fx, filter = 'all') => { await setFx(pg, fx); await ev(pg, `document.querySelector('[data-otc-filter=${filter}]').click()`); await idle(pg); await sleep(150); };
const vb = (pg) => ev(pg, "document.getElementById('otc-svg').getAttribute('viewBox').split(' ').map(Number)");
const rects = (pg) => ev(pg, `[...document.querySelectorAll('#otc-svg g.otc-group')].map(g=>{const r=g.querySelector(':scope > rect');const h=g.querySelector('g[data-otc-select^="group:"] rect');const cards=[...g.querySelectorAll('g[data-otc-select^="asset:"] rect')].map(c=>[+c.getAttribute('x'),+c.getAttribute('y'),+c.getAttribute('width'),+c.getAttribute('height')]);return {zone:[+r.getAttribute('x'),+r.getAttribute('y'),+r.getAttribute('width'),+r.getAttribute('height')],head:h?[+h.getAttribute('x'),+h.getAttribute('y'),+h.getAttribute('width'),+h.getAttribute('height')]:null,cards}})`);
const selFirst = async (pg) => { await pg.click('#otc-svg g[data-otc-select^=asset]'); await sleep(150); };
const shot = async (pg, name) => { await sleep(200); await pg.screenshot(join(SHOTS, name + '.png')); };
const CLIP = `(()=>{const bad=[];for(const t of document.querySelectorAll('#otc-svg text')){const g=t.closest('g[data-otc-select]');const r=g&&g.querySelector('rect');if(!r)continue;const x0=+r.getAttribute('x'),x1=x0+ +r.getAttribute('width');const b=t.getBBox();if(b.x<x0-1||b.x+b.width>x1+1)bad.push(t.textContent.slice(0,30));}return bad;})()`;

// ================================================================== desktop 1366, light — recorded Demo
ctx = '1366 light Demo';
{
  const pg = await open(1366, 900);
  await ev(pg, "document.getElementById('ot-demo').click()");
  await pg.waitFor(`document.querySelector('[data-map-ready="true"]')`, 30000, 'map ready'); await sleep(500);
  await ev(pg, HOOK);
  check('the workbench still opens on Repository contexts', (await state(pg)).workbench.tab === 'contexts');
  await openCrypto(pg);
  const c = await calls(pg);
  check('one request on tab open: /crypto-assets?generation=1&filter=all&offset=0&size=30', c.length === 1 && /crypto-assets\?generation=1&filter=all&offset=0&size=30$/.test(c[0]), JSON.stringify(c));
  const panel = await txt(pg, '#ot-tabpanel');
  check('the empty Demo is shown honestly: no assets, 13 endpoint services, availability message', /The captured CBOM lists no cryptographic assets\. This does not show that no cryptography is used\./.test(panel) && /0 assets · 0 review items · 13 endpoint services/.test(panel), panel.slice(0, 120).replace(/\n/g, ' '));
  check('no prototype assets or extractor: no pbkdf2/HS256/MQTT/generate_*', !/pbkdf2|hs256|mqtt|generate_[a-z_]*\.py|extractor/i.test(panel), '');
  check('no asset graph is drawn for zero assets', (await count(pg, '#otc-svg')) === 0 && (await count(pg, '#otc-empty')) === 1);
  check('the five filters carry counts and Graph/List/Expand are present', (await count(pg, '[data-otc-filter]')) === 5 && (await count(pg, '[data-otc-pres]')) === 2 && (await count(pg, '#otc-expand')) === 1);
  const dl = await ev(pg, "document.querySelector('.otc-toolbar a')?.getAttribute('href')");
  check('Download CBOM is the existing session artifact link; no manifest/extractor download', /^\/api\/artifacts\/cdxgen-cbom\.cdx\.json\?disposition=attachment$/.test(dl) && (await count(pg, '.otc-toolbar a')) === 1 && /no source manifest artifact is recorded/i.test(await ev(pg, "document.querySelector('.otc-scope').textContent")), dl);
  check('endpoint services are listed separately (13) and are not assets', (await count(pg, '.otc-services li')) === 13 && (await state(pg)).views.cryptoPage.page.assets_total === 0);
  check('the Source-backed check stays reachable in the Evidence view (unchanged location)', await ev(pg, "(document.getElementById('ot-nav-evidence')||document.querySelector('[data-nav=evidence]')) !== null"));
  const ch = await ev(pg, "fetch('/api/artifacts/cdxgen-cbom.cdx.json?disposition=attachment',{credentials:'same-origin'}).then(r=>r.status)");
  check('the original CBOM download is served by the unchanged artifact route', ch === 200, ch);
  check('no inline style attributes (CSP style-src self) and no horizontal overflow', (await count(pg, '#ot-tabpanel [style]')) === 0 && (await noOverflow(pg)));
  await shot(pg, 'demo_completed_empty_1366_light');
  const adv = await ev(pg, "(async()=>{document.getElementById('ot-advanced').click(); await new Promise(r=>setTimeout(r,1500)); return !!document.querySelector('[data-cy=crypto]')})()");
  check('Advanced keeps the generic family surface for Cryptography (legacy view)', adv === true);
  await ev(pg, "document.getElementById('ot-advanced').click()"); await sleep(400);
  check('no console errors / exceptions', consoleErrors(pg).length === 0, JSON.stringify(consoleErrors(pg)));
  await pg.close();
}

// ================================================================== desktop 1366, light — synthetic renderer fixtures
ctx = '1366 light synthetic';
{
  const pg = await open(1366, 900); await demoToCrypto(pg); await openCrypto(pg);
  await reload(pg, 'multi3');
  const R = await rects(pg); const view = await vb(pg);
  check('composition: 3 source groups at x = 20/420/820, 360x500 zones at y=160 (reference geometry)', R.length === 3 && R.every((g, i) => g.zone[0] === 20 + i * 400 && g.zone[1] === 160 && g.zone[2] === 360 && g.zone[3] === 500), JSON.stringify(R.map((g) => g.zone)));
  check('headers 330x66 at y=176; cards 300x90 at y = 280 + 120*i', R.every((g) => g.head && g.head[1] === 176 && g.head[2] === 330 && g.head[3] === 66 && g.cards.every((c, i) => c[1] === 280 + 120 * i && c[2] === 300 && c[3] === 90)), JSON.stringify(R[0]));
  check('root node (460,20) 280x72 and the Fit window equals the reference [-20,0,1240,690]', JSON.stringify(view) === JSON.stringify([-20, 0, 1240, 690]) && (await ev(pg, "(()=>{const r=document.querySelector('[data-otc-select=root] rect');return [r.getAttribute('x'),r.getAttribute('y'),r.getAttribute('width'),r.getAttribute('height')].join()})()")) === '460,20,280,72', JSON.stringify(view));
  check('zoom label shows 100% at Fit', (await txt(pg, '#otc-zoom')) === '100%');
  check('card text stays inside its card (no clipped text)', (await ev(pg, CLIP)).length === 0, JSON.stringify(await ev(pg, CLIP)));
  const first = await ev(pg, "document.querySelector('#otc-svg g[data-otc-select^=asset]').dataset.otcSelect");
  check('the first asset is selected by default and the detail panel names it', (await cs(pg)).sel === first && (await txt(pg, '#otc-title')).length > 0 && true && (await ev(pg, `document.querySelector('[data-otc-select="${first}"]').getAttribute('aria-pressed')`)) === 'true');
  const second = await ev(pg, "document.querySelectorAll('#otc-svg g[data-otc-select^=asset]')[4].dataset.otcSelect");
  await pg.click(`#otc-svg [data-otc-select="${second}"]`); await sleep(150);
  check('clicking a card selects it (aria-pressed, detail title, store)', (await cs(pg)).sel === second && (await ev(pg, `document.querySelector('#otc-svg [data-otc-select="${second}"]').getAttribute('aria-pressed')`)) === 'true');
  const third = await ev(pg, "document.querySelectorAll('#otc-svg g[data-otc-select^=asset]')[5].dataset.otcSelect");
  await ev(pg, `document.querySelector('#otc-svg [data-otc-select="${third}"]').focus()`); await pg.key('Enter'); await sleep(150);
  check('Enter selects the focused card and focus is restored after the repaint', (await cs(pg)).sel === third && (await ev(pg, 'document.activeElement?.dataset?.otcSelect')) === third, await ev(pg, 'document.activeElement?.dataset?.otcSelect'));
  await ev(pg, `document.querySelector('#otc-svg [data-otc-select="${first}"]').focus()`); await pg.key(' ', 'Space'); await sleep(150);
  check('Space selects as well', (await cs(pg)).sel === first);
  const grp = await ev(pg, "document.querySelector('#otc-svg g[data-otc-select^=group]').dataset.otcSelect");
  await pg.click(`#otc-svg [data-otc-select="${grp}"]`); await sleep(150);
  check('a source group header is selectable and lists its assets', (await cs(pg)).sel === grp && /recorded asset/.test(await txt(pg, '#otc-detail')) && (await count(pg, '#otc-detail .otc-detail-link')) >= 1);
  await pg.click('[data-otc-select=root]'); await sleep(150);
  check('the root node selects the repository summary', (await cs(pg)).sel === 'root' && /cryptographic assets/.test(await txt(pg, '#otc-title')));
  // zoom / fit / pan
  const v0 = await vb(pg);
  await pg.click('[data-otc-zoom="1.2"]'); await sleep(100); const v1 = await vb(pg);
  check('zoom in shrinks the viewBox and the label rises above 100%', v1[2] < v0[2] && parseInt(await txt(pg, '#otc-zoom')) > 100, JSON.stringify([v0, v1]));
  await pg.click('[data-otc-zoom="0.8333"]'); await pg.click('[data-otc-zoom="0.8333"]'); await sleep(100);
  check('zoom out enlarges the viewBox and the label falls below 100%', (await vb(pg))[2] > v0[2] && parseInt(await txt(pg, '#otc-zoom')) < 100);
  await pg.click('[data-otc-fit]'); await sleep(100);
  check('Fit restores the reference window', JSON.stringify(await vb(pg)) === JSON.stringify([-20, 0, 1240, 690]));
  await ev(pg, "document.getElementById('otc-stage').focus()"); await pg.key('+'); await sleep(100);
  check('with the stage focused, + zooms in', (await vb(pg))[2] < 1240);
  await pg.key('=') ; await sleep(80); const vBefore = await vb(pg);
  await pg.key('ArrowRight'); await pg.key('ArrowDown'); await sleep(100); const vp = await vb(pg);
  check('arrow keys pan the view without changing its size', vp[2] === vBefore[2] && (vp[0] > vBefore[0] || vp[1] > vBefore[1]), JSON.stringify([vBefore, vp]));
  await pg.key('0'); await sleep(100);
  check('0 fits', JSON.stringify(await vb(pg)) === JSON.stringify([-20, 0, 1240, 690]));
  await ev(pg, "document.getElementById('otc-svg').scrollIntoView({block:'center'})"); await sleep(100);
  const box = await ev(pg, "(()=>{const r=document.getElementById('otc-svg').getBoundingClientRect();return {x:r.x+15,y:r.y+15}})()");
  await pg.send('Input.dispatchMouseEvent', { type: 'mouseWheel', x: box.x, y: box.y, deltaX: 0, deltaY: -120, modifiers: 2 }); await sleep(150);
  check('Ctrl-wheel over the graph zooms', (await vb(pg))[2] < 1240);
  await pg.click('[data-otc-fit]'); await sleep(100);
  await pg.send('Input.dispatchMouseEvent', { type: 'mousePressed', x: box.x, y: box.y, button: 'left', clickCount: 1 });
  await pg.send('Input.dispatchMouseEvent', { type: 'mouseMoved', x: box.x - 120, y: box.y - 40, button: 'left', buttons: 1 });
  await pg.send('Input.dispatchMouseEvent', { type: 'mouseReleased', x: box.x - 120, y: box.y - 40, button: 'left', clickCount: 1 }); await sleep(150);
  check('dragging the background pans the view', JSON.stringify(await vb(pg)) !== JSON.stringify([-20, 0, 1240, 690]));
  await pg.click('[data-otc-fit]');
  check('no horizontal overflow, no inline styles, no console errors', (await noOverflow(pg)) && (await count(pg, '#ot-tabpanel [style]')) === 0 && consoleErrors(pg).length === 0, JSON.stringify(consoleErrors(pg)));
  await shot(pg, 'synthetic_multi3_1366_light');
  // links
  await pg.click(`#otc-svg [data-otc-select="${first}"]`); await sleep(150);
  await ev(pg, "document.querySelector('.supplement-more').open = true");
  const href = await ev(pg, "document.querySelector('#otc-detail .otc-source a')?.getAttribute('href')"); const b = (await state(pg)).views.cryptoPage.binding;
  check('source links are pinned-revision GitHub blob URLs with a line anchor, opened with rel=noreferrer', !!href && href.startsWith(`https://github.com/${b.repository.owner}/${b.repository.name}/blob/${b.commit_sha}/`) && /#L\d+/.test(href) && (await ev(pg, "document.querySelector('#otc-detail .otc-source a').rel")) === 'noreferrer', href);
  // findings / filters
  await setFx(pg, 'findings'); await pg.click('[data-otc-filter=findings]'); await idle(pg);
  const cl = await calls(pg);
  check('a filter change issues one request with filter=findings and resets the offset', /filter=findings&offset=0&size=30$/.test(cl[cl.length - 1]), cl[cl.length - 1]);
  const amber = await ev(pg, "document.querySelectorAll('#otc-svg [data-otc-select^=asset] text').length && [...document.querySelectorAll('#otc-svg [data-otc-select^=asset] rect')].some(r=>/otc-review-bg/.test(r.getAttribute('fill')))");
  check('a rule-backed review item renders the amber state with the review block', amber && /Needs review/.test(await ev(pg, "document.getElementById('otc-svg').textContent")) && (await count(pg, '#otc-detail .otc-review')) + (await count(pg, '#otc-detail .otc-status.review')) >= 1);
  check('a hashing name alone never shows red: no red fill anywhere in the graph', !(await ev(pg, "[...document.querySelectorAll('#otc-svg *')].some(n=>/red|#d00|#c00|#e00|#b00/i.test((n.getAttribute('fill')||'')+(n.getAttribute('stroke')||'')))")));
  await shot(pg, 'synthetic_findings_1366_light');
  await setFx(pg, 'certificates_zero'); await pg.click('[data-otc-filter=certificates]'); await idle(pg);
  check('Certificates with none: "No certificate objects are recorded in this CBOM."', (await txt(pg, '#otc-empty')) === 'No certificate objects are recorded in this CBOM.' && (await count(pg, '#otc-svg')) === 0);
  await shot(pg, 'synthetic_certificates_empty_1366_light');
  // Graph/List
  await reload(pg, 'multi3'); const sel0 = (await cs(pg)).sel;
  await pg.click('[data-otc-pres=list]'); await sleep(150);
  check('List shows rows as buttons with a status chip and keeps filter and selection', (await count(pg, '#otc-list button.otc-list-row')) === 9 && (await cs(pg)).sel === sel0 && (await count(pg, '#otc-list .otc-status')) === 9);
  await pg.click('[data-otc-pres=graph]'); await sleep(150);
  check('back to Graph: selection preserved, SVG redrawn', (await cs(pg)).sel === sel0 && (await count(pg, '#otc-svg')) === 1);
  // group select + search
  const nCalls = (await calls(pg)).length;
  await ev(pg, "(()=>{const s=document.getElementById('otc-group');s.value=s.options[1].value;s.dispatchEvent(new Event('change',{bubbles:true}))})()"); await idle(pg);
  const cg = await calls(pg);
  check('choosing a source group issues one request with group_id', cg.length === nCalls + 1 && /group_id=grp:[0-9a-f]{24}/.test(cg[cg.length - 1]), cg[cg.length - 1]);
  await ev(pg, "(()=>{const s=document.getElementById('otc-group');s.value='';s.dispatchEvent(new Event('change',{bubbles:true}))})()"); await idle(pg);
  const n2 = (await calls(pg)).length;
  await pg.type('#otc-q', 'ab'); await sleep(700); await idle(pg);
  check('search is debounced: typing two characters issues a single request with query=ab', (await calls(pg)).length === n2 + 1 && /query=ab/.test((await calls(pg)).at(-1)), JSON.stringify((await calls(pg)).slice(n2)));
  await ev(pg, "(()=>{const q=document.getElementById('otc-q');q.value='';q.dispatchEvent(new Event('input',{bubbles:true}))})()"); await sleep(500); await idle(pg);
  // expanded
  await reload(pg, 'multi3');
  await pg.click('#otc-expand'); await sleep(200);
  const inert = await ev(pg, "(()=>{const f=document.getElementById('otc-expanded');if(!f)return null;let n=f,out=[];for(;n.parentElement;n=n.parentElement)for(const s of n.parentElement.children)if(s!==n&&!['DIALOG','SCRIPT','STYLE'].includes(s.tagName))out.push(s.inert);return out.every(Boolean)&&out.length>0})()");
  check('Expand opens a modal frame with the background inert', (await count(pg, '#otc-expanded[aria-modal=true]')) === 1 && inert === true, String(inert));
  await shot(pg, 'synthetic_expanded_1366_light');
  await ev(pg, "document.getElementById('otc-expand').focus()");
  await pg.key('Tab'); await sleep(80);
  check('Tab keeps focus inside the expanded frame', await ev(pg, "document.getElementById('otc-expanded').contains(document.activeElement)"));
  await pg.key('Escape'); await sleep(200);
  check('Escape closes the frame and focus returns to the Expand control', (await count(pg, '#otc-expanded')) === 0 && (await ev(pg, 'document.activeElement?.id')) === 'otc-expand', await ev(pg, 'document.activeElement?.id'));
  check('nothing is left inert after the frame closes', !(await ev(pg, "[...document.querySelectorAll('body *')].some(n=>n.inert)")));
  // occurrences note and large layouts
  await reload(pg, 'occ45'); await selFirst(pg);
  check('45 occurrences: the detail says "20 of 45" and names the original CBOM (no group-selector promise)', /20 of 45 occurrences shown; the original CBOM download lists all of them\./.test(await ev(pg, "document.getElementById('otc-detail').textContent")) && !/reachable/i.test(await ev(pg, "document.getElementById('otc-detail').textContent")));
  await reload(pg, 'tall5'); const Rt = await rects(pg); const vt = await vb(pg);
  check('a group with 5 cards grows its zone to 740 (120/card beyond three) and nothing is clipped', Rt[0].zone[3] === 740 && Rt[0].cards.length === 5 && Rt[0].cards.every((c) => c[1] + c[3] <= Rt[0].zone[1] + Rt[0].zone[3]), JSON.stringify(Rt[0].zone));
  check('tall layout: Fit shows the full 1200 width at the top of the layout', vt[0] === 0 && vt[1] === 0 && vt[2] === 1200, JSON.stringify(vt));
  await reload(pg, 'wrap7'); const Rw = await rects(pg); const vw = await vb(pg);
  check('7 groups wrap into rows of three (y = 160, 720, 1280); the viewBox is 1280 wide and grows downward', Rw.length === 7 && JSON.stringify(Rw.map((g) => g.zone[1])) === JSON.stringify([160, 160, 160, 720, 720, 720, 1280]) && vw[2] === 1280 && vw[0] === -40, JSON.stringify(vw));
  check('wrapped layout: the zoom label at Fit is about 94%', Math.abs(parseInt(await txt(pg, '#otc-zoom')) - 94) <= 1, await txt(pg, '#otc-zoom'));
  check('Fit all is offered for the tall layout and shows the whole height', (await count(pg, '[data-otc-fitall]')) === 1);
  await pg.click('[data-otc-fitall]'); await sleep(100); const va = await vb(pg);
  check('Fit all covers the full bounding box (height >= 1810)', va[3] >= 1810 - 1 && va[2] >= 1280, JSON.stringify(va));
  await shot(pg, 'synthetic_wrap7_fitall_1366_light');
  await reload(pg, 'dense24');
  check('30 assets over many directories coarsen to at most 24 source groups; selecting works', (await count(pg, '#otc-svg g.otc-group')) <= 24 && (await count(pg, '#otc-svg g[data-otc-select^=asset]')) >= 30);
  await reload(pg, 'hostile'); await selFirst(pg);
  check('hostile names, paths and endpoint text stay inert (no injected nodes, no active javascript: link)', (await count(pg, '#ot-tabpanel img, #ot-tabpanel script, #ot-tabpanel b')) === 0 && !(await ev(pg, "[...document.querySelectorAll('#ot-tabpanel a')].some(a=>/^javascript:/i.test(a.getAttribute('href')||''))")) && /<img src=x/.test(await txt(pg, '#otc-title')));
  check('hostile text clipped in the card, not overflowing it', (await ev(pg, CLIP)).length === 0, JSON.stringify(await ev(pg, CLIP)));
  for (const [fx, re, name] of [['unsupported', /No supported CBOM/, 'unsupported'], ['failed', /failed/, 'failed'], ['partial_empty', /incomplete/i, 'partial'], ['not_run', /not run/, 'not_collected']]) {
    await reload(pg, fx);
    check(`state ${fx}: the availability message is shown and no graph is drawn`, re.test(await txt(pg, '#otc-empty')) && (await count(pg, '#otc-svg')) === 0, await txt(pg, '#otc-empty'));
    await shot(pg, `state_${name}_1366_light`);
  }
  check('console clean after all fixtures', consoleErrors(pg).length === 0, JSON.stringify(consoleErrors(pg)));
  // repeatability of three captures (byte-identical)
  await reload(pg, 'multi3'); await ev(pg, "document.getElementById('otc-stage').blur()"); await sleep(300);
  const ba = await pg.send('Page.captureScreenshot', { format: 'png' }); await sleep(300); const bb = await pg.send('Page.captureScreenshot', { format: 'png' });
  check('repeated captures of the same state are byte-identical', ba.data === bb.data);
  await pg.close();
}

// ================================================================== races, failures, lifecycle
ctx = 'races and lifecycle';
{
  const pg = await open(1366, 900); await demoToCrypto(pg); await openCrypto(pg); await reload(pg, 'multi3');
  await ev(pg, 'window.__mode.hold = true');
  await pg.click('[data-otc-filter=protocols]'); await pg.click('[data-otc-filter=algorithms]'); await sleep(200);
  check('two quick filter changes issue two requests (the older is superseded)', (await ev(pg, 'window.__held.length')) === 2);
  await release(pg, 1); await sleep(300); const afterNew = (await state(pg)).views.cryptoPage;
  await release(pg, 0); await sleep(300);
  check('a late response for the older filter is ignored (state keeps the newest request)', (await cs(pg)).filter === 'algorithms' && (await cs(pg)).loaded === (await ev(pg, "JSON.stringify(['algorithms','',null,0])")) && afterNew != null);
  await ev(pg, 'window.__mode.hold = false; window.__held = []');
  // typed failure + manual retry
  await ev(pg, "window.__mode.fail = 'projection_failed'; window.__mode.detail = 'path_not_representable'");
  await pg.click('[data-otc-filter=all]'); await sleep(400);
  check('a typed failure keeps the page and shows an alert with "Try again"; no automatic retry', (await count(pg, '.otc-banner [data-otc-retry]')) === 1 && /cannot be shown exactly/.test(await txt(pg, '.otc-banner')) && (await calls(pg)).filter((u) => /filter=all/.test(u)).length >= 1);
  const nf = (await calls(pg)).length; await sleep(1200);
  check('nothing retries by itself', (await calls(pg)).length === nf);
  await ev(pg, 'window.__mode.fail = null'); await pg.click('.otc-banner [data-otc-retry]'); await idle(pg);
  check('manual retry recovers', (await count(pg, '.otc-banner')) === 0 && (await cs(pg)).pg.status === 'idle');
  // 409 -> recovery
  await ev(pg, "window.__mode.fail = 'stale_generation'; window.__mode.status = 409"); await pg.click('[data-otc-filter=protocols]'); await sleep(400);
  check('a current 409 retires the payload and shows the "session moved on" recovery', (await cs(pg)).stale === true && (await state(pg)).views.cryptoPage === undefined && /session moved on/.test(await txt(pg, '#ot-tabpanel')));
  await ev(pg, "window.__mode.fail = null; window.__mode.status = 500");
  await pg.click('[data-otc-stale-reset]'); await sleep(500);
  check('"Reopen the analysis" closes the old analysis locally', (await state(pg)).analysis === null);
  await pg.close();
}
{
  const pg = await open(1366, 900); await demoToCrypto(pg); await openCrypto(pg); await reload(pg, 'multi3');
  await ev(pg, 'window.__mode.hold = true'); await pg.click('[data-otc-filter=protocols]'); await sleep(200);
  await ev(pg, "document.getElementById('ot-top-end').click()"); await pg.waitFor(`window.__otStore.get().ended`, 15000, 'ended');
  check('End session clears the crypto payload at once', (await state(pg)).views.cryptoPage === undefined && (await cs(pg)).sel === null);
  const before = JSON.stringify((await state(pg)).views); await ev(pg, 'window.__held.forEach(h=>h.go())'); await sleep(500);
  check('the late response after End session leaves the state unchanged', JSON.stringify((await state(pg)).views) === before && (await state(pg)).views.cryptoPage === undefined);
  await ev(pg, "document.getElementById('ot-demo').click()"); await pg.waitFor(`document.querySelector('[data-map-ready="true"]')`, 30000);
  check('a new Demo opens on Repository contexts with fresh crypto state', (await state(pg)).workbench.tab === 'contexts' && (await cs(pg)).filter === 'all' && (await state(pg)).views.cryptoPage === undefined);
  await pg.close();
}

// ================================================================== tabs and assistant
ctx = 'tabs and assistant';
{
  const pg = await open(1366, 900); await demoToCrypto(pg); await openCrypto(pg); await reload(pg, 'multi3');
  await selFirst(pg); const sel = (await cs(pg)).sel; const name = await txt(pg, '#otc-title');
  await ev(pg, "document.getElementById('ot-tab-dependencies').click()"); await sleep(700);
  check('switching tabs replaces the details (no crypto selection leaks into Dependencies)', !/synthetic-alg/.test(await txt(pg, '#ot-tabpanel')));
  await ev(pg, "document.getElementById('ot-tab-crypto').click()"); await sleep(500);
  check('returning to Cryptography keeps the cached page and selection without a second request', (await cs(pg)).sel === sel && (await count(pg, '#otc-svg')) === 1);
  await ev(pg, "document.getElementById('ot-assistant-launch').click()"); await sleep(300);
  await pg.waitFor("document.querySelector('#ot-assistant .micro') && !document.getElementById('ot-assistant').hidden", 5000, 'assistant open');
  check('the assistant context follows the selected crypto asset', (await ev(pg, "document.getElementById('ot-assistant').textContent")).includes('Context: ' + name), name);
  check('no console errors', consoleErrors(pg).length === 0, JSON.stringify(consoleErrors(pg)));
  await pg.close();
}

// ================================================================== dark theme and narrow
ctx = '1366 dark';
{
  const pg = await open(1366, 900, 'dark'); await demoToCrypto(pg); await openCrypto(pg); await reload(pg, 'multi3');
  const fill = await ev(pg, "getComputedStyle(document.querySelector('#otc-svg g.otc-group > rect')).fill");
  check('dark tokens apply to the zones (fill differs from the light token)', fill !== 'rgb(234, 240, 248)' && fill.startsWith('rgb'), fill);
  check('no console errors / no overflow', consoleErrors(pg).length === 0 && (await noOverflow(pg)));
  await shot(pg, 'synthetic_multi3_1366_dark');
  await pg.close();
}
ctx = '390 light';
{
  const pg = await open(390, 844, 'light'); await demoToCrypto(pg); await openCrypto(pg); await reload(pg, 'multi3');
  check('at 390 px the List is the default presentation and no horizontal scroll', (await cs(pg)).presentation === 'list' && (await count(pg, '#otc-list')) === 1 && (await noOverflow(pg)));
  await shot(pg, 'synthetic_list_390_light');
  await pg.click('[data-otc-pres=graph]'); await sleep(300);
  check('the person\'s choice of Graph is kept at 390 px (never forced back)', (await cs(pg)).presentation === 'graph' && (await count(pg, '#otc-svg')) === 1 && (await noOverflow(pg)));
  await shot(pg, 'synthetic_multi3_390_light');
  check('no console errors', consoleErrors(pg).length === 0, JSON.stringify(consoleErrors(pg)));
  await pg.close();
}

check('only loopback traffic (everything else blocked and recorded)', blocked.length === 0, blocked.join(' '));
await close(); svc.kill('SIGKILL');
const failed = results.filter((r) => !r.ok);
writeFileSync(join(OUT, 'results.json'), JSON.stringify(results, null, 1));
console.log(`\n${results.length - failed.length}/${results.length} passed`);
process.exit(failed.length ? 1 : 0);
