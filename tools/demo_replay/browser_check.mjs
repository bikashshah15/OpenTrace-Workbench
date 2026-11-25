// Drive the replay Workbench in an ISOLATED headless Chrome (throwaway profile, so no cookie is shared with any other browser session).
//   node tools/demo_replay/browser_check.mjs <base-url, e.g. http://127.0.0.1:8799/> <outDir>
// Opens the demo through the normal Demo button, visits each of the five Workbench tabs, and records per tab: the visible text, a screenshot,
// graph/evidence-panel presence, links, and every API response with status >= 400 plus console errors. Writes <outDir>/browser-report.json.
// Loopback only: any other request is blocked and listed. Nothing here is committed; outDir should be private.
import { mkdirSync, writeFileSync } from 'node:fs';
import { resolve, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { launch, newPage } from '../../tests/ui/browser/cdp.mjs';

const base = process.argv[2]; const OUT = resolve(process.argv[3] || '.');
if (!base || !/^http:\/\/127\.0\.0\.1:\d+\/?$/.test(base)) { console.error('usage: browser_check.mjs http://127.0.0.1:PORT/ outDir'); process.exit(2); }
mkdirSync(OUT, { recursive: true, mode: 0o700 });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const { browser, close } = await launch();
const blocked = [];
const pg = await newPage(browser, { width: 1600, height: 1000 });
await pg.send('Fetch.enable', { patterns: [{ urlPattern: '*' }] });
browser.on((m) => {
  if (m.sessionId !== pg.sessionId || m.method !== 'Fetch.requestPaused') return;
  const url = m.params.request.url; const ok = /^(http:\/\/(127\.0\.0\.1|localhost)[:/])|^(data:|blob:|about:)/.test(url);
  if (ok) pg.send('Fetch.continueRequest', { requestId: m.params.requestId }).catch(() => {});
  else { blocked.push(url); pg.send('Fetch.failRequest', { requestId: m.params.requestId, errorReason: 'BlockedByClient' }).catch(() => {}); }
});
const report = { base, tabs: {}, errors: [], blocked };
const txt = (sel) => pg.eval(`(document.querySelector(${JSON.stringify(sel)})?.innerText||'')`);
const state = () => pg.eval('JSON.parse(JSON.stringify(window.__otStore.get()))');
try {
  await pg.goto(base); await sleep(400);
  report.banner_before = await txt('#ot-bar-text');
  await pg.click('#ot-demo');
  await pg.waitFor("window.__otStore.get().analysis && window.__otStore.get().analysis.ok !== false", 30000, 'analysis ready');
  const s0 = await state();
  report.analysis = { commit: s0.analysis.identity.commit, mode: s0.analysis.identity.mode, digest: s0.analysis.identity.analysis_digest };
  await sleep(500); report.banner_after = await txt('#ot-bar-text');
  await pg.eval("document.querySelector('[data-nav=workbench]').click()"); await sleep(1200);
  await pg.screenshot(join(OUT, 'banner.png'));
  for (const tab of ['contexts', 'dependencies', 'crypto', 'ai', 'bom']) {
    await pg.eval(`document.getElementById('ot-tab-${tab}').click()`); await sleep(2500);
    const body = await txt('#ot-tabpanel');
    const probe = await pg.eval(`(()=>{const p=document.getElementById('ot-tabpanel')||document; const q=(s)=>p.querySelectorAll(s).length; return {
      graph_canvases: q('canvas, .ot-graph, [data-graph]'), svg: q('svg'), inspector: q('.ot-inspector, aside'), list_rows: q('tr, li, [role=row], .ot-row'),
      links: [...p.querySelectorAll('a[href]')].map(a=>({text:(a.textContent||'').trim().slice(0,70), href:a.getAttribute('href')})).slice(0,12),
      buttons: [...p.querySelectorAll('button')].map(b=>(b.textContent||'').trim()).filter(Boolean).slice(0,25)}})()`);
    await pg.screenshot(join(OUT, `tab-${tab}.png`));
    writeFileSync(join(OUT, `tab-${tab}.txt`), body, { mode: 0o600 });
    report.tabs[tab] = { text_chars: body.length, ...probe, head: body.slice(0, 400) };
    console.log(`${tab}: ${body.length} chars, svg=${probe.svg}, canvases=${probe.graph_canvases}, inspector=${probe.inspector}, links=${probe.links.length}`);
  }
  report.api_errors = pg.log.responses.filter((r) => /\/api\//.test(r.url) && r.status >= 400).map((r) => ({ url: r.url.replace(base, '/'), status: r.status }));
  report.api_calls = pg.log.responses.filter((r) => /\/api\//.test(r.url)).map((r) => r.status + ' ' + r.url.replace(base, '/').slice(0, 90));
  report.console_errors = pg.log.console.filter((c) => c.type === 'error').map((c) => c.text.slice(0, 200)).concat(pg.log.exceptions.map((e) => String(e).slice(0, 200)));
} catch (e) { report.errors.push(String(e)); }
writeFileSync(join(OUT, 'browser-report.json'), JSON.stringify(report, null, 1), { mode: 0o600 });
console.log(JSON.stringify({ analysis: report.analysis, banner_before: report.banner_before, banner_after: report.banner_after, errors: report.errors, api_errors: report.api_errors, console_errors: report.console_errors, blocked: report.blocked }, null, 1));
await close();
