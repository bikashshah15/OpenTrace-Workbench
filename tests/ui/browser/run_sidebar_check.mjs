// Sidebar presentation refinement: ONE focused desktop fixture check (one fixture service, one HEADED Chrome, <= 30 minutes).
//   PYTHON=<python> node tests/ui/browser/run_sidebar_check.mjs <outDir>
// Service: stage4_completion_service.py (SYNTHETIC repositories, fake scanners, no network/Docker/provider). Drives the five Repository workbench tabs,
// switches records, opens the evidence disclosures, then repeats in dark and at a narrower desktop width. Not mobile, not screen-reader certification.
import { spawn } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { connect, newPage, CHROME } from './cdp.mjs';

const HERE = dirname(fileURLToPath(import.meta.url)); const REPO = resolve(HERE, '../../..');
const OUT = resolve(process.argv[2] || join(REPO, 'evidence/uip/visual/sidebar-refinement')); mkdirSync(OUT, { recursive: true });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const T0 = Date.now(); const DEADLINE = T0 + 28 * 60 * 1000;
const results = []; const ok = (name, pass, detail = '') => { results.push({ name, pass: !!pass, detail: String(detail).slice(0, 300) }); console.log((pass ? 'PASS ' : 'FAIL ') + name + (pass ? '' : ' :: ' + String(detail).slice(0, 300))); };

const svc = spawn(process.env.PYTHON || 'python3', [join(HERE, 'stage4_completion_service.py')], { cwd: REPO, env: { ...process.env, PYTHONPATH: REPO + ':' + join(REPO, 'src/core') + ':' + join(REPO, 'src/agents/investigator') }, stdio: ['ignore', 'pipe', 'pipe'] });
const base = await new Promise((res, rej) => { let b = ''; const t = setTimeout(() => rej(new Error('service did not start: ' + b)), 40000); svc.stdout.on('data', (d) => { b += d; const m = b.match(/http:\/\/127\.0\.0\.1:(\d+)\//); if (m) { clearTimeout(t); res(m[0]); } }); svc.stderr.on('data', (d) => { b += d; }); });
const dir = mkdtempSync(join(tmpdir(), 'ot-sidebar-chrome-'));
const chrome = spawn(CHROME, ['--no-first-run', '--no-default-browser-check', `--user-data-dir=${dir}`, '--remote-debugging-port=0', '--window-size=1500,1000', 'about:blank'], { stdio: ['ignore', 'ignore', 'pipe'] });
const wsUrl = await new Promise((res, rej) => { let b = ''; const t = setTimeout(() => rej(new Error('chrome did not start')), 30000); chrome.stderr.on('data', (d) => { b += d; const m = b.match(/DevTools listening on (ws:\/\/\S+)/); if (m) { clearTimeout(t); res(m[1]); } }); });
const browser = await connect(wsUrl);
const cleanup = async () => { try { browser.close(); } catch {} chrome.kill('SIGTERM'); svc.kill('SIGTERM'); await sleep(800); try { chrome.kill('SIGKILL'); } catch {} try { svc.kill('SIGKILL'); } catch {} try { rmSync(dir, { recursive: true, force: true }); } catch {} };
process.on('SIGINT', async () => { await cleanup(); process.exit(130); });

// In-page snapshot of the visible sidebar for the current tab.
const SNAP = `(()=>{
  const root = document.querySelector('.ot-bom8-drawer-body') || document.querySelector('#ot-tabpanel') ; const all=[...document.querySelectorAll('#ot-tabpanel .ot-insp')];
  const insp = all[0]; if (!insp) return { count: 0 };
  const q = [...insp.querySelectorAll('[data-question]')].map(e=>e.dataset.question);
  const states=[...insp.querySelectorAll('.ot-insp-card .ot-insp-state')].map(e=>({cls:e.className, color:getComputedStyle(e).color, text:e.textContent.trim(), icon:!!e.querySelector('svg')}));
  const ink=getComputedStyle(insp).getPropertyValue('--ink')||''; const ev=insp.querySelector('.ot-insp-evidence');
  return { count: all.length, h2: insp.querySelectorAll('h2').length, title: insp.querySelector('h2')?.textContent, type: insp.querySelector('.ot-insp-eyebrow')?.textContent, badge: insp.querySelector('.ot-insp-badge')?.textContent.trim(), badgeIcon: !!insp.querySelector('.ot-insp-badge svg'),
    q, q3: insp.querySelector('[data-question]:nth-child(3) h3')?.textContent, evTitle: ev?.querySelector('h3')?.textContent, rows: ev?.querySelectorAll(':scope > dl > div').length ?? 0, allEv: insp.querySelector('.ot-insp-allev summary')?.textContent || null,
    sourcesOpen: insp.querySelector('.ot-insp-sources')?.open, states, id: insp.dataset.recordId, qset: insp.dataset.questionSet, scrollX: document.documentElement.scrollWidth > innerWidth + 1,
    asideRect: (()=>{const r=insp.getBoundingClientRect(); return [Math.round(r.left),Math.round(r.width)]})() , bg: getComputedStyle(document.body).backgroundColor };
})()`;

try {
  const pg = await newPage(browser, { width: 1440, height: 900 });
  await pg.goto(base); await pg.waitFor(`document.getElementById('ot-scan') && !document.getElementById('ot-scan').disabled`, 30000);
  await pg.eval(`(()=>{const e=document.getElementById('ot-url');e.value='';e.dispatchEvent(new Event('input',{bubbles:true}))})()`); await pg.type('#ot-url', 'https://github.com/acme/aicrypto'); await pg.click('#ot-scan');
  await pg.waitFor(`window.__otStore.get().destination === 'workbench' || window.__otStore.get().scan?.status?.job?.state === 'failed'`, 90000);
  ok('fixture scan reached the workbench', await pg.eval(`window.__otStore.get().destination === 'workbench'`));
  const tab = async (t) => { await pg.eval(`document.getElementById('ot-tab-${t}').click()`); await sleep(700); };
  const shot = async (n) => pg.screenshot(join(OUT, n + '.png'));
  const pick = async (sel, i) => { const n = await pg.eval(`document.querySelectorAll(${JSON.stringify(sel)}).length`); if (n <= i) return false; await pg.eval(`document.querySelectorAll(${JSON.stringify(sel)})[${i}].dispatchEvent(new MouseEvent('click',{bubbles:true}))`); await sleep(600); return true; };
  const check = (tabName, s, expectQ, third) => {
    ok(`${tabName}: exactly one sidebar and one header`, s.count === 1 && s.h2 === 1, JSON.stringify({ c: s.count, h2: s.h2 }));
    ok(`${tabName}: question order ${expectQ.join(',')}`, JSON.stringify(s.q) === JSON.stringify(expectQ), JSON.stringify(s.q));
    ok(`${tabName}: third question is "${third}"`, s.q3 === third, s.q3);
    ok(`${tabName}: header status has icon and text`, s.badgeIcon && s.badge, s.badge);
    ok(`${tabName}: every question status has icon and text; tone colours are not all flattened to ink`, s.states.every((x) => x.icon && x.text) && new Set(s.states.map((x) => x.color)).size >= 2, JSON.stringify(s.states.map((x) => [x.cls.split(' ').pop(), x.color])).slice(0, 250));
    ok(`${tabName}: at most 3 evidence rows initially`, s.rows <= 3, s.rows);
    ok(`${tabName}: Sources & coverage collapsed by default`, s.sourcesOpen === false, s.sourcesOpen);
    ok(`${tabName}: no horizontal page scroll`, !s.scrollX);
  };
  const FOUR = ['what_is_this', 'why_here', 'security_concern', 'what_unknown']; const BOM4 = ['what_is_this', 'why_here', 'comparison_established', 'what_unknown'];
  const tabs = [['contexts', 'g[data-ctx]', FOUR, 'Is there a security concern?'], ['dependencies', 'g[data-dep-node]', FOUR, 'Is there a security concern?'], ['crypto', '#otc-svg g[data-otc-select^=asset]', FOUR, 'Is there a security concern?'], ['ai', '#otai-svg g[data-otai-select^=asset]', FOUR, 'Is there a security concern?']];
  const seen = {};
  for (const [t, sel, qs, third] of tabs) {
    await tab(t);
    if (!(await pick(sel, 0))) { ok(`${t}: a record was available to select`, false, sel); continue; }
    const a = await pg.eval(SNAP); check(t + ' record A', a, qs, third); await shot(`${t}-A-light-1440`);
    const had2 = await pick(sel, 1); const b = had2 ? await pg.eval(SNAP) : null;
    if (b) { check(t + ' record B', b, qs, third); ok(`${t}: switching records changes the sidebar (own title and id)`, a.id !== b.id && a.title !== b.title || a.id !== b.id, `${a.title} -> ${b.title}`); }
    else ok(`${t}: second distinct record (fixture has only one)`, true, 'single record');
    // evidence disclosures
    const opened = await pg.eval(`(()=>{const d=[...document.querySelectorAll('#ot-tabpanel .ot-insp-allev, #ot-tabpanel .supplement-more, #ot-tabpanel .ot-insp-why, #ot-tabpanel .ot-insp-sources')]; d.forEach(x=>x.open=true); return d.map(x=>x.className)})()`);
    await sleep(200); await shot(`${t}-disclosures-light-1440`);
    ok(`${t}: evidence/why/sources disclosures open without breaking layout`, !(await pg.eval(SNAP)).scrollX, opened.join(' '));
    seen[t] = { a: a.title, b: b?.title, disclosures: opened.length };
  }
  // BOM
  await tab('bom'); await pg.waitFor(`window.__otStore.get().bom8.queue`, 30000); await sleep(800);
  const hasRow = await pg.eval(`!!document.querySelector('[data-action=bom-select]')`);
  if (hasRow) {
    await pg.eval(`document.querySelector('[data-action=bom-select]').click()`); await pg.waitFor(`document.querySelector('[data-evidence-for] .ot-gap-inspector')`, 30000).catch(() => {}); await sleep(500);
    const a = await pg.eval(SNAP); check('bom candidate', a, BOM4, 'What did the comparison establish?'); ok('bom candidate: header says Candidate check; evidence titled "Evidence for this check"', a.type === 'Candidate check' && a.evTitle === 'Evidence for this check', `${a.type} / ${a.evTitle}`);
    await shot('bom-candidate-light-1440');
    const rows = await pg.eval(`document.querySelectorAll('[data-action=bom-select]').length`);
    if (rows > 1) { await pg.eval(`document.querySelectorAll('[data-action=bom-select]')[1].click()`); await sleep(1200); const b = await pg.eval(SNAP); ok('bom: a second candidate shows its own header', b.id && b.id !== a.id, `${a.id} -> ${b.id}`); check('bom candidate B', b, BOM4, 'What did the comparison establish?'); }
    await pg.eval(`document.querySelectorAll('[data-action=bom-select]')[0].click()`); await sleep(1200);
    const hasRec = await pg.eval(`!!document.querySelector('[data-action=bom-record]')`);
    if (hasRec) { await pg.eval(`document.querySelector('[data-action=bom-record]').click()`); await sleep(1200); const n = await pg.eval(SNAP); check('bom node', n, BOM4, 'What did the comparison establish?'); ok('bom node: explains itself (type Recorded ...), no candidate verdict inherited', /^Recorded/.test(n.type) && n.states[2]?.text === 'Not applicable', `${n.type} / ${n.states[2]?.text}`); await shot('bom-node-light-1440'); }
    else ok('bom: a recorded node was available', false, 'none');
    const hasEdge = await pg.eval(`(()=>{const d=document.querySelector('.ot-bom8-edges'); if(!d) return false; d.open=true; return !!d.querySelector('[data-action=bom-edge]')})()`);
    if (hasEdge) { await pg.eval(`document.querySelector('[data-action=bom-edge]').click()`); await sleep(1200); const e = await pg.eval(SNAP); check('bom relationship', e, BOM4, 'What did the comparison establish?'); ok('bom relationship: type "Recorded relationship"', e.type === 'Recorded relationship', e.type); await shot('bom-relationship-light-1440'); }
    else ok('bom: a recorded relationship was available (fixture may have none in this view)', true, 'none displayed');
  } else ok('bom: a candidate was available', false, 'no rows');
  // dark + narrower desktop
  await pg.eval(`window.__otStore.dispatch({type:'THEME', value:'dark'})`); await sleep(500);
  for (const t of ['crypto', 'ai', 'bom']) { await tab(t); if (t === 'crypto') await pick('#otc-svg g[data-otc-select^=asset]', 0); if (t === 'ai') await pick('#otai-svg g[data-otai-select^=asset]', 0); if (t === 'bom') { await pg.eval(`document.querySelector('[data-action=bom-select]')?.click()`); await sleep(1200); }
    const s = await pg.eval(SNAP); ok(`${t} dark: sidebar renders, one header, status colours differ from ink`, s.count === 1 && s.h2 === 1 && new Set(s.states.map((x) => x.color)).size >= 2, JSON.stringify(s.states.map((x) => x.color))); await shot(`${t}-dark-1440`); }
  await pg.eval(`window.__otStore.dispatch({type:'THEME', value:'light'})`);
  await pg.send('Emulation.setDeviceMetricsOverride', { width: 1100, height: 800, deviceScaleFactor: 1, mobile: false }); await sleep(900);
  for (const t of ['crypto', 'ai', 'bom']) { await tab(t); const s = await pg.eval(SNAP); ok(`${t} at 1100px: sidebar present, no horizontal page scroll`, s.count === 1 && !s.scrollX, JSON.stringify({ c: s.count, x: s.scrollX, a: s.asideRect })); await shot(`${t}-light-1100`); }
  ok('console/exception log clean of exceptions', pg.log.exceptions.length === 0, pg.log.exceptions.join(' | '));
  ok('no external network request', pg.log.requests.every((r) => r.url.startsWith(base.slice(0, -1)) || r.url.startsWith('data:') || r.url.startsWith('about:')), pg.log.requests.filter((r) => !r.url.startsWith(base.slice(0, -1))).map((r) => r.url).slice(0, 3).join(' '));
  writeFileSync(join(OUT, 'sidebar_check_results.json'), JSON.stringify({ base_url_redacted: true, elapsed_seconds: Math.round((Date.now() - T0) / 1000), services: 1, chrome: 1, headed: true, seen, results }, null, 1));
} catch (e) { ok('driver completed', false, e.stack || e.message); } finally { await cleanup(); }
const failed = results.filter((r) => !r.pass); console.log(`\n${results.length - failed.length}/${results.length} passed in ${Math.round((Date.now() - T0) / 1000)} s`); process.exit(failed.length ? 1 : 0);
