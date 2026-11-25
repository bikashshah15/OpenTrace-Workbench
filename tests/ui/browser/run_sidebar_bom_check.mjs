// Sidebar presentation refinement: BOM-focused rerun on the corrected source (one fixture service, one HEADED Chrome, <= 10 minutes from first launch, NO retry).
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
const OUT = resolve(process.argv[2] || join(REPO, 'evidence/uip/visual/sidebar-refinement-bom-rerun')); mkdirSync(OUT, { recursive: true });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const T0 = Date.now(); const DEADLINE = T0 + Number(process.env.DEADLINE_MS || 9 * 60 * 1000); const SHA = process.env.TESTED_SHA || 'unset';
const results = []; const ok = (name, pass, detail = '') => { results.push({ name, pass: !!pass, detail: String(detail).slice(0, 300) }); console.log((pass ? 'PASS ' : 'FAIL ') + name + (pass ? '' : ' :: ' + String(detail).slice(0, 300))); };

let svc = null; let chrome = null; let browser = null; let dir = null; let base = '';
const pids = []; let cleaned = false; let finished = false;
const writeResults = (extra = {}) => { try { writeFileSync(join(OUT, 'bom_rerun_results.json'), JSON.stringify({ tested_sha: SHA, elapsed_seconds: Math.round((Date.now() - T0) / 1000), services: svc ? 1 : 0, chrome: chrome ? 1 : 0, headed: true, retries: 0, started_pids: pids, seen: globalThis.__seen || {}, ...extra, results }, null, 1)); } catch (e) { console.log('could not write results: ' + e.message); } };
// Stops ONLY the processes this run started (service, Chrome) and removes its own profile dir; safe to call at any point, including after a startup failure.
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
// A real deadline: when it fires the run records what it has, cleans up and exits non-zero.
const timer = setTimeout(async () => { ok('deadline: run finished within its time limit', false, 'deadline reached'); writeResults({ deadline_hit: true }); await cleanup(); process.exit(3); }, DEADLINE - T0);
process.on('SIGINT', async () => { writeResults({ interrupted: true }); await cleanup(); process.exit(130); });
async function startAll() {
  svc = spawn(process.env.PYTHON || 'python3', [join(HERE, 'stage4_completion_service.py')], { cwd: REPO, env: { ...process.env, PYTHONPATH: REPO + ':' + join(REPO, 'src/core') + ':' + join(REPO, 'src/agents/investigator') }, stdio: ['ignore', 'pipe', 'pipe'] }); if (svc.pid) pids.push(svc.pid);
  base = await new Promise((res, rej) => { let b = ''; const t = setTimeout(() => rej(new Error('service did not start: ' + b)), 40000); svc.stdout.on('data', (d) => { b += d; const m = b.match(/http:\/\/127\.0\.0\.1:(\d+)\//); if (m) { clearTimeout(t); res(m[0]); } }); svc.stderr.on('data', (d) => { b += d; }); svc.on('exit', () => rej(new Error('service exited: ' + b))); svc.on('error', (e) => rej(new Error('service spawn error: ' + e.message))); });
  dir = mkdtempSync(join(tmpdir(), 'ot-sidebar-chrome-'));
  chrome = spawn(CHROME, ['--no-first-run', '--no-default-browser-check', `--user-data-dir=${dir}`, '--remote-debugging-port=0', '--window-size=1500,1000', 'about:blank'], { stdio: ['ignore', 'ignore', 'pipe'] }); if (chrome.pid) pids.push(chrome.pid);
  const wsUrl = await new Promise((res, rej) => { let b = ''; const t = setTimeout(() => rej(new Error('chrome did not start')), 30000); chrome.stderr.on('data', (d) => { b += d; const m = b.match(/DevTools listening on (ws:\/\/\S+)/); if (m) { clearTimeout(t); res(m[1]); } }); chrome.on('exit', () => rej(new Error('chrome exited'))); chrome.on('error', (e) => rej(new Error('chrome spawn error: ' + e.message))); });
  browser = await connect(wsUrl);
}

// In-page snapshot of the visible sidebar for the current tab.
const SNAP = `(()=>{
  const root = document.querySelector('.ot-bom8-drawer-body') || document.querySelector('#ot-tabpanel') ; const all=[...document.querySelectorAll('#ot-tabpanel .ot-insp')];
  const insp = all[0]; if (!insp) return { count: 0 };
  const q = [...insp.querySelectorAll('[data-question]')].map(e=>e.dataset.question);
  const states=[...insp.querySelectorAll('.ot-insp-card .ot-insp-state')].map(e=>({cls:e.className, color:getComputedStyle(e).color, text:e.textContent.trim(), icon:!!e.querySelector('svg')}));
  const ink=getComputedStyle(insp).getPropertyValue('--ink')||''; const ev=insp.querySelector('.ot-insp-evidence');
  return { count: all.length, h2: insp.querySelectorAll('h2').length, title: insp.querySelector('h2')?.textContent, type: insp.querySelector('.ot-insp-eyebrow')?.textContent, badge: insp.querySelector('.ot-insp-badge')?.textContent.trim(), badgeIcon: !!insp.querySelector('.ot-insp-badge svg'),
    q, q3: insp.querySelector('[data-question]:nth-child(3) h3')?.textContent, evTitle: ev?.querySelector('h3')?.textContent, rows: ev?.querySelectorAll(':scope > dl > div').length ?? 0, allEv: insp.querySelector('.ot-insp-allev summary')?.textContent || null,
    sourcesOpen: insp.querySelector('.ot-insp-sources')?.open, states, id: insp.dataset.recordId, qset: insp.dataset.questionSet, scrollX: document.documentElement.scrollWidth > innerWidth + 1, overflowers: (()=>{const w=innerWidth; return [...document.querySelectorAll('#ot-tabpanel *')].filter(e=>e.getBoundingClientRect().right>w+1).slice(0,4).map(e=>e.tagName+'.'+String(e.className).slice(0,40))})(), insideScrollX: insp.scrollWidth>insp.clientWidth+1, text: insp.innerText.replace(/\\s+/g,' ').slice(0,4000),
    asideRect: (()=>{const r=insp.getBoundingClientRect(); return [Math.round(r.left),Math.round(r.width)]})() , bg: getComputedStyle(document.body).backgroundColor };
})()`;

try {
  await startAll();
  const pg = await newPage(browser, { width: 1440, height: 900 });
  await pg.goto(base); await pg.waitFor(`document.getElementById('ot-scan') && !document.getElementById('ot-scan').disabled`, 30000);
  await pg.eval(`(()=>{const e=document.getElementById('ot-url');e.value='';e.dispatchEvent(new Event('input',{bubbles:true}))})()`); await pg.type('#ot-url', 'https://github.com/acme/aicrypto'); await pg.click('#ot-scan');
  await pg.waitFor(`window.__otStore.get().destination === 'workbench'`, 90000);
  await pg.eval(`document.getElementById('ot-tab-bom').click()`); await pg.waitFor(`window.__otStore.get().bom8.queue`, 30000); await sleep(800);
  const shot = (n) => pg.screenshot(join(OUT, n + '.png'));
  const BOM4 = ['what_is_this', 'why_here', 'comparison_established', 'what_unknown'];
  const settle = () => sleep(1200);
  const check = (label, s, want) => {
    ok(`${label}: one sidebar, one header`, s.count === 1 && s.h2 === 1, JSON.stringify({ c: s.count, h2: s.h2 }));
    ok(`${label}: four questions in order, third = comparison`, JSON.stringify(s.q) === JSON.stringify(BOM4) && s.q3 === 'What did the comparison establish?', JSON.stringify(s.q) + s.q3);
    ok(`${label}: header status icon + text`, s.badgeIcon && !!s.badge, s.badge);
    ok(`${label}: question statuses have icon + text`, s.states.every((x) => x.icon && x.text), '');
    ok(`${label}: status tones are coloured (not all ink)`, new Set(s.states.map((x) => x.color)).size >= 2, JSON.stringify(s.states.map((x) => [x.cls.split(' ').pop(), x.color])).slice(0, 260));
    ok(`${label}: <= 3 evidence rows initially, sources collapsed`, s.rows <= 3 && s.sourcesOpen === false, `${s.rows} ${s.sourcesOpen}`);
    ok(`${label}: no horizontal page overflow`, !s.scrollX && !s.insideScrollX, JSON.stringify({ x: s.scrollX, inner: s.insideScrollX, o: s.overflowers }));
    if (want) ok(`${label}: type is "${want}"`, s.type === want, s.type);
  };
  const selectItem = async (i) => { await pg.eval(`document.querySelectorAll('[data-action=bom-select]')[${i}].click()`); await pg.waitFor(`document.querySelector('[data-evidence-for] .ot-gap-inspector')`, 30000).catch(() => {}); await settle(); };
  const nItems = await pg.eval(`document.querySelectorAll('[data-action=bom-select]').length`);
  const seen = globalThis.__seen = {};
  // 1440 light: candidate A, candidate B, node, relationship
  await selectItem(0); const A = await pg.eval(SNAP); check('light1440 candidate A', A, 'Candidate check'); await shot('bom-candidate-A-light-1440');
  if (nItems > 1) { await selectItem(1); const B = await pg.eval(SNAP); check('light1440 candidate B', B, 'Candidate check');
    ok('switching candidates: own id, own title, own status; the previous verdict text is not retained', B.id !== A.id && B.title !== A.title && (B.badge !== A.badge || B.q.length === 4) && !B.text.includes(A.title), `${A.id}/${A.badge} -> ${B.id}/${B.badge}`); await shot('bom-candidate-B-light-1440'); seen.B = { id: B.id, badge: B.badge }; }
  seen.A = { id: A.id, badge: A.badge };
  await selectItem(0);
  // expansion
  const exp = await pg.eval(`(()=>{const d=[...document.querySelectorAll('.ot-bom8-drawer-body .ot-insp-allev, .ot-bom8-drawer-body .ot-insp-why, .ot-bom8-drawer-body .ot-insp-sources, .ot-bom8-drawer-body .ot-more')]; d.forEach(x=>x.open=true); return d.map(x=>x.className.split(' ')[0])})()`); await sleep(300);
  const E = await pg.eval(SNAP); ok('evidence expansion and Sources & coverage open and stay usable (no overflow)', exp.includes('ot-insp-sources') && !E.scrollX && !E.insideScrollX, JSON.stringify({ exp, o: E.overflowers })); await shot('bom-candidate-A-expanded-light-1440');
  await pg.eval(`document.querySelector('.ot-bom8-drawer-body .ot-insp-sources').open=false`);
  const hasNode = await pg.eval(`!!document.querySelector('[data-action=bom-record]')`);
  if (hasNode) { await pg.eval(`document.querySelector('[data-action=bom-record]').click()`); await settle(); const N = await pg.eval(SNAP); check('light1440 node', N, null);
    ok('node: explains itself (Recorded ...), third answer Not applicable, candidate verdict not inherited', /^Recorded/.test(N.type) && N.states[2]?.text === 'Not applicable' && !N.text.includes(A.title), `${N.type}/${N.states[2]?.text}`); await shot('bom-node-light-1440'); seen.node = N.id; }
  else ok('a recorded node was available', false, 'none');
  const hasEdge = await pg.eval(`(()=>{const d=document.querySelector('.ot-bom8-edges'); if(!d) return false; d.open=true; return !!d.querySelector('[data-action=bom-edge]')})()`);
  if (hasEdge) { await pg.eval(`document.querySelector('[data-action=bom-edge]').click()`); await settle(); const R = await pg.eval(SNAP); check('light1440 relationship', R, 'Recorded relationship');
    ok('relationship: no data-flow claim, no inherited verdict', /not data flow or runtime use/.test(R.text) && R.states[2]?.text === 'Not applicable', R.states[2]?.text); await shot('bom-relationship-light-1440'); seen.edge = R.id; }
  else ok('a recorded relationship was available', false, 'none displayed');
  // dark 1440 and light/dark 1100, for the three selection kinds
  const kinds = [['candidate', async () => { await selectItem(0); }], ['node', async () => { if (hasNode) { await pg.eval(`document.querySelector('[data-action=bom-record]').click()`); await settle(); } }], ['relationship', async () => { if (hasEdge) { await pg.eval(`(()=>{const d=document.querySelector('.ot-bom8-edges'); if(d) d.open=true; document.querySelector('[data-action=bom-edge]')?.click()})()`); await settle(); } }]];
  const modes = [['dark', 1440, 900, 'dark'], ['light', 1100, 800, 'light'], ['dark', 1100, 800, 'dark']];
  for (const [theme, w, h] of modes) {
    await pg.eval(`window.__otStore.dispatch({type:'THEME', value:'${theme}'})`); await pg.send('Emulation.setDeviceMetricsOverride', { width: w, height: h, deviceScaleFactor: 1, mobile: false }); await sleep(900);
    for (const [k, go] of kinds) { await go(); const s = await pg.eval(SNAP); const label = `${theme}${w} ${k}`; check(label, s, null); await shot(`bom-${k}-${theme}-${w}`); }
  }
  ok('no exceptions in the page log', pg.log.exceptions.length === 0, pg.log.exceptions.join(' | '));
  ok('no external network request', pg.log.requests.every((r) => r.url.startsWith(base.slice(0, -1)) || r.url.startsWith('data:') || r.url.startsWith('about:')), '');
  globalThis.__seen = seen;
} catch (e) { ok('driver completed', false, e.stack || e.message); } finally { finished = true; clearTimeout(timer); writeResults(); await cleanup(); writeResults({ cleanup_alive: globalThis.__alive || [] }); }
const failed = results.filter((r) => !r.pass); console.log(`\n${results.length - failed.length}/${results.length} passed in ${Math.round((Date.now() - T0) / 1000)} s`); process.exit(failed.length ? 1 : 0);
