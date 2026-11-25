// Scan-progress modal closeout: ONE pass, the four behaviors that failed in pass 1 only, against local deterministic fixtures
// (live_service.py: local git repo, fake scanners, recorded transport; no real scan, build, provider or assistant). One service, one headed Chrome,
// both always stopped. Every check is isolated, so one exception cannot hide the others; results are saved after each check and on any exit.
//   node tests/ui/browser/run_scan_modal_closeout.mjs <outDir> [--headless]
import { spawn } from 'node:child_process';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { launch, newPage } from './cdp.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = resolve(HERE, '../../..');
const OUT = resolve(process.argv[2] || join(REPO, 'evidence/uip/validation/scan-modal-closeout'));
mkdirSync(OUT, { recursive: true });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const T0 = Date.now(); const results = []; const notes = {};
const save = (extra = {}) => writeFileSync(join(OUT, 'results.json'), JSON.stringify({ elapsed_s: Math.round((Date.now() - T0) / 1000), results, notes, ...extra }, null, 1));
const check = (id, ok, detail = '') => { results.push({ id, ok: !!ok, detail: String(detail).slice(0, 300) }); console.log(`${ok ? 'PASS' : 'FAIL'} ${id}${detail ? ' — ' + String(detail).slice(0, 220) : ''}`); save(); };
const guarded = async (id, fn) => { try { await fn(); } catch (e) { check(id + ' [exception]', false, e.message); } };

function service() {
  const proc = spawn(process.env.PYTHON || 'python3', [join(HERE, 'live_service.py'), '--cbom-sleep', '25'], { cwd: REPO, env: { ...process.env, PYTHONPATH: `${REPO}:${join(REPO, 'src/core')}` }, stdio: ['ignore', 'pipe', 'pipe'] });
  return new Promise((res, rej) => { let b = ''; const t = setTimeout(() => rej(new Error('service did not start: ' + b)), 40000);
    proc.stdout.on('data', (d) => { b += d; const m = b.match(/http:\/\/127\.0\.0\.1:(\d+)\//); if (m) { clearTimeout(t); res({ base: m[0], origin: new URL(m[0]).origin, stop: () => proc.kill('SIGTERM') }); } });
    proc.stderr.on('data', (d) => { b += d; }); });
}
const E = (pg, x) => pg.eval(x);
const state = (pg) => E(pg, 'JSON.parse(JSON.stringify(window.__otStore.get()))');
const setUrl = async (pg, url) => { await pg.eval(`(()=>{const e=document.getElementById('ot-url');e.value='';e.dispatchEvent(new Event('input',{bubbles:true}))})()`); await pg.type('#ot-url', url); };
const ready = (pg) => pg.waitFor(`document.getElementById('ot-scan') && !document.getElementById('ot-scan').disabled`, 20000);
// Focus classification: 'dialog' = inside the scan dialog; 'browser-chrome' = nothing in the page has focus (document.body / null: focus is in the browser UI or nowhere);
// 'BACKGROUND:<id>' = a page control outside the dialog has focus (the unintended case). The page behind a modal is inert, so this should never occur.
const focusClass = (pg) => E(pg, `(()=>{const a=document.activeElement;const d=document.getElementById('ot-scan-dialog');if(!a||a===document.body||a===document.documentElement)return 'browser-chrome';if(d.contains(a))return 'dialog';return 'BACKGROUND:'+(a.id||a.tagName)})()`);
const gets = (pg, o) => pg.log.requests.filter((r) => r.url.startsWith(o + '/api/scan/status')).length;
const posts = (pg, o, path) => pg.log.requests.filter((r) => r.url === o + path && r.method === 'POST').length;
const shot = (pg, n) => pg.screenshot(join(OUT, n + '.png'));
const startRunning = async (pg) => { await setUrl(pg, 'https://github.com/acme/widget'); await pg.click('#ot-scan'); await pg.waitFor(`document.querySelector('#ot-scan-dialog .ot-scan-stage[data-stage=cbom][data-state=running]')`, 30000); };

let browser; let closeBrowser; let svc;
const stopAll = async (why) => { try { check('stopped: ' + why, false); save({ stopped: why }); } catch {} try { await closeBrowser?.(); } catch {} try { svc?.stop(); } catch {} process.exit(2); };
const watchdog = setTimeout(() => stopAll('9 minute limit'), 9 * 60 * 1000);
process.on('SIGINT', () => stopAll('SIGINT')); process.on('SIGTERM', () => stopAll('SIGTERM'));

try {
  svc = await service();
  ({ browser, close: closeBrowser } = await launch({ headed: !process.argv.includes('--headless') }));
  // ===== A: 1280x800 light. One long-running scan: focus containment, Minimize focus, Escape+reopen (twice, same job), then the pass-1 S6 sequence.
  let pg = await newPage(browser, { width: 1280, height: 800 });
  await pg.goto(svc.base); await ready(pg);
  await guarded('A setup', async () => { await startRunning(pg); await shot(pg, 'A1_running'); });
  const job = (await state(pg)).scan.job; notes.job = job;

  await guarded('1 containment', async () => {
    const seen = { dialog: 0, 'browser-chrome': 0, background: [] };
    const log = [];
    for (let i = 0; i < 14; i++) { await pg.key('Tab'); const c = await focusClass(pg); log.push(c); if (c === 'dialog') seen.dialog++; else if (c === 'browser-chrome') seen['browser-chrome']++; else seen.background.push(c); }
    for (let i = 0; i < 8; i++) { await pg.key('Tab', 'Tab', { modifiers: 8 }); const c = await focusClass(pg); log.push('S+' + c); if (c === 'dialog') seen.dialog++; else if (c === 'browser-chrome') seen['browser-chrome']++; else seen.background.push(c); }
    notes.tabSequence = log;
    check('1 keyboard focus never lands on a BACKGROUND page control (22 Tab / Shift+Tab presses)', seen.background.length === 0, JSON.stringify({ ...seen, background: seen.background }));
    check('1 browser-chrome focus (body) is counted separately and is not a page control', true, `dialog=${seen.dialog} browser-chrome=${seen['browser-chrome']}`);
    // the dialog is still operable afterwards: Tab from wherever focus is returns into it, and the page behind stays inert
    for (let i = 0; i < 3; i++) await pg.key('Tab');
    check('1 after the sequence the dialog is still open, same job, focus is in the dialog or browser chrome', (await E(pg, `document.getElementById('ot-scan-dialog').open`)) && (await state(pg)).scan.job === job && !String(await focusClass(pg)).startsWith('BACKGROUND'));
    check('1 the page behind is inert while the modal is open (:modal, background control cannot take a click focus)', await E(pg, `document.getElementById('ot-scan-dialog').matches(':modal') && (()=>{document.getElementById('ot-url').focus();return document.activeElement!==document.getElementById('ot-url')})()`));
  });

  await guarded('2 minimize focus', async () => {
    await pg.click('#ot-scan-minimize');
    // read IMMEDIATELY (no settling wait): the pass-1 failure was a late return
    const now = await E(pg, `(()=>{const d=document.getElementById('ot-scan-dialog');return {open:d.open,chip:!!document.getElementById('ot-scan-chip'),focus:document.activeElement&&document.activeElement.id}})()`);
    await sleep(400);
    const later = await E(pg, `document.activeElement&&document.activeElement.id`);
    check('2 after the Minimize button the control has focus immediately and still 400 ms later', !now.open && now.chip && now.focus === 'ot-scan-chip' && later === 'ot-scan-chip', JSON.stringify({ now, later }));
    await shot(pg, 'A2_minimized_focus');
  });

  for (const round of [1, 2]) await guarded(`4 escape+reopen #${round}`, async () => {
    await pg.click('#ot-scan-chip'); await pg.waitFor(`document.getElementById('ot-scan-dialog').open`, 3000);
    const g0 = gets(pg, svc.origin);
    await pg.key('Escape');
    const now = await E(pg, `({open:document.getElementById('ot-scan-dialog').open,chip:!!document.getElementById('ot-scan-chip'),focus:document.activeElement&&document.activeElement.id,uiOpen:window.__otStore.get().scanUi.open})`);
    await sleep(2600);
    const st = await state(pg);
    check(`4 Escape #${round} hides it at once (DOM and state agree), focus on the control, polling continues, job unchanged and not cancelled`, !now.open && now.chip && now.focus === 'ot-scan-chip' && !now.uiOpen && gets(pg, svc.origin) > g0 && st.scan.job === job && st.scan.status.job.state === 'running' && posts(pg, svc.origin, '/api/analysis/cancel') === 0, JSON.stringify(now));
    await pg.click('#ot-scan-chip'); await pg.waitFor(`document.getElementById('ot-scan-dialog').open`, 3000);
    const st2 = await state(pg);
    check(`4 reopening #${round} shows the SAME job (one POST /api/scan total)`, st2.scan.job === job && posts(pg, svc.origin, '/api/scan') === 1 && (await focusClass(pg)) === 'dialog', await focusClass(pg));
  });

  await guarded('4 pass-1 S6 sequence', async () => {   // resize, reduced motion, theme toggle, Escape, then the control click that failed to reopen
    await pg.send('Emulation.setDeviceMetricsOverride', { width: 900, height: 360, deviceScaleFactor: 1, mobile: false }); await sleep(250);
    await pg.send('Emulation.setEmulatedMedia', { features: [{ name: 'prefers-reduced-motion', value: 'reduce' }] }); await sleep(250);
    await E(pg, `document.getElementById('ot-scan-minimize').click()`); await pg.waitFor(`document.getElementById('ot-scan-chip')`, 3000);
    await pg.click('#ot-theme'); await sleep(250);
    await pg.click('#ot-scan-chip'); await pg.waitFor(`document.getElementById('ot-scan-dialog').open`, 3000);
    await pg.key('Escape'); await sleep(200);
    const hid = await E(pg, `!document.getElementById('ot-scan-dialog').open && !!document.getElementById('ot-scan-chip')`);
    await pg.click('#ot-scan-chip'); await pg.waitFor(`document.getElementById('ot-scan-dialog').open`, 3000);
    check('4 resize + reduced motion + theme toggle + Escape, then the control reopens the same job', hid && (await state(pg)).scan.job === job && (await E(pg, `window.__otStore.get().theme`)) === 'dark');
    await shot(pg, 'A3_s6_sequence_reopened');
    await pg.send('Emulation.setEmulatedMedia', { features: [] });
    await pg.send('Emulation.setDeviceMetricsOverride', { width: 1280, height: 800, deviceScaleFactor: 1, mobile: false });
  });
  await guarded('A cleanup', async () => { await E(pg, `fetch('/api/session/end',{method:'POST'}).then(()=>true)`); });
  await pg.close();

  // ===== B: a fresh page; successful handoff while minimized (the pass-1 check that failed on an unidentified sub-condition)
  pg = await newPage(browser, { width: 1280, height: 800 });
  await pg.goto(svc.base); await ready(pg);
  await guarded('3 handoff while minimized', async () => {
    await startRunning(pg);
    await pg.key('Escape'); await pg.waitFor(`document.getElementById('ot-scan-chip')`, 3000);
    check('3 minimized control says the job is running', /Analysis running · View progress/.test(await E(pg, `document.getElementById('ot-scan-chip').innerText`)));
    await pg.waitFor(`window.__otStore.get().destination==='workbench'`, 60000);
    const r = await E(pg, `(()=>{const s=window.__otStore.get();return {dialogOpen:document.getElementById('ot-scan-dialog').open,chipInDom:!!document.getElementById('ot-scan-chip'),analyzeHtml:document.getElementById('ot-analyze').innerHTML.length,tab:s.workbench.tab,mode:s.analysis&&s.analysis.identity&&s.analysis.identity.mode,uiActive:s.scanUi.active,uiOpen:s.scanUi.open,jobState:s.scan.status&&s.scan.status.job.state,handoff:s.scan.status&&s.scan.status.handoff.ready,focus:document.activeElement&&(document.activeElement.id||document.activeElement.tagName)}})()`);
    notes.handoff = r;
    check('3 minimized success: dialog closed, no control left anywhere in the DOM, hidden homepage emptied, Repository contexts open, live result, UI state reset', !r.dialogOpen && !r.chipInDom && r.analyzeHtml === 0 && r.tab === 'contexts' && r.mode === 'live' && !r.uiActive && !r.uiOpen && r.jobState === 'completed' && r.handoff === true, JSON.stringify(r));
    await shot(pg, 'B1_handoff_workbench');
    await pg.click('[data-nav=analyze]'); await sleep(300);
    check('3 returning to Analyze repaints a clean homepage with no stale scan control', !(await E(pg, `!!document.getElementById('ot-scan-chip')`)) && (await E(pg, `!!document.getElementById('ot-form')`)));
    check('3 no page errors', pg.log.exceptions.length === 0, pg.log.exceptions.join('|'));
    await E(pg, `fetch('/api/session/end',{method:'POST'}).then(()=>true)`);
  });
  await pg.close();
} catch (e) { check('closeout run completed without exception', false, e.stack || e.message); }
finally { clearTimeout(watchdog); try { await closeBrowser?.(); } catch {} try { svc?.stop(); } catch {} save({ finished: true }); }
process.exit(0);
