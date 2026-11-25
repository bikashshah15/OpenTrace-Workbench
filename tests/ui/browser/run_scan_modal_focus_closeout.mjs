// Scan-progress modal, SMR-13 focus closeout: ONE pass, ONLY the focus behaviour of the transitions that REMOVE the focused scan control, against local
// deterministic fixtures (live_service.py: local git repo, fake scanners, recorded transport; no real scan, build or provider). One fixture service and one
// headed Chrome, always stopped. Each scenario starts on a fresh page; every check is isolated and saved as it runs.
//   node tests/ui/browser/run_scan_modal_focus_closeout.mjs <outDir> [--headless]
// Scenarios (sequenced so none depends on a control another scenario removes):
//   M    minimized hand-off              O    open-dialog hand-off
//   E1   End session from the dialog footer (dialog open)
//   E2   End session from the in-page button while minimized
//   E3   End session from the header control while minimized
//   R1   403 retirement while minimized  (session revoked on the service; the next status poll gets 403)
//   R2   403 retirement while the dialog is open
// Assertions per scenario: the focus target immediately after the transition's repaint (captured by a store subscriber that runs right after the app's own
// render) and again 400 ms later; the dialog does not reopen; no duplicate POST /api/scan; no further status polls after a retirement.
import { spawn } from 'node:child_process';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { launch, newPage } from './cdp.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = resolve(HERE, '../../..');
const OUT = resolve(process.argv[2] || join(REPO, 'evidence/uip/validation/scan-modal-focus-closeout'));
mkdirSync(OUT, { recursive: true });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const T0 = Date.now(); const results = []; const notes = {};
const save = (extra = {}) => writeFileSync(join(OUT, 'results.json'), JSON.stringify({ elapsed_s: Math.round((Date.now() - T0) / 1000), results, notes, ...extra }, null, 1));
const check = (id, ok, detail = '') => { results.push({ id, ok: !!ok, detail: String(detail).slice(0, 320) }); console.log(`${ok ? 'PASS' : 'FAIL'} ${id}${detail ? ' — ' + String(detail).slice(0, 240) : ''}`); save(); };
const guarded = async (id, fn) => { try { await fn(); } catch (e) { check(id + ' [exception]', false, e.message); } };

function service() {
  const proc = spawn(process.env.PYTHON || 'python3', [join(HERE, 'live_service.py'), '--cbom-sleep', '25'], { cwd: REPO, env: { ...process.env, PYTHONPATH: `${REPO}:${join(REPO, 'src/core')}` }, stdio: ['ignore', 'pipe', 'pipe'] });
  return new Promise((res, rej) => { let b = ''; const t = setTimeout(() => rej(new Error('service did not start: ' + b)), 40000);
    proc.stdout.on('data', (d) => { b += d; const m = b.match(/http:\/\/127\.0\.0\.1:(\d+)\//); if (m) { clearTimeout(t); res({ base: m[0], origin: new URL(m[0]).origin, stop: () => proc.kill('SIGTERM') }); } });
    proc.stderr.on('data', (d) => { b += d; }); });
}
const E = (pg, x) => pg.eval(x);
const setUrl = async (pg, url) => { await pg.eval(`(()=>{const e=document.getElementById('ot-url');e.value='';e.dispatchEvent(new Event('input',{bubbles:true}))})()`); await pg.type('#ot-url', url); };
const ready = (pg) => pg.waitFor(`document.getElementById('ot-scan') && !document.getElementById('ot-scan').disabled`, 20000);
const startRunning = async (pg) => { await setUrl(pg, 'https://github.com/acme/widget'); await pg.click('#ot-scan'); await pg.waitFor(`document.querySelector('#ot-scan-dialog .ot-scan-stage[data-stage=cbom][data-state=running]')`, 30000); };
const polls = (pg, o) => pg.log.requests.filter((r) => r.url.startsWith(o + '/api/scan/status')).length;
const scanPosts = (pg, o) => pg.log.requests.filter((r) => r.url === o + '/api/scan' && r.method === 'POST').length;
const activeId = (pg) => E(pg, `document.activeElement ? (document.activeElement.id || document.activeElement.tagName) : 'none'`);
// Capture the focus target IMMEDIATELY after the transition's repaint: this subscriber is registered after the app's render subscriber, so it runs right after it.
const arm = (pg, kind) => E(pg, `(()=>{window.__cap=null;window.__otStore.subscribe((s)=>{if(window.__cap)return;const hit=${kind === 'handoff' ? "s.destination==='workbench'" : "s.ended!=null"};if(hit){const a=document.activeElement;window.__cap={id:a?(a.id||a.tagName):'none',dialogOpen:document.getElementById('ot-scan-dialog').open,chip:!!document.getElementById('ot-scan-chip')}}})})()`);
const cap = (pg) => E(pg, `window.__cap`);
const shot = (pg, n) => pg.screenshot(join(OUT, n + '.png'));
// What counts as a good target. A page control (not <body>, which is "browser chrome / nowhere").
const HOME = ['ot-scan', 'ot-url', 'ot-main'];
const cleanup = (pg) => E(pg, `fetch('/api/session/end',{method:'POST'}).then(()=>true).catch(()=>true)`);

let browser; let closeBrowser; let svc;
const stopAll = async (why) => { try { check('stopped: ' + why, false); save({ stopped: why }); } catch {} try { await closeBrowser?.(); } catch {} try { svc?.stop(); } catch {} process.exit(2); };
const watchdog = setTimeout(() => stopAll('9 minute limit'), 9 * 60 * 1000);
process.on('SIGINT', () => stopAll('SIGINT')); process.on('SIGTERM', () => stopAll('SIGTERM'));

// A scenario: open a page, run `setup`, trigger the transition, then assert focus immediately + after 400 ms, no reopen, no duplicate submit.
async function scenario(id, { kind, expect, minimize, trigger, retired }) {
  const pg = await newPage(browser, { width: 1280, height: 800 });
  try {
    await pg.goto(svc.base); await ready(pg);
    await startRunning(pg);
    if (minimize) { await pg.key('Escape'); await pg.waitFor(`document.getElementById('ot-scan-chip')`, 3000); }
    const pre = await activeId(pg);
    if (minimize) check(`${id} precondition: the minimized control holds focus`, pre === 'ot-scan-chip', pre);
    else check(`${id} precondition: focus is inside the open dialog`, await E(pg, `document.getElementById('ot-scan-dialog').contains(document.activeElement)`), pre);
    await arm(pg, kind);
    await trigger(pg);
    await pg.waitFor(`window.__cap`, kind === 'handoff' ? 60000 : 15000);
    const c = await cap(pg); notes[id] = { pre, immediate: c };
    const okTarget = (x) => expect.includes(x);
    check(`${id} focus target immediately after the transition is a page control, not <body>`, okTarget(c.id), JSON.stringify(c));
    await sleep(400);
    const later = await activeId(pg); notes[id].after400 = later;
    check(`${id} focus is the same intended target 400 ms later`, okTarget(later) && later === c.id, `${c.id} -> ${later}`);
    const p0 = polls(pg, svc.origin); await sleep(3200);
    const st = await E(pg, `({open:document.getElementById('ot-scan-dialog').open,uiOpen:window.__otStore.get().scanUi.open,uiActive:window.__otStore.get().scanUi.active,chip:!!document.getElementById('ot-scan-chip'),job:window.__otStore.get().scan.job})`);
    check(`${id} no unexpected reopening of the dialog or a stale control after 3 s; exactly one scan submission`, !st.open && !st.uiOpen && !st.chip && scanPosts(pg, svc.origin) === 1, JSON.stringify({ ...st, posts: scanPosts(pg, svc.origin) }));
    if (retired) check(`${id} no further status polls after the session was retired`, polls(pg, svc.origin) === p0, `polls ${p0}->${polls(pg, svc.origin)}`);
    if (kind === 'handoff') {
      const r = await E(pg, `(()=>{const s=window.__otStore.get();return {tab:s.workbench.tab,mode:s.analysis&&s.analysis.identity&&s.analysis.identity.mode,uiActive:s.scanUi.active}})()`);
      check(`${id} Repository contexts opened with the live result, scan UI state reset`, r.tab === 'contexts' && r.mode === 'live' && !r.uiActive, JSON.stringify(r));
    } else {
      const ended = await E(pg, `window.__otStore.get().ended`);
      check(`${id} the session ended and the scan state is cleared`, !!ended && (await E(pg, `window.__otStore.get().scan.job`)) === null, String(ended));
    }
    await shot(pg, id);
    check(`${id} no page errors`, pg.log.exceptions.length === 0, pg.log.exceptions.join('|'));
    await cleanup(pg);
  } finally { await pg.close(); }
}

// E4 (reviewer SMR-15): after a hand-off the person is on the Workbench; End session from the header button, which is only HIDDEN afterwards.
async function workbenchEnd() {
  const id = 'E4 End session from the header on the Workbench';
  const pg = await newPage(browser, { width: 1280, height: 800 });
  try {
    await pg.goto(svc.base); await ready(pg); await startRunning(pg);
    await pg.waitFor(`window.__otStore.get().destination==='workbench'`, 60000);
    await sleep(500);
    await arm(pg, 'end');
    await pg.click('#ot-top-end');
    await pg.waitFor(`window.__cap`, 15000);
    const c = await cap(pg); await sleep(400); const later = await activeId(pg);
    notes[id] = { immediate: c, after400: later };
    check(`${id}: focus is a page control, not <body> and not the hidden header button, immediately and 400 ms later`, HOME.includes(c.id) && later === c.id, JSON.stringify({ c, later }));
    check(`${id}: one scan submission, no reopening`, scanPosts(pg, svc.origin) === 1 && !(await E(pg, `document.getElementById('ot-scan-dialog').open`)));
    await shot(pg, 'E4'); await cleanup(pg);
  } finally { await pg.close(); }
}

try {
  svc = await service();
  ({ browser, close: closeBrowser } = await launch({ headed: !process.argv.includes('--headless') }));
  await guarded('M', () => scenario('M minimized hand-off', { kind: 'handoff', expect: ['ot-main'], minimize: true, trigger: async () => {} }));
  await guarded('O', () => scenario('O open-dialog hand-off', { kind: 'handoff', expect: ['ot-main'], minimize: false, trigger: async () => {} }));
  await guarded('E1', () => scenario('E1 End session from the dialog footer', { kind: 'end', expect: HOME, minimize: false, retired: true, trigger: (pg) => pg.click('#ot-scan-dialog-end') }));
  await guarded('E2', () => scenario('E2 End session from the in-page button (minimized)', { kind: 'end', expect: HOME, minimize: true, retired: true, trigger: (pg) => pg.click('#ot-end-session') }));
  await guarded('E3', () => scenario('E3 End session from the header (minimized)', { kind: 'end', expect: HOME, minimize: true, retired: true, trigger: (pg) => pg.click('#ot-top-end') }));
  // 403 retirement: the service revokes the session (as if ended elsewhere); the next status poll returns 403 and the page retires locally.
  await guarded('R1', () => scenario('R1 403 retirement while minimized', { kind: 'end', expect: HOME, minimize: true, retired: true, trigger: (pg) => E(pg, `fetch('/api/session/end',{method:'POST'}).then(()=>true)`) }));
  await guarded('R2', () => scenario('R2 403 retirement with the dialog open', { kind: 'end', expect: HOME, minimize: false, retired: true, trigger: (pg) => E(pg, `fetch('/api/session/end',{method:'POST'}).then(()=>true)`) }));
  await guarded('E4', workbenchEnd);
} catch (e) { check('focus closeout run completed without exception', false, e.stack || e.message); }
finally { clearTimeout(watchdog); try { await closeBrowser?.(); } catch {} try { svc?.stop(); } catch {} save({ finished: true }); }
process.exit(0);
