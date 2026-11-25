// Scan-progress modal: focused desktop browser checks against the REAL Workbench with live scanning enabled on LOCAL deterministic fixtures
// (tests/ui/browser/live_service.py: a local git repository, fake scanner scripts, recorded GitHub answers; no network, no Docker, no real repository,
// scanner, build, credential or provider).  One fixture service and one headed Chrome are kept alive across passes:
//   node tests/ui/browser/run_scan_modal_checks.mjs <outDir> [--headless]
// Pass 1 runs at once. Afterwards the process waits for <outDir>/next (run one more pass in the SAME processes; the UI files are read from disk per request)
// or <outDir>/done (clean up and exit). Results are written after every pass and on any exception; Chrome and the service are always stopped.
import { spawn } from 'node:child_process';
import { existsSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { launch, newPage } from './cdp.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = resolve(HERE, '../../..');
const OUT = resolve(process.argv[2] || join(REPO, 'evidence/scan-modal-checks'));
const HEADLESS = process.argv.includes('--headless');
mkdirSync(OUT, { recursive: true });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const T0 = Date.now();
let results = []; let pass = 0;
const check = (id, ok, detail = '') => { results.push({ pass, id, ok: !!ok, detail: String(detail).slice(0, 240) }); console.log(`${ok ? 'PASS' : 'FAIL'} [p${pass}] ${id}${detail ? ' — ' + String(detail).slice(0, 200) : ''}`); };
const save = (extra = {}) => writeFileSync(join(OUT, 'results.json'), JSON.stringify({ elapsed_s: Math.round((Date.now() - T0) / 1000), results, ...extra }, null, 1));

function service() {
  const proc = spawn(process.env.PYTHON || 'python3', [join(HERE, 'live_service.py'), '--cbom-sleep', '8'], { cwd: REPO, env: { ...process.env, PYTHONPATH: `${REPO}:${join(REPO, 'src/core')}` }, stdio: ['ignore', 'pipe', 'pipe'] });
  return new Promise((res, rej) => { let b = ''; const t = setTimeout(() => rej(new Error('service did not start: ' + b)), 40000);
    proc.stdout.on('data', (d) => { b += d; const m = b.match(/http:\/\/127\.0\.0\.1:(\d+)\//); if (m) { clearTimeout(t); res({ base: m[0], origin: new URL(m[0]).origin, stop: () => proc.kill('SIGTERM') }); } });
    proc.stderr.on('data', (d) => { b += d; }); });
}

const E = (pg, expr) => pg.eval(expr);
const state = (pg) => E(pg, 'JSON.parse(JSON.stringify(window.__otStore.get()))');
const dlgOpen = (pg) => E(pg, `document.getElementById('ot-scan-dialog').open`);
const inDialog = (pg) => E(pg, `document.getElementById('ot-scan-dialog').contains(document.activeElement)`);
const posts = (pg, origin, path, method) => pg.log.requests.filter((r) => r.url === origin + path && r.method === method).length;
const gets = (pg, origin) => pg.log.requests.filter((r) => r.url.startsWith(origin + '/api/scan/status')).length;
const setUrl = async (pg, url) => { await pg.eval(`(()=>{const e=document.getElementById('ot-url');e.value='';e.dispatchEvent(new Event('input',{bubbles:true}))})()`); await pg.type('#ot-url', url); };
const ready = (pg) => pg.waitFor(`document.getElementById('ot-scan') && !document.getElementById('ot-scan').disabled`, 20000);
const cleanup = (pg) => E(pg, `fetch('/api/session/end',{method:'POST'}).then(()=>true).catch(()=>true)`);
const shot = (pg, name) => pg.screenshot(join(OUT, `p${pass}_${name}.png`));
async function fresh(svc, width, height, { dark = false } = {}) {
  const pg = await newPage(browser, { width, height });
  await pg.goto(svc.base); await ready(pg);
  if (dark) await pg.click('#ot-theme');
  return pg;
}
const startRunning = async (pg, url = 'https://github.com/acme/widget') => {
  await setUrl(pg, url); await pg.click('#ot-scan');
  await pg.waitFor(`document.querySelector('#ot-scan-dialog .ot-scan-stage[data-stage=cbom][data-state=running]')`, 30000);
};

let browser; let closeBrowser;
async function runPass(svc) {
  pass += 1;
  // ---------------------------------------------------------------- S1: open / minimize / reopen / focus / polling / handoff (1280x800, light)
  let pg = await fresh(svc, 1280, 800);
  try {
    await setUrl(pg, ''); await pg.click('#ot-scan');
    await sleep(300);
    check('S1 empty URL: no dialog; the error stays beside the input', !(await dlgOpen(pg)) && /Enter a GitHub repository URL/.test(await E(pg, `document.getElementById('ot-error').innerText`)) && posts(pg, svc.origin, '/api/scan', 'POST') === 0);
    await setUrl(pg, 'https://github.com/acme/widget');
    await E(pg, `(()=>{const b=document.getElementById('ot-scan');b.click();b.click();})()`);   // a double click must start exactly one job
    const t0 = Date.now(); await pg.waitFor(`document.getElementById('ot-scan-dialog').open`, 3000);
    check('S1 submit opens the dialog immediately (native modal)', true, `${Date.now() - t0} ms`);
    const first = await E(pg, `document.getElementById('ot-scan-dialog-body').innerText`);
    check('S1 first content is "Starting analysis…" or the first reported status', /Starting analysis…|Scan progress/.test(first), first.replace(/\n+/g, ' '));
    await pg.waitFor(`document.querySelector('#ot-scan-dialog .ot-scan-stage[data-stage=cbom][data-state=running]')`, 30000);
    await sleep(200);
    check('S1 exactly one POST /api/scan after a double click', posts(pg, svc.origin, '/api/scan', 'POST') === 1, String(posts(pg, svc.origin, '/api/scan', 'POST')));
    const m = await E(pg, `(()=>{const d=document.getElementById('ot-scan-dialog');const r=d.getBoundingClientRect();return {title:document.getElementById('ot-scan-dialog-title').innerText,labelled:d.getAttribute('aria-labelledby'),inForm:!!d.closest('form'),top:r.top,bottom:r.bottom,h:innerHeight,w:innerWidth,left:r.left,right:r.right,
      text:document.getElementById('ot-scan-dialog-body').innerText, btnTypes:[...d.querySelectorAll('button')].map(b=>b.type), hasCancel:!!d.querySelector('#ot-scan-cancel'),hasMin:!!d.querySelector('#ot-scan-minimize'),hasEnd:!!d.querySelector('#ot-scan-dialog-end'),minLabel:document.getElementById('ot-scan-minimize').innerText,inlinePanel:!!document.querySelector('#ot-analyze #ot-scan-status'), modalTop:d.matches(':modal')}})()`);
    check('S1 labelled heading; dialog outside the form; modal; bounded in the viewport', m.title === 'Repository analysis' && m.labelled === 'ot-scan-dialog-title' && !m.inForm && m.modalTop && m.top >= 0 && m.bottom <= m.h && m.left >= 0 && m.right <= m.w, JSON.stringify([m.top, m.bottom, m.h]));
    check('S1 every dialog button is type="button"; Cancel scan, Minimize and End session all inside', m.btnTypes.every((t) => t === 'button') && m.hasCancel && m.hasMin && m.hasEnd && m.minLabel === 'Minimize', m.btnTypes.join());
    check('S1 stages, pin and elapsed time are shown; no percentage and no ETA; no inline panel behind the dialog', /Resolve and pin/.test(m.text) && /Elapsed/.test(m.text) && /pinned commit/.test(m.text) && !/%|ETA|remaining/i.test(m.text) && !m.inlinePanel, m.text.replace(/\n+/g, ' ').slice(0, 160));
    check('S1 focus moved into the dialog once on open', await inDialog(pg));
    await shot(pg, 's1_running_light_1280');
    // keyboard containment
    let escaped = 0; for (let i = 0; i < 9; i++) { await pg.key('Tab'); if (!(await inDialog(pg))) escaped++; }
    for (let i = 0; i < 3; i++) { await pg.key('Tab', 'Tab', { modifiers: 8 }); if (!(await inDialog(pg))) escaped++; }
    check('S1 Tab / Shift+Tab never leave the dialog', escaped === 0, `escaped=${escaped}`);
    // a poll update must not steal focus
    await E(pg, `document.getElementById('ot-scan-minimize').focus()`);
    const g0 = gets(pg, svc.origin); await pg.waitFor(`true`); await sleep(3200);
    check('S1 polling continues while the dialog is open and does not move focus', gets(pg, svc.origin) > g0 && (await E(pg, `document.activeElement.id`)) === 'ot-scan-minimize', `gets ${g0}->${gets(pg, svc.origin)}`);
    const job = (await state(pg)).scan.job;
    // Escape minimizes (no cancel, no restart)
    await pg.key('Escape');
    await pg.waitFor(`!document.getElementById('ot-scan-dialog').open && document.getElementById('ot-scan-chip')`, 3000);
    const c1 = await E(pg, `({chip:document.getElementById('ot-scan-chip').innerText,focus:document.activeElement.id,inForm:!!document.getElementById('ot-scan-chip').closest('form'),live:document.getElementById('ot-scan-chip').closest('p').getAttribute('aria-live')})`);
    check('S1 Escape hides the dialog; compact control "Analysis running · View progress" outside the form, focus on it', /Analysis running · View progress/.test(c1.chip) && c1.focus === 'ot-scan-chip' && !c1.inForm && c1.live === 'polite', JSON.stringify(c1));
    const g1 = gets(pg, svc.origin); await sleep(2500);
    const s1 = await state(pg);
    check('S1 polling continues while minimized; the job is not cancelled or restarted; still one POST /api/scan', gets(pg, svc.origin) > g1 && s1.scan.job === job && s1.scan.status.job.state === 'running' && posts(pg, svc.origin, '/api/scan', 'POST') === 1 && posts(pg, svc.origin, '/api/analysis/cancel', 'POST') === 0, `gets ${g1}->${gets(pg, svc.origin)}`);
    check('S1 Scan stays disabled while minimized (no second job can start); URL retained', await E(pg, `document.getElementById('ot-scan').disabled && document.getElementById('ot-url').value==='https://github.com/acme/widget'`));
    await shot(pg, 's1_minimized_light_1280');
    await pg.click('#ot-scan-chip');
    await pg.waitFor(`document.getElementById('ot-scan-dialog').open`, 2000);
    const s2 = await state(pg);
    check('S1 reopening preserves the current job and shows it; focus inside the dialog', s2.scan.job === job && (await inDialog(pg)) && /Elapsed/.test(await E(pg, `document.getElementById('ot-scan-dialog-body').innerText`)));
    await pg.click('#ot-scan-minimize');
    await pg.waitFor(`!document.getElementById('ot-scan-dialog').open && document.getElementById('ot-scan-chip')`, 2000);
    check('S1 the Minimize button hides it too; focus returns to the control', (await E(pg, `document.activeElement.id`)) === 'ot-scan-chip');
    await pg.waitFor(`window.__otStore.get().destination==='workbench'`, 40000);
    const s3 = await state(pg);
    check('S1 minimized success closes everything and opens Repository contexts automatically', !(await dlgOpen(pg)) && !(await E(pg, `!!document.getElementById('ot-scan-chip')`)) && s3.workbench.tab === 'contexts' && s3.analysis.identity.mode === 'live' && s3.scanUi.active === false);
    await shot(pg, 's1_handoff_workbench');
    check('S1 no page errors', pg.log.exceptions.length === 0, pg.log.exceptions.join('|'));
    await cleanup(pg);
  } finally { await pg.close(); }

  // ---------------------------------------------------------------- S2: cancel and cleanup outcome; close keeps URL; reopen last status
  pg = await fresh(svc, 1280, 800);
  try {
    await startRunning(pg);
    await pg.click('#ot-scan-cancel');
    await pg.waitFor(`document.querySelector('#ot-scan-dialog .ot-scan-outcome[data-kind=cancelled]')`, 45000);
    const s = await state(pg);
    check('S2 Cancel waits for the reported outcome: cancelled + cleanup verified; nothing handed off; dialog stays open', await dlgOpen(pg) && s.scan.status.job.state === 'cancelled' && s.scan.status.cleanup.state !== 'pending' && s.analysis === null, `cleanup=${s.scan.status.cleanup.state}`);
    const t = await E(pg, `document.getElementById('ot-scan-dialog-body').innerText`);
    check('S2 the cancelled explanation is shown, no Cancel control remains, primary action reads Close', /Scan cancelled/.test(t) && !(await E(pg, `!!document.getElementById('ot-scan-cancel')`)) && (await E(pg, `document.getElementById('ot-scan-minimize').innerText`)) === 'Close', t.replace(/\n+/g, ' ').slice(-160));
    await shot(pg, 's2_cancelled');
    await pg.click('#ot-scan-minimize'); await pg.waitFor(`document.getElementById('ot-scan-chip')`, 2000);
    check('S2 closing returns to the homepage with the URL retained and a way to reopen the last status', /Scan cancelled · View last status/.test(await E(pg, `document.getElementById('ot-scan-chip').innerText`)) && (await E(pg, `document.getElementById('ot-url').value`)) === 'https://github.com/acme/widget' && !(await E(pg, `document.getElementById('ot-scan').disabled`)));
    await pg.click('#ot-scan-chip'); await pg.waitFor(`document.getElementById('ot-scan-dialog').open`, 2000);
    check('S2 reopening shows the same last status', /Scan cancelled/.test(await E(pg, `document.getElementById('ot-scan-dialog-body').innerText`)));
    await pg.key('Escape'); await pg.waitFor(`!document.getElementById('ot-scan-dialog').open`, 2000);
    await cleanup(pg);
  } finally { await pg.close(); }

  // ---------------------------------------------------------------- S3: refusal / failed resolution (dark, 1000x700)
  pg = await fresh(svc, 1000, 700, { dark: true });
  try {
    await setUrl(pg, 'https://github.com/acme/other'); await pg.click('#ot-scan');
    await pg.waitFor(`document.querySelector('#ot-scan-dialog .ot-scan-outcome[data-kind=failed]')`, 30000);
    const t = await E(pg, `document.getElementById('ot-scan-dialog-body').innerText`);
    check('S3 a failed scan stays visible in the dialog with its stage, fixed reason and next step; nothing handed off', await dlgOpen(pg) && /Resolve and pin the revision/.test(t) && /Failed/.test(t) && /not admitted|pilot list|try again later/.test(t) && (await state(pg)).analysis === null, t.replace(/\n+/g, ' ').slice(0, 200));
    check('S3 dark theme: dialog uses theme tokens', await E(pg, `(()=>{const d=document.getElementById('ot-scan-dialog');const cs=getComputedStyle(d);return document.documentElement.dataset.theme==='dark' && cs.backgroundColor!=='rgb(247, 246, 241)' && cs.color!==''})()`));
    await shot(pg, 's3_failed_dark_1000');
    await pg.click('#ot-scan-minimize'); await pg.waitFor(`document.getElementById('ot-scan-chip')`, 2000);
    check('S3 closing a failed scan leaves "Scan did not complete · View last status"; Scan is available again', /Scan did not complete · View last status/.test(await E(pg, `document.getElementById('ot-scan-chip').innerText`)) && !(await E(pg, `document.getElementById('ot-scan').disabled`)));
    await shot(pg, 's3_failed_chip_dark_1000');
    await cleanup(pg);
  } finally { await pg.close(); }

  // ---------------------------------------------------------------- S4: stale status (status reads fail), minimized, then recovery
  pg = await fresh(svc, 1280, 800);
  try {
    await startRunning(pg);
    await E(pg, `(()=>{window.__realFetch=window.fetch;window.fetch=(u,...a)=>String(u).includes('/api/scan/status')?Promise.reject(new TypeError('blocked by test')):window.__realFetch(u,...a);})()`);
    await pg.waitFor(`document.querySelector('#ot-scan-dialog #ot-scan-stale')`, 30000);
    const t = await E(pg, `document.getElementById('ot-scan-dialog-body').innerText`);
    check('S4 stale: last report kept, "Status updates stopped", no activity animation, no Cancel, Check again and End session present', /Status updates stopped/.test(t) && /Current status unknown/.test(t) && /Check again/.test(t) && !(await E(pg, `!!document.querySelector('#ot-scan-dialog .ot-scan-indeterminate')`)) && !(await E(pg, `!!document.getElementById('ot-scan-cancel')`)) && (await E(pg, `!!document.getElementById('ot-scan-recheck') && !!document.getElementById('ot-scan-dialog-end')`)) && !/was stopped|has stopped running|job stopped/i.test(t), t.replace(/\n+/g, ' ').slice(0, 200));
    await shot(pg, 's4_stale_light');
    await pg.click('#ot-scan-minimize'); await pg.waitFor(`document.getElementById('ot-scan-chip')`, 2000);
    check('S4 minimized chip says status updates stopped (not "running")', /Status updates stopped · View last status/.test(await E(pg, `document.getElementById('ot-scan-chip').innerText`)));
    await E(pg, `window.fetch=window.__realFetch`);
    await pg.click('#ot-scan-chip'); await pg.waitFor(`document.getElementById('ot-scan-recheck')`, 2000);
    await pg.click('#ot-scan-recheck');
    await pg.waitFor(`window.__otStore.get().destination==='workbench'`, 40000);
    check('S4 Check again resumes the SAME job and the success hand-off closes the dialog', !(await dlgOpen(pg)) && (await state(pg)).analysis.identity.mode === 'live');
    await cleanup(pg);
  } finally { await pg.close(); }

  // ---------------------------------------------------------------- S5: End session inside the modal while running; no late reopen
  pg = await fresh(svc, 1280, 800);
  try {
    await startRunning(pg);
    await pg.click('#ot-scan-dialog-end');
    await pg.waitFor(`document.getElementById('ot-ended-note')`, 45000);
    const s = await state(pg); const g = gets(pg, svc.origin);
    check('S5 End session inside the modal closes it and clears the job, status and URL', !(await dlgOpen(pg)) && s.scan.job === null && s.scan.status === null && s.scanUi.active === false && s.intake.url === '' && s.busy === null && !(await E(pg, `!!document.getElementById('ot-scan-chip')`)));
    await sleep(3600);
    check('S5 no late response reopens the dialog or restores data; no further status polls', !(await dlgOpen(pg)) && (await state(pg)).scan.job === null && gets(pg, svc.origin) === g, `gets ${g}->${gets(pg, svc.origin)}`);
    check('S5 focus lands on a usable homepage control', ['ot-url', 'ot-scan', 'ot-ended-note'].includes(await E(pg, `document.activeElement.id`)) || (await E(pg, `document.activeElement===document.body`)), await E(pg, `document.activeElement.id||document.activeElement.tagName`));
  } finally { await pg.close(); }

  // ---------------------------------------------------------------- S6: narrower desktop, short viewport, reduced motion, dark
  pg = await fresh(svc, 1000, 700, { dark: true });
  try {
    await startRunning(pg);
    await shot(pg, 's6_running_dark_1000');
    await pg.send('Emulation.setDeviceMetricsOverride', { width: 900, height: 360, deviceScaleFactor: 1, mobile: false });
    await sleep(300);
    const g = await E(pg, `(()=>{const d=document.getElementById('ot-scan-dialog');const r=d.getBoundingClientRect();const b=document.getElementById('ot-scan-dialog-body');return {top:r.top,bottom:r.bottom,h:innerHeight,scrolls:b.scrollHeight>b.clientHeight,foot:document.getElementById('ot-scan-minimize').getBoundingClientRect().bottom,pageScroll:document.documentElement.scrollWidth>innerWidth}})()`);
    check('S6 short viewport: the dialog stays inside the viewport, its body scrolls, the Minimize/End controls stay visible, no horizontal page scroll', g.top >= 0 && g.bottom <= g.h && g.scrolls && g.foot <= g.h && !g.pageScroll, JSON.stringify(g));
    await shot(pg, 's6_short_viewport_dark');
    await pg.send('Emulation.setDeviceMetricsOverride', { width: 1000, height: 700, deviceScaleFactor: 1, mobile: false });
    await pg.send('Emulation.setEmulatedMedia', { features: [{ name: 'prefers-reduced-motion', value: 'reduce' }] });
    await sleep(300);
    check('S6 reduced motion: the activity animation is off', await E(pg, `getComputedStyle(document.querySelector('#ot-scan-dialog .ot-scan-indeterminate')).animationName`) === 'none');
    await pg.send('Emulation.setEmulatedMedia', { features: [] });
    await pg.click('#ot-theme'); await pg.waitFor(`document.documentElement.dataset.theme==='light'`, 2000).catch(() => {});
    await shot(pg, 's6_running_light_1000');
    check('S6 the sample path stays separate: the dialog never shows sample evidence for the submitted repository', !/frigate/i.test(await E(pg, `document.getElementById('ot-scan-dialog-body').innerText`)) && !(await E(pg, `!!document.getElementById('nh-sample') && document.getElementById('ot-scan-dialog').contains(document.getElementById('nh-sample'))`)));
    await pg.key('Escape'); await sleep(200);
    await E(pg, `document.getElementById('ot-scan-dialog-end')`); await pg.click('#ot-scan-chip'); await pg.waitFor(`document.getElementById('ot-scan-dialog').open`, 2000);
    await pg.click('#ot-scan-dialog-end'); await pg.waitFor(`document.getElementById('ot-ended-note')`, 45000);
  } finally { await pg.close(); }
}

const svc = await service();
// Hard stop: the authorization is 20 minutes from first launch. Results are saved and both processes are stopped even if a step hangs.
const stopAll = async (why) => { try { check('watchdog/signal stop: ' + why, false); save({ passes: pass, stopped: why }); } catch {} try { await closeBrowser?.(); } catch {} try { svc.stop(); } catch {} process.exit(2); };
const watchdog = setTimeout(() => stopAll('19 minute limit'), 19 * 60 * 1000);
process.on('SIGINT', () => stopAll('SIGINT')); process.on('SIGTERM', () => stopAll('SIGTERM'));
({ browser, close: closeBrowser } = await launch({ headed: !HEADLESS }));
try {
  // A scenario exception is recorded as a failed check and never ends the processes, so a targeted correction pass can still run in them.
  const guarded = async () => { try { await runPass(svc); } catch (e) { check('pass aborted by an exception', false, e.stack || e.message); } save({ passes: pass }); const f = results.filter((r) => r.pass === pass && !r.ok); console.log(`\nPASS ${pass} DONE: ${results.filter((r) => r.pass === pass).length - f.length}/${results.filter((r) => r.pass === pass).length} (elapsed ${Math.round((Date.now() - T0) / 1000)} s)`); };
  await guarded();
  // wait for the owner of this run to request one targeted correction pass (same processes) or finish
  for (;;) {
    if (existsSync(join(OUT, 'done'))) break;
    if (existsSync(join(OUT, 'next'))) { rmSync(join(OUT, 'next')); await guarded(); }
    await sleep(500);
  }
} catch (e) { check('run completed without exception', false, e.stack || e.message); save({ passes: pass, exception: String(e.stack || e) }); }
finally { clearTimeout(watchdog); try { await closeBrowser(); } catch {} try { svc.stop(); } catch {} save({ passes: pass, finished: true }); }
process.exit(0);
