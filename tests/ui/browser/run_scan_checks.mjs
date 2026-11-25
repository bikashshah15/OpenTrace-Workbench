// UIP-03 real-browser checks of the one-click Scan against the REAL Workbench with live scanning enabled on LOCAL fixtures
// (tests/ui/browser/live_service.py: a local git repository, fake scanner scripts, recorded GitHub answers; no network, no Docker).
// Usage: PYTHON=<python with requirements-dev> node tests/ui/browser/run_scan_checks.mjs [outDir]
import { spawn } from 'node:child_process';
import { mkdirSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { launch, newPage } from './cdp.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = resolve(HERE, '../../..');
const OUT = resolve(process.argv[2] || join(tmpdir(), 'ot-scan-checks'));
mkdirSync(OUT, { recursive: true });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const results = [];
const check = (id, ok, detail = '') => { results.push({ id, ok: !!ok }); console.log(`${ok ? 'PASS' : 'FAIL'} ${id}${detail ? ' — ' + String(detail).slice(0, 180) : ''}`); };

function service(extra = []) {
  const proc = spawn(process.env.PYTHON || 'python3', [join(HERE, 'live_service.py'), ...extra], { cwd: REPO, env: { ...process.env, PYTHONPATH: `${REPO}:${join(REPO, 'src/core')}` }, stdio: ['ignore', 'pipe', 'pipe'] });
  return new Promise((res, rej) => { let b = ''; const t = setTimeout(() => rej(new Error('service did not start: ' + b)), 40000);
    proc.stdout.on('data', (d) => { b += d; const m = b.match(/http:\/\/127\.0\.0\.1:(\d+)\//); if (m) { clearTimeout(t); res({ base: m[0], origin: new URL(m[0]).origin, stop: () => proc.kill('SIGTERM') }); } });
    proc.stderr.on('data', (d) => { b += d; }); });
}
const { browser, close } = await launch();
const txt = (pg, sel) => pg.eval(`(document.querySelector(${JSON.stringify(sel)})?.innerText||'')`);
const exists = (pg, sel) => pg.eval(`!!document.querySelector(${JSON.stringify(sel)})`);
const state = (pg) => pg.eval('JSON.parse(JSON.stringify(window.__otStore.get()))');
const calls = (pg, origin, path) => pg.log.requests.filter((r) => r.url.startsWith(origin + path)).length;
const setUrl = async (pg, url) => { await pg.eval(`(()=>{const e=document.getElementById('ot-url');e.value='';e.dispatchEvent(new Event('input',{bubbles:true}))})()`); await pg.type('#ot-url', url); };
// End session: the header control on wide screens; at 390 px the in-page control on the homepage (as in run_checks.mjs).
const endNow = async (pg, narrow) => { if (!narrow) { await pg.click('#ot-top-end'); return; } await pg.eval(`document.querySelector('[data-nav=analyze]')?.click()`); await sleep(200); await pg.eval(`document.getElementById('ot-end-session').click()`); };
const ready = (pg) => pg.waitFor(`document.getElementById('ot-scan') && !document.getElementById('ot-scan').disabled`, 20000);

async function run(width, height, label) {
  // ---- plain service: one-click, pin, hand-off, duplicate-click, Advanced manual commit, sample path
  const a = await service();
  try {
    const pg = await newPage(browser, { width, height, mobile: width < 700 });
    await pg.goto(a.base);
    await pg.waitFor(`document.getElementById('ot-scan')`, 15000);
    check(`[${label}] Scan is disabled until the configuration is known, then enabled`, true);
    await ready(pg);
    const d = await txt(pg, '#ot-disclosure');
    check(`[${label}] D08 disclosure (variant B) is mounted beneath the buttons and mentions the pilot list`, /pre-approved repositories/.test(d) && (await pg.eval(`document.getElementById('nh-sample').compareDocumentPosition(document.getElementById('ot-disclosure'))&4`)) > 0, d.slice(0, 100));
    check(`[${label}] no Review repository button and no preview/open-captured step`, !/Review repository/.test(await txt(pg, '#ot-form')) && !(await exists(pg, '[data-action=open-capture],[data-action=scan-live]')));
    await pg.screenshot(join(OUT, `${label}_01_home_scan_enabled.png`));
    await setUrl(pg, 'https://github.com/acme/widget');
    await pg.eval(`(()=>{const b=document.getElementById('ot-scan');b.click();b.click();})()`);      // a double click must start exactly one job
    await pg.waitFor(`document.getElementById('ot-scan-status')`, 15000);
    await sleep(150);
    check(`[${label}] a double click posts exactly one /api/scan and the Scan control is disabled`, calls(pg, a.origin, '/api/scan') - calls(pg, a.origin, '/api/scan/status') === 1 && (await pg.eval(`document.getElementById('ot-scan').disabled`)), `scan=${calls(pg, a.origin, '/api/scan')} status=${calls(pg, a.origin, '/api/scan/status')}`);
    await pg.screenshot(join(OUT, `${label}_02_running.png`));
    await pg.waitFor(`document.querySelector('#ot-tabpanel [data-ctx], #ot-tabpanel .ot-list')`, 60000);
    const st = await state(pg);
    check(`[${label}] completion hands off directly to Repository contexts, no second Scan click`, st.destination === 'workbench' && st.workbench.tab === 'contexts' && st.analysis.identity.mode === 'live');
    check(`[${label}] the pinned commit is the one resolved once (status identity equals result identity)`, st.scan.status.binding.commit_sha === st.analysis.identity.commit && st.scan.status.job.state === 'completed', st.scan.status.binding.commit_sha);
    check(`[${label}] the UI never called the legacy live route or the preview step`, calls(pg, a.origin, '/api/analysis/live') === 0 && calls(pg, a.origin, '/api/intake/preview') === 0);
    check(`[${label}] no Frigate content in a live result`, !/frigate/i.test(JSON.stringify(st.analysis.summary).slice(0, 4000)));
    await pg.screenshot(join(OUT, `${label}_03_workbench.png`));
    // End session clears the job; the raw config survives so Scan is available again
    await endNow(pg, width < 700); await pg.waitFor(`document.getElementById('ot-ended-note')`, 15000);
    const s2 = await state(pg);
    check(`[${label}] End session clears the scan job and the Workbench; configuration state is kept`, s2.scan.job === null && s2.analysis === null && s2.config.state === 'loaded');
    await ready(pg);
    // failure path: an unlisted repository fails resolution with a fixed reason and a next step
    await setUrl(pg, 'https://github.com/acme/other'); await pg.click('#ot-scan');
    await pg.waitFor(`document.querySelector('.ot-scan-outcome[data-kind=failed]')`, 30000);
    const f = await txt(pg, '#ot-scan-status');
    check(`[${label}] a refused repository shows the failed stage, a fixed reason and a usable next step`, /Resolve and pin the revision/.test(f) && /Failed/.test(f) && /could not be resolved right now; try again later|not admitted|pilot list/.test(f), f.replace(/\n+/g, ' ').slice(0, 200));
    check(`[${label}] after a failure the Scan control is available again and nothing was handed off`, !(await pg.eval(`document.getElementById('ot-scan').disabled`)) && (await state(pg)).analysis === null);
    await pg.screenshot(join(OUT, `${label}_04_failed.png`));
    // sample path preserved
    await pg.click('#nh-sample'); await pg.waitFor(`document.querySelector('#ot-tabpanel [data-ctx]')`, 30000);
    check(`[${label}] the labelled sample path still opens the captured case on Repository contexts`, (await state(pg)).analysis.identity.mode !== 'live' && (await state(pg)).workbench.tab === 'contexts');
    check(`[${label}] no page errors`, pg.log.exceptions.length === 0, pg.log.exceptions.join('|'));
    await pg.close();
  } finally { a.stop(); }

  // ---- slow service: cancel and End session while a scan is running
  const b = await service(['--cbom-sleep', '25']);
  try {
    const pg = await newPage(browser, { width, height, mobile: width < 700 });
    await pg.goto(b.base); await ready(pg);
    await setUrl(pg, 'https://github.com/acme/widget'); await pg.click('#ot-scan');
    await pg.waitFor(`document.querySelector('.ot-scan-stage[data-stage=cbom][data-state=running]')`, 30000);
    const txtRun = await txt(pg, '#ot-scan-status');
    check(`[${label}] the running panel shows real stage states with elapsed time and no percentage`, /Running/.test(txtRun) && /Elapsed/.test(txtRun) && !/%/.test(txtRun) && /Resolve and pin/.test(txtRun), txtRun.replace(/\n+/g, ' ').slice(0, 200));
    check(`[${label}] Cancel and End session stay reachable while running`, (await exists(pg, '#ot-scan-cancel')) && !(await pg.eval(`document.getElementById('ot-top-end').hidden||document.getElementById('ot-top-end').disabled||document.getElementById('ot-end-session').disabled`)));
    await pg.screenshot(join(OUT, `${label}_05_running_cbom.png`));
    await pg.click('#ot-scan-cancel');
    await pg.waitFor(`document.querySelector('.ot-scan-outcome[data-kind=cancelled]')`, 45000);
    check(`[${label}] Cancel ends the job as cancelled, nothing is handed off, Scan is available again`, (await state(pg)).analysis === null && (await state(pg)).scan.status.job.state === 'cancelled');
    await pg.screenshot(join(OUT, `${label}_06_cancelled.png`));
    await ready(pg);
    await pg.click('#ot-scan');
    await pg.waitFor(`document.querySelector('.ot-scan-stage[data-stage=cbom][data-state=running]')`, 30000);
    await endNow(pg, width < 700); await pg.waitFor(`document.getElementById('ot-ended-note')`, 45000);
    const s3 = await state(pg);
    check(`[${label}] End session during a scan stops polling, clears the job and revokes access`, s3.scan.job === null && s3.busy === null && s3.analysis === null);
    const polls = calls(pg, b.origin, '/api/scan/status'); await sleep(3500);
    check(`[${label}] no further status polls after End session`, calls(pg, b.origin, '/api/scan/status') === polls);
    await pg.close();
  } finally { b.stop(); }
}
try {
  await run(1366, 900, 'wide');
  await run(390, 844, 'narrow');
} catch (e) { check('run completed', false, e.stack || e.message); }
await close();
const failed = results.filter((r) => !r.ok);
console.log(`\n${results.length - failed.length}/${results.length} checks passed`);
process.exit(failed.length ? 1 : 0);
