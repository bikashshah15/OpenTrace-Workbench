// RT-01 correction: real-browser (headless Chrome via CDP) checks of the live advisory lookup through the REAL app path -- one-click scan job,
// Dependencies tab, lookup panel, filter, per-package evidence, End session -- against tests/ui/browser/advisory_service.py
// (local git fixture, fake scanners, real Evidence Specialist B, RECORDED OSV answers; no network, no Docker, no credentials).
// Usage: PYTHON=<python with requirements-dev + Go on PATH> node tests/ui/browser/run_advisory_checks.mjs [outDir]
import { spawn } from 'node:child_process';
import { mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { launch, newPage } from './cdp.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = resolve(HERE, '../../..');
const OUT = resolve(process.argv[2] || join(tmpdir(), 'ot-advisory-checks'));
mkdirSync(OUT, { recursive: true });
let failed = 0;
const check = (id, ok, detail = '') => { if (!ok) failed++; console.log(`${ok ? 'PASS' : 'FAIL'} ${id}${detail ? ' — ' + String(detail).slice(0, 200) : ''}`); };

function service(mode) {
  const proc = spawn(process.env.PYTHON || 'python3', [join(HERE, 'advisory_service.py'), '--mode', mode], { cwd: REPO,
    env: { ...process.env, PYTHONPATH: `${REPO}:${join(REPO, 'src/core')}:${join(REPO, 'src/agents/investigator')}` }, stdio: ['ignore', 'pipe', 'pipe'] });
  return new Promise((res, rej) => { let b = ''; const t = setTimeout(() => rej(new Error('service did not start: ' + b)), 60000);
    proc.stdout.on('data', (d) => { b += d; const m = b.match(/http:\/\/127\.0\.0\.1:(\d+)\//); if (m) { clearTimeout(t); res({ base: m[0], stop: () => proc.kill('SIGTERM') }); } });
    proc.stderr.on('data', (d) => { b += d; }); });
}
const { browser, close } = await launch();
const txt = (pg, sel) => pg.eval(`(document.querySelector(${JSON.stringify(sel)})?.innerText||'')`);
// DOM-dispatched click: goes through the app's real delegated handlers but cannot miss when the layout shifts between scroll and press.
const domClick = (pg, sel) => pg.eval(`(()=>{const e=document.querySelector(${JSON.stringify(sel)}); if(!e) throw new Error('no element '+${JSON.stringify(sel)}); e.click(); return true;})()`);
const state = (pg) => pg.eval('JSON.parse(JSON.stringify(window.__otStore.get()))');

async function scanAndOpenDependencies(pg, base) {
  await pg.goto(base);
  await pg.waitFor(`document.getElementById('ot-scan') && !document.getElementById('ot-scan').disabled`, 20000);
  await pg.eval(`(()=>{const e=document.getElementById('ot-url');e.value='';e.dispatchEvent(new Event('input',{bubbles:true}))})()`);
  await pg.type('#ot-url', 'https://github.com/acme/widget/tree/v1');
  await pg.click('#ot-scan');
  await pg.waitFor(`window.__otStore.get().analysis?.identity?.mode === 'live'`, 90000);
  await pg.waitFor(`document.getElementById('ot-tab-dependencies')`, 15000);
  await pg.click('#ot-tab-dependencies');
}

try {
  // ---- RT-01: zero joined packages, no dependency context
  const z = await service('zero');
  try {
    const pg = await newPage(browser, { width: 1440, height: 900 });
    await scanAndOpenDependencies(pg, z.base);
    await pg.waitFor(`document.querySelector('#ot-adv-lookup .ot-lookup-row')`, 20000);
    const s0 = await state(pg);
    check('[zero] no dependency context exists and the legacy dependency view never loaded (nothing invented)', s0.workbench.perTab.dependencies.ctxId === null && !s0.views.dependencies);
    check('[zero] the headline stays SBOM-linked (0) and names the lockfile-only match', /0\s*advisory groups matched/.test(await txt(pg, '#ot2-enrichment')) && /lockfile-only package/.test(await txt(pg, '#ot2-enrichment')), await txt(pg, '#ot2-enrichment'));
    check('[zero] the context chooser does not read "Loading source contexts…" forever', !/Loading source contexts/.test(await txt(pg, '#ot-workbench')) && /No source contexts in this analysis/.test(await txt(pg, '#ot-workbench')));
    const panel = await txt(pg, '#ot-adv-lookup');
    check('[zero] the lookup panel shows the repository-wide scope, completion limits and exploitability language', /Repository-wide/.test(panel) && /does not mean the SBOM lists every package/.test(panel) && /Reachability and exploitability are not established/.test(panel));
    check('[zero] the lockfile-only note is shown', /1 lockfile-only package with advisory matches/.test(panel));
    await pg.screenshot(join(OUT, 'zero_01_panel.png'));
    await domClick(pg, '[data-action=lookup-state][data-state=match]');
    await pg.waitFor(`document.querySelectorAll('#ot-adv-lookup .ot-lookup-row').length === 1 && /minimatch/.test(document.querySelector('#ot-adv-lookup .ot-lookup-row').textContent)`, 15000);
    check('[zero] the Advisory match filter leaves exactly the lockfile-only minimatch row, labelled "Lockfile only"', /Lockfile only/i.test(await txt(pg, '#ot-adv-lookup .ot-lookup-row')));
    await domClick(pg, '[data-action=lookup-evidence]');
    await pg.waitFor(`document.getElementById('ot-dialog').open && /Query sent/.test(document.getElementById('ot-dialog-content').textContent)`, 15000);
    const ev = await txt(pg, '#ot-dialog-content');
    check('[zero] per-package evidence opens: the query, the recorded answer, lockfile origin, no SBOM component attributed', /minimatch/.test(ev) && /Lockfile:/.test(ev) && !/SBOM: /.test(ev) && /not attached to an SBOM component/.test(ev) && /Not established/.test(ev), ev.slice(0, 160));
    await pg.screenshot(join(OUT, 'zero_02_evidence.png'));
    await pg.eval(`document.getElementById('ot-dialog').close()`);
    await pg.click('#ot-top-end');
    await pg.waitFor(`document.getElementById('ot-ended-note')`, 15000);
    const se = await state(pg);
    check('[zero] End session clears the lookup results and the panel', se.advLookup.data === null && !(await pg.eval(`!!document.getElementById('ot-adv-lookup')`)) && se.analysis === null);
    await pg.screenshot(join(OUT, 'zero_03_ended.png'));
  } finally { z.stop(); }

  // ---- normal joined case
  const j = await service('joined');
  try {
    const pg = await newPage(browser, { width: 1440, height: 900 });
    await scanAndOpenDependencies(pg, j.base);
    await pg.waitFor(`document.querySelector('#ot-adv-lookup .ot-lookup-row')`, 20000);
    check('[joined] the headline counts the SBOM-linked group and does not add lockfile-only rows', /1\s*advisory groups matched/.test(await txt(pg, '#ot2-enrichment')), await txt(pg, '#ot2-enrichment'));
    await domClick(pg, '[data-action=lookup-state][data-state=match]');
    await pg.waitFor(`document.querySelectorAll('#ot-adv-lookup .ot-lookup-row').length === 1`, 15000);
    check('[joined] the match row is SBOM-linked ("In SBOM and lockfile")', /In SBOM and lockfile/i.test(await txt(pg, '#ot-adv-lookup .ot-lookup-row')));
    await domClick(pg, '[data-action=lookup-evidence]');
    await pg.waitFor(`document.getElementById('ot-dialog').open && /Query sent/.test(document.getElementById('ot-dialog-content').textContent)`, 15000);
    const ev = await txt(pg, '#ot-dialog-content');
    check('[joined] evidence shows the SBOM component and the match basis', /SBOM: /.test(ev) && /equal in the SBOM component and the lockfile inventory row/.test(ev), ev.slice(0, 160));
    await pg.screenshot(join(OUT, 'joined_01_evidence.png'));
    await pg.eval(`document.getElementById('ot-dialog').close()`);
    await pg.click('#ot-top-end');
    await pg.waitFor(`document.getElementById('ot-ended-note')`, 15000);
    check('[joined] End session clears the lookup results', (await state(pg)).advLookup.data === null);
  } finally { j.stop(); }
} finally { await close(); }
console.log(failed ? `${failed} check(s) FAILED` : 'all checks passed');
process.exit(failed ? 1 : 0);
