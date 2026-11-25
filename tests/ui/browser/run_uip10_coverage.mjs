// UIP-10 validation (test harness): real-browser checks of the BOM coverage states.
// Fixture cases run the REAL Workbench against local fixtures (tests/ui/browser/uip10_coverage_service.py; no network, Docker, real scanner or provider).
// The intended capability state is asserted from the live API BEFORE the UI is assessed. At most one service + one Chrome per case.
// Usage: PYTHON=<python with requirements-dev> node tests/ui/browser/run_uip10_coverage.mjs <case: partial|empty|unsupported|failed> <outDir> [--v3 <port> <cookieFile> <responseJson>]
import { spawn } from 'node:child_process';
import { appendFileSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { launch, newPage } from './cdp.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = resolve(HERE, '../../..');
const [CASE, OUTARG, ...rest] = process.argv.slice(2);
const OUT = resolve(OUTARG); mkdirSync(OUT, { recursive: true });
const V3 = rest[0] === '--v3' ? { port: rest[1], cookie: readFileSync(rest[2], 'utf8').trim(), response: JSON.parse(readFileSync(rest[3], 'utf8')).body } : null;
const PIDS = process.env.OT_PIDS_FILE;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const results = [];
const check = (id, ok, detail = '') => { results.push({ id, ok: !!ok, detail: String(detail).slice(0, 300) }); console.log(`${ok ? 'PASS' : 'FAIL'} ${id}${detail ? ' — ' + String(detail).slice(0, 220) : ''}`); };
const evidence = {};

function service() {
  const proc = spawn(process.env.PYTHON || 'python3', [join(HERE, 'uip10_coverage_service.py'), '--case', CASE, '--marker', process.env.OT_MARKER || ''], { cwd: REPO, env: { ...process.env, PYTHONPATH: `${REPO}:${join(REPO, 'src/core')}` }, stdio: ['ignore', 'pipe', 'pipe'] });
  if (PIDS) appendFileSync(PIDS, proc.pid + '\n');
  return new Promise((res, rej) => { let b = ''; const t = setTimeout(() => rej(new Error('service did not start: ' + b)), 40000);
    proc.stdout.on('data', (d) => { b += d; const m = b.match(/http:\/\/127\.0\.0\.1:(\d+)\//); if (m) { clearTimeout(t); res({ base: m[0], origin: new URL(m[0]).origin, stop: () => proc.kill('SIGTERM') }); } });
    proc.stderr.on('data', (d) => { b += d; }); });
}
const txt = (pg, sel) => pg.eval(`(document.querySelector(${JSON.stringify(sel)})?.innerText||'')`);
const exists = (pg, sel) => pg.eval(`!!document.querySelector(${JSON.stringify(sel)})`);
const state = (pg) => pg.eval('JSON.parse(JSON.stringify(window.__otStore.get()))');
const api = (pg, path) => pg.eval(`fetch(${JSON.stringify(path)}, { credentials: 'same-origin' }).then((r) => r.json())`);
const setUrl = async (pg, url) => { await pg.eval(`(()=>{const e=document.getElementById('ot-url');e.value='';e.dispatchEvent(new Event('input',{bubbles:true}))})()`); await pg.type('#ot-url', url); };
const narrow = (pg, on) => pg.send('Emulation.setDeviceMetricsOverride', on ? { width: 390, height: 844, deviceScaleFactor: 1, mobile: true } : { width: 1366, height: 900, deviceScaleFactor: 1, mobile: false });
const layout = (pg) => pg.eval(`(()=>{const n=document.querySelector('.ot-bom8-coverage'); const doc=document.documentElement; const base={hscroll:doc.scrollWidth>innerWidth+1,w:innerWidth}; if(!n) return {...base,present:false}; const r=n.getBoundingClientRect(); const nx=n.nextElementSibling?.getBoundingClientRect(); const pv=n.previousElementSibling?.getBoundingClientRect(); return {...base,present:true,clipX:r.left<-0.5||r.right>innerWidth+0.5,overNext:!!nx&&nx.top<r.bottom-1,overPrev:!!pv&&pv.bottom>r.top+1,textFits:n.scrollHeight<=n.clientHeight+1,height:Math.round(r.height)}})()`);
const caps = async (pg, extra = '') => { const g = (await state(pg)).analysis.generation; const p = await api(pg, `/api/workbench/v1/bom-candidates?schema_version=1&generation=${g}${extra}`); return { mode: p.mode, software: (p.capabilities || []).find((c) => c.family === 'software'), total: p.counts?.candidates_total, filtered: p.counts?.filtered_total }; };
const openBom = async (pg) => { await pg.click('#ot-tab-bom'); await pg.waitFor(`window.__otStore.get().bom8.queue`, 30000); await sleep(300); };
const view = async (pg, v) => { await pg.click(`[data-action=bom-view][data-view=${v}]`); await sleep(500); await pg.waitFor(`window.__otStore.get().bom8.queue && !window.__otStore.get().bom8.error`, 30000); };
const scan = async (pg, repo) => {
  await pg.waitFor(`document.getElementById('ot-scan') && !document.getElementById('ot-scan').disabled`, 20000);
  await setUrl(pg, 'https://github.com/acme/' + repo); await pg.click('#ot-scan');
  await pg.waitFor(`window.__otStore.get().destination === 'workbench' || window.__otStore.get().scan?.status?.job?.state === 'failed'`, 90000);
  evidence['scan_' + repo] = (await state(pg)).scan?.status?.job?.state;
};
// A not-compared analysis has no bound discovery assessment: the Full evidence graph request is refused and the queue may stay empty. Record what the page shows instead of waiting for a queue.
const viewTolerant = async (pg, v) => { await pg.click(`[data-action=bom-view][data-view=${v}]`); await sleep(1500); const b = (await state(pg)).bom8; evidence[`${CASE}_${v}_view`] = { queue: !!b.queue, error: b.error, text: (await txt(pg, '.ot-bom8')).replace(/\s+/g, ' ').slice(0, 400) }; };
const shot = (pg, name) => pg.screenshot(join(OUT, `${CASE}_${name}.png`));
const noticeAssertions = async (pg, label, expectPresent) => {
  const l = await layout(pg);
  check(`${label}: partial notice ${expectPresent ? 'present' : 'absent'}`, l.present === expectPresent, JSON.stringify(l));
  if (expectPresent) check(`${label}: notice not clipped, no overlap, no horizontal page scroll`, !l.clipX && !l.overNext && !l.overPrev && l.textFits && !l.hscroll, JSON.stringify(l));
  evidence[label] = l;
};

async function v3capture(pg) {
  // Completed presentation from the real V3 scan through the same live stack. The scan itself was submitted once by the driver; here the page gets the
  // same session cookie and the store receives the real analysis response (state hand-off); every BOM read afterwards is the app's own request to the live route.
  await narrow(pg, false);
  // Cookies are shared by host, not port: the fixture service's session cookie (same name, Path=/api) would be sent first and be refused. Clear it, then use the V3 session.
  await pg.send('Network.clearBrowserCookies');
  await pg.send('Network.setCookie', { name: V3.cookie.split('=')[0], value: V3.cookie.split('=').slice(1).join('='), url: `http://127.0.0.1:${V3.port}/` });
  await pg.goto(`http://127.0.0.1:${V3.port}/`);
  await pg.waitFor(`window.__otStore`, 15000);
  await pg.eval(`(()=>{const s=window.__otStore; s.dispatch({type:'ANALYSIS_START'}); const e=s.get().epoch; s.dispatch({type:'ANALYSIS_READY', epoch:e, analysis:${JSON.stringify(V3.response)}});})()`);
  await pg.waitFor(`document.querySelector('#ot-tab-bom')`, 15000);
  try { await openBom(pg); } catch (e) { evidence.v3_bom8_on_failure = (await state(pg)).bom8; evidence.v3_failed_requests = pg.log.failed; evidence.v3_responses = pg.log.responses.filter((r) => r.url.includes('/api/')).map((r) => [r.url.slice(0, 120), r.status]); await pg.screenshot(join(OUT, 'v3_capture_failure.png')); throw e; }
  const c3 = await caps(pg); evidence.v3_caps = c3;
  check('V3 completed: API state is software completed, discovery_compared, 0 candidates (54 declarations all represented)', c3.mode === 'discovery_compared' && c3.software.state === 'completed' && c3.total === 0, JSON.stringify(c3));
  await noticeAssertions(pg, 'V3 completed software view', false);
  evidence.v3_prompt = await txt(pg, '.ot-bom8 .ot-prompt');
  await view(pg, 'full'); await noticeAssertions(pg, 'V3 completed full view', false);
  await pg.screenshot(join(OUT, 'v3_completed_full_1366.png')); await view(pg, 'software'); await pg.screenshot(join(OUT, 'v3_completed_software_1366.png'));
  await narrow(pg, true); await sleep(600); await pg.screenshot(join(OUT, 'v3_completed_software_390.png'));
  evidence.v3_layout_390 = await layout(pg);
  check('V3 completed 390px: no horizontal page scroll', !(await layout(pg)).hscroll);
}

const { browser, close, proc } = await launch();
if (PIDS) appendFileSync(PIDS, proc.pid + '\n');
const svc = await service();
try {
  const pg = await newPage(browser, { width: 1366, height: 900 });
  await pg.goto(svc.base);
  if (CASE === 'partial') {
    await scan(pg, 'widget'); await openBom(pg);
    const c = await caps(pg); evidence.widget_caps = c;
    check('partial/populated: API state is software partial/partial_coverage, discovery_compared, 1 candidate', c.mode === 'discovery_compared' && c.software.state === 'partial' && c.software.reason_code === 'partial_coverage' && c.total === 1, JSON.stringify(c));
    for (const v of ['gaps', 'software', 'full']) { await view(pg, v); await noticeAssertions(pg, `partial/populated ${v} view`, true); if (v !== 'software') await shot(pg, `populated_${v}`); }
    await view(pg, 'software'); await shot(pg, 'populated_software');
    check('partial/populated: the candidate row is still listed beside the notice', (await exists(pg, '.ot-bom8-row')));
    await pg.click('[data-action=bom-filter][data-filter=represented]'); await sleep(600);
    check('partial/empty-by-filter: no rows (Represented filter) yet the notice stays', !(await exists(pg, '.ot-bom8-row')) && (await layout(pg)).present, JSON.stringify(await layout(pg)));
    await shot(pg, 'empty_by_filter');
    await pg.click('[data-action=bom-filter][data-filter=all]'); await sleep(400);
    await pg.eval(`(()=>{const e=document.getElementById('ot-bom8-q');e.value='zzzz-no-match';e.dispatchEvent(new Event('input',{bubbles:true}))})()`); await sleep(900);
    check('partial/empty-by-search: no rows and the notice stays', !(await exists(pg, '.ot-bom8-row')) && (await layout(pg)).present, JSON.stringify(await layout(pg)));
    await pg.eval(`(()=>{const e=document.getElementById('ot-bom8-q');e.value='';e.dispatchEvent(new Event('input',{bubbles:true}))})()`); await sleep(700);
    await narrow(pg, true); await sleep(600); await view(pg, 'software'); await noticeAssertions(pg, 'partial/populated software 390px', true); await shot(pg, 'populated_software_390');
    await view(pg, 'full'); await noticeAssertions(pg, 'partial/populated full 390px', true); await shot(pg, 'populated_full_390');
    await narrow(pg, false); await sleep(400);
    // ---- partial with ZERO candidates (second fixture repository, same service)
    await pg.click('#ot-top-end'); await pg.waitFor(`document.getElementById('ot-ended-note')`, 20000);
    await scan(pg, 'gadget'); await openBom(pg);
    const z = await caps(pg); evidence.gadget_caps = z;
    check('partial/zero-candidates: API state is partial/partial_coverage, discovery_compared, 0 candidates', z.mode === 'discovery_compared' && z.software.state === 'partial' && z.total === 0, JSON.stringify(z));
    for (const v of ['software', 'gaps', 'full']) { await view(pg, v); await noticeAssertions(pg, `partial/zero ${v} view`, true); }
    await view(pg, 'software'); await shot(pg, 'zero_software');
    const prompt = await txt(pg, '.ot-bom8 .ot-prompt'); evidence.zero_prompt = prompt;
    await narrow(pg, true); await sleep(600); await noticeAssertions(pg, 'partial/zero software 390px', true); await shot(pg, 'zero_software_390'); await narrow(pg, false);
  } else {
    await scan(pg, ({ empty: 'plain', unsupported: 'nodeonly', failed: 'widget' })[CASE]); await openBom(pg);
    const c = await caps(pg); evidence.caps = c;
    const want = { empty: ['completed_empty', 'discovery_compared'], unsupported: ['unsupported', 'not_compared'], failed: ['failed', 'not_compared'] }[CASE];
    check(`${CASE}: API state is software ${want[0]} on a ${want[1]} page`, c.software.state === want[0] && c.mode === want[1], JSON.stringify(c));
    await viewTolerant(pg, 'software'); await noticeAssertions(pg, `${CASE} software view`, false);
    const prompt = await txt(pg, '.ot-bom8 .ot-prompt'); evidence.prompt = prompt;
    check(`${CASE}: the page states its situation in words`, CASE === 'empty' ? /completed with no candidates/.test(prompt) : /Not compared/.test(prompt), prompt.slice(0, 200));
    if (CASE === 'failed') check('failed: no raw exception text or absolute path in the page', !/injected|PermissionError|\/tmp\/|\/private\//.test(await txt(pg, '.ot-bom8')), '');
    await shot(pg, 'software_1366');
    await narrow(pg, true); await sleep(600); await noticeAssertions(pg, `${CASE} 390px`, false); await shot(pg, 'software_390'); await narrow(pg, false); await sleep(400);
    for (const v of ['gaps', 'full']) { await viewTolerant(pg, v); await noticeAssertions(pg, `${CASE} ${v} view`, false); await shot(pg, `${v}_view`); }
    if (CASE === 'failed' && V3) { try { await v3capture(pg); } catch (e) { check('V3 completed capture finished', false, e.message); } }
  }
  check(`${CASE}: no page errors`, pg.log.exceptions.length === 0, pg.log.exceptions.join('|'));
} catch (e) { check(`${CASE}: run completed`, false, e.stack || e.message); }
finally { svc.stop(); await close(); }
writeFileSync(join(OUT, `${CASE}_results.json`), JSON.stringify({ case: CASE, results, evidence }, null, 1));
const failed = results.filter((r) => !r.ok).length;
console.log(`${results.length - failed}/${results.length} checks passed`);
process.exit(failed ? 1 : 0);
