// Stage 4 desktop acceptance driver (test harness only; no product behaviour; existing harnesses and product source untouched).
//
// One process, ONE headed hermetic Chrome (browser contexts isolate cases), services started one phase at a time and stopped at the end of the phase.
// Imports only reusable modules (cdp.mjs, uip13_graph_probe.mjs probe scripts, uip12_lib.mjs helpers); never imports a monolithic runner.
// Launch map and coverage: run_stage4_plan.mjs (checked offline by run_stage4_selftest.mjs). Offline checks do not establish runtime correctness.
//
//   node run_stage4_desktop.mjs --plan                    print the launch/coverage plan (no launch)
//   node run_stage4_desktop.mjs --selftest                parse in-page scripts + plan arithmetic (no launch; the real offline tests are run_stage4_selftest.mjs)
//   PYTHON=<py> node run_stage4_desktop.mjs run <label> [P1,P2,...]   EXECUTE (only after assistant integration + passing P0 + owner-authorized window)
//
// Row policy: never "matched" here. A failed observation => "not matched"; otherwise "not yet exercised (partial)". Every observation carries an evidence mode:
// real-server | fixture-substituted (frontend response from a contract JSON file; NOT backend evidence) | adapter-synthesized | ui-only.
import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { newPage, connect, CHROME } from './cdp.mjs';
import { ANALYZE, HOOK, SAMPLE, SUMMARY } from './uip13_graph_probe.mjs';
import { apiJson, endSession, settled, setUrl, inspectorContent } from './uip12_lib.mjs';
import { CEILINGS, createLedger, createDeadline, createSupervisor, createRecorder, sleep } from './run_stage4_lib.mjs';
import { loadFixture, analysisEnvelope, installRouting } from './run_stage4_fixtures.mjs';
import { UIP12_MATRIX, UIP13_MATRIX } from './run_stage4_cases.mjs';
import { DA_ROWS, LAUNCHES, PHASES, UNEXERCISED, COUNTS } from './run_stage4_plan.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = resolve(HERE, '../../..');
const LEDGER_FILE = join(REPO, 'evidence/uip/validation/stage4-desktop/allowance.json');
const DIAG_LEDGER_FILE = join(REPO, 'evidence/uip/validation/stage4-desktop/allowance_diagnostic.json');   // D-17
const CLOS_LEDGER_FILE = join(REPO, 'evidence/uip/validation/stage4-desktop/allowance_closure.json');       // consolidated closure run (1 service, 1 Chrome, 10 minutes)
const EXT2_LEDGER_FILE = join(REPO, 'evidence/uip/validation/stage4-desktop/allowance_extension2.json');     // closing extension 2: fixed path, never reset
const EXT_LEDGER_FILE = join(REPO, 'evidence/uip/validation/stage4-desktop/allowance_extension.json');       // closing extension: fixed path, never reset
const FINAL_LEDGER_FILE = join(REPO, 'evidence/uip/validation/stage4-desktop/allowance_final.json');     // closing campaign: fixed path, never reset by choosing another outDir
const CONF_LEDGER_FILE = join(REPO, 'evidence/uip/validation/stage4-desktop/allowance_confirmation.json'); // S4-FIX-01 confirmation (1 service, 1 Chrome, 10 minutes)   // fixed path: never reset by choosing another outDir
const SCRUB = /^(OPENAI|ANTHROPIC|CISCO|GITHUB|GH_|AWS_|AZURE|GOOGLE|HF_|HUGGING|OPENTRACE_LIVE_|OSV|.*API_KEY|.*_TOKEN|.*SECRET)/i;
const cleanEnv = () => Object.fromEntries(Object.entries(process.env).filter(([k]) => !SCRUB.test(k)));
const PYENV = () => ({ ...cleanEnv(), PYTHONPATH: `${REPO}:${join(REPO, 'src/core')}:${join(REPO, 'src/agents/investigator')}`, OPENTRACE_DEMO_REPLAY: '', OPENTRACE_LIVE_SCAN: '0', OPENTRACE_LIVE_ADVISORIES: '0', OPENTRACE_LIVE_AIBOM: '0' });

// ---------------------------------------------------------------- in-page scripts (parse-checked offline)
export const FOCUS = "(()=>new Promise((res)=>{let n=0;const t0=performance.now();const f=()=>{n++;if(performance.now()-t0>500)res({vs:document.visibilityState,focus:document.hasFocus(),raf500ms:n});else requestAnimationFrame(f)};requestAnimationFrame(f);setTimeout(()=>res({vs:document.visibilityState,focus:document.hasFocus(),raf500ms:n,timeout:true}),1500)}))()";
export const NO_ALERT = "(()=>{window.__alerted=0;window.alert=window.confirm=window.prompt=()=>{window.__alerted++;return false};})()";
export const CLIP = (svg, node) => `(()=>{const bad=[];for(const g of document.querySelectorAll(${JSON.stringify(svg + ' ' + node)})){const r=g.querySelector('rect');if(!r)continue;const x0=+r.getAttribute('x'),x1=x0+ +r.getAttribute('width');for(const t of g.querySelectorAll('text')){const b=t.getBBox();if(b.x<x0-1||b.x+b.width>x1+1)bad.push((t.textContent||'').slice(0,40))}}return bad})()`;
export const PILLS = "(()=>{const o={};document.querySelectorAll('[data-ot5-filter]').forEach((b)=>{const m=b.innerText.match(/(\\d[\\d,]*)/);o[b.dataset.ot5Filter]=m?+m[1].replace(/,/g,''):null});return o})()";
export const inPageScripts = { FOCUS, NO_ALERT, PILLS, CLIP1: CLIP('#ot4-svg', 'g[data-ctx]'), CLIP2: CLIP('#ot5-svg', 'g[data-dep-node]') };

if (process.argv[2] === '--plan') { console.log(JSON.stringify({ ceilings: CEILINGS, counts: COUNTS(), launches: LAUNCHES, phases: PHASES, unexercised: UNEXERCISED }, null, 1)); process.exit(0); }
if (process.argv[2] === '--selftest') {
  let e = null; for (const [n, s] of Object.entries({ ...inPageScripts, ANALYZE: ANALYZE('AAAA'), HOOK, SAMPLE, SUMMARY })) { try { new Function('return ' + s); } catch (x) { e = e || `${n}: ${x.message}`; } }
  const c = COUNTS(); if (c.service > CEILINGS.service || c.chrome > CEILINGS.chrome) e = e || 'plan exceeds ceilings';
  console.log(e ? 'SELFTEST FAIL ' + e : 'SELFTEST OK (parse + plan arithmetic only; nothing launched)'); process.exit(e ? 1 : 0);
}
if (process.argv[2] !== 'run' || !process.argv[3]) { console.error('usage: run <label> [P1,P2,...] [--rerun] | run <label> D1 --diagnostic'); process.exit(2); }
const CLOS = process.argv.includes('--closure');            // consolidated closure run: its own ledger, phase D3 only
const CONF = process.argv.includes('--confirmation');      // S4-FIX-01 confirmation allowance: its own ledger, phase D2 only
const EXT2 = process.argv.includes('--ext2');            // closing extension 2 (EXTENSION2_FROZEN_EXPECTATIONS.md): own ledger allowance_extension2.json (6 services / 2 Chrome / 45 min / 1 rerun); phases Y, YE, YN, YI
const EXT = process.argv.includes('--ext');              // closing extension (EXTENSION_FROZEN_EXPECTATIONS.md): own ledger allowance_extension.json (4 services / 2 Chrome / 45 min / 1 rerun); phases X, P7, X6
const FINAL = process.argv.includes('--final');          // closing campaign (FINAL_CAMPAIGN_FROZEN_EXPECTATIONS_v2.md): its own ledger allowance_final.json (8 services / 4 Chrome / 90 min / 1 rerun); phases F1 and P1..P6
const DIAG = process.argv.includes('--diagnostic');      // D-17: separate diagnostic allowance; its own ledger; never touches the historical ledger

// ================================================================= run setup
const LABEL = process.argv[3].replace(/[^\w.-]/g, '_');
const WANT = ((process.argv[4] && !process.argv[4].startsWith('--') ? process.argv[4] : (EXT2 ? 'Y' : EXT ? 'X' : FINAL ? 'F1' : DIAG ? 'D1' : CONF ? 'D2' : CLOS ? 'D3' : Object.keys(PHASES).join(','))).split(','));
const SPECIAL = DIAG ? 'D1' : CONF ? 'D2' : CLOS ? 'D3' : null;
if (CONF && !readFileSync(join(REPO, 'src/ui/lib/graph_lifecycle.js'), 'utf8').includes('export function fitHost')) { console.error(`refused: the product tree at ${REPO} does not contain the S4-FIX-01 fix (src/ui/lib/graph_lifecycle.js has no fitHost); the single confirmation launch must not be spent on the wrong tree`); process.exit(2); }
if ([DIAG, CONF, CLOS, FINAL, EXT, EXT2].filter(Boolean).length > 1) { console.error('--diagnostic, --confirmation, --closure, --final, --ext and --ext2 are mutually exclusive'); process.exit(2); }
if (EXT2 && !WANT.every((x) => ['Y', 'YE', 'YN', 'YI'].includes(x))) { console.error('--ext2 runs only Y, YE, YN and YI'); process.exit(2); }
if (!EXT2 && WANT.some((x) => ['Y', 'YE', 'YN', 'YI'].includes(x))) { console.error('Y, YE, YN and YI run only with --ext2'); process.exit(2); }
const STEPS_RAW = (process.argv.find((a) => a.startsWith('--steps=')) || '').slice(8).split(',').filter(Boolean);
if (STEPS_RAW.length && (!(EXT || EXT2) || STEPS_RAW.some((x) => !(EXT ? ['X1a', 'X1b', 'X1c', 'X1d', 'X2', 'X3r', 'X3', 'X4', 'X5'] : ['Y1', 'Y2', 'Y3', 'Y4']).includes(x)))) { console.error('--steps is valid only with --ext (X1a..X5) or --ext2 (Y1..Y4), exact case-sensitive names'); process.exit(2); }
if (EXT2 && process.argv.includes('--rerun') && WANT.length > 2) { console.error('--ext2 --rerun runs at most two single-service phases (the two reserved service slots)'); process.exit(2); }
if (EXT && process.argv.includes('--rerun') && WANT.length !== 1) { console.error('--ext --rerun runs exactly one single-service phase (X, P7 or X6)'); process.exit(2); }
if (EXT && !WANT.every((x) => ['X', 'P7', 'X6'].includes(x))) { console.error('--ext runs only X, P7 and X6'); process.exit(2); }
if (!EXT && (WANT.includes('X') || WANT.includes('X6'))) { console.error('X and X6 run only with --ext'); process.exit(2); }
if (FINAL && !WANT.every((x) => ['F1', 'P1', 'P2', 'P3', 'P4', 'P5', 'P6'].includes(x))) { console.error('--final runs only F1 and P1..P6 (P7/P8 and D1-D3 are not part of the closing campaign)'); process.exit(2); }
if (!FINAL && WANT.includes('F1')) { console.error('F1 runs only as `run <label> F1 --final`'); process.exit(2); }
if (FINAL && WANT.includes('F1') && WANT.length !== 1) { console.error('F1 runs alone (it owns its service and Chrome)'); process.exit(2); }
if (SPECIAL ? (WANT.length !== 1 || WANT[0] !== SPECIAL || process.argv.includes('--rerun')) : (WANT.includes('D1') || WANT.includes('D2') || WANT.includes('D3'))) { console.error('D1 runs only as `run <label> D1 --diagnostic`, D2 only as `run <label> D2 --confirmation`, D3 only as `run <label> D3 --closure` (no --rerun, nothing else with them)'); process.exit(2); }
if (CLOS) { const lc = readFileSync(join(REPO, 'src/ui/lib/graph_lifecycle.js'), 'utf8'); if (!lc.includes('export function fitHost') || !lc.includes('host._clearTimer = (id) => clearTimer(id)')) { console.error(`refused: the product tree at ${REPO} lacks the S4-FIX-01 fix including the unbound-timer correction; the single closure launch must not be spent on the wrong tree`); process.exit(2); } }
const OUT = resolve(REPO, 'evidence/uip/validation/stage4-desktop', LABEL);
if (existsSync(OUT) && readdirSync(OUT).length) { console.error(`refused: output directory ${OUT} already holds evidence (S4D-03: a label may not overwrite earlier results)`); process.exit(2); }
mkdirSync(OUT, { recursive: true });
const RERUN = process.argv.includes('--rerun');          // the ONLY way to open the reserved slots (S8 + C2): the single harness-correction rerun
const ledger = EXT2 ? createLedger({ file: EXT2_LEDGER_FILE, ceilings: Object.freeze({ service: 6, chrome: 2, minutes: 45, rerun: 1 }), planned: { service: 4, chrome: 1 } }) : EXT ? createLedger({ file: EXT_LEDGER_FILE, ceilings: Object.freeze({ service: 4, chrome: 2, minutes: 45, rerun: 1 }), planned: { service: 3, chrome: 1 } }) : FINAL ? createLedger({ file: FINAL_LEDGER_FILE, ceilings: Object.freeze({ service: 8, chrome: 4, minutes: 90, rerun: 1 }), planned: { service: 7, chrome: 3 } }) : CLOS ? createLedger({ file: CLOS_LEDGER_FILE, ceilings: Object.freeze({ service: 1, chrome: 1, minutes: 10, rerun: 0 }) }) : CONF ? createLedger({ file: CONF_LEDGER_FILE, ceilings: Object.freeze({ service: 1, chrome: 1, minutes: 10, rerun: 0 }) }) : DIAG ? createLedger({ file: DIAG_LEDGER_FILE, ceilings: Object.freeze({ service: 1, chrome: 1, minutes: 25, rerun: 0 }) }) : createLedger({ file: LEDGER_FILE, planned: { service: 7, chrome: 1 } });
console.log('allowance before launch:', JSON.stringify({ ...ledger.snapshot(), events: undefined }));
const sup = createSupervisor();
const rec = createRecorder(DA_ROWS);
const meta = { label: LABEL, sha: execFileSync('git', ['-C', REPO, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).trim(), srcDirty: execFileSync('git', ['-C', REPO, 'status', '--porcelain', '--', 'src', 'tests', 'tools'], { encoding: 'utf8' }).trim() !== '', started: new Date().toISOString(), phases: [] };
if ((FINAL || EXT || EXT2) && meta.srcDirty) { console.error('refused: the final campaign runs only on a clean src/tests/tools tree (the tested SHA must identify the product exactly); nothing launched'); process.exit(2); }
const EXPSHA = (process.argv.find((a) => a.startsWith('--expect-sha=')) || '').slice(13);
if ((FINAL || EXT || EXT2) && !(EXPSHA.length >= 12 && meta.sha.startsWith(EXPSHA))) { console.error(`refused: --final/--ext require --expect-sha=<sha of the reviewed candidate> equal to HEAD (HEAD ${meta.sha}); nothing launched`); process.exit(2); }
if (RERUN) ledger.markRerun(`harness-correction rerun of ${process.argv[3]} ${process.argv[4] || ''}`);   // only after every refusal above
const results = { meta, chromeFlags: null, removed: [], cleanup: [], stopped: null };
let deadline = null, finished = false, chrome = null;
const armDeadline = () => { if (deadline) return; const end = ledger.endAt(); if (end) deadline = createDeadline({ endAtMs: end, onExpire: () => finish(CLOS ? 'DEADLINE: 10-minute closure allowance expired' : CONF ? 'DEADLINE: 10-minute confirmation allowance expired' : DIAG ? 'DEADLINE: 25-minute diagnostic allowance expired' : (EXT ? 'DEADLINE: 45-minute extension allowance expired' : 'DEADLINE: 90-minute allowance expired'), 3) }).start(); };
const spend = (kind, note) => { ledger.spend(kind, note, { rerun: RERUN }); armDeadline(); };
const guard = () => { if (deadline?.expired) throw new Error('DEADLINE'); };

async function finish(reason, code = 0) {              // idempotent: preserves results, stops owned processes, removes dirs ONLY when their owners have exited
  if (finished) return; finished = true; deadline?.stop(); results.stopped = reason;
  try { chrome?.browser?.close(); } catch { /* ignore */ }
  rec.finalize();
  try { writeFileSync(join(OUT, 'stage4_desktop_results.partial.json'), JSON.stringify({ ...results, rows: rec.rows, note: 'written before cleanup (S4H3-03)' }, null, 1)); } catch { /* ignore */ }
  try { results.cleanup.push(...await sup.stopAll()); sup.stopTicker(); results.removed.push(...sup.removeDirs(results.cleanup)); } catch (e) { results.cleanupError = String(e && e.message || e); }
  const survivors = results.cleanup.filter((r) => r.survivors.length);
  Object.assign(results, { diag: typeof diag !== 'undefined' ? diag : null, confirmation: typeof confirm2 !== 'undefined' ? confirm2 : null, closure: typeof closure3 !== 'undefined' ? closure3 : null, final: typeof fin !== 'undefined' ? fin : null, ext: typeof ext !== 'undefined' ? ext : null, ext2: typeof ext2 !== 'undefined' ? ext2 : null, rows: rec.rows, hygiene: rec.hygiene, unexercised: UNEXERCISED, allowance: ledger.snapshot(), survivors: survivors.map((r) => ({ label: r.label, pids: r.survivors })), finished: new Date().toISOString() });
  writeFileSync(join(OUT, 'stage4_desktop_results.json'), JSON.stringify(results, null, 1));
  sup.detach(); setTimeout(() => process.exit(process.exitCode ?? 0), 1500).unref();
  console.log(survivors.length ? `SURVIVORS (state dirs preserved): ${JSON.stringify(survivors.map((r) => [r.label, r.survivors]))}` : 'no owned processes remain; owned dirs removed');
  if (code || survivors.length) process.exitCode = code || 4;
}

// ================================================================= launches (every launch is spent in the ledger BEFORE it happens)
const READY_URL = /http:\/\/127\.0\.0\.1:(\d+)\//;
async function startApp(label, root) {
  spend('service', label);
  const r = await sup.spawnOwned({ label, cmd: process.env.PYTHON || 'python3', args: ['-m', 'opentrace_core.app', '--port', '0', '--session-root', join(root, 's')], opts: { cwd: REPO, env: PYENV() }, ready: READY_URL, timeoutMs: 30000, dirs: [root] });
  return { entry: r.entry, base: r.match[0] };
}
async function startScript(label, script, args) {
  spend('service', label);
  const r = await sup.spawnOwned({ label, cmd: process.env.PYTHON || 'python3', args: [join(HERE, script), ...args], opts: { cwd: REPO, env: PYENV() }, ready: READY_URL, timeoutMs: 60000, dirs: [] });
  return { entry: r.entry, base: r.match[0] };
}
async function startChrome(label) {
  spend('chrome', label);
  const dir = mkdtempSync(join(tmpdir(), 'ot-stage4-chrome-'));
  const args = [`--user-data-dir=${dir}`, '--no-first-run', '--no-default-browser-check', '--remote-debugging-port=0', '--window-size=1366,900', '--window-position=40,40',
    '--disable-background-networking', '--disable-component-update', '--disable-sync', '--disable-default-apps', '--metrics-recording-only', '--no-pings',
    '--disable-backgrounding-occluded-windows', '--disable-renderer-backgrounding', '--disable-background-timer-throttling', '--disable-features=OptimizationHints,Translate,MediaRouter', '--host-resolver-rules=MAP * ~NOTFOUND , EXCLUDE 127.0.0.1', 'about:blank'];
  results.chromeFlags = args.map((a) => a.replace(dir, '<fresh-profile-dir>'));
  const r = await sup.spawnOwned({ label, cmd: CHROME, args, opts: {}, ready: /DevTools listening on (ws:\/\/\S+)/, timeoutMs: 25000, dirs: [dir], tokens: [dir] });
  const raw = await connect(r.match[1]);
  const TMO = 45000;   // S4H3-01: cdp.mjs never rejects on a dead socket; bound every CDP call so a crashed/hung Chrome fails the phase instead of consuming the 90-minute allowance
  const browser = { ...raw, send: (m, p, sid) => Promise.race([raw.send(m, p, sid), new Promise((_, rej) => setTimeout(() => rej(new Error(`CDP timeout ${TMO}ms: ${m}`)), TMO).unref())]) };
  return { browser, entry: r.entry };
}
const stopService = async (svc) => { const r = await sup.stopAll({ only: svc.entry, graceMs: 6000 }); results.removed.push(...sup.removeDirs(r)); results.cleanup.push(...r); return r; };
const withService = async (start, fn) => {
  let s; const before = sup.entries.length; try { s = await start(); } catch (e) { const ent = sup.entries.length > before ? sup.entries[before] : null; if (ent && !ent.stopped) { const r = await sup.stopAll({ only: ent, graceMs: 4000 }); results.cleanup.push(...r); results.removed.push(...sup.removeDirs(r)); } throw e; }   // a failed start is stopped now, not at the end of the run
  try { await fn(s.base); } finally { await stopService(s); }
};

// ================================================================= isolated cases (one browser context per case)
async function openCase(browser, { w = 1366, h = 900, theme = 'light', fixture = null, hook = false, noRouting = false } = {}) {
  const { browserContextId } = await browser.send('Target.createBrowserContext', { disposeOnDetach: true });
  const b2 = { send: (m, p, s) => browser.send(m, m === 'Target.createTarget' ? { ...p, browserContextId } : p, s), on: (fn) => browser.on(fn) };
  const pg = await newPage(b2, { width: w, height: h });
  const st = { fixture, envelope: fixture ? analysisEnvelope(fixture) : null, log: { served: [], blocked: [] } };
  browser.on((m) => { if (m.sessionId === pg.sessionId && m.method === 'Page.javascriptDialogOpening') pg.send('Page.handleJavaScriptDialog', { accept: false }).catch(() => {}); });
  if (!noRouting) await installRouting(pg, browser, st);   // noRouting (harness-only, extension 2): a case that installs its OWN Fetch interception must not share the page with the routing handler (double handling -> Invalid InterceptionId)
  await pg.send('Emulation.setEmulatedMedia', { features: [{ name: 'prefers-reduced-motion', value: 'reduce' }, { name: 'prefers-color-scheme', value: theme }] });
  await pg.send('Page.addScriptToEvaluateOnNewDocument', { source: NO_ALERT });
  if (hook) await pg.send('Page.addScriptToEvaluateOnNewDocument', { source: HOOK });
  await pg.send('Target.activateTarget', { targetId: pg.targetId }).catch(() => {}); await pg.send('Page.bringToFront').catch(() => {});
  return { pg, st, browser, dispose: async () => { try { await browser.send('Target.disposeBrowserContext', { browserContextId }); } catch { /* ignore */ } } };
}
const ev = (pg, e) => pg.eval(e);
const state = (pg) => ev(pg, 'JSON.parse(JSON.stringify(window.__otStore.get()))');
const txt = (pg, sel) => ev(pg, `(document.querySelector(${JSON.stringify(sel)})?.innerText||'')`);
const count = (pg, sel) => ev(pg, `document.querySelectorAll(${JSON.stringify(sel)}).length`);
const exists = (pg, sel) => ev(pg, `!!document.querySelector(${JSON.stringify(sel)})`);
const compOk = (r) => !!r && r.nonDominantShare > 0.03 && r.distinctColours > 20;      // same thresholds as run_uip13_graph_fix.mjs; the raw value is always recorded beside it
async function region(pg, name, sel) {                                                  // graph-host clip: a full page always has text, so only a region can show a blank graph
  const r = await ev(pg, `(()=>{const e=document.querySelector(${JSON.stringify(sel)});if(!e)return null;e.scrollIntoView({block:'center',behavior:'instant'});const b=e.getBoundingClientRect();return {x:Math.max(0,b.x+scrollX),y:Math.max(0,b.y+scrollY),width:Math.max(1,Math.min(b.width,1700)),height:Math.max(1,Math.min(b.height,1200))}})()`);
  if (!r) return { err: 'region missing: ' + sel };
  const { data } = await pg.send('Page.captureScreenshot', { format: 'png', clip: { ...r, scale: 1 }, captureBeyondViewport: true });
  writeFileSync(join(OUT, name.replace(/[^\w.-]+/g, '_') + '.png'), Buffer.from(data, 'base64'));
  return ev(pg, ANALYZE(data));
}
const settle = (pg, expr, ms = 30000) => pg.waitFor(expr, ms, expr.slice(0, 80));
const mapReady = (pg) => settle(pg, `document.querySelector('[data-map-ready="true"]')`);
const tab = async (pg, t) => { await ev(pg, `document.getElementById('ot-tab-${t}').click()`); await sleep(250); };
const gen = async (pg) => (await state(pg)).analysis.generation;
const O = (row, id, ok, detail, c) => { rec.obs(row, id, ok, detail, c); console.log(`${ok ? 'PASS' : 'FAIL'} ${row} ${id}${detail ? ' — ' + String(detail).slice(0, 140) : ''}`); };
const ctxOf = (mode, extra = {}) => ({ mode, sha: meta.sha, viewport: '1366x900', theme: 'light', ...extra });
const setViewport = (pg, w, h) => pg.send('Emulation.setDeviceMetricsOverride', { width: w, height: h, deviceScaleFactor: 1, mobile: false });
// REAL window resize: the device-metrics override that newPage() installs must be cleared first, otherwise innerWidth/layout stay at the override and the resize is only cosmetic.
const windowSize = async (c, pg, w, h) => { await pg.send('Emulation.clearDeviceMetricsOverride'); const { windowId } = await c.browser.send('Browser.getWindowForTarget', { targetId: pg.targetId }); await c.browser.send('Browser.setWindowBounds', { windowId, bounds: { windowState: 'normal', width: w, height: h } }); await pg.waitFor(`Math.abs(outerWidth-${w})<=2`, 8000).catch(() => {}); await sleep(400); return ev(pg, '({iw:innerWidth,ih:innerHeight,ow:outerWidth,oh:outerHeight})'); };
const hygiene = async (id, c) => rec.note(`${id}: no non-loopback request, no page exception, no alert fired`, c.st.log.blocked.length === 0 && c.pg.log.exceptions.length === 0 && (await ev(c.pg, 'window.__alerted||0')) === 0, JSON.stringify({ blocked: c.st.log.blocked.slice(0, 3), exceptions: c.pg.log.exceptions.slice(0, 2) }));

// ================================================================= P1: offline Demo, real server
async function P1(base) {
  const c = await openCase(chrome.browser, {}); const { pg } = c; const R = (extra) => ctxOf('real-server', { fixture: 'recorded Demo (offline service)', ...extra });
  await pg.goto(base); await pg.waitFor(`document.querySelector('#ot-demo')`, 20000);
  const f0 = await ev(pg, FOCUS);
  const home = await txt(pg, '#ot-analyze');
  O('DA-01', 'hero/section copy, form and sample action present; no fixed "Live analysis unavailable"', /Know what's inside\./i.test(home) && /Verify what you trust\./i.test(home) && /Three inventories\. One evidence trail\./i.test(home) && /A camera app's AI model/i.test(home) && (await exists(pg, '#ot-form #ot-url')) && (await exists(pg, '#nh-sample')) && !/Live analysis unavailable/.test(home), home.slice(0, 80).replace(/\n/g, ' '), R({ focus: f0 }));
  O('DA-01', 'header (About/Demo/End) and rail (Workbench/Evidence) intact; session status "No active session"; End disabled', (await exists(pg, '.topbar #ot-about')) && (await exists(pg, '.topbar #ot-demo')) && (await exists(pg, '.topbar #ot-top-end')) && (await exists(pg, 'nav.ot-rail [data-nav=workbench]')) && (await exists(pg, 'nav.ot-rail [data-nav=evidence]')) && /No active session/.test(await txt(pg, '#ot-session-status')) && (await ev(pg, "document.getElementById('ot-end-session').disabled")), '', R());
  O('DA-01', 'Scan control is labelled Scan (not "Preview review"/"Review repository"); the offline service states scanning is not enabled', !/Preview review|Review repository/.test(await txt(pg, '#ot-form')) && /Live scanning is not enabled/.test(await txt(pg, '#ot-disclosure')), (await txt(pg, '#ot-disclosure')).slice(0, 100), R());
  const t0 = (await state(pg)).theme; await ev(pg, "document.getElementById('ot-theme').click()"); await sleep(200); const t1 = (await state(pg)).theme;
  O('DA-15', 'theme toggle changes the stored theme', t0 !== t1, `${t0}->${t1}`, R()); if (t1 !== 'light') await ev(pg, "document.getElementById('ot-theme').click()");
  const csp = pg.log.responses.find((r) => r.url === base)?.headers || {}; const cspv = Object.entries(csp).find(([k]) => k.toLowerCase() === 'content-security-policy')?.[1] || '';
  O('DA-17', 'document is served with a Content-Security-Policy without unsafe-eval or a wildcard script source', !!cspv && !/unsafe-eval/.test(cspv) && !/script-src[^;]*\*/.test(cspv), cspv.slice(0, 140), R());
  await ev(pg, "document.getElementById('ot-demo').click()"); await mapReady(pg); await sleep(400);
  const st = await state(pg); const insp0 = await txt(pg, '.ot4-inspector');
  O('DA-04', 'opens on Repository contexts (selected tab) with four summary pills', st.workbench.tab === 'contexts' && (await ev(pg, "document.getElementById('ot-tab-contexts').getAttribute('aria-selected')")) === 'true' && (await count(pg, '#ot2-enrichment li')) === 4, `tab=${st.workbench.tab} pills=${await count(pg, '#ot2-enrichment li')}`, R());
  O('DA-04', 'each pill value is rendered (non-empty digits)', await ev(pg, "[...document.querySelectorAll('#ot2-enrichment li')].every((l)=>/\\d/.test(l.innerText))"), (await txt(pg, '#ot2-enrichment')).replace(/\n+/g, ' ').slice(0, 120), R());
  O('DA-14', 'root inspector asks the four fixed questions; says it is not a security assessment; Sources & coverage collapsed', ['What is this?', 'Why is it here?', 'Is there a security concern?', 'What remains unknown?'].every((q) => insp0.toLowerCase().includes(q.toLowerCase())) && /not a security assessment/i.test(insp0) && !(await ev(pg, "document.querySelector('.ot-insp-sources')?.open")), insp0.slice(0, 80).replace(/\n/g, ' '), R());
  const a1 = await ev(pg, "(()=>{const s=document.getElementById('ot4-stage');return s?{ready:s.dataset.mapReady,cards:+s.dataset.cardCount,groups:+s.dataset.groupCount}:null})()");
  const model = st.views.contexts;
  O('DA-05', 'map ready; group count equals the contexts/1 payload; no label clipped', !!a1 && a1.ready === 'true' && a1.cards > 0 && a1.groups === model.groups.length && (await ev(pg, inPageScripts.CLIP1)).length === 0, JSON.stringify(a1) + ' payloadGroups=' + model.groups.length, R());
  const v1 = await region(pg, 'p1_da05_contexts_1366_light', '#ot4-stage'); O('DA-05', 'contexts graph region painted (raw value recorded)', compOk(v1), JSON.stringify(v1), R());
  await tab(pg, 'dependencies'); await settle(pg, `document.querySelector('#ot5-svg [data-dep-node]')`); await tab(pg, 'contexts'); await mapReady(pg); await sleep(350);
  const a2 = await ev(pg, "(()=>{const s=document.getElementById('ot4-stage');return s?{cards:+s.dataset.cardCount,groups:+s.dataset.groupCount}:null})()");
  const v2 = await region(pg, 'p1_da05_contexts_after_switch', '#ot4-stage');
  O('DA-05', 'after switching away and back the map repaints with the same cards/groups and is painted', !!a2 && a2.cards === a1.cards && a2.groups === a1.groups && compOk(v2), JSON.stringify({ a2, v2 }), R());
  await setViewport(pg, 1100, 800); await sleep(500);
  const a3 = await ev(pg, "(()=>{const s=document.getElementById('ot4-stage');return s?{ready:s.dataset.mapReady,cards:+s.dataset.cardCount,overflow:document.documentElement.scrollWidth>innerWidth+1}:null})()");
  O('DA-05', 'after resize to 1100x800: still ready, same cards, no horizontal page scroll', !!a3 && a3.ready === 'true' && a3.cards === a1.cards && !a3.overflow, JSON.stringify(a3), R({ viewport: '1100x800' })); await setViewport(pg, 1366, 900);
  await tab(pg, 'dependencies'); await settle(pg, `document.querySelector('#ot5-svg [data-dep-node]')`); await sleep(300);
  const s6 = await state(pg); const page = s6.views.depPage; const total = page.page.matches_total;           // every expected number below is DERIVED from the bound payload
  O('DA-06', `pager text equals the payload range (${page.page.range_first}-${page.page.range_last} of ${total})`, (await txt(pg, '#ot5-page-count')) === `${page.page.range_first}–${page.page.range_last} of ${total}`, await txt(pg, '#ot5-page-count'), R({ fixture: 'recorded Demo; dataset identity ' + s6.analysis.identity.analysis_digest.slice(0, 19) }));
  const pills = await ev(pg, PILLS); const ft = page.filter_totals;
  const K2P = { gaps: 'evidence_gaps' };      // UI filter key -> payload name (FILTERS in lib/dependency_graph.js)
  O('DA-06', 'rendered pill counts equal the payload filter_totals; every drawn edge is a payload edge; drawn nodes equal payload nodes', Object.entries(pills).every(([k, v]) => v === null || v === ft[K2P[k] || k]) && (await count(pg, '#ot5-svg .ot5-edge')) === page.edges.length && (await count(pg, '#ot5-svg [data-dep-node]')) === page.nodes.length, JSON.stringify({ pills, ft, edges: [await count(pg, '#ot5-svg .ot5-edge'), page.edges.length], nodes: [await count(pg, '#ot5-svg [data-dep-node]'), page.nodes.length] }), R());
  const v3 = await region(pg, 'p1_da06_deps_1366_light', '#ot5-svg'); O('DA-06', 'dependency graph region painted (raw value recorded)', compOk(v3), JSON.stringify(v3), R());
  O('DA-06', 'no card label clipped; no horizontal page scroll', (await ev(pg, inPageScripts.CLIP2)).length === 0 && !(await ev(pg, 'document.documentElement.scrollWidth>innerWidth+1')), '', R());
  for (const [row, t, route] of [['DA-07', 'crypto', 'crypto-assets'], ['DA-08', 'ai', 'ai-assets']]) {
    await tab(pg, t); await sleep(700); const g = await gen(pg); const api = await apiJson(pg, `/api/workbench/v1/${route}?generation=${g}`); const panel = await txt(pg, '#ot-tabpanel');
    O(row, `${t} tab shows the server's availability message (not a generic or empty panel)`, api.status === 200 && !!api.body?.availability?.message && panel.includes(String(api.body.availability.message).slice(0, 40)), `${api.body?.availability?.state}: ${String(api.body?.availability?.message).slice(0, 80)}`, R());
    O(row, `${t} tab total shown equals the server's total`, api.status === 200 && (api.body?.filter_totals?.all === 0 || panel.includes(String(api.body?.filter_totals?.all))), `all=${api.body?.filter_totals?.all}`, R());
  }
  await tab(pg, 'bom'); await settle(pg, `window.__otStore.get().bom8.queue?.items?.length > 0`); await settle(pg, `document.querySelector('[data-bom-cy="inline"]')?._cy?.nodes().length > 0`); await sleep(400);
  const b0 = (await state(pg)).bom8; const g1 = await gen(pg); const q0 = await apiJson(pg, `/api/workbench/v1/bom-candidates?generation=${g1}&size=25`);
  O('DA-09', 'candidate total in the UI equals the server queue total (data-derived)', q0.status === 200 && b0.queue.counts.candidates_total === q0.body.counts.candidates_total, `${b0.queue.counts.candidates_total} vs ${q0.body?.counts?.candidates_total}`, R());
  const tabs = await ev(pg, "[...document.querySelectorAll('.ot-bom8-tabs button')].map((b)=>b.innerText.trim())");
  O('DA-10', 'BOM inner views are exactly five, in order, with Focused gaps initial', tabs.length === 5 && b0.view === 'gaps', JSON.stringify(tabs), R());
  const gi = await ev(pg, "(()=>{const h=document.querySelector('[data-bom-cy=\"inline\"]');return {nodes:h._cy.nodes().length,edges:h._cy.edges().length}})()");
  O('DA-10', 'inline graph is a live Cytoscape graph with nodes and edges', gi.nodes > 0 && gi.edges > 0, JSON.stringify(gi), R());
  const vb = await region(pg, 'p1_da10_bom_inline_1366', '[data-bom-cy="inline"]'); O('DA-10', 'BOM inline graph region painted (raw value recorded)', compOk(vb), JSON.stringify(vb), R());
  const gid = await ev(pg, 'window.__otStore.get().bom8.graph.nodes[0].node_id'); await ev(pg, `document.querySelector('[data-bom-cy="inline"]')._cy.getElementById(${JSON.stringify(gid)}).emit('tap');0`);
  await settle(pg, `window.__otStore.get().bom8.selectedRecord===${JSON.stringify(gid)} && window.__otStore.get().bom8.related?.subject.id===${JSON.stringify(gid)}`);
  O('DA-11', 'graph node selection selects exactly that record and requests its related checks (programmatic tap; real mouse clicks are in P8). Recorded after the preceding wait succeeded: that wait is the check', true, gid.slice(0, 60), R());
  if (await ev(pg, '!!window.__otStore.get().bom8.popup')) await pg.key('Escape');
  await ev(pg, `document.querySelectorAll('[data-action="bom-select"]')[1]?.click()`); await settle(pg, `window.__otStore.get().bom8.graph?.scope.candidate_id===window.__otStore.get().bom8.selected`);
  O('DA-10', 'queue selection synchronizes graph and inspector', await ev(pg, `!!document.querySelector('.ot-bom8-inspector h3') && window.__otStore.get().bom8.graph.scope.candidate_id===window.__otStore.get().bom8.selected`), '', R());
  const det = await ev(pg, "(document.querySelector('[data-evidence-for] .ot-gap-inspector')||document.querySelector('.ot-bom8-inspector'))?.innerText||''");
  O('DA-13', 'evidence inspector shows evidence text and a SHA-256 value for the selected check', det.length > 40 && /sha-?256/i.test(det), det.slice(0, 100).replace(/\n/g, ' '), R());
  await ev(pg, `document.querySelector('[data-action="bom-expand"]').click()`); await settle(pg, `document.querySelector('[data-bom-cy="popup"]')?._cy?.nodes().length > 0`); await pg.key('Escape'); await sleep(250);
  O('DA-11', 'Escape closes the expanded popup and restores focus to the control', await ev(pg, `!document.querySelector('.ot-bom8-overlay') && document.activeElement?.dataset.action==='bom-expand'`), '', R());
  await ev(pg, `document.querySelector('[data-action="bom-view"][data-view="full"]').click()`); await settle(pg, `window.__otStore.get().bom8.graph?.scope.kind==='full_view'`); await settle(pg, `document.querySelector('[data-bom-cy="inline"]')?._cy?.nodes().length > 0`);
  const fg = (await state(pg)).bom8.graph; O('DA-11', 'Full evidence graph window is bounded and states its range (primary_size and offset come from the payload)', !!fg.page && fg.page.primary_size > 0 && fg.page.offset === 0, JSON.stringify(fg.page).slice(0, 160), R());
  if (fg.page.has_more !== false) { await ev(pg, `document.querySelector('[data-action="bom-full-page"][data-dir="1"]')?.click()`); await settle(pg, `window.__otStore.get().bom8.graph?.page.offset===${fg.page.primary_size}`); O('DA-11', 'Next page moves the Full graph window by exactly primary_size (recorded after the preceding wait succeeded: that wait is the check)', true, 'offset=' + fg.page.primary_size, R()); }
  await tab(pg, 'contexts'); await ev(pg, "document.getElementById('ot-tab-contexts').focus()"); await pg.key('ArrowRight', 'ArrowRight'); await sleep(300);
  const right = (await ev(pg, "document.getElementById('ot-tab-dependencies').getAttribute('aria-selected')")) === 'true'; await pg.key('ArrowLeft', 'ArrowLeft'); await sleep(300);
  O('DA-15', 'ArrowRight on the focused tab selects the next tab; ArrowLeft returns', right && (await ev(pg, "document.getElementById('ot-tab-contexts').getAttribute('aria-selected')")) === 'true', '', R());
  await tab(pg, 'dependencies'); await settle(pg, `document.querySelector('#ot5-svg [data-dep-node]')`);
  O('DA-15', 'graph controls carry accessible names; at least one live status region exists', (await ev(pg, "[...document.querySelectorAll('[data-action=gfit],[data-action=dep-expand],[data-action=dep-page]')].every((e)=>(e.getAttribute('aria-label')||e.innerText||'').trim().length>0)")) && (await count(pg, '[aria-live],[role=status]')) > 0, '', R());
  await ev(pg, "document.querySelector('[data-dep-node]')?.focus()"); await sleep(200);
  O('DA-15', 'a focused dependency node has a visible focus indicator', await ev(pg, "(()=>{const e=document.activeElement;if(!e||e===document.body)return false;const c=getComputedStyle(e);return (c.outlineStyle!=='none'&&parseFloat(c.outlineWidth)>0)||c.boxShadow!=='none'||e.matches(':focus-visible')})()"), '', R());
  await setViewport(pg, 1600, 900); await sleep(600); await tab(pg, 'dependencies'); await settle(pg, `document.querySelector('#ot5-svg [data-dep-node]')`);
  const v4 = await region(pg, 'p1_da19_deps_1600', '#ot5-svg'); const f1 = await ev(pg, FOCUS);
  O('DA-19', `1600x900 dependencies graph region: raw ${JSON.stringify(v4)}; predicate (share>0.03 strict, colours>20)=${compOk(v4)}. A NEW measurement: it neither reproduces nor retires the retained PR #76 0.0300 (BOM inline graph under a real window resize; see P8)`, compOk(v4), JSON.stringify(v4), R({ viewport: '1600x900', focus: f1 }));
  O('DA-19', 'no horizontal page scroll and no clipped card label at 1600x900', !(await ev(pg, 'document.documentElement.scrollWidth>innerWidth+1')) && (await ev(pg, inPageScripts.CLIP2)).length === 0, '', R({ viewport: '1600x900' }));
  await setViewport(pg, 1366, 900); await pg.click('#ot-top-end'); await settle(pg, `document.getElementById('ot-ended-note')`, 30000);
  const se = await state(pg); O('DA-16', 'End session clears analysis, graph hosts and inspector content', se.analysis === null && (await count(pg, '[data-cy],[data-bom-cy],#ot4-stage,#ot5-svg')) === 0, `analysis=${se.analysis === null}`, R());
  await hygiene('P1', c); await c.dispose();
}

// ================================================================= P2: contract fixtures through the real frontend (fixture-substituted)
async function P2(base) {
  const F = (extra) => ctxOf('fixture-substituted', extra);
  const caseRun = async (name, select, fn) => {
    guard(); const fixture = loadFixture(name, undefined, select); const c = await openCase(chrome.browser, { fixture });
    const dig = Object.values(fixture.files).find((b) => b.binding)?.binding?.analysis_digest?.slice(0, 19);
    const fx = F({ fixture: `${name} (builder ${String(fixture.builderSha256).slice(0, 12)}; analysis ${dig}; envelope summary borrowed from uip04-one-group)` });
    try { await c.pg.goto(base); await c.pg.waitFor(`document.querySelector('#ot-demo')`, 20000); await ev(c.pg, "document.getElementById('ot-demo').click()"); await settle(c.pg, `window.__otStore.get().analysis`); await fn(c, fx, fixture); }
    catch (e) { if (e.message === 'DEADLINE') throw e; rec.note(`P2 ${name}: case completed`, false, e.message); }
    rec.note(`P2 ${name}: routing log (not a pass criterion)`, true, JSON.stringify({ served: c.st.log.served.length, unrouted: c.st.log.served.filter((s) => s.served.startsWith('unrouted')).map((s) => s.url).slice(0, 4), adapter: c.st.log.served.filter((s) => s.served.startsWith('adapter')).map((s) => s.served).slice(0, 3) }));
    await hygiene('P2 ' + name, c); await c.dispose();
  };
  await caseRun('contexts-600-synthetic', {}, async (c, fx, fixture) => {
    const { pg } = c; await mapReady(pg).catch(() => {}); await sleep(400); const p0 = fixture.files['contexts-page-0.json']; const stg = await ev(pg, "(()=>{const s=document.getElementById('ot4-stage');return s?{ready:s.dataset.mapReady,groups:+s.dataset.groupCount}:null})()");
    O('DA-05', 'fixture map is ready and shows every group of the payload', !!stg && stg.ready === 'true' && stg.groups === p0.groups.length, JSON.stringify(stg) + ' payloadGroups=' + p0.groups.length, fx);
    const body = (await txt(pg, '#ot-tabpanel')) + (await ev(pg, "document.getElementById('ot4-svg')?.textContent||''"));
    const big = p0.groups.filter((g) => g.membership_total >= 20).map((g) => g.membership_total);       // >=20 avoids matching unrelated small numbers as substrings
    O('DA-21', 'hidden/total numbers are visible: every membership_total >= 20 appears as a whole number token in the rendered map', big.length > 0 && big.every((n) => new RegExp('(^|\\D)' + n + '(\\D|$)').test(body)), big.join(','), fx);
    const reg = await region(pg, 'p2_da21_contexts600', '#ot4-stage'); O('DA-21', '600-file map region painted (raw value recorded)', compOk(reg), JSON.stringify(reg), fx);
    const pyGroup = fixture.files['contexts-group-python-offset-20.json'].groups[0].group_id;      // the only group the fixture has further pages for
    const moreSel = `[data-action=ctx-more][data-group="${pyGroup}"]`;
    if ((await count(pg, moreSel)) > 0) { const before = c.st.log.served.length; await ev(pg, `document.querySelector(${JSON.stringify(moreSel)}).dispatchEvent(new MouseEvent('click',{bubbles:true}))`); await sleep(900); const got = c.st.log.served.slice(before).filter((s) => /contexts\?/.test(s.url)); O('DA-21', 'the "show more" of a truncated group requests exactly one further bounded contexts page and it is SERVED FROM THE FIXTURE (an unrouted 404 does not count)', got.length === 1 && got[0].served.startsWith('fixture:'), JSON.stringify(got.map((s) => s.served)), fx); }
    else O('DA-21', 'the truncated python group offers a "show more" control', false, 'no ctx-more control for ' + pyGroup, fx);
  });
  await caseRun('deps-82-synthetic', {}, async (c, fx, fixture) => {
    const { pg } = c; await tab(pg, 'dependencies'); await settle(pg, `document.querySelector('#ot5-svg [data-dep-node]')`, 20000).catch(() => {});
    const tot = fixture.files['page-offset-00.json'].page.matches_total; const sizes = ['page-offset-00.json', 'page-offset-30.json', 'page-offset-60.json'].map((f) => fixture.files[f].page.matches_shown);
    O('DA-06', `fixture identified as an ${tot}-match dataset paging ${sizes.join('/')} (MANIFEST-verified files)`, tot === 82 && sizes.join('/') === '30/30/22', `${tot} ${sizes}`, fx);
    await ev(pg, "document.querySelector('[data-ot5-filter=all]')?.click()"); await sleep(700);
    const seen = []; for (let i = 0; i < 3; i++) { seen.push(await txt(pg, '#ot5-page-count')); if (i < 2) { await ev(pg, `document.querySelector('[data-action=dep-page][data-dir="1"]')?.click()`); await sleep(700); } }
    O('DA-21', 'pager walks 1–30 / 31–60 / 61–82 of 82 with the total visible (bounded, never silently truncated)', seen.join(' | ') === '1–30 of 82 | 31–60 of 82 | 61–82 of 82', seen.join(' | '), fx);
    await ev(pg, "document.querySelector('[data-ot5-filter=transitive]')?.click()"); await sleep(700);
    O('DA-06', 'an empty filter (transitive = 0) shows an empty state and no stale package list', (await count(pg, '#ot5-empty')) === 1, (await txt(pg, '#ot5-empty')).slice(0, 80), fx);
  });
  await caseRun('bom-large-synthetic', {}, async (c, fx, fixture) => {
    const { pg } = c; await tab(pg, 'bom'); await settle(pg, `window.__otStore.get().bom8.queue`, 20000).catch(() => {});
    const q = fixture.files['candidates-offset-00.json']; const bq = (await state(pg)).bom8.queue;
    O('DA-21', 'queue shows the payload total (60 candidates, 25 per page), not a truncated count', !!bq && bq.counts.candidates_total === q.counts.candidates_total && bq.page.size === 25, `${bq?.counts?.candidates_total}/${q.counts.candidates_total}`, fx);
    await ev(pg, `document.querySelector('[data-action="bom-view"][data-view="full"]')?.click()`); await settle(pg, `window.__otStore.get().bom8.graph?.scope.kind==='full_view'`, 20000).catch(() => {});
    const g0 = (await state(pg)).bom8.graph; O('DA-21', 'Full graph first window: primary_size 100, offset 0, paging stated by the payload', !!g0 && g0.page.primary_size === 100 && g0.page.offset === 0, JSON.stringify(g0?.page), fx);
    await ev(pg, `document.querySelector('[data-action="bom-full-page"][data-dir="1"]')?.click()`); await settle(pg, `window.__otStore.get().bom8.graph?.page.offset===100`, 20000).catch(() => {});
    const g1 = (await state(pg)).bom8.graph; O('DA-21', 'Next shows the second bounded window (offset 100), not a different graph', g1?.page?.offset === 100 && g1.scope.kind === 'full_view', JSON.stringify(g1?.page), fx);
  });
  await caseRun('malicious-text-synthetic', { '/api/workbench/v1/contexts': 'contexts-hostile.json', '/api/workbench/v1/crypto-assets': 'crypto-hostile.json' }, async (c, fx) => {
    const { pg } = c; await mapReady(pg).catch(() => {}); await sleep(500);
    const dom = () => ev(pg, "({img: !!document.querySelector('img[onerror], [onerror]'), script: [...document.querySelectorAll('script')].some((s)=>!s.src&&/alert\\(1\\)/.test(s.textContent)), alerted: window.__alerted||0, escaped: (document.body.textContent||'').includes('<img src=x onerror=alert(1)>')})");
    let d = await dom(); O('DA-17', 'contexts: hostile names create no element or handler and run nothing; the text is shown escaped', !d.img && !d.script && d.alerted === 0 && d.escaped, JSON.stringify(d), fx);
    await tab(pg, 'crypto'); await sleep(900); d = await dom(); O('DA-17', 'crypto: hostile text creates no element or handler and runs nothing', !d.img && !d.script && d.alerted === 0, JSON.stringify(d), fx);
    O('DA-17', 'no anchor carries a javascript: href', await ev(pg, "[...document.querySelectorAll('a[href]')].every((a)=>!/^\\s*javascript:/i.test(a.getAttribute('href')))"), '', fx);
  });
  const typed = [['cbom-empty-and-partial-synthetic', 'crypto-assets', 'crypto-completed-empty.json', 'crypto', 'DA-07'], ['cbom-empty-and-partial-synthetic', 'crypto-assets', 'crypto-partial.json', 'crypto', 'DA-07'],
    ['cbom-empty-and-partial-synthetic', 'crypto-assets', 'crypto-failed.json', 'crypto', 'DA-07'], ['nonpython-synthetic', 'crypto-assets', 'crypto-unsupported.json', 'crypto', 'DA-07'],
    ['cbom-empty-and-partial-synthetic', 'ai-assets', 'ai-unsupported.json', 'ai', 'DA-08'], ['no-ai-synthetic', 'ai-assets', 'ai-not-run.json', 'ai', 'DA-08'], ['no-ai-synthetic', 'ai-assets', 'ai-completed-empty.json', 'ai', 'DA-08']];
  const texts = { crypto: new Map(), ai: new Map() };
  for (const [name, route, file, t, row] of typed) await caseRun(name, { ['/api/workbench/v1/' + route]: file }, async (c, fx, fixture) => {
    const { pg } = c; await tab(pg, t); await sleep(900); const body = fixture.files[file]; const panel = await txt(pg, '#ot-tabpanel');
    O(row, `${file}: state "${body.availability?.state}" is shown with its own message`, !!body.availability?.message && panel.includes(String(body.availability.message).slice(0, 40)), `${body.availability?.state}: ${String(body.availability?.message).slice(0, 70)}`, fx);
    texts[t].set(file, panel.replace(/\s+/g, ' ').slice(0, 300));
  });
  for (const [t, row] of [['crypto', 'DA-07'], ['ai', 'DA-08']]) { const vals = [...texts[t].values()]; O(row, `${t}: the typed states render as distinct panels (${vals.length} compared)`, vals.length >= 2 && new Set(vals).size === vals.length, [...texts[t].keys()].join(','), F()); }
}

// ================================================================= P3 / P4: Scan on the live fixture service (1366 only)
const scanReady = (pg) => pg.waitFor(`document.getElementById('ot-scan') && !document.getElementById('ot-scan').disabled`, 20000);
const postCount = (pg, p) => pg.log.requests.filter((r) => r.method === 'POST' && new URL(r.url).pathname === p).length;
async function P3(base) {
  const c = await openCase(chrome.browser, {}); const { pg } = c; const R = (e) => ctxOf('real-server', { fixture: 'live_service.py (local git repo, fake scanners, recorded GitHub answers)', ...e });
  await pg.goto(base); await pg.waitFor(`document.getElementById('ot-scan')`, 15000); await scanReady(pg);
  const d = await txt(pg, '#ot-disclosure'); O('DA-01', 'with scanning configured: Scan enabled, pilot-list disclosure shown, no fixed "Live analysis unavailable"', /pre-approved repositories/.test(d) && !/Live analysis unavailable/.test(await txt(pg, '#ot-analyze')), d.slice(0, 100), R());
  await setUrl(pg, 'https://github.com/acme/widget'); await ev(pg, `(()=>{const b=document.getElementById('ot-scan');b.click();b.click();})()`);
  await pg.waitFor(`document.getElementById('ot-scan-status')`, 15000); await sleep(150);
  O('DA-02', 'a double click starts exactly one job and Scan is disabled while it runs', postCount(pg, '/api/scan') === 1 && (await ev(pg, "document.getElementById('ot-scan').disabled")), `POST /api/scan x${postCount(pg, '/api/scan')}`, R());
  await pg.waitFor(`document.querySelector('#ot-tabpanel [data-ctx], #ot-tabpanel .ot-list')`, 60000); const st = await state(pg);
  O('DA-02', 'completion hands off directly to Repository contexts with no second Scan click; mode live', st.destination === 'workbench' && st.workbench.tab === 'contexts' && st.analysis.identity.mode === 'live', `dest=${st.destination} tab=${st.workbench.tab}`, R());
  O('DA-02', 'the pinned commit in the progress status equals the identity of the artifacts (single resolution)', st.scan.status.binding.commit_sha === st.analysis.identity.commit && st.scan.status.job.state === 'completed', `${String(st.scan.status.binding.commit_sha).slice(0, 12)} / ${String(st.analysis.identity.commit).slice(0, 12)}`, R());
  O('DA-03', 'live result carries no Frigate content and the UI never called the legacy live route or the preview step', !/frigate/i.test(JSON.stringify(st.analysis.summary).slice(0, 4000)) && !pg.log.requests.some((r) => /\/api\/analysis\/live|\/api\/intake\/preview/.test(r.url)), '', R());
  await region(pg, 'p3_live_workbench', '#ot-tabpanel');
  await pg.click('#ot-top-end'); await pg.waitFor(`document.getElementById('ot-ended-note')`, 15000); const s2 = await state(pg);
  O('DA-16', 'End session clears the scan job and Workbench; configuration state is kept', s2.scan.job === null && s2.analysis === null && s2.config.state === 'loaded', '', R());
  await scanReady(pg); await setUrl(pg, 'https://github.com/acme/other'); await pg.click('#ot-scan'); await pg.waitFor(`document.querySelector('.ot-scan-outcome[data-kind=failed]')`, 30000);
  const f = await txt(pg, '#ot-scan-status');
  O('DA-02', 'a refused repository shows the failed stage, a fixed reason and a next step; Scan available again; nothing handed off', /Resolve and pin the revision/.test(f) && /Failed/.test(f) && !(await ev(pg, "document.getElementById('ot-scan').disabled")) && (await state(pg)).analysis === null, f.replace(/\n+/g, ' ').slice(0, 140), R());
  await pg.click('#nh-sample'); await pg.waitFor(`document.querySelector('#ot-tabpanel [data-ctx]')`, 30000);
  O('DA-03', 'the labelled sample path still opens the captured case (not the live result)', (await state(pg)).analysis.identity.mode !== 'live', '', R());
  await hygiene('P3', c); await c.dispose();
}
async function P4(base) {
  const c = await openCase(chrome.browser, {}); const { pg } = c; const R = (e) => ctxOf('real-server', { fixture: 'live_service.py --cbom-sleep 25', ...e });
  await pg.goto(base); await scanReady(pg); await setUrl(pg, 'https://github.com/acme/widget'); await pg.click('#ot-scan');
  await pg.waitFor(`document.querySelector('.ot-scan-stage[data-stage=cbom][data-state=running]')`, 30000); const run = await txt(pg, '#ot-scan-status');
  O('DA-02', 'running panel shows real stage states with elapsed time and no percentage', /Running/.test(run) && /Elapsed/.test(run) && !/%/.test(run) && /Resolve and pin/.test(run), run.replace(/\n+/g, ' ').slice(0, 140), R());
  O('DA-16', 'Cancel and End session stay reachable while running', (await exists(pg, '#ot-scan-cancel')) && !(await ev(pg, "document.getElementById('ot-top-end').hidden||document.getElementById('ot-top-end').disabled")), '', R());
  await pg.click('#ot-scan-cancel'); await pg.waitFor(`document.querySelector('.ot-scan-outcome[data-kind=cancelled]')`, 45000);
  O('DA-02', 'Cancel ends the job as cancelled, nothing is handed off, Scan is available again', (await state(pg)).analysis === null && (await state(pg)).scan.status.job.state === 'cancelled', '', R());
  await scanReady(pg); await pg.click('#ot-scan'); await pg.waitFor(`document.querySelector('.ot-scan-stage[data-stage=cbom][data-state=running]')`, 30000);
  await pg.click('#ot-top-end'); await pg.waitFor(`document.getElementById('ot-ended-note')`, 45000); const s3 = await state(pg);
  O('DA-16', 'End session during a scan clears the job and revokes access', s3.scan.job === null && s3.busy === null && s3.analysis === null, '', R());
  const polls = pg.log.requests.filter((r) => r.url.includes('/api/scan/status')).length; await sleep(3500);
  O('DA-16', 'no further status polls after End session; a late response cannot repopulate the session', pg.log.requests.filter((r) => r.url.includes('/api/scan/status')).length === polls && (await state(pg)).analysis === null, '', R());
  await hygiene('P4', c); await c.dispose();
}

// ================================================================= P5 / P6 / P7: typed correspondence on real projections (synthetic repos), desktop only
const scanRepo = async (pg, repo, first) => {
  if (!first) await endSession(pg);
  await scanReady(pg); await setUrl(pg, 'https://github.com/acme/' + repo); await pg.click('#ot-scan');
  await pg.waitFor(`window.__otStore.get().destination === 'workbench' || window.__otStore.get().scan?.status?.job?.state === 'failed'`, 90000);
  await pg.click('#ot-tab-bom'); await pg.waitFor(`window.__otStore.get().bom8.queue`, 30000);
  await pg.waitFor(`(()=>{const b=window.__otStore.get().bom8; return b.queue && !b.req.queue && !b.req.graph && !b.req.detail})()`, 30000);
};
const queueOf = async (pg) => { const r = await apiJson(pg, `/api/workbench/v1/bom-candidates?schema_version=1&generation=${await gen(pg)}`); return { mode: r.body?.mode, caps: Object.fromEntries((r.body?.capabilities || []).map((x) => [x.family, x.state + (x.reason_code ? '/' + x.reason_code : '')])), items: r.body?.items || [], counts: r.body?.counts }; };
const inspectOne = async (pg, row, label, id, ex, R) => {
  await ev(pg, `document.querySelector('[data-action=bom-select][data-id=${JSON.stringify(id)}]')?.click()`); await pg.waitFor(`document.querySelector('[data-evidence-for=${JSON.stringify(id)}] .ot-gap-inspector')`, 20000);
  const t = await inspectorContent(pg);
  for (const [name, ok] of ex(t)) O(row, `${label}: ${name}`, ok, t.slice(0, 160), R);
  O(row, `${label}: no horizontal page scroll; no hostile element created; no leaked exception text`, !(await ev(pg, 'document.documentElement.scrollWidth>innerWidth+1')) && !(await ev(pg, "!!document.querySelector('.ot-bom8 script, .ot-bom8 img[onerror]')")) && !/Traceback|PermissionError|\/private\/|\/tmp\//.test(t), '', R);
};
async function typedMatrix(base, family, table, label) {
  const c = await openCase(chrome.browser, {}); const { pg } = c; const R = (e) => ctxOf('real-server', { fixture: `${label} (synthetic local repos, fake scanners; REAL server projections)`, ...e });
  await pg.goto(base); let first = true; const view = family === 'crypto' ? 'crypto' : 'ai', capKey = family === 'crypto' ? 'cryptography' : 'ai_model', row = family === 'crypto' ? 'DA-07' : 'DA-08';
  for (const [repo, w] of Object.entries(table)) {
    guard();
    try {
      await scanRepo(pg, repo, first); first = false; await ev(pg, `document.querySelector('[data-action=bom-view][data-view=${view}]').click()`); await settled(pg, view);
      const q = await queueOf(pg); const want = w.cr || w.cap;
      O(row, `${repo}: ${w.n} candidate(s), page-level discovery_compared, ${capKey} capability ${want}`, q.items.length === w.n && q.mode === 'discovery_compared' && (q.caps[capKey] || '').startsWith(want), JSON.stringify({ n: q.items.length, mode: q.mode, cap: q.caps[capKey] }), R());
      if (w.state) O('DA-12', `${repo}: candidate state ${w.state}`, q.items.every((i) => i.state === w.state), JSON.stringify(q.items.map((i) => i.state)), R());
      O('DA-10', `${repo}: the queue holds only the ${capKey} family`, q.items.every((i) => i.family === capKey), JSON.stringify([...new Set(q.items.map((i) => i.family))]), R());
      for (const it of q.items) { const ex = typeof w.ex === 'function' ? w.ex : w.ex?.[it.state]; if (ex) await inspectOne(pg, 'DA-12', `${repo}${it.state ? ' ' + it.state : ''}`, it.item_id, ex, R()); else O('DA-12', `${repo}: candidate state ${it.state} is expected`, false, JSON.stringify(Object.keys(w.ex || {})), R()); }
      if (['hostile', 'cbomfail', 'aibomfail'].includes(repo)) { const dom = await ev(pg, "({script:!!document.querySelector('.ot-bom8 script'),img:!!document.querySelector('.ot-bom8 img[onerror]'),alerted:window.__alerted||0})"); O('DA-17', `${repo}: hostile/failed-producer text creates no element and runs nothing`, !dom.script && !dom.img && dom.alerted === 0, JSON.stringify(dom), R()); }
    } catch (e) { if (e.message === 'DEADLINE') throw e; O('DA-12', `${repo}: case completed`, false, e.message.slice(0, 200), R()); }
  }
  await hygiene(label, c); await c.dispose();
}
async function P7(base) {
  const c = await openCase(chrome.browser, {}); const { pg } = c; const R = (e) => ctxOf('real-server', { fixture: 'uip12 states (synthetic local repos; REAL server projections)', ...e });
  await pg.goto(base); let first = true;
  for (const [repo, [sw, cr]] of Object.entries({ partial: ['partial', 'partial'], empty: ['completed_empty', 'completed_empty'], nosource: ['completed_empty', 'completed_empty'], nodeonly: ['unsupported', 'unsupported'], failrepo: ['failed', 'failed'] })) {
    guard();
    try {
      await scanRepo(pg, repo, first); first = false; const q = await queueOf(pg);
      O('DA-07', `${repo}: software ${sw} and cryptography ${cr} are separate family states`, (q.caps.software || '').startsWith(sw) && (q.caps.cryptography || '').startsWith(cr), JSON.stringify(q.caps), R());
      for (const v of ['software', 'crypto', 'gaps', 'full']) { await ev(pg, `document.querySelector('[data-action=bom-view][data-view=${v}]').click()`); await settled(pg, v); const t = await txt(pg, '.ot-bom8');
        O('DA-10', `${repo}/${v}: view renders, no horizontal scroll, no leaked path or exception text`, !(await ev(pg, 'document.documentElement.scrollWidth>innerWidth+1')) && !/injected|PermissionError|\/tmp\/|\/private\/|Traceback/.test(t), t.slice(0, 80).replace(/\n/g, ' '), R());
        if (repo === 'partial' && v === 'crypto') O('DA-07', 'partial cryptography has its own disclosure wording', (await exists(pg, '.ot-bom8-coverage[data-family=cryptography]')) && /no cryptography is used/.test(t), t.slice(0, 160).replace(/\n/g, ' '), R());
        if (q.mode === 'discovery_compared' && (repo === 'empty' || repo === 'nosource') && v === 'crypto') O('DA-07', `${repo}: an empty result is stated as not-evidence-of-absence`, /not evidence|nothing was compared|no candidates|No requirement declarations|assessment has no candidates/i.test(t), t.slice(0, 160).replace(/\n/g, ' '), R());
        if (q.mode !== 'discovery_compared') O('DA-12', `${repo}/${v}: a non-compared result states why it was not compared`, /Not compared\./.test(t), t.slice(0, 120).replace(/\n/g, ' '), R()); }
    } catch (e) { if (e.message === 'DEADLINE') throw e; O('DA-07', `${repo}: case completed`, false, e.message.slice(0, 200), R()); }
  }
  await hygiene('P7', c); await c.dispose();
}

// ================================================================= P8: BOM inline graph battery (retained PR #76 failures re-measured, headed, real window resize)
async function P8(base) {
  const c = await openCase(chrome.browser, { hook: true }); const { pg } = c; const R = (e) => ctxOf('real-server', { fixture: 'uip13_followup_service.py: modelsupp (synthetic; REAL server projections)', ...e }); const SEL = '[data-bom-cy="inline"]';
  const sample = (ink) => ev(pg, `(${SAMPLE})(${JSON.stringify(SEL)},${ink})`);
  const painted = async (ms = 5000) => { const t0 = Date.now(); for (;;) { const s = await sample(true); const cy = s.cy; const ok = !!cy && cy.nodes > 0 && cy.nodes === cy.expectedNodes && cy.edges === cy.expectedEdges && cy.finite && cy.rendererDestroyed === false && cy.destroyed === false && cy.container === true && s.ink >= 300 * cy.nodes && s.edgesWithInk >= Math.ceil(0.8 * cy.edges); if (ok || Date.now() - t0 > ms) return { ok, s }; await sleep(120); } };
  const cam = () => ev(pg, `(()=>{const cy=document.querySelector(${JSON.stringify(SEL)})._cy;const h=document.querySelector(${JSON.stringify(SEL)}).getBoundingClientRect();const bb=cy.elements().renderedBoundingBox();return {zoom:cy.zoom(),pan:{...cy.pan()},inside:bb.x1>=-2&&bb.y1>=-2&&bb.x2<=h.width+2&&bb.y2<=h.height+2}})()`);
  await pg.goto(base); const w0 = await windowSize(c, pg, 1366, 900); rec.note('P8 baseline window (override cleared)', true, JSON.stringify(w0)); await scanRepo(pg, 'modelsupp', true); await ev(pg, `document.querySelector('[data-action=bom-view][data-view=ai]').click()`); await settled(pg, 'ai');
  const f0 = await ev(pg, FOCUS); const items = (await queueOf(pg)).items; const sup = items.find((i) => i.state === 'supported') || items[0];
  await ev(pg, `document.querySelector('[data-action=bom-select][data-id=${JSON.stringify(sup.item_id)}]').click()`); await settle(pg, `window.__otStore.get().bom8.graph?.scope?.candidate_id===${JSON.stringify(sup.item_id)}`); await settle(pg, `document.querySelector(${JSON.stringify(SEL)})?._cy?.nodes().length>0`);
  const p0 = await painted(); const reg0 = await region(pg, 'p8_bom_graph_1366', SEL); const id0 = p0.s.cy?.id;
  O('DA-10', 'focused graph painted: nodes/edges equal the payload, ink on canvas and on >=80% of edge midpoints', p0.ok, JSON.stringify({ nodes: p0.s.cy?.nodes, edges: p0.s.cy?.edges, ink: p0.s.ink, edgesWithInk: p0.s.edgesWithInk }), R({ focus: f0 }));
  O('DA-10', 'graph-host region colour analysis recorded (raw value beside the predicate)', compOk(reg0), JSON.stringify(reg0), R());
  const ids = p0.s.cy?.nodeIds || [];
  const pick = async (skip = []) => { for (const id of ids) { if (skip.includes(id)) continue; await ev(pg, `document.querySelector(${JSON.stringify(SEL)}).scrollIntoView({block:'center',behavior:'instant'})`); await sleep(120); const pt = await ev(pg, `(()=>{const h=document.querySelector(${JSON.stringify(SEL)});const n=h._cy.getElementById(${JSON.stringify(id)});const r=h.getBoundingClientRect();const q=n.renderedPosition();return {id:${JSON.stringify(id)},x:r.x+q.x,y:r.y+q.y,inside:q.x>5&&q.y>5&&q.x<r.width-5&&q.y<r.height-5}})()`); if (pt.inside) return pt; } return null; };
  const click = async (pt) => { await pg.send('Input.dispatchMouseEvent', { type: 'mouseMoved', x: pt.x, y: pt.y }); await pg.send('Input.dispatchMouseEvent', { type: 'mousePressed', x: pt.x, y: pt.y, button: 'left', clickCount: 1 }); await pg.send('Input.dispatchMouseEvent', { type: 'mouseReleased', x: pt.x, y: pt.y, button: 'left', clickCount: 1 }); await sleep(250); if ((await ev(pg, 'window.__otStore.get().bom8.popup')) === 'chooser') { await pg.key('Escape', 'Escape'); await sleep(250); } };
  const A = await pick();
  if (A) {
    await click(A); const a = await painted(); const sel = (await state(pg)).bom8.selectedRecord;
    O('DA-10', 'a REAL mouse click on a node selects that record (store and Cytoscape agree); graph stays painted on the same instance', sel === A.id && !!a.s.cy?.selected?.includes(A.id) && a.ok && a.s.cy.id === id0, JSON.stringify({ sel, id: a.s.cy?.id, id0 }), R());
    await ev(pg, `(()=>{const cy=document.querySelector(${JSON.stringify(SEL)})._cy;cy.zoom({level:Math.min(2.4,cy.zoom()*1.15),renderedPosition:{x:cy.width()/2,y:cy.height()/2}});cy.pan({x:cy.pan().x+14,y:cy.pan().y+9})})()`);
    const cam0 = await cam(); const B = await pick([A.id]);
    if (B) { await click(B); const b = await painted(); const cam1 = await cam();
      O('DA-10', 'a surrounding repaint (selection change) keeps instance, camera (zoom and pan) and paint', b.ok && b.s.cy.id === id0 && Math.abs(cam0.zoom - cam1.zoom) < 1e-6 && Math.abs(cam0.pan.x - cam1.pan.x) < 0.01 && Math.abs(cam0.pan.y - cam1.pan.y) < 0.01, JSON.stringify({ cam0, cam1 }), R()); }
  } else O('DA-10', 'a node inside the host was available for a real click', false, 'no node inside host', R());
  const w1 = await windowSize(c, pg, 1600, 900); O('DA-19', `the window resize changed the layout viewport (override cleared; innerWidth ${w1.iw}x${w1.ih} for a 1600x900 request)`, w1.iw >= 1560 && w1.iw <= 1600, JSON.stringify(w1), R({ viewport: '1600x900 (window)' }));
  const p1 = await painted(6000); const r1 = await region(pg, 'p8_bom_graph_1600_window', SEL); const f1 = await ev(pg, FOCUS);
  O('DA-19', `1600x900 REAL window resize, BOM inline graph region: raw ${JSON.stringify(r1)}; predicate=${compOk(r1)}; ink painted=${p1.ok}. This IS the retained PR #76 observation class; a failure is recorded as observed and its cause is not asserted`, compOk(r1) && p1.ok, JSON.stringify(r1), R({ viewport: `${w1.iw}x${w1.ih} (window)`, focus: f1 }));
  const w2 = await windowSize(c, pg, 1100, 800); await sleep(500); O('DA-19', `the shrink changed the layout viewport (innerWidth ${w2.iw}x${w2.ih} for a 1100x800 request)`, w2.iw >= 1060 && w2.iw <= 1100, JSON.stringify(w2), R({ viewport: '1100x800 (window)' }));
  const p2 = await painted(6000); const camS = await cam();
  O('DA-19', 'after the window shrinks to 1100x800 the graph is still painted and every element is inside the host (the retained PR #76 failure was "camera not refit")', p2.ok && camS.inside, JSON.stringify(camS), R({ viewport: `${w2.iw}x${w2.ih} (window)` }));
  await ev(pg, `document.querySelector('.ot-bom8-main [data-action=bom-fit]')?.click()`); await sleep(400); const camF = await cam();   // bom-fit is the BOM graph's Fit control (app.js:713); gfit serves the [data-cy] tab graphs (run1 clicked gfit: a no-op)
  O('DA-11', 'the Fit control brings every element back inside the graph host', camF.inside, JSON.stringify(camF), R({ viewport: '1100x800 (window)' }));
  const sm = await ev(pg, SUMMARY); O('DA-10', 'graph lifecycle: no unintentional renderer destroy and no live-but-detached instance across the battery', sm.unintentionalDestroys === 0 && sm.liveDetached === 0, JSON.stringify({ unintentional: sm.unintentionalDestroys, detached: sm.liveDetached, live: sm.liveCount }), R());
  await hygiene('P8', c); await c.dispose();
}

// ================================================================= D1: authorized diagnostic (D-17): BOM graph resize/Fit geometry + failed-CBOM scan status (UIP-D19 stays open)
// EXPECTATIONS FROZEN BEFORE LAUNCH (changing them after observing a result is not permitted; failures are preserved as observed):
//  E1  at 1366x900, after settling, with NO camera nudge: graph painted and every element inside the host (precondition).
//  E2  real window shrink to 1100x800, no interaction: (a) Cytoscape's canvas size equals the host size; (b) every element inside the host (AUTOMATIC behaviour).
//  E3  a REAL mouse click on the BOM graph's `bom-fit` control: every element inside the host (EXPLICIT behaviour).
//  E4  real window grow to 1600x900: (a) canvas size equals host; (b) every element inside the host.
//  E5  deliberate user zoom (real wheel) + pan (real drag) then shrink to 1100x800: INFORMATION ONLY (numbers recorded, no pass criterion; policy is "preserve deliberate user camera").
//  E6  explicit Fit after E5: every element inside the host.
//  C1  failed-CBOM scan: job state `failed`, destination not `workbench`, no analysis handed off.   C2  handoff.ready === false with a non-empty blocked_reason.
//  C3  a stage row with data-state=failed and a non-empty label is visible.   C4  a non-empty next-step (`.ot-scan-next`) is shown.   C5  no raw path/exception text.   C6  Scan is enabled again.
//  C7  INFORMATION ONLY: BOM tab presence (UIP-D19 unresolved: absence is not a failure).  Whether the wording is understandable is a REVIEWER/OWNER judgment; only presence is automated.
const diag = { metrics: [], cbomfail: null };
async function D1(base) {
  const c = await openCase(chrome.browser, { hook: false }); const { pg } = c; const SEL = '[data-bom-cy="inline"]'; const R = (e) => ctxOf('real-server', { fixture: 'stage4_diag_service.py (synthetic; REAL server projections)', ...e });
  let lastStable = null;
  const M = async (label, extra = {}) => {                           // numeric geometry + camera + clipping (never a predicate threshold)
    const m = await ev(pg, `(()=>{const h=document.querySelector(${JSON.stringify(SEL)});if(!h||!h._cy)return {missing:true};const cy=h._cy,r=h.getBoundingClientRect();const bb=cy.elements().renderedBoundingBox();
      const out=cy.nodes().filter((n)=>{const b=n.renderedBoundingBox();return b.x1<-2||b.y1<-2||b.x2>r.width+2||b.y2>r.height+2}).length;
      return {win:{iw:innerWidth,ih:innerHeight,ow:outerWidth,oh:outerHeight},host:{w:Math.round(r.width*10)/10,h:Math.round(r.height*10)/10},canvas:{w:cy.width(),h:cy.height()},
        bounds:{x1:Math.round(bb.x1),y1:Math.round(bb.y1),x2:Math.round(bb.x2),y2:Math.round(bb.y2)},zoom:cy.zoom(),pan:{...cy.pan()},nodes:cy.nodes().length,edges:cy.edges().length,
        nodesOutside:out,inside:bb.x1>=-2&&bb.y1>=-2&&bb.x2<=r.width+2&&bb.y2<=r.height+2,canvasMatchesHost:Math.abs(cy.width()-h.clientWidth)<=2&&Math.abs(cy.height()-h.clientHeight)<=2,hostClient:{w:h.clientWidth,h:h.clientHeight},canvasEl:(()=>{const c=h.querySelector('canvas');return c?{w:c.clientWidth,h:c.clientHeight}:null})()}})()`);
    const row = { label, settledBeforeMeasure: lastStable, ...m, ...extra }; diag.metrics.push(row); console.log('METRIC', JSON.stringify(row)); return m;
  };
  const stable = async (minMs = 700) => { await sleep(minMs); let prev = null, same = 0; const t0 = Date.now(); while (Date.now() - t0 < 9000) { const k = JSON.stringify(await ev(pg, `(()=>{const h=document.querySelector(${JSON.stringify(SEL)});const cy=h&&h._cy;if(!cy)return null;const b=cy.elements().renderedBoundingBox();return [h.clientWidth,h.clientHeight,cy.zoom(),cy.pan(),Math.round(b.x1),Math.round(b.x2),Math.round(b.y1),Math.round(b.y2)]})()`)); if (k === prev) { if (++same >= 2) return (lastStable = true); } else { same = 0; prev = k; } await sleep(350); } return (lastStable = false); };   // S4D-05: two identical consecutive samples, not a fixed sleep
  const clickSel = async (sel) => { const pt = await ev(pg, `(()=>{const e=document.querySelector(${JSON.stringify(sel)});if(!e)return null;e.scrollIntoView({block:'center',behavior:'instant'});const b=e.getBoundingClientRect();return {x:b.x+b.width/2,y:b.y+b.height/2}})()`); if (!pt) return false;
    await pg.send('Input.dispatchMouseEvent', { type: 'mouseMoved', x: pt.x, y: pt.y }); await pg.send('Input.dispatchMouseEvent', { type: 'mousePressed', x: pt.x, y: pt.y, button: 'left', clickCount: 1 }); await pg.send('Input.dispatchMouseEvent', { type: 'mouseReleased', x: pt.x, y: pt.y, button: 'left', clickCount: 1 }); await sleep(600); return true; };
  await pg.goto(base); const w0 = await windowSize(c, pg, 1366, 900); rec.note('D1 baseline window (override cleared)', true, JSON.stringify(w0));
  await scanRepo(pg, 'modelsupp', true); await ev(pg, `document.querySelector('[data-action=bom-view][data-view=ai]').click()`); await settled(pg, 'ai');
  const items = (await queueOf(pg)).items; const sup = items.find((i) => i.state === 'supported') || items[0];
  await ev(pg, `document.querySelector('[data-action=bom-select][data-id=${JSON.stringify(sup.item_id)}]').click()`); await settle(pg, `window.__otStore.get().bom8.graph?.scope?.candidate_id===${JSON.stringify(sup.item_id)}`); await settle(pg, `document.querySelector(${JSON.stringify(SEL)})?._cy?.nodes().length>0`);
  await stable(1200);                                                  // layout/fit settled (no camera nudge anywhere before E1)
  const m0 = await M('M0 1366x900 settled, fitted, no interaction'); await region(pg, 'd1_m0_1366', SEL);
  O('DA-10', 'E1 settled graph at 1366x900 (no camera nudge): nodes drawn and every element inside the host', !m0.missing && m0.nodes > 0 && m0.inside, JSON.stringify(m0), R());
  const w1 = await windowSize(c, pg, 1100, 800); await stable(); O('DA-19', `real window resize to 1100x800 took effect (innerWidth ${w1.iw}; a clamped resize would void E2)`, w1.iw >= 1060 && w1.iw <= 1100, JSON.stringify(w1), R({ viewport: `${w1.iw}x${w1.ih} (window)` })); const m1 = await M('M1 after real shrink to 1100x800, no interaction (AUTOMATIC)', { requested: '1100x800' }); await region(pg, 'd1_m1_shrunk', SEL);
  O('DA-19', `E2a after the real shrink (innerWidth ${w1.iw}) Cytoscape's canvas size equals the host size (the renderer knows the new size)`, !m1.missing && m1.canvasMatchesHost, JSON.stringify({ host: m1.host, canvas: m1.canvas }), R({ viewport: `${w1.iw}x${w1.ih} (window)` }));
  O('DA-19', 'E2b after the real shrink, with no interaction, every element is inside the host (automatic refit)', !m1.missing && m1.inside, JSON.stringify({ bounds: m1.bounds, host: m1.host, zoom: m1.zoom, pan: m1.pan, nodesOutside: m1.nodesOutside }), R({ viewport: `${w1.iw}x${w1.ih} (window)` }));
  const clicked1 = await clickSel('.ot-bom8-main [data-action=bom-fit]'); const m3 = await M('M3 after REAL click on the BOM Fit control at 1100x800 (EXPLICIT)', { clicked: clicked1 }); await region(pg, 'd1_m3_fit_1100', SEL);
  O('DA-11', 'E3 a real mouse click on the BOM graph Fit control brings every element inside the host', clicked1 && !m3.missing && m3.inside, JSON.stringify({ clicked: clicked1, bounds: m3.bounds, host: m3.host, zoom: m3.zoom, pan: m3.pan }), R({ viewport: '1100x800 (window)' }));
  const w4 = await windowSize(c, pg, 1600, 900); await stable(); O('DA-19', `real window resize to 1600x900 took effect (innerWidth ${w4.iw}; a clamped resize would void E4)`, w4.iw >= 1560 && w4.iw <= 1600, JSON.stringify(w4), R({ viewport: `${w4.iw}x${w4.ih} (window)` })); const m4 = await M('M4 after real grow to 1600x900 (AUTOMATIC)', { requested: '1600x900' }); await region(pg, 'd1_m4_grown', SEL);
  O('DA-19', `E4a after the real grow (innerWidth ${w4.iw}) Cytoscape's canvas size equals the host size`, !m4.missing && m4.canvasMatchesHost, JSON.stringify({ host: m4.host, canvas: m4.canvas }), R({ viewport: `${w4.iw}x${w4.ih} (window)` }));
  O('DA-19', 'E4b after the real grow every element is inside the host', !m4.missing && m4.inside, JSON.stringify({ bounds: m4.bounds, host: m4.host }), R({ viewport: `${w4.iw}x${w4.ih} (window)` }));
  // E5: deliberate user camera (real wheel + real drag on empty canvas), then shrink: information only
  const hp = await ev(pg, `(()=>{const h=document.querySelector(${JSON.stringify(SEL)});h.scrollIntoView({block:'center',behavior:'instant'});const b=h.getBoundingClientRect();return {x:b.x,y:b.y,w:b.width,h:b.height}})()`);
  await sleep(500);                                                    // Cytoscape ignores wheel events shortly after a page scroll (S4D-02)
  await pg.send('Input.dispatchMouseEvent', { type: 'mouseWheel', x: hp.x + hp.w / 2, y: hp.y + hp.h / 2, deltaX: 0, deltaY: -240 }); await sleep(500);
  await pg.send('Input.dispatchMouseEvent', { type: 'mouseMoved', x: hp.x + 8, y: hp.y + 8 }); await pg.send('Input.dispatchMouseEvent', { type: 'mousePressed', x: hp.x + 8, y: hp.y + 8, button: 'left', buttons: 1, clickCount: 1 });
  for (let i = 1; i <= 5; i++) await pg.send('Input.dispatchMouseEvent', { type: 'mouseMoved', x: hp.x + 8 + i * 8, y: hp.y + 8 + i * 5, button: 'left', buttons: 1 });
  await pg.send('Input.dispatchMouseEvent', { type: 'mouseReleased', x: hp.x + 48, y: hp.y + 33, button: 'left', buttons: 0, clickCount: 1 }); await stable(400);
  const m5 = await M('M5 after deliberate user zoom (wheel) and pan (drag) at 1600x900');
  const userMoved = !m5.missing && !m4.missing && (Math.abs(m5.zoom - m4.zoom) > 1e-6 || Math.abs(m5.pan.x - m4.pan.x) > 0.5 || Math.abs(m5.pan.y - m4.pan.y) > 0.5);
  diag.userCameraChanged = { zoomDelta: m5.zoom - m4.zoom, panDelta: { x: m5.pan.x - m4.pan.x, y: m5.pan.y - m4.pan.y }, changed: userMoved }; console.log('USERCAM', JSON.stringify(diag.userCameraChanged));
  await windowSize(c, pg, 1100, 800); await stable(); const m6 = await M('M6 after real shrink to 1100x800 with a deliberate user camera (INFO ONLY)');
  diag.userCameraPreservedAcrossResize = !userMoved ? null : (!m6.missing && Math.abs(m5.zoom - m6.zoom) < 1e-6 && Math.abs(m5.pan.x - m6.pan.x) < 0.01 && Math.abs(m5.pan.y - m6.pan.y) < 0.01);   // null = E5 not exercised (the user camera did not change)
  const clicked2 = await clickSel('.ot-bom8-main [data-action=bom-fit]'); const m7 = await M('M7 after REAL Fit click following a user camera and a shrink (EXPLICIT)', { clicked: clicked2 }); await region(pg, 'd1_m7_fit_after_user', SEL);
  O('DA-11', 'E6 explicit Fit after a deliberate user camera and a shrink brings every element inside the host', clicked2 && !m7.missing && m7.inside, JSON.stringify({ bounds: m7.bounds, host: m7.host, zoom: m7.zoom, pan: m7.pan }), R({ viewport: '1100x800 (window)' }));
  // ---- cbomfail: scan-status explanation and blocked hand-off (UIP-D19 open: a BOM tab is NOT required)
  await endSession(pg); await scanReady(pg); await setUrl(pg, 'https://github.com/acme/cbomfail'); await pg.click('#ot-scan');
  try { await pg.waitFor(`window.__otStore.get().destination === 'workbench' || (window.__otStore.get().scan?.status?.job?.state === 'failed' && window.__otStore.get().scan?.status?.cleanup?.state !== 'pending' && !!document.querySelector('.ot-scan-outcome[data-kind=failed]'))`, 90000); } catch (e) { rec.note('C0 the failed scan status did not settle within 90 s (cleanup still pending or no failed outcome rendered); the panel is observed as it stands', false, String(e.message).slice(0, 200)); } await sleep(1300);   // S4D-01: wait for the FINAL panel (cleanup settled), longer than the 1000 ms poll
  const st = await state(pg); const panel = await txt(pg, '#ot-scan-status'); const job = st.scan?.status; await region(pg, 'd1_cbomfail_scan_status', '#ot-scan-status');
  const failedRow = await ev(pg, `(()=>{const r=document.querySelector('#ot-scan-status .ot-scan-stage[data-state=failed]');return r?{id:r.dataset.stage,label:(r.querySelector('.ot-scan-label')?.innerText||'').trim(),note:(r.querySelector('.ot-scan-note')?.innerText||'').trim()}:null})()`);
  const nextTxt = await txt(pg, '#ot-scan-status .ot-scan-next'); const outcomeTxt = await txt(pg, '#ot-scan-status .ot-scan-outcome'); const scanEnabled = !(await ev(pg, "document.getElementById('ot-scan').disabled")); const bomTab = await exists(pg, '#ot-tab-bom');
  diag.cbomfail = { jobState: job?.job?.state, destination: st.destination, analysis: st.analysis === null ? null : 'present', handoff: job?.handoff, failedRow, outcome: outcomeTxt, next: nextTxt, panelText: panel.replace(/\n+/g, ' | ').slice(0, 900), scanEnabled, bomTabPresent: bomTab };
  console.log('CBOMFAIL', JSON.stringify(diag.cbomfail));
  const R2 = (e) => R({ fixture: 'stage4_diag_service.py: cbomfail (synthetic repo; fake cdxgen fails; REAL server projection)', ...e });
  O('DA-02', 'C1 failed-CBOM scan: job state failed, destination is not the Workbench, nothing handed off', job?.job?.state === 'failed' && st.destination !== 'workbench' && st.analysis === null, JSON.stringify({ state: job?.job?.state, destination: st.destination }), R2());
  O('DA-02', 'C2 hand-off is blocked (ready false) with a fixed blocked_reason', job?.handoff?.ready === false && !!job?.handoff?.blocked_reason, JSON.stringify(job?.handoff), R2());
  O('DA-02', 'C3 a failed stage row with a label is visible', !!failedRow && failedRow.label.length > 0, JSON.stringify(failedRow), R2());
  O('DA-02', 'C4 a next-step is shown beside the outcome', nextTxt.trim().length > 0, `${outcomeTxt} || ${nextTxt}`.slice(0, 220), R2());
  O('DA-17', 'C5 the status text carries no raw path or exception text', !/Traceback|PermissionError|\/tmp\/|\/private\/|\/var\/folders/.test(panel), panel.replace(/\n+/g, ' ').slice(0, 160), R2());
  O('DA-02', 'C6 Scan is enabled again so the user can act', scanEnabled, String(scanEnabled), R2());
  rec.note(`C7 INFO ONLY (UIP-D19 open; not a criterion): BOM tab present after the failed CBOM scan = ${bomTab}`, true, '');
  const bytes = readdirSync(OUT).reduce((n, f) => n + statSync(join(OUT, f)).size, 0); diag.evidenceBytesBeforeResultsJson = bytes; rec.note(`D-17 evidence written so far is under the 5 MB cap (${bytes} bytes)`, bytes < 5 * 1024 * 1024, String(bytes));
  await hygiene('D1', c); await c.dispose();
}

// ================================================================= D2: S4-FIX-01 confirmation (own allowance: 1 service, 1 headed Chrome, 10 minutes; no rerun)
// EXPECTATIONS FROZEN BEFORE LAUNCH (failures are preserved as observed; nothing is tuned afterwards):
//  F0  settled 1366x900 BOM inline graph, no nudge: every element inside the host; auto-fit armed (host._autoFit true); exactly one APP graph ResizeObserver live (Cytoscape's own renderer observer on the same host is counted separately as roAllOnGraphHosts, information only); instance marked for identity checks.
//  F1  [check 1] real shrink to 1100x800, no interaction: canvas equals host; every element inside the host (automatic refit).
//  F2  [check 2] real grow to 1600x900 (inside); real wheel zoom + real drag pan: the camera really changed (precondition); real shrink to 1100x800: zoom and pan unchanged (|dz|<1e-6, |dpan|<0.01),
//      canvas equals host, auto-fit disarmed. (Elements may be clipped here: that is the deliberate user camera; informational.)
//  F3  [check 3] real click on the BOM Fit control at 1100x800: every element inside the host; auto-fit re-armed.
//  F4  [check 4] real grow to 1600x900 (inside), then real shrink to 1100x800: every element inside the host (automatic refit after Fit re-armed it).
//  F5  [check 5] a real node click (surrounding repaint) keeps the SAME instance, camera and armed state, and exactly one live graph observer; lifecycle summary: zero unintentional renderer destroys and zero
//      live-but-detached instances; End session leaves no graph host and zero live graph observers (graph teardown through disposeGraph releases the observer).
//  Captures (only if F0..F5 pass and elapsed < 7 min): application-only PNGs at 1366, 1100, 1600 (Contexts, Dependencies, Cryptography, AI, BOM) + dark theme at 1366 (Contexts, BOM). The Update 9 prototype is NOT opened
//  or executed (plan precondition 4); reference captures are therefore absent and recorded as missing; the BOM has no reference captures in the tree at all.
const confirm2 = { metrics: [], captures: [], missingReferences: [], notes: [] };
const RO_TRACK = "(()=>{const O=window.ResizeObserver;if(!O||window.__roLive)return;window.__roLive=new Set();window.__roCreated=0;window.ResizeObserver=class extends O{constructor(cb){super(cb);this.__t=new Set();this.__app=/_lastSize/.test(String(cb));window.__roCreated++}observe(el,o){if(el&&el.hasAttribute&&el.hasAttribute('data-bom-cy')){this.__t.add(el);window.__roLive.add(this)}return super.observe(el,o)}unobserve(el){this.__t.delete(el);if(!this.__t.size)window.__roLive.delete(this);return super.unobserve(el)}disconnect(){this.__t.clear();window.__roLive.delete(this);return super.disconnect()}}})()";
async function D2(base) {
  const c = await openCase(chrome.browser, { hook: true }); const { pg } = c; const SEL = '[data-bom-cy="inline"]'; const R = (e) => ctxOf('real-server', { fixture: 'stage4_diag_service.py: modelsupp (synthetic; REAL server projections); product tree = S4-FIX-01 branch', ...e });
  await pg.send('Page.addScriptToEvaluateOnNewDocument', { source: RO_TRACK });
  let lastStable = null;
  const M = async (label, extra = {}) => {
    const m = await ev(pg, `(()=>{const h=document.querySelector(${JSON.stringify(SEL)});if(!h||!h._cy)return {missing:true,roLive:window.__roLive?[...window.__roLive].filter((o)=>o.__app).length:null};const cy=h._cy,r=h.getBoundingClientRect();const bb=cy.elements().renderedBoundingBox();
      const out=cy.nodes().filter((n)=>{const b=n.renderedBoundingBox();return b.x1<-2||b.y1<-2||b.x2>r.width+2||b.y2>r.height+2}).length;
      return {win:{iw:innerWidth,ih:innerHeight,ow:outerWidth,oh:outerHeight},host:{w:Math.round(r.width*10)/10,h:Math.round(r.height*10)/10},canvas:{w:cy.width(),h:cy.height()},hostClient:{w:h.clientWidth,h:h.clientHeight},
        bounds:{x1:Math.round(bb.x1),y1:Math.round(bb.y1),x2:Math.round(bb.x2),y2:Math.round(bb.y2)},zoom:cy.zoom(),pan:{...cy.pan()},nodes:cy.nodes().length,nodesOutside:out,
        inside:bb.x1>=-2&&bb.y1>=-2&&bb.x2<=r.width+2&&bb.y2<=r.height+2,canvasMatchesHost:Math.abs(cy.width()-h.clientWidth)<=2&&Math.abs(cy.height()-h.clientHeight)<=2,
        autoFit:h._autoFit,sameInstance:window.__cy0?h._cy===window.__cy0:null,roLive:window.__roLive?[...window.__roLive].filter((o)=>o.__app).length:null,roAllOnGraphHosts:window.__roLive?window.__roLive.size:null,roCreated:window.__roCreated}})()`);
    const row = { label, settledBeforeMeasure: lastStable, ...m, ...extra }; lastStable = null; confirm2.metrics.push(row); console.log('METRIC', JSON.stringify(row)); return m;
  };
  const stable = async (minMs = 700) => { await sleep(minMs); let prev = null, same = 0; const t0 = Date.now(); while (Date.now() - t0 < 9000) { const k = JSON.stringify(await ev(pg, `(()=>{const h=document.querySelector(${JSON.stringify(SEL)});const cy=h&&h._cy;if(!cy)return null;const b=cy.elements().renderedBoundingBox();return [h.clientWidth,h.clientHeight,cy.zoom(),cy.pan(),Math.round(b.x1),Math.round(b.x2),Math.round(b.y1),Math.round(b.y2)]})()`)); if (k === prev) { if (++same >= 2) return (lastStable = true); } else { same = 0; prev = k; } await sleep(350); } return (lastStable = false); };
  const clickSel = async (sel) => { const pt = await ev(pg, `(()=>{const e=document.querySelector(${JSON.stringify(sel)});if(!e)return null;e.scrollIntoView({block:'center',behavior:'instant'});const b=e.getBoundingClientRect();return {x:b.x+b.width/2,y:b.y+b.height/2}})()`); if (!pt) return false;
    await pg.send('Input.dispatchMouseEvent', { type: 'mouseMoved', x: pt.x, y: pt.y }); await pg.send('Input.dispatchMouseEvent', { type: 'mousePressed', x: pt.x, y: pt.y, button: 'left', clickCount: 1 }); await pg.send('Input.dispatchMouseEvent', { type: 'mouseReleased', x: pt.x, y: pt.y, button: 'left', clickCount: 1 }); await sleep(600); return true; };
  const resizeTo = async (w, h, tol) => { const wz = await windowSize(c, pg, w, h); await stable(); O('DA-19', `real window resize to ${w}x${h} took effect (innerWidth ${wz.iw})`, Math.abs(wz.iw - w) <= tol, JSON.stringify(wz), R({ viewport: `${wz.iw}x${wz.ih} (window)` })); return wz; };
  const t0 = Date.now(); const near = (a, b, e) => Math.abs(a - b) <= e;
  await pg.goto(base); await windowSize(c, pg, 1366, 900); await scanRepo(pg, 'modelsupp', true); await ev(pg, `document.querySelector('[data-action=bom-view][data-view=ai]').click()`); await settled(pg, 'ai');
  const items = (await queueOf(pg)).items; const sup = items.find((i) => i.state === 'supported') || items[0];
  await ev(pg, `document.querySelector('[data-action=bom-select][data-id=${JSON.stringify(sup.item_id)}]').click()`); await settle(pg, `window.__otStore.get().bom8.graph?.scope?.candidate_id===${JSON.stringify(sup.item_id)}`); await settle(pg, `document.querySelector(${JSON.stringify(SEL)})?._cy?.nodes().length>0`);
  await stable(1200); await ev(pg, `window.__cy0=document.querySelector(${JSON.stringify(SEL)})._cy;0`); const m0 = await M('M0 1366x900 settled, no interaction'); await region(pg, 'd2_m0_1366', SEL);   // ';0': the Core is circular and cannot be returned by value
  O('DA-10', 'F0 settled graph inside the host, auto-fit armed, exactly one graph ResizeObserver live', !m0.missing && m0.inside && m0.autoFit === true && m0.roLive === 1, JSON.stringify(m0), R());
  await resizeTo(1100, 800, 40); const m1 = await M('M1 real shrink to 1100x800, no interaction (AUTOMATIC)'); await region(pg, 'd2_m1_shrunk', SEL);
  O('DA-19', 'F1 [check 1] after the real shrink the canvas equals the host and every element is inside the host', !m1.missing && m1.canvasMatchesHost && m1.inside, JSON.stringify({ host: m1.host, bounds: m1.bounds, nodesOutside: m1.nodesOutside, zoom: m1.zoom }), R({ viewport: '1100x800 (window)' }));
  await resizeTo(1600, 900, 40); const m2 = await M('M2 real grow to 1600x900 (AUTOMATIC)');
  const hp = await ev(pg, `(()=>{const h=document.querySelector(${JSON.stringify(SEL)});h.scrollIntoView({block:'center',behavior:'instant'});const b=h.getBoundingClientRect();return {x:b.x,y:b.y,w:b.width,h:b.height}})()`); await sleep(500);
  await pg.send('Input.dispatchMouseEvent', { type: 'mouseWheel', x: hp.x + hp.w / 2, y: hp.y + hp.h / 2, deltaX: 0, deltaY: -240 }); await sleep(500);
  await pg.send('Input.dispatchMouseEvent', { type: 'mouseMoved', x: hp.x + 8, y: hp.y + 8 }); await pg.send('Input.dispatchMouseEvent', { type: 'mousePressed', x: hp.x + 8, y: hp.y + 8, button: 'left', buttons: 1, clickCount: 1 });
  for (let i = 1; i <= 5; i++) await pg.send('Input.dispatchMouseEvent', { type: 'mouseMoved', x: hp.x + 8 + i * 8, y: hp.y + 8 + i * 5, button: 'left', buttons: 1 });
  await pg.send('Input.dispatchMouseEvent', { type: 'mouseReleased', x: hp.x + 48, y: hp.y + 33, button: 'left', buttons: 0, clickCount: 1 }); await stable(400);
  const m3 = await M('M3 after deliberate user zoom (wheel) and pan (drag) at 1600x900'); const moved = !m3.missing && (Math.abs(m3.zoom - m2.zoom) > 1e-6 || Math.abs(m3.pan.x - m2.pan.x) > 0.5 || Math.abs(m3.pan.y - m2.pan.y) > 0.5);
  O('DA-10', 'F2 precondition: the real grow left every element inside, and the real wheel/drag changed the camera and disarmed auto-fit', !m2.missing && m2.inside && moved && m3.autoFit === false, JSON.stringify({ zoom: [m2.zoom, m3.zoom], pan: [m2.pan, m3.pan], autoFit: m3.autoFit }), R({ viewport: '1600x900 (window)' }));
  await resizeTo(1100, 800, 40); const m4 = await M('M4 real shrink to 1100x800 with the deliberate user camera');
  O('DA-19', 'F2 [check 2] the deliberate user pan/zoom survives the resize (camera numerically unchanged), the canvas equals the host, auto-fit stays disarmed', !m4.missing && Math.abs(m4.zoom - m3.zoom) < 1e-6 && near(m4.pan.x, m3.pan.x, 0.01) && near(m4.pan.y, m3.pan.y, 0.01) && m4.canvasMatchesHost && m4.autoFit === false, JSON.stringify({ zoom: [m3.zoom, m4.zoom], pan: [m3.pan, m4.pan], canvasMatchesHost: m4.canvasMatchesHost, autoFit: m4.autoFit, nodesOutside_informational: m4.nodesOutside }), R({ viewport: '1100x800 (window)' }));
  const fitClicked = await clickSel('.ot-bom8-main [data-action=bom-fit]'); const m5 = await M('M5 after REAL click on the BOM Fit control at 1100x800', { clicked: fitClicked }); await region(pg, 'd2_m5_fit_1100', SEL);
  O('DA-11', 'F3 [check 3] explicit Fit by a real click brings every element inside the host and re-arms auto-fit', fitClicked && !m5.missing && m5.inside && m5.autoFit === true, JSON.stringify({ clicked: fitClicked, bounds: m5.bounds, host: m5.host, autoFit: m5.autoFit }), R({ viewport: '1100x800 (window)' }));
  await resizeTo(1600, 900, 40); const m6 = await M('M6 real grow to 1600x900'); await resizeTo(1100, 800, 40); const m7 = await M('M7 real shrink to 1100x800 after Fit re-armed auto-fit'); await region(pg, 'd2_m7_auto_after_fit', SEL);
  O('DA-19', 'F4 [check 4] after Fit re-armed auto-fit, a subsequent real shrink fits automatically (every element inside the host)', !m6.missing && m6.inside && !m7.missing && m7.canvasMatchesHost && m7.inside, JSON.stringify({ grown_inside: m6.inside, bounds: m7.bounds, host: m7.host, nodesOutside: m7.nodesOutside }), R({ viewport: '1100x800 (window)' }));
  // F5: a surrounding repaint by a real node click; then lifecycle and teardown
  const camB = await M('M8 before the node click (1100x800)'); const ids = await ev(pg, `(()=>{const h=document.querySelector(${JSON.stringify(SEL)});const r=h.getBoundingClientRect();return h._cy.nodes().map((n)=>{const q=n.renderedPosition();return {id:n.id(),x:r.x+q.x,y:r.y+q.y,ok:q.x>6&&q.y>6&&q.x<r.width-6&&q.y<r.height-6}}).filter((p)=>p.ok)})()`);
  let clicked = false; if (ids.length) { await pg.send('Input.dispatchMouseEvent', { type: 'mouseMoved', x: ids[0].x, y: ids[0].y }); await pg.send('Input.dispatchMouseEvent', { type: 'mousePressed', x: ids[0].x, y: ids[0].y, button: 'left', clickCount: 1 }); await pg.send('Input.dispatchMouseEvent', { type: 'mouseReleased', x: ids[0].x, y: ids[0].y, button: 'left', clickCount: 1 }); await sleep(800); if ((await ev(pg, 'window.__otStore.get().bom8.popup')) === 'chooser') { await pg.key('Escape', 'Escape'); await sleep(300); } clicked = true; }
  const camA = await M('M9 after the node click (surrounding repaint)'); const sm = await ev(pg, SUMMARY);
  O('DA-10', 'F5a a real node click (surrounding repaint) keeps the same instance, the camera, the armed state and exactly one live graph observer', clicked && !camA.missing && camA.sameInstance === true && Math.abs(camA.zoom - camB.zoom) < 1e-6 && near(camA.pan.x, camB.pan.x, 0.01) && near(camA.pan.y, camB.pan.y, 0.01) && camA.autoFit === camB.autoFit && camA.roLive === 1, JSON.stringify({ clicked, same: camA.sameInstance, zoom: [camB.zoom, camA.zoom], autoFit: [camB.autoFit, camA.autoFit], roLive: camA.roLive }), R());
  O('DA-10', 'F5b lifecycle: zero unintentional renderer destroys and zero live-but-detached instances across the whole battery', sm.unintentionalDestroys === 0 && sm.liveDetached === 0, JSON.stringify({ unintentional: sm.unintentionalDestroys, detached: sm.liveDetached, live: sm.liveCount }), R());
  await endSession(pg); await sleep(800); const after = await ev(pg, `({hosts:document.querySelectorAll('[data-bom-cy]').length,roLive:window.__roLive?[...window.__roLive].filter((o)=>o.__app).length:null,roAllOnGraphHosts:window.__roLive?window.__roLive.size:null,roCreated:window.__roCreated})`); const sm2 = await ev(pg, SUMMARY);
  O('DA-16', 'F5c End session leaves no graph host and zero live graph observers (teardown released the observer)', after.hosts === 0 && after.roLive === 0, JSON.stringify({ ...after, liveCount_info: sm2.liveCount, unintentional: sm2.unintentionalDestroys, detached: sm2.liveDetached }), R());
  // ---- captures (application-only), only if the confirmation checks passed and time remains
  const passed = ['DA-10', 'DA-11', 'DA-16', 'DA-19'].every((r) => (rec.rows[r]?.obs || []).filter((o) => /^(F\d|real window resize)/.test(o.id)).every((o) => o.ok));
  const elapsedMin = (10 * 60000 - ledger.remainingMs()) / 60000;
  confirm2.captureDecision = { checksPassed: passed, elapsedMin: Math.round(elapsedMin * 10) / 10 };   // minutes since the FIRST launch (the allowance clock)
  confirm2.missingReferences.push({ what: 'Update 9 reference views at 1366/1100/1600', why: 'the prototype is never opened or executed by the harness (plan precondition 4); existing reference captures predate main and exist only for UIP-02/04/05/06/07 light/dark at 1366/1920/390' }, { what: 'BOM verification views (queue, inner views, Full graph, popup, chooser)', why: 'no reference captures exist in the tree' });
  if (passed && elapsedMin < 7) {
    const capBytes = () => confirm2.captures.reduce((n, x) => n + x.bytes, 0);
    const cap = async (name, w, theme) => { if (capBytes() > 3.5 * 1024 * 1024) { confirm2.notes.push('capture cap reached before ' + name); return; } const { data } = await pg.send('Page.captureScreenshot', { format: 'png' }); const buf = Buffer.from(data, 'base64'); writeFileSync(join(OUT, name + '.png'), buf); confirm2.captures.push({ name, width: w, theme, bytes: buf.length, kind: 'application-only' }); };
    await scanRepo(pg, 'modelsupp', true); await sleep(1500);
    for (const w of [1366, 1100, 1600]) { await windowSize(c, pg, w, w === 1366 ? 900 : w === 1100 ? 800 : 900); for (const t of ['contexts', 'dependencies', 'crypto', 'ai', 'bom']) { guard(); try { await tab(pg, t); await sleep(t === 'bom' ? 1500 : 900); await cap(`cap_${w}_light_${t}`, w, 'light'); } catch (e) { if (e.message === 'DEADLINE') throw e; confirm2.notes.push(`capture ${w} ${t} failed: ${String(e.message).slice(0, 120)}`); } } }
    await windowSize(c, pg, 1366, 900); await ev(pg, "document.getElementById('ot-theme').click()"); await sleep(500);
    for (const t of ['contexts', 'bom']) { guard(); try { await tab(pg, t); await sleep(t === 'bom' ? 1500 : 900); await cap(`cap_1366_dark_${t}`, 1366, 'dark'); } catch (e) { if (e.message === 'DEADLINE') throw e; confirm2.notes.push(`dark capture ${t} failed: ${String(e.message).slice(0, 120)}`); } }
    await ev(pg, "document.getElementById('ot-theme').click()"); await sleep(200);
    rec.note(`D2 captures taken: ${confirm2.captures.length} application-only PNGs, ${capBytes()} bytes`, confirm2.captures.length > 0, '');
  } else rec.note('D2 captures skipped (a confirmation check failed or time was short); recorded, not attempted', false, JSON.stringify(confirm2.captureDecision));
  await hygiene('D2', c); await c.dispose();
}

// ================================================================= D3: consolidated closure run (own allowance: 1 service, 1 headed Chrome, 10 minutes; no rerun)
// FROZEN BEFORE LAUNCH (failures are preserved as observed; no assertion is weakened and nothing is retried):
//  ORDER  Part 1 CAPTURES first (each PNG is written to disk the moment it is taken; teardown success cannot affect them) -> Part 2 TEARDOWN T -> Part 3 REACHABILITY probe R (separate scenario, a second session).
//  CAPTURE LIST (application-only, real headed window, fixture service `modelsupp`, synthetic data): 1366x900 light: Home, Contexts, Dependencies, Cryptography, AI, BOM (AI view, candidate selected, graph shown);
//    1100x800 light: Contexts, Dependencies, BOM;  1600x900 light: Contexts, Dependencies, BOM;  1366x900 dark: Contexts, BOM.  Total 14 PNGs, bounded to 3.5 MB.
//  REFERENCES  The Update 9 prototype is NOT opened or executed by this driver (plan precondition 4); comparisons use only pinned, already-captured reference PNGs in the tree, paired offline afterwards. Missing ones are labelled.
//  T  (teardown through a REAL click on #ot-top-end, with a resize debounce deliberately pending: a device-metrics change ~30 ms before the click, the path that exposed the unbound clearTimeout defect):
//    T1 End is reachable: elementFromPoint at the End button's centre is the button (or inside it).      T2 `#ot-ended-note` appears within 10 s of the click.   (The success condition is the product's own ended note, which the intake page renders when
//        store.ended is set; the helper's 30 s wait is not assumed correct: the state below is checked independently.)
//    T3 session retired: destination is not `workbench`, analysis is null, scan job is null.      T4 graph disposed: no `[data-bom-cy]` host; the pre-captured host reference has `_cy`, `_resizeObs`, `_resizeTimer` null and `_autoFit` unset.
//    T5 zero live app graph observers.   T6 zero page exceptions during teardown.   T7 no resize callback fires after the ended note (700 ms window).   T8 lifecycle: 0 unintentional renderer destroys, 0 live-but-detached, 0 live instances.
//    INFO (no pass criterion): whether a debounce was actually pending at click time (`host._resizeTimer` truthy), the hit-test element, popup/drawer/dialog state.
//  R  (second session, real node click first so the inspector/popup state is whatever the product produces): R1 End reachable by hit-test; R2 `#ot-ended-note` within 10 s of a real click; R3 no graph host, zero app observers, zero page exceptions. popup/drawer/dialog states recorded as info.
const closure3 = { captures: [], missingReferences: [], notes: [], teardown: null, reach: null };
const TIMER_TRACK = "(()=>{if(window.__rt)return;const S=window.setTimeout;const rt=window.__rt={scheduled:0,fired:0,log:[]};window.setTimeout=function(fn,ms,...a){if(ms===120&&typeof fn==='function'){rt.scheduled++;rt.log.push({k:'sched',t:performance.now()});const w=function(){rt.fired++;rt.log.push({k:'fire',t:performance.now()});return fn.apply(this,arguments)};return S.call(window,w,ms,...a)}return S.call(window,fn,ms,...a)}})()";   // clearTimeout is deliberately NOT wrapped: the native one must be exercised
async function D3(base) {
  const c = await openCase(chrome.browser, { hook: true }); const { pg } = c; const SEL = '[data-bom-cy="inline"]'; const R = (e) => ctxOf('real-server', { fixture: 'stage4_diag_service.py: modelsupp (synthetic; REAL server projections); product tree = the candidate head in meta.sha (under --final this is stage4_completion_service.py repo modelsupp)', ...e });
  await pg.send('Page.addScriptToEvaluateOnNewDocument', { source: RO_TRACK }); await pg.send('Page.addScriptToEvaluateOnNewDocument', { source: TIMER_TRACK });
  const capBytes = () => closure3.captures.reduce((n, x) => n + x.bytes, 0);
  const cap = async (name, w, theme, view) => { if (capBytes() > 3.5 * 1024 * 1024) { closure3.notes.push('capture cap reached before ' + name); return; } const dim = await ev(pg, '({w:innerWidth,h:innerHeight})'); const { data } = await pg.send('Page.captureScreenshot', { format: 'png', clip: { x: 0, y: 0, width: dim.w, height: dim.h, scale: 1 } }); const buf = Buffer.from(data, 'base64'); writeFileSync(join(OUT, name + '.png'), buf); closure3.captures.push({ name, width: w, theme, view, bytes: buf.length, css: `${dim.w}x${dim.h}`, kind: 'application-only' }); };   // 1 CSS px per image px (bounded size at any device pixel ratio)
  const shot = async (name, w, theme, view, ms = 900) => { guard(); try { await sleep(ms); await cap(name, w, theme, view); } catch (e) { if (e.message === 'DEADLINE') throw e; closure3.notes.push(`capture ${name} failed: ${String(e.message).slice(0, 120)}`); } };
  const gotoTab = async (t) => { await tab(pg, t); };
  const showBom = async () => { await tab(pg, 'bom'); await ev(pg, `document.querySelector('[data-action=bom-view][data-view=ai]').click()`); await settled(pg, 'ai'); const items = (await queueOf(pg)).items; const sup = items.find((i) => i.state === 'supported') || items[0];
    await ev(pg, `document.querySelector('[data-action=bom-select][data-id=${JSON.stringify(sup.item_id)}]').click()`); await settle(pg, `window.__otStore.get().bom8.graph?.scope?.candidate_id===${JSON.stringify(sup.item_id)}`); await settle(pg, `document.querySelector(${JSON.stringify(SEL)})?._cy?.nodes().length>0`); await sleep(1500); };
  const probe = () => ev(pg, `(()=>{const b=document.getElementById('ot-top-end');const r=b?b.getBoundingClientRect():null;const e=r?document.elementFromPoint(r.x+r.width/2,r.y+r.height/2):null;const h=window.__host0;const st=window.__otStore.get();
    return {endVisible:!!b&&!b.hidden,hitIsEnd:!!e&&(e===b||b.contains(e)),hit:e?(e.id||e.dataset?.action||e.tagName):null,pendingDebounce:!!(h&&h._resizeTimer),popup:st.bom8.popup,drawer:st.bom8.drawer,dialogOpen:!!document.getElementById('ot-dialog')?.open,
      hosts:document.querySelectorAll('[data-bom-cy]').length,roApp:window.__roLive?[...window.__roLive].filter((o)=>o.__app).length:null,roAll:window.__roLive?window.__roLive.size:null,destination:st.destination,analysisNull:st.analysis===null,scanJobNull:(st.scan?st.scan.job:null)===null,
      host0:h?{cy:!!h._cy,obs:!!h._resizeObs,timer:h._resizeTimer||null,autoFit:h._autoFit==null?'unset':h._autoFit}:null}})()`);
  // ------------------------------------------------ Part 1: captures
  await pg.goto(base); await windowSize(c, pg, 1366, 900); await pg.waitFor("document.getElementById('ot-scan')", 15000); await scanReady(pg);
  await shot('cap_1366_light_home', 1366, 'light', 'home', 1200);
  await scanRepo(pg, 'modelsupp', true); await sleep(1200);
  for (const t of ['contexts', 'dependencies', 'crypto', 'ai']) { try { await gotoTab(t); } catch (e) { closure3.notes.push(`tab ${t}: ${String(e.message).slice(0, 100)}`); } await shot(`cap_1366_light_${t}`, 1366, 'light', t, t === 'contexts' ? 1500 : 900); }
  try { await showBom(); } catch (e) { closure3.notes.push('bom setup failed: ' + String(e.message).slice(0, 120)); } await shot('cap_1366_light_bom', 1366, 'light', 'bom', 600);
  for (const [w, h] of [[1100, 800], [1600, 900]]) { await windowSize(c, pg, w, h); await sleep(800);
    for (const t of ['contexts', 'dependencies']) { try { await gotoTab(t); } catch (e) { closure3.notes.push(`tab ${t}@${w}: ${String(e.message).slice(0, 100)}`); } await shot(`cap_${w}_light_${t}`, w, 'light', t, 1200); }
    try { await showBom(); } catch (e) { closure3.notes.push(`bom@${w}: ${String(e.message).slice(0, 100)}`); } await shot(`cap_${w}_light_bom`, w, 'light', 'bom', 800); }
  await windowSize(c, pg, 1366, 900); await sleep(500); await ev(pg, "document.getElementById('ot-theme').click()"); await sleep(500);
  for (const t of ['contexts', 'bom']) { try { if (t === 'bom') await showBom(); else await gotoTab(t); } catch (e) { closure3.notes.push(`dark ${t}: ${String(e.message).slice(0, 100)}`); } await shot(`cap_1366_dark_${t}`, 1366, 'dark', t, 1000); }
  await ev(pg, "document.getElementById('ot-theme').click()"); await sleep(400);
  rec.note(`D3 captures: ${closure3.captures.length} of 14 application-only PNGs taken, ${capBytes()} bytes`, closure3.captures.length === 14, JSON.stringify(closure3.notes).slice(0, 300));
  closure3.missingReferences.push({ what: 'Update 9 reference views re-captured at this run\'s SHA/viewports', why: 'the prototype is never opened or executed by the harness (plan precondition 4); only pinned, already-captured reference PNGs may be paired (UIP-02/04/05/06/07, earlier code)' }, { what: 'BOM verification views', why: 'no reference captures exist in the tree' }, { what: 'Reference at 1100 and 1600 widths and for dark Dependencies/Crypto/AI', why: 'not in the tree' });
  // ------------------------------------------------ Part 2: teardown T (real click; a resize debounce deliberately pending)
  try {
  await windowSize(c, pg, 1100, 800); await sleep(1200); await showBom(); await ev(pg, `window.__host0=document.querySelector(${JSON.stringify(SEL)});0`);
  const exc0 = pg.log.exceptions.length; await pg.send('Emulation.setDeviceMetricsOverride', { width: 1366, height: 900, deviceScaleFactor: 1, mobile: false }); await sleep(30);
  const pre = await probe(); const pend = pre.pendingDebounce; await pg.click('#ot-top-end'); const tClick = Date.now();   // probe AFTER the layout change so the hit-test uses the layout the click will meet
  let ended = false; try { await pg.waitFor("document.getElementById('ot-ended-note')", 10000); ended = true; } catch { /* observed below */ }
  const noteAt = await ev(pg, 'performance.now()'); await sleep(700); const post = await probe(); const sm = await ev(pg, SUMMARY); const firesAfterNote = await ev(pg, `window.__rt.log.filter((e)=>e.k==='fire'&&e.t>${JSON.stringify(noteAt)}).length`); const exc1 = pg.log.exceptions.slice(exc0);
  closure3.teardown = { pre, pendingDebounceAtClick: pend, ended, msFromClickToNote: ended ? Date.now() - tClick : null, post, lifecycle: { unintentional: sm.unintentionalDestroys, detached: sm.liveDetached, live: sm.liveCount }, firesAfterNote, exceptions: exc1.slice(0, 3) };
  console.log('TEARDOWN', JSON.stringify(closure3.teardown));
  rec.note(`T INFO: debounce pending at click = ${pend}; hit element = ${pre.hit}`, true, JSON.stringify({ popup: pre.popup, drawer: pre.drawer, dialogOpen: pre.dialogOpen }));
  O('DA-16', 'T1 End session is reachable: the element at the End button centre is the button', pre.endVisible && pre.hitIsEnd, JSON.stringify({ endVisible: pre.endVisible, hit: pre.hit }), R());
  O('DA-16', 'T2 a real click on End shows the ended note within 10 s', ended, ended ? `${closure3.teardown.msFromClickToNote} ms` : 'no #ot-ended-note within 10 s', R());
  O('DA-16', 'T3 session retired: destination is not the Workbench, no analysis, no scan job', post.destination !== 'workbench' && post.analysisNull && post.scanJobNull, JSON.stringify({ destination: post.destination, analysisNull: post.analysisNull, scanJobNull: post.scanJobNull }), R());
  O('DA-16', 'T4 graph disposed: no graph host in the page; the captured host holds no instance, observer, pending timer or auto-fit state', post.hosts === 0 && !!post.host0 && post.host0.cy === false && post.host0.obs === false && post.host0.timer === null && post.host0.autoFit === 'unset', JSON.stringify({ hosts: post.hosts, host0: post.host0 }), R());
  O('DA-16', 'T5 zero live app graph observers after disposal', post.roApp === 0, JSON.stringify({ roApp: post.roApp, roAll: post.roAll }), R());
  O('DA-16', 'T6 zero page exceptions during the teardown', exc1.length === 0, JSON.stringify(exc1.slice(0, 2)).slice(0, 300), R());
  O('DA-16', 'T7 no resize callback fires after the ended note (700 ms)', firesAfterNote === 0, String(firesAfterNote), R());
  O('DA-10', 'T8 lifecycle: zero unintentional renderer destroys, zero live-but-detached, zero live instances after teardown', sm.unintentionalDestroys === 0 && sm.liveDetached === 0 && sm.liveCount === 0, JSON.stringify(closure3.teardown.lifecycle), R());
  } catch (e) { if (e.message === 'DEADLINE') throw e; rec.note('T scenario aborted before all its assertions (preserved as observed; Part 3 still runs)', false, String(e.message).slice(0, 300)); closure3.teardown = closure3.teardown || { aborted: String(e.message).slice(0, 300) }; }
  // ------------------------------------------------ Part 3: reachability probe R (second session, real node click first)
  try {
    await windowSize(c, pg, 1366, 900); await sleep(600); await scanRepo(pg, 'modelsupp', true); await showBom(); await ev(pg, `window.__host0=document.querySelector(${JSON.stringify(SEL)});0`);
    const pts = await ev(pg, `(()=>{const h=document.querySelector(${JSON.stringify(SEL)});const r=h.getBoundingClientRect();return h._cy.nodes().map((n)=>{const q=n.renderedPosition();return {x:r.x+q.x,y:r.y+q.y,ok:q.x>6&&q.y>6&&q.x<r.width-6&&q.y<r.height-6}}).filter((p)=>p.ok)})()`);
    if (pts.length) { await pg.send('Input.dispatchMouseEvent', { type: 'mouseMoved', x: pts[0].x, y: pts[0].y }); await pg.send('Input.dispatchMouseEvent', { type: 'mousePressed', x: pts[0].x, y: pts[0].y, button: 'left', clickCount: 1 }); await pg.send('Input.dispatchMouseEvent', { type: 'mouseReleased', x: pts[0].x, y: pts[0].y, button: 'left', clickCount: 1 }); await sleep(900); }
    const exc2 = pg.log.exceptions.length; const pre2 = await probe(); await pg.click('#ot-top-end'); let ended2 = false; try { await pg.waitFor("document.getElementById('ot-ended-note')", 10000); ended2 = true; } catch { /* observed below */ }
    await sleep(700); const post2 = await probe(); const exc3 = pg.log.exceptions.slice(exc2); closure3.reach = { nodeClicked: pts.length > 0, pre: pre2, ended: ended2, post: post2, exceptions: exc3.slice(0, 3) }; console.log('REACH', JSON.stringify(closure3.reach));
    rec.note(`R INFO: after a real node click popup=${pre2.popup} drawer=${pre2.drawer} dialogOpen=${pre2.dialogOpen} hit=${pre2.hit}`, true, '');
    O('DA-16', 'R1 End session is reachable after a real node click: the element at the End button centre is the button', pts.length > 0 && pre2.endVisible && pre2.hitIsEnd, JSON.stringify({ nodeClicked: pts.length > 0, hit: pre2.hit }), R());
    O('DA-16', 'R2 a real click on End shows the ended note within 10 s', ended2, String(ended2), R());
    O('DA-16', 'R3 no graph host, zero app observers, zero page exceptions after that teardown', post2.hosts === 0 && post2.roApp === 0 && exc3.length === 0, JSON.stringify({ hosts: post2.hosts, roApp: post2.roApp, exceptions: exc3.length }), R());
  } catch (e) { if (e.message === 'DEADLINE') throw e; rec.note('R scenario aborted before its assertions (preserved as observed)', false, String(e.message).slice(0, 300)); closure3.reach = { aborted: String(e.message).slice(0, 300) }; }
  await hygiene('D3', c); await c.dispose();
}

// ================================================================= F1: closing campaign (launch A): E0-E11, then the closure body D3, then E9.
// EXPECTATIONS FROZEN BEFORE LAUNCH in .context/stage4-prep/FINAL_CAMPAIGN_FROZEN_EXPECTATIONS_v2.md (v1 retained). A failed predicate is preserved as observed: no retry, no relabel.
const fin = { viewports: [], scenarios: {}, launcher: [], regions: [], e9: null, infos: [] };
const winSize = (pg) => ev(pg, '({w:innerWidth,h:innerHeight,ow:outerWidth,oh:outerHeight})');
const noteVp = async (pg, scenario) => { const v = await winSize(pg); fin.viewports.push({ scenario, ...v }); return v; };
const aiApi = async (pg) => (await apiJson(pg, `/api/workbench/v1/ai-assets?generation=${await gen(pg)}`));
const crApi = async (pg) => (await apiJson(pg, `/api/workbench/v1/crypto-assets?generation=${await gen(pg)}`));
const producerRows = (b) => (b?.producers || []).map((p) => [p.provenance.producer_id, p.outcome]);
const hasProducer = (b, id, outcome) => producerRows(b).some(([i, o]) => i === id && (outcome === undefined || o === outcome));
const namesOf = (b) => (b?.assets || []).map((a) => a.display_name);
const ABS_PATH = /"\/(?:private|tmp|Users|var|home|opt|etc)\//;
const LAUNCH_PROBE = `(()=>{const L=document.getElementById('ot-assistant-launch');if(!L)return {missing:true};const lr=L.getBoundingClientRect();const vis=(e)=>{const s=getComputedStyle(e);return s.visibility!=='hidden'&&s.display!=='none'&&+s.opacity>0};const hits=[];
  for(const e of document.querySelectorAll('body *')){if(e===L||L.contains(e)||e.contains(L)||!vis(e))continue;const own=[...e.childNodes].some((n)=>n.nodeType===3&&n.textContent.trim().length>0);const ctl=e.matches('button,a,input,select,textarea,summary,[role=button]');if(!own&&!ctl)continue;
    const r=e.getBoundingClientRect();if(r.width<1||r.height<1)continue;const w=Math.min(r.right,lr.right)-Math.max(r.left,lr.left),h=Math.min(r.bottom,lr.bottom)-Math.max(r.top,lr.top);
    if(w>0&&h>0)hits.push({tag:e.tagName,id:e.id,cls:String(typeof e.className==='string'?e.className:(e.className&&e.className.baseVal)||'').slice(0,40),area:Math.round(w*h),text:(e.innerText||e.textContent||'').trim().slice(0,30)});}
  const max=document.documentElement.scrollHeight-innerHeight;return {launcher:{x:Math.round(lr.x),y:Math.round(lr.y),w:Math.round(lr.width),h:Math.round(lr.height)},scrollY:Math.round(scrollY),maxScroll:max,atEnd:Math.abs(scrollY-max)<=2,vp:{w:innerWidth,h:innerHeight},hitCount:hits.length,hits:hits.slice(0,8)}})()`;
const cardClick = async (pg, svg, needle) => {                     // a REAL hit-tested click on the card whose text contains `needle` (the element is tagged, then clicked by the CDP helper)
  const ok = await ev(pg, `(()=>{for(const g of document.querySelectorAll(${JSON.stringify(svg + ' g[role=button][data-' + (svg === '#otc-svg' ? 'otc' : 'otai') + '-select^=asset]')})){if((g.textContent||'').includes(${JSON.stringify(needle)})){g.setAttribute('data-f1pick','1');g.scrollIntoView({block:'center',behavior:'instant'});return true}}return false})()`);
  if (!ok) return false; await pg.click('[data-f1pick="1"]'); await ev(pg, "document.querySelector('[data-f1pick]')?.removeAttribute('data-f1pick')"); await sleep(400); return true;
};
async function f1Region(c, label, sel, expectNonEmpty, row, R) {
  const r = await region(c.pg, label, sel); const v = await winSize(c.pg); fin.regions.push({ label, viewport: v, raw: r, expectNonEmpty });
  if (expectNonEmpty) O(row, `${label}: non-empty region is painted (raw value recorded; viewport ${v.w}x${v.h})`, compOk(r), JSON.stringify(r), R({ viewport: `${v.w}x${v.h}` }));
  else O(row, `${label}: legitimately empty by payload (no paint requirement; raw value recorded)`, true, JSON.stringify(r), R({ viewport: `${v.w}x${v.h}` }));
}
async function F1(base) {
  const c = await openCase(chrome.browser, {}); const { pg } = c; const R = (e) => ctxOf('real-server', { fixture: 'stage4_completion_service.py (synthetic; REAL server projections)', ...e });
  await pg.goto(base); await pg.waitFor(`document.getElementById('ot-scan')`, 15000); await windowSize(c, pg, 1366, 900);
  const FX = (name) => R({ fixture: `stage4_completion_service.py repo "${name}" (synthetic; REAL server projections)` });
  const RA = (e) => FX('aicrypto');
  const FXI = (name) => R({ fixture: `stage4_completion_service.py repo "${name}" (synthetic; REAL server projection and UI; the COLLECTOR FAULT is injected by the fixture-service process, not product behaviour)` });
  const scanFresh = async (pg2, repo) => { if ((await state(pg2)).analysis) await endSession(pg2).catch(() => {}); await scanRepo(pg2, repo, true); };
  const step = async (name, fn) => { guard(); try { await fn(); } catch (e) { if (e.message === 'DEADLINE') throw e; rec.note(`F1 ${name}: aborted before all its assertions (preserved as observed)`, false, String(e.message).slice(0, 300)); } };
  // ---------------------------------------------------------------- aicrypto: E1, E2, E6, E8
  await step('aicrypto E1/E2/E6/E7/E8', async () => {
  await scanFresh(pg, 'aicrypto'); await noteVp(pg, 'aicrypto'); await tab(pg, 'ai'); await settle(pg, `document.querySelector('#otai-svg, #otai-list, #otai-empty')`, 30000); await sleep(600);
  const ai = (await aiApi(pg)).body; const by = Object.fromEntries((ai?.assets || []).map((a) => [a.display_name, a])); const pre = by.tflite_runtime, fb = by.ai_edge_litert, svc = by['http://127.0.0.1:11434/api/generate'], mdl = (ai?.assets || []).find((a) => a.kind === 'model_reference');
  O('DA-08', 'E1 API: availability completed; filter totals {5,1,3,1,0}; producers {cisco-aibom, opentrace-source-ai}; runtimes, service and model as frozen', !!ai && ai.availability.state === 'completed' && [['all', 5], ['models', 1], ['runtimes', 3], ['ai_services', 1], ['findings', 0]].every(([k, v]) => ai.filter_totals[k] === v) && JSON.stringify(producerRows(ai).map((x) => x[0]).sort()) === JSON.stringify(['cisco-aibom', 'opentrace-source-ai']) && JSON.stringify(ai.assets.filter((a) => a.kind === 'runtime').map((a) => a.display_name).sort()) === JSON.stringify(['ai_edge_litert', 'hailo_platform', 'tflite_runtime']) && !!svc && svc.kind === 'ai_service' && !!mdl, JSON.stringify({ state: ai?.availability?.state, ft: ai?.filter_totals, p: producerRows(ai) }), FX('aicrypto'));
  const link = ai?.links?.[0];
  O('DA-08', 'E1 API: exactly one conditionally_selects link tflite_runtime -> ai_edge_litert; the fallback occurrence alternative_of equals the preferred occurrence id', ai?.links?.length === 1 && link.relation === 'conditionally_selects' && link.from === pre?.asset_id && link.to === fb?.asset_id && fb.occurrences[0].alternative_of === pre.occurrences[0].occurrence_id, JSON.stringify(link || null).slice(0, 200), FX('aicrypto'));
  O('DA-08', 'E1 API: every source asset is experimental with origin supplemental_observation; the model asset is original_artifact and not experimental; no absolute path in the payload', [pre, fb, svc, by.hailo_platform].every((a) => a && a.provenance.experimental === true && a.provenance.origin === 'supplemental_observation') && mdl.provenance.origin === 'original_artifact' && mdl.provenance.experimental === false && !ABS_PATH.test(JSON.stringify(ai)) && ai.assets.every((a) => a.occurrences.every((o) => !String(o.source_location?.path || '').startsWith('/'))), '', FX('aicrypto'));
  const pills = await txt(pg, '.otai-filters');
  O('DA-08', 'E1 DOM: pills Runtimes 3, AI services 1, Models 1', /Runtimes\s*3/.test(pills) && /AI services\s*1/.test(pills) && /Models\s*1/.test(pills), pills.replace(/\s+/g, ' ').slice(0, 120), FX('aicrypto'));
  await pg.click('[data-otai-filter=runtimes]'); await sleep(500); const nRt = await count(pg, '#otai-svg g[data-otai-select^=asset]');
  await pg.click('[data-otai-filter=all]'); await sleep(500); const nAlt = await count(pg, '.otai-alt');
  O('DA-08', 'E1 DOM: Runtimes filter shows 3 cards; All shows exactly one alternative connector', nRt === 3 && nAlt === 1, JSON.stringify({ runtimeCards: nRt, otaiAlt: nAlt }), FX('aicrypto'));
  const picked = await cardClick(pg, '#otai-svg', 'tflite_runtime'); const det = await txt(pg, '.otai-aside'); const panelAi = await txt(pg, '#ot-tabpanel');
  O('DA-08', 'E1 DOM: a real click on the tflite_runtime card opens the inspector (aside) that says experimental source observation and that installation or use of the runtime is not established; no "vulnerab" anywhere', picked && /Experimental source observation/i.test(det) && /(not established|does not show)[^.]*(install|active|used?)|(install|active|used?)[^.]*not established/i.test(det) && !/vulnerab/i.test(panelAi), det.replace(/\s+/g, ' ').slice(0, 200), FX('aicrypto'));
  fin.scenarios.e1 = { state: ai?.availability?.state, ft: ai?.filter_totals, producers: producerRows(ai), runtimeCards: nRt, otaiAlt: nAlt };
  // E6 launcher geometry (AI tab, real window sizes)
  for (const [w, h] of [[1366, 900], [1100, 800]]) {
    guard(); await windowSize(c, pg, w, h); await sleep(700); const vp = await winSize(pg);
    await ev(pg, 'window.scrollTo(0,0)'); await sleep(200); const top = await ev(pg, LAUNCH_PROBE); await ev(pg, 'window.scrollTo(0,document.documentElement.scrollHeight)'); await sleep(500); const end = await ev(pg, LAUNCH_PROBE);
    fin.launcher.push({ requested: `${w}x${h}`, viewport: vp, atTop_info: top, atEnd: end });
    O('DA-16', `E6 launcher at the document end (${vp.w}x${vp.h}) intersects no text-bearing element or control (area 0)`, !end.missing && end.atEnd === true && end.hitCount === 0, JSON.stringify({ atEnd: end.atEnd, hitCount: end.hitCount, hits: end.hits, maxScroll: end.maxScroll }), FX('aicrypto'));
  }
  await windowSize(c, pg, 1366, 900); await sleep(500);
  // E2 crypto
  await tab(pg, 'crypto'); await settle(pg, `document.querySelector('#otc-svg, #otc-list, #otc-empty')`, 30000); await sleep(600);
  const cr = (await crApi(pg)).body; const want = ['HS256', 'RS256', 'md5', 'sha256', 'MQTT TLS configuration', 'TLS context configuration (ssl module)'];
  const kindOf = Object.fromEntries((cr?.assets || []).map((a) => [a.asset_id, a.kind]));
  O('DA-07', 'E2 API: names contain the six frozen assets; cdxgen and opentrace-source-crypto are separate producer rows', want.every((n) => namesOf(cr).includes(n)) && hasProducer(cr, 'cdxgen') && hasProducer(cr, 'opentrace-source-crypto'), JSON.stringify({ names: namesOf(cr), p: producerRows(cr) }).slice(0, 300), FX('aicrypto'));
  O('DA-07', 'E2 API: exactly one review item, tone review, rule source-observation.tls_verification_relaxed, on a protocol asset; none on any algorithm asset', cr?.review_items?.length === 1 && cr.review_items[0].tone === 'review' && cr.review_items[0].rule_id === 'source-observation.tls_verification_relaxed' && kindOf[cr.review_items[0].asset_id] === 'protocol' && cr.review_items.every((r) => kindOf[r.asset_id] !== 'algorithm'), JSON.stringify((cr?.review_items || []).map((r) => [r.rule_id, r.tone, kindOf[r.asset_id]])), FX('aicrypto'));
  const hs = await cardClick(pg, '#otc-svg', 'HS256'); const cdet = await txt(pg, '.otc-aside'); const panelCr = await txt(pg, '#ot-tabpanel');
  O('DA-07', 'E2 DOM: a real click on HS256 opens an inspector labelled as an experimental source observation; no "vulnerab" in the panel', hs && /Experimental source observation/i.test(cdet) && !/vulnerab/i.test(panelCr), cdet.replace(/\s+/g, ' ').slice(0, 200), FX('aicrypto'));
  fin.scenarios.e2 = { names: namesOf(cr), producers: producerRows(cr), reviews: (cr?.review_items || []).length };
  // E8 graph hosts on aicrypto (non-empty fixtures), 1366 then a real resize to 1100x800
  for (const [w, h] of [[1366, 900], [1100, 800]]) {
    guard(); await windowSize(c, pg, w, h); await sleep(700);
    await tab(pg, 'contexts'); await mapReady(pg).catch(() => {}); await sleep(500); const nCtx = (await state(pg)).views.contexts?.groups?.length || 0; await f1Region(c, `e8_contexts_${w}`, '#ot4-stage', nCtx > 0, 'DA-05', RA);
    await tab(pg, 'dependencies'); await settle(pg, `document.querySelector('#ot5-svg [data-dep-node]')`, 15000).catch(() => {}); await sleep(400); const nDep = (await state(pg)).views.depPage?.nodes?.length || 0; await f1Region(c, `e8_dependencies_${w}`, '#ot5-svg', nDep > 0, 'DA-06', RA);
    await tab(pg, 'crypto'); await settle(pg, `document.querySelector('#otc-svg')`, 15000).catch(() => {}); await sleep(500); await f1Region(c, `e8_crypto_${w}`, '#otc-svg', true, 'DA-07', RA);
    await tab(pg, 'ai'); await settle(pg, `document.querySelector('#otai-svg')`, 15000).catch(() => {}); await sleep(500); await f1Region(c, `e8_ai_${w}`, '#otai-svg', true, 'DA-08', RA);
  }
  await windowSize(c, pg, 1366, 900); await sleep(400);
  // E7 (part 1): the AI selection must not appear on the Crypto tab
  await tab(pg, 'ai'); await sleep(400); await cardClick(pg, '#otai-svg', 'tflite_runtime'); await tab(pg, 'crypto'); await sleep(500); const crossTxt = await txt(pg, '#ot-tabpanel');
  O('DA-17', 'E7 the Crypto tab shows no trace of the AI selection (tflite_runtime)', !/tflite_runtime/.test(crossTxt), crossTxt.replace(/\s+/g, ' ').slice(0, 100), FX('aicrypto'));
  await tab(pg, 'ai'); await sleep(400); fin.infos.push({ id: 'E7 info: AI selection after returning to the AI tab', detail: (await txt(pg, '#otai-detail')).replace(/\s+/g, ' ').slice(0, 160) });
  await pg.click('#ot-top-end'); let ended = true; try { await pg.waitFor(`document.getElementById('ot-ended-note')`, 15000); } catch { ended = false; }
  O('DA-16', 'E7 End session (real click) shows the ended note', ended, '', FX('aicrypto'));
  });
  // ---------------------------------------------------------------- unsupp: E3 (+ E7 part 2)
  await step('unsupp E3/E7', async () => {
  await scanFresh(pg, 'unsupp'); await noteVp(pg, 'unsupp');
  const idn = JSON.stringify((await state(pg)).analysis?.identity || {});
  await tab(pg, 'ai'); await sleep(700); const uai = (await aiApi(pg)).body; const aiPanel = await txt(pg, '#ot-tabpanel'); const aiCards = await count(pg, '#otai-svg g[data-otai-select^=asset], #otai-list .otai-list-row');
  await tab(pg, 'crypto'); await sleep(700); const ucr = (await crApi(pg)).body; const crPanel = await txt(pg, '#ot-tabpanel'); const crCards = await count(pg, '#otc-svg g[data-otc-select^=asset], #otc-list .otc-list-row');
  const noSrc = (b) => producerRows(b).every(([i]) => !i.startsWith('opentrace-source-'));
  O('DA-07', 'E3 negative/unsupported: no opentrace-source-* producer in either tab; both totals 0; no asset card; none of the unsupported forms appears', noSrc(uai) && noSrc(ucr) && uai.filter_totals.all === 0 && ucr.filter_totals.all === 0 && aiCards === 0 && crCards === 0 && !/onnxruntime|openvino|tensorrt|HS256|chat\/completions/.test(aiPanel + crPanel), JSON.stringify({ ai: producerRows(uai), cr: producerRows(ucr), aiCards, crCards }), FX('unsupp'));
  O('DA-16', 'E7 a new scan of unsupp shows no tflite_runtime anywhere and the store identity names unsupp', /unsupp/.test(idn) && !/tflite_runtime/.test(await ev(pg, 'document.body.innerText')), idn.slice(0, 160), FX('unsupp'));
  });
  // ---------------------------------------------------------------- partial: E4
  await step('partial E4', async () => {
  await scanFresh(pg, 'partial'); await noteVp(pg, 'partial'); await tab(pg, 'ai'); await sleep(800); const pai = (await aiApi(pg)).body; const pPanel = await txt(pg, '#ot-tabpanel');
  O('DA-08', 'E4 partial: opentrace-source-ai outcome partial, availability partial, exactly the onnxruntime runtime, the panel says the collection was incomplete', hasProducer(pai, 'opentrace-source-ai', 'partial') && pai.availability.state === 'partial' && JSON.stringify(namesOf(pai)) === JSON.stringify(['onnxruntime']) && /incomplete/i.test(pPanel), JSON.stringify({ p: producerRows(pai), names: namesOf(pai) }), FX('partial'));
  });
  // ---------------------------------------------------------------- bounds: E10
  await step('bounds E10', async () => {
  await scanFresh(pg, 'bounds'); await noteVp(pg, 'bounds'); await tab(pg, 'ai'); await sleep(900); const bai = (await aiApi(pg)).body; const bPanel = await txt(pg, '#ot-tabpanel');
  O('DA-21', 'E10 AI bounds: partial; 500 services recorded of 520; page shows 30 and is truncated; the panel states 500', hasProducer(bai, 'opentrace-source-ai', 'partial') && bai.availability.state === 'partial' && bai.filter_totals.all === 500 && bai.counts.shown === 30 && bai.counts.truncated === true && /500/.test(bPanel), JSON.stringify({ ft: bai?.filter_totals, counts: bai?.counts, p: producerRows(bai) }), FX('bounds'));
  const rng0 = await txt(pg, '.otai-pager span'); const nextSel = '.otai-pager [data-otai-page="1"]:not([disabled])'; const hasNext = (await count(pg, nextSel)) > 0; if (hasNext) await pg.click(nextSel); await sleep(900); const rng1 = await txt(pg, '.otai-pager span');
  O('DA-21', 'E10 AI paging: a real click on the pager moves to the next bounded range (the range text changes; the total stays 500)', hasNext && rng0 !== rng1 && /31–60 of 500/.test(rng1), JSON.stringify({ rng0: rng0.replace(/\s+/g, ' ').slice(0, 60), rng1: rng1.replace(/\s+/g, ' ').slice(0, 60) }), FX('bounds'));
  await tab(pg, 'crypto'); await sleep(900); const bcr = (await crApi(pg)).body; O('DA-21', 'E10 Crypto bounds: the source producer is partial and the panel says the collection was incomplete', hasProducer(bcr, 'opentrace-source-crypto', 'partial') && /incomplete/i.test(await txt(pg, '#ot-tabpanel')), JSON.stringify(producerRows(bcr)), FX('bounds'));
  });
  // ---------------------------------------------------------------- collector fault isolation: E11
  await step('faults E11', async () => {
  await scanFresh(pg, 'aifault'); await noteVp(pg, 'aifault'); await tab(pg, 'ai'); await sleep(800); const fai = (await aiApi(pg)).body; const fAiPanel = await txt(pg, '#ot-tabpanel'); await tab(pg, 'crypto'); await sleep(800); const fcr = (await crApi(pg)).body;
  O('DA-08', 'E11 aifault: the AI source producer is failed, availability partial and the panel says incomplete; the other collector and hashlib are intact (Crypto completed with HS256 and sha256)', hasProducer(fai, 'opentrace-source-ai', 'failed') && fai.availability.state === 'partial' && /incomplete/i.test(fAiPanel) && fcr.availability.state === 'completed' && namesOf(fcr).includes('HS256') && namesOf(fcr).includes('sha256'), JSON.stringify({ ai: producerRows(fai), crState: fcr?.availability?.state, crNames: namesOf(fcr) }), FXI('aifault'));
  await scanFresh(pg, 'cryptofault'); await noteVp(pg, 'cryptofault'); await tab(pg, 'crypto'); await sleep(800); const gcr = (await crApi(pg)).body; await tab(pg, 'ai'); await sleep(800); const gai = (await aiApi(pg)).body;
  O('DA-07', 'E11 cryptofault: the Crypto source producer is partial with sha256 present and HS256 absent; the AI source producer is completed with onnxruntime', hasProducer(gcr, 'opentrace-source-crypto', 'partial') && namesOf(gcr).includes('sha256') && !namesOf(gcr).includes('HS256') && hasProducer(gai, 'opentrace-source-ai', 'completed') && namesOf(gai).includes('onnxruntime'), JSON.stringify({ cr: producerRows(gcr), crNames: namesOf(gcr), ai: producerRows(gai), aiNames: namesOf(gai) }), FXI('cryptofault'));
  });
  const asst = pg.log.requests.filter((r) => /\/api\/assistant/.test(r.url));
  O('DA-17', 'E0 no assistant request, no non-loopback request in F1 aicrypto..cryptofault', asst.length === 0 && c.st.log.blocked.length === 0, JSON.stringify({ assistantRequests: asst.length, blocked: c.st.log.blocked.length }), R());
  await hygiene('F1', c); await c.dispose();
  // ---------------------------------------------------------------- E5 cbomfail through the one-click Scan (own context)
  const c5 = await openCase(chrome.browser, {}); const p5 = c5.pg;
  await step('cbomfail E5', async () => { await p5.goto(base); await scanReady(p5); await noteVp(p5, 'cbomfail'); await setUrl(p5, 'https://github.com/acme/cbomfail'); await p5.click('#ot-scan');
  let failedShown = true; try { await p5.waitFor(`document.querySelector('.ot-scan-outcome[data-kind=failed]')`, 90000); } catch { failedShown = false; }
  const ft = await txt(p5, '#ot-scan-status'); const st5 = await state(p5);
  O('DA-02', 'E5 cbomfail: failed outcome names the failed stage and that the Workbench was not opened; finished steps do not mean success; not handed off; Scan available; no path or exception text', failedShown && /CBOM[^.]*cdxgen[^.]*failed, so the Workbench was not opened/i.test(ft) && /Steps that finished do not mean the scan succeeded/i.test(ft) && st5.destination !== 'workbench' && !(await ev(p5, "document.getElementById('ot-scan').disabled")) && !/\/(private|tmp|Users|var)\/|Traceback|Error:/.test(ft), ft.replace(/\s+/g, ' ').slice(0, 260), FX('cbomfail'));
  fin.scenarios.e5 = { text: ft.replace(/\s+/g, ' ').slice(0, 300), destination: st5.destination };
  });
  try { await hygiene('F1 cbomfail', c5); } catch { /* recorded elsewhere */ } try { await c5.dispose(); } catch { /* ignore */ }
  // ---------------------------------------------------------------- closure body D3 on modelsupp (captures first, then T, then R: unchanged), then E9
  await D3(base);
  await E9(base);
}
// E9: a SEPARATE observation of End-session reachability (it never replaces R1). Frozen: after a real node click record scrollY, the End rect and the hit-test; scroll to top; hit-test; real click on End; pass = hit at scrollY 0 is End AND the ended note appears within 10 s.
async function E9(base) {
  const c = await openCase(chrome.browser, { hook: false }); const { pg } = c; const R = () => ctxOf('real-server', { fixture: 'stage4_completion_service.py repo "modelsupp" (synthetic; REAL server projections)' });
  try {
    await pg.goto(base); await windowSize(c, pg, 1366, 900); await scanReady(pg); await scanRepo(pg, 'modelsupp', true); await noteVp(pg, 'E9');
    await ev(pg, `document.querySelector('[data-action=bom-view][data-view=ai]').click()`); await settled(pg, 'ai'); const items = (await queueOf(pg)).items; const sup = items.find((i) => i.kind === 'model_reference' || i.family === 'ai_model') || items[0];
    await ev(pg, `document.querySelector('[data-action=bom-select][data-id=${JSON.stringify(sup.item_id)}]').click()`); await settle(pg, `window.__otStore.get().bom8.graph?.scope?.candidate_id===${JSON.stringify(sup.item_id)}`);
    await sleep(900); const SEL = '[data-bom-cy="inline"]';
    await ev(pg, `document.querySelector(${JSON.stringify(SEL)}).scrollIntoView({block:'center',behavior:'instant'});0`); await sleep(500);   // harness-only correction (rerun): the graph host must be in view to receive a real click; the frozen predicate is unchanged
    const pts = await ev(pg, `(()=>{const h=document.querySelector(${JSON.stringify(SEL)});const r=h.getBoundingClientRect();return h._cy.nodes().map((n)=>{const q=n.renderedPosition();return {x:r.x+q.x,y:r.y+q.y,ok:q.x>6&&q.y>6&&q.x<r.width-6&&q.y<r.height-6}}).filter((p)=>p.ok&&p.y>0&&p.y<innerHeight)})()`);
    if (pts.length) { await pg.send('Input.dispatchMouseEvent', { type: 'mouseMoved', x: pts[0].x, y: pts[0].y }); await pg.send('Input.dispatchMouseEvent', { type: 'mousePressed', x: pts[0].x, y: pts[0].y, button: 'left', clickCount: 1 }); await pg.send('Input.dispatchMouseEvent', { type: 'mouseReleased', x: pts[0].x, y: pts[0].y, button: 'left', clickCount: 1 }); await sleep(700); }
    const HIT = `(()=>{const b=document.getElementById('ot-top-end');const r=b?b.getBoundingClientRect():null;const e=r&&r.width?document.elementFromPoint(r.x+r.width/2,r.y+r.height/2):null;return {scrollY:Math.round(scrollY),endRect:r?{x:Math.round(r.x),y:Math.round(r.y),w:Math.round(r.width),h:Math.round(r.height)}:null,hit:e?(e.id||e.dataset?.action||e.tagName):null,hitIsEnd:!!e&&(e===b||b.contains(e))}})()`;
    const afterClick = await ev(pg, HIT); await ev(pg, 'window.scrollTo(0,0)'); await sleep(400); const atTop = await ev(pg, HIT);
    await pg.click('#ot-top-end'); let ended = false; const t0 = Date.now(); try { await pg.waitFor("document.getElementById('ot-ended-note')", 10000); ended = true; } catch { /* observed */ }
    fin.e9 = { nodeClicked: pts.length > 0, afterNodeClick: afterClick, atScrollTop: atTop, endedWithin10s: ended, ms: ended ? Date.now() - t0 : null, note: 'a separate observation; the original R1 result is preserved unchanged' };
    console.log('E9', JSON.stringify(fin.e9));
    rec.note(`E9 INFO: after a real node click scrollY=${afterClick.scrollY} hit=${afterClick.hit} hitIsEnd=${afterClick.hitIsEnd}`, true, JSON.stringify(afterClick.endRect));
    O('DA-16', 'E9 normal End-session reachability: at scrollY 0 the hit-test returns End and a real click shows the ended note within 10 s (a separate observation; the original R1 failure is preserved)', pts.length > 0 && atTop.hitIsEnd && ended, JSON.stringify(fin.e9).slice(0, 380), R());
  } catch (e) { if (e.message === 'DEADLINE') throw e; rec.note('E9 aborted before its assertions (preserved as observed)', false, String(e.message).slice(0, 300)); fin.e9 = { aborted: String(e.message).slice(0, 300) }; }
  await hygiene('E9', c); await c.dispose();
}

// ================================================================= X: closing extension (phases X on the offline Demo service, P7, X6; ledger allowance_extension.json)
// EXPECTATIONS FROZEN BEFORE LAUNCH in .context/stage4-prep/EXTENSION_FROZEN_EXPECTATIONS.md. Failed predicates are preserved as observed; nothing is retried or relabelled.
// X1 is the C22M diagnostic; it never changes or replaces the original C22M FAIL of the closing campaign (final-assistant).
const STEPS = (process.argv.find((a) => a.startsWith('--steps=')) || '').slice(8).split(',').filter(Boolean);   // rerun only: restrict the X phase to named sub-steps (e.g. X1d,X3,X4); default = all
const want = (id) => !STEPS.length || STEPS.includes(id);
const ext = { viewports: [], x1: { trials: [], notes: [] }, x2: null, x3: null, x4: null, x5: null, x6: [] };
const PAN_INSTALL2 = `(()=>{window.__pan={ev:[]};if(!window.__panL){window.__panL=(e)=>{const P=window.__pan;if(!P||P.ev.length>800)return;P.ev.push({t:e.type,x:Math.round(e.clientX),y:Math.round(e.clientY),b:e.buttons,trusted:e.isTrusted,sx:Math.round(e.screenX),sy:Math.round(e.screenY)})};for(const t of ['pointerdown','pointermove','pointerup','mousedown','mousemove','mouseup'])document.addEventListener(t,window.__panL,true)}return true})()`;
const PAN_CAM = `(()=>{const h=document.querySelector('[data-bom-cy="inline"]');const c=h&&h._cy;return c?{px:c.pan().x,py:c.pan().y,z:c.zoom(),sel:c.$(':selected').length}:null})()`;
const PAN_POINTS2 = (margin = 40) => `(()=>{const h=document.querySelector('[data-bom-cy="inline"]');if(!h||!h._cy)return [];h.scrollIntoView({block:'center',behavior:'instant'});const cy=h._cy;const r=h.getBoundingClientRect();const bbs=cy.nodes().map((n)=>n.renderedBoundingBox());const ok=(x,y)=>bbs.every((b)=>x<b.x1-${margin}||x>b.x2+${margin}||y<b.y1-${margin}||y>b.y2+${margin});const out=[];
  for(let y=20;y<r.height-20;y+=10)for(let x=20;x<r.width-300;x+=10){if(!ok(x,y)||!ok(x+40,y+25))continue;const px=r.x+x,py=r.y+y;const e=document.elementFromPoint(px,py);if(e&&h.contains(e))out.push({x:px,y:py})}return out})()`;
async function dragTrial(pg, start, { inject = null, tail = 0 } = {}) {
  try { await pg.send('Page.bringToFront'); } catch { /* best effort */ }
  { let last = null, same = 0; const t0 = Date.now(); while (same < 4 && Date.now() - t0 < 6000) { const k = JSON.stringify(await ev(pg, PAN_CAM)); same = k === last ? same + 1 : 0; last = k; await sleep(150); } }   // S4XR-07: the camera must be settled before a drag
  await ev(pg, PAN_INSTALL2); const p0 = await ev(pg, PAN_CAM); const mv = (type, x, y, extra = {}) => pg.send('Input.dispatchMouseEvent', { type, x, y, ...extra });
  const end = { x: start.x + 40, y: start.y + 25 }; const sent = [{ x: start.x, y: start.y }];
  await mv('mouseMoved', start.x, start.y); await mv('mousePressed', start.x, start.y, { button: 'left', clickCount: 1 });
  for (let i = 1; i <= 5; i++) { const x = start.x + 40 * i / 5, y = start.y + 25 * i / 5; sent.push({ x, y }); await mv('mouseMoved', x, y, { button: 'left', buttons: 1 }); }
  if (inject) { sent.push(inject); await mv('mouseMoved', inject.x, inject.y, { buttons: 0 }); }
  sent.push(end); await mv('mouseReleased', end.x, end.y, { button: 'left', clickCount: 1 }); await sleep(300); const p1 = await ev(pg, PAN_CAM);
  let p2 = p1; if (tail) { for (let i = 1; i <= tail; i++) { sent.push({ x: end.x + 30 * i, y: end.y + 10 * i }); await mv('mouseMoved', end.x + 30 * i, end.y + 10 * i, { buttons: 0 }); } await sleep(300); p2 = await ev(pg, PAN_CAM); }
  const evs = (await ev(pg, 'window.__pan.ev')) || []; const known = (e) => sent.some((s) => Math.abs(s.x - e.x) <= 1.5 && Math.abs(s.y - e.y) <= 1.5);
  const strays = evs.filter((e) => /move/.test(e.t) && !known(e)).map((e) => ({ t: e.t, x: e.x, y: e.y, b: e.b, sx: e.sx, sy: e.sy }));
  return { start, end, inject, delta: { dx: p1.px - p0.px, dy: p1.py - p0.py }, afterTail: tail ? { dx: p2.px - p1.px, dy: p2.py - p1.py } : null, zoomSame: p1.z === p0.z, strays, nEvents: evs.length };
}
const near = (d, ex, ey, tol = 1) => Math.abs(d.dx - ex) <= tol && Math.abs(d.dy - ey) <= tol;
async function X1(c, R) {
  const { pg } = c; const host = '[data-bom-cy="inline"]';
  const attempt = async (name, expect, opts = {}, margin = 40) => {                  // a trial with a stray (non-dispatched) pointer event during the drag is recorded and repeated up to 3 times; ALL attempts are kept
    const atts = []; let good = null;
    for (let k = 0; k < 3; k++) { guard(); const pts = await ev(pg, PAN_POINTS2(margin)); if (!pts.length) { atts.push({ noClearPoints: true, margin }); break; } const s = pts[Math.min(pts.length - 1, (k + 1) * 7)]; const t = await dragTrial(pg, s, opts); atts.push(t); if (!t.strays.length) { good = t; break; } }
    ext.x1.trials.push({ name, attempts: atts, clean: !!good }); return { atts, good };
  };
  await pg.goto(base0); await windowSize(c, pg, 1366, 900); await pg.waitFor("document.getElementById('ot-demo')", 20000); await ev(pg, "document.getElementById('ot-demo').click()"); await mapReady(pg); await tab(pg, 'bom');
  await settle(pg, `window.__otStore.get().bom8.queue?.items?.length > 0`);   /* S4XR-01: stay in the default Focused-gaps view (the Demo has no AI/crypto candidates) */ await sleep(600);
  await settle(pg, `document.querySelector(${JSON.stringify(host)})?._cy?.nodes().length > 0`, 20000).catch(() => {});
  const rows = await ev(pg, "[...document.querySelectorAll('[data-action=bom-select]')].map((b)=>b.dataset.id)"); if (rows.length) { await pg.click(`[data-action=bom-select][data-id=${JSON.stringify(rows[0])}]`); await sleep(1200); }
  ext.viewports.push({ phase: 'X1', ...(await winSize(pg)) }); const sel0 = await ev(pg, PAN_CAM);
  // (a) controls: clean drags pan 1:1
  if (want('X1a')) {
  const c1 = await attempt('control-1 (candidate selected)', [40, 25]); O('DA-18', 'X1a control drag 1 (candidate selected): camera moves exactly the 1:1 drag delta (no stray pointer events during the drag)', !!c1.good && near(c1.good.delta, 40, 25) && c1.good.zoomSame, JSON.stringify(c1.atts.map((a) => ({ d: a.delta, strays: a.strays?.length }))).slice(0, 300), R());
  const c2 = await attempt('control-2 (candidate selected, second drag, different start)', [40, 25]); O('DA-18', 'X1a control drag 2 (the v3 "selected-alt" configuration): 1:1', !!c2.good && near(c2.good.delta, 40, 25) && c2.good.zoomSame, JSON.stringify(c2.atts.map((a) => ({ d: a.delta, strays: a.strays?.length }))).slice(0, 300), R());
  }
  if (want('X1b')) {
  // (b) reproduction of the measured mechanism: ONE interleaved no-button pointer position during an in-progress drag
  const pts = await ev(pg, PAN_POINTS2()); const s = pts[Math.min(pts.length - 1, 5)]; const far = { x: s.x + 439, y: s.y + 137 };
  const rp = await dragTrial(pg, s, { inject: far });
  ext.x1.trials.push({ name: 'reproduction: interleaved no-button pointer at +(439,137) before release', attempts: [rp], clean: rp.strays.length === 0 });
  O('DA-18', 'X1b mechanism: with one interleaved no-button pointer position during the drag the camera follows that position (delta = +(439,137) +-1), reproducing the v3 selected-alt jump from input geometry alone', near(rp.delta, 439, 137) && rp.strays.length === 0, JSON.stringify({ delta: rp.delta, strays: rp.strays.length }), R());
  }
  if (want('X1c')) {
  // (c) after the button is released, no-button pointer movement does not pan
  const pts3 = await ev(pg, PAN_POINTS2()); const rc = await dragTrial(pg, pts3[Math.min(pts3.length - 1, 9)], { tail: 3 });
  ext.x1.trials.push({ name: 'after release, no-button moves', attempts: [rc], clean: rc.strays.length === 0 });
  O('DA-18', 'X1c after release, further no-button pointer movement does not pan (drag ended)', !rc.strays.length && near(rc.delta, 40, 25) && rc.afterTail && Math.abs(rc.afterTail.dx) < 1 && Math.abs(rc.afterTail.dy) < 1, JSON.stringify({ d: rc.delta, tail: rc.afterTail, strays: rc.strays.length }), R());
  }
  if (want('X1d')) {
  // (d) the v3 matrix configurations (selected x2 above; cleared x2 in the Full evidence graph view) on clean input
  await ev(pg, `document.querySelector('[data-action="bom-view"][data-view="full"]')?.click()`); await settle(pg, `window.__otStore.get().bom8.view==='full' && document.querySelector(${JSON.stringify(host)})?._cy?.nodes().length > 0`, 20000).catch(() => {}); await sleep(900);
  await ev(pg, `document.querySelector('[data-action="bom-group"]')?.click()`); await sleep(900);
  const d1 = await attempt('cleared-1 (Full evidence graph, no record selected)', [40, 25], {}, 12); const d2 = await attempt('cleared-2', [40, 25], {}, 12);   // harness-only (rerun): the Full graph fills the host, so the clearance around nodes is 12 px instead of 40 px
  O('DA-18', 'X1d cleared-state drags (two) pan 1:1 on clean input', !!d1.good && !!d2.good && near(d1.good.delta, 40, 25) && near(d2.good.delta, 40, 25), JSON.stringify([d1, d2].map((x) => x.atts.map((a) => ({ d: a.delta, strays: a.strays?.length })))).slice(0, 300), R());
  }
  ext.x1.notes.push({ clean_attempts_total: ext.x1.trials.reduce((n, t) => n + t.attempts.length, 0), strays_seen: ext.x1.trials.reduce((n, t) => n + t.attempts.filter((a) => a.strays?.length).length, 0), sel0 });
}
const FOUR_Q = ['What is this?', 'Why is it here?', 'Is there a security concern?', 'What remains unknown?'];
async function X2(c, R) {                                                // DA-09: queue paging, search focus/caret, scroll preservation
  const { pg } = c; await pg.goto(base0); await pg.waitFor("document.getElementById('ot-demo')", 20000); await ev(pg, "document.getElementById('ot-demo').click()"); await mapReady(pg); await tab(pg, 'bom');
  await settle(pg, `window.__otStore.get().bom8.queue?.items?.length > 0 && !window.__otStore.get().bom8.req.queue`, 30000); await sleep(500);
  const q0 = await queueOf(pg); const total = q0.counts.filtered_total ?? q0.counts.candidates_total; const ids0 = (await ev(pg, "[...document.querySelectorAll('[data-action=bom-select]')].map((b)=>b.dataset.id)"));
  const pgTxt = () => txt(pg, '.ot-bom8-queue .ot-pager span'); const next = '.ot-bom8-queue [data-action=bom-page][data-dir="1"]'; const prev = '.ot-bom8-queue [data-action=bom-page][data-dir="-1"]';
  O('DA-09', `X2 page 1 shows 1-25 of the server total (${total}) and Previous is disabled`, /^1[–-]25 of /.test((await pgTxt()).replace(/\s+/g, ' ').trim()) && (await ev(pg, `document.querySelector(${JSON.stringify(prev)}).disabled`)) && ids0.length === 25, (await pgTxt()), R());
  await pg.click(next); await sleep(1200); const ids1 = await ev(pg, "[...document.querySelectorAll('[data-action=bom-select]')].map((b)=>b.dataset.id)"); const t1 = (await pgTxt()).replace(/\s+/g, ' ').trim();
  O('DA-09', 'X2 Next shows the second bounded range with different candidates', /^26[–-]50 of /.test(t1) && ids1.length === 25 && ids1.every((i) => !ids0.includes(i)), t1, R());
  await pg.click(next); await sleep(1200); const t2 = (await pgTxt()).replace(/\s+/g, ' ').trim(); const ids2 = await ev(pg, "[...document.querySelectorAll('[data-action=bom-select]')].map((b)=>b.dataset.id)");
  O('DA-09', `X2 Next again shows the remaining range up to the total (${total})`, new RegExp('^51[–-]' + Math.min(75, total) + ' of ').test(t2) && ids2.length === Math.min(25, Math.max(0, total - 50)), t2, R());
  await pg.click(prev); await sleep(1000); O('DA-09', 'X2 Previous returns to the previous range and the same candidates as before', (await ev(pg, "[...document.querySelectorAll('[data-action=bom-select]')].map((b)=>b.dataset.id)")).join() === ids1.join(), (await pgTxt()), R());
  // search: focus and caret survive the refresh; the list is the server's filtered list
  await pg.click('#ot-bom8-q'); await pg.type('#ot-bom8-q', 'pe'); await sleep(1500); const sf = await ev(pg, `(()=>{const e=document.getElementById('ot-bom8-q');return {active:document.activeElement===e,value:e.value,caret:e.selectionStart,end:e.selectionEnd}})()`); const q1 = await queueOf(pg);
  O('DA-09', 'X2 typing in search keeps focus and the caret after the list refreshes', sf.active && sf.value === 'pe' && sf.caret === 2 && sf.end === 2, JSON.stringify(sf), R());
  const shown = await ev(pg, "document.querySelectorAll('[data-action=bom-select]').length"); const ftot = await ev(pg, 'window.__otStore.get().bom8.queue.counts.filtered_total'); O('DA-09', 'X2 the search result count equals the server filtered total (bounded by the page size)', shown === Math.min(25, ftot) && ftot <= total && ftot > 0, JSON.stringify({ shown, filtered: ftot, total }), R());
  await ev(pg, "(()=>{const e=document.getElementById('ot-bom8-q');e.value='';e.dispatchEvent(new Event('input',{bubbles:true}))})()"); await sleep(1500);
  // scroll position of the queue survives selecting a row (real click)
  const sc = await ev(pg, `(()=>{const s=document.querySelector('[data-scroll-key=bom8queue]');if(!s)return null;s.scrollTop=Math.min(240,s.scrollHeight-s.clientHeight);return {top:s.scrollTop,scrollable:s.scrollHeight>s.clientHeight}})()`);
  const rowId = await ev(pg, "(()=>{const s=document.querySelector('[data-scroll-key=bom8queue]');s.scrollIntoView({block:'center',behavior:'instant'});const q=s.getBoundingClientRect();const rows=[...s.querySelectorAll('[data-action=bom-select]')].map((b)=>({b,r:b.getBoundingClientRect()})).filter((o)=>o.r.top>q.top+10&&o.r.bottom<q.bottom-10&&o.r.top>=0&&o.r.bottom<=innerHeight);rows.sort((a,b)=>Math.abs(a.r.top+a.r.height/2-(q.top+q.height/2))-Math.abs(b.r.top+b.r.height/2-(q.top+q.height/2)));return rows.length?{id:rows[0].b.dataset.id,x:rows[0].r.x+rows[0].r.width/2,y:rows[0].r.y+rows[0].r.height/2}:null})()");
  if (rowId) { const sc0 = await ev(pg, "document.querySelector('[data-scroll-key=bom8queue]').scrollTop"); await pg.send('Input.dispatchMouseEvent', { type: 'mouseMoved', x: rowId.x, y: rowId.y }); await pg.send('Input.dispatchMouseEvent', { type: 'mousePressed', x: rowId.x, y: rowId.y, button: 'left', clickCount: 1 }); await pg.send('Input.dispatchMouseEvent', { type: 'mouseReleased', x: rowId.x, y: rowId.y, button: 'left', clickCount: 1 }); await sleep(1200); const top2 = await ev(pg, "document.querySelector('[data-scroll-key=bom8queue]')?.scrollTop"); O('DA-09', 'X2 selecting a visible row keeps the queue scroll position (+-2 px)', !!sc && sc.scrollable && Math.abs(top2 - sc0) <= 2 && sc0 > 0, JSON.stringify({ before: sc, beforeClick: sc0, after: top2 }), R()); }
  else O('DA-09', 'X2 selecting a visible row keeps the queue scroll position', false, 'no scrollable/visible row precondition: ' + JSON.stringify(sc), R());
  ext.x2 = { total, ids0: ids0.length };
}
async function X3(c, R) {                                                // DA-11: shared-record chooser and restoration
  const { pg } = c; await pg.goto(base0); await pg.waitFor("document.getElementById('ot-demo')", 20000); await ev(pg, "document.getElementById('ot-demo').click()"); await mapReady(pg); await tab(pg, 'bom');
  await settle(pg, `window.__otStore.get().bom8.queue?.items?.length > 0 && !window.__otStore.get().bom8.req.queue`, 30000); await settle(pg, `document.querySelector('[data-bom-cy="inline"]')?._cy?.nodes().length > 0 && !window.__otStore.get().bom8.req.graph`, 30000).catch(() => {}); await sleep(600);   // harness-only (rerun): wait for the initial Focused-gaps graph before switching view
  await ev(pg, `document.querySelector('[data-action="bom-view"][data-view="full"]').click()`);
  try { await settle(pg, `window.__otStore.get().bom8.view==='full' && window.__otStore.get().bom8.graph?.scope.kind==='full_view' && document.querySelector('[data-bom-cy="inline"]')?._cy?.nodes().length > 0`, 45000); } catch (e) { ext.x3 = { diag: await ev(pg, '({view:window.__otStore.get().bom8.view,scope:window.__otStore.get().bom8.graph?.scope?.kind,req:window.__otStore.get().bom8.req,hosts:document.querySelectorAll("[data-bom-cy]").length,err:window.__otStore.get().bom8.error||null})') }; throw e; }
  await sleep(800);
  const ids = await ev(pg, `document.querySelector('[data-bom-cy="inline"]')._cy.nodes().map((n)=>n.id())`); let found = null; const tried = [];
  await ev(pg, `(()=>{const s=document.querySelector('[data-scroll-key=bom8queue]');if(s)s.scrollTop=Math.min(120,s.scrollHeight-s.clientHeight);return 0})()`); await sleep(600); const before = { cam: await ev(pg, PAN_CAM), q: await ev(pg, "document.getElementById('ot-bom8-full-q')?.value||''"), scroll: await ev(pg, "document.querySelector('[data-scroll-key=bom8queue]')?.scrollTop||0") };   // S4XR-06: the restoration baseline (camera, graph search text, queue scroll) is captured BEFORE any chooser is opened
  for (const id of ids.slice(0, 60)) { guard(); await ev(pg, `document.querySelector('[data-bom-cy="inline"]')._cy.getElementById(${JSON.stringify(id)}).emit('tap');0`); await sleep(500); const st = await ev(pg, '({popup:window.__otStore.get().bom8.popup, res:window.__otStore.get().bom8.related?.resolution})'); tried.push(st.res || st.popup || null); if (st.popup === 'chooser') { found = id; break; } if (await ev(pg, '!!window.__otStore.get().bom8.popup')) await pg.key('Escape'); }
  ext.x3 = { nodesTried: tried.length, resolutions: [...new Set(tried)], chooserFound: !!found };
  if (!found) { O('DA-11', 'X3 a shared record opens the bounded chooser', false, `precondition unmet: no tapped node resolved to "multiple" among ${tried.length} nodes (resolutions seen: ${[...new Set(tried)].join(',')}); the Demo may hold no shared record`, R()); return; }
  const rel = await ev(pg, "document.querySelectorAll('.ot-bom8-overlay [data-action=bom-related]').length"); const total = await ev(pg, 'window.__otStore.get().bom8.related?.related_total');   // (the before-state was captured BEFORE the tap loop)
  O('DA-11', 'X3 the chooser lists the related checks of the shared record, bounded by its page, with the total stated', rel >= 2 && rel <= 25 && total >= rel, JSON.stringify({ listed: rel, total }), R());
  await pg.key('Escape'); await sleep(500); const after = { cam: await ev(pg, PAN_CAM), q: await ev(pg, "document.getElementById('ot-bom8-full-q')?.value||''"), scroll: await ev(pg, "document.querySelector('[data-scroll-key=bom8queue]')?.scrollTop||0"), popup: await ev(pg, 'window.__otStore.get().bom8.popup') };
  O('DA-11', 'X3 Escape closes the chooser and restores the camera, graph search text and queue scroll', !after.popup && Math.abs(after.cam.px - before.cam.px) < 1 && Math.abs(after.cam.py - before.cam.py) < 1 && after.cam.z === before.cam.z && after.q === before.q && Math.abs(after.scroll - before.scroll) <= 2, JSON.stringify({ before, after }).slice(0, 360), R());
}
async function X3r(c, R) {                                              // INFO only: does clicking "Full evidence graph" while the initial Focused-gaps graph request may still be in flight ever produce the Full graph? (hypothesis for the ext-1 X3 timeout; S4XR3-05)
  const { pg } = c; await pg.goto(base0); await pg.waitFor("document.getElementById('ot-demo')", 20000); await ev(pg, "document.getElementById('ot-demo').click()"); await mapReady(pg); await tab(pg, 'bom');
  await settle(pg, `window.__otStore.get().bom8.queue?.items?.length > 0`, 30000);
  const atClick = await ev(pg, '({view:window.__otStore.get().bom8.view,req:window.__otStore.get().bom8.req,graphScope:window.__otStore.get().bom8.graph?.scope?.kind||null})');
  await ev(pg, `document.querySelector('[data-action="bom-view"][data-view="full"]').click()`); let arrived = true; try { await settle(pg, `window.__otStore.get().bom8.graph?.scope.kind==='full_view'`, 20000); } catch { arrived = false; }
  const after = await ev(pg, '({view:window.__otStore.get().bom8.view,req:window.__otStore.get().bom8.req,graphScope:window.__otStore.get().bom8.graph?.scope?.kind||null})');
  ext.x3r = { atClick, fullGraphArrivedWithin20s: arrived, after }; rec.note(`X3r INFO (not a pass criterion): immediate Full click after the queue loaded: full graph arrived=${arrived}`, true, JSON.stringify(ext.x3r).slice(0, 380));
}
async function X4(c, R) {                                                // DA-13: downloaded-artifact hash equality; I5C source-backed check presence
  const { pg } = c; await pg.goto(base0); await pg.waitFor("document.getElementById('ot-demo')", 20000); await ev(pg, "document.getElementById('ot-demo').click()"); await mapReady(pg); await ev(pg, "document.querySelector('[data-nav=evidence]').click()"); await sleep(1200);
  const arts = await ev(pg, `window.__otStore.get().evidence.artifacts.map((a)=>({name:a.name,size:a.size,sha256:a.sha256}))`);
  const res = await ev(pg, `(async()=>{const out=[];for(const a of window.__otStore.get().evidence.artifacts){const r=await fetch('/api/artifacts/'+encodeURIComponent(a.name),{credentials:'same-origin'});const b=new Uint8Array(await r.arrayBuffer());const h=[...new Uint8Array(await crypto.subtle.digest('SHA-256',b))].map((x)=>x.toString(16).padStart(2,'0')).join('');out.push({name:a.name,status:r.status,bytes:b.length,sha256:h})}return out})()`);
  const shown = await ev(pg, "(document.getElementById('ot-evidence')?.textContent||'')"); const evVisible = await ev(pg, "(()=>{const e=document.getElementById('ot-evidence');return !!e&&!e.hidden&&e.getBoundingClientRect().height>0})()"); const eq = res.every((r, i) => r.status === 200 && r.bytes === arts[i].size && r.sha256 === arts[i].sha256);
  O('DA-13', `X4 every listed artifact (${arts.length}) downloaded through /api/artifacts has the byte length and SHA-256 the Evidence view lists`, arts.length > 0 && eq, JSON.stringify(res.map((r, i) => [r.name, r.status, r.bytes === arts[i].size, r.sha256 === arts[i].sha256])).slice(0, 300), R());
  O('DA-13', 'X4 the Evidence view displays the (shortened) SHA-256 of each listed artifact that has one', arts.filter((a) => a.sha256).every((a) => shown.includes(a.sha256.slice(0, 8))), JSON.stringify({ artifacts: arts.filter((a) => a.sha256).length, evVisible, textLen: shown.length, missing: arts.filter((a) => a.sha256 && !shown.includes(a.sha256.slice(0, 8))).map((a) => a.name) }), R());
  const sbc = /Source-backed check/.test(shown);
  ext.x4 = { artifacts: arts.length, sourceBackedCheckSection: sbc };
  if (sbc) { const parts = await ev(pg, "[...document.querySelectorAll('#ot-evidence [class*=sourcecheck], #ot-evidence .ot-sc-block, #ot-evidence .ot-source-block')].length"); O('DA-13', 'X4 the I5C source-backed check section is present in the Evidence view', true, 'blocks=' + parts, R()); }
  else O('DA-13', 'X4 the I5C source-backed check section is present in the Evidence view of this analysis', false, 'section absent in the Demo (Frigate) analysis: the I5C check belongs to the pinned Inspector capture; this is a precondition gap, not evidence about I5C', R());
}
async function X5(c, R) {                                                // DA-14: representative selection and inspector context for each outer tab
  const { pg } = c; await pg.goto(base0); await pg.waitFor("document.getElementById('ot-demo')", 20000); await ev(pg, "document.getElementById('ot-demo').click()"); await mapReady(pg); await sleep(600);
  const insp = () => ev(pg, "(document.querySelector('#ot-tabpanel .ot-inspector, #ot-tabpanel aside')?.innerText||'').replace(/\\s+/g,' ')");
  const four = (t) => FOUR_Q.every((q) => t.toLowerCase().includes(q.toLowerCase())); const seen = {};
  await tab(pg, 'contexts'); await mapReady(pg); const g = await ev(pg, "document.querySelector('#ot4-stage [data-ctx]')?document.querySelector('#ot4-stage [data-ctx]').getAttribute('data-ctx'):null"); if (g) { await ev(pg, "document.querySelector('#ot4-stage [data-ctx]').dispatchEvent(new MouseEvent('click',{bubbles:true}))"); await sleep(500); } seen.contexts = await insp();
  O('DA-14', 'X5 contexts: after a selection the shared inspector asks the four fixed questions', four(seen.contexts), seen.contexts.slice(0, 120), R());
  await tab(pg, 'dependencies'); await settle(pg, `document.querySelector('#ot5-svg [data-dep-node]')`); const dn = await ev(pg, "document.querySelectorAll('#ot5-svg [data-dep-node]')[1]?.getAttribute('data-dep-node')"); if (dn) { await ev(pg, "document.querySelectorAll('#ot5-svg [data-dep-node]')[1].dispatchEvent(new MouseEvent('click',{bubbles:true}))"); await sleep(500); } seen.dependencies = await insp();
  O('DA-14', 'X5 dependencies: the inspector shows the selected package context with the four fixed questions and does not carry the contexts selection', four(seen.dependencies) && seen.dependencies !== seen.contexts, seen.dependencies.slice(0, 120), R());
  for (const [t, sel, pre] of [['crypto', '#otc-svg g[role=button][data-otc-select^=asset]', 'otc'], ['ai', '#otai-svg g[role=button][data-otai-select^=asset]', 'otai']]) {
    await tab(pg, t); await sleep(900); const n = await count(pg, sel); if (n > 0) { await pg.click(`${sel}`); await sleep(500); seen[t] = await insp(); O('DA-14', `X5 ${t}: after a card selection the inspector asks the four fixed questions`, four(seen[t]), seen[t].slice(0, 120), R()); }
    else { seen[t] = await insp(); O('DA-14', `X5 ${t}: representative selection`, false, `precondition unmet: the Demo ${t} tab has no asset card (availability: ${(await txt(pg, '#ot-tabpanel')).slice(0, 80)}); the inspector shows its root context: four questions=${four(seen[t])}`, R()); }
  }
  await tab(pg, 'bom'); await settle(pg, `window.__otStore.get().bom8.queue?.items?.length > 0`); await ev(pg, "document.querySelector('[data-action=bom-select]').click()"); await sleep(1200); const bi = await txt(pg, '.ot-bom8-inspector, .ot-bom8-drawer-body'); const bomName = await ev(pg, "(document.querySelector('[data-action=bom-select][aria-pressed=true], [data-action=bom-select].selected, [data-action=bom-select]')?.innerText||'').trim().split('\\n')[0].slice(0, 30)");
  O('DA-14', 'X5 BOM: a selected candidate opens its own inspector (candidate-specific, not the earlier tab selections)', bi.length > 40 && !bi.includes(String(seen.dependencies).slice(0, 40)), bi.replace(/\s+/g, ' ').slice(0, 120), R());
  await tab(pg, 'contexts'); await sleep(500); const back = await insp(); O('DA-14', 'X5 switching back to contexts does not show the BOM selection', four(back) && bomName.length > 3 && !back.includes(bomName), JSON.stringify({ bomName, back: back.slice(0, 100) }), R());
  ext.x5 = { seen: Object.fromEntries(Object.entries(seen).map(([k, v]) => [k, v.slice(0, 160)])) };
}
let base0 = null;
async function XALL(base) {
  base0 = base; const c = await openCase(chrome.browser, {}); const R = (e) => ctxOf('real-server', { fixture: 'recorded Demo (offline service; captured Frigate case)', ...e });
  const step2 = async (name, fn) => { guard(); try { await fn(c, R); } catch (e) { if (e.message === 'DEADLINE') throw e; rec.note(`${name}: aborted before all its assertions (preserved as observed)`, false, String(e.message).slice(0, 300)); } };
  if (['X1', 'X1a', 'X1b', 'X1c', 'X1d'].some(want)) await step2('X1', X1); if (want('X2')) await step2('X2', X2); if (want('X3r')) await step2('X3r', X3r); if (want('X3')) await step2('X3', X3); if (want('X4')) await step2('X4', X4); if (want('X5')) await step2('X5', X5);
  try { await hygiene('XALL', c); } catch { /* recorded */ } try { await c.dispose(); } catch { /* ignore */ }
}
async function X6(base) {                                                // uip13 `states` on real projections (expectations copied from run_uip13_inspector.mjs `caseStates`)
  const c = await openCase(chrome.browser, {}); const { pg } = c; const R = (e) => ctxOf('real-server', { fixture: 'uip13 states (synthetic local repos; REAL server projections)', ...e }); await pg.goto(base); let first = true;
  const want = { dyn: ['partial', 0, /1 dynamic expression/], empty: ['completed_empty', 0, null], nosource: ['unsupported', 0, null], mixed: ['partial', 1, null], bigtree: ['completed', 30, null] };
  for (const [repo, [cap, n, re]] of Object.entries(want)) { guard(); try {
    await scanRepo(pg, repo, first); first = false; const q = await queueOf(pg); const got = repo === 'bigtree' ? q.counts?.family_counts?.ai_model : q.items.length;
    O('DA-08', `X6 ${repo}: ai_model capability is ${cap}`, (q.caps.ai_model || '').startsWith(cap), JSON.stringify({ caps: q.caps, got }), R());
    const gq = await gen(pg); const qa = await apiJson(pg, `/api/workbench/v1/bom-candidates?schema_version=1&generation=${gq}&family=ai_model`); const gotAi = repo === 'bigtree' ? qa.body?.counts?.family_counts?.ai_model : (qa.body?.items || []).length;   // S4XR-05: the original harness queried the ai_model family
    O('DA-08', `X6 ${repo}: the ai_model family queue has ${n} candidate(s)`, gotAi === n, String(gotAi), R());
    if (re) { await ev(pg, `document.querySelector('[data-action=bom-view][data-view=ai]').click()`); await settled(pg, 'ai'); O('DA-08', `X6 ${repo}: the dynamic-expression diagnostic is disclosed in the BOM AI view`, re.test(await ev(pg, 'document.body.innerText')), String(re), R()); }
    await tab(pg, 'ai'); await sleep(800); const g = await gen(pg); const api = (await apiJson(pg, `/api/workbench/v1/ai-assets?generation=${g}`)).body; const panel = await txt(pg, '#ot-tabpanel');
    O('DA-08', `X6 ${repo}: the AI tab shows the server availability message for its state`, !!api?.availability?.message && panel.includes(String(api.availability.message).slice(0, 40)), `${api?.availability?.state}: ${String(api?.availability?.message).slice(0, 70)}`, R());
  } catch (e) { if (e.message === 'DEADLINE') throw e; O('DA-08', `X6 ${repo}: case completed`, false, e.message.slice(0, 200), R()); } }
  await hygiene('X6', c); await c.dispose();
}

// ================================================================= Y: closing extension 2 (phases Y, YE, YN, YI; ledger allowance_extension2.json)
// EXPECTATIONS FROZEN BEFORE LAUNCH in .context/stage4-prep/EXTENSION2_FROZEN_EXPECTATIONS.md. Failed predicates are preserved as observed; the affected scenario STOPS (no search for a passing interaction).
const ext2 = { viewports: [], y1: null, y2: null, y3: null, y4: null, ye: null, yn: null, yi: null };
const DEMO_SHARED = 'entity:scope:frigate-v0.18.2-cpu-pilot::inv:curated-source-reading::inventory-syft-source-dir';   // verified OFFLINE against the production Demo handlers: a primary node of Full-graph page offset 200; bom-related-checks resolution `multiple`, related_total 75, 20 listed (the other `multiple` nodes of the Demo have 2, 2, 2 and 66 related)
const openDemoBom = async (pg, base) => { await pg.goto(base); await pg.waitFor("document.getElementById('ot-demo')", 20000); await ev(pg, "document.getElementById('ot-demo').click()"); await mapReady(pg); await tab(pg, 'bom'); await settle(pg, `window.__otStore.get().bom8.queue?.items?.length > 0 && !window.__otStore.get().bom8.req.queue`, 30000); await sleep(500); };
const qRows = (pg) => ev(pg, "[...document.querySelectorAll('[data-action=bom-select]')].map((b)=>b.dataset.id)");
const qPager = async (pg) => (await txt(pg, '.ot-bom8-queue .ot-pager span')).replace(/\s+/g, ' ').trim();
async function Y1(c, R) {                                              // DA-09: the final queue page (76-79 of 79)
  const { pg } = c; await openDemoBom(pg, base0); const total = (await queueOf(pg)).counts.filtered_total; const next = '.ot-bom8-queue [data-action=bom-page][data-dir="1"]', prev = '.ot-bom8-queue [data-action=bom-page][data-dir="-1"]'; const seen = [await qPager(pg)];
  for (let i = 0; i < 3; i++) { await pg.click(next); await sleep(1100); seen.push(await qPager(pg)); }
  const rows = await qRows(pg); const nextDisabled = await ev(pg, `document.querySelector(${JSON.stringify(next)}).disabled`);
  O('DA-09', `Y1 the pager walks 1-25 / 26-50 / 51-75 / 76-${total} of ${total} through real Next clicks`, total === 79 && seen.map((t) => t.replace(/–/g, '-')).join('|') === `1-25 of 79|26-50 of 79|51-75 of 79|76-79 of 79`, seen.join(' | '), R());
  O('DA-09', 'Y1 the final page shows exactly the remaining 4 candidates and Next is disabled', rows.length === 4 && nextDisabled === true, JSON.stringify({ rows: rows.length, nextDisabled }), R());
  await pg.click(prev); await sleep(1000); O('DA-09', 'Y1 Previous from the final page returns to 51-75 with 25 rows', /^51[–-]75 of 79$/.test(await qPager(pg)) && (await qRows(pg)).length === 25, await qPager(pg), R());
  ext2.y1 = { seen, finalRows: rows.length };
}
async function Y2(c, R) {                                              // DA-11: the recorded shared record opens the chooser; selection, Escape, Close and restoration
  const { pg } = c; await openDemoBom(pg, base0); await ev(pg, `document.querySelector('[data-action="bom-view"][data-view="full"]').click()`);
  await settle(pg, `window.__otStore.get().bom8.view==='full' && window.__otStore.get().bom8.graph?.scope.kind==='full_view' && document.querySelector('[data-bom-cy="inline"]')?._cy?.nodes().length > 0 && !window.__otStore.get().bom8.req.graph`, 45000); await sleep(800);
  const FIND = `(()=>{const h=document.querySelector('[data-bom-cy="inline"]');if(!h||!h._cy)return null;const n=h._cy.getElementById(${JSON.stringify(DEMO_SHARED)});if(!n.length)return null;h.scrollIntoView({block:'center',behavior:'instant'});const r=h.getBoundingClientRect(),q=n.renderedPosition();return {x:r.x+q.x,y:r.y+q.y,inView:q.x>4&&q.y>4&&q.x<r.width-4&&q.y<r.height-4}})()`;
  let pt = await ev(pg, FIND); const tries = ['direct'];
  for (let k = 0; !pt && k < 2; k++) { tries.push('page' + (k + 1)); await pg.click('[data-action="bom-full-page"][data-dir="1"]'); await settle(pg, `window.__otStore.get().bom8.graph?.scope.kind==='full_view' && window.__otStore.get().bom8.graph?.page.offset===${(k + 1) * 100} && !window.__otStore.get().bom8.req.graph && document.querySelector('[data-bom-cy="inline"]')?._cy?.nodes().length > 0`, 45000); await sleep(800); pt = await ev(pg, FIND); }   // real Next-window clicks, each awaited to completion (S4ZR-01)
  if (pt && !pt.inView) { await ev(pg, `document.querySelector('[data-bom-cy="inline"]')._cy.center(document.querySelector('[data-bom-cy="inline"]')._cy.getElementById(${JSON.stringify(DEMO_SHARED)}));0`); await sleep(500); pt = await ev(pg, FIND); tries.push('centered'); }   // setup only: bring the verified node into the viewport before the baseline is captured
  ext2.y2 = { tries, found: !!pt };
  if (!pt || !pt.inView) { O('DA-11', 'Y2 the verified shared record node (Full-graph page offset 200) is present and in view', false, JSON.stringify({ tries, pt }), R()); return; }     // stop: no further hunting
  await ev(pg, `(()=>{const s=document.querySelector('[data-scroll-key=bom8queue]');if(s)s.scrollTop=Math.min(120,s.scrollHeight-s.clientHeight);return 0})()`); await sleep(500);
  const snap = async () => ({ cam: await ev(pg, PAN_CAM), q: await ev(pg, "document.getElementById('ot-bom8-full-q')?.value||''"), scroll: await ev(pg, "document.querySelector('[data-scroll-key=bom8queue]')?.scrollTop||0"), popup: await ev(pg, 'window.__otStore.get().bom8.popup') });
  const same = (a, b) => !b.popup && Math.abs(a.cam.px - b.cam.px) < 1 && Math.abs(a.cam.py - b.cam.py) < 1 && a.cam.z === b.cam.z && a.q === b.q && Math.abs(a.scroll - b.scroll) <= 2;
  const base = await snap(); const open = async () => { pt = await ev(pg, FIND); const hit = await ev(pg, `(()=>{const e=document.elementFromPoint(${pt.x},${pt.y});return !!e&&!!e.closest('[data-bom-cy="inline"]')})()`); await pg.send('Input.dispatchMouseEvent', { type: 'mouseMoved', x: pt.x, y: pt.y }); await pg.send('Input.dispatchMouseEvent', { type: 'mousePressed', x: pt.x, y: pt.y, button: 'left', clickCount: 1 }); await pg.send('Input.dispatchMouseEvent', { type: 'mouseReleased', x: pt.x, y: pt.y, button: 'left', clickCount: 1 }); await sleep(900); return hit; };
  const hit = await open(); const st = await ev(pg, '({popup:window.__otStore.get().bom8.popup,res:window.__otStore.get().bom8.related?.resolution,total:window.__otStore.get().bom8.related?.related_total,listed:document.querySelectorAll(".ot-bom8-overlay [data-action=bom-related]").length})');
  O('DA-11', 'Y2 a real click on the recorded shared record opens the chooser: resolution multiple, 75 related checks, 20 listed', hit && st.popup === 'chooser' && st.res === 'multiple' && st.total === 75 && st.listed === 20, JSON.stringify({ hit, ...st }), R());
  if (st.popup !== 'chooser') return;                                   // stop this scenario: the chooser did not open
  const first = await ev(pg, "[...document.querySelectorAll('.ot-bom8-overlay [data-action=bom-related]')].map((b)=>b.dataset.id)");
  await pg.click('.ot-bom8-overlay [data-action=bom-chooser-page][data-dir="1"]'); await sleep(900); const second = await ev(pg, "[...document.querySelectorAll('.ot-bom8-overlay [data-action=bom-related]')].map((b)=>b.dataset.id)");
  O('DA-11', 'Y2 the chooser pages through the related checks (20 per page; the second page differs)', second.length === 20 && second.every((i) => !first.includes(i)), JSON.stringify({ first: first.length, second: second.length }), R());
  await pg.key('Escape'); await sleep(600); const aE = await snap(); O('DA-11', 'Y2 Escape closes the chooser and restores camera, graph search text and queue scroll', same(base, aE), JSON.stringify({ base, after: aE }).slice(0, 380), R());
  await open(); const st2 = await ev(pg, 'window.__otStore.get().bom8.popup'); await pg.click('.ot-bom8-overlay [data-action=bom-close]'); await sleep(600); const aC = await snap();
  O('DA-11', 'Y2 reopened, the Close button closes the chooser and restores camera, graph search text and queue scroll', st2 === 'chooser' && same(base, aC), JSON.stringify({ reopened: st2, after: aC }).slice(0, 380), R());
  await open(); const pick = await ev(pg, "document.querySelector('.ot-bom8-overlay [data-action=bom-related]')?.dataset.id"); await pg.click(`.ot-bom8-overlay [data-action=bom-related][data-id=${JSON.stringify(pick)}]`); await sleep(1500); const sel = await ev(pg, '({popup:window.__otStore.get().bom8.popup,selected:window.__otStore.get().bom8.selected})');
  O('DA-11', 'Y2 choosing a related check selects exactly that candidate and closes the chooser', !!pick && sel.selected === pick && !sel.popup, JSON.stringify({ pick, ...sel }), R());
}
async function Y3(c, R) {                                              // DA-13: each artifact's digest text is rendered AND individually visible (not occluded); ext-1's container-level failure is preserved separately
  const { pg } = c; await pg.goto(base0); await pg.waitFor("document.getElementById('ot-demo')", 20000); await ev(pg, "document.getElementById('ot-demo').click()"); await mapReady(pg); await ev(pg, "document.querySelector('[data-nav=evidence]').click()"); await sleep(1500);
  const arts = await ev(pg, `window.__otStore.get().evidence.artifacts.map((a)=>({name:a.name,sha256:a.sha256}))`); ext2.y3 = { artifacts: arts.length };
  for (const a of arts) { guard();
    const r = await ev(pg, `(()=>{const want='sha256 '+${JSON.stringify(a.sha256.slice(0, 12))}+'…';const els=[...document.querySelectorAll('#ot-evidence p, #ot-evidence span, #ot-evidence code, #ot-evidence dd')].filter((e)=>e.children.length===0&&(e.textContent||'').includes(want));if(!els.length)return {found:0};const e=els[0];e.scrollIntoView({block:'center',behavior:'instant'});const b=e.getBoundingClientRect(),cs=getComputedStyle(e);const top=document.elementFromPoint(b.x+b.width/2,b.y+b.height/2);return {found:els.length,text:e.textContent.trim().slice(0,80),area:Math.round(b.width*b.height),visible:cs.visibility!=='hidden'&&cs.display!=='none'&&+cs.opacity>0,inViewport:b.top>=0&&b.bottom<=innerHeight&&b.left>=0&&b.right<=innerWidth,hitIsElement:!!top&&(top===e||e.contains(top)||top.contains(e)),clippedByAncestor:(()=>{for(let p=e.parentElement;p&&p!==document.body;p=p.parentElement){const s=getComputedStyle(p);if(/(hidden|clip)/.test(s.overflowX+s.overflowY)){const pb=p.getBoundingClientRect();if(b.right>pb.right+1||b.bottom>pb.bottom+1||b.left<pb.left-1||b.top<pb.top-1)return true}}return false})()}})()`);
    O('DA-13', `Y3 ${a.name}: its own rendered "sha256 <12 hex>…" text is present once, has area, is visible, in the viewport, not clipped by an ancestor and is the element at its own centre`, r.found >= 1 && r.area > 0 && r.visible && r.inViewport && r.hitIsElement && !r.clippedByAncestor, JSON.stringify(r), R()); }
}
async function Y4(c0, R) {
  let c = c0;                                              // DA-12: conflicting_evidence / no_rule rows — FRONTEND-ONLY (two item states of the recorded production page substituted in the response)
  await c.dispose(); c = await openCase(chrome.browser, { noRouting: true }); const { pg } = c; const RA = (e) => ctxOf('adapter-synthesized', { fixture: 'recorded Demo; the bom-candidates response is SUBSTITUTED in flight (items 0,1 -> conflicting_evidence, no_rule; counts adjusted) - frontend rendering only, paired with tests/core/app/test_stage4_bom_states_production.py', ...e });
  let mutated = 0; const off = c.browser.on(async (m) => {
    if (m.sessionId !== pg.sessionId || m.method !== 'Fetch.requestPaused') return; const { requestId, responseStatusCode } = m.params;
    try {
      if (responseStatusCode === 200) { const { body, base64Encoded } = await pg.send('Fetch.getResponseBody', { requestId }); const j = JSON.parse(base64Encoded ? Buffer.from(body, 'base64').toString('utf8') : body);
        if (Array.isArray(j.items) && j.items.length >= 2 && j.counts?.state_counts && (j.page?.offset ?? 0) === 0 && j.counts.filtered_total === j.counts.candidates_total && j.items[0].state === 'contradicted' && j.items[1].state === 'contradicted') {
          j.items[0].state = 'conflicting_evidence'; j.items[1].state = 'no_rule'; j.items[0].filter_group = j.items[1].filter_group = 'unknown'; j.counts.state_counts.contradicted -= 2; j.counts.state_counts.conflicting_evidence += 1; j.counts.state_counts.no_rule += 1; j.counts.filter_group_counts.not_represented -= 2; j.counts.filter_group_counts.unknown += 2; mutated++; }
        await pg.send('Fetch.fulfillRequest', { requestId, responseCode: 200, responseHeaders: [{ name: 'Content-Type', value: 'application/json' }], body: Buffer.from(JSON.stringify(j)).toString('base64') }); }
      else await pg.send('Fetch.continueRequest', { requestId });
    } catch { try { await pg.send('Fetch.continueRequest', { requestId }); } catch { /* ignore */ } }
  });
  await pg.send('Fetch.enable', { patterns: [{ urlPattern: '*/api/workbench/v1/bom-candidates?*', requestStage: 'Response' }] });
  await openDemoBom(pg, base0); const t = await ev(pg, "[...document.querySelectorAll('[data-action=bom-select]')].slice(0,2).map((b)=>b.innerText.replace(/\\s+/g,' ').trim())"); const pills = await txt(pg, '.ot-bom8-filters'); const unk = await txt(pg, '[data-action=bom-filter][data-filter=unknown]'); const nrep = await txt(pg, '[data-action=bom-filter][data-filter=not_represented]');
  ext2.y4 = { mutated, rows: t, pills: pills.slice(0, 200) };
  O('DA-12', 'Y4 (frontend-only) the first two queue rows render the substituted states "conflicting evidence" and "no rule"', mutated >= 1 && /^[^·]*\n?[^·]*conflicting evidence/i.test(t[0] || '') && /no rule/i.test(t[1] || ''), JSON.stringify(t).slice(0, 300), RA());
  O('DA-12', 'Y4 (frontend-only) the Unknown filter group count includes both substituted candidates (10 -> 12) and Not represented decreases by two (69 -> 67)', /\b12\b/.test(unk) && /\b67\b/.test(nrep), JSON.stringify({ unk: unk.replace(/\s+/g, ' '), nrep: nrep.replace(/\s+/g, ' ') }), RA());
  try { await pg.send('Fetch.disable'); } catch { /* ignore */ } off?.();
  try { await hygiene('Y4', c); } catch { /* recorded */ } try { await c.dispose(); } catch { /* ignore */ }
}
async function YALL(base) {
  base0 = base; const c = await openCase(chrome.browser, {}); const R = (e) => ctxOf('real-server', { fixture: 'recorded Demo (offline service; captured Frigate case; production handlers)', ...e });
  const st = async (name, fn) => { guard(); try { await fn(c, R); } catch (e) { if (e.message === 'DEADLINE') throw e; rec.note(`${name}: aborted before all its assertions (preserved as observed)`, false, String(e.message).slice(0, 300)); } };
  if (want('Y1')) await st('Y1', Y1); if (want('Y2')) await st('Y2', Y2); if (want('Y3')) await st('Y3', Y3); if (want('Y4')) await st('Y4', Y4);
  try { await hygiene('Y', c); } catch { /* recorded */ } try { await c.dispose(); } catch { /* ignore */ }
}
async function YE(base) {                                              // ext fixture service: I5C (production collector with an injected target), R2-03 (production shared-input failure path, fault injected by the service), AI banner (generated / requested-not-delivered)
  const c = await openCase(chrome.browser, {}); const { pg } = c; await pg.goto(base); const R = (name, extra) => ctxOf('real-server', { fixture: `stage4_ext_service.py repo "${name}" (synthetic; production handlers; ${name === 'r203' ? 'the shared-input failure is injected by the fixture-service process' : name === 'i5c' ? 'the reviewed I5C target is injected through the documented source_check_targets seam' : 'fake scanners'})`, ...extra });
  const scan = async (repo, first) => { if (!first && (await state(pg)).analysis) await endSession(pg).catch(() => {}); await scanReady(pg); await setUrl(pg, 'https://github.com/acme/' + repo); await pg.click('#ot-scan'); await pg.waitFor(`window.__otStore.get().destination === 'workbench' || window.__otStore.get().scan?.status?.job?.state === 'failed'`, 90000); };
  const step3 = async (name, fn) => { guard(); try { await fn(); } catch (e) { if (e.message === 'DEADLINE') throw e; O('DA-13', `${name}: case completed`, false, String(e.message).slice(0, 250), R(name)); } };
  await step3('i5c', async () => {
    await scan('i5c', true); const sum = (await state(pg)).analysis.summary; await ev(pg, "document.querySelector('[data-nav=evidence]').click()"); await sleep(1500); const t = await txt(pg, '#ot-evidence'); const n = await count(pg, '#ot-evidence .ot-source-check'); const blocks = await ev(pg, "[...document.querySelectorAll('#ot-evidence .ot-source-check .ot-source-block h3')].map((h)=>h.textContent)");
    O('DA-13', 'Y-I5C the production summary holds exactly one source-backed check and the Evidence view renders its three separate blocks (Source observation, CBOM record, Rule conclusion)', (sum.source_checks || []).length === 1 && n === 1 && JSON.stringify(blocks) === JSON.stringify(['Source observation', 'CBOM record', 'Rule conclusion']) && /Source-backed check/.test(t), JSON.stringify({ checks: (sum.source_checks || []).length, n, blocks }), R('i5c'));
    O('DA-13', 'Y-I5C the observation shows the file, line 76, the verbatim createHash line and a file SHA-256; the CBOM record shows the SHA-256 occurrence at the same file:line; the rule conclusion states a rule id and a verdict label', /clients\/mcpdo\/src\/connection\/auth-helper\.ts/.test(t) && /createHash\("sha256"\)/.test(t) && /Line\s*76/.test(t) && /File SHA-256\s*[0-9a-f]{64}/.test(t) && /auth-helper\.ts:76/.test(t) && /SHA-256/.test(t) && /Rule\s*\S+/.test(t) && /DECLARATION AGREES/.test(t) && /crypto_attribution\.operation_declared_in_cbom\/3/.test(t), t.replace(/\s+/g, ' ').slice(0, 300), R('i5c'));
    await pg.click('#ot-evidence [data-action=open-check]'); await sleep(1500); await settle(pg, `document.querySelector('#otc-check')`, 20000); O('DA-13', 'Y-I5C a real click on "Inspect in Cryptography" shows the requested source-backed check in the Cryptography view', await exists(pg, '#otc-check'), (await txt(pg, '#otc-check')).slice(0, 120), R('i5c'));
  });
  await step3('r203', async () => {
    await scan('r203', false); await tab(pg, 'bom'); await settle(pg, `window.__otStore.get().bom8.queue`, 30000); const q = await queueOf(pg); const t = await txt(pg, '.ot-bom8'); const sup = Object.values(q.caps);
    O('DA-12', 'Y-R2-03 the production whole-comparison failure: mode not_compared, every comparison family failed, no candidate listed', q.mode === 'not_compared' && ['software', 'cryptography', 'ai_model'].every((f) => (q.caps[f] || '').startsWith('failed')) && q.items.length === 0, JSON.stringify({ mode: q.mode, caps: q.caps, items: q.items.length }), R('r203'));
    O('DA-12', 'Y-R2-03 the BOM view states that nothing was compared and why, and never says "no references/none found/no gaps"', /Not compared\./.test(t) && !/no (model )?references|none found|no gaps|nothing missing/i.test(t), t.replace(/\s+/g, ' ').slice(0, 260), R('r203'));
  });
  await step3('pos', async () => { await scan('pos', false); await tab(pg, 'ai'); await sleep(900); const note = await txt(pg, '.ot-layer-note'); O('DA-08', 'Y-banner an acquired AI-BOM: the live AI note says the inventory was generated in this scan by Cisco AI-BOM, separately from Syft and cdxgen', /generated in this live scan by Cisco AI-BOM, separately from Syft and cdxgen/.test(note) && !/No AI inventory/.test(note), note.slice(0, 220), R('pos')); });
  await step3('aibomfail', async () => { await scan('aibomfail', false); await tab(pg, 'ai'); await sleep(900); const note = await txt(pg, '.ot-layer-note'); O('DA-08', 'Y-banner an AI-BOM that failed: the live AI note says no inventory is available because it did not deliver, never that one was generated', /No AI inventory is available for this live scan: an AI-BOM was requested/.test(note) && !/was generated/.test(note), note.slice(0, 220), R('aibomfail')); });
  try { await hygiene('YE', c); } catch { /* recorded */ } try { await c.dispose(); } catch { /* ignore */ }
}
async function YN(base) {                                              // uip13 `norun` on the production path + the no-inventory banner (expectations copied from run_uip13_inspector.mjs caseNorun)
  const c = await openCase(chrome.browser, {}); const { pg } = c; const R = (e) => ctxOf('real-server', { fixture: 'uip13 norun (synthetic local repos; production projections; no AI-BOM producer configured)', ...e }); await pg.goto(base); let first = true;
  for (const [repo, cap, n] of [['norun', 'not_run', 2], ['blankrepo', 'completed_empty', 0]]) { guard(); try {
    await scanRepo(pg, repo, first); first = false; const q = await queueOf(pg); await ev(pg, `document.querySelector('[data-action=bom-view][data-view=ai]').click()`); await settled(pg, 'ai'); const t = await txt(pg, '.ot-bom8');
    O('DA-08', `YN ${repo}: ai_model ${cap}, ${n} candidate(s)`, (q.caps.ai_model || '').startsWith(cap) && q.items.length === n, JSON.stringify({ caps: q.caps, n: q.items.length }), R());
    if (cap === 'not_run') {
      O('DA-08', 'YN norun: no producer ran, stated, with the source references still listed', /Model comparison: not run/.test(t) && /because none was produced/.test(t) && /2 references observed/.test(t), t.replace(/\s+/g, ' ').slice(0, 300), R());
      for (const it of q.items) await inspectOne(pg, 'DA-08', `YN norun ${it.item_id.slice(-8)}`, it.item_id, (x) => [['source shown, no AI-BOM record or scope fabricated', x.includes('Model reference in source') && !x.includes('Selected AI-BOM') && !x.includes('AI-BOM scan scope')]], R());
    }
    await tab(pg, 'ai'); await sleep(800); const note = await txt(pg, '.ot-layer-note'); O('DA-08', `YN ${repo}: the live AI note says no inventory is available because the AI-BOM phase did not run`, /^No AI inventory is available for this live scan: the AI-BOM phase did not run/.test(note), note.slice(0, 200), R());
  } catch (e) { if (e.message === 'DEADLINE') throw e; O('DA-08', `YN ${repo}: case completed`, false, e.message.slice(0, 200), R()); } }
  await hygiene('YN', c); await c.dispose();
}
async function YI(base) {                                              // uip12 `interact` T1-T3 (desktop): late response, filter change during an in-flight detail, candidate-local failure (ported from run_uip12_inspector.mjs pairInteract)
  const c = await openCase(chrome.browser, { noRouting: true }); const { pg } = c; const R = (e) => ctxOf('real-server', { fixture: 'uip12 interact (synthetic local repo "multi"; production projections; the in-flight delay and the forced 500 are injected by the harness through Fetch interception)', ...e }); await pg.goto(base);
  try {
    await scanRepo(pg, 'multi', true); await ev(pg, `document.querySelector('[data-action=bom-view][data-view=crypto]').click()`); await settled(pg, 'crypto'); const q = await queueOf(pg); const rowSel = (id) => `[data-action=bom-select][data-id=${JSON.stringify(id)}]`; const waitEv = (id) => pg.waitFor(`document.querySelector('[data-evidence-for=${JSON.stringify(id)}] .ot-gap-inspector')`, 20000);
    const byPath = Object.fromEntries(q.items.map((i) => [i.location.path, i.item_id])); const A = byPath['app/a.py'], B = byPath['app/b.py'], C = byPath['app/c.py']; const mark = { [A]: 'hashlib.sha256(b"a")', [B]: 'hashlib.md5(b"b")', [C]: 'pbkdf2_hmac' };
    O('DA-12', 'YI three candidates (supported, unverifiable, observation-only)', q.items.length === 3 && !!A && !!B && !!C, JSON.stringify(q.items.map((i) => [i.location.path, i.state])), R());
    const held = []; let hold = false, failNext = false; c.browser.on(async (m) => { if (m.sessionId !== pg.sessionId || m.method !== 'Fetch.requestPaused') return; const { requestId, request } = m.params; try {
      if (failNext && request.url.includes('/api/view/gap')) { failNext = false; await pg.send('Fetch.fulfillRequest', { requestId, responseCode: 500, responseHeaders: [{ name: 'Content-Type', value: 'application/json' }], body: Buffer.from('{"error":"injected failure"}').toString('base64') }); }
      else if (hold) held.push({ requestId, url: request.url }); else await pg.send('Fetch.continueRequest', { requestId }); } catch { /* ignore */ } });
    await pg.send('Fetch.enable', { patterns: [{ urlPattern: '*/api/view/gap?*', requestStage: 'Request' }] }); const release = (h) => pg.send('Fetch.continueRequest', { requestId: h.requestId });
    const waitHeld = async (id) => { const t0 = Date.now(); while (Date.now() - t0 < 10000) { const h = held.find((x) => x.url.includes(encodeURIComponent(id))); if (h) return h; await sleep(50); } throw new Error('request not held: ' + id); };
    await sleep(500); hold = true; held.length = 0; await pg.click(rowSel(B)); const hb = await waitHeld(B); await pg.click(rowSel(C)); const hc = await waitHeld(C); await release(hc); await waitEv(C); await release(hb); await sleep(600);
    let t = await inspectorContent(pg); let s = await state(pg); O('DA-12', 'YI T1 a late response for the previous candidate never replaces the visible one', s.bom8.selected === C && t.includes(mark[C]) && !t.includes(mark[B]), t.slice(0, 160), R());
    held.length = 0; await pg.click(rowSel(A)); const ha = await waitHeld(A); await pg.click('[data-action=bom-filter][data-filter=not_represented]'); await pg.waitFor(`window.__otStore.get().bom8.filter==='not_represented' && !window.__otStore.get().bom8.req.queue`, 15000); await release(ha); await sleep(600); t = await inspectorContent(pg); s = await state(pg);
    O('DA-12', 'YI T2 a filter change during an in-flight detail leaves no other candidate\'s evidence', s.bom8.detail === null && !(await exists(pg, '[data-evidence-for]')) && !t.includes(mark[A]), t.slice(0, 160), R());
    hold = false; await pg.click('[data-action=bom-filter][data-filter=all]'); await pg.waitFor(`window.__otStore.get().bom8.filter==='all' && !window.__otStore.get().bom8.req.queue`, 15000); await sleep(500);
    failNext = true; await pg.click(rowSel(B)); await pg.waitFor(`document.querySelector('.ot-bom8-evidence [role=alert]')`, 15000); s = await state(pg); const rows = await count(pg, '.ot-bom8-row');
    O('DA-12', 'YI T3 a failed detail is shown in the inspector only; the queue and workspace stay usable', rows === 3 && s.bom8.error === null && /could not be loaded/.test(await inspectorContent(pg)), `rows=${rows} error=${s.bom8.error}`, R());
    await pg.click(rowSel(C)); await waitEv(C); O('DA-12', 'YI T3b selecting another candidate recovers', (await inspectorContent(pg)).includes(mark[C]), '', R());
  } catch (e) { if (e.message === 'DEADLINE') throw e; O('DA-12', 'YI scenario completed', false, String(e.message).slice(0, 250), R()); }
  await hygiene('YI', c); await c.dispose();
}

// ================================================================= orchestration
const startOffline = () => { const root = mkdtempSync(join(tmpdir(), 'ot-stage4-s1-')); return startApp('S1 offline app', root); };
const runners = {
  P1: async () => withService(startOffline, async (b) => {
    let err = null; try { await P1(b); } catch (e) { if (e.message === 'DEADLINE') throw e; err = e; rec.note('P1 interrupted (P2 still runs on the same S1)', false, String(e.message).slice(0, 300)); }
    if (WANT.includes('P2')) await P2(b); if (err) throw err;
  }),
  P2: async () => withService(startOffline, P2),
  P3: async () => withService(() => startScript('S2 live_service', 'live_service.py', []), P3),
  P4: async () => withService(() => startScript('S3 live_service --cbom-sleep 25', 'live_service.py', ['--cbom-sleep', '25']), P4),
  P5: async () => withService(() => startScript('S4 uip12 matrix', 'uip12_crypto_service.py', ['--case', 'matrix']), (b) => typedMatrix(b, 'crypto', UIP12_MATRIX, 'uip12 matrix')),
  P6: async () => withService(() => startScript('S5 uip13 matrix', 'uip13_model_service.py', ['--case', 'matrix']), (b) => typedMatrix(b, 'ai', UIP13_MATRIX, 'uip13 matrix')),
  P7: async () => withService(() => startScript('S6 uip12 states', 'uip12_crypto_service.py', ['--case', 'states']), P7),
  P8: async () => withService(() => startScript('S7 followup', 'uip13_followup_service.py', []), P8),
  Y: async () => withService(() => startOffline(), YALL),     // extension 2: one offline Demo service hosts Y1-Y4
  YE: async () => withService(() => startScript('S stage4_ext_service', 'stage4_ext_service.py', []), YE),
  YN: async () => withService(() => startScript('S uip13 norun', 'uip13_model_service.py', ['--case', 'norun']), YN),
  YI: async () => withService(() => startScript('S uip12 interact', 'uip12_crypto_service.py', ['--case', 'interact']), YI),
  X: async () => withService(() => startOffline(), XALL),   // extension: one offline Demo service hosts X1-X5
  X6: async () => withService(() => startScript('S uip13 states', 'uip13_model_service.py', ['--case', 'states']), X6),
  F1: async () => withService(() => startScript('S1 completion service', 'stage4_completion_service.py', []), F1),   // closing campaign launch A (own ledger allowance_final.json)
  D3: async () => withService(() => startScript('S11 closure', 'stage4_diag_service.py', []), D3),   // consolidated closure launch (own ledger)
  D2: async () => withService(() => startScript('S10 confirmation', 'stage4_diag_service.py', []), D2),   // S4-FIX-01 confirmation launch (own ledger)
  D1: async () => withService(() => startScript('S9 diagnostic', 'stage4_diag_service.py', []), D1),   // D-17 diagnostic launch (own ledger)
};
process.on('SIGINT', () => finish('SIGINT', 130)); process.on('SIGTERM', () => finish('SIGTERM', 143));
try {
  guard(); chrome = await startChrome('chrome C1');
  for (const p of WANT.filter((x) => !(x === 'P2' && WANT.includes('P1')))) {                 // P2 shares P1's S1 launch when both are requested
    guard(); const t0 = Date.now();
    try { await runners[p](); meta.phases.push({ id: p, ok: true, ms: Date.now() - t0 }); }
    catch (e) { meta.phases.push({ id: p, ok: false, ms: Date.now() - t0, error: String(e.stack || e.message).slice(0, 500) }); console.error('PHASE', p, 'STOPPED', e.message); if (e.message === 'DEADLINE' || /CEILING|CDP timeout|ledger|JSON|closed/i.test(e.message)) throw e; }
  }
  await finish('completed');
} catch (e) { await finish('STOPPED: ' + String(e.stack || e.message).slice(0, 400), 1); }
