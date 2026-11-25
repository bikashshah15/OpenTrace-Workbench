// UIP-02 visual harness runner (C5): capture, variance, side-by-side. LOCAL FIXTURES ONLY.
//
//   node tools/uip/visual/run.mjs capture      --out DIR [--viewports 1366,1920,390] [--themes light,dark]
//   node tools/uip/visual/run.mjs variance     --out DIR [--repeats 10]
//   node tools/uip/visual/run.mjs side-by-side --out DIR           (needs the reference and application captures in DIR)
//
// Network rule: loopback HTTP to the local OpenTrace service and the browser's own IPC are permitted. Every other request is blocked by
// the DevTools Fetch domain and recorded; a blocked request makes the run fail. The reference HTML is opened from disk (file:) and its
// embedded text URLs are never followed. Requires Node >= 22 and Google Chrome (CHROME_BIN overrides the path).
import { spawn, execFileSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync, existsSync, rmSync, readdirSync, renameSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { launch, newPage, CHROME } from '../../../tests/ui/browser/cdp.mjs';
import { VIEWPORTS, THEMES, SETTINGS, MAX_PAGE_HEIGHT, isLoopbackUrl, sha256, decodePng, encodePng, diffStats, summarize, sideBySide, captureRecord, CaptureError, walkStates, assertMatrix, reviewableCoverage, APP_STATE_IDS, REFERENCE_STATE_IDS } from './lib.mjs';

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), '../../..');
const REFERENCE = join(REPO, '.context/references/prototypes/OpenTrace-UI-Update-9-Combined.html');
const REFERENCE_HASH = 'd5bc14fabff29dc42a53dab1f91ae88a6165d70aee808f17e76d066901b3a148';
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const args = process.argv.slice(2); const cmd = args[0];
const opt = (k, d) => { const i = args.indexOf('--' + k); return i >= 0 ? args[i + 1] : d; };
const OUT = resolve(opt('out', join(REPO, 'evidence/uip/visual/uip-02')));
const STAGE = join(OUT, '.staging');
const vpIds = opt('viewports', VIEWPORTS.map((v) => v.id).join(',')).split(',');
const themes = opt('themes', THEMES.join(',')).split(',');
const viewports = VIEWPORTS.filter((v) => vpIds.includes(v.id));

const git = (...a) => execFileSync('git', a, { cwd: REPO, encoding: 'utf8' }).trim();
const COMMIT = (() => { try { return git('rev-parse', 'HEAD'); } catch { return 'unknown'; } })();
if (sha256(readFileSync(REFERENCE)) !== REFERENCE_HASH) { console.error('reference hash mismatch: refusing to capture'); process.exit(2); }

// ---------------------------------------------------------------- service + browser
async function startService() {
  const root = mkdtempSync(join(tmpdir(), 'ot-visual-'));
  const svc = spawn(process.env.PYTHON || 'python3', ['-m', 'opentrace_core.app', '--port', '0', '--session-root', join(root, 's')], { cwd: REPO, env: { ...process.env, PYTHONPATH: join(REPO, 'src/core') }, stdio: ['ignore', 'pipe', 'pipe'] });
  const base = await new Promise((res, rej) => { let b = ''; const t = setTimeout(() => rej(new Error('service did not start: ' + b)), 30000); svc.stdout.on('data', (d) => { b += d; const m = b.match(/http:\/\/127\.0\.0\.1:(\d+)\//); if (m) { clearTimeout(t); res(m[0]); } }); svc.stderr.on('data', (d) => { b += d; }); });
  return { base, stop: () => { svc.kill('SIGTERM'); try { rmSync(root, { recursive: true, force: true }); } catch {} } };
}

const blocked = [];

async function openPage(browser, vp, theme) {
  const pg = await newPage(browser, { width: vp.width, height: vp.height, mobile: !!vp.mobile, scale: SETTINGS.deviceScaleFactor });
  await pg.send('Fetch.enable', { patterns: [{ urlPattern: '*' }] });
  browser.on((m) => {
    if (m.sessionId !== pg.sessionId || m.method !== 'Fetch.requestPaused') return;
    const url = m.params.request.url;
    if (isLoopbackUrl(url)) pg.send('Fetch.continueRequest', { requestId: m.params.requestId }).catch(() => {});
    else { blocked.push(url); pg.send('Fetch.failRequest', { requestId: m.params.requestId, errorReason: 'BlockedByClient' }).catch(() => {}); }
  });
  await pg.send('Emulation.setEmulatedMedia', { features: [{ name: 'prefers-reduced-motion', value: 'reduce' }, { name: 'prefers-color-scheme', value: theme }] });
  await pg.send('Emulation.setTimezoneOverride', { timezoneId: 'UTC' }).catch(() => {});
  await pg.send('Emulation.setLocaleOverride', { locale: 'en-US' }).catch(() => {});
  return pg;
}

// Readiness: fonts, two quiet animation frames, and two identical screenshots 200 ms apart. Fails (never retries silently).
async function shot(pg) {
  await pg.eval(`document.activeElement&&document.activeElement.blur&&document.activeElement.blur()`);
  await pg.eval(`document.fonts.ready.then(()=>true)`);
  await pg.eval(`new Promise((res)=>{let quiet=0;const mo=new MutationObserver(()=>{quiet=-1});mo.observe(document.documentElement,{subtree:true,childList:true,attributes:true,characterData:true});const tick=()=>{quiet++;if(quiet>=2){mo.disconnect();res(true)}else requestAnimationFrame(tick)};requestAnimationFrame(tick)})`);
  const height = Math.min(MAX_PAGE_HEIGHT, await pg.eval('Math.max(document.documentElement.scrollHeight, innerHeight)'));
  const grab = async () => { const r = await pg.send('Page.captureScreenshot', { format: 'png', captureBeyondViewport: true, clip: { x: 0, y: 0, width: pg.width, height, scale: 1 } }); return Buffer.from(r.data, 'base64'); };
  // Stabilization: poll (200 ms apart, at most 25 times = 5 s) until two consecutive screenshots are byte-identical; never accept a pair that differs.
  let prev = await grab();
  for (let i = 0; i < 25; i++) { await sleep(200); const cur = await grab(); if (cur.equals(prev)) return cur; prev = cur; }
  throw new Error('readiness failed: the page did not stabilise within 5 s');
}

async function setTheme(pg, theme) {
  await pg.eval(`window.__otStore.dispatch({type:'THEME',value:${JSON.stringify(theme)}})`); await sleep(150);
  const got = await pg.eval(`document.documentElement.dataset.theme||'light'`);
  if (got !== theme) throw new Error(`theme ${theme} not applied (got ${got})`);
}

// ---------------------------------------------------------------- state walks (fail-closed; UIP-02-IR-04)
// Every state declares what the page must look like AFTER its step. The harness observes the page and refuses to capture (and to
// record a state) unless the observation matches; a missing control or a failed click is an explicit CaptureError.
const clickOrThrow = async (pg, selector, what) => {
  const found = await pg.eval(`(()=>{const e=document.querySelector(${JSON.stringify(selector)});if(!e)return false;e.dispatchEvent(new MouseEvent('click',{bubbles:true,cancelable:true,view:window}));return true})()`);
  if (found !== true) throw new CaptureError(`${what}: control ${selector} was not found`);
};
const APP_OBSERVE = `(()=>{const s=window.__otStore&&window.__otStore.get();if(!s)return null;const i=document.querySelector('.ot-inspector .ot-insp');
  return {destination:s.destination,tab:s.workbench&&s.workbench.tab,has_analysis:!!s.analysis,record_id:i?i.getAttribute('data-record-id'):null,record_origin:i?i.getAttribute('data-origin'):null,record_title:i?((i.querySelector('h2')||{}).textContent||null):null,theme:document.documentElement.dataset.theme||'light'}})()`;
// At 390 px neither side offers a root control, so BOTH select this same named source file (not "the first listed", which differs by side).
const MOBILE_FILE = 'docs/package-lock.json';
const wbExpect = (tab) => ({ destination: 'workbench', tab, has_analysis: true });
const APP_STATES = [
  { id: 'home', tab: 'analyze', selection: 'none', run: async () => {}, expect: { destination: 'analyze', has_analysis: false } },
  { id: 'workbench-contexts', tab: 'contexts', selection: 'none', run: async (pg) => { await pg.click('#ot-demo'); await pg.waitFor(`document.querySelector('#ot-tabpanel [data-ctx]')`, 30000); await sleep(400); }, expect: wbExpect('contexts') },
  { id: 'inspector-contexts', tab: 'contexts', selection: 'repository root', run: async (pg, ctx) => { const sel = ctx.vp.mobile ? `[data-ctx="context:${MOBILE_FILE}"]` : '[data-ctx=root]'; await clickOrThrow(pg, sel, 'application inspector-contexts'); await sleep(300); },
    expectFor: (ctx) => ({ ...wbExpect('contexts'), record_origin: 'local_presentation_model', record_id: ctx.vp.mobile ? `context:${MOBILE_FILE}` : 'root' }) },
  { id: 'inspector-dependencies', tab: 'dependencies', selection: 'default focus package', run: async (pg) => { await pg.click('#ot-tab-dependencies'); await pg.waitFor(`document.querySelector('[data-dep-node]')&&document.querySelector('.ot-inspector h2')`, 30000); await sleep(500); }, expect: { ...wbExpect('dependencies'), record_origin: 'local_presentation_model', record_id: (v) => !!v } },
  { id: 'inspector-crypto', tab: 'crypto', selection: 'default rule-backed check', run: async (pg) => { await pg.click('#ot-tab-crypto'); await pg.waitFor(`document.querySelector('.ot-inspector h2')`, 30000); await sleep(1500); }, expect: { ...wbExpect('crypto'), record_origin: 'local_presentation_model', record_id: (v) => !!v } },
  { id: 'inspector-ai', tab: 'ai', selection: 'default check', run: async (pg) => { await pg.click('#ot-tab-ai'); await pg.waitFor(`document.querySelector('.ot-inspector h2')`, 30000); await sleep(1500); }, expect: { ...wbExpect('ai'), record_origin: 'local_presentation_model', record_id: (v) => !!v } },
];

async function environment(pg) {
  const fonts = await pg.eval(`(()=>{const f=[...document.fonts].filter(x=>x.status==='loaded').map(x=>x.family);return {loaded:[...new Set(f)].sort(),body:getComputedStyle(document.body).fontFamily}})()`);
  return { fonts: JSON.stringify(fonts), zoom: await pg.eval('devicePixelRatio') };
}

async function walkApp(browser, base, vp, theme, sink) {
  const pg = await openPage(browser, vp, theme); const ctx = { vp, theme };
  try { await pg.goto(base); await sleep(500); await setTheme(pg, theme); } catch (e) { await pg.close().catch(() => {}); throw e; }
  return walkStates(APP_STATES, pg, {
    settle: async (p) => { await setTheme(p, theme); },
    observe: (p) => p.eval(APP_OBSERVE),
    capture: (p) => shot(p),
    sink: async ({ state, observed, png }) => { const st = APP_STATES.find((x) => x.id === state); await sink({ state, tab: st.tab, selection: observed.record_id ? `${vp.mobile && state === 'inspector-contexts' ? 'source file ' + MOBILE_FILE + ' (the 390 px list has no root control)' : st.selection} (record ${observed.record_id}: ${String(observed.record_title || '').slice(0, 60)})` : st.selection, png, env: await environment(pg), vp, theme }); },
  }, ctx);
}

// The reference is a static prototype: its observable state is the active page, the pressed layer tab, the pressed context control and
// the visible inspector text. Its root control exists only in the wide graph; the 390 px list offers files only, so at 390 px BOTH sides
// select the same named source file. They do NOT end in the same place: the reference drills into its Dependencies layer (software-component
// inspector) while the application stays in Contexts (source-file inspector). That is a documented difference in destination, recorded in the
// manifest from the OBSERVED layer, not a harness fault and not a claim of parity.
const REF_OBSERVE = `(()=>{const vis=e=>!!(e.offsetParent||e.getClientRects().length)&&getComputedStyle(e).visibility!=='hidden';
  const page=document.querySelector('[data-ot-page].active');const layer=document.querySelector('[data-ot2-layer][aria-pressed=true]');
  const root=document.querySelector('[data-context-root]');const insp=[...document.querySelectorAll('aside.inspector')].filter(vis).map((e)=>e.textContent.replace(/\\s+/g,' ').trim()).find(Boolean)||'';
  return {page:page?page.dataset.otPage:null,layer:layer?layer.dataset.ot2Layer:null,root_pressed:!!(root&&root.getAttribute('aria-pressed')==='true'),inspector_text:insp,theme:document.documentElement.dataset.theme||'light'}})()`;
const refStates = [
  { id: 'home', tab: 'analyze', selection: 'none', run: async () => {}, expect: { page: 'analyze' } },
  { id: 'workbench-contexts', tab: 'contexts', selection: 'none', run: async (pg) => { await pg.click('#ot-demo'); await sleep(2500); }, expect: { page: 'workbench', layer: 'contexts' } },
  { id: 'inspector-contexts', tab: 'contexts', selection: 'repository root', run: async (pg, ctx) => { await clickOrThrow(pg, ctx.vp.mobile ? `[data-ot2-context="${MOBILE_FILE}"]` : '[data-context-root]', 'reference inspector-contexts'); await sleep(600); },
    expectFor: (ctx) => (ctx.vp.mobile ? { page: 'workbench', layer: 'dependencies', inspector_text: /\S/ } : { page: 'workbench', layer: 'contexts', root_pressed: true, inspector_text: /Frigate repository context/ }) },
];
async function walkReference(browser, vp, theme, sink) {
  const pg = await openPage(browser, vp, theme); const ctx = { vp, theme };
  try { await pg.goto('file://' + REFERENCE); await sleep(1500); } catch (e) { await pg.close().catch(() => {}); throw e; }
  return walkStates(refStates, pg, {
    settle: async (p) => { await p.eval(`document.documentElement.dataset.theme=${JSON.stringify(theme)};true`); await sleep(300); },
    observe: (p) => p.eval(REF_OBSERVE),
    capture: (p) => shot(p),
    sink: async ({ state, observed, png }) => { const st = refStates.find((x) => x.id === state); const drill = state === 'inspector-contexts' && vp.mobile; await sink({ state, tab: drill ? observed.layer : st.tab, selection: drill ? `source file ${MOBILE_FILE}; the 390 px reference has no root control and its file selection opens its ${observed.layer} layer (a different destination from the application)` : st.selection, png, env: await environment(pg), vp, theme }); },
  }, ctx);
}
const browserName = async (browser) => (await browser.send('Browser.getVersion')).product;
function writeCapture(dir, kind, c, repeat, ver) {
  const name = `${kind}${repeat != null ? `_r${String(repeat).padStart(2, '0')}` : ''}_${c.vp.id}_${c.theme}_${c.state}.png`;
  const path = join(dir, name); writeFileSync(path, c.png);
  const d = decodePng(c.png);
  return captureRecord({ reference_hash: REFERENCE_HASH, tested_commit: COMMIT, fixture: kind === 'reference' ? 'reference (embedded captured Frigate case)' : 'captured Frigate case (Demo)', viewport: c.vp.id, theme: c.theme, tab: c.tab, selection: c.selection, state: c.state,
    browser: ver, device_scale_factor: SETTINGS.deviceScaleFactor, zoom: c.env.zoom, fonts: c.env.fonts, readiness: SETTINGS.readiness, png_sha256: sha256(c.png), png_bytes: c.png.length, width: d.width, height: d.height, path: name });
}

// `verify`: the committed evidence set must give a reviewable image per state/viewport/theme (contract §6) and agree with its manifest.
function verify() {
  const m = JSON.parse(readFileSync(join(OUT, 'manifest.json'), 'utf8')); const problems = [];
  problems.push(...reviewableCoverage(VIEWPORTS.map((v) => v.id), THEMES, (rel) => existsSync(join(OUT, rel))).map((p) => 'missing committed image ' + p));
  try { assertMatrix(m.captures, { app: APP_STATE_IDS, reference: REFERENCE_STATE_IDS }, VIEWPORTS.map((v) => v.id), THEMES); } catch (e) { problems.push(e.message); }
  for (const c of m.captures) { const f = join(OUT, c.path.startsWith('app_') ? 'app' : 'reference', c.path); if (existsSync(f) && sha256(readFileSync(f)) !== c.png_sha256) problems.push('manifest digest differs from the committed image ' + c.path); }
  if (m.reference_hash !== REFERENCE_HASH) problems.push('manifest reference hash differs');
  if (problems.length) { console.error('visual evidence incomplete:\n- ' + problems.join('\n- ')); process.exitCode = 1; } else console.log('visual evidence complete:', m.captures.length, 'manifest records');
}

async function main() {
  if (cmd === 'verify') return verify();
  mkdirSync(OUT, { recursive: true }); rmSync(STAGE, { recursive: true, force: true });
  const svc = await startService(); const { browser, close } = await launch(); const ver = await browserName(browser);
  const records = []; let failed = null;
  try {
    if (cmd === 'capture') {
      // Captures are staged and promoted only when the whole requested matrix succeeded; a failed run leaves nothing half-written.
      for (const k of ['app', 'reference']) mkdirSync(join(STAGE, k), { recursive: true });
      for (const vp of viewports) for (const theme of themes) {
        await walkApp(browser, svc.base, vp, theme, async (c) => { records.push(writeCapture(join(STAGE, 'app'), 'app', c, null, ver)); });
        await walkReference(browser, vp, theme, async (c) => { records.push(writeCapture(join(STAGE, 'reference'), 'reference', c, null, ver)); });
        console.log('captured', vp.id, theme);
      }
      assertMatrix(records, { app: APP_STATE_IDS, reference: REFERENCE_STATE_IDS }, viewports.map((v) => v.id), themes);
      for (const k of ['app', 'reference']) { mkdirSync(join(OUT, k), { recursive: true }); for (const f of readdirSync(join(STAGE, k))) renameSync(join(STAGE, k, f), join(OUT, k, f)); }
      writeFileSync(join(OUT, 'manifest.json'), JSON.stringify({ reference_hash: REFERENCE_HASH, tested_commit: COMMIT, browser: ver, settings: SETTINGS, captures: records }, null, 2) + '\n');
    } else if (cmd === 'variance') {
      const repeats = Number(opt('repeats', SETTINGS.repeats)); const first = new Map(); const ratios = new Map(); const hashes = new Map();
      mkdirSync(join(OUT, 'repeats'), { recursive: true });
      for (let r = 1; r <= repeats; r++) for (const vp of viewports) for (const theme of themes) {
        await walkApp(browser, svc.base, vp, theme, async (c) => {
          const key = `${vp.id}/${theme}/${c.state}`; const dec = decodePng(c.png);
          hashes.set(key, [...(hashes.get(key) || []), sha256(c.png)]);
          if (r === 1) first.set(key, dec); else ratios.set(key, [...(ratios.get(key) || []), diffStats(first.get(key), dec).ratio]);
        });
        console.log('repeat', r, vp.id, theme);
      }
      const states = {}; let worst = 0;
      for (const key of first.keys()) { const s = summarize(ratios.get(key) || []); states[key] = { ...s, distinct_png_hashes: new Set(hashes.get(key)).size, repeats }; worst = Math.max(worst, s.max); }
      writeFileSync(join(OUT, 'variance.json'), JSON.stringify({ metric: 'ratio of pixels with any channel difference > 0 (repeats 2..N against repeat 1)', repeats, tested_commit: COMMIT, reference_hash: REFERENCE_HASH, browser: ver, settings: SETTINGS, states }, null, 2) + '\n');
      writeFileSync(join(OUT, '..', 'thresholds.json'), JSON.stringify({ rule: 'threshold = 2 x maximum observed repeat ratio, rounded up to 1e-6; 0 when no variance was measured; never raised to accommodate a regression', repeats, tested_commit: COMMIT, browser: ver, thresholds: Object.fromEntries(Object.entries(states).map(([k, v]) => [k, v.threshold])) }, null, 2) + '\n');
      console.log('worst observed ratio', worst);
    } else if (cmd === 'side-by-side') {
      const m = JSON.parse(readFileSync(join(OUT, 'manifest.json'), 'utf8')); mkdirSync(join(OUT, 'side-by-side'), { recursive: true });
      for (const a of m.captures.filter((c) => c.path && existsSync(join(OUT, 'app', c.path)))) {
        const refName = a.path.replace(/^app_/, 'reference_'); const refPath = join(OUT, 'reference', refName); if (!existsSync(refPath)) continue;
        const sbs = sideBySide(decodePng(readFileSync(refPath)), decodePng(readFileSync(join(OUT, 'app', a.path))));
        writeFileSync(join(OUT, 'side-by-side', a.path.replace(/^app_/, 'sbs_')), encodePng(sbs));
      }
    } else { console.error('usage: capture | variance | side-by-side'); process.exitCode = 2; }
  } catch (e) { failed = e; } finally { await close(); svc.stop(); rmSync(STAGE, { recursive: true, force: true }); }
  if (blocked.length) { console.error('BLOCKED non-loopback requests:', [...new Set(blocked)].slice(0, 5)); process.exitCode = 3; }
  if (failed) { console.error(failed.stack || failed); process.exitCode = 1; }
}
main();
