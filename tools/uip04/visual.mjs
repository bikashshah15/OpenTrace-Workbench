// UIP-04 visual evidence (verification tool; no application code). LOCAL FIXTURES ONLY (the recorded Demo and the approved reference).
//
//   node tools/uip04/visual.mjs capture      [--out DIR] [--viewports 1366,1920,390] [--themes light,dark]
//   node tools/uip04/visual.mjs variance     [--out DIR] [--repeats 10]
//   node tools/uip04/visual.mjs side-by-side [--out DIR]
//
// Reference-match states (contract section 6): fixture Frigate recorded; tab Contexts; viewports 1366/1920/390; themes light/dark;
// presentation Graph (390 px: List, as the reference); selections S1 repository root, S2 group "Python requirements", S3 file
// docs/package-lock.json. Capture is fail-closed: before EVERY capture the harness asserts the observable postconditions (theme, viewport,
// Contexts tab selected, map ready, selection kind/id, rendered card count, no pending contexts request, viewBox after Fit, fonts ready,
// reduced motion, scroll at top, no focus ring, inspector title) and aborts on any mismatch; nothing half-written is promoted.
// Repeatability (variance) is measured separately, application against itself, with UIP-02's metric; thresholds are written to this
// increment's own file and NEVER touch evidence/uip/visual/thresholds.json (UIP-02/03). Network: loopback only; anything else is blocked.
import { spawn, execFileSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync, existsSync, rmSync, readdirSync, renameSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { launch, newPage } from '../../tests/ui/browser/cdp.mjs';
import { VIEWPORTS, THEMES, SETTINGS, MAX_PAGE_HEIGHT, isLoopbackUrl, sha256, decodePng, encodePng, diffStats, summarize, sideBySide, thresholdFor } from '../uip/visual/lib.mjs';

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const REFERENCE = join(REPO, '.context/references/prototypes/OpenTrace-UI-Update-9-Combined.html');
const REFERENCE_HASH = 'd5bc14fabff29dc42a53dab1f91ae88a6165d70aee808f17e76d066901b3a148';
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const args = process.argv.slice(2); const cmd = args[0];
const opt = (k, d) => { const i = args.indexOf('--' + k); return i >= 0 ? args[i + 1] : d; };
const OUT = resolve(opt('out', join(REPO, 'evidence/uip/visual/uip-04')));
const STAGE = join(OUT, '.staging');
const viewports = VIEWPORTS.filter((v) => opt('viewports', VIEWPORTS.map((x) => x.id).join(',')).split(',').includes(v.id));
const themes = opt('themes', THEMES.join(',')).split(',');
const git = (...a) => execFileSync('git', a, { cwd: REPO, encoding: 'utf8' }).trim();
const COMMIT = (() => { try { return git('rev-parse', 'HEAD'); } catch { return 'unknown'; } })();
if (sha256(readFileSync(REFERENCE)) !== REFERENCE_HASH) { console.error('reference hash mismatch: refusing to capture'); process.exit(2); }

const STATES = [
  { id: 's1-root', selection: 'repository root', app: { kind: 'root', id: 'root', title: (m) => m.root.name }, ref: { sel: '[data-context-root]', desktopOnly: true } },
  { id: 's2-group-python', selection: 'group Python requirements', app: { kind: 'group', title: () => 'Python requirements' }, ref: { sel: '[data-context-group=python]', desktopOnly: true } },
  { id: 's3-file-docs', selection: 'file docs/package-lock.json', app: { find: 'docs/package-lock.json', kind: 'file', title: () => 'docs/package-lock.json' }, ref: { sel: '[data-context-file="docs/package-lock.json"]', mobileSel: '[data-ot2-context="docs/package-lock.json"]' } },
];
const blocked = [];
async function startService() {
  const root = mkdtempSync(join(tmpdir(), 'ot-uip04-'));
  const svc = spawn(process.env.PYTHON || 'python3', ['-m', 'opentrace_core.app', '--port', '0', '--session-root', join(root, 's')], { cwd: REPO, env: { ...process.env, PYTHONPATH: join(REPO, 'src/core') }, stdio: ['ignore', 'pipe', 'pipe'] });
  const base = await new Promise((res, rej) => { let b = ''; const t = setTimeout(() => rej(new Error('service did not start: ' + b)), 30000); svc.stdout.on('data', (d) => { b += d; const m = b.match(/http:\/\/127\.0\.0\.1:(\d+)\//); if (m) { clearTimeout(t); res(m[0]); } }); svc.stderr.on('data', (d) => { b += d; }); });
  return { base, stop: () => { svc.kill('SIGTERM'); try { rmSync(root, { recursive: true, force: true }); } catch {} } };
}
async function openPage(browser, vp, theme) {
  const pg = await newPage(browser, { width: vp.width, height: vp.height, mobile: !!vp.mobile, scale: SETTINGS.deviceScaleFactor });
  await pg.send('Fetch.enable', { patterns: [{ urlPattern: '*' }] });
  browser.on((m) => { if (m.sessionId !== pg.sessionId || m.method !== 'Fetch.requestPaused') return; const url = m.params.request.url;
    if (isLoopbackUrl(url)) pg.send('Fetch.continueRequest', { requestId: m.params.requestId }).catch(() => {}); else { blocked.push(url); pg.send('Fetch.failRequest', { requestId: m.params.requestId, errorReason: 'BlockedByClient' }).catch(() => {}); } });
  await pg.send('Emulation.setEmulatedMedia', { features: [{ name: 'prefers-reduced-motion', value: 'reduce' }, { name: 'prefers-color-scheme', value: theme }] });
  await pg.send('Emulation.setTimezoneOverride', { timezoneId: 'UTC' }).catch(() => {});
  await pg.send('Emulation.setLocaleOverride', { locale: 'en-US' }).catch(() => {});
  return pg;
}
async function shot(pg) {
  await pg.eval('document.activeElement&&document.activeElement.blur&&document.activeElement.blur()');
  await pg.eval('document.fonts.ready.then(()=>true)');
  await pg.eval('window.scrollTo(0,0)');
  const height = Math.min(MAX_PAGE_HEIGHT, await pg.eval('Math.max(document.documentElement.scrollHeight, innerHeight)'));
  const grab = async () => { const r = await pg.send('Page.captureScreenshot', { format: 'png', captureBeyondViewport: true, clip: { x: 0, y: 0, width: pg.width, height, scale: 1 } }); return Buffer.from(r.data, 'base64'); };
  let prev = await grab();
  for (let i = 0; i < 25; i++) { await sleep(200); const cur = await grab(); if (cur.equals(prev)) return cur; prev = cur; }
  throw new Error('readiness failed: the page did not stabilise within 5 s');
}
const must = (cond, msg, detail) => { if (!cond) throw new Error(`postcondition failed: ${msg}${detail !== undefined ? ' (' + JSON.stringify(detail) + ')' : ''}`); };

// ---------------------------------------------------------------- application walk
async function walkApp(browser, base, vp, theme, sink) {
  const pg = await openPage(browser, vp, theme); const narrow = !!vp.mobile;
  try {
    await pg.goto(base); await sleep(500);
    await pg.eval(`window.__otStore.dispatch({type:'THEME',value:${JSON.stringify(theme)}})`); await sleep(150);
    await pg.eval("document.getElementById('ot-demo').click()");
    await pg.waitFor(`document.querySelector('[data-map-ready="true"]')`, 30000, 'map ready'); await sleep(400);
    const out = [];
    for (const st of STATES) {
      const sel = await pg.eval(`(()=>{const q=${JSON.stringify(st.app)};
        if(q.find) return [...document.querySelectorAll('[data-ctx-kind=file]')].find(e=>(e.querySelector('title')?.textContent||e.innerText||'').includes(q.find))?.dataset.ctx;
        if(q.kind==='root') return document.querySelector('[data-ctx=root]')?.dataset.ctx;
        return [...document.querySelectorAll('[data-ctx-kind=group]')].find(e=>/Python requirements/.test(e.getAttribute('aria-label')||e.innerText))?.dataset.ctx;})()`);
      must(sel, `control for ${st.id} not found`);
      await pg.eval(`document.querySelector('[data-ctx="${sel}"]').dispatchEvent(new MouseEvent('click',{bubbles:true,cancelable:true,view:window}))`); await sleep(350);
      if (!narrow) { await pg.eval("document.querySelector('[data-ctx-fit]').click()"); await sleep(150); }
      const o = await pg.eval(`(()=>{const s=window.__otStore.get();const m=s.views.contexts;const st=document.querySelector('[data-selection-kind]');const stage=document.getElementById('ot4-stage');
        return {theme:document.documentElement.dataset.theme||'light',w:innerWidth,h:innerHeight,tab:document.querySelector('[role=tab][aria-selected=true]')?.id,ready:st?.dataset.mapReady,kind:st?.dataset.selectionKind,id:st?.dataset.selectionId,
          cards:st?.dataset.cardCount,loading:Object.values(s.workbench.perTab.contexts.map.groups).filter((g)=>g.state==='loading').length+(s.workbench.perTab.contexts.map.status==='loading'?1:0),
          viewBox:document.getElementById('ot4-svg')?.getAttribute('viewBox')||null,fit:stage?.dataset.fit||null,presentation:s.workbench.perTab.contexts.presentation,
          reduced:matchMedia('(prefers-reduced-motion: reduce)').matches,fonts:document.fonts.status,scrollY:scrollY,focus:document.activeElement===document.body||!document.activeElement,
          title:document.querySelector('.ot4-inspector .ot-insp-head h2')?.textContent||'',rootName:m.root.name,fontsLoaded:[...new Set([...document.fonts].filter((x)=>x.status==='loaded').map((x)=>x.family))].sort().join(',')}})()`);
      must(o.theme === theme, 'theme attribute equals the state', o.theme); must(o.w === vp.width && o.h === vp.height, 'viewport equals the state', [o.w, o.h]);
      must(o.tab === 'ot-tab-contexts', 'Contexts tab aria-selected', o.tab); must(o.ready === 'true' && o.loading === 0, 'map ready and no pending contexts request', [o.ready, o.loading]);
      must(o.kind === st.app.kind && (st.app.id ? o.id === st.app.id : o.id === sel), 'selection kind/id equal the state', [o.kind, o.id]);
      must(o.cards === '13', 'rendered card count equals the expected 13', o.cards); must(o.presentation === (narrow ? 'list' : 'graph'), 'presentation (Graph; 390 px List)', o.presentation);
      if (!narrow) must(o.viewBox === '0 0 1400 1206' && o.fit === o.viewBox, 'viewBox after Fit equals the expected value', [o.viewBox, o.fit]);
      must(o.fonts === 'loaded', 'document.fonts ready', o.fonts); must(o.reduced, 'animations disabled (reduced motion)'); must(o.title === st.app.title({ root: { name: o.rootName } }), 'inspector title equals the expected title', o.title);
      await pg.eval('document.activeElement&&document.activeElement.blur&&document.activeElement.blur(); window.scrollTo(0,0)'); await sleep(100);
      must(await pg.eval('scrollY === 0 && (document.activeElement === document.body)'), 'scroll at top and no focus ring');
      const png = await shot(pg);
      out.push({ state: st.id, selection: st.selection, png, observed: o });
    }
    for (const x of out) await sink(x);
  } finally { await pg.close().catch(() => {}); }
}

// ---------------------------------------------------------------- reference walk
async function walkReference(browser, vp, theme, sink) {
  const pg = await openPage(browser, vp, theme); const narrow = !!vp.mobile;
  try {
    await pg.goto('file://' + REFERENCE); await sleep(1500);
    await pg.eval(`document.documentElement.dataset.theme=${JSON.stringify(theme)};true`); await sleep(300);
    await pg.eval("document.getElementById('ot-demo').click()"); await sleep(2500);
    for (const st of STATES) {
      if (narrow && st.ref.desktopOnly) continue;                      // the 390 px reference is a file list: no root or group control exists
      const sel = narrow ? st.ref.mobileSel : st.ref.sel;
      const found = await pg.eval(`(()=>{const e=document.querySelector(${JSON.stringify(sel)});if(!e)return false;e.dispatchEvent(new MouseEvent('click',{bubbles:true,cancelable:true,view:window}));return true})()`);
      must(found === true, `reference control ${sel} not found`); await sleep(600);
      await pg.eval(`document.documentElement.dataset.theme=${JSON.stringify(theme)};true`);
      const o = await pg.eval(`(()=>({theme:document.documentElement.dataset.theme||'light',w:innerWidth,h:innerHeight,layer:document.querySelector('[data-ot2-layer][aria-pressed=true]')?.dataset.ot2Layer,svgSelected:[...document.querySelectorAll('#context-map-svg [aria-pressed=true]')].map(e=>e.getAttribute('aria-label')),fonts:document.fonts.status}))()`);
      must(o.theme === theme && o.w === vp.width && o.h === vp.height, 'reference theme and viewport', o);
      if (!narrow) must(o.layer === 'contexts' && o.svgSelected.length === 1, 'reference Contexts layer with exactly one selected map item', o);
      await pg.eval('document.activeElement&&document.activeElement.blur&&document.activeElement.blur(); window.scrollTo(0,0)');
      await sink({ state: st.id, selection: st.selection, png: await shot(pg), observed: o });
    }
  } finally { await pg.close().catch(() => {}); }
}

const record = (kind, vp, theme, c, ver, repeat) => {
  const d = decodePng(c.png); const name = `${kind}${repeat != null ? '_r' + String(repeat).padStart(2, '0') : ''}_${vp.id}_${theme}_${c.state}.png`;
  return { name, record: { reference_hash: REFERENCE_HASH, tested_commit: COMMIT, fixture: kind === 'reference' ? 'reference (embedded captured Frigate case)' : 'captured Frigate case (Demo)', viewport: vp.id, theme, tab: 'contexts', selection: c.selection, state: c.state,
    presentation: vp.mobile ? 'list' : 'graph', browser: ver, device_scale_factor: SETTINGS.deviceScaleFactor, readiness: SETTINGS.readiness, observed: c.observed, png_sha256: sha256(c.png), png_bytes: c.png.length, width: d.width, height: d.height, path: name } };
};

async function main() {
  mkdirSync(OUT, { recursive: true }); rmSync(STAGE, { recursive: true, force: true });
  const svc = await startService(); const { browser, close } = await launch(); const ver = (await browser.send('Browser.getVersion')).product;
  let failed = null;
  try {
    if (cmd === 'capture') {
      const records = [];
      for (const k of ['app', 'reference']) mkdirSync(join(STAGE, k), { recursive: true });
      for (const vp of viewports) for (const theme of themes) {
        await walkApp(browser, svc.base, vp, theme, async (c) => { const r = record('app', vp, theme, c, ver); writeFileSync(join(STAGE, 'app', r.name), c.png); records.push(r.record); });
        await walkReference(browser, vp, theme, async (c) => { const r = record('reference', vp, theme, c, ver); writeFileSync(join(STAGE, 'reference', r.name), c.png); records.push(r.record); });
        console.log('captured', vp.id, theme);
      }
      for (const k of ['app', 'reference']) { mkdirSync(join(OUT, k), { recursive: true }); for (const f of readdirSync(join(STAGE, k))) renameSync(join(STAGE, k, f), join(OUT, k, f)); }
      writeFileSync(join(OUT, 'manifest.json'), JSON.stringify({ reference_hash: REFERENCE_HASH, tested_commit: COMMIT, browser: ver, settings: SETTINGS, matrix: { viewports: viewports.map((v) => v.id), themes, states: STATES.map((s) => s.id), reference_390: 'S3 only (the 390 px reference is a file list)' }, captures: records }, null, 2) + '\n');
    } else if (cmd === 'variance') {
      const repeats = Number(opt('repeats', SETTINGS.repeats)); const first = new Map(); const ratios = new Map(); const hashes = new Map();
      for (let r = 1; r <= repeats; r++) for (const vp of viewports) for (const theme of themes) {
        await walkApp(browser, svc.base, vp, theme, async (c) => { const key = `${vp.id}/${theme}/${c.state}`; const dec = decodePng(c.png); hashes.set(key, [...(hashes.get(key) || []), sha256(c.png)]);
          if (r === 1) first.set(key, dec); else ratios.set(key, [...(ratios.get(key) || []), diffStats(first.get(key), dec).ratio]); });
        console.log('repeat', r, vp.id, theme);
      }
      const states = {}; let worst = 0;
      for (const key of first.keys()) { const s = summarize(ratios.get(key) || []); states[key] = { ...s, distinct_png_hashes: new Set(hashes.get(key)).size, repeats }; worst = Math.max(worst, s.max); }
      writeFileSync(join(OUT, 'variance.json'), JSON.stringify({ metric: 'ratio of pixels with any channel difference > 0 (repeats 2..N against repeat 1)', repeats, tested_commit: COMMIT, reference_hash: REFERENCE_HASH, browser: ver, settings: SETTINGS, states }, null, 2) + '\n');
      writeFileSync(join(OUT, 'thresholds.json'), JSON.stringify({ rule: 'threshold = 2 x maximum observed repeat ratio, rounded up to 1e-6; 0 when no variance was measured; never raised to accommodate a regression; governs regression only and is not parity evidence', repeats, tested_commit: COMMIT, browser: ver, thresholds: Object.fromEntries(Object.entries(states).map(([k, v]) => [k, v.threshold])) }, null, 2) + '\n');
      console.log('worst observed ratio', worst);
    } else if (cmd === 'side-by-side') {
      const m = JSON.parse(readFileSync(join(OUT, 'manifest.json'), 'utf8')); mkdirSync(join(OUT, 'side-by-side'), { recursive: true });
      for (const a of m.captures.filter((c) => c.path.startsWith('app_'))) {
        const refPath = join(OUT, 'reference', a.path.replace(/^app_/, 'reference_')); if (!existsSync(refPath)) continue;
        writeFileSync(join(OUT, 'side-by-side', a.path.replace(/^app_/, 'sbs_')), encodePng(sideBySide(decodePng(readFileSync(refPath)), decodePng(readFileSync(join(OUT, 'app', a.path))))));
      }
    } else { console.error('usage: capture | variance | side-by-side'); process.exitCode = 2; }
  } catch (e) { failed = e; } finally { await close(); svc.stop(); rmSync(STAGE, { recursive: true, force: true }); }
  if (blocked.length) { console.error('BLOCKED non-loopback requests:', [...new Set(blocked)].slice(0, 5)); process.exitCode = 3; }
  if (failed) { console.error(failed.stack || failed); process.exitCode = 1; }
}
main();
