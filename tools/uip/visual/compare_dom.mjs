// Prototype-led DOM / computed-style / interaction comparison (UIP-03 acceptance packet; verification tool, no application code).
//   PYTHON=<python> node tools/uip/visual/compare_dom.mjs --out DIR [--viewports 1366,1920,390] [--themes light,dark]
// Opens the approved reference (file:, hash-gated) and the application (local OpenTrace service, offline captured Demo) at the same
// viewport/theme/state, extracts the visible controls/headings/tabs/pills with text, rectangle and computed style, pairs them by
// normalized label and reports label inventory differences, tab order and per-pair style/size deltas. Raw HTML equality is not required.
// Network: loopback only (everything else blocked and recorded). Local fixtures only.
import { spawn } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { launch, newPage } from '../../../tests/ui/browser/cdp.mjs';
import { VIEWPORTS, THEMES, SETTINGS, isLoopbackUrl } from './lib.mjs';

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), '../../..');
const REFERENCE = join(REPO, '.context/references/prototypes/OpenTrace-UI-Update-9-Combined.html');
const REFERENCE_HASH = 'd5bc14fabff29dc42a53dab1f91ae88a6165d70aee808f17e76d066901b3a148';
const args = process.argv.slice(2);
const opt = (k, d) => { const i = args.indexOf('--' + k); return i >= 0 ? args[i + 1] : d; };
const OUT = resolve(opt('out', join(REPO, 'evidence/uip/acceptance/uip-03')));
const viewports = VIEWPORTS.filter((v) => opt('viewports', '1366,1920,390').split(',').includes(v.id));
const themes = opt('themes', THEMES.join(',')).split(',');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const sha = (b) => createHash('sha256').update(b).digest('hex');
if (sha(readFileSync(REFERENCE)) !== REFERENCE_HASH) { console.error('reference hash mismatch'); process.exit(2); }
const git = (...a) => { try { return spawnSyncGit(a); } catch { return 'unknown'; } };
import { execFileSync } from 'node:child_process';
const spawnSyncGit = (a) => execFileSync('git', a, { cwd: REPO, encoding: 'utf8' }).trim();
const COMMIT = git('rev-parse', 'HEAD');
mkdirSync(OUT, { recursive: true });

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
  return pg;
}

async function startService() {
  const root = mkdtempSync(join(tmpdir(), 'ot-cmp-'));
  const svc = spawn(process.env.PYTHON || 'python3', ['-m', 'opentrace_core.app', '--port', '0', '--session-root', join(root, 's')], { cwd: REPO, env: { ...process.env, PYTHONPATH: join(REPO, 'src/core') }, stdio: ['ignore', 'pipe', 'pipe'] });
  const base = await new Promise((res, rej) => { let b = ''; const t = setTimeout(() => rej(new Error('service did not start: ' + b)), 30000); svc.stdout.on('data', (d) => { b += d; const m = b.match(/http:\/\/127\.0\.0\.1:(\d+)\//); if (m) { clearTimeout(t); res(m[0]); } }); svc.stderr.on('data', (d) => { b += d; }); });
  return { base, stop: () => { svc.kill('SIGTERM'); try { rmSync(root, { recursive: true, force: true }); } catch {} } };
}

// In-page extractor: visible interactive/heading elements with text, rect and the computed style subset that defines the look.
const EXTRACT = `(()=>{const vis=e=>{const r=e.getBoundingClientRect();const cs=getComputedStyle(e);return r.width>0&&r.height>0&&cs.visibility!=='hidden'&&cs.display!=='none'&&!e.closest('[hidden],[aria-hidden=true],dialog:not([open]),template,script,style')};
 const norm=t=>String(t||'').replace(/\\s+/g,' ').trim();
 const q=['header','nav','h1','h2','h3','button','a[href]','input','select','textarea','[role=tab]','[role=tablist]','.ot2-summary-pills li','aside','label','summary'];
 const out=[];const seen=new Set();
 for(const e of document.querySelectorAll(q.join(','))){if(seen.has(e)||!vis(e))continue;seen.add(e);const r=e.getBoundingClientRect(),cs=getComputedStyle(e);
  const text=norm(e.innerText||e.value||e.placeholder||e.getAttribute('aria-label')||'').slice(0,80);
  out.push({tag:e.tagName.toLowerCase(),role:e.getAttribute('role')||'',text,rect:{x:Math.round(r.x),y:Math.round(r.y+scrollY),w:Math.round(r.width),h:Math.round(r.height)},
   style:{color:cs.color,bg:cs.backgroundColor,fs:cs.fontSize,fw:cs.fontWeight,radius:cs.borderTopLeftRadius,border:cs.borderTopColor+' '+cs.borderTopWidth,pad:cs.padding,ff:cs.fontFamily.split(',')[0].replace(/["']/g,'')}});}
 return {tabs:[...document.querySelectorAll('[role=tab]')].filter(vis).map(e=>norm(e.innerText)),h1:[...document.querySelectorAll('h1')].filter(vis).map(e=>norm(e.innerText)),
  scrollW:document.documentElement.scrollWidth,innerW:innerWidth,els:out}})()`;

const key = (e) => (e.tag + '|' + e.text.toLowerCase().replace(/[0-9][0-9,.]*/g, '#')).slice(0, 90);
const rgb = (s) => s;
function compare(refX, appX) {
  const index = (x) => { const m = new Map(); for (const e of x.els) { const k = key(e); if (!m.has(k)) m.set(k, e); } return m; };
  const R = index(refX), A = index(appX);
  const onlyRef = [...R.keys()].filter((k) => !A.has(k) && R.get(k).text), onlyApp = [...A.keys()].filter((k) => !R.has(k) && A.get(k).text);
  const pairs = [];
  for (const [k, r] of R) { const a = A.get(k); if (!a || !r.text) continue;
    const d = {};
    for (const f of ['w', 'h']) if (Math.abs(r.rect[f] - a.rect[f]) > 4) d[f] = [r.rect[f], a.rect[f]];
    for (const f of ['color', 'bg', 'fs', 'fw', 'radius', 'border', 'ff']) if (r.style[f] !== a.style[f]) d[f] = [r.style[f], a.style[f]];
    pairs.push({ key: k, text: r.text, diff: d }); }
  // Manual pairs: controls that are the same role with a deliberately different label (approved contract changes) or a prefixed accessible name.
  const find = (x, tag, re) => x.els.find((e) => e.tag === tag && re.test(e.text));
  const manual = [['primary action (reference Preview review → / application Scan ↗)', 'button', /^preview review/i, /^scan/i], ['theme switch', 'button', /^switch (to dark )?theme|^switch to (dark|light)/i, /^switch to (dark|light) theme|^switch theme/i],
    ['hero heading', 'h1', /know what/i, /know what/i], ['repository URL input', 'input', /github|owner|repo|url|https/i, /github|owner|repo|url|https/i], ['demo link/button', 'button', /demo/i, /demo/i]].map(([name, tag, rr, ar]) => {
    const r = find(refX, tag, rr), a = find(appX, tag, ar); if (!r || !a) return { name, found: { ref: !!r, app: !!a } };
    const d = {}; for (const f of ['w', 'h', 'x', 'y']) if (Math.abs(r.rect[f] - a.rect[f]) > (f === 'x' || f === 'y' ? 8 : 4)) d[f] = [r.rect[f], a.rect[f]];
    for (const f of ['color', 'bg', 'fs', 'fw', 'radius', 'border', 'ff']) if (r.style[f] !== a.style[f]) d[f] = [r.style[f], a.style[f]];
    return { name, ref_text: r.text, app_text: a.text, diff: d }; });
  return { manual_pairs: manual, tabs: { ref: refX.tabs, app: appX.tabs, same_order: JSON.stringify(refX.tabs) === JSON.stringify(appX.tabs) }, h1: { ref: refX.h1, app: appX.h1 },
    horizontal_overflow: { ref: refX.scrollW > refX.innerW, app: appX.scrollW > appX.innerW }, counts: { ref: refX.els.length, app: appX.els.length, paired: pairs.length },
    only_in_reference: onlyRef, only_in_application: onlyApp, paired_with_differences: pairs.filter((p) => Object.keys(p.diff).length), paired_identical: pairs.filter((p) => !Object.keys(p.diff).length).length };
}

const { browser, close } = await launch();
const svc = await startService();
const results = []; const environment = { browser: null, commit: COMMIT, reference_hash: REFERENCE_HASH };
try {
  for (const vp of viewports) for (const theme of themes) {
    const ref = await openPage(browser, vp, theme), app = await openPage(browser, vp, theme);
    await ref.goto('file://' + REFERENCE); await sleep(1500); await ref.eval(`document.documentElement.dataset.theme=${JSON.stringify(theme)};true`);
    await app.goto(svc.base); await sleep(800); await app.eval(`window.__otStore.dispatch({type:'THEME',value:${JSON.stringify(theme)}})`); await sleep(400);
    environment.browser ||= await ref.eval('navigator.userAgent');
    const rec = { viewport: vp.id, theme, states: {} };
    await sleep(300);
    rec.states.home = compare(await ref.eval(EXTRACT), await app.eval(EXTRACT));
    // interaction: the sample (Demo) entry on both sides, then the Workbench handoff view
    const clicked = { ref: await ref.eval(`(()=>{const b=document.querySelector('#ot-demo');if(!b)return false;b.click();return true})()`), app: await app.eval(`(()=>{const b=document.querySelector('#ot-demo');if(!b)return false;b.click();return true})()`) };
    await sleep(2800);
    rec.demo_control_found = clicked;
    rec.states.workbench = compare(await ref.eval(EXTRACT), await app.eval(EXTRACT));
    results.push(rec);
    await ref.close(); await app.close();
  }
} finally { svc.stop(); await close(); }
const doc = { schema: 'opentrace.uip.dom_compare/1', increment: 'UIP-03 acceptance packet', tested_commit: COMMIT, environment, blocked_requests: blocked, tolerance: { size_px: 4, style: 'exact computed value' }, results };
writeFileSync(join(OUT, 'dom_compare.json'), JSON.stringify(doc, null, 1) + '\n');
console.log('wrote', join(OUT, 'dom_compare.json'), 'blocked:', blocked.length);
