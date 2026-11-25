// UIP-05 verification tool (no application code): compares the Dependencies tab with the approved reference prototype on the recorded
// Demo (the reference carries the same captured data), and captures a small representative screenshot set.
//   PYTHON=<python> node tools/uip05/reference_compare.mjs [--out evidence/uip/visual/uip-05]
// The reference is opened from file: after its SHA-256 is verified; its Cytoscape instance (container._cyreg) is read for node
// positions and computed styles. Network: loopback and file: only; anything else is blocked and recorded.
// Output: reference_compare.json (facts + per-item verdict), screenshots/*.png. Nothing is edited; no threshold is raised.
import { spawn } from 'node:child_process';
import { readFileSync, writeFileSync, mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { launch, newPage } from '../../tests/ui/browser/cdp.mjs';

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const REFERENCE = join(REPO, '.context/references/prototypes/OpenTrace-UI-Update-9-Combined.html');
const HASH = 'd5bc14fabff29dc42a53dab1f91ae88a6165d70aee808f17e76d066901b3a148';
const args = process.argv.slice(2); const oi = args.indexOf('--out');
const OUT = resolve(oi >= 0 ? args[oi + 1] : join(REPO, 'evidence/uip/visual/uip-05'));
const SHOTS = join(OUT, 'screenshots'); mkdirSync(SHOTS, { recursive: true });
const sha = createHash('sha256').update(readFileSync(REFERENCE)).digest('hex');
if (sha !== HASH) { console.error('reference hash mismatch', sha); process.exit(2); }
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const blocked = []; let lastHash = null;

const root = mkdtempSync(join(tmpdir(), 'ot-uip05-'));
const svc = spawn(process.env.PYTHON || 'python3', ['-m', 'opentrace_core.app', '--port', '0', '--session-root', join(root, 's')], { cwd: REPO,
  env: { ...process.env, PYTHONPATH: join(REPO, 'src/core') + ':' + join(REPO, 'src/agents/investigator') }, stdio: ['ignore', 'pipe', 'pipe'] });
const base = await new Promise((res, rej) => { let b = ''; const t = setTimeout(() => rej(new Error('service did not start: ' + b)), 30000); svc.stdout.on('data', (d) => { b += d; const m = b.match(/http:\/\/127\.0\.0\.1:(\d+)\//); if (m) { clearTimeout(t); res(m[0]); } }); svc.stderr.on('data', (d) => { b += d; }); });
const { browser, close } = await launch();

async function page(width, height, theme, url) {
  const pg = await newPage(browser, { width, height, mobile: width <= 700 });
  await pg.send('Fetch.enable', { patterns: [{ urlPattern: '*' }] });
  browser.on((m) => { if (m.sessionId !== pg.sessionId || m.method !== 'Fetch.requestPaused') return; const u = m.params.request.url;
    if (/^(http:\/\/(127\.0\.0\.1|localhost)[:/])|^(file:|data:|blob:|about:)/.test(u)) pg.send('Fetch.continueRequest', { requestId: m.params.requestId }).catch(() => {});
    else { blocked.push(u); pg.send('Fetch.failRequest', { requestId: m.params.requestId, errorReason: 'BlockedByClient' }).catch(() => {}); } });
  await pg.send('Emulation.setEmulatedMedia', { features: [{ name: 'prefers-reduced-motion', value: 'reduce' }, { name: 'prefers-color-scheme', value: theme }] });
  await pg.goto(url); await sleep(900);
  return pg;
}
const shot = async (pg, sel, file) => {
  const r = await pg.eval(`(()=>{const e=document.querySelector(${JSON.stringify(sel)}); if(!e) return null; e.scrollIntoView({block:'start'}); const b=e.getBoundingClientRect(); return {x:Math.max(0,b.x), y:Math.max(0,b.y), width:b.width, height:Math.min(b.height, 1400)}})()`);
  if (!r) return false;
  const res = await pg.send('Page.captureScreenshot', { format: 'png', clip: { ...r, scale: 1 }, captureBeyondViewport: true });
  const buf = Buffer.from(res.data, 'base64'); if (file) writeFileSync(join(SHOTS, file), buf); return createHash('sha256').update(buf).digest('hex');
};

// ------------------------------------------------------------------ extraction
const PILL = `(sel)=>[...document.querySelectorAll(sel)].map(b=>{const c=getComputedStyle(b);return {label:b.childNodes[0].textContent.trim(),count:b.querySelector('span').textContent.trim(),pressed:b.getAttribute('aria-pressed'),color:c.color,background:c.backgroundColor,border:c.borderTopColor+' '+c.borderTopWidth,radius:c.borderTopLeftRadius,font:c.fontSize+' '+c.fontFamily.split(',')[0],padding:c.padding}})`;
const REF_EXTRACT = `(()=>{const cy=document.getElementById('flow-canvas')._cyreg.cy; const w=cy.width(); const ns=cy.nodes().map(n=>({id:n.id(),x:n.position().x,y:n.position().y,w:+n.style('width').replace('px',''),h:+n.style('height').replace('px',''),border:n.style('border-color'),bw:+n.style('border-width').replace('px',''),bg:n.style('background-color'),bs:n.style('border-style'),op:+n.style('opacity'),label:n.data('label'),flags:['root','connector','matched','gap','chosen'].filter(k=>n.data(k)).concat([n.data('relation')])}));
  const pager=document.getElementById('friendly-pager'); const pc=pager&&getComputedStyle(pager);
  const edges=cy.edges().length;
  return {stageWidth:w, columns:Math.max(2,Math.min(6,Math.floor((w-48)/160))), nodes:ns, edges, pills:(${PILL})('[data-friendly-filter]'), pager:pager?{text:document.getElementById('friendly-page-count').innerText,top:pc.top,right:pc.right,font:pc.fontSize,hidden:pager.hidden}:null, caption:document.getElementById('flow-status')?.innerText, captionNote:document.getElementById('ot2-graph-caption')?.innerText, stageHeight:document.getElementById('ot2-dep-stage')?.getBoundingClientRect().height}})()`;
const APP_EXTRACT = `(()=>{const svg=document.getElementById('ot5-svg'); const st=document.getElementById('ot5-stage'); const g=[...svg.querySelectorAll('[data-dep-node]')].map(n=>{const r=n.querySelector('rect'); const c=getComputedStyle(r); return {id:n.dataset.depNode,x:+r.getAttribute('x')+80,y:+r.getAttribute('y')+32,w:+r.getAttribute('width'),h:+r.getAttribute('height'),border:c.stroke,bw:parseFloat(c.strokeWidth),bg:c.fill,bs:c.strokeDasharray==='none'?'solid':'dashed',op:+getComputedStyle(n).opacity,label:[...n.querySelectorAll('text')].map(t=>t.textContent).join('\\n'),role:n.dataset.role,cls:n.getAttribute('class'),title:n.querySelector('title').textContent}});
  const pager=document.getElementById('ot5-pager'); const pc=pager&&getComputedStyle(pager);
  return {stageWidth:st.clientWidth, columns:+svg.dataset.cols, nodes:g, edges:svg.querySelectorAll('.ot5-edge').length, pills:(${PILL})('[data-ot5-filter]'), pager:pager?{text:document.getElementById('ot5-page-count').innerText,top:pc.top,right:pc.right,font:pc.fontSize,hidden:false}:null, caption:document.getElementById('ot5-status')?.innerText, captionNote:document.getElementById('ot5-caption')?.innerText, stageHeight:st.getBoundingClientRect().height, viewBox:svg.getAttribute('viewBox')}})()`;

const rgb = (s) => String(s).replace(/\s+/g, '');
const verdicts = [];
const verdict = (id, status, detail) => { verdicts.push({ id, status, detail }); console.log(status.toUpperCase().padEnd(14), id, detail || ''); };

async function refState(width, theme, file) {
  const pg = await page(width, 900, theme, 'file://' + REFERENCE);
  await pg.eval(`document.getElementById('ot-demo').click()`); await sleep(1200);
  if (theme === 'dark') await pg.eval(`document.documentElement.dataset.theme='dark'`);
  await pg.eval(`document.querySelector('[data-ot2-layer=dependencies]').click()`); await sleep(2500);
  const data = await pg.eval(REF_EXTRACT);
  await shot(pg, '#ot2-graph-frame', file);
  await pg.close(); return data;
}
async function appState(width, theme, file, hooks) {
  const pg = await page(width, 900, theme, base);
  if ((await pg.eval('window.__otStore.get().theme')) !== theme) await pg.eval("document.getElementById('ot-theme').click()");
  await pg.eval("document.getElementById('ot-demo').click()");
  await pg.waitFor(`document.querySelector('[data-map-ready="true"]')`, 30000, 'map'); await sleep(700);
  await pg.eval("document.getElementById('ot-tab-dependencies').click()");
  await pg.waitFor(`document.querySelector('#ot5-svg [data-dep-node]')`, 30000, 'graph'); await sleep(500);
  if (hooks) await hooks(pg);
  const data = await pg.eval(`document.getElementById('ot5-svg') ? ${APP_EXTRACT} : null`);
  lastHash = await shot(pg, '#ot-graph-frame', file);
  await pg.close(); return data;
}

const result = { reference: { file: '.context/references/prototypes/OpenTrace-UI-Update-9-Combined.html', sha256: HASH }, fixture: 'recorded Demo (Frigate case); same captured data in both', commit: null, viewports: {} };
try {
  for (const [w, theme, tag] of [[1366, 'light', '1366_light'], [1366, 'dark', '1366_dark'], [1920, 'light', '1920_light'], [390, 'light', '390_light']]) {
    const ref = await refState(w, theme, `reference_${tag}.png`); const app = await appState(w, theme, `app_${tag}.png`);
    result.viewports[tag] = { ref, app };
    const L = `[${tag}]`;
    verdict(`${L} columns follow the stage width`, ref.columns === app.columns ? 'matched' : 'not matched', `ref ${ref.columns} (stage ${Math.round(ref.stageWidth)}px), app ${app.columns} (stage ${Math.round(app.stageWidth)}px)`);
    verdict(`${L} 30 matching packages on the first page`, (ref.nodes.length - 1 === 30 && app.nodes.length - 1 === 30) ? 'matched' : 'not matched', `ref ${ref.nodes.length - 1}, app ${app.nodes.length - 1}`);
    const key = (n) => `${Math.round(n.x)},${Math.round(n.y)}`;
    const refPos = ref.nodes.map(key).sort(); const appPos = app.nodes.map(key).sort();
    verdict(`${L} node centre positions (root top-centre, depth band, columns, row step)`, JSON.stringify(refPos) === JSON.stringify(appPos) ? 'matched' : (ref.columns === app.columns ? 'not matched' : 'not comparable'), refPos.length === appPos.length ? '' : `${refPos.length} vs ${appPos.length}`);
    verdict(`${L} card size 160x64`, ref.nodes.every((n) => n.w === 160 && n.h === 64) && app.nodes.every((n) => n.w === 160 && n.h === 64) ? 'matched' : 'not matched');
    const refPills = ref.pills.map((p) => p.label + ' ' + p.count).join(' | '); const appPills = app.pills.map((p) => p.label + ' ' + p.count).join(' | ');
    verdict(`${L} pill labels and order`, ref.pills.map((p) => p.label).join('|') === app.pills.map((p) => p.label).join('|') ? 'matched' : 'not matched', `${refPills} || ${appPills}`);
    for (let i = 0; i < Math.min(ref.pills.length, app.pills.length); i++) {
      const a = ref.pills[i]; const b = app.pills[i];
      const same = ['color', 'background', 'border', 'radius', 'font', 'padding'].filter((k) => rgb(a[k]) !== rgb(b[k]));
      verdict(`${L} pill "${a.label}" style (${tag.endsWith('dark') ? 'dark' : 'light'})`, same.length ? 'not matched' : 'matched', same.map((k) => `${k}: ${a[k]} vs ${b[k]}`).join('; '));
    }
    const diffCounts = ref.pills.map((p, i) => [p.label, p.count, app.pills[i]?.count]).filter(([, a, b]) => a !== b);
    if (diffCounts.length) verdict(`${L} pill counts`, 'not matched', diffCounts.map(([l, a, b]) => `${l}: ref ${a}, app ${b}`).join('; ') + ' (approved contract: recorded advisory coverage is not_run; see log)');
    else verdict(`${L} pill counts`, 'matched');
    verdict(`${L} compact pager text`, ref.pager?.text === app.pager?.text ? 'matched' : 'not matched', `${ref.pager?.text} vs ${app.pager?.text}`);
    if (ref.pager && app.pager) verdict(`${L} pager placement and font`, ref.pager.top === app.pager.top && ref.pager.right === app.pager.right && ref.pager.font === app.pager.font ? 'matched' : 'not matched', `${ref.pager.top}/${ref.pager.right}/${ref.pager.font} vs ${app.pager.top}/${app.pager.right}/${app.pager.font}`);
    if (tag === '1366_light' || tag === '1366_dark') {
      const rootR = ref.nodes.find((n) => n.flags.includes('root')); const rootA = app.nodes.find((n) => n.role === 'focus');
      verdict(`${L} focus card border and fill`, rgb(rootR.border) === rgb(rootA.border) && rootR.bw === rootA.bw && rgb(rootR.bg) === rgb(rootA.bg) ? 'matched' : 'not matched', `${rootR.border} ${rootR.bw} ${rootR.bg} vs ${rootA.border} ${rootA.bw} ${rootA.bg}`);
      const dR = ref.nodes.find((n) => n.flags.includes('direct') && !n.flags.includes('matched') && !n.flags.includes('gap') && !n.flags.includes('root') && !n.flags.includes('connector')); const dA = app.nodes.find((n) => /\bdirect\b/.test(n.cls) && !/matched|gap|connector|root/.test(n.cls));
      if (dR && dA) verdict(`${L} direct card border and fill`, rgb(dR.border) === rgb(dA.border) && dR.bw === dA.bw && rgb(dR.bg) === rgb(dA.bg) ? 'matched' : 'not matched', `${dR.border} ${dR.bw} ${dR.bg} vs ${dA.border} ${dA.bw} ${dA.bg}`);
      const mR = ref.nodes.find((n) => n.flags.includes('matched')); const mA = app.nodes.find((n) => /matched/.test(n.cls));
      if (mR && mA) verdict(`${L} advisory-match card border`, rgb(mR.border) === rgb(mA.border) && mR.bw === mA.bw ? 'matched' : 'not matched', `${mR.border} ${mR.bw} vs ${mA.border} ${mA.bw}`);
    }
    verdict(`${L} graph caption sentence`, ref.captionNote === app.captionNote ? 'matched' : 'not matched', `${ref.captionNote} || ${app.captionNote}`);
    verdict(`${L} caption wording (focus, shown of total)`, ref.caption?.replace(/\s+/g, ' ') === app.caption?.replace(/\s+/g, ' ') ? 'matched' : 'not matched', `${ref.caption} || ${app.caption}`);
  }
  // package set: the reference pages in declaration order; the frozen contract orders matches by name, version, id.
  const r = result.viewports['1366_light'];
  const refNames = r.ref.nodes.map((n) => n.label.split('\n')[0].replace('\u2026', ''));
  const overlap = r.app.nodes.filter((n) => refNames.some((rn) => n.title.startsWith(rn))).length;
  verdict('[1366_light] which 30 of the 82 packages are on page 1', overlap === 31 ? 'matched' : 'approved exception', `reference order = declaration order; app order = name, version, id (frozen contract 4.3): ${overlap - 1}/30 identical`);
  // app-only state screenshots
  for (const [name, hook] of [['page2', "document.querySelector('[data-action=dep-page][data-dir=\"1\"]').click()"], ['transitive', "document.querySelector('[data-ot5-filter=transitive]').click()"], ['advisory', "document.querySelector('[data-ot5-filter=advisory]').click()"], ['gaps', "document.querySelector('[data-ot5-filter=gaps]').click()"], ['list', "document.querySelector('[data-action=dep-pres][data-p=list]').click()"]]) {
    await appState(1366, 'light', `app_state_${name}.png`, async (pg) => { await pg.eval(hook); await sleep(1500); });
  }
  await appState(1366, 'light', 'app_state_empty.png', async (pg) => {
    await pg.eval("(()=>{const n=[...document.querySelectorAll('#ot5-svg [data-dep-node]')].find(x=>x.dataset.role!=='focus'); n.dispatchEvent(new MouseEvent('click',{bubbles:true}));})()"); await sleep(300);
    await pg.eval("(()=>{const n=[...document.querySelectorAll('#ot5-svg [data-dep-node]')].find(x=>x.dataset.role!=='focus'); n.dispatchEvent(new MouseEvent('dblclick',{bubbles:true}));})()"); await sleep(1800);
  });
  // repeatability of the app capture itself (same state, same browser, fresh page each time); thresholds are not used or raised
  const REPEATS = 5; const hashes = [];
  for (let i = 0; i < REPEATS; i++) hashes.push(await appState(1366, 'light', null).then(() => lastHash));
  result.repeatability = { state: '1366 light, recorded Demo, Dependencies Direct page 1', repeats: REPEATS, sha256: hashes, identical: new Set(hashes).size === 1 };
  verdict('app screenshot repeatability (5 fresh captures, same state)', result.repeatability.identical ? 'matched' : 'not matched', result.repeatability.identical ? 'byte-identical' : 'differs');
} finally { await close(); svc.kill(); try { rmSync(root, { recursive: true, force: true }); } catch {} }
result.verdicts = verdicts; result.blocked_requests = blocked;
writeFileSync(join(OUT, 'reference_compare.json'), JSON.stringify(result, null, 1) + '\n');
const c = (s) => verdicts.filter((v) => v.status === s).length;
console.log(`\nmatched ${c('matched')} · not matched ${c('not matched')} · approved exception ${c('approved exception')} · not comparable ${c('not comparable')} · blocked requests ${blocked.length}`);
