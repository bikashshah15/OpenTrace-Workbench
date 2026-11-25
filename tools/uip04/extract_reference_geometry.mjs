// UIP-04 verification tool (no application code): opens the approved reference prototype (file:, hash-gated, loopback-only network
// policy) in Chrome and records the repository-context map's SVG geometry, text, connectors and the four category tokens (light and
// dark computed fill/stroke) as DOM/SVG attribute facts. The output is the test oracle for the layout model; it contains reference
// content, so it lives with the reference artifacts and is labelled as such.
//   node tools/uip04/extract_reference_geometry.mjs [--out evidence/uip/visual/uip-04/reference_geometry.json]
import { readFileSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { launch, newPage } from '../../tests/ui/browser/cdp.mjs';
import { isLoopbackUrl } from '../uip/visual/lib.mjs';

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const REFERENCE = join(REPO, '.context/references/prototypes/OpenTrace-UI-Update-9-Combined.html');
const HASH = 'd5bc14fabff29dc42a53dab1f91ae88a6165d70aee808f17e76d066901b3a148';
const args = process.argv.slice(2); const oi = args.indexOf('--out');
const OUT = resolve(oi >= 0 ? args[oi + 1] : join(REPO, 'evidence/uip/visual/uip-04/reference_geometry.json'));
const sha = createHash('sha256').update(readFileSync(REFERENCE)).digest('hex');
if (sha !== HASH) { console.error('reference hash mismatch', sha); process.exit(2); }

const EXTRACT = `(()=>{
  const svg=document.getElementById('context-map-svg'); const num=(e,a)=>Number(e.getAttribute(a));
  const rect=e=>({x:num(e,'x'),y:num(e,'y'),w:num(e,'width'),h:num(e,'height')});
  const txt=e=>({x:num(e,'x'),y:num(e,'y'),size:num(e,'font-size'),text:e.textContent});
  const rootG=svg.querySelector('[data-context-root]');
  const groups=[...svg.querySelectorAll('.context-map-group')].map(g=>{
    const kind=g.dataset.contextKind; const zone=g.querySelector(':scope > rect');
    const head=g.querySelector('[data-context-group]'); const files=[...g.querySelectorAll('[data-context-file]')];
    return {kind,zone:rect(zone),header:rect(head.querySelector('rect')),headerText:[...head.querySelectorAll('text')].map(txt),
      files:files.map(f=>({path:f.dataset.contextFile,rect:rect(f.querySelector('rect')),texts:[...f.querySelectorAll('text')].map(txt)})),
      links:[...g.querySelectorAll(':scope > path')].map(p=>p.getAttribute('d'))};});
  const cs=(el,p)=>getComputedStyle(el)[p];
  const tokens={};
  for(const g of svg.querySelectorAll('.context-map-group')){const z=g.querySelector(':scope > rect'),h=g.querySelector('[data-context-group] rect'),f=g.querySelector('[data-context-file] rect');
    tokens[g.dataset.contextKind]={zoneFill:cs(z,'fill'),edge:cs(z,'stroke'),headerFill:cs(h,'fill'),fileFill:cs(f,'fill')};}
  return {viewBox:svg.getAttribute('viewBox'),connectors:svg.querySelector(':scope > path').getAttribute('d'),
    root:{rect:rect(rootG.querySelector('rect')),texts:[...rootG.querySelectorAll('text')].map(txt)},groups,tokens};
})()`;

const blocked = [];
const { browser, close } = await launch();
const out = { reference: { file: '.context/references/prototypes/OpenTrace-UI-Update-9-Combined.html', sha256: HASH }, viewport: '1366x900', themes: {} };
try {
  const pg = await newPage(browser, { width: 1366, height: 900 });
  await pg.send('Fetch.enable', { patterns: [{ urlPattern: '*' }] });
  browser.on((m) => { if (m.sessionId !== pg.sessionId || m.method !== 'Fetch.requestPaused') return; const u = m.params.request.url; if (isLoopbackUrl(u)) pg.send('Fetch.continueRequest', { requestId: m.params.requestId }).catch(() => {}); else { blocked.push(u); pg.send('Fetch.failRequest', { requestId: m.params.requestId, errorReason: 'BlockedByClient' }).catch(() => {}); } });
  await pg.goto('file://' + REFERENCE);
  await pg.waitFor(`document.getElementById('context-map-svg') && document.querySelectorAll('#context-map-svg .context-map-group').length===4`, 30000, 'reference map');
  for (const theme of ['light', 'dark']) {
    await pg.eval(`document.documentElement.dataset.theme=${JSON.stringify(theme)}`);
    await new Promise((r) => setTimeout(r, 200));
    out.themes[theme] = await pg.eval(EXTRACT);
  }
  out.blocked_requests = blocked;
} finally { await close(); }
writeFileSync(OUT, JSON.stringify(out, null, 2) + '\n');
console.log('wrote', OUT, 'blocked', blocked.length);
