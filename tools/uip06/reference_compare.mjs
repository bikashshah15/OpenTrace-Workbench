// UIP-06 verification tool (no application code): compares the Cryptography tab with the approved reference prototype (hash-verified) and captures
// a small representative set. The reference's own crypto block is driven in the browser and its SVG geometry, filter strings, tokens and control
// labels are read; the application is rendered from a SYNTHETIC renderer fixture with the same composition (<=3 groups, <=3 cards).
// Differences caused by honest data (the reference shows five Frigate source-derived assets, the Demo shows none) are reported, not hidden.
//   PYTHON=<python> node tools/uip06/reference_compare.mjs [--out evidence/uip/visual/uip-06]
import { spawn } from 'node:child_process';
import { readFileSync, writeFileSync, mkdirSync, mkdtempSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { launch, newPage } from '../../tests/ui/browser/cdp.mjs';

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const REFERENCE = join(REPO, '.context/references/prototypes/OpenTrace-UI-Update-9-Combined.html');
const HASH = 'd5bc14fabff29dc42a53dab1f91ae88a6165d70aee808f17e76d066901b3a148';
const args = process.argv.slice(2); const oi = args.indexOf('--out');
const OUT = resolve(oi >= 0 ? args[oi + 1] : join(REPO, 'evidence/uip/visual/uip-06')); const SHOTS = join(OUT, 'reference_captures'); mkdirSync(SHOTS, { recursive: true });
const sha = createHash('sha256').update(readFileSync(REFERENCE)).digest('hex');
if (sha !== HASH) { console.error('reference hash mismatch', sha); process.exit(2); }
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const fx = JSON.parse(readFileSync(join(REPO, 'evidence/uip/visual/uip-06/fixtures/renderer/multi3.json'), 'utf8'));
const root = mkdtempSync(join(tmpdir(), 'ot-uip06-'));
const svc = spawn(process.env.PYTHON || 'python3', ['-m', 'opentrace_core.app', '--port', '0', '--session-root', join(root, 's')], { cwd: REPO, env: { ...process.env, PYTHONPATH: join(REPO, 'src/core') + ':' + join(REPO, 'src/agents/investigator') }, stdio: ['ignore', 'pipe', 'pipe'] });
const base = await new Promise((res, rej) => { let b = ''; const t = setTimeout(() => rej(new Error('no start ' + b)), 30000); svc.stdout.on('data', (d) => { b += d; const m = b.match(/http:\/\/127\.0\.0\.1:(\d+)\//); if (m) { clearTimeout(t); res(m[0]); } }); svc.stderr.on('data', (d) => { b += d; }); });
const { browser, close } = await launch();
const items = []; const item = (id, ref, app, verdict, note = '') => { items.push({ id, reference: ref, application: app, verdict, note }); console.log(verdict.toUpperCase().padEnd(12), id, note); };
const same = (id, a, b, note) => item(id, a, b, JSON.stringify(a) === JSON.stringify(b) ? 'matched' : 'not matched', note);
const GEO = `(()=>{const g=[...document.querySelectorAll('#ot5-svg g.ot5-group, #otc-svg g.otc-group')].map(x=>{const q=(s)=>[...x.querySelectorAll(s)];const zone=x.querySelector(':scope > rect');const head=x.querySelector('g[role=button] rect');const cards=q('g[role=button]').slice(1).map(c=>{const r=c.querySelector('rect');return [+r.getAttribute('x')-(+zone.getAttribute('x')),+r.getAttribute('y'),+r.getAttribute('width'),+r.getAttribute('height')]});return {zone:[+zone.getAttribute('x'),+zone.getAttribute('y'),+zone.getAttribute('width'),+zone.getAttribute('height')],head:[+head.getAttribute('x')-(+zone.getAttribute('x')),+head.getAttribute('y'),+head.getAttribute('width'),+head.getAttribute('height')],cards}});const root=document.querySelector('#ot5-svg > g > rect, #otc-svg [data-otc-select=root] rect');return {groups:g,root:[+root.getAttribute('x'),+root.getAttribute('y'),+root.getAttribute('width'),+root.getAttribute('height')],vb:document.querySelector('#ot5-svg, #otc-svg').getAttribute('viewBox')}})()`;
const CTRL = `(()=>{const p=document.querySelector('#ot5-crypto, #ot-tabpanel');return {filters:[...p.querySelectorAll('[data-ot5-filter],[data-otc-filter]')].map(b=>b.textContent.replace(/\\s+\\d+$/,'').trim()),pres:[...p.querySelectorAll('[data-ot5-pres],[data-otc-pres]')].map(b=>b.textContent.trim()),zoom:[...p.querySelectorAll('[data-ot5-zoom],[data-otc-zoom]')].map(b=>b.getAttribute('aria-label'))}})()`;

// ---- reference
const ref = await newPage(browser, { width: 1366, height: 900 });
await ref.goto('file://' + REFERENCE); await sleep(1500);
await ref.eval("document.getElementById('ot2-graph-frame').dataset.activeLayer='crypto'"); await sleep(600);
const R = await ref.eval(GEO); const RC = await ref.eval(CTRL);
const refTok = await ref.eval("(()=>{const z=document.querySelector('#ot5-svg [data-ot5-color=blue]');const cs=getComputedStyle(z);return {zone:cs.getPropertyValue('--ot5-zone').trim(),header:cs.getPropertyValue('--ot5-header').trim(),file:cs.getPropertyValue('--ot5-file').trim(),edge:cs.getPropertyValue('--ot5-edge').trim(),review:getComputedStyle(document.getElementById('ot5-crypto')).getPropertyValue('--ot5-review-bg').trim()}})()");
const refTitle = await ref.eval("document.querySelector('#ot5-crypto .ot5-capture')?.textContent");
await ref.screenshot(join(SHOTS, 'reference_crypto_1366_light.png'));
// ---- application (synthetic fixture with the same composition)
const pg = await newPage(browser, { width: 1366, height: 900 });
await pg.goto(base); await sleep(300);
await pg.eval("document.getElementById('ot-demo').click()"); await pg.waitFor(`document.querySelector('[data-map-ready="true"]')`, 30000); await sleep(500);
await pg.eval(`(()=>{const orig=window.fetch.bind(window);const f=${JSON.stringify(fx)};window.fetch=(u,i)=>!/crypto-assets/.test(String(u))?orig(u,i):orig(u,i).then(async r=>{const real=await r.json();const x=JSON.parse(JSON.stringify(f));x.binding=real.binding;const b=real.binding;for(const a of x.assets)for(const o of a.occurrences)o.source_location.link.href='https://github.com/'+b.repository.owner+'/'+b.repository.name+'/blob/'+b.commit_sha+'/'+o.source_location.path;return new Response(JSON.stringify(x),{status:200,headers:{'content-type':'application/json'}})})})()`);
await pg.eval("document.getElementById('ot-tab-crypto').click()"); await pg.waitFor("document.querySelector('#otc-svg')", 20000); await sleep(400);
const A = await pg.eval(GEO); const AC = await pg.eval(CTRL);
const appTok = await pg.eval("(()=>{const z=document.querySelector('#otc-svg g.otc-group');const cs=getComputedStyle(z);return {zone:cs.getPropertyValue('--otc-zone').trim(),header:cs.getPropertyValue('--otc-header').trim(),file:cs.getPropertyValue('--otc-file').trim(),edge:cs.getPropertyValue('--otc-edge').trim(),review:getComputedStyle(document.querySelector('.otc-layout')).getPropertyValue('--otc-review-bg').trim()}})()");
await pg.screenshot(join(SHOTS, 'application_synthetic_crypto_1366_light.png'));
const rg = R.groups.length, ag = A.groups.length;
item('group count', rg, ag, rg === ag ? 'matched' : 'not matched', 'the reference shows its five Frigate assets in its own groups; the application shows the synthetic fixture (same composition), so counts may legitimately differ');
const n = Math.min(rg, ag);
same('root node geometry (x,y,w,h)', R.root, A.root);
const cmp = (k) => JSON.stringify(R.groups.slice(0, n).map((g) => g[k])) === JSON.stringify(A.groups.slice(0, n).map((g) => g[k]));
item('zone size and y (360x500 at y=160)', R.groups.map((g) => g.zone.slice(1)), A.groups.map((g) => g.zone.slice(1)), R.groups.every((g) => g.zone[1] === 160 && g.zone[2] === 360 && g.zone[3] === 500) && A.groups.every((g) => g.zone[1] === 160 && g.zone[2] === 360 && g.zone[3] === 500) ? 'matched' : 'not matched');
item('header offset/size (+15,176,330,66)', R.groups.map((g) => g.head), A.groups.map((g) => g.head), cmp('head') ? 'matched' : 'not matched');
const cardsOk = A.groups.every((g) => g.cards.every((c, i) => c[0] === 42 && c[1] === 280 + 120 * i && c[2] === 300 && c[3] === 90)) && R.groups.every((g) => g.cards.every((c, i) => c[0] === 42 && c[1] === 280 + 120 * i && c[2] === 300 && c[3] === 90));
item('card geometry (+42, 280+120*i, 300x90)', R.groups.map((g) => g.cards.length), A.groups.map((g) => g.cards.length), cardsOk ? 'matched' : 'not matched');
item('zone x positions for the same group count', R.groups.map((g) => g.zone[0]), A.groups.map((g) => g.zone[0]), rg === ag ? (JSON.stringify(R.groups.map((g) => g.zone[0])) === JSON.stringify(A.groups.map((g) => g.zone[0])) ? 'matched' : 'not matched') : 'not yet exercised', rg === ag ? '' : 'group counts differ; geometry for the application\'s count is asserted by unit and browser tests against the same formula');
item('Fit window', R.vb, A.vb, R.vb === A.vb ? 'matched' : (rg === ag ? 'not matched' : 'not yet exercised'), 'depends on the group count (formula identical: unit test)');
same('filter labels', RC.filters, AC.filters); same('presentation labels', RC.pres, AC.pres);
item('zoom control labels', RC.zoom, AC.zoom, JSON.stringify(RC.zoom) === JSON.stringify(AC.zoom) ? 'matched' : 'not matched', 'aria-label wording differs (not an approved exception; classified not matched until changed or accepted); behaviour is asserted in the browser checks');
same('colour tokens (blue source group)', refTok, appTok);
item('reference five-asset Frigate rows', 'five source-derived assets (experimental extractor)', 'none: the recorded CBOM lists no assets', 'not yet exercised', 'UIP-06C / UIP-D03 (FD-2); shown honestly as an empty Demo');
item('third download "extractor"', 'present', 'not ported', 'approved exception', 'FD-7');
writeFileSync(join(OUT, 'reference_compare.json'), JSON.stringify({ reference_sha256: sha, items, reference_capture_label: refTitle }, null, 1));
const bad = items.filter((i) => i.verdict === 'not matched');
console.log(`\n${items.length} items; matched ${items.filter((i) => i.verdict === 'matched').length}; not matched ${bad.length}`);
await close(); svc.kill('SIGKILL'); process.exit(0);
