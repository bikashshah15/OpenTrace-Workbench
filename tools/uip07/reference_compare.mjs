// UIP-07 verification tool (no application code): compares the AI models tab with the approved reference prototype (hash-verified) on structure, computed
// style and interaction, and captures a small representative set. The reference's own AI block is driven in the browser (its geometry, strings, resolved
// colours, fonts and interaction results are read); the application is rendered from a SYNTHETIC renderer fixture with the same composition
// (two source groups with 2 and 3 cards: 2 model references, 3 runtime options incl. a preferred/fallback pair). Structural equality alone does not establish
// visual parity; no visual acceptance is claimed (UIP-D29). Differences caused by honest data (the reference shows five Frigate assets with invented-by-extractor
// metadata, the Demo shows one inventory-reported model) are reported, not hidden.
//   PYTHON=<python> node tools/uip07/reference_compare.mjs [--out evidence/uip/visual/uip-07]
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
const OUT = resolve(oi >= 0 ? args[oi + 1] : join(REPO, 'evidence/uip/visual/uip-07')); const SHOTS = join(OUT, 'reference_captures'); mkdirSync(SHOTS, { recursive: true });
const sha = createHash('sha256').update(readFileSync(REFERENCE)).digest('hex');
if (sha !== HASH) { console.error('reference hash mismatch', sha); process.exit(2); }
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const fx = JSON.parse(readFileSync(join(REPO, 'evidence/uip/visual/uip-07/fixtures/renderer/ref_composition.json'), 'utf8'));
const root = mkdtempSync(join(tmpdir(), 'ot-uip07-'));
const svc = spawn(process.env.PYTHON || 'python3', ['-m', 'opentrace_core.app', '--port', '0', '--session-root', join(root, 's')], { cwd: REPO, env: { ...process.env, PYTHONPATH: join(REPO, 'src/core') + ':' + join(REPO, 'src/agents/investigator') }, stdio: ['ignore', 'pipe', 'pipe'] });
const base = await new Promise((res, rej) => { let b = ''; const t = setTimeout(() => rej(new Error('no start ' + b)), 30000); svc.stdout.on('data', (d) => { b += d; const m = b.match(/http:\/\/127\.0\.0\.1:(\d+)\//); if (m) { clearTimeout(t); res(m[0]); } }); svc.stderr.on('data', (d) => { b += d; }); });
const { browser, close } = await launch();
const items = []; const item = (id, ref, app, verdict, note = '') => { items.push({ id, reference: ref, application: app, verdict, note }); console.log(verdict.toUpperCase().padEnd(16), id, note); };
const same = (id, a, b, note) => item(id, a, b, JSON.stringify(a) === JSON.stringify(b) ? 'matched' : 'not matched', note);

// One probe for both documents: P = {ref prefix, app prefix}. Geometry, resolved paint, fonts and structure of the same composition.
const PROBE = (svgSel, groupSel, kindAttr, filterSel, presSel, zoomSel, toolbarSel, stageSel) => `(()=>{
  const num=(v)=>+v; const cs=(el,p)=>getComputedStyle(el).getPropertyValue(p).trim();
  const svg=document.querySelector(${JSON.stringify(svgSel)}); const groups=[...svg.querySelectorAll(${JSON.stringify(groupSel)})];
  const out={groups:[],cards:[]};
  groups.forEach((g)=>{ const zone=g.querySelector(':scope > rect'); const head=g.querySelector('g[role=button] rect'); const zx=num(zone.getAttribute('x'));
    out.groups.push({zone:[zx,num(zone.getAttribute('y')),num(zone.getAttribute('width')),num(zone.getAttribute('height'))],head:[num(head.getAttribute('x'))-zx,num(head.getAttribute('y')),num(head.getAttribute('width')),num(head.getAttribute('height'))],
      zoneFill:cs(zone,'fill'),zoneStroke:cs(zone,'stroke'),zoneDash:zone.getAttribute('stroke-dasharray'),headFill:cs(head,'fill'),headStroke:cs(head,'stroke')});
    [...g.querySelectorAll('g[role=button]')].slice(1).forEach((c)=>{ const r=c.querySelector('rect'); const t=[...c.querySelectorAll('text')];
      out.cards.push({kind:c.getAttribute(${JSON.stringify(kindAttr)}),rect:[num(r.getAttribute('x'))-zx,num(r.getAttribute('y')),num(r.getAttribute('width')),num(r.getAttribute('height')),num(r.getAttribute('rx'))],fill:cs(r,'fill'),stroke:cs(r,'stroke'),sw:r.getAttribute('stroke-width'),
        text:t.map((x)=>[num(x.getAttribute('x'))-num(r.getAttribute('x')),num(x.getAttribute('y'))-num(r.getAttribute('y')),x.getAttribute('font-size'),x.getAttribute('font-weight')||'400',cs(x,'fill')]),role:c.getAttribute('role'),tab:c.getAttribute('tabindex'),pressed:c.getAttribute('aria-pressed')}); }); });
  const rootEl=[...svg.querySelectorAll('rect')].find((r)=>r.getAttribute('width')==='280'&&r.getAttribute('height')==='72');
  out.root=[num(rootEl.getAttribute('x')),num(rootEl.getAttribute('y')),num(rootEl.getAttribute('width')),num(rootEl.getAttribute('height'))]; out.rootFill=cs(rootEl,'fill'); out.rootStroke=cs(rootEl,'stroke');
  out.connectors=[...svg.querySelectorAll(':scope > g > path')].filter((p)=>p.getAttribute('stroke-dasharray')==='5 5').map((p)=>p.getAttribute('d'));
  const panel=document.querySelector(${JSON.stringify(toolbarSel)});
  out.filters=[...panel.querySelectorAll(${JSON.stringify(filterSel)})].map((b)=>({label:b.textContent.replace(/\\s+\\d+$/,'').trim(),bg:cs(b,'background-color'),color:cs(b,'color'),border:cs(b,'border-top-color'),font:cs(b,'font-size'),radius:cs(b,'border-top-left-radius')}));
  out.pres=[...panel.querySelectorAll(${JSON.stringify(presSel)})].map((b)=>b.textContent.trim());
  out.zoom=[...panel.querySelectorAll(${JSON.stringify(zoomSel)})].map((b)=>b.getAttribute('aria-label'));
  const st=document.querySelector(${JSON.stringify(stageSel)}); out.stageH=cs(st,'height'); out.stageBg=cs(st,'background-color'); out.vb=svg.getAttribute('viewBox');
  return out; })()`;
const REFP = PROBE('#ot6-svg', 'g.ot6-group', 'data-ot6-kind', '[data-ot6-filter]', '[data-ot6-pres]', '[data-ot6-zoom]', '#ot6-ai', '#ot6-stage');
const APPP = PROBE('#otai-svg', 'g.otai-group', 'data-otai-kind', '[data-otai-filter]', '[data-otai-pres]', '[data-otai-zoom]', '#ot-tabpanel', '#otai-stage');

// ---- reference
const ref = await newPage(browser, { width: 1366, height: 900 });
await ref.goto('file://' + REFERENCE); await sleep(1500);
await ref.eval("document.querySelectorAll('.ot-page').forEach((p)=>{p.hidden=p.id!=='ot-workbench'})"); await sleep(400);
await ref.eval("document.getElementById('ot2-graph-frame').dataset.activeLayer='ai'"); await sleep(800);
await ref.waitFor("document.querySelector('#ot6-svg g.ot6-group')", 20000);
const R = await ref.eval(REFP);
const refCapture = await ref.eval("document.querySelector('#ot6-ai .ot6-capture')?.textContent");
await ref.eval("document.getElementById('ot6-ai').scrollIntoView({block:'start'})"); await sleep(400);
await ref.screenshot(join(SHOTS, 'reference_ai_1366_light.png'));
// interactions on the reference
const refInter = await ref.eval(`(async()=>{const w=(ms)=>new Promise(r=>setTimeout(r,ms)); const q=(s)=>document.querySelector(s); const out={};
  out.zoom0=q('#ot6-zoom').textContent; q('[data-ot6-zoom="1.2"]').click(); await w(80); out.zoomOut=q('#ot6-zoom').textContent; q('[data-ot6-zoom="0.8333333333333334"]').click(); await w(80); q('[data-ot6-zoom="0.8333333333333334"]').click(); await w(80); out.zoomIn=q('#ot6-zoom').textContent; q('#ot6-fit').click(); await w(80); out.fit=q('#ot6-zoom').textContent;
  q('[data-ot6-filter=models]').click(); await w(80); out.modelsCards=document.querySelectorAll('#ot6-svg g[data-ot6-kind]').length; q('[data-ot6-filter=runtimes]').click(); await w(80); out.runtimeCards=document.querySelectorAll('#ot6-svg g[data-ot6-kind]').length;
  q('[data-ot6-filter=services]').click(); await w(80); out.servicesEmpty=!q('#ot6-empty').hidden; q('[data-ot6-filter=findings]').click(); await w(80); out.findingsEmpty=!q('#ot6-empty').hidden; q('[data-ot6-filter=all]').click(); await w(80);
  const c=q('#ot6-svg g[data-ot6-kind=runtime]'); c.focus(); c.dispatchEvent(new KeyboardEvent('keydown',{key:'Enter',bubbles:true})); await w(80); out.pressedAfterEnter=document.querySelector('#ot6-svg g[data-ot6-kind=runtime][aria-pressed=true]')!==null;
  q('[data-ot6-pres=list]').click(); await w(80); out.listShown=!q('#ot6-list').hidden&&q('#ot6-stage').hidden; q('[data-ot6-pres=graph]').click(); await w(80); out.graphBack=q('#ot6-stage').hidden===false; return out;})()`);

// ---- application (synthetic fixture with the same composition)
const pg = await newPage(browser, { width: 1366, height: 900 });
await pg.goto(base); await sleep(300);
await pg.eval("document.getElementById('ot-demo').click()"); await pg.waitFor(`document.querySelector('[data-map-ready="true"]')`, 30000); await sleep(500);
await pg.eval(`(()=>{const orig=window.fetch.bind(window);const f=${JSON.stringify(fx)};window.fetch=(u,i)=>!/ai-assets/.test(String(u))?orig(u,i):orig(u,i).then(async r=>{const real=await r.json();const x=JSON.parse(JSON.stringify(f));x.binding=real.binding;const b=real.binding;const fl=new URL(String(u),location.href).searchParams.get('filter')||'all';const kind=(k)=>k==='runtime'?'runtimes':k==='ai_service'?'ai_services':'models';const rv=new Set(x.review_items.map(r=>r.asset_id));x.assets=x.assets.filter(a=>fl==='all'||(fl==='findings'?rv.has(a.asset_id):kind(a.kind)===fl));x.filter=fl;x.page.assets_total=x.page.assets_shown=x.assets.length;x.page.has_more=false;x.counts={total:x.assets.length,shown:x.assets.length,truncated:false};const ids=new Set(x.assets.map(a=>a.asset_id));x.links=x.links.filter(l=>ids.has(l.from)&&ids.has(l.to));const used=new Set(x.assets.flatMap(a=>a.source_group_ids));x.source_groups=x.source_groups.filter(g=>used.has(g.group_id));for(const a of x.assets)for(const o of a.occurrences)o.source_location.link.href='https://github.com/'+b.repository.owner+'/'+b.repository.name+'/blob/'+b.commit_sha+'/'+o.source_location.path;return new Response(JSON.stringify(x),{status:200,headers:{'content-type':'application/json'}})})})()`);
await pg.eval("document.getElementById('ot-tab-ai').click()"); await pg.waitFor("document.querySelector('#otai-svg g.otai-group')", 20000); await sleep(400);
const A = await pg.eval(APPP);
await pg.eval("document.getElementById('otai-stage').scrollIntoView({block:'start'})"); await sleep(300);
await pg.screenshot(join(SHOTS, 'application_synthetic_ai_1366_light.png'));
const appInter = await pg.eval(`(async()=>{const w=(ms)=>new Promise(r=>setTimeout(r,ms)); const q=(s)=>document.querySelector(s); const out={}; const idle=async()=>{for(let i=0;i<60;i++){await w(50); if(window.__otStore.get().workbench.perTab.ai.pg.status==='idle')return;}};
  out.zoom0=q('#otai-zoom').textContent; q('[data-otai-zoom="0.8333333333333334"]').click(); await w(80); out.zoomOut=q('#otai-zoom').textContent; q('[data-otai-zoom="1.2"]').click(); await w(80); q('[data-otai-zoom="1.2"]').click(); await w(80); out.zoomIn=q('#otai-zoom').textContent; q('#otai-fit').click(); await w(80); out.fit=q('#otai-zoom').textContent;
  q('[data-otai-filter=models]').click(); await idle(); await w(150); out.modelsCards=document.querySelectorAll('#otai-svg g[data-otai-kind]').length; q('[data-otai-filter=runtimes]').click(); await idle(); await w(150); out.runtimeCards=document.querySelectorAll('#otai-svg g[data-otai-kind]').length;
  q('[data-otai-filter=ai_services]').click(); await idle(); await w(150); out.servicesEmpty=!!q('#otai-empty'); q('[data-otai-filter=findings]').click(); await idle(); await w(150); out.findingsEmpty=!!q('#otai-empty'); q('[data-otai-filter=all]').click(); await idle(); await w(150);
  const c=q('#otai-svg g[data-otai-kind=runtime]'); c.focus(); c.dispatchEvent(new KeyboardEvent('keydown',{key:'Enter',bubbles:true})); await w(150); out.pressedAfterEnter=document.querySelector('#otai-svg g[data-otai-kind=runtime][aria-pressed=true]')!==null;
  q('[data-otai-pres=list]').click(); await w(150); out.listShown=!!q('#otai-list')&&!q('#otai-stage'); q('[data-otai-pres=graph]').click(); await w(150); out.graphBack=!!q('#otai-stage'); return out;})()`);

// ---- classification
const rg = R.groups.length, ag = A.groups.length;
same('group count (2 source groups)', rg, ag);
same('root node geometry (x,y,w,h)', R.root, A.root);
same('zone size and y (360x500 at y=160) and x positions', R.groups.map((g) => g.zone), A.groups.map((g) => g.zone));
same('header offset/size (+15,176,330,66)', R.groups.map((g) => g.head), A.groups.map((g) => g.head));
same('card geometry incl. corner radius', R.cards.map((c) => c.rect), A.cards.map((c) => c.rect));
same('card text positions, sizes and weights', R.cards.map((c) => c.text.map((t) => t.slice(0, 4))), A.cards.map((c) => c.text.map((t) => t.slice(0, 4))));
same('card kinds in order (model, runtime, ...)', R.cards.map((c) => (c.kind || '').replace('data-', '')), A.cards.map((c) => c.kind));
same('root connectors (dashed paths)', R.connectors, A.connectors);
same('card roles, tab stops', R.cards.map((c) => [c.role, c.tab]), A.cards.map((c) => [c.role, c.tab]));
same('Fit window (viewBox)', R.vb, A.vb);
same('computed fill/stroke of model and runtime cards (resolved colours)', R.cards.map((c) => [c.fill, c.stroke, c.sw]), A.cards.map((c) => [c.fill, c.stroke, c.sw]));
same('computed text colours on cards', R.cards.map((c) => c.text.map((t) => t[4])), A.cards.map((c) => c.text.map((t) => t[4])));
same('computed zone and header paint', R.groups.map((g) => [g.zoneFill, g.zoneStroke, g.zoneDash, g.headFill, g.headStroke]), A.groups.map((g) => [g.zoneFill, g.zoneStroke, g.zoneDash, g.headFill, g.headStroke]));
same('root node paint', [R.rootFill, R.rootStroke], [A.rootFill, A.rootStroke]);
same('filter labels and order', R.filters.map((f) => f.label), A.filters.map((f) => f.label), 'reference "AI services" chip is data-ot6-filter=services; the application key is ai_services (label equal)');
same('computed filter chip paint, font and radius', R.filters.map((f) => [f.bg, f.color, f.border, f.font, f.radius]), A.filters.map((f) => [f.bg, f.color, f.border, f.font, f.radius]));
same('presentation labels', R.pres, A.pres);
item('zoom control labels and order', R.zoom, A.zoom, JSON.stringify(R.zoom) === JSON.stringify(A.zoom) ? 'matched' : 'not matched', 'reference order: out, in; the percentage sits between the two buttons in both');
same('stage height (620 px at 1366)', R.stageH, A.stageH);
same('interaction: zoom out / in / Fit percentages', [refInter.zoom0, refInter.zoomOut, refInter.zoomIn, refInter.fit], [appInter.zoom0, appInter.zoomOut, appInter.zoomIn, appInter.fit], 'both start at 100%');
same('interaction: Models / Runtimes filter card counts', [refInter.modelsCards, refInter.runtimeCards], [appInter.modelsCards, appInter.runtimeCards]);
same('interaction: AI services and Findings filters show an empty state', [refInter.servicesEmpty, refInter.findingsEmpty], [appInter.servicesEmpty, appInter.findingsEmpty]);
same('interaction: Enter on a card selects it', refInter.pressedAfterEnter, appInter.pressedAfterEnter);
same('interaction: Graph/List toggle', [refInter.listShown, refInter.graphBack], [appInter.listShown, appInter.graphBack]);
item('capture label', refCapture, 'AI-BOM inventory · <producer> (from the payload)', 'not matched', 'truthfulness-forced: the reference label says "AI-BOM + verified source references" and names the Frigate revision; the application derives its label from the producer and never claims verified source references');
item('reference five Frigate assets and their metadata (task, format, provider text)', 'five assets with invented-by-extractor purpose/format/task text', 'one inventory-reported model, no purpose/format/task text', 'not yet exercised', 'UIP-07C / UIP-D04 (FD-2); shown honestly on the Demo');
item('"Source-declared download locations" outbound anchors', 'present', 'inert text only', 'approved exception', 'FD-6');
item('prototype-generated downloads (aibom / manifest / original)', 'generated from embedded data', 'existing session artifact only', 'approved exception', 'FD-6');
writeFileSync(join(OUT, 'reference_compare.json'), JSON.stringify({ reference_sha256: sha, items, reference_capture_label: refCapture, reference: { interactions: refInter }, application: { interactions: appInter } }, null, 1));
const count = (v) => items.filter((i) => i.verdict === v).length;
console.log(`\n${items.length} items; matched ${count('matched')}; not matched ${count('not matched')}; approved exception ${count('approved exception')}; not yet exercised ${count('not yet exercised')}`);
await close(); svc.kill('SIGKILL'); process.exit(0);
