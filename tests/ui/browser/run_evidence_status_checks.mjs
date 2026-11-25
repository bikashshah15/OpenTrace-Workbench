// UI-EVIDENCE-STATUS-01 bounded desktop browser session: ONE deterministic fixture service (stage4_completion_service.py: SYNTHETIC repositories, fake scanners, no
// network/Docker/provider/credential) and ONE headed Chrome, both launched AND cleaned up by this single driver. No attach mode, no relaunch.
//   PYTHON=<python> node tests/ui/browser/run_evidence_status_checks.mjs <outDir>   # pass 1 at once; then waits for <outDir>/next (re-run ONLY failed blocks, same processes) or <outDir>/done
//   node tests/ui/browser/run_evidence_status_checks.mjs --dry                      # offline preflight: parse, selectors, sequencing and failure isolation against a stub page
// INJECTED EVIDENCE: some states (loading, request failure, empty/partial/unsupported inventory, hostile strings) are produced by an in-page fetch wrapper installed by THIS driver
// (window.__evMode / window.__evMut) that stalls, fails or rewrites the response of the existing crypto-assets / ai-assets requests. The production backend is not changed; every such
// result is named "[injected]". Real states come from the fixture repositories (aicrypto, unsupp, partial, cbomfail).
import { spawn } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url)); const REPO = resolve(HERE, '../../..');
const DRY = process.argv.includes('--dry');
const OUT = resolve(process.argv.find((a, i) => i >= 2 && !a.startsWith('--')) || join(REPO, 'evidence/ui-evidence-status-01'));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const T0 = Date.now(); const DEADLINE_MS = Number(process.env.DEADLINE_MS || 14 * 60 * 1000); const SHA = process.env.TESTED_SHA || 'unset';
let pass = 0; let block = ''; const results = []; const steps = []; const observed = []; const failedBlocks = new Set();
const ok = (name, good, detail = '') => { results.push({ pass, block, name, ok: !!good, detail: String(detail).slice(0, 400) }); console.log(`${good ? 'PASS' : 'FAIL'} [p${pass}/${block}] ${name}${good ? '' : ' :: ' + String(detail).slice(0, 300)}`); };
const step_ = (name) => steps.push(`p${pass} ${name}`);
const note = (rec) => observed.push({ pass, block, ...rec });

// ---------------------------------------------------------------- in-page code (strings)
const INSTALL = `(()=>{ if(window.__evInstalled) return true; window.__evInstalled=true; window.__evMode={crypto:'pass',ai:'pass'}; window.__evMut={};
  const of=window.fetch.bind(window); window.fetch=async(u,o)=>{ const url=String(u); const m=/crypto-assets/.test(url)?'crypto':/ai-assets/.test(url)?'ai':null; if(!m) return of(u,o); const mode=window.__evMode[m];
    if(mode==='hang') return new Promise(()=>{}); if(mode==='fail') return new Response(JSON.stringify({error:{code:'request_failed'}}),{status:500,headers:{'content-type':'application/json'}});
    const r=await of(u,o); if(mode==='pass'||!r.ok||!window.__evMut[mode]) return r; const j=await r.json(); window.__evMut[mode](j); return new Response(JSON.stringify(j),{status:200,headers:{'content-type':'application/json'}}); };
  const EVIL='<img src=x onerror="window.__pwn=1">"\\'&';
  const origOf=(j)=>(j.producers||[]).find((p)=>p.provenance.origin==='original_artifact');
  const emptyIt=(j)=>{ let o=origOf(j); if(!o){ o={provenance:{producer_id:'injected',producer_version:null,origin:'original_artifact',artifact_id:null,json_pointer:null,experimental:false},scope:'injected empty inventory',outcome:'completed',coverage:{files_considered:0,files_parsed:0,files_excluded:0,excluded_paths:[],unparsed_total:0,unknown_dynamic_values_total:0}}; j.producers=[o]; } else { o.outcome='completed'; j.producers=[o]; }
    j.availability={state:'completed_empty',reason_code:'no_applicable_assets',message:'The inventory lists no assets (injected).'}; j.assets=[]; j.source_groups=[]; j.links=[]; j.review_items=[]; for(const k of Object.keys(j.filter_totals)) j.filter_totals[k]=0;
    Object.assign(j.page,{assets_total:0,assets_shown:0,has_more:false,offset:0}); if(j.services){ j.services=[]; j.services_counts={...j.services_counts,total:0,shown:0,truncated:false}; } };
  window.__evMut.empty=(j)=>emptyIt(j);
  window.__evMut.partial=(j)=>{ const o=origOf(j); if(o) o.outcome='partial'; j.availability={state:'partial',reason_code:'partial_coverage',message:'Collection was incomplete (injected).'}; };
  window.__evMut.unsupported=(j)=>{ const o=origOf(j); if(o) o.outcome='unsupported'; j.availability={state:'unsupported',reason_code:'unsupported_ecosystem',message:'No supported inventory (injected).'}; };
  window.__evMut.hostile=(j)=>{ const o=origOf(j); if(o){ o.provenance.producer_version=EVIL; o.scope=EVIL; } };
  return true })()`;
const STRIP = `(()=>{ const strip=document.getElementById('ot-evidence-strip'); const tl=document.querySelector('.ot-tabs'); const det=strip&&strip.querySelector('.otev-details');
  const P=(c)=>{const m=String(c).match(/rgba?\\(([^)]+)\\)/); if(!m) return null; const a=m[1].split(/[ ,\\/]+/).filter(Boolean).map(Number); return {r:a[0],g:a[1],b:a[2]}};
  const L=(c)=>{const f=(v)=>{v/=255; return v<=0.03928? v/12.92 : Math.pow((v+0.055)/1.055,2.4)}; return 0.2126*f(c.r)+0.7152*f(c.g)+0.0722*f(c.b)};
  const R=(a,b)=>{if(!a||!b) return null; const x=L(a),y=L(b); return Math.round(((Math.max(x,y)+0.05)/(Math.min(x,y)+0.05))*100)/100};
  const bgOf=(el)=>{let e=el; while(e){const m=getComputedStyle(e).backgroundColor; const c=P(m); if(c&&!/rgba\\(.*,\\s*0\\)/.test(m)) return c; e=e.parentElement;} return {r:255,g:255,b:255}};
  const items=strip?[...strip.querySelectorAll('.otev-item')].map((i)=>{ const sp=i.querySelector('span'); const ic=i.querySelector('svg'); return { text:sp.textContent, state:i.dataset.state, tone:i.dataset.tone, role:i.dataset.role||null, bom:i.dataset.bom||null, hasIcon:!!ic, iconHidden:ic?.getAttribute('aria-hidden')==='true', iconColor:ic?getComputedStyle(ic).color:null, textRatio:R(P(getComputedStyle(sp).color),bgOf(i)), iconRatio:ic?R(P(getComputedStyle(ic).color),bgOf(i)):null, h:Math.round(i.getBoundingClientRect().height) }; }):[];
  return { present:!!strip, adjacent: !!(strip&&tl&&tl.nextElementSibling===strip), tabs:[...document.querySelectorAll('.ot-tabs button')].map((b)=>b.textContent.trim()), items, scope:strip?.querySelector('.otev-scope')?.textContent||null,
    detailsOpen: !!(det&&det.open), detailsText: det? det.textContent : null, imgs: strip? strip.querySelectorAll('img').length : 0, pwn: window.__pwn||null,
    pageOverflow: document.documentElement.scrollWidth>innerWidth+1, stripOverflow: strip? strip.scrollWidth>strip.clientWidth+1 : null, vw: innerWidth, stripW: strip?Math.round(strip.getBoundingClientRect().width):null,
    layerNote: document.querySelector('.ot-layer-note')?.textContent||null, activeTab: window.__otStore?.get().workbench.tab, stripCount: document.querySelectorAll('#ot-evidence-strip').length } })()`;

// ---------------------------------------------------------------- helpers
const TABS = ['contexts', 'dependencies', 'crypto', 'ai', 'bom'];
async function freshScan(pg, env, repo, first) {
  step_(`scan ${repo}`);
  if (!first) { try { await pg.eval(`fetch('/api/session/end',{method:'POST'}).then(()=>true).catch(()=>true)`); } catch {} }
  await pg.goto(env.base); await env.ready(); await pg.eval(INSTALL); await env.setTheme('light'); await env.setWidth(1440, 900);
  await pg.eval(`(()=>{const e=document.getElementById('ot-url');e.value='';e.dispatchEvent(new Event('input',{bubbles:true}))})()`); await pg.type('#ot-url', 'https://github.com/acme/' + repo);
  return pg;
}
const openScan = async (pg) => { await pg.click('#ot-scan'); await pg.waitFor(`window.__otStore.get().destination === 'workbench'`, 90000); };
const goTab = async (pg, tab) => { await pg.click(`#ot-tab-${tab}`); await sleep(350); };
const settle = (pg) => pg.waitFor(`(()=>{ const s=document.getElementById('ot-evidence-strip'); return s && !/Loading/.test(s.textContent) })()`, 20000).catch(() => false);
const read = async (pg) => (await pg.eval(STRIP)) || {};
async function record(pg, env, label, tab, { settleFirst = true, shot = true } = {}) {
  if (settleFirst) await settle(pg); await sleep(250);
  const r = await read(pg); const texts = (r.items || []).map((i) => i.text);
  note({ label, tab, texts, scope: r.scope, vw: r.vw });
  ok(`${label}: strip present, directly below the tabs, once`, r.present && r.adjacent && r.stripCount === 1, JSON.stringify({ present: r.present, adjacent: r.adjacent, n: r.stripCount }));
  ok(`${label}: tab names unchanged`, JSON.stringify(r.tabs) === JSON.stringify(['Repository contexts', 'Dependencies', 'Cryptography', 'AI models', 'BOM connections']), (r.tabs || []).join('|'));
  ok(`${label}: no horizontal overflow`, !r.pageOverflow && !r.stripOverflow, `page=${r.pageOverflow} strip=${r.stripOverflow} vw=${r.vw}`);
  ok(`${label}: every indicator has an icon (aria-hidden) and visible text`, (r.items || []).length > 0 && r.items.every((i) => i.hasIcon && i.iconHidden && i.text.trim().length > 0), JSON.stringify(texts));
  ok(`${label}: indicator text contrast >= 4.5`, (r.items || []).every((i) => i.textRatio === null || i.textRatio >= 4.5), JSON.stringify((r.items || []).map((i) => i.textRatio)));
  if (shot) await env.shot(label.replace(/[^a-z0-9]+/gi, '_'));
  return r;
}

// ---------------------------------------------------------------- blocks
const BLOCKS = (pg, env) => [
  { name: 'aicrypto-all-tabs-light-1440', run: async () => {
    await freshScan(pg, env, 'aicrypto', true); await openScan(pg);
    for (const t of TABS) { await goTab(pg, t); const r = await record(pg, env, `aicrypto ${t} light 1440`, t); if (t === 'contexts') ok('contexts: scope sentence says SBOM source locations, not a file tree', /source locations recorded in the SBOM, not a complete repository file tree/.test(r.scope || ''), r.scope);
      if (t === 'dependencies') ok('dependencies: advisory coverage stated as separate', /Advisory-query coverage is reported separately/.test(r.scope || ''), r.scope);
      if (t === 'bom') { ok('bom: three separate indicators', (r.items || []).filter((i) => !i.role).length === 3, JSON.stringify((r.items || []).map((i) => i.text))); ok('bom: comparison caveat, no workspace-wide label', /does not establish comparison completion or success/.test(r.scope || '') && !(r.items || []).some((i) => /workspace/i.test(i.text)), r.scope); }
      if (t === 'crypto' || t === 'ai') ok(`${t}: states whether source observations are displayed`, (r.items || []).some((i) => i.role === 'source'), JSON.stringify((r.items || []).map((i) => i.text))); }
  } },
  { name: 'details-and-tab-switching', run: async () => {
    await goTab(pg, 'bom'); await settle(pg); let r = await read(pg); ok('Details collapsed by default', !r.detailsOpen, '');
    await pg.click('#ot-evidence-strip .otev-details summary'); await sleep(300); r = await read(pg); ok('Details opens', r.detailsOpen, '');
    ok('Details shows producer/origin/scope text from existing facts', /Origin/.test(r.detailsText || '') && /Live scan|Captured/.test(r.detailsText || ''), (r.detailsText || '').slice(0, 200));
    await env.shot('details_open_bom'); await goTab(pg, 'dependencies'); await sleep(300); r = await read(pg); ok('Details open state survives a tab switch repaint (viewer preference)', r.detailsOpen, '');
    await goTab(pg, 'crypto'); await settle(pg); await goTab(pg, 'ai'); await settle(pg); r = await read(pg); ok('AI tab Details holds the live AI-BOM meaning', /AI inventory|AI-BOM/.test(r.detailsText || ''), (r.detailsText || '').slice(0, 240));
    await pg.click('#ot-evidence-strip .otev-details summary'); await sleep(200); r = await read(pg); ok('Details closes', !r.detailsOpen, '');
  } },
  { name: 'aicrypto-dark-1100', run: async () => {
    await env.setTheme('dark'); await env.setWidth(1100, 800);
    for (const t of ['dependencies', 'crypto', 'ai', 'bom']) { await goTab(pg, t); await record(pg, env, `aicrypto ${t} dark 1100`, t); }
    await pg.click('#ot-evidence-strip .otev-details summary'); await sleep(250); const r = await read(pg); ok('dark 1100 BOM Details open: no overflow', !r.pageOverflow && !r.stripOverflow, ''); await env.shot('details_open_bom_dark_1100');
    await pg.click('#ot-evidence-strip .otev-details summary'); await env.setTheme('light'); await env.setWidth(1440, 900);
  } },
  { name: 'advanced-view-unchanged-graph', run: async () => {
    await pg.eval(`window.__otStore.dispatch({type:'ADVANCED', value:true})`).catch(() => {}); await sleep(400);
    const adv = await pg.eval(`window.__otStore.get().advanced`);
    if (!adv) { ok('Advanced toggled (via store action)', false, 'ADVANCED action not available; use the toggle control'); return; }
    for (const t of ['dependencies', 'crypto', 'ai']) { await goTab(pg, t); await sleep(500); const r = await record(pg, env, `aicrypto ${t} advanced`, t, { settleFirst: false, shot: t === 'ai' }); ok(`advanced ${t}: no false "Loading" claim`, !(r.items || []).some((i) => /Loading/.test(i.text)), JSON.stringify((r.items || []).map((i) => i.text))); }
    await pg.eval(`window.__otStore.dispatch({type:'ADVANCED', value:false})`).catch(() => {});
  } },
  { name: 'loading-error-recovery-injected', run: async () => {
    await freshScan(pg, env, 'aicrypto', false); await pg.eval(`window.__evMode.crypto='hang'; window.__evMode.ai='hang'`); await openScan(pg);
    await goTab(pg, 'crypto'); await sleep(500); let r = await read(pg); note({ label: '[injected] crypto request stalled', texts: (r.items || []).map((i) => i.text) });
    ok('[injected] stalled request: "Loading CBOM status…", never an absence claim', (r.items || []).some((i) => i.text === 'Loading CBOM status…') && !(r.items || []).some((i) => /No CBOM|step not run|failed/.test(i.text)), JSON.stringify((r.items || []).map((i) => i.text))); await env.shot('injected_loading_crypto');
    await goTab(pg, 'ai'); await sleep(500); r = await read(pg); ok('[injected] AI stalled: "Loading AI-BOM status…"', (r.items || []).some((i) => i.text === 'Loading AI-BOM status…'), JSON.stringify((r.items || []).map((i) => i.text)));
    // a fresh analysis for the failure path: both requests fail
    await freshScan(pg, env, 'aicrypto', false); await pg.eval(`window.__evMode.crypto='fail'; window.__evMode.ai='fail'`); await openScan(pg); await goTab(pg, 'crypto'); await sleep(900); r = await read(pg);
    note({ label: '[injected] crypto request failed', texts: (r.items || []).map((i) => i.text) });
    ok('[injected] failed request: "CBOM status unavailable", not "No CBOM"', (r.items || []).some((i) => i.text === 'CBOM status unavailable') && !(r.items || []).some((i) => /^No CBOM/.test(i.text)), JSON.stringify((r.items || []).map((i) => i.text))); await env.shot('injected_request_failed_crypto');
    await pg.eval(`window.__evMode.crypto='pass'`);
    const retry = await pg.eval(`!!document.querySelector('[data-otc-retry]')`);
    if (retry) { await pg.click('[data-otc-retry]'); await settle(pg); r = await read(pg); ok('[injected] after Try again the real inventory status is shown', (r.items || []).some((i) => /^CBOM available|^Partial CBOM|^No CBOM available/.test(i.text)), JSON.stringify((r.items || []).map((i) => i.text))); } else ok('[injected] a Try again control exists after a failed request', false, 'no [data-otc-retry]');
    await pg.eval(`window.__evMode.ai='pass'`);
  } },
  { name: 'real-states-unsupp-partial-cbomfail', run: async () => {
    for (const repo of ['unsupp', 'partial', 'cbomfail']) {
      await freshScan(pg, env, repo, false); await openScan(pg);
      for (const t of ['crypto', 'ai', 'bom']) { await goTab(pg, t); await record(pg, env, `${repo} ${t} light 1440`, t, { shot: t !== 'ai' || repo === 'partial' }); }
    }
    const cf = observed.filter((o) => o.label === 'cbomfail bom light 1440').pop(); ok('cbomfail BOM tab: CBOM shown as failed while SBOM/AI-BOM keep their own indicators', cf && cf.texts.some((x) => /CBOM/.test(x) && !/^CBOM available/.test(x)) && cf.texts.length >= 3, JSON.stringify(cf && cf.texts));
  } },
  { name: 'injected-inventory-variants', run: async () => {
    const variants = [['empty', 'crypto', /available · No assets recorded within its scope/], ['partial', 'crypto', /^Partial CBOM · Coverage incomplete/], ['unsupported', 'ai', /unavailable · Input unsupported/], ['empty', 'ai', /available · No assets recorded within its scope/], ['partial', 'ai', /^Partial AI-BOM · Coverage incomplete/]];
    for (const [mut, tab, re] of variants) {
      await freshScan(pg, env, 'aicrypto', false); await pg.eval(`window.__evMode.${tab}='${mut}'`); await openScan(pg); await goTab(pg, tab); const r = await record(pg, env, `[injected ${mut}] ${tab}`, tab);
      ok(`[injected ${mut}] ${tab}: expected wording`, (r.items || []).some((i) => re.test(i.text)), JSON.stringify((r.items || []).map((i) => i.text)));
    }
  } },
  { name: 'injected-hostile-strings', run: async () => {
    await freshScan(pg, env, 'aicrypto', false); await pg.eval(`window.__evMode.crypto='hostile'`); await openScan(pg); await goTab(pg, 'crypto'); await settle(pg);
    await pg.click('#ot-evidence-strip .otev-details summary'); await sleep(300); const r = await read(pg);
    ok('[injected] hostile producer/scope strings stay inert (no img element, no handler ran)', r.imgs === 0 && !r.pwn && /<img/.test(r.detailsText || ''), `imgs=${r.imgs} pwn=${r.pwn}`); await env.shot('injected_hostile_details'); await pg.eval(`window.__evMode.crypto='pass'`);
  } },
];
async function runBlocks(pg, env, only) {
  for (const b of BLOCKS(pg, env)) {
    if (only && !only.has(b.name)) continue;
    block = b.name; const before = results.length;
    try { await b.run(); } catch (e) { ok(`block "${b.name}" completed`, false, e.message); }
    if (results.slice(before).some((r) => !r.ok)) failedBlocks.add(b.name); else failedBlocks.delete(b.name);
  }
  block = 'final'; try { await pg.eval(`fetch('/api/session/end',{method:'POST'}).then(()=>true).catch(()=>true)`); } catch {}
  ok('no page exceptions', (pg.log?.exceptions || []).length === 0, (pg.log?.exceptions || []).join(' | '));
  ok('no external network request', (pg.log?.requests || []).every((r) => r.url.startsWith(env.base.slice(0, -1)) || r.url.startsWith('data:') || r.url.startsWith('about:')), '');
}
const writeResults = (extra = {}) => { try { mkdirSync(OUT, { recursive: true }); writeFileSync(join(OUT, 'results.json'), JSON.stringify({ tested_sha: SHA, elapsed_seconds: Math.round((Date.now() - T0) / 1000), passes: pass, headed: true, relaunch: false, services: 1, chrome: 1, failed_blocks: [...failedBlocks], results, observed, steps, ...extra }, null, 1)); } catch {} };

// ---------------------------------------------------------------- dry run
if (DRY) {
  let thrown = 0;
  const stub = { log: { requests: [], exceptions: [] }, eval: async () => null, send: async () => ({}), click: async () => {}, type: async () => {}, goto: async () => {}, screenshot: async () => {}, close: async () => {},
    waitFor: async (expr) => { if (!thrown && String(expr).includes('destination')) { thrown = 1; throw new Error('INJECTED failure in the first block'); } return true; } };
  const noop = async () => {};
  for (const [name, expr] of [['INSTALL', INSTALL], ['STRIP', STRIP]]) { try { new Function('return ' + expr); } catch (e) { console.log('PARSE FAIL', name, e.message); process.exit(2); } }
  pass = 1; await runBlocks(stub, { ready: noop, shot: noop, setTheme: noop, setWidth: noop, base: 'http://127.0.0.1:0/' });
  const injected = results.find((r) => /block "aicrypto-all-tabs-light-1440" completed/.test(r.name) && !r.ok);
  const laterRan = steps.some((s) => /scan unsupp/.test(s)) || steps.some((s) => /scan cbomfail/.test(s));
  console.log('DRY blocks: ' + BLOCKS(stub, {}).length + '; steps (' + steps.length + '):\n  ' + steps.join('\n  '));
  console.log('failure isolation: injected failure recorded=' + !!injected + ', later blocks ran=' + laterRan + ', failed_blocks=' + [...failedBlocks].join(','));
  process.exit(injected && laterRan ? 0 : 2);
}

// ---------------------------------------------------------------- real run (this process owns launch AND cleanup)
const { connect, newPage, CHROME } = await import('./cdp.mjs');
let svc = null; let chrome = null; let browser = null; let dir = null; let cleaned = false; const pids = [];
const cleanup = async () => {
  if (cleaned) return; cleaned = true;
  try { browser && browser.close(); } catch {}
  for (const p of [chrome, svc]) { try { p && p.pid && p.kill('SIGTERM'); } catch {} }
  await sleep(1000);
  for (const p of [chrome, svc]) { try { p && p.exitCode === null && p.kill('SIGKILL'); } catch {} }
  try { dir && rmSync(dir, { recursive: true, force: true }); } catch {}
  const alive = pids.filter((pid) => { try { process.kill(pid, 0); return true; } catch { return false; } });
  console.log('CLEANUP started=' + JSON.stringify(pids) + ' still_alive=' + JSON.stringify(alive)); globalThis.__alive = alive;
};
const timer = setTimeout(async () => { block = 'deadline'; ok('deadline: finished within the time limit', false, 'deadline reached'); writeResults({ deadline_hit: true }); await cleanup(); process.exit(3); }, DEADLINE_MS);
process.on('SIGINT', async () => { writeResults({ interrupted: true }); await cleanup(); process.exit(130); });
mkdirSync(OUT, { recursive: true });
try {
  svc = spawn(process.env.PYTHON || 'python3', [join(HERE, 'stage4_completion_service.py')], { cwd: REPO, env: { ...process.env, PYTHONPATH: REPO + ':' + join(REPO, 'src/core') + ':' + join(REPO, 'src/agents/investigator') }, stdio: ['ignore', 'pipe', 'pipe'] }); if (svc.pid) pids.push(svc.pid);
  const base = await new Promise((res, rej) => { let b = ''; const t = setTimeout(() => rej(new Error('service did not start: ' + b)), 40000); svc.stdout.on('data', (d) => { b += d; const m = b.match(/http:\/\/127\.0\.0\.1:(\d+)\//); if (m) { clearTimeout(t); res(m[0]); } }); svc.stderr.on('data', (d) => { b += d; }); });
  dir = mkdtempSync(join(tmpdir(), 'ot-evstatus-chrome-'));
  chrome = spawn(CHROME, ['--no-first-run', '--no-default-browser-check', `--user-data-dir=${dir}`, '--remote-debugging-port=0', '--window-size=1500,1000', 'about:blank'], { stdio: ['ignore', 'ignore', 'pipe'] }); if (chrome.pid) pids.push(chrome.pid);
  const wsUrl = await new Promise((res, rej) => { let b = ''; const t = setTimeout(() => rej(new Error('chrome did not start')), 30000); chrome.stderr.on('data', (d) => { b += d; const m = b.match(/DevTools listening on (ws:\/\/\S+)/); if (m) { clearTimeout(t); res(m[1]); } }); chrome.on('exit', () => rej(new Error('chrome exited'))); });
  browser = await connect(wsUrl);
  const pg = await newPage(browser, { width: 1440, height: 900 });
  const env = { base,
    ready: () => pg.waitFor(`document.getElementById('ot-scan') && !document.getElementById('ot-scan').disabled`, 30000),
    shot: (name) => pg.screenshot(join(OUT, `p${pass}_${name}.png`)),
    setTheme: (t) => pg.eval(`(()=>{ if(!window.__otStore) throw new Error('app not ready'); window.__otStore.dispatch({type:'THEME', value:'${t}'}); return true })()`),
    setWidth: (w, h) => pg.send('Emulation.setDeviceMetricsOverride', { width: w, height: h, deviceScaleFactor: 1, mobile: false }) };
  for (;;) {
    pass += 1; await runBlocks(pg, env, pass === 1 ? null : new Set(failedBlocks)); writeResults();
    const mine = results.filter((r) => r.pass === pass); const bad = mine.filter((r) => !r.ok).length; console.log(`pass ${pass}: ${mine.length - bad}/${mine.length} passed; failed blocks: ${[...failedBlocks].join(', ') || 'none'}`);
    if (pass >= 2) break;
    console.log(`WAITING for ${OUT}/next (one targeted correction pass: re-runs only the failed blocks, same processes) or ${OUT}/done`);
    let go = null; while (!go) { if (existsSync(join(OUT, 'done'))) go = 'done'; else if (existsSync(join(OUT, 'next'))) go = 'next'; else await sleep(1000); }
    if (go === 'done') break;
  }
} catch (e) { block = 'driver'; ok('driver completed', false, e.stack || e.message); } finally { clearTimeout(timer); writeResults(); await cleanup(); writeResults({ cleanup_alive: globalThis.__alive || [] }); }
const bad = results.filter((r) => !r.ok); console.log(`\n${results.length - bad.length}/${results.length} passed in ${Math.round((Date.now() - T0) / 1000)} s`); process.exit(bad.length ? 1 : 0);
