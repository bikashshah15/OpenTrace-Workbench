// UIP-13 validation (test harness): the ACTIVE BOM workspace (AI models view) through real browser interaction at DESKTOP width on LOCAL SYNTHETIC fixtures
// (tests/ui/browser/uip13_model_service.py). One fixture service + one headless Chrome per invocation. A synthetic positive AI-BOM is NOT a third-party live comparison
// and NOT a Cisco run. Mobile (390 px) is intentionally not exercised (owner decision D6; the open mobile gap is preserved).
// Usage: OT_DEADLINE_MS=<epoch ms> OT_PIDS_FILE=<file> node run_uip13_inspector.mjs <case: matrix|states|norun|interact> <outDir>
import { spawn } from 'node:child_process';
import { appendFileSync, writeFileSync } from 'node:fs';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { launch, newPage } from './cdp.mjs';
import { harness, sleep, txt, state, apiJson, viewport, settled, setUrl, detailRequests, inspectorContent, layoutProbe, endSession } from './uip12_lib.mjs';

const HERE = dirname(fileURLToPath(import.meta.url)); const REPO = resolve(HERE, '../../..');
const [PAIR, OUTARG] = process.argv.slice(2);
const H = harness({ out: OUTARG, label: 'uip13_' + PAIR, synthetic: true });
const { check, guard, evidence, OUT } = H;
const ROUTES = ['/api/workbench/v1/bom-candidates', '/api/workbench/v1/bom-graph', '/api/view/gap'];

function service() {
  const proc = spawn(process.env.PYTHON || 'python3', [join(HERE, 'uip13_model_service.py'), '--case', PAIR], { cwd: REPO, env: { ...process.env, PYTHONPATH: `${REPO}:${join(REPO, 'src/core')}` }, stdio: ['ignore', 'pipe', 'pipe'] });
  if (process.env.OT_PIDS_FILE) appendFileSync(process.env.OT_PIDS_FILE, proc.pid + '\n');
  return new Promise((res, rej) => { let b = ''; const t = setTimeout(() => rej(new Error('service did not start: ' + b)), 40000);
    proc.stdout.on('data', (d) => { b += d; const m = b.match(/http:\/\/127\.0\.0\.1:(\d+)\//); if (m) { clearTimeout(t); res({ base: m[0], stop: () => proc.kill('SIGTERM') }); } });
    proc.stderr.on('data', (d) => { b += d; try { appendFileSync(join(OUT, 'service_stderr.log'), d); } catch {} }); });
}
const scanRepo = async (pg, repo, first) => {
  guard(); if (!first) await endSession(pg);
  await pg.waitFor(`document.getElementById('ot-scan') && !document.getElementById('ot-scan').disabled`, 20000);
  await setUrl(pg, 'https://github.com/acme/' + repo); await pg.click('#ot-scan');
  await pg.waitFor(`window.__otStore.get().destination === 'workbench' || window.__otStore.get().scan?.status?.job?.state === 'failed'`, 90000);
  const st = await state(pg);
  if (st.destination !== 'workbench') throw new Error('scan did not reach the workbench: ' + JSON.stringify({ dest: st.destination, job: st.scan?.status?.job, error: st.scan?.error, stages: st.scan?.status?.job?.stages }).slice(0, 1500));
  await pg.click('#ot-tab-bom'); await pg.waitFor(`window.__otStore.get().bom8.queue`, 30000);
  await pg.waitFor(`(()=>{const b=window.__otStore.get().bom8; return b.queue && !b.req.queue && !b.req.graph && !b.req.detail})()`, 30000);
};
const gen = async (pg) => (await state(pg)).analysis.generation;
const queue = async (pg, family = 'ai_model') => {
  const g = await gen(pg); const r = await apiJson(pg, `/api/workbench/v1/bom-candidates?schema_version=1&generation=${g}&family=${family}`);
  const caps = Object.fromEntries((r.body?.capabilities || []).map((c) => [c.family, `${c.state}${c.reason_code ? '/' + c.reason_code : ''}`]));
  return { mode: r.body?.mode, caps, items: r.body?.items || [], counts: r.body?.counts };
};
const openAI = async (pg) => { await pg.click('[data-action=bom-view][data-view=ai]'); await settled(pg, 'ai'); };
const rowSel = (id) => `[data-action=bom-select][data-id=${JSON.stringify(id)}]`;
const waitEvidence = (pg, id) => pg.waitFor(`document.querySelector('[data-evidence-for=${JSON.stringify(id)}] .ot-gap-inspector')`, 20000);
const select = async (pg, id) => { await pg.click(rowSel(id)); await waitEvidence(pg, id); };
const summaryText = async (pg) => txt(pg, '.ot-bom8');

async function inspect(pg, label, item, expect) {
  guard(); await viewport(pg, false);
  const before = detailRequests(pg).length; await select(pg, item.item_id);
  const t = await inspectorContent(pg); const lp = await layoutProbe(pg); const reqs = detailRequests(pg).slice(before);
  evidence[label] = { text: t.slice(0, 3000), layout: lp, detail_requests: reqs.map((r) => r.url) };
  const tags = { routes: ROUTES, actions: ['click candidate row', 'inspector at 1366 px'] };
  check(`${label}: selection requested exactly this candidate's evidence`, reqs.length >= 1 && reqs.every((r) => r.url.includes(encodeURIComponent(item.item_id))), `${reqs.length}`, tags);
  for (const [name, ok] of expect(t)) check(`${label}: ${name}`, ok, t.slice(0, 260), tags);
  check(`${label}: no horizontal page scroll; evidence inside the viewport`, !lp.hscroll && lp.evInside, JSON.stringify(lp), tags);
  check(`${label}: source occurrence is shown before the AI-BOM record when both exist`, !t.includes('Selected AI-BOM') || t.indexOf('Model reference in source') < t.indexOf('Selected AI-BOM'), '', tags);
  await pg.screenshot(join(OUT, `${label.replace(/[^a-z0-9]+/gi, '_')}_1366.png`));
}
const has = (t, s) => t.includes(s);

async function caseMatrix(pg) {
  const want = {
    pos: { n: 2, cap: 'completed', ex: { supported: (t) => [['shows source path:line, verbatim excerpt, exact locator and digest', /app\/m\.py:1/.test(t) && has(t, 'det.onnx') && has(t, 'Locator (exact') && /File SHA-256/.test(t)],
        ['shows the AI-BOM identity: producer, digest, recorded acquisition binding and scan scope', has(t, 'Selected AI-BOM') && /cisco-aibom/.test(t) && has(t, 'Acquisition binding: recorded') && has(t, 'AI-BOM scan scope (as recorded)')],
        ['conclusion is declaration level, with the intended-scope limit', /Declared in the AI-BOM \(declaration level\)/i.test(t) && /not that it examined every file or reference/.test(t) && /Declaration-level agreement only/.test(t)],
        ['download, load, execution and independent verification are explicitly NOT claimed', /not downloaded or executed/.test(t) && /not artifact identity, digest verification, independent verification, or evidence that the model is loaded/.test(t)]],
      unverifiable: (t) => [['inconclusive: no matching model record, with the reason', /no_matching_model_record|no matching model record/i.test(t) || /Could not/i.test(t)], ['query and fragment are part of the shown locator', has(t, '?download=1#v2')]] } },
    zeromodel: { n: 1, cap: 'completed', ex: { unverifiable: (t) => [['zero-model AI-BOM: record shown, 0 models declared, inconclusive (not an empty result)', has(t, 'Selected AI-BOM') && /0 models declared/.test(t)]] } },
    ambig: { n: 1, cap: 'completed', ex: { unverifiable: (t) => [['two exact locators: ambiguous, never supported', /ambiguous/i.test(t) && /2 AI-BOM models considered/.test(t)]] } },
    basename: { n: 1, cap: 'completed', ex: { unverifiable: (t) => [['basename-only is a candidate, not identity', /candidates_without_locator_match|basename|name or basename/i.test(t)]] } },
    outside: { n: 1, cap: 'partial', ex: { unknown_coverage: (t) => [['outside scope: source shown, reason visible, no verdict', has(t, 'Model reference in source') && /outside_aibom_scan_scope|outside the AI-BOM scope|outside aibom scan scope/i.test(t) && !/Declared in the AI-BOM \(declaration level\)/i.test(t)]] } },
    noscope: { n: 1, cap: 'partial', ex: { unknown_coverage: (t) => [['unrecorded scope: reason visible, no verdict', /scope_missing|does not record a usable scan scope|scope missing/i.test(t)]] } },
    aibomfail: { n: 1, cap: 'failed', ex: { unknown_coverage: (t) => [['producer failed: source shown, no AI-BOM record fabricated', has(t, 'Model reference in source') && !has(t, 'Selected AI-BOM') && !has(t, 'AI-BOM scan scope')]] } },
    hostile: { n: 1, cap: 'completed', ex: { supported: (t) => [['hostile AI-BOM text is shown as text', true]], unverifiable: (t) => [['hostile AI-BOM text is shown as text', true]] } },
  };
  let first = true;
  for (const [repo, w] of Object.entries(want)) {
    try {
      await scanRepo(pg, repo, first); first = false; await viewport(pg, false); await openAI(pg);
      const q = await queue(pg); evidence[`${repo}_queue`] = { mode: q.mode, caps: q.caps, n: q.items.length, states: q.items.map((i) => i.state) };
      check(`${repo}: ${w.n} model candidate(s) and page-level discovery_compared`, q.items.length === w.n && q.mode === 'discovery_compared', JSON.stringify(evidence[`${repo}_queue`]), { routes: ['/api/workbench/v1/bom-candidates'], actions: ['scan fixture', 'open AI models view'] });
      check(`${repo}: ai_model capability is ${w.cap}`, (q.caps.ai_model || '').startsWith(w.cap), q.caps.ai_model, { routes: ['/api/workbench/v1/bom-candidates'] });
      check(`${repo}: queue family and counts are the model family`, q.items.every((i) => i.family === 'ai_model') && (q.counts?.family_counts?.ai_model || 0) === w.n, JSON.stringify(q.counts?.family_counts || {}));
      if (w.cap === 'failed') check(`${repo}: the unavailable producer is stated in the AI view`, /Model comparison: failed/.test(await summaryText(pg)), '');
      for (const it of q.items) { const ex = w.ex[it.state]; if (ex) await inspect(pg, `${repo}${it.state ? ' ' + it.state : ''}`, it, ex); else check(`${repo}: candidate state ${it.state} is expected`, false, JSON.stringify(Object.keys(w.ex))); }
      if (repo === 'hostile') {
        const dom = await pg.eval(`({script: !!document.querySelector('.ot-bom8 script'), img: !!document.querySelector('.ot-bom8 img[onerror]'), escaped: document.body.innerText.includes('<script>alert(1)</script>') || document.body.textContent.includes('<script>alert(1)</script>')})`);
        check('hostile: the AI-BOM text creates no element and runs nothing', !dom.script && !dom.img, JSON.stringify(dom), { routes: ROUTES, actions: ['select hostile candidate'] });
      }
      if (repo === 'pos') {     // graph: focused graph for the supported candidate loads within bounds
        const sup = q.items.find((i) => i.state === 'supported'); await select(pg, sup.item_id);
        const g = await apiJson(pg, `/api/workbench/v1/bom-graph?schema_version=1&generation=${await gen(pg)}&scope_kind=focused_candidate&candidate_id=${encodeURIComponent(sup.item_id)}`);
        evidence.pos_graph = { status: g.status, nodes: g.body?.nodes?.length, edges: g.body?.edges?.length };
        check('pos: the focused graph for the supported candidate loads and is bounded', g.status === 200 && (g.body?.nodes?.length || 0) <= 80 && (g.body?.edges?.length || 0) <= 160 && (g.body?.nodes || []).some((n) => n.kind === 'assertion'), JSON.stringify(evidence.pos_graph), { routes: ['/api/workbench/v1/bom-graph'] });
      }
    } catch (e) { if (e.message === 'DEADLINE') { H.unfinished.push(repo + ': deadline'); break; } check(`${repo}: run completed`, false, e.stack || e.message); }
  }
}

async function caseStates(pg) {
  const want = { dyn: ['partial', 0, /1 dynamic expression/], empty: ['completed_empty', 0, null], nosource: ['unsupported', 0, null], mixed: ['partial', 1, null], bigtree: ['completed', 30, null] };
  let first = true;
  for (const [repo, [cap, n, facts]] of Object.entries(want)) {
    try {
      await scanRepo(pg, repo, first); first = false; await viewport(pg, false);
      const q = await queue(pg); await openAI(pg); const t = await summaryText(pg); evidence[`${repo}_text`] = t.slice(0, 900);
      check(`${repo}: ai_model ${cap} with ${n} candidate(s)`, (q.caps.ai_model || '').startsWith(cap) && (repo === 'bigtree' ? (q.counts?.family_counts?.ai_model === n) : q.items.length === n), JSON.stringify({ caps: q.caps, n: q.items.length, counts: q.counts?.family_counts }), { routes: ['/api/workbench/v1/bom-candidates'], actions: ['scan fixture', 'open AI models view'] });
      check(`${repo}: collection facts are stated separately from the state`, /Model-reference collection:/.test(t), t.slice(0, 300), { actions: ['read AI view'] });
      if (facts) check(`${repo}: dynamic expression is disclosed, not resolved into a locator`, facts.test(t) && q.items.length === 0, t.slice(0, 300));
      if (cap === 'partial') check(`${repo}: partial model coverage has its own wording`, !!(await pg.eval(`!!document.querySelector('.ot-bom8-coverage[data-family=ai_model][data-coverage=partial]')`)) && /no model is used/.test(t), t.slice(0, 300));
      if (cap === 'completed_empty') check(`${repo}: empty is not described as a finding that no model is used`, !/No models are used/i.test(t), t.slice(0, 200));
      if (cap === 'unsupported') check(`${repo}: unsupported does not claim observations`, /No static model reference was observed/.test(t) && !/references that were observed/.test(t), t.slice(0, 300));
      if (repo === 'bigtree') { await select(pg, q.items[0].item_id); const lp = await layoutProbe(pg); check('bigtree: 30 candidates paginate (25 per page) and the first is inspectable', (await pg.eval(`document.querySelectorAll('.ot-bom8-row').length`)) === 25 && lp.evInside, JSON.stringify(lp)); }
      await pg.screenshot(join(OUT, `${repo}_1366.png`));
    } catch (e) { if (e.message === 'DEADLINE') { H.unfinished.push(repo + ': deadline'); break; } check(`${repo}: run completed`, false, e.stack || e.message); }
  }
}

async function caseNorun(pg) {
  let first = true;
  for (const [repo, cap, n] of [['norun', 'not_run', 2], ['blankrepo', 'completed_empty', 0]]) {
    try {
      await scanRepo(pg, repo, first); first = false; await viewport(pg, false);
      const q = await queue(pg); await openAI(pg); const t = await summaryText(pg);
      check(`${repo}: ai_model ${cap}, ${n} candidate(s)`, (q.caps.ai_model || '').startsWith(cap) && q.items.length === n, JSON.stringify({ caps: q.caps, n: q.items.length }), { routes: ['/api/workbench/v1/bom-candidates'], actions: ['scan fixture without an AI-BOM', 'open AI models view'] });
      if (cap === 'not_run') {
        check('norun: no producer ran, stated, with the source references still listed', /Model comparison: not run/.test(t) && /because none was produced/.test(t) && /2 references observed/.test(t), t.slice(0, 320));
        for (const it of q.items) await inspect(pg, `norun ${it.item_id.slice(-8)}`, it, (x) => [['source shown, no AI-BOM record or scope fabricated', has(x, 'Model reference in source') && !has(x, 'Selected AI-BOM') && !has(x, 'AI-BOM scan scope')], ['reason aibom_not_run is visible', /aibom_not_run|aibom not run|no AI-BOM producer ran/i.test(x)]]);
      }
    } catch (e) { if (e.message === 'DEADLINE') { H.unfinished.push(repo + ': deadline'); break; } check(`${repo}: run completed`, false, e.stack || e.message); }
  }
}

async function caseInteract(pg, browser) {
  await scanRepo(pg, 'multi', true); await viewport(pg, false); await openAI(pg);
  const q = await queue(pg); evidence.items = q.items.map((i) => ({ id: i.item_id, path: i.location?.path, state: i.state }));
  const byPath = Object.fromEntries(q.items.map((i) => [i.location.path, i.item_id]));
  check('interact: three model candidates (supported, inconclusive, basename-only)', q.items.length === 3, JSON.stringify(evidence.items), { routes: ['/api/workbench/v1/bom-candidates'] });
  const A = byPath['app/a.py'], B = byPath['app/b.py'], C = byPath['app/c.py']; const mark = { [A]: 'det.onnx', [B]: 'other.tflite', [C]: 'third.hef' };
  const held = []; let hold = false, failNext = false;
  browser.on(async (m) => {
    if (m.sessionId !== pg.sessionId || m.method !== 'Fetch.requestPaused') return;
    const { requestId, request } = m.params;
    try {
      if (failNext && request.url.includes('/api/view/gap')) { failNext = false; await pg.send('Fetch.fulfillRequest', { requestId, responseCode: 500, responseHeaders: [{ name: 'Content-Type', value: 'application/json' }], body: Buffer.from('{"error":"injected failure"}').toString('base64') }); }
      else if (hold) held.push({ requestId, url: request.url });
      else await pg.send('Fetch.continueRequest', { requestId });
    } catch {}
  });
  await pg.send('Fetch.enable', { patterns: [{ urlPattern: '*/api/view/gap?*', requestStage: 'Request' }] });
  const release = async (h) => { await pg.send('Fetch.continueRequest', { requestId: h.requestId }); };
  const heldFor = (id) => held.find((h) => h.url.includes(encodeURIComponent(id)));
  const waitHeld = async (id) => { const t0 = Date.now(); while (Date.now() - t0 < 10000) { if (heldFor(id)) return heldFor(id); await sleep(50); } throw new Error('request not held: ' + id); };
  await sleep(500);
  hold = true; held.length = 0;
  await pg.click(rowSel(B)); const hb = await waitHeld(B); await pg.click(rowSel(C)); const hc = await waitHeld(C);
  await release(hc); await waitEvidence(pg, C); await release(hb); await sleep(600);
  let t = await inspectorContent(pg); let s = await state(pg);
  check('interact T1: a late detail response for the previous candidate never replaces the visible one', s.bom8.selected === C && t.includes(mark[C]) && !t.includes(mark[B]), t.slice(0, 200), { routes: ['/api/view/gap'], actions: ['click B then C; release C then B'] });
  held.length = 0; await pg.click(rowSel(A)); const ha = await waitHeld(A);
  await pg.click('[data-action=bom-filter][data-filter=not_represented]'); await pg.waitFor(`window.__otStore.get().bom8.filter==='not_represented' && !window.__otStore.get().bom8.req.queue`, 15000);
  await release(ha); await sleep(600); t = await inspectorContent(pg); s = await state(pg);
  check('interact T2: a filter change during an in-flight detail leaves no other candidate\'s evidence', s.bom8.detail === null && !(await pg.eval(`!!document.querySelector('[data-evidence-for]')`)) && !t.includes(mark[A]), t.slice(0, 200), { routes: ['/api/view/gap', '/api/workbench/v1/bom-candidates'], actions: ['click A; change filter; release'] });
  hold = false; await pg.click('[data-action=bom-filter][data-filter=all]'); await pg.waitFor(`window.__otStore.get().bom8.filter==='all' && !window.__otStore.get().bom8.req.queue`, 15000); await sleep(500);
  failNext = true; await pg.click(rowSel(B)); await pg.waitFor(`document.querySelector('.ot-bom8-evidence [role=alert]')`, 15000);
  s = await state(pg); const rows = await pg.eval(`document.querySelectorAll('.ot-bom8-row').length`);
  check('interact T3: a failed detail is shown in the inspector only; the queue stays usable', rows === 3 && s.bom8.error === null && /could not be loaded/.test(await inspectorContent(pg)), `rows=${rows}`, { routes: ['/api/view/gap (forced 500)'] });
  await pg.click(rowSel(C)); await waitEvidence(pg, C); check('interact T3b: selecting another candidate recovers', (await inspectorContent(pg)).includes(mark[C]), '');
  await select(pg, A); const lp = await layoutProbe(pg);
  check('interact T4 1366: evidence inside the viewport, no horizontal scroll', lp.evInside && !lp.hscroll, JSON.stringify(lp));
  hold = true; held.length = 0; await pg.click(rowSel(B)); const hb2 = await waitHeld(B);
  await pg.click('#ot-top-end'); await pg.waitFor(`document.getElementById('ot-ended-note')`, 30000); await release(hb2); await sleep(600); s = await state(pg);
  check('interact T5: ending the session with a detail in flight leaves no evidence and an explicit ended state', !s.analysis && !(await pg.eval(`!!document.querySelector('[data-evidence-for]')`)) && s.bom8.detail === null, JSON.stringify(s.session), { routes: ['/api/view/gap'], actions: ['click B; End session; release'] });
  await pg.send('Fetch.disable');
}

let svc, chrome;
try {
  svc = await service(); chrome = await launch(); if (process.env.OT_PIDS_FILE) appendFileSync(process.env.OT_PIDS_FILE, chrome.proc.pid + '\n');
  const pg = await newPage(chrome.browser, { width: 1366, height: 900 }); await pg.goto(svc.base);
  await pg.waitFor(`document.getElementById('ot-url')`, 30000);
  if (PAIR === 'matrix') await caseMatrix(pg); else if (PAIR === 'states') await caseStates(pg); else if (PAIR === 'norun') await caseNorun(pg); else await caseInteract(pg, chrome.browser);
  check(`${PAIR}: no page exceptions`, pg.log.exceptions.length === 0, pg.log.exceptions.join(' | ').slice(0, 300));
} catch (e) { H.unfinished.push('driver stopped: ' + e.message); check(`${PAIR}: run completed`, false, e.stack || e.message); }
finally { H.save(); try { svc && svc.stop(); } catch {} if (chrome) await chrome.close(); }
const failed = H.results.filter((r) => !r.ok).length; console.log(`${H.results.length - failed}/${H.results.length} checks passed; unfinished: ${H.unfinished.length}`);
