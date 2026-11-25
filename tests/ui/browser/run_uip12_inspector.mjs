// UIP-12 V2 (test harness): the ACTIVE BOM inspector through real browser interaction on LOCAL SYNTHETIC fixtures (tests/ui/browser/uip12_crypto_service.py).
// One fixture service + one headless Chrome per invocation (pair). A synthetic positive CBOM is NOT a third-party live comparison.
// Usage: OT_DEADLINE_MS=<epoch ms> OT_PIDS_FILE=<file> node run_uip12_inspector.mjs <pair: matrix|states|interact> <outDir>
import { spawn } from 'node:child_process';
import { appendFileSync } from 'node:fs';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { launch, newPage } from './cdp.mjs';
import { harness, sleep, txt, state, api, apiJson, frames, viewport, settled, setUrl, detailRequests, inspectorContent, layoutProbe, endSession } from './uip12_lib.mjs';

const HERE = dirname(fileURLToPath(import.meta.url)); const REPO = resolve(HERE, '../../..');
const [PAIR, OUTARG] = process.argv.slice(2);
const H = harness({ out: OUTARG, label: PAIR, synthetic: true });
const { check, guard, evidence, OUT } = H;
const ROUTES_BOM = ['/api/workbench/v1/bom-candidates', '/api/workbench/v1/bom-graph', '/api/view/gap'];

function service() {
  const proc = spawn(process.env.PYTHON || 'python3', [join(HERE, 'uip12_crypto_service.py'), '--case', PAIR], { cwd: REPO, env: { ...process.env, PYTHONPATH: `${REPO}:${join(REPO, 'src/core')}` }, stdio: ['ignore', 'pipe', 'pipe'] });
  if (process.env.OT_PIDS_FILE) appendFileSync(process.env.OT_PIDS_FILE, proc.pid + '\n');
  return new Promise((res, rej) => { let b = ''; const t = setTimeout(() => rej(new Error('service did not start: ' + b)), 40000);
    proc.stdout.on('data', (d) => { b += d; const m = b.match(/http:\/\/127\.0\.0\.1:(\d+)\//); if (m) { clearTimeout(t); res({ base: m[0], stop: () => proc.kill('SIGTERM') }); } });
    proc.stderr.on('data', (d) => { b += d; }); });
}
const scanRepo = async (pg, repo, first) => {
  guard(); if (!first) await endSession(pg);
  await pg.waitFor(`document.getElementById('ot-scan') && !document.getElementById('ot-scan').disabled`, 20000);
  await setUrl(pg, 'https://github.com/acme/' + repo); await pg.click('#ot-scan');
  await pg.waitFor(`window.__otStore.get().destination === 'workbench' || window.__otStore.get().scan?.status?.job?.state === 'failed'`, 90000);
  await pg.click('#ot-tab-bom'); await pg.waitFor(`window.__otStore.get().bom8.queue`, 30000);
  await pg.waitFor(`(()=>{const b=window.__otStore.get().bom8; return b.queue && !b.req.queue && !b.req.graph && !b.req.detail})()`, 30000);
};
const gen = async (pg) => (await state(pg)).analysis.generation;
const queue = async (pg) => { const g = await gen(pg); const r = await apiJson(pg, `/api/workbench/v1/bom-candidates?schema_version=1&generation=${g}`); const caps = Object.fromEntries((r.body?.capabilities || []).map((c) => [c.family, c.state + (c.reason_code ? '/' + c.reason_code : '')])); return { mode: r.body?.mode, caps, items: r.body?.items || [], counts: r.body?.counts }; };
const openCrypto = async (pg) => { await pg.click('[data-action=bom-view][data-view=crypto]'); await settled(pg, 'crypto'); };
const rowSel = (id) => `[data-action=bom-select][data-id=${JSON.stringify(id)}]`;
const waitEvidence = (pg, id) => pg.waitFor(`document.querySelector('[data-evidence-for=${JSON.stringify(id)}] .ot-gap-inspector')`, 20000);
const select = async (pg, id) => { await pg.click(rowSel(id)); await waitEvidence(pg, id); };
const hasRecord = (t, kind) => t.includes(kind);

async function inspectBoth(pg, label, id, expect) {
  for (const vp of ['1366', '390']) {
    guard(); await viewport(pg, vp === '390');
    const before = detailRequests(pg).length; await select(pg, id); const t = await inspectorContent(pg); const lp = await layoutProbe(pg); const reqs = detailRequests(pg).slice(before);
    evidence[`${label}_${vp}`] = { text: t.slice(0, 2500), layout: lp, detail_requests: reqs.map((r) => r.url) };
    const tags = { routes: ROUTES_BOM, actions: ['click candidate row', vp === '390' ? 'drawer at 390 px' : 'inspector at 1366 px'] };
    check(`${label} ${vp}: selection requested this candidate's evidence`, reqs.length >= 1 && reqs.every((r) => r.url.includes(encodeURIComponent(id))), `${reqs.length}`, tags);
    for (const [name, ok] of expect(t)) check(`${label} ${vp}: ${name}`, ok, t.slice(0, 220), tags);
    check(`${label} ${vp}: no horizontal page scroll; evidence inside the viewport`, !lp.hscroll && lp.evInside, JSON.stringify(lp), tags);
    if (vp === '390') await pg.screenshot(join(OUT, `${label}_390.png`)); else await pg.screenshot(join(OUT, `${label}_1366.png`));
  }
}

async function pairMatrix(pg) {
  const want = {
    positive: { n: 1, state: 'supported', cr: 'completed', ex: (t) => [['source call site shown (path:line, verbatim excerpt, digest)', hasRecord(t, 'Source call site') && /app\/m\.py:4/.test(t) && /hashlib\.sha256\(x\)\.hexdigest\(\)/.test(t) && /File SHA-256/.test(t)], ['CBOM record shown separately with census', hasRecord(t, 'Selected CBOM') && /1 cryptographic asset/.test(t)], ['conclusion supported with bounded meaning', /Conclusion:/.test(t) && /call_site_in_range_unique/.test(t) && /Declaration-level/.test(t)], ['alias decision shown, spelling applied', /Algorithm spelling/.test(t) && /finite alias mapping applied/.test(t)]] },
    renamed: { n: 1, state: 'supported', cr: 'completed', ex: (t) => [['verbatim renamed excerpt and imported name shown', /x = s\(b"x"\)/.test(t) && /imported name sha256/.test(t)], ['supported without synthetic text in the excerpt', /call_site_in_range_unique/.test(t)]] },
    zeroasset: { n: 1, state: 'unverifiable', cr: 'completed', ex: (t) => [['zero-asset CBOM census and no_algorithm_record', hasRecord(t, 'Selected CBOM') && /0 cryptographic assets/.test(t) && /no_algorithm_record/.test(t)], ['absence is not a contradiction', /Absence is not a contradiction/.test(t)]] },
    obsonly: { n: 2, state: null, cr: 'completed', ex: (t) => [['observation only: source record, no CBOM record fabricated', hasRecord(t, 'Source call site') && !hasRecord(t, 'Selected CBOM')], ['says it was not compared', /not compared|observed/i.test(t)]] },
    outside: { n: 1, state: null, cr: 'partial', ex: (t) => [['outside-scope: source shown, no CBOM record, reason visible', hasRecord(t, 'Source call site') && !hasRecord(t, 'Selected CBOM') && /outside/i.test(t)]] },
    noscope: { n: 1, state: null, cr: 'partial', ex: (t) => [['unrecorded scope: source shown, no CBOM record, reason visible', hasRecord(t, 'Source call site') && !hasRecord(t, 'Selected CBOM') && /scope/i.test(t)]] },
    cbomfail: { n: 1, state: null, cr: 'failed', ex: (t) => [['producer failed: source shown, no CBOM record fabricated', hasRecord(t, 'Source call site') && !hasRecord(t, 'Selected CBOM')]] },
  };
  let first = true;
  for (const [repo, w] of Object.entries(want)) {
    try {
      await scanRepo(pg, repo, first); first = false; await viewport(pg, false); await openCrypto(pg);
      const q = await queue(pg); evidence[`${repo}_queue`] = { mode: q.mode, caps: q.caps, n: q.items.length, states: q.items.map((i) => i.state) };
      check(`${repo}: ${w.n} cryptography candidate(s) and page-level discovery_compared`, q.items.length === w.n && q.mode === 'discovery_compared', JSON.stringify(evidence[`${repo}_queue`]), { routes: ['/api/workbench/v1/bom-candidates'], actions: ['scan fixture', 'open Cryptography view'] });
      check(`${repo}: cryptography capability is ${w.cr}`, (q.caps.cryptography || '').startsWith(w.cr), q.caps.cryptography, { routes: ['/api/workbench/v1/bom-candidates'] });
      if (w.state) check(`${repo}: candidate state ${w.state}`, q.items.every((i) => i.state === w.state), JSON.stringify(q.items.map((i) => i.state)));
      for (const [k, it] of q.items.entries()) await inspectBoth(pg, `${repo}${q.items.length > 1 ? '_' + k : ''}`, it.item_id, w.ex);
    } catch (e) { if (e.message === 'DEADLINE') { H.unfinished.push(repo + ': deadline'); break; } check(`${repo}: run completed`, false, e.stack || e.message); }
  }
}

async function pairStates(pg) {
  const want = { partial: ['partial', 'partial'], empty: ['completed_empty', 'completed_empty'], nosource: ['completed_empty', 'completed_empty'], nodeonly: ['unsupported', 'unsupported'], failrepo: ['failed', 'failed'] };
  let first = true;
  for (const [repo, [sw, cr]] of Object.entries(want)) {
    try {
      await scanRepo(pg, repo, first); first = false;
      const q = await queue(pg); evidence[`${repo}_queue`] = { mode: q.mode, caps: q.caps, n: q.items.length };
      check(`${repo}: software ${sw} and cryptography ${cr} (separate family states)`, (q.caps.software || '').startsWith(sw) && (q.caps.cryptography || '').startsWith(cr), JSON.stringify(q.caps), { routes: ['/api/workbench/v1/bom-candidates'], actions: ['scan fixture'] });
      for (const vp of ['1366', '390']) {
        await viewport(pg, vp === '390');
        for (const v of ['software', 'crypto', 'gaps', 'full']) {
          guard(); await pg.click(`[data-action=bom-view][data-view=${v}]`); await settled(pg, v);
          const t = await txt(pg, '.ot-bom8'); const lp = await layoutProbe(pg); const id = `${repo} ${v} ${vp}`;
          evidence[`${repo}_${v}_${vp}`] = t.slice(0, 700);
          check(`${id}: no horizontal scroll`, !lp.hscroll, JSON.stringify(lp), { routes: ROUTES_BOM, actions: ['switch BOM view', vp + ' px'] });
          check(`${id}: no leaked exception text or path`, !/injected|PermissionError|\/tmp\/|\/private\/|Traceback/.test(t), t.slice(0, 160));
          if (repo === 'partial' && v === 'crypto') check(`${id}: partial cryptography disclosure has its own wording`, !!(await pg.eval(`!!document.querySelector('.ot-bom8-coverage[data-family=cryptography]')`)) && /no cryptography is used/.test(t), t.slice(0, 220));
          if (q.mode === 'discovery_compared' && (repo === 'empty' || repo === 'nosource') && v === 'crypto') check(`${id}: empty state is stated, not described as a finding of no cryptography`, /not evidence|nothing was compared|no candidates|No requirement declarations|assessment has no candidates/i.test(t), t.slice(0, 260));
          if (q.mode !== 'discovery_compared') check(`${id}: not-compared reason visible`, /Not compared\./.test(t), t.slice(0, 220));
        }
        await pg.screenshot(join(OUT, `${repo}_${vp}.png`));
      }
      if (repo === 'partial') {   // empty by filter / search while partial: list empty, detail empty, notice stays
        await viewport(pg, false); await pg.click('[data-action=bom-view][data-view=crypto]'); await settled(pg, 'crypto');
        await pg.click('[data-action=bom-filter][data-filter=not_represented]'); await pg.waitFor(`window.__otStore.get().bom8.filter==='not_represented' && !window.__otStore.get().bom8.req.queue`, 15000);
        const t = await txt(pg, '.ot-bom8'); const s = await state(pg);
        check('partial: empty by filter - no rows, no evidence, disclosure stays, no stale detail', !(await pg.eval(`!!document.querySelector('.ot-bom8-row')`)) && !(await pg.eval(`!!document.querySelector('[data-evidence-for]')`)) && s.bom8.detail === null && /Partial coverage/.test(t), t.slice(0, 200), { actions: ['click filter Not represented'] });
        await pg.click('[data-action=bom-filter][data-filter=all]'); await pg.waitFor(`window.__otStore.get().bom8.filter==='all' && !window.__otStore.get().bom8.req.queue`, 15000);
      }
    } catch (e) { if (e.message === 'DEADLINE') { H.unfinished.push(repo + ': deadline'); break; } check(`${repo}: run completed`, false, e.stack || e.message); }
  }
}

async function pairInteract(pg, browser) {
  await scanRepo(pg, 'multi', true); await viewport(pg, false); await openCrypto(pg);
  const q = await queue(pg); const ids = await pg.eval(`[...document.querySelectorAll('[data-action=bom-select]')].map((e)=>e.dataset.id)`);
  const byPath = Object.fromEntries(q.items.map((i) => [i.location.path, i.item_id])); evidence.items = q.items.map((i) => ({ id: i.item_id, path: i.location.path, state: i.state }));
  check('interact: three candidates (supported, unverifiable, observation-only)', q.items.length === 3 && ids.length === 3, JSON.stringify(evidence.items), { routes: ['/api/workbench/v1/bom-candidates'], actions: ['scan fixture', 'open Cryptography view'] });
  const A = byPath['app/a.py'], B = byPath['app/b.py'], C = byPath['app/c.py']; const mark = { [A]: 'hashlib.sha256(b"a")', [B]: 'hashlib.md5(b"b")', [C]: 'pbkdf2_hmac' };
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
  const waitHeld = (id) => pg.waitFor(`true`, 1).then(async () => { const t0 = Date.now(); while (Date.now() - t0 < 10000) { if (heldFor(id)) return heldFor(id); await sleep(50); } throw new Error('request not held: ' + id); });
  await sleep(500); // the auto-selected candidate's own request passed through (hold was off)
  // T1 late response: B is requested and held, C is requested; C answers first, then the late B answer arrives
  hold = true; held.length = 0;
  await pg.click(rowSel(B)); const hb = await waitHeld(B); await pg.click(rowSel(C)); const hc = await waitHeld(C);
  await release(hc); await waitEvidence(pg, C); await release(hb); await sleep(600);
  let t = await inspectorContent(pg); let s = await state(pg);
  check('interact T1: a late response for the previous candidate never replaces the visible one', s.bom8.selected === C && t.includes(mark[C]) && !t.includes(mark[B]) && !!(await pg.eval(`!!document.querySelector('[data-evidence-for=${JSON.stringify(C)}]')`)), t.slice(0, 200), { routes: ['/api/view/gap'], actions: ['click candidate B', 'click candidate C', 'release responses out of order'] });
  // T2 in-flight request then a filter change that leaves nothing selected
  held.length = 0; await pg.click(rowSel(A)); const ha = await waitHeld(A);
  await pg.click('[data-action=bom-filter][data-filter=not_represented]'); await pg.waitFor(`window.__otStore.get().bom8.filter==='not_represented' && !window.__otStore.get().bom8.req.queue`, 15000);
  await release(ha); await sleep(600); t = await inspectorContent(pg); s = await state(pg);
  check('interact T2: a filter change during an in-flight detail leaves no other candidate\'s evidence', s.bom8.detail === null && !(await pg.eval(`!!document.querySelector('[data-evidence-for]')`)) && !t.includes(mark[A]), t.slice(0, 200), { routes: ['/api/view/gap', '/api/workbench/v1/bom-candidates'], actions: ['click candidate A', 'click filter Not represented', 'release late response'] });
  hold = false; await pg.click('[data-action=bom-filter][data-filter=all]'); await pg.waitFor(`window.__otStore.get().bom8.filter==='all' && !window.__otStore.get().bom8.req.queue`, 15000); await sleep(500);
  // T3 candidate-local failure
  failNext = true; await pg.click(rowSel(B)); await pg.waitFor(`document.querySelector('.ot-bom8-evidence [role=alert]')`, 15000);
  s = await state(pg); const rows = await pg.eval(`document.querySelectorAll('.ot-bom8-row').length`);
  check('interact T3: a failed detail is shown in the inspector only; queue and workspace stay usable', rows === 3 && s.bom8.error === null && /could not be loaded/.test(await inspectorContent(pg)), `rows=${rows} error=${s.bom8.error}`, { routes: ['/api/view/gap (forced 500)'], actions: ['click candidate B'] });
  await pg.click(rowSel(C)); await waitEvidence(pg, C); check('interact T3b: selecting another candidate recovers', (await inspectorContent(pg)).includes(mark[C]), '');
  // T4 layout, scrolling, drawer, focus at 390 px
  await viewport(pg, true); await select(pg, A); let lp = await layoutProbe(pg);
  check('interact T4 390: evidence inside viewport, no horizontal scroll, drawer open', lp.evInside && !lp.hscroll && lp.drawerOpen, JSON.stringify(lp), { actions: ['click candidate at 390 px'] });
  await pg.eval(`document.querySelector('.ot-bom8-drawer-body')?.scrollTo(0, 99999)`); await frames(pg); lp = await layoutProbe(pg);
  evidence.t4_scroll = lp; check('interact T4 390: the evidence body scrolls inside the drawer (no clipping of the end of the evidence)', lp.bodyScrollable === false || lp.bodyOverflowY !== 'visible', JSON.stringify(lp), { actions: ['scroll drawer'] });
  await pg.eval(`document.querySelector('[data-action=bom-drawer]').focus()`); await pg.key('Enter'); await frames(pg); const closed = !(await layoutProbe(pg)).drawerOpen;
  await pg.eval(`document.querySelector('[data-action=bom-drawer]').focus()`); await pg.key('Enter'); await frames(pg); const reopened = (await layoutProbe(pg)).drawerOpen;
  check('interact T4 390: keyboard (Enter on the drawer button) closes and reopens the drawer', closed && reopened, `closed=${closed} reopened=${reopened}`, { actions: ['focus drawer button', 'press Enter twice'] });
  const cover = await pg.eval(`(()=>{const L=document.getElementById('ot-assistant-launch'); const p=document.querySelector('.ot-bom8-evidence .ot-raw'); if(!L||!p) return {err:'missing'}; const a=L.getBoundingClientRect(), b=p.getBoundingClientRect(); const w=Math.min(a.right,b.right)-Math.max(a.left,b.left), h=Math.min(a.bottom,b.bottom)-Math.max(a.top,b.top); return {overlap: w>1&&h>1, launcher:[a.left,a.top,a.right,a.bottom].map(Math.round), pre:[b.left,b.top,b.right,b.bottom].map(Math.round)}})()`);
  evidence.t4_launcher = cover; check('interact T4 390: the floating assistant button does not cover the source excerpt at the top of the evidence', cover.err ? false : !cover.overlap, JSON.stringify(cover), { actions: ['measure launcher vs excerpt'] });
  await pg.screenshot(join(OUT, 'interact_390.png'));
  // T5 session retirement with a request in flight
  await viewport(pg, false); hold = true; held.length = 0; await pg.click(rowSel(B)); const hb2 = await waitHeld(B);
  await pg.click('#ot-top-end'); await pg.waitFor(`document.getElementById('ot-ended-note')`, 30000); await release(hb2); await sleep(600); s = await state(pg);
  check('interact T5: ending the session with a detail in flight leaves no evidence and an explicit ended state', !s.analysis && !(await pg.eval(`!!document.querySelector('[data-evidence-for]')`)) && s.bom8.detail === null && !!(await pg.eval(`!!document.getElementById('ot-ended-note')`)), JSON.stringify(s.session), { routes: ['POST /api/session/end', '/api/view/gap'], actions: ['click candidate B', 'click End session', 'release late response'] });
  await pg.send('Fetch.disable');
}

let svc, chrome;
try {
  svc = await service(); chrome = await launch(); if (process.env.OT_PIDS_FILE) appendFileSync(process.env.OT_PIDS_FILE, chrome.proc.pid + '\n');
  const pg = await newPage(chrome.browser, { width: 1366, height: 900 }); await pg.goto(svc.base);
  await pg.waitFor(`document.getElementById('ot-url')`, 30000);
  if (PAIR === 'matrix') await pairMatrix(pg); else if (PAIR === 'states') await pairStates(pg); else await pairInteract(pg, chrome.browser);
  check(`${PAIR}: no page exceptions`, pg.log.exceptions.length === 0, pg.log.exceptions.join(' | ').slice(0, 300));
} catch (e) { H.unfinished.push('driver stopped: ' + e.message); check(`${PAIR}: run completed`, false, e.stack || e.message); }
finally { H.save(); try { svc && svc.stop(); } catch {} if (chrome) await chrome.close(); }
const failed = H.results.filter((r) => !r.ok).length; console.log(`${H.results.length - failed}/${H.results.length} checks passed; unfinished: ${H.unfinished.length}`);
