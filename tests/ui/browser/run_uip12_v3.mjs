// UIP-12 V3 + V1b + V3-UI (test harness): ONE real, commit-pinned scan of a public Python repository through the Dockerized Workbench UI, then the legacy/v1 route reads,
// then the actual active BOM inspector in the same Chrome session, then End session in the browser. No retries: a failed or timed-out scan is reported.
// Usage: OT_DEADLINE_MS=<epoch ms> OT_PIDS_FILE=<file> node run_uip12_v3.mjs <outDir> <https url> <commit sha>
import { appendFileSync } from 'node:fs';
import { join } from 'node:path';
import { launch, newPage } from './cdp.mjs';
import { harness, sleep, txt, state, api, apiJson, frames, viewport, settled, setUrl, detailRequests, inspectorHtml, inspectorText, layoutProbe, endSession } from './uip12_lib.mjs';

const [OUTARG, URL, PIN] = process.argv.slice(2);
const BASE = 'http://127.0.0.1:' + (process.env.OPENTRACE_PORT || '8770') + '/';
const SCAN_CAP_MS = 9 * 60 * 1000;
const H = harness({ out: OUTARG, label: 'v3', synthetic: false });
const { check, guard, evidence, OUT } = H;
let chrome;
try {
  chrome = await launch();
  if (process.env.OT_PIDS_FILE) appendFileSync(process.env.OT_PIDS_FILE, chrome.proc.pid + '\n');
  const pg = await newPage(chrome.browser, { width: 1366, height: 900 });
  await pg.goto(BASE);
  await pg.waitFor(`document.getElementById('ot-scan') && !document.getElementById('ot-scan').disabled || (document.getElementById('ot-url'))`, 30000);
  // ---- V3: the single scan, submitted through the UI (no retry)
  await setUrl(pg, URL);
  await pg.waitFor(`document.getElementById('ot-scan') && !document.getElementById('ot-scan').disabled`, 20000);
  const t0 = Date.now(); await pg.click('#ot-scan');
  let scanEnd = 'timeout';
  while (Date.now() - t0 < SCAN_CAP_MS) {
    guard();
    const s = await state(pg);
    if (s.destination === 'workbench' && s.analysis) { scanEnd = 'analysis'; break; }
    if (s.scan?.status?.job?.state === 'failed' || s.scan?.status?.job?.state === 'cancelled') { scanEnd = 'job_' + s.scan.status.job.state; break; }
    await sleep(500);
  }
  evidence.scan = { end: scanEnd, seconds: Math.round((Date.now() - t0) / 100) / 10 };
  if (scanEnd === 'timeout') { try { await pg.click('#ot-scan-cancel'); } catch {} evidence.scan.cancel_clicked = true; await sleep(3000); }
  check('V3 scan reached an analysis', scanEnd === 'analysis', JSON.stringify(evidence.scan), { routes: ['POST /api/scan', 'GET /api/scan/status'], actions: ['enter URL', 'click Scan'] });
  const s = await state(pg);
  evidence.scan_state = s.scan?.status ? { job: s.scan.status.job } : null;
  if (scanEnd === 'analysis') {
    const id = s.analysis.identity; evidence.identity = { repository: id.repository, commit: id.commit, requested: id.requested, basis: id.basis, mode: id.mode, analysis_digest: id.analysis_digest };
    check('V3 commit equals the pinned commit', id.commit === PIN, `${id.commit} vs ${PIN}`);
    const gen = s.analysis.generation, live = s.analysis.summary.live;
    evidence.live = { source: live.source, scan: (live.scan || []).map((r) => ({ scanner: r.scanner, outcome: r.outcome, reason: r.reason, sha256: r.sha256, record_count: r.record_count, tool: r.tool, version: r.version })), advisory: live.advisory };
    // ---- V1b: legacy and v1 routes for the live analysis (same-origin fetch in this page; payloads saved for offline frozen-schema validation)
    const routes = { gaps: '/api/view/gaps?offset=0', bom: '/api/view/bom', crypto: '/api/view/crypto', ai: '/api/view/ai', contexts: '/api/view/contexts', dependencies: '/api/view/dependencies?per_side=6' };
    for (const [n, p] of Object.entries(routes)) { const r = await api(pg, p); check(`V1b GET ${p} is 200`, r.status === 200, r.status, { routes: [p] }); H.evidence['legacy_' + n] = { status: r.status, bytes: r.body.length }; }
    const q = await apiJson(pg, `/api/workbench/v1/bom-candidates?schema_version=1&generation=${gen}`);
    check('V1b bom-candidates 200 and discovery_compared', q.status === 200 && q.body?.mode === 'discovery_compared', `${q.status} ${q.body?.mode}`, { routes: ['bom-candidates'] });
    writeSave(OUT, 'payload_bom_candidates.json', q.raw);
    const caps = Object.fromEntries((q.body?.capabilities || []).map((c) => [c.family, { state: c.state, reason: c.reason_code }])); evidence.capabilities = caps;
    evidence.counts = q.body?.counts; evidence.crypto_collection = (await apiJson(pg, '/api/view/gaps?offset=0')).body?.collection ?? null;
    const items = (q.body?.items || []); const crypto = items.filter((x) => x.family === 'cryptography'); evidence.crypto_items = crypto.map((x) => ({ item_id: x.item_id, state: x.state, location: x.location, display: x.display?.name }));
    if (crypto[0]) {
      const g = await apiJson(pg, `/api/workbench/v1/bom-graph?schema_version=1&generation=${gen}&scope_kind=focused_candidate&candidate_id=${encodeURIComponent(crypto[0].item_id)}`);
      check('V1b bom-graph focused candidate 200', g.status === 200, g.status, { routes: ['bom-graph'] }); writeSave(OUT, 'payload_bom_graph.json', g.raw);
      const nid = g.body?.nodes?.[0]?.canonical_ref?.record_id;
      if (nid) { const r = await apiJson(pg, `/api/workbench/v1/bom-related-checks?schema_version=1&generation=${gen}&subject_kind=record&subject_id=${encodeURIComponent(nid)}`); check('V1b bom-related-checks 200', r.status === 200, r.status, { routes: ['bom-related-checks'] }); writeSave(OUT, 'payload_bom_related.json', r.raw); }
      const d = await apiJson(pg, `/api/view/gap?id=${encodeURIComponent(crypto[0].item_id)}`); writeSave(OUT, 'payload_gap_detail.json', d.raw); evidence.gap_detail_status = d.status;
    }
    // ---- V3-UI: the actual active inspector, before the session ends
    await pg.click('#ot-tab-bom'); await pg.waitFor(`window.__otStore.get().bom8.queue`, 30000);
    await pg.click('[data-action=bom-view][data-view=crypto]'); await settled(pg, 'crypto');
    const rows = await pg.eval(`document.querySelectorAll('.ot-bom8-row').length`); check('V3-UI cryptography view lists the observed site(s)', rows >= 1, `rows=${rows} predicted 1`, { routes: ['bom-candidates'], actions: ['open BOM tab', 'open Cryptography view'] });
    for (const vp of ['1366', '390']) {
      guard(); await viewport(pg, vp === '390');
      const before = detailRequests(pg).length;
      await pg.click('[data-action=bom-select]'); await pg.waitFor(`document.querySelector('[data-evidence-for]')`, 30000);
      await settled(pg, 'crypto');
      const reqs = detailRequests(pg).slice(before); const t = await inspectorText(pg); const lp = await layoutProbe(pg);
      evidence['inspector_' + vp] = { text: t.slice(0, 3000), layout: lp, detail_requests: reqs.map((r) => r.url) };
      check(`V3-UI ${vp}: selecting the candidate requested its own evidence (route /api/view/gap)`, reqs.length >= 1 && reqs.every((r) => r.url.includes('id=')), `${reqs.length} requests`, { routes: ['/api/view/gap'], actions: ['click candidate row'] });
      check(`V3-UI ${vp}: source excerpt, path:line and file digest shown`, /hashlib\.sha256\(\)/.test(t) && /integrity_checker\.py:14/.test(t) && /File SHA-256/.test(t), t.slice(0, 200));
      check(`V3-UI ${vp}: CBOM record (if a CBOM was acquired) and conclusion shown`, /Conclusion:/.test(t) && (/Selected CBOM/.test(t) || !/acquired/.test(JSON.stringify(caps))), t.slice(0, 200));
      check(`V3-UI ${vp}: limits and bounded meaning present`, /Not established/.test(t) || /Sources & coverage/.test(t), '');
      check(`V3-UI ${vp}: no page-level horizontal scroll, evidence inside viewport`, !lp.hscroll && lp.evInside, JSON.stringify(lp));
      if (vp === '390') {
        await pg.eval(`document.querySelector('.ot-bom8-drawer-body')?.scrollTo(0, 99999)`); await frames(pg);
        const open = (await layoutProbe(pg)).drawerOpen; check('V3-UI 390: details drawer is open after selection and scrollable content stays inside it', open, JSON.stringify(await layoutProbe(pg)), { actions: ['scroll drawer'] });
        await pg.click('[data-action=bom-drawer]'); await frames(pg); const closed = !(await layoutProbe(pg)).drawerOpen; check('V3-UI 390: drawer toggles closed', closed, '', { actions: ['click Close details'] });
        await pg.click('[data-action=bom-drawer]'); await frames(pg); check('V3-UI 390: drawer reopens and keeps this candidate\'s evidence', (await layoutProbe(pg)).evidence, '', { actions: ['click Open details'] });
      }
      await pg.screenshot(join(OUT, `v3_inspector_${vp}.png`));
    }
    evidence.console_errors = pg.log.console.filter((c) => c.type === 'error').slice(0, 10); evidence.exceptions = pg.log.exceptions.slice(0, 5);
    check('V3-UI no page exceptions', pg.log.exceptions.length === 0, pg.log.exceptions.join(' | ').slice(0, 200));
    // ---- End session in the browser (after the V3-UI pass)
    await endSession(pg); const after = await state(pg); evidence.session_after_end = after.session;
    check('V1d End session completed in the browser and the analysis is gone', !after.analysis && /ended|deleted/.test(JSON.stringify(after.session)) , JSON.stringify(after.session).slice(0, 200), { routes: ['POST /api/session/end'], actions: ['click End session'] });
  } else {
    try { await endSession(pg); } catch (e) { H.unfinished.push('end session after failed scan: ' + e.message); }
  }
} catch (e) { H.unfinished.push('driver stopped: ' + e.message); console.log('STOPPED', e.message); }
finally { H.save(); if (chrome) await chrome.close(); }
import { writeFileSync } from 'node:fs';
function writeSave(out, name, text) { writeFileSync(join(out, name), text); }
