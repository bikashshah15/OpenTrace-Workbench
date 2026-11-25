// UIP-12-IR-04: the ACTIVE versioned BOM workspace shows the selected candidate's evidence. These drive the real request flow (src/ui/lib/bom_flow.js),
// the real store/reducer and the real active renderer (renderBomWorkspace) with a fake `api` that records every path and releases responses in any order.
// Nothing here calls the legacy exported inspector().
import test from 'node:test';
import assert from 'node:assert/strict';
import { createStore, initial, bomContextPatch } from '../../../src/ui/lib/store.js';
import { createBomFlow } from '../../../src/ui/lib/bom_flow.js';
import { renderBomWorkspace, inspector } from '../../../src/ui/components/gaps.js';

const qs = (o) => Object.entries(o).filter(([, v]) => v !== null && v !== undefined && v !== '').map(([k, v]) => `${k}=${encodeURIComponent(v)}`).join('&');
const identity = { analysis_digest: 'a'.repeat(64), owner: 'review', name: 'fixture', commit: 'b'.repeat(40) };
const binding = { analysis_digest: identity.analysis_digest };
const item = (id, name) => ({ item_id: id, assertion_id: `as-${id}`, display: { name, raw_title: name }, state: 'unverifiable', category: 'unknown_coverage', graph_state: 'assertion_graph',
  family: 'cryptography', location: { path: `app/${id}.py`, line_start: 2, line_end: 2 }, inventory: { inventory_id: 'inv:cbom', generator: 'cdxgen 12.9.0' }, rule_id: 'crypto_attribution.operation_declared_in_cbom/4' });
const queue = (...items) => ({ binding, mode: 'discovery_compared', counts: { candidates_total: items.length, filtered_total: items.length, records_total: 0 }, items, page: { offset: 0, size: 25, has_more: false },
  capabilities: [{ family: 'software', state: 'completed', reason_code: null }, { family: 'cryptography', state: 'completed', reason_code: null }] });
const src = (id, excerpt) => ({ evidence_id: `src-${id}`, kind: 'source_excerpt', role: 'source_reference', relation: 'context', reason: `app/${id}.py shows the call`, method: 'python-ast', origin: 'captured',
  source: { file: `app/${id}.py`, file_sha256: 'd'.repeat(64), lines: [2, 2] }, excerpt, excerpt_truncated: false, operation: 'hash',
  resolution: { call: 'python:hashlib.sha256', algorithm_source: 'function_name', binding: 'from_import', binding_status: 'unique_module_level', imported_name: 'sha256', local_module_named_hashlib: 'absent_after_complete_search' },
  checks: { audit_complete: true, source_digest_verified: true } });
const cbom = (id) => ({ evidence_id: `cbom-${id}`, kind: 'cbom_document', role: 'cbom_document', relation: 'inconclusive', reason: 'the document has 1 cryptographic asset(s); none is an admissible sha256 record', method: 'cyclonedx', origin: 'captured',
  document: { format: 'CycloneDX', spec_version: '1.6', raw_sha256: 'e'.repeat(64) }, status: 'ok', producer: [{ name: 'cdxgen', version: '12.9.0' }], census: { components: 3, assets: 1, services: 0 } });
const detail = (id, records, extra = {}) => ({ binding, candidate: { candidate_id: id, state: 'unverifiable', state_label: 'Could not be confirmed', category_label: 'Unknown coverage', title: `sha256 call at app/${id}.py:2`,
  rationale: `RATIONALE-${id}`, bom: { label: 'cdxgen 12.9.0', inventory_id: 'inv:cbom', sha256: 'c'.repeat(64) }, trigger: 'searched', records, reason_codes: ['no_algorithm_record'], assertion_id: `as-${id}`,
  rule_id: 'crypto_attribution.operation_declared_in_cbom/4', not_established: ['that the code runs', 'independent verification'], bounded_meaning: 'BOUNDED-MEANING declaration-level only', identity_basis: 'finite mapping',
  algorithm_alias: { canonical: 'sha256', applied: true, assertion_value: 'sha256', source_value: 'sha256', cbom_value: 'SHA-256' },
  excluded_assets: [{ name: 'sha256', reason_code: 'operation_context_mismatch', detail: 'the occurrence records hashlib.md5' }], ...extra } });

function rig() {
  const store = createStore({ ...initial(), epoch: 3, analysis: { generation: 7, identity }, workbench: { ...initial().workbench, tab: 'bom' } });
  const sent = [];
  const api = (path) => new Promise((resolve, reject) => { sent.push({ path, kind: path.startsWith('/api/view/gap?') ? 'detail' : path.includes('/bom-graph') ? 'graph' : path.includes('/bom-candidates') ? 'queue' : 'other', resolve, reject }); });
  const flow = createBomFlow({ store, api, qs });
  const of = (kind) => sent.filter((r) => r.kind === kind);
  const tick = () => new Promise((r) => setImmediate(r));
  const err = (status, message) => Object.assign(new Error(message), { status });
  const html = () => renderBomWorkspace(store.get());
  const inspectorHtml = () => html().match(/<div class="ot-bom8-drawer-body">([\s\S]*?)<\/div><\/aside>/)[1];
  return { store, sent, flow, of, tick, err, html, inspectorHtml };
}
async function loadedQueue(r, ...items) {
  r.flow.switchBomView('crypto');
  r.of('queue')[0].resolve(queue(...items)); await r.tick();
}

test('the active workspace loads and renders the selected candidate\'s own evidence through the real request path', async () => {
  const r = rig();
  await loadedQueue(r, item('A', 'sha256 A'), item('B', 'sha256 B'));
  assert.equal(r.of('detail').length, 1, 'the auto-selected first candidate requests its evidence once');
  assert.equal(r.of('detail')[0].path, '/api/view/gap?id=A&generation=7');
  assert.match(r.inspectorHtml(), /Loading evidence/);
  r.of('detail')[0].resolve(detail('A', [src('A', 'x = s(b"x")'), cbom('A')])); await r.tick();
  const html = r.inspectorHtml();
  assert.match(html, /data-evidence-for="A"/);
  assert.match(html, /Source call site/); assert.match(html, /Selected CBOM/);
  assert.ok(html.indexOf('Source call site') < html.indexOf('Selected CBOM'), 'source and CBOM are separate records, source first');
  assert.match(html, /app\/A\.py:2/); assert.match(html, /x = s\(b&quot;x&quot;\)/);               // verbatim excerpt (only HTML-escaped, never edited)
  assert.match(html, /dddddddddddd…/);                                                          // file digest (short form)
  assert.match(html, /python:hashlib\.sha256/); assert.match(html, /imported name <code>sha256<\/code>/); assert.match(html, /binding unique_module_level/);
  assert.match(html, /absent after complete search/); assert.match(html, /Binding checks/);
  assert.match(html, /cdxgen 12\.9\.0 · CycloneDX 1\.6 · 1 cryptographic asset among 3 components/); assert.match(html, /eeeeeeeeeeee…/); assert.match(html, /cccccccccccc…/);   // CBOM identity, digest, census
  assert.match(html, /What did the comparison establish\?<\/h3><p class="ot-insp-state ot-insp-unknown">[\s\S]*?<span>Cannot establish<\/span>/); assert.match(html, /no_algorithm_record/); assert.match(html, /RATIONALE-A/);
  assert.match(html, /BOUNDED-MEANING/); assert.match(html, /that the code runs/); assert.match(html, /independent verification/);
  assert.match(html, /source <code>sha256<\/code> · CBOM <code>SHA-256<\/code> · finite alias mapping applied/);
  assert.match(html, /1 CBOM record seen but not used/); assert.match(html, /operation context mismatch: the occurrence records hashlib\.md5/);
  assert.equal(r.store.get().bom8.error, null);
});

test('clicking another candidate requests and renders that candidate; a late answer for the first never replaces it', async () => {
  const r = rig();
  await loadedQueue(r, item('A', 'sha256 A'), item('B', 'sha256 B'));
  const a = r.of('detail')[0];
  r.flow.selectBomCandidate('B');
  assert.equal(r.of('detail').length, 2); assert.equal(r.of('detail')[1].path, '/api/view/gap?id=B&generation=7');
  a.resolve(detail('A', [src('A', 'AAA-EXCERPT')])); await r.tick();
  assert.doesNotMatch(r.inspectorHtml(), /AAA-EXCERPT/); assert.equal(r.store.get().bom8.detail, null, 'the stale answer never reached the state');
  assert.match(r.inspectorHtml(), /Loading evidence/);
  r.of('detail')[1].resolve(detail('B', [src('B', 'BBB-EXCERPT')])); await r.tick();
  assert.match(r.inspectorHtml(), /BBB-EXCERPT/); assert.match(r.inspectorHtml(), /data-evidence-for="B"/);
  assert.equal(r.of('detail').length, 2, 'no duplicate request for an already loaded selection');
  // out of order the other way: B was requested last, A is selected again, B arrives late
  r.flow.selectBomCandidate('A');
  r.of('detail')[2].resolve(detail('A', [src('A', 'AAA-AGAIN')])); await r.tick();
  assert.match(r.inspectorHtml(), /AAA-AGAIN/);
});

test('a response bound to another analysis, epoch or generation is rejected', async () => {
  const r = rig();
  await loadedQueue(r, item('A', 'sha256 A'));
  const wrong = detail('A', [src('A', 'OTHER-ANALYSIS')]); wrong.binding = { analysis_digest: 'f'.repeat(64) };
  r.of('detail')[0].resolve(wrong); await r.tick();
  assert.equal(r.store.get().bom8.detail, null); assert.doesNotMatch(r.html(), /OTHER-ANALYSIS/);
  // the session ends while a detail request is in flight: epoch advances, the late answer is discarded
  const r2 = rig(); await loadedQueue(r2, item('A', 'sha256 A'));
  r2.store.dispatch({ type: 'END_STARTED' });
  r2.of('detail')[0].resolve(detail('A', [src('A', 'AFTER-END')])); await r2.tick();
  assert.equal(r2.store.get().bom8.detail, null);
});

test('filter, search or view changes and empty results never keep another candidate\'s detail', async () => {
  const r = rig();
  await loadedQueue(r, item('A', 'sha256 A'));
  r.of('detail')[0].resolve(detail('A', [src('A', 'KEEP-ME-NOT')])); await r.tick();
  assert.match(r.inspectorHtml(), /KEEP-ME-NOT/);
  r.store.dispatch({ type: 'BOM_PATCH', patch: bomContextPatch({ filter: 'represented', offset: 0 }) });      // what a filter click dispatches
  assert.equal(r.store.get().bom8.detail, null); assert.doesNotMatch(r.html(), /KEEP-ME-NOT/);
  r.flow.loadBomQueue();
  r.of('queue')[1].resolve(queue()); await r.tick();                                                      // zero matches
  assert.equal(r.store.get().bom8.selected, null); assert.equal(r.store.get().bom8.detail, null);
  assert.doesNotMatch(r.html(), /KEEP-ME-NOT/); assert.doesNotMatch(r.html(), /data-evidence-for/);
  assert.equal(r.of('detail').length, 1, 'nothing selected, so nothing requested');
  // a different candidate appears after the change: it gets its own request, not A's detail
  r.flow.loadBomQueue(); r.of('queue')[2].resolve(queue(item('C', 'sha256 C'))); await r.tick();
  assert.equal(r.of('detail')[1].path, '/api/view/gap?id=C&generation=7');
  r.of('detail')[1].resolve(detail('A', [src('A', 'WRONG-ID')])); await r.tick();                         // a payload for another candidate is not shown for C
  assert.doesNotMatch(r.html(), /WRONG-ID/);
});

test('failures and an ended session stay visible and do not hide the queue', async () => {
  const r = rig();
  await loadedQueue(r, item('A', 'sha256 A'), item('B', 'sha256 B'));
  r.of('detail')[0].reject(r.err(500, 'Evidence exploded')); await r.tick();
  assert.match(r.inspectorHtml(), /role="alert">The evidence could not be loaded \(Evidence exploded\)/);
  assert.equal(r.store.get().bom8.error, null, 'a detail failure is not a workspace-wide error');
  assert.match(r.html(), /sha256 B/);                                                                       // the queue is still there
  r.flow.selectBomCandidate('B');                                                                           // selecting again retries and clears the message
  assert.doesNotMatch(r.inspectorHtml(), /Evidence exploded/);
  r.of('detail')[1].reject(r.err(409, 'stale')); await r.tick();
  assert.equal(r.store.get().bom8.stale, true); assert.match(r.html(), /belongs to an ended session/); assert.doesNotMatch(r.html(), /data-evidence-for/);
});

test('observation-only candidates are shown honestly: the source record without any CBOM record, and the source text is escaped', async () => {
  const r = rig();
  await loadedQueue(r, item('A', 'sha256 A'));
  r.of('detail')[0].resolve(detail('A', [src('A', '<img src=x onerror=alert(1)>')], { algorithm_alias: undefined, excluded_assets: undefined, bom: null, reason_codes: [], assertion_id: null, rule_id: null })); await r.tick();
  const html = r.inspectorHtml();
  assert.match(html, /Source call site/); assert.doesNotMatch(html, /Selected CBOM/); assert.match(html, /BOM checked:<\/strong> none/);
  assert.match(html, /&lt;img src=x onerror=alert\(1\)&gt;/); assert.doesNotMatch(html, /<img src=x/);
  assert.doesNotMatch(html, /Algorithm spelling/); assert.doesNotMatch(html, /seen but not used/);
});

test('choosing a related check requests the evidence of exactly that check', async () => {
  const r = rig();
  await loadedQueue(r, item('A', 'sha256 A'));
  r.of('detail')[0].resolve(detail('A', [src('A', 'AAA')])); await r.tick();
  r.store.dispatch({ type: 'BOM_PATCH', patch: { related: { items: [{ item_id: 'R', display_name: 'related R', family: 'cryptography', state: 'unverifiable', assertion_id: 'as-R' }] } } });
  r.flow.chooseBomRelated('R');
  assert.equal(r.store.get().bom8.selected, 'R'); assert.equal(r.store.get().bom8.detail, null);
  const d = r.of('detail'); assert.equal(d[d.length - 1].path, '/api/view/gap?id=R&generation=7');
});

test('the legacy inspector keeps rendering the same records and now also the alias and excluded-record disclosure', () => {
  const c = detail('A', [src('A', 'legacy')]).candidate;
  const html = inspector({ ...initial(), gaps: { selected: 'A', detail: c }, advanced: false });
  assert.match(html, /Source call site/); assert.match(html, /RATIONALE-A/); assert.match(html, /finite alias mapping applied/);
  const plain = inspector({ ...initial(), gaps: { selected: 'R', detail: { candidate_id: 'R', state: 'contradicted', state_label: 'Not represented', category_label: 'Missing component', title: 't', records: [], not_established: [] } } });
  assert.doesNotMatch(plain, /Algorithm spelling/); assert.match(plain, /No separate evidence record/);
});
