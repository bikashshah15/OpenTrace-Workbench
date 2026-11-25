// BOM connections: long coverage text folds into the evidence strip's collapsed Details; the candidate's detailed evidence folds into "Show all evidence (N)".
import test from 'node:test';
import assert from 'node:assert/strict';
import { createStore, initial, bomContextPatch } from '../../../src/ui/lib/store.js';
import { createBomFlow } from '../../../src/ui/lib/bom_flow.js';
import { renderBomWorkspace, bomDetailsHtml } from '../../../src/ui/components/gaps.js';

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
import { renderEvidenceStrip, resetEvidenceDetails } from '../../../src/ui/components/evidence_strip.js';
import { renderInspector } from '../../../src/ui/components/inspector.js';

async function loaded(r, caps) {
  r.flow.switchBomView('crypto');
  const q = queue(item('A', 'sha256 A')); if (caps) q.capabilities = caps;
  r.of('queue')[0].resolve(q); await r.tick();
}
const strip = (r) => renderEvidenceStrip({ ...r.store.get(), analysis: { ...r.store.get().analysis, summary: {} } }, 'bom', { detailsHtml: bomDetailsHtml(r.store.get()) });
const partialCaps = ['software', 'cryptography', 'ai_model'].map((family) => ({ family, state: 'partial', reason_code: 'partial_coverage' }));

test('coverage text lives in the collapsed Details, not in the workspace', async () => {
  resetEvidenceDetails();
  const r = rig(); await loaded(r, partialCaps);
  const ws = r.html();
  for (const re of [/Bound inventory and rule evidence/, /Partial coverage/, /data-coverage="partial"/]) assert.doesNotMatch(ws, re);
  const s = strip(r);
  const m = s.match(/<details class="otev-details"( open)?>([\s\S]*?)<\/details>/);
  assert.ok(m, 'Details disclosure exists'); assert.equal(m[1], undefined, 'starts collapsed');
  for (const re of [/Bound inventory and rule evidence for review\/fixture/, /Partial coverage\.<\/strong> Requirement files/, /Partial coverage \(cryptography\)/, /Partial coverage \(AI models\)/]) assert.match(m[2], re);
  assert.match(s, /Inventory availability does not establish comparison completion or success\./);        // the short line stays visible
  assert.doesNotMatch(s.replace(m[0], ''), /Partial coverage|Bound inventory/);
});
test('loading, error and not-compared states stay in the workspace', async () => {
  const r = rig(); r.flow.switchBomView('crypto'); assert.match(r.html(), /Loading bound BOM assessment/);
});
test('candidate detail folds into "Show all evidence (N)"; preview, answers and related navigation stay visible', async () => {
  const r = rig(); await loaded(r);
  r.of('detail')[0].resolve(detail('A', [src('A', 'x = s(b"x")'), cbom('A')])); await r.tick();
  const h = r.inspectorHtml();
  const m = h.match(/<details class="ot-insp-allev">\s*<summary>Show all evidence \((\d+)\)<\/summary>([\s\S]*?)<\/details>\s*(?:<div class="ot-insp-extra"|<\/section>)/);
  assert.ok(m, 'disclosure present and collapsed (no open attribute)');
  assert.equal(Number(m[1]), (h.match(/<dt>/g) || []).length, 'N is the actual row count');
  for (const re of [/BOM checked:/, /Source call site/, /Selected CBOM/, /cccccccccccc…/, /dddddddddddd…/, /algorithm spelling/i, /seen but not used/]) assert.match(m[2], re);
  const outside = h.replace(m[0], '');
  for (const re of [/BOM checked:/, /Source call site/, /Selected CBOM/]) assert.doesNotMatch(outside, re);
  assert.match(outside, /data-question="what_is_this"/); assert.match(outside, /Source location/);   // preview rows + answers stay
});
test('loading and failed evidence stay visible outside the disclosure', async () => {
  const r = rig(); await loaded(r);
  const h = r.inspectorHtml(); assert.match(h, /Loading evidence/); assert.doesNotMatch(h, /BOM checked:/);
  r.of('detail')[0].reject(r.err(500, 'boom')); await r.tick();
  assert.match(r.inspectorHtml(), /role="alert">The evidence could not be loaded/);
});
test('the shared inspector is unchanged without evidenceDetail', () => {
  const model = { origin: 'x', id: 'i', type: 't', title: 'T', badge: { kind: 'neutral', label: 'b' }, question_set: 'q', answers: [], evidence_rows: [{ label: 'a', state: 'captured', text: 'b' }], sources: [] };
  assert.doesNotMatch(renderInspector(model), /Show all evidence/);
  assert.match(renderInspector(model, { evidenceDetail: '<p>D</p>' }), /Show all evidence \(1\)<\/summary><div class="ot-insp-allev-detail"><p>D<\/p>/);
});
