// I8: how the Workbench shows Candidate gaps — compared, not compared, unknown coverage — and that a failed comparison is never drawn as "no gaps".
// Pure string renderers and a pure reducer: no browser or network. Run: node --test tests/ui/unit/
import test from 'node:test';
import assert from 'node:assert/strict';
import { createStore, initial } from '../../../src/ui/lib/store.js';
import { section, inspector, gapsEnabled, renderBomWorkspace } from '../../../src/ui/components/gaps.js';
import { bomKey } from '../../../src/ui/lib/store.js';

const TFLITE = { candidate_id: 'cand:missing_component:88eb4e77', category: 'missing_component', category_label: 'Missing component', state: 'contradicted', state_label: 'Not represented in the BOM',
  title: 'tflite_runtime (direct_url) declared at docker/main/requirements-wheels.txt:75,76 has no record in inv:syft-source-dir', location: 'docker/main/requirements-wheels.txt:75,76',
  bom: { inventory_id: 'inv:syft-source-dir', label: 'syft 1.51.1', kind: 'sbom', sha256: '8ee39ed7f937158ecc782d5839608079f1750dc9855212c54035b596e03513e7' }, rule_id: 'inventory_coverage.requirement_represented/1', assertion_id: 'p5' };
const UNKNOWN = { candidate_id: 'cand:unknown_coverage:350d0726', category: 'unknown_coverage', category_label: 'Unknown coverage', state: 'unknown_coverage', state_label: 'Coverage unknown: not compared',
  title: '4 declaration(s) in docker/main/requirements-wheels.txt carry environment markers; no target environment was recorded', location: 'docker/main/requirements-wheels.txt:16', bom: null, rule_id: null, assertion_id: null };
const totals = { candidates: 79, by_category: { missing_component: 69, unknown_coverage: 10 }, by_state: { contradicted: 69, unknown_coverage: 4, unverifiable: 6 } };
const page = (items, over) => ({ status: 'compared', totals, items, filtered_total: items.length, offset: 0, limit: 25, has_more: false, ...over });
const st = (gaps, summary, extra) => ({ analysis: { summary: { gaps: summary } }, gaps: { state: null, q: '', offset: 0, data: null, error: null, selected: null, detail: null, detailError: null, ...gaps }, advanced: false, ...extra });
const ok = { status: 'compared', totals };

test('a live analysis has no Candidate gaps section', () => {
  assert.equal(gapsEnabled({ analysis: { summary: {} } }), false);
  assert.equal(section({ analysis: { summary: {} }, gaps: {} }), '');
});

test('compared: candidate, BOM checked, verdict and an Inspect evidence action; unknown coverage is stated, not a verdict', () => {
  const html = section(st({ data: page([TFLITE, UNKNOWN]) }, ok));
  assert.match(html, /Candidate gaps/);
  assert.match(html, /tflite_runtime \(direct_url\)/);
  assert.match(html, /BOM checked: <strong>syft 1\.51\.1<\/strong>/);
  assert.match(html, /Not represented in the BOM/);
  assert.match(html, /Coverage unknown: not compared/);
  assert.match(html, /BOM checked: none \(nothing was compared\)/);
  assert.equal((html.match(/data-action="gap-inspect"/g) || []).length, 2);
  assert.match(html, /data-id="cand:missing_component:88eb4e77"/);
  assert.match(html, /not vulnerabilities/);
  assert.match(html, /Only requirement declarations are compared/);
  assert.match(html, /Coverage unknown <b>4<\/b>/);
});

test('not compared is labeled with its reason and never shown as "no gaps"', () => {
  const html = section(st({}, { status: 'not_compared', code: 'declarations_digest_mismatch', message: 'The captured source declarations do not match their pinned digest, so nothing was compared.' }));
  assert.match(html, /Not compared\./);
  assert.match(html, /pinned digest/);
  assert.match(html, /not a “no gaps” result/);
  assert.doesNotMatch(html, /data-action="gap-inspect"/);
  assert.doesNotMatch(html, /No candidate matches/);
});

test('inspector shows the source requirement and the selected SBOM lookup for the tflite_runtime gap', () => {
  const detail = { ...TFLITE, trigger: 'inv:syft-source-dir lists docker/main/requirements-wheels.txt with the same SHA-256 and has no component named tflite-runtime among 1976 library components',
    rationale: 'Contradicted: the declared requirement has no component of that name in the fully parsed inventory.', coverage_contract: { established: false }, reason_codes: ['not_represented_in_fully_parsed_inventory'],
    records: [{ evidence_id: 'ev14', role: 'declaration', kind: 'requirement_declaration', method: 'requirements-line-parse', origin: 'captured', source: { file: 'docker/main/requirements-wheels.txt', file_sha256: '7c60b79abb0dade8f167e21ab3af4a442d601a27f7370838e6317f452495bd20' },
      declarations: [{ line: 75, form: 'direct_url', text: "tflite_runtime @ https://example.invalid/tflite_runtime-2.17.1-cp311-cp311-linux_x86_64.whl; platform_machine == 'x86_64'" }] },
    { evidence_id: 'ev09', role: 'inventory_lookup', kind: 'inventory_name_lookup', method: 'cyclonedx-exact-name-lookup', origin: 'captured', inventory: { generator: 'syft 1.51.1', raw_sha256: TFLITE.bom.sha256 },
      query: { normalized_name: 'tflite-runtime', ecosystem: 'pypi', match: 'exact normalized name; no substring matching' }, matches: 0, parse: { complete: true, library_components: 1976 }, scanned_file: { path: 'docker/main/requirements-wheels.txt', file_records: 1, recorded_sha256: ['7c60b79abb0dade8f167e21ab3af4a442d601a27f7370838e6317f452495bd20'] } }] };
  const html = inspector(st({ selected: TFLITE.candidate_id, detail }, ok));
  assert.match(html, /Source requirement/);
  assert.match(html, /docker\/main\/requirements-wheels\.txt:75/);
  assert.match(html, /tflite_runtime @ https/);
  assert.match(html, /Selected inventory lookup/);
  assert.match(html, /<strong>0 matching components<\/strong> among 1,?976 library components/);
  assert.match(html, /lists <code>docker\/main\/requirements-wheels\.txt<\/code>/);
  assert.match(html, /No coverage contract is established/);
  assert.equal(inspector(st({}, ok)), null);   // nothing selected: the existing record inspector stays
});

test('inspector never shows a stale candidate while another loads, and a failed load is an alert', () => {
  const loading = inspector(st({ selected: 'cand:b', detail: { ...TFLITE, records: [] } }, ok));
  assert.match(loading, /Loading evidence/);
  assert.match(inspector(st({ selected: 'cand:b', detailError: 'not_found' }, ok)), /role="alert"/);
});

test('reducer: stale epoch, generation or request never reaches candidate-gap state; End session clears it', () => {
  const store = createStore({ ...initial(), epoch: 2, analysis: { generation: 3, summary: { gaps: ok } }, gaps: { ...initial().gaps, seq: 5, detailSeq: 7 } });
  store.dispatch({ type: 'GAPS_LOADED', epoch: 1, generation: 3, seq: 5, data: page([TFLITE]) });
  store.dispatch({ type: 'GAPS_LOADED', epoch: 2, generation: 2, seq: 5, data: page([TFLITE]) });
  store.dispatch({ type: 'GAPS_LOADED', epoch: 2, generation: 3, seq: 4, data: page([TFLITE]) });
  assert.equal(store.get().gaps.data, null);
  store.dispatch({ type: 'GAPS_LOADED', epoch: 2, generation: 3, seq: 5, data: page([TFLITE]) });
  assert.equal(store.get().gaps.data.items.length, 1);
  store.dispatch({ type: 'GAP_DETAIL_LOADED', epoch: 2, generation: 3, seq: 6, data: { candidate: TFLITE } });
  assert.equal(store.get().gaps.detail, null);
  store.dispatch({ type: 'GAP_DETAIL_LOADED', epoch: 2, generation: 3, seq: 7, data: { candidate: TFLITE } });
  assert.equal(store.get().gaps.detail.candidate_id, TFLITE.candidate_id);
  store.dispatch({ type: 'ENDED', state: 'deleted_verified' });
  assert.equal(store.get().gaps.data, null);
  assert.equal(store.get().gaps.detail, null);
  assert.equal(store.get().gaps.selected, null);
});

test('UIP-08 five views use bounded payloads and render the recorded scan-root ID inert', () => {
  const id = 'entity:scope:x_y_<scan-root>/frigate/a.py_50';
  const candidate = { item_id: 'cand:a', display: { name: '<img src=x>', raw_title: '<img src=x>' }, state: 'contradicted', category: 'missing_component', family: 'software', graph_state: 'assertion_graph', location: { path: 'requirements.txt' }, inventory: { generator: 'Syft', inventory_id: 'inv:one' }, rule_id: 'rule:one' };
  const queue = { mode: 'discovery_compared', items: [candidate], counts: { candidates_total: 1, assertions_unique: 1, filtered_total: 1, records_total: 2, relationships_total: 1, filter_group_counts: { not_represented: 1 }, family_counts: { software: 1 } }, page: { offset: 0, has_more: false }, capabilities: [{ family: 'software', state: 'completed' }] };
  const graph = { scope: { kind: 'focused_candidate', candidate_id: 'cand:a' }, graph_state: 'assertion_graph', nodes: [{ node_id: id, full_label: '<svg onload=alert(1)>', kind: 'entity', role: 'primary' }], edges: [], counts: { nodes_shown: 1, nodes_in_scope: 1, edges_shown: 0, edges_in_scope: 0 } };
  const s = { analysis: { identity: { owner: 'o', name: 'r', commit: 'a'.repeat(40) } }, bom8: { ...initial().bom8, queue, graph, selected: 'cand:a' } };
  const html = renderBomWorkspace(s);
  for (const label of ['Software · SBOM', 'Cryptography · CBOM', 'AI models · AI-BOM', 'Full evidence graph', 'Focused gaps']) assert.ok(html.includes(label));
  assert.match(html, /&lt;img src=x&gt;/);
  assert.match(html, /&lt;scan-root&gt;/);
  assert.match(html, /&lt;svg onload=alert\(1\)&gt;/);
  assert.doesNotMatch(html, /<img src=x>|<svg onload/);
  assert.match(html, /What did the comparison establish\?/);
  const full = renderBomWorkspace({ ...s, bom8: { ...s.bom8, view: 'full', group: 'all', graph: { ...graph, scope: { kind: 'full_view' } } } });
  assert.match(full, /All recorded evidence/);
  assert.match(full, /Find recorded nodes/);
});

test('UIP-08 request stamps reject old selection and End retires BOM payloads immediately', () => {
  const identity = { analysis_digest: 'a'.repeat(64) };
  const store = createStore({ ...initial(), epoch: 3, analysis: { generation: 7, identity }, workbench: { ...initial().workbench, tab: 'bom' } });
  const first = { kind: 'related', epoch: 3, generation: 7, seq: 1, key: bomKey(store.get().bom8, 'related') };
  store.dispatch({ type: 'BOM_PATCH', patch: { selectedRecord: 'entity:a' } });
  const current = { ...first, key: bomKey(store.get().bom8, 'related') };
  store.dispatch({ type: 'BOM_REQUEST', ...current });
  store.dispatch({ type: 'BOM_PATCH', patch: { selectedRecord: 'entity:b' } });
  store.dispatch({ type: 'BOM_LOADED', ...current, data: { binding: { analysis_digest: identity.analysis_digest }, subject: { id: 'entity:a' } } });
  assert.equal(store.get().bom8.related, null);
  store.dispatch({ type: 'BOM_REQUEST', ...first, seq: 2, key: bomKey(store.get().bom8, 'related') });
  store.dispatch({ type: 'END_STARTED' });
  assert.equal(store.get().bom8.selectedRecord, null);
  assert.equal(store.get().bom8.related, null);
  assert.equal(store.get().bom8.queue, null);
});
