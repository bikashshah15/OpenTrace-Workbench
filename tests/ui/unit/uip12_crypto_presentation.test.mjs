// UIP-12: the narrow BOM-connections presentation of the cryptography family (pure renderer tests, no browser, no server).
// The source observation and the CBOM record stay separate records in the inspector; partial cryptography coverage has its own disclosure.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createStore, initial } from '../../../src/ui/lib/store.js';
import { bomDetailsHtml, renderBomWorkspace, inspector } from '../../../src/ui/components/gaps.js';

const identity = { analysis_digest: 'a'.repeat(64), owner: 'review', name: 'fixture', commit: 'b'.repeat(40) };
const cand = { item_id: 'cand:1', assertion_id: null, display: { name: 'sha256 call', raw_title: 'sha256 call' }, state: 'unknown_coverage', category: 'unknown_coverage', graph_state: 'evidence_only', family: 'cryptography' };
const caps = (sw, cr) => [{ family: 'software', state: sw[0], reason_code: sw[1] }, { family: 'cryptography', state: cr[0], reason_code: cr[1] },
  ...['ai_model', 'other'].map((family) => ({ family, state: 'not_run', reason_code: 'not_configured' }))];
const render = (capabilities) => {
  const s = createStore({ ...initial(), epoch: 3, analysis: { generation: 7, identity }, workbench: { ...initial().workbench, tab: 'bom' } });
  s.dispatch({ type: 'BOM_PATCH', patch: { view: 'crypto', queue: { mode: 'discovery_compared', counts: { candidates_total: 1, filtered_total: 1, records_total: 0 }, items: [cand], capabilities, page: { offset: 0, size: 25, has_more: false }, filters: {} }, graph: null } });
  const html = renderBomWorkspace(s.get());
  assert.doesNotMatch(html, /data-coverage="partial"|Bound inventory and rule evidence/);   // folded into the evidence strip's Details
  return html + bomDetailsHtml(s.get());
};

test('partial cryptography coverage is disclosed with its own wording, never the requirement wording', () => {
  const html = render(caps(['completed', null], ['partial', 'partial_coverage']));
  assert.match(html, /data-family="cryptography"/);
  assert.match(html, /no cryptography is used/);
  assert.doesNotMatch(html, /Requirement files were compared with the SBOM/);
});

test('partial software coverage keeps the original disclosure; both may apply', () => {
  assert.match(render(caps(['partial', 'partial_coverage'], ['completed', null])), /Requirement files were compared with the SBOM/);
  const both = render(caps(['partial', 'partial_coverage'], ['partial', 'partial_coverage']));
  assert.match(both, /Requirement files were compared/);
  assert.match(both, /data-family="cryptography"/);
});

test('completed cryptography carries no partial disclosure', () => {
  assert.doesNotMatch(render(caps(['completed', null], ['completed', null])), /data-coverage/);
});

const detail = (records) => ({ candidate_id: 'cand:1', state: 'unverifiable', state_label: 'Could not be confirmed', category_label: 'Unknown coverage', title: 'sha256 call at app/m.py:4: compared with inv:x',
  rationale: 'Unverifiable: no record', bom: { label: 'cdxgen 12.9.0', inventory_id: 'inv:x', sha256: 'c'.repeat(64) }, trigger: 't', records, not_established: ['independent verification'], bounded_meaning: 'Declaration-level only.',
  identity_basis: 'finite mapping', next_action: 'n', assertion_id: 'a1', rule_id: 'crypto_attribution.operation_declared_in_cbom/4', reason_codes: ['no_algorithm_record'] });
const inspect = (d) => inspector({ ...initial(), gaps: { selected: 'cand:1', detail: d }, advanced: false });

test('the inspector shows the source observation and the CBOM record as two separate records with limits', () => {
  const html = inspect(detail([
    { evidence_id: 'e1', kind: 'source_excerpt', role: 'source_reference', method: 'python-ast', origin: 'captured', source: { file: 'app/m.py', file_sha256: 'd'.repeat(64), lines: [4, 4] },
      excerpt: 'hashlib.sha256(x).hexdigest()', excerpt_truncated: false, operation: 'hash', resolution: { call: 'python:hashlib.sha256', binding_status: 'unique_module_level', local_module_named_hashlib: 'absent_after_complete_search' }, checks: { audit_complete: true, excerpt_complete: false } },
    { evidence_id: 'e2', kind: 'cbom_document', role: 'cbom_document', method: 'cyclonedx', origin: 'captured', document: { spec_version: '1.6', raw_sha256: 'e'.repeat(64) }, status: 'ok', producer: [{ name: 'cdxgen', version: '12.9.0' }],
      census: { components: 0, assets: 0 }, reason: 'the document has 0 cryptographic assets' }]));
  assert.match(html, /Source call site/);
  assert.match(html, /Selected CBOM/);
  assert.match(html, /app\/m\.py:4/);
  assert.match(html, /hashlib\.sha256\(x\)\.hexdigest\(\)/);
  assert.match(html, /statically observed, not executed/);
  assert.match(html, /absent after complete search/);
  assert.match(html, /0 cryptographic assets/);
  assert.match(html, /independent verification/);
  assert.ok(html.indexOf('Source call site') < html.indexOf('Selected CBOM'));
  assert.equal((html.match(/data-record=/g) || []).length, 2);
});

test('a truncated excerpt is marked and the excerpt is escaped, not interpreted', () => {
  const html = inspect(detail([{ evidence_id: 'e1', kind: 'source_excerpt', role: 'source_reference', source: { file: 'a.py', file_sha256: 'd'.repeat(64), lines: [1, 1] }, excerpt: '<img src=x onerror=1>', excerpt_truncated: true, resolution: {}, checks: {} }]));
  assert.match(html, /&lt;img src=x onerror=1&gt;/);
  assert.doesNotMatch(html, /<img src=x/);
  assert.match(html, /\(cut\)/);
});
