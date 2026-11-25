// UIP-13: the narrow BOM-connections presentation of the model family (pure renderer tests, no browser, no server).
// The source occurrence and the AI-BOM record stay separate records; the AI-BOM identity and scan scope are shown only when one was selected.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createStore, initial } from '../../../src/ui/lib/store.js';
import { bomDetailsHtml, renderBomWorkspace, inspector, section } from '../../../src/ui/components/gaps.js';

const totals = { candidates: 1, by_category: { unknown_coverage: 1 }, by_state: { unknown_coverage: 1 } };
const renderGapsList = (over) => section({ analysis: { summary: { gaps: { status: 'compared', totals } } },
  gaps: { state: null, q: '', offset: 0, data: { status: 'compared', totals, items: [], filtered_total: 0, offset: 0, limit: 25, has_more: false, ...over }, error: null, selected: null, detail: null, detailError: null } });
const identity = { analysis_digest: 'a'.repeat(64), owner: 'review', name: 'fixture', commit: 'b'.repeat(40) };
const cand = { item_id: 'cand:m1', assertion_id: null, display: { name: 'det.onnx referenced', raw_title: 'det.onnx referenced' }, state: 'unknown_coverage', category: 'unknown_coverage', graph_state: 'evidence_only',
  family: 'ai_model', filter_group: 'unknown', location: { path: 'app/m.py', line_start: 1, line_end: 1 }, inventory: null, rule_id: null, canonical_ref: {} };
const caps = (ai) => [{ family: 'software', state: 'completed', reason_code: null }, { family: 'cryptography', state: 'completed', reason_code: null },
  { family: 'ai_model', state: ai[0], reason_code: ai[1] }, { family: 'other', state: 'not_run', reason_code: 'not_configured' }];
const render = (capabilities, view = 'ai') => {
  const s = createStore({ ...initial(), epoch: 3, analysis: { generation: 7, identity }, workbench: { ...initial().workbench, tab: 'bom' } });
  s.dispatch({ type: 'BOM_PATCH', patch: { view, queue: { mode: 'discovery_compared', counts: { candidates_total: 1, filtered_total: 1, records_total: 0, family_counts: { ai_model: 1 } }, items: [cand], capabilities, page: { offset: 0, size: 25, has_more: false }, filters: {} } } });
  const html = renderBomWorkspace(s.get());
  assert.doesNotMatch(html, /data-coverage="partial"|Bound inventory and rule evidence/);   // folded into the evidence strip's Details
  return html + bomDetailsHtml(s.get());
};

test('partial model coverage has its own wording and never the requirement or cryptography wording', () => {
  const html = render(caps(['partial', 'partial_coverage']));
  assert.match(html, /data-family="ai_model"/);
  assert.match(html, /no model is used/);
  assert.doesNotMatch(html, /Requirement files were compared with the SBOM/);
  assert.doesNotMatch(html, /data-family="cryptography"/);
});

test('not run, failed and unsupported model comparisons are stated in the AI view and keep collection coverage separate', () => {
  for (const state of ['not_run', 'failed', 'unsupported']) {
    const html = render(caps([state, state === 'not_run' ? 'not_configured' : 'output_invalid']));
    assert.match(html, new RegExp(`data-availability="${state}"`));
    assert.match(html, /Collection coverage is separate/);
  }
  assert.doesNotMatch(render(caps(['completed', null])), /data-availability/);
});

test('the model family wording is not shown in another family view', () => {
  assert.doesNotMatch(render(caps(['not_run', 'not_configured']), 'software'), /data-availability/);
});

const detail = (records, extra = {}) => ({ candidate_id: 'cand:m1', state: 'supported', state_label: 'Declared in the AI-BOM (declaration level)', category_label: 'Unknown coverage', title: 'det.onnx referenced', rationale: 'Supported (declaration level)',
  bom: { label: 'cisco-aibom 1.10.1', inventory_id: 'inv:cisco-aibom', sha256: 'c'.repeat(64) }, trigger: 't', records, not_established: ['model acquisition, loading or execution'], bounded_meaning: 'Declaration-level agreement only',
  identity_basis: 'exact acquisition locator', next_action: 'n', assertion_id: 'a1', rule_id: 'model_identity.declared_in_aibom/1', reason_codes: ['locator_equal_unique'], ...extra });
const inspect = (d) => inspector({ ...initial(), gaps: { selected: 'cand:m1', detail: d }, advanced: false });
const src = (role = 'source_reference', extra = {}) => ({ evidence_id: 'e1', kind: 'source_excerpt', reference_kind: 'model_reference', role, method: 'model-reference-python-ast-string-constant', origin: 'captured',
  source: { file: 'app/m.py', file_sha256: 'd'.repeat(64), lines: [1, 1] }, excerpt: 'M = "https://h/m.onnx?x=1"', excerpt_truncated: false,
  model_reference: { locator: 'https://h/m.onnx?x=1', method: 'python-ast-string-constant', source_kind: 'python', gate: null }, ...extra });
const doc = { evidence_id: 'e2', kind: 'aibom_document', role: 'aibom_document', method: 'cyclonedx-1.6-intake', origin: 'captured', document: { spec_version: '1.6', raw_sha256: 'e'.repeat(64) }, status: 'ok',
  producer: [{ name: 'cisco-aibom', version: '1.10.1' }], binding: { level: 'recorded', revision: 'b'.repeat(40), conflicts: [] }, census: { models: 1, components: 1 } };

test('the inspector shows the source occurrence and the AI-BOM as separate records with identity, scope and limits', () => {
  const html = inspect(detail([src(), doc], { aibom: { inventory_id: 'inv:cisco-aibom', completeness: 'verified', scan_scope: { revision: 'b'.repeat(40), file_count: 2, listing_sha256: 'c'.repeat(64), paths: ['.'] },
    limits: ['the scope states what was intended and prepared for the producer, not that it examined every file or reference'] },
    model_detail: { occurrences_total: 2, occurrences_in_scope: 2, occurrences_not_compared: 0, occurrences_cited: 2, reason_code: null },
    matching_models: [{ name: 'det', bom_ref: 'r', match: 'locator_equal', has_hash: false, locators: ['https://h/m.onnx?x=1'] }], matching_models_total: 1 }));
  assert.match(html, /Model reference in source/);
  assert.match(html, /Selected AI-BOM/);
  assert.match(html, /app\/m\.py:1/);
  assert.match(html, /not downloaded or executed/);
  assert.match(html, /Locator \(exact, query and fragment included\)/);
  assert.match(html, /Acquisition binding: recorded/);
  assert.match(html, /AI-BOM scan scope \(as recorded\)/);
  assert.match(html, /not that it examined every file or reference/);
  assert.match(html, /declares no hash/);
  assert.match(html, /Declared in the AI-BOM \(declaration level\)/i);
  assert.ok(html.indexOf('Model reference in source') < html.indexOf('Selected AI-BOM'));
});

test('with no AI-BOM nothing is fabricated: no AI-BOM record and no scope are rendered', () => {
  const html = inspect(detail([src('cited', { reason_code: 'aibom_not_run' })], { state: 'unknown_coverage', state_label: 'Coverage unknown: not compared', bom: null, rule_id: null, assertion_id: null,
    model_detail: { occurrences_total: 1, occurrences_in_scope: 0, occurrences_not_compared: 1, occurrences_cited: 1, reason_code: 'aibom_not_run' } }));
  assert.doesNotMatch(html, /Selected AI-BOM/);
  assert.doesNotMatch(html, /AI-BOM scan scope/);
  assert.match(html, /Cited, not compared: aibom not run/);
  assert.match(html, /reason: <code>aibom_not_run<\/code>/);
});

test('excerpts, locators and AI-BOM text are escaped, not interpreted', () => {
  const html = inspect(detail([src('source_reference', { excerpt: '<img src=x onerror=1>', model_reference: { locator: '<b>x</b>', source_kind: 'shell', method: 'line-url-token' } }),
    { ...doc, producer: [{ name: '<i>p</i>', version: '1' }], binding: { level: 'recorded', conflicts: ['<script>x</script>'] } }]));
  assert.doesNotMatch(html, /<img src=x/);
  assert.doesNotMatch(html, /<script>x/);
  assert.doesNotMatch(html, /<b>x<\/b>/);
  assert.match(html, /&lt;img src=x onerror=1&gt;/);
});

test('crypto call sites keep their own rendering', () => {
  const html = inspect(detail([{ evidence_id: 'e1', kind: 'source_excerpt', reference_kind: 'call_site', role: 'source_reference', source: { file: 'a.py', file_sha256: 'd'.repeat(64), lines: [1, 1] }, excerpt: 'hashlib.sha256(x)', operation: 'hash', resolution: {}, checks: {} }]));
  assert.match(html, /Source call site/);
  assert.doesNotMatch(html, /Model reference in source/);
});

test('the list help text names every family that was compared (both crypto and models)', () => {
  const html = renderGapsList({ ported_scope: ['requirement_declarations_vs_sbom', 'python_hashlib_call_sites_vs_cbom', 'model_references_vs_aibom'] });
  assert.match(html, /hashlib/);
  assert.match(html, /static model references/);
  assert.doesNotMatch(html, /models and dependency edges are not/);
  assert.match(renderGapsList({ ported_scope: ['python_hashlib_call_sites_vs_cbom'] }), /models and dependency edges are not/);
  assert.match(renderGapsList({ ported_scope: [] }), /Only requirement declarations are compared/);
});

test('collection facts are shown in the AI view for not run, with lower bounds and dynamic expressions', () => {
  const s = createStore({ ...initial(), epoch: 3, analysis: { generation: 7, identity, summary: { gaps: { collection: { models: { coverage: { references: { observed: 3 }, processed: 4, selected: 5, count_kind: 'at_least', complete: false, dynamic: { count: 2 } } } } } } },
    workbench: { ...initial().workbench, tab: 'bom' } });
  s.dispatch({ type: 'BOM_PATCH', patch: { view: 'ai', queue: { mode: 'discovery_compared', counts: { candidates_total: 1, filtered_total: 1, records_total: 0, family_counts: { ai_model: 1 } }, items: [cand], capabilities: caps(['not_run', 'not_configured']), page: { offset: 0, size: 25, has_more: false }, filters: {} } } });
  const html = renderBomWorkspace(s.get());
  assert.match(html, /data-collection-facts/);
  assert.match(html, /3 references observed \(at least; the search was incomplete\) in 4 of 5 selected/);
  assert.match(html, /2 dynamic expressions not resolved/);
  assert.match(html, /collection incomplete/);
  assert.match(html, /nothing was compared with an AI-BOM because none was produced/);
});

test('an unsupported model state with no observed reference does not claim observations', () => {
  const s = createStore({ ...initial(), epoch: 3, analysis: { generation: 7, identity, summary: { gaps: { collection: { models: { coverage: { references: { observed: 0 }, processed: 0, selected: 0, complete: true, dynamic: { count: 0 } } } } } } },
    workbench: { ...initial().workbench, tab: 'bom' } });
  s.dispatch({ type: 'BOM_PATCH', patch: { view: 'ai', queue: { mode: 'discovery_compared', counts: { candidates_total: 0, filtered_total: 0, records_total: 0, family_counts: {} }, items: [], capabilities: caps(['unsupported', 'unsupported_ecosystem']), page: { offset: 0, size: 25, has_more: false }, filters: {} } } });
  const html = renderBomWorkspace(s.get());
  assert.match(html, /No static model reference was observed/);
  assert.doesNotMatch(html, /references that were observed/);
});

test('a missing scan-scope file count is not rendered as NaN', () => {
  const html = inspect(detail([src(), doc], { aibom: { inventory_id: 'i', scan_scope: { revision: 'b'.repeat(40), file_count: null, listing_sha256: 'c'.repeat(64), paths: ['.'] }, limits: [] }, model_detail: { occurrences_total: 1 } }));
  assert.doesNotMatch(html, /NaN/);
  assert.match(html, /file count not recorded/);
});

test('the ACTIVE BOM workspace inspector (not the legacy one) shows candidate -> source -> AI-BOM -> conclusion for the selected candidate only', () => {
  const s = createStore({ ...initial(), epoch: 3, analysis: { generation: 7, identity }, workbench: { ...initial().workbench, tab: 'bom' } });
  const d = detail([src(), doc], { aibom: { inventory_id: 'inv:cisco-aibom', scan_scope: { revision: 'b'.repeat(40), file_count: 2, listing_sha256: 'c'.repeat(64), paths: ['.'] }, limits: ['the scope states what was intended'] }, model_detail: { occurrences_total: 1 } });
  s.dispatch({ type: 'BOM_PATCH', patch: { view: 'ai', selected: 'cand:m1', detail: { candidate: d },
    queue: { mode: 'discovery_compared', counts: { candidates_total: 1, filtered_total: 1, records_total: 0, family_counts: { ai_model: 1 } }, items: [{ ...cand, item_id: 'cand:m1' }], capabilities: caps(['completed', null]), page: { offset: 0, size: 25, has_more: false }, filters: {} } } });
  const html = renderBomWorkspace(s.get());
  assert.match(html, /data-evidence-for="cand:m1"/);
  assert.ok(html.indexOf('Model reference in source') < html.indexOf('Selected AI-BOM') && html.indexOf('Selected AI-BOM') < html.indexOf('Sources &amp; coverage'));
  assert.match(html, /What did the comparison establish\?/);
  s.dispatch({ type: 'BOM_PATCH', patch: { detail: { candidate: { ...d, candidate_id: 'cand:other' } } } });
  assert.doesNotMatch(renderBomWorkspace(s.get()), /Selected AI-BOM/);
});

import { liveBarText } from '../../../src/ui/lib/copy.js';
test('the live-scan banner no longer says there is no AI-BOM when one was produced (R3-03), and is unchanged otherwise', () => {
  const none = liveBarText({ cards: [{ kind: 'sbom' }], advisory_lookup: null });
  assert.equal(none, 'Live scan of one resolved commit. Syft and cdxgen ran in a no-network sandbox; no advisory matching or AI-BOM was run.');
  const withAi = liveBarText({ cards: [{ kind: 'sbom' }, { kind: 'aibom' }], advisory_lookup: null });
  assert.doesNotMatch(withAi, /AI-BOM was run|inventory checks/);
  assert.match(withAi, /AI-BOM was produced separately by Cisco AI-BOM/);
  assert.match(liveBarText({ cards: [], advisory_lookup: {} }), /looked up in OSV\. No AI-BOM\./);
  assert.match(liveBarText({ cards: [{ kind: 'aibom' }], advisory_lookup: {}, inventory_checks: 1 }), /looked up in OSV\. One source-backed CBOM check was assessed\./);
  assert.doesNotMatch(liveBarText({ cards: [{ kind: 'aibom' }], advisory_lookup: {} }), /inventory check/i);
});

test('live banner wording follows the reported advisory lookup status', () => {
  const t = (lookup, cards = [{ kind: 'sbom' }]) => liveBarText({ cards, advisory_lookup: { lookup } });
  assert.match(t('complete'), /were then looked up in OSV\./);
  assert.match(t('partial'), /only partly looked up in OSV\./);
  for (const bad of ['unavailable', 'not_run']) assert.doesNotMatch(t(bad), /were then looked up|partly looked up/, bad);
  assert.match(t('unavailable'), /unavailable, so no versions were looked up/);
  assert.match(t('not_run'), /no advisory matching or AI-BOM was run/);
  assert.match(t('not_run', [{ kind: 'aibom' }]), /no advisory matching was run \(the AI-BOM was produced separately/);
  assert.doesNotMatch(t('unavailable', [{ kind: 'aibom' }]), /No AI-BOM/);
});
test('replay banner: says it is a replay of a recorded scan and keeps the pinned commit; normal live text is unchanged', () => {
  const live = { cards: [{ kind: 'sbom' }, { kind: 'aibom' }], advisory_lookup: {}, live: { source: {} } };
  const replay = { ...live, live: { replay: { revision: '3bca9b8676846d175f6b9f53f5818cbb9d36ec3e', job_id: 'job:x' } } };
  assert.equal(liveBarText(live), 'Live scan of one resolved commit. Syft and cdxgen ran in a no-network sandbox; lockfile versions were then looked up in OSV.');
  assert.equal(liveBarText(replay), 'Replay of a recorded scan of commit 3bca9b867684. Syft and cdxgen ran in a no-network sandbox; lockfile versions were then looked up in OSV.');
});
