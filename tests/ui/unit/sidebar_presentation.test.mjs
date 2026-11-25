// Sidebar presentation refinement: ONE header and ONE question set per selection across the Crypto, AI and ACTIVE BOM tabs, drawn by the shared shell.
// Drives the real renderers (renderCryptoView / renderAiView / renderBomWorkspace) and the real store. No browser, network or service.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createStore, initial } from '../../../src/ui/lib/store.js';
import * as CM from '../../../src/ui/lib/crypto_graph.js';
import * as AM from '../../../src/ui/lib/ai_graph.js';
import { renderCryptoView } from '../../../src/ui/components/crypto_graph.js';
import { renderAiView } from '../../../src/ui/components/ai_graph.js';
import { renderBomWorkspace } from '../../../src/ui/components/gaps.js';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '../../..');
const cfx = (n) => JSON.parse(readFileSync(join(ROOT, 'evidence/uip/visual/uip-06/fixtures/renderer', n + '.json'), 'utf8'));
const afx = (n) => JSON.parse(readFileSync(join(ROOT, 'evidence/uip/visual/uip-07/fixtures/renderer', n + '.json'), 'utf8'));
const css = readFileSync(join(ROOT, 'src/ui/styles/app.css'), 'utf8');

const analysis = (digest) => ({ generation: 1, identity: { mode: 'captured', owner: 'example-org', name: 'synthetic-lab', commit: '0'.repeat(40), analysis_digest: digest },
  summary: { components: 1, checks: [], cards: [{ kind: 'cbom', artifact_name: 'c.cdx.json' }, { kind: 'aibom', artifact_name: 'a.cdx.json' }] } });
function tab(kind, M, load, page, extra) {
  const st = createStore(initial()); st.dispatch({ type: 'ANALYSIS_START' }); const e = st.get().epoch;
  st.dispatch({ type: 'ANALYSIS_READY', epoch: e, analysis: analysis(page.binding.analysis_digest) });
  st.dispatch({ type: 'TAB_STATE', tab: kind, patch: extra });
  const key = M.requestKey(st.get().workbench.perTab[kind]); st.dispatch({ type: kind === 'crypto' ? 'CRYPTO_REQUEST' : 'AI_REQUEST', epoch: e, generation: 1, seq: 1, key });
  st.dispatch({ type: load, epoch: e, generation: 1, seq: 1, key, data: page });
  return st;
}
const crypto = (page, extra) => renderCryptoView(tab('crypto', CM, 'CRYPTO_LOADED', page, extra).get());
const ai = (page, extra) => renderAiView(tab('ai', AM, 'AI_LOADED', page, extra).get());
const aside = (h) => h.match(/<aside class="ot-inspector[\s\S]*?<\/aside>/)[0];
const ORDER = ['what_is_this', 'why_here', 'security_concern', 'what_unknown'];
const questions = (a) => [...a.matchAll(/data-question="([a-z_]+)"/g)].map((m) => m[1]);
const headers = (a) => (a.match(/<h2/g) || []).length;

for (const [name, render, fixture, multi] of [['Cryptography', crypto, cfx('findings'), cfx('multi3')], ['AI models', ai, afx('findings'), afx('multi3')]]) {
  const asset = fixture.assets.find((a) => fixture.review_items.some((r) => r.asset_id === a.asset_id));
  const plain = fixture.assets.find((a) => !fixture.review_items.some((r) => r.asset_id === a.asset_id));
  const group = fixture.source_groups[0];
  const sels = [['reviewed asset', 'asset:' + asset.asset_id], ['group', 'group:' + group.group_id], ['repository', 'root'], ...(plain ? [['unreviewed asset', 'asset:' + plain.asset_id]] : [])];
  for (const [label, sel] of sels) {
    test(`${name} ${label}: one header, the four approved questions in order, no duplicate status/purpose block, Sources & coverage collapsed`, () => {
      const a = aside(render(fixture, { filter: 'all', sel, selUser: true }));
      assert.equal(headers(a), 1, 'exactly one title');
      assert.deepEqual(questions(a), ORDER);
      assert.ok(a.indexOf('Evidence for this record') > a.indexOf('What remains unknown?'));
      assert.ok(a.indexOf('Sources &amp; coverage') > a.indexOf('Evidence for this record'));
      assert.match(a, /<details class="ot-insp-sources"><summary>/); assert.doesNotMatch(a, /<details class="ot-insp-sources" open/);
      assert.doesNotMatch(a, /otc-status|otai-status|otc-purpose|otai-purpose/);
      assert.match(a, /<span class="ot-insp-badge[^>]*><svg[\s\S]*?<\/svg><span>[^<]+<\/span><\/span>/, 'status is an icon AND text');
    });
  }
  test(`${name}: the reviewed asset keeps its rule rationale, evidence id, next step and source observation (nothing lost in the consolidation)`, () => {
    const a = aside(render(fixture, { filter: 'all', sel: 'asset:' + asset.asset_id, selUser: true }));
    const r = fixture.review_items.find((x) => x.asset_id === asset.asset_id);
    assert.match(a, /ot-insp-review/); assert.match(a, /Rule result and rationale/);
    for (const t of [r.rule_id, r.rationale, r.next_action, ...(r.evidence_ids || [])].filter(Boolean)) assert.ok(a.includes(t.replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;')), `kept: ${t}`);
    assert.match(a, /<h3>Next step<\/h3>/); assert.match(a, /Source observations · /); assert.match(a, /Source SHA-256 /);
  });
  test(`${name}: two selections produce their own title and evidence`, () => {
    const [x, y] = multi.assets; const fixture2 = multi;
    const ax = aside(render(fixture2, { filter: 'all', sel: 'asset:' + x.asset_id, selUser: true })); const ay = aside(render(fixture2, { filter: 'all', sel: 'asset:' + y.asset_id, selUser: true }));
    assert.notEqual(ax, ay); assert.ok(ax.includes(`data-record-id="${x.asset_id}"`)); assert.ok(!ax.includes(y.asset_id)); assert.ok(ay.includes(`data-record-id="${y.asset_id}"`)); assert.ok(!ay.includes(x.asset_id));
  });
}

test('a group lists its assets as selectable buttons inside the single sidebar', () => {
  const f = cfx('multi3'); const g = f.source_groups[0];
  const a = aside(crypto(f, { filter: 'all', sel: 'group:' + g.group_id, selUser: true }));
  assert.match(a, /Assets in this group on this page/); assert.match(a, /class="otc-detail-link" data-otc-select="asset:/);
});

test('more than three evidence rows: three show first, the rest sit behind "Show all evidence (N)"; one row shows no disclosure', () => {
  const f = cfx('occ45'); const asset = f.assets.find((x) => x.occurrences.length > 4) || f.assets[0];
  const a = aside(crypto(f, { filter: 'all', sel: 'asset:' + asset.asset_id, selUser: true }));
  const ev = a.match(/<section class="ot-insp-evidence"[\s\S]*?<\/section>/)[0];
  const first = ev.split('<details class="ot-insp-allev">')[0];
  assert.equal((first.match(/<dt>/g) || []).length, 3);
  const m = ev.match(/Show all evidence \((\d+)\)/); assert.ok(m && Number(m[1]) > 3);
  assert.equal((ev.split('<details class="ot-insp-allev">')[1].match(/<dt>/g) || []).length, Number(m[1]) - 3, 'every remaining row is reachable');
  const one = aside(crypto(cfx('multi3'), { filter: 'all', sel: 'root', selUser: true }));
  assert.doesNotMatch(one, /Show all evidence/);
});

test('hostile asset text stays inert in the single sidebar', () => {
  const f = cfx('hostile'); const a = aside(crypto(f, { filter: 'all', sel: 'asset:' + f.assets[0].asset_id, selUser: true }));
  assert.doesNotMatch(a, /<img|<[a-z]+[^>]*\sonerror=/); assert.match(a, /&lt;img src=x onerror=alert\(1\)&gt;/);
  const g = afx('hostile'); const b = aside(ai(g, { filter: 'all', sel: 'asset:' + g.assets[0].asset_id, selUser: true }));
  assert.doesNotMatch(b, /<img|<script|<[a-z]+[^>]*\sonerror=/); assert.match(b, /&lt;/);
});

test('source links remain pinned-revision links and are never created without a recorded location', () => {
  const f = cfx('findings'); const a = aside(crypto(f, { filter: 'all', sel: 'asset:' + f.review_items[0].asset_id, selUser: true }));
  for (const [, href] of a.matchAll(/<a href="([^"]+)"/g)) assert.match(href, /^https:\/\/github\.com\/[^/]+\/[^/]+\/blob\/[0-9a-f]{40}\//);
  const d = afx('demo_like'); const b = aside(ai(d, { filter: 'all', sel: 'asset:' + d.assets[0].asset_id, selUser: true }));
  assert.doesNotMatch(b, /<a href=/);
});

test('the unknown answer is tailored to the record: an AI asset names its unrecorded attributes and an experimental crypto asset says other sites are not ruled out', () => {
  const d = afx('demo_like'); const b = aside(ai(d, { filter: 'all', sel: 'asset:' + d.assets[0].asset_id, selUser: true }));
  assert.match(b, /No recorded value for: provider, model version/); assert.match(b, /not a verified model identity/);
  const f = cfx('findings'); const exp = f.assets.find((x) => x.provenance.experimental);
  if (exp) assert.match(aside(crypto(f, { filter: 'all', sel: 'asset:' + exp.asset_id, selUser: true })), /Call sites elsewhere are not ruled out/);
});

test('CSS: the status line keeps its tone colour (the card paragraph colour no longer overrides it) and no green "safe" tone exists', () => {
  assert.doesNotMatch(css, /\.ot-insp-card p\{[^}]*color:var\(--ink\)!important/);
  assert.match(css, /\.ot-insp-card \.ot-insp-state\.ot-insp-review\{color:var\(--ot-insp-review\)!important\}/);
  assert.match(css, /\.ot-insp-card \.ot-insp-state\.ot-insp-advisory\{color:var\(--ot-insp-advisory\)!important\}/);
  assert.match(css, /\.ot-insp-card \.ot-insp-state\.ot-insp-checked\{color:var\(--ot-insp-checked\)!important\}/);
  assert.doesNotMatch(css, /--ot-insp-[a-z]+:\s*#(?:0[0-9a-f]{2}[89a-f][0-9a-f]{2}|2[0-9a-f]a[0-9a-f]4[0-9a-f])/i, 'no green verdict tone');
});

test('CSS: the tone tokens are defined on the shell itself, so the BOM drawer (which is not inside .ot-inspector) keeps its status colours in light and dark', () => {
  assert.match(css, /\n\.ot-insp\{--ot-insp-checked:#[0-9a-f]{6};--ot-insp-reported:#[0-9a-f]{6};--ot-insp-unknown:#[0-9a-f]{6};--ot-insp-review:#[0-9a-f]{6};--ot-insp-advisory:#[0-9a-f]{6}/);
  assert.match(css, /html\[data-theme=dark\] \.ot-insp\{--ot-insp-checked:/); assert.match(css, /\.ot-insp-evidence dd>span\{overflow-wrap:anywhere\}/);
});

// ------------------------------------------------------------------------------------------------------------ ACTIVE BOM workspace
const identity = { analysis_digest: 'a'.repeat(64), owner: 'review', name: 'fixture', commit: 'b'.repeat(40) };
const item = (id, name, over = {}) => ({ item_id: id, assertion_id: `as-${id}`, display: { name, raw_title: name }, state: 'unverifiable', category: 'unknown_coverage', graph_state: 'assertion_graph', family: 'cryptography', location: { path: `app/${id}.py`, line_start: 2, line_end: 2 },
  inventory: { inventory_id: 'inv:cbom', generator: 'cdxgen 12.9.0' }, rule_id: 'crypto_attribution.operation_declared_in_cbom/4', ...over });
const queue = (...items) => ({ mode: 'discovery_compared', counts: { candidates_total: items.length, filtered_total: items.length, records_total: 0, family_counts: {} }, items, page: { offset: 0, size: 25, has_more: false }, filters: {},
  capabilities: [{ family: 'software', state: 'completed' }, { family: 'cryptography', state: 'completed' }] });
const detail = (id, over = {}) => ({ candidate: { candidate_id: id, state: 'unverifiable', state_label: 'Could not be confirmed', category_label: 'Unknown coverage', title: id, rationale: `RATIONALE-${id}`, trigger: `TRIGGER-${id}`, bom: { label: 'cdxgen', inventory_id: 'inv:cbom', sha256: 'c'.repeat(64) },
  records: [{ evidence_id: 'e1', kind: 'source_excerpt', role: 'source_reference', source: { file: `app/${id}.py`, file_sha256: 'd'.repeat(64), lines: [2, 2] }, excerpt: `EXC-${id} <img src=x onerror=1>`, operation: 'hash', resolution: {}, checks: {} },
    { evidence_id: 'e2', kind: 'cbom_document', role: 'cbom_document', document: { format: 'CycloneDX', spec_version: '1.6', raw_sha256: 'e'.repeat(64) }, status: 'ok', producer: [], census: {} }, { evidence_id: 'e3', kind: 'x', role: 'r' }, { evidence_id: 'e4', kind: 'y', role: 'r' }],
  reason_codes: ['no_algorithm_record'], assertion_id: `as-${id}`, rule_id: 'r/4', not_established: ['that the code runs'], bounded_meaning: 'BOUNDED', next_action: `NEXT-${id}`, identity_basis: 'finite', ...over } });
const graph = (id) => ({ scope: { kind: 'focused_candidate', candidate_id: id }, nodes: [{ node_id: 'n1', full_label: 'sha256 call', kind: 'source_observation', evidence_role: 'source_reference' }, { node_id: 'n2', full_label: 'CBOM record', kind: 'cbom_document', evidence_role: 'cbom_document' }],
  edges: [{ edge_id: 'x1', from: 'n1', to: 'n2', type: 'compared_with', role: 'comparison', rationale: 'EDGE-RATIONALE', label: 'compared with' }], counts: { nodes_shown: 2, nodes_in_scope: 2, edges_shown: 1, edges_in_scope: 1 }, truncated: false });
function bom(patch) {
  const st = createStore({ ...initial(), epoch: 3, analysis: { generation: 7, identity }, workbench: { ...initial().workbench, tab: 'bom' } });
  st.dispatch({ type: 'BOM_PATCH', patch: { view: 'crypto', selected: 'A', queue: queue(item('A', 'sha256 A'), item('B', 'sha256 B', { state: 'contradicted', category: 'missing_component' })), ...patch } });
  return st;
}
const bomAside = (st) => renderBomWorkspace(st.get()).match(/<div class="ot-bom8-drawer-body">([\s\S]*?)<\/div><\/aside>/)[1];
const BOMQ = ['what_is_this', 'why_here', 'comparison_established', 'what_unknown'];

test('BOM candidate: one header, the comparison question third, "Evidence for this check", own rationale/next step, collapsed Sources & coverage', () => {
  const a = bomAside(bom({ detail: detail('A') }));
  assert.equal(headers(a), 1); assert.deepEqual(questions(a), BOMQ); assert.match(a, /What did the comparison establish\?/); assert.doesNotMatch(a, /security concern/i);
  assert.match(a, /Evidence for this check/); assert.match(a, /data-evidence-for="A"/);
  assert.match(a, /TRIGGER-A/); assert.match(a, /RATIONALE-A/); assert.match(a, /<h3>Next step<\/h3><p>NEXT-A/); assert.match(a, /Not established: that the code runs/);
  assert.match(a, /<details class="ot-insp-sources"><summary>/); assert.doesNotMatch(a, /<details class="ot-insp-sources" open/);
  assert.match(a, /EXC-A &lt;img src=x onerror=1&gt;/); assert.doesNotMatch(a, /<img src=x/);
  const ev = a.match(/<section class="ot-insp-evidence"[\s\S]*?<\/section>/)[0];
  assert.equal((ev.split('<details class="ot-insp-allev">')[0].match(/<dt>/g) || []).length, 3); assert.match(ev, /Show all evidence \(\d+\)/);
});
test('BOM candidate: a different candidate shows its own facts; a detail loaded for another candidate is never shown; loading and error are stated for this one', () => {
  const b = bomAside(bom({ selected: 'B', detail: detail('A') }));
  assert.match(b, /data-record-id="B"/); assert.doesNotMatch(b, /RATIONALE-A|EXC-A|TRIGGER-A|NEXT-A/); assert.match(b, /Loading evidence/); assert.match(b, /Not represented/);
  assert.match(bomAside(bom({ selected: 'B', detail: null, detailError: 'boom' })), /The evidence could not be loaded \(boom\)/);
  assert.notEqual(bomAside(bom({ detail: detail('A') })), b);
});
test('BOM node and arrow explain themselves: no inherited verdict, no data-flow claim, related checks reachable', () => {
  const base = { graph: graph('A'), detail: detail('A'), selectedRecord: 'x1', related: { subject: { id: 'x1' }, resolution: 'single', related_total: 1, items: [{ item_id: 'A', display_name: 'sha256 A' }] } };
  const e = bomAside(bom(base));
  assert.equal(headers(e), 1); assert.deepEqual(questions(e), BOMQ); assert.match(e, /Recorded relationship/); assert.match(e, /EDGE-RATIONALE/); assert.match(e, /not data flow or runtime use/);
  assert.doesNotMatch(e, /Could not be confirmed|Cannot establish|RATIONALE-A|NEXT-A|Candidate check/); assert.match(e, /data-action="bom-related" data-id="A"/); assert.match(e, /Not applicable/);
  const n = bomAside(bom({ ...base, selectedRecord: 'n2', related: { subject: { id: 'n2' }, resolution: 'multiple', related_total: 2, items: [{ item_id: 'A', display_name: 'one' }, { item_id: 'B', display_name: 'two' }] } }));
  assert.match(n, /Recorded cbom document/); assert.match(n, /CBOM record/); assert.doesNotMatch(n, /RATIONALE-A|Cannot establish/); assert.match(n, /2 related checks/);
  assert.match(bomAside(bom({ ...base, selectedRecord: 'n1', related: null })), /Looking up related checks/);
  assert.match(bomAside(bom({ ...base, selectedRecord: 'gone' })), /not in the graph that is currently loaded/);
});
test('review corrections: error is not "loading"; family text names no collector; edge ends show names; an unloaded record offers no related lookup', () => {
  const e = bomAside(bom({ selected: 'B', detail: null, detailError: 'boom' }));
  assert.match(e, /The rationale could not be loaded/); assert.doesNotMatch(e, /rationale is loading/); assert.doesNotMatch(e, /hashlib|static model reference/);
  const edge = bomAside(bom({ graph: graph('A'), selectedRecord: 'x1', related: null })); assert.match(edge, /sha256 call \(n1\)/); assert.match(edge, /CBOM record \(n2\)/);
  const gone = bomAside(bom({ graph: graph('A'), selectedRecord: 'gone', related: null })); assert.doesNotMatch(gone, /Looking up related checks|bom-related/);
});
test('BOM with nothing selected asks for a selection', () => {
  assert.match(bomAside(bom({ selected: null })), /Select a candidate or recorded item/);
});
