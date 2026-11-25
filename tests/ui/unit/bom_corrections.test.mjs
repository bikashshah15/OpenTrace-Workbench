// UIP-08 correction round (independent review UIP08-IR-01..03). These assert the CORRECT behavior; the reviewer's probe (preserved unchanged under
// .context/reviews/UIP-08_INDEPENDENT_REVIEW_2026-11-15_evidence/) asserts the old bad observations and is not modified.
// Handler patches come from the store helpers that app.js uses; on the pre-fix source those helpers do not exist, so the fallbacks below are the old
// handlers' literal patches (this is how the failures are demonstrated on the starting source).
import test from 'node:test';
import assert from 'node:assert/strict';
import * as S from '../../../src/ui/lib/store.js';
import { renderBomWorkspace } from '../../../src/ui/components/gaps.js';

const { createStore, initial, bomKey } = S;
const identity = { analysis_digest: 'a'.repeat(64), owner: 'review', name: 'fixture', commit: 'b'.repeat(40) };
const mk = () => createStore({ ...initial(), epoch: 3, analysis: { generation: 7, identity }, workbench: { ...initial().workbench, tab: 'bom' } });
const patch = (s, p) => s.dispatch({ type: 'BOM_PATCH', patch: p });
const request = (s, kind) => { const a = { kind, epoch: 3, generation: 7, seq: s.get().bom8.seq[kind] + 1, key: bomKey(s.get().bom8, kind) }; s.dispatch({ type: 'BOM_REQUEST', ...a }); return a; };
const data = (more) => ({ binding: { analysis_digest: identity.analysis_digest }, ...more });
const cand = (id, name = id) => ({ item_id: id, assertion_id: null, display: { name, raw_title: name }, state: 'unknown_coverage', category: 'requirement', graph_state: 'no_graph', location: null, inventory: null, rule_id: null });
const page = (items, more = {}) => data({ mode: 'discovery_compared', counts: { candidates_total: items.length, filtered_total: items.length, records_total: 0 }, items, page: { offset: 0, size: 25, has_more: false }, capabilities: [], ...more });
const graphFor = (id, label = 'G ' + id) => ({ scope: { kind: 'focused_candidate', candidate_id: id, group: null, query: '' }, nodes: [{ node_id: 'entity:' + id, kind: 'entity', full_label: label, role: 'primary' }], edges: [], records: [], counts: { nodes_shown: 1, nodes_in_scope: 1, edges_shown: 0, edges_in_scope: 0 }, truncated: false });
const relatedMultiple = (subject, items) => data({ subject: { id: subject }, resolution: 'multiple', related_total: items.length, items: items.map((i) => ({ item_id: i, assertion_id: null, display_name: 'Check ' + i, family: 'software', state: 'unknown_coverage', location: null })), record_detail: null, counts: {}, page: { offset: 0, size: 20, has_more: false } });

// Old handler literals (fallbacks only when the corrected helpers are absent).
const relatedPatch = (s, id) => S.bomRelatedPatch ? S.bomRelatedPatch(s.get().bom8, id)
  : { selected: id, selectedRecord: null, related: null, view: 'gaps', graph: null, popup: null, chooserQ: '', chooserOffset: 0 };
const contextPatch = (extra) => S.bomContextPatch ? S.bomContextPatch(extra)
  : { ...extra, queue: null };

// ---------- IR-01: exact related-check navigation ----------
for (const order of ['queue-first', 'graph-first']) {
  test(`IR-01 (${order}): a chooser selection beyond page 1 and outside the current filter/search is never replaced by the first queue item`, () => {
    const s = mk();
    patch(s, { filter: 'contradicted', q: 'zzz', offset: 25, popup: 'chooser', selectedRecord: 'entity:r', related: relatedMultiple('entity:r', ['cand:far', 'cand:near']) });
    patch(s, relatedPatch(s, 'cand:far'));
    const q = request(s, 'queue'), g = request(s, 'graph');
    const deliverQ = () => s.dispatch({ type: 'BOM_LOADED', ...q, data: page([cand('cand:first-page-item')]) });
    const deliverG = () => s.dispatch({ type: 'BOM_LOADED', ...g, data: data(graphFor('cand:far')) });
    if (order === 'queue-first') { deliverQ(); deliverG(); } else { deliverG(); deliverQ(); }
    const b = s.get().bom8;
    assert.equal(b.selected, 'cand:far', 'exact chosen ID kept');
    assert.equal(b.graph?.scope.candidate_id, 'cand:far', 'its own graph kept/synchronized');
    const html = renderBomWorkspace(s.get());
    assert.match(html, /G cand:far/);
    assert.match(html, /Check cand:far|cand:far/, 'inspector names the chosen candidate even though it is not on the queue page');
    assert.doesNotMatch(html, /Canonical candidate <code>cand:first-page-item/);
  });
}

test('IR-01: ordinary navigation without an explicit pin still selects the first queue item', () => {
  const s = mk(); patch(s, { selected: null });
  const q = request(s, 'queue');
  s.dispatch({ type: 'BOM_LOADED', ...q, data: page([cand('cand:one'), cand('cand:two')]) });
  assert.equal(s.get().bom8.selected, 'cand:one');
});

test('IR-01: a pinned selection is dropped (not substituted) once the queue context changes', () => {
  const s = mk();
  patch(s, { popup: 'chooser', selectedRecord: 'entity:r', related: relatedMultiple('entity:r', ['cand:far']) });
  patch(s, relatedPatch(s, 'cand:far'));
  patch(s, contextPatch({ q: 'new', offset: 0 }));
  const b = s.get().bom8;
  assert.equal(b.selected, null); assert.equal(b.graph, null);
});

// ---------- IR-02: queue-context changes and zero matches ----------
test('IR-02: a search/filter change clears the selection, graph, record, inspector and related state immediately', () => {
  const s = mk();
  patch(s, { selected: 'cand:old', graph: graphFor('cand:old', 'OLD GRAPH RECORD'), selectedRecord: 'entity:cand:old', related: relatedMultiple('entity:cand:old', ['cand:old']), drawer: true });
  patch(s, contextPatch({ q: 'no-matches', offset: 0 }));
  const b = s.get().bom8;
  assert.equal(b.selected, null); assert.equal(b.graph, null); assert.equal(b.selectedRecord, null); assert.equal(b.related, null);
});

test('IR-02: a zero-match queue shows no old graph or inspector, even with a retained record selection', () => {
  const s = mk();
  patch(s, { selected: 'cand:old', graph: graphFor('cand:old', 'OLD GRAPH RECORD'), selectedRecord: 'entity:cand:old' });
  patch(s, contextPatch({ q: 'no-matches', offset: 0 }));
  const q = request(s, 'queue');
  s.dispatch({ type: 'BOM_LOADED', ...q, data: page([], { counts: { candidates_total: 1, filtered_total: 0, records_total: 0 } }) });
  const html = renderBomWorkspace(s.get());
  assert.doesNotMatch(html, /OLD GRAPH RECORD/); assert.doesNotMatch(html, /cand:old/);
  assert.equal(s.get().bom8.selected, null);
});

test('IR-02: even if the queue-context reset was skipped, an accepted empty page clears unpinned selection state', () => {
  const s = mk();
  patch(s, { selected: 'cand:old', graph: graphFor('cand:old', 'OLD GRAPH RECORD'), selectedRecord: 'entity:cand:old', q: 'none', queue: null });
  const q = request(s, 'queue');
  s.dispatch({ type: 'BOM_LOADED', ...q, data: page([], { counts: { candidates_total: 1, filtered_total: 0, records_total: 0 } }) });
  const b = s.get().bom8;
  assert.equal(b.selected, null); assert.equal(b.graph, null); assert.equal(b.selectedRecord, null);
  assert.doesNotMatch(renderBomWorkspace(s.get()), /OLD GRAPH RECORD/);
});

test('IR-02: a delayed earlier queue response cannot restore a cleared selection', () => {
  const s = mk();
  const early = request(s, 'queue');                      // for the original context
  patch(s, { selected: 'cand:old' });
  patch(s, contextPatch({ q: 'x', offset: 0 }));
  const late = request(s, 'queue');
  s.dispatch({ type: 'BOM_LOADED', ...late, data: page([], { counts: { candidates_total: 1, filtered_total: 0, records_total: 0 } }) });
  s.dispatch({ type: 'BOM_LOADED', ...early, data: page([cand('cand:old')]) });
  assert.equal(s.get().bom8.selected, null); assert.equal(s.get().bom8.queue.items.length, 0);
});

test('IR-02: replacing the selection by a first-queue substitution drops the old candidate graph', () => {
  const s = mk();
  patch(s, { selected: 'cand:old', graph: graphFor('cand:old', 'OLD GRAPH RECORD'), selectedRecord: 'entity:cand:old' });
  const q = request(s, 'queue');
  s.dispatch({ type: 'BOM_LOADED', ...q, data: page([cand('cand:new')]) });
  const b = s.get().bom8;
  assert.equal(b.selected, 'cand:new'); assert.equal(b.graph, null); assert.equal(b.selectedRecord, null);
});

// ---------- IR-03: request lifetimes ----------
const accepted = (s, a, payload) => { s.dispatch({ type: 'BOM_LOADED', ...a, data: payload }); return s.get().bom8.related === payload; };

test('IR-03: leaving the BOM tab and returning to the same key does not revive an earlier related request', () => {
  const s = mk(); patch(s, { selectedRecord: 'entity:old' });
  const a = request(s, 'related');
  s.dispatch({ type: 'TAB', tab: 'dependencies' }); s.dispatch({ type: 'TAB', tab: 'bom' });
  assert.equal(accepted(s, a, relatedMultiple('entity:old', ['cand:old'])), false);
  assert.equal(s.get().bom8.popup, null);
});

test('IR-03: leaving the tab also retires queue and graph requests', () => {
  const s = mk(); patch(s, { selected: 'cand:old' });
  const q = request(s, 'queue'), g = request(s, 'graph');
  s.dispatch({ type: 'TAB', tab: 'ai' }); s.dispatch({ type: 'TAB', tab: 'bom' });
  s.dispatch({ type: 'BOM_LOADED', ...q, data: page([cand('cand:old')]) });
  s.dispatch({ type: 'BOM_LOADED', ...g, data: data(graphFor('cand:old')) });
  assert.equal(s.get().bom8.queue, null); assert.equal(s.get().bom8.graph, null);
});

test('IR-03: popup close then reopen with the same visible key does not revive an earlier related request', () => {
  const s = mk(); patch(s, { selectedRecord: 'entity:old', popup: 'chooser' });
  const a = request(s, 'related');
  patch(s, { popup: null }); patch(s, { popup: 'chooser' });
  assert.equal(accepted(s, a, relatedMultiple('entity:old', [])), false);
});

test('IR-03: the expanded-graph popup path reachable from the handlers (record click, close, expand again) also retires the request', () => {
  const s = mk(); patch(s, { popup: 'graph', selected: 'cand:a' });
  patch(s, { selectedRecord: 'entity:r', related: null });   // bomSelectRecord
  const a = request(s, 'related');                            // key includes the open graph popup
  patch(s, { popup: null }); patch(s, { popup: 'graph' });    // bom-close, bom-expand
  assert.equal(accepted(s, a, relatedMultiple('entity:r', ['cand:b'])), false);
  assert.equal(s.get().bom8.popup, 'graph', 'the stale response must not replace the graph popup with a chooser');
});

test('IR-03: a current related response is still accepted, and a popup change that does not alter the popup keeps it', () => {
  const s = mk(); patch(s, { selectedRecord: 'entity:r' });
  const a = request(s, 'related');
  patch(s, { drawer: true });                                  // unrelated patch
  patch(s, { popup: null });                                   // same popup value: not a transition
  assert.equal(accepted(s, a, relatedMultiple('entity:r', ['cand:b'])), true);
});

test('IR-03: a changed selection or End/new generation still rejects earlier responses', () => {
  const s = mk(); patch(s, { selectedRecord: 'entity:a' });
  const a = request(s, 'related');
  patch(s, { selectedRecord: 'entity:b' });
  assert.equal(accepted(s, a, relatedMultiple('entity:a', [])), false);
  const c = request(s, 'related');
  s.dispatch({ type: 'ENDED' });
  s.dispatch({ type: 'BOM_LOADED', ...c, data: relatedMultiple('entity:b', []) });
  assert.equal(s.get().bom8.related, null);
});

test('IR-03: the post-response follow-up helper acts only on a response the reducer accepted', () => {
  assert.equal(typeof S.bomAccepted, 'function', 'app.js guards callbacks with the shared acceptance check');
  const s = mk(); patch(s, { selected: 'cand:old' });
  const q = request(s, 'queue'); const payload = page([cand('cand:old')]);
  s.dispatch({ type: 'TAB', tab: 'ai' }); s.dispatch({ type: 'TAB', tab: 'bom' });
  s.dispatch({ type: 'BOM_LOADED', ...q, data: payload });
  assert.equal(S.bomAccepted(s.get(), 'queue', payload), false, 'a discarded queue response triggers no graph follow-up');
  const q2 = request(s, 'queue'); const p2 = page([cand('cand:old')]);
  s.dispatch({ type: 'BOM_LOADED', ...q2, data: p2 });
  assert.equal(S.bomAccepted(s.get(), 'queue', p2), true);
});
