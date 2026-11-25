// UIP-10-IR-03: a partial collection must be visible next to populated candidate results, in the queue, focused and full views.
// Pure renderer tests (no browser). These fail on the reviewed renderer, which showed capability state only for an empty family list.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createStore, initial } from '../../../src/ui/lib/store.js';
import { bomDetailsHtml, renderBomWorkspace } from '../../../src/ui/components/gaps.js';

const identity = { analysis_digest: 'a'.repeat(64), owner: 'review', name: 'fixture', commit: 'b'.repeat(40) };
const cand = { item_id: 'cand:1', assertion_id: null, display: { name: 'flask', raw_title: 'flask' }, state: 'unknown_coverage', category: 'requirement', graph_state: 'no_graph', location: null, inventory: null, rule_id: null };
const caps = (state, reason) => [{ family: 'software', state, reason_code: reason }, ...['cryptography', 'ai_model', 'other'].map((family) => ({ family, state: 'not_run', reason_code: 'not_configured' }))];
const render = (state, reason, view = 'gaps', items = [cand], mode = 'discovery_compared') => {
  const s = createStore({ ...initial(), epoch: 3, analysis: { generation: 7, identity }, workbench: { ...initial().workbench, tab: 'bom' } });
  s.dispatch({ type: 'BOM_PATCH', patch: { view, queue: { mode, counts: { candidates_total: items.length, filtered_total: items.length, records_total: 0 }, items, page: { offset: 0, size: 25, has_more: false }, capabilities: caps(state, reason) } } });
  const html = renderBomWorkspace(s.get());
  assert.doesNotMatch(html, /data-coverage="partial"|Bound inventory and rule evidence/);   // folded into the evidence strip's Details
  return html + bomDetailsHtml(s.get());
};

for (const view of ['gaps', 'software', 'full']) {
  test(`partial software coverage is disclosed with populated candidates in the ${view} view`, () => {
    const html = render('partial', 'partial_coverage', view);
    assert.match(html, /data-coverage="partial"/);
    assert.match(html, /not everything in this repository was checked/);
    assert.match(html, /do not show that nothing is missing/);
  });
}

test('the disclosure is independent of the list length (empty list)', () => {
  assert.match(render('partial', 'partial_coverage', 'gaps', []), /data-coverage="partial"/);
});

test('completed and completed-empty collections carry no partial disclosure; candidate rows are unchanged', () => {
  for (const [st, rs] of [['completed', null], ['completed_empty', 'no_applicable_assets']]) {
    const html = render(st, rs);
    assert.doesNotMatch(html, /data-coverage/);
    assert.match(html, /data-id="cand:1"/);
  }
  assert.match(render('partial', 'partial_coverage'), /data-id="cand:1"/);
});

test('a not-compared page does not claim partial coverage', () => {
  assert.doesNotMatch(render('failed', 'upstream_failed', 'gaps', [], 'not_compared'), /data-coverage/);
});
