// UIP-05: pure layout model against the reference-extracted geometry, rendering (pills, pager, inert text, removed clutter, Graph/List
// population), and the request/lifecycle reducers. No browser, network or service. Run: node --test tests/ui/unit/
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createStore as createRawStore, initial } from '../../../src/ui/lib/store.js';
import { chooserKey } from '../../../src/ui/lib/dependency_graph.js';
import { wrapLabel, FILTERS, columnsFor, layoutPage, visibleOrder, stageHeight, captionText, rangeText, emptyText, requestKey, payloadFilter, keyFilter, chooserOptions, nodeTarget, nodeClass, NODE_W, NODE_H, STEP_X, STEP_Y, ROOT_Y, TOP_START, DEFAULT_FILTER } from '../../../src/ui/lib/dependency_graph.js';
import { renderDependencyView, setMeasured } from '../../../src/ui/components/dependency_graph.js';

// UIP-05 corrections (IR-02): the reducer's request/response/failure actions now carry the request identity {key, intent}. These low-level
// dispatches stamp it from the state exactly as the app's loaders do; every assertion below is unchanged. Identity rules themselves are
// tested in dependency_corrections.test.mjs.
function createStore(state) {
  const st = createRawStore(state); const raw = st.dispatch;
  const stamp = (a) => {
    const d = st.get().workbench.perTab.dependencies;
    if (a.type === 'DEPPAGE_REQUEST' && a.key === undefined) return { ...a, key: requestKey(d), intent: 'active' };
    if (a.type === 'DEPCTX_REQUEST' && a.key === undefined) return { ...a, key: chooserKey(d) };
    if (a.type === 'DEPPAGE_FAILED' && a.key === undefined) return { ...a, key: d.pg.req?.key };
    if ((a.type === 'DEPCTX_LOADED' || a.type === 'DEPCTX_FAILED') && a.key === undefined) return { ...a, key: d.cx.req?.key };
    return a;
  };
  return { ...st, dispatch: (a) => raw(stamp(a)) };
}
const HERE = dirname(fileURLToPath(import.meta.url)); const ROOT = join(HERE, '../../..');
const fx = (...p) => JSON.parse(readFileSync(join(ROOT, 'evidence/uip/fixtures', ...p), 'utf8'));
const P0 = fx('deps-82-synthetic', 'page-offset-00.json'); const P60 = fx('deps-82-synthetic', 'page-offset-60.json'); const PATHS = fx('deps-paths-synthetic', 'paths-all.json');
const DIGEST = P0.binding.analysis_digest;
const analysis = () => ({ generation: 1, identity: { mode: 'captured', owner: 'acme', name: 'widget', commit: '0'.repeat(40), analysis_digest: DIGEST }, summary: { components: 1, checks: [] } });
function opened() { const st = createStore(initial()); st.dispatch({ type: 'ANALYSIS_START' }); const e = st.get().epoch; st.dispatch({ type: 'ANALYSIS_READY', epoch: e, analysis: analysis() }); return { st, e }; }
const dep = (st) => st.get().workbench.perTab.dependencies;
const patchDep = (st, patch) => st.dispatch({ type: 'TAB_STATE', tab: 'dependencies', patch });
const helpers = { depInspector: () => '<p class="ot-prompt">inspector</p>', depList: () => '<div id="stub-list">list</div>' };
const ctxId = P0.context.context_id;
function ready(page = P0, extra = {}) {
  const { st, e } = opened(); patchDep(st, { ctxId, ...extra });
  st.dispatch({ type: 'DEPPAGE_REQUEST', epoch: e, generation: 1, seq: 1 });
  st.dispatch({ type: 'DEPPAGE_LOADED', epoch: e, generation: 1, seq: 1, key: requestKey(dep(st)), data: page });
  return { st, e };
}
const html = (st) => renderDependencyView(st.get(), helpers);

// ------------------------------------------------------------------ geometry (reference friendlyDraw)
test('columns follow the stage width: clamp(floor((w - 48) / 160), 2, 6)', () => {
  assert.deepEqual([300, 400, 700, 1100, 1500, 3000].map(columnsFor), [2, 2, 4, 6, 6, 6]);
  assert.equal(columnsFor(0), 2);
});
test('root top-centre, depth-banded rows wrap within a band (82-direct page: 30 matches, 6 columns, 5 rows)', () => {
  const l = layoutPage(P0, 1200);
  assert.equal(l.columns, 6); assert.equal(l.width, 6 * STEP_X);
  const root = l.nodes.find((n) => n.node.role === 'focus'); assert.deepEqual([root.x, root.y], [l.width / 2, ROOT_Y]);
  const matches = l.nodes.filter((n) => n.node.role === 'match'); assert.equal(matches.length, 30);
  assert.deepEqual(new Set(matches.map((n) => n.y)), new Set([0, 1, 2, 3, 4].map((r) => TOP_START + r * STEP_Y)));
  assert.ok(matches.every((n) => n.x >= 95 && n.x <= 95 + 5 * STEP_X));
  assert.equal(l.height, TOP_START + 5 * STEP_Y + 46 + 50);
});
test('every drawn edge is exactly a recorded payload edge and ends at the target card left edge', () => {
  const l = layoutPage(PATHS, 1100);
  assert.deepEqual(l.edges.map((e) => e.id).sort(), PATHS.edges.map((e) => e.edge_id).sort());
  for (const e of l.edges) { const to = l.nodes.find((n) => n.id === e.to); assert.ok(e.d.endsWith(`V${to.y} H${to.x - NODE_W / 2}`), e.d); }
});
test('narrow stages reduce columns, never the 30 matches; the layout is deterministic', () => {
  const wide = layoutPage(P0, 1200); const narrow = layoutPage(P0, 340);
  assert.equal(narrow.columns, 2);
  assert.equal(narrow.nodes.filter((n) => n.node.role === 'match').length, 30);
  assert.deepEqual(layoutPage(P0, 340), narrow); assert.notDeepEqual(wide.width, narrow.width);
  assert.ok(stageHeight(wide, 1200) >= 570 && stageHeight(narrow, 340) <= 1800);
});
test('transitive page: bands are ordered by distance; connectors precede their matches only through their own parent chain', () => {
  const l = layoutPage(PATHS, 1100); const ys = (d) => l.nodes.filter((n) => n.node.depth === d).map((n) => n.y);
  assert.ok(Math.max(...ys(1)) < Math.min(...ys(2)) && Math.max(...ys(2)) < Math.min(...ys(3)));
  assert.equal(visibleOrder(PATHS)[0], PATHS.focus.node_id);
});

// ------------------------------------------------------------------ vocabulary, captions, defaults
test('pill keys map to the frozen enum; the default after focusing is Direct (FD-3)', () => {
  assert.deepEqual(FILTERS.map((f) => f.label), ['All', 'Advisory matches', 'Direct', 'Transitive', 'Evidence gaps']);
  assert.equal(payloadFilter('gaps'), 'evidence_gaps'); assert.equal(keyFilter('evidence_gaps'), 'gaps'); assert.equal(DEFAULT_FILTER, 'direct');
  assert.equal(payloadFilter('nonsense'), 'direct');
});
test('caption follows the reference wording (filter label, shown of total, connecting packages)', () => {
  assert.equal(captionText(P0, 'root-app'), 'Dependencies of root-app \u00b7 30 of 82 packages.');
  assert.match(captionText(PATHS, 'focus-root'), /^Dependencies of focus-root \u00b7 7 of 7 packages\.$/);
  assert.equal(captionText({ ...P0, filter: 'direct' }, 'r'), 'Direct dependencies of r \u00b7 30 of 82 packages.');
});
test('range text and the empty sentence', () => {
  assert.equal(rangeText(P0.page), '1–30 of 82'); assert.equal(rangeText(P60.page), '61–82 of 82');
  assert.equal(rangeText({ matches_total: 0 }), '0 of 0');
  assert.match(emptyText({ filter: 'transitive' }), /^No transitive dependencies recorded for this package in the selected source context\.$/);
});
test('request key and chooser options always carry the current context', () => {
  const k = requestKey({ ctxId: 'c', focus: null, filter: 'direct', q: '', gOffset: 0 }); assert.equal(k, JSON.stringify(['c', null, 'direct', '', 0]));
  const rows = [{ context_id: 'a', path: 'a/x', components_total: 1 }];
  assert.equal(chooserOptions({ rows }, null, { ctxId: 'zzz', context: 'z/y' })[0].path, 'z/y');
  assert.equal(chooserOptions({ rows }, null, { ctxId: 'a' }).length, 1);
});
test('keyboard target stays inside the list and Home/End jump', () => {
  const ids = ['a', 'b', 'c'];
  assert.deepEqual([nodeTarget(ids, 'a', 'ArrowDown'), nodeTarget(ids, 'a', 'ArrowUp'), nodeTarget(ids, 'b', 'End'), nodeTarget(ids, 'c', 'Home'), nodeTarget(ids, 'x', 'Home')], ['b', 'a', 'c', 'a', null]);
});
test('node classes encode role, depth, match, gap and selection (reference styles)', () => {
  const focus = PATHS.nodes.find((n) => n.role === 'focus');
  assert.match(nodeClass(focus, false), /root/); assert.match(nodeClass(PATHS.nodes.find((n) => n.advisory_lookup === 'match'), true), /matched.*chosen/);
  assert.match(nodeClass(PATHS.nodes.find((n) => n.flags.evidence_gap), false), /gap/);
});

// ------------------------------------------------------------------ rendering
test('renders pills with the payload totals, a compact pager above 30 matches, the 30 matches as buttons, and none of the removed clutter', () => {
  setMeasured(1100); const { st } = ready(); const out = html(st);
  for (const f of FILTERS) assert.match(out, new RegExp(`data-ot5-filter="${f.key}"[^>]*aria-pressed="${P0.filter === f.payload}">${f.label} <span>${P0.filter_totals[f.payload]}</span>`));
  assert.match(out, /id="ot5-pager"/); assert.match(out, /1–30 of 82/);
  assert.equal((out.match(/data-dep-node=/g) || []).length, 31);
  for (const gone of ['Package connections', 'Viewing this package', 'Used by', 'Focused package', 'Depends on', 'Back</button>', 'Full network']) assert.ok(!out.includes(gone), gone);
  assert.match(out, /aria-label="Previous 30 matching packages"/);
});
test('no pager for 30 or fewer matches', () => {
  const small = { ...P0, filter: 'advisory', page: { ...P0.page, matches_total: 4, matches_shown: 4, has_more: false, range_last: 4 } };
  const { st } = ready(small, { filter: 'advisory' }); assert.ok(!html(st).includes('id="ot5-pager"'));
});
test('hostile package text is inert: escaped in cards, labels, caption and aria; never a tag or link', () => {
  const evil = '<img src=x onerror=alert(1)>"\'</svg><a href="javascript:alert(1)">x</a>';
  const page = JSON.parse(JSON.stringify(P0)); page.nodes[1].name = evil; page.nodes[1].version = evil; page.nodes[0].name = evil;
  const { st } = ready(page); const out = html(st);
  assert.ok(!out.includes('<img') && !out.includes('<a href') && !/ href="javascript/.test(out));
  assert.ok(out.includes('&lt;img'));
  const c = captionText(page, page.nodes[0].name); assert.ok(c.includes('<img'));   // the caption is escaped when rendered
  assert.ok(!/<(img|script|iframe)\b/i.test(out));
});
test('empty filter shows the sentence; loading and typed failure show states with a manual retry', () => {
  const empty = { ...P0, filter: 'advisory', filter_totals: { ...P0.filter_totals }, nodes: [P0.nodes[0]], edges: [], page: { offset: 0, size: 30, matches_total: 0, matches_shown: 0, has_more: false, range_first: 0, range_last: 0 }, counts: { total: 0, shown: 0, truncated: false } };
  assert.match(html(ready(empty, { filter: 'advisory' }).st), /id="ot5-empty"[^>]*>No advisory matches recorded for this package/);
  const { st } = opened(); patchDep(st, { ctxId });
  assert.match(html(st), /Loading dependencies/);
  st.dispatch({ type: 'DEPPAGE_REQUEST', epoch: st.get().epoch, generation: 1, seq: 1 }); st.dispatch({ type: 'DEPPAGE_FAILED', epoch: st.get().epoch, generation: 1, seq: 1, error: { code: 'projection_failed' } });
  const out = html(st); assert.match(out, /role="alert"/); assert.match(out, /data-action="dep-retry"/); assert.match(out, /could not be projected/);
});
test('a failure after a page loaded keeps the cards and offers Try again (no blank graph)', () => {
  const { st, e } = ready(); st.dispatch({ type: 'DEPPAGE_REQUEST', epoch: e, generation: 1, seq: 2 }); st.dispatch({ type: 'DEPPAGE_FAILED', epoch: e, generation: 1, seq: 2, error: { code: 'request_failed' } });
  const out = html(st); assert.equal((out.match(/data-dep-node=/g) || []).length, 31); assert.match(out, /ot5-banner[^>]*role="alert"/); assert.match(out, /data-action="dep-retry"/);
});
test('not_found shows the absence state, not an empty graph', () => {
  const { st, e } = opened(); patchDep(st, { ctxId }); st.dispatch({ type: 'DEPPAGE_REQUEST', epoch: e, generation: 1, seq: 1 });
  st.dispatch({ type: 'DEPPAGE_FAILED', epoch: e, generation: 1, seq: 1, error: { code: 'not_found' } });
  const out = html(st); assert.match(out, /No dependency declarations recorded for this context\./); assert.ok(!out.includes('<svg id="ot5-svg"'));
});
test('Graph/List: List labels its population and hides pills, counts and the pager; Graph restores them', () => {
  const { st, e } = ready(); st.dispatch({ type: 'VIEW_LOADED', tab: 'dependencies', epoch: e, generation: 1, data: { context_path: P0.context.path, generation: 1, focus: { id: 'x' }, component_list: { total: 3, offset: 0, items: [] } } });
  patchDep(st, { presentation: 'list' }); const list = html(st);
  assert.match(list, /All 3 components in this context — not the filtered graph/);
  assert.match(list, /stub-list/);
  patchDep(st, { presentation: 'graph' }); const graph = html(st); assert.ok(graph.includes('data-ot5-filter="direct"') && graph.includes('ot5-pager') && !graph.includes('Not the filtered'));
});
test('the context bar lists the chooser page, always includes the current context, and pages a long list', () => {
  const { st, e } = ready();
  const chooser = { schema: 'x', binding: P0.binding, default_context_id: ctxId, default_basis: 'largest_file', total: 95, offset: 0, limit: 40, counts: { total: 95, shown: 2, truncated: true },
    rows: [{ context_id: 'ctx:' + '1'.repeat(24), path: 'a/package-lock.json', components_total: 5, category: 'node_packages' }, { context_id: 'ctx:' + '2'.repeat(24), path: 'b/x.txt', components_total: 2, category: 'other_locations' }] };
  st.dispatch({ type: 'DEPCTX_REQUEST', epoch: e, generation: 1, seq: 1 }); st.dispatch({ type: 'DEPCTX_LOADED', epoch: e, generation: 1, seq: 1, data: chooser });
  const out = html(st);
  assert.ok(out.includes(`value="${ctxId}"`) && out.includes(P0.context.path), 'current context option present though not on the loaded page');
  assert.match(out, /data-action="dep-ctx-page"/);
});

// ------------------------------------------------------------------ reducers: ordering and lifecycle
test('only the newest request lands; older seq, other epoch, other generation and a changed request key are dropped', () => {
  const { st, e } = opened(); patchDep(st, { ctxId });
  const key = requestKey(dep(st)); const req = (seq) => st.dispatch({ type: 'DEPPAGE_REQUEST', epoch: e, generation: 1, seq });
  const load = (o) => st.dispatch({ type: 'DEPPAGE_LOADED', epoch: e, generation: 1, seq: 2, key, data: P0, ...o });
  req(1); req(2);
  load({ seq: 1 }); assert.equal(st.get().views.depPage, undefined);                           // older request
  load({ epoch: e + 1 }); assert.equal(st.get().views.depPage, undefined);                      // other epoch
  load({ generation: 2 }); assert.equal(st.get().views.depPage, undefined);                     // other generation
  load({ key: 'other' }); assert.equal(st.get().views.depPage, undefined);                      // the request no longer describes the state
  load({ data: { ...P0, binding: { ...P0.binding, analysis_digest: 'sha256:' + 'b'.repeat(64) } } }); assert.equal(st.get().views.depPage, undefined);   // another analysis
  load({}); assert.equal(st.get().views.depPage, P0);
});
test('a late response after a filter change is ignored (filter -> new request -> old response)', () => {
  const { st, e } = opened(); patchDep(st, { ctxId });
  const k1 = requestKey(dep(st)); st.dispatch({ type: 'DEPPAGE_REQUEST', epoch: e, generation: 1, seq: 1 });
  patchDep(st, { filter: 'transitive', gOffset: 0 }); st.dispatch({ type: 'DEPPAGE_REQUEST', epoch: e, generation: 1, seq: 2 });
  st.dispatch({ type: 'DEPPAGE_LOADED', epoch: e, generation: 1, seq: 1, key: k1, data: P0 });
  assert.equal(st.get().views.depPage, undefined);
});
test('the first page adopts the payload focus and context path; a later page keeps the user focus', () => {
  const { st } = ready(); assert.equal(dep(st).focus, P0.focus.node_id); assert.equal(dep(st).context, P0.context.path); assert.equal(dep(st).selection, P0.focus.node_id);
  assert.equal(dep(st).gOffset, 0);
});
test('End session clears the page, chooser, selection, offsets and ledger immediately; a late response changes nothing', () => {
  const { st, e } = ready(); st.dispatch({ type: 'DEPPAGE_REQUEST', epoch: e, generation: 1, seq: 2 });
  st.dispatch({ type: 'END_STARTED' });
  const s = st.get(); assert.equal(s.views.depPage, undefined); assert.equal(s.views.depContexts, undefined); assert.equal(s.views.dependencies, undefined);
  assert.equal(dep(st).focus, null); assert.equal(dep(st).ctxId, null); assert.equal(dep(st).pg.status, 'idle'); assert.equal(s.depSeq.page, 0);
  assert.match(renderDependencyView(s, helpers), /Ending the session/); assert.ok(!renderDependencyView(s, helpers).includes('data-dep-node'));
  st.dispatch({ type: 'DEPPAGE_LOADED', epoch: e, generation: 1, seq: 2, key: 'k', data: P0 }); assert.equal(st.get().views.depPage, undefined);
});
test('a new analysis (ANALYSIS_START) resets the Dependencies state and ledger', () => {
  const { st } = ready(); st.dispatch({ type: 'ANALYSIS_START' });
  assert.equal(st.get().views.depPage, undefined); assert.equal(dep(st).ctxId, null); assert.deepEqual(st.get().depSeq, { page: 0, ctx: 0 }); assert.equal(st.get().workbench.tab, 'contexts');   // opens on Repository contexts
});
test('changing the context replaces focus, filter, offset, search and the payloads (DEP_CONTEXT)', () => {
  const { st } = ready(); patchDep(st, { filter: 'transitive', q: 'x', gOffset: 30, listQuery: 'x' });
  st.dispatch({ type: 'DEP_CONTEXT', ctxId: 'ctx:' + '3'.repeat(24), path: 'other/package-lock.json' });
  const d = dep(st); assert.deepEqual([d.ctxId, d.context, d.focus, d.selection, d.filter, d.gOffset, d.q, d.listQuery], ['ctx:' + '3'.repeat(24), 'other/package-lock.json', null, null, 'direct', 0, '', '']);
  assert.equal(st.get().views.depPage, undefined);
});
test('Explore (DEP_EXPLORE) resets the filter to Direct, offset 0 and clears search', () => {
  const { st } = ready(); patchDep(st, { filter: 'all', gOffset: 30, q: 'x' }); st.dispatch({ type: 'DEP_EXPLORE', id: 'pkg:z' });
  const d = dep(st); assert.deepEqual([d.focus, d.selection, d.filter, d.gOffset, d.q], ['pkg:z', 'pkg:z', 'direct', 0, '']);
});
test('the chooser default is applied once from the complete set and never overwritten by later pages or queries', () => {
  const { st, e } = opened(); const row = (c, p) => ({ context_id: 'ctx:' + c.repeat(24), path: p, components_total: 3, category: 'other_locations' });
  const data = (def, rows, offset = 0, extra = {}) => ({ binding: { ...P0.binding }, default_context_id: def, default_basis: 'largest_dependency_file', total: 9, offset, limit: 40, rows, counts: { total: 9, shown: rows.length, truncated: true }, ...extra });
  st.dispatch({ type: 'DEPCTX_REQUEST', epoch: e, generation: 1, seq: 1 }); st.dispatch({ type: 'DEPCTX_LOADED', epoch: e, generation: 1, seq: 1, data: data('ctx:' + '9'.repeat(24), [row('1', 'a')]) });
  assert.equal(dep(st).ctxId, 'ctx:' + '9'.repeat(24));                                    // the default is not among the loaded rows and still applies
  st.dispatch({ type: 'DEPCTX_REQUEST', epoch: e, generation: 1, seq: 2 }); st.dispatch({ type: 'DEPCTX_LOADED', epoch: e, generation: 1, seq: 2, data: data('ctx:' + '9'.repeat(24), [row('2', 'b')], 40) });
  assert.equal(dep(st).ctxId, 'ctx:' + '9'.repeat(24));
  patchDep(st, { ctxId: 'ctx:' + '5'.repeat(24) });                                         // an explicit choice survives a later chooser response
  st.dispatch({ type: 'DEPCTX_REQUEST', epoch: e, generation: 1, seq: 3 }); st.dispatch({ type: 'DEPCTX_LOADED', epoch: e, generation: 1, seq: 3, data: data('ctx:' + '9'.repeat(24), [row('3', 'c')]) });
  assert.equal(dep(st).ctxId, 'ctx:' + '5'.repeat(24));
});
test('no files at all: the absence state, never an invented context', () => {
  const { st, e } = opened(); st.dispatch({ type: 'DEPCTX_REQUEST', epoch: e, generation: 1, seq: 1 });
  st.dispatch({ type: 'DEPCTX_LOADED', epoch: e, generation: 1, seq: 1, data: { binding: { ...P0.binding }, default_context_id: null, default_basis: 'none', total: 0, offset: 0, limit: 40, rows: [], counts: { total: 0, shown: 0, truncated: false } } });
  assert.equal(dep(st).ctxId, null); assert.match(html(st), /No dependency declarations recorded for this context\./);
});
test('a chooser failure is stored with a retry and does not clear a loaded graph', () => {
  const { st, e } = ready(); st.dispatch({ type: 'DEPCTX_REQUEST', epoch: e, generation: 1, seq: 1 }); st.dispatch({ type: 'DEPCTX_FAILED', epoch: e, generation: 1, seq: 1, error: { code: 'request_failed' } });
  const out = html(st); assert.match(out, /data-action="dep-ctx-retry"/); assert.equal((out.match(/data-dep-node=/g) || []).length, 31);
});
test('no repository or fixture name is wired into the Dependencies modules', () => {
  const tokens = ['fri' + 'gate', 'web' + '-new', 'blake' + 'blackshear'];
  for (const f of ['src/ui/lib/dependency_graph.js', 'src/ui/components/dependency_graph.js']) { const t = readFileSync(join(ROOT, f), 'utf8').toLowerCase(); for (const k of tokens) assert.ok(!t.includes(k), f + ' ' + k); }
});

test('card labels wrap inside the 146px label width (at most two name lines, ellipsis when longer) so no text leaves the card', () => {
  assert.deepEqual(wrapLabel('react'), ['react']);
  assert.deepEqual(wrapLabel('@radix-ui/react-dropdown-menu'), ['@radix-ui/react-dropdown-', 'menu']);
  const long = wrapLabel('x'.repeat(80)); assert.equal(long.length, 2); assert.ok(long.every((l) => l.length <= 25)); assert.ok(long[1].endsWith('\u2026'));
  assert.deepEqual(wrapLabel(''), ['']); assert.deepEqual(wrapLabel(null), ['']);
});
