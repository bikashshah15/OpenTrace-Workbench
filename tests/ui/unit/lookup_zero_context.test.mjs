// RT-01 correction (independent finding): with an SBOM that holds none of the lockfile packages there is no dependency focus/context, the
// legacy dependency view never loads, and the lookup panel used to be gated on it. These tests drive the REAL reducer and the REAL
// Workbench renderer through the same action sequence app.js dispatches (ANALYSIS_READY -> DEPCTX_* -> LOOKUP_*); they invent no
// SBOM component or dependency context. The end-to-end browser path is tests/ui/browser/run_advisory_checks.mjs.
// Run: node --test tests/ui/unit/        (Node >= 22)
import test from 'node:test';
import assert from 'node:assert/strict';
import { createStore, initial } from '../../../src/ui/lib/store.js';
import { renderWorkbench } from '../../../src/ui/components/workbench.js';

const DIGEST = 'sha256:' + 'a'.repeat(64);
const states = (o) => ({ match: 0, no_match: 0, unavailable: 0, not_looked_up: 0, ...o });
const LOOKUP = (over = {}) => ({ lookup: 'complete', lookup_reason: null, inventory: 'complete', rows: 2, states: states({ match: 1, no_match: 1 }),
  join: { both: 0, sbom_only: 1, inventory_only: 2 }, joined: { rows: 0, match: 0, no_match: 0, unavailable: 0 }, lockfile_only: { rows: 2, match: 1, advisory_groups: 1 },
  counts: { planned_queries: 2, answered: 2, answered_with_advisories: 1, failed: 0, records_fetched: 1, records_failed: 0 }, ...over });
const analysis = (lookup) => ({ generation: 1, identity: { mode: 'live', owner: 'acme', name: 'widget', commit: 'a'.repeat(40), analysis_digest: DIGEST },
  summary: { components: 1, edges: 0, advisory_groups: 0, inventory_checks: 0, checks: [], cards: [], source_checks: [], advisory_lookup: lookup } });
const ROW = { id: 'npm|minimatch|3.1.2', ecosystem: 'npm', name: 'minimatch', version: '3.1.2', state: 'match', state_label: 'Advisory match', join: 'inventory_only',
  reason: null, reason_text: null, sbom_records: 0, inventory_records: 1, locations: ['package-lock.json'], families: [{ key: 'K1', label: 'GHSA-23c5-xmqv-rm74', severity: 'HIGH', summary: 's', withdrawn: false }], has_evidence: true, incomplete: false };
const NOROW = { ...ROW, id: 'npm|ms|2.1.3', name: 'ms', version: '2.1.3', state: 'no_match', families: [], has_evidence: true };
const page = (items, total = items.length) => ({ items, total, page: 0, page_size: 25, summary: LOOKUP() });
const emptyContexts = { binding: { analysis_digest: DIGEST }, offset: 0, total: 0, rows: [], default_context_id: null };

// Exactly what app.js does for a live analysis, minus the network: open, request the context chooser and the lookup table.
function open({ lookup = LOOKUP(), contexts = emptyContexts, data } = {}) {
  const st = createStore(initial());
  st.dispatch({ type: 'ANALYSIS_START' });
  const e = st.get().epoch;
  st.dispatch({ type: 'ANALYSIS_READY', epoch: e, analysis: analysis(lookup) });
  st.dispatch({ type: 'TAB', tab: 'dependencies' });
  const stamp = { epoch: e, generation: 1, seq: 1, key: JSON.stringify(['', 0]) };
  st.dispatch({ type: 'DEPCTX_REQUEST', ...stamp }); st.dispatch({ type: 'DEPCTX_LOADED', ...stamp, data: contexts });
  st.dispatch({ type: 'LOOKUP_STATE', patch: { seq: 1 } });
  if (data) st.dispatch({ type: 'LOOKUP_LOADED', epoch: e, generation: 1, seq: 1, data });
  return { st, e };
}

test('zero joined packages, no dependency context: the lookup panel renders with the lockfile-only match, its evidence link and the scope', () => {
  const { st } = open({ data: page([ROW, NOROW]) });
  const s = st.get();
  assert.equal(s.views.dependencies, undefined, 'precondition: the dependency view never loaded (no focus/context)');
  assert.equal(s.workbench.perTab.dependencies.ctxId, null, 'precondition: no context');
  const html = renderWorkbench(s);
  assert.match(html, /id="ot-adv-lookup"/);
  assert.match(html, /minimatch/); assert.match(html, /Lockfile only/); assert.match(html, /data-action="lookup-evidence"/);
  assert.match(html, /data-action="lookup-state" data-state="match"/);                       // the filter is reachable
  assert.match(html, /1 lockfile-only package with advisory matches/);                       // inventory_only is distinguished and counted separately
  assert.match(html, /0 in both inventories · 1 SBOM only · 2 lockfile only \(1 with advisory matches\)/);
  assert.match(html, /Repository-wide:<\/strong> these rows cover every lockfile version in this analysis; they are not filtered by, or attributed to, the selected context or package/);
  assert.match(html, /Complete covers the planned lockfile queries only; it does not mean the SBOM lists every package/);
  assert.match(html, /Reachability and exploitability are not established/);
  assert.doesNotMatch(html, /Loading source contexts/);                                     // a loaded, empty chooser is not "still loading"
  assert.match(html, /No source contexts in this analysis/);
});

test('the panel distinguishes loading, empty, failed and unavailable instead of staying blank or loading forever', () => {
  const loading = renderWorkbench(open().st.get());
  assert.match(loading, /id="ot-adv-lookup"/); assert.match(loading, /role="status">Loading…/);
  const empty = renderWorkbench(open({ lookup: LOOKUP({ rows: 0, states: states({}), join: { both: 0, sbom_only: 0, inventory_only: 0 }, lockfile_only: { rows: 0, match: 0, advisory_groups: 0 } }), data: page([]) }).st.get());
  assert.match(empty, /The lookup produced no rows: no lockfile package versions were looked up/);
  const f = open(); f.st.dispatch({ type: 'LOOKUP_FAILED', epoch: f.e, seq: 1, message: 'request failed' });
  assert.match(renderWorkbench(f.st.get()), /role="alert">The lookup table could not be loaded \(request failed\)/);
  const un = renderWorkbench(open({ lookup: LOOKUP({ lookup: 'unavailable', lookup_reason: 'network_error', states: states({ unavailable: 2 }), lockfile_only: { rows: 2, match: 0, advisory_groups: 0 } }), data: page([{ ...ROW, state: 'unavailable', reason: 'network_error', reason_text: 'the advisory source could not be reached', families: [], has_evidence: false }]) }).st.get());
  assert.match(un, /Advisory lookup unavailable/); assert.match(un, /No advisory match and no “no match” claim is made/);
  assert.doesNotMatch(un, /1 lockfile-only package with advisory matches/);               // nothing is claimed when the lookup did not answer
});

test('normal joined case still works: the panel renders next to a loaded dependency view', () => {
  const joined = { ...ROW, join: 'both', sbom_records: 1, locations: ['package-lock.json'] };
  const { st, e } = open({ lookup: LOOKUP({ join: { both: 1, sbom_only: 0, inventory_only: 1 }, joined: { rows: 1, match: 1, no_match: 0, unavailable: 0 }, lockfile_only: { rows: 1, match: 0, advisory_groups: 0 } }), data: page([joined, NOROW]) });
  st.dispatch({ type: 'VIEW_LOADED', tab: 'dependencies', epoch: e, generation: 1, seq: 1, data: { generation: 1, context_path: 'package-lock.json', focus: { id: 'f' }, advisories: { items: [], total: 0, page: 0, page_size: 25 } } });
  const html = renderWorkbench(st.get());
  assert.match(html, /id="ot-adv-lookup"/); assert.match(html, /In SBOM and lockfile/);
  assert.doesNotMatch(html, /lockfile-only package/);                                       // no lockfile-only note when none matched
});

test('captured analyses and a service without lookup are unchanged: no live lookup panel without lookup data', () => {
  const st = createStore(initial()); st.dispatch({ type: 'ANALYSIS_START' });
  const a = analysis(null); a.identity.mode = 'captured';
  st.dispatch({ type: 'ANALYSIS_READY', epoch: st.get().epoch, analysis: a }); st.dispatch({ type: 'TAB', tab: 'dependencies' });
  assert.doesNotMatch(renderWorkbench(st.get()), /ot-adv-lookup|ot-adv-live/);
  const live = createStore(initial()); live.dispatch({ type: 'ANALYSIS_START' });
  live.dispatch({ type: 'ANALYSIS_READY', epoch: live.get().epoch, analysis: analysis(null) }); live.dispatch({ type: 'TAB', tab: 'dependencies' });
  assert.doesNotMatch(renderWorkbench(live.get()), /ot-adv-lookup/);
});

test('request guards: a late lookup response cannot repopulate an ended session or overwrite a newer analysis; End session clears the results', () => {
  const { st, e } = open({ data: page([ROW]) });
  assert.equal(st.get().advLookup.data.items.length, 1);
  st.dispatch({ type: 'END_STARTED' }); st.dispatch({ type: 'ENDED', state: 'deleted_verified' });
  assert.equal(st.get().advLookup.data, null, 'End session clears the lookup results');
  assert.equal(renderWorkbench(st.get()), '');
  st.dispatch({ type: 'LOOKUP_LOADED', epoch: e, generation: 1, seq: 1, data: page([ROW]) });   // a response that arrives after End session
  assert.equal(st.get().advLookup.data, null);
  // a newer analysis: the old response (older epoch / older seq) is ignored
  st.dispatch({ type: 'ANALYSIS_START' }); const e2 = st.get().epoch;
  st.dispatch({ type: 'ANALYSIS_READY', epoch: e2, analysis: analysis(LOOKUP()) });
  st.dispatch({ type: 'LOOKUP_STATE', patch: { seq: 5 } });
  st.dispatch({ type: 'LOOKUP_LOADED', epoch: e, generation: 1, seq: 5, data: page([ROW]) });   // old epoch
  st.dispatch({ type: 'LOOKUP_LOADED', epoch: e2, generation: 1, seq: 4, data: page([ROW]) });  // old request
  assert.equal(st.get().advLookup.data, null);
  st.dispatch({ type: 'LOOKUP_LOADED', epoch: e2, generation: 1, seq: 5, data: page([NOROW]) });
  assert.equal(st.get().advLookup.data.items[0].name, 'ms');
});
