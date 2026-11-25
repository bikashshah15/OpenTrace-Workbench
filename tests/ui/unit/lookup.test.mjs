// I5B: how the Workbench shows a match, no match and an unavailable lookup — and that a failed lookup is never drawn as "no match".
// The renderers are pure strings and the reducer is pure, so no browser or network is involved.
// Run: node --test tests/ui/unit/        (Node >= 22)
import test from 'node:test';
import assert from 'node:assert/strict';
import { createStore, initial } from '../../../src/ui/lib/store.js';
import { panel, banner, chips, row, evidenceHtml } from '../../../src/ui/components/lookup.js';

const states = (o) => ({ match: 0, no_match: 0, unavailable: 0, not_looked_up: 0, ...o });
const summary = (over) => ({ lookup: 'complete', lookup_reason: null, inventory: 'complete', rows: 6, states: states({ match: 1, no_match: 3, not_looked_up: 2 }),
  join: { both: 4, sbom_only: 1, inventory_only: 1 }, counts: { planned_queries: 4, answered: 4, answered_with_advisories: 1, failed: 0, records_fetched: 1, records_failed: 0 }, ...over });
const R = (o) => ({ id: 'npm|ms|2.1.3', ecosystem: 'npm', name: 'ms', version: '2.1.3', state: 'no_match', join: 'both', reason: null, reason_text: null, locations: ['package-lock.json'], families: [], has_evidence: true, ...o });
const state = (sum, data) => ({ analysis: { summary: { advisory_lookup: sum } }, advLookup: { state: null, q: '', page: 0, data, error: null } });
const page = (items, total = items.length) => ({ items, total, page: 0, page_size: 25 });

test('a failed lookup shows an alert, says no claim is made, and counts nothing as no match', () => {
  const sum = summary({ lookup: 'unavailable', lookup_reason: 'network_error', states: states({ unavailable: 4, not_looked_up: 2 }), counts: { planned_queries: 4, answered: 0, answered_with_advisories: 0, failed: 4 } });
  const html = panel(state(sum, page([R({ state: 'unavailable', reason: 'network_error', has_evidence: false }), R({ id: 'x', name: 'minimatch', version: '3.1.2', state: 'unavailable', reason: 'network_error', has_evidence: false })])));
  assert.match(html, /role="alert"/);
  assert.match(html, /Advisory lookup unavailable/);
  assert.match(html, /The advisory source could not be reached\./);
  assert.match(html, /No advisory match and no “no match” claim is made/);
  assert.match(html, /Lookup unavailable <b>4<\/b>/);
  assert.match(html, /No advisory returned <b>0<\/b>/);
  assert.equal((html.match(/class="ot-state unavailable"/g) || []).length, 2);
  assert.doesNotMatch(html, /class="ot-state ok"/);               // nothing is drawn as "no advisory returned"
  assert.doesNotMatch(html, /data-action="lookup-evidence"/);      // there is no evidence to open for a failed query
});

test('a partial lookup keeps answered and unanswered versions apart', () => {
  const sum = summary({ lookup: 'partial', states: states({ match: 1, no_match: 1, unavailable: 2, not_looked_up: 2 }), counts: { planned_queries: 4, answered: 2, answered_with_advisories: 1, failed: 2, records_failed: 1 } });
  const b = banner(sum);
  assert.match(b, /Partial advisory lookup/);
  assert.match(b, /2 of 4 versions were answered; 2 are shown as “Lookup unavailable” and 1 advisory record could not be fetched/);
  assert.match(b, /not reported as having no advisories/);
});

test('match, no match and not looked up are three different labels with their own wording', () => {
  const m = row(R({ name: 'minimatch', version: '3.1.2', state: 'match', families: [{ key: 'CVE-2026-27904', label: 'CVE-2026-27904', severity: 'HIGH', summary: 's' }] }));
  assert.match(m, /Advisory match/); assert.match(m, /data-action="read-advisory"/); assert.match(m, /data-action="lookup-evidence"/); assert.match(m, /HIGH/);
  const n = row(R());
  assert.match(n, /No advisory returned/); assert.doesNotMatch(n, /read-advisory/);
  const u = row(R({ id: 'u', name: 'sbomonly', state: 'not_looked_up', join: 'sbom_only', reason: 'not_in_lockfile_inventory', reason_text: 'The SBOM lists this component but no parsed lockfile row asked for it.', has_evidence: false }));
  assert.match(u, /Not looked up/); assert.match(u, /SBOM only/); assert.match(u, /no parsed lockfile row asked for it/);
});

test('the completed banner states what "no advisory returned" does not mean; the panel repeats that reachability is not established', () => {
  assert.match(banner(summary()), /not a statement that the package is safe/);
  assert.match(panel(state(summary(), page([R()]))), /Reachability and exploitability are not established/);
});

test('hostile package text is escaped', () => {
  const html = row(R({ name: '<img src=x onerror=alert(1)>', version: '"><script>1</script>' }));
  assert.doesNotMatch(html, /<img src=x/); assert.doesNotMatch(html, /<script>/);
});

test('filter chips carry counts and mark the active filter', () => {
  const c = chips(summary(), 'unavailable');
  assert.match(c, /data-state="unavailable" aria-pressed="true"/);
  assert.match(c, /data-state="match" aria-pressed="false"/);
});

test('evidence view shows the exact query, the answer slot, the digests and what is not established', () => {
  const html = evidenceHtml({ name: 'minimatch', version: '3.1.2', state_label: 'Advisory match', match_basis: 'ecosystem, normalized package name and version equal in the SBOM component and the lockfile inventory row',
    not_established: 'Reachability and exploitability are not established.', sbom: [{ purl: 'pkg:npm/minimatch@3.1.2' }], inventory: [{ path: 'package-lock.json', locator: '/packages/node_modules/minimatch', direct: true }],
    evidence: { query: { package: { name: 'minimatch', ecosystem: 'npm' }, version: '3.1.2' }, source: 'OSV (api.osv.dev) POST /v1/querybatch', queried_at: '2026-11-05T12:00:00Z', truncated: false,
      response_slot: { vulns: [{ id: 'GHSA-23c5-xmqv-rm74' }] }, exchange: { status: 200, request_sha256: 'a'.repeat(64), response_sha256: 'b'.repeat(64), bytes: 120 },
      records: [{ id: 'GHSA-23c5-xmqv-rm74', sha256: 'c'.repeat(64) }, { id: 'GHSA-x', sha256: null, unavailable: 'network_error' }] } });
  assert.match(html, /&quot;name&quot;: &quot;minimatch&quot;/); assert.match(html, /GHSA-23c5-xmqv-rm74/);
  assert.match(html, new RegExp('b'.repeat(64))); assert.match(html, /record not fetched \(the advisory source could not be reached\)/);
  assert.match(html, /package-lock\.json/); assert.match(html, /Not established:<\/strong> Reachability/);
});

// ---- reducer: stale responses never reach the table
function open() {
  const store = createStore(initial());
  store.dispatch({ type: 'ANALYSIS_START' });
  const epoch = store.get().epoch;
  store.dispatch({ type: 'ANALYSIS_READY', epoch, analysis: { generation: 1, identity: {}, summary: { advisory_lookup: summary() } } });
  return { store, epoch };
}

test('REDUCER: only the newest lookup request for the current generation lands', () => {
  const { store, epoch } = open();
  store.dispatch({ type: 'LOOKUP_STATE', patch: { seq: 1 } });
  store.dispatch({ type: 'LOOKUP_STATE', patch: { seq: 2, state: 'match' } });
  store.dispatch({ type: 'LOOKUP_LOADED', epoch, generation: 1, seq: 1, data: { marker: 'old' } });
  assert.equal(store.get().advLookup.data, null);
  store.dispatch({ type: 'LOOKUP_LOADED', epoch, generation: 2, seq: 2, data: { marker: 'other generation' } });
  assert.equal(store.get().advLookup.data, null);
  store.dispatch({ type: 'LOOKUP_LOADED', epoch, generation: 1, seq: 2, data: { marker: 'new' } });
  assert.equal(store.get().advLookup.data.marker, 'new');
});

test('REDUCER: a load failure is stored, shown as an alert, and a new analysis clears it', () => {
  const { store, epoch } = open();
  store.dispatch({ type: 'LOOKUP_STATE', patch: { seq: 1 } });
  store.dispatch({ type: 'LOOKUP_FAILED', epoch, seq: 1, message: 'stale_generation' });
  assert.equal(store.get().advLookup.error, 'stale_generation');
  assert.match(panel(store.get()), /The lookup table could not be loaded \(stale_generation\)/);
  store.dispatch({ type: 'ANALYSIS_START' });
  assert.equal(store.get().advLookup.error, null);
  assert.equal(store.get().advLookup.state, null);
});

test('REDUCER: a live analysis starts from all contexts, not the Frigate default context', () => {
  const store = createStore(initial());
  store.dispatch({ type: 'ANALYSIS_START' });
  store.dispatch({ type: 'ANALYSIS_READY', epoch: store.get().epoch, analysis: { generation: 1, identity: { mode: 'live' }, summary: {} } });
  assert.equal(store.get().workbench.perTab.dependencies.context, null);
});

// The graph legend needs a full graph payload to render, so this guards the wording at the source: every legend entry and the
// footnote that names a match is conditional on the live mode, and the captured wording is kept for the captured demo.
import { readFileSync } from 'node:fs';
test('LEGEND: live analyses say "live advisory match"; the captured demo keeps the captured wording', () => {
  const src = readFileSync(new URL('../../../src/ui/components/workbench.js', import.meta.url), 'utf8');
  assert.equal((src.match(/isLive\(s\) \? 'Live advisory match' : 'Advisory match'/g) || []).length, 2);
  assert.match(src, /isLive\(s\) \? 'live advisory match from this analysis\\u2019s OSV lookup' : 'captured package-version advisory match'/);
  assert.doesNotMatch(src, /<i class="match"><\/i>Advisory match/);
});

test('page limit: an incomplete match is flagged on the row and in the partial banner; an unavailable one says why', () => {
  assert.match(row(R({ state: 'match', incomplete: true, families: [{ key: 'k', label: 'k', severity: null }] })), /Incomplete: the page limit was reached, so more advisories may exist/);
  assert.match(banner(summary({ lookup: 'partial', counts: { planned_queries: 4, answered: 4, failed: 0, incomplete_answers: 1 } })), /1 match is incomplete: the page limit was reached/);
  assert.match(row(R({ state: 'unavailable', reason: 'page_limit_reached', reason_text: null, has_evidence: false })), /the page limit was reached before any advisory was seen/);
});

test('RT-01: zero SBOM-linked rows with lockfile-only matches still shows the matches and their scope', () => {
  const sum = summary({ rows: 3, states: states({ match: 3, no_match: 0 }), join: { both: 0, sbom_only: 0, inventory_only: 3 }, joined: { rows: 0, match: 0, no_match: 0, unavailable: 0 },
    lockfile_only: { rows: 3, match: 3, advisory_groups: 2 }, counts: { planned_queries: 3, answered: 3, answered_with_advisories: 3, failed: 0 } });
  const lockRow = R({ name: 'minimatch', version: '10.2.6', state: 'match', join: 'inventory_only', families: [{ key: 'K', label: 'GHSA-x', severity: 'HIGH', summary: 's' }] });
  const html = panel(state(sum, page([lockRow])));
  assert.match(html, /3 lockfile-only packages with advisory matches/);
  assert.match(html, /not<\/em> linked to an SBOM component/);
  assert.match(html, /not in the SBOM-linked headline count/);
  assert.match(html, /does not mean the SBOM lists every package/);
  assert.match(html, /0 in both inventories · 0 SBOM only · 3 lockfile only \(3 with advisory matches\)/);
  assert.match(html, /Advisory match/); assert.match(html, /Lockfile only/); assert.match(html, /data-action="lookup-evidence"/);
  assert.doesNotMatch(banner(summary()), /lockfile-only package/);   // no note when there are none
});
