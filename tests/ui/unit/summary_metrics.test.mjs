// UIP-02 §4.1: the four pills come from the active analysis only (pure adapter; no backend change).
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { summaryMetrics } from '../../../src/ui/lib/summary_metrics.js';

const sm = (over = {}) => ({ components: 12, edges: 30, advisory_groups: 4, advisory_rows: 9, inventory_checks: 2, checks: [], ...over });
const by = (list, key) => list.find((m) => m.key === key);
const keys = ['components', 'edges', 'advisory_groups', 'bom_review'];
const gaps = (candidates, over = {}) => ({ status: 'compared', totals: { candidates }, ...over });

test('four entries in the fixed order with the existing labels', () => {
  const m = summaryMetrics({ identity: { mode: 'captured' }, summary: sm() });
  assert.deepEqual(m.map((x) => x.key), keys);
  assert.deepEqual(m.map((x) => x.label), ['Component records', 'Declared dependency edges', 'Advisory groups matched', 'BOM connections']);
  assert.deepEqual(m.map((x) => x.value), [12, 30, 4, null]);   // no comparison in this summary: not a zero
});

test('captured case: captured advisory evidence, not a live lookup, with or without lookup metadata', () => {
  for (const extra of [{}, { advisory_lookup: null }]) {
    const a = by(summaryMetrics({ identity: { mode: 'captured' }, summary: sm(extra) }), 'advisory_groups');
    assert.equal(a.state, 'captured'); assert.equal(a.value, 4);
    assert.match(a.reason, /captured advisory evidence/i); assert.match(a.reason, /not a live lookup/i); assert.match(a.reason, /complete coverage/i);
  }
});

test('live: lookup not run, unavailable, partial, complete', () => {
  const live = { mode: 'live' };
  let a = by(summaryMetrics({ identity: live, summary: sm() }), 'advisory_groups');
  assert.deepEqual([a.state, a.value, a.reason], ['not_run', null, 'advisory matching not run']);
  a = by(summaryMetrics({ identity: live, summary: sm({ advisory_lookup: { lookup: 'unavailable', lookup_reason: 'network_error' } }) }), 'advisory_groups');
  assert.equal(a.state, 'unavailable'); assert.equal(a.value, null); assert.match(a.reason, /could not be reached/);
  a = by(summaryMetrics({ identity: live, summary: sm({ advisory_lookup: { lookup: 'partial', counts: { answered: 3, planned_queries: 5 } } }) }), 'advisory_groups');
  assert.equal(a.state, 'partial'); assert.equal(a.value, 4); assert.match(a.reason, /3 of 5/);
  a = by(summaryMetrics({ identity: live, summary: sm({ advisory_lookup: { lookup: 'complete' } }) }), 'advisory_groups');
  assert.equal(a.state, 'live_complete'); assert.equal(a.value, 4); assert.match(a.reason, /live OSV lookup/);
});

test('missing, non-finite and non-integer values are null with a reason, never 0', () => {
  for (const bad of [undefined, null, NaN, Infinity, -1, 1.5, '7']) {
    const m = summaryMetrics({ identity: { mode: 'captured' }, summary: sm({ components: bad, edges: bad, advisory_groups: bad, gaps: { status: 'compared', totals: { candidates: bad } } }) });
    for (const e of m) { assert.equal(e.value, null, String(bad) + e.key); assert.match(e.reason, /not available in this analysis|BOM comparison|no BOM comparison/i); }
  }
  assert.equal(summaryMetrics(null).every((e) => e.value === null), true);
});

test('BOM connections badge: unfiltered candidate total, singular, zero, partial', () => {
  const run = (g, mode = 'captured') => by(summaryMetrics({ identity: { mode }, summary: sm({ inventory_checks: 0, gaps: g }) }), 'bom_review');
  for (const mode of ['captured', 'live']) {
    let b = run(gaps(97), mode); assert.deepEqual([b.value, b.text, b.state, b.bare], [97, 'items to review in BOM connections', 'measured', undefined]);
    b = run(gaps(1), mode); assert.equal(b.text, 'item to review in BOM connections');
    b = run(gaps(0), mode); assert.deepEqual([b.text, b.state, b.bare], ['No items flagged in the checked scope', 'zero', true]);
  }
  const c = { collection: { software: { state: 'partial' }, cryptography: { state: 'completed' }, ai_model: { state: 'not_run' } } };
  let b = run(gaps(5, c)); assert.equal(b.short, 'Partial coverage'); assert.equal(b.value, 5);
  b = run(gaps(0, c)); assert.equal(b.short, 'Partial coverage'); assert.equal(b.text, 'No items flagged in the checked scope');
  assert.equal(run(gaps(5, { collection: { software: { state: 'completed' } } })).short, null);
  assert.equal(by(summaryMetrics({ identity: { mode: 'captured' }, summary: sm({ gaps: gaps(97), inventory_checks: 0 }) }), 'bom_review').value, 97);   // never the assessed-check count
});
test('BOM connections badge: skipped, failed, unavailable are stated, never a zero', () => {
  const run = (g) => by(summaryMetrics({ identity: { mode: 'live' }, summary: sm({ gaps: g }) }), 'bom_review');
  assert.equal(run({ status: 'not_compared', code: 'collection_not_run', message: 'm' }).text, 'BOM comparison not run');
  assert.equal(run(undefined).text, 'BOM comparison not run');
  for (const code of ['collector_failed', 'inventory_unavailable', 'no_requirement_files']) { const b = run({ status: 'not_compared', code, message: 'm' }); assert.deepEqual([b.text, b.state, b.value], ['BOM comparison unavailable', 'unavailable', null]); }
});
test('advisory badge: short cues; lockfile-only packages stay separate from the group count', () => {
  const live = { mode: 'live' };
  let a = by(summaryMetrics({ identity: live, summary: sm({ advisory_groups: 44, advisory_lookup: { lookup: 'complete', lockfile_only: { match: 2 } } }) }), 'advisory_groups');
  assert.deepEqual([a.value, a.short], [44, '2 lockfile-only packages']);
  a = by(summaryMetrics({ identity: live, summary: sm({ advisory_groups: 44, advisory_lookup: { lookup: 'complete', lockfile_only: { match: 1 } } }) }), 'advisory_groups'); assert.equal(a.short, '1 lockfile-only package');
  a = by(summaryMetrics({ identity: live, summary: sm({ advisory_lookup: { lookup: 'complete' } }) }), 'advisory_groups'); assert.equal(a.short, null);
  a = by(summaryMetrics({ identity: live, summary: sm({ advisory_lookup: { lookup: 'partial', lockfile_only: { match: 2 }, counts: { answered: 3, planned_queries: 5 } } }) }), 'advisory_groups'); assert.equal(a.short, 'partial lookup \u00b7 2 lockfile-only packages'); assert.equal(a.value, 4);
  assert.equal(by(summaryMetrics({ identity: live, summary: sm() }), 'advisory_groups').short, 'not run');
  a = by(summaryMetrics({ identity: live, summary: sm({ advisory_lookup: { lookup: 'not_run' } }) }), 'advisory_groups');   // an explicit not_run is not a completed lookup
  assert.deepEqual([a.state, a.value, a.short, a.reason], ['not_run', null, 'not run', 'advisory matching not run']);
  a = by(summaryMetrics({ identity: live, summary: sm({ advisory_lookup: { lookup: 'complete', lockfile_only: { match: 0 } } }) }), 'advisory_groups'); assert.equal(a.short, null);
  assert.equal(by(summaryMetrics({ identity: live, summary: sm({ advisory_lookup: { lookup: 'unavailable' } }) }), 'advisory_groups').short, 'unavailable');
});

test('lookup state comes from the analysis, not service configuration', () => {
  const analysis = { identity: { mode: 'live' }, summary: sm({ advisory_lookup: { lookup: 'complete' } }) };
  const before = JSON.stringify(summaryMetrics(analysis));
  globalThis.CONFIG = { live: { enabled: false, advisories: { enabled: false } } };
  assert.equal(JSON.stringify(summaryMetrics(analysis)), before);
  delete globalThis.CONFIG;
});

test('a non-Frigate analysis shows its own numbers and no Frigate constant is in production UI code', () => {
  const m = summaryMetrics({ identity: { mode: 'live', name: 'other' }, summary: sm({ components: 7, edges: 3, advisory_groups: 0, gaps: gaps(3), advisory_lookup: { lookup: 'complete' } }) });
  assert.deepEqual(m.map((x) => x.value), [7, 3, 0, 3]);
  // The pills and shells are data-driven; captured Frigate demo copy in lib/copy.js is existing, separately owned text.
  const files = ['src/ui/lib/summary_metrics.js', 'src/ui/components/workbench.js', 'src/ui/components/intake.js', 'src/ui/components/inspector.js', 'src/ui/lib/inspector_model.js'];
  for (const p of files) {
    let t; try { t = readFileSync(p, 'utf8'); } catch { continue; }
    for (const lit of ['1,989', '5,483', '1989', '5483']) assert.equal(t.includes(lit), false, p + ' contains ' + lit);
  }
});

test('RT-01: a zero SBOM-linked count carries the lockfile-only match count and is not inflated', () => {
  const adv = { lookup: 'complete', lockfile_only: { rows: 3, match: 3, advisory_groups: 2 } };
  const a = by(summaryMetrics({ identity: { mode: 'live' }, summary: sm({ advisory_groups: 0, advisory_lookup: adv }) }), 'advisory_groups');
  assert.equal(a.value, 0);
  assert.match(a.scope, /SBOM-linked/);
  assert.match(a.reason, /plus 3 lockfile-only packages with advisory matches not linked to an SBOM component/);
  const p = by(summaryMetrics({ identity: { mode: 'live' }, summary: sm({ advisory_groups: 0, advisory_lookup: { ...adv, lookup: 'partial', counts: { answered: 2, planned_queries: 4 } } }) }), 'advisory_groups');
  assert.match(p.reason, /partial lookup/); assert.match(p.reason, /plus 3 lockfile-only/);
  const none = by(summaryMetrics({ identity: { mode: 'live' }, summary: sm({ advisory_lookup: { lookup: 'complete', lockfile_only: { match: 0 } } }) }), 'advisory_groups');
  assert.doesNotMatch(none.reason, /lockfile-only/);
});
