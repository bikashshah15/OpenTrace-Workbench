// UIP-02: default tab, compact opening, relocation, inspector shell + adapters, session status. Pure string renderers and the
// pure reducer: no browser, network or service. Run: node --test tests/ui/unit/
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { createStore, initial, freshWorkbench } from '../../../src/ui/lib/store.js';
import { renderWorkbench } from '../../../src/ui/components/workbench.js';
import { renderEvidence } from '../../../src/ui/components/evidence.js';
import { renderAnalyze, liveStatusText } from '../../../src/ui/components/intake.js';
import { renderInspector } from '../../../src/ui/components/inspector.js';
import { fromBoundInspector, fromSelection, stateMeta, STATE_META } from '../../../src/ui/lib/inspector_model.js';

// ------------------------------------------------------------------ fixtures
const check = (id, state = 'contradicted') => ({ assertion_id: id, rule_id: 'rule/1', state, category: 'x', reason_codes: [], rationale: 'because', bounded_meaning: 'bounded', next_action: null, not_established: ['coverage'], used_evidence: [{ evidence_id: 'ev1', role: 'declaration' }], excluded_evidence: [] });
const demoAnalysis = (over = {}) => ({
  generation: 1, identity: { mode: 'captured', owner: 'acme', name: 'widget', commit: 'abcdef0123456789abcdef0123456789abcdef01', analysis_digest: 'sha256:' + 'a'.repeat(64) },
  summary: { components: 12, edges: 30, advisory_groups: 4, inventory_checks: 1, checks: [check('p5-requirement-represented-in-inventory')], cards: [] , ...over },
});
// UIP-04: the Contexts view is the merged opentrace.workbench.contexts/1 payload (was the legacy rows shape); the root opening selection is `root`.
const GRP_WEB = 'grp:' + 'b'.repeat(24); const GRP_UNL = 'grp:' + 'c'.repeat(24);
const ctxView = { schema: 'opentrace.workbench.contexts/1', edge_semantics: 'grouping_or_inventory_location', selected_id: null, counts: { total: 2, shown: 2, truncated: false },
  binding: { analysis_digest: 'sha256:' + 'a'.repeat(64), generation: 1, mode: 'captured', commit_sha: 'abcdef0123456789abcdef0123456789abcdef01', repository: { host: 'github.com', owner: 'acme', name: 'widget', canonical_url: 'https://github.com/acme/widget' }, requested_ref: { kind: 'tag', text: 'v1' }, assessment: null },
  root: { name: 'acme/widget', canonical_url: 'https://github.com/acme/widget', commit_sha: 'abcdef0123456789abcdef0123456789abcdef01', distinct_total: 7, membership_total: 5, located_distinct_total: 5, unlocated_total: 2 },
  groups: [
    { group_id: GRP_WEB, kind: 'located', category: 'web', token: 'green', label: 'Web application', basis: 'path_prefix', distinct_total: 5, membership_total: 5, files_offset: 0, files_counts: { total: 1, shown: 1, truncated: false },
      files: [{ file_id: 'ctx:a', path: 'web/package-lock.json', raw_locations: ['web/package-lock.json'], raw_locations_total: 1, normalization_basis: ['path'], distinct_total: 5, membership_total: 5, dependency_context_id: 'ctx:a', revision_link: { href: 'https://github.com/acme/widget/blob/abcdef0123456789abcdef0123456789abcdef01/web/package-lock.json', text: 'web/package-lock.json' } }] },
    { group_id: GRP_UNL, kind: 'unlocated', category: null, token: 'neutral', label: 'Unlocated components', basis: 'fallback', distinct_total: 2, membership_total: 2, files: [], files_offset: 0, files_counts: { total: 0, shown: 0, truncated: false } }] };
function state(over = {}) {
  const s = initial(); const base = { ...s, analysis: demoAnalysis(), destination: 'workbench', views: { contexts: ctxView }, workbench: freshWorkbench(false), evidence: { artifacts: [], records: [], preview: null } };
  return { ...base, ...over };
}
const sel = (s, tab, selection) => ({ ...s, workbench: { ...s.workbench, perTab: { ...s.workbench.perTab, [tab]: { ...s.workbench.perTab[tab], selection } } } });

// ------------------------------------------------------------------ 1 default tab
test('every way of opening an analysis lands on Repository contexts', () => {
  assert.equal(freshWorkbench(false).tab, 'contexts'); assert.equal(freshWorkbench(true).tab, 'contexts');
  const store = createStore(initial());
  const open = () => { store.dispatch({ type: 'ANALYSIS_START' }); const e = store.get().epoch; store.dispatch({ type: 'ANALYSIS_READY', epoch: e, analysis: demoAnalysis() }); return e; };
  let e = open(); assert.equal(store.get().workbench.tab, 'contexts');
  store.dispatch({ type: 'TAB', tab: 'crypto' });
  e = open(); assert.equal(store.get().workbench.tab, 'contexts', 'a new scan/demo resets the tab');
  store.dispatch({ type: 'TAB', tab: 'ai' });
  store.dispatch({ type: 'END_STARTED' }); store.dispatch({ type: 'ENDED', result: 'deleted_verified' });
  e = open(); assert.equal(store.get().workbench.tab, 'contexts', 'after Reset');
});

test('a Dependencies preload does not select that tab and a stale epoch cannot change the tab', () => {
  const store = createStore(initial());
  store.dispatch({ type: 'ANALYSIS_START' }); const e = store.get().epoch;
  store.dispatch({ type: 'ANALYSIS_READY', epoch: e, analysis: demoAnalysis() });
  store.dispatch({ type: 'VIEW_LOADED', tab: 'dependencies', epoch: e, generation: 1, seq: 1, data: { context_path: 'web/package-lock.json', generation: 1, focus: { id: 'f' } } });
  assert.equal(store.get().workbench.tab, 'contexts');
  store.dispatch({ type: 'TAB', tab: 'dependencies' }); store.dispatch({ type: 'TAB_STATE', tab: 'dependencies', patch: { search: 'q' } });
  store.dispatch({ type: 'TAB', tab: 'contexts' }); store.dispatch({ type: 'TAB', tab: 'dependencies' });
  assert.equal(store.get().workbench.perTab.dependencies.search, 'q', 'per-tab state survives tab switching');
  store.dispatch({ type: 'ANALYSIS_START' });
  store.dispatch({ type: 'VIEW_LOADED', tab: 'dependencies', epoch: e, generation: 1, seq: 2, data: { generation: 1 } });
  assert.equal(store.get().workbench.tab, 'contexts', 'an old-epoch response is discarded');
});

// ------------------------------------------------------------------ 2 compact opening + relocation
const GONE = ['ot-demo-guide', 'ot-step-copy', 'ot-identity', 'Inspect this repository. Follow the evidence.', 'data-action="export"', 'Export captured case', 'Export assessment', 'Source inspection only', 'id="ot-findings"', 'Inventory checks', 'class="ot-note"', 'follow the evidence'];
const WANT = ['id="ot2-enrichment"', 'class="ot2-summary-pills"', 'Repository graphs', 'role="tablist"', 'id="ot-tab-contexts"', 'aria-selected="true"'];
for (const mode of ['captured', 'live']) {
  test(`compact opening (${mode}): clutter absent, pills/tabs present, checks live in Evidence`, () => {
    const a = demoAnalysis(); a.identity.mode = mode;
    if (mode === 'live') { a.summary.advisory_lookup = { lookup: 'complete' }; a.summary.source_checks = []; }
    const s = state({ analysis: a });
    const html = renderWorkbench(s);
    for (const g of GONE) assert.equal(html.includes(g), false, `Workbench still contains: ${g}`);
    for (const w of WANT) assert.ok(html.includes(w), `Workbench lacks: ${w}`);
    assert.equal((html.match(/<li data-metric=/g) || []).length, 4);
    assert.match(html, /data-tab="contexts"[^>]*>|id="ot-tab-contexts"[^>]*aria-selected="true"/);
    const ev = renderEvidence(s);
    assert.ok(ev.includes('id="ot-findings"') && ev.includes('Inventory checks'), 'Inventory checks moved to Evidence');
    assert.ok(ev.includes('data-action="open-check"'), 'check cards keep their open-check action');
  });
}

test('pills render the adapter values, an honest dash and a reason, never a fabricated zero', () => {
  const a = demoAnalysis({ components: 7, edges: 3, advisory_groups: undefined, inventory_checks: 0 }); a.identity.mode = 'live';
  const html = renderWorkbench(state({ analysis: a }));
  assert.match(html, /data-metric="advisory_groups" data-state="not_run"[^>]*><strong>\u2014<\/strong> advisory groups matched <small>\u00b7 not run<\/small><span class="sr-only">advisory matching not run<\/span>/);
  assert.doesNotMatch(html, /BOM inventory checks|0 BOM/);
  assert.match(html, /data-metric="components"[^>]*><strong>7<\/strong>/);
  assert.match(html, /data-metric="bom_review" data-state="not_run"[^>]*>BOM comparison not run/);   // no gaps in this analysis: stated, not a zero
});

test('advisory pill: a complete lookup with no lockfile-only matches shows only the count; the note appears when they exist', () => {
  const pill = (L) => renderWorkbench(state({ analysis: { ...demoAnalysis({ advisory_lookup: L }), identity: { ...demoAnalysis().identity, mode: 'live' } } })).match(/<li data-metric="advisory_groups"[^>]*>[\s\S]*?<\/li>/)[0];
  const none = pill({ lookup: 'complete', lockfile_only: { match: 0 } });
  assert.match(none, /<strong>4<\/strong> advisory groups matched<span class="sr-only">live OSV lookup/); assert.doesNotMatch(none, /<small>/); assert.match(none, /title="[^"]*live OSV lookup/);
  assert.match(pill({ lookup: 'complete', lockfile_only: { match: 2 } }), /advisory groups matched <small>\u00b7 2 lockfile-only packages<\/small><span class="sr-only">[^<]*plus 2 lockfile-only packages with advisory matches not linked/);
  assert.match(pill({ lookup: 'not_run' }), /<strong>\u2014<\/strong> advisory groups matched <small>\u00b7 not run<\/small>/);
});
test('BOM connections pill renders the count, the bare states and the short partial cue', () => {
  const pill = (g) => { const a = demoAnalysis({ gaps: g }); return renderWorkbench(state({ analysis: a })).match(/<li data-metric="bom_review"[^>]*>[\s\S]*?<\/li>/)[0]; };
  assert.match(pill({ status: 'compared', totals: { candidates: 97 } }), /<strong>97<\/strong> items to review in BOM connections<\/li>/);
  assert.match(pill({ status: 'compared', totals: { candidates: 1 } }), /<strong>1<\/strong> item to review in BOM connections/);
  const z = pill({ status: 'compared', totals: { candidates: 0 }, collection: { software: { state: 'partial' } } });
  assert.doesNotMatch(z, /<strong>/); assert.match(z, /No items flagged in the checked scope <small>\u00b7 Partial coverage<\/small>/);
  assert.match(pill({ status: 'not_compared', code: 'collection_not_run' }), />BOM comparison not run</);
  assert.match(pill({ status: 'not_compared', code: 'collector_failed' }), />BOM comparison unavailable</);
});

// ------------------------------------------------------------------ 3 inspector shell
const FIX = 'evidence/uip/fixtures';
const fixtures = readdirSync(FIX, { withFileTypes: true }).filter((d) => d.isDirectory() && d.name !== 'invalid' && d.name !== 'legacy-view-snapshots')
  .flatMap((d) => readdirSync(join(FIX, d.name)).filter((f) => /^inspector-.*\.json$/.test(f)).map((f) => join(FIX, d.name, f)));

test('every valid UIP-01B inspector fixture renders through the shell', () => {
  assert.ok(fixtures.length >= 6);
  for (const p of fixtures) {
    const obj = JSON.parse(readFileSync(p, 'utf8'));
    const m = fromBoundInspector(obj); assert.equal(m.origin, 'bound_inspector');
    const html = renderInspector(m);
    const ids = [...html.matchAll(/data-question="([a-z_]+)"/g)].map((x) => x[1]);
    assert.deepEqual(ids, obj.answers.map((a) => a.question_id), p);
    assert.match(html, /Sources &amp; coverage/); assert.match(html, /<details class="ot-insp-sources">(?!.*\sopen)/s);
    assert.ok(html.includes(obj.question_set === 'bom_comparison' ? 'Evidence for this check' : 'Evidence for this record'));
  }
});

test('fixed question text and order; all seven symbols have a visible text label', () => {
  const ctx = JSON.parse(readFileSync(join(FIX, 'frigate-recorded/inspector-file.json'), 'utf8'));
  const html = renderInspector(fromBoundInspector(ctx));
  const labels = [...html.matchAll(/<h3>([^<]+)<\/h3>/g)].map((x) => x[1]);
  assert.deepEqual(labels.slice(0, 4), ['What is this?', 'Why is it here?', 'Is there a security concern?', 'What remains unknown?']);
  assert.equal(labels[4], 'Evidence for this record');
  const syms = new Set(Object.values(STATE_META).map((m) => m.sym));
  assert.deepEqual([...syms].sort(), ['alert', 'checked', 'dash', 'hollow', 'reported', 'unknown', 'warning']);
  for (const [state, m] of Object.entries(STATE_META)) {
    const h = renderInspector({ origin: 'x', id: '1', tab: 'contexts', type: 't', title: 'T', subtitle: '', badge: { kind: 'neutral', label: 'b' }, question_set: 'context_four', answers: [{ question_id: 'what_is_this', label: 'What is this?', state, body: 'b', missing: [] }], evidence_rows: [], sources: [], actions: [] });
    assert.ok(h.includes(`data-symbol="${m.sym}"`) && h.includes(`<span>${m.label}</span>`), state);
  }
  assert.equal(stateMeta('nonsense').sym, 'unknown');
});

test('hostile repository text is inert and no active link is emitted', () => {
  const obj = JSON.parse(readFileSync(join(FIX, 'malicious-text-synthetic/inspector-hostile.json'), 'utf8'));
  const html = renderInspector(fromBoundInspector(obj));
  const tags = html.match(/<[^>]+>/g) || [];
  for (const t of tags) { assert.equal(/^<(script|img|iframe|object|embed|a)\b/i.test(t), false, t); assert.equal(/\s(href|src|on\w+)=/i.test(t), false, t); }
  const bad = { ...obj, title: '<img src=x onerror=alert(1)>', answers: obj.answers.map((a) => ({ ...a, body: '<script>1</script> javascript:alert(1)' })) };
  const h2 = renderInspector(fromBoundInspector(bad));
  assert.equal(h2.includes('<img'), false); assert.equal(h2.includes('<script'), false); assert.ok(h2.includes('&lt;script&gt;'));
});

test('bound actions: only ask has a handler; the rest are disabled with a reason, never a dead button', () => {
  const obj = JSON.parse(readFileSync(join(FIX, 'frigate-recorded/inspector-file.json'), 'utf8'));
  const html = renderInspector(fromBoundInspector(obj));
  assert.match(html, /data-action="ask"/); assert.match(html, /<button type="button" class="button small" disabled title="Not connected in this view yet\.">Source access/);
});

// ------------------------------------------------------------------ 4 local presentation model (existing data)
const FORBIDDEN = ['binding', 'canonical_ref', 'analysis_digest', 'assessment', 'bundle_sha256', 'validation_digest', 'schema', 'sources_coverage'];
const noManufactured = (m) => { for (const k of FORBIDDEN) assert.equal(k in m, false, `local model has ${k}`); assert.equal(m.origin, 'local_presentation_model'); };
const unknownsNameMissing = (m) => { for (const a of m.answers) if (['unknown', 'not_assessed', 'cannot_establish'].includes(a.state)) assert.ok(a.missing.length > 0 || a.question_id === 'security_concern' || /not (established|run|assessed|covered)/i.test(a.body) || /not/i.test(a.body), a.question_id); };

test('contexts: root, file, unlocated map to honest local models with preserved actions', () => {
  const s0 = state(); const root = fromSelection(sel(s0, 'contexts', 'root'), 'contexts');
  noManufactured(root); assert.equal(root.title, 'acme/widget'); assert.equal(root.badge.label, 'Repository context');
  assert.equal(root.answers.find((a) => a.question_id === 'security_concern').state, 'not_applicable');
  assert.ok(root.answers.find((a) => a.question_id === 'security_concern').body.includes('not a security assessment'));
  assert.equal(JSON.stringify(root).includes('No security concern'), false);
  assert.ok(root.sources.some((t) => t.includes('abcdef012345')), 'genuine revision shown as text');
  const file = fromSelection(sel(s0, 'contexts', 'ctx:a'), 'contexts'); noManufactured(file); unknownsNameMissing(file);
  assert.deepEqual(file.actions.map((a) => a.id), ['drill', 'ctx-evidence', 'ask']); // UIP-04: Explore components + evidence access are both reachable
  assert.equal(file.actions[0].attrs['data-path'], 'web/package-lock.json');
  const unl = fromSelection(sel(s0, 'contexts', GRP_UNL), 'contexts'); noManufactured(unl); assert.equal(unl.type, 'No location'); assert.ok(unl.answers[0].body.includes('2 component records'));
  assert.ok(file.answers.find((a) => a.question_id === 'what_unknown').missing.length > 0);
  assert.equal(JSON.stringify(root).includes('frigate'), false, 'no hard-coded Frigate text');
});

test('stale or foreign selection yields no record (empty prompt), never the old one', () => {
  const s = sel(state(), 'contexts', 'ctx:gone'); assert.equal(fromSelection(s, 'contexts'), null);
  const fresh = createStore(initial()); fresh.dispatch({ type: 'ANALYSIS_START' });
  const e = fresh.get().epoch; fresh.dispatch({ type: 'ANALYSIS_READY', epoch: e, analysis: demoAnalysis() });
  assert.equal(fresh.get().workbench.perTab.contexts.selection, 'root', 'UIP-04 FR-7: a new analysis opens on the repository root');
  const stamp = { epoch: e, generation: 1, kind: 'full', group: null, seq: 1 };
  fresh.dispatch({ type: 'CTX_REQUEST', ...stamp }); fresh.dispatch({ type: 'CTX_LOADED', ...stamp, data: ctxView });
  fresh.dispatch({ type: 'TAB_STATE', tab: 'contexts', patch: { selection: 'ctx:a' } });
  assert.ok(fromSelection(fresh.get(), 'contexts'));
  fresh.dispatch({ type: 'ANALYSIS_START' });
  const e2 = fresh.get().epoch; fresh.dispatch({ type: 'ANALYSIS_READY', epoch: e2, analysis: demoAnalysis() });
  assert.equal(fresh.get().workbench.perTab.contexts.selection, 'root', 'a new analysis resets the per-tab selection to the root');
  fresh.dispatch({ type: 'CTX_LOADED', ...stamp, seq: 9, data: { ...ctxView, groups: [{ ...ctxView.groups[0], group_id: 'grp:' + 'd'.repeat(24) }] } });
  assert.equal(fresh.get().views.contexts, undefined, 'an older-epoch contexts response never reaches the state');
  const html = renderWorkbench(fresh.get()); assert.equal(html.includes('web/package-lock.json'), false);
});

// UIP-02-IR-01: badge, security answer and evidence row come from ONE component-level state. Each case asserts all three.
const depComp = { id: 'c1', name: 'left-pad', version: '1.0.0', bom_ref: 'pkg:npm/left-pad@1.0.0', type: 'library', locations: ['web/package-lock.json'] };
const depState = (advisories, extra = {}, an = demoAnalysis()) => state({ analysis: an, views: { contexts: ctxView, dependencies: { inspected: { component: depComp, advisories, depends_on: 2, used_by: 1, ...extra } } } });
const liveAnalysis = (lookup) => { const a = demoAnalysis(); a.identity.mode = 'live'; if (lookup) a.summary.advisory_lookup = { lookup }; return a; };
const triple = (m) => { const sec = m.answers.find((a) => a.question_id === 'security_concern'); const row = m.evidence_rows.find((r) => r.label === 'Advisory query'); return { badge: m.badge.label, kind: m.badge.kind, state: sec.state, body: sec.body, row: row.text, rowState: row.state, missing: sec.missing }; };
const DEP_CASES = [
  ['captured match', () => depState([{}, {}]), { badge: 'Advisory match', state: 'advisory_match', row: '2 advisory matches', body: /not confirmed exploitability/ }],
  ['captured record with no coverage evidence', () => depState([]), { badge: 'Coverage not recorded', state: 'unknown', row: 'Coverage not recorded', body: /does not record whether this version was queried/, missing: true }],
  ['explicit captured negative evidence', () => depState([], { advisory_lookup: { state: 'no_match' } }), { badge: 'No match in captured query', state: 'captured', row: 'No match in captured query', body: /does not establish absence/ }],
  ['live, matching not run for the analysis', () => depState([], {}, liveAnalysis(null)), { badge: 'Not assessed', state: 'not_assessed', row: 'Advisory matching not run', body: /was not run/, missing: true }],
  ['live, completed no-match', () => depState([], { advisory_lookup: { state: 'no_match' } }, liveAnalysis('partial')), { badge: 'No match returned', state: 'inventory_reported', row: 'No advisory returned', body: /does not establish absence/ }],
  ['live, lookup unavailable for this version', () => depState([], { advisory_lookup: { state: 'unavailable', reason: 'network_error' } }, liveAnalysis('partial')), { badge: 'Lookup unavailable', state: 'unknown', row: 'Lookup unavailable', body: /did not complete/, missing: true }],
  ['live, not looked up', () => depState([], { advisory_lookup: { state: 'not_looked_up', reason: 'not_attempted' } }, liveAnalysis('partial')), { badge: 'Not looked up', state: 'not_assessed', row: 'Not looked up', body: /was not looked up/, missing: true }],
  ['live, component lookup record missing', () => depState([], {}, liveAnalysis('partial')), { badge: 'Coverage not recorded', state: 'unknown', row: 'Coverage not recorded', body: /not covered by the advisory lookup/, missing: true }],
];
for (const [name, make, want] of DEP_CASES) {
  test(`dependency (${name}): badge, answer and evidence row agree`, () => {
    const m = fromSelection(make(), 'dependencies'); noManufactured(m); const t = triple(m);
    assert.equal(t.badge, want.badge); assert.equal(t.state, want.state); assert.equal(t.row, want.row); assert.equal(t.rowState, want.state);
    assert.match(t.body, want.body); if (want.missing) assert.ok(t.missing.length);
    if (want.badge !== 'Advisory match') assert.equal(t.kind, 'neutral');
    assert.equal(m.question_set, 'context_four'); assert.equal(m.id, 'c1'); assert.equal(m.subtitle, '1.0.0 · NPM');
    assert.ok(m.actions.some((a) => a.id === 'ask'));
    // A negative-match badge is only ever shown together with a completed negative state.
    if (/^No match/.test(t.badge)) assert.ok(['captured', 'inventory_reported'].includes(t.state));
    if (['unknown', 'not_assessed'].includes(t.state)) assert.equal(/^No match/.test(t.badge), false, 'uncertainty must not read as a negative match');
  });
}

// ------------------------------------------------------------------ evidence / entity / assertion selections
const famView = (extra = []) => ({ nodes: [{ id: 'assertion:p8', type: 'assertion' }, { id: 'evidence:e1', type: 'evidence', origin: 'source', method: 'static', observation: { artifact: { locator: 'a.py' }, lines: [3, 4], excerpt: 'md5()' }, limitations: [] }, { id: 'entity:x', type: 'entity', origin: 'cbom', kind: 'algorithm', name: 'MD5' }, ...extra], checks: [check('p8')] });
const QUESTIONS = ['What is this?', 'Why is it here?', 'Is there a security concern?', 'What remains unknown?'];
const labelsOf = (m) => [...renderInspector(m).matchAll(/<h3>([^<]+)<\/h3>/g)].map((x) => x[1]).slice(0, 4);

// UIP-02-IR-03 (the earlier expectation `bom_comparison` for a crypto assertion contradicted report §5.7, which fixes the four
// questions for every non-BOM tab; only the BOM tab substitutes the comparison question).
for (const tab of ['crypto', 'ai']) {
  test(`${tab}: assertion, evidence and entity selections keep the four approved questions`, () => {
    const base = state({ views: { contexts: ctxView, [tab]: famView() } });
    for (const id of ['assertion:p8', 'evidence:e1', 'entity:x']) {
      const m = fromSelection(sel(base, tab, id), tab); noManufactured(m);
      assert.equal(m.question_set, 'context_four', id); assert.deepEqual(m.answers.map((a) => a.label), QUESTIONS, id); assert.deepEqual(labelsOf(m), QUESTIONS, id);
    }
    const a = fromSelection(sel(base, tab, 'assertion:p8'), tab);
    const sec = a.answers.find((x) => x.question_id === 'security_concern');
    assert.equal(sec.state, 'not_represented'); assert.match(sec.body, /Recorded comparison: contradicted\. because/); assert.match(sec.body, /not a vulnerability finding/);
    assert.equal(a.answers.some((x) => x.question_id === 'comparison_established'), false);
    assert.equal(a.evidence_rows[0].label, 'ev1'); assert.deepEqual(a.technical[0], ['Assertion', 'p8']);
  });
}
test('bom: an assertion keeps the approved comparison question; entities and evidence keep the four', () => {
  const base = state({ views: { contexts: ctxView, bom: famView() } });
  const a = fromSelection(sel(base, 'bom', 'assertion:p8'), 'bom');
  assert.equal(a.question_set, 'bom_comparison'); assert.equal(a.answers[2].question_id, 'comparison_established'); assert.equal(a.answers[2].state, 'not_represented'); assert.equal(a.answers[2].label, 'What did the comparison establish?');
  assert.ok(renderInspector(a).includes('Evidence for this check'));
  assert.equal(fromSelection(sel(base, 'bom', 'entity:x'), 'bom').question_set, 'context_four');
});

test('evidence and entity records: no verdict, honest unknowns, unknown selection yields nothing', () => {
  const base = state({ views: { contexts: ctxView, crypto: famView() } });
  const e = fromSelection(sel(base, 'crypto', 'evidence:e1'), 'crypto');
  assert.equal(e.answers[2].state, 'not_applicable'); assert.ok(e.answers[1].body.includes('a.py lines 3–4'));
  assert.ok(e.answers[3].missing.length, 'no limitation recorded -> names the missing statement');
  const n = fromSelection(sel(base, 'crypto', 'entity:x'), 'crypto'); noManufactured(n); assert.equal(n.answers[2].state, 'not_applicable');
  assert.equal(fromSelection(sel(base, 'crypto', 'entity:nope'), 'crypto'), null);
});

// UIP-02-IR-02: the captured excerpt is never silently shortened.
const evView = (observation) => ({ nodes: [{ id: 'evidence:e2', type: 'evidence', origin: 'source', method: 'static', observation, limitations: [] }], checks: [] });
const evHtml = (observation) => { const m = fromSelection(sel(state({ views: { contexts: ctxView, crypto: evView(observation) } }), 'crypto', 'evidence:e2'), 'crypto'); return { m, html: renderInspector(m) }; };
test('short excerpt renders whole with no disclosure', () => {
  const { m, html } = evHtml({ artifact: { locator: 'a.py' }, lines: [1, 1], excerpt: 'createHash("sha256")' });
  assert.ok(html.includes('createHash(&quot;sha256&quot;)')); assert.equal(html.includes('ot-insp-full'), false); assert.equal(m.evidence_rows.find((r) => r.label === 'Excerpt').full, undefined);
});
test('long excerpt: decisive text past character 380 stays reachable and the omission is stated', () => {
  const excerpt = 'x'.repeat(400) + 'IMPORTANT_TAIL';
  const { m, html } = evHtml({ artifact: { locator: 'a.py' }, excerpt });
  const r = m.evidence_rows.find((x) => x.label === 'Excerpt');
  assert.equal(r.full, excerpt); assert.equal(r.omitted, 14 + 20); assert.ok(r.text.endsWith('…') && r.text.length === 381);
  assert.ok(html.includes('IMPORTANT_TAIL'), 'the full captured text is in the rendered inspector');
  assert.match(html, /<details><summary>Show the full captured text \(34 more characters\)<\/summary><pre class="ot-raw">x+IMPORTANT_TAIL<\/pre><\/details>/);
  assert.equal(html.includes('<details open'), false, 'collapsed by default; native <details> is keyboard operable');
});
test('hostile text in the omitted portion is inert', () => {
  const { html } = evHtml({ artifact: { locator: 'a.py' }, excerpt: 'y'.repeat(390) + '<script>alert(1)</script><img src=x onerror=alert(1)> javascript:alert(1)' });
  assert.ok(html.includes('&lt;script&gt;')); for (const t of html.match(/<[^>]+>/g) || []) { assert.equal(/^<(script|img|iframe|object|embed|a)\b/i.test(t), false, t); assert.equal(/\s(href|src|on\w+)=/i.test(t), false, t); }
});
test('multi-code-unit characters are not split by the preview', () => {
  const { m } = evHtml({ artifact: { locator: 'a.py' }, excerpt: '😀'.repeat(381) }); const r = m.evidence_rows.find((x) => x.label === 'Excerpt');
  assert.equal(r.omitted, 1); assert.equal([...r.text].length, 381); assert.equal(/[\ud800-\udbff](?![\udc00-\udfff])/.test(r.text), false);
});
test('an unavailable source locator is stated, not invented', () => {
  const { m, html } = evHtml({ excerpt: 'z' });
  const r = m.evidence_rows.find((x) => x.label === 'Source location'); assert.equal(r.state, 'unknown'); assert.match(r.text, /No source locator was recorded/);
  assert.ok(html.includes('No source locator was recorded')); assert.equal(/\shref=/.test(html), false);
});

test('advanced mode adds technical detail only when asked', () => {
  const m = fromSelection(sel(state(), 'contexts', 'root'), 'contexts');
  m.technical = [['Record', 'x']];
  assert.equal(renderInspector(m).includes('Technical detail'), false);
  assert.ok(renderInspector(m, { advanced: true }).includes('Technical detail'));
});

// ------------------------------------------------------------------ 5 session status (homepage) + header preserved
test('session status, End session and cleanup notes stay visible on the homepage', () => {
  const base = initial();
  let h = renderAnalyze({ ...base, session: { ...base.session, status: 'none' } });
  assert.match(h, /id="ot-session-status"[^>]*>No active session</); assert.match(h, /id="ot-end-session" data-action="end" disabled/);
  h = renderAnalyze({ ...base, session: { ...base.session, status: 'active' } });
  assert.match(h, />Active session · temporary</); assert.match(h, /id="ot-end-session" data-action="end" >End session/);
  assert.match(renderAnalyze({ ...base, busy: 'ending' }), />Ending session…</);
  assert.match(renderAnalyze({ ...base, busy: 'analysis' }), />Analyzing…</);
  const msgs = { deleted_verified: /removal was verified/, cleanup_failed: /cleanup could not be verified/, gone: /no longer active on the service/ };
  for (const [k, re] of Object.entries(msgs)) { const html = renderAnalyze({ ...base, ended: k }); assert.match(html, re); assert.match(html, /id="ot-ended-note"/); if (k === 'cleanup_failed') assert.match(html, /ot-session-error/); }
  assert.match(renderAnalyze({ ...base, notice: 'cleanup error' }), /role="alert">cleanup error</);
  assert.equal(renderAnalyze(base).includes('ot3-session-strip'), false);
});

test('homepage: reference content present, form ids kept, Scan submit (UIP-03), no fixed "Live analysis unavailable"', () => {
  const h = renderAnalyze(initial());
  for (const t of ['Know what\'s inside.', 'Verify what you trust.', 'Three inventories. One evidence trail.', 'A camera app\'s AI model', 'BOM comparison outcomes', 'See what the evidence supports.', 'Represented', 'Not represented', 'Coverage unknown', 'SBOM', 'CBOM', 'AI-BOM']) assert.ok(h.includes(t), t);
  for (const id of ['ot-form', 'ot-url', 'ot-error']) assert.ok(h.includes(`id="${id}"`), id);
  // UIP-03 (legacy assertion updated, recorded reason): the review step is replaced by one Scan action; it is disabled until the config says scanning is available.
  assert.match(h, /id="ot-scan"[^>]*type="submit"|type="submit"[^>]*>Scan|id="ot-scan"/); assert.equal(h.includes('Review repository'), false); assert.equal(h.includes('Explore sample findings'), false);
  assert.equal(h.includes('Live analysis unavailable'), false);
  assert.equal(liveStatusText(null), 'Captured sample available');
  assert.match(liveStatusText({ enabled: true }), /Live scanning is enabled/);
  assert.equal(h.includes('<script'), false); assert.equal(/\son\w+=/.test(h), false);
  assert.match(renderAnalyze({ ...initial(), live: { enabled: true } }), /Repository roots and \/tree\/reference links are supported\./);
});

test('the brand combines logo and name in an accessible home button; the Demo header action remains', () => {
  const t = readFileSync('src/ui/index.html', 'utf8'); const i = t.indexOf('<header class="topbar">'); const k = t.indexOf('</nav>') + 6;
  const header = t.slice(i, k);
  assert.match(header, /<button[^>]*class="brand ot-home-brand"[^>]*data-nav="analyze" aria-label="OpenTrace home"[^>]*><img[^>]*>\s*<span><strong>OpenTrace<\/strong><small>One repository\. Traceable evidence\.<\/small><\/span><\/button>/);
  assert.match(header, /id="ot-demo">Demo ↗<\/button>/);
  assert.match(readFileSync('src/ui/styles/app.css', 'utf8'), /\.ot-home-brand:focus-visible\{outline:3px solid var\(--teal\)/);
});

test('no inline style attribute is rendered (the app CSP is style-src self)', () => {
  const s = state(); const outputs = [renderAnalyze(initial()), renderWorkbench(s), renderEvidence(s), renderInspector(fromSelection(sel(s, 'contexts', 'root'), 'contexts'))];
  for (const h of outputs) assert.equal(/\sstyle\s*=/i.test(h), false);
});
