// UIP-05 correction regressions (UIP-05-IR-01..03). They run the PRODUCTION loaders, reducer and event snippets extracted unchanged from
// src/ui/app.js inside a Node VM with a controllable api(); there is no DOM and no browser. They are implementation regressions, kept
// separate from the independent review's reproduction script (evidence/uip/reviews/uip-05/independent_probes.mjs), which is unchanged.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';
import { initial, createStore } from '../../../src/ui/lib/store.js';
import { requestKey, pageKey, payloadFilter, PAGE_SIZE, CHOOSER_PAGE, chooserKey, legacyKey, pageNeeded } from '../../../src/ui/lib/dependency_graph.js';
import { ApiError, qs } from '../../../src/ui/lib/api.js';

const source = readFileSync(new URL('../../../src/ui/app.js', import.meta.url), 'utf8');
const cut = (a, b) => { const i = source.indexOf(a); const j = source.indexOf(b, i + 1); assert.ok(i >= 0 && j > i, 'anchor ' + a); return source.slice(i, j); };
const block = cut('let depPageSeq =', 'const depNode =');
const legacy = cut('async function loadDeps()', '// ------------------------------------------------------------------ UIP-05:');
const handler = cut('function handleError(', 'function runSearch');
const presCase = cut("case 'dep-pres':", "case 'list-page':");
const searchLine = cut("else if (t.id === 'ot5-search') {", "else if (t.id === 'ot5-ctx-q')");
const ctxLine = cut("else if (t.id === 'ot5-ctx-q') {", "else if (t.id === 'ot-pkg-search')");
const fixture = JSON.parse(readFileSync(new URL('../../../evidence/uip/fixtures/deps-82-synthetic/page-offset-00.json', import.meta.url), 'utf8'));
const clone = (x) => structuredClone(x);
const chooserData = () => ({ binding: fixture.binding, default_context_id: fixture.context.context_id, offset: 0, total: 1, limit: CHOOSER_PAGE, rows: [{ context_id: fixture.context.context_id, path: fixture.context.path, components_total: 5 }] });
const legacyData = (marker) => ({ generation: 1, context_path: fixture.context.path, focus: { id: fixture.focus.node_id }, component_list: { total: 1, offset: 0, page_size: 40, rows: [] }, marker });

async function setup({ presentation = 'graph', loadChooser = true } = {}) {
  const store = createStore(initial()); store.dispatch({ type: 'ANALYSIS_START' });
  const e = store.get().epoch;
  store.dispatch({ type: 'ANALYSIS_READY', epoch: e, analysis: { generation: 1, identity: { analysis_digest: fixture.binding.analysis_digest }, summary: {} } });
  store.dispatch({ type: 'TAB_STATE', tab: 'dependencies', patch: { ctxId: fixture.context.context_id, context: fixture.context.path, focus: fixture.focus.node_id, selection: fixture.focus.node_id, filter: 'all' } });
  const pending = []; const timers = []; let generation = 1; const effects = { network: 0, ended: 0, logged: 0 };
  const c = vm.createContext({ store, requestKey, pageKey, chooserKey, legacyKey, pageNeeded, payloadFilter, PAGE_SIZE, CHOOSER_PAGE, ApiError, qs, console: { error: () => { effects.logged++; } }, depsSeq: 0,
    dispatch: (a) => store.dispatch(a), gen: () => generation, epoch: () => store.get().epoch, depNow: () => store.get().workbench.perTab.dependencies,
    loadNetworkIfNeeded: () => { effects.network++; }, dispatchEnded: () => { effects.ended++; }, closeDialog: () => {}, setTimeout: (fn) => { timers.push(fn); return timers.length; }, clearTimeout: (id) => { if (id) timers[id - 1] = null; },
    api: (url) => new Promise((resolve, reject) => pending.push({ url, resolve, reject })) });
  vm.runInContext(legacy + block + handler + `\nfunction switchView(p){const t={dataset:{p}};switch('dep-pres'){${presCase}}}\nfunction typeSearch(value){const t={id:'ot5-search',value}; if(false){} ${searchLine}}\nfunction typeCtx(value){const t={id:'ot5-ctx-q',value}; if(false){} ${ctxLine}}`, c);
  const run = (code) => vm.runInContext(code, c);
  const patch = (p) => store.dispatch({ type: 'TAB_STATE', tab: 'dependencies', patch: p });
  const dep = () => store.get().workbench.perTab.dependencies;
  const take = (re) => { const i = pending.findIndex((p) => re.test(p.url)); assert.ok(i >= 0, 'no pending request for ' + re); return pending.splice(i, 1)[0]; };
  const flush = () => new Promise((r) => setImmediate(r));
  if (presentation === 'list') patch({ presentation: 'list' });
  const task = run('loadDepPage()'); take(/\/dependencies\?/).resolve(clone(fixture)); await task;
  if (loadChooser) { const t2 = run('loadDepContexts()'); take(/dependency-contexts/).resolve(chooserData()); await t2; }
  pending.length = 0;
  return { store, run, patch, dep, pending, take, flush, timers, effects, setGeneration: (g) => { generation = g; } };
}
const pageUrls = (t) => t.pending.filter((p) => /\/api\/workbench\/v1\/dependencies\?/.test(p.url));

// ---- UIP-05-IR-01: Graph/List cache consistency
test('IR-01: List search then Graph loads the current shared query', async () => {
  const t = await setup(); t.patch({ presentation: 'list' });
  t.patch({ q: 'dep-04', listQuery: 'dep-04', gOffset: 0, listOffset: 0 });
  t.run("switchView('graph')");
  const reqs = pageUrls(t); assert.equal(reqs.length, 1, 'Graph must request the page for the current query');
  assert.match(reqs[0].url, /query=dep-04/);
  const shown = clone(fixture); shown.query = 'dep-04'; shown.page = { ...shown.page, matches_total: 3 };
  reqs[0].resolve(shown); await t.flush();
  assert.equal(t.store.get().views.depPage.query, 'dep-04');
  assert.equal(t.dep().q, 'dep-04');
});
test('IR-01: clearing the search while in List reuses the still-valid cached page (no request)', async () => {
  const t = await setup(); t.patch({ presentation: 'list' }); t.patch({ q: 'dep-04', listQuery: 'dep-04' }); t.patch({ q: '', listQuery: '' });
  t.run("switchView('graph')");
  assert.equal(pageUrls(t).length, 0); assert.equal(t.store.get().views.depPage.query, '');
});
test('IR-01: List search, switch back before the debounce fires, selection and graph filter survive', async () => {
  const t = await setup(); t.patch({ presentation: 'list', selection: 'sel-x' });
  t.run("typeSearch('dep-0')");                                   // debounce pending
  t.run("switchView('graph')");
  assert.equal(pageUrls(t).length, 1, 'a request for the new query is issued by the switch itself');
  assert.equal(t.dep().selection, 'sel-x'); assert.equal(t.dep().filter, 'all');
  t.timers.forEach((fn) => fn && fn()); await t.flush();           // the old debounce must not issue a stale or second request
  assert.equal(pageUrls(t).length, 1, 'the pending debounce was cancelled by the switch');
});
test('IR-01: Graph search typed, switch to List before the debounce: the timer follows the CURRENT presentation', async () => {
  const t = await setup(); t.run("typeSearch('x')"); t.run("switchView('list')");
  t.pending.length = 0; t.timers.forEach((fn) => fn && fn()); await t.flush();
  assert.equal(pageUrls(t).length, 0, 'no Graph request while List is shown');
});
test('IR-01: per-view paging is preserved when the query is unchanged', async () => {
  const t = await setup(); t.patch({ gOffset: 0, listOffset: 40, presentation: 'list' }); t.run("switchView('graph')");
  assert.equal(t.dep().gOffset, 0); assert.equal(t.dep().listOffset, 40); assert.equal(pageUrls(t).length, 0);
});

// ---- UIP-05-IR-02: complete response identity
test('IR-02: a late error for a query superseded during the debounce window changes nothing', async () => {
  const t = await setup(); const task = t.run('loadDepPage()'); t.patch({ q: 'newer', gOffset: 0 });
  const before = t.store.get(); t.take(/\/dependencies\?/).reject(new ApiError(500, { error: 'projection_failed' })); await task;
  assert.equal(t.store.get(), before, 'state object identity unchanged');
});
test('IR-02: a late success for a superseded query is dropped and causes no side effect', async () => {
  const t = await setup(); const task = t.run('loadDepPage()'); t.patch({ q: 'newer', gOffset: 0 });
  const shown = t.store.get().views.depPage; t.take(/\/dependencies\?/).resolve(clone(fixture)); await task; await t.flush();
  assert.equal(t.store.get().views.depPage, shown); assert.equal(t.pending.length, 0);
});
test('IR-02: a Graph response released after switching to List is discarded', async () => {
  const t = await setup(); const task = t.run('loadDepPage()'); t.run("switchView('list')");
  const before = t.store.get().views.depPage; t.pending.find((p) => /\/dependencies\?/.test(p.url)).resolve(clone(fixture)); await task;
  assert.equal(t.store.get().views.depPage, before);
  assert.notEqual(t.dep().pg.status, 'loading', 'the superseded request must not leave Graph loading');
  assert.equal(t.dep().presentation, 'list');
});
test('IR-02: Graph error released after switching to List is discarded', async () => {
  const t = await setup(); const task = t.run('loadDepPage()'); t.run("switchView('list')");
  t.pending.find((p) => /\/dependencies\?/.test(p.url)).reject(new ApiError(500, { error: 'projection_failed' })); await task;
  assert.notEqual(t.dep().pg.status, 'error');
});
test('IR-02: returning to Graph after a discarded response requests the page again (not stuck loading)', async () => {
  const t = await setup(); t.patch({ gOffset: 30 }); const task = t.run('loadDepPage()'); t.run("switchView('list')");
  t.pending.find((p) => /\/dependencies\?/.test(p.url)).resolve(clone(fixture)); await task; t.pending.length = 0;
  t.run("switchView('graph')"); assert.equal(pageUrls(t).length, 1);
});
test('IR-02: deliberate preload while List is shown is still applied', async () => {
  const t = await setup({ presentation: 'list' });      // setup requests the page while List is presented and expects it to apply
  assert.ok(t.store.get().views.depPage, 'a page requested during List (preload) is applied'); assert.equal(t.dep().pg.status, 'idle');
  t.run("switchView('graph')"); assert.equal(pageUrls(t).length, 0, 'the preloaded page is reused');
});
test('IR-02: manual retry works and nothing retries by itself', async () => {
  const t = await setup(); const task = t.run('loadDepPage()'); t.take(/\/dependencies\?/).reject(new ApiError(500, { error: 'projection_failed' })); await task; await t.flush();
  assert.equal(t.dep().pg.status, 'error'); assert.equal(pageUrls(t).length, 0, 'no automatic retry');
  const again = t.run('loadDepPage()'); assert.equal(pageUrls(t).length, 1); t.take(/\/dependencies\?/).resolve(clone(fixture)); await again;
  assert.equal(t.dep().pg.status, 'idle');
});
test('IR-02: chooser success and error for a superseded query are dropped', async () => {
  const t = await setup(); const a = t.run('loadDepContexts()'); t.patch({ cx: { ...t.dep().cx, query: 'abc', offset: 0 } });
  const before = t.store.get(); t.take(/dependency-contexts/).reject(new ApiError(500, { error: 'projection_failed' })); await a;
  assert.equal(t.store.get(), before, 'late chooser error ignored');
  const b = t.run('loadDepContexts()'); t.patch({ cx: { ...t.dep().cx, query: 'abcd', offset: 0 } });
  const had = t.store.get().views.depContexts; const stale = chooserData(); stale.total = 99; t.take(/dependency-contexts/).resolve(stale); await b;
  assert.equal(t.store.get().views.depContexts, had, 'late chooser success ignored');
});
test('IR-02: legacy List response for a superseded list query is dropped', async () => {
  const t = await setup({ presentation: 'list' }); const task = t.run('loadDeps()'); t.patch({ listQuery: 'zz', listOffset: 0 });
  const before = t.store.get().views.dependencies; t.take(/\/api\/view\/dependencies/).resolve(legacyData('stale')); await task;
  assert.equal(t.store.get().views.dependencies, before);
});
test('IR-02: legacy inspector response for a superseded selection is dropped', async () => {
  const t = await setup(); const task = t.run('loadDeps()'); t.patch({ selection: 'other' });
  const before = t.store.get().views.dependencies; t.take(/\/api\/view\/dependencies/).resolve(legacyData('stale')); await task;
  assert.equal(t.store.get().views.dependencies, before);
});
test('IR-02: End session / replacement drops every late dependency response', async () => {
  const t = await setup(); const a = t.run('loadDepPage()'); const b = t.run('loadDepContexts()');
  t.store.dispatch({ type: 'ANALYSIS_START' }); const before = t.store.get();
  t.take(/\/dependencies\?/).resolve(clone(fixture)); t.take(/dependency-contexts/).resolve(chooserData()); await a; await b;
  assert.equal(t.store.get(), before);
});

// ---- UIP-05-IR-03: stale generation
const stale = () => new ApiError(409, { error: 'stale_generation', generation: 2 });
test('IR-03: a current 409 on the page route retires dependency state and exposes recovery (cached data)', async () => {
  const t = await setup(); const task = t.run('loadDepPage()'); t.take(/\/dependencies\?/).reject(stale()); await task; await t.flush();
  const s = t.store.get();
  assert.notEqual(t.dep().pg.status, 'loading'); assert.equal(t.dep().stale, true);
  assert.equal(s.views.depPage, undefined); assert.equal(s.views.depContexts, undefined);
  assert.equal(s.analysis.generation, 1, 'the new generation is never adopted into the old analysis');
  assert.equal(t.pending.length, 0, 'no silent retry');
});
test('IR-03: a current 409 on the page route without cached data', async () => {
  const t = await setup(); t.store.dispatch({ type: 'DEP_CONTEXT', ctxId: fixture.context.context_id, path: fixture.context.path });
  const task = t.run('loadDepPage()'); t.take(/\/dependencies\?/).reject(stale()); await task;
  assert.notEqual(t.dep().pg.status, 'loading'); assert.equal(t.dep().stale, true); assert.equal(t.pending.length, 0);
});
test('IR-03: a current 409 on the chooser route (cached and uncached)', async () => {
  const t = await setup(); const a = t.run('loadDepContexts()'); t.take(/dependency-contexts/).reject(stale()); await a;
  assert.notEqual(t.dep().cx.status, 'loading'); assert.equal(t.dep().stale, true); assert.equal(t.store.get().views.depContexts, undefined); assert.equal(t.pending.length, 0);
  const u = await setup({ loadChooser: false }); const b = u.run('loadDepContexts()'); u.take(/dependency-contexts/).reject(stale()); await b;
  assert.notEqual(u.dep().cx.status, 'loading'); assert.equal(u.dep().stale, true);
});
test('IR-03: a 409 for a superseded request is ignored', async () => {
  const t = await setup(); const task = t.run('loadDepPage()'); t.patch({ q: 'newer', gOffset: 0 });
  const before = t.store.get(); t.take(/\/dependencies\?/).reject(stale()); await task;
  assert.equal(t.store.get(), before); assert.notEqual(t.dep().stale, true);
});
test('IR-03: a late 409 after the session was replaced is ignored', async () => {
  const t = await setup(); const a = t.run('loadDepPage()'); const b = t.run('loadDepContexts()');
  t.store.dispatch({ type: 'ANALYSIS_START' }); const before = t.store.get();
  t.take(/\/dependencies\?/).reject(stale()); t.take(/dependency-contexts/).reject(stale()); await a; await b;
  assert.equal(t.store.get(), before);
});
test('IR-03: while stale nothing is requested; the recovery action ends the dead session view', async () => {
  const t = await setup(); const task = t.run('loadDepPage()'); t.take(/\/dependencies\?/).reject(stale()); await task;
  t.run('ensureDepPage()'); t.run('loadDepPage()'); t.run('loadDepContexts()'); assert.equal(t.pending.length, 0);
});

// ---- UIP-05-IR-04: expanded graph (render contract; the browser run exercises focus, Escape, inert background and lifecycle)
import { renderDependencyView } from '../../../src/ui/components/dependency_graph.js';
const renderState = (patch = {}) => {
  const store = createStore(initial()); store.dispatch({ type: 'ANALYSIS_START' }); const e = store.get().epoch;
  store.dispatch({ type: 'ANALYSIS_READY', epoch: e, analysis: { generation: 1, identity: { analysis_digest: fixture.binding.analysis_digest, mode: 'demo' }, summary: {} } });
  store.dispatch({ type: 'TAB_STATE', tab: 'dependencies', patch: { ctxId: fixture.context.context_id, context: fixture.context.path, focus: fixture.focus.node_id, filter: 'all', ...patch } });
  store.dispatch({ type: 'DEPPAGE_REQUEST', epoch: e, generation: 1, seq: 1, key: requestKey(store.get().workbench.perTab.dependencies), intent: 'active' });
  store.dispatch({ type: 'DEPPAGE_LOADED', epoch: e, generation: 1, seq: 1, key: requestKey(store.get().workbench.perTab.dependencies), data: clone(fixture) });
  return store;
};
const helpers = { depInspector: () => '<p>inspector</p>', depList: () => '<p>list</p>' };
test('IR-04: Expand control is present, collapsed by default, and no dialog frame exists', () => {
  const html = renderDependencyView(renderState().get(), helpers);
  assert.match(html, /id="ot5-expand"[^>]*aria-expanded="false"[^>]*>Expand</); assert.ok(!html.includes('id="ot5-expanded"'));
});
test('IR-04: expanded state renders a modal dialog frame with the same controls and a Close control', () => {
  const html = renderDependencyView(renderState({ expanded: true }).get(), helpers);
  assert.match(html, /<div class="ot5-expanded" id="ot5-expanded" role="dialog" aria-modal="true" aria-label="Expanded dependency graph">/);
  assert.match(html, /id="ot5-expand"[^>]*aria-expanded="true"[^>]*>Close expanded view</);
  for (const needle of ['data-ot5-filter="direct"', 'data-ot5-zoom="1.25"', 'data-ot5-fit', 'id="ot5-search"', 'id="ot5-context"', 'data-dep-node=']) assert.ok(html.includes(needle), needle);
});
test('IR-04: expanded is session state: End/ANALYSIS_START/ADVANCED clear it, paging and search keep it', () => {
  const st = renderState({ expanded: true });
  st.dispatch({ type: 'TAB_STATE', tab: 'dependencies', patch: { gOffset: 30, q: 'dep' } }); assert.equal(st.get().workbench.perTab.dependencies.expanded, true);
  st.dispatch({ type: 'ADVANCED', value: true }); assert.equal(st.get().workbench.perTab.dependencies.expanded, false);
  const a = renderState({ expanded: true }); a.dispatch({ type: 'END_STARTED' }); assert.equal(a.get().workbench.perTab.dependencies.expanded, false);
  const b = renderState({ expanded: true }); b.dispatch({ type: 'ANALYSIS_START' }); assert.equal(b.get().workbench.perTab.dependencies.expanded, false);
  const c = renderState({ expanded: true }); c.dispatch({ type: 'ENDED', state: 'gone' }); assert.equal(c.get().workbench.perTab.dependencies.expanded, false);
});
test('IR-04: the ending state never renders the frame', () => {
  const st = renderState({ expanded: true }); st.dispatch({ type: 'END_STARTED' });
  const html = renderDependencyView(st.get(), helpers); assert.ok(!html.includes('ot5-expanded')); assert.match(html, /Ending the session/);
});
test('IR-03: the retired state renders the session-moved-on message with a Reopen action and no graph', async () => {
  const t = await setup(); const task = t.run('loadDepPage()'); t.take(/\/dependencies\?/).reject(stale()); await task;
  const html = renderDependencyView(t.store.get(), helpers);
  assert.match(html, /The session moved on; reopen the analysis\./); assert.match(html, /data-action="dep-stale-reset"/); assert.ok(!html.includes('data-dep-node'));
});

// ---- UIP-05-IR-03 residual: a legacy dependency completion must not outlive the retirement of the dependency state
const legacyOk = (marker = 'x') => legacyData(marker);
test('IR-03 residual: a legacy success held across a current PAGE 409 is rejected after retirement (no view, no state change, no side effect)', async () => {
  const t = await setup(); const old = t.run('loadDeps()'); const pg = t.run('loadDepPage()');
  const held = t.take(/\/api\/view\/dependencies/); t.take(/\/dependencies\?/).reject(stale()); await pg;
  assert.equal(t.dep().stale, true); const before = t.store.get(); const n = t.effects.network;
  held.resolve(legacyOk('retired')); await old; await t.flush();
  assert.equal(t.store.get().views.dependencies, undefined); assert.equal(t.store.get(), before, 'state unchanged'); assert.equal(t.effects.network, n, 'loadNetworkIfNeeded not run');
  assert.equal(t.pending.length, 0);
});
test('IR-03 residual: a legacy success held across a current CHOOSER 409 is rejected after retirement', async () => {
  const t = await setup(); const old = t.run('loadDeps()'); const cx = t.run('loadDepContexts()');
  const held = t.take(/\/api\/view\/dependencies/); t.take(/dependency-contexts/).reject(stale()); await cx;
  const before = t.store.get(); const n = t.effects.network; held.resolve(legacyOk('retired')); await old; await t.flush();
  assert.equal(t.store.get().views.dependencies, undefined); assert.equal(t.store.get(), before); assert.equal(t.effects.network, n);
});
test('IR-03 residual: a late legacy ERROR after retirement acts on nothing (no log, no session end, no state change)', async () => {
  for (const status of [500, 403, 409]) {
    const t = await setup(); const old = t.run('loadDeps()'); const pg = t.run('loadDepPage()');
    const held = t.take(/\/api\/view\/dependencies/); t.take(/\/dependencies\?/).reject(stale()); await pg;
    const before = t.store.get(); held.reject(new ApiError(status, { error: 'x' })); await old; await t.flush();
    assert.equal(t.store.get(), before, 'status ' + status); assert.equal(t.effects.ended, 0, 'no session end for ' + status); assert.equal(t.effects.logged, 0, 'no log for ' + status);
  }
});
test('IR-03 residual: a superseded legacy error does not act (a newer legacy request exists)', async () => {
  const t = await setup(); const first = t.run('loadDeps()'); const second = t.run('loadDeps()');
  const a = t.take(/\/api\/view\/dependencies/); const b = t.take(/\/api\/view\/dependencies/);
  a.reject(new ApiError(403, { error: 'no_session' })); await first; assert.equal(t.effects.ended, 0);
  b.resolve(legacyOk('current')); await second; assert.equal(t.store.get().views.dependencies.marker, 'current');
});
test('IR-03 residual: late legacy success and error after replacement and after End session stay inert', async () => {
  for (const kind of ['ANALYSIS_START', 'END_STARTED']) {
    const t = await setup(); const a = t.run('loadDeps()'); const b = t.run('loadDeps()'); const [x, y] = [t.take(/\/api\/view\/dependencies/), t.take(/\/api\/view\/dependencies/)];
    t.store.dispatch({ type: kind }); const before = t.store.get(); const n = t.effects.network;
    x.resolve(legacyOk('late')); y.reject(new ApiError(500, { error: 'x' })); await a; await b; await t.flush();
    assert.equal(t.store.get(), before, kind); assert.equal(t.effects.network, n); assert.equal(t.effects.logged, 0);
  }
});
test('IR-03 residual: a valid current legacy response still applies and runs its completion', async () => {
  const t = await setup(); const old = t.run('loadDeps()'); const n = t.effects.network;
  t.take(/\/api\/view\/dependencies/).resolve(legacyOk('current')); await old;
  assert.equal(t.store.get().views.dependencies.marker, 'current'); assert.equal(t.effects.network, n + 1);
});
test('IR-03 residual: Reopen recovery, manual retry and preload still work around the guard', async () => {
  const t = await setup({ presentation: 'list' }); assert.ok(t.store.get().views.depPage, 'preload applied');
  const pg = t.run('loadDepPage()'); t.take(/\/dependencies\?/).reject(new ApiError(500, { error: 'projection_failed' })); await pg; assert.equal(t.dep().pg.status, 'error');
  const again = t.run('loadDepPage()'); t.take(/\/dependencies\?/).resolve(clone(fixture)); await again; assert.equal(t.dep().pg.status, 'idle');
  const s = t.run('depStaleReset'); assert.equal(typeof s, 'function'); t.run('depStaleReset()'); assert.equal(t.effects.ended, 1);
});
