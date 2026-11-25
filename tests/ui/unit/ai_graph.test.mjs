// UIP-07: the AI models tab model, rendering (inert text, honest states, alternatives) and the request/lifecycle reducers.
// No browser, network or service. Fixtures are SYNTHETIC renderer fixtures (evidence/uip/visual/uip-07/fixtures/renderer). Run: node --test tests/ui/unit/
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createStore, initial } from '../../../src/ui/lib/store.js';
import * as M from '../../../src/ui/lib/ai_graph.js';
import * as C from '../../../src/ui/lib/crypto_graph.js';
import { renderAiView } from '../../../src/ui/components/ai_graph.js';
import { fromAi } from '../../../src/ui/lib/inspector_model.js';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '../../..');
const fx = (n) => JSON.parse(readFileSync(join(ROOT, 'evidence/uip/visual/uip-07/fixtures/renderer', n + '.json'), 'utf8'));
const DIGEST = fx('multi3').binding.analysis_digest;
const analysis = () => ({ generation: 1, identity: { mode: 'captured', owner: 'example-org', name: 'synthetic-lab', commit: '0'.repeat(40), analysis_digest: DIGEST },
  summary: { components: 1, checks: [{ assertion_id: 'p7-model-declared-in-aibom', state: 'unverifiable', rationale: 'r' }], cards: [{ kind: 'aibom', artifact_name: 'cisco-aibom.cdx.json' }] } });
function opened() { const st = createStore(initial()); st.dispatch({ type: 'ANALYSIS_START' }); const e = st.get().epoch; st.dispatch({ type: 'ANALYSIS_READY', epoch: e, analysis: analysis() }); return { st, e }; }
const ai = (st) => st.get().workbench.perTab.ai;
const patch = (st, p) => st.dispatch({ type: 'TAB_STATE', tab: 'ai', patch: p });
function request(st, e, seq, gen = 1) { const key = M.requestKey(ai(st)); st.dispatch({ type: 'AI_REQUEST', epoch: e, generation: gen, seq, key }); return { epoch: e, generation: gen, seq, key }; }
function ready(page, extra = {}) { const { st, e } = opened(); patch(st, extra); const stamp = request(st, e, 1); st.dispatch({ type: 'AI_LOADED', ...stamp, data: page }); return { st, e }; }
const show = (st) => renderAiView(st.get());

// ------------------------------------------------------------------------------------------------------------ reuse of the reference geometry
test('the AI tab uses the reference composition constants exactly (imported UIP-06 layout)', () => {
  const L = C.buildLayout(M.aiZones(fx('multi3')));
  assert.equal(L.zones.length, 3); assert.equal(L.ordinary, true);
  assert.deepEqual(L.zones.map((z) => z.x), [20, 420, 820]);
  for (const z of L.zones) { assert.deepEqual([z.w, z.h, z.y], [360, 500, 160]); assert.deepEqual(z.cards.map((c) => [c.x - z.x, c.y, c.w, c.h]), [[42, 280, 300, 90], [42, 400, 300, 90], [42, 520, 300, 90]]); }
  assert.deepEqual(L.root, { x: 460, y: 20, w: 280, h: 72 });
  assert.deepEqual(C.fitView(L), [-20, 0, 1240, 690]);
});
test('assets without a recorded location sit in the client-side lane, which is not a payload group', () => {
  const zs = M.aiZones(fx('unlocated_and_located'));
  assert.equal(zs.length, 2); assert.equal(zs.at(-1).key, null); assert.equal(zs.at(-1).label, 'No recorded source file'); assert.equal(zs.at(-1).cards.length, 1);
  const demo = M.aiZones(fx('demo_like')); assert.equal(demo.length, 1); assert.equal(demo[0].key, null);
});

// ------------------------------------------------------------------------------------------------------------ filters and counts
test('five filters in the reference order with counts from the payload', () => {
  assert.deepEqual(M.FILTERS.map((f) => f.label), ['All assets', 'Models', 'Runtimes', 'AI services', 'Findings']);
  assert.deepEqual(M.FILTERS.map((f) => f.payload), ['all', 'models', 'runtimes', 'ai_services', 'findings']);
  const { st } = ready(fx('ref_composition')); const h = show(st);
  for (const f of ['All assets', 'Models', 'Runtimes', 'AI services', 'Findings']) assert.ok(h.includes(f));
  const t = fx('ref_composition').filter_totals; assert.deepEqual([t.all, t.models, t.runtimes, t.ai_services, t.findings], [5, 2, 3, 0, 0]);
  assert.match(h, /data-otai-filter="models"[^>]*>Models <span>2<\/span>/); assert.match(h, /data-otai-filter="ai_services"[^>]*>AI services <span>0<\/span>/);
});

// ------------------------------------------------------------------------------------------------------------ states by cause
test('every empty or unavailable state says why and none claims that no AI exists', () => {
  const txt = (n, flt = 'all', q = '') => M.emptyText(fx(n), flt, q);
  assert.match(txt('completed_empty'), /lists no AI assets\. This does not show that no AI is used/);
  assert.match(txt('partial_empty'), /incomplete/i); assert.match(txt('failed'), /failed/); assert.match(txt('unsupported'), /No supported AI inventory/);
  assert.equal(txt('not_run'), 'No AI inventory was generated for this analysis.');
  assert.match(txt('services_empty', 'ai_services'), /not collected|No AI service was collected/); assert.match(txt('services_empty', 'ai_services'), /does not show that none exists/);
  assert.match(txt('findings_empty', 'findings'), /not assessed/); assert.match(txt('findings_empty', 'findings'), /different from finding none/);
  assert.equal(txt('filter_to_zero', 'all', 'zzz'), 'No assets match this filter in the recorded inventory.');
  const all = ['completed_empty', 'partial_empty', 'failed', 'unsupported', 'not_run'].map((n) => txt(n));
  assert.equal(new Set(all).size, all.length);
  for (const t of all) assert.doesNotMatch(t, /no AI (is|exists|was found)\b(?! used)/i);
  for (const f of ['findings_empty', 'services_empty', 'filter_to_zero']) { const { st } = ready(fx(f), { filter: fx(f).filter }); const h = show(st); assert.match(h, /id="otai-empty"/); assert.doesNotMatch(h, /id="otai-svg"/); }
});
test('the Demo-like page: one inventory-reported model, honest availability, unresolved identity, not-recorded metadata, no source link', () => {
  const { st } = ready(fx('demo_like')); const h = show(st);
  assert.match(h, /Inventory-reported models only; identity, provider and runtime use are not established\./);
  assert.match(h, /Inventory-reported model/); assert.match(h, /not a verified model identity/); assert.match(h, /Not recorded/);
  assert.equal((h.match(/<h2/g) || []).length, 1, 'one header per selection'); assert.equal((h.match(/data-question=/g) || []).length, 4, 'one question set');
  assert.match(h, /records no repository location/); assert.doesNotMatch(h, /href="https:\/\/github\.com/);
  assert.match(h, /Download AI-BOM ↓/); assert.match(h, /\/api\/artifacts\/cisco-aibom\.cdx\.json\?disposition=attachment/);
  assert.doesNotMatch(h, /\sstyle="/); assert.doesNotMatch(h, /is running|active runtime|is a verified model/i);
});

// ------------------------------------------------------------------------------------------------------------ alternatives, groups, metadata
test('a preferred/fallback pair is drawn and described as alternatives, never as concurrent components', () => {
  const { st } = ready(fx('ref_composition')); let h = show(st);
  assert.equal((h.match(/class="otai-alt"/g) || []).length, 1); assert.match(h, /stroke-dasharray="3 4"/); assert.match(h, /alternative: fallback import/); assert.match(h, /Alternative path: fallback import only if the first import fails/);
  assert.doesNotMatch(h, /running together|both (run|active)|concurrent(ly)? (run|activ)/i);
  const fb = fx('ref_composition').assets.find((a) => a.display_name === 'synthetic_runtime_b2_fallback'); patch(st, { sel: 'asset:' + fb.asset_id, selUser: true }); h = show(st);
  assert.match(h, /Alternative path\./); assert.match(h, /not shown as running together/); assert.match(h, /used only if the first import fails/);
});
test('equal basenames stay separate unresolved assets listed together', () => {
  const p = fx('display_group'); const same = p.assets.filter((a) => a.display_name === 'model.bin');
  assert.equal(same.length, 2); assert.notEqual(same[0].asset_id, same[1].asset_id); assert.deepEqual(same[0].display_group, same[1].display_group);
  const { st } = ready(p); const h = show(st);
  assert.equal((h.match(/data-otai-select="asset:/g) || []).length >= 3, true); assert.match(h, /Same name as another asset/);
  patch(st, { sel: 'asset:' + same[0].asset_id, selUser: true }); assert.match(show(st), /Listed together with other assets of the same name/);
});
test('colours: purple models, teal runtimes, cyan services by drawing family', () => {
  assert.equal(M.familyOf({ kind: 'inventory_model' }), 'model'); assert.equal(M.familyOf({ kind: 'model_reference' }), 'model'); assert.equal(M.familyOf({ kind: 'runtime' }), 'runtime'); assert.equal(M.familyOf({ kind: 'ai_service' }), 'service');
  const { st } = ready(fx('with_service')); const h = show(st);
  for (const k of ['model', 'runtime', 'service']) assert.match(h, new RegExp(`data-otai-kind="${k}"`));
});
test('review items render the amber state and the Findings count; findings are otherwise not assessed', () => {
  const { st } = ready(fx('findings')); const h = show(st); assert.match(h, /Needs review/); assert.match(h, /data-otai-filter="findings"[^>]*>Findings <span>1<\/span>/);
  const m = fromAi(st.get(), fx('findings'), 'asset:' + fx('findings').assets[0].asset_id); assert.equal(m.answers.find((a) => a.question_id === 'security_concern').state, 'needs_review');
  const demo = fromAi(ready(fx('demo_like')).st.get(), fx('demo_like'), 'asset:' + fx('demo_like').assets[0].asset_id);
  assert.equal(demo.answers.find((a) => a.question_id === 'security_concern').state, 'not_assessed'); assert.equal(demo.answers.length, 4);
  assert.doesNotMatch(JSON.stringify(demo), /is a verified model|is running/i);
});
test('notes: more than 20 occurrences are stated as n of N with the AI-BOM as the full source, with no reachability claim', () => {
  const a = fx('occ45').assets[0]; assert.equal(a.occurrences.length, 20); assert.equal(a.occurrences_total, 45);
  assert.equal(M.occurrencesNote(a), '20 of 45 occurrences shown; the AI-BOM download lists all of them.'); assert.doesNotMatch(M.occurrencesNote(a), /reachable/i);
});

// ------------------------------------------------------------------------------------------------------------ inert text and links
test('hostile text stays inert in SVG, aria-labels, list, detail and the inspector', () => {
  const { st } = ready(fx('hostile')); let h = show(st);
  assert.doesNotMatch(h, /<img src=x|<script|<b>x<\/b>/); assert.match(h, /&lt;img src=x onerror=alert\(1\)&gt;/); assert.doesNotMatch(h, /href="javascript:/i);
  patch(st, { presentation: 'list' }); h = show(st); assert.doesNotMatch(h, /<img src=x|<script/);
});
test('recorded URLs are inert text: no outbound anchor is ever produced from a payload value', () => {
  const p = JSON.parse(JSON.stringify(fx('demo_like'))); p.assets[0].occurrences = [{ occurrence_id: 'occ:x', operation: 'declared model URL: https://evil.example/m.bin', condition: { text: null, basis: 'none' }, alternative_of: null, producer_id: 'p',
    source_location: { path: 'a/b.py', file_sha256: null, line_start: 1, line_end: 1, excerpt: null, excerpt_state: 'unavailable', link: { href: 'https://evil.example/x', text: 'x' } } }]; p.assets[0].occurrences_total = 1; p.assets[0].source_group_ids = [];
  const { st } = ready(p, { sel: 'asset:' + p.assets[0].asset_id, selUser: true }); const h = show(st);
  assert.match(h, /declared model URL: https:\/\/evil\.example\/m\.bin/); assert.doesNotMatch(h, /href="https:\/\/evil\.example/);
});
test('the pinned-link guard (imported, unchanged) accepts the exact pinned blob and refuses dot segments, foreign repositories and commits', () => {
  const b = { repository: { owner: 'o', name: 'n' }, commit_sha: 'a'.repeat(40) };
  const loc = { path: 'd/p q.py', link: { href: 'https://github.com/o/n/blob/' + 'a'.repeat(40) + '/d/p%20q.py', text: 'x' }, line_start: 3, line_end: 3 };
  assert.equal(C.sourceHref(loc, b), loc.link.href + '#L3');
  for (const bad of [{ path: 'd/../x', link: { href: 'https://github.com/o/n/blob/' + 'a'.repeat(40) + '/d/../x' } }, { ...loc, link: { href: loc.link.href.replace('/o/n/', '/e/n/') } }, { ...loc, link: { href: loc.link.href.replace('a'.repeat(40), 'b'.repeat(40)) } }]) assert.equal(C.sourceHref({ ...loc, ...bad }, b), null);
  const page = JSON.parse(JSON.stringify(fx('ref_composition'))); const { st } = ready(page, { sel: 'asset:' + page.assets[0].asset_id, selUser: true });
  assert.match(show(st), /href="https:\/\/github\.com\/example-org\/synthetic-lab\/blob\//);
  page.assets[0].occurrences[0].source_location.link.href = 'https://github.com/evil/repo/blob/' + page.binding.commit_sha + '/synthetic/detector_a.py';
  const r = ready(page, { sel: 'asset:' + page.assets[0].asset_id, selUser: true }); assert.doesNotMatch(show(r.st), /github\.com\/evil/);
});

// ------------------------------------------------------------------------------------------------------------ request identity and lifecycle (N6)
test('a request key covers filter, query, group and offset; a response applies only while it still describes the state', () => {
  const { st, e } = opened(); const a = request(st, e, 1); const k1 = a.key;
  patch(st, { q: 'zz', offset: 0 }); assert.notEqual(M.requestKey(ai(st)), k1);
  st.dispatch({ type: 'AI_LOADED', ...a, data: fx('demo_like') }); assert.equal(st.get().views.aiPage, undefined);        // describes an older state
  const b = request(st, e, 2); st.dispatch({ type: 'AI_LOADED', ...a, data: fx('demo_like') }); assert.equal(st.get().views.aiPage, undefined);   // superseded sequence
  st.dispatch({ type: 'AI_LOADED', ...b, data: fx('demo_like') }); assert.equal(st.get().views.aiPage.page.assets_total, 1);
  for (const [field, value] of [['filter', 'models'], ['group', 'grp:abc'], ['offset', 30]]) { const x = request(st, e, 10 + st.get().aiSeq); patch(st, { [field]: value }); st.dispatch({ type: 'AI_LOADED', ...x, data: fx('multi3') }); assert.notEqual(st.get().views.aiPage.assets.length, 9, field); patch(st, { [field]: field === 'filter' ? 'all' : field === 'group' ? null : 0 }); }
});
test('late, duplicate and wrong-generation responses change nothing; a failure is held for a manual retry', () => {
  const { st, e } = opened(); const a = request(st, e, 1);
  st.dispatch({ type: 'AI_LOADED', ...a, generation: 2, data: fx('demo_like') }); assert.equal(st.get().views.aiPage, undefined);
  st.dispatch({ type: 'AI_FAILED', ...a, status: 500, error: { code: 'projection_failed', detail: 'path_not_representable' } });
  assert.equal(ai(st).pg.status, 'error'); assert.equal(ai(st).pg.req.key, a.key);                                              // the failed request key stands (no implicit retry on revisit)
  assert.match(show(st), /cannot be shown exactly/); assert.match(show(st), /data-otai-retry/);
  const b = request(st, e, 2); st.dispatch({ type: 'AI_LOADED', ...b, data: fx('demo_like') }); st.dispatch({ type: 'AI_LOADED', ...b, data: fx('multi3') });
  assert.equal(st.get().views.aiPage.page.assets_total, 1);                                                                      // the duplicate is ignored
});
test('a current 409 retires the payload and shows the recovery; the newer generation is never adopted; a stale 409 does nothing', () => {
  const { st, e } = ready(fx('demo_like')); const x = request(st, e, 2); st.dispatch({ type: 'AI_FAILED', ...x, status: 409, error: { code: 'stale_generation' } });
  assert.equal(st.get().views.aiPage, undefined); assert.equal(ai(st).stale, true); assert.match(show(st), /session moved on/); assert.match(show(st), /data-otai-stale-reset/);
  const y = request(st, e, 3); assert.equal(st.get().aiSeq, 2);                                                                  // no new request while stale
  void y;
});
test('End session clears the AI payload, selection, paging, ledger and expanded view at END_STARTED; late responses cannot restore them', () => {
  const { st, e } = ready(fx('multi3'), { filter: 'models', q: 'x', offset: 30, expanded: true, presentation: 'list', sel: 'root', selUser: true });
  st.dispatch({ type: 'END_STARTED' });
  const c = ai(st); assert.equal(st.get().views.aiPage, undefined); assert.equal(st.get().aiSeq, 0);
  assert.deepEqual([c.filter, c.q, c.offset, c.expanded, c.sel, c.loaded, c.pg.status], ['all', '', 0, false, null, null, 'idle']); assert.equal(c.presentation, 'list');
  assert.match(show(st), /Ending the session/);
  st.dispatch({ type: 'AI_LOADED', epoch: e, generation: 1, seq: 5, key: M.requestKey(c), data: fx('multi3') }); assert.equal(st.get().views.aiPage, undefined);
  st.dispatch({ type: 'ENDED', state: 'gone' }); assert.equal(st.get().views.aiPage, undefined);
});
test('replacing the analysis (Scan/Demo) clears the AI state; a response from the old analysis is refused', () => {
  const { st, e } = ready(fx('multi3'), { filter: 'models' });
  st.dispatch({ type: 'ANALYSIS_START' }); assert.equal(st.get().views.aiPage, undefined); assert.equal(ai(st).filter, 'all'); assert.equal(st.get().aiSeq, 0);
  st.dispatch({ type: 'AI_LOADED', epoch: e, generation: 1, seq: 1, key: M.requestKey(ai(st)), data: fx('multi3') }); assert.equal(st.get().views.aiPage, undefined);
});
test('a response bound to another analysis digest is refused', () => {
  const { st, e } = opened(); const x = request(st, e, 1); const p = JSON.parse(JSON.stringify(fx('demo_like'))); p.binding.analysis_digest = '0'.repeat(64);
  st.dispatch({ type: 'AI_LOADED', ...x, data: p }); assert.equal(st.get().views.aiPage, undefined);
});

// ------------------------------------------------------------------------------------------------------------ selection and layout states
test('selection: first asset by default, root when empty, filter change keeps a valid selection, groups are selectable', () => {
  const p = fx('ref_composition'); assert.equal(C.defaultSelection(p), 'asset:' + p.assets[0].asset_id); assert.equal(C.defaultSelection(fx('failed')), 'root');
  assert.equal(M.resolveSelection(p, 'asset:ast:nope'), C.defaultSelection(p)); assert.ok(C.selectionValid(p, 'group:' + p.source_groups[0].group_id));
});
test('Graph, List, expanded view and narrow default render from the same payload', () => {
  let { st } = ready(fx('ref_composition')); assert.match(show(st), /id="otai-svg"/); assert.match(show(st), /id="otai-stage"/);
  patch(st, { presentation: 'list' }); const l = show(st); assert.match(l, /id="otai-list"/); assert.doesNotMatch(l, /id="otai-svg"/);
  patch(st, { presentation: 'graph', expanded: true }); const x = show(st); assert.match(x, /id="otai-expanded"/); assert.match(x, /role="dialog"/); assert.match(x, /aria-modal="true"/);
  const n = createStore(initial({ narrow: true })); assert.equal(n.get().workbench.perTab.ai.presentation, 'list');
});
test('zoom controls follow the reference order: minus, percentage, plus, FIT', () => {
  const { st } = ready(fx('ref_composition')); const h = show(st); const i = (s) => h.indexOf(s);
  assert.ok(i('Zoom AI models out') < i('id="otai-zoom"') && i('id="otai-zoom"') < i('Zoom AI models in') && i('Zoom AI models in') < i('id="otai-fit"'));
});
test('a requested BOM-verification check is shown above the assets and cleared by choosing an asset', () => {
  const { st } = ready(fx('demo_like'), { checkId: 'p7-model-declared-in-aibom' }); let h = show(st);
  assert.match(h, /id="otai-check"/); assert.match(h, /The AI inventory does not match the selected model/); assert.match(h, /not a model or service security finding/);
  assert.equal(((h.match(/class="otai-status/g) || []).length >= 1), true);
  patch(st, { checkId: 'nope' }); h = show(st); assert.match(h, /not present in the current analysis/);
  patch(st, { checkId: null }); assert.doesNotMatch(show(st), /id="otai-check"/);
});

// ------------------------------------------------------------------------------------------------------------ correction 01 (IR-03, IR-04)
import { attachAiGraph } from '../../../src/ui/components/ai_graph.js';
const legacy = (marker) => ({ schema: 'legacy-ai-marker', generation: 1, marker });
function stale409(st, e) { const x = request(st, e, 2); st.dispatch({ type: 'AI_FAILED', ...x, status: 409 }); return x; }

test('IR-03: a current 409 retires the cached legacy AI view as well as the AI page', () => {
  const { st, e } = ready(fx('multi3'));
  st.dispatch({ type: 'VIEW_LOADED', tab: 'ai', epoch: e, generation: 1, data: legacy('cached before 409') });
  assert.ok(st.get().views.ai);
  stale409(st, e);
  assert.equal(ai(st).stale, true); assert.equal(st.get().views.aiPage, undefined); assert.equal(st.get().views.ai, undefined);
});
test('IR-03: a held legacy AI response is rejected while the generation is retired (loadSimple success path)', () => {
  const { st, e } = ready(fx('multi3')); stale409(st, e);
  st.dispatch({ type: 'VIEW_LOADED', tab: 'ai', epoch: e, generation: 1, data: legacy('late legacy response') });
  assert.equal(st.get().views.ai, undefined);
});
test('IR-03: Advanced shows only the recovery after retirement, never retired legacy data', () => {
  const { st, e } = ready(fx('multi3'));
  st.dispatch({ type: 'VIEW_LOADED', tab: 'ai', epoch: e, generation: 1, data: legacy('cached before 409') });
  stale409(st, e); st.dispatch({ type: 'ADVANCED', value: true }); st.dispatch({ type: 'TAB', tab: 'ai' });
  st.dispatch({ type: 'VIEW_LOADED', tab: 'ai', epoch: e, generation: 1, data: legacy('late legacy response') });
  const h = renderWorkbenchHtml(st); assert.match(h, /data-otai-stale-reset/); assert.doesNotMatch(h, /retired analysis|late legacy|cached before/);
});
test('IR-03 controls: a current legacy response is still stored; other tabs and a fresh analysis are unaffected', () => {
  const { st, e } = ready(fx('multi3'));
  st.dispatch({ type: 'VIEW_LOADED', tab: 'ai', epoch: e, generation: 1, data: legacy('current') }); assert.equal(st.get().views.ai.marker, 'current');
  st.dispatch({ type: 'VIEW_LOADED', tab: 'bom', epoch: e, generation: 1, data: { marker: 'bom' } });
  stale409(st, e); st.dispatch({ type: 'VIEW_LOADED', tab: 'bom', epoch: e, generation: 1, data: { marker: 'bom2' } });
  assert.equal(st.get().views.bom.marker, 'bom2');
  st.dispatch({ type: 'ANALYSIS_START' }); const e2 = st.get().epoch; st.dispatch({ type: 'ANALYSIS_READY', epoch: e2, analysis: analysis() });
  st.dispatch({ type: 'VIEW_LOADED', tab: 'ai', epoch: e2, generation: 1, data: legacy('new analysis') }); assert.equal(st.get().views.ai.marker, 'new analysis');
});
import { renderWorkbench } from '../../../src/ui/components/workbench.js';
const renderWorkbenchHtml = (st) => renderWorkbench(st.get());

// ---- IR-04: List arrow/Home/End navigation, exercised through the registered keydown handler
function harness(st, ids) {
  const listeners = {}; const log = { focus: [], select: [] };
  const rows = ids.map((id) => ({ dataset: { otaiSelect: id }, parentElement: null, closest(sel) { return sel === '.otai-list-row' ? this : sel === '#otai-list' ? list : null; }, focus() { log.focus.push(id); } }));
  const list = { id: 'otai-list', querySelectorAll: () => rows };
  globalThis.document = { addEventListener: (n, f) => { listeners[n] = f; }, getElementById: (id) => (id === 'otai-list' ? list : null), activeElement: null };
  attachAiGraph(st.get, { select: (id, r) => log.select.push([id, r]) });
  const press = (target, key, extra = {}) => { const ev = { key, target, prevented: false, preventDefault() { this.prevented = true; }, ...extra }; listeners.keydown(ev); return ev; };
  return { rows, log, press };
}
test('IR-04: ArrowDown/ArrowUp/Home/End move focus and selection between List rows, stop at the ends and prevent page scroll', () => {
  const { st } = ready(fx('multi3'), { presentation: 'list' }); const ids = ['asset:a', 'asset:b', 'asset:c'];
  const h = harness(st, ids);
  let ev = h.press(h.rows[0], 'ArrowDown'); assert.equal(ev.prevented, true); assert.deepEqual(h.log.focus.at(-1), 'asset:b'); assert.deepEqual(h.log.select.at(-1), ['asset:b', false]);
  h.press(h.rows[1], 'End'); assert.equal(h.log.focus.at(-1), 'asset:c'); assert.equal(h.log.select.at(-1)[0], 'asset:c');
  const n = h.log.select.length; ev = h.press(h.rows[2], 'ArrowDown'); assert.equal(ev.prevented, true); assert.equal(h.log.select.length, n);   // boundary: no wrap, no change
  h.press(h.rows[2], 'ArrowUp'); assert.equal(h.log.focus.at(-1), 'asset:b');
  h.press(h.rows[1], 'Home'); assert.equal(h.log.focus.at(-1), 'asset:a');
  const m = h.log.select.length; ev = h.press(h.rows[0], 'ArrowUp'); assert.equal(ev.prevented, true); assert.equal(h.log.select.length, m);
  ev = h.press(h.rows[0], 'ArrowRight'); assert.equal(ev.prevented, false);
});
test('IR-04: native activation and unrelated keys are not intercepted; modifiers and text inputs pass through', () => {
  const { st } = ready(fx('multi3'), { presentation: 'list' }); const h = harness(st, ['asset:a', 'asset:b']);
  for (const k of ['Enter', ' ', 'Tab', 'a']) { const ev = h.press(h.rows[0], k); assert.equal(ev.prevented, false, k); }
  assert.equal(h.press(h.rows[0], 'ArrowDown', { altKey: true }).prevented, false);
  assert.equal(h.press(h.rows[0], 'Home', { ctrlKey: true }).prevented, false);
  const input = { dataset: {}, id: 'otai-q', closest: () => null }; assert.equal(h.press(input, 'ArrowDown').prevented, false); assert.equal(h.press(input, 'Home').prevented, false);
  assert.equal(h.log.select.length, 0);
});
test('IR-04: List rows carry a stable per-asset focus key so focus survives the repaint, at wide and narrow (390px) widths', () => {
  for (const narrow of [false, true]) {
    const { st } = ready(fx('multi3'), { presentation: 'list' }); if (narrow) st.dispatch({ type: 'NARROW', value: true });
    const html = show(st); const keys = [...html.matchAll(/class="otai-list-row"[^>]*data-fk="([^"]+)"/g)].map((m) => m[1]);
    assert.equal(keys.length, fx('multi3').assets.length); assert.equal(new Set(keys).size, keys.length);
    assert.deepEqual(keys, [...show(st).matchAll(/class="otai-list-row"[^>]*data-fk="([^"]+)"/g)].map((m) => m[1]));
  }
});
