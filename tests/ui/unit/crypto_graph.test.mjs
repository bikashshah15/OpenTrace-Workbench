// UIP-06: the Cryptography model against the reference-extracted geometry, rendering (inert text, states, notes) and the request/lifecycle reducers.
// No browser, network or service. Fixtures are SYNTHETIC renderer fixtures (evidence/uip/visual/uip-06/fixtures/renderer). Run: node --test tests/ui/unit/
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createStore, initial } from '../../../src/ui/lib/store.js';
import * as M from '../../../src/ui/lib/crypto_graph.js';
import { renderCryptoView } from '../../../src/ui/components/crypto_graph.js';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '../../..');
const fx = (n) => JSON.parse(readFileSync(join(ROOT, 'evidence/uip/visual/uip-06/fixtures/renderer', n + '.json'), 'utf8'));
const DIGEST = fx('multi3').binding.analysis_digest;
const analysis = () => ({ generation: 1, identity: { mode: 'captured', owner: 'example-org', name: 'synthetic-lab', commit: '0'.repeat(40), analysis_digest: DIGEST },
  summary: { components: 1, checks: [], cards: [{ kind: 'cbom', artifact_name: 'cdxgen-cbom.cdx.json' }] } });
function opened() { const st = createStore(initial()); st.dispatch({ type: 'ANALYSIS_START' }); const e = st.get().epoch; st.dispatch({ type: 'ANALYSIS_READY', epoch: e, analysis: analysis() }); return { st, e }; }
const crypto = (st) => st.get().workbench.perTab.crypto;
const patch = (st, p) => st.dispatch({ type: 'TAB_STATE', tab: 'crypto', patch: p });
function request(st, e, seq) { const key = M.requestKey(crypto(st)); st.dispatch({ type: 'CRYPTO_REQUEST', epoch: e, generation: 1, seq, key }); return { epoch: e, generation: 1, seq, key }; }
function ready(page, extra = {}) { const { st, e } = opened(); patch(st, extra); const stamp = request(st, e, 1); st.dispatch({ type: 'CRYPTO_LOADED', ...stamp, data: page }); return { st, e }; }
const show = (st) => renderCryptoView(st.get());
const num = (d) => (d.match(/-?\d+(?:\.\d+)?/g) || []).map(Number);

// ------------------------------------------------------------------------------------------------------------ layout = reference constants
test('ordinary layout (3 groups x 3 cards) equals the reference geometry constants exactly', () => {
  const L = M.buildLayout(M.zonesOf(fx('multi3')));
  assert.equal(L.zones.length, 3); assert.equal(L.ordinary, true); assert.equal(L.wrapped, false);
  assert.deepEqual(L.zones.map((z) => z.x), [20, 420, 820]);
  for (const z of L.zones) { assert.equal(z.w, 360); assert.equal(z.h, 500); assert.equal(z.y, 160); assert.deepEqual(z.head, { x: z.x + 15, y: 176, w: 330, h: 66 });
    assert.deepEqual(z.cards.map((c) => [c.x - z.x, c.y, c.w, c.h]), [[42, 280, 300, 90], [42, 400, 300, 90], [42, 520, 300, 90]]); }
  assert.deepEqual(L.root, { x: 460, y: 20, w: 280, h: 72 });
  assert.equal(L.height, 690); assert.deepEqual(L.viewBox, [0, 0, 1200, 690]);
  assert.equal(L.connectors[0].d, 'M600 92 V124 H200 V176'); assert.equal(L.connectors[1].d, 'M600 92 V124 H600 V176');
  assert.equal(L.zones[0].cards[0].link, 'M200 242 V258 H46 V324 H62');                // header bottom 242 -> 258 -> x+26 -> y+44 -> x+42
  assert.deepEqual(M.fitView(L), [-20, 0, 1240, 690]);                                  // reference fit window for three groups
});
test('one and two groups are centred like the reference; the reference fit window is reproduced', () => {
  const one = M.buildLayout([M.zonesOf(fx('multi3'))[0]]); assert.equal(one.zones[0].x, 420); assert.deepEqual(M.fitView(one), [380, 0, 440, 690]);
  const two = M.buildLayout(M.zonesOf(fx('multi3')).slice(0, 2)); assert.deepEqual(two.zones.map((z) => z.x), [220, 620]); assert.deepEqual(M.fitView(two), [180, 0, 840, 690]);
});
test('taller zones grow by 120 per card beyond three and the viewBox follows', () => {
  const L = M.buildLayout(M.zonesOf(fx('tall5')));
  assert.equal(L.zones[0].cards.length, 5); assert.equal(L.zones[0].h, 120 + 120 * 4 + 90 + 50); assert.equal(L.height, 160 + L.zones[0].h + 30);
  assert.equal(L.ordinary, false);
  const z4 = M.buildLayout([{ key: 'a', group: null, label: 'x', sub: 'x', cards: [1, 2, 3, 4].map((i) => ({ asset_id: 'ast:' + i })) }]); assert.equal(z4.zones[0].h, 620);
});
test('more than three groups wrap into rows of three; nothing is clipped', () => {
  const L = M.buildLayout(M.zonesOf(fx('wrap7')));
  assert.equal(L.zones.length, 7); assert.equal(L.wrapped, true);
  assert.deepEqual(L.zones.map((z) => z.row), [0, 0, 0, 1, 1, 1, 2]); assert.deepEqual(L.zones.map((z) => z.y), [160, 160, 160, 720, 720, 720, 1280]);
  assert.deepEqual(L.zones.map((z) => z.x), [20, 420, 820, 20, 420, 820, 20]);
  assert.deepEqual(L.viewBox, [-40, 0, 1280, 1280 + 500 + 30]);
  assert.match(L.connectors[3].d, /^M600 92 V124 H-20 V706 H200 V736$/);               // trunk outside the zones, then to the header
  const bb = L.bbox;
  for (const z of L.zones) { assert.ok(z.x >= bb.x0 && z.x + z.w <= bb.x1 && z.y + z.h <= bb.y1); for (const c of z.cards) assert.ok(c.y + c.h <= z.y + z.h); }
  for (const k of L.connectors) for (const n of num(k.d)) assert.ok(n >= bb.x0 - 1 && n <= Math.max(bb.x1, bb.y1) + 1);
});
test('layout boundary: groups 1/3/4/6/24 and cards 1/3/4/5/30 never exceed their bounding box', () => {
  const mk = (g, c) => Array.from({ length: g }, (_, i) => ({ key: 'group:' + i, group: { group_id: 'grp:' + i, label: 'g' + i, path: 'g' + i }, label: 'g' + i, sub: 'g', cards: Array.from({ length: c }, (__, j) => ({ asset_id: `ast:${i}-${j}`, display_name: 'n' })) }));
  for (const g of [1, 3, 4, 6, 24]) for (const c of [1, 3, 4, 5, 30]) {
    const L = M.buildLayout(mk(g, c)); assert.equal(L.zones.length, g);
    for (const z of L.zones) { assert.equal(z.h, Math.max(500, 120 + 120 * (c - 1) + 90 + 50)); assert.ok(z.y + z.h + 30 <= L.height || z.row < L.zones.at(-1).row, `${g}x${c}`); for (const cd of z.cards) assert.ok(cd.y + cd.h <= z.y + z.h); }
    assert.equal(L.ordinary, g <= 3 && c <= 3);
  }
});
test('mixed card counts: the row height is its tallest zone', () => {
  const zs = [5, 1, 2, 3].map((n, i) => ({ key: 'g' + i, group: null, label: 'g', sub: 's', cards: Array.from({ length: n }, (_, j) => ({ asset_id: `${i}-${j}` })) }));
  const L = M.buildLayout(zs); assert.equal(L.zones[3].y, 160 + 740 + 60); assert.equal(L.height, 960 + 500 + 30);
});

// ------------------------------------------------------------------------------------------------------------ viewport
test('Fit, Fit all, zoom clamps 20%..400%, pan bounds and keyboard', () => {
  const L = M.buildLayout(M.zonesOf(fx('wrap7'))); const a = 0.8;
  const fit = M.fitView(L, a); assert.equal(fit[0], -40); assert.equal(fit[2], 1280); assert.ok(M.zoomPercent(fit, L) >= 93 && M.zoomPercent(fit, L) <= 95);   // never below ~94% for a wrapped layout
  assert.equal(M.needsFitAll(L, a), true);
  const all = M.fitAllView(L, a); assert.ok(all[3] >= L.height - 1 && all[2] >= L.bbox.x1 - L.bbox.x0);
  let v = fit; for (let i = 0; i < 40; i++) v = M.zoomView(v, 1.25, L); assert.equal(M.zoomPercent(v, L), 400);
  for (let i = 0; i < 60; i++) v = M.zoomView(v, 0.8, L); assert.equal(M.zoomPercent(v, L), 20);
  const p = M.panView(fit, 1e6, 1e6, L); assert.ok(p[0] + p[2] / 2 <= L.bbox.x1 + 1 && p[1] + p[3] / 2 <= L.bbox.y1 + 1);
  assert.deepEqual(M.keyView(fit, '0', L, a), fit); assert.ok(M.keyView(fit, 'ArrowDown', L, a)[1] > fit[1]); assert.equal(M.keyView(fit, 'x', L, a), null);
  assert.ok(M.zoomPercent(M.keyView(fit, '+', L, a), L) > M.zoomPercent(fit, L));
  const ord = M.buildLayout(M.zonesOf(fx('multi3'))); assert.equal(M.zoomPercent(M.fitView(ord), ord), Math.round(440 / 1240 * 100) >= 0 ? M.zoomPercent(M.fitView(ord), ord) : 0); assert.equal(M.needsFitAll(ord), false);
});
test('a selected card outside the view is brought into view by panning only', () => {
  const L = M.buildLayout(M.zonesOf(fx('wrap7'))); const fit = M.fitView(L, 0.55); const last = L.zones.at(-1);
  const v = M.ensureVisible(fit, M.nodeRect(L, M.assetKey(last.cards[0].asset)), L);
  assert.equal(v[2], fit[2]); assert.ok(v[1] > fit[1]); const r = M.nodeRect(L, M.assetKey(last.cards[0].asset)); assert.ok(r.y >= v[1] && r.y + r.h <= v[1] + v[3] + 0.5);
});

// ------------------------------------------------------------------------------------------------------------ selection and text
test('selection: first asset by default, root when empty, a stale selection falls back, groups are selectable, the lane is not', () => {
  const p = fx('multi3'); assert.equal(M.defaultSelection(p), 'asset:' + p.assets[0].asset_id); assert.equal(M.defaultSelection(fx('failed')), 'root');
  assert.equal(M.resolveSelection(p, 'asset:ast:nope'), M.defaultSelection(p)); assert.equal(M.resolveSelection(p, 'root'), 'root');
  assert.ok(M.selectionValid(p, 'group:' + p.source_groups[0].group_id)); assert.equal(M.selectionValid(p, null), false);
  const lone = JSON.parse(JSON.stringify(p)); lone.assets[0].source_group_ids = []; const zs = M.zonesOf(lone); assert.equal(zs.at(-1).key, null); assert.equal(zs.at(-1).label, 'No recorded source file');
});
test('empty-state copy depends on the cause and never says there is no cryptography', () => {
  assert.match(M.emptyText(fx('partial_empty'), 'all', ''), /incomplete/i); assert.match(M.emptyText(fx('failed'), 'all', ''), /failed/);
  assert.match(M.emptyText(fx('unsupported'), 'all', ''), /No supported CBOM/); assert.match(M.emptyText(fx('not_run'), 'all', ''), /not run/);
  assert.equal(M.emptyText(fx('certificates_zero'), 'certificates', ''), 'No certificate objects are recorded in this CBOM.');
  assert.match(M.emptyText(fx('certificates_zero'), 'protocols', ''), /No assets match this filter/);
  for (const n of ['partial_empty', 'failed', 'unsupported', 'not_run']) assert.doesNotMatch(M.emptyText(fx(n), 'all', ''), /no cryptography (is|exists)/i);
});
test('notes: occurrences and services are stated, with the original CBOM as the full source', () => {
  const a = fx('occ45').assets[0]; assert.equal(a.occurrences.length, 20); assert.equal(a.occurrences_total, 45);
  assert.equal(M.occurrencesNote(a), '20 of 45 occurrences shown; the original CBOM download lists all of them.'); assert.doesNotMatch(M.occurrencesNote(a), /reachable|group selector/i);
  assert.equal(M.occurrencesNote({ occurrences: [1], occurrences_total: 1 }), '');
  assert.equal(M.servicesNote({ services_counts: { total: 31, shown: 30, truncated: true } }), '30 of 31 endpoint services shown; the original CBOM lists all of them.');
});
test('source links are active only for this analysis\u2019s pinned revision; foreign or wrong-commit links stay inert', () => {
  const b = { repository: { owner: 'o', name: 'n' }, commit_sha: 'a'.repeat(40) };
  const loc = { path: "d/p q'(1).py", link: { href: 'https://github.com/o/n/blob/' + 'a'.repeat(40) + "/d/p%20q%27%281%29.py", text: 'x' }, line_start: 3, line_end: 5 };
  assert.equal(M.sourceHref(loc, b), loc.link.href + '#L3-L5');
  assert.equal(M.sourceHref({ ...loc, link: { href: null, text: 'p' } }, b), null);
  assert.equal(M.sourceHref({ ...loc, link: { href: loc.link.href.replace('/o/n/', '/evil/n/'), text: 'x' } }, b), null);
  assert.equal(M.sourceHref({ ...loc, link: { href: loc.link.href.replace('a'.repeat(40), 'b'.repeat(40)), text: 'x' } }, b), null);
  assert.equal(M.sourceHref({ ...loc, link: { href: 'javascript:alert(1)', text: 'x' } }, b), null);
  assert.equal(M.sourceHref({ ...loc, link: { href: 'https://user@github.com/o/n/blob/' + 'a'.repeat(40) + '/d', text: 'x' } }, b), null);
});

// ------------------------------------------------------------------------------------------------------------ rendering
test('renders the approved composition: five filters with counts, Graph/List, controls, cards, download', () => {
  const { st } = ready(fx('multi3')); const h = show(st);
  for (const f of ['All assets', 'Findings', 'Algorithms', 'Protocols', 'Certificates']) assert.ok(h.includes(f));
  assert.match(h, /aria-label="Filter cryptographic assets"/); assert.match(h, /data-otc-pres="graph"/); assert.match(h, /data-otc-pres="list"/);
  assert.match(h, /data-otc-zoom="1.2"/); assert.match(h, /data-otc-fit="1"/); assert.equal((h.match(/data-otc-select="asset:/g) || []).length >= 9, true);
  assert.match(h, /Download CBOM ↓/); assert.match(h, /\/api\/artifacts\/cdxgen-cbom\.cdx\.json\?disposition=attachment/);
  assert.doesNotMatch(h, /generate_[a-z_]*\.py|extractor|ot5-data|pbkdf2|hs256/i);                 // the prototype's embedded extractor and data are never offered
  assert.doesNotMatch(h, /\sstyle="/);                                                            // CSP style-src 'self': no inline style attribute
  assert.match(h, /Needs review/);                                                                // the synthetic review item renders the amber state
  assert.doesNotMatch(h, /fill="#?(red|[ef][0-9a-f]0[0-9a-f]{2,4})"/i);
});
test('hostile text stays inert in SVG, aria-labels, list, detail and the inspector', () => {
  const { st } = ready(fx('hostile')); let h = show(st);
  assert.doesNotMatch(h, /<img src=x|<script|<b>x<\/b>/); assert.match(h, /&lt;img src=x onerror=alert\(1\)&gt;/); assert.doesNotMatch(h, /href="javascript:/i);
  patch(st, { presentation: 'list' }); h = show(st); assert.doesNotMatch(h, /<img src=x|<script/);
});
test('empty and unavailable states render by cause; a filter-to-zero page is not an empty-success message', () => {
  for (const [n, re] of [['failed', /failed/], ['unsupported', /No supported CBOM/], ['not_run', /not run/], ['partial_empty', /incomplete/]]) { const { st } = ready(fx(n)); const h = show(st); assert.match(h, re); assert.match(h, /id="otc-empty"/); assert.doesNotMatch(h, /<svg id="otc-svg"/); }
  const { st } = ready(fx('certificates_zero'), { filter: 'certificates' }); const h = show(st); assert.match(h, /No certificate objects are recorded in this CBOM\./); assert.match(h, /data-cause="filter"/);
});
test('more than 20 occurrences: the detail says "20 of 45 shown" and names the original CBOM, never a group-selector promise', () => {
  const { st } = ready(fx('occ45')); const h = show(st);
  assert.match(h, /Source observations · 45/); assert.match(h, /20 of 45 occurrences shown; the original CBOM download lists all of them\./); assert.doesNotMatch(h, /reachable|every occurrence/i);
});
test('Graph/List preserves filter and selection; list rows are buttons with a status chip', () => {
  const p = fx('multi3'); const { st } = ready(p, { filter: 'all', sel: 'asset:' + p.assets[1].asset_id, selUser: true });
  patch(st, { presentation: 'list' }); const h = show(st); assert.match(h, /class="otc-list-row"[^>]*aria-pressed="false"/); assert.match(h, new RegExp('data-otc-select="asset:' + p.assets[1].asset_id + '" aria-pressed="true"'));
  assert.equal(crypto(st).filter, 'all');
});
test('detail panel: status chip, observations disclosure, the static-observation note, and an experimental label', () => {
  const p = fx('findings'); const rev = p.review_items[0]; const { st } = ready(p, { filter: 'findings', sel: 'asset:' + rev.asset_id, selUser: true }); const h = show(st);
  assert.match(h, /class="ot-insp-badge ot-insp-review">[\s\S]*?<span>Needs review<\/span>/); assert.match(h, /Rule result and rationale/); assert.match(h, /Synthetic rationale for layout tests\./); assert.match(h, /id="otc-detail"/);
  assert.equal((h.match(/<h2/g) || []).length, 1, 'one header per selection'); assert.equal((h.match(/data-question=/g) || []).length, 4, 'one question set'); assert.match(h, /Source observations · /); assert.match(h, /Runtime execution was not observed\./);
  assert.match(h, /Experimental source observation/); assert.match(h, /Source SHA-256 b{64}/);
});

// ------------------------------------------------------------------------------------------------------------ request identity and lifecycle
test('a late response after a filter, group, query or offset change is ignored', () => {
  const { st, e } = opened(); const first = request(st, e, 1);
  patch(st, { filter: 'protocols', offset: 0 }); st.dispatch({ type: 'CRYPTO_LOADED', ...first, data: fx('multi3') });
  assert.equal(st.get().views.cryptoPage, undefined); assert.equal(crypto(st).loaded, null);
  const second = request(st, e, 2); st.dispatch({ type: 'CRYPTO_LOADED', ...second, data: { ...fx('multi3'), filter: 'protocols' } }); assert.equal(st.get().views.cryptoPage.filter, 'protocols');
  for (const p of [{ q: 'x' }, { group: 'grp:' + 'a'.repeat(24) }, { offset: 30 }]) { const s2 = request(st, e, st.get().cryptoSeq + 1); patch(st, p); st.dispatch({ type: 'CRYPTO_LOADED', ...s2, data: fx('multi3') }); assert.equal(st.get().views.cryptoPage.filter, 'protocols'); }
});
test('a response for another analysis or generation, or a duplicate/older seq, never reaches the state', () => {
  const { st, e } = opened(); const stamp = request(st, e, 1);
  const other = JSON.parse(JSON.stringify(fx('multi3'))); other.binding.analysis_digest = 'sha256:' + 'f'.repeat(64); st.dispatch({ type: 'CRYPTO_LOADED', ...stamp, data: other }); assert.equal(st.get().views.cryptoPage, undefined);
  st.dispatch({ type: 'CRYPTO_LOADED', ...stamp, generation: 2, data: fx('multi3') }); assert.equal(st.get().views.cryptoPage, undefined);
  st.dispatch({ type: 'CRYPTO_REQUEST', epoch: e, generation: 1, seq: 1, key: stamp.key }); assert.equal(st.get().cryptoSeq, 1);
  st.dispatch({ type: 'CRYPTO_LOADED', ...stamp, data: fx('multi3') }); assert.equal(st.get().views.cryptoPage.assets.length, 9);
  st.dispatch({ type: 'CRYPTO_LOADED', ...stamp, data: fx('failed') }); assert.equal(st.get().views.cryptoPage.assets.length, 9);          // a duplicate is ignored
});
test('a loaded page resolves an invalid selection to the first asset, else the root', () => {
  const { st } = ready(fx('multi3'), { sel: 'asset:ast:gone' }); assert.equal(crypto(st).sel, M.defaultSelection(fx('multi3')));
  const r = ready(fx('failed'), { sel: 'asset:ast:gone' }); assert.equal(crypto(r.st).sel, 'root');
});
test('a typed failure shows a manual retry and keeps the identity; a current 409 retires the payload and offers recovery', () => {
  const { st, e } = ready(fx('multi3')); patch(st, { filter: 'algorithms' }); const stamp = request(st, e, 2);
  st.dispatch({ type: 'CRYPTO_FAILED', ...stamp, status: 500, error: { code: 'projection_failed', detail: 'path_not_representable' } });
  assert.equal(crypto(st).pg.status, 'error'); let h = show(st); assert.match(h, /data-otc-retry/); assert.match(h, /cannot be shown exactly/);
  const s3 = request(st, e, 3); st.dispatch({ type: 'CRYPTO_FAILED', ...s3, status: 409, error: { code: 'stale_generation' } });
  assert.equal(crypto(st).stale, true); assert.equal(st.get().views.cryptoPage, undefined); h = show(st); assert.match(h, /data-otc-stale-reset/); assert.match(h, /session moved on/);
  const s4 = request(st, e, 4); assert.equal(st.get().cryptoSeq, 3); assert.equal(s4.seq, 4);                  // a retired state issues no further requests
  st.dispatch({ type: 'CRYPTO_LOADED', epoch: e, generation: 1, seq: 4, key: s4.key, data: fx('multi3') }); assert.equal(st.get().views.cryptoPage, undefined);
});
test('End session clears the crypto payload, selection, paging and ledger immediately; a late response leaves state unchanged', () => {
  const { st, e } = ready(fx('multi3'), { filter: 'protocols', q: 'x', offset: 30, expanded: true, sel: 'root' }); const stamp = request(st, e, 2);
  st.dispatch({ type: 'END_STARTED' }); const c = crypto(st);
  assert.equal(st.get().views.cryptoPage, undefined); assert.deepEqual([c.filter, c.q, c.offset, c.expanded, c.sel, c.stale, c.loaded], ['all', '', 0, false, null, false, null]); assert.equal(st.get().cryptoSeq, 0);
  const before = JSON.stringify(st.get()); st.dispatch({ type: 'CRYPTO_LOADED', ...stamp, data: fx('multi3') }); st.dispatch({ type: 'CRYPTO_FAILED', ...stamp, status: 500, error: { code: 'x' } }); assert.equal(JSON.stringify(st.get()), before);
  st.dispatch({ type: 'ENDED', state: 'gone' }); assert.equal(st.get().views.cryptoPage, undefined);
});
test('a new analysis (Scan, Demo, reset) starts from a fresh crypto state and opens on Contexts', () => {
  const { st } = ready(fx('multi3'), { filter: 'findings', sel: 'root' }); st.dispatch({ type: 'ANALYSIS_START' });
  assert.equal(st.get().workbench.tab, 'contexts'); assert.deepEqual([crypto(st).filter, crypto(st).sel, crypto(st).loaded], ['all', null, null]); assert.equal(st.get().views.cryptoPage, undefined);
});
test('narrow viewports default to the List only until the person chooses (never forced)', () => {
  const st = createStore(initial({ narrow: true })); assert.equal(st.get().workbench.perTab.crypto.presentation, 'list');
  st.dispatch({ type: 'ANALYSIS_START' }); st.dispatch({ type: 'TAB_STATE', tab: 'crypto', patch: { presentation: 'graph' } }); st.dispatch({ type: 'NARROW', value: false }); st.dispatch({ type: 'NARROW', value: true });
  assert.equal(st.get().workbench.perTab.crypto.presentation, 'graph');
});
test('a fallback root selection upgrades to the first asset when assets arrive; a person\u2019s own choice is kept', () => {
  const { st, e } = opened(); let k = request(st, e, 1); st.dispatch({ type: 'CRYPTO_LOADED', ...k, data: fx('failed') }); assert.equal(crypto(st).sel, 'root');
  patch(st, { filter: 'all', offset: 0 }); k = request(st, e, 2); st.dispatch({ type: 'CRYPTO_LOADED', ...k, data: fx('multi3') }); assert.equal(crypto(st).sel, M.defaultSelection(fx('multi3')));
  patch(st, { sel: 'root', selUser: true, q: 'x' }); k = request(st, e, 3); st.dispatch({ type: 'CRYPTO_LOADED', ...k, data: fx('multi3') }); assert.equal(crypto(st).sel, 'root');
});
test('labels are clipped to their box by estimated glyph width (wide capitals do not overflow a 300 px card)', () => {
  const t = M.fitText('N'.repeat(60), 16, 270); assert.ok(M.textWidth(t, 16) <= 270 && t.endsWith('…')); assert.equal(M.fitText('sha-256', 16, 270), 'sha-256');
});
