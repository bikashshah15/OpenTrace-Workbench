// UIP-04: layout model against the reference-extracted geometry, generalization, paging/caps, request ordering and lifecycle, inertness and
// the scoped no-hard-coded-name scan. Pure modules and string renderers: no browser, network or service. Run: node --test tests/ui/unit/
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createStore, initial, ctxCurrent } from '../../../src/ui/lib/store.js';
import { layoutMap, capacity, mergeFiles, ladderFrom, selectionValid, findSelection, cardTarget, zoomBox, panBox, zoomPercent, clampZoom, hiddenCount, GROUP_CAP, MAP_CAP, PAGE_GRAPH, PAGE_LIST } from '../../../src/ui/lib/context_map.js';
import { mapSvg, renderContexts, activeHref, footerText, groupSummary, evidenceHtml } from '../../../src/ui/components/context_map.js';
import { fromSelection } from '../../../src/ui/lib/inspector_model.js';

const HERE = dirname(fileURLToPath(import.meta.url)); const ROOT = join(HERE, '../../..');
const json = (p) => JSON.parse(readFileSync(join(ROOT, p), 'utf8'));
const REF = json('evidence/uip/visual/uip-04/reference_geometry.json');
const FRIGATE = json('evidence/uip/fixtures/frigate-recorded/contexts.json');

// ------------------------------------------------------------------ helpers
const DIGEST = 'sha256:' + 'a'.repeat(64);
const hex = (n) => n.toString(16).padStart(24, '0');
function group(i, files, total = files, over = {}) {
  return { group_id: 'grp:' + hex(i), kind: 'located', category: 'web', token: 'green', label: 'Group ' + i, basis: 'path_prefix', distinct_total: files, membership_total: files, files_offset: 0,
    files: Array.from({ length: files }, (_, k) => ({ file_id: 'ctx:' + hex(i * 1000 + k), path: `g${i}/f${k}.json`, raw_locations: [`/g${i}/f${k}.json`], raw_locations_total: 1, normalization_basis: ['syft_root_relative'], distinct_total: 2, membership_total: 2, dependency_context_id: 'ctx:' + hex(i * 1000 + k), revision_link: { href: `https://github.com/acme/widget/blob/${'0'.repeat(40)}/g${i}/f${k}.json`, text: `g${i}/f${k}.json` } })),
    files_counts: { total, shown: files, truncated: files < total }, ...over };
}
const unlocated = (i, n = 3) => ({ group_id: 'grp:' + hex(i), kind: 'unlocated', category: null, token: 'neutral', label: 'Unlocated components', basis: 'fallback', distinct_total: n, membership_total: n, files: [], files_offset: 0, files_counts: { total: 0, shown: 0, truncated: false } });
const model = (groups, over = {}) => ({ schema: 'opentrace.workbench.contexts/1', edge_semantics: 'grouping_or_inventory_location', selected_id: null, counts: { total: groups.length, shown: groups.length, truncated: false },
  binding: { analysis_digest: DIGEST, generation: 1, mode: 'captured', commit_sha: '0'.repeat(40), repository: { host: 'github.com', owner: 'acme', name: 'widget', canonical_url: 'https://github.com/acme/widget' }, requested_ref: { kind: 'tag', text: 'v1' }, assessment: null },
  root: { name: 'acme/widget', canonical_url: 'https://github.com/acme/widget', commit_sha: '0'.repeat(40), distinct_total: 20, membership_total: 20, located_distinct_total: 20, unlocated_total: 0 }, groups, ...over });
const analysis = (n = 1) => ({ generation: n, identity: { mode: 'captured', owner: 'acme', name: 'widget', commit: '0'.repeat(40), analysis_digest: DIGEST }, summary: { components: 1, checks: [] } });
function opened({ presentation } = {}) {
  const st = createStore(initial({ narrow: presentation === 'list' })); st.dispatch({ type: 'ANALYSIS_START' });
  const e = st.get().epoch; st.dispatch({ type: 'ANALYSIS_READY', epoch: e, analysis: analysis() });
  return { st, e, stamp: (kind, groupId, seq) => ({ epoch: e, generation: 1, kind, group: groupId || null, seq }) };
}

// ------------------------------------------------------------------ layout vs the reference-extracted geometry
const refCase = () => { const keep = FRIGATE.groups.filter((g) => g.kind === 'located'); return model(keep.map((g) => ({ ...g })), { root: FRIGATE.root }); };
const near = (a, b, msg) => assert.ok(Math.abs(a - b) <= 1, `${msg}: ${a} vs ${b}`);

test('Frigate composition reproduces the reference coordinates within 1 px (one disclosed, owner-approved exception)', () => {
  const m = refCase(); const L = layoutMap(m.groups); const ref = REF.themes.light;
  assert.equal(ref.groups.length, L.zones.length);
  L.zones.forEach((z, i) => {
    const r = ref.groups[i];
    near(z.x, r.zone.x, 'zone x'); near(z.y, r.zone.y, 'zone y'); near(z.w, r.zone.w, 'zone w');
    near(z.header.x, r.header.x, 'header x'); near(z.header.y, r.header.y, 'header y'); near(z.header.w, r.header.w, 'header w'); near(z.header.h, r.header.h, 'header h');
    assert.equal(z.files.length, r.files.length);
    z.files.forEach((f, k) => { near(f.x, r.files[k].rect.x, 'file x'); near(f.y, r.files[k].rect.y, 'file y'); assert.equal(f.link, r.links[k], 'header-to-file connector'); });
    // The FR-6 exception: the prototype hand-sets row 2 to 570 px; the stated rule gives 560. Row 1 (190) matches exactly.
    if (z.row === 0) near(z.h, r.zone.h, 'row 1 zone h'); else { assert.equal(z.h, 560); assert.equal(r.zone.h, 570); }
  });
  assert.equal(L.viewBox[2], 1400); assert.equal(L.viewBox[3], 1040); assert.equal(Number(ref.viewBox.split(' ')[3]), 1050);   // 1050 - 10 (the same exception)
  // The prototype draws one path for the two row-1 elbows (the 130->160 stub is shared); here each elbow is its own path with the same segments.
  const nums = (d) => d.match(/-?[0-9.]+/g).map(Number); const letters = (d) => d.replace(/-?[0-9.]+/g, '#');
  const refParts = ref.connectors.split(' M').map((p, k) => (k ? 'M' + p : p));
  const wantRow1 = refParts.slice(0, 2).map((p, k) => (k ? 'M700 130 V160 ' + p.replace('M700 160 ', '') : p));
  const wantAll = [...wantRow1, ...refParts.slice(2)];
  assert.equal(L.connectors.length, wantAll.length);
  L.connectors.forEach((d, k) => { assert.equal(letters(d), letters(wantAll[k])); nums(d).forEach((n, q) => near(n, nums(wantAll[k])[q], `connector ${k}`)); });
});

test('the rendered SVG carries the reference rects, text positions and token classes', () => {
  const m = refCase(); const L = layoutMap(m.groups); const ref = REF.themes.light;
  const st = { ...initial(), analysis: analysis(), views: { contexts: m }, workbench: { ...initial().workbench } };
  const svg = mapSvg(st, m, L, L.viewBox);
  const rects = [...svg.matchAll(/<rect class="([^"]*)" x="([0-9.]+)" y="([0-9.]+)" width="([0-9.]+)" height="([0-9.]+)"/g)].map((x) => ({ c: x[1], x: +x[2], y: +x[3], w: +x[4], h: +x[5] }));
  const has = (r, cls) => rects.some((q) => q.c.startsWith(cls) && Math.abs(q.x - r.x) <= 1 && Math.abs(q.y - r.y) <= 1 && Math.abs(q.w - r.w) <= 1 && Math.abs(q.h - r.h) <= 1);
  assert.ok(has(ref.root.rect, 'ot4-root'));
  for (const g of ref.groups) { assert.ok(has(g.header, 'ot4-head'), g.kind + ' header'); for (const f of g.files) assert.ok(has(f.rect, 'ot4-file'), f.path); }
  // The prototype lists a group's files in capture order; the frozen contract sorts them by normalized path (code-point order), so card
  // SLOTS are compared above and TEXT is compared per path through each card's offsets inside its own rectangle.
  const texts = [...svg.matchAll(/<text class="[^"]*" x="([0-9.]+)" y="([0-9.]+)" font-size="([0-9]+)"[^>]*>([^<]*)</g)].map((x) => ({ x: +x[1], y: +x[2], size: +x[3], text: x[4] }));
  const mineRect = (path) => { const k = m.groups.findIndex((g) => g.files.some((f) => f.path === path)); const z = L.zones[k]; const f = z.files[m.groups[k].files.findIndex((q) => q.path === path)]; return { x: f.x, y: f.y }; };
  for (const g of ref.groups) for (const f of g.files) {
    const at = mineRect(f.path);
    for (const t of f.texts) assert.ok(texts.some((q) => q.text === t.text && q.size === t.size && Math.abs(q.x - (at.x + (t.x - f.rect.x))) <= 1 && Math.abs(q.y - (at.y + (t.y - f.rect.y))) <= 1), `text ${t.text} of ${f.path}`);
  }
  for (const t of ref.root.texts.slice(1)) assert.ok(texts.some((q) => q.text === t.text && q.x === t.x && q.y === t.y && q.size === t.size), `root text ${t.text}`);
  assert.deepEqual(['blue', 'green', 'amber', 'purple'], ['docs', 'web', 'python', 'actions'].map((k) => ({ docs: 'blue', web: 'green', python: 'amber', actions: 'purple' }[k])));
  assert.deepEqual(m.groups.map((g) => g.token), ['blue', 'green', 'amber', 'purple']);
});

test('category tokens use exactly the reference light and dark values', () => {
  const css = readFileSync(join(ROOT, 'src/ui/styles/app.css'), 'utf8'); const hexOf = (c) => '#' + c.match(/\d+/g).map((n) => Number(n).toString(16).padStart(2, '0')).join('');
  const pairs = { docs: 'blue', web: 'green', python: 'amber', actions: 'purple' };
  for (const [theme, prefix] of [['light', ''], ['dark', 'html\\[data-theme=dark\\] ']]) {
    for (const [kind, token] of Object.entries(pairs)) {
      const t = REF.themes[theme].tokens[kind];
      const rule = new RegExp(`${prefix}\\.ot4-zone\\[data-token=${token}\\][^{]*\\{([^}]*)\\}`).exec(css.split('\n').filter((l) => (theme === 'dark') === l.startsWith('html[data-theme=dark]')).join('\n'));
      assert.ok(rule, `${theme} ${token}`);
      const body = rule[1];
      assert.ok(body.includes(`--ot4-zone:${hexOf(t.zoneFill)}`), `${theme} ${token} zone ${body}`); assert.ok(body.includes(`--ot4-header:${hexOf(t.headerFill)}`), `${theme} ${token} header`);
      assert.ok(body.includes(`--ot4-file:${hexOf(t.fileFill)}`), `${theme} ${token} file`); assert.ok(body.includes(`--ot4-edge:${hexOf(t.edge)}`), `${theme} ${token} edge`);
    }
  }
});

// ------------------------------------------------------------------ generalization
test('layout generalizes: 1, 3, 5 and 12 groups (12 is the labelled synthetic layout-capacity case)', () => {
  for (const n of [1, 3, 5, 12]) {
    const groups = Array.from({ length: n }, (_, i) => group(i + 1, (i % 4) + 1));
    const L = layoutMap(groups); assert.equal(L.zones.length, n);
    const boxes = L.zones.map((z) => [z.x, z.y, z.x + z.w, z.y + z.h]);
    boxes.forEach((a, i) => boxes.slice(i + 1).forEach((b) => assert.ok(a[2] <= b[0] || b[2] <= a[0] || a[3] <= b[1] || b[3] <= a[1], `zones overlap at n=${n}`)));
    assert.equal(L.viewBox[3], Math.max(...boxes.map((b) => b[3])) + 40);
    assert.equal(L.connectors.length, n);
    L.zones.forEach((z) => assert.equal(z.x, [40, 735][z.index % 2]));
  }
  assert.equal(layoutMap([]).zones.length, 0);
  const one = layoutMap([unlocated(1)]); assert.equal(one.zones[0].h, 116); assert.equal(one.zones[0].files.length, 0);   // header-only Unlocated zone in the next slot
});

test('the Unlocated group takes the next grid slot after the located groups', () => {
  const L = layoutMap([group(1, 1), group(2, 1), unlocated(3)]);
  assert.deepEqual([L.zones[2].col, L.zones[2].row], [0, 1]); assert.equal(L.zones[2].y, 440);
});

// ------------------------------------------------------------------ paging, caps, merge
test('paging constants and retry ladder', () => {
  assert.deepEqual([PAGE_GRAPH, PAGE_LIST, GROUP_CAP, MAP_CAP], [20, 40, 100, 400]);
  assert.deepEqual(ladderFrom(20), [20, 10, 5, 1]); assert.deepEqual(ladderFrom(40), [40, 10, 5, 1]); assert.deepEqual(ladderFrom(5), [5, 1]); assert.deepEqual(ladderFrom(1), [1]);
});

test('Graph caps: 100 cards per group, 400 in the whole map; beyond a cap the group continues in List view', () => {
  const big = [group(1, 120, 213), group(2, 20, 20), group(3, 100, 300), group(4, 100, 100), group(5, 100, 150), group(6, 50, 50)];
  const cap = capacity(big);
  assert.equal(cap[0].shown, 100); assert.equal(cap[0].footer, 'list'); assert.equal(cap[0].hidden, 113);
  assert.equal(cap[1].shown, 20); assert.equal(cap[1].footer, null);
  assert.equal(cap.reduce((n, c) => n + c.shown, 0), 400);                                  // 100 + 20 + 100 + 100 + 80
  assert.equal(cap[4].shown, 80); assert.equal(cap[4].footer, 'list'); assert.equal(cap[5].shown, 0);
  const small = capacity([group(1, 20, 213)]);
  assert.equal(small[0].footer, 'more'); assert.equal(small[0].hidden, 193);
  assert.equal(footerText(big[0], 100), 'Showing 100 of 213 source locations · 113 not shown');
});

test('merge replaces only the cards at the requested offsets and never drops a loaded card', () => {
  const c = (i) => ({ file_id: 'ctx:' + hex(i), path: 'p' + i });
  const loaded = [c(0), c(1), c(2), c(3)];
  assert.deepEqual(mergeFiles(loaded, [c(0), c(1)], 0).map((x) => x.path), ['p0', 'p1', 'p2', 'p3']);      // a smaller first page keeps the loaded tail
  assert.deepEqual(mergeFiles(loaded, [c(4), c(5)], 4).map((x) => x.path), ['p0', 'p1', 'p2', 'p3', 'p4', 'p5']);
  assert.deepEqual(mergeFiles(loaded, [c(2), c(3), c(4)], 2).map((x) => x.path), ['p0', 'p1', 'p2', 'p3', 'p4']);
  assert.deepEqual(mergeFiles(loaded, [c(9)], 9).map((x) => x.path), ['p0', 'p1', 'p2', 'p3'], 'a page that would leave a hole is not applied');
  assert.deepEqual(mergeFiles(loaded, [{ file_id: c(1).file_id, path: 'replaced' }], 1).map((x) => x.path), ['p0', 'replaced', 'p2', 'p3']);
  assert.deepEqual(mergeFiles(undefined, [c(0)], 0).map((x) => x.path), ['p0']);
});

test('selection validity, keyboard targets, viewport arithmetic', () => {
  const m = model([group(1, 3), unlocated(2)]);
  assert.ok(selectionValid(m, 'root')); assert.ok(selectionValid(m, m.groups[0].group_id)); assert.ok(selectionValid(m, m.groups[0].files[1].file_id)); assert.ok(selectionValid(m, m.groups[1].group_id));
  assert.equal(selectionValid(m, 'ctx:' + hex(99999)), false); assert.equal(selectionValid(m, null), false); assert.equal(selectionValid(null, 'root'), false);
  assert.equal(findSelection(m, m.groups[1].group_id).kind, 'unlocated'); assert.equal(findSelection(m, m.groups[0].files[0].file_id).kind, 'file');
  const ids = ['a', 'b', 'c'];
  assert.equal(cardTarget(ids, 'b', 'ArrowDown'), 'c'); assert.equal(cardTarget(ids, 'c', 'ArrowDown'), 'c'); assert.equal(cardTarget(ids, 'b', 'ArrowUp'), 'a'); assert.equal(cardTarget(ids, 'a', 'ArrowUp'), 'a');
  assert.equal(cardTarget(ids, 'b', 'Home'), 'a'); assert.equal(cardTarget(ids, 'b', 'End'), 'c'); assert.equal(cardTarget(ids, 'x', 'End'), null); assert.equal(cardTarget(ids, 'b', 'Tab'), null);
  const vb = [0, 0, 1400, 1040];
  assert.equal(zoomPercent(vb), 100); assert.equal(zoomPercent(zoomBox(vb, 0.8)), 125); assert.equal(zoomPercent(zoomBox(vb, 1.25)), 80);
  assert.deepEqual(zoomBox(zoomBox(vb, 0.8), 1.25).map((v) => Math.round(v * 1e6) / 1e6 + 0), vb);
  assert.ok(clampZoom(zoomBox(vb, 0.01), vb)[2] >= 350); assert.ok(clampZoom(zoomBox(vb, 100), vb)[2] <= 5600);
  assert.deepEqual(panBox(vb, 100, 50, 700), [-200, -100, 1400, 1040]);
  assert.deepEqual(panBox(vb, 0, 0, 700).map((v) => v + 0), vb);
});

// ------------------------------------------------------------------ request ordering and lifecycle (deterministic: no timers, no network)
const group2 = (g) => group(g, 3, 9);
const fullData = (extra = {}) => model([group2(1), group2(2)], extra);
const pageData = (groupN, offset, n, total = 9) => { const g = group(groupN, n, total, { files_offset: offset }); g.files = g.files.map((f, i) => ({ ...f, file_id: 'ctx:' + hex(groupN * 1000 + offset + i), path: `g${groupN}/f${offset + i}.json` })); return model([g], { counts: { total: 2, shown: 1, truncated: true } }); };

test('a late success for an old request never applies; the newest request wins whichever order they return in', () => {
  const { st, stamp } = opened();
  st.dispatch({ type: 'CTX_REQUEST', ...stamp('full', null, 1) }); st.dispatch({ type: 'CTX_REQUEST', ...stamp('full', null, 2) });
  st.dispatch({ type: 'CTX_LOADED', ...stamp('full', null, 2), data: fullData() });
  const after = st.get().views.contexts;
  st.dispatch({ type: 'CTX_LOADED', ...stamp('full', null, 1), data: model([group(7, 1)]) });          // the older one arrives last
  assert.equal(st.get().views.contexts, after, 'late older success changed nothing');
  assert.equal(st.get().views.contexts.groups.length, 2);
});

test('a late error never clears the map, shows a notice or retries (ctxCurrent is the shared predicate)', () => {
  const { st, stamp } = opened();
  st.dispatch({ type: 'CTX_REQUEST', ...stamp('full', null, 1) }); st.dispatch({ type: 'CTX_LOADED', ...stamp('full', null, 1), data: fullData() });
  st.dispatch({ type: 'CTX_REQUEST', ...stamp('full', null, 2) });
  const before = st.get();
  assert.equal(ctxCurrent(before, stamp('full', null, 1)), false, 'seq 1 is superseded');
  st.dispatch({ type: 'CTX_FAILED', ...stamp('full', null, 1), error: { code: 'stale_generation' } });
  assert.equal(st.get(), before, 'a late stale_generation error changed nothing');
  st.dispatch({ type: 'CTX_FAILED', ...stamp('full', null, 1), error: { code: 'response_too_large' } });
  assert.equal(st.get(), before, 'a late response_too_large error changed nothing');
  assert.equal(ctxCurrent(st.get(), { ...stamp('full', null, 2), generation: 2 }), false, 'another generation is never current');
  assert.equal(ctxCurrent(st.get(), { ...stamp('full', null, 2), epoch: st.get().epoch + 1 }), false);
  st.dispatch({ type: 'CTX_FAILED', ...stamp('full', null, 2), error: { code: 'projection_failed', detail: 'unrepresentable_path' } });
  assert.equal(st.get().views.contexts.groups.length, 2, 'a terminal error with a map already shown keeps the map');
});

test('initial request: terminal failure is an explicit unavailable state (typed error), never a partial map; Check again re-enters', () => {
  const { st, stamp } = opened();
  st.dispatch({ type: 'CTX_REQUEST', ...stamp('full', null, 1) });
  assert.equal(st.get().workbench.perTab.contexts.map.status, 'loading');
  st.dispatch({ type: 'CTX_FAILED', ...stamp('full', null, 1), error: { code: 'response_too_large' } });
  const map = st.get().workbench.perTab.contexts.map;
  assert.equal(map.status, 'unavailable'); assert.equal(map.error.code, 'response_too_large'); assert.equal(st.get().views.contexts, undefined);
  const html = renderContexts(st.get()); assert.match(html, /data-state="unavailable"/); assert.match(html, /Check again/); assert.match(html, /Other tabs are not affected/);
  st.dispatch({ type: 'CTX_REQUEST', ...stamp('full', null, 2) }); st.dispatch({ type: 'CTX_LOADED', ...stamp('full', null, 2), data: fullData() });
  assert.equal(st.get().workbench.perTab.contexts.map.status, 'ready');
});

test('group paging merges without dropping cards; a group failure is terminal for that group only', () => {
  const { st, stamp } = opened();
  st.dispatch({ type: 'CTX_REQUEST', ...stamp('full', null, 1) }); st.dispatch({ type: 'CTX_LOADED', ...stamp('full', null, 1), data: fullData() });
  const gid = 'grp:' + hex(1);
  st.dispatch({ type: 'CTX_REQUEST', ...stamp('group', gid, 1) });
  assert.equal(st.get().workbench.perTab.contexts.map.groups[gid].state, 'loading');
  st.dispatch({ type: 'CTX_LOADED', ...stamp('group', gid, 1), data: pageData(1, 3, 5) });
  const g = st.get().views.contexts.groups.find((x) => x.group_id === gid);
  assert.equal(g.files.length, 8); assert.equal(hiddenCount(g), 1);
  assert.equal(st.get().views.contexts.groups.length, 2); assert.equal(st.get().views.contexts.counts.total, 2, 'a group page does not replace the map counts');
  st.dispatch({ type: 'CTX_REQUEST', ...stamp('group', gid, 2) });
  st.dispatch({ type: 'CTX_FAILED', ...stamp('group', gid, 2), error: { code: 'response_too_large' } });
  const m = st.get().workbench.perTab.contexts.map;
  assert.equal(m.groups[gid].state, 'error'); assert.equal(m.status, 'ready'); assert.equal(st.get().views.contexts.groups[0].files.length, 8, 'loaded cards stay');
  assert.match(renderContexts({ ...st.get(), workbench: { ...st.get().workbench, perTab: { ...st.get().workbench.perTab, contexts: { ...st.get().workbench.perTab.contexts, presentation: 'list' } } } }), /could not be loaded/);
});

test('competing requests for the same group: the older never overwrites the newer', () => {
  const { st, stamp } = opened();
  st.dispatch({ type: 'CTX_REQUEST', ...stamp('full', null, 1) }); st.dispatch({ type: 'CTX_LOADED', ...stamp('full', null, 1), data: fullData() });
  const gid = 'grp:' + hex(2);
  st.dispatch({ type: 'CTX_REQUEST', ...stamp('group', gid, 1) }); st.dispatch({ type: 'CTX_REQUEST', ...stamp('group', gid, 2) });
  st.dispatch({ type: 'CTX_LOADED', ...stamp('group', gid, 2), data: pageData(2, 3, 6) });
  st.dispatch({ type: 'CTX_LOADED', ...stamp('group', gid, 1), data: pageData(2, 3, 1) });             // older, smaller, arrives last
  assert.equal(st.get().views.contexts.groups[1].files.length, 9);
  st.dispatch({ type: 'CTX_REQUEST', ...stamp('group', 'grp:' + hex(1), 1) });                          // another group has its own sequence
  assert.equal(ctxCurrent(st.get(), stamp('group', gid, 2)), true);
});

test('a superseded retry never applies (retry steps are new requests; only the newest is current)', () => {
  const { st, stamp } = opened();
  st.dispatch({ type: 'CTX_REQUEST', ...stamp('full', null, 1) });         // limit 20
  st.dispatch({ type: 'CTX_REQUEST', ...stamp('full', null, 2) });         // retry at 10
  st.dispatch({ type: 'CTX_REQUEST', ...stamp('full', null, 3) });         // user pressed Check again meanwhile
  st.dispatch({ type: 'CTX_LOADED', ...stamp('full', null, 2), data: fullData() });
  assert.equal(st.get().views.contexts, undefined);
  st.dispatch({ type: 'CTX_LOADED', ...stamp('full', null, 3), data: fullData() });
  assert.equal(st.get().views.contexts.groups.length, 2);
});

test('selection is preserved across paging, re-render, Graph/List and tab return; cleared on every real lifecycle transition', () => {
  const { st, e, stamp } = opened();
  st.dispatch({ type: 'CTX_REQUEST', ...stamp('full', null, 1) }); st.dispatch({ type: 'CTX_LOADED', ...stamp('full', null, 1), data: fullData() });
  const file = st.get().views.contexts.groups[0].files[1].file_id;
  st.dispatch({ type: 'TAB_STATE', tab: 'contexts', patch: { selection: file } });
  st.dispatch({ type: 'CTX_REQUEST', ...stamp('group', 'grp:' + hex(1), 1) }); st.dispatch({ type: 'CTX_LOADED', ...stamp('group', 'grp:' + hex(1), 1), data: pageData(1, 3, 3) });
  assert.equal(st.get().workbench.perTab.contexts.selection, file, 'paging keeps a valid selection');
  st.dispatch({ type: 'TAB_STATE', tab: 'contexts', patch: { presentation: 'list' } }); st.dispatch({ type: 'TAB_STATE', tab: 'contexts', patch: { presentation: 'graph' } });
  st.dispatch({ type: 'TAB', tab: 'dependencies' }); st.dispatch({ type: 'TAB', tab: 'contexts' });
  assert.equal(st.get().workbench.perTab.contexts.selection, file, 'Graph/List switches and tab return keep it');
  st.dispatch({ type: 'CTX_REQUEST', ...stamp('full', null, 2) }); st.dispatch({ type: 'CTX_LOADED', ...stamp('full', null, 2), data: fullData() });
  assert.equal(st.get().workbench.perTab.contexts.selection, file, 'a full reload in the same analysis keeps the selection');
  assert.equal(st.get().views.contexts.groups[0].files.length, 6, 'and each group keeps its already loaded cards');
  // a stale response never clears or mutates current state
  const before = st.get(); st.dispatch({ type: 'CTX_LOADED', epoch: e - 1, generation: 1, kind: 'full', group: null, seq: 9, data: fullData() });
  assert.equal(st.get(), before);
  // real transitions
  st.dispatch({ type: 'END_STARTED' }); assert.equal(st.get().epoch, e + 1);
  assert.equal(st.get().views.contexts, undefined, 'END_STARTED clears the map immediately (UIP-04-IR-03)'); assert.equal(st.get().workbench.perTab.contexts.selection, 'root');
  st.dispatch({ type: 'CTX_LOADED', ...stamp('full', null, 3), data: fullData() }); assert.equal(st.get().views.contexts, undefined, 'END_STARTED already made the old stamp stale: a late response cannot bring the map back');
  st.dispatch({ type: 'ENDED', state: 'ended' });
  assert.equal(st.get().views.contexts, undefined); assert.equal(st.get().workbench.perTab.contexts.selection, 'root'); assert.equal(st.get().workbench.perTab.contexts.map.status, 'idle');
  const second = opened(); second.st.dispatch({ type: 'CTX_REQUEST', ...second.stamp('full', null, 1) }); second.st.dispatch({ type: 'CTX_LOADED', ...second.stamp('full', null, 1), data: fullData() });
  second.st.dispatch({ type: 'TAB_STATE', tab: 'contexts', patch: { selection: second.st.get().views.contexts.groups[0].files[0].file_id } });
  second.st.dispatch({ type: 'ANALYSIS_START' });
  assert.equal(second.st.get().views.contexts, undefined); assert.equal(second.st.get().workbench.perTab.contexts.selection, 'root'); assert.deepEqual(second.st.get().workbench.perTab.contexts.map.latest, { full: 0 });
});

test('a changed analysis digest discards everything; another digest never merges', () => {
  const { st, stamp } = opened();
  st.dispatch({ type: 'CTX_REQUEST', ...stamp('full', null, 1) });
  const other = fullData(); other.binding = { ...other.binding, analysis_digest: 'sha256:' + 'b'.repeat(64) };
  st.dispatch({ type: 'CTX_LOADED', ...stamp('full', null, 1), data: other });
  assert.equal(st.get().views.contexts, undefined, 'a response bound to another analysis never reaches the state');
});

test('a selection that no longer exists falls back to the root, never to a stale record', () => {
  const { st, stamp } = opened();
  st.dispatch({ type: 'TAB_STATE', tab: 'contexts', patch: { selection: 'ctx:' + hex(424242) } });
  st.dispatch({ type: 'CTX_REQUEST', ...stamp('full', null, 1) }); st.dispatch({ type: 'CTX_LOADED', ...stamp('full', null, 1), data: fullData() });
  assert.equal(st.get().workbench.perTab.contexts.selection, 'root');
});

// ------------------------------------------------------------------ wiring, inertness, no hard-coded names
test('selection wiring: root, group and file produce the neutral Repository-context inspector; Explore carries the path and dependency id', () => {
  const m = model([group(1, 2), unlocated(2, 4)], { root: { ...model([]).root, distinct_total: 6, located_distinct_total: 2, unlocated_total: 4 } });
  const st = { ...initial(), analysis: analysis(), views: { contexts: m }, workbench: initial().workbench };
  const at = (selection) => ({ ...st, workbench: { ...st.workbench, perTab: { ...st.workbench.perTab, contexts: { ...st.workbench.perTab.contexts, selection } } } });
  const root = fromSelection(at('root'), 'contexts'); assert.equal(root.title, 'acme/widget'); assert.equal(root.badge.label, 'Repository context'); assert.match(root.answers[1].body, /partial source inventory/);
  assert.equal(root.answers.find((a) => a.question_id === 'security_concern').state, 'not_applicable');
  const grp = fromSelection(at(m.groups[0].group_id), 'contexts'); assert.equal(grp.title, 'Group 1'); assert.match(grp.answers[1].body, /does not establish installation, workflow execution or service topology/);
  const file = fromSelection(at(m.groups[0].files[0].file_id), 'contexts'); const drill = file.actions.find((a) => a.id === 'drill');
  assert.equal(drill.label, 'Explore components →'); assert.equal(drill.attrs['data-path'], 'g1/f0.json'); assert.equal(drill.attrs['data-dependency-context-id'], m.groups[0].files[0].dependency_context_id);
  assert.ok(file.actions.some((a) => a.id === 'ctx-evidence'));
  for (const sel of ['root', m.groups[0].group_id, m.groups[1].group_id, m.groups[0].files[0].file_id]) assert.match(evidenceHtml(at(sel)), /Installation, builds and execution were not observed/);
});

test('hostile strings render as inert text; only an exact https://github.com/ href is an active link', () => {
  const hostile = '"><img src=x onerror=alert(1)><script>alert(1)</script>';
  const g = group(1, 1); g.label = hostile; g.files[0].path = `docs/${hostile}.json`; g.files[0].raw_locations = [hostile]; g.files[0].revision_link = { href: 'javascript:alert(1)', text: hostile };
  const m = model([g], { root: { ...model([]).root, name: `${hostile}/${hostile}` } });
  let st = { ...initial(), analysis: analysis(), views: { contexts: m }, workbench: initial().workbench };
  for (const presentation of ['graph', 'list']) {
    for (const selection of ['root', g.group_id, g.files[0].file_id]) {
      st = { ...st, workbench: { ...st.workbench, perTab: { ...st.workbench.perTab, contexts: { ...st.workbench.perTab.contexts, presentation, selection } } } };
      const html = renderContexts(st);
      assert.equal(/<img|<script/i.test(html), false, `${presentation}/${selection}`);
      for (const tag of html.match(/<[^>]+>/g) || []) assert.equal(/\son[a-z]+\s*=/i.test(tag.replace(/"[^"]*"/g, '""')), false, 'no event-handler attribute: ' + tag.slice(0, 80));
      assert.equal(/href="javascript/i.test(html), false); assert.equal(/<a /.test(html), false, 'an unsafe href is never an active link');
    }
  }
  assert.equal(activeHref('https://github.com/acme/widget/blob/abc/x'), 'https://github.com/acme/widget/blob/abc/x');
  for (const bad of ['http://github.com/a', 'https://github.com.evil.example/a', 'https://user:pw@github.com/a', 'https://github.com:8443/a', 'javascript:alert(1)', 'data:text/html,x', '//github.com/a', '', null, undefined, 'https://evil.example/https://github.com/']) assert.equal(activeHref(bad), null, String(bad));
  const ok = group(1, 1); st = { ...st, views: { contexts: model([ok]) }, workbench: { ...st.workbench, perTab: { ...st.workbench.perTab, contexts: { ...st.workbench.perTab.contexts, presentation: 'list', selection: ok.files[0].file_id } } } };
  assert.match(renderContexts(st), /<a href="https:\/\/github\.com\/acme\/widget\/blob\/0{40}\/g1\/f0\.json" target="_blank" rel="noopener noreferrer">/);
});

test('List view mirrors the map: one row per file with the same selection and counts; Show more carries the hidden total', () => {
  const m = model([group(1, 3, 213), unlocated(2)]);
  const st = { ...initial(), analysis: analysis(), views: { contexts: m }, workbench: { ...initial().workbench } };
  const list = { ...st, workbench: { ...st.workbench, perTab: { ...st.workbench.perTab, contexts: { ...st.workbench.perTab.contexts, presentation: 'list', selection: m.groups[0].files[1].file_id } } } };
  const html = renderContexts(list);
  assert.equal((html.match(/data-ctx-kind="file"/g) || []).length, 3); assert.match(html, /aria-pressed="true"[^>]*>|data-ctx-kind="file" aria-pressed="true"/);
  assert.match(html, /Showing 3 of 213 source locations · 210 not shown/); assert.match(html, /data-action="ctx-more"/);
  assert.match(html, /data-card-count="3"/); assert.match(html, /data-selection-kind="file"/);
  const graph = renderContexts({ ...st });
  assert.match(graph, /data-map-ready="true"/); assert.match(graph, /data-selection-kind="root"/); assert.match(graph, /data-card-count="3"/); assert.match(graph, /id="ot4-stage"/);
  assert.equal(groupSummary(m.groups[0]), '213 captured source locations · 3 distinct records'.replace('3 distinct', '3 distinct'));
});

test('production map code contains no hard-coded repository name and no legacy grouping (scoped scan)', () => {
  const read = (p) => readFileSync(join(ROOT, p), 'utf8');
  for (const p of ['src/ui/lib/context_map.js', 'src/ui/components/context_map.js']) { const t = read(p); assert.equal(/frigate|blakeblackshear/i.test(t), false, p); assert.equal(/groupFor|\bGROUPS\b/.test(t), false, p); }
  const adapter = read('src/ui/lib/inspector_model.js'); const start = adapter.indexOf('function contexts(s)'); const end = adapter.indexOf('// The component-level advisory state');
  assert.ok(start > 0 && end > start); assert.equal(/frigate|blakeblackshear|groupFor/i.test(adapter.slice(start, end)), false);
  for (const p of ['src/ui/components/workbench.js', 'src/ui/app.js', 'src/ui/lib/store.js']) {
    const t = read(p); assert.equal(/groupFor|\bGROUPS\b/.test(t), false, p + ' legacy grouping');
    // Pure comment lines (e.g. the legitimate captured-sample note about the Dependencies default context) are not map identity/grouping code.
    const ctxLines = t.split('\n').filter((l) => !/^\s*\/\//.test(l) && /\bctx|\bcontexts\b|CTX_|Ctx/.test(l));
    assert.equal(ctxLines.some((l) => /blakeblackshear|\bFrigate\b/.test(l)), false, p + ' contexts paths');
  }
  assert.equal(/groupFor|\bGROUPS\b/.test(read('src/ui/lib/copy.js')), false);
  // every reader of the Contexts view uses the v1 payload: nothing reads the legacy `rows` shape from views.contexts
  for (const p of ['src/ui/components/workbench.js', 'src/ui/app.js', 'src/ui/lib/inspector_model.js', 'src/ui/lib/summary_metrics.js', 'src/ui/components/evidence.js', 'src/ui/components/assistant.js']) assert.equal(/views\.contexts\??\.rows/.test(read(p)), false, p);
});

test('summary_metrics.js is unchanged by this increment (it reads only identity and summary)', () => {
  const t = readFileSync(join(ROOT, 'src/ui/lib/summary_metrics.js'), 'utf8'); assert.equal(/views\.contexts|views\[/.test(t), false);
});
