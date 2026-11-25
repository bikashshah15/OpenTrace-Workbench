// UIP-04 correction 01 (independent review IR-01..IR-04). Each test reproduces the reviewer's probe against the real modules
// (store reducer, string renderers, the document-level key handler) with the committed uip04-large-map payload.
// Run: node --test tests/ui/unit/context_map_corrections.test.mjs
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createStore, initial } from '../../../src/ui/lib/store.js';
import { renderContexts, pinnedHref, attachContextMap } from '../../../src/ui/components/context_map.js';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '../../..');
const FX = 'evidence/uip/visual/uip-04/fixtures/uip04-large-map/';
const json = (f) => JSON.parse(readFileSync(join(ROOT, FX, f), 'utf8'));
const PAGE0 = json('contexts-page-0.json'); const ANALYSIS = json('analysis.json');
const copy = (x) => JSON.parse(JSON.stringify(x));
const digest = PAGE0.binding.analysis_digest;

function opened(presentation = 'graph') {
  const st = createStore(initial({ narrow: false })); st.dispatch({ type: 'ANALYSIS_START' });
  const e = st.get().epoch; st.dispatch({ type: 'ANALYSIS_READY', epoch: e, analysis: { ...copy(ANALYSIS), generation: 1, identity: { ...(ANALYSIS.identity || {}), mode: 'captured', analysis_digest: digest } } });
  const stamp = (kind, group, seq) => ({ epoch: e, generation: 1, kind, group: group || null, seq });
  st.dispatch({ type: 'CTX_REQUEST', ...stamp('full', null, 1) }); st.dispatch({ type: 'CTX_LOADED', ...stamp('full', null, 1), data: copy(PAGE0) });
  st.dispatch({ type: 'TAB_STATE', tab: 'contexts', patch: { presentation } });
  return { st, e, stamp };
}
const webGroup = (s) => s.views.contexts.groups.find((g) => g.files_counts.total === 213);

// ------------------------------------------------------------------ IR-01
const withLink = (path, href) => {
  const { st } = opened('list'); const m = copy(st.get().views.contexts); const f = m.groups[0].files[0];
  f.path = path; f.revision_link = { href, text: path };
  const s = { ...st.get(), views: { contexts: m } };
  return renderContexts({ ...s, workbench: { ...s.workbench, perTab: { ...s.workbench.perTab, contexts: { ...s.workbench.perTab.contexts, presentation: 'list', selection: f.file_id } } } });
};
const PIN = (m) => `https://github.com/${m.binding.repository.owner}/${m.binding.repository.name}/blob/${m.root.commit_sha}/`;

test('IR-01 an href that the URL parser resolves outside the repository/commit is inert (the reviewer reproduction)', () => {
  const m = PAGE0; const evil = PIN(m) + '../../../../attacker/other/blob/main/README.md';
  assert.equal(new URL(evil).pathname.startsWith('/attacker/'), true, 'precondition: WHATWG normalization escapes the repository');
  assert.equal(pinnedHref(evil, m), null);
  assert.equal(/<a /.test(withLink('../../../../attacker/other/blob/main/README.md', evil)), false, 'no active link in the Inspector');
});

test('IR-01 dot segments, even those that normalize back inside the pinned prefix, never produce an active link', () => {
  const m = PAGE0;
  for (const p of ['..', '.', 'a/./b', 'a/../b', 'a/..', './a', '../a', 'a/%2e%2e/b', 'a/%2E/b']) assert.equal(pinnedHref(PIN(m) + p, m), null, p);
});

test('IR-01 another repository, another commit, another host, query or fragment is inert; the exact pinned URL is active', () => {
  const m = PAGE0; const r = m.binding.repository; const sha = m.root.commit_sha;
  for (const bad of [`https://github.com/other/${r.name}/blob/${sha}/x`, `https://github.com/${r.owner}/other/blob/${sha}/x`, `https://github.com/${r.owner}/${r.name}/blob/${'f'.repeat(40)}/x`,
    `https://github.com/${r.owner}/${r.name}/blob/main/x`, `https://github.com/${r.owner}/${r.name}/tree/${sha}/x`, PIN(m) + 'x?raw=1', PIN(m) + 'x#L1', PIN(m), `https://gist.github.com/${r.owner}/${r.name}/blob/${sha}/x`,
    PIN(m).replace('https://', 'http://') + 'x', PIN(m) + 'a\\..\\b'])
    assert.equal(pinnedHref(bad, m), null, bad);
  assert.equal(pinnedHref(PIN(m) + 'web/package-lock.json', m), PIN(m) + 'web/package-lock.json');
  assert.equal(pinnedHref(null, m), null); assert.equal(pinnedHref(PIN(m) + 'x', null), null);
});

test('IR-01 ordinary special characters, percent-encoded by the service, and legitimate dotted names stay active links', () => {
  const m = PAGE0;
  for (const p of ['web/a%20b/%252e%252e/c%23frag%3Fq=1.json', '.github/workflows/ci.yml', 'docs/..hidden', 'docs/a...b', 'web/v1.2/x.json', 'a//b', 'web/%C3%A9.json'])
    assert.equal(pinnedHref(PIN(m) + p, m), PIN(m) + p, p);
  const html = withLink('.github/workflows/ci.yml', PIN(PAGE0) + '.github/workflows/ci.yml');
  assert.match(html, /<a href="https:\/\/github\.com\/[^"]+\/blob\/[0-9a-f]{40}\/\.github\/workflows\/ci\.yml" target="_blank" rel="noopener noreferrer">/);
});

// ------------------------------------------------------------------ IR-02
function failedGroup(presentation) {
  const { st, stamp } = opened(presentation); const web = webGroup(st.get());
  st.dispatch({ type: 'CTX_REQUEST', ...stamp('group', web.group_id, 1) });
  return { st, web, stamp };
}
test('IR-02 Graph shows group loading, the typed terminal failure, the hidden total and a manual retry, like List', () => {
  for (const presentation of ['graph', 'list']) {
    const { st, web, stamp } = failedGroup(presentation); const grp = (h) => h.match(new RegExp('data-action="ctx-more" data-group="' + web.group_id + '"[^>]*>[\\s\\S]{0,400}'))?.[0] || '';
    let html = renderContexts(st.get());
    assert.match(html, /Loading…/, presentation + ' loading'); assert.match(grp(html), /aria-disabled="true"|disabled/, presentation + ' the loading control is disabled');
    st.dispatch({ type: 'CTX_FAILED', ...stamp('group', web.group_id, 1), error: { code: 'response_too_large' } });
    html = renderContexts(st.get());
    assert.match(html, /response_too_large/, presentation + ' typed failure visible'); assert.match(html, /role="alert"/);
    assert.match(html, /193 not shown/, presentation + ' hidden total stays'); assert.match(grp(html), /Try again/, presentation + ' manual retry');
    assert.equal(webGroup(st.get()).files.length, 20, 'loaded cards preserved');
    assert.equal(st.get().workbench.perTab.contexts.map.groups[web.group_id].state, 'error');
    // no automatic retry: only a user action dispatches another request; rendering alone never does
    const seq = st.get().workbench.perTab.contexts.map.latest['g:' + web.group_id]; renderContexts(st.get()); assert.equal(st.get().workbench.perTab.contexts.map.latest['g:' + web.group_id], seq);
  }
});
test('IR-02 the Graph retry control stays keyboard-focusable and re-enters loading from the error state', () => {
  const { st, web, stamp } = failedGroup('graph');
  st.dispatch({ type: 'CTX_FAILED', ...stamp('group', web.group_id, 1), error: { code: 'response_too_large' } });
  const html = renderContexts(st.get());
  assert.match(html, new RegExp('<g data-action="ctx-more" data-group="' + web.group_id + '" role="button" tabindex="0"'));
  st.dispatch({ type: 'CTX_REQUEST', ...stamp('group', web.group_id, 2) });
  assert.equal(st.get().workbench.perTab.contexts.map.groups[web.group_id].state, 'loading'); assert.equal(webGroup(st.get()).files.length, 20);
});

// ------------------------------------------------------------------ IR-03
test('IR-03 END_STARTED removes the Contexts payload, selection, paging and map immediately; ending status stays visible', () => {
  const { st, stamp } = opened('list'); const web = webGroup(st.get());
  st.dispatch({ type: 'TAB_STATE', tab: 'contexts', patch: { selection: web.files[0].file_id } });
  st.dispatch({ type: 'CTX_REQUEST', ...stamp('group', web.group_id, 1) });
  assert.ok(renderContexts(st.get()).includes('data-ctx-kind="file"'), 'precondition: file rows are rendered');
  const before = st.get(); const analysisBefore = before.analysis;
  st.dispatch({ type: 'END_STARTED' });
  const s = st.get(); const c = s.workbench.perTab.contexts;
  assert.equal(s.busy, 'ending'); assert.equal(s.views.contexts, undefined); assert.equal(c.selection, 'root'); assert.deepEqual(c.map, { status: 'idle', error: null, latest: { full: 0 }, groups: {} });
  assert.equal(c.presentation, 'list', 'the presentation preference is kept');
  assert.equal(s.analysis, analysisBefore, 'unrelated lifecycle state (analysis until ENDED) is untouched');
  const html = renderContexts(s);
  assert.equal(/data-ctx-kind|ot4-svg|<a /.test(html), false, 'no card, row, map or source link while ending'); assert.match(html, /Ending session/);
  assert.equal(renderContexts({ ...s, workbench: { ...s.workbench, perTab: { ...s.workbench.perTab, contexts: { ...c, presentation: 'graph' } } } }).includes('ot4-svg'), false);
});
test('IR-03 a late contexts response after END_STARTED is refused, and ENDED reports the final cleanup state', () => {
  const { st, stamp } = opened('graph'); const web = webGroup(st.get());
  st.dispatch({ type: 'CTX_REQUEST', ...stamp('group', web.group_id, 1) });
  st.dispatch({ type: 'END_STARTED' });
  const held = st.get();
  st.dispatch({ type: 'CTX_LOADED', ...stamp('group', web.group_id, 1), data: copy(PAGE0) }); st.dispatch({ type: 'CTX_LOADED', ...stamp('full', null, 1), data: copy(PAGE0) });
  st.dispatch({ type: 'CTX_FAILED', ...stamp('group', web.group_id, 1), error: { code: 'x' } });
  assert.equal(st.get(), held, 'late success and failure change nothing');
  st.dispatch({ type: 'ENDED', state: 'deleted_verified' });
  const s = st.get(); assert.equal(s.ended, 'deleted_verified'); assert.equal(s.views.contexts, undefined); assert.equal(s.analysis, null); assert.equal(s.workbench.perTab.contexts.selection, 'root');
});

// ------------------------------------------------------------------ IR-04
function fakeDom() {
  const handlers = []; const focused = [];
  const mk = (id, kind, group) => ({ dataset: { ctx: id, ctxKind: kind }, matches: () => false, focus() { focused.push(id); }, closest(sel) { return sel === '#ot4-list' ? list : sel === '[data-group-id]' ? group : sel === '#ot4-stage' ? null : null; } });
  const list = {}; const mkGroup = (ids) => { const g = { dataset: { groupId: 'g' } }; const nodes = ids.map((id) => mk(id, 'file', g)); g.querySelectorAll = () => nodes; g.querySelector = (q) => nodes.find((n) => q.includes('"' + n.dataset.ctx + '"')); g.nodes = nodes; return g; };
  const doc = { addEventListener: (t, f) => handlers.push([t, f]), getElementById: () => null, querySelector: () => null, activeElement: null };
  return { doc, handlers, focused, mkGroup, mk };
}
function press(h, target, key, extra = {}) { let prevented = false; const ev = { key, target, ctrlKey: false, metaKey: false, altKey: false, preventDefault() { prevented = true; }, ...extra }; for (const [t, f] of h.handlers) if (t === 'keydown') f(ev); return prevented; }
test('IR-04 List file buttons move within their group with ArrowUp/Down and Home/End, stopping at group boundaries', () => {
  const h = fakeDom(); globalThis.document = h.doc; globalThis.CSS = { escape: (x) => x }; globalThis.MouseEvent = class {};
  attachContextMap(() => ({}));
  const a = h.mkGroup(['a1', 'a2', 'a3']); const [a1, a2, a3] = a.nodes;
  assert.equal(press(h, a1, 'ArrowDown'), true); assert.deepEqual(h.focused, ['a2']);
  assert.equal(press(h, a2, 'ArrowDown'), true); assert.equal(press(h, a3, 'ArrowDown'), true); assert.deepEqual(h.focused.slice(-2), ['a3', 'a3'], 'no wrap or crossing past the group end');
  press(h, a3, 'ArrowUp'); assert.equal(h.focused.at(-1), 'a2'); press(h, a2, 'Home'); assert.equal(h.focused.at(-1), 'a1'); press(h, a2, 'End'); assert.equal(h.focused.at(-1), 'a3');
  press(h, a1, 'ArrowUp'); assert.equal(h.focused.at(-1), 'a1', 'start boundary');
});
test('IR-04 native controls, group headers, modifier chords and other keys are left alone', () => {
  const h = fakeDom(); globalThis.document = h.doc; globalThis.CSS = { escape: (x) => x }; globalThis.MouseEvent = class {};
  attachContextMap(() => ({}));
  const a = h.mkGroup(['a1', 'a2']); const [a1] = a.nodes; const n0 = h.focused.length;
  const more = { dataset: { action: 'ctx-more' }, matches: () => false, closest: (s) => (s === '#ot4-list' ? {} : null) }; const head = { dataset: { ctx: 'grp', ctxKind: 'group' }, matches: () => false, closest: (s) => (s === '#ot4-list' ? {} : null) };
  assert.equal(press(h, more, 'ArrowDown'), false); assert.equal(press(h, head, 'ArrowDown'), false);
  assert.equal(press(h, a1, 'ArrowDown', { ctrlKey: true }), false); assert.equal(press(h, a1, 'Tab'), false); assert.equal(press(h, a1, 'Enter'), false);
  assert.equal(h.focused.length, n0);
});
