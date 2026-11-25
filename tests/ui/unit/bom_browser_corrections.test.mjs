// UIP-08 browser-evidence corrections (independent review UIP08-BR-01, BR-02, BR-D01). These assert the CORRECT behavior.
// Where a corrected helper does not exist on the starting source, the old literal behavior is used as the fallback so the failure is demonstrable.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import * as S from '../../../src/ui/lib/store.js';
import { answer } from '../../../src/ui/components/assistant.js';

const { createStore, initial } = S;
const read = (p) => readFileSync(new URL('../../../' + p, import.meta.url), 'utf8');
const identity = { analysis_digest: 'a'.repeat(64), owner: 'review', name: 'fixture', commit: 'b'.repeat(40) };
const mk = () => createStore({ ...initial(), epoch: 3, analysis: { generation: 7, identity }, workbench: { ...initial().workbench, tab: 'bom' } });
const patch = (s, p) => s.dispatch({ type: 'BOM_PATCH', patch: p });

// ---------- BR-02: the offline guide for out-of-list pinned candidates ----------
// The starting source's literal app.js BOM branch (only used when the corrected helper is absent).
const oldInline = (b) => { const item = S.bomSelectedItem(b); if (!item) return null;
  return { title: item.display.name, cite: [item.item_id, item.assertion_id, item.rule_id, item.inventory?.inventory_id].filter(Boolean),
    meaning: `${item.display.raw_title}. The bound comparison recorded ${item.state.replaceAll('_', ' ')}${item.inventory ? ' against ' + item.inventory.generator : ''}.`,
    limits: item.graph_state === 'assertion_graph' ? 'The inventory check does not establish installation, runtime use or completeness beyond its recorded scope.' : 'More evidence is needed; no rule verdict or completeness conclusion is established.',
    next: 'Inspect the recorded graph, source location and inventory identity for this candidate.' }; };
const ctxOf = (b) => (S.bomAssistantContext || oldInline)(b);
const ID = 'cand:missing_component:82ad0e88', AID = 'dreq-onnxruntime-4e607741';
const chooserRow = (over = {}) => ({ item_id: ID, assertion_id: AID, display_name: 'onnxruntime (wildcard_pin) declared at docker/main/requirements-wheels.txt:46 has no record in inv:syft-source-dir', family: 'software', state: 'contradicted', location: { path: 'docker/main/requirements-wheels.txt' }, ...over });
const pinned = (row) => { const s = mk(); patch(s, { related: { subject: { id: 'entity:r' }, resolution: 'multiple', related_total: 1, items: [row] }, popup: 'chooser', selectedRecord: 'entity:r' }); patch(s, S.bomRelatedPatch(s.get().bom8, row.item_id)); return s.get().bom8; };

test('BR-02: a pinned out-of-list candidate with a recorded assertion and verdict is not described as having no rule verdict', () => {
  const ctx = ctxOf(pinned(chooserRow()));
  const limits = answer('limits', ctx).text, meaning = answer('meaning', ctx).text;
  assert.doesNotMatch(limits, /no rule verdict/i, limits);
  assert.match(limits, /contradicted/, 'states the recorded verdict');
  assert.match(limits, /not loaded/i, 'says which details are not loaded');
  assert.match(limits, /does not establish installation, runtime use or completeness/i, 'keeps the cautious limits');
  assert.match(meaning, /contradicted/);
});
test('BR-02: citations keep the exact IDs and invent no rule ID, inventory or verdict', () => {
  const ctx = ctxOf(pinned(chooserRow()));
  assert.deepEqual(answer('limits', ctx).cite, [ID, AID]);
  const text = JSON.stringify(ctx);
  assert.doesNotMatch(text, /inventory_coverage/, 'no invented rule ID');
  assert.doesNotMatch(answer('limits', ctx).text, /Syft|against /);
});
test('BR-02: a genuine pinned no-verdict / unknown-coverage task keeps the cautious no-verdict wording', () => {
  const ctx = ctxOf(pinned(chooserRow({ assertion_id: null, state: 'unknown_coverage' })));
  assert.match(answer('limits', ctx).text, /no rule verdict/i);
  assert.deepEqual(answer('limits', ctx).cite, [ID]);
});
test('BR-02: ordinary queue candidates keep their existing answers', () => {
  const s = mk(); const base = { item_id: 'cand:x', assertion_id: 'dreq-x', display: { name: 'x', raw_title: 'x raw' }, state: 'contradicted', category: 'software', location: null, inventory: { generator: 'syft 1.51.1', inventory_id: 'inv:a' }, rule_id: 'r/1' };
  patch(s, { selected: 'cand:x', queue: { items: [{ ...base, graph_state: 'assertion_graph' }] } });
  let ctx = ctxOf(s.get().bom8);
  assert.equal(answer('limits', ctx).text, 'The inventory check does not establish installation, runtime use or completeness beyond its recorded scope.');
  assert.deepEqual(ctx.cite, ['cand:x', 'dreq-x', 'r/1', 'inv:a']);
  patch(s, { queue: { items: [{ ...base, assertion_id: null, rule_id: null, inventory: null, state: 'unknown_coverage', graph_state: 'no_graph_collection_task' }] } });
  ctx = ctxOf(s.get().bom8);
  assert.equal(answer('limits', ctx).text, 'More evidence is needed; no rule verdict or completeness conclusion is established.');
});
test('BR-02: the app calls the shared helper (the tested path is the shipped path)', () => {
  const app = read('src/ui/app.js');
  assert.match(app, /bomAssistantContext\(s\.bom8\)/, 'assistantContext delegates to the store helper');
  assert.doesNotMatch(app, /no rule verdict or completeness conclusion/, 'no inline copy of the wording remains in app.js');
});

// ---------- BR-01: readable Details toggle in the mobile drawer ----------
test('BR-01: the mobile Details toggle uses themed foreground, background and border tokens and keeps its focus outline', () => {
  const css = read('src/ui/styles/app.css');
  const rule = [...css.matchAll(/\.ot-bom8-drawer-head button\{[^}]*\}/g)].map((m) => m[0]).find((r) => /color:/.test(r));
  assert.ok(rule, 'a BOM-scoped drawer-toggle rule sets a foreground color');
  assert.match(rule, /color:var\(--ink\)/); assert.match(rule, /background:var\(--raised\)/); assert.match(rule, /border:1px solid var\(--line\)/);
  assert.doesNotMatch(rule, /outline:\s*(none|0)/, 'focus indicator is not removed');
  assert.match(css, /\.ot-bom8-drawer-head button\{display:none\}@media\(max-width:700px\)\{\.ot-bom8-drawer-head button\{display:inline-flex;/, 'hidden on desktop, shown at narrow width (visibility behavior unchanged)');
});

// ---------- BR-D01: Cytoscape construction on a detached host ----------
// Real Cytoscape computes its container's content size as clientWidth minus padding parsed from getComputedStyle; for a detached element the
// computed values are empty, so the size is NaN and the default initial layout receives an undefined bounding box ("reading 'h'").
test('BR-D01 (characterization): vendored Cytoscape throws the observed TypeError when the container size is not a number', () => {
  const cytoscape = createRequire(import.meta.url)('../../../src/ui/vendor/cytoscape.min.js');
  const cy = cytoscape({ headless: true, elements: [] }); cy.width = () => NaN; cy.height = () => NaN;
  assert.throws(() => cy.layout({ name: 'grid' }).run(), (e) => e instanceof TypeError && /reading 'h'/.test(e.message));
});
async function withDomDoubles(fn) {
  const created = []; const old = { window: globalThis.window, document: globalThis.document };
  const win = { cytoscape: (o) => { created.push({ connected: o.container.isConnected }); const cy = { destroyed: false, add() {}, on() {}, edges: () => ({ map: () => [] }), resize() {}, fit() {}, style() {}, $: () => ({ unselect() {} }), getElementById: () => ({ nonempty: () => false, position() {} }), destroy() { this.destroyed = true; }, layout: () => ({ run() {} }) }; return cy; },
    ELK: class { layout() { return Promise.resolve({ children: [] }); } }, Worker: class {} };
  globalThis.window = win; globalThis.Worker = win.Worker;
  globalThis.document = { head: { appendChild: (s) => queueMicrotask(() => s.onload()) }, createElement: () => ({}), documentElement: {} };
  globalThis.getComputedStyle = () => ({ getPropertyValue: () => '#000' }); globalThis.MutationObserver = class { observe() {} disconnect() {} };
  try { return await fn(created); } finally { globalThis.window = old.window; globalThis.document = old.document; }
}
const host = (connected) => ({ isConnected: connected, setAttribute() {}, _onSelect: null });
test('BR-D01: a host detached while the libraries are loading never gets a Cytoscape instance', async () => {
  const G = await import('../../../src/ui/lib/graphs.js?detached');
  await withDomDoubles(async (created) => {
    const h = host(true); const p = G.syncGraph(h, { nodes: [{ id: 'a', type: 'entity' }], edges: [], selected: null, onSelect() {} });
    h.isConnected = false;                                   // a repaint replaces the host before the awaited library step resumes
    await p;
    assert.equal(created.length, 0, 'no Cytoscape construction on a detached host');
    assert.equal(h._cy, undefined);
  });
});
test('BR-D01: a connected host still builds its graph (other consumers unchanged)', async () => {
  const G = await import('../../../src/ui/lib/graphs.js?connected');
  await withDomDoubles(async (created) => {
    const h = host(true); await G.syncGraph(h, { nodes: [{ id: 'a', type: 'entity' }], edges: [], selected: null, onSelect() {} });
    assert.equal(created.length, 1); assert.equal(created[0].connected, true); assert.ok(h._cy);
  });
});
