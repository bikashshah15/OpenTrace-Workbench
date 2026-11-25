// UIP-13 graph-renderer correction: lifecycle regression. No browser, network or service. A fake DOM and a fake Cytoscape implement the library contract MEASURED in the browser
// (UIP-13 smoke + product capture): the canvas renderer observes the PARENT of its container and destroys the renderer - NOT the Core - when the container leaves that parent;
// mount(host) tears the old renderer down (disconnecting its observer) and builds a new one observing the new parent; pan/zoom/selection/handlers live on the Core.
// Run: node --test tests/ui/unit/graph_lifecycle.test.mjs
// BEFORE run (same assertions, starting source): OT_SRC_ROOT=<dir holding the starting lib/graphs.js; it has no lib/graph_lifecycle.js> node --test ... ; then the paint logic below
// (ORIGINAL_PAINT_KEEPERS, a verbatim transcription of the three keeper lines of paint() at a8bdc01) stands in for the missing helper.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = process.env.OT_SRC_ROOT || join(dirname(fileURLToPath(import.meta.url)), '../../../src/ui');
const TREE = ROOT;

// ---------------------------------------------------------------- fake DOM
let DOC;
class FNode {
  constructor(tag = 'div') { this.tag = tag; this.parentNode = null; this.children = []; this.dataset = {}; this.attrs = {}; }
  get isConnected() { let n = this; while (n.parentNode) n = n.parentNode; return n === DOC; }
  setAttribute(k, v) { this.attrs[k] = v; if (k === 'data-keep') this.dataset.keep = v; }
  getAttribute(k) { return this.attrs[k] ?? null; }
  appendChild(c) { if (c.parentNode) c.parentNode.removeChild(c); c.parentNode = this; this.children.push(c); return c; }
  removeChild(c) { const i = this.children.indexOf(c); if (i < 0) return c; this.children.splice(i, 1); c.parentNode = null; FMO.notify(this, c); return c; }
  replaceWith(n) { const p = this.parentNode; const i = p.children.indexOf(this); if (n.parentNode) n.parentNode.removeChild(n); p.children.splice(i, 0, n); n.parentNode = p; this.removeChild?.call(p, this); }
  clear() { [...this.children].forEach((c) => this.removeChild(c)); }
  walk(f) { for (const c of this.children) { f(c); c.walk(f); } }
  querySelectorAll(sel) { assert.equal(sel, '[data-keep]'); const out = []; this.walk((n) => { if (n.dataset.keep !== undefined) out.push(n); }); return out; }
}
class FMO {   // MutationObserver (childList only); disconnect() discards records not yet delivered, as the DOM spec says
  static all = new Set(); static live() { return [...FMO.all].filter((m) => m.targets.length); }
  constructor(cb) { this.cb = cb; this.targets = []; this.gen = 0; FMO.all.add(this); }
  observe(t) { this.targets.push(t); }
  disconnect() { this.targets = []; this.gen++; }
  static notify(parent, removed) { for (const m of FMO.all) if (m.targets.includes(parent)) { const g = m.gen; queueMicrotask(() => { if (m.gen === g) m.cb([{ removedNodes: [removed] }]); }); } }
}
const tick = () => new Promise((r) => setTimeout(r, 0));

// ---------------------------------------------------------------- fake Cytoscape (the measured contract)
class FakeCy {
  constructor(opts) { this._c = opts.container; this._opt = opts; this._style = opts.style; this._dead = false; this.z = 1; this.p = { x: 0, y: 0 }; this.sel = new Set(); this.ls = []; this.els = new Map(); this.initCount = 0; this.initRenderer(); }
  initRenderer() { const R = { destroyed: false }; R.mo = new FMO((recs) => { for (const r of recs) for (const n of r.removedNodes) if (n === this._c) R.destroy(); });
    if (this._c.parentNode) R.mo.observe(this._c.parentNode); R.destroy = () => { R.destroyed = true; R.mo.disconnect(); }; this._r = R; this.initCount++; }
  renderer() { return this._r; } container() { return this._c; } destroyed() { return this._dead; }
  destroy() { if (!this._dead) { this._r.destroy(); this._dead = true; } }
  mount(h) { this._r.destroy(); this._c = h; this._style = this._opt.style; this.initRenderer(); }
  style(x) { if (x === undefined) return { json: () => JSON.parse(JSON.stringify(this._style)) }; this._style = x; this.styleSets = (this.styleSets || 0) + 1; return this; }
  zoom(z) { if (z === undefined) return this.z; this.z = typeof z === 'number' ? z : z.level; return this; }
  pan(p) { if (p === undefined) return { ...this.p }; this.p = { ...p }; return this; }
  resize() { this.resizes = (this.resizes || 0) + 1; } fit() { this.fits = (this.fits || 0) + 1; this.z = 0.5; }
  on(evt, a, b) { this.ls.push([evt, typeof a === 'string' ? a : null]); }
  add(list) { for (const e of list) this.els.set(e.data.id, { e, sel: false, pos: { x: 0, y: 0 } }); }
  edges() { const a = [...this.els.values()].filter((x) => x.e.data.source).map((x) => ({ id: () => x.e.data.id, data: (k) => x.e.data[k] })); return a; }
  getElementById(id) { const x = this.els.get(id); return { nonempty: () => !!x, position: (p) => { if (p) x.pos = p; return x.pos; }, select: () => { x.sel = true; this.sel.add(id); } }; }
  $() { return { unselect: () => { this.sel.clear(); for (const x of this.els.values()) x.sel = false; } }; }
  layout() { return { run: () => { this.gridRuns = (this.gridRuns || 0) + 1; } }; }
}
FakeCy.created = [];
const factory = (opts) => { const cy = new FakeCy(opts); FakeCy.created.push(cy); return cy; };

// ELK whose layout() completion the test controls
const elkQueue = [];
class FakeELK { layout(graph) { return new Promise((res, rej) => elkQueue.push({ graph, res, rej })); } }
const settleElk = (i, ok = true) => { const q = elkQueue[i]; ok ? q.res({ children: q.graph.children.map((c, k) => ({ id: c.id, x: 10 * k, y: 5 * k })) }) : q.rej(new Error('layout failed')); };

DOC = new FNode('document'); const docEl = new FNode('html'); DOC.appendChild(docEl);
Object.assign(globalThis, {
  window: globalThis, document: { createElement: () => ({}), head: { appendChild: (s) => queueMicrotask(() => s.onload && s.onload()) }, documentElement: docEl },
  getComputedStyle: () => ({ getPropertyValue: () => '#123' }), MutationObserver: FMO, Worker: class {},
});
globalThis.cytoscape = factory; globalThis.ELK = FakeELK;

const G = await import(join(ROOT, 'lib/graphs.js'));
const HAVE_HELPER = existsSync(join(ROOT, 'lib/graph_lifecycle.js'));
const L = HAVE_HELPER ? await import(join(ROOT, 'lib/graph_lifecycle.js')) : null;

// Verbatim transcription of the three keeper statements of paint() at the starting source a8bdc01 (used only when the helper does not exist = the BEFORE run).
const ORIGINAL_PAINT_KEEPERS = {
  keepersOf: (el) => { const keepers = new Map(); el.querySelectorAll('[data-keep]').forEach((n) => keepers.set(n.dataset.keep, n)); return keepers; },
  restoreKeepers: (el, keepers) => { const reused = new Set();
    el.querySelectorAll('[data-keep]').forEach((ph) => { const old = keepers.get(ph.dataset.keep); if (old) { ph.replaceWith(old); reused.add(ph.dataset.keep); } });
    keepers.forEach((n, k) => { if (!reused.has(k)) { n._cy?.destroy(); n._themeObs?.disconnect(); n._cy = null; } }); },
};
const P = L || ORIGINAL_PAINT_KEEPERS;
const disposeGraphsIn = L ? L.disposeGraphsIn : () => {};   // the starting source's render() clears the workbench innerHTML without disposing

// paint() equivalent: collect keepers, rewrite the root (all children removed), put placeholders back, restore keepers.
function repaint(root, keys) { const keepers = P.keepersOf(root); root.clear(); const wrap = new FNode('div'); root.appendChild(wrap);
  for (const k of keys) { const ph = new FNode('div'); ph.setAttribute('data-keep', k); wrap.appendChild(ph); } P.restoreKeepers(root, keepers); }
function mountHost(root, key) { const wrap = new FNode('div'); root.appendChild(wrap); const h = new FNode('div'); h.setAttribute('data-keep', key); wrap.appendChild(h); return h; }
const nodes = (ids) => ids.map((id) => ({ id, type: 'assertion' })); const edges = [{ from: 'a', to: 'b', type: 'x' }, { from: 'b', to: 'c', type: 'x' }];
async function build(root, key = 'cy-bom8-inline', ids = ['a', 'b', 'c'], sel = null, onSelect = () => {}) {
  const h = mountHost(root, key); const p = G.syncGraph(h, { nodes: nodes(ids), edges, selected: sel, onSelect }); await tick(); await tick(); return { h, p }; }
const fresh = () => { elkQueue.length = 0; FakeCy.created.length = 0; FMO.all.clear(); const root = new FNode('div'); root.id = 'ot-workbench'; docEl.children.length = 0; docEl.appendChild(root); return root; };

test('a surrounding repaint leaves the kept graph with a LIVE renderer on the SAME instance (library contract: re-parent destroys the renderer)', async () => {
  const root = fresh(); const { h, p } = await build(root); settleElk(0); await p; const cy = h._cy;
  repaint(root, ['cy-bom8-inline']); await tick();
  assert.equal(h._cy, cy, 'same instance');
  assert.equal(cy.destroyed(), false);
  assert.equal(cy.renderer().destroyed, false, 'renderer must be usable after the surrounding repaint');
  assert.equal(cy.container(), h); assert.ok(h.isConnected);
});

test('repeated surrounding repaints keep the renderer alive, the camera, selection and membership, and add no handlers or observers', async () => {
  const root = fresh(); const { h, p } = await build(root, 'cy-bom8-inline', ['a', 'b', 'c'], 'b'); settleElk(0); await p; const cy = h._cy;
  cy.zoom(1.7); cy.pan({ x: 31, y: -12 }); const ids0 = [...cy.els.keys()].join(); const ls0 = cy.ls.length; const nodeLs = cy.ls.filter((l) => l[0] === 'tap').length;
  for (let i = 0; i < 5; i++) { repaint(root, ['cy-bom8-inline']); await tick(); assert.equal(cy.renderer().destroyed, false, `renderer alive after repaint ${i + 1}`); }
  assert.equal(h._cy, cy); assert.equal(cy.zoom(), 1.7); assert.deepEqual(cy.pan(), { x: 31, y: -12 });
  assert.deepEqual([...cy.sel], ['b'], 'selection survives'); assert.equal([...cy.els.keys()].join(), ids0, 'membership survives');
  assert.equal(cy.ls.length, ls0, 'no Core handler is registered by repaints'); assert.equal(cy.ls.filter((l) => l[0] === 'tap').length, nodeLs);
  const live = FMO.live().filter((m) => m.targets.some((t) => t === h.parentNode)); assert.equal(live.length, 1, 'exactly one live observer on the host parent (the current renderer)');
  assert.equal(FMO.live().filter((m) => m.targets.includes(h)).length, 0);
});

test('a renderer destroyed under a live instance is recovered by syncGraph (same instance, not rebuilt)', async () => {
  const root = fresh(); const { h, p } = await build(root); settleElk(0); await p; const cy = h._cy; cy.zoom(0.9);
  cy.renderer().destroy();   // simulate any other path that destroys the renderer only
  const ELK_CALLS = elkQueue.length; await G.syncGraph(h, { nodes: nodes(['a', 'b', 'c']), edges, selected: null, onSelect() {} });
  assert.equal(h._cy, cy); assert.equal(cy.renderer().destroyed, false); assert.equal(cy.zoom(), 0.9); assert.equal(elkQueue.length, ELK_CALLS, 'no new layout');
});

test('intentional teardown is preserved: a kept host that does not come back is destroyed and cleared', async () => {
  const root = fresh(); const { h, p } = await build(root); settleElk(0); await p; const cy = h._cy;
  repaint(root, []);   // the markup no longer contains the graph
  assert.equal(cy.destroyed(), true); assert.equal(h._cy, null);
  assert.equal(FMO.live().filter((m) => m.targets.includes(h) || m.targets.includes(h.parentNode)).length, 0, 'no observer left on the retired host');
});

test('changing the node set rebuilds exactly one new instance and destroys the old one', async () => {
  const root = fresh(); const { h, p } = await build(root); settleElk(0); await p; const old = h._cy;
  const p2 = G.syncGraph(h, { nodes: nodes(['a', 'b']), edges: [{ from: 'a', to: 'b', type: 'x' }], selected: null, onSelect() {} }); await tick(); await tick(); settleElk(1); await p2;
  assert.equal(old.destroyed(), true); assert.notEqual(h._cy, old); assert.equal(h._cy.destroyed(), false); assert.equal(FakeCy.created.length, 2);
});

test('stale layout: a layout that completes after the instance was replaced mutates neither the old nor the new instance (success path)', async () => {
  const root = fresh(); const { h, p } = await build(root); const first = h._cy;           // layout 0 pending
  const p2 = G.syncGraph(h, { nodes: nodes(['a', 'b']), edges: [{ from: 'a', to: 'b', type: 'x' }], selected: null, onSelect() {} }); await tick(); await tick();   // replaces it; layout 1 pending
  const second = h._cy; assert.notEqual(first, second);
  settleElk(0); await p; const fitsFirst = first.fits || 0;
  assert.equal(second.fits || 0, 0, 'the replacement was not fitted by the stale completion'); assert.equal(first.fits || 0, fitsFirst);
  assert.equal([...second.els.values()].every((x) => x.pos.x === 0 && x.pos.y === 0), true, 'the replacement positions were not written by the stale layout');
  settleElk(1); await p2; assert.equal(second.fits, 1);
});

test('stale layout: a FAILED layout that rejects after replacement or navigation does not run the grid fallback or fit on a dead instance', async () => {
  const root = fresh(); const { h, p } = await build(root); const first = h._cy;
  const p2 = G.syncGraph(h, { nodes: nodes(['a', 'b']), edges: [{ from: 'a', to: 'b', type: 'x' }], selected: null, onSelect() {} }); await tick(); await tick();
  settleElk(0, false); await p; assert.equal(first.destroyed(), true); assert.equal(first.gridRuns || 0, 0, 'no grid layout on the destroyed instance'); assert.equal(first.fits || 0, 0, 'no fit on the destroyed instance');
  settleElk(1); await p2;
  // navigation: the host is retired while its layout is pending
  const root2 = fresh(); const b = await build(root2); const cy = b.h._cy; (L ? L.disposeGraph : (x) => { x._cy.destroy(); x._cy = null; })(b.h); settleElk(0, false); await b.p;
  assert.equal(cy.gridRuns || 0, 0); assert.equal(cy.fits || 0, 0);
});

test('leaving the Workbench retires every graph instance and leaves no theme/renderer observer behind', async () => {
  const root = fresh(); const { h, p } = await build(root); settleElk(0); await p; const cy = h._cy;
  assert.equal(FMO.live().some((m) => m.targets.includes(docEl)), true, 'theme observer exists while the graph is shown');
  disposeGraphsIn(root); root.clear();   // render(): destination left the Workbench
  assert.equal(cy.destroyed(), true, 'instance retired when the Workbench is left'); assert.equal(FMO.live().some((m) => m.targets.includes(docEl)), false, 'theme observer disconnected');
});

test('wiring: paint() routes kept hosts through the lifecycle helper and render() retires graphs when the Workbench is left', () => {
  const app = readFileSync(join(TREE, 'app.js'), 'utf8');
  assert.match(app, /restoreKeepers\(el, keepers\)/); assert.match(app, /disposeGraphsIn\(\$\('ot-workbench'\)\)/);
  assert.doesNotMatch(app, /keepers\.forEach\(\(n, k\) => \{ if \(!reused\.has\(k\)\) \{ n\._cy\?\.destroy\(\)/, 'the original inline teardown (which re-parents without re-attaching) is gone');
});

test('R9-02: a re-attach re-applies the CURRENT stylesheet (host._restyle), and a host without _restyle keeps its current stylesheet via the snapshot', async () => {
  const root = fresh(); const { h, p } = await build(root); settleElk(0); await p; const cy = h._cy;
  cy.style(['THEME-B']); h._restyle = () => ['THEME-B']; repaint(root, ['cy-bom8-inline']); await tick();
  assert.deepEqual(cy._style, ['THEME-B'], 'not the creation-time stylesheet');
  cy.style(['SNAP']); h._restyle = null; repaint(root, ['cy-bom8-inline']); await tick();
  assert.deepEqual(cy._style, ['SNAP'], 'snapshot path');
  assert.equal(cy.renderer().destroyed, false);
});
test('R9-03: a kept host that is a DIRECT child of the paint root (same parent after the repaint) still gets a live renderer', async () => {
  const root = fresh(); const h = new FNode('div'); h.setAttribute('data-keep', 'k'); root.appendChild(h);
  const p = G.syncGraph(h, { nodes: nodes(['a', 'b', 'c']), edges, selected: null, onSelect() {} }); await tick(); await tick(); settleElk(0); await p; const cy = h._cy;
  const keepers = P.keepersOf(root); root.clear(); const ph = new FNode('div'); ph.setAttribute('data-keep', 'k'); root.appendChild(ph); P.restoreKeepers(root, keepers); await tick();
  assert.equal(h.parentNode, root); assert.equal(cy.renderer().destroyed, false);
});
test('R9-04: disposing a host invalidates a pending layout token (dense.js-style completion cannot act on the retired host)', () => {
  if (!L) return; const h = new FNode('div'); h._token = 4; h._cy = { destroy() {} }; L.disposeGraph(h); assert.equal(h._token, 5);
});
