// S4-FIX-01 regression: a graph host in auto-fit mode refits when its host is resized; a deliberate user pan/zoom is never moved by a resize; explicit Fit re-arms auto-fit;
// observers, timers and listeners go with the instance. No browser, network or service: fakes implement only the measured library contract
// (Cytoscape emits dragpan/scrollzoom/pinchzoom ONLY for user input; fit()/zoom()/pan() emit pan/zoom/viewport; the canvas is resized to the host by cy.resize()).
// Run: node --test tests/ui/unit/graph_resize.test.mjs
import test from 'node:test';
import assert from 'node:assert/strict';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '../../../src/ui');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ---------------------------------------------------------------- fakes
class FakeRO {                                   // ResizeObserver: the test triggers callbacks
  static all = [];
  constructor(cb) { this.cb = cb; this.targets = []; this.disconnected = false; FakeRO.all.push(this); }
  observe(t) { this.targets.push(t); } disconnect() { this.disconnected = true; this.targets = []; }
  fire(w, h) { if (!this.disconnected) this.cb([{ contentRect: { width: w, height: h } }]); }
}
class FakeCy {
  constructor() { this.dead = false; this.live = true; this.z = 1; this.p = { x: 0, y: 0 }; this.resizes = 0; this.fits = 0; this.handlers = []; this.sel = new Set(); }
  destroyed() { return this.dead; } renderer() { return { destroyed: !this.live }; } container() { return this.host; }
  width() { return 600; } height() { return 400; }
  resize() { this.resizes++; } fit() { this.fits++; this.z = 0.5; this.p = { x: 7, y: 7 }; }
  zoom(z) { if (z === undefined) return this.z; this.z = typeof z === 'number' ? z : z.level; return this; }
  pan(p) { if (p === undefined) return { ...this.p }; this.p = { ...p }; return this; }
  on(evt, a, b) { this.handlers.push({ evt, fn: typeof a === 'function' ? a : b, sel: typeof a === 'string' ? a : null }); }
  emitUser(evt) { for (const h of this.handlers) if (!h.sel && h.evt.split(' ').includes(evt)) h.fn({ type: evt }); }
  destroy() { this.dead = true; }
}
const mkHost = (w = 600, h = 400) => ({ clientWidth: w, clientHeight: h, isConnected: true, parentNode: {}, dataset: {}, setAttribute() {}, getAttribute() { return null; } });
const timers = () => { const t = { n: 0, pending: new Map(), cleared: [] };
  t.setTimer = (fn, ms) => { const id = ++t.n; t.pending.set(id, { fn, ms }); return id; };
  t.clearTimer = (id) => { t.cleared.push(id); t.pending.delete(id); };
  t.flush = () => { const all = [...t.pending]; t.pending.clear(); all.forEach(([, v]) => v.fn()); return all.length; };
  return t; };

const L = await import(join(ROOT, 'lib/graph_lifecycle.js'));
function armed({ w = 600, h = 400 } = {}) {
  FakeRO.all.length = 0; const host = mkHost(w, h); const cy = new FakeCy(); cy.host = host; host._cy = cy; const t = timers();
  L.armUserCamera(host, cy); L.fitHost(host);
  const ok = L.observeResize(host, { ResizeObserverImpl: FakeRO, setTimer: t.setTimer, clearTimer: t.clearTimer });
  return { host, cy, t, ro: FakeRO.all[0], ok };
}
const resizeTo = (E, w, h) => { E.host.clientWidth = w; E.host.clientHeight = h; E.ro.fire(w, h); const passes = E.t.flush(); return passes; };

test('fitHost fits the current host, arms auto-fit and records the size; refuses a missing or destroyed instance', () => {
  const host = mkHost(); assert.equal(L.fitHost(host), false); host._cy = new FakeCy(); host._cy.dead = true; assert.equal(L.fitHost(host), false);
  const cy = new FakeCy(); host._cy = cy; assert.equal(L.fitHost(host, 24), true);
  assert.equal(cy.resizes, 1); assert.equal(cy.fits, 1); assert.equal(host._autoFit, true); assert.deepEqual(host._lastSize, { w: 600, h: 400 });
});

test('1. a fitted graph refits automatically after the host shrinks (one pass, not one per intermediate size)', () => {
  const E = armed(); assert.equal(E.ok, true); assert.equal(E.host._autoFit, true); const fits0 = E.cy.fits, rs0 = E.cy.resizes;
  for (const w of [560, 480, 420, 380]) { E.host.clientWidth = w; E.ro.fire(w, 400); }       // a drag-resize delivers many sizes before the debounce elapses
  assert.equal(E.t.pending.size, 1, 'one pending debounced pass (earlier timers cleared)');
  assert.equal(E.t.flush(), 1); assert.equal(E.cy.fits, fits0 + 1, 'exactly one refit'); assert.equal(E.cy.resizes, rs0 + 1);
  assert.deepEqual(E.host._lastSize, { w: 380, h: 400 });
});

test('2. a deliberate user pan/zoom survives resize: the renderer is told the new size but the camera is not moved', () => {
  for (const evt of ['dragpan', 'scrollzoom', 'pinchzoom']) {
    const E = armed(); E.cy.zoom(1.7); E.cy.pan({ x: 31, y: -12 }); E.cy.emitUser(evt);
    assert.equal(E.host._autoFit, false, `${evt} leaves auto-fit mode`);
    const fits0 = E.cy.fits, rs0 = E.cy.resizes; assert.equal(resizeTo(E, 380, 400), 1);
    assert.equal(E.cy.fits, fits0, `no refit after ${evt}`); assert.equal(E.cy.resizes, rs0 + 1, 'renderer resized'); assert.equal(E.cy.zoom(), 1.7); assert.deepEqual(E.cy.pan(), { x: 31, y: -12 });
  }
});

test('programmatic camera changes are not mistaken for user gestures (fit/zoom/pan do not emit the gesture events); the listener is registered once per instance on the exact events', () => {
  const E = armed(); const regs = E.cy.handlers.filter((h) => h.evt === L.USER_CAMERA_EVENTS); assert.equal(regs.length, 1); assert.equal(L.USER_CAMERA_EVENTS, 'dragpan scrollzoom pinchzoom');
  E.cy.fit(); E.cy.zoom(2); E.cy.pan({ x: 1, y: 1 }); assert.equal(E.host._autoFit, true, 'programmatic changes keep auto-fit');
  const stale = armed(); const other = new FakeCy(); stale.host._cy = other; stale.cy.emitUser('dragpan'); assert.equal(stale.host._autoFit, true, 'a gesture from a replaced instance is ignored');
});

test('3./4. explicit Fit restores visibility and re-arms auto-fit; a subsequent shrink then fits automatically', () => {
  const E = armed(); E.cy.emitUser('scrollzoom'); assert.equal(E.host._autoFit, false); resizeTo(E, 400, 400); const fitsA = E.cy.fits;
  L.fitHost(E.host); assert.equal(E.host._autoFit, true); assert.equal(E.cy.fits, fitsA + 1, 'explicit Fit fits the current host');
  resizeTo(E, 300, 400); assert.equal(E.cy.fits, fitsA + 2, 'the next shrink refits automatically');
});

test('toolbar zoom (noteUserCamera) also leaves auto-fit mode', () => { const E = armed(); L.noteUserCamera(E.host); assert.equal(E.host._autoFit, false); resizeTo(E, 300, 400); assert.equal(E.cy.fits, 1); });

test('zero sizes, unchanged sizes and the first measurement never act; hidden then visible at the same size does not refit; at a new size it does', () => {
  const E = armed(); const fits0 = E.cy.fits;
  E.ro.fire(0, 0); E.ro.fire(600, 0); assert.equal(E.t.pending.size, 0, 'zero size ignored (hidden tab / detached host)');
  E.ro.fire(600, 400); assert.equal(E.t.pending.size, 0, 'unchanged size ignored (re-parent/repaint)');
  E.ro.fire(0, 0); E.ro.fire(600, 400); assert.equal(E.t.pending.size, 0, 'hidden then visible at the same size: nothing to do'); assert.equal(E.cy.fits, fits0);
  E.ro.fire(0, 0); E.host.clientWidth = 500; E.ro.fire(500, 400); assert.equal(E.t.flush(), 1); assert.equal(E.cy.fits, fits0 + 1, 'a new size after hidden refits');
  const F = armed(); F.host._lastSize = null; F.ro.fire(300, 300); assert.equal(F.t.pending.size, 0, 'first measurement is recorded only'); assert.deepEqual(F.host._lastSize, { w: 300, h: 300 });
});

test('the debounced pass does nothing for a stale, destroyed or renderer-less instance, and does not loop on its own fit', () => {
  for (const mutate of [(E) => { E.host._cy = new FakeCy(); }, (E) => { E.cy.dead = true; }, (E) => { E.cy.live = false; }]) {
    const E = armed(); const fits0 = E.cy.fits; E.host.clientWidth = 300; E.ro.fire(300, 400); mutate(E); E.t.flush(); assert.equal(E.cy.fits, fits0); }
  const E = armed(); resizeTo(E, 300, 400); const fits1 = E.cy.fits; E.ro.fire(300, 400); assert.equal(E.t.pending.size, 0, 'the size recorded by the pass makes a repeat callback a no-op (no self-loop)'); assert.equal(E.cy.fits, fits1);
});

test('without ResizeObserver the graph keeps the previous behaviour (no throw, no observer)', () => {
  const host = mkHost(); host._cy = new FakeCy(); assert.equal(L.observeResize(host, { ResizeObserverImpl: null }), false); assert.equal(host._resizeObs, undefined);
  assert.equal(L.observeResize(null), false);
});

test('observeResize is idempotent per host; disposeGraph disconnects the observer, clears the pending timer, ignores a late callback and resets the mode', () => {
  const E = armed(); assert.equal(L.observeResize(E.host, { ResizeObserverImpl: FakeRO, setTimer: E.t.setTimer, clearTimer: E.t.clearTimer }), false); assert.equal(FakeRO.all.length, 1);
  E.host.clientWidth = 300; E.ro.fire(300, 400); const pending = [...E.t.pending.keys()]; assert.equal(pending.length, 1);
  L.disposeGraph(E.host);
  assert.equal(E.ro.disconnected, true); assert.deepEqual(E.t.cleared, pending); assert.equal(E.t.pending.size, 0);
  assert.equal(E.host._resizeObs, null); assert.equal(E.host._resizeTimer, null); assert.equal(E.host._autoFit, null); assert.equal(E.host._lastSize, null); assert.equal(E.host._cy, null); assert.equal(E.cy.dead, true);
  E.ro.fire(200, 200); assert.equal(E.t.pending.size, 0, 'a late callback after dispose does nothing'); assert.equal(E.cy.fits, 1, 'only the layout fit ever happened');
});

// ---------------------------------------------------------------- integration through the real syncGraph (fake globals; one instance per host)
const elkQ = []; class FakeELK { layout(g) { return new Promise((res) => elkQ.push(() => res({ children: g.children.map((c, k) => ({ id: c.id, x: 10 * k, y: 5 * k })) }))); } }
const created = [];
class IntCy extends FakeCy {
  constructor(opts) { super(); this.host = opts.container; this.els = new Map(); created.push(this); }
  add(list) { for (const e of list) this.els.set(e.data.id, { e, pos: {} }); } edges() { return [...this.els.values()].filter((x) => x.e.data.source).map((x) => ({ id: () => x.e.data.id, data: (k) => x.e.data[k] })); }
  getElementById(id) { const x = this.els.get(id); return { nonempty: () => !!x, position: (p) => { if (p) x.pos = p; return x.pos; }, select() {} }; }
  $() { return { unselect() {} }; } layout() { return { run() {} }; } style(x) { return x === undefined ? { json: () => ({}) } : this; } mount(h) { this.host = h; }
}
class FakeMO { observe() {} disconnect() {} }
const docEl = {};
Object.assign(globalThis, { window: globalThis, document: { createElement: () => ({}), head: { appendChild: (s) => queueMicrotask(() => s.onload && s.onload()) }, documentElement: docEl }, getComputedStyle: () => ({ getPropertyValue: () => '#123' }), MutationObserver: FakeMO, Worker: class {}, ResizeObserver: FakeRO });
globalThis.cytoscape = (o) => new IntCy(o); globalThis.ELK = FakeELK;
const G = await import(join(ROOT, 'lib/graphs.js'));
const nodes = ['a', 'b', 'c'].map((id) => ({ id, type: 'assertion' })); const edges = [{ from: 'a', to: 'b', type: 'x' }, { from: 'b', to: 'c', type: 'x' }];
async function build() { FakeRO.all.length = 0; created.length = 0; elkQ.length = 0; const host = mkHost(); const p = G.syncGraph(host, { nodes, edges, selected: null, onSelect() {} });
  for (let i = 0; i < 6 && !elkQ.length; i++) await sleep(0); elkQ.shift()(); await p; return { host, cy: created[0], ro: FakeRO.all[0] }; }
const realResize = async (E, w, h) => { E.host.clientWidth = w; E.host.clientHeight = h; E.ro.fire(w, h); await sleep(L.RESIZE_DEBOUNCE_MS + 60); };

test('syncGraph: initial layout fit arms auto-fit, registers exactly one gesture listener and one observer; a shrink then refits once', async () => {
  const E = await build(); assert.equal(E.host._autoFit, true); assert.equal(E.cy.fits, 1); assert.equal(FakeRO.all.length, 1); assert.equal(E.ro.targets[0], E.host);
  assert.equal(E.cy.handlers.filter((h) => h.evt === L.USER_CAMERA_EVENTS).length, 1);
  await realResize(E, 380, 400); assert.equal(E.cy.fits, 2);
});

test('syncGraph: user gesture then shrink keeps the camera; explicit graphs.fit() re-arms; the next shrink refits; toolbar zoom() disarms', async () => {
  const E = await build(); E.cy.zoom(1.6); E.cy.pan({ x: 20, y: 30 }); E.cy.emitUser('dragpan');
  await realResize(E, 380, 400); assert.equal(E.cy.fits, 1, 'no refit'); assert.equal(E.cy.zoom(), 1.6); assert.deepEqual(E.cy.pan(), { x: 20, y: 30 });
  G.fit(E.host); assert.equal(E.cy.fits, 2); assert.equal(E.host._autoFit, true);
  await realResize(E, 300, 400); assert.equal(E.cy.fits, 3, 'auto-fit again');
  G.zoom(E.host, 1.2); assert.equal(E.host._autoFit, false); await realResize(E, 250, 400); assert.equal(E.cy.fits, 3);
});

test('syncGraph: a repaint with the same node set keeps the instance, the single observer and the mode; teardown through disposeGraph releases everything', async () => {
  const E = await build(); await G.syncGraph(E.host, { nodes, edges, selected: 'b', onSelect() {} });
  assert.equal(E.host._cy, E.cy); assert.equal(created.length, 1); assert.equal(FakeRO.all.length, 1); assert.equal(E.cy.handlers.filter((h) => h.evt === L.USER_CAMERA_EVENTS).length, 1); assert.equal(E.host._autoFit, true);
  E.host.clientWidth = 300; E.ro.fire(300, 400); L.disposeGraph(E.host); assert.equal(E.ro.disconnected, true); assert.equal(E.cy.dead, true);
  await sleep(L.RESIZE_DEBOUNCE_MS + 60); assert.equal(E.cy.fits, 1, 'the pending pass was cancelled by disposal');
});

test('syncGraph: replacing the node set disposes the old observer and arms a fresh instance', async () => {
  const E = await build(); const p = G.syncGraph(E.host, { nodes: nodes.slice(0, 2), edges: [{ from: 'a', to: 'b', type: 'x' }], selected: null, onSelect() {} });
  for (let i = 0; i < 6 && !elkQ.length; i++) await sleep(0); elkQ.shift()(); await p;
  assert.equal(E.ro.disconnected, true); assert.equal(created.length, 2); assert.equal(FakeRO.all.length, 2); assert.equal(E.host._autoFit, true); assert.equal(FakeRO.all[1].targets[0], E.host);
});

test('disposal with a pending debounce calls the timer API UNBOUND (browsers throw "Illegal invocation" for window.clearTimeout called as a method of another object)', () => {
  const E = (() => { FakeRO.all.length = 0; const host = mkHost(); const cy = new FakeCy(); cy.host = host; host._cy = cy; const t = timers(); const cleared = [];
    const browserClear = function (id) { if (this !== undefined && this !== globalThis) throw new TypeError('Illegal invocation'); cleared.push(id); t.clearTimer(id); };   // strict-mode function: plain call => this undefined
    L.armUserCamera(host, cy); L.fitHost(host); L.observeResize(host, { ResizeObserverImpl: FakeRO, setTimer: t.setTimer, clearTimer: browserClear }); return { host, cy, t, ro: FakeRO.all[0], cleared }; })();
  E.host.clientWidth = 300; E.ro.fire(300, 400); assert.equal(E.t.pending.size, 1, 'a debounce is pending at disposal (as when a resize is immediately followed by End session)');
  assert.doesNotThrow(() => L.disposeGraph(E.host)); assert.equal(E.t.pending.size, 0); assert.equal(E.cleared.length, 1);
  const E2 = (() => { FakeRO.all.length = 0; const host = mkHost(); const cy = new FakeCy(); cy.host = host; host._cy = cy; const t = timers(); L.fitHost(host);
    L.observeResize(host, { ResizeObserverImpl: FakeRO, setTimer: t.setTimer, clearTimer: function (id) { if (this !== undefined && this !== globalThis) throw new TypeError('Illegal invocation'); t.clearTimer(id); } }); return { host, t, ro: FakeRO.all[0] }; })();
  E2.host.clientWidth = 300; E2.ro.fire(300, 400); E2.host.clientWidth = 250; E2.ro.fire(250, 400);   // a second size change replaces the pending timer: the rescheduling path also calls it unbound
  assert.equal(E2.t.pending.size, 1);
});
