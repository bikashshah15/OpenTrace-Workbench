// Deterministic regression for the Dependencies context-switch race (PR #23 independent review).
// The reducer is pure, so out-of-order delivery is reproduced exactly, with no timers or network.
// Run: node --test tests/ui/unit/        (Node >= 22)
import test from 'node:test';
import assert from 'node:assert/strict';
import { createStore, initial } from '../../../src/ui/lib/store.js';

const A = 'web/package-lock.json';
const B = 'docker/main/requirements-wheels.txt';
const C = 'docs/package-lock.json';

function open() {
  const store = createStore(initial());
  store.dispatch({ type: 'ANALYSIS_START' });
  const epoch = store.get().epoch;
  store.dispatch({ type: 'ANALYSIS_READY', epoch, analysis: { generation: 1, identity: {}, summary: {} } });
  return { store, epoch };
}
const ctx = (store, context) => store.dispatch({ type: 'TAB_STATE', tab: 'dependencies', patch: { context } });
const view = (context, marker) => ({ context_path: context, generation: 1, marker, focus: { id: 'focus-' + marker } });
const net = (context, marker) => ({ context_path: context, generation: 1, marker, nodes: [], edges: [] });
const loadView = (store, epoch, context, marker, seq, generation = 1) =>
  store.dispatch({ type: 'VIEW_LOADED', tab: 'dependencies', epoch, generation, seq, data: view(context, marker) });
const loadNet = (store, epoch, context, marker, seq, generation = 1) =>
  store.dispatch({ type: 'NETWORK_LOADED', epoch, generation, seq, network: net(context, marker) });
const request = (store, kind, seq) => store.dispatch({ type: 'REQUEST', kind, seq });

test('REVIEW SEQUENCE: A→B, B network arrives, delayed A network must not overwrite it', () => {
  const { store, epoch } = open();
  ctx(store, A); request(store, 'network', 1);          // network request for A is in flight
  ctx(store, B); request(store, 'network', 2);          // user switches to B; B's request starts
  loadNet(store, epoch, B, 'B', 2);                     // B's response arrives first
  assert.equal(store.get().network.context_path, B);
  loadNet(store, epoch, A, 'A-late', 1);                // A's delayed response arrives second
  assert.equal(store.get().network.context_path, B, 'the stale A network must be discarded');
  assert.equal(store.get().network.marker, 'B');
});

test('A→B and A answers before B: A is dropped on arrival because the selection moved on', () => {
  const { store, epoch } = open();
  ctx(store, A); request(store, 'network', 1);
  ctx(store, B);                                        // B's network not requested yet (its view is pending)
  loadNet(store, epoch, A, 'A', 1);                     // newest request id, but no longer the selected context
  assert.equal(store.get().network, null, 'a response for a context that is no longer selected never lands');
  request(store, 'network', 2); loadNet(store, epoch, B, 'B', 2);
  assert.equal(store.get().network.marker, 'B');
});

test('dependency view: delayed A response cannot overwrite B', () => {
  const { store, epoch } = open();
  ctx(store, A); request(store, 'deps', 1);
  ctx(store, B); request(store, 'deps', 2);
  loadView(store, epoch, B, 'B', 2);
  loadView(store, epoch, A, 'A-late', 1);
  assert.equal(store.get().views.dependencies.marker, 'B');
  assert.equal(store.get().views.dependencies.context_path, B);
});

test('dependency view: an older request in the SAME context cannot overwrite a newer one', () => {
  const { store, epoch } = open();
  ctx(store, A);
  request(store, 'deps', 1);   // e.g. page offset 0
  request(store, 'deps', 2);   // e.g. page offset 6 (newer)
  loadView(store, epoch, A, 'newer', 2);
  loadView(store, epoch, A, 'older', 1);
  assert.equal(store.get().views.dependencies.marker, 'newer');
});

test('network: an older request in the same context cannot overwrite a newer one', () => {
  const { store, epoch } = open();
  ctx(store, A); request(store, 'network', 1); request(store, 'network', 2);
  loadNet(store, epoch, A, 'newer', 2); loadNet(store, epoch, A, 'older', 1);
  assert.equal(store.get().network.marker, 'newer');
});

test('context guard holds even when the stale response is the newest request id', () => {
  const { store, epoch } = open();
  ctx(store, A); request(store, 'deps', 1); request(store, 'network', 1);
  ctx(store, B);                                        // selection changed without a newer request yet
  loadView(store, epoch, A, 'A', 1); loadNet(store, epoch, A, 'A', 1);
  assert.equal(store.get().views.dependencies, undefined);
  assert.equal(store.get().network, null);
});

test('three-way interleaving A→C→B delivered B, A, C keeps only B', () => {
  const { store, epoch } = open();
  ctx(store, A); request(store, 'deps', 1); request(store, 'network', 1);
  ctx(store, C); request(store, 'deps', 2); request(store, 'network', 2);
  ctx(store, B); request(store, 'deps', 3); request(store, 'network', 3);
  loadView(store, epoch, B, 'B', 3); loadNet(store, epoch, B, 'B', 3);
  loadView(store, epoch, A, 'A', 1); loadNet(store, epoch, A, 'A', 1);
  loadView(store, epoch, C, 'C', 2); loadNet(store, epoch, C, 'C', 2);
  assert.equal(store.get().views.dependencies.marker, 'B');
  assert.equal(store.get().network.marker, 'B');
});

test('in-order delivery is still accepted (the guard is not over-restrictive)', () => {
  const { store, epoch } = open();
  ctx(store, A); request(store, 'deps', 1); request(store, 'network', 1);
  loadView(store, epoch, A, 'A', 1); loadNet(store, epoch, A, 'A', 1);
  assert.equal(store.get().views.dependencies.marker, 'A');
  assert.equal(store.get().network.marker, 'A');
  ctx(store, B); request(store, 'deps', 2); request(store, 'network', 2);
  loadView(store, epoch, B, 'B', 2); loadNet(store, epoch, B, 'B', 2);
  assert.equal(store.get().views.dependencies.marker, 'B');
  assert.equal(store.get().network.marker, 'B');
});

test('search results for another context are discarded', () => {
  const { store, epoch } = open();
  ctx(store, A); request(store, 'search', 1);
  ctx(store, B); request(store, 'search', 2);
  store.dispatch({ type: 'SEARCH_LOADED', epoch, seq: 2, context: B, search: { query: 'x', items: ['B'] } });
  store.dispatch({ type: 'SEARCH_LOADED', epoch, seq: 1, context: A, search: { query: 'x', items: ['A'] } });
  assert.deepEqual(store.get().search.items, ['B']);
});

test('existing guards are preserved: stale epoch, wrong generation, End session', () => {
  const { store, epoch } = open();
  ctx(store, A); request(store, 'deps', 1); request(store, 'network', 1);
  loadView(store, epoch - 1, A, 'old-epoch', 1); loadNet(store, epoch - 1, A, 'old-epoch', 1);
  assert.equal(store.get().views.dependencies, undefined); assert.equal(store.get().network, null);
  loadView(store, epoch, A, 'wrong-generation', 1, 2); loadNet(store, epoch, A, 'wrong-generation', 1, 2);
  assert.equal(store.get().views.dependencies, undefined); assert.equal(store.get().network, null);
  loadView(store, epoch, A, 'ok', 1); loadNet(store, epoch, A, 'ok', 1);
  assert.equal(store.get().network.marker, 'ok');
  store.dispatch({ type: 'END_STARTED' });
  store.dispatch({ type: 'ENDED', state: 'deleted_verified' });
  loadView(store, epoch, A, 'late-after-end', 1); loadNet(store, epoch, A, 'late-after-end', 1);
  const s = store.get();
  assert.equal(s.analysis, null); assert.equal(s.network, null); assert.deepEqual(s.views, {});
});

test('a new analysis resets the request ledger and discards the previous analysis responses', () => {
  const { store, epoch } = open();
  ctx(store, A); request(store, 'network', 5);
  store.dispatch({ type: 'ANALYSIS_START' });
  const next = store.get().epoch;
  assert.deepEqual(store.get().latest, { deps: 0, network: 0, search: 0 });
  store.dispatch({ type: 'ANALYSIS_READY', epoch: next, analysis: { generation: 2, identity: {}, summary: {} } });
  loadNet(store, epoch, A, 'previous-analysis', 5);
  assert.equal(store.get().network, null);
});
