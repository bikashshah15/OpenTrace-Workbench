// UIP-10 F1 request sequencing: the REAL request flow (src/ui/lib/bom_flow.js) with the real store and a fake `api` that records every HTTP request path
// and lets each response be released in any order. These assert what was SENT, which renderer/store-only tests cannot.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createStore, initial, bomContextPatch } from '../../../src/ui/lib/store.js';
import { createBomFlow } from '../../../src/ui/lib/bom_flow.js';

const qs = (o) => Object.entries(o).filter(([, v]) => v !== null && v !== undefined && v !== '').map(([k, v]) => `${k}=${encodeURIComponent(v)}`).join('&');
const identity = { analysis_digest: 'a'.repeat(64), owner: 'review', name: 'fixture', commit: 'b'.repeat(40) };
const comparedQ = { binding: { analysis_digest: identity.analysis_digest }, mode: 'discovery_compared', counts: { candidates_total: 0, filtered_total: 0, records_total: 5 }, items: [], page: { offset: 0, size: 25, has_more: false }, capabilities: [{ family: 'software', state: 'completed', reason_code: null }] };
const notComparedQ = { binding: { analysis_digest: identity.analysis_digest }, mode: 'not_compared', status_detail: { code: 'x', message: 'REASON' }, counts: { candidates_total: 0, filtered_total: 0, records_total: 0 }, items: [], page: { offset: 0, size: 25, has_more: false }, capabilities: [{ family: 'software', state: 'unsupported', reason_code: 'unsupported_ecosystem' }] };
const graphData = { binding: { analysis_digest: identity.analysis_digest }, scope: { kind: 'full_view', group: 'all', query: '' }, nodes: [], edges: [], records: [], counts: { nodes_shown: 0, nodes_in_scope: 0, edges_shown: 0, edges_in_scope: 0 }, truncated: false };

function rig() {
  const store = createStore({ ...initial(), epoch: 3, analysis: { generation: 7, identity }, workbench: { ...initial().workbench, tab: 'bom' } });
  const sent = [];
  const api = (path) => new Promise((resolve, reject) => { sent.push({ path, kind: path.includes('/bom-graph') ? 'graph' : path.includes('/bom-candidates') ? 'queue' : 'other', resolve, reject }); });
  const flow = createBomFlow({ store, api, qs });
  const count = (kind) => sent.filter((r) => r.kind === kind).length;
  const tick = () => new Promise((r) => setImmediate(r));
  const err = (status, message) => Object.assign(new Error(message), { status });
  return { store, sent, flow, count, tick, err };
}

test('cause replay: the OLD call order (clear queue, request queue, request graph at click time) does send a graph request for a not-compared analysis', async () => {
  const { store, flow, count } = rig();
  store.dispatch({ type: 'BOM_PATCH', patch: bomContextPatch({ view: 'full', offset: 0 }) });
  flow.loadBomQueue(); flow.loadBomGraph();
  assert.equal(count('graph'), 1, 'queue is null at click time, so the guard cannot know');
});
test('F1: not-compared analysis - entering Full view sends the queue request only, never a graph request', async () => {
  const { store, sent, flow, count, tick } = rig();
  flow.switchBomView('full');
  assert.deepEqual(sent.map((r) => r.kind), ['queue']);
  sent[0].resolve(notComparedQ); await tick();
  assert.equal(count('graph'), 0); assert.equal(store.get().bom8.error, null); assert.equal(store.get().bom8.queue.mode, 'not_compared');
  flow.switchBomView('gaps'); sent[1].resolve(notComparedQ); await tick(); flow.switchBomView('full'); sent[2].resolve(notComparedQ); await tick();
  assert.equal(count('graph'), 0, 'repeated entries stay request-free');
});
test('F1: compared analysis - the Full graph is requested once, after the accepted queue, and loads', async () => {
  const { store, sent, flow, count, tick } = rig();
  flow.switchBomView('full');
  assert.equal(count('graph'), 0, 'not before the queue answer');
  sent[0].resolve(comparedQ); await tick();
  assert.equal(count('graph'), 1);
  assert.match(sent[1].path, /scope_kind=full_view/); assert.match(sent[1].path, /generation=7/);
  sent[1].resolve(graphData); await tick();
  assert.equal(store.get().bom8.graph.scope.kind, 'full_view'); assert.equal(store.get().bom8.error, null); assert.equal(count('graph'), 1);
});
test('F1: out of order - a stale queue answer (view switched away, or an older request) never triggers a graph request', async () => {
  const { store, sent, flow, count, tick } = rig();
  flow.switchBomView('full');           // req0 (stale after the next switch)
  flow.switchBomView('gaps');           // req1
  flow.switchBomView('full');           // req2 (current)
  sent[0].resolve(comparedQ); await tick(); assert.equal(count('graph'), 0, 'req0 is stale');
  sent[1].resolve(comparedQ); await tick(); assert.equal(count('graph'), 0, 'req1 belongs to another view');
  sent[2].resolve(notComparedQ); await tick(); assert.equal(count('graph'), 0, 'current answer is not-compared');
  assert.equal(store.get().bom8.queue.mode, 'not_compared');
});
test('F1: out of order - the current compared answer still requests exactly one graph even if older answers arrive late', async () => {
  const { store, sent, flow, count, tick } = rig();
  flow.switchBomView('full'); flow.switchBomView('software'); flow.switchBomView('full');
  sent[2].resolve(comparedQ); await tick(); assert.equal(count('graph'), 1);
  sent[0].resolve(notComparedQ); sent[1].resolve(notComparedQ); await tick();
  assert.equal(count('graph'), 1); assert.equal(store.get().bom8.queue.mode, 'discovery_compared');
  sent[3].resolve(graphData); await tick(); assert.equal(store.get().bom8.graph.scope.kind, 'full_view');
});
test('F1: genuine failures stay visible and trigger no graph request (queue 500, queue network failure, graph 404 on a compared analysis, graph 500, ended session)', async () => {
  for (const [label, run] of [
    ['queue 500', async (r) => { r.flow.switchBomView('full'); r.sent[0].reject(r.err(500, 'Server error')); await r.tick(); assert.match(r.store.get().bom8.error, /Server error/); assert.equal(r.count('graph'), 0); }],
    ['queue network', async (r) => { r.flow.switchBomView('full'); r.sent[0].reject(new Error('Failed to fetch')); await r.tick(); assert.match(r.store.get().bom8.error, /Failed to fetch/); assert.equal(r.count('graph'), 0); }],
    ['graph 404 (compared)', async (r) => { r.flow.switchBomView('full'); r.sent[0].resolve(comparedQ); await r.tick(); r.sent[1].reject(r.err(404, 'nf')); await r.tick(); assert.match(r.store.get().bom8.error, /endpoint is unavailable/); }],
    ['graph 500 (compared)', async (r) => { r.flow.switchBomView('full'); r.sent[0].resolve(comparedQ); await r.tick(); r.sent[1].reject(r.err(500, 'Graph exploded')); await r.tick(); assert.match(r.store.get().bom8.error, /Graph exploded/); }],
    ['ended session', async (r) => { r.flow.switchBomView('full'); r.sent[0].reject(r.err(409, 'stale')); await r.tick(); assert.match(r.store.get().bom8.error, /ended session/); assert.equal(r.store.get().bom8.stale, true); assert.equal(r.count('graph'), 0); }],
  ]) await run(rig()).catch((e) => { e.message = `${label}: ${e.message}`; throw e; });
});
test('F1: transitions compared -> not-compared -> compared keep no stale error and request the graph again only when compared', async () => {
  const { store, sent, flow, count, tick } = rig();
  flow.switchBomView('full'); sent[0].resolve(comparedQ); await tick(); sent[1].resolve(graphData); await tick();
  flow.switchBomView('software'); sent[2].resolve(comparedQ); await tick();
  flow.switchBomView('full'); sent[3].resolve(notComparedQ); await tick();
  assert.equal(count('graph'), 1); assert.equal(store.get().bom8.error, null); assert.equal(store.get().bom8.graph, null);
  flow.switchBomView('full'); sent[4].resolve(comparedQ); await tick(); assert.equal(count('graph'), 2);
  sent[5].resolve(graphData); await tick(); assert.equal(store.get().bom8.error, null); assert.equal(store.get().bom8.graph.scope.kind, 'full_view');
});
test('F1: a late graph 404 after the queue turned not-compared is not shown as an error (reducer guard still holds)', async () => {
  const { store, sent, flow, count, tick, err } = rig();
  flow.switchBomView('full'); sent[0].resolve(comparedQ); await tick();                 // graph request in flight
  flow.switchBomView('full'); await tick();                                             // re-enter: a new queue request
  const q2 = sent.filter((r) => r.kind === 'queue')[1]; q2.resolve(notComparedQ); await tick();
  sent.filter((r) => r.kind === 'graph')[0].reject(err(404, 'nf')); await tick();
  assert.equal(store.get().bom8.error, null); assert.equal(store.get().bom8.queue.mode, 'not_compared');
});
