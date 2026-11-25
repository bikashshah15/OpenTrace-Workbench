// UIP-08/UIP-10 BOM request flow, factored out of app.js so the real sequencing can be exercised with a fake `api` (no DOM, no network).
// Every request is bound to the current epoch, generation and exact UI key (bomKey); the reducer rejects stale responses.
// UIP-10-F1: the Full evidence graph is requested only after the ACCEPTED queue says a comparison is bound. The view switch clears the queue
// (bomContextPatch), so the decision cannot be made at click time; it is made when the queue answer for the exact current view is accepted.
import { bomKey, bomContextPatch, bomAccepted, bomRelatedPatch } from './store.js';

export function createBomFlow({ store, api, qs }) {
  const bomPatch = (patch) => store.dispatch({ type: 'BOM_PATCH', patch });

  async function bomRequest(kind, params) {
    const s = store.get(), e = s.epoch, generation = s.analysis?.generation;
    if (!generation || s.bom8.stale) return;
    const seq = s.bom8.seq[kind] + 1, key = bomKey(s.bom8, kind);
    const stamp = { kind, epoch: e, generation, seq, key };
    store.dispatch({ type: 'BOM_REQUEST', ...stamp });
    const path = { queue: 'bom-candidates', graph: 'bom-graph', related: 'bom-related-checks' }[kind];
    try {
      // UIP-12-IR-04: the evidence detail reuses the existing candidate-detail route (same payload the legacy inspector renders)
      const data = await api(kind === 'detail' ? `/api/view/gap?${qs({ id: params.id, generation })}` : `/api/workbench/v1/${path}?${qs({ generation, ...params })}`);
      store.dispatch({ type: 'BOM_LOADED', ...stamp, data });
      // UIP08-IR-03: follow-up work only for a response the reducer accepted; a discarded response triggers nothing.
      if (kind === 'related' && bomAccepted(store.get(), 'related', data) && data.resolution === 'multiple') bomPatch({ popup: 'chooser' });
      if (kind === 'queue' && bomAccepted(store.get(), 'queue', data)) {
        const b = store.get().bom8;
        if (b.view !== 'full') { if (!(b.graph?.scope.kind === 'focused_candidate' && b.graph.scope.candidate_id === b.selected)) loadBomGraph(); }
        else if (data.mode === 'discovery_compared' && !b.graph && !b.req.graph) loadBomGraph();   // F1: the Full graph follows an accepted compared queue
        if (data.mode === 'discovery_compared') loadBomDetail();                                   // the selected (possibly just auto-selected) candidate's evidence
      }
    } catch (err) {
      store.dispatch({ type: 'BOM_FAILED', ...stamp, status: err.status, error: err.status === 404 ? 'The versioned BOM endpoint is unavailable in this build.' : err.message });
    }
  }
  function loadBomQueue() {
    const b = store.get().bom8;
    const family = { software: 'software', crypto: 'cryptography', ai: 'ai_model' }[b.view];
    return bomRequest('queue', { family, filter_group: b.filter === 'all' ? null : b.filter, query: b.q, offset: b.offset, size: 25 });
  }
  function loadBomGraph() {
    const b = store.get().bom8;
    if (b.queue && b.queue.mode !== 'discovery_compared') return;   // no bound comparison, so there is no graph to request; the queue already states why
    if (b.view === 'full') return bomRequest('graph', { scope_kind: 'full_view', group: b.group, query: b.fullQ || '', offset: b.fullOffset });
    if (b.selected) return bomRequest('graph', { scope_kind: 'focused_candidate', candidate_id: b.selected });
  }
  // Requests the evidence detail of the CURRENT selection unless it is loaded or already in flight for exactly this selection (no duplicate, no other candidate's).
  function loadBomDetail() {
    const b = store.get().bom8;
    if (!b.selected || b.stale) return;
    if (b.detail?.candidate?.candidate_id === b.selected || b.req.detail?.key === bomKey(b, 'detail')) return;
    return bomRequest('detail', { id: b.selected });
  }
  // The actual candidate selection (queue row click): clear everything that belongs to the previous candidate, then request this one's graph and evidence.
  function selectBomCandidate(id) {
    bomPatch({ selected: id, selectedRecord: null, related: null, graph: null, detail: null, detailError: null, drawer: true });
    loadBomGraph();
    return loadBomDetail();
  }
  // Choosing a related check from the chooser: exactly that ID, its queue/graph/evidence are requested for the new selection.
  function chooseBomRelated(id) {
    bomPatch(bomRelatedPatch(store.get().bom8, id));
    loadBomQueue(); loadBomGraph();
    return loadBomDetail();
  }
  function switchBomView(view) {
    bomPatch(bomContextPatch({ view, offset: 0 }));
    return loadBomQueue();     // the Full graph (if any) is requested by the queue's accepted answer, not here
  }
  return { bomRequest, loadBomQueue, loadBomGraph, loadBomDetail, selectBomCandidate, chooseBomRelated, switchBomView };
}
