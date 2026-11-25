import { $, esc, fmt, isNarrow, NARROW } from './lib/util.js';
import { createStore, initial, freshDense, TABS, TAB_LABEL, ctxCurrent, bomKey, bomContextPatch, bomSelectedItem, bomAssistantContext, bomAccepted, assistantCanSubmit } from './lib/store.js';
import { api, ApiError, qs } from './lib/api.js';
import { createBomFlow } from './lib/bom_flow.js';
import { ABOUT, INFO, liveBarText } from './lib/copy.js';
import { syncGraph, fit as gfit, warm } from './lib/graphs.js';
import { keepersOf, restoreKeepers, disposeGraphsIn } from './lib/graph_lifecycle.js';   // UIP-13-GRAPH-LIFECYCLE
import { renderAnalyze } from './components/intake.js';
import { attachEvidenceStrip } from './components/evidence_strip.js';
import { renderWorkbench, stateLabel, denseVisible, activeNetwork } from './components/workbench.js';
import { syncDense, fitAll, fitSelection, resetView, zoomBy, pathSet, children, allIds, initialVisible, BATCH, PATH_CAP } from './lib/dense.js';
import { renderEvidence } from './components/evidence.js';
import { evidenceHtml } from './components/lookup.js';
import { renderAssistant } from './components/assistant.js';
import { isTerminal, POLL_RETRY_DELAYS, SCAN_SCHEMA, scanGate } from './lib/scan_model.js';
import { refusalText, renderScanDialogBody, scanDialogModel, focusRestoreNeeded } from './components/scan_status.js';
import { attachContextMap, applyContextMapView, evidenceHtml as contextEvidenceHtml, pageSizeFor, groupSummary } from './components/context_map.js';
import { RETRY_LADDER, ladderFrom, loadedCount, hiddenCount, findSelection } from './lib/context_map.js';
import { attachDependencyGraph, applyDependencyView, remeasure, syncExpandedShell } from './components/dependency_graph.js';
import { attachCryptoGraph, applyCryptoView, revealSelection, syncCryptoExpandedShell } from './components/crypto_graph.js';
import { formatArtifact, searchArtifact } from './lib/preview.js';
import { attachAiGraph, applyAiView, revealAiSelection, syncAiExpandedShell } from './components/ai_graph.js';
import { payloadFilter as cryptoFilterOf, requestKey as cryptoReqKey, pageNeeded as cryptoPageNeeded, PAGE_SIZE as CRYPTO_PAGE, assetKey as cryptoAssetKey, findAsset as cryptoFindAsset, findGroup as cryptoFindGroup, reviewsOf as cryptoReviewsOf, resolveSelection as cryptoResolve, ROOT_KEY as CRYPTO_ROOT } from './lib/crypto_graph.js';
import { payloadFilter as aiFilterOf, requestKey as aiReqKey, pageNeeded as aiPageNeeded, findAsset as aiFindAsset, findGroup as aiFindGroup, reviewsOf as aiReviewsOf, resolveSelection as aiResolve } from './lib/ai_graph.js';
import { payloadFilter, requestKey, keyFilter, DEFAULT_FILTER, CHOOSER_PAGE, PAGE_SIZE, chooserKey, legacyKey, pageNeeded } from './lib/dependency_graph.js';

// Browser storage holds only these two presentation keys (REQ-10).
const store_ = { get(k) { try { return localStorage.getItem(k); } catch { return null; } }, set(k, v) { try { localStorage.setItem(k, v); } catch { /* ignore */ } } };
const store = createStore(initial({ advanced: store_.get('oecl.ui.advanced') === 'true', theme: store_.get('oecl.ui.theme') === 'dark' ? 'dark' : 'light', narrow: isNarrow() }));
window.__otStore = store; // read-only inspection aid for browser checks
const { bomRequest, loadBomQueue, loadBomGraph, selectBomCandidate, chooseBomRelated, switchBomView } = createBomFlow({ store, api, qs });   // lib/bom_flow.js (UIP-10-F1 sequencing)

// ------------------------------------------------------------------ rendering
function paint(el, html) {
  if (el._html === html) return;
  const active = document.activeElement; const fk = el.contains(active) ? active.dataset?.fk : null;
  const caret = fk && active.selectionStart != null ? [active.selectionStart, active.selectionEnd] : null;
  const keepers = keepersOf(el);   // UIP-13-GRAPH-LIFECYCLE
  const scrollers = new Map(); el.querySelectorAll('[data-scroll-key]').forEach((n) => scrollers.set(n.dataset.scrollKey, n.scrollTop));
  const scroll = el.scrollTop;
  el.innerHTML = html; el._html = html;
  restoreKeepers(el, keepers);   // UIP-13-GRAPH-LIFECYCLE: re-parent the kept hosts AND re-attach their Cytoscape instances (the renderer is destroyed by a re-parent otherwise); retire the rest
  el.scrollTop = scroll;
  el.querySelectorAll('[data-scroll-key]').forEach((n) => { n.scrollTop = scrollers.get(n.dataset.scrollKey) || 0; });
  if (fk) { const n = el.querySelector(`[data-fk="${fk}"]`); if (n) { n.focus({ preventScroll: true }); if (caret && n.setSelectionRange) try { n.setSelectionRange(...caret); } catch { /* ignore */ } } }
}

let depZoom = { s: 1, x: 0, y: 0, key: '' };
function applyZoom() {
  const svg = $('ot-dep-svg'); const vp = $('ot-dep-vp'); if (!svg || !vp) return;
  const s = store.get(); const d = s.views.dependencies; const key = d?.focus?.id + '|' + (d?.incoming?.offset) + '|' + (d?.outgoing?.offset) + '|' + s.narrow;
  if (depZoom.key !== key) depZoom = { s: 1, x: 0, y: 0, key };
  vp.setAttribute('transform', `translate(${depZoom.x} ${depZoom.y}) scale(${depZoom.s})`);
  const label = $('ot-zoom-label'); if (label) label.textContent = Math.round(depZoom.s * 100) + '%';
}

function render() {
  const s = store.get();
  const focused = document.activeElement;      // what holds focus before this repaint (see focusRestoreNeeded below)
  const focusOwner = !focused ? null : focused.id === 'ot-scan-chip' ? 'chip' : focused.closest?.('#ot-analyze') ? 'analyze' : null;
  document.documentElement.dataset.advanced = String(s.advanced);
  document.documentElement.dataset.theme = s.theme;
  const bar = $('ot-bar-text');
  if (bar) bar.textContent = s.analysis?.identity?.mode === 'live'
    ? liveBarText(s.analysis.summary)
    : s.live ? 'Captured Frigate demo available offline. ' + (s.live.policy?.effective === 'bounded' ? 'Live scanning is enabled for public GitHub repositories within the stated limits.' : 'Live scanning is enabled for allowlisted commits only.')
    : 'Captured Frigate inventories + OSV query snapshot 2026-11-04. Offline preview · live repository acquisition is not connected.';
  $('ot-advanced').checked = s.advanced;
  $('ot-theme').setAttribute('aria-label', s.theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme');
  const active = s.session.status === 'active' && (!!s.analysis || !!s.scan.job);   // UIP-03: End session stays reachable from the header while a scan runs
  $('ot-top-end').hidden = !active;
  document.querySelectorAll('[data-nav]').forEach((b) => {
    const to = b.dataset.nav; b.disabled = to !== 'analyze' && !s.analysis;
    b.classList.toggle('active', to === s.destination);
    if (to === s.destination) b.setAttribute('aria-current', 'page'); else b.removeAttribute('aria-current');
  });
  for (const p of ['analyze', 'workbench', 'evidence']) $('ot-' + p).hidden = p !== s.destination;
  if (s.destination === 'analyze') paint($('ot-analyze'), renderAnalyze(s));
  else if (s.destination === 'workbench') paint($('ot-workbench'), renderWorkbench(s));
  else paint($('ot-evidence'), renderEvidence(s));
  if (s.destination !== 'analyze') { $('ot-analyze')._html = ''; $('ot-analyze').innerHTML = ''; }   // a hidden homepage must not keep a stale scan control (it is repainted on return)
  if (s.destination !== 'workbench') { disposeGraphsIn($('ot-workbench')); $('ot-workbench')._html = ''; $('ot-workbench').innerHTML = ''; }   // UIP-13-GRAPH-LIFECYCLE: leaving the Workbench retires its graph instances
  if (s.destination !== 'evidence') { $('ot-evidence')._html = ''; $('ot-evidence').innerHTML = ''; }
  renderScanDialog(s);
  // The minimized control (or another homepage element) was removed by this repaint (hand-off, End session, 403) and focus fell to <body>: restore it. Never during ordinary polling.
  if (focusRestoreNeeded({ owner: focusOwner, connected: !!focused && focused.isConnected, activeIsBody: !document.activeElement || document.activeElement === document.body, destination: s.destination })) scanReturnFocus();
  renderAssistantPanel();
  if (s.destination === 'workbench') { syncGraphs(); applyZoom(); applyContextMapView(store.get); applyDependencyView(store.get); applyCryptoView(store.get); applyAiView(store.get); remeasure(store.get, render); }
  syncExpandedShell(); syncCryptoExpandedShell(); syncAiExpandedShell();
}
store.subscribe(render);

function syncGraphs() {
  const s = store.get();
  syncDenseHost(s);
  document.querySelectorAll('[data-cy]').forEach((host) => {
    const tab = host.dataset.cy; const v = s.views[tab]; if (!v) return;
    syncGraph(host, { nodes: v.nodes, edges: v.edges, selected: s.workbench.perTab[tab].selection, direction: tab === 'bom' ? 'RIGHT' : 'RIGHT',
      onSelect: (id) => store.dispatch({ type: 'TAB_STATE', tab, patch: { selection: id } }) }).catch((e) => console.error(e));
  });
  document.querySelectorAll('[data-bom-cy]').forEach((host) => {
    const g = s.bom8.graph; if (!g || (s.bom8.view === 'full' ? g.scope.kind !== 'full_view' : g.scope.candidate_id !== s.bom8.selected)) return;
    syncGraph(host, { nodes: g.nodes.map((n) => ({ id: n.node_id, type: n.kind, name: n.label, state: n.state })), edges: g.edges, selected: s.bom8.selectedRecord,
      onSelect: (id) => bomSelectRecord(id) }).catch((e) => console.error(e));
  });
}

function syncDenseHost(s) {
  const net = activeNetwork(s); const host = document.querySelector('[data-cy-dense]'); if (!host || !net) return;
  const dep = s.workbench.perTab.dependencies; const dn = dep.dense; const sel = dep.selection || dep.focus;
  syncDense(host, { net, visible: denseVisible(s), selected: sel, layout: dn.layout, arrange: dn.arrange,
    onSelect: (id) => denseSelect(id), onExpand: (id) => denseExpandAt(id),
    onBusy: (b) => { const el = $('ot-dense-busy'); if (el) el.hidden = !b; } }).catch((e) => console.error(e));
}

// ------------------------------------------------------------------ dialogs
let returnFocus = null;
function modal(title, html, wide = false) {
  returnFocus = document.activeElement;
  $('ot-dialog-title').textContent = title; $('ot-dialog-content').innerHTML = html;
  $('ot-dialog').classList.toggle('wide', wide);
  if (!$('ot-dialog').open) $('ot-dialog').showModal();
}
$('ot-dialog').addEventListener('close', () => { $('ot-dialog-content').innerHTML = ''; returnFocus?.focus?.(); });
const closeDialog = () => { if ($('ot-dialog').open) $('ot-dialog').close(); };

// ------------------------------------------------------------------ scan-progress modal
// A dedicated native <dialog> with stable DOM (separate from the evidence/info dialog above). Its body is repainted through paint(), which keeps
// focus, caret and scroll, so a polling update never moves focus. Visibility follows state.scanUi only; the dialog never starts, stops or polls anything.
function renderScanDialog(s) {
  const d = $('ot-scan-dialog'); if (!d) return;
  if (s.scanUi.open) {
    const m = scanDialogModel(s); const body = $('ot-scan-dialog-body');
    const hadFocus = d.open && body.contains(document.activeElement);
    paint(body, renderScanDialogBody(s));
    if (hadFocus && !d.contains(document.activeElement)) focusScanStatus();     // a control that vanished on repaint (Cancel, Check again) must not drop focus to <body>
    const min = $('ot-scan-minimize'); if (min.textContent !== m.primary) min.textContent = m.primary;
    $('ot-scan-dialog-end').disabled = m.endDisabled;
    if (!d.open) { d.showModal(); focusScanStatus(); }      // opening moves focus to the status region once; later repaints never do
  } else if (d.open) { d.close(); scanReturnFocus(); }     // every state-driven close (hand-off, End session, 403) restores focus synchronously, not only Escape/Minimize
}
// After the dialog hides: the compact control, else the Scan button, else the URL field (first one that is present and enabled); on the Workbench, the main region.
function scanReturnFocus() {
  const s = store.get();
  const to = s.destination === 'analyze' ? [$('ot-scan-chip'), $('ot-scan'), $('ot-url'), $('ot-main')].find((x) => x && !x.disabled) : $('ot-main');
  if (to) to.focus();
}
// Escape: state, not the browser, closes the dialog (a native close would leave state "open" until the later close event, and a render in that gap would reopen it).
// The dialog only hides: nothing is cancelled and polling is not touched.
$('ot-scan-dialog').addEventListener('cancel', (ev) => { ev.preventDefault(); store.dispatch({ type: 'SCAN_UI_CLOSE', epoch: epoch() }); scanReturnFocus(); });
// Backstop for any other close path.
$('ot-scan-dialog').addEventListener('close', () => {
  if ($('ot-scan-dialog').open) return;      // a stale close event after a quick reopen must not hide the reopened dialog
  if (!store.get().scanUi.open) return;      // state already closed it (Escape / Minimize restored focus synchronously): do not pull focus back later
  store.dispatch({ type: 'SCAN_UI_CLOSE' });
  scanReturnFocus();
});

// ------------------------------------------------------------------ effects
const epoch = () => store.get().epoch;
const gen = () => store.get().analysis?.generation;

let depsSeq = 0; let netSeq = 0; let searchSeq = 0;
let lookupSeq = 0;
async function loadLookup() {
  const s = store.get(); if (!s.analysis?.summary?.advisory_lookup) return;
  const seq = ++lookupSeq; const e = s.epoch; const g = gen(); const lk = s.advLookup;
  store.dispatch({ type: 'LOOKUP_STATE', patch: { seq } });
  try {
    const data = await api('/api/view/advisory-lookup?' + qs({ state: lk.state, q: lk.q, page: lk.page, generation: g }));
    store.dispatch({ type: 'LOOKUP_LOADED', epoch: e, generation: g, seq, data });
  } catch (err) { store.dispatch({ type: 'LOOKUP_FAILED', epoch: e, seq, message: err?.code || 'request failed' }); }
}
let gapsSeq = 0; let gapDetailSeq = 0;
async function loadGaps() {
  const s = store.get(); if (!s.analysis?.summary?.gaps || s.analysis.summary.gaps.status !== 'compared') return;
  const seq = ++gapsSeq; const e = s.epoch; const g = gen(); const gp = s.gaps;
  store.dispatch({ type: 'GAPS_STATE', patch: { seq } });
  try {
    const data = await api('/api/view/gaps?' + qs({ offset: gp.offset, state: gp.state, q: gp.q, generation: g }));
    store.dispatch({ type: 'GAPS_LOADED', epoch: e, generation: g, seq, data });
  } catch (err) { store.dispatch({ type: 'GAPS_FAILED', epoch: e, seq, message: err?.code || 'request failed' }); }
}
async function inspectGap(id) {
  const s = store.get(); const e = s.epoch; const g = gen(); const seq = ++gapDetailSeq;
  store.dispatch({ type: 'GAPS_STATE', patch: { selected: id, detail: null, detailError: null, detailSeq: seq } });
  store.dispatch({ type: 'TAB_STATE', tab: 'bom', patch: { selection: null } });
  try {
    const data = await api('/api/view/gap?' + qs({ id, generation: g }));
    store.dispatch({ type: 'GAP_DETAIL_LOADED', epoch: e, generation: g, seq, data });
  } catch (err) { store.dispatch({ type: 'GAP_DETAIL_FAILED', epoch: e, seq, message: err?.code || 'request failed' }); }
  $('ot-graph-frame')?.scrollIntoView({ block: 'start' });
}
async function openLookupEvidence(id) {
  const e = epoch();
  modal('Advisory lookup evidence', '<p class="ot-help" role="status">Loading\u2026</p>', true);
  try {
    const ev = await api('/api/view/advisory-evidence?' + qs({ id, generation: gen() })); if (e !== epoch()) return;
    modal('Advisory lookup evidence', evidenceHtml(ev), true);
  } catch (err) { if (e === epoch()) modal('Advisory lookup evidence', `<p class="ot-prompt" role="alert">The evidence could not be loaded (${esc(err?.code || 'request failed')}).</p>`, true); }
}
async function loadDeps() {
  const s = store.get(); if (!s.analysis) return;
  const d = s.workbench.perTab.dependencies; const e = s.epoch; const g = gen();
  if (d.stale) return;                                                        // UIP-05 IR-03: the dependency state was retired; only the recovery action remains
  const normal = !s.advanced;       // UIP-05 (FD-6): the normal view takes its focus and context from dependency_page/1, never from the legacy default focus
  if (normal && (!d.focus || !d.context)) return;
  const seq = ++depsSeq; const key = legacyKey(d); store.dispatch({ type: 'REQUEST', kind: 'deps', seq });
  const params = { context: d.context, selected: d.focus, inspect: d.selection, per_side: normal || s.narrow ? 1 : 6, in_offset: d.offsets[0], out_offset: d.offsets[1], adv_q: d.advQuery, adv_page: d.advPage, generation: g };
  if (d.presentation === 'list') Object.assign(params, { list: 1, list_q: d.listQuery, list_offset: d.listOffset });
  try {
    const data = await api('/api/view/dependencies?' + qs(params));
    store.dispatch({ type: 'VIEW_LOADED', tab: 'dependencies', data, epoch: e, generation: data.generation, seq, key });   // key: IR-02, dropped when focus/selection/query/offset moved on
    if (store.get().views.dependencies !== data) return; // superseded or for another context: it changes nothing, not even focus
    const cur = store.get().workbench.perTab.dependencies;
    if (e === store.get().epoch) loadNetworkIfNeeded();
    if (e === store.get().epoch && !normal && !cur.focus && data.focus) store.dispatch({ type: 'TAB_STATE', tab: 'dependencies', patch: { focus: data.focus.id, selection: cur.selection || data.focus.id } });
    else if (e === store.get().epoch && cur.focus && !cur.selection) store.dispatch({ type: 'TAB_STATE', tab: 'dependencies', patch: { selection: cur.focus } });
  } catch (err) {
    const cur = store.get().workbench.perTab.dependencies;
    if (e !== epoch() || cur.stale || seq !== depsSeq || key !== legacyKey(cur)) return;   // IR-03: a retired or superseded legacy request acts on nothing
    handleError(err, e);
  }
}
// ------------------------------------------------------------------ UIP-05: Dependencies page and context chooser
// GET /api/workbench/v1/dependencies and /dependency-contexts. Every request is stamped {epoch, generation, seq, key[, intent]}; the reducer
// applies a success, an error or a 409 only while that identity is still current AND still describes the state (query/context/focus/offset,
// and for a Graph request still the Graph view), so a superseded response never changes state or triggers a side effect - including during
// a debounce window before the successor is issued. A typed failure is shown with a manual "Try again"; nothing retries by itself. A current
// 409 retires the dependency payloads and shows the "session moved on" recovery (IR-03); the newer generation is never adopted.
let depPageSeq = 0; let depCtxSeq = 0; let searchTimer = 0; let ctxTimer = 0;
const depError = (err) => ({ code: err?.code || 'request_failed', detail: err?.body?.detail_code || null });
async function loadDepPage() {
  const s = store.get(); const d = s.workbench.perTab.dependencies;
  if (!s.analysis || s.busy === 'ending' || !d.ctxId || d.stale) return;
  const e = s.epoch; const g = gen(); const seq = ++depPageSeq;
  const stamp = { epoch: e, generation: g, seq, key: requestKey(d), intent: d.presentation === 'graph' ? 'active' : 'preload' };
  store.dispatch({ type: 'DEPPAGE_REQUEST', ...stamp });
  try {
    const data = await api('/api/workbench/v1/dependencies?' + qs({ generation: g, context_id: d.ctxId, focus_id: d.focus, filter: payloadFilter(d.filter), query: d.q, offset: d.gOffset, size: PAGE_SIZE }));
    store.dispatch({ type: 'DEPPAGE_LOADED', ...stamp, data });
    if (store.get().views.depPage !== data) return;                         // not applied (superseded): no side effect
    const cur = store.get(); const dep = cur.workbench.perTab.dependencies; const v = cur.views.dependencies;
    if (!cur.advanced && dep.focus && (!v || (v.context_path || null) !== (dep.context || null) || v.focus?.id !== dep.focus)) loadDeps();
  } catch (err) {
    if (e !== epoch()) return;                                              // a late error after replacement or End session changes nothing
    if (err instanceof ApiError && err.status === 403) { handleError(err, e); return; }
    store.dispatch({ type: 'DEPPAGE_FAILED', ...stamp, status: err?.status, error: depError(err) });
  }
}
async function loadDepContexts() {
  const s = store.get(); const d = s.workbench.perTab.dependencies;
  if (!s.analysis || s.busy === 'ending' || d.stale) return;
  const e = s.epoch; const g = gen(); const seq = ++depCtxSeq;
  const stamp = { epoch: e, generation: g, seq, key: chooserKey(d) };
  store.dispatch({ type: 'DEPCTX_REQUEST', ...stamp });
  try {
    const data = await api('/api/workbench/v1/dependency-contexts?' + qs({ generation: g, limit: CHOOSER_PAGE, offset: d.cx.offset, query: d.cx.query }));
    store.dispatch({ type: 'DEPCTX_LOADED', ...stamp, data });
    if (store.get().views.depContexts !== data) return;                     // not applied (superseded): no side effect
    const dep = store.get().workbench.perTab.dependencies;
    if (dep.ctxId && !store.get().views.depPage && dep.pg.status !== 'loading') loadDepPage();   // deliberate preload of the default page
  } catch (err) {
    if (e !== epoch()) return;
    if (err instanceof ApiError && err.status === 403) { handleError(err, e); return; }
    store.dispatch({ type: 'DEPCTX_FAILED', ...stamp, status: err?.status, error: depError(err) });
  }
}
function ensureDepPage() {
  const s = store.get(); if (!s.analysis || s.advanced || s.busy === 'ending') return;
  const d = s.workbench.perTab.dependencies; if (d.stale) return;
  if (!s.views.depContexts && d.cx.status === 'idle') loadDepContexts();
  else if (pageNeeded(s.views.depPage, d)) loadDepPage();                   // IR-01: a cached page that describes a different query/context/focus/offset is reloaded
}
// Graph/List: the shared q is the single source; leaving a view cancels the debounce typed in it, and the view being entered loads what its state needs.
function depPresent(p) {
  clearTimeout(searchTimer);
  dispatch({ type: 'TAB_STATE', tab: 'dependencies', patch: { presentation: p } });
  if (p === 'list') loadDeps(); else ensureDepPage();
}
function depSearchInput(value) {
  dispatch({ type: 'TAB_STATE', tab: 'dependencies', patch: { q: value, listQuery: value, gOffset: 0, listOffset: 0 } });
  clearTimeout(searchTimer);
  searchTimer = setTimeout(() => (depNow().presentation === 'list' ? loadDeps() : loadDepPage()), 200);   // decided when the timer fires, not when the key was typed
}
function depStaleReset() { dispatchEnded('gone'); closeDialog(); }          // IR-03 recovery: the old analysis is closed locally; the person reopens it
const depNode = (id) => { dispatch({ type: 'DEP_EXPLORE', id }); dispatch({ type: 'TAB_STATE', tab: 'dependencies', patch: { presentation: 'graph' } }); loadDepPage(); loadDeps(); };
let networkLoading = null;
function loadNetworkIfNeeded() {
  const s = store.get(); const ctx = s.workbench.perTab.dependencies.context || null;
  if (!s.analysis || (s.network && s.network.context_path === ctx) || networkLoading === ctx + '#' + s.epoch) return;
  networkLoading = ctx + '#' + s.epoch; const e = s.epoch;
  const seq = ++netSeq; store.dispatch({ type: 'REQUEST', kind: 'network', seq });
  api('/api/view/dependencies/network?' + qs({ context: ctx, generation: gen() }))
    .then((data) => { if (networkLoading === ctx + '#' + e) networkLoading = null; store.dispatch({ type: 'NETWORK_LOADED', epoch: e, generation: data.generation, network: data, seq }); })
    .catch((err) => { networkLoading = null; handleError(err, e); });
}
// ------------------------------------------------------------------ UIP-06: Cryptography page
// GET /api/workbench/v1/crypto-assets. Stamped {epoch, generation, seq, key}; a success, an error or a 409 acts only while that identity is
// still current and still describes (filter, query, group, offset). A typed failure shows a manual "Try again"; nothing retries by itself. A
// current 409 retires the payload and shows the "session moved on" recovery; the newer generation is never adopted.
let cryptoSeq = 0; let cryptoTimer = 0;
const cryptoError = (err) => ({ code: err?.code || 'request_failed', detail: err?.body?.detail_code || null });
async function loadCryptoPage() {
  const s = store.get(); const c = s.workbench.perTab.crypto;
  if (!s.analysis || s.busy === 'ending' || c.stale) return;
  const e = s.epoch; const g = gen(); const seq = ++cryptoSeq;
  const stamp = { epoch: e, generation: g, seq, key: cryptoReqKey(c) };
  store.dispatch({ type: 'CRYPTO_REQUEST', ...stamp });
  try {
    const data = await api('/api/workbench/v1/crypto-assets?' + qs({ generation: g, filter: cryptoFilterOf(c.filter), query: c.q, group_id: c.group, offset: c.offset, size: CRYPTO_PAGE }));
    store.dispatch({ type: 'CRYPTO_LOADED', ...stamp, data });
    if (store.get().views.cryptoPage === data) revealSelection(store.get);        // applied (not superseded): keep the selected card in view
  } catch (err) {
    if (e !== epoch()) return;                                                       // a late error after replacement or End session changes nothing
    if (err instanceof ApiError && err.status === 403) { handleError(err, e); return; }
    store.dispatch({ type: 'CRYPTO_FAILED', ...stamp, status: err?.status, error: cryptoError(err) });
  }
}
function ensureCryptoPage() {
  const s = store.get(); if (!s.analysis || s.advanced || s.busy === 'ending') return;
  const c = s.workbench.perTab.crypto; if (c.stale || c.pg.status === 'loading') return;
  // IR-03: a failed CURRENT request stays failed until "Try again" or a changed request identity; revisiting the tab never retries it
  if (c.pg.status === 'error' && c.pg.req?.key === cryptoReqKey(c)) return;
  if (cryptoPageNeeded(s.views.cryptoPage, c)) loadCryptoPage();
}
const cryptoPatch = (patch) => store.dispatch({ type: 'TAB_STATE', tab: 'crypto', patch });
// ------------------------------------------------------------------ UIP-07: AI models page
// GET /api/workbench/v1/ai-assets. Same request-identity rules as the Cryptography page: stamped {epoch, generation, seq, key}; a success, an error or a 409
// acts only while that identity is still current and still describes (filter, query, group, offset); a typed failure shows a manual "Try again" and nothing
// retries by itself (no implicit retry on tab revisit); a current 409 retires the payload and shows the "session moved on" recovery.
let aiSeq = 0; let aiTimer = 0;
async function loadAiPage() {
  const s = store.get(); const c = s.workbench.perTab.ai;
  if (!s.analysis || s.busy === 'ending' || c.stale) return;
  const e = s.epoch; const g = gen(); const seq = ++aiSeq;
  const stamp = { epoch: e, generation: g, seq, key: aiReqKey(c) };
  store.dispatch({ type: 'AI_REQUEST', ...stamp });
  try {
    const data = await api('/api/workbench/v1/ai-assets?' + qs({ generation: g, filter: aiFilterOf(c.filter), query: c.q, group_id: c.group, offset: c.offset, size: CRYPTO_PAGE }));
    store.dispatch({ type: 'AI_LOADED', ...stamp, data });
    if (store.get().views.aiPage === data) revealAiSelection(store.get);
  } catch (err) {
    if (e !== epoch()) return;
    if (err instanceof ApiError && err.status === 403) { handleError(err, e); return; }
    store.dispatch({ type: 'AI_FAILED', ...stamp, status: err?.status, error: cryptoError(err) });
  }
}
function ensureAiPage() {
  const s = store.get(); if (!s.analysis || s.advanced || s.busy === 'ending') return;
  const c = s.workbench.perTab.ai; if (c.stale || c.pg.status === 'loading') return;
  if (c.pg.status === 'error' && c.pg.req?.key === aiReqKey(c)) return;          // a failed CURRENT request stays failed until "Try again" or a changed request identity
  if (aiPageNeeded(s.views.aiPage, c)) loadAiPage();
}
const aiPatch = (patch) => store.dispatch({ type: 'TAB_STATE', tab: 'ai', patch });
function aiSelect(id, restoreFocus) {
  const c = store.get().workbench.perTab.ai; if (c.sel !== id || !c.selUser || c.checkId) aiPatch({ sel: id, selUser: true, checkId: null });
  revealAiSelection(store.get);
  if (restoreFocus) document.querySelector(`#otai-svg [data-otai-select="${CSS.escape(id)}"]`)?.focus();
}
function aiCollapse() { aiPatch({ expanded: false }); $('otai-expand')?.focus(); }
const openTab = (tab) => { if (tab === 'dependencies') { ensureDepPage(); loadDeps(); } else if (tab === 'crypto' && !store.get().advanced) ensureCryptoPage(); else if (tab === 'ai' && !store.get().advanced) ensureAiPage(); else if (tab === 'bom') loadBomQueue(); else if (tab !== 'contexts') loadSimple(tab); };
function cryptoSelect(id, restoreFocus) {
  const c = store.get().workbench.perTab.crypto; if (c.sel !== id || !c.selUser || c.checkId) cryptoPatch({ sel: id, selUser: true, checkId: null });
  revealSelection(store.get);
  if (restoreFocus) document.querySelector(`#otc-svg [data-otc-select="${CSS.escape(id)}"]`)?.focus();     // focus survives the repaint
}
function cryptoCollapse() { cryptoPatch({ expanded: false }); $('otc-expand')?.focus(); }                   // focus returns to the Expand control

// UIP-08 requests are bound to the current epoch, generation and exact UI key.
const bomPatch = (patch) => store.dispatch({ type: 'BOM_PATCH', patch });
let bomTimer = null;
function bomSelectRecord(id) {
  bomPatch({ selectedRecord: id, related: null, drawer: !!id });
  if (!id) return;
  const edge = store.get().bom8.graph?.edges?.some((x) => x.edge_id === id);
  bomRequest('related', { subject_kind: edge ? 'relationship' : 'record', subject_id: id, query: store.get().bom8.chooserQ, offset: store.get().bom8.chooserOffset, size: 20 });
}

async function loadSimple(tab) {
  const s = store.get(); const e = s.epoch;
  try {
    const data = await api(`/api/view/${tab}?generation=${gen()}`);
    store.dispatch({ type: 'VIEW_LOADED', tab, data, epoch: e, generation: data.generation });
    if (tab === 'bom' && e === store.get().epoch && !store.get().gaps.data) loadGaps();
    // Like the prototype, the Cryptography and AI tabs open on their rule-backed check.
    if (e === store.get().epoch && (tab === 'crypto' || tab === 'ai') && !store.get().workbench.perTab[tab].selection) {
      const chk = data.checks.find((c) => c.rule_id);
      if (chk) store.dispatch({ type: 'TAB_STATE', tab, patch: { selection: 'assertion:' + chk.assertion_id } });
    }
  } catch (err) { handleError(err, e); }
}
// ------------------------------------------------------------------ UIP-04: repository contexts map
// GET /api/workbench/v1/contexts. Every request is stamped {epoch, generation, kind, group, seq}; a response (success OR error) acts only
// if the stamp is still current and its seq is the newest issued for its (kind, group) - otherwise it is dropped without a state change,
// a notice or a retry. response_too_large retries the same request with a smaller page (20/page size -> 10 -> 5 -> 1); the last step
// failing is terminal (the whole map for the initial request, only that group for a group request).
const ctxSeq = { full: 0, group: {} };
const ctxError = (err) => ({ code: err?.code || 'request_failed', detail: err?.body?.detail_code || null });
async function ctxRequest(kind, group, sizes) {
  const e = epoch(); const g = gen();
  for (let i = 0; i < sizes.length; i++) {
    const seq = kind === 'full' ? ++ctxSeq.full : (ctxSeq.group[group] = (ctxSeq.group[group] || 0) + 1);
    const stamp = { epoch: e, generation: g, kind, group, seq };
    store.dispatch({ type: 'CTX_REQUEST', ...stamp });
    const params = { generation: g, files_limit: sizes[i] };
    if (kind === 'group') { const grp = store.get().views.contexts?.groups.find((x) => x.group_id === group); if (!grp) return; params.group_id = group; params.files_offset = loadedCount(grp); }
    try {
      const data = await api('/api/workbench/v1/contexts?' + qs(params));
      store.dispatch({ type: 'CTX_LOADED', ...stamp, data });
      return;
    } catch (err) {
      if (!ctxCurrent(store.get(), stamp)) return;                              // a late or superseded error changes nothing and is never retried
      if (err instanceof ApiError && err.code === 'response_too_large' && i < sizes.length - 1) continue;
      if (err instanceof ApiError && (err.status === 403 || err.status === 409)) { handleError(err, e); return; }
      store.dispatch({ type: 'CTX_FAILED', ...stamp, error: ctxError(err) });
      return;
    }
  }
}
const loadContexts = () => (store.get().analysis ? ctxRequest('full', null, RETRY_LADDER) : Promise.resolve());
function loadContextGroup(id) {
  const s = store.get(); const g = s.views.contexts?.groups.find((x) => x.group_id === id);
  if (!g || hiddenCount(g) <= 0 || s.workbench.perTab.contexts.map.groups[id]?.state === 'loading') return Promise.resolve();
  return ctxRequest('group', id, ladderFrom(pageSizeFor(s.workbench.perTab.contexts.presentation)));
}
// The Dependencies tab's context chooser needs every path: it keeps using the unchanged legacy list route.
async function loadContextList() {
  const e = epoch();
  try {
    const data = await api(`/api/view/contexts?generation=${gen()}`);
    store.dispatch({ type: 'VIEW_LOADED', tab: 'contextList', data, epoch: e, generation: data.generation });
  } catch (err) { handleError(err, e); }
}
async function loadEvidence() {
  const e = epoch();
  try {
    const [list, bom] = await Promise.all([api('/api/artifacts'), api(`/api/view/bom?generation=${gen()}`)]);
    store.dispatch({ type: 'EVIDENCE_LOADED', epoch: e, patch: { artifacts: list.artifacts, records: bom.supporting_records } });
    store.dispatch({ type: 'VIEW_LOADED', tab: 'bom', data: bom, epoch: e, generation: bom.generation });
  } catch (err) { handleError(err, e); }
}
function handleError(err, e) {
  if (e !== epoch()) return; // a stale response is discarded silently
  if (err instanceof ApiError && err.status === 403) { dispatchEnded('gone'); closeDialog(); return; }
  if (err instanceof ApiError && err.status === 409) return;
  console.error(err);
}
function runSearch() {
  clearTimeout(searchTimer);
  searchTimer = setTimeout(async () => {
    const s = store.get(); const d = s.workbench.perTab.dependencies; const e = s.epoch; if (!d.search || !s.analysis) return;
    const seq = ++searchSeq; store.dispatch({ type: 'REQUEST', kind: 'search', seq }); const ctx = d.context || null;
    try {
      const data = await api('/api/view/dependencies?' + qs({ context: d.context, selected: d.focus, q: d.search, per_side: s.narrow ? 1 : 6, generation: gen() }));
      store.dispatch({ type: 'SEARCH_LOADED', epoch: e, search: data.search, seq, context: ctx });
    } catch (err) { handleError(err, e); }
  }, 150);
}

const SCAN_WORDS = { acquired: 'completed', failed: 'failed', unavailable: 'unavailable', cancelled: 'cancelled' };
function failureMessage(res) {
  const base = res.message || 'The analysis did not complete (' + (res.code || 'unknown') + ').';
  const runs = (res.scan || []).map((r) => `${r.tool} ${r.version || r.pinned_version}: ${SCAN_WORDS[r.outcome] || r.outcome}${r.reason ? ' (' + r.reason.replaceAll('_', ' ') + ')' : ''}`);
  return runs.length ? base + ' ' + runs.join('; ') + '.' : base;
}

async function openAnalysis(url) {
  store.dispatch({ type: 'INTAKE_STATE', patch: { error: '' } });
  store.dispatch({ type: 'ANALYSIS_START' });
  store.dispatch({ type: 'SCAN_CLEAR' });
  const e = epoch();
  try {
    const sess = await api('/api/session', { method: 'POST' });
    store.dispatch({ type: 'SESSION', patch: { status: 'active', generation: sess.generation } });
    const res = await api('/api/analysis/demo', { method: 'POST', body: url ? { url } : {} });   // the sample path; live scanning is the one-click Scan above
    if (e !== epoch()) return;
    if (!res.ok) { store.dispatch({ type: 'ANALYSIS_FAILED', epoch: e, message: failureMessage(res) }); return; }
    store.dispatch({ type: 'ANALYSIS_READY', epoch: e, analysis: res });
    warm().catch(() => {});
    await Promise.all([loadContexts(), loadContextList(), loadDeps(), loadDepContexts(), loadEvidence(), loadLookup()]);
  } catch (err) { if (e === epoch()) store.dispatch({ type: 'ANALYSIS_FAILED', epoch: e, message: 'The service could not complete the request.' }); }
}

// ------------------------------------------------------------------ UIP-03: one-click Scan
// POST /api/scan (the single resolution and pin happen on the server), then generation-bound polling with bounded backoff
// (1 s, up to 3 s while nothing changes). Every response is checked against the epoch, the job id, the generation and the
// newest applied seq, so a late poll can never overwrite newer status or repopulate a newer or ended session.
function dispatchEnded(state) {
  store.dispatch({ type: 'ENDED', state });
  store.dispatch({ type: 'CONFIG_RAW', ok: rawConfig.ok, live: rawConfig.live });   // the reset keeps the service configuration
}
const sleepMs = (ms) => new Promise((r) => setTimeout(r, ms));
let rawConfig = { ok: false, live: null };

async function startScan() {
  const s0 = store.get(); const url = s0.intake.url.trim();
  if (!url) { store.dispatch({ type: 'INTAKE_STATE', patch: { state: 'invalid', error: 'Enter a GitHub repository URL', errorField: 'url' } }); return; }
  store.dispatch({ type: 'INTAKE_STATE', patch: { error: '', errorField: null } });
  store.dispatch({ type: 'ANALYSIS_START' });
  const e = epoch();
  store.dispatch({ type: 'SCAN_UI_BEGIN', epoch: e });     // the dialog opens at once with "Starting analysis…"; refusals and errors appear there
  try {
    const sess = await api('/api/session', { method: 'POST' });
    if (e !== epoch()) return;
    store.dispatch({ type: 'SESSION', patch: { status: 'active', generation: sess.generation } });
    store.dispatch({ type: 'SCAN_BEGIN', epoch: e, generation: sess.generation });
    const s = store.get();
    const res = await api('/api/scan', { method: 'POST', body: { url, generation: sess.generation, advanced: !!s.advanced, manual_sha: s.advanced ? s.intake.manualSha : '' } });
    if (e !== epoch()) return;
    if (res.ok === false) { store.dispatch({ type: 'SCAN_ERROR', epoch: e, message: refusalText(res) }); store.dispatch({ type: 'ANALYSIS_FAILED', epoch: e, message: '' }); return; }
    if (res.schema !== SCAN_SCHEMA) throw new Error('unexpected response');
    store.dispatch({ type: 'SCAN_RESPONSE', epoch: e, envelope: res });
    pollScan(e);
  } catch (err) {
    if (e !== epoch()) return;
    const msg = err instanceof ApiError && err.status === 409 ? refusalText({ code: 'stale_generation' }) : 'The service could not start the scan.';
    store.dispatch({ type: 'SCAN_ERROR', epoch: e, message: msg }); store.dispatch({ type: 'ANALYSIS_FAILED', epoch: e, message: '' });
  }
}
function focusScanStatus() { const el = document.getElementById('ot-scan-status'); if (el) el.focus({ preventScroll: true }); }

let pollSeq = 0;                       // the newest polling loop; an older loop (superseded by a recheck) stops at its next step
async function pollScan(e) {
  const me = ++pollSeq;
  let delay = 1000; let failures = 0;
  for (;;) {
    await sleepMs(delay);
    const s = store.get();
    if (me !== pollSeq || e !== s.epoch || !s.scan.job || s.scan.epoch !== e) return;     // ended, replaced or cleared: stop polling
    let env;
    try { env = await api(`/api/scan/status?job=${encodeURIComponent(s.scan.job)}&generation=${s.scan.generation}`); }
    catch (err) {
      if (me !== pollSeq || e !== epoch()) return;
      if (err instanceof ApiError && err.status === 403) { dispatchEnded('gone'); closeDialog(); return; }
      // 404/409: the service no longer holds this job for this page (replaced, retired or another generation); retrying cannot help.
      const lost = err instanceof ApiError && (err.status === 404 || err.status === 409);
      if (!lost && failures < POLL_RETRY_DELAYS.length) { delay = POLL_RETRY_DELAYS[failures++]; continue; }   // bounded automatic retry
      // The last status stays visible but is marked stale; nothing is inferred about the server work, and End session stays available.
      store.dispatch({ type: 'SCAN_ERROR', epoch: e, kind: lost ? 'lost' : 'transient', message: lost
        ? 'The service no longer has this scan for this page.'
        : 'The scan status could not be read.' });
      store.dispatch({ type: 'ANALYSIS_FAILED', epoch: e, message: '' }); return;
    }
    if (me !== pollSeq || e !== epoch()) return;
    failures = 0;
    const before = store.get().scan.lastSeq;
    store.dispatch({ type: 'SCAN_RESPONSE', epoch: e, envelope: env });
    const st = store.get().scan;
    if (st.status && isTerminal(st.status)) { await finishScan(e); return; }
    delay = st.lastSeq !== before ? 1000 : Math.min(3000, delay + 500);
  }
}

// One manual, bounded recovery: clear the error and poll again for the SAME job, generation and epoch (every guard above still applies).
function recheckScan() {
  const s = store.get(); const e = s.epoch;
  if (!s.scan.job || s.scan.epoch !== e || s.scan.errorKind !== 'transient') return;
  store.dispatch({ type: 'SCAN_ERROR', epoch: e, message: '' });
  pollScan(e);
}

async function finishScan(e) {
  const sc = store.get().scan;
  if (e !== epoch()) return;
  if (sc.status && sc.status.handoff.ready && sc.result && sc.result.ok) {
    store.dispatch({ type: 'ANALYSIS_READY', epoch: e, analysis: sc.result });        // direct hand-off to Repository contexts (UIP-02 default tab)
    warm().catch(() => {});
    await Promise.all([loadContexts(), loadContextList(), loadDeps(), loadDepContexts(), loadEvidence(), loadLookup()]);
  } else {
    store.dispatch({ type: 'ANALYSIS_FAILED', epoch: e, message: '' });               // the panel shows the reason and the next step
  }
}

async function cancelScan() {
  const s = store.get(); if (!s.scan.job || (s.scan.status && isTerminal(s.scan.status))) return;
  try { await api('/api/analysis/cancel', { method: 'POST' }); } catch { /* the polled status is the truth */ }
}

async function endSession() {
  const s = store.get(); if (s.busy === 'ending') return;
  store.dispatch({ type: 'END_STARTED' });
  let state = 'gone';
  try { const r = await api('/api/session/end', { method: 'POST' }); state = r.state; } catch (err) { if (err instanceof ApiError && err.body?.state) state = err.body.state; else if (!(err instanceof ApiError && err.status === 403)) state = 'cleanup_failed'; }
  closeDialog(); closePreview();
  dispatchEnded(state);
  window.scrollTo(0, 0);
  { const a = document.activeElement; if (!a || a === document.body || !a.isConnected || a.closest?.('[hidden]')) scanReturnFocus(); }   // End session is an explicit action: the control that held focus is gone or hidden (the header button is only hidden, and Chrome blurs it lazily); never moves focus from a surviving control
}

// ------------------------------------------------------------------ preview + records + advisory dialogs
let previewEpoch = 0;
function closePreview() { previewEpoch++; }
async function sha256(buf) { const d = await crypto.subtle.digest('SHA-256', buf); return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, '0')).join(''); }
async function openPreview(name) {
  const e = epoch(); const mine = ++previewEpoch;
  modal('Artifact preview', '<p class="ot-help" role="status">Loading…</p>', true);
  try {
    const res = await fetch('/api/artifacts/' + encodeURIComponent(name), { credentials: 'same-origin' });
    if (!res.ok) throw new ApiError(res.status, null);
    const buf = await res.arrayBuffer(); const header = res.headers.get('X-Artifact-Sha256'); const kind = res.headers.get('X-Artifact-Kind');
    if (e !== epoch() || mine !== previewEpoch) return;
    const digest = await sha256(buf); if (e !== epoch() || mine !== previewEpoch) return;
    const text = new TextDecoder().decode(buf);
    let doc = null; try { doc = JSON.parse(text); } catch { /* raw only */ }
    const facts = readable(name, kind, doc, buf.byteLength);
    const fmtd = formatArtifact(text);       // the whole document is formatted first; only the display is limited
    const view = { mode: 'readable', q: '' };
    const hitsHtml = () => {
      const r = searchArtifact(text, view.q);
      return { count: view.q ? `${r.hits.length}${r.more ? '+' : ''} match${r.hits.length === 1 && !r.more ? '' : 'es'} in the whole artifact` : 'Enter text to search the whole artifact.',
        html: r.hits.map((h) => `<div class="ot-hit"><small>${esc(h.where)}</small> ${esc(h.before)}<mark>${esc(h.match)}</mark>${esc(h.after)}</div>`).join('') };
    };
    const body = () => {
      if (view.mode === 'readable') return facts;
      if (view.mode === 'raw') return `${fmtd.json ? '' : '<p class="ot-help">This file is not valid JSON, so it is shown as plain text.</p>'}<pre id="ot-raw">${esc(fmtd.shown)}</pre>${fmtd.truncated ? '<p class="ot-help">Preview limited. Download the original for the full file.</p>' : ''}`;
      const h = hitsHtml();
      return `<input type="search" id="ot-prev-q" class="ot-commit" placeholder="Search this artifact…" aria-label="Search this artifact" value="${esc(view.q)}"><p class="ot-help" id="ot-pv-count">${h.count}</p><div id="ot-pv-hits">${h.html}</div>`;
    };
    const MODES = [['readable', 'Overview'], ['raw', 'Formatted JSON'], ['search', 'Search']];
    const draw = () => {
      $('ot-dialog-content').innerHTML = `<p class="mono micro">${esc(name)} · ${fmt(buf.byteLength)} bytes · ${kind === 'derived' ? 'derived output' : 'original artifact'}<br>sha256 ${esc(digest)} ${digest === header ? '— matches the session record ✓' : '— DOES NOT MATCH the session record'}</p>
      <div class="ot-previewbar">${MODES.map(([m, label]) => `<button type="button" class="button small" data-pv="${m}" aria-pressed="${view.mode === m}">${label}</button>`).join('')}<a class="button small" href="/api/artifacts/${encodeURIComponent(name)}?disposition=attachment" download="${esc(name)}">Download original ↓</a></div><div id="ot-pv-body">${body()}</div>`;
    };
    draw();
    const root = $('ot-dialog-content');
    root.onclick = (ev) => { const b = ev.target.closest('[data-pv]'); if (b) { view.mode = b.dataset.pv; draw(); (view.mode === 'search' ? $('ot-prev-q') : b)?.focus(); } };
    root.oninput = (ev) => { if (ev.target.id === 'ot-prev-q') { view.q = ev.target.value; const h = hitsHtml(); $('ot-pv-hits').innerHTML = h.html; $('ot-pv-count').textContent = h.count; } };
  } catch (err) { if (e === epoch()) { closeDialog(); handleError(err, e); } }
}
// The same labels the Evidence tab uses for the derived artifacts (filenames are unchanged).
const DERIVED_LABEL = { 'bombridge-result.json': 'Inventory assessment record', 'source-declarations.json': 'Source evidence', 'advisory-lookup.json': 'Advisory lookup record' };
function readable(name, kind, doc, size) {
  if (!doc) return '<p>This artifact is not JSON; use Formatted JSON to view it as text.</p>';
  if (kind === 'derived' && name !== 'bombridge-result.json') return `<h3>${esc(DERIVED_LABEL[name] || name)} (derived)</h3><p>Derived by OpenTrace; not an original capture.</p><dl class="readable-facts"><div><dt>Schema</dt><dd>${esc(doc.schema || 'not recorded')}</dd></div><div><dt>Size</dt><dd>${fmt(size)} bytes</dd></div></dl>`;
  if (kind === 'derived') return `<h3>${esc(DERIVED_LABEL[name])} (derived)</h3><p>Recorded inventory information and any checks included in the assessment.</p><dl class="readable-facts"><div><dt>Schema</dt><dd>${esc(doc.schema)}</dd></div><div><dt>Findings</dt><dd>${(doc.findings || []).length} assertions</dd></div><div><dt>Graph</dt><dd>${(doc.graph?.nodes || []).length} nodes · ${(doc.graph?.edges || []).length} edges</dd></div><div><dt>Inventory links</dt><dd>${(doc.inventory_links || []).length}</dd></div></dl>`;
  const comps = (doc.components || []).length; const svcs = (doc.services || []).length;
  const tool = doc.metadata?.tools?.components?.map((t) => `${t.name} ${t.version || ''}`.trim()).join(', ') || (doc.metadata?.tools || []).map?.((t) => `${t.name || ''} ${t.version || ''}`.trim()).join(', ') || 'not recorded';
  return `<h3>${esc(doc.bomFormat || 'BOM')} ${esc(doc.specVersion || '')}</h3><dl class="readable-facts"><div><dt>Component records</dt><dd>${fmt(comps)}</dd></div><div><dt>Services</dt><dd>${fmt(svcs)}</dd></div><div><dt>Dependency rows</dt><dd>${fmt((doc.dependencies || []).length)}</dd></div><div><dt>Producer</dt><dd>${esc(tool)}</dd></div><div><dt>Size</dt><dd>${fmt(size)} bytes</dd></div></dl><p class="artifact-boundary">Download original to get the exact file. A record's presence or absence does not establish installation, model loading or runtime use.</p>`;
}
async function showRecord(id) {
  const rec = store.get().evidence.records.find((r) => r.evidence_id === id); if (!rec) return;
  const n = rec.record;
  modal(id, `${n.observation?.excerpt ? `<pre class="ot-raw">${esc(n.observation.excerpt)}</pre>` : ''}<p>${esc(rec.label === 'used' ? 'Used by a displayed check.' : 'Excluded by a displayed check.')}</p>${n.observation?.artifact?.locator ? `<p><strong>Source locator:</strong> ${esc(n.observation.artifact.locator)}</p>` : ''}<p><strong>Origin:</strong> ${esc(n.origin || '')} · <strong>Method:</strong> ${esc(n.method || '')}</p>${(n.limitations || []).map((l) => `<p>${esc(l)}</p>`).join('')}${store.get().advanced ? `<details open><summary>Technical JSON</summary><pre class="ot-raw">${esc(JSON.stringify(n, null, 2))}</pre></details>` : ''}`);
}
async function readAdvisory(key, pkg) {
  const e = epoch();
  try {
    const f = await api('/api/view/advisory/' + encodeURIComponent(key)); if (e !== epoch()) return;
    modal(f.label, `<span class="ot-sev ${f.severity === 'HIGH' || f.severity === 'CRITICAL' ? 'warn' : ''}">Package-version match · ${esc(f.severity || 'Not rated')}</span><p>${esc(f.summary)}</p><p><strong>Matched package:</strong> ${esc(pkg)}</p><p>Captured OSV query: ${esc(f.captured_at.slice(0, 10))}. This establishes an advisory match for a reported package version, not application reachability, exploitability or a confirmed incident.</p><p><strong>Aliases:</strong> ${esc(f.aliases.join(', ') || 'None recorded')}</p><details><summary>Advisory details and affected ranges</summary>${f.records.map((r) => `<h3>${esc(r.id)}</h3><p>${esc(r.details || 'No additional description recorded')}</p><pre>${esc(JSON.stringify(r.affected, null, 2))}</pre>`).join('')}</details>${store.get().advanced ? `<details><summary>Raw advisory records</summary><pre>${esc(JSON.stringify(f.raw, null, 2))}</pre></details>` : ''}`, true);
  } catch (err) { handleError(err, e); }
}

// ------------------------------------------------------------------ assistant
function assistantContext() {
  const s = store.get(); if (!s.analysis) return null;
  const tab = s.workbench.tab; const per = s.workbench.perTab[tab];
  if (tab === 'dependencies') {
    const x = s.views.dependencies?.inspected; if (!x) return null; const c = x.component;
    return { title: `${c.name} ${c.version || ''}`.trim(), cite: [c.id], meaning: `${c.name} ${c.version || ''} is a package record declared in ${c.locations.join(', ') || 'no captured location'}. In this context it depends on ${x.depends_on} and is used by ${x.used_by} captured records.`, limits: 'Declarations in a source inventory do not establish runtime use, reachability or exploitability. A package-version advisory match is not a confirmed incident.', next: x.advisories.length ? 'Read the advisory and compare the affected range with how the package is actually used.' : 'No advisory matched in the captured query; this does not establish absence of vulnerabilities.' };
  }
  if (tab === 'contexts') {
    const f = findSelection(s.views.contexts, per.selection); if (!f) return null;
    const limits = 'Counts can overlap between files. Lines show grouping, not dependency or runtime relationships.';
    if (f.kind === 'file') return { title: f.file.path, cite: [f.file.file_id], meaning: `${f.file.path} is a recorded source location for ${fmt(f.file.distinct_total)} distinct component records. Contexts are source locations in this one repository.`, limits, next: 'Open the file in Dependencies to see its declared dependency neighborhood.' };
    if (f.kind === 'root') return { title: f.root.name, cite: [], meaning: `${fmt(f.root.distinct_total)} distinct component records: ${fmt(f.root.located_distinct_total)} with a recorded source location and ${fmt(f.root.unlocated_total)} without one. This is a partial source inventory.`, limits, next: 'Select a group or source file to inspect its evidence.' };
    return { title: f.group.label, cite: [f.group.group_id], meaning: `${groupSummary(f.group)}. This grouping does not establish installation, workflow execution or service topology.`, limits, next: 'Select a source file in this group to see its records.' };
  }
  if (tab === 'ai' && !s.advanced) {                // UIP-07: the assistant follows the ai_assets/1 selection (ids are scoped to this analysis and generation)
    const pg = s.views.aiPage; if (!pg) return null; const sel = aiResolve(pg, per.sel);
    const asset = aiFindAsset(pg, sel); const grp = aiFindGroup(pg, sel);
    if (asset) { const rv = aiReviewsOf(pg, asset); const locs = asset.occurrences.slice(0, 3).map((o) => o.source_location.path + (o.source_location.line_start ? ':' + o.source_location.line_start : '')).join(', ');
      return { title: asset.display_name, cite: [asset.asset_id, ...rv.map((r) => r.review_id)], meaning: `${asset.display_name} is a ${asset.kind.replaceAll('_', ' ')} recorded by the AI-BOM inventory with identity ${asset.identity_state}${locs ? ', at ' + locs : ''}${rv.length ? '. A rule-backed review item exists: ' + rv[0].condition : ''}.`, limits: 'A name, file name or URL is not a verified model identity; nothing here says which model is loaded. Runtime execution was not observed.', next: rv[0]?.next_action || 'Open the asset metadata and source observations.' }; }
    if (grp) return { title: grp.label, cite: [grp.group_id], meaning: `${grp.label} is a display grouping of ${grp.assets_total} recorded asset${grp.assets_total === 1 ? '' : 's'}.`, limits: 'A grouping is not a dependency or runtime relationship.', next: 'Select an asset in this group.' };
    return { title: `${pg.binding.repository.owner}/${pg.binding.repository.name}`, cite: [], meaning: `${pg.filter_totals.all} recorded AI asset(s). ${pg.availability.message}`, limits: 'An AI inventory that lists no assets does not show that no AI is used.', next: 'Choose an asset or source group.' };
  }
  if (tab === 'crypto' && !s.advanced) {            // UIP-06: the assistant follows the crypto_assets/1 selection (ids are scoped to this analysis and generation)
    const pg = s.views.cryptoPage; if (!pg) return null; const sel = cryptoResolve(pg, per.sel);
    const asset = cryptoFindAsset(pg, sel); const grp = cryptoFindGroup(pg, sel);
    if (asset) { const rv = cryptoReviewsOf(pg, asset); const locs = asset.occurrences.slice(0, 3).map((o) => o.source_location.path + (o.source_location.line_start ? ':' + o.source_location.line_start : '')).join(', ');
      return { title: asset.display_name, cite: [asset.asset_id, ...rv.map((r) => r.review_id)], meaning: `${asset.display_name} is a ${asset.kind.replaceAll('_', ' ')} asset ${asset.provenance.experimental ? 'seen by an experimental source observation' : 'recorded in the original CBOM'}${locs ? ' at ' + locs : ''}${rv.length ? '. A rule-backed review item exists: ' + rv[0].condition : ''}.`, limits: 'Static recorded data only; runtime execution was not observed, and an algorithm name alone is not a finding.', next: rv[0]?.next_action || 'Open the source observations to see the recorded locations.' }; }
    if (grp) return { title: grp.label, cite: [grp.group_id], meaning: `${grp.label} is a display grouping of ${grp.assets_total} recorded asset${grp.assets_total === 1 ? '' : 's'}.`, limits: 'A grouping is not a dependency or runtime relationship.', next: 'Select an asset in this group.' };
    return { title: `${pg.binding.repository.owner}/${pg.binding.repository.name}`, cite: [], meaning: `${pg.filter_totals.all} recorded cryptographic asset(s) and ${pg.services_counts.total} endpoint service(s). ${pg.availability.message}`, limits: 'A CBOM that lists no assets does not show that no cryptography is used.', next: 'Choose an asset or source group.' };
  }
  if (tab === 'bom') return bomAssistantContext(s.bom8);
  const v = s.views[tab]; const n = v?.nodes.find((x) => x.id === per.selection); if (!n) return null;
  const chk = v.checks.find((c) => 'assertion:' + c.assertion_id === n.id);
  if (chk) return { title: chk.assertion_id, cite: [chk.assertion_id, chk.rule_id].filter(Boolean), meaning: `${stateLabel(chk.state)}. ${chk.rationale || ''}`, limits: (chk.not_established || []).join('; ') || chk.bounded_meaning || 'No further limits recorded.', next: chk.next_action || 'No next action is recorded for this check.' };
  return { title: n.id, cite: [n.id], meaning: n.observation?.excerpt ? `Source observation: ${n.observation.excerpt}` : `${n.name || n.id} is a captured record.`, limits: (n.limitations || []).join('; ') || 'No limitations recorded.', next: 'Follow the check that uses this record to see what it supports.' };
}
function renderAssistantPanel() {
  const s = store.get(); const el = $('ot-assistant'); const a = s.assistant;
  el.hidden = !a.open; el.classList.toggle('min', a.minimized); $('ot-assistant-launch').setAttribute('aria-expanded', String(a.open));
  if (!a.open) { el._html = ''; return; }
  const html = renderAssistant(s, assistantSelection()); paint(el, html);
  if (a.position) { el.style.left = a.position.x + 'px'; el.style.top = a.position.y + 'px'; el.style.right = 'auto'; el.style.bottom = 'auto'; }
  // A new request brings its question and Thinking indicator into view ONCE (scrolling only the panel's own body, never the page). The answer or error then replaces that turn in
  // place, and any later scrolling by the user is left alone: paint() keeps the body's scroll position across every re-render.
  if (a.pending && a.requestId && el._followed !== a.requestId) {
    el._followed = a.requestId;
    const body = el.querySelector('.body'); const turn = body?.querySelector('.ot-assistant-turn-pending');
    if (body && turn) body.scrollTop += turn.getBoundingClientRect().top - body.getBoundingClientRect().top - 8;
  }
}
// Enter submits the assistant composer; Shift+Enter inserts a newline; Enter during input-method composition is left to the input method. The ordinary form submit runs, so the
// pending, empty-draft and paused-subject checks in submitAssistant() apply unchanged.
document.addEventListener('keydown', (ev) => {
  if (ev.target?.id !== 'ot-assistant-question' || ev.key !== 'Enter') return;
  if (ev.shiftKey || ev.ctrlKey || ev.altKey || ev.metaKey || ev.isComposing || ev.keyCode === 229) return;
  ev.preventDefault();
  if (ev.target.value.trim()) $('ot-assistant-form')?.requestSubmit();
});

function assistantSelection() {
  const s = store.get(); if (!s.analysis) return null;
  const tab = s.workbench.tab; const per = s.workbench.perTab[tab];
  if (tab === 'contexts') {
    const contexts = s.views.contexts; const id = per.selection;
    if (!id || id === 'root') return null;
    for (const group of contexts?.groups || []) {
      if (group.group_id === id) return { kind: 'context', id, label: group.label };
      const file = group.files?.find((item) => item.file_id === id);
      if (file) return { kind: 'context', id, label: file.path };
    }
    return null;
  }
  if (tab === 'dependencies') {
    const item = s.views.dependencies?.inspected?.component;
    return item ? { kind: 'dependency', id: item.id, label: `${item.name} ${item.version || ''}`.trim() } : null;
  }
  if (tab === 'crypto') {
    const page = s.views.cryptoPage; const key = page && cryptoResolve(page, per.sel); const item = page && cryptoFindAsset(page, key);
    return item ? { kind: 'crypto', id: item.asset_id, label: item.display_name } : null;
  }
  if (tab === 'ai') {
    const page = s.views.aiPage; const key = page && aiResolve(page, per.sel); const item = page && aiFindAsset(page, key);
    return item ? { kind: 'model', id: item.asset_id, label: item.display_name } : null;
  }
  if (tab === 'bom') {
    const relations = s.bom8.graph?.edges || [];
    const chosenRelation = relations.find((edge) => edge.edge_id === s.assistant.subjectChoice);
    if (chosenRelation) return { kind: 'relationship', id: chosenRelation.edge_id,
      label: chosenRelation.label || chosenRelation.kind || chosenRelation.edge_id, relations };
    const item = bomSelectedItem(s.bom8);
    return item ? { kind: 'bom', id: item.item_id, label: item.display?.name || item.item_id, relations } :
      (relations.length ? { kind: 'relationship', id: null, label: '', relations } : null);
  }
  const view = s.views[tab]; const node = view?.nodes?.find((x) => x.id === per?.selection);
  if (node?.type === 'assertion' && node.assertion_id) return { kind: 'bom', id: node.assertion_id, label: node.label || node.assertion_id };
  return null;
}

// ------------------------------------------------------------------ Advanced dense exploration (presentation only)
const depNow = () => store.get().workbench.perTab.dependencies;
function denseSet(patch, push = true) {
  const s = store.get(); const dep = depNow(); const dn = dep.dense;
  const snap = { visible: denseVisible(s), layout: dn.layout, view: dn.view, paths: dn.paths, selection: dep.selection };
  const history = push ? [...dn.history, snap].slice(-20) : dn.history;
  store.dispatch({ type: 'TAB_STATE', tab: 'dependencies', patch: { dense: { ...dn, visible: denseVisible(s), ...patch, history } } });
}
function denseSelect(id) { const dep = depNow(); if (dep.selection === id) return; store.dispatch({ type: 'TAB_STATE', tab: 'dependencies', patch: { selection: id } }); loadDeps(); }
function denseExpandAt(id) {
  const s = store.get(); const net = activeNetwork(s); if (!net) return;
  const vis = new Set(denseVisible(s)); const batch = children(net, id).filter((c) => !vis.has(c)).slice(0, BATCH);
  if (id !== depNow().selection) store.dispatch({ type: 'TAB_STATE', tab: 'dependencies', patch: { selection: id } });
  if (batch.length) denseSet({ visible: [...vis, ...batch], paths: null }); loadDeps();
}
function denseNavigate(id) {
  const s = store.get(); const net = activeNetwork(s); if (!net) return;
  const p = pathSet(net, id); const vis = new Set(denseVisible(s));
  for (const x of [...new Set([id, ...p.shortest, ...p.paths])].slice(0, PATH_CAP)) vis.add(x);
  store.dispatch({ type: 'TAB_STATE', tab: 'dependencies', patch: { selection: id, search: '' } });
  denseSet({ visible: [...vis], paths: { ids: [...p.paths], rooted: p.rooted } }); loadDeps();
}
const denseHost = () => document.querySelector('[data-cy-dense]');
function denseAction(act, t) {
  const s = store.get(); const net = activeNetwork(s); const dep = depNow(); const dn = dep.dense; const sel = dep.selection || dep.focus;
  switch (act) {
    case 'dense-layout': denseSet({ layout: t.dataset.v }); break;
    case 'dense-expand': if (net) denseExpandAt(sel); break;
    case 'dense-paths': if (net) denseNavigate(sel); break;
    case 'dense-allpaths': if (dn.paths) denseSet({ visible: [...new Set([...denseVisible(s), ...dn.paths.ids])] }); break;
    case 'dense-back': { const prev = dn.history[dn.history.length - 1]; if (!prev) break; const changed = prev.selection !== dep.selection;
      store.dispatch({ type: 'TAB_STATE', tab: 'dependencies', patch: { selection: prev.selection, dense: { ...dn, visible: prev.visible, layout: prev.layout, view: prev.view, paths: prev.paths, history: dn.history.slice(0, -1) } } }); if (changed) loadDeps(); break; }
    case 'dense-fit': fitAll(denseHost()); break;
    case 'dense-fitsel': fitSelection(denseHost(), sel); break;
    case 'dense-reset': resetView(denseHost(), sel); break;
    case 'dense-arrange': denseSet({ arrange: dn.arrange + 1 }, false); break;
    case 'dense-zoom': zoomBy(denseHost(), Number(t.dataset.f)); break;
    default: break;
  }
}

// ------------------------------------------------------------------ events
const dispatch = (a) => store.dispatch(a);
document.addEventListener('click', (ev) => {
  const t = ev.target.closest('[data-action],[data-nav],[data-info],[data-dep-node],[data-ctx],[data-node]'); if (!t) return;
  const s = store.get(); const d = s.workbench.perTab.dependencies;
  if (t.dataset.nav) { dispatch({ type: 'NAVIGATE', to: t.dataset.nav }); if (t.dataset.nav === 'workbench' || t.id === 'ot-home-brand') window.scrollTo(0, 0); return; }
  if (t.dataset.info) { modal('More information', `<p>${esc(t.dataset.info)}</p>`); return; }
  if (t.dataset.depNode) { dispatch({ type: 'TAB_STATE', tab: 'dependencies', patch: { selection: t.dataset.depNode } }); if (t.dataset.depNode !== d.selection) loadDeps(); return; }
  if (t.dataset.ctx) { dispatch({ type: 'TAB_STATE', tab: 'contexts', patch: { selection: t.dataset.ctx } }); return; }
  if (t.dataset.node) { if (s.gaps.selected) dispatch({ type: 'GAPS_STATE', patch: { selected: null, detail: null } }); dispatch({ type: 'TAB_STATE', tab: s.workbench.tab, patch: { selection: t.dataset.node } }); return; }
  const act = t.dataset.action;
  switch (act) {
    case 'bom-view': switchBomView(t.dataset.view); break;
    case 'bom-filter': bomPatch(bomContextPatch({ filter: t.dataset.filter, offset: 0 })); loadBomQueue(); break;
    case 'bom-select': selectBomCandidate(t.dataset.id); break;
    case 'bom-page': bomPatch({ offset: Math.max(0, s.bom8.offset + 25 * Number(t.dataset.dir)), queue: null }); loadBomQueue(); break;
    case 'bom-group': bomPatch({ group: t.dataset.group, fullOffset: 0, graph: null, selectedRecord: null, related: null }); loadBomGraph(); break;
    case 'bom-full-page': bomPatch({ fullOffset: Math.max(0, s.bom8.fullOffset + 100 * Number(t.dataset.dir)), graph: null }); loadBomGraph(); break;
    case 'bom-record': bomSelectRecord(t.dataset.id); break;
    case 'bom-edge': bomSelectRecord(t.dataset.id); break;
    case 'bom-drawer': bomPatch({ drawer: !s.bom8.drawer }); break;
    case 'bom-related': chooseBomRelated(t.dataset.id); break;
    case 'bom-chooser-page': bomPatch({ chooserOffset: Math.max(0, s.bom8.chooserOffset + 20 * Number(t.dataset.dir)), related: null }); bomSelectRecord(s.bom8.selectedRecord); break;
    case 'bom-fit': { const host = t.closest('.ot-bom8-main,.ot-bom8-popup')?.querySelector('[data-bom-cy]'); if (host) gfit(host); break; }
    case 'bom-expand': bomPatch({ popup: 'graph' }); break;
    case 'bom-close': { const focusId = s.bom8.selectedRecord; bomPatch({ popup: null }); ([...document.querySelectorAll('[data-action="bom-record"]')].find((x) => x.dataset.id === focusId) || document.querySelector('[data-action="bom-expand"]'))?.focus(); break; }
    case 'bom-ask': { const item = bomSelectedItem(s.bom8); if (item) explainSelection(); break; }
    case 'ctx-more': loadContextGroup(t.dataset.group); break;
    case 'ctx-retry': loadContexts(); break;
    case 'ctx-evidence': modal('Repository context evidence', contextEvidenceHtml(store.get()), true); break;
    case 'scan-cancel': cancelScan(); break;
    case 'scan-minimize': dispatch({ type: 'SCAN_UI_CLOSE', epoch: epoch() }); scanReturnFocus(); break;
    case 'scan-reopen': dispatch({ type: 'SCAN_UI_OPEN', epoch: epoch() }); break;
    case 'scan-recheck': recheckScan(); break;
    case 'end': endSession(); break;
    case 'tab': { const tab = t.dataset.tab; dispatch({ type: 'TAB', tab }); openTab(tab); break; }
    case 'gap-inspect': inspectGap(t.dataset.id); break;
    case 'gap-state': dispatch({ type: 'GAPS_STATE', patch: { state: t.dataset.state || null, offset: 0 } }); loadGaps(); break;
    case 'gap-page': { const lim = s.gaps.data?.limit || 25; dispatch({ type: 'GAPS_STATE', patch: { offset: Math.max(0, (s.gaps.data?.offset || 0) + Number(t.dataset.dir) * lim) } }); loadGaps(); break; }
    case 'open-check': { const tab = t.dataset.mode; dispatch({ type: 'TAB', tab }); const chk = 'assertion:' + t.dataset.check; dispatch({ type: 'GAPS_STATE', patch: { selected: null, detail: null } }); dispatch({ type: 'TAB_STATE', tab, patch: { selection: chk } }); if (tab === 'crypto' && !store.get().advanced) cryptoPatch({ checkId: t.dataset.check }); if (tab === 'ai' && !store.get().advanced) aiPatch({ checkId: t.dataset.check }); dispatch({ type: 'NAVIGATE', to: 'workbench' }); openTab(tab); $('ot-graph-frame')?.scrollIntoView({ block: 'start' }); break; }
    case 'open-tab': { const tab = t.dataset.tab; dispatch({ type: 'TAB', tab }); dispatch({ type: 'NAVIGATE', to: 'workbench' }); openTab(tab); window.scrollTo(0, 0); break; }   // Evidence links into an existing Workbench tab
    case 'tab-pres': dispatch({ type: 'TAB_STATE', tab: t.dataset.tab, patch: { presentation: t.dataset.p } }); break;
    case 'dep-pres': depPresent(t.dataset.p); break;
    case 'dep-expand': dispatch({ type: 'TAB_STATE', tab: 'dependencies', patch: { expanded: !d.expanded } }); break;
    case 'dep-stale-reset': depStaleReset(); break;
    case 'list-page': { const size = s.views.dependencies?.component_list?.page_size || 40; dispatch({ type: 'TAB_STATE', tab: 'dependencies', patch: { listOffset: Math.max(0, (s.views.dependencies?.component_list?.offset || 0) + Number(t.dataset.dir) * size) } }); loadDeps(); break; }
    case 'page': { const i = t.dataset.side === 'in' ? 0 : 1; const v = s.views.dependencies; const side = i === 0 ? v.incoming : v.outgoing; const per = s.narrow ? 1 : 6; const off = [...d.offsets]; off[i] = Math.max(0, side.offset + Number(t.dataset.dir) * per); dispatch({ type: 'TAB_STATE', tab: 'dependencies', patch: { offsets: off } }); loadDeps(); break; }
    case 'explore': dispatch({ type: 'DEP_EXPLORE', id: d.selection }); loadDeps(); break;
    case 'dep-explore': if (d.selection) depNode(d.selection); break;
    case 'dep-page': { const off = s.views.depPage?.page.offset || 0; dispatch({ type: 'TAB_STATE', tab: 'dependencies', patch: { gOffset: Math.max(0, off + Number(t.dataset.dir) * PAGE_SIZE) } }); loadDepPage(); break; }
    case 'dep-retry': loadDepPage(); break;
    case 'dep-ctx-retry': loadDepContexts(); break;
    case 'dep-ctx-page': { const ch = s.views.depContexts; if (!ch) break; dispatch({ type: 'TAB_STATE', tab: 'dependencies', patch: { cx: { ...d.cx, offset: Math.max(0, ch.offset + Number(t.dataset.dir) * CHOOSER_PAGE) } } }); loadDepContexts(); break; }
    case 'back': dispatch({ type: 'DEP_BACK' }); loadDeps(); break;
    case 'reset': depZoom.key = ''; dispatch({ type: 'TAB_STATE', tab: 'dependencies', patch: { focus: null, selection: null, offsets: [0, 0], history: [], search: '', listQuery: '', listOffset: 0, dense: freshDense() } }); loadDeps(); break;
    case 'fit': depZoom = { ...depZoom, s: 1, x: 0, y: 0 }; applyZoom(); break;
    case 'zoom': { const f = Number(t.dataset.f); depZoom.s = Math.max(0.4, Math.min(2.5, depZoom.s * f)); applyZoom(); break; }
    case 'gfit': { const host = document.querySelector(`[data-cy="${t.dataset.tab}"]`); if (host) gfit(host); break; }
    case 'pick': { if (s.advanced && activeNetwork(s)) denseNavigate(t.dataset.id); else { dispatch({ type: 'DEP_EXPLORE', id: t.dataset.id }); loadDeps(); } break; }
    case 'adv-package': { dispatch({ type: 'DEP_EXPLORE', id: t.dataset.id }); loadDeps(); $('ot-graph-frame')?.scrollIntoView({ block: 'start' }); break; }
    case 'lookup-state': dispatch({ type: 'LOOKUP_STATE', patch: { state: t.dataset.state || null, page: 0 } }); loadLookup(); break;
    case 'lookup-page': dispatch({ type: 'LOOKUP_STATE', patch: { page: Math.max(0, s.advLookup.page + Number(t.dataset.dir)) } }); loadLookup(); break;
    case 'lookup-evidence': openLookupEvidence(t.dataset.id); break;
    case 'adv-page': { const p = Math.max(0, d.advPage + Number(t.dataset.dir)); dispatch({ type: 'TAB_STATE', tab: 'dependencies', patch: { advPage: p } }); loadDeps(); break; }
    case 'read-advisory': readAdvisory(t.dataset.key, t.dataset.pkg); break;
    case 'drill': { if (t.dataset.dependencyContextId && !s.advanced) { dispatch({ type: 'DEP_CONTEXT', ctxId: t.dataset.dependencyContextId, path: t.dataset.path }); dispatch({ type: 'TAB_STATE', tab: 'dependencies', patch: { presentation: 'graph' } }); dispatch({ type: 'TAB', tab: 'dependencies' }); loadDepPage(); break; } dispatch({ type: 'TAB_STATE', tab: 'dependencies', patch: { context: t.dataset.path, focus: null, selection: null, offsets: [0, 0], history: [], search: '', advPage: 0, listQuery: '', listOffset: 0, dense: freshDense() } }); dispatch({ type: 'TAB', tab: 'dependencies' }); loadDeps(); break; }
    case 'preview': openPreview(t.dataset.name); break;
    case 'record': showRecord(t.dataset.id); break;
    case 'ask': explainSelection(); break;
    case 'a-position': dispatch({ type: 'ASSISTANT', patch: { positionLocked: !s.assistant.positionLocked } }); break;
    case 'a-min': dispatch({ type: 'ASSISTANT', patch: { minimized: !s.assistant.minimized } }); break;
    case 'a-close': dispatch({ type: 'ASSISTANT', patch: { open: false } }); $('ot-assistant-launch').focus(); break;
    case 'a-restore': dispatch({ type: 'ASSISTANT_RESTORE' }); $('ot-assistant-question')?.focus(); break;
    case 'a-retry': { const retry = s.assistant.retry; if (retry && !s.assistant.pending) submitAssistant(retry); break; }
    case 'a-cancel': api('/api/assistant/cancel', { method: 'POST' }).catch(() => {}); break;
    case 'a-citation': openAssistantCitation(t.dataset.context, t.dataset.evidence); break;
    default: if (act && act.startsWith('dense-')) denseAction(act, t); break;
  }
});
// "Explain this": open the assistant on the item selected in the Workbench and ask for a short plain explanation, with no typing. This is the ONLY way the subject of a thread
// changes: a free-form question never adopts the current selection, so clicking another row cannot silently retarget a follow-up.
const EXPLAIN_PROMPT = 'Explain this item to someone who is not a specialist, in two or three plain sentences: what it is and why it matters.';
function explainSelection() {
  const s = store.get(); dispatch({ type: 'ASSISTANT', patch: { open: true, minimized: false } });
  const selection = assistantSelection();
  if (!s.analysis || s.assistant.pending) return;
  if (!selection?.id) { dispatch({ type: 'ASSISTANT', patch: { error: 'Select an item in the Workbench first, then choose “Explain this”.' } }); return; }
  submitAssistant({ ask: EXPLAIN_PROMPT, display: `Explain ${selection.label || 'this item'}`, selection });
}
async function submitAssistant(explain) {
  const s = store.get(); if (!s.analysis || s.assistant.pending) return;
  if (!(explain && explain.selection) && !assistantCanSubmit(s.assistant)) return;     // subject uncertain after a lost "Explain this": free-form questions wait; the typed draft is kept
  const question = explain ? explain.display : s.assistant.draft.trim(); if (!question) return;
  const selection = explain ? explain.selection : null; const adopt = !!selection;     // only "Explain this" adopts a selection; a free-form question (or its retry) never does
  const requestId = crypto.randomUUID(); const e = s.epoch; const generation = s.analysis.generation;
  dispatch({ type: 'ASSISTANT_SUBMIT', requestId, question, keepDraft: !!explain, dropFailed: !!explain?.retry });
  try {
    const response = await api('/api/assistant/ask', { method: 'POST', body: {
      question: explain ? explain.ask : question, generation, adopt_subject: adopt,
      subject: adopt ? { kind: selection.kind, id: selection.id } : null,
    } });
    if (response.clarify) dispatch({ type: 'ASSISTANT_NOTE', epoch: e, requestId, question, note: response.clarify });
    else dispatch({ type: 'ASSISTANT_RESULT', epoch: e, generation, requestId, question, response });
  } catch (err) {
    const failure = err instanceof ApiError ? (err.body?.message || err.code || 'The answer could not be completed.') : 'The assistant service is unavailable.';
    const lost = !(err instanceof ApiError) || err.status === 500;   // a refusal the server reports (4xx, 502, 503) was rolled back before any adoption; only a lost response or an internal error leaves the subject uncertain
    const uncertain = adopt && lost;
    const message = failure;      // the recovery instruction is rendered once from the uncertain state, not repeated in the error
    // "Try again" is offered only for a TEMPORARY busy state. An exhausted allowance, a withheld answer, or any other failure never gets it.
    const temporary = err instanceof ApiError && (err.code === 'broker_busy' || err.code === 'assistant_busy');
    const retry = temporary ? { ask: explain ? explain.ask : question, display: question, selection, retry: true } : null;
    dispatch({ type: 'ASSISTANT_FAILED', epoch: e, requestId, message, question, noRestore: !!explain, adoptionAttempted: uncertain, retry });
  }
}
async function openAssistantCitation(contextId, evidenceId) {
  const s = store.get(); const e = s.epoch; const generation = s.analysis?.generation;
  try {
    const item = await api('/api/assistant/citation?' + qs({ context_id: contextId, evidence_id: evidenceId }));
    if (e !== store.get().epoch || generation !== store.get().analysis?.generation) return;
    modal(item.label, `<p><strong>${esc(item.source.replaceAll('_', ' '))} · ${esc(item.state.replaceAll('_', ' '))}</strong></p><pre class="source-excerpt">${esc(item.excerpt)}</pre>`);
  } catch (err) { if (e !== store.get().epoch || generation !== store.get().analysis?.generation) return; modal('Evidence unavailable', `<p>${esc(err instanceof ApiError ? (err.body?.message || err.code) : 'This citation is no longer available for the current session.')}</p>`); }
}
document.addEventListener('dblclick', (ev) => {
  const t = ev.target.closest('[data-dep-node]'); if (!t) return;
  if (store.get().advanced) { dispatch({ type: 'DEP_EXPLORE', id: t.dataset.depNode }); loadDeps(); return; }
  depNode(t.dataset.depNode);          // UIP-05: the focus changes: Direct, offset 0, search cleared, back on the Graph
});
document.addEventListener('keydown', (ev) => {
  const t = ev.target.closest?.('[data-dep-node]');
  if (t && (ev.key === 'Enter' || ev.key === ' ')) { ev.preventDefault(); dispatch({ type: 'TAB_STATE', tab: 'dependencies', patch: { selection: t.dataset.depNode } }); loadDeps(); }
  const tab = ev.target.closest?.('[role=tab]');
  if (tab && (ev.key === 'ArrowRight' || ev.key === 'ArrowLeft')) { const i = TABS.indexOf(tab.dataset.tab); const n = TABS[(i + (ev.key === 'ArrowRight' ? 1 : TABS.length - 1)) % TABS.length]; dispatch({ type: 'TAB', tab: n }); openTab(n); setTimeout(() => $('ot-tab-' + n)?.focus(), 0); }
  if (ev.key === 'Escape' && store.get().assistant.open && !$('ot-dialog').open && !$('ot-scan-dialog').open) { dispatch({ type: 'ASSISTANT', patch: { open: false } }); $('ot-assistant-launch').focus(); }
  if (ev.key === 'Escape' && store.get().bom8.popup) { ev.preventDefault(); const id = store.get().bom8.selectedRecord; bomPatch({ popup: null }); ([...document.querySelectorAll('[data-action="bom-record"]')].find((x) => x.dataset.id === id) || document.querySelector('[data-action="bom-expand"]'))?.focus(); }
});
document.addEventListener('input', (ev) => {
  const t = ev.target;
  if (t.id === 'ot-assistant-question') dispatch({ type: 'ASSISTANT', patch: { draft: t.value } });
  else if (t.id === 'ot-url') dispatch({ type: 'INTAKE_EDIT', field: 'url', value: t.value });
  else if (t.id === 'ot-commit') dispatch({ type: 'INTAKE_EDIT', field: 'manualSha', value: t.value });
  else if (t.id === 'ot5-search') { depSearchInput(t.value); }
  else if (t.id === 'otai-q') { aiPatch({ q: t.value, offset: 0 }); clearTimeout(aiTimer); aiTimer = setTimeout(loadAiPage, 200); }
  else if (t.id === 'otc-q') { cryptoPatch({ q: t.value, offset: 0 }); clearTimeout(cryptoTimer); cryptoTimer = setTimeout(loadCryptoPage, 200); }
  else if (t.id === 'ot5-ctx-q') { dispatch({ type: 'TAB_STATE', tab: 'dependencies', patch: { cx: { ...depNow().cx, query: t.value, offset: 0 } } }); clearTimeout(ctxTimer); ctxTimer = setTimeout(loadDepContexts, 200); }
  else if (t.id === 'ot-pkg-search') { dispatch({ type: 'TAB_STATE', tab: 'dependencies', patch: { search: t.value } }); runSearch(); }
  else if (t.id === 'ot-list-search') { dispatch({ type: 'TAB_STATE', tab: 'dependencies', patch: { listQuery: t.value, listOffset: 0 } }); clearTimeout(searchTimer); searchTimer = setTimeout(loadDeps, 200); }
  else if (t.id === 'ot-gap-q') { dispatch({ type: 'GAPS_STATE', patch: { q: t.value, offset: 0 } }); clearTimeout(searchTimer); searchTimer = setTimeout(loadGaps, 200); }
  else if (t.id === 'ot-bom8-q') { bomPatch(bomContextPatch({ q: t.value, offset: 0 })); clearTimeout(bomTimer); bomTimer = setTimeout(loadBomQueue, 200); }
  else if (t.id === 'ot-bom8-full-q') { bomPatch({ fullQ: t.value, fullOffset: 0, graph: null }); clearTimeout(bomTimer); bomTimer = setTimeout(loadBomGraph, 200); }
  else if (t.id === 'ot-bom8-chooser-q') { bomPatch({ chooserQ: t.value, chooserOffset: 0, related: null }); clearTimeout(bomTimer); bomTimer = setTimeout(() => bomSelectRecord(store.get().bom8.selectedRecord), 200); }
  else if (t.id === 'ot-lookup-q') { dispatch({ type: 'LOOKUP_STATE', patch: { q: t.value, page: 0 } }); clearTimeout(searchTimer); searchTimer = setTimeout(loadLookup, 200); }
  else if (t.id === 'ot-adv-q') { dispatch({ type: 'TAB_STATE', tab: 'dependencies', patch: { advQuery: t.value, advPage: 0 } }); clearTimeout(searchTimer); searchTimer = setTimeout(loadDeps, 200); }
  else if (t.id === 'ot-prev-q') { /* handled by the preview dialog */ }
});
document.addEventListener('change', (ev) => {
  if (ev.target.matches('.ot-assistant-adopt input')) { dispatch({ type: 'ASSISTANT', patch: { adoptNext: ev.target.checked } }); return; }
  if (ev.target.id === 'ot-assistant-relationship') { dispatch({ type: 'ASSISTANT', patch: { subjectChoice: ev.target.value || null } }); return; }
  if (ev.target.id === 'otai-group') { aiPatch({ group: ev.target.value || null, offset: 0 }); loadAiPage(); return; }
  if (ev.target.id === 'otc-group') { cryptoPatch({ group: ev.target.value || null, offset: 0 }); loadCryptoPage(); return; }
  if (ev.target.id === 'ot5-context') { const o = ev.target.selectedOptions[0]; if (!o || !ev.target.value) return; dispatch({ type: 'DEP_CONTEXT', ctxId: ev.target.value, path: o.dataset.path }); loadDepPage(); }
  else if (ev.target.id === 'ot-context') { dispatch({ type: 'TAB_STATE', tab: 'dependencies', patch: { context: ev.target.value, focus: null, selection: null, offsets: [0, 0], history: [], advPage: 0, search: '', listQuery: '', listOffset: 0, dense: freshDense() } }); loadDeps(); }
  else if (ev.target.id === 'ot-dense-view') { const net = activeNetwork(store.get()); if (!net) return; const v = ev.target.value; const dep = depNow(); denseSet(v === 'full' ? { view: 'full', visible: allIds(net), paths: null } : { view: 'explore', visible: initialVisible(net, dep.selection || dep.focus, 8), paths: null }); }
});
document.addEventListener('submit', (ev) => {
  if (ev.target.id === 'ot-assistant-form') { ev.preventDefault(); submitAssistant(); return; }
  if (ev.target.id !== 'ot-form') return; ev.preventDefault();
  if (scanGate(store.get()).enabled) startScan();     // one click: no review step, no second confirmation; blocked while a scan runs or is unavailable
});
$('ot-advanced').addEventListener('change', (ev) => {
  store_.set('oecl.ui.advanced', String(ev.target.checked)); dispatch({ type: 'ADVANCED', value: ev.target.checked });
  if (ev.target.checked) { const tb = store.get().workbench.tab; if ((tb === 'crypto' || tb === 'ai') && !store.get().views[tb]) loadSimple(tb); return; }   // UIP-06: Advanced shows the generic family surface
  if (store.get().workbench.tab === 'crypto') ensureCryptoPage();
  if (store.get().workbench.tab === 'ai') ensureAiPage();
  // UIP-05: back on the normal view, reload only what no longer matches the state (nothing is requested when it still does).
  const cur = store.get(); const dd = cur.workbench.perTab.dependencies; const v = cur.views.dependencies; const pg = cur.views.depPage;
  if (dd.focus && (!v || (v.context_path || null) !== (dd.context || null) || v.focus?.id !== dd.focus)) loadDeps();
  if (pg && dd.focus && dd.focus !== pg.focus.node_id) loadDepPage();
});
$('ot-theme').addEventListener('click', () => { const v = store.get().theme === 'dark' ? 'light' : 'dark'; store_.set('oecl.ui.theme', v); dispatch({ type: 'THEME', value: v }); });
$('ot-about').addEventListener('click', () => modal('How OpenTrace works', ABOUT, true));
$('ot-demo').addEventListener('click', () => openAnalysis());
$('ot-top-end').addEventListener('click', endSession);
$('ot-assistant-launch').addEventListener('click', () => dispatch({ type: 'ASSISTANT', patch: { open: !store.get().assistant.open, minimized: false } }));
// Move the assistant by dragging its header (unless pinned).
let drag = null;
document.addEventListener('pointerdown', (ev) => { const h = ev.target.closest('#ot-assistant-handle'); if (!h || ev.target.closest('button') || store.get().assistant.positionLocked) return; const r = $('ot-assistant').getBoundingClientRect(); drag = { dx: ev.clientX - r.left, dy: ev.clientY - r.top }; h.setPointerCapture(ev.pointerId); });
document.addEventListener('pointermove', (ev) => { if (!drag) return; const x = Math.max(0, Math.min(innerWidth - 120, ev.clientX - drag.dx)); const y = Math.max(0, Math.min(innerHeight - 60, ev.clientY - drag.dy)); dispatch({ type: 'ASSISTANT', patch: { position: { x, y } } }); });
document.addEventListener('pointerup', () => { drag = null; });
// Wheel zoom + drag pan on the dependency SVG (presentation only).
document.addEventListener('wheel', (ev) => { const svg = ev.target.closest?.('#ot-dep-svg'); if (!svg) return; ev.preventDefault(); depZoom.s = Math.max(0.4, Math.min(2.5, depZoom.s * Math.exp(-ev.deltaY * 0.0015))); applyZoom(); }, { passive: false });
let pan = null;
document.addEventListener('pointerdown', (ev) => { const svg = ev.target.closest?.('#ot-dep-svg'); if (!svg || ev.target.closest('[data-dep-node]')) return; pan = { x: ev.clientX - depZoom.x, y: ev.clientY - depZoom.y }; });
document.addEventListener('pointermove', (ev) => { if (!pan) return; depZoom.x = ev.clientX - pan.x; depZoom.y = ev.clientY - pan.y; applyZoom(); });
document.addEventListener('pointerup', () => { pan = null; });
attachDependencyGraph(store.get, { filter: (key) => { dispatch({ type: 'TAB_STATE', tab: 'dependencies', patch: { filter: key, gOffset: 0 } }); loadDepPage(); }, explore: (id) => depNode(id), collapse: () => { dispatch({ type: 'TAB_STATE', tab: 'dependencies', patch: { expanded: false } }); $('ot5-expand')?.focus(); } });   // focus returns to the Expand control   // UIP-05
attachCryptoGraph(store.get, {
  select: cryptoSelect,
  filter: (key) => { cryptoPatch({ filter: key, offset: 0 }); loadCryptoPage(); },                         // a filter change refits the view and keeps a valid selection (the reducer resolves it)
  present: (p) => cryptoPatch({ presentation: p }),
  expand: () => { const c = store.get().workbench.perTab.crypto; cryptoPatch({ expanded: !c.expanded }); if (c.expanded) $('otc-expand')?.focus(); },
  collapse: cryptoCollapse,
  page: (dir) => { const pg = store.get().views.cryptoPage; if (!pg) return; cryptoPatch({ offset: Math.max(0, pg.page.offset + dir * CRYPTO_PAGE) }); loadCryptoPage(); },
  retry: () => loadCryptoPage(),
  closeCheck: () => cryptoPatch({ checkId: null }),
  staleReset: () => { dispatchEnded('gone'); closeDialog(); },                                            // the old analysis is closed locally; the person reopens it
});   // UIP-06
attachAiGraph(store.get, {
  select: aiSelect,
  filter: (key) => { aiPatch({ filter: key, offset: 0 }); loadAiPage(); },
  present: (p) => aiPatch({ presentation: p }),
  expand: () => { const c = store.get().workbench.perTab.ai; aiPatch({ expanded: !c.expanded }); if (c.expanded) $('otai-expand')?.focus(); },
  collapse: aiCollapse,
  page: (dir) => { const pg = store.get().views.aiPage; if (!pg) return; aiPatch({ offset: Math.max(0, pg.page.offset + dir * CRYPTO_PAGE) }); loadAiPage(); },
  retry: () => loadAiPage(),
  closeCheck: () => aiPatch({ checkId: null }),
  staleReset: () => { dispatchEnded('gone'); closeDialog(); },
});   // UIP-07
window.addEventListener('resize', () => { if (store.get().analysis && store.get().workbench.tab === 'dependencies') remeasure(store.get, render); });
attachEvidenceStrip();
attachContextMap(store.get);      // UIP-04: map pan/zoom/keyboard/focus handlers (document level, attached once)
// Crossing the narrow breakpoint changes the neighborhood size (one per side), a presentation request.
window.matchMedia(NARROW).addEventListener('change', (ev) => { dispatch({ type: 'NARROW', value: ev.matches }); if (store.get().analysis) loadDeps(); });

// Live scanning is opt-in on the service; the page only learns whether it is enabled.
api('/api/config').then((c) => { rawConfig = { ok: true, live: c.live || null }; dispatch({ type: 'CONFIG', live: c.live }); dispatch({ type: 'CONFIG_RAW', ok: true, live: rawConfig.live }); }).catch(() => { rawConfig = { ok: false, live: null }; dispatch({ type: 'CONFIG_RAW', ok: false }); });

render();
