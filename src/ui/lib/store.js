// One state object, reducers only (architecture §11). Views are cached per generation; a response
// from an older epoch/generation never reaches the state.
import { freshScan, applyEnvelope } from './scan_model.js';
import { mergeFiles, selectionValid } from './context_map.js';
import { DEFAULT_FILTER, requestKey, chooserKey, legacyKey } from './dependency_graph.js';
import { DEFAULT_FILTER as CRYPTO_FILTER, requestKey as cryptoKey, resolveSelection as cryptoResolve } from './crypto_graph.js';
import { DEFAULT_FILTER as AI_FILTER, requestKey as aiKey, resolveSelection as aiResolve } from './ai_graph.js';
export const TABS = ['contexts', 'dependencies', 'crypto', 'ai', 'bom'];
export const TAB_LABEL = { contexts: 'Repository contexts', dependencies: 'Dependencies', crypto: 'Cryptography', ai: 'AI models', bom: 'BOM connections' };
export const DEFAULT_CONTEXT = 'web/package-lock.json';

export const freshDense = () => ({ view: 'explore', layout: 'flow', visible: null, history: [], paths: null, arrange: 0 });
export const assistantCanSubmit = (assistant) => !assistant.adoptionUncertain || assistant.adoptNext;

// UIP-04: request bookkeeping for the contexts map. `latest` holds the newest issued seq per (kind, group); the merged payload itself
// lives in views.contexts. Everything here is cleared by freshWorkbench (ANALYSIS_START) and by ENDED (initial values).
export const freshCtxMap = () => ({ status: 'idle', error: null, latest: { full: 0 }, groups: {} });
export const ctxKey = (kind, group) => (kind === 'full' ? 'full' : 'g:' + group);
// A contexts response (success or error) may only act if it still describes the current epoch and generation AND is the newest
// request issued for its (kind, group). Anything else is discarded with no state change.
export const ctxCurrent = (s, a) => a.epoch === s.epoch && !!s.analysis && a.generation === s.analysis.generation
  && a.seq === (s.workbench.perTab.contexts.map.latest[ctxKey(a.kind, a.group)] ?? 0);
const withCtxMap = (s, map, views) => ({ ...s, views: views || s.views, workbench: { ...s.workbench, perTab: { ...s.workbench.perTab, contexts: { ...s.workbench.perTab.contexts, map } } } });

// UIP-05: request bookkeeping for the Dependencies page and the context chooser. The payloads live in views.depPage / views.depContexts;
// everything here is cleared by freshWorkbench (ANALYSIS_START), END_STARTED and ENDED.
// `pg.req` / `cx.req` = the identity of the one request whose response may still apply ({seq, key, intent}); a response that does not match it,
// or whose key no longer describes the state, is dropped (UIP-05-IR-02). `stale` = a current 409 retired the dependency payloads (IR-03);
// `expanded` = the expanded graph (UIP-05 §6 / UIP-COMMON C5).
export const freshDepState = () => ({ ctxId: null, filter: DEFAULT_FILTER, q: '', gOffset: 0, stale: false, expanded: false, pg: { status: 'idle', error: null, req: null }, cx: { offset: 0, query: '', status: 'idle', error: null, req: null } });
export const freshDepSeq = () => ({ page: 0, ctx: 0 });   // newest issued seq per request kind (kept outside `latest`, whose shape existing tests pin)

// A dependency response acts only while its identity is still the one recorded at request time AND still describes the state (IR-02).
const depBase = (s, a) => a.epoch === s.epoch && !!s.analysis && a.generation === s.analysis.generation && !s.workbench.perTab.dependencies.stale;
const depPageCurrent = (s, a) => {
  if (!depBase(s, a) || a.seq !== s.depSeq.page) return false;
  const d = s.workbench.perTab.dependencies; const r = d.pg.req;
  return !!r && r.seq === a.seq && r.key === a.key && a.key === requestKey(d) && (r.intent !== 'active' || d.presentation === 'graph');
};
const depCtxCurrent = (s, a) => {
  if (!depBase(s, a) || a.seq !== s.depSeq.ctx) return false;
  const d = s.workbench.perTab.dependencies; const r = d.cx.req;
  return !!r && r.seq === a.seq && r.key === a.key && a.key === chooserKey(d);
};
// IR-03: retire everything keyed by the dead generation; the analysis itself keeps its generation (the server's newer one is never adopted).
const retireDependencies = (s) => {
  const { depPage: _p, depContexts: _c, dependencies: _d, ...views } = s.views; const d = s.workbench.perTab.dependencies;
  return { ...s, views, depSeq: { ...s.depSeq }, workbench: { ...s.workbench, perTab: { ...s.workbench.perTab, dependencies: { ...d, stale: true, pg: { status: 'idle', error: null, req: null }, cx: { ...d.cx, status: 'idle', error: null, req: null } } } } };
};

// UIP-06: Cryptography tab state. `selection` is the legacy rule-check selection (Advanced / generic family view); `sel` is the crypto_assets/1
// selection (an `asset:`, `group:` or `root` key). The payload lives in views.cryptoPage; `loaded` is the key of the request whose page is cached.
// Everything here is cleared by freshWorkbench (ANALYSIS_START), END_STARTED and ENDED. `pg.req` = the one request whose response may still apply.
export const freshCrypto = (narrow) => ({ selection: null, presentation: narrow ? 'list' : 'graph', sel: null, selUser: false, checkId: null, filter: CRYPTO_FILTER, q: '', group: null, offset: 0, stale: false, expanded: false, loaded: null, pg: { status: 'idle', error: null, req: null } });
const cryptoBase = (s, a) => a.epoch === s.epoch && !!s.analysis && a.generation === s.analysis.generation && !s.workbench.perTab.crypto.stale;
const cryptoCurrent = (s, a) => {
  if (!cryptoBase(s, a) || a.seq !== s.cryptoSeq) return false;
  const c = s.workbench.perTab.crypto; const r = c.pg.req;
  return !!r && r.seq === a.seq && r.key === a.key && a.key === cryptoKey(c);
};
// UIP-07: AI models tab state, the same shape and lifecycle as the Cryptography tab (`sel` is the ai_assets/1 selection; the payload lives in views.aiPage;
// `checkId` is a requested BOM-verification check shown above the assets). Cleared by freshWorkbench (ANALYSIS_START), END_STARTED and ENDED.
export const freshAi = (narrow) => ({ selection: null, presentation: narrow ? 'list' : 'graph', sel: null, selUser: false, checkId: null, filter: AI_FILTER, q: '', group: null, offset: 0, stale: false, expanded: false, loaded: null, pg: { status: 'idle', error: null, req: null } });
const aiBase = (s, a) => a.epoch === s.epoch && !!s.analysis && a.generation === s.analysis.generation && !s.workbench.perTab.ai.stale;
const aiCurrent = (s, a) => {
  if (!aiBase(s, a) || a.seq !== s.aiSeq) return false;
  const c = s.workbench.perTab.ai; const r = c.pg.req;
  return !!r && r.seq === a.seq && r.key === a.key && a.key === aiKey(c);
};
const withAi = (s, patch, views) => ({ ...s, views: views || s.views, workbench: { ...s.workbench, perTab: { ...s.workbench.perTab, ai: { ...s.workbench.perTab.ai, ...patch } } } });
const withCrypto = (s, patch, views) => ({ ...s, views: views || s.views, workbench: { ...s.workbench, perTab: { ...s.workbench.perTab, crypto: { ...s.workbench.perTab.crypto, ...patch } } } });

// UIP-08: all BOM v1 payloads and request identities are generation-scoped.
export const freshBom8 = () => ({ view: 'gaps', filter: 'all', q: '', offset: 0, selected: null, selectedRecord: null,
  group: 'all', fullOffset: 0, drawer: false, popup: null, chooserQ: '', chooserOffset: 0,
  queue: null, graph: null, related: null, error: null, stale: false,
  detail: null, detailError: null,   // UIP-12-IR-04: the evidence detail (existing /api/view/gap payload) of the SELECTED candidate; never another candidate's
  pin: null,                  // UIP08-IR-01: an explicit, bounded chooser selection that may lie outside the queue page/filter; never auto-replaced
  tlife: 0, plife: 0,         // UIP08-IR-03: monotonic tab / popup-dismissal lifetimes; both are part of every request key
  req: { queue: null, graph: null, related: null, detail: null }, seq: { queue: 0, graph: 0, related: 0, detail: 0 } });
// UIP08-IR-01/02: shared by the handlers and the tests. A queue-context change (search, filter, family view) clears every selection-dependent field.
export const bomClear = () => ({ selected: null, selectedRecord: null, related: null, graph: null, detail: null, detailError: null, pin: null, drawer: false });
export const bomContextPatch = (extra) => ({ ...extra, ...bomClear(), queue: null });
// Choosing a related check records exactly the chosen ID plus the bounded display fields of the chooser row (no new lookup, no ID rewriting).
export const bomRelatedPatch = (b, id) => {
  const it = b.related?.items?.find((x) => x.item_id === id) || {};
  return { selected: id, selectedRecord: null, related: null, view: 'gaps', graph: null, detail: null, detailError: null, popup: null, chooserQ: '', chooserOffset: 0,
    pin: { item_id: id, assertion_id: it.assertion_id ?? null, display_name: it.display_name ?? id, family: it.family ?? 'other', state: it.state ?? 'unknown_coverage', location: it.location ?? null } };
};
// The selected candidate: the queue row when listed, else the explicitly pinned chooser row (marked partial: rule/inventory facts are not loaded for it).
export const bomSelectedItem = (b) => {
  const row = b.queue?.items?.find((x) => x.item_id === b.selected);
  if (row) return row;
  const p = b.pin; if (!p || p.item_id !== b.selected) return null;
  return { item_id: p.item_id, assertion_id: p.assertion_id, display: { name: p.display_name, raw_title: p.display_name }, state: p.state, category: p.family, location: p.location, inventory: null, rule_id: null, graph_state: null, partial: true };
};
// UIP08-BR-02: the offline guide's BOM context. A pinned (out-of-list) candidate keeps its recorded state and assertion ID; only the inventory/rule
// details are unloaded, so that is stated instead of claiming that no rule verdict exists. Nothing is invented: no rule ID, inventory or verdict.
export const bomAssistantContext = (b) => {
  const item = bomSelectedItem(b); if (!item) return null;
  const recorded = item.partial && !!item.assertion_id && item.state !== 'unknown_coverage';
  return { title: item.display.name, cite: [item.item_id, item.assertion_id, item.rule_id, item.inventory?.inventory_id].filter(Boolean),
    meaning: `${item.display.raw_title}. The bound comparison recorded ${item.state.replaceAll('_', ' ')}${item.inventory ? ' against ' + item.inventory.generator : ''}.`,
    limits: item.graph_state === 'assertion_graph' ? 'The inventory check does not establish installation, runtime use or completeness beyond its recorded scope.'
      : recorded ? `The bound comparison recorded ${item.state.replaceAll('_', ' ')} for this assertion; its inventory and rule details are not loaded for this list. This does not establish installation, runtime use or completeness beyond its recorded scope.`
      : 'More evidence is needed; no rule verdict or completeness conclusion is established.',
    next: 'Inspect the recorded graph, source location and inventory identity for this candidate.' };
};
// A post-response callback may act only when the reducer actually accepted this payload for the visible BOM tab.
const bomNoError = (b) => { if (!('errorKind' in b)) return b; const { errorKind, errorStatus, ...rest } = b; return rest; };
export const bomAccepted = (s, kind, data) => s.workbench.tab === 'bom' && s.bom8[kind] === data;
const bomFamily = (v) => ({ software: 'software', crypto: 'cryptography', ai: 'ai_model' })[v] || null;
export const bomKey = (b, kind) => kind === 'queue'
  ? JSON.stringify([b.view, bomFamily(b.view), b.filter, b.q, b.offset, b.tlife])
  : kind === 'detail' ? JSON.stringify(['detail', b.selected, b.tlife])
  : kind === 'graph' ? JSON.stringify([b.view, b.view === 'full' ? b.group : b.selected, b.view === 'full' ? b.fullOffset : 0, b.view === 'full' ? b.fullQ : '', b.tlife])
  : JSON.stringify([b.popup, b.selectedRecord, b.chooserQ, b.chooserOffset, b.tlife, b.plife]);
export const freshLookup = () => ({ state: null, q: '', page: 0, data: null, error: null, seq: 0 });
export const freshGaps = () => ({ state: null, q: '', offset: 0, data: null, error: null, seq: 0, selected: null, detail: null, detailError: null, detailSeq: 0 });

export const freshWorkbench = (narrow) => ({
  tab: 'contexts',
  perTab: {
    contexts: { selection: 'root', presentation: narrow ? 'list' : 'graph', map: freshCtxMap() },   // UIP-04 (FR-7): opens on the repository root
    dependencies: { context: DEFAULT_CONTEXT, focus: null, selection: null, offsets: [0, 0], history: [], search: '', presentation: 'graph', advPage: 0, advQuery: '', listQuery: '', listOffset: 0, dense: freshDense(), ...freshDepState() },
    crypto: freshCrypto(narrow),
    ai: freshAi(narrow),
    bom: { selection: null, presentation: narrow ? 'list' : 'graph' },
  },
});

export const freshScanUi = () => ({ active: false, open: false });

export const initial = ({ advanced = false, theme = 'light', narrow = false } = {}) => ({
  epoch: 0,
  session: { id: null, generation: null, status: 'none', cleanup: null },
  destination: 'analyze',
  intake: { url: '', manualSha: '', state: 'untouched', error: '', errorField: null, preview: null },
  advanced, theme, narrow,
  analysis: null,
  live: null,           // /api/config live block (enabled, allowlist, scanners, isolation)
  config: { state: 'unknown', live: null },   // UIP-03: the RAW /api/config live block (a disabled service stays {enabled:false}); `live` above is unchanged
  scan: freshScan(),    // UIP-03: the one-click scan job (frozen scan_status/1 via scan_job_response/1)
  scanUi: freshScanUi(),  // scan-progress modal presentation only: `active` = a scan was started in this epoch; `open` = the dialog is showing (else the compact control is)
  workbench: freshWorkbench(narrow),
  depSeq: freshDepSeq(),  // UIP-05 request ledger
  cryptoSeq: 0,           // UIP-06 request ledger (newest issued crypto_assets seq)
  aiSeq: 0,               // UIP-07 request ledger (newest issued ai_assets seq)
  views: {},            // tab -> payload (current generation only)
  network: null,        // scope node/edge arrays for Advanced dense exploration (current epoch only)
  latest: { deps: 0, network: 0, search: 0 }, // newest request id per kind: older responses are discarded
  search: null,         // dependency search result
  evidence: { artifacts: [], records: [], preview: null },
  advLookup: freshLookup(),   // live advisory lookup table (I5B): filter, search, page, current-generation payload
  bom8: freshBom8(),          // UIP-08 versioned BOM workspace; current generation only
  gaps: freshGaps(),          // candidate gaps (I8): filter, search, page, selected candidate and its evidence; current generation only
  assistant: { open: false, minimized: false, positionLocked: false, position: null, turns: [], draft: '', pending: false, pendingQuestion: null, failedQuestion: null, retry: null, error: null, adoptNext: false, adoptionUncertain: false, subject: null, subjectChoice: null, requestId: null },
  ended: null, busy: null, notice: null,
});

// A response may only land if it is the newest request of its kind AND still describes the selected context.
const ctxOf = (s) => s.workbench.perTab.dependencies.context || null;
const isLatest = (s, kind, seq) => seq === undefined || seq === s.latest[kind];

export function reducer(s, a) {
  switch (a.type) {
    case 'NAVIGATE': return s.analysis || a.to === 'analyze' ? { ...s, destination: a.to } : s;
    case 'ADVANCED': {
      // Presentation only. The manual SHA is removed from the request state with the field (DEV-01).
      let intake = s.intake;
      if (!a.value && (intake.manualSha || intake.preview?.manual)) {
        intake = { ...intake, manualSha: '', preview: intake.preview?.manual ? null : intake.preview, state: intake.preview?.manual ? 'stale' : intake.state };
      }
      let dep = s.workbench.perTab.dependencies;
      // UIP-05: Advanced may have moved the legacy context/focus; the normal view is keyed by its own context id, so leaving Advanced returns to it.
      const pg = s.views.depPage;
      if (!a.value && pg && pg.context.context_id === dep.ctxId && dep.context !== pg.context.path) dep = { ...dep, context: pg.context.path, focus: pg.focus.node_id, selection: pg.focus.node_id };
      const perTab = { ...s.workbench.perTab, dependencies: { ...dep, dense: freshDense(), expanded: false }, crypto: { ...s.workbench.perTab.crypto, expanded: false }, ai: { ...s.workbench.perTab.ai, expanded: false } };
      return { ...s, advanced: a.value, intake, workbench: { ...s.workbench, perTab } };
    }
    case 'THEME': return { ...s, theme: a.value };
    case 'NARROW': return { ...s, narrow: a.value };
    case 'INTAKE_EDIT': return { ...s, intake: { ...s.intake, [a.field]: a.value, preview: null, error: '', errorField: null, state: 'untouched' } };
    case 'CONFIG': return { ...s, live: a.live && a.live.enabled ? a.live : null };
    case 'CONFIG_RAW': return { ...s, config: a.ok ? { state: 'loaded', live: a.live || null } : { state: 'failed', live: null } };
    case 'SCAN_BEGIN': return { ...s, scan: { ...freshScan(), epoch: a.epoch, generation: a.generation } };
    case 'SCAN_RESPONSE': { const scan = applyEnvelope(s.scan, a.envelope, a.epoch); return scan === s.scan ? s : { ...s, scan }; }
    case 'SCAN_ERROR': return a.epoch !== s.epoch ? s : { ...s, scan: { ...s.scan, error: a.message || null, errorKind: a.message ? (a.kind || null) : null } };
    case 'SCAN_CLEAR': return { ...s, scan: freshScan() };
    // Presentation only; every action is bound to the epoch so a late call can never reopen the dialog for a retired or replaced session.
    case 'SCAN_UI_BEGIN': return a.epoch !== s.epoch ? s : { ...s, scanUi: { active: true, open: true } };
    case 'SCAN_UI_OPEN': return a.epoch !== s.epoch || !s.scanUi.active || s.scanUi.open ? s : { ...s, scanUi: { active: true, open: true } };
    case 'SCAN_UI_CLOSE': return !s.scanUi.open || (a.epoch !== undefined && a.epoch !== s.epoch) ? s : { ...s, scanUi: { active: s.scanUi.active, open: false } };
    case 'INTAKE_STATE': return { ...s, intake: { ...s.intake, ...a.patch } };
    case 'SESSION': {
      const changed = a.patch.id && s.session.id && a.patch.id !== s.session.id;
      return { ...s, session: { ...s.session, ...a.patch }, assistant: changed ? { ...s.assistant, turns: [], draft: '', pending: false, pendingQuestion: null, failedQuestion: null, retry: null, error: null, subject: null, subjectChoice: null, requestId: null, adoptNext: false, adoptionUncertain: false } : s.assistant };
    }
    case 'ANALYSIS_START': {
      const epoch = s.epoch + 1;
      return { ...s, epoch, busy: 'analysis', scanUi: freshScanUi(), views: {}, network: null, search: null, latest: { deps: 0, network: 0, search: 0 }, depSeq: freshDepSeq(), cryptoSeq: 0, aiSeq: 0, ended: null, notice: null,
        assistant: { ...s.assistant, turns: [], draft: '', pending: false, pendingQuestion: null, failedQuestion: null, error: null, adoptNext: false, adoptionUncertain: false, subject: null, subjectChoice: null, requestId: null },
        workbench: freshWorkbench(s.narrow), evidence: { artifacts: [], records: [], preview: null }, advLookup: freshLookup(), bom8: freshBom8(), gaps: freshGaps() };
    }
    case 'ANALYSIS_READY': return a.epoch !== s.epoch ? s : { ...s, busy: null, scanUi: freshScanUi(), analysis: a.analysis, destination: 'workbench',
      // The Frigate default context does not exist in a live repository: start from all contexts (null).
      workbench: a.analysis.identity?.mode === 'live' ? { ...s.workbench, perTab: { ...s.workbench.perTab, dependencies: { ...s.workbench.perTab.dependencies, context: null } } } : s.workbench,
      session: { ...s.session, generation: a.analysis.generation, status: 'active' } };
    case 'ANALYSIS_FAILED': return a.epoch !== s.epoch ? s : { ...s, busy: null, notice: a.message };
    case 'REQUEST': return a.seq > s.latest[a.kind] ? { ...s, latest: { ...s.latest, [a.kind]: a.seq } } : s;
    case 'BOM_PATCH': {
      const b = s.bom8, nb = { ...b, ...a.patch };
      // UIP08-IR-03: dismissing or replacing an open popup retires its earlier related request even if the visible key later recurs.
      if ('popup' in a.patch && b.popup !== null && a.patch.popup !== b.popup) { nb.plife = b.plife + 1; nb.req = { ...nb.req, related: null }; }
      return { ...s, bom8: nb };
    }
    case 'BOM_REQUEST': {
      if (a.epoch !== s.epoch || !s.analysis || a.generation !== s.analysis.generation || s.bom8.stale || a.seq <= s.bom8.seq[a.kind]) return s;
      const b = s.bom8;
      if (a.kind === 'detail') return { ...s, bom8: { ...b, detail: null, detailError: null, seq: { ...b.seq, detail: a.seq }, req: { ...b.req, detail: { seq: a.seq, key: a.key } } } };   // does not clear a queue/graph error
      return { ...s, bom8: { ...bomNoError(b), error: null, seq: { ...b.seq, [a.kind]: a.seq }, req: { ...b.req, [a.kind]: { seq: a.seq, key: a.key } } } };
    }
    case 'BOM_LOADED':
    case 'BOM_FAILED': {
      const b = s.bom8, r = b.req[a.kind];
      if (a.epoch !== s.epoch || !s.analysis || a.generation !== s.analysis.generation || s.workbench.tab !== 'bom' || b.stale || !r || r.seq !== a.seq || r.key !== a.key || a.key !== bomKey(b, a.kind)) return s;
      if (a.type === 'BOM_FAILED') {
        if (a.status === 409) return { ...s, bom8: { ...freshBom8(), stale: true, error: 'This comparison belongs to an ended session.' } };
        // UIP-12-IR-04: a failed evidence detail is shown in the inspector for that candidate only; it does not replace the queue/graph or hide their errors.
        if (a.kind === 'detail') return { ...s, bom8: { ...b, detail: null, detailError: a.error || 'The evidence could not be loaded.', req: { ...b.req, detail: null } } };
        // UIP-10-F1: a graph request refused (404) because the authoritative queue says nothing was compared is the expected answer, not an unavailable endpoint.
        if (a.kind === 'graph' && a.status === 404 && b.queue && b.queue.mode !== 'discovery_compared') return { ...s, bom8: { ...b, req: { ...b.req, graph: null } } };
        return { ...s, bom8: { ...b, error: a.error || 'The BOM view is unavailable.', errorKind: a.kind, errorStatus: a.status ?? null, req: { ...b.req, [a.kind]: null } } };
      }
      if (a.data?.binding?.analysis_digest !== s.analysis.identity?.analysis_digest) return s;
      const patch = { [a.kind]: a.data, req: { ...b.req, [a.kind]: null }, error: null };
      if (a.kind === 'queue' && !(b.pin && b.pin.item_id === b.selected)) {
        const items = a.data.items || [];
        if (!items.length) Object.assign(patch, bomClear());                                       // UIP08-IR-02: zero matches leave no old candidate state
        else if (!items.some((x) => x.item_id === b.selected)) Object.assign(patch, { selected: items[0].item_id, graph: null, selectedRecord: null, related: null, detail: null, detailError: null, pin: null });
      }
      return { ...s, bom8: { ...bomNoError(b), ...patch } };
    }
    case 'VIEW_LOADED': {
      if (a.epoch !== s.epoch || !s.analysis || a.generation !== s.analysis.generation) return s; // stale: discard
      if (a.tab === 'dependencies' && (!isLatest(s, 'deps', a.seq) || (a.data.context_path || null) !== ctxOf(s))) return s;
      if (a.tab === 'ai' && s.workbench.perTab.ai.stale) return s;   // UIP-07 IR-03: a retired AI generation is never restored by a late legacy response (also Advanced)
      if (a.tab === 'dependencies' && s.workbench.perTab.dependencies.stale) return s;   // IR-03: retired dependency state is never restored by an older legacy response
      if (a.tab === 'dependencies' && a.key !== undefined && a.key !== legacyKey(s.workbench.perTab.dependencies)) return s;   // IR-02: the request no longer describes focus/selection/query/offset
      return { ...s, views: { ...s.views, [a.tab]: a.data } };
    }
    case 'DEP_CONTEXT': {   // UIP-05: a different source context replaces everything keyed by the old one (focus, filter, offsets, search, payloads)
      const d = s.workbench.perTab.dependencies; const { depPage: _p, dependencies: _d, ...views } = s.views;
      return { ...s, views, workbench: { ...s.workbench, perTab: { ...s.workbench.perTab, dependencies: { ...d, ctxId: a.ctxId, context: a.path, focus: null, selection: null, offsets: [0, 0], history: [], advPage: 0, search: '', listQuery: '', listOffset: 0,
        dense: freshDense(), filter: DEFAULT_FILTER, gOffset: 0, q: '', pg: { status: 'idle', error: null, req: null } } } } };
    }
    case 'DEPPAGE_REQUEST': {
      if (a.epoch !== s.epoch || !s.analysis || a.generation !== s.analysis.generation || a.seq <= s.depSeq.page) return s;
      const d = s.workbench.perTab.dependencies; if (d.stale) return s;
      return { ...s, depSeq: { ...s.depSeq, page: a.seq }, workbench: { ...s.workbench, perTab: { ...s.workbench.perTab, dependencies: { ...d, pg: { status: 'loading', error: null, req: { seq: a.seq, key: a.key, intent: a.intent } } } } } };
    }
    case 'DEPPAGE_LOADED': {
      if (!depPageCurrent(s, a)) return s;
      const d = s.workbench.perTab.dependencies;
      if (a.data?.binding?.analysis_digest !== s.analysis.identity?.analysis_digest) return s;
      const patch = { pg: { status: 'idle', error: null, req: null }, context: a.data.context.path, gOffset: a.data.page.offset };
      if (!d.focus) { patch.focus = a.data.focus.node_id; patch.selection = d.selection || a.data.focus.node_id; }
      return { ...s, views: { ...s.views, depPage: a.data }, workbench: { ...s.workbench, perTab: { ...s.workbench.perTab, dependencies: { ...d, ...patch } } } };
    }
    case 'DEPPAGE_FAILED': {
      if (!depPageCurrent(s, a)) return s;
      if (a.status === 409) return retireDependencies(s);                  // a CURRENT stale generation: retire the payloads, show the recovery (IR-03)
      const d = s.workbench.perTab.dependencies; const empty = a.error?.code === 'not_found';
      const { depPage: _drop, ...views } = s.views;
      return { ...s, views: empty ? views : s.views, workbench: { ...s.workbench, perTab: { ...s.workbench.perTab, dependencies: { ...d, pg: { status: empty ? 'empty' : 'error', error: a.error || { code: 'request_failed' }, req: d.pg.req } } } } };
    }
    case 'DEPCTX_REQUEST': {
      if (a.epoch !== s.epoch || !s.analysis || a.generation !== s.analysis.generation || a.seq <= s.depSeq.ctx) return s;
      const d = s.workbench.perTab.dependencies; if (d.stale) return s;
      return { ...s, depSeq: { ...s.depSeq, ctx: a.seq }, workbench: { ...s.workbench, perTab: { ...s.workbench.perTab, dependencies: { ...d, cx: { ...d.cx, status: 'loading', error: null, req: { seq: a.seq, key: a.key } } } } } };
    }
    case 'DEPCTX_LOADED': {
      if (!depCtxCurrent(s, a)) return s;
      if (a.data?.binding?.analysis_digest !== s.analysis.identity?.analysis_digest) return s;
      const d = s.workbench.perTab.dependencies; const patch = { cx: { ...d.cx, offset: a.data.offset, status: 'idle', error: null, req: null } };
      if (!d.ctxId) { if (a.data.default_context_id) patch.ctxId = a.data.default_context_id; else patch.pg = { status: 'empty', error: null, req: null }; }   // the default comes from the complete set, never from loaded rows
      return { ...s, views: { ...s.views, depContexts: a.data }, workbench: { ...s.workbench, perTab: { ...s.workbench.perTab, dependencies: { ...d, ...patch } } } };
    }
    case 'DEPCTX_FAILED': {
      if (!depCtxCurrent(s, a)) return s;
      if (a.status === 409) return retireDependencies(s);
      const d = s.workbench.perTab.dependencies;
      return { ...s, workbench: { ...s.workbench, perTab: { ...s.workbench.perTab, dependencies: { ...d, cx: { ...d.cx, status: 'error', error: a.error || { code: 'request_failed' }, req: d.cx.req } } } } };
    }
    case 'CRYPTO_REQUEST': {
      if (a.epoch !== s.epoch || !s.analysis || a.generation !== s.analysis.generation || a.seq <= s.cryptoSeq) return s;
      const c = s.workbench.perTab.crypto; if (c.stale) return s;
      return { ...withCrypto(s, { pg: { status: 'loading', error: null, req: { seq: a.seq, key: a.key } } }), cryptoSeq: a.seq };
    }
    case 'CRYPTO_LOADED': {
      if (!cryptoCurrent(s, a)) return s;
      if (a.data?.binding?.analysis_digest !== s.analysis.identity?.analysis_digest) return s;
      const c = s.workbench.perTab.crypto;
      // a fallback selection (root on an empty page) upgrades to the first asset once assets arrive; a selection the person made is kept while it is valid
      return withCrypto(s, { sel: cryptoResolve(a.data, c.selUser ? c.sel : null), loaded: a.key, pg: { status: 'idle', error: null, req: null } }, { ...s.views, cryptoPage: a.data });
    }
    case 'CRYPTO_FAILED': {
      if (!cryptoCurrent(s, a)) return s;
      if (a.status === 409) {          // a CURRENT stale generation: retire the payload and show the recovery; the newer generation is never adopted
        const { cryptoPage: _gone, ...views } = s.views;
        return withCrypto(s, { stale: true, expanded: false, loaded: null, pg: { status: 'idle', error: null, req: null } }, views);
      }
      return withCrypto(s, { pg: { status: 'error', error: a.error || { code: 'request_failed' }, req: s.workbench.perTab.crypto.pg.req } });
    }
    case 'AI_REQUEST': {
      if (a.epoch !== s.epoch || !s.analysis || a.generation !== s.analysis.generation || a.seq <= s.aiSeq) return s;
      const c = s.workbench.perTab.ai; if (c.stale) return s;
      return { ...withAi(s, { pg: { status: 'loading', error: null, req: { seq: a.seq, key: a.key } } }), aiSeq: a.seq };
    }
    case 'AI_LOADED': {
      if (!aiCurrent(s, a)) return s;
      if (a.data?.binding?.analysis_digest !== s.analysis.identity?.analysis_digest) return s;
      const c = s.workbench.perTab.ai;
      return withAi(s, { sel: aiResolve(a.data, c.selUser ? c.sel : null), loaded: a.key, pg: { status: 'idle', error: null, req: null } }, { ...s.views, aiPage: a.data });
    }
    case 'AI_FAILED': {
      if (!aiCurrent(s, a)) return s;
      if (a.status === 409) {          // a CURRENT stale generation: retire the payload and show the recovery; the newer generation is never adopted
        const { aiPage: _gone, ai: _legacy, ...views } = s.views;   // IR-03: the cached legacy AI view (Advanced) is retired with it
        return withAi(s, { stale: true, expanded: false, loaded: null, pg: { status: 'idle', error: null, req: null } }, views);
      }
      return withAi(s, { pg: { status: 'error', error: a.error || { code: 'request_failed' }, req: s.workbench.perTab.ai.pg.req } });
    }
    case 'CTX_REQUEST': {
      if (a.epoch !== s.epoch || !s.analysis || a.generation !== s.analysis.generation) return s;
      const m = s.workbench.perTab.contexts.map; const key = ctxKey(a.kind, a.group);
      if (a.seq <= (m.latest[key] ?? 0)) return s;
      const next = { ...m, latest: { ...m.latest, [key]: a.seq } };
      if (a.kind === 'full') { if (!s.views.contexts) { next.status = 'loading'; next.error = null; } }
      else next.groups = { ...m.groups, [a.group]: { state: 'loading', error: null } };
      return withCtxMap(s, next);
    }
    case 'CTX_LOADED': {
      if (!ctxCurrent(s, a) || a.data?.binding?.analysis_digest !== s.analysis.identity?.analysis_digest) return s;
      const prev = s.views.contexts; const same = !!prev && prev.binding.analysis_digest === a.data.binding.analysis_digest;
      let model;
      if (a.kind === 'full') {
        const groups = a.data.groups.map((g) => { const old = same ? prev.groups.find((x) => x.group_id === g.group_id) : null; return { ...g, files: old ? mergeFiles(old.files, g.files, g.files_offset) : g.files }; });
        model = { schema: a.data.schema, binding: a.data.binding, root: a.data.root, counts: a.data.counts, groups, edge_semantics: a.data.edge_semantics };
      } else {
        const g = a.data.groups[0]; if (!same || !g) return s;
        model = { ...prev, binding: a.data.binding, root: a.data.root,
          groups: prev.groups.map((x) => (x.group_id === g.group_id ? { ...g, files: mergeFiles(x.files, g.files, g.files_offset) } : x)) };
      }
      const m = s.workbench.perTab.contexts.map;
      const map = a.kind === 'full' ? { ...m, status: 'ready', error: null } : { ...m, status: 'ready', groups: { ...m.groups, [a.group]: { state: 'idle', error: null } } };
      const out = withCtxMap(s, map, { ...s.views, contexts: model });
      const c = out.workbench.perTab.contexts;     // a selection that no longer exists falls back to the root (never to a stale record)
      return selectionValid(model, c.selection) ? out : { ...out, workbench: { ...out.workbench, perTab: { ...out.workbench.perTab, contexts: { ...c, selection: 'root' } } } };
    }
    case 'CTX_FAILED': {
      if (!ctxCurrent(s, a)) return s;
      const m = s.workbench.perTab.contexts.map;
      return withCtxMap(s, a.kind === 'full' ? { ...m, status: s.views.contexts ? m.status : 'unavailable', error: a.error || { code: 'request_failed' } }
        : { ...m, groups: { ...m.groups, [a.group]: { state: 'error', error: a.error || { code: 'request_failed' } } } });
    }
    case 'LOOKUP_STATE': return { ...s, advLookup: { ...s.advLookup, ...a.patch } };
    case 'LOOKUP_LOADED': {   // a stale epoch/generation or an older request never reaches the state
      if (a.epoch !== s.epoch || !s.analysis || a.generation !== s.analysis.generation || a.seq !== s.advLookup.seq) return s;
      return { ...s, advLookup: { ...s.advLookup, data: a.data, error: null } };
    }
    case 'GAPS_STATE': return { ...s, gaps: { ...s.gaps, ...a.patch } };
    case 'GAPS_LOADED': {   // a stale epoch/generation or an older request never reaches the state
      if (a.epoch !== s.epoch || !s.analysis || a.generation !== s.analysis.generation || a.seq !== s.gaps.seq) return s;
      return { ...s, gaps: { ...s.gaps, data: a.data, error: null } };
    }
    case 'GAPS_FAILED': return a.epoch !== s.epoch || a.seq !== s.gaps.seq ? s : { ...s, gaps: { ...s.gaps, data: null, error: a.message } };
    case 'GAP_DETAIL_LOADED': {
      if (a.epoch !== s.epoch || !s.analysis || a.generation !== s.analysis.generation || a.seq !== s.gaps.detailSeq) return s;
      return { ...s, gaps: { ...s.gaps, detail: a.data.candidate, detailError: null } };
    }
    case 'GAP_DETAIL_FAILED': return a.epoch !== s.epoch || a.seq !== s.gaps.detailSeq ? s : { ...s, gaps: { ...s.gaps, detail: null, detailError: a.message } };
    case 'LOOKUP_FAILED':
      return a.epoch !== s.epoch || a.seq !== s.advLookup.seq ? s : { ...s, advLookup: { ...s.advLookup, data: null, error: a.message } };
    case 'NETWORK_LOADED':
      if (a.epoch !== s.epoch || !s.analysis || a.generation !== s.analysis.generation) return s;
      if (!isLatest(s, 'network', a.seq) || (a.network.context_path || null) !== ctxOf(s)) return s;
      return { ...s, network: a.network };
    case 'SEARCH_LOADED':
      if (a.epoch !== s.epoch || !isLatest(s, 'search', a.seq) || (a.context !== undefined && (a.context || null) !== ctxOf(s))) return s;
      return { ...s, search: a.search };
    case 'EVIDENCE_LOADED': return a.epoch !== s.epoch ? s : { ...s, evidence: { ...s.evidence, ...a.patch } };
    case 'PREVIEW': return { ...s, evidence: { ...s.evidence, preview: a.preview } };
    case 'TAB': {
      // A tab switch replaces selection details (UI-F08): other tabs keep only their own valid selection.
      const leaving = s.workbench.tab === 'bom' && a.tab !== 'bom';       // UIP08-IR-03: leaving the BOM tab retires every in-flight BOM request
      return { ...s, workbench: { ...s.workbench, tab: a.tab }, bom8: leaving ? { ...s.bom8, tlife: s.bom8.tlife + 1, req: { queue: null, graph: null, related: null, detail: null } } : s.bom8 };
    }
    case 'TAB_STATE': {
      let patch = a.patch;
      if (a.tab === 'dependencies' && patch.presentation === 'list') {     // IR-02: a Graph request issued for the Graph view is superseded by leaving it (a preload is kept)
        const d = s.workbench.perTab.dependencies;
        if (d.pg.status === 'loading' && d.pg.req?.intent === 'active') patch = { ...patch, pg: { status: 'idle', error: null, req: null } };
      }
      const per = { ...s.workbench.perTab, [a.tab]: { ...s.workbench.perTab[a.tab], ...patch } };
      return { ...s, workbench: { ...s.workbench, perTab: per } };
    }
    case 'DEP_EXPLORE': {
      const d = s.workbench.perTab.dependencies;
      const history = d.focus ? [...d.history, { focus: d.focus, selection: d.selection, offsets: d.offsets }].slice(-20) : d.history;
      return reducer(s, { type: 'TAB_STATE', tab: 'dependencies', patch: { focus: a.id, selection: a.id, offsets: [0, 0], history, search: '', dense: freshDense(), filter: DEFAULT_FILTER, gOffset: 0, q: '', listQuery: '', listOffset: 0 } });
    }
    case 'DEP_BACK': {
      const d = s.workbench.perTab.dependencies; const prev = d.history[d.history.length - 1];
      if (!prev) return s;
      return reducer(s, { type: 'TAB_STATE', tab: 'dependencies', patch: { focus: prev.focus, selection: prev.selection, offsets: prev.offsets, history: d.history.slice(0, -1), dense: freshDense() } });
    }
    case 'ASSISTANT': return { ...s, assistant: { ...s.assistant, ...a.patch } };
    case 'ASSISTANT_SUBMIT': {
      // The question moves from the composer into the transcript immediately; the composer is empty for the next draft while the answer is pending.
      return { ...s, assistant: { ...s.assistant, pending: true, error: null, requestId: a.requestId, pendingQuestion: a.question, failedQuestion: null, retry: null, draft: a.keepDraft ? s.assistant.draft : '',
        turns: a.dropFailed && s.assistant.turns.at(-1)?.error ? s.assistant.turns.slice(0, -1) : s.assistant.turns } };   // a retried temporary failure replaces its failed turn
    }
    case 'ASSISTANT_NOTE': {
      // The server asked which item is meant (no model call was made): show it as a plain reply; the typed draft is untouched.
      if (a.epoch !== s.epoch || a.requestId !== s.assistant.requestId) return s;
      return { ...s, assistant: { ...s.assistant, pending: false, pendingQuestion: null, failedQuestion: null, retry: null, error: null, requestId: null,
        turns: [...s.assistant.turns, { question: a.question, note: a.note }] } };
    }
    case 'ASSISTANT_RESTORE': {
      // Put a failed question back WITHOUT overwriting a newer draft: it goes after the draft, separated by a blank line.
      const q = s.assistant.failedQuestion; if (!q) return s;
      const draft = s.assistant.draft.trim() ? s.assistant.draft.replace(/\s+$/, '') + '\n\n' + q : q;
      return { ...s, assistant: { ...s.assistant, draft, failedQuestion: null } };
    }
    case 'ASSISTANT_RESULT': {
      if (a.epoch !== s.epoch || !s.analysis || a.generation !== s.analysis.generation || a.requestId !== s.assistant.requestId) return s;
      return { ...s, assistant: { ...s.assistant, pending: false, pendingQuestion: null, failedQuestion: null, retry: null, error: null, subject: a.response.subject || s.assistant.subject,
        turns: [...s.assistant.turns, { question: a.question, response: a.response, subjectLabel: a.response.subject?.label || s.assistant.subject?.label || 'Whole repository analysis' }], requestId: null, adoptNext: false, adoptionUncertain: false } };
    }
    case 'ASSISTANT_FAILED': {
      if (a.epoch !== s.epoch || a.requestId !== s.assistant.requestId) return s;
      const message = a.message || 'The answer could not be completed.'; const q = a.question || s.assistant.pendingQuestion;
      const draftFree = !s.assistant.draft.trim();           // an empty composer gets the question back at once; a newer draft is never overwritten
      const restorable = q && !a.noRestore && !a.retry;                  // an "Explain this" request has no typed question to give back
      return { ...s, assistant: { ...s.assistant, pending: false, pendingQuestion: null, error: q ? null : message, requestId: null, adoptNext: false,
        turns: q ? [...s.assistant.turns, { question: q, error: message }] : s.assistant.turns, draft: restorable && draftFree ? q : s.assistant.draft,
        failedQuestion: restorable && !draftFree ? q : null, adoptionUncertain: a.adoptionAttempted ? true : s.assistant.adoptionUncertain, retry: a.retry || null } };
    }
    case 'END_STARTED': {
      // The retired map must not stay usable while the end request is in flight: drop the Contexts payload, selection, paging and
      // request ledger now (the epoch advance also makes every in-flight contexts response stale). Everything else clears at ENDED.
      const c = s.workbench.perTab.contexts; const { contexts: _gone, depPage: _p, depContexts: _c, dependencies: _d, cryptoPage: _cp, aiPage: _ap, ...views } = s.views;
      const dep = s.workbench.perTab.dependencies;     // UIP-05: the Dependencies payloads, selection, offsets and request ledger go too (their epoch is stale)
      return { ...s, epoch: s.epoch + 1, busy: 'ending', scanUi: freshScanUi(), views, depSeq: freshDepSeq(), cryptoSeq: 0, aiSeq: 0, bom8: freshBom8(),
        assistant: { ...s.assistant, turns: [], draft: '', pending: false, pendingQuestion: null, failedQuestion: null, retry: null, error: null, subject: null, subjectChoice: null, requestId: null, adoptNext: false, adoptionUncertain: false },
        workbench: { ...s.workbench, perTab: { ...s.workbench.perTab, contexts: { ...c, selection: 'root', map: freshCtxMap() },
          dependencies: { ...dep, focus: null, selection: null, offsets: [0, 0], history: [], search: '', listQuery: '', listOffset: 0, dense: freshDense(), ...freshDepState() },
          crypto: { ...freshCrypto(s.narrow), presentation: s.workbench.perTab.crypto.presentation },
          ai: { ...freshAi(s.narrow), presentation: s.workbench.perTab.ai.presentation } } } };   // UIP-07: the AI payload, selection, paging, request ledger and expanded view go now   // UIP-06: payload, selection, paging, request ledger and expanded view go now
    }
    case 'ENDED': {
      // Everything session-scoped is cleared; only presentation preferences survive.
      return { ...initial({ advanced: s.advanced, theme: s.theme, narrow: s.narrow }), epoch: s.epoch + 1, ended: a.state,
        assistant: { ...s.assistant, turns: [], draft: '', pending: false, pendingQuestion: null, failedQuestion: null, retry: null, adoptNext: false, adoptionUncertain: false } };
    }
    default: return s;
  }
}

export function createStore(state) {
  let current = state; const subs = new Set();
  return {
    get: () => current,
    dispatch(action) { const next = reducer(current, action); if (next !== current) { current = next; subs.forEach((f) => f(current, action)); } },
    subscribe(fn) { subs.add(fn); return () => subs.delete(fn); },
  };
}
