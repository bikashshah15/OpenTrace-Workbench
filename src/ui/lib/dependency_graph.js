// UIP-05: pure model of the Dependencies focus graph (no DOM). Constants and rules are ported from the approved reference
// (friendlyModel / friendlyDraw / friendlyCaption / friendlyInit in OpenTrace-UI-Update-9-Combined.html).
// The input is a validated opentrace.workbench.dependency_page/1 payload; nothing here infers a path or an edge.
export const NODE_W = 160;
export const NODE_H = 64;
export const STEP_X = 190;
export const STEP_Y = 108;
export const ROOT_Y = 64;
export const TOP_START = 190;
export const MIN_COLS = 2;
export const MAX_COLS = 6;
export const PAGE_SIZE = 30;
export const DEFAULT_FILTER = 'direct';           // FD-3: the reference opens a focus on Direct
export const CHOOSER_PAGE = 40;

// key = the reference's data-friendly-filter, payload = the frozen request/payload enum value.
export const FILTERS = [
  { key: 'all', payload: 'all', label: 'All', caption: 'Dependencies', title: 'All reachable dependencies of the focused package.' },
  { key: 'advisory', payload: 'advisory', label: 'Advisory matches', caption: 'Advisory matches', title: 'Reachable packages with a captured advisory match. Connecting packages remain visible.' },
  { key: 'direct', payload: 'direct', label: 'Direct', caption: 'Direct dependencies', title: 'Packages one recorded dependency edge from the focused package.' },
  { key: 'transitive', payload: 'transitive', label: 'Transitive', caption: 'Transitive dependencies', title: 'Packages whose shortest recorded path from the focused package is two or more edges. Connecting packages remain visible.' },
  { key: 'gaps', payload: 'evidence_gaps', label: 'Evidence gaps', caption: 'Evidence gaps', title: 'Reachable packages missing a source location or a completed supported advisory query.' },
];
export const FILTER_BY_PAYLOAD = Object.fromEntries(FILTERS.map((f) => [f.payload, f]));
export const payloadFilter = (key) => (FILTERS.find((f) => f.key === key) || FILTERS.find((f) => f.key === DEFAULT_FILTER)).payload;
export const keyFilter = (payload) => (FILTER_BY_PAYLOAD[payload] || FILTER_BY_PAYLOAD[payloadFilter(DEFAULT_FILTER)]).key;

// columns = clamp(floor((stage width - 48) / 160), 2, 6) (reference friendlyDraw)
export const columnsFor = (stageWidth) => Math.max(MIN_COLS, Math.min(MAX_COLS, Math.floor(((Number(stageWidth) || 0) - 48) / 160)));

// Card text wraps inside the 146px label width of the reference (text-max-width) at about 25 characters per line, at most two name lines.
export function wrapLabel(text, width = 25, maxLines = 2) {
  let rest = String(text ?? ''); const lines = [];
  while (rest && lines.length < maxLines) {
    if (rest.length <= width) { lines.push(rest); rest = ''; break; }
    const seg = rest.slice(0, width); const m = Math.max(seg.lastIndexOf('/'), seg.lastIndexOf('-'), seg.lastIndexOf('_'), seg.lastIndexOf('.'));
    const cut = m >= width - 10 ? m + 1 : width; lines.push(rest.slice(0, cut)); rest = rest.slice(cut);
  }
  if (rest) lines[lines.length - 1] = lines[lines.length - 1].slice(0, width - 1) + '\u2026';
  return lines.length ? lines : [''];
}
export const truncate = (text, n = 32) => { const t = String(text ?? ''); return t.length > n ? t.slice(0, n - 2) + '…' : t; };

// Parent used for layout order: the first recorded edge (edges are sorted by from,to) that enters a node from the previous depth.
export function parentMap(page) {
  const depth = new Map(page.nodes.map((n) => [n.node_id, n.depth]));
  const parent = new Map();
  for (const e of page.edges) {
    if (parent.has(e.to)) continue;
    if (depth.get(e.from) === depth.get(e.to) - 1) parent.set(e.to, e.from);
  }
  return parent;
}

// Reference order: the focus, then for each shown match in page order the node itself and then its ancestors (until one is visible).
export function visibleOrder(page) {
  const focus = page.focus.node_id; const parent = parentMap(page); const order = [focus]; const seen = new Set(order);
  const byId = new Map(page.nodes.map((n) => [n.node_id, n]));
  for (const m of page.nodes.filter((n) => n.role === 'match')) {
    for (let at = m.node_id; at && !seen.has(at) && byId.has(at); at = parent.get(at)) { seen.add(at); order.push(at); }
  }
  for (const n of page.nodes) if (!seen.has(n.node_id)) { seen.add(n.node_id); order.push(n.node_id); }   // e.g. a match whose path was omitted
  return order;
}

// Depth-banded layout (reference geometry). Returns node boxes, edge paths and the content size; positions are node centres.
export function layoutPage(page, stageWidth) {
  const columns = columnsFor(stageWidth); const width = columns * STEP_X;
  const byId = new Map(page.nodes.map((n) => [n.node_id, n]));
  const order = visibleOrder(page); const focus = page.focus.node_id;
  const pos = new Map([[focus, { x: width / 2, y: ROOT_Y }]]);
  const levels = new Map();
  for (const id of order) { if (id === focus) continue; const d = byId.get(id).depth; if (!levels.has(d)) levels.set(d, []); levels.get(d).push(id); }
  let top = TOP_START;
  for (const d of [...levels.keys()].sort((a, b) => a - b)) {
    const ids = levels.get(d);
    ids.forEach((id, i) => pos.set(id, { x: 95 + (i % columns) * STEP_X, y: top + Math.floor(i / columns) * STEP_Y }));
    top += Math.ceil(ids.length / columns) * STEP_Y + 46;
  }
  const nodes = order.map((id) => ({ id, node: byId.get(id), ...pos.get(id) }));
  // Elbow route of the reference: leave the parent below its box, run to the target's left gutter, drop to the target's mid-height.
  const edges = page.edges.filter((e) => pos.has(e.from) && pos.has(e.to)).map((e) => {
    const a = pos.get(e.from); const b = pos.get(e.to); const gx = b.x - 98; const by = a.y + 52;
    return { id: e.edge_id, from: e.from, to: e.to, d: `M${a.x} ${a.y + NODE_H / 2} V${by} H${gx} V${b.y} H${b.x - NODE_W / 2}` };
  });
  return { columns, width, height: top + 50, nodes, edges };
}

// Stage height in CSS px for a stage of `stageWidth` px (reference: min 570, max 1800, scaled by the fit zoom).
export function stageHeight(layout, stageWidth) {
  const zoom = Math.min(1, Math.max(0.25, ((Number(stageWidth) || layout.width) - 48) / layout.width));
  return Math.round(Math.min(1800, Math.max(570, layout.height * zoom)));
}

export function nodeClass(node, selected) {
  const c = ['ot5-node'];
  if (node.role === 'focus') c.push('root');
  else if (node.depth === 1) c.push('direct');
  if (node.role === 'connector') c.push('connector');
  if (node.advisory_lookup === 'match') c.push('matched');
  if (node.flags.evidence_gap) c.push('gap');
  if (selected) c.push('chosen');
  return c.join(' ');
}

export function captionText(page, focusName) {
  const f = FILTER_BY_PAYLOAD[page.filter]; const shown = page.page.matches_shown; const total = page.page.matches_total;
  const connectors = page.nodes.filter((n) => n.role === 'connector').length;
  const omitted = page.nodes.filter((n) => n.role === 'match' && n.path_state !== 'complete').length;
  let t = `${f.caption} of ${focusName} · ${shown} of ${total} packages`;
  if (connectors) t += ` · ${connectors} connecting packages`;
  if (omitted) t += ` · ${omitted} without a drawn path`;
  return t + '.';
}
export const rangeText = (p) => (p.matches_total ? `${p.range_first}–${p.range_last} of ${p.matches_total}` : '0 of 0');
export const emptyText = (page) => `No ${FILTER_BY_PAYLOAD[page.filter].caption.toLowerCase()} recorded for this package in the selected source context.`;

// A request key; a response is applied only when it still describes the current request (the store also checks seq/epoch/generation).
export const requestKey = (dep) => JSON.stringify([dep.ctxId, dep.focus || null, payloadFilter(dep.filter), dep.q || '', dep.gOffset || 0]);
export const pageKey = (page) => JSON.stringify([page.context.context_id, page.focus.node_id, page.filter, page.query, page.page.offset]);
// Does a cached page describe the request the current state would make? (IR-01: Graph/List share q, so a cached page can go stale in List.)
export const pageMatches = (page, dep) => !!page && pageKey(page) === requestKey(dep);
// Chooser request identity and legacy (inspector / Component list / Advanced) request identity (IR-02).
export const chooserKey = (dep) => JSON.stringify([dep.cx.query || '', dep.cx.offset || 0]);
export const legacyKey = (dep) => JSON.stringify([dep.context || null, dep.focus || null, dep.selection || null, dep.presentation === 'list' ? [dep.listQuery || '', dep.listOffset || 0] : null, dep.offsets, dep.advQuery || '', dep.advPage || 0]);
// Does a page request still need to be issued for the current state? A cached page for the current key, a request in flight for it, or a
// failure for it (manual "Try again" only, never an automatic retry) all mean no.
export function pageNeeded(page, dep) {
  if (dep.stale || !dep.ctxId) return false;
  if (pageMatches(page, dep)) return false;
  const key = requestKey(dep); const r = dep.pg.req;
  if (dep.pg.status === 'empty') return false;
  if ((dep.pg.status === 'loading' || dep.pg.status === 'error') && r && r.key === key) return false;
  return true;
}

// Chooser option bookkeeping: the current context always has an option even when its page is not loaded.
export function chooserOptions(chooser, page, dep) {
  const rows = chooser?.rows || [];
  if (dep.ctxId && !rows.some((r) => r.context_id === dep.ctxId)) {
    const path = page?.context?.context_id === dep.ctxId ? page.context.path : dep.context;
    if (path) return [{ context_id: dep.ctxId, path, components_total: null, current: true }, ...rows];
  }
  return rows;
}

// Keyboard move between graph nodes in reading order (Arrow keys / Home / End).
export function nodeTarget(ids, current, key) {
  const i = ids.indexOf(current); if (i < 0 || !ids.length) return null;
  if (key === 'Home') return ids[0]; if (key === 'End') return ids[ids.length - 1];
  const step = key === 'ArrowDown' || key === 'ArrowRight' ? 1 : key === 'ArrowUp' || key === 'ArrowLeft' ? -1 : 0; if (!step) return null;
  return ids[Math.max(0, Math.min(ids.length - 1, i + step))];
}
