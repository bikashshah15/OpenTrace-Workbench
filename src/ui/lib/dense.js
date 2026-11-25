// Advanced dependency exploration (UI-F05): presentation-only views over the scope's already
// loaded node/edge arrays. Nothing here requests data; it never changes findings or provenance.
import { libs, getElk, css } from './graphs.js';

export const FULL_LIMIT = 600;     // largest scope loaded as "Full context"
export const BATCH = 8;            // Expand dependencies adds this many branches at a time
export const PATH_CAP = 80;

const cache = new WeakMap();
export function index(net) {
  let x = cache.get(net);
  if (x) return x;
  const byId = new Map(net.nodes.map((n) => [n.id, n]));
  const out = new Map(); const inc = new Map();
  for (const [a, b] of net.edges) {
    const A = net.nodes[a].id; const B = net.nodes[b].id;
    if (!out.has(A)) out.set(A, []); out.get(A).push(B);
    if (!inc.has(B)) inc.set(B, []); inc.get(B).push(A);
  }
  const name = (id) => byId.get(id).name || '';
  for (const list of out.values()) list.sort((p, q) => name(p).localeCompare(name(q)) || p.localeCompare(q));
  const roots = net.nodes.filter((n) => !(inc.get(n.id) || []).length)
    .sort((p, q) => (out.get(q.id) || []).length - (out.get(p.id) || []).length || (p.name || '').localeCompare(q.name || '')).map((n) => n.id);
  x = { byId, out, inc, roots }; cache.set(net, x);
  return x;
}
export const children = (net, id) => index(net).out.get(id) || [];
export const canFull = (net) => net.nodes.length <= FULL_LIMIT;

function bfs(net, id, next) {
  const seen = new Set([id]); const q = [id];
  for (let i = 0; i < q.length; i++) for (const x of next(q[i])) if (!seen.has(x)) { seen.add(x); q.push(x); }
  return seen;
}
export const ancestors = (net, id) => bfs(net, id, (x) => index(net).inc.get(x) || []);
export const descendants = (net, id) => bfs(net, id, (x) => index(net).out.get(x) || []);

// Introduction paths: every node on a declared path from a graph root to the package, plus the shortest one.
export function pathSet(net, id) {
  const ix = index(net); const anc = ancestors(net, id);
  const roots = ix.roots.filter((r) => anc.has(r));
  const paths = new Set([id]);
  for (const root of roots) {
    const q = [root]; const seen = new Set(q);
    for (let i = 0; i < q.length; i++) { paths.add(q[i]); for (const to of ix.out.get(q[i]) || []) if (anc.has(to) && !seen.has(to)) { seen.add(to); q.push(to); } }
  }
  const queue = [id]; const next = new Map(); const seen = new Set(queue); const rootSet = new Set(roots); let closest = null;
  for (let i = 0; i < queue.length; i++) {
    const at = queue[i]; if (rootSet.has(at)) { closest = at; break; }
    for (const parent of ix.inc.get(at) || []) if (!seen.has(parent)) { seen.add(parent); next.set(parent, at); queue.push(parent); }
  }
  const shortest = []; for (let at = closest; at; at = next.get(at)) { shortest.push(at); if (at === id) break; }
  return { paths, rooted: roots.length > 0, shortest };
}

export const initialVisible = (net, focus, n = 6) => (focus ? [focus, ...children(net, focus).slice(0, n)] : []);
export const allIds = (net) => net.nodes.map((n) => n.id);
export const visibleEdges = (net, visible) => { const v = new Set(visible); let c = 0; for (const [a, b] of net.edges) if (v.has(net.nodes[a].id) && v.has(net.nodes[b].id)) c++; return c; };

const label = (net, id, visible) => {
  const n = index(net).byId.get(id) || { name: id, version: null, advisory: false }; const hidden = children(net, id).filter((c) => !visible.has(c)).length;
  const name = n.name || '';
  return `${name.length > 29 ? name.slice(0, 27) + '…' : name}\n${n.version || 'Version not reported'}\n${hidden ? `+${hidden} deps${n.advisory ? ' · advisory match' : ''}` : n.advisory ? 'Advisory match' : ''}`;
};
const styles = (layout) => [
  { selector: 'node', style: { shape: layout === 'network' ? 'ellipse' : 'round-rectangle', width: layout === 'network' ? 26 : 196, height: layout === 'network' ? 26 : 70, 'background-color': css('--graph-node'), 'border-width': 1.2, 'border-color': css('--graph-edge'), label: 'data(label)', 'text-wrap': 'wrap', 'text-max-width': 180, 'font-size': 12, color: css('--ink'), 'text-valign': layout === 'network' ? 'bottom' : 'center', 'text-halign': 'center', 'min-zoomed-font-size': 7 } },
  { selector: 'node.related', style: { 'border-color': css('--dep-path'), 'border-width': 2 } },
  { selector: 'node.match', style: { 'border-color': css('--dep-match'), 'border-width': 2.5 } },
  { selector: 'node.chosen', style: { 'border-color': css('--dep-selected'), 'border-width': 3, 'background-color': css('--dep-selected-soft'), 'min-zoomed-font-size': 0 } },
  { selector: 'edge', style: { width: 1.4, 'line-color': css('--graph-edge'), 'target-arrow-color': css('--graph-edge'), 'target-arrow-shape': 'triangle', 'arrow-scale': 0.7, 'curve-style': 'bezier', opacity: 0.5 } },
  { selector: 'edge.path', style: { width: 2.8, 'line-color': css('--dep-path'), 'target-arrow-color': css('--dep-path'), opacity: 1 } },
  { selector: 'node.dim', style: { opacity: 0.5 } }, { selector: 'edge.dim', style: { opacity: 0.12 } },
];

function highlight(cy, net, selected) {
  const anc = ancestors(net, selected); const desc = descendants(net, selected);
  cy.batch(() => {
    cy.elements().removeClass('related chosen dim path');
    cy.nodes().forEach((n) => { const id = n.id(); if (id === selected) n.addClass('chosen'); else if (anc.has(id) || desc.has(id)) n.addClass('related'); else n.addClass('dim'); });
    cy.edges().forEach((e) => { const a = e.source().id(); const b = e.target().id(); if ((anc.has(a) && anc.has(b)) || (desc.has(a) && desc.has(b))) e.addClass('path'); else e.addClass('dim'); });
  });
}

// Rebuild only when the visible set, layout or arrange counter changes; otherwise just re-highlight.
export async function syncDense(host, { net, visible, selected, layout, arrange, onSelect, onExpand, onBusy }) {
  await libs();
  const vis = new Set(visible);
  const sig = [layout, arrange, visible.length, visible.join('|')].join('#');
  host._onSelect = onSelect; host._onExpand = onExpand;
  if (!host._cy || host._sig !== sig) {
    const token = (host._token = (host._token || 0) + 1);
    host._sig = sig;
    onBusy?.(true);
    if (host._cy) host._cy.destroy();
    const ix = index(net);
    const cy = window.cytoscape({ container: host, elements: [], style: styles(layout), minZoom: 0.08, maxZoom: 2.5, boxSelectionEnabled: false, selectionType: 'single' });
    host._cy = cy;
    const nodes = visible.map((id) => ({ data: { id, label: label(net, id, vis) }, classes: ix.byId.get(id).advisory ? 'match' : '' }));
    const edges = []; for (const [a, b] of net.edges) { const A = net.nodes[a].id; const B = net.nodes[b].id; if (vis.has(A) && vis.has(B)) edges.push({ data: { id: 'e' + edges.length, source: A, target: B } }); }
    cy.add(nodes); cy.add(edges);
    cy.on('tap', 'node', (e) => host._onSelect?.(e.target.id()));
    cy.on('dbltap', 'node', (e) => host._onExpand?.(e.target.id()));
    host.setAttribute('role', 'application');
    host.setAttribute('aria-label', 'Interactive dependency explorer. Drag the background to pan, scroll or pinch to zoom. The component list is a keyboard-accessible alternative.');
    try {
      if (layout === 'network') {
        cy.nodes().forEach((n, i) => { const a = i * 2.399963229728653; n.position({ x: Math.cos(a) * Math.sqrt(i + 1) * 90, y: Math.sin(a) * Math.sqrt(i + 1) * 90 }); });
        cy.layout({ name: 'cose', animate: false, fit: false, randomize: false, numIter: nodes.length > 800 ? 150 : 350, nodeRepulsion: () => 5000, idealEdgeLength: () => 70, gravity: 0.4, componentSpacing: 80 }).run();
      } else {
        const graph = { id: 'root', layoutOptions: { 'elk.algorithm': 'layered', 'elk.direction': 'RIGHT', 'elk.spacing.nodeNode': '36', 'elk.layered.spacing.nodeNodeBetweenLayers': '90', 'elk.edgeRouting': 'ORTHOGONAL' },
          children: visible.map((id) => ({ id, width: 196, height: 70 })), edges: edges.map((e) => ({ id: e.data.id, sources: [e.data.source], targets: [e.data.target] })) };
        const out = await getElk().layout(graph);
        if (host._token !== token) return;
        out.children.forEach((c) => cy.getElementById(c.id).position({ x: c.x + 98, y: c.y + 35 }));
      }
    } catch (err) { if (host._token === token) console.error(err); }
    if (host._token !== token) return;
    cy.resize(); cy.fit(undefined, 45); if (cy.zoom() > 1) cy.zoom(1); cy.center(cy.nodes());
    host._themeObs?.disconnect();
    host._themeObs = new MutationObserver(() => cy.style(styles(layout)));
    host._themeObs.observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] });
    onBusy?.(false);
  }
  if (host._cy && selected) highlight(host._cy, net, selected);
}
export const cyOf = (host) => host?._cy;
export function fitAll(host) { const cy = host?._cy; if (cy && cy.nodes().length) cy.fit(cy.nodes(), 45); }
export function fitSelection(host, id) { const cy = host?._cy; const n = cy?.getElementById(id); if (!n || n.empty()) return; cy.zoom(1); cy.pan({ x: cy.width() / 2 - n.position().x, y: cy.height() / 2 - n.position().y }); }
export function resetView(host, id) { const cy = host?._cy; if (!cy) return; cy.zoom(0.9); const n = cy.getElementById(id); if (n.nonempty()) cy.pan({ x: cy.width() / 2 - n.position().x * 0.9, y: cy.height() / 2 - n.position().y * 0.9 }); }
export function zoomBy(host, f) { const cy = host?._cy; if (cy) cy.zoom({ level: Math.min(2.5, Math.max(0.08, cy.zoom() * f)), renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 } }); }
