// Cytoscape + ELK (vendored, same-origin) for the bounded check subgraphs. No network, no CDN.
import { isLive, isStale, isDestroyed, remountGraph, disposeGraph, fitHost, noteUserCamera, armUserCamera, observeResize } from './graph_lifecycle.js';   // UIP-13-GRAPH-LIFECYCLE
let loading = null;
const load = (src) => new Promise((res, rej) => { const s = document.createElement('script'); s.src = src; s.onload = res; s.onerror = () => rej(new Error('failed to load ' + src)); document.head.appendChild(s); });
export function libs() {
  loading ||= (async () => { await load('/static/vendor/cytoscape.min.js'); await load('/static/vendor/elk.bundled.js'); })();
  return loading;
}
let elk = null;
export const getElk = () => (elk ||= new window.ELK({ workerFactory: () => new Worker('/static/vendor/elk-worker.js') }));
export const css = (n) => getComputedStyle(document.documentElement).getPropertyValue(n).trim();

export function nodeLabel(n) {
  const id = n.id.replace(/^(assertion|evidence|entity):/, '');
  if (n.type === 'assertion') return `${id.split('-').slice(0, 1)[0]} · ${n.predicate || ''}\n${n.state || ''}`.slice(0, 60);
  if (n.type === 'evidence') return `${id.slice(0, 28)}\n${n.method || ''}`.slice(0, 60);
  return `${(n.name || id).slice(0, 28)}\n${n.kind || n.type}`;
}
const styles = () => [
  { selector: 'node', style: { shape: 'round-rectangle', width: 190, height: 54, 'background-color': css('--graph-node'), 'border-width': 1.4, 'border-color': css('--graph-edge'), label: 'data(label)', 'text-wrap': 'wrap', 'text-max-width': 170, 'font-size': 11, color: css('--ink'), 'text-valign': 'center', 'text-halign': 'center' } },
  { selector: 'node[type="assertion"]', style: { 'border-color': css('--amber') || '#9a6a1c', 'border-width': 2 } },
  { selector: 'node:selected', style: { 'border-color': css('--dep-selected'), 'border-width': 3.5, 'background-color': css('--dep-selected-soft') } },
  { selector: 'edge', style: { width: 1.5, 'line-color': css('--graph-edge'), 'target-arrow-color': css('--graph-edge'), 'target-arrow-shape': 'triangle', 'curve-style': 'bezier', 'arrow-scale': 0.8 } },
  { selector: 'edge[type="excluded_from"]', style: { 'line-style': 'dashed', 'line-color': css('--red'), 'target-arrow-color': css('--red') } },
];

// signature -> rebuild only when the node/edge set changes; selection is applied in place.
export async function syncGraph(host, { nodes, edges, selected, onSelect, direction = 'RIGHT' }) {
  await libs();
  // UIP08-BR-D01: a repaint can replace the host while the libraries load. Cytoscape sizes a detached container from empty computed styles (NaN), and
  // its initial layout then throws "reading 'h'". The replacement host receives its own syncGraph call after the repaint, so nothing is lost by skipping.
  if (host.isConnected === false) return;
  const sig = nodes.map((n) => n.id).join('|') + '#' + edges.length + direction;
  if (host._cy && host._sig === sig && !isLive(host._cy)) remountGraph(host);   // UIP-13: a host whose renderer was destroyed under a live instance is re-attached (same camera/selection), not left blank
  if (!host._cy || host._sig !== sig) {
    if (host._cy) disposeGraph(host);   // UIP-13: also drops the previous instance's theme observer
    host._sig = sig;
    const cy = window.cytoscape({ container: host, elements: [], style: styles(), minZoom: 0.2, maxZoom: 2.5, boxSelectionEnabled: false, selectionType: 'single' });
    host._cy = cy; host._restyle = styles; host._mountParent = host.parentNode;
    const ids = new Set(nodes.map((n) => n.id));
    cy.add(nodes.map((n) => ({ data: { id: n.id, label: nodeLabel(n), type: n.type } })));
    cy.add(edges.filter((e) => ids.has(e.from) && ids.has(e.to)).map((e, i) => ({ data: { id: 'e' + i, source: e.from, target: e.to, type: e.type } })));
    cy.on('tap', 'node', (ev) => host._onSelect?.(ev.target.id()));
    cy.on('tap', (ev) => { if (ev.target === cy) host._onSelect?.(null); });
    armUserCamera(host, cy);   // S4-FIX-01: a deliberate user pan/zoom leaves auto-fit mode
    host.setAttribute('role', 'application');
    host.setAttribute('aria-label', 'Interactive check subgraph. Drag to pan, scroll to zoom. The list view is a keyboard-accessible alternative.');
    const graph = { id: 'root', layoutOptions: { 'elk.algorithm': 'layered', 'elk.direction': direction, 'elk.spacing.nodeNode': '34', 'elk.layered.spacing.nodeNodeBetweenLayers': '70' },
      children: nodes.map((n) => ({ id: n.id, width: 190, height: 54 })),
      edges: cy.edges().map((e) => ({ id: e.id(), sources: [e.data('source')], targets: [e.data('target')] })) };
    try {
      const out = await getElk().layout(graph);
      if (isStale(host, cy)) return;   // UIP-13: a layout that completes after a replacement, navigation or retirement mutates nothing
      out.children.forEach((c) => cy.getElementById(c.id).position({ x: c.x + 95, y: c.y + 27 }));
    } catch { if (host.isConnected === false || isStale(host, cy)) return; cy.layout({ name: 'grid' }).run(); }
    if (isStale(host, cy)) return;
    fitHost(host, 24);   // S4-FIX-01: fits and arms auto-fit (same resize + fit as before)
    observeResize(host); // S4-FIX-01: refit on host resize only while auto-fit is armed
    host._themeObs?.disconnect();
    host._themeObs = new MutationObserver(() => { if (!isDestroyed(cy)) cy.style(styles()); });
    host._themeObs.observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] });
  }
  host._onSelect = onSelect;
  const cy = host._cy;
  cy.$(':selected').unselect();
  if (selected && cy.getElementById(selected).nonempty()) cy.getElementById(selected).select();
}
export function fit(host) { fitHost(host, 24); }   // explicit Fit: fits the current host and re-arms auto-fit
export function zoom(host, factor) { const cy = host._cy; if (cy) noteUserCamera(host); if (cy) cy.zoom({ level: Math.max(0.2, Math.min(2.5, cy.zoom() * factor)), renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 } }); }

// Load Cytoscape, ELK and its worker once, when an analysis opens, so that toggling Advanced later
// is purely presentational and issues no request of any kind.
export async function warm() {
  await libs();
  try { await getElk().layout({ id: 'root', children: [{ id: 'warm', width: 1, height: 1 }], edges: [] }); } catch { /* layout is retried on use */ }
}
