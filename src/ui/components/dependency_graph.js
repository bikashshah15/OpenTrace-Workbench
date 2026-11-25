// UIP-05: the Dependencies tab (normal, non-Advanced view): focus graph, pills, pager, search, Graph/List switch, context chooser.
// Ported from the approved reference (friendly dependency graph); fed only by dependency_page/1 and dependency_contexts/1.
// Repository text is always escaped. Nothing here infers a path or an edge: every drawn line is a recorded edge of the payload.
import { esc, fmt } from '../lib/util.js';
import { infoButton } from './intake.js';
import { INFO } from '../lib/copy.js';
import { FILTERS, keyFilter, layoutPage, stageHeight, nodeClass, wrapLabel, captionText, rangeText, emptyText, truncate, chooserOptions, nodeTarget, columnsFor, NODE_W, NODE_H, CHOOSER_PAGE } from '../lib/dependency_graph.js';

const isLive = (s) => s.analysis?.identity?.mode === 'live';
export const DEP_ERRORS = {
  stale_generation: 'The session moved on; reopen the analysis.', no_analysis: 'No completed analysis is active.', not_found: 'No dependency declarations are recorded for this context.',
  invalid_request: 'The request was refused.', projection_failed: 'The dependencies could not be projected.', response_too_large: 'The response was too large to show.',
};
const errText = (e) => (e && (DEP_ERRORS[e.code] || 'The dependencies could not be loaded (' + esc(e.code || 'request failed') + ').')) || '';

// The measured stage width (px) drives the column count; before the first measurement a viewport estimate is used.
let measured = 0;
export const stageWidth = () => measured || Math.max(320, Math.min(1100, (typeof window !== 'undefined' ? window.innerWidth : 1100) - 380));
export const setMeasured = (w) => { measured = Math.round(w); };

function labelSvg(x, y, name, ver) {
  const lines = wrapLabel(name); const top = lines.length === 1 ? y - 5 : y - 12;
  return lines.map((t, i) => `<text x="${x}" y="${top + i * 14}" text-anchor="middle" class="name">${esc(t)}</text>`).join('') + `<text x="${x}" y="${top + lines.length * 14 + (lines.length === 1 ? 5 : 4)}" text-anchor="middle" class="sub">${esc(truncate(ver, 24))}</text>`;
}
function nodeSvg(n, dep, s) {
  const node = n.node; const name = node.name || '(unnamed)'; const ver = node.version || 'Version not reported';
  const chosen = dep.selection === n.id;
  const notes = [node.role === 'focus' ? 'focused package' : node.role === 'connector' ? 'connecting package' : null, node.advisory_lookup === 'match' ? (isLive(s) ? 'live advisory match' : 'advisory match') : null, node.flags.evidence_gap ? 'evidence gap' : null].filter(Boolean);
  const x = n.x - NODE_W / 2; const y = n.y - NODE_H / 2;
  return `<g class="${nodeClass(node, chosen)}" role="button" tabindex="0" data-dep-node="${esc(n.id)}" data-role="${esc(node.role)}" aria-pressed="${chosen}" aria-label="${esc(name + ' ' + ver + (notes.length ? ', ' + notes.join(', ') : ''))}"><title>${esc(name + ' ' + ver)}</title><rect x="${x}" y="${y}" width="${NODE_W}" height="${NODE_H}" rx="9"/>${labelSvg(n.x, n.y, name, ver)}</g>`;
}

export function graphSvg(s, page, layout) {
  const dep = s.workbench.perTab.dependencies;
  const edges = layout.edges.map((e) => `<path class="ot5-edge" data-edge="${esc(e.id)}" d="${e.d}" marker-end="url(#ot5-arrow)"/>`).join('');
  return `<svg id="ot5-svg" data-w="${layout.width}" data-h="${layout.height}" data-cols="${layout.columns}" viewBox="0 0 ${layout.width} ${layout.height}" preserveAspectRatio="xMidYMin meet" role="group" aria-label="${esc('Dependency graph for ' + (page.nodes.find((n) => n.role === 'focus')?.name || 'the focused package'))}"><defs><marker id="ot5-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0 0 10 5 0 10z" class="ot5-arrowhead"/></marker></defs><g id="ot5-vp">${edges}${layout.nodes.map((n) => nodeSvg(n, dep, s)).join('')}</g></svg>`;
}

function contextBar(s, page) {
  const dep = s.workbench.perTab.dependencies; const ch = s.views.depContexts; const cx = dep.cx;
  const opts = chooserOptions(ch, page, dep);
  const options = opts.length ? opts.map((r) => `<option value="${esc(r.context_id)}" data-path="${esc(r.path)}" ${dep.ctxId === r.context_id ? 'selected' : ''}>${esc(r.path)}${r.components_total == null ? '' : ' · ' + fmt(r.components_total)}</option>`).join('') : `<option value="">${ch ? 'No source contexts in this analysis' : cx.status === 'error' ? 'Source contexts unavailable' : 'Loading source contexts…'}</option>`;   // a loaded-but-empty list must not read as still loading
  const total = ch?.total || 0; const from = total ? ch.offset + 1 : 0; const to = ch ? ch.offset + ch.rows.length : 0;
  const pager = ch && total > CHOOSER_PAGE ? `<span class="ot5-ctx-pager"><button type="button" data-action="dep-ctx-page" data-dir="-1" aria-label="Previous source files" ${ch.offset <= 0 ? 'disabled' : ''}>‹</button><span aria-live="polite">${from}–${to} of ${fmt(total)}</span><button type="button" data-action="dep-ctx-page" data-dir="1" aria-label="Next source files" ${to >= total ? 'disabled' : ''}>›</button></span>` : '';
  const filter = (ch && (total > CHOOSER_PAGE || cx.query)) || cx.query ? `<input type="search" id="ot5-ctx-q" data-fk="ctxq" class="ot5-ctx-q" placeholder="Filter source files…" aria-label="Filter source files" autocomplete="off" value="${esc(cx.query)}">` : '';
  const fail = cx.status === 'error' ? `<span class="ot5-ctx-err" role="alert">The source files could not be listed. <button type="button" class="text-action" data-action="dep-ctx-retry">Try again</button></span>` : '';
  return `<div class="ot-context-bar ot5-context-bar"><label for="ot5-context">Dependency &amp; advisory context</label><select id="ot5-context" data-fk="ctx5">${options}</select>${pager}${filter}${fail}${infoButton(INFO.context, 'About dependency and advisory context')}</div>`;
}

const SEARCH_ICON = '<svg class="ot5-search-icon" viewBox="0 0 20 20" aria-hidden="true"><circle cx="8.5" cy="8.5" r="5.5"/><path d="m13 13 5 5"/></svg>';
function toolbar(s, list) {
  const dep = s.workbench.perTab.dependencies;
  const label = list ? 'Search components in this context' : 'Search matching packages';
  return `<div class="ot-toolbar"><div class="ot-search ot5-search"><input id="ot5-search" data-fk="search5" type="search" placeholder="${list ? 'Search components in this context…' : 'Find a package…'}" aria-label="${label}" autocomplete="off" value="${esc(dep.q)}">${SEARCH_ICON}</div>
    <div class="segmented" aria-label="Dependency presentation"><button type="button" data-action="dep-pres" data-p="graph" aria-pressed="${!list}">Graph</button><button type="button" data-action="dep-pres" data-p="list" aria-pressed="${list}">Component list</button></div>
    <button type="button" class="button small ot5-expand" id="ot5-expand" data-fk="ot5-expand" data-action="dep-expand" aria-expanded="${!!dep.expanded}" aria-controls="ot5-expanded" title="${dep.expanded ? 'Close the expanded view' : 'Open the dependency graph in an expanded view'}">${dep.expanded ? 'Close expanded view' : 'Expand'}</button></div>`;
}

function pills(page) {
  const t = page.filter_totals;
  return `<div class="ot5-controls" id="ot5-controls"><div class="ot5-filters" role="group" aria-label="Filter dependency graph">${FILTERS.map((f) => `<button type="button" data-ot5-filter="${f.key}" title="${esc(f.title)}" aria-pressed="${page.filter === f.payload}">${esc(f.label)} <span>${fmt(t[f.payload])}</span></button>`).join('')}</div>${infoButton('Filters apply to descendants of the focused package in the selected source context. Direct means one recorded edge. Transitive means a shortest path of two or more edges. Evidence gaps mean missing source locations or advisory-query coverage. Filtered views keep the connecting packages needed to show a recorded path; they do not count toward the 30 packages per page.', 'About dependency filters')}</div>`;
}

function pager(page) {
  const p = page.page;
  if (p.matches_total <= 30 && p.offset === 0) return '';
  return `<div id="ot5-pager" class="ot5-pager"><button type="button" data-action="dep-page" data-dir="-1" aria-label="Previous 30 matching packages" ${p.offset <= 0 ? 'disabled' : ''}>‹</button><span id="ot5-page-count" aria-live="polite">${rangeText(p)}</span><button type="button" data-action="dep-page" data-dir="1" aria-label="Next 30 matching packages" ${p.has_more ? '' : 'disabled'}>›</button></div>`;
}

function stateBox(text, retry) {
  return `<div class="ot5-state" role="${retry ? 'alert' : 'status'}"><p>${text}</p>${retry ? '<button type="button" class="button small" data-action="dep-retry">Try again</button>' : ''}</div>`;
}

function graphMain(s, dep, page) {
  if (!page) {
    if (dep.pg.status === 'error') return stateBox(esc(errText(dep.pg.error)), dep.pg.error?.code !== 'not_found');
    if (dep.pg.status === 'empty') return stateBox('No dependency declarations recorded for this context.', false);
    return stateBox('Loading dependencies…', false);
  }
  const w = stageWidth(); const layout = layoutPage(page, w); const focus = page.nodes.find((n) => n.role === 'focus');
  const failed = dep.pg.status === 'error' ? `<div class="ot5-banner" role="alert">${esc(errText(dep.pg.error))} <button type="button" class="text-action" data-action="dep-retry">Try again</button></div>` : '';
  const loading = dep.pg.status === 'loading' ? '<p class="ot-help ot5-loading" role="status">Updating…</p>' : '';
  const empty = page.page.matches_total === 0 ? `<p id="ot5-empty" class="ot5-empty" role="status">${esc(emptyText(page))}</p>` : '';
  const trunc = page.limits.connectors_truncated || page.limits.edges_truncated ? '<p class="ot-help ot5-truncated">Some packages on this page are listed without a drawn path because the page reached its connector or edge limit. Open the package to see its recorded connections.</p>' : '';
  const lookup = page.lookup.explanation ? `<p class="ot-help ot5-lookup" role="note">${esc(page.lookup.explanation)}</p>` : '';
  return `${pills(page)}${failed}${lookup}
    <div class="ot-stage ot5-stage" id="ot5-stage" data-cols="${layout.columns}" data-stage-h="${stageHeight(layout, w)}" tabindex="0" role="application" aria-label="Dependency graph. Click a package to inspect it; double-click or press Shift+Enter to make it the focus. Plus, minus and zero zoom and fit.">${graphSvg(s, page, layout)}${pager(page)}${empty}<div class="ot-zoom"><button type="button" data-ot5-zoom="0.8" aria-label="Zoom out">−</button><span id="ot5-zoom-label">100%</span><button type="button" data-ot5-zoom="1.25" aria-label="Zoom in">+</button><button type="button" data-ot5-fit aria-label="Fit all">Fit</button></div></div>
    <p class="ot5-sr" id="ot5-status" role="status" aria-live="polite">${esc(captionText(page, focus.name || '(unnamed)'))}</p><p class="ot-help ot5-caption" id="ot5-caption">Arrows follow recorded dependency declarations. Click to inspect; double-click a package to make it the focus.</p>${loading}${trunc}`;
}

// helpers: { depInspector(s, v), depList(s, v) } from workbench.js (the legacy inspector record and component list stay unchanged).
export function renderDependencyView(s, helpers) {
  if (s.busy === 'ending') return '<p class="ot-prompt" role="status">Ending the session… the dependency data has been cleared.</p>';
  const dep = s.workbench.perTab.dependencies; const page = s.views.depPage; const v = s.views.dependencies;
  if (dep.stale) return `<div class="ot-layout"><div class="ot-surface"><div class="ot5-state ot5-stale" role="alert"><p>${esc(DEP_ERRORS.stale_generation)}</p><button type="button" class="button small" data-action="dep-stale-reset" data-fk="ot5-stale-reset">Reopen the analysis</button></div></div><aside class="ot-inspector" aria-label="Selected package"></aside></div>`;
  const list = dep.presentation === 'list';
  let main;
  if (list) {
    const cl = v?.component_list;
    const head = `<p class="ot-help ot5-population" id="ot5-population">All ${cl ? fmt(cl.total) : ''} components in this context — not the filtered graph. Filters, counts and the 30-package pager apply to the Graph only.</p>`;
    main = `${head}${v ? helpers.depList(s, v) : '<p class="ot-prompt ot-loading" role="status">Loading components…</p>'}`;
  } else main = graphMain(s, dep, page);
  const foot = `<div class="ot-foot"><p>Red is a ${isLive(s) ? 'live advisory match from this analysis’s OSV lookup' : 'captured package-version advisory match'}, not confirmed exploitability. Green highlights declarations, not safety. These source inventories include documentation and development contexts; shipped/runtime composition was not established.</p></div>`;
  const inspector = v && v.inspected ? helpers.depInspector(s, v) : '<p class="ot-prompt">Select a package to see its details.</p>';
  const layout = `<div class="ot-layout"><div class="ot-surface">${contextBar(s, page)}${toolbar(s, list)}${main}${foot}</div><aside class="ot-inspector" aria-label="Selected package">${inspector}</aside></div>`;
  // Expanded view (UIP-05 §6 / C5): the same surface in a modal frame, ported from the reference's expanded workbench. State lives in dep.expanded.
  return dep.expanded ? `<div class="ot5-expanded" id="ot5-expanded" role="dialog" aria-modal="true" aria-label="Expanded dependency graph">${layout}</div>` : layout;
}

// ---------------------------------------------------------------------------------------------- viewport (pan/zoom) and keyboard
const view = { s: 1, x: 0, y: 0, key: '' };
const viewKey = (st) => { const p = st.views.depPage; return p ? JSON.stringify([p.context.context_id, p.focus.node_id, p.filter, p.query, p.page.offset, st.narrow, measured, !!st.workbench.perTab.dependencies.expanded]) : ''; };
export function applyDependencyView(getState) {
  const vp = document.getElementById('ot5-vp'); if (!vp) return;
  const stage = document.getElementById('ot5-stage'); if (stage?.dataset.stageH) stage.style.height = stage.dataset.stageH + 'px';   // CSSOM, not a style attribute (CSP style-src 'self')
  const st = getState(); const k = viewKey(st);
  if (view.key !== k) { view.s = 1; view.x = 0; view.y = 0; view.key = k; }
  vp.setAttribute('transform', `translate(${view.x} ${view.y}) scale(${view.s})`);
  const label = document.getElementById('ot5-zoom-label'); if (label) label.textContent = Math.round(view.s * 100) + '%';
}
// While the expanded frame is open everything outside it is inert (no focus, no pointer, hidden from assistive technology); the native
// modal <dialog> used for information popovers stays usable. Called after every render and cleared as soon as the frame is gone
// (collapse, End session, a retired session), so nothing is left inert.
let inerted = [];
export function syncExpandedShell() {
  if (typeof document === 'undefined') return;
  const frame = document.getElementById('ot5-expanded');
  for (const n of inerted) n.inert = false;
  inerted = [];
  if (!frame) return;
  for (let n = frame; n.parentElement; n = n.parentElement) for (const sib of n.parentElement.children) {
    if (sib === n || sib.tagName === 'DIALOG' || sib.tagName === 'SCRIPT' || sib.tagName === 'STYLE') continue;
    sib.inert = true; inerted.push(sib);
  }
}
// After a render: re-measure the stage; a different column count re-renders once with the measured width (reference: columns follow the stage width).
export function remeasure(getState, rerender) {
  const stage = document.getElementById('ot5-stage'); if (!stage) return;
  const w = stage.clientWidth; if (!w) return;
  if (columnsFor(w) !== columnsFor(stageWidth()) || !measured) { const before = columnsFor(stageWidth()); setMeasured(w); if (columnsFor(w) !== before) rerender(); } else setMeasured(w);
}

export function attachDependencyGraph(getState, hooks) {
  const MIN = 0.4; const MAX = 2.5; let pan = null;
  const zoom = (f) => { view.s = Math.max(MIN, Math.min(MAX, view.s * f)); applyDependencyView(getState); };
  document.addEventListener('click', (ev) => {
    const z = ev.target.closest?.('[data-ot5-zoom]'); if (z) { zoom(Number(z.dataset.ot5Zoom)); return; }
    if (ev.target.closest?.('[data-ot5-fit]')) { view.s = 1; view.x = 0; view.y = 0; applyDependencyView(getState); return; }
    const f = ev.target.closest?.('[data-ot5-filter]'); if (f) hooks.filter(f.dataset.ot5Filter);
  });
  document.addEventListener('keydown', (ev) => {
    const frame = document.getElementById('ot5-expanded');
    if (frame && !document.getElementById('ot-dialog')?.open) {            // expanded frame: Escape closes it, Tab stays inside it
      if (ev.key === 'Escape') { ev.preventDefault(); hooks.collapse(); return; }
      if (ev.key === 'Tab') {
        const items = [...frame.querySelectorAll('button,[href],input,select,textarea,[tabindex]:not([tabindex="-1"])')].filter((n) => !n.disabled && n.getClientRects().length);
        if (items.length) { const first = items[0]; const last = items[items.length - 1]; const at = document.activeElement;
          if (!frame.contains(at)) { ev.preventDefault(); first.focus(); } else if (ev.shiftKey && at === first) { ev.preventDefault(); last.focus(); } else if (!ev.shiftKey && at === last) { ev.preventDefault(); first.focus(); } }
        return;
      }
    }
    const t = ev.target; const stage = t.closest?.('#ot5-stage'); if (!stage) return;
    if (t.id === 'ot5-stage') { if (ev.key === '+' || ev.key === '=') { ev.preventDefault(); zoom(1.25); } else if (ev.key === '-' || ev.key === '_') { ev.preventDefault(); zoom(0.8); } else if (ev.key === '0') { ev.preventDefault(); view.s = 1; view.x = 0; view.y = 0; applyDependencyView(getState); } return; }
    const id = t.dataset?.depNode; if (!id) return;
    if (ev.key === 'Enter' && ev.shiftKey) { ev.preventDefault(); hooks.explore(id); return; }
    if (['ArrowDown', 'ArrowUp', 'ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(ev.key) && !ev.ctrlKey && !ev.metaKey && !ev.altKey) {
      const ids = [...stage.querySelectorAll('[data-dep-node]')].map((n) => n.dataset.depNode); const target = nodeTarget(ids, id, ev.key);
      if (target) { ev.preventDefault(); stage.querySelector(`[data-dep-node="${CSS.escape(target)}"]`)?.focus(); }
    }
  });
  document.addEventListener('pointerdown', (ev) => { const svg = ev.target.closest?.('#ot5-svg'); if (!svg || ev.target.closest('[data-dep-node]')) return; pan = { x: ev.clientX - view.x, y: ev.clientY - view.y }; });
  document.addEventListener('pointermove', (ev) => { if (!pan) return; view.x = ev.clientX - pan.x; view.y = ev.clientY - pan.y; applyDependencyView(getState); });
  document.addEventListener('pointerup', () => { pan = null; });
  document.addEventListener('pointercancel', () => { pan = null; });
  document.addEventListener('wheel', (ev) => { if (!ev.target.closest?.('#ot5-svg') || !(ev.ctrlKey || ev.metaKey)) return; ev.preventDefault(); zoom(ev.deltaY > 0 ? 0.89 : 1.12); }, { passive: false });
}
