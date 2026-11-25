// UIP-04: the repository contexts map (Graph SVG + List), ported from the approved prototype's structure and bound to the
// frozen `opentrace.workbench.contexts/1` payload. Every server string (paths, names, labels) is inserted escaped as text;
// nothing here knows a repository by name. Selection and paging are dispatched through the shared document handlers in app.js
// (`data-ctx`, `data-action`); pan, zoom, focus return and arrow-key navigation live here.
import { esc, fmt } from '../lib/util.js';
import { renderInspector } from './inspector.js';
import { fromSelection } from '../lib/inspector_model.js';
import { VB_W, ROOT, ZONE, PAGE_GRAPH, PAGE_LIST, capacity, layoutMap, loadedCount, totalFiles, hiddenCount, zoomPercent, zoomBox, clampZoom, panBox, cardTarget } from '../lib/context_map.js';

const isLive = (s) => s.analysis?.identity?.mode === 'live';
export const pageSizeFor = (presentation) => (presentation === 'list' ? PAGE_LIST : PAGE_GRAPH);

// ------------------------------------------------------------------ text helpers (all output is escaped by the caller)
const clipRight = (t, n) => (t.length > n ? t.slice(0, n - 1) + '…' : t);
const clipLeft = (t, n) => (t.length > n ? '…' + t.slice(t.length - n + 1) : t);
const shortName = (name) => String(name).split('/').pop() || String(name);
const plural = (n, w) => `${fmt(n)} ${w}${n === 1 ? '' : 's'}`;
const sha7 = (m) => String(m.root.commit_sha).slice(0, 7);
// A source link is active only for an exact https://github.com/ URL without credentials; everything else is inert text.
export function activeHref(href) {
  if (typeof href !== 'string') return null;
  try { const u = new URL(href); return u.protocol === 'https:' && u.hostname === 'github.com' && u.port === '' && !u.username && !u.password && href.startsWith('https://github.com/') ? href : null; } catch { return null; }
}

// The pinned-revision link must resolve, as a URL parser sees it, to exactly this repository at exactly this commit: the parsed
// destination is checked against the binding (not merely the host), and any href the parser would rewrite (dot segments, encoded
// dots, backslashes, query, fragment) is inert. Recorded paths are never altered; an unfaithful link is simply not offered.
export function pinnedHref(href, m) {
  const base = activeHref(href); const repo = m?.binding?.repository; const sha = m?.root?.commit_sha;
  if (!base || !repo || typeof sha !== 'string' || !sha) return null;
  try {
    const u = new URL(base); const prefix = `/${encodeURIComponent(repo.owner)}/${encodeURIComponent(repo.name)}/blob/${sha}/`;
    return u.href === base && !u.search && !u.hash && u.pathname.startsWith(prefix) && u.pathname.length > prefix.length ? base : null;
  } catch { return null; }
}

// The prototype prints card and header counts as plain numbers (only the root card uses thousands separators); the same text is used here.
const plain = (n, w) => `${n} ${w}${n === 1 ? '' : 's'}`;
export function groupSummary(g) {
  if (g.kind === 'unlocated') return `${plain(g.distinct_total, 'component record')} without a recorded source location`;
  const n = totalFiles(g);
  return `${plain(n, 'captured source location')} \u00b7 ${g.distinct_total} distinct records${g.membership_total > g.distinct_total ? ` \u00b7 ${plain(g.membership_total, 'file membership')}` : ''}`;
}
export function footerText(g, shown) {
  const total = totalFiles(g);
  return `Showing ${fmt(shown)} of ${fmt(total)} source locations · ${fmt(total - shown)} not shown`;
}

// ------------------------------------------------------------------ Graph
function fileCard(f, z, i, sel) {
  const yes = sel === f.file_id; const x = z.files[i].x; const y = z.files[i].y;
  const cut = f.path.lastIndexOf('/'); const dir = f.path.slice(0, cut + 1); const name = f.path.slice(cut + 1);
  return `<path class="ot4-link" d="${z.files[i].link}"/><g data-ctx="${esc(f.file_id)}" data-ctx-kind="file" role="button" tabindex="0" aria-pressed="${yes}" aria-label="Inspect ${esc(f.path)}; ${f.distinct_total} component records"><title>${esc(f.path)}</title>`
    + `<rect class="ot4-file${yes ? ' chosen' : ''}" x="${x}" y="${y}" width="${ZONE.fileW}" height="${ZONE.fileH}" rx="5"/>`
    + `<text class="ot4-dir" x="${x + 15}" y="${y + 21}" font-size="15">${esc(clipLeft(dir, 52))}</text><text class="ot4-name" x="${x + 15}" y="${y + 43}" font-size="17" font-weight="500">${esc(clipRight(name, 44))}</text>`
    + `<text class="ot4-count" x="${x + 530}" y="${y + 22}" font-size="14" text-anchor="end">${f.distinct_total} records</text></g>`;
}

// Graph "Show more": the same three states as List (idle / loading / terminal failure with a manual retry). The control stays focusable
// while loading (aria-disabled, the shared handler ignores the click) so keyboard focus is never lost to a repaint.
function moreButtonSvg(g, f, gs) {
  const loading = gs.state === 'loading'; const failed = gs.state === 'error';
  const label = loading ? 'Loading…' : failed ? 'Try again' : 'Show more';
  const aria = `${failed ? 'Try again: show' : 'Show'} more source locations in ${esc(g.label)}; ${fmt(hiddenCount(g))} not shown`;
  const note = loading ? `<text class="ot4-foot" role="status" x="${f.x + 4}" y="${f.y + 31}" font-size="13">Loading more source locations…</text>`
    : failed ? `<text class="ot4-foot" role="alert" x="${f.x + 4}" y="${f.y + 31}" font-size="13">Could not load more (${esc(gs.error?.code || 'request failed')}). Loaded ones stay.</text>` : '';
  return `${note}<g data-action="ctx-more" data-group="${esc(g.group_id)}" role="button" tabindex="0"${loading ? ' aria-disabled="true"' : ''} aria-label="${aria}"><rect class="ot4-more" x="${f.x + ZONE.fileW - 126}" y="${f.y + 2}" width="122" height="30" rx="5"/><text class="ot4-more-text" x="${f.x + ZONE.fileW - 65}" y="${f.y + 22}" font-size="14" text-anchor="middle">${label}</text></g>`;
}

function zoneSvg(g, z, sel, gs = {}) {
  const yes = sel === g.group_id; const h = z.header;
  let out = `<g class="ot4-zone" data-token="${esc(g.token)}" data-group-id="${esc(g.group_id)}" data-zone="${esc(g.group_id)}"><rect class="ot4-zone-box" x="${z.x}" y="${z.y}" width="${z.w}" height="${z.h}" rx="8"/>`
    + `<g data-ctx="${esc(g.group_id)}" data-ctx-kind="${g.kind === 'unlocated' ? 'unlocated' : 'group'}" role="button" tabindex="0" aria-pressed="${yes}" aria-label="Inspect ${esc(g.label)} context">`
    + `<rect class="ot4-head${yes ? ' chosen' : ''}" x="${h.x}" y="${h.y}" width="${h.w}" height="${h.h}" rx="5"/>`
    + `<text class="ot4-head-title" x="${z.x + 33}" y="${z.y + 41}" font-size="19" font-weight="600">${esc(clipRight(g.label, 40))}</text>`
    + `<text class="ot4-head-sub" x="${z.x + 33}" y="${z.y + 61}" font-size="14">${esc(groupSummary(g))}</text></g>`;
  g.files.slice(0, z.shown).forEach((f, i) => { out += fileCard(f, z, i, sel); });
  if (z.footer) {
    const f = z.footer; const list = f.kind === 'list';
    out += `<text class="ot4-foot" x="${f.x + 4}" y="${f.y + 14}" font-size="13">${esc(footerText(g, z.shown))}</text>`
      + (list ? `<text class="ot4-foot" x="${f.x + 4}" y="${f.y + 31}" font-size="13">Continue in List view for the remaining source locations.</text>`
        : moreButtonSvg(g, f, gs));
  }
  return out + '</g>';
}

export function mapSvg(s, m, layout, vb) {
  const sel = s.workbench.perTab.contexts.selection; const yes = sel === 'root';
  const r = ROOT;
  const root = `<g data-ctx="root" data-ctx-kind="root" role="button" tabindex="0" aria-pressed="${yes}" aria-label="Inspect repository ${esc(m.root.name)}"><title>${esc(m.root.name)}</title>`
    + `<rect class="ot4-root${yes ? ' chosen' : ''}" x="${r.x}" y="${r.y}" width="${r.w}" height="${r.h}" rx="6"/>`
    + `<text class="ot4-name" x="${r.x + 20}" y="${r.y + 30}" font-size="20" font-weight="600">${esc(clipRight(shortName(m.root.name), 17))} · ${esc(sha7(m))}</text>`
    + `<text class="ot4-dir" x="${r.x + 20}" y="${r.y + 54}" font-size="15">${esc(fmt(m.root.distinct_total))} component records</text>`
    + `<text class="ot4-dir" x="${r.x + 20}" y="${r.y + 75}" font-size="13">${esc(plural(m.groups.filter((g) => g.kind === 'located').reduce((n, g) => n + totalFiles(g), 0), 'captured source location'))}</text></g>`;
  const zones = layout.zones.map((z) => zoneSvg(m.groups[z.index], z, sel, s.workbench.perTab.contexts.map.groups[m.groups[z.index].group_id])).join('');
  return `<svg id="ot4-svg" class="ot4-svg" viewBox="${vb.join(' ')}" role="group" aria-label="Repository context map for ${esc(m.root.name)}"><path class="ot4-connectors" d="${layout.connectors.join(' ')}"/>${root}${zones}</svg>`;
}

// ------------------------------------------------------------------ List
function listRows(s, m) {
  const sel = s.workbench.perTab.contexts.selection;
  const row = (id, kind, eyebrow, title, small, cls = '') => `<button type="button" class="component-item ot4-row ${cls}${sel === id ? ' selected' : ''}" data-ctx="${esc(id)}" data-ctx-kind="${kind}" aria-pressed="${sel === id}"><span><span class="eyebrow">${esc(eyebrow)}</span><strong>${esc(title)}</strong><small>${esc(small)}</small></span></button>`;
  let out = row('root', 'root', 'Repository', m.root.name, `${plural(m.root.distinct_total, 'distinct component record')} · ${plural(m.root.located_distinct_total, 'record')} with a location · ${fmt(m.root.unlocated_total)} without`, 'ot4-row-root');
  for (const g of m.groups) {
    out += `<div class="ot4-list-group" data-token="${esc(g.token)}" data-group-id="${esc(g.group_id)}">`
      + row(g.group_id, g.kind === 'unlocated' ? 'unlocated' : 'group', g.kind === 'unlocated' ? 'No location' : 'Context group', g.label, groupSummary(g), 'ot4-row-group');
    for (const f of g.files) out += row(f.file_id, 'file', g.label, f.path, `${plural(f.distinct_total, 'record')}${f.membership_total > f.distinct_total ? ` · ${plural(f.membership_total, 'membership')}` : ''}`, 'ot4-row-file');
    if (hiddenCount(g) > 0) out += moreRow(s, g, loadedCount(g));
    out += '</div>';
  }
  return `<div class="ot-list ot4-list" id="ot4-list">${out}</div>`;
}
function moreRow(s, g, shown) {
  const st = s.workbench.perTab.contexts.map.groups[g.group_id] || {};
  const busy = st.state === 'loading';
  const err = st.state === 'error' ? `<p class="ot4-note" role="alert">More source locations could not be loaded (${esc(st.error?.code || 'request failed')}); the loaded ones stay.</p>` : '';
  return `<div class="ot4-more-row"><p class="ot4-note">${esc(footerText(g, shown))}</p>${err}<button type="button" class="button small" data-action="ctx-more" data-group="${esc(g.group_id)}" aria-label="Show more source locations in ${esc(g.label)}; ${fmt(hiddenCount(g))} not shown" ${busy ? 'disabled' : ''}>${busy ? 'Loading…' : st.state === 'error' ? 'Try again' : 'Show more'}</button></div>`;
}

// ------------------------------------------------------------------ states + page
function unavailable(map) {
  const code = map.error?.code || 'request_failed';
  return `<div class="ot4-state" role="alert" data-state="unavailable"><strong>Repository contexts are unavailable.</strong><p>The context map could not be built for this analysis (${esc(code)}${map.error?.detail ? ': ' + esc(map.error.detail) : ''}). Nothing is shown as a partial map. Other tabs are not affected.</p><button type="button" class="button small" data-action="ctx-retry">Check again</button></div>`;
}

// The module-owned viewport: null = Fit. Reset whenever another analysis is shown.
let view = { key: '', vb: null };
const fitBox = (layout) => layout.viewBox;
// The viewport belongs to one epoch (a new analysis, End session and generation replacement all advance it) and one analysis digest.
const viewKey = (s) => `${s.epoch}|${s.views.contexts.binding.analysis_digest}`;
function currentBox(key, layout) { if (view.key !== key) view = { key, vb: null }; return view.vb || fitBox(layout); }

export function renderContexts(s) {
  const c = s.workbench.perTab.contexts; const m = s.views.contexts; const map = c.map;
  if (s.busy === 'ending') { view = { key: '', vb: null }; return '<p class="ot-prompt ot-loading" role="status" data-state="ending">Ending session… the repository map and its selection have been cleared.</p>'; }
  if (!m) return map.status === 'unavailable' ? unavailable(map) : '<p class="ot-prompt ot-loading" role="status">Loading contexts…</p>';
  const graph = c.presentation === 'graph';
  const cap = capacity(m.groups); const layout = layoutMap(m.groups, cap);
  const vb = currentBox(viewKey(s), layout);
  const pending = Object.values(map.groups).some((g) => g.state === 'loading');
  const sel = c.selection; const model = fromSelection(s, 'contexts');
  const toolbar = `<div class="ot-toolbar ot4-toolbar"><div class="segmented" aria-label="Repository contexts presentation"><button type="button" data-action="tab-pres" data-tab="contexts" data-p="graph" aria-pressed="${graph}">Graph</button><button type="button" data-action="tab-pres" data-tab="contexts" data-p="list" aria-pressed="${!graph}">List</button></div><span class="ot-help">Select a group or source file to inspect its evidence</span></div>`;
  const body = graph
    ? `<div id="ot4-stage" class="ot4-stage" tabindex="0" role="group" aria-label="Repository context map. Plus and minus zoom, 0 fits." data-map-ready="${!pending}" data-selection-kind="${esc(selKind(m, sel))}" data-selection-id="${esc(sel || '')}" data-card-count="${layout.rendered}" data-group-count="${m.groups.length}" data-fit="${fitBox(layout).join(' ')}">`
      + `<div class="ot4-caption">REPOSITORY CONTEXTS / ${esc(sha7(m))} <span>${isLive(s) ? 'SCANNED' : 'CAPTURED'} SOURCE · READ ONLY</span></div>${mapSvg(s, m, layout, vb)}`
      + `<div class="ot4-controls"><button type="button" class="graph-tool" data-ctx-zoom="1.25" aria-label="Zoom repository contexts out">−</button><span id="ot4-zoom" role="status">${zoomPercent(vb)}%</span><button type="button" class="graph-tool" data-ctx-zoom="0.8" aria-label="Zoom repository contexts in">+</button><button type="button" class="graph-tool" data-ctx-fit>Fit</button></div></div>`
    : `<div class="ot4-listwrap" data-map-ready="${!pending}" data-selection-kind="${esc(selKind(m, sel))}" data-selection-id="${esc(sel || '')}" data-card-count="${m.groups.reduce((n, g) => n + loadedCount(g), 0)}">${listRows(s, m)}</div>`;
  const note = '<p class="ot4-boundary">Lines show source-file grouping and recorded inventory locations. No install context, workflow dependency, runtime call or service topology is inferred.</p>';
  return `<div class="ot-layout ot4-layout"><div class="ot-surface ot4-surface">${toolbar}${body}${note}</div><aside class="ot-inspector ot4-inspector" aria-label="Selected repository context details">${inspectorHtml(s, m, model)}</aside></div>`;
}
const selKind = (m, sel) => findKind(m, sel);
function findKind(m, sel) {
  if (sel === 'root') return 'root';
  for (const g of m.groups) { if (g.group_id === sel) return g.kind === 'unlocated' ? 'unlocated' : 'group'; if (g.files.some((f) => f.file_id === sel)) return 'file'; }
  return 'none';
}
function inspectorHtml(s, m, model) {
  const base = renderInspector(model, { advanced: s.advanced }) || '<p class="ot-prompt">Select a group or source file to inspect its evidence.</p>';
  const sel = s.workbench.perTab.contexts.selection;
  let file = null; for (const g of m.groups) { const f = g.files.find((x) => x.file_id === sel); if (f) file = f; }
  if (!file) return base;
  const href = pinnedHref(file.revision_link?.href, m);
  const text = esc(file.revision_link?.text || file.path);
  return base + `<p class="ot4-source-link">Source at the pinned revision: ${href ? `<a href="${esc(href)}" target="_blank" rel="noopener noreferrer">${text}</a>` : `<span>${text}</span>`}</p>`;
}

// Facts of the reference's evidence dialog, from the recorded data (reachable from every selection).
export function evidenceHtml(s) {
  const m = s.views.contexts; const sel = s.workbench.perTab.contexts.selection; if (!m) return '';
  const kind = findKind(m, sel); let title = m.root.name; let description = ''; let n = m.root.distinct_total;
  if (kind === 'group' || kind === 'unlocated') { const g = m.groups.find((x) => x.group_id === sel); title = g.label; n = g.distinct_total; description = groupSummary(g); }
  else if (kind === 'file') { const f = m.groups.flatMap((g) => g.files).find((x) => x.file_id === sel); title = f.path; n = f.distinct_total; description = `${plural(f.distinct_total, 'component record')} cite this path.`; }
  else description = `One pinned repository revision ${m.root.commit_sha.slice(0, 12)}. ${plural(m.root.located_distinct_total, 'distinct record')} have a recorded source location; ${fmt(m.root.unlocated_total)} do not.`;
  return `<p><strong>${esc(title)}</strong></p><p>${esc(description)}</p><p>Source: the recorded software inventory for this analysis, bound to its pinned revision. File membership comes from the recorded location properties. Directory-path categories are a display grouping, not an analysis of runtime behavior.</p><p>${esc(plural(n, 'recorded component record'))} are associated with this selection. Installation, builds and execution were not observed.</p>`;
}

// ------------------------------------------------------------------ viewport, focus and keyboard (document-level, once)
const stage = () => document.getElementById('ot4-stage');
const svgEl = () => document.getElementById('ot4-svg');
function layoutNow(getState) { const s = getState(); const m = s.views.contexts; return m ? layoutMap(m.groups, capacity(m.groups)) : null; }

export function applyContextMapView(getState) {
  const el = svgEl(); const s = getState();
  if (el && s.views.contexts) {
    const layout = layoutNow(getState); const vb = currentBox(viewKey(s), layout);
    el.setAttribute('viewBox', vb.join(' ')); const z = document.getElementById('ot4-zoom'); if (z) z.textContent = zoomPercent(vb) + '%';
  }
  restoreFocus(getState);
}

// Focus returns to the activated item after a re-render replaced it (an SVG card is a fresh element every paint).
let pendingFocus = null;
const focusKey = (t) => (t.dataset.ctx ? `[data-ctx="${CSS.escape(t.dataset.ctx)}"]` : t.dataset.action === 'ctx-more' ? `[data-action="ctx-more"][data-group="${CSS.escape(t.dataset.group || '')}"]` : null);
// A "Show more / Try again" control is repainted twice by one request (to Loading…, then to its final state): its pending focus is kept
// while that group's request is in flight and released by the repaint that follows the final state.
function restoreFocus(getState) {
  if (!pendingFocus) return;
  const g = pendingFocus.group; const inFlight = !!g && getState().workbench.perTab.contexts.map.groups[g]?.state === 'loading';
  const a = document.activeElement;
  if (a && a !== document.body && a.isConnected && a.closest?.('#ot-workbench')) { if (!inFlight) pendingFocus = null; return; }
  const el = document.querySelector(pendingFocus.sel) || (pendingFocus.fallback && document.querySelector(pendingFocus.fallback));
  if (el) el.focus({ preventScroll: true });
  if (!inFlight) pendingFocus = null;
}

export function attachContextMap(getState) {
  const remember = (ev) => {
    const t = ev.target.closest?.('[data-ctx],[data-action="ctx-more"]'); if (!t || !t.closest('#ot4-stage,#ot4-list')) return;
    const sel = focusKey(t); if (!sel) return;
    pendingFocus = { group: t.dataset.action === 'ctx-more' ? t.dataset.group : null, sel, fallback: t.closest('[data-group-id]') ? `[data-ctx="${CSS.escape(t.closest('[data-group-id]').dataset.groupId)}"]` : null };
  };
  document.addEventListener('click', remember, true);
  document.addEventListener('keydown', (ev) => { if (ev.key === 'Enter' || ev.key === ' ') remember(ev); }, true);

  const setBox = (vb) => { const s = getState(); const m = s.views.contexts; if (!m) return; const layout = layoutNow(getState); view = { key: viewKey(s), vb: vb && !same(vb, layout.viewBox) ? vb : null }; applyContextMapView(getState); };
  const same = (a, b) => a.every((v, i) => Math.abs(v - b[i]) < 1e-6);
  const zoom = (f) => { const s = getState(); const m = s.views.contexts; if (!m) return; const layout = layoutNow(getState); const vb = currentBox(viewKey(s), layout); setBox(clampZoom(zoomBox(vb, f), [0, 0, VB_W, layout.viewBox[3]])); };
  const fit = () => setBox(null);

  document.addEventListener('click', (ev) => {
    const z = ev.target.closest?.('[data-ctx-zoom]'); if (z) { zoom(Number(z.dataset.ctxZoom)); return; }
    if (ev.target.closest?.('[data-ctx-fit]')) fit();
  });
  // SVG buttons: Enter/Space activate through the shared click handler; arrows/Home/End move between a zone's cards; the stage zooms.
  // List view: Arrow Up/Down and Home/End move between the file buttons of the focused file's own group (never across groups);
  // native controls (Show more, group and root rows, Tab, Enter, chords) are not touched.
  document.addEventListener('keydown', (ev) => {
    const t = ev.target; if (!['ArrowDown', 'ArrowUp', 'Home', 'End'].includes(ev.key) || ev.ctrlKey || ev.metaKey || ev.altKey) return;
    if (t.dataset?.ctxKind !== 'file' || !t.closest?.('#ot4-list')) return;
    const groupEl = t.closest('[data-group-id]'); if (!groupEl) return;
    const ids = [...groupEl.querySelectorAll('[data-ctx-kind=file]')].map((n) => n.dataset.ctx);
    const target = cardTarget(ids, t.dataset.ctx, ev.key); if (!target) return;
    ev.preventDefault(); groupEl.querySelector(`[data-ctx="${CSS.escape(target)}"]`)?.focus();
  });
  document.addEventListener('keydown', (ev) => {
    const t = ev.target; if (!t.closest?.('#ot4-stage')) return;
    if ((ev.key === 'Enter' || ev.key === ' ') && t.matches('g[role=button]')) { ev.preventDefault(); t.dispatchEvent(new MouseEvent('click', { bubbles: true })); return; }
    if (t.id === 'ot4-stage') { if (ev.key === '+' || ev.key === '=') { ev.preventDefault(); zoom(0.8); } else if (ev.key === '-' || ev.key === '_') { ev.preventDefault(); zoom(1.25); } else if (ev.key === '0') { ev.preventDefault(); fit(); } return; }
    if (t.dataset?.ctxKind === 'file' && ['ArrowDown', 'ArrowUp', 'Home', 'End'].includes(ev.key)) {
      const zoneEl = t.closest('[data-zone]'); const ids = [...zoneEl.querySelectorAll('[data-ctx-kind=file]')].map((n) => n.dataset.ctx);
      const target = cardTarget(ids, t.dataset.ctx, ev.key); if (target) { ev.preventDefault(); zoneEl.querySelector(`[data-ctx="${CSS.escape(target)}"]`)?.focus(); }
    }
  });
  let drag = null;
  document.addEventListener('pointerdown', (ev) => {
    const svg = ev.target.closest?.('#ot4-svg'); if (!svg || ev.target.closest('[data-ctx],[data-action]')) return;
    const m = getState().views.contexts; if (!m) return;
    drag = { x: ev.clientX, y: ev.clientY, vb: [...currentBox(viewKey(getState()), layoutNow(getState))], width: svg.getBoundingClientRect().width };
  });
  document.addEventListener('pointermove', (ev) => { if (!drag) return; setBox(panBox(drag.vb, ev.clientX - drag.x, ev.clientY - drag.y, drag.width)); });
  document.addEventListener('pointerup', () => { drag = null; });
  document.addEventListener('pointercancel', () => { drag = null; });
  document.addEventListener('wheel', (ev) => { if (!ev.target.closest?.('#ot4-svg') || !(ev.ctrlKey || ev.metaKey)) return; ev.preventDefault(); zoom(ev.deltaY > 0 ? 1.12 : 0.89); }, { passive: false });
}
