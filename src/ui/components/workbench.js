import { esc, fmt } from '../lib/util.js';
import { TABS, TAB_LABEL } from '../lib/store.js';
import { FINDING_COPY, FINDING_ORDER, LAYER_NOTE, LAYER_SUB, INFO, LIVE_LAYER_NOTE } from '../lib/copy.js';
import { renderContexts } from './context_map.js';
import { renderDependencyView } from './dependency_graph.js';
import { renderCryptoView } from './crypto_graph.js';
import { renderAiView } from './ai_graph.js';
const isLive = (s) => s.analysis?.identity?.mode === 'live';
import { infoButton } from './intake.js';
import { section as gapsSection, inspector as gapInspector, renderBomWorkspace, bomDetailsHtml } from './gaps.js';
import { renderSourceChecks, conclusionLabel } from './sourcecheck.js';
import { panel as lookupPanel } from './lookup.js';
const lookupOf = (s) => s.analysis?.summary?.advisory_lookup || null;
import { summaryMetrics } from '../lib/summary_metrics.js';
import { renderInspector } from './inspector.js';
import { renderEvidenceStrip } from './evidence_strip.js';
import { fromSelection } from '../lib/inspector_model.js';
import { allIds, children, canFull, initialVisible, visibleEdges, FULL_LIMIT } from '../lib/dense.js';

const STATE_LABEL = { unverifiable: 'Could not confirm', contradicted: 'Inventory discrepancy', supported: 'Declared in inventory', inconclusive: 'Could not confirm' };
export const stateLabel = (s) => STATE_LABEL[s] || String(s || '').replaceAll('_', ' ');
const sevClass = (s) => (s === 'HIGH' || s === 'CRITICAL' ? 'warn' : '');

// ---------------------------------------------------------------- summary + checks
function liveCopy(s, c) {
  const sc = (s.analysis.summary.source_checks || []).find((x) => x.assertion_id === c.assertion_id);
  if (!sc) return null;
  const o = sc.source_observation;
  return { mode: 'crypto', tag: sc.conclusion ? conclusionLabel(sc.conclusion.state) : stateLabel(c.state), title: 'A source hash call and the CBOM',
    copy: `createHash("${o.resolution.literal_algorithm}") at ${o.path}:${o.line} compared with the cdxgen CBOM.`, limit: 'Declaration level only; the code is not run.' };
}
function checks(s) {
  const list = s.analysis.summary.checks;
  const byId = Object.fromEntries(list.map((c) => [c.assertion_id, c]));
  const ordered = [...FINDING_ORDER.filter((k) => byId[k]), ...list.map((c) => c.assertion_id).filter((k) => !FINDING_ORDER.includes(k))];
  return ordered.map((id) => {
    const c = byId[id]; const f = FINDING_COPY[id] || liveCopy(s, c);
    const tag = f?.tag || stateLabel(c.state);
    return `<button type="button" class="ot-small-card ot-finding" data-action="open-check" data-check="${esc(id)}" data-mode="${f?.mode || 'bom'}" aria-pressed="false">
      <span class="ot-badge">${esc(tag)}</span><h3>${esc(f?.title || id)}</h3>
      <p>${esc(f?.copy || c.rationale || '')}</p><p>${esc(f?.limit || (c.not_established || [])[0] || '')}</p>
      <span class="text-action">Inspect evidence →</span>
      ${s.advanced ? `<p class="ot-advanced-detail">${esc(id)} · ${esc(c.rule_id || 'no rule')}</p>` : ''}</button>`;
  }).join('');
}

// ---------------------------------------------------------------- dependencies
const trunc = (t, n) => (t.length > n ? t.slice(0, n - 1) + '…' : t);
const advMatch = (n) => false; // advisory match flags come from the payload (see nodeFlags)

function depNodes(d, narrow) {
  const sideItems = (side) => (side?.items || []);
  return { left: sideItems(d.incoming), right: sideItems(d.outgoing), focus: d.focus };
}

function depSvg(s, d) {
  const dep = s.workbench.perTab.dependencies; const narrow = s.narrow;
  const { left, right, focus } = depNodes(d, narrow);
  const matched = new Set((d.matched_ids || []));
  const node = (c, x, y, w, cls) => {
    const name = c.name || '(unnamed)'; const v = c.version || 'Version not reported';
    const flag = cls.includes('focus') ? 'focus' : '';
    const chosen = dep.selection === c.id ? ' chosen' : '';
    const pathCls = c.advisory ? ' match' : (cls.includes('focus') ? '' : ' path');
    return `<g class="ot-node${chosen}${pathCls}" role="button" tabindex="0" data-dep-node="${esc(c.id)}" data-flag="${flag}" aria-pressed="${dep.selection === c.id}" aria-label="${esc(name + ' ' + v)}${flag ? ', focused package' : ''}"><title>${esc(name + ' ' + v)}</title><rect x="${x}" y="${y}" width="${w}" height="54" rx="6"/><text x="${x + w / 2}" y="${y + 23}" text-anchor="middle" font-size="12.5" font-weight="600">${esc(trunc(name, narrow ? 34 : 24))}</text><text class="sub" x="${x + w / 2}" y="${y + 41}" text-anchor="middle" font-size="11.5">${esc(trunc(v, 26))}${s.advanced ? '' : ''}</text></g>`;
  };
  let body = ''; let W; let H;
  if (!narrow) {
    const rows = Math.max(left.length, right.length, 1); H = rows * 70 + 30; W = 780;
    const cy = H / 2 - 27; const fx = 285, fw = 210, lx = 15, rx = 555, nw = 210;
    left.forEach((c, i) => { const y = 15 + i * 70 + (rows - left.length) * 35; body += `<path class="ot-edge" d="M${lx + nw} ${y + 27} C ${lx + nw + 40} ${y + 27}, ${fx - 40} ${cy + 27}, ${fx} ${cy + 27}" marker-end="url(#ot-arrow)"/>`; });
    right.forEach((c, i) => { const y = 15 + i * 70 + (rows - right.length) * 35; body += `<path class="ot-edge" d="M${fx + fw} ${cy + 27} C ${fx + fw + 40} ${cy + 27}, ${rx - 40} ${y + 27}, ${rx} ${y + 27}" marker-end="url(#ot-arrow)"/>`; });
    left.forEach((c, i) => { body += node(c, lx, 15 + i * 70 + (rows - left.length) * 35, nw, ''); });
    right.forEach((c, i) => { body += node(c, rx, 15 + i * 70 + (rows - right.length) * 35, nw, ''); });
    body += node(focus, fx, cy, fw, 'focus');
  } else {
    W = 340; const nw = 290; const x = 25; let y = 12; const ly = []; const ry = [];
    left.forEach(() => { ly.push(y); y += 74; }); const fy = y + 14; y = fy + 54 + 40; right.forEach(() => { ry.push(y); y += 74; });
    H = y + 6;
    ly.forEach((yy) => { body += `<path class="ot-edge" d="M170 ${yy + 54} V ${fy}" marker-end="url(#ot-arrow)"/>`; });
    ry.forEach((yy) => { body += `<path class="ot-edge" d="M170 ${fy + 54} V ${yy}" marker-end="url(#ot-arrow)"/>`; });
    left.forEach((c, i) => { body += node(c, x, ly[i], nw, ''); }); right.forEach((c, i) => { body += node(c, x, ry[i], nw, ''); });
    body += node(focus, x, fy, nw, 'focus');
  }
  return `<svg id="ot-dep-svg" data-w="${W}" data-h="${H}" viewBox="0 0 ${W} ${H}" role="group" aria-label="Package connections for ${esc(focus.name)}"><defs><marker id="ot-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0 0 10 5 0 10z" fill="var(--dep-path)"/></marker></defs><g id="ot-dep-vp">${body}</g></svg>`;
}

function pager(side, which, narrow) {
  if (!side) return '';
  const per = narrow ? 1 : 6;
  const from = side.total ? side.offset + 1 : 0; const to = side.offset + side.shown;
  return `<div class="ot-pager"><button type="button" data-action="page" data-side="${which}" data-dir="-1" aria-label="Previous ${which === 'in' ? 'used by' : 'dependencies'}" ${side.offset <= 0 ? 'disabled' : ''}>‹</button><span>${side.total ? `${from}–${to} of ${fmt(side.total)}` : 'None recorded in this context'}</span><button type="button" data-action="page" data-side="${which}" data-dir="1" aria-label="Next ${which === 'in' ? 'used by' : 'dependencies'}" ${side.has_more ? '' : 'disabled'}>›</button></div>`;
}

function depList(s, d, shared = false) {
  const dep = s.workbench.perTab.dependencies; const cl = d.component_list;
  if (!cl) return '<p class="ot-prompt ot-loading" role="status">Loading components…</p>';
  const from = cl.total ? cl.offset + 1 : 0; const to = cl.offset + cl.items.length;
  const row = (c) => `<button type="button" class="component-item${dep.selection === c.id ? ' selected' : ''}" data-dep-node="${esc(c.id)}" aria-pressed="${dep.selection === c.id}"><span><strong>${esc(c.name)}</strong><small>${esc(c.version || 'Version not reported')} · ${esc(c.type || '')}${s.advanced ? ' · ' + esc(c.locations.join(', ') || 'no location') : ''}</small></span><span class="component-tag">${c.advisory ? 'Advisory match' : ''}</span></button>`;
  const explore = shared ? `<button type="button" class="button small" data-action="dep-explore" ${dep.selection && dep.selection !== dep.focus ? '' : 'disabled'}>Explore selected package</button>` : '';
  return `<div class="ot-list-head">${shared ? explore : `<input type="search" id="ot-list-search" data-fk="lq" placeholder="Search components in this context…" aria-label="Search components in this context" autocomplete="off" value="${esc(dep.listQuery)}">`}<p class="ot-help" id="ot-list-count" aria-live="polite">${fmt(cl.total)} component record${cl.total === 1 ? '' : 's'}${dep.listQuery ? ` matching “${esc(dep.listQuery)}”` : ''} · showing ${from}–${to}</p></div>
  <div class="ot-list" id="ot-component-list">${cl.items.map(row).join('') || '<p class="ot-prompt">No captured component matches in this source context.</p>'}</div>
  <div class="ot-pager"><button type="button" data-action="list-page" data-dir="-1" ${cl.offset <= 0 ? 'disabled' : ''}>‹ Previous</button><span>${cl.total ? `Page ${Math.floor(cl.offset / cl.page_size) + 1} of ${Math.max(1, Math.ceil(cl.total / cl.page_size))}` : ''}</span><button type="button" data-action="list-page" data-dir="1" ${to >= cl.total ? 'disabled' : ''}>Next ›</button></div>
  <p class="ot-help ot-list-note">Selecting a row inspects it without changing the graph focus${d.focus ? ` (${esc(d.focus.name)})` : ''}. Use “Explore selected package” to recenter.</p>`;
}

// Advanced: dense exploration of the scope's already-loaded network. Presentation only.
// The loaded network only applies while it belongs to the selected context (it reloads on context change).
export function activeNetwork(s) {
  const dep = s.workbench.perTab.dependencies;
  return s.network && s.network.context_path === (dep.context || null) ? s.network : null;
}
export function denseVisible(s) {
  const net = activeNetwork(s); const dep = s.workbench.perTab.dependencies; const f = s.views.dependencies?.focus;
  if (!net) return [];
  if (dep.dense.visible) return dep.dense.visible;
  return dep.dense.view === 'full' ? allIds(net) : initialVisible(net, f?.id);
}
function densePanel(s, d) {
  const net = activeNetwork(s); const dep = s.workbench.perTab.dependencies; const dn = dep.dense;
  if (!net) return '<p class="ot-prompt ot-loading" role="status">Loading the dependency network…</p>';
  const visible = denseVisible(s); const vis = new Set(visible); const sel = dep.selection || d.focus?.id;
  const hidden = sel ? children(net, sel).filter((id) => !vis.has(id)) : [];
  const full = canFull(net);
  const edgesShown = visibleEdges(net, visible);
  const pathInfo = dn.paths ? (dn.paths.rooted ? ` ${dn.paths.ids.filter((id) => vis.has(id)).length} / ${dn.paths.ids.length} introduction-path nodes included.` : ' No recorded path to a graph root was established.') : '';
  const morePaths = dn.paths && dn.paths.ids.some((id) => !vis.has(id));
  return `<div class="ot-dense-controls" id="ot-dense-controls"><div class="segmented" aria-label="Dependency layout"><button type="button" data-action="dense-layout" data-v="flow" aria-pressed="${dn.layout === 'flow'}">Dependency flow</button><button type="button" data-action="dense-layout" data-v="network" aria-pressed="${dn.layout === 'network'}">Network</button></div>
  <label>Show <select id="ot-dense-view" data-fk="dview"><option value="explore" ${dn.view === 'explore' ? 'selected' : ''}>Explore branches</option><option value="full" ${dn.view === 'full' ? 'selected' : ''} ${full ? '' : 'disabled'}>Full context</option></select></label>
  <button type="button" class="button small" data-action="dense-expand" ${hidden.length ? '' : 'disabled'}>${hidden.length ? `Expand dependencies · ${hidden.length} more` : 'Dependencies expanded'}</button>
  <button type="button" class="button small" data-action="dense-paths">Show introduction paths</button>
  <button type="button" class="button small" data-action="dense-back" ${dn.history.length ? '' : 'disabled'}>Back</button>
  ${morePaths ? '<button type="button" class="button small" data-action="dense-allpaths">Show all path nodes</button>' : ''}</div>
  ${full ? '' : `<p class="ot-help ot-dense-limit">Full context is limited to ${FULL_LIMIT} component records; this context has ${fmt(net.nodes.length)}. Choose a narrower source context, or use Explore branches.</p>`}
  <div class="ot-legend"><span><i class="match"></i>${isLive(s) ? 'Live advisory match' : 'Advisory match'}</span><span><i class="path"></i>Highlighted declared path</span><span><i class="chosen"></i>Selected</span><span>Click to inspect · double-click to expand · drag to pan</span></div>
  <div class="ot-stage tall" data-keep="cy-dep" data-cy-dense="1"></div><div id="ot-dense-busy" class="ot-help" role="status" hidden>Arranging captured dependencies…</div>
  <div class="ot-viewport-actions"><button type="button" class="button small" data-action="dense-fit">Fit all</button><button type="button" class="button small" data-action="dense-fitsel">Fit selection</button><button type="button" class="button small" data-action="dense-reset">Reset</button><button type="button" class="button small" data-action="dense-arrange">Arrange</button><button type="button" class="button small" data-action="dense-zoom" data-f="0.8" aria-label="Zoom out">−</button><button type="button" class="button small" data-action="dense-zoom" data-f="1.25" aria-label="Zoom in">+</button><span class="ot-help">Scroll zooms · drag pans</span></div>
  <p class="ot-help ot-dense-status" id="ot-dense-status" role="status">${dn.view === 'full' ? 'Full context' : 'Exploring'} · ${fmt(visible.length)} of ${fmt(net.nodes.length)} component records · ${fmt(edgesShown)} of ${fmt(net.edges.length)} captured edges visible.${pathInfo} ${dn.view === 'full' ? 'All captured relationships in this context are loaded.' : 'Hidden branches remain available.'} Arrows are declarations, not runtime calls.</p>`;
}

function depInspector(s, d) {
  if (!d.inspected) return '<p class="ot-prompt">Select a package to see its details.</p>';
  return renderInspector(fromSelection(s, 'dependencies'), { advanced: s.advanced }) || '<p class="ot-prompt">Select a package to see its details.</p>';
}

function advisories(s, d) {
  if (isLive(s) && lookupOf(s)) return lookupPanel(s);
  if (isLive(s)) return `<section class="ot-advisories" id="ot-adv-live" aria-labelledby="ot-adv-h"><div class="ot-adv-head"><div><h2 id="ot-adv-h">Package advisory matches</h2><p class="ot-help">Advisory lookup is not enabled for this service, so no advisory source was contacted. The captured Frigate advisory snapshot is never applied to live results, and the absence of matches here is not a finding.</p></div></div></section>`;
  const a = d.advisories; const dep = s.workbench.perTab.dependencies;
  const rows = a.items.map((r) => `<article class="ot-adv-row"><div><button type="button" class="ot-pkg" data-action="adv-package" data-id="${esc(r.component_id)}">${esc(r.name)} <span>${esc(r.version)}</span></button><p>${esc(r.summary)}</p><small class="micro">${esc(r.label)} · ${r.records} inventory record${r.records === 1 ? '' : 's'}</small></div><div><span class="ot-sev ${sevClass(r.severity)}">${esc(r.severity || 'Not rated')}</span><p><button type="button" class="evidence-link" data-action="read-advisory" data-key="${esc(r.family)}" data-pkg="${esc(r.name + ' ' + r.version)}">Read advisory ↗</button></p></div></article>`).join('');
  const from = a.total ? a.page * a.page_size + 1 : 0; const to = Math.min((a.page + 1) * a.page_size, a.total);
  return `<section class="ot-advisories" aria-labelledby="ot-adv-h"><div class="ot-adv-head"><div><h2 id="ot-adv-h">Package advisory matches</h2><p class="ot-help">Version-matched findings · OSV snapshot 2026-11-04. Package presence does not establish exploitability.</p></div>${infoButton(INFO.advisories, 'About advisory matches')}</div>
  <div class="ot-search-line"><span class="ot-help">${fmt(a.package_versions)} package versions · ${fmt(a.advisory_groups)} advisory groups</span><input type="search" id="ot-adv-q" data-fk="advq" placeholder="Search package or advisory…" aria-label="Search package or advisory" value="${esc(dep.advQuery)}"></div>
  <div class="ot-adv-list">${rows || '<div class="ot-adv-row"><p>No matches in this filter. This does not establish absence of vulnerabilities.</p></div>'}</div>
  <div class="ot-search-line"><span class="ot-help">${a.total ? `Showing ${from}–${to} of ${fmt(a.total)} package/advisory matches` : ''}</span><span><button type="button" class="button small" data-action="adv-page" data-dir="-1" ${a.page <= 0 ? 'disabled' : ''}>Previous</button> <button type="button" class="button small" data-action="adv-page" data-dir="1" ${to >= a.total ? 'disabled' : ''}>Next</button></span></div>
  <details class="ot-more"><summary>Capture scope and query coverage</summary><p>${fmt(1775)} unique version queries; ${fmt(1955)} versioned npm and PyPI component records were queried across the captured source contexts, including documentation and development contexts. Package matches use the dated OSV snapshot and are separate from the inventory checks.</p></details></section>`;
}

function renderDeps(s) {
  if (!s.advanced) return renderDependencyView(s, { depInspector, depList: (st, v) => depList(st, v, true) });   // UIP-05: the normal view; Advanced keeps the original surface below
  const v = s.views.dependencies; const dep = s.workbench.perTab.dependencies; const ctx = s.views.contextList;   // UIP-04: the full path list comes from the unchanged legacy contexts route
  if (!v || !ctx) return '<p class="ot-prompt ot-loading" role="status">Loading dependencies…</p>';
  const opts = [`<option value="">All captured contexts · ${fmt(s.analysis.summary.components)}</option>`, ...ctx.rows.map((r) => `<option value="${esc(r.path)}" ${dep.context === r.path ? 'selected' : ''}>${esc(r.path)} · ${fmt(r.total)}</option>`)].join('').replace('<option value="">', `<option value="" ${dep.context ? '' : 'selected'}>`);
  const f = v.focus;
  const sr = s.search && s.search.query === dep.search ? s.search : null;
  const results = dep.search ? `<div class="ot-results" id="ot-results" role="listbox" aria-label="Matching components">${(sr?.items || []).map((c) => `<button type="button" role="option" data-action="pick" data-id="${esc(c.id)}"><strong>${esc(c.name)}</strong><span>${esc(c.version || 'Version not reported')} · ${esc(c.locations.join(', ') || 'No source location')}</span></button>`).join('') || (sr ? '<p>No captured component matches in this source context.</p>' : '<p>Searching…</p>')}</div>` : '';
  const canExplore = f && dep.selection && dep.selection !== dep.focus;
  const list = dep.presentation === 'list';
  const dense = s.advanced && !list;
  const bar = f ? `<div class="ot-nbhd-bar"><strong class="ot-nbhd-title">${list ? 'Components' : dense ? 'Dependency network' : 'Package connections'}</strong><span class="ot-grow"></span>${dense ? '' : `<button type="button" class="button small" data-action="back" ${dep.history.length ? '' : 'disabled'}>← Back</button>`}<button type="button" class="button small" data-action="explore" ${canExplore ? '' : 'disabled'}>${canExplore ? 'Explore selected package' : 'Viewing this package'}</button></div>` : '';
  let main;
  if (!f) main = '<p class="ot-prompt">No package is available in this context.</p>';
  else if (list) main = `<div class="ot-nbhd">${bar}</div>${depList(s, v)}`;
  else if (dense) main = `<div class="ot-nbhd">${bar}<p class="ot-help">Explore captured paths, expand branches or inspect the full source network. Arrows are declarations, not runtime calls.</p></div>${densePanel(s, v)}`;
  else main = `<div class="ot-nbhd">${bar}<p class="ot-help">Full network &amp; path tools are in Advanced.</p>
      <div class="ot-cols"><div><strong>Used by</strong><small>Packages that depend on this</small>${pager(v.incoming, 'in', s.narrow)}</div><div><strong>Focused package</strong><small>Click to inspect · double-click to explore</small></div><div><strong>Depends on</strong><small>This package's dependencies</small>${pager(v.outgoing, 'out', s.narrow)}</div></div></div>
      <div class="ot-legend"><span><i class="match"></i>${isLive(s) ? 'Live advisory match' : 'Advisory match'}</span><span><i class="path"></i>Highlighted declared path</span><span><i class="chosen"></i>Selected</span></div>
      <div class="ot-stage">${depSvg(s, v)}<div class="ot-zoom"><button type="button" data-action="zoom" data-f="0.8" aria-label="Zoom out">−</button><button type="button" data-action="zoom" data-f="1.25" aria-label="Zoom in">+</button><span id="ot-zoom-label">100%</span></div></div>
      <div class="ot-viewport-actions"><button type="button" class="button small" data-action="fit">Fit all</button><button type="button" class="button small" data-action="reset">Reset</button></div>`;
  const tail = f && v.incoming && !list && !dense ? `Showing ${1 + v.incoming.shown + v.outgoing.shown} packages around ${esc(f.name)}. Immediate connections only; more packages remain available through search and paging.` : '';
  return `<div class="ot-context-bar"><label for="ot-context">Dependency &amp; advisory context</label><select id="ot-context" data-fk="context">${opts}</select>${infoButton(INFO.context, 'About dependency and advisory context')}</div>
  <div class="ot-layout"><div class="ot-surface">
    <div class="ot-toolbar">${list ? '<span class="ot-help">Search every component in this context; selecting a row inspects it.</span>' : `<div class="ot-search"><input id="ot-pkg-search" data-fk="search" type="search" role="combobox" aria-expanded="${!!dep.search}" aria-controls="ot-results" aria-autocomplete="list" placeholder="Find a package…" autocomplete="off" value="${esc(dep.search)}">${results}</div>`}
      <div class="segmented" aria-label="Dependency presentation"><button type="button" data-action="dep-pres" data-p="graph" aria-pressed="${dep.presentation === 'graph'}">Graph</button><button type="button" data-action="dep-pres" data-p="list" aria-pressed="${dep.presentation === 'list'}">Component list</button></div></div>
    ${main}
    <div class="ot-foot"><p>${tail}</p><p>Source: ${esc(dep.context || 'All captured contexts')}. Arrows mean “declares a dependency on”. Source records do not establish runtime use.</p><p>Red is a ${isLive(s) ? 'live advisory match from this analysis\u2019s OSV lookup' : 'captured package-version advisory match'}, not confirmed exploitability. Green highlights declarations, not safety. These source inventories include documentation and development contexts; shipped/runtime composition was not established.</p></div>
  </div><aside class="ot-inspector" aria-label="Selected package">${depInspector(s, v)}</aside></div>`;
}

// ---------------------------------------------------------------- crypto / ai / bom
function renderFamily(s, tab) {
  const v = s.views[tab]; if (!v) return '<p class="ot-prompt ot-loading" role="status">Loading…</p>';
  const t = s.workbench.perTab[tab]; const sel = t.selection;
  const node = v.nodes.find((n) => n.id === sel);
  let panel = `<p class="ot-prompt">${v.selection_prompt ? esc(v.selection_prompt) : 'Select a check or record in this tab to see its details.'}</p>`;
  if (node) panel = renderInspector(fromSelection(s, tab), { advanced: s.advanced }) || panel;
  const gp = tab === 'bom' ? gapInspector(s) : null;
  if (gp) panel = gp;
  const list = `<div class="ot-list">${v.nodes.map((n) => `<button type="button" class="component-item${sel === n.id ? ' selected' : ''}" data-node="${esc(n.id)}" aria-pressed="${sel === n.id}"><span><strong>${esc(n.id.replace(/^(assertion|evidence|entity):/, ''))}</strong><small>${esc(n.type)}${n.state ? ' · ' + esc(stateLabel(n.state)) : n.kind ? ' · ' + esc(n.kind) : ''}</small></span></button>`).join('')}</div>`;
  const stage = t.presentation === 'graph' ? `<div class="ot-stage tall" data-keep="cy-${tab}" data-cy="${tab}"></div>` : list;
  const scope = tab === 'bom' ? `<div class="ot-foot"><p><strong>Scope relations</strong> (shared scan paths relate two scan scopes; they do not connect records):</p>${(v.scope_links || []).map((l) => `<p>${esc(l.title)} — ${esc(l.reason)}</p>`).join('') || '<p>None recorded.</p>'}<p><strong>Record relations</strong>:</p>${(v.record_links || []).map((l) => `<p>${esc(l.title)} · ${esc(l.status)} — ${esc(l.reason)}</p>`).join('') || '<p>None recorded.</p>'}</div>` : `<div class="ot-foot"><p>Relationships record observation and assessment. No model-to-runtime or cryptographic-protection relationship is asserted.</p>${tab === 'crypto' ? `<p>The CBOM reports ${v.crypto_asset_total} cryptographic assets and ${v.services.length} endpoint services; Python algorithm coverage is not established.</p>` : ''}</div>`;
  return `<div class="ot-layout"><div class="ot-surface"><div class="ot-toolbar"><div class="segmented" aria-label="Presentation"><button type="button" data-action="tab-pres" data-tab="${tab}" data-p="graph" aria-pressed="${t.presentation === 'graph'}">Graph</button><button type="button" data-action="tab-pres" data-tab="${tab}" data-p="list" aria-pressed="${t.presentation === 'list'}">List</button></div><span class="ot-help">Showing ${v.nodes.length} records in this bounded check subgraph.</span>${t.presentation === 'graph' ? `<span><button type="button" class="button small" data-action="gfit" data-tab="${tab}">Fit</button></span>` : ''}</div>${stage}${scope}${tab === 'bom' ? gapsSection(s) : ''}</div><aside class="ot-inspector" aria-label="${gp ? 'Selected candidate gap' : 'Selected record'}">${panel}</aside></div>`;
}

// ---------------------------------------------------------------- page
// UIP-02 §4.1: four small wrapping pills from the pure adapter (values come from the active analysis only).
function renderPills(a) {
  const pill = (m) => `<li data-metric="${esc(m.key)}" data-state="${esc(m.state)}" title="${esc(m.reason ? m.scope + ' \u2014 ' + m.reason : m.scope)}">${m.bare ? '' : `<strong>${m.value === null ? '\u2014' : fmt(m.value)}</strong> `}${esc(m.text)}${m.short ? ` <small>\u00b7 ${esc(m.short)}</small>` : ''}${m.reason && (m.state !== 'measured' || m.short) ? `<span class="sr-only">${esc(m.reason)}</span>` : ''}</li>`;
  return `<div id="ot2-enrichment"><ul class="ot2-summary-pills" role="list" aria-label="Repository summary">${summaryMetrics(a).map(pill).join('')}</ul></div>`;
}

// UIP-02 §3.3: the inventory-check cards and source-backed checks moved here unchanged in behavior; the Evidence view mounts them.
export function inventoryChecks(s) {
  const list = s.analysis.summary.checks || [];
  return `<div class="ot-section-heading"><h2>Inventory checks</h2>${infoButton(INFO.findings, 'About findings')}</div><div class="ot-grid" id="ot-findings">${list.length ? checks(s) : '<p class="ot-prompt">No inventory check is assessed in this analysis.</p>'}</div>${isLive(s) ? renderSourceChecks(s.analysis.summary) : ''}`;
}

export function renderWorkbench(s) {
  const a = s.analysis; if (!a) return '';
  const wb = s.workbench; const id = a.identity;
  const tab = wb.tab;
  const body = tab === 'bom' ? renderBomWorkspace(s) : tab === 'dependencies' ? renderDeps(s) : tab === 'contexts' ? renderContexts(s) : tab === 'crypto' && !s.advanced ? renderCryptoView(s) : tab === 'ai' && (!s.advanced || s.workbench.perTab.ai.stale) ? renderAiView(s) : renderFamily(s, tab);   // UIP-06: the normal Cryptography view; Advanced keeps the generic family surface
  const dv = s.views.dependencies;
  return `${renderPills(a)}
  <div class="ot-section-heading"><h2>Repository graphs</h2>${infoButton(INFO.graphs, 'About repository graphs')}</div>
  <div class="ot-explorer" id="ot-graph-frame" data-active-layer="${tab}"><div class="ot-explorer-head"><div><strong>Repository workbench</strong><span class="micro">${esc(LAYER_SUB[tab])}</span></div><code class="ot-explorer-id" title="${esc(id.commit)}">${esc(id.owner)}/${esc(id.name)} \u00b7 ${esc(id.commit.slice(0, 7))} \u00b7 ${isLive(s) ? 'live scan evidence' : 'captured evidence'}</code></div>
    <div class="ot-tabs" role="tablist" aria-label="Repository graph views">${TABS.map((t) => `<button type="button" role="tab" id="ot-tab-${t}" data-action="tab" data-tab="${t}" aria-selected="${t === tab}" tabindex="${t === tab ? 0 : -1}" aria-controls="ot-tabpanel">${TAB_LABEL[t]}</button>`).join('')}</div>
    ${renderEvidenceStrip(s, tab, tab === 'bom' ? { detailsHtml: bomDetailsHtml(s) } : {})}
    ${isLive(s) && (tab === 'ai' || tab === 'crypto') ? '' : `<p class="ot-help ot-layer-note">${esc((isLive(s) && LIVE_LAYER_NOTE[tab]) || LAYER_NOTE[tab])}</p>`}
    <div id="ot-tabpanel" role="tabpanel" aria-labelledby="ot-tab-${tab}">${body}</div></div>
  ${tab === 'dependencies' && (dv || (isLive(s) && lookupOf(s))) ? advisories(s, dv) : ''}`;   // the live lookup panel needs the lookup data only, never a dependency focus/context (RT-01: zero joined packages leaves no context)
}
