// UIP-07: the AI models tab (normal, non-Advanced view): root -> source groups -> asset cards, five filters, Graph/List, zoom/fit/pan, detail
// panel, expanded view and the AI-BOM download. Ported from the approved reference (`ot6-ai`); fed only by ai_assets/1. Repository text is
// always escaped. Nothing here infers a group, asset or connector: every drawn node is a payload record. Layout, viewport maths and the
// pinned-link guard are the accepted UIP-06 functions, imported unchanged.
import { esc, fmt } from '../lib/util.js';
import { renderInspector } from './inspector.js';
import { fromAi } from '../lib/inspector_model.js';
import { FINDING_COPY } from '../lib/copy.js';
import {
  REF, buildLayout, fitView, fitAllView, needsFitAll, zoomPercent, zoomView, panView, ensureVisible, nodeRect, keyView, truncate, fitText, basename,
  sourceHref, lineText, DEFAULT_ASPECT,
} from '../lib/crypto_graph.js';
import {
  FILTERS, requestKey, aiZones, alternativeLinks, resolveSelection, assetKey, findAsset, findGroup, reviewsOf, familyOf, kindLabel, originLabel, statusLabel,
  emptyText, captureLabel, countsLine, occurrencesNote, producerStateText, ATTRIBUTE_LABELS, AI_ERRORS, PROJECTION_DETAILS, ROOT_KEY,
} from '../lib/ai_graph.js';

const errText = (e) => {
  if (!e) return '';
  if (e.code === 'projection_failed' && PROJECTION_DETAILS[e.detail]) return PROJECTION_DETAILS[e.detail];
  return AI_ERRORS[e.code] || 'The AI assets could not be loaded (' + (e.code || 'request failed') + ').';
};
const aibomName = (s) => { const c = (s.analysis?.summary?.cards || []).find((x) => x.kind === 'aibom'); return c && c.artifact_name ? c.artifact_name : null; };

// ----------------------------------------------------------------------------------------------------------------------- graph
function zoneSvg(z, sel, state) {
  const chosenGroup = z.key !== null && sel === z.key;
  const name = fitText(z.group ? basename(z.group.path || z.group.label) || z.label : z.label, 17, 300);
  const head = z.key === null
    ? `<g class="otai-lane"><rect x="${z.head.x}" y="${z.head.y}" width="${z.head.w}" height="${z.head.h}" rx="6" fill="var(--otai-header)" stroke="var(--otai-edge)" stroke-width="1"/><text x="${z.x + 29}" y="${z.y + 41}" font-size="17" font-weight="600" fill="var(--ink)">${esc(fitText(z.label, 17, 300))}</text><text x="${z.x + 29}" y="${z.y + 63}" font-size="12" fill="var(--muted)">${esc(fitText(z.sub, 12, 300))}</text></g>`
    : `<g role="button" tabindex="0" data-otai-select="${esc(z.key)}" aria-pressed="${chosenGroup}" aria-label="${esc(`${z.label}, ${z.cards.length} asset${z.cards.length === 1 ? '' : 's'}`)}"><rect x="${z.head.x}" y="${z.head.y}" width="${z.head.w}" height="${z.head.h}" rx="6" fill="var(--otai-header)" stroke="${chosenGroup ? 'var(--teal)' : 'var(--otai-edge)'}" stroke-width="${chosenGroup ? 3 : 1}"/><title>${esc(z.label)}</title><text x="${z.x + 29}" y="${z.y + 41}" font-size="17" font-weight="600" fill="var(--ink)">${esc(name)}</text><text x="${z.x + 29}" y="${z.y + 63}" font-size="12" fill="var(--muted)">${esc(fitText(z.sub, 12, 300))}</text></g>`;
  const cards = z.cards.map((c) => {
    const a = c.asset; const key = assetKey(a); const chosen = sel === key; const review = reviewsOf(state.page, a).length > 0;
    const stroke = chosen ? 'var(--dep-selected)' : review ? 'var(--otai-review-edge)' : 'var(--otai-asset-edge)'; const sw = chosen ? 3 : review ? 2 : 1.3;
    const third = review ? 'Needs review' : a.display_group ? 'Same name as another asset' : originLabel(a);
    const label = `${a.display_name}. ${kindLabel(a.kind)}. ${review ? 'Needs review' : originLabel(a)}`;
    return `<path d="${c.link}" fill="none" stroke="var(--otai-edge)" stroke-width="1.4"/><g role="button" tabindex="0" data-otai-select="${esc(key)}" data-otai-kind="${familyOf(a)}" aria-pressed="${chosen}" aria-label="${esc(label)}"><title>${esc(a.display_name)}</title><rect x="${c.x}" y="${c.y}" width="${c.w}" height="${c.h}" rx="7" fill="${review ? 'var(--otai-review-bg)' : 'var(--otai-asset-bg)'}" stroke="${stroke}" stroke-width="${sw}"/><text x="${c.x + 15}" y="${c.y + 24}" fill="var(--ink)" font-size="16" font-weight="600">${esc(fitText(a.display_name, 16, 270))}</text><text x="${c.x + 15}" y="${c.y + 47}" fill="var(--muted)" font-size="13">${esc(fitText(kindLabel(a.kind), 13, 270))}</text><text x="${c.x + 15}" y="${c.y + 70}" fill="${review ? 'var(--otai-review-ink)' : 'var(--muted)'}" font-size="11">${esc(fitText(third, 11, 270))}</text></g>`;
  }).join('');
  return `<g class="otai-group" data-otai-color="blue"><rect x="${z.x}" y="${z.y}" width="${z.w}" height="${z.h}" rx="9" fill="var(--otai-zone)" stroke="var(--otai-edge)" stroke-dasharray="6 5"/>${head}${cards}</g>`;
}
// A preferred/fallback pair is drawn as a dashed labelled alternative path between the two cards (never as concurrently running components).
function altSvg(layout, page) {
  const rect = new Map(); layout.zones.forEach((z) => z.cards.forEach((c) => rect.set(c.asset.asset_id, c)));
  return alternativeLinks(page).map((l) => {
    const a = rect.get(l.from); const b = rect.get(l.to); if (!a || !b) return '';
    const d = a.x === b.x ? `M${a.x + a.w} ${a.y + 45} h14 V${b.y + 45} h-14` : `M${a.x + a.w} ${a.y + 45} L${b.x} ${b.y + 45}`;
    const lx = a.x === b.x ? a.x + 15 : (a.x + b.x) / 2; const ly = a.x === b.x ? Math.min(a.y, b.y) + a.h + 17 : (a.y + b.y) / 2 + 40;     // inside the 30 px gap below the upper card
    const cond = l.condition || 'alternative path';
    return `<g class="otai-alt"><path d="${d}" fill="none" stroke="var(--teal)" stroke-width="1.6" stroke-dasharray="3 4"><title>${esc('Alternative path: ' + cond)}</title></path><text x="${lx}" y="${ly}" font-size="10" fill="var(--muted)">${esc(fitText('alternative: ' + cond, 10, a.x === b.x ? 255 : 150))}</text></g>`;
  }).join('');
}
export function graphSvg(s, page, layout, sel, viewBox) {
  const connectors = layout.connectors.map((k) => `<path d="${k.d}" fill="none" stroke="var(--graph-edge)" stroke-width="1.5" stroke-dasharray="5 5"/>`).join('');
  const repo = page.binding.repository; const chosenRoot = sel === ROOT_KEY; const r = layout.root;
  const root = `<g role="button" tabindex="0" data-otai-select="${ROOT_KEY}" aria-pressed="${chosenRoot}" aria-label="${esc(`${repo.owner}/${repo.name} at ${page.binding.commit_sha.slice(0, 7)}`)}"><rect x="${r.x}" y="${r.y}" width="${r.w}" height="${r.h}" rx="7" fill="var(--dep-selected-soft)" stroke="var(--dep-selected)" stroke-width="${chosenRoot ? 3 : 2}"/><text x="${r.x + 20}" y="${r.y + 28}" font-size="18" font-weight="600" fill="var(--ink)">${esc(fitText(repo.name, 18, 245))} · ${esc(page.binding.commit_sha.slice(0, 7))}</text><text x="${r.x + 20}" y="${r.y + 52}" font-size="12" fill="var(--muted)">${esc(fitText(`${page.filter_totals.all} recorded AI asset${page.filter_totals.all === 1 ? '' : 's'}`, 12, 245))}</text></g>`;
  const zones = layout.zones.map((z) => zoneSvg(z, sel, { page })).join('');
  return `<svg id="otai-svg" viewBox="${viewBox.join(' ')}" role="group" aria-label="Source groups and their recorded AI assets"><g font-family="Arial,sans-serif">${root}${connectors}${zones}${altSvg(layout, page)}</g></svg>`;
}

// ----------------------------------------------------------------------------------------------------------------------- detail
function occurrenceHtml(o, binding) {
  const loc = o.source_location; const href = sourceHref(loc, binding);
  const where = `${loc.path} · ${lineText(loc)}`;
  const link = href ? `<a href="${esc(href)}" target="_blank" rel="noreferrer">${esc(where)} ↗</a>` : `<span>${esc(where)}</span>`;
  const note = loc.excerpt_state === 'unavailable' ? '<p class="ot-help">No excerpt is recorded for this location.</p>' : `<pre>${esc(loc.excerpt || '')}</pre>${loc.excerpt_state === 'clipped' ? '<p class="ot-help">The excerpt was clipped for display.</p>' : ''}`;
  const alt = o.alternative_of ? '<p class="otai-alt-note"><strong>Alternative path.</strong> A preferred/fallback option declared in the source; it is not shown as running together with the other option.</p>' : '';
  const cond = o.condition?.text ? `<section class="otai-condition"><strong>Source condition</strong><p>${esc(o.condition.text)}</p></section>` : '';
  return `<div class="otai-source">${link}${o.operation ? `<p>${esc(o.operation)}</p>` : ''}${alt}${cond}${note}${loc.file_sha256 ? `<small>Source SHA-256 ${esc(loc.file_sha256)}</small>` : ''}</div>`;
}
function metadataHtml(a) {
  const rows = Object.entries(ATTRIBUTE_LABELS).map(([k, label]) => { const v = a.attributes[k]; const val = v && v.state === 'recorded' ? `${esc(v.value)}${v.basis ? `<br><small>${esc(v.basis)}</small>` : ''}` : (v && v.state === 'unknown' ? 'Unknown' : 'Not recorded'); return `<div><dt>${esc(label)}</dt><dd>${val}</dd></div>`; }).join('');
  return `<details class="supplement-more"><summary>Asset metadata</summary><dl class="otai-facts">${rows}</dl></details>`;
}
// See crypto_graph.js detailExtra: metadata, per-location source observations (conditions, alternatives, excerpts, links) and group members, rendered inside the
// single shared inspector. Identity, review and status wording come from the shared model.
export function detailExtra(s, page, sel) {
  const asset = findAsset(page, sel); const group = findGroup(page, sel); const b = page.binding;
  if (asset) {
    const occ = asset.occurrences.length ? `<details class="supplement-more"><summary>Source observations · ${fmt(asset.occurrences_total)}</summary>${asset.occurrences.map((o) => occurrenceHtml(o, b)).join('')}${occurrencesNote(asset) ? `<p class="ot-help otai-occ-note">${esc(occurrencesNote(asset))}</p>` : ''}</details>` : '<p class="ot-help">This asset records no repository location. A declared location, if any, is listed in the AI-BOM download.</p>';
    return `${metadataHtml(asset)}${occ}`;
  }
  if (group) {
    const here = page.assets.filter((a) => a.source_group_ids.includes(group.group_id));
    return `<p><strong>Assets in this group on this page (${fmt(here.length)} of ${fmt(group.assets_total)}):</strong></p>${here.map((a) => `<button type="button" class="otai-detail-link" data-otai-select="${esc(assetKey(a))}">${esc(a.display_name)} →</button>`).join('')}`;
  }
  return '';
}

// The existing BOM-verification check a person opened from the Evidence/finding cards ("Inspect evidence"). It is a recorded comparison of the AI inventory
// with a curated declaration - not a model or service security finding - and is read from the analysis summary by its assertion id (nothing is mapped to an asset).
function checkPanel(s, c) {
  if (!c.checkId) return '';
  const chk = (s.analysis?.summary?.checks || []).find((x) => x.assertion_id === c.checkId); const f = FINDING_COPY[c.checkId];
  const body = chk ? `<p><span class="otai-status">${esc(f?.tag || chk.state || 'Recorded check')}</span></p><h3>${esc(f?.title || c.checkId)}</h3><p>${esc(f?.copy || chk.rationale || '')}</p><p class="ot-help">${esc(f?.limit || (chk.not_established || [])[0] || '')}</p><p class="ot-help">This is a BOM-verification check of the AI inventory against a declaration. It is not a model or service security finding.</p>`
    : '<p class="ot-help">This recorded check is not present in the current analysis.</p>';
  return `<section class="otai-check" id="otai-check" aria-label="Requested check" data-check-id="${esc(c.checkId)}"><div class="otai-check-head"><strong>Requested check</strong><button type="button" class="button small" data-otai-check-close="1" data-fk="otai-check-close">Back to assets</button></div>${body}</section>`;
}
// ----------------------------------------------------------------------------------------------------------------------- page chrome
function filters(page) {
  const t = page.filter_totals;
  return `<div class="otai-filters" role="group" aria-label="Filter AI assets">${FILTERS.map((f) => `<button type="button" data-otai-filter="${f.key}" title="${esc(f.title)}" aria-pressed="${page.filter === f.payload}">${esc(f.label)} <span>${fmt(t[f.payload])}</span></button>`).join('')}</div>`;
}
function stateBox(text, retry) {
  return `<div class="otai-state" role="${retry ? 'alert' : 'status'}"><p>${text}</p>${retry ? '<button type="button" class="button small" data-otai-retry="1">Try again</button>' : ''}</div>`;
}
function scopeDetails(page) {
  const prods = page.producers.map((p) => `<li><strong>${esc(p.provenance.producer_version || p.provenance.producer_id)}</strong> · ${esc(producerStateText(p))}${p.provenance.experimental ? ' · experimental' : ''}<br><span class="ot-help">${esc(p.scope)}</span></li>`).join('') || '<li>No producer is recorded for this analysis.</li>';
  return `<details class="otai-scope"><summary>Scope and producers</summary><ul class="otai-producers">${prods}</ul><p class="ot-help">This view lists the models the AI-BOM inventory reports and, when listed above as experimental, runtime imports, inference-API endpoint literals and import fallbacks that a static source scan observed in supported forms. An import or literal does not show that a runtime is installed or in use, or that a service is reachable. Other runtime forms, hosted services and model security findings are not collected or assessed; an empty list does not show that none exist.</p></details>`;
}
function controls(page, c) {
  const groupOpts = page.source_groups.length ? `<label class="otai-group-pick"><span class="ot-help">Source group</span><select id="otai-group" data-fk="otai-group" aria-label="Limit to one source group"><option value="">All source groups</option>${page.source_groups.map((g) => `<option value="${esc(g.group_id)}" ${c.group === g.group_id ? 'selected' : ''}>${esc(truncate(g.label, 60))} · ${fmt(g.assets_total)}</option>`).join('')}</select></label>` : '';
  const search = `<input type="search" id="otai-q" data-fk="otai-q" class="otai-q" placeholder="Search assets or paths…" aria-label="Search AI assets and repository paths" autocomplete="off" value="${esc(c.q)}">`;
  const list = c.presentation === 'list';
  return `<div class="otai-controls"><div class="segmented" aria-label="AI models presentation"><button type="button" data-otai-pres="graph" aria-pressed="${!list}">Graph</button><button type="button" data-otai-pres="list" aria-pressed="${list}">List</button></div>${search}${groupOpts}<button type="button" class="button small otai-expand" id="otai-expand" data-fk="otai-expand" data-otai-expand="1" aria-expanded="${!!c.expanded}">${c.expanded ? 'Close expanded view' : 'Expand'}</button></div>`;
}
function pager(page) {
  const p = page.page; if (p.assets_total <= p.size && p.offset === 0) return '';
  const from = p.assets_total ? p.offset + 1 : 0; const to = p.offset + p.assets_shown;
  return `<div class="otai-pager"><button type="button" data-otai-page="-1" aria-label="Previous 30 assets" ${p.offset <= 0 ? 'disabled' : ''}>‹</button><span aria-live="polite">${from}–${to} of ${fmt(p.assets_total)}</span><button type="button" data-otai-page="1" aria-label="Next 30 assets" ${p.has_more ? '' : 'disabled'}>›</button></div>`;
}
function listHtml(page, sel) {
  return `<div class="otai-list" id="otai-list">${page.assets.map((a) => { const has = reviewsOf(page, a).length > 0;
    return `<button type="button" class="otai-list-row" data-fk="otai-row:${esc(assetKey(a))}" data-otai-select="${esc(assetKey(a))}" aria-pressed="${sel === assetKey(a)}"><span><strong>${esc(a.display_name)}</strong><small>${esc(originLabel(a))} · ${esc(kindLabel(a.kind))}</small></span><span class="otai-status ${has ? 'review' : ''}">${has ? 'Needs review' : esc(kindLabel(a.kind))}</span></button>`; }).join('')}</div>`;
}

export function renderAiView(s) {
  if (s.busy === 'ending') return '<p class="ot-prompt" role="status">Ending the session… the AI models data has been cleared.</p>';
  const c = s.workbench.perTab.ai; const page = s.views.aiPage;
  if (c.stale) return `<div class="ot-layout"><div class="ot-surface"><div class="otai-state otai-stale" role="alert"><p>${esc(AI_ERRORS.stale_generation)}</p><button type="button" class="button small" data-otai-stale-reset="1" data-fk="otai-stale-reset">Reopen the analysis</button></div></div></div>`;
  if (!page) {
    const failed = c.pg.status === 'error';
    return `<div class="ot-layout"><div class="ot-surface">${checkPanel(s, c)}${failed ? stateBox(esc(errText(c.pg.error)), true) : stateBox('Loading AI assets…', false)}</div></div>`;
  }
  const sel = resolveSelection(page, c.sel); const zones = aiZones(page); const layout = buildLayout(zones);
  const list = c.presentation === 'list'; const hasAssets = page.assets.length > 0;
  const dl = aibomName(s);
  const download = dl ? `<a class="button small" href="/api/artifacts/${encodeURIComponent(dl)}?disposition=attachment" download="${esc(dl)}">Download AI-BOM ↓</a>` : '<span class="ot-help">No AI-BOM artifact to download for this analysis</span>';
  const banner = `<p class="otai-availability" role="status" data-state="${esc(page.availability.state)}">${esc(page.availability.message)}</p>`;
  const failed = c.pg.status === 'error' ? `<div class="otai-banner" role="alert">${esc(errText(c.pg.error))} <button type="button" class="text-action" data-otai-retry="1">Try again</button></div>` : '';
  const loading = c.pg.status === 'loading' ? '<p class="ot-help otai-loading" role="status">Updating…</p>' : '';
  let main;
  if (!hasAssets) main = `<p id="otai-empty" class="otai-empty" role="status" data-cause="${page.filter_totals.all === 0 ? esc(page.availability.state) : 'filter'}">${esc(emptyText(page, c.filter, c.q))}</p>`;
  else if (list) main = listHtml(page, sel);
  else {
    const vb = fitView(layout);
    main = `<div class="ot-stage otai-stage" id="otai-stage" tabindex="0" role="application" aria-label="AI models graph. Click an asset to inspect it. Arrow keys pan; plus, minus and zero zoom and fit.">${graphSvg(s, page, layout, sel, vb)}<div class="otai-zoomctl"><button type="button" class="graph-tool" data-otai-zoom="0.8333333333333334" aria-label="Zoom AI models out">−</button><span class="otai-zoom" id="otai-zoom">100%</span><button type="button" class="graph-tool" data-otai-zoom="1.2" aria-label="Zoom AI models in">+</button><button type="button" class="graph-tool" data-otai-fit="1" id="otai-fit">Fit</button>${needsFitAll(layout) ? '<button type="button" class="graph-tool" data-otai-fitall="1">Fit all</button>' : ''}</div></div><p class="context-map-boundary ot-help">Connections show recorded locations. Preferred and fallback options, where recorded, are alternative paths. Execution was not observed.</p>`;
  }
  const insp = renderInspector(fromAi(s, page, sel), { advanced: s.advanced, extra: detailExtra(s, page, sel), ids: { title: 'otai-title', detail: 'otai-detail' } });
  const aside = `<aside class="ot-inspector otai-aside" aria-label="Selected AI asset">${insp}</aside>`;
  const surface = `<div class="ot-surface">${checkPanel(s, c)}<div class="otai-toolbar"><div><span class="otai-capture">${esc(captureLabel(page))}</span><span class="ot-help">${esc(countsLine(page))}</span></div>${download}</div>${filters(page)}${controls(page, c)}${banner}${failed}${main}${pager(page)}${loading}<p class="ot-help otai-sr" id="otai-status" role="status" aria-live="polite">${esc(`${page.page.assets_total} AI asset${page.page.assets_total === 1 ? '' : 's'} match this view.`)}</p>${scopeDetails(page)}</div>`;
  const body = `<div class="ot-layout otai-layout">${surface}${aside}</div>`;
  return c.expanded ? `<div class="otai-expanded" id="otai-expanded" role="dialog" aria-modal="true" aria-label="Expanded AI models graph">${body}</div>` : body;
}

// ----------------------------------------------------------------------------------------------------------------------- viewport
const vp = { view: null, key: '' };
const aspectOf = () => { const st = typeof document !== 'undefined' ? document.getElementById('otai-stage') : null; return st && st.clientWidth && st.clientHeight ? st.clientHeight / st.clientWidth : DEFAULT_ASPECT; };
function currentLayout(s) { const page = s.views.aiPage; return page ? buildLayout(aiZones(page)) : null; }
const keyOf = (s) => { const c = s.workbench.perTab.ai; const p = s.views.aiPage; return p ? JSON.stringify([requestKey(c), p.page.offset, p.assets.length, p.source_groups.length, s.narrow, !!c.expanded, c.presentation]) : ''; };
export function applyAiView(getState) {
  const svg = document.getElementById('otai-svg'); if (!svg) { vp.view = null; vp.key = ''; return; }
  const s = getState(); const layout = currentLayout(s); if (!layout) return;
  const k = keyOf(s); const aspect = aspectOf();
  if (vp.key !== k || !vp.view) { vp.view = fitView(layout, aspect); vp.key = k; }
  svg.setAttribute('viewBox', vp.view.join(' '));
  const z = document.getElementById('otai-zoom'); if (z) z.textContent = zoomPercent(vp.view, layout) + '%';
}
export function revealAiSelection(getState) {
  const s = getState(); const page = s.views.aiPage; if (!page || !vp.view) return;
  const layout = currentLayout(s); const rect = nodeRect(layout, resolveSelection(page, s.workbench.perTab.ai.sel)); if (!rect) return;
  vp.view = ensureVisible(vp.view, rect, layout); applyAiView(getState);
}
let inerted = [];
export function syncAiExpandedShell() {
  if (typeof document === 'undefined') return;
  const frame = document.getElementById('otai-expanded');
  for (const n of inerted) n.inert = false;
  inerted = [];
  if (!frame) return;
  for (let n = frame; n.parentElement; n = n.parentElement) for (const sib of n.parentElement.children) {
    if (sib === n || sib.tagName === 'DIALOG' || sib.tagName === 'SCRIPT' || sib.tagName === 'STYLE') continue;
    sib.inert = true; inerted.push(sib);
  }
}

// hooks: { select(id, restoreFocus), filter(key), present(p), expand(), collapse(), page(dir), retry(), staleReset() }
export function attachAiGraph(getState, hooks) {
  let drag = null;
  const setView = (v) => { if (!v) return; vp.view = v; applyAiView(getState); };
  document.addEventListener('click', (ev) => {
    const t = ev.target; if (!t.closest) return;
    const z = t.closest('[data-otai-zoom]'); if (z) { const l = currentLayout(getState()); if (l && vp.view) setView(zoomView(vp.view, Number(z.dataset.otaiZoom), l)); return; }
    if (t.closest('[data-otai-fit]')) { const l = currentLayout(getState()); if (l) setView(fitView(l, aspectOf())); return; }
    if (t.closest('[data-otai-fitall]')) { const l = currentLayout(getState()); if (l) setView(fitAllView(l, aspectOf())); return; }
    const f = t.closest('[data-otai-filter]'); if (f) { hooks.filter(f.dataset.otaiFilter); return; }
    const p = t.closest('[data-otai-pres]'); if (p) { hooks.present(p.dataset.otaiPres); return; }
    const pg = t.closest('[data-otai-page]'); if (pg && !pg.disabled) { hooks.page(Number(pg.dataset.otaiPage)); return; }
    if (t.closest('[data-otai-expand]')) { hooks.expand(); return; }
    if (t.closest('[data-otai-retry]')) { hooks.retry(); return; }
    if (t.closest('[data-otai-check-close]')) { hooks.closeCheck(); return; }
    if (t.closest('[data-otai-stale-reset]')) { hooks.staleReset(); return; }
    const sel = t.closest('[data-otai-select]'); if (sel) hooks.select(sel.dataset.otaiSelect, false);
  });
  document.addEventListener('keydown', (ev) => {
    const frame = document.getElementById('otai-expanded');
    if (frame && !document.getElementById('ot-dialog')?.open) {
      if (ev.key === 'Escape') { ev.preventDefault(); hooks.collapse(); return; }
      if (ev.key === 'Tab') {
        const items = [...frame.querySelectorAll('button,[href],input,select,textarea,summary,[tabindex]:not([tabindex="-1"])')].filter((n) => !n.disabled && n.getClientRects().length);
        if (items.length) { const first = items[0]; const last = items[items.length - 1]; const at = document.activeElement;
          if (!frame.contains(at)) { ev.preventDefault(); first.focus(); } else if (ev.shiftKey && at === first) { ev.preventDefault(); last.focus(); } else if (!ev.shiftKey && at === last) { ev.preventDefault(); first.focus(); } }
        return;
      }
    }
    const t = ev.target; if (!t.closest) return;
    const row = t.closest('.otai-list-row');                       // IR-04: List arrows/Home/End; Tab/Enter/Space stay native, modifiers and text inputs pass through
    if (row && ['ArrowDown', 'ArrowUp', 'Home', 'End'].includes(ev.key) && !(ev.ctrlKey || ev.metaKey || ev.altKey || ev.shiftKey)) {
      const rows = [...(row.closest('#otai-list') || document.getElementById('otai-list'))?.querySelectorAll('.otai-list-row') || []];
      const at = rows.indexOf(row); if (at < 0) return;
      ev.preventDefault();
      const to = ev.key === 'Home' ? 0 : ev.key === 'End' ? rows.length - 1 : Math.min(rows.length - 1, Math.max(0, at + (ev.key === 'ArrowDown' ? 1 : -1)));
      if (to !== at) { rows[to].focus(); hooks.select(rows[to].dataset.otaiSelect, false); }   // focus first: the repaint restores it by data-fk
      return;
    }
    const node = t.closest('g[data-otai-select]');
    if (node && (ev.key === 'Enter' || ev.key === ' ')) { ev.preventDefault(); hooks.select(node.dataset.otaiSelect, true); return; }
    if (t.id === 'otai-stage' && vp.view) {
      const l = currentLayout(getState()); const v = l ? keyView(vp.view, ev.key, l, aspectOf()) : null;
      if (v) { ev.preventDefault(); setView(v); }
    }
  });
  document.addEventListener('pointerdown', (ev) => {
    const svg = ev.target.closest?.('#otai-svg'); if (!svg || ev.target.closest('[data-otai-select]') || !vp.view) return;
    drag = { x: ev.clientX, y: ev.clientY, view: [...vp.view] };
  });
  document.addEventListener('pointermove', (ev) => {
    if (!drag) return; const svg = document.getElementById('otai-svg'); if (!svg) { drag = null; return; }
    const r = svg.getBoundingClientRect(); const scale = Math.max(drag.view[2] / r.width, drag.view[3] / r.height); const l = currentLayout(getState());
    if (l) setView(panView(drag.view, -(ev.clientX - drag.x) * scale, -(ev.clientY - drag.y) * scale, l));
  });
  const stop = () => { drag = null; };
  document.addEventListener('pointerup', stop); document.addEventListener('pointercancel', stop);
  document.addEventListener('wheel', (ev) => {
    if (!ev.target.closest?.('#otai-svg') || !(ev.ctrlKey || ev.metaKey)) return;
    ev.preventDefault(); const l = currentLayout(getState()); if (l && vp.view) setView(zoomView(vp.view, ev.deltaY > 0 ? 0.9 : 1 / 0.9, l));
  }, { passive: false });
}
