// UIP-06: the Cryptography tab (normal, non-Advanced view): root -> source groups -> asset cards, five filters, Graph/List, zoom/fit/pan,
// detail panel, expanded view and the original-CBOM download. Ported from the approved reference (`ot5-crypto`); fed only by crypto_assets/1.
// Repository text is always escaped. Nothing here infers a group, asset or connector: every drawn node is a payload record.
import { esc, fmt } from '../lib/util.js';
import { renderInspector } from './inspector.js';
import { sourceObservation, cbomRecord, ruleConclusion } from './sourcecheck.js';
import { fromCrypto } from '../lib/inspector_model.js';
import {
  FILTERS, REF, requestKey, zonesOf, buildLayout, fitView, fitAllView, needsFitAll, zoomPercent, zoomView, panView, ensureVisible, nodeRect, keyView, resolveSelection, assetKey,
  findAsset, findGroup, reviewsOf, truncate, fitText, basename, kindLabel, originLabel, statusLabel, emptyText, captureLabel, countsLine, occurrencesNote, servicesNote, producerStateText,
  sourceHref, lineText, CRYPTO_ERRORS, PROJECTION_DETAILS, DEFAULT_ASPECT, ROOT_KEY, groupKey,
} from '../lib/crypto_graph.js';

const errText = (e) => {
  if (!e) return '';
  if (e.code === 'projection_failed' && PROJECTION_DETAILS[e.detail]) return PROJECTION_DETAILS[e.detail];
  return CRYPTO_ERRORS[e.code] || 'The cryptographic assets could not be loaded (' + (e.code || 'request failed') + ').';
};
const cbomName = (s) => (s.analysis?.summary?.cards || []).find((c) => c.kind === 'cbom')?.artifact_name || null;

// ----------------------------------------------------------------------------------------------------------------------- graph
function zoneSvg(z, sel, state) {
  const chosenGroup = z.key !== null && sel === z.key;
  const name = fitText(z.group ? basename(z.group.path || z.group.label) || z.label : z.label, 17, 300);
  const head = z.key === null
    ? `<g class="otc-lane"><rect x="${z.head.x}" y="${z.head.y}" width="${z.head.w}" height="${z.head.h}" rx="6" fill="var(--otc-header)" stroke="var(--otc-edge)" stroke-width="1"/><text x="${z.x + 29}" y="${z.y + 41}" font-size="17" font-weight="600" fill="var(--ink)">${esc(fitText(z.label, 17, 300))}</text><text x="${z.x + 29}" y="${z.y + 63}" font-size="12" fill="var(--muted)">${esc(fitText(z.sub, 12, 300))}</text></g>`
    : `<g role="button" tabindex="0" data-otc-select="${esc(z.key)}" aria-pressed="${chosenGroup}" aria-label="${esc(`${z.label}, ${z.cards.length} asset${z.cards.length === 1 ? '' : 's'}`)}"><rect x="${z.head.x}" y="${z.head.y}" width="${z.head.w}" height="${z.head.h}" rx="6" fill="var(--otc-header)" stroke="${chosenGroup ? 'var(--teal)' : 'var(--otc-edge)'}" stroke-width="${chosenGroup ? 3 : 1}"/><title>${esc(z.label)}</title><text x="${z.x + 29}" y="${z.y + 41}" font-size="17" font-weight="600" fill="var(--ink)">${esc(name)}</text><text x="${z.x + 29}" y="${z.y + 63}" font-size="12" fill="var(--muted)">${esc(fitText(z.sub, 12, 300))}</text></g>`;
  const cards = z.cards.map((c) => {
    const a = c.asset; const key = assetKey(a); const chosen = sel === key; const review = reviewsOf(state.page, a).length > 0;
    const stroke = chosen ? 'var(--dep-selected)' : review ? 'var(--otc-review-edge)' : 'var(--otc-edge)'; const sw = chosen ? 3 : review ? 2 : 1.3;
    const label = `${a.display_name}. ${originLabel(a)}. ${review ? 'Needs review' : 'Recorded ' + kindLabel(a.kind)}`;
    return `<path d="${c.link}" fill="none" stroke="var(--otc-edge)" stroke-width="1.4"/><g role="button" tabindex="0" data-otc-select="${esc(key)}" aria-pressed="${chosen}" aria-label="${esc(label)}"><title>${esc(a.display_name)}</title><rect x="${c.x}" y="${c.y}" width="${c.w}" height="${c.h}" rx="7" fill="${review ? 'var(--otc-review-bg)' : 'var(--otc-file)'}" stroke="${stroke}" stroke-width="${sw}"/><text x="${c.x + 15}" y="${c.y + 24}" fill="var(--ink)" font-size="16" font-weight="600">${esc(fitText(a.display_name, 16, 270))}</text><text x="${c.x + 15}" y="${c.y + 47}" fill="var(--muted)" font-size="13">${esc(fitText(originLabel(a), 13, 270))}</text><text x="${c.x + 15}" y="${c.y + 70}" fill="${review ? 'var(--otc-review-ink)' : 'var(--muted)'}" font-size="11">${review ? 'Needs review' : esc('Recorded ' + kindLabel(a.kind))}</text></g>`;
  }).join('');
  return `<g class="otc-group" data-otc-color="blue"><rect x="${z.x}" y="${z.y}" width="${z.w}" height="${z.h}" rx="9" fill="var(--otc-zone)" stroke="var(--otc-edge)" stroke-dasharray="6 5"/>${head}${cards}</g>`;
}

export function graphSvg(s, page, layout, sel, viewBox) {
  const connectors = layout.connectors.map((k) => `<path d="${k.d}" fill="none" stroke="var(--graph-edge)" stroke-width="1.5" stroke-dasharray="5 5"/>`).join('');
  const repo = page.binding.repository; const chosenRoot = sel === ROOT_KEY; const r = layout.root;
  const root = `<g role="button" tabindex="0" data-otc-select="${ROOT_KEY}" aria-pressed="${chosenRoot}" aria-label="${esc(`${repo.owner}/${repo.name} at ${page.binding.commit_sha.slice(0, 7)}`)}"><rect x="${r.x}" y="${r.y}" width="${r.w}" height="${r.h}" rx="7" fill="var(--dep-selected-soft)" stroke="var(--dep-selected)" stroke-width="${chosenRoot ? 3 : 2}"/><text x="${r.x + 20}" y="${r.y + 28}" font-size="18" font-weight="600" fill="var(--ink)">${esc(fitText(repo.name, 18, 150))} · ${esc(page.binding.commit_sha.slice(0, 7))}</text><text x="${r.x + 20}" y="${r.y + 52}" font-size="12" fill="var(--muted)">Recorded crypto inventory</text></g>`;
  const zones = layout.zones.map((z) => zoneSvg(z, sel, { page })).join('');
  return `<svg id="otc-svg" viewBox="${viewBox.join(' ')}" role="group" aria-label="Source groups and their recorded cryptographic assets"><g font-family="Arial,sans-serif">${root}${connectors}${zones}</g></svg>`;
}

// ----------------------------------------------------------------------------------------------------------------------- detail
function occurrenceHtml(o, binding) {
  const loc = o.source_location; const href = sourceHref(loc, binding);
  const where = `${loc.path} · ${lineText(loc)}`;
  const link = href ? `<a href="${esc(href)}" target="_blank" rel="noreferrer">${esc(where)} ↗</a>` : `<span>${esc(where)}</span>`;
  const note = loc.excerpt_state === 'unavailable' ? '<p class="ot-help">No excerpt is recorded for this location.</p>' : `<pre>${esc(loc.excerpt || '')}</pre>${loc.excerpt_state === 'clipped' ? '<p class="ot-help">The excerpt was clipped for display.</p>' : ''}`;
  return `<div class="otc-source">${link}${o.operation ? `<p>${esc(o.operation)}</p>` : ''}${note}${loc.file_sha256 ? `<small>Source SHA-256 ${esc(loc.file_sha256)}</small>` : ''}</div>`;
}
function attributesHtml(a) {
  const rows = Object.entries(a.attributes).filter(([, v]) => v.state === 'recorded').map(([k, v]) => `${esc(k.replaceAll('_', ' '))}: ${esc(v.value)}${v.basis ? ` (${esc(v.basis)})` : ''}`);
  return rows.length ? rows.join(' · ') : 'No further attributes are recorded for this asset.';
}
// The evidence that has no row form: recorded attributes, per-location source observations (excerpt, pinned-revision link, digest) and, for a group, its
// assets. It renders INSIDE the single shared inspector (see renderInspector); the title, status and explanations come from the shared model.
export function detailExtra(s, page, sel) {
  const asset = findAsset(page, sel); const group = findGroup(page, sel); const b = page.binding;
  if (asset) {
    const occ = asset.occurrences.length ? `<details class="supplement-more"><summary>Source observations · ${fmt(asset.occurrences_total)}</summary>${asset.occurrences.map((o) => occurrenceHtml(o, b)).join('')}${occurrencesNote(asset) ? `<p class="ot-help otc-occ-note">${esc(occurrencesNote(asset))}</p>` : ''}</details>` : '<p class="ot-help">This asset records no source location.</p>';
    return `<p class="otc-attrs"><strong>Recorded attributes:</strong> ${attributesHtml(asset)}</p>${occ}`;
  }
  if (group) {
    const here = page.assets.filter((a) => a.source_group_ids.includes(group.group_id));
    return `<p><strong>Assets in this group on this page (${fmt(here.length)} of ${fmt(group.assets_total)}):</strong></p>${here.map((a) => `<button type="button" class="otc-detail-link" data-otc-select="${esc(assetKey(a))}">${esc(a.display_name)} →</button>`).join('')}`;
  }
  return '';
}

// IR-02: the recorded source-backed check requested from the Evidence view's "Inspect in Cryptography" action, shown with the same three separate
// blocks (observation, CBOM record, rule conclusion). It is read from the analysis summary by its assertion id; nothing is mapped to an asset.
function checkPanel(s, c) {
  if (!c.checkId) return '';
  const sc = (s.analysis?.summary?.source_checks || []).find((x) => x.assertion_id === c.checkId);
  const body = sc && sc.status === 'observed' ? sourceObservation(sc.source_observation) + cbomRecord(sc.cbom_record) + (sc.conclusion ? ruleConclusion(sc.conclusion, sc.assertion_id, false) : '')
    : '<p class="ot-help">This recorded check is not present in the current analysis.</p>';
  return `<section class="otc-check" id="otc-check" aria-label="Requested source-backed check" data-check-id="${esc(c.checkId)}"><div class="otc-check-head"><strong>Source-backed check</strong><button type="button" class="button small" data-otc-check-close="1" data-fk="otc-check-close">Back to assets</button></div>${body}</section>`;
}
// ----------------------------------------------------------------------------------------------------------------------- page chrome
function filters(page) {
  const t = page.filter_totals;
  return `<div class="otc-filters" role="group" aria-label="Filter cryptographic assets">${FILTERS.map((f) => `<button type="button" data-otc-filter="${f.key}" title="${esc(f.title)}" aria-pressed="${page.filter === f.payload}">${esc(f.label)} <span>${fmt(t[f.payload])}</span></button>`).join('')}</div>`;
}
function stateBox(text, retry) {
  return `<div class="otc-state" role="${retry ? 'alert' : 'status'}"><p>${text}</p>${retry ? '<button type="button" class="button small" data-otc-retry="1">Try again</button>' : ''}</div>`;
}
function scopeDetails(s, page) {
  const prods = page.producers.map((p) => `<li><strong>${esc(p.provenance.producer_version || p.provenance.producer_id)}</strong> · ${esc(producerStateText(p))}${p.provenance.experimental ? ' · experimental' : ''}<br><span class="ot-help">${esc(p.scope)}</span></li>`).join('') || '<li>No producer is recorded for this analysis.</li>';
  const svc = page.services.length ? `<ul class="otc-services">${page.services.map((v) => `<li><strong>${esc(v.name)}</strong> <span class="ot-help">${esc(v.endpoint_text)}</span></li>`).join('')}</ul>${servicesNote(page) ? `<p class="ot-help">${esc(servicesNote(page))}</p>` : ''}` : '<p class="ot-help">No endpoint service is listed.</p>';
  return `<details class="otc-scope"><summary>Scope, producers and endpoint services (${fmt(page.services_counts.total)})</summary><ul class="otc-producers">${prods}</ul><p class="ot-help">Endpoint services are listed from the original CBOM; they are not cryptographic assets and are never counted as assets. No source manifest artifact is recorded for this analysis, so no manifest download is offered.</p>${svc}</details>`;
}
function controls(s, page, c, narrowList) {
  const groupOpts = page.source_groups.length ? `<label class="otc-group-pick"><span class="ot-help">Source group</span><select id="otc-group" data-fk="otc-group" aria-label="Limit to one source group"><option value="">All source groups</option>${page.source_groups.map((g) => `<option value="${esc(g.group_id)}" ${c.group === g.group_id ? 'selected' : ''}>${esc(truncate(g.label, 60))} · ${fmt(g.assets_total)}</option>`).join('')}</select></label>` : '';
  const search = `<input type="search" id="otc-q" data-fk="otc-q" class="otc-q" placeholder="Search assets or paths…" aria-label="Search cryptographic assets and source paths" autocomplete="off" value="${esc(c.q)}">`;
  const list = c.presentation === 'list';
  return `<div class="otc-controls"><div class="segmented" aria-label="Cryptography presentation"><button type="button" data-otc-pres="graph" aria-pressed="${!list}">Graph</button><button type="button" data-otc-pres="list" aria-pressed="${list}">List</button></div>${search}${groupOpts}<button type="button" class="button small otc-expand" id="otc-expand" data-fk="otc-expand" data-otc-expand="1" aria-expanded="${!!c.expanded}" aria-controls="otc-expanded">${c.expanded ? 'Close expanded view' : 'Expand'}</button></div>`;
}
function pager(page) {
  const p = page.page; if (p.assets_total <= p.size && p.offset === 0) return '';
  const from = p.assets_total ? p.offset + 1 : 0; const to = p.offset + p.assets_shown;
  return `<div class="otc-pager"><button type="button" data-otc-page="-1" aria-label="Previous 30 assets" ${p.offset <= 0 ? 'disabled' : ''}>‹</button><span aria-live="polite">${from}–${to} of ${fmt(p.assets_total)}</span><button type="button" data-otc-page="1" aria-label="Next 30 assets" ${p.has_more ? '' : 'disabled'}>›</button></div>`;
}
function listHtml(page, sel) {
  return `<div class="otc-list" id="otc-list">${page.assets.map((a) => { const has = reviewsOf(page, a).length > 0;
    return `<button type="button" class="otc-list-row" data-otc-select="${esc(assetKey(a))}" aria-pressed="${sel === assetKey(a)}"><span><strong>${esc(a.display_name)}</strong><small>${esc(originLabel(a))} · ${esc(kindLabel(a.kind))}</small></span><span class="otc-status ${has ? 'review' : ''}">${has ? 'Needs review' : esc(kindLabel(a.kind))}</span></button>`; }).join('')}</div>`;
}

// helpers: none needed from workbench.js (the inspector shell is imported directly).
export function renderCryptoView(s) {
  if (s.busy === 'ending') return '<p class="ot-prompt" role="status">Ending the session… the cryptography data has been cleared.</p>';
  const c = s.workbench.perTab.crypto; const page = s.views.cryptoPage;
  if (c.stale) return `<div class="ot-layout"><div class="ot-surface"><div class="otc-state otc-stale" role="alert"><p>${esc(CRYPTO_ERRORS.stale_generation)}</p><button type="button" class="button small" data-otc-stale-reset="1" data-fk="otc-stale-reset">Reopen the analysis</button></div></div></div>`;
  if (!page) {
    const failed = c.pg.status === 'error';
    return `<div class="ot-layout"><div class="ot-surface">${checkPanel(s, c)}${failed ? stateBox(esc(errText(c.pg.error)), true) : stateBox('Loading cryptographic assets…', false)}</div></div>`;
  }
  const sel = resolveSelection(page, c.sel); const zones = zonesOf(page); const layout = buildLayout(zones);
  const list = c.presentation === 'list'; const hasAssets = page.assets.length > 0;
  const dl = cbomName(s);
  const download = dl ? `<a class="button small" href="/api/artifacts/${encodeURIComponent(dl)}?disposition=attachment" download="${esc(dl)}">Download CBOM ↓</a>` : '<span class="ot-help">No CBOM artifact to download</span>';
  const banner = hasAssets && page.availability.state !== 'completed' ? `<p class="otc-availability" role="status" data-state="${esc(page.availability.state)}">${esc(page.availability.message)}</p>` : '';
  const failed = c.pg.status === 'error' ? `<div class="otc-banner" role="alert">${esc(errText(c.pg.error))} <button type="button" class="text-action" data-otc-retry="1">Try again</button></div>` : '';
  const loading = c.pg.status === 'loading' ? '<p class="ot-help otc-loading" role="status">Updating…</p>' : '';
  let main;
  if (!hasAssets) main = `<p id="otc-empty" class="otc-empty" role="status" data-cause="${page.filter_totals.all === 0 ? esc(page.availability.state) : 'filter'}">${esc(emptyText(page, c.filter, c.q))}</p>`;
  else if (list) main = listHtml(page, sel);
  else {
    const vb = fitView(layout);
    main = `<div class="ot-stage otc-stage" id="otc-stage" tabindex="0" role="application" aria-label="Cryptography graph. Click an asset to inspect it. Arrow keys pan; plus, minus and zero zoom and fit.">${graphSvg(s, page, layout, sel, vb)}<div class="otc-zoomctl"><button type="button" class="graph-tool" data-otc-zoom="0.8333" aria-label="Zoom cryptography out">−</button><span id="otc-zoom" class="otc-zoom" aria-live="off">100%</span><button type="button" class="graph-tool" data-otc-zoom="1.2" aria-label="Zoom cryptography in">+</button><button type="button" class="graph-tool" data-otc-fit="1" aria-label="Fit cryptography graph">Fit</button>${needsFitAll(layout) ? '<button type="button" class="graph-tool" data-otc-fitall="1" aria-label="Fit the whole cryptography graph">Fit all</button>' : ''}</div></div>`;
  }
  const insp = renderInspector(fromCrypto(s, page, sel), { advanced: s.advanced, extra: detailExtra(s, page, sel), ids: { title: 'otc-title', detail: 'otc-detail' } });
  const aside = `<aside class="ot-inspector otc-aside" aria-label="Selected cryptographic asset">${insp}</aside>`;
  const surface = `<div class="ot-surface">${checkPanel(s, c)}<div class="otc-toolbar"><div><span class="otc-capture">${esc(captureLabel(page))}</span><span class="ot-help">${esc(countsLine(page))}</span></div>${download}</div>${filters(page)}${controls(s, page, c, list)}${banner}${failed}${main}${pager(page)}${loading}<p class="ot-help otc-sr" id="otc-status" role="status" aria-live="polite">${esc(`${page.page.assets_total} asset${page.page.assets_total === 1 ? '' : 's'} shown for this filter.`)}</p>${scopeDetails(s, page)}</div>`;
  const body = `<div class="ot-layout otc-layout">${surface}${aside}</div>`;
  return c.expanded ? `<div class="otc-expanded" id="otc-expanded" role="dialog" aria-modal="true" aria-label="Expanded cryptography graph">${body}</div>` : body;
}

// ----------------------------------------------------------------------------------------------------------------------- viewport
const vp = { view: null, key: '', fit: null, layoutKey: '' };
const aspectOf = () => { const st = typeof document !== 'undefined' ? document.getElementById('otc-stage') : null; return st && st.clientWidth && st.clientHeight ? st.clientHeight / st.clientWidth : DEFAULT_ASPECT; };
function currentLayout(s) { const page = s.views.cryptoPage; return page ? buildLayout(zonesOf(page)) : null; }
const keyOf = (s) => { const c = s.workbench.perTab.crypto; const p = s.views.cryptoPage; return p ? JSON.stringify([requestKey(c), p.page.offset, p.assets.length, p.source_groups.length, s.narrow, !!c.expanded, c.presentation]) : ''; };
export function applyCryptoView(getState) {
  const svg = document.getElementById('otc-svg'); if (!svg) { vp.view = null; vp.key = ''; return; }
  const s = getState(); const layout = currentLayout(s); if (!layout) return;
  const k = keyOf(s); const aspect = aspectOf();
  if (vp.key !== k || !vp.view) { vp.view = fitView(layout, aspect); vp.key = k; }
  svg.setAttribute('viewBox', vp.view.join(' '));
  const z = document.getElementById('otc-zoom'); if (z) z.textContent = zoomPercent(vp.view, layout) + '%';
}
// Keep the selected card in view after a selection change (pan only, never a zoom change).
export function revealSelection(getState) {
  const s = getState(); const page = s.views.cryptoPage; if (!page || !vp.view) return;
  const layout = currentLayout(s); const rect = nodeRect(layout, resolveSelection(page, s.workbench.perTab.crypto.sel)); if (!rect) return;
  vp.view = ensureVisible(vp.view, rect, layout); applyCryptoView(getState);
}
// While the expanded frame is open everything outside it is inert; the native modal <dialog> for information popovers stays usable.
let inerted = [];
export function syncCryptoExpandedShell() {
  if (typeof document === 'undefined') return;
  const frame = document.getElementById('otc-expanded');
  for (const n of inerted) n.inert = false;
  inerted = [];
  if (!frame) return;
  for (let n = frame; n.parentElement; n = n.parentElement) for (const sib of n.parentElement.children) {
    if (sib === n || sib.tagName === 'DIALOG' || sib.tagName === 'SCRIPT' || sib.tagName === 'STYLE') continue;
    sib.inert = true; inerted.push(sib);
  }
}

// hooks: { select(id, restoreFocus), filter(key), present(p), expand(), collapse(), page(dir), retry(), staleReset() }
export function attachCryptoGraph(getState, hooks) {
  let drag = null;
  const setView = (v) => { if (!v) return; vp.view = v; applyCryptoView(getState); };
  document.addEventListener('click', (ev) => {
    const t = ev.target; if (!t.closest) return;
    const z = t.closest('[data-otc-zoom]'); if (z) { const l = currentLayout(getState()); if (l && vp.view) setView(zoomView(vp.view, Number(z.dataset.otcZoom), l)); return; }
    if (t.closest('[data-otc-fit]')) { const l = currentLayout(getState()); if (l) setView(fitView(l, aspectOf())); return; }
    if (t.closest('[data-otc-fitall]')) { const l = currentLayout(getState()); if (l) setView(fitAllView(l, aspectOf())); return; }
    const f = t.closest('[data-otc-filter]'); if (f) { hooks.filter(f.dataset.otcFilter); return; }
    const p = t.closest('[data-otc-pres]'); if (p) { hooks.present(p.dataset.otcPres); return; }
    const pg = t.closest('[data-otc-page]'); if (pg && !pg.disabled) { hooks.page(Number(pg.dataset.otcPage)); return; }
    if (t.closest('[data-otc-expand]')) { hooks.expand(); return; }
    if (t.closest('[data-otc-retry]')) { hooks.retry(); return; }
    if (t.closest('[data-otc-check-close]')) { hooks.closeCheck(); return; }
    if (t.closest('[data-otc-stale-reset]')) { hooks.staleReset(); return; }
    const sel = t.closest('[data-otc-select]'); if (sel) hooks.select(sel.dataset.otcSelect, false);
  });
  document.addEventListener('keydown', (ev) => {
    const frame = document.getElementById('otc-expanded');
    if (frame && !document.getElementById('ot-dialog')?.open) {            // expanded frame: Escape closes it, Tab stays inside it
      if (ev.key === 'Escape') { ev.preventDefault(); hooks.collapse(); return; }
      if (ev.key === 'Tab') {
        const items = [...frame.querySelectorAll('button,[href],input,select,textarea,summary,[tabindex]:not([tabindex="-1"])')].filter((n) => !n.disabled && n.getClientRects().length);
        if (items.length) { const first = items[0]; const last = items[items.length - 1]; const at = document.activeElement;
          if (!frame.contains(at)) { ev.preventDefault(); first.focus(); } else if (ev.shiftKey && at === first) { ev.preventDefault(); last.focus(); } else if (!ev.shiftKey && at === last) { ev.preventDefault(); first.focus(); } }
        return;
      }
    }
    const t = ev.target; if (!t.closest) return;
    const node = t.closest('g[data-otc-select]');
    if (node && (ev.key === 'Enter' || ev.key === ' ')) { ev.preventDefault(); hooks.select(node.dataset.otcSelect, true); return; }
    if (t.id === 'otc-stage' && vp.view) {
      const l = currentLayout(getState()); const v = l ? keyView(vp.view, ev.key, l, aspectOf()) : null;
      if (v) { ev.preventDefault(); setView(v); }
    }
  });
  document.addEventListener('pointerdown', (ev) => {
    const svg = ev.target.closest?.('#otc-svg'); if (!svg || ev.target.closest('[data-otc-select]') || !vp.view) return;
    drag = { x: ev.clientX, y: ev.clientY, view: [...vp.view] };
  });
  document.addEventListener('pointermove', (ev) => {
    if (!drag) return; const svg = document.getElementById('otc-svg'); if (!svg) { drag = null; return; }
    const r = svg.getBoundingClientRect(); const scale = Math.max(drag.view[2] / r.width, drag.view[3] / r.height); const l = currentLayout(getState());
    if (l) setView(panView(drag.view, -(ev.clientX - drag.x) * scale, -(ev.clientY - drag.y) * scale, l));
  });
  const stop = () => { drag = null; };
  document.addEventListener('pointerup', stop); document.addEventListener('pointercancel', stop);
  document.addEventListener('wheel', (ev) => {
    if (!ev.target.closest?.('#otc-svg') || !(ev.ctrlKey || ev.metaKey)) return;
    ev.preventDefault(); const l = currentLayout(getState()); if (l && vp.view) setView(zoomView(vp.view, ev.deltaY > 0 ? 0.9 : 1 / 0.9, l));
  }, { passive: false });
}
