// UIP-06: the Cryptography tab model. Pure (no DOM): request identity, selection rules, display text and the SVG layout/viewport.
//
// Geometry is ported from the approved reference (`ot5-crypto` block of OpenTrace-UI-Update-9-Combined.html): the viewBox is 1200 wide, the root
// node is (460,20) 280x72, source-group zones are 360 wide with 40 px gaps, a group header is 330x66 and asset cards are 300x90 at 120 px steps.
// For ordinary data (at most three groups, each with at most three cards) every constant equals the reference. Larger data grows the zones
// downward and wraps groups into rows of three (contract UIP-06 6.2); the model's bounding box is the single source for the viewBox, Fit and pan.
// Nothing here invents a group, asset, connector or text: every drawn node is a payload record.

export const PAGE_SIZE = 30;
export const DEFAULT_FILTER = 'all';
export const FILTERS = [
  { key: 'all', payload: 'all', label: 'All assets', title: 'Every recorded cryptographic asset' },
  { key: 'findings', payload: 'findings', label: 'Findings', title: 'Assets with a rule-backed review item' },
  { key: 'algorithms', payload: 'algorithms', label: 'Algorithms', title: 'Algorithm assets' },
  { key: 'protocols', payload: 'protocols', label: 'Protocols', title: 'Protocol assets' },
  { key: 'certificates', payload: 'certificates', label: 'Certificates', title: 'Certificate assets' },
];
export const payloadFilter = (key) => (FILTERS.find((f) => f.key === key) || FILTERS[0]).payload;

// One request per (filter, group, query, offset); the key is the request's identity (UIP-05 lesson: a response applies only while it still describes the state).
export const requestKey = (c) => JSON.stringify([c.filter, c.q, c.group || null, c.offset]);
export const pageNeeded = (page, c) => !page || c.loaded !== requestKey(c);   // `loaded` = the key of the request whose page is cached

export const REF = {
  W: 1200, ROOT: { x: 460, y: 20, w: 280, h: 72 }, ZONE_W: 360, STRIDE: 400, ZONE_Y: 160, ZONE_H: 500, HEAD: { dx: 15, dy: 16, w: 330, h: 66 },
  CARD: { dx: 42, w: 300, h: 90, first: 120, step: 120 }, ROW_GAP: 60, BOTTOM: 30, TRUNK_X: -20, MIN_ZOOM: 0.2, MAX_ZOOM: 4,
};
export const UNLOCATED_LABEL = 'No recorded source file';

// ------------------------------------------------------------------------------------------------------------------ selection
export const assetKey = (a) => 'asset:' + a.asset_id;
export const groupKey = (g) => 'group:' + g.group_id;
export const ROOT_KEY = 'root';
export function defaultSelection(page) { return page && page.assets.length ? assetKey(page.assets[0]) : ROOT_KEY; }
export function selectionValid(page, sel) {
  if (!page || !sel) return false;
  if (sel === ROOT_KEY) return true;
  return page.assets.some((a) => assetKey(a) === sel) || page.source_groups.some((g) => groupKey(g) === sel);
}
export const resolveSelection = (page, sel) => (selectionValid(page, sel) ? sel : defaultSelection(page));
export const findAsset = (page, sel) => page?.assets.find((a) => assetKey(a) === sel) || null;
export const findGroup = (page, sel) => page?.source_groups.find((g) => groupKey(g) === sel) || null;
export const reviewsOf = (page, asset) => (page?.review_items || []).filter((r) => r.asset_id === asset.asset_id);

// ------------------------------------------------------------------------------------------------------------------ text
export const truncate = (t, n) => { const s = String(t ?? ''); const cp = [...s]; return cp.length > n ? cp.slice(0, n - 1).join('') + '…' : s; };
// Estimated rendered width (px) of `text` at `size` px in the graph's sans font; used to clip labels to their box without measuring the DOM.
const GLYPH = (ch) => (/[WM@]/.test(ch) ? 0.95 : /[A-Z]/.test(ch) ? 0.74 : /[il.,;:'|!]/.test(ch) ? 0.3 : /[ftrj()\[\] ]/.test(ch) ? 0.4 : /[mw]/.test(ch) ? 0.85 : /[\u0300-\u036f\u200b-\u200f\u202a-\u202e]/.test(ch) ? 0 : /[^\u0000-\u024f]/.test(ch) ? 1.05 : 0.58);
export const textWidth = (text, size) => [...String(text ?? '')].reduce((n, ch) => n + GLYPH(ch), 0) * size;
export function fitText(text, size, maxPx) {
  const cp = [...String(text ?? '')]; if (textWidth(cp.join(''), size) <= maxPx) return cp.join('');
  while (cp.length > 1 && textWidth(cp.join('') + '…', size) > maxPx) cp.pop();
  return cp.join('') + '…';
}
export const basename = (path) => { const parts = String(path || '').split('/').filter(Boolean); return parts.length ? parts[parts.length - 1] : String(path || ''); };
export const KIND_LABEL = { algorithm: 'algorithm', protocol: 'protocol', certificate: 'certificate', other_crypto: 'cryptographic material' };
export const kindLabel = (k) => KIND_LABEL[k] || 'asset';
export const originLabel = (a) => (a.provenance.origin === 'supplemental_observation' ? 'Experimental source observation' : 'From the original CBOM');
export const statusLabel = (hasReview) => (hasReview ? 'Needs review' : 'Recorded asset');

// The producer's own words are used where they exist; nothing here says that no cryptography exists.
export function emptyText(page, filterKey, query) {
  const t = page.filter_totals;
  if (t.all === 0) return page.availability.message;                                  // an availability message (never an empty-success claim of "no cryptography")
  if (filterKey === 'certificates' && !query && !page.page.assets_total) return 'No certificate objects are recorded in this CBOM.';
  return 'No assets match this filter in the recorded inventory.';
}
export const captureLabel = (page) => {
  const orig = page.producers.find((p) => p.provenance.origin === 'original_artifact');
  const sups = page.producers.filter((p) => p.provenance.origin === 'supplemental_observation');
  const sup = sups.find((p) => p.outcome !== 'not_run' && p.outcome !== 'unsupported') || sups[0];   // a page may list a not-run target-based producer next to the source scan that ran
  const bits = [orig ? `Original CBOM · ${orig.provenance.producer_version || orig.provenance.producer_id}${page.binding.mode === 'captured' ? ' (captured)' : ''}` : 'No CBOM recorded'];
  if (sup) bits.push(sup.outcome === 'not_run' || sup.outcome === 'unsupported' ? 'Source observations not collected' : 'Experimental source observations');
  return bits.join(' · ');
};
export const countsLine = (page) => {
  const n = page.filter_totals.all; const r = page.filter_totals.findings; const s = page.services_counts.total;
  return `${n} asset${n === 1 ? '' : 's'} · ${r} review item${r === 1 ? '' : 's'} · ${s} endpoint service${s === 1 ? '' : 's'}`;
};
export const occurrencesNote = (a) => (a.occurrences_total > a.occurrences.length ? `${a.occurrences.length} of ${a.occurrences_total} occurrences shown; the original CBOM download lists all of them.` : '');
export const servicesNote = (page) => (page.services_counts.truncated ? `${page.services_counts.shown} of ${page.services_counts.total} endpoint services shown; the original CBOM lists all of them.` : '');
export const producerStateText = (p) => ({ completed: 'collected', partial: 'collected in part', failed: 'failed', not_run: 'not collected', unsupported: 'not collected (unsupported)' }[p.outcome] || p.outcome);
// A source link is active only when the payload's destination is exactly the pinned revision of THIS analysis (GitHub blob at the resolved
// commit, percent-encoded path, no credentials); anything else - another repository, another commit, a stray scheme - is plain text.
// Same percent-encoding as the server's quote(path, safe="/"): unreserved = letters, digits and _.-~
const pyQuote = (t) => encodeURIComponent(t).replace(/[!'()*]/g, (c) => '%' + c.charCodeAt(0).toString(16).toUpperCase());
export function pinnedHref(binding, loc) {
  const h = loc?.link?.href; const r = binding?.repository;
  if (typeof h !== 'string' || !r || typeof loc.path !== 'string' || !/^[0-9a-f]{40}$/.test(binding.commit_sha || '')) return null;
  if (loc.path.split('/').some((seg) => seg === '.' || seg === '..')) return null;                  // dot segments are reinterpreted by every URL parser
  const want = `https://github.com/${r.owner}/${r.name}/blob/${binding.commit_sha}/` + String(loc.path).split('/').map(pyQuote).join('/');
  if (h !== want) return null;
  try {
    const u = new URL(h);                                                                           // the parsed destination must equal the string and the bound revision
    const prefix = `/${pyQuote(r.owner)}/${pyQuote(r.name)}/blob/${binding.commit_sha}/`;
    if (u.href !== h || u.protocol !== 'https:' || u.hostname !== 'github.com' || u.port || u.username || u.password || u.search || u.hash) return null;
    return u.pathname.startsWith(prefix) && u.pathname.length > prefix.length ? h : null;
  } catch { return null; }
}
export function sourceHref(loc, binding) {
  const h = pinnedHref(binding, loc); if (!h) return null;
  return loc.line_start ? `${h}#L${loc.line_start}${loc.line_end && loc.line_end !== loc.line_start ? '-L' + loc.line_end : ''}` : h;
}
export const lineText = (loc) => (loc.line_start ? (loc.line_end && loc.line_end !== loc.line_start ? `${loc.line_start}–${loc.line_end}` : String(loc.line_start)) : 'line not recorded');

// ------------------------------------------------------------------------------------------------------------------ zones
// One zone per payload source group that the page's assets reference (order = the payload's group order); an asset appears under every group in
// its source_group_ids. Assets without a recorded location go to a client-side lane that is not a payload group.
export function zonesOf(page) {
  if (!page) return [];
  const zones = page.source_groups.map((g) => ({ key: groupKey(g), group: g, label: g.label, sub: g.path || g.label, cards: page.assets.filter((a) => a.source_group_ids.includes(g.group_id)) })).filter((z) => z.cards.length);
  const lone = page.assets.filter((a) => a.source_group_ids.length === 0);
  if (lone.length) zones.push({ key: null, group: null, label: UNLOCATED_LABEL, sub: 'Assets whose CBOM entry records no source file', cards: lone });
  return zones;
}

// ------------------------------------------------------------------------------------------------------------------ layout (contract 6.2)
const zoneHeight = (m) => Math.max(REF.ZONE_H, 120 + 120 * (m - 1) + 90 + 50);
export function buildLayout(zones) {
  const n = zones.length; const wrapped = n > 3; const root = { ...REF.ROOT };
  if (!n) return { zones: [], connectors: [], root, wrapped: false, bbox: { x0: 0, y0: 0, x1: REF.W, y1: 690 }, viewBox: [0, 0, REF.W, 690], ordinary: true, baseW: 440, n: 0, start: 350 };
  const rows = []; for (let i = 0; i < n; i += 3) rows.push(zones.slice(i, i + 3));
  const rowH = rows.map((r) => Math.max(...r.map((z) => zoneHeight(z.cards.length))));
  const rowY = []; rows.forEach((_, r) => { rowY.push(r === 0 ? REF.ZONE_Y : rowY[r - 1] + rowH[r - 1] + REF.ROW_GAP); });
  const start = wrapped ? 20 : (REF.W - (n * REF.ZONE_W + (n - 1) * 40)) / 2;
  const out = []; const connectors = [];
  rows.forEach((row, r) => row.forEach((z, c) => {
    const x = wrapped ? 20 + c * REF.STRIDE : start + c * REF.STRIDE; const y0 = rowY[r]; const h = zoneHeight(z.cards.length);
    const head = { x: x + REF.HEAD.dx, y: y0 + REF.HEAD.dy, w: REF.HEAD.w, h: REF.HEAD.h };
    const cards = z.cards.map((a, i) => { const y = y0 + REF.CARD.first + i * REF.CARD.step; return { asset: a, x: x + REF.CARD.dx, y, w: REF.CARD.w, h: REF.CARD.h, link: `M${x + 180} ${head.y + head.h} V${head.y + head.h + 16} H${x + 26} V${y + 44} H${x + 42}` }; });
    out.push({ ...z, x, y: y0, w: REF.ZONE_W, h, head, cards, row: r, col: c });
    connectors.push({ d: r === 0 ? `M600 92 V124 H${x + 180} V${head.y}` : `M600 92 V124 H${REF.TRUNK_X} V${y0 - 14} H${x + 180} V${head.y}`, root: true });
  }));
  const last = rows.length - 1; const height = rowY[last] + rowH[last] + REF.BOTTOM;
  const bbox = wrapped ? { x0: -40, y0: 0, x1: 1240, y1: height } : { x0: 0, y0: 0, x1: REF.W, y1: height };
  const ordinary = !wrapped && rowH.every((h) => h === REF.ZONE_H);
  // The reference's own fit window for ordinary data (n <= 3 groups, <= 3 cards).
  const refX = Math.min(420, start) - 40; const refW = Math.max(780, start + (n - 1) * REF.STRIDE + REF.ZONE_W) - Math.min(420, start) + 80;
  return { zones: out, connectors, root, wrapped, bbox, viewBox: [bbox.x0, 0, bbox.x1 - bbox.x0, height], ordinary, baseW: ordinary ? refW : REF.W, refFit: [refX, 0, refW, 690], n, start, height };
}

// ------------------------------------------------------------------------------------------------------------------ viewport
// `aspect` = stage height / stage width (measured by the component; a default is used before the first measurement).
export const DEFAULT_ASPECT = 620 / 760;
export function fitView(layout, aspect = DEFAULT_ASPECT) {
  if (layout.ordinary) return [...layout.refFit];                                                  // identical to the reference
  const w = layout.bbox.x1 - layout.bbox.x0;
  return [layout.bbox.x0, 0, w, Math.min(layout.height, w * aspect)];                               // full width at the layout's top; the rest is reachable by pan
}
export function fitAllView(layout, aspect = DEFAULT_ASPECT) {
  const w = layout.bbox.x1 - layout.bbox.x0; const h = layout.height;
  const vw = Math.max(w, h / aspect); const vh = vw * aspect;
  return [layout.bbox.x0 - (vw - w) / 2, 0, vw, vh];
}
export const needsFitAll = (layout, aspect = DEFAULT_ASPECT) => !layout.ordinary && layout.height > (layout.bbox.x1 - layout.bbox.x0) * aspect + 1;
export const zoomPercent = (view, layout) => Math.round((layout.baseW / view[2]) * 100);
export function zoomView(view, factor, layout) {                                                   // factor > 1 enlarges the picture (smaller viewBox)
  const base = layout.baseW; const wantedPct = (base / view[2]) * factor * 100;
  const pct = Math.min(REF.MAX_ZOOM * 100, Math.max(REF.MIN_ZOOM * 100, wantedPct));
  const nw = base / (pct / 100); const k = nw / view[2];
  return clampView([view[0] + view[2] * (1 - k) / 2, view[1] + view[3] * (1 - k) / 2, nw, view[3] * k], layout);
}
export function clampView(view, layout) {                                                          // the view's centre stays inside the bounding box
  const b = layout.bbox; const [x, y, w, h] = view;
  const cx = Math.min(b.x1, Math.max(b.x0, x + w / 2)); const cy = Math.min(b.y1, Math.max(b.y0, y + h / 2));
  return [cx - w / 2, cy - h / 2, w, h];
}
export const panView = (view, dx, dy, layout) => clampView([view[0] + dx, view[1] + dy, view[2], view[3]], layout);
// Pan the view the least amount that brings `rect` fully inside it (when it fits).
export function ensureVisible(view, rect, layout) {
  const pad = 24; let [x, y, w, h] = view;
  if (rect.x < x + pad) x = rect.x - pad; else if (rect.x + rect.w > x + w - pad) x = rect.x + rect.w - w + pad;
  if (rect.y < y + pad) y = rect.y - pad; else if (rect.y + rect.h > y + h - pad) y = rect.y + rect.h - h + pad;
  return clampView([x, y, w, h], layout);
}
export function nodeRect(layout, sel) {
  for (const z of layout.zones) {
    if (z.key === sel) return { x: z.x, y: z.y, w: z.w, h: z.h };
    for (const c of z.cards) if (assetKey(c.asset) === sel) return { x: c.x, y: c.y, w: c.w, h: c.h };
  }
  return null;
}
// Keyboard on the focused SVG: arrows pan by a tenth of the view, + and - zoom, 0 fits. Returns the new view or null when the key is not handled.
export function keyView(view, key, layout, aspect) {
  if (key === '+' || key === '=') return zoomView(view, 1.25, layout);
  if (key === '-' || key === '_') return zoomView(view, 0.8, layout);
  if (key === '0') return fitView(layout, aspect);
  const step = { ArrowLeft: [-0.1, 0], ArrowRight: [0.1, 0], ArrowUp: [0, -0.1], ArrowDown: [0, 0.1] }[key];
  return step ? panView(view, step[0] * view[2], step[1] * view[3], layout) : null;
}

// ------------------------------------------------------------------------------------------------------------------ errors
export const CRYPTO_ERRORS = {
  stale_generation: 'The session moved on; reopen the analysis.', no_analysis: 'No completed analysis is active.', not_found: 'That source group is not in this analysis.',
  invalid_request: 'The request was refused.', projection_failed: 'The cryptographic assets could not be projected.', response_too_large: 'The response was too large to show.',
};
export const PROJECTION_DETAILS = { path_not_representable: 'A recorded source path cannot be shown exactly, so no partial list is given. The original CBOM download is unaffected.', review_items_exceed_bound: 'This page would need more review items than the display allows.' };
