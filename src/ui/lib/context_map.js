// UIP-04: pure layout, paging and merge model for the repository contexts map. No DOM, no network, no repository names.
//
// Geometry is the approved prototype's (reference hash d5bc14fa…3a148), generalized from data: viewBox width 1400; root card
// 280x86 at (560,44); two columns (zone width 625 at x=40 and x=735); zone header 593x58 at (zone.x+16, zone.y+15); file cards
// 545x64 at (zone.x+49, zone.y+91+74i). Zones fill row-major in server order. Row 1 starts at y=200 and each next row starts 50
// below the tallest zone of the previous one. The prototype hand-sets its second row to 570 px where this rule gives 560: an
// owner-approved exception (FR-6) that is disclosed in the evidence, not reproduced here.

export const VB_W = 1400;
export const ROOT = { x: 560, y: 44, w: 280, h: 86 };
export const ZONE = { w: 625, cols: [40, 735], headerW: 593, headerH: 58, fileW: 545, fileH: 64, step: 74, firstRowY: 200, rowGap: 50, base: 116, footer: 44, bottom: 40 };

// Owner-approved bounds (FR-8).
export const PAGE_GRAPH = 20;         // initial and Graph "Show more" page
export const PAGE_LIST = 40;          // List "Show more" page (the frozen maximum)
export const GROUP_CAP = 100;         // rendered Graph cards per group
export const MAP_CAP = 400;           // rendered Graph cards in the whole map
export const RETRY_LADDER = [20, 10, 5, 1];

// The retry ladder for a page of `size` cards: the page size, then 10, 5, 1 (each strictly smaller).
export const ladderFrom = (size) => [size, ...[10, 5, 1].filter((n) => n < size)];

// ------------------------------------------------------------------ paging / merge
export const loadedCount = (g) => (g.files || []).length;
export const totalFiles = (g) => g.files_counts?.total ?? loadedCount(g);
export const hiddenCount = (g) => Math.max(0, totalFiles(g) - loadedCount(g));

// Cards are keyed by file_id: a page replaces only the cards at its own offsets and never removes a loaded card. A page that
// would leave a hole (offset past the loaded prefix) is not applied.
export function mergeFiles(existing, page, offset) {
  const out = (existing || []).slice();
  if (offset > out.length) return out;
  page.forEach((card, i) => { out[offset + i] = card; });
  const seen = new Set();
  return out.filter((c) => (seen.has(c.file_id) ? false : seen.add(c.file_id)));
}

// What the Graph renders: per group min(loaded, GROUP_CAP, remaining whole-map budget), in server order.
export function capacity(groups, cap = MAP_CAP, groupCap = GROUP_CAP) {
  let budget = cap;
  return groups.map((g) => {
    const loaded = loadedCount(g);
    const shown = Math.max(0, Math.min(loaded, groupCap, budget));
    budget -= shown;
    // 'more': the next page can still be drawn in the Graph; 'list': a cap (group or whole map) was reached or cards are held back.
    const hidden = totalFiles(g) - shown;
    const heldBack = shown < loaded || shown >= groupCap || budget <= 0;
    return { shown, hidden, footer: hidden > 0 ? (heldBack ? 'list' : 'more') : null };
  });
}

// ------------------------------------------------------------------ layout
export function layoutMap(groups, cap = capacity(groups)) {
  const zones = []; const connectors = [];
  let y = ZONE.firstRowY; let rowEnd = y;
  const rows = [];
  groups.forEach((g, i) => {
    const c = cap[i]; const row = Math.floor(i / 2); const col = i % 2;
    const h = ZONE.base + ZONE.step * c.shown + (c.footer ? ZONE.footer : 0);
    (rows[row] ||= []).push({ g, c, col, h, i });
  });
  rows.forEach((members, r) => {
    if (r > 0) y = rowEnd + ZONE.rowGap;
    const rowH = Math.max(...members.map((m) => m.h));
    for (const m of members) {
      const x = ZONE.cols[m.col];
      const files = [];
      for (let k = 0; k < m.c.shown; k++) files.push({ x: x + 49, y: y + 91 + k * ZONE.step, link: `M${x + 32} ${y + 73} V${y + 91 + k * ZONE.step + 31} H${x + 49}` });
      const header = { x: x + 16, y: y + 15, w: ZONE.headerW, h: ZONE.headerH };
      const footer = m.c.footer ? { kind: m.c.footer, x: x + 49, y: y + 91 + m.c.shown * ZONE.step + 4, w: ZONE.fileW, h: 34 } : null;
      zones.push({ index: m.i, row: r, col: m.col, x, y, w: ZONE.w, h: rowH, own: m.h, header, files, footer, shown: m.c.shown, hidden: m.c.hidden });   // the prototype draws both zones of a row at the row's height
      const cx = x + 16 + ZONE.headerW / 2;
      connectors.push(r === 0 ? `M700 130 V160 H${cx} V${y + 15}`
        : m.col === 0 ? `M560 88 H18 V${y + 30} H${x + 16}` : `M840 88 H1384 V${y + 30} H${x + 16 + ZONE.headerW}`);
    }
    rowEnd = y + rowH;
  });
  const height = (groups.length ? rowEnd : ZONE.firstRowY - ZONE.rowGap + 0) + ZONE.bottom;
  return { viewBox: [0, 0, VB_W, groups.length ? height : 260], zones, connectors, rendered: cap.reduce((n, c) => n + c.shown, 0) };
}

// ------------------------------------------------------------------ viewport (viewBox arithmetic, as the prototype)
export const zoomPercent = (vb) => Math.round((VB_W / vb[2]) * 100);
export function zoomBox(vb, f) { return [vb[0] + (vb[2] * (1 - f)) / 2, vb[1] + (vb[3] * (1 - f)) / 2, vb[2] * f, vb[3] * f]; }
export function clampZoom(vb, fit) { const w = Math.min(Math.max(vb[2], fit[2] / 4), fit[2] * 4); const k = w / vb[2]; return k === 1 ? vb : zoomBox(vb, k); }
export function panBox(start, dxPx, dyPx, widthPx) { const k = start[2] / Math.max(1, widthPx); return [start[0] - dxPx * k, start[1] - dyPx * k, start[2], start[3]]; }

// ------------------------------------------------------------------ keyboard
// `ids` is the DOM-order list of a zone's card ids; Arrow Up/Down move one, Home/End jump. Returns the target id or null.
export function cardTarget(ids, current, key) {
  const i = ids.indexOf(current); if (i < 0 || !ids.length) return null;
  if (key === 'ArrowDown') return ids[Math.min(ids.length - 1, i + 1)];
  if (key === 'ArrowUp') return ids[Math.max(0, i - 1)];
  if (key === 'Home') return ids[0];
  if (key === 'End') return ids[ids.length - 1];
  return null;
}

// ------------------------------------------------------------------ selection
// Valid = the repository root, or a group id or file id that exists among the loaded groups/cards.
export function selectionValid(model, id) {
  if (id === 'root') return !!model;
  if (!model || !id) return false;
  return model.groups.some((g) => g.group_id === id || (g.files || []).some((f) => f.file_id === id));
}
export function findSelection(model, id) {
  if (!model || !id) return null;
  if (id === 'root') return { kind: 'root', root: model.root };
  for (const g of model.groups) {
    if (g.group_id === id) return { kind: g.kind === 'unlocated' ? 'unlocated' : 'group', group: g };
    const f = (g.files || []).find((x) => x.file_id === id);
    if (f) return { kind: 'file', group: g, file: f };
  }
  return null;
}
