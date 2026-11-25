// Artifact preview helpers (pure, no DOM): formatted-JSON display and full-artifact snippet search.
// The artifact bytes are never changed: these only build what the dialog displays. Download always serves the original file.
export const DISPLAY_LIMIT = 200000;
export const MAX_HITS = 60;
const CONTEXT = 70;      // characters of context on each side of a match

// Re-indent a document that is already known to be valid JSON. ONLY whitespace outside strings changes: every other character
// (strings with their escapes, numbers of any size, literals, duplicate keys, key order) is copied through unchanged.
export function indentJson(text) {
  let out = ''; let depth = 0; let i = 0; const n = text.length;
  const pad = () => '\n' + '  '.repeat(depth);
  const nextToken = (from) => { let k = from; while (k < n && /\s/.test(text[k])) k++; return k; };
  while (i < n) {
    const ch = text[i];
    if (ch === '"') { let k = i + 1; while (k < n && text[k] !== '"') k += text[k] === '\\' ? 2 : 1; out += text.slice(i, k + 1); i = k + 1; continue; }
    if (/\s/.test(ch)) { i++; continue; }
    if (ch === '{' || ch === '[') {
      const k = nextToken(i + 1);
      if (text[k] === (ch === '{' ? '}' : ']')) { out += ch + text[k]; i = k + 1; continue; }     // an empty container stays on one line
      depth++; out += ch + pad(); i++; continue;
    }
    if (ch === '}' || ch === ']') { depth--; out += pad() + ch; i++; continue; }
    if (ch === ',') { out += ',' + pad(); i++; continue; }
    if (ch === ':') { out += ': '; i++; continue; }
    out += ch; i++;
  }
  return out;
}

// Format the COMPLETE document first, then apply the display limit. Invalid JSON falls back to the plain text.
export function formatArtifact(text, limit = DISPLAY_LIMIT) {
  let full = text; let json = false;
  try { JSON.parse(text); full = indentJson(text); json = true; } catch { /* plain-text fallback */ }
  return { json, total: full.length, shown: full.length > limit ? full.slice(0, limit) : full, truncated: full.length > limit };
}

// Search the whole original text, case-insensitively. A hit is a short snippet around the match, so a one-line JSON file works too;
// a multi-line file also reports the line number. Several matches on one line are separate hits. Capped at `max` (more=true when capped).
export function searchArtifact(text, q, max = MAX_HITS) {
  if (!q) return { hits: [], more: false };
  const re = new RegExp(q.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'gi');
  const multiline = text.includes('\n'); const hits = []; let m; let line = 1; let last = 0;
  while ((m = re.exec(text))) {
    if (!m[0].length) { re.lastIndex++; continue; }
    if (hits.length >= max) return { hits, more: true };
    if (multiline) { for (let i = text.indexOf('\n', last); i !== -1 && i < m.index; i = text.indexOf('\n', i + 1)) { line++; last = i + 1; } }
    const a = Math.max(0, m.index - CONTEXT); const b = Math.min(text.length, m.index + m[0].length + CONTEXT);
    const flat = (s) => s.replace(/\s+/g, ' ');
    hits.push({ where: multiline ? `line ${line}` : `character ${m.index + 1}`, before: (a > 0 ? '… ' : '') + flat(text.slice(a, m.index)), match: m[0], after: flat(text.slice(m.index + m[0].length, b)) + (b < text.length ? ' …' : '') });
  }
  return { hits, more: false };
}
