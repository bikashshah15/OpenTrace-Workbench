// UI-EVIDENCE-STATUS-01: the compact evidence-status strip under the outer graph tabs. Presentation only: it reads the pure model in
// lib/evidence_status.js and adds no fetch, request or lifecycle. Every payload/producer-derived string goes through esc() as inert text.
import { esc } from '../lib/util.js';
import { evidenceStatus } from '../lib/evidence_status.js';

const SVG = (body) => `<svg class="otev-icon" viewBox="0 0 16 16" width="16" height="16" fill="none" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false">${body}</svg>`;
const ICON = {
  doc: SVG('<path d="M4 1.8h5.2L12.2 5v9.2H4z"/><path d="M9 1.8V5h3.2"/><path d="M6 8.2h4M6 10.6h4"/>'),
  neutral: SVG('<circle cx="8" cy="8" r="6"/><path d="M5.2 8h5.6"/>'),
  warn: SVG('<path d="M8 2 14.2 13H1.8z"/><path d="M8 6.4v3.2"/><path d="M8 11.4v.2"/>'),
  loading: SVG('<circle cx="8" cy="8" r="6"/><path d="M8 4.6V8l2.2 1.4"/>'),
};

// The Details disclosure belongs to the viewer, not to a payload: remember it across repaints in this page only (never persisted).
let detailsOpen = false;
export function attachEvidenceStrip(doc = typeof document !== 'undefined' ? document : null) {
  if (!doc) return;
  doc.addEventListener('toggle', (ev) => { const d = ev.target; if (d && d.classList && d.classList.contains('otev-details')) detailsOpen = d.open; }, true);
}
export const evidenceDetailsOpen = () => detailsOpen;
export const resetEvidenceDetails = () => { detailsOpen = false; };

const chip = (code, tone, text, extra = '') => `<li class="otev-item" data-state="${esc(code)}" data-tone="${esc(tone)}"${extra}>${ICON[code === 'loading' ? 'loading' : tone] || ICON.neutral}<span>${esc(text)}</span></li>`;

// `detailsHtml` (BOM connections only): already-escaped coverage text folded into the collapsed Details disclosure.
export function renderEvidenceStrip(s, tab, { detailsHtml = '' } = {}) {
  if (s.busy === 'ending') return '';
  const m = evidenceStatus(s, tab); if (!m) return '';
  const inv = m.items.map((i) => chip(i.code, i.tone, i.text, ` data-bom="${esc(i.kind)}"`)).join('');
  const src = m.sources.map((c) => chip(c.code, c.tone, c.text, ' data-role="source"')).join('');
  const rows = m.details.map((d) => `<div class="otev-block" data-bom="${esc(d.name)}"><h4>${esc(d.name)}</h4><dl>${d.rows.map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(v)}</dd>`).join('')}</dl>${d.notes.map((n) => `<p>${esc(n)}</p>`).join('')}</div>`).join('');
  const extra = m.extra.filter(Boolean).map((t) => `<p class="otev-extra">${esc(t)}</p>`).join('');
  return `<section class="otev" id="ot-evidence-strip" data-tab="${esc(tab)}" aria-label="Inventory evidence status"><ul class="otev-list" role="list">${inv}${src}</ul>${m.scope ? `<p class="otev-scope">${esc(m.scope)}</p>` : ''}<details class="otev-details"${detailsOpen ? ' open' : ''}><summary>Details</summary><div class="otev-body">${detailsHtml}${rows}${extra}<p class="otev-note">Inventory status describes the recorded inventory; it does not establish that the repository contains or lacks anything, or how it runs.</p></div></details></section>`;
}
