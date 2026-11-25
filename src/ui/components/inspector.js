// UIP-02 §4.2: the shared inspector shell. One structure for every outer tab: header (type, title, subtitle, badge), the
// fixed question cards, "Evidence for this record", collapsed "Sources & coverage", actions. It renders the presentation
// model from lib/inspector_model.js and never invents data: every string is escaped and the shell emits no URL.
import { esc } from '../lib/util.js';
import { QUESTION_LABEL, stateMeta } from '../lib/inspector_model.js';

const ICON = {
  checked: '<circle cx="10" cy="10" r="8"/><path d="m6 10 3 3 5-6"/>',
  reported: '<circle cx="10" cy="10" r="5" fill="currentColor" stroke="none"/>',
  unknown: '<circle cx="10" cy="10" r="8"/><path d="M8 8a2 2 0 1 1 3 1.7c-.7.4-1 .8-1 1.6M10 14.2v.1"/>',
  hollow: '<circle cx="10" cy="10" r="6"/>',
  dash: '<path d="M5 10h10"/>',
  warning: '<path d="M10 3 18 17H2Z"/><path d="M10 8v4M10 14.4v.1"/>',
  alert: '<path d="M10 3 18 17H2Z"/><path d="M10 8v4M10 14.4v.1"/>',
};
export const symbol = (state) => { const m = stateMeta(state); return `<svg class="ot-insp-icon" viewBox="0 0 20 20" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" data-symbol="${esc(m.sym)}">${ICON[m.sym]}</svg>`; };

// Header status: an icon AND text, from the record's own state (never a bare colour). `kind` selects tone and symbol.
const BADGE_STATE = { context: 'not_assessed', neutral: 'not_assessed', review: 'needs_review', advisory: 'advisory_match', inventory: 'inventory_reported', checked: 'source_checked', unknown: 'unknown' };
const BADGE_TONE = { context: 'neutral', neutral: 'neutral', review: 'review', advisory: 'advisory', inventory: 'reported', checked: 'checked', unknown: 'unknown' };
// A row may carry `full` (the complete captured text) when its visible text is a preview: the omission is stated and the full text
// is one native <details> away (keyboard accessible, inert text). Nothing is dropped silently (UIP-02-IR-02).
const row = (r) => {
  const m = stateMeta(r.state);
  const more = r.full ? `<dd class="ot-insp-full"><details><summary>Show the full captured text (${esc(r.omitted)} more character${r.omitted === 1 ? '' : 's'})</summary><pre class="ot-raw">${esc(r.full)}</pre></details></dd>` : '';
  return `<div><dt>${esc(r.label)}</dt><dd class="ot-insp-${m.tone}">${symbol(r.state)}<span>${esc(r.text || m.label)}</span></dd>${more}</div>`;
};
export const INITIAL_EVIDENCE_ROWS = 3;

// One sidebar per selection. `extra` is caller-built, already-escaped markup for evidence that has no row form (source observations with their
// excerpts and pinned-revision links, metadata, per-record rule results); it renders inside the evidence section so nothing is dropped.
// `ids` lets a tab keep stable element ids (title/detail) for its own tests and focus handling.
// `evidenceDetail` (BOM connections only): already-escaped markup folded into the "Show all evidence (N)" disclosure; it makes the toggle available even when every row is already in the preview.
export function renderInspector(model, { advanced = false, extra = '', ids = {}, evidenceDetail = '' } = {}) {
  if (!model) return '';
  const qs = model.answers.map((a) => {
    const m = stateMeta(a.state);
    const why = (a.detail || []).length ? `<details class="ot-insp-why"><summary>${esc(a.detail_label || 'How this was determined')}</summary>${a.detail.map((t) => `<p>${esc(t)}</p>`).join('')}</details>` : '';
    return `<section class="ot-insp-card" data-question="${esc(a.question_id)}"><h3>${esc(a.label || QUESTION_LABEL[a.question_id] || a.question_id)}</h3><p class="ot-insp-state ot-insp-${m.tone}">${symbol(a.state)}<span>${esc(m.label)}</span></p><p class="ot-insp-body">${esc(a.body)}</p>${(a.missing || []).length ? `<p class="ot-insp-missing"><strong>Missing evidence:</strong> ${esc(a.missing.join('; '))}</p>` : ''}${why}</section>`;
  }).join('');
  const evTitle = model.question_set === 'bom_comparison' ? 'Evidence for this check' : 'Evidence for this record';
  const acts = (model.actions || []).map((a) => (a.disabled
    ? `<button type="button" class="button small" disabled title="${esc(a.disabled)}">${esc(a.label)}</button>`
    : `<button type="button" class="button small" ${Object.entries(a.attrs || {}).map(([k, v]) => `${esc(k)}="${esc(v)}"`).join(' ')}>${esc(a.label)}</button>`)).join('');
  const tech = advanced && (model.technical || []).length ? `<details class="ot-more" open><summary>Technical detail</summary>${model.technical.map(([k, v]) => `<p>${esc(k)}: <code>${esc(v)}</code></p>`).join('')}</details>` : '';
  const rows = model.evidence_rows || []; const shown = rows.slice(0, INITIAL_EVIDENCE_ROWS); const rest = rows.slice(INITIAL_EVIDENCE_ROWS);
  const allEv = rest.length || evidenceDetail ? `<details class="ot-insp-allev"><summary>Show all evidence (${rows.length})</summary>${rest.length ? `<dl>${rest.map(row).join('')}</dl>` : ''}${evidenceDetail ? `<div class="ot-insp-allev-detail">${evidenceDetail}</div>` : ''}</details>` : '';
  const rowsHtml = rows.length || evidenceDetail ? `${shown.length ? `<dl>${shown.map(row).join('')}</dl>` : ''}${allEv}` : (extra ? '' : '<p class="ot-insp-none">No evidence rows are attached to this record.</p>');
  const bk = model.badge.kind; const bs = model.badge.state || BADGE_STATE[bk] || 'not_assessed';
  return `<div class="ot-insp" data-origin="${esc(model.origin)}" data-record-id="${esc(model.id)}" data-question-set="${esc(model.question_set)}">
<header class="ot-insp-head"><div class="ot-insp-eyebrow">${esc(model.type)}</div><h2${ids.title ? ` id="${esc(ids.title)}"` : ''}>${esc(model.title)}</h2><span class="ot-insp-badge ot-insp-${BADGE_TONE[bk] || 'neutral'}">${symbol(bs)}<span>${esc(model.badge.label)}</span></span>${model.subtitle ? `<p class="ot-insp-sub">${esc(model.subtitle)}</p>` : ''}</header>
<div class="ot-insp-questions">${qs}</div>
<section class="ot-insp-evidence"${model.evidence_for ? ` data-evidence-for="${esc(model.evidence_for)}"` : ''}><h3>${esc(evTitle)}</h3>${rowsHtml}${extra ? `<div class="ot-insp-extra"${ids.detail ? ` id="${esc(ids.detail)}"` : ''}>${extra}</div>` : ''}</section>
${model.next_step ? `<section class="ot-insp-evidence ot-insp-next"><h3>Next step</h3><p>${esc(model.next_step)}</p></section>` : ''}
<details class="ot-insp-sources"><summary>Sources &amp; coverage<span aria-hidden="true">›</span></summary><div class="ot-insp-source-content">${(model.sources || []).map((t) => `<p>${esc(t)}</p>`).join('') || '<p>No source or coverage statement is available for this record.</p>'}</div></details>
${tech ? `<div class="ot-insp-tech">${tech}</div>` : ''}
${acts ? `<div class="ot-insp-actions">${acts}</div>` : ''}</div>`;
}
