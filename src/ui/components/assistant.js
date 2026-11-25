import { esc } from '../lib/util.js';

// Kept as a presentation-model helper for existing BOM evidence regressions;
// the Lab Assistant product path no longer invokes fixed answer templates.
export function answer(kind, ctx) {
  if (!ctx) return { text: 'No selected evidence is available.', cite: [] };
  if (kind === 'meaning') return { text: ctx.meaning, cite: ctx.cite };
  if (kind === 'limits') return { text: ctx.limits, cite: ctx.cite };
  return { text: ctx.next, cite: ctx.cite };
}

const citation = (id, contextId, label, title) => {
  const text = label || 'Open evidence';
  return `<button type="button" class="ot-assistant-citation" data-action="a-citation" data-evidence="${esc(id)}" data-context="${esc(contextId)}" title="${esc(title || text)}">${esc(text)}</button>`;
};

// Plain-language names for the evidence families; unknown names fall back to a readable form of the key.
const SOURCE_NAME = { repository: 'Repository', dependencies: 'Dependencies', advisories: 'Advisories', crypto: 'Cryptography', model_observations: 'Model references',
  model_correspondence: 'Model-to-BOM comparison', candidate_gaps: 'BOM comparison', bom: 'BOM', relationships: 'Relationships' };
const STATE_PHRASE = { not_run: 'was not run', unavailable: 'was not available', failed: 'failed', partial: 'was only partly covered', unsupported: 'is not supported',
  not_compared: 'was not compared', completed: 'was checked' };
const sourceName = (key) => SOURCE_NAME[key] || (key.charAt(0).toUpperCase() + key.slice(1).replaceAll('_', ' '));

// Server limitations arrive as "<source>: <technical text>"; show the same fact in plain words (the raw state stays under Details).
function plainLimit(text) {
  const m = /^([a-z_]+): (.*)$/s.exec(text);
  if (!m) return text;
  const name = sourceName(m[1]);
  const st = /^evidence state is ([a-z_]+)/.exec(m[2]);
  if (st) return `${name} ${STATE_PHRASE[st[1]] || 'could not be confirmed'}.`;
  if (/deterministically truncated/.test(m[2])) return `${name}: only part of the evidence fit, so some may be missing.`;
  if (/binding changed/.test(m[2])) return `${name} was left out because it no longer matches this analysis.`;
  return `${name}: ${m[2]}`;
}

// Header and composer icons: the same outline style as the rest of the app (24-unit box, 1.6 stroke, round caps). Decorative; every button keeps its accessible name and tooltip.
const ICON = {
  lock: '<rect x="5" y="11" width="14" height="9" rx="2"/><path d="M8 11V8a4 4 0 0 1 8 0v3"/>',
  unlock: '<rect x="5" y="11" width="14" height="9" rx="2"/><path d="M8 11V8a4 4 0 0 1 7.5-2"/>',
  minimize: '<path d="M6 9l6 6 6-6"/>',
  expand: '<path d="M6 15l6-6 6 6"/>',
  ask: '<path d="M5 12h13"/><path d="M13 6l6 6-6 6"/>',
};
const icon = (name) => `<svg class="ot-assistant-icon" viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false">${ICON[name]}</svg>`;
const iconButton = (action, name, label, extra = '') => `<button type="button" class="ot-assistant-iconbtn" data-action="${action}" aria-label="${esc(label)}" title="${esc(label)}" ${extra}>${icon(name)}</button>`;

const VERDICT = { partial: 'Partly answered — part of the evidence was missing or incomplete.', unknown: 'Cannot be determined from the evidence available.' };

function renderTurn(turn) {
  const answer = turn.response?.answer;
  const q = `<p class="ot-assistant-q">${esc(turn.question)}</p>`;
  if (turn.note) return `<article class="ot-assistant-turn">${q}<p class="ot-assistant-reply">${esc(turn.note)}</p></article>`;
  if (!answer) return `<article class="ot-assistant-turn">${q}<p class="ot-assistant-error" role="alert">${esc(turn.error || 'No answer was returned.')}</p></article>`;
  const ctx = turn.response.context_id;
  const citationItems = turn.response.citations || [];
  const citations = new Map(citationItems.map((item) => [item.evidence_id, item]));
  const sources = (ids) => (ids || []).map((id, i, all) => citation(id, ctx, all.length > 1 ? `View evidence ${i + 1}` : 'View evidence', citations.get(id)?.label)).join('');
  const stateEvidenceFor = (source) => citationItems.find((item) => item.source === source && item.kind === 'source_state');
  const claims = answer.claims.map((claim) => `<section class="ot-assistant-claim"><p>${claim.kind === 'background' ? '<em class="ot-assistant-bg">General explanation, not from this repository:</em> ' : ''}${esc(claim.text)}</p>${claim.evidence_ids.length ? `<div class="ot-assistant-sources">${sources(claim.evidence_ids)}</div>` : ''}</section>`).join('');
  // One limits list. A server-derived limitation is dropped ONLY when the answer already says the same thing in the same words
  // (normalized text equality with a model limitation or a limitation/unknown claim). Citing a source-state record never hides it:
  // the model's wording can understate the state, and one source can carry several distinct limitations.
  const seen = new Set(); const items = [];
  const key = (t) => t.toLowerCase().replace(/[^a-z0-9]+/g, ' ').trim();
  const stated = new Set(answer.claims.filter((c) => c.kind === 'limitation' || c.kind === 'unknown').map((c) => key(c.text)));
  answer.limitations.forEach((item) => { const k = key(item.text); if (!seen.has(k)) { seen.add(k); stated.add(k); items.push(`<li>${esc(item.text)} ${sources(item.evidence_ids)}</li>`); } });
  (turn.response.limitations || []).forEach((raw) => {
    const m = /^([a-z_]+):/.exec(raw); const stateEv = m && stateEvidenceFor(m[1]);
    const plain = plainLimit(raw); const k = key(plain);
    if (seen.has(k) || stated.has(k) || stated.has(key(raw))) return;
    seen.add(k); items.push(`<li>${esc(plain)}${stateEv ? ' ' + sources([stateEv.evidence_id]) : ''}</li>`);
  });
  // Minimal by default: ONE material scope note beside the answer (the answer's own limitation first, then the server's, in order); the complete list is under Details.
  // A limitation shows beside the answer only when the answer itself raised one (it matters to this question); the server's coverage list stays under Details.
  const own = answer.limitations.length > 0;
  const limits = own ? `<section class="ot-assistant-limit"><strong>What this does not cover</strong><ul>${items[0]}</ul></section>` : '';
  const rest = own ? items.slice(1) : items;       // the one beside the answer is not repeated; the count and the rest live under Details
  const fullLimits = rest.length ? `<section class="ot-assistant-fulllimits"><strong>${own ? `${rest.length} more ${rest.length === 1 ? 'limitation' : 'limitations'}` : 'All limitations'}</strong><ul>${rest.join('')}</ul></section>` : '';
  const verdict = answer.answer_status === 'unknown' && VERDICT[answer.answer_status] ? `<p class="ot-assistant-verdict" data-status="${esc(answer.answer_status)}">${VERDICT[answer.answer_status]}</p>` : '';
  const next = (answer.next_steps || []).map((step) => `<p class="ot-assistant-next">Next: ${citation(step.evidence_id, ctx, step.label)}</p>`).join('');
  const rows = Object.entries(turn.response.source_states || {}).map(([source, state]) => {
    const ev = stateEvidenceFor(source);
    const facts = [state.state, `${state.entry_count} evidence records`, state.truncated ? 'truncated' : null, state.reason_code].filter(Boolean).join(' · ');
    return `<li><strong>${esc(source.replaceAll('_', ' '))}:</strong> ${esc(facts)}${ev ? ' ' + citation(ev.evidence_id, ctx, 'Open coverage evidence') : ''}</li>`;
  }).join('');
  const provider = turn.response.provider;
  const detail = `${provider ? `<p class="ot-assistant-provider">${esc(provider.profile)} / ${esc(provider.model)} · ${esc(provider.validation_level)} · status ${esc(answer.answer_status)}</p>` : ''}${fullLimits}${rows ? `<strong>Evidence coverage</strong><ul>${rows}</ul>` : ''}`;
  const details = detail ? `<details class="ot-assistant-details"><summary>Details</summary>${detail}</details>` : '';
  return `<article class="ot-assistant-turn">${q}<div class="ot-assistant-answer">${verdict}${claims}${limits}${next}</div>${details}</article>`;
}

export function renderAssistant(s, selection) {
  const a = s.assistant;
  const frozen = a.subject?.label && a.subject.kind !== 'analysis' ? a.subject.label : null;
  const intro = a.turns.length ? '' : '<p class="ot-help">Select an item in the Workbench and choose “Explain this”, or ask a question about this analysis. The assistant is read-only.</p>';
  return `<header id="ot-assistant-handle" data-fk="ahandle"><div><strong>Lab assistant</strong> <span class="micro">READ-ONLY</span></div><div>${iconButton('a-position', a.positionLocked ? 'unlock' : 'lock', a.positionLocked ? 'Unlock position' : 'Lock position', `aria-pressed="${a.positionLocked}"`)}${iconButton('a-min', a.minimized ? 'expand' : 'minimize', a.minimized ? 'Expand' : 'Minimize', `aria-expanded="${!a.minimized}"`)}<button type="button" data-action="a-close" aria-label="Close Lab assistant">✕</button></div></header>
  <div class="body" data-scroll-key="assistant-body">${intro}
  <p class="ot-assistant-subject">${frozen ? `About <strong>${esc(frozen)}</strong>` : 'About this analysis'}</p>
  ${selection?.relations?.length ? `<label class="ot-assistant-adopt" for="ot-assistant-relationship">Relationship subject<select id="ot-assistant-relationship" data-fk="arel"><option value="">Use current object</option>${selection.relations.map((edge) => `<option value="${esc(edge.edge_id)}" ${selection.kind === 'relationship' && selection.id === edge.edge_id ? 'selected' : ''}>${esc(edge.label || edge.kind || edge.edge_id)}</option>`).join('')}</select></label>` : ''}
  ${a.turns.map(renderTurn).join('')}
  ${a.pending && a.pendingQuestion ? `<article class="ot-assistant-turn ot-assistant-turn-pending" aria-busy="true"><p class="ot-assistant-q">${esc(a.pendingQuestion)}</p><p class="ot-assistant-thinking" role="status"><span class="ot-assistant-dots" aria-hidden="true"><i></i><i></i><i></i></span><span>Thinking…</span></p></article>` : a.pending ? '<p role="status" class="ot-assistant-pending ot-assistant-thinking"><span class="ot-assistant-dots" aria-hidden="true"><i></i><i></i><i></i></span><span>Thinking…</span></p>' : ''}
  ${a.error ? `<p class="ot-assistant-error" role="status">${esc(a.error)}</p>` : ''}
  ${a.retry && !a.pending ? '<p class="ot-assistant-restore"><button type="button" class="button small" data-action="a-retry">Try again</button></p>' : ''}
  ${a.adoptionUncertain && !a.pending ? '<p class="ot-assistant-error" role="status">Choose Explain this again to confirm which item you’re asking about.</p>' : ''}
  ${a.failedQuestion ? '<p class="ot-assistant-restore"><button type="button" class="button small" data-action="a-restore">Restore my previous question</button> <small>Adds it below your new draft.</small></p>' : ''}
  <form id="ot-assistant-form"><label for="ot-assistant-question">Ask a question</label><textarea id="ot-assistant-question" data-fk="adraft" maxlength="4000" rows="3" required>${esc(a.draft)}</textarea><div><small>Up to 4,000 characters</small><span>${a.pending ? '<button type="button" class="button small" data-action="a-cancel">Cancel request</button>' : '<button type="submit" class="button small ot-assistant-ask" aria-label="Ask" title="Ask (Enter)" ' + (!s.analysis || a.pending || a.adoptionUncertain ? 'disabled' : '') + '>Ask ' + icon('ask') + '</button>'}</span></div></form></div>`;
}
