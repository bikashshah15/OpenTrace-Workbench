// Candidate gaps (I8): under BOM connections. Pure string renderers over the bounded /api/view/gaps and /api/view/gap payloads,
// so every outcome (compared, not compared, unknown coverage) can be tested without a browser.
// A candidate is a hypothesis from a set comparison; its verdict is a rule's finding. Unknown coverage is stated, never a defect.
import { esc, fmt } from '../lib/util.js';
import { bomSelectedItem } from '../lib/store.js';
import { renderInspector } from './inspector.js';
import { fromBom } from '../lib/inspector_model.js';

export const STATE_CLASS = { contradicted: 'warn', supported: 'ok', unverifiable: 'unavailable', conflicting_evidence: 'warn', unknown_coverage: 'muted', no_rule: 'muted' };
const FILTERS = [['', 'All'], ['contradicted', 'Not represented in the BOM'], ['unknown_coverage', 'Coverage unknown'], ['unverifiable', 'Could not be confirmed']];
const short = (h) => (h ? String(h).slice(0, 12) + '…' : '—');

export const gapsEnabled = (s) => !!s.analysis?.summary?.gaps;

function row(it, selected) {
  const bom = it.bom ? `BOM checked: <strong>${esc(it.bom.label)}</strong> <span class="mono">${esc(it.bom.inventory_id)}</span>` : 'BOM checked: none (nothing was compared)';
  return `<article class="ot-lookup-row ot-gap-row${selected ? ' selected' : ''}" data-gap="${esc(it.candidate_id)}"><div><strong class="ot-pkg-name">${esc(it.title)}</strong>
    <small class="micro">${esc(it.category_label)}${it.location ? ' · ' + esc(it.location) : ''}</small><p class="ot-lookup-why">${bom}</p></div>
    <div class="ot-lookup-side"><span class="ot-state ${STATE_CLASS[it.state] || 'muted'}">${esc(it.state_label)}</span>
    <p><button type="button" class="evidence-link" data-action="gap-inspect" data-id="${esc(it.candidate_id)}" aria-pressed="${selected}">Inspect evidence →</button></p></div></article>`;
}

export function section(s) {
  if (!gapsEnabled(s)) return '';
  const g = s.gaps || {}; const sum = s.analysis.summary.gaps; const d = g.data;
  const head = `<h3 id="ot-gaps-h">Candidate gaps</h3><p class="ot-help">Differences between what the repository’s requirement files declare and what the selected software inventory (Syft SBOM) records, found by the inventory assessment from captured inputs. A candidate is a hypothesis; each verdict comes from a rule. These are inventory differences, not vulnerabilities, and installation or use is not established.</p>`;
  if (sum.status !== 'compared' || (d && d.status === 'not_compared')) {
    const m = (d && d.message) || sum.message || 'The comparison could not complete, so nothing was compared.';
    return `<section class="ot-gaps" id="ot-gaps" aria-labelledby="ot-gaps-h">${head}<p class="ot-prompt" role="status"><strong>Not compared.</strong> ${esc(m)} This is not a “no gaps” result.</p></section>`;
  }
  const t = (d && d.totals) || sum.totals; const by = t.by_state || {};
  const active = g.state || '';
  const chips = `<div class="ot-lookup-chips" role="group" aria-label="Filter candidate gaps">${FILTERS.map(([k, label]) => {
    const n = k ? (by[k] || 0) : t.candidates;
    return `<button type="button" class="ot-chip-button ${STATE_CLASS[k] || ''}${active === k ? ' active' : ''}" data-action="gap-state" data-state="${k}" aria-pressed="${active === k}">${esc(label)} <b>${fmt(n)}</b></button>`;
  }).join('')}</div>`;
  const list = g.error ? `<p class="ot-prompt" role="alert">The candidate list could not be loaded (${esc(g.error)}).</p>`
    : !d ? '<p class="ot-prompt" role="status">Loading…</p>'
    : d.items.length ? d.items.map((it) => row(it, g.selected === it.candidate_id)).join('') : '<p class="ot-prompt">No candidate matches this filter.</p>';
  const from = d && d.filtered_total ? d.offset + 1 : 0; const to = d ? Math.min(d.filtered_total, d.offset + d.limit) : 0;
  const unknown = t.by_category?.unknown_coverage || 0;
  return `<section class="ot-gaps" id="ot-gaps" aria-labelledby="ot-gaps-h">${head}
    <p class="ot-help">${fmt(t.candidates)} candidates: ${fmt(t.by_category?.missing_component || 0)} declared requirements without a record in the SBOM and ${fmt(unknown)} where coverage is unknown (the SBOM could not be bound to the file, or the declaration form or environment cannot be evaluated). ${(() => { const sc = d?.ported_scope || []; const cr = sc.includes('python_hashlib_call_sites_vs_cbom'); const ai = sc.includes('model_references_vs_aibom');
      if (!cr && !ai) return 'Only requirement declarations are compared in this build; models, cryptographic call sites and dependency edges are not.';
      const parts = ['Requirement declarations'].concat(cr ? ['Python <code>hashlib</code> call sites (compared with the selected CBOM; an absent CBOM record is not a defect)'] : [], ai ? ['static model references (compared with the selected AI-BOM at declaration level; an absent declaration is not a defect)'] : []);
      return `${parts.join(' and ')} are compared in this build; ${ai ? '' : 'models and '}dependency edges are not.`; })()}</p>
    ${chips}<div class="ot-search-line"><span class="ot-help">${d && d.filtered_total ? `Showing ${from}–${to} of ${fmt(d.filtered_total)}` : ''}</span><input type="search" id="ot-gap-q" placeholder="Search candidate, e.g. tflite_runtime…" value="${esc(g.q || '')}" aria-label="Search candidate gaps"></div>
    <div class="ot-lookup-rows" aria-live="polite">${list}</div>
    <div class="ot-search-line"><span></span><span><button type="button" class="button small" data-action="gap-page" data-dir="-1" ${!d || d.offset <= 0 ? 'disabled' : ''}>Previous</button> <button type="button" class="button small" data-action="gap-page" data-dir="1" ${!d || !d.has_more ? 'disabled' : ''}>Next</button></span></div></section>`;
}

function record(r) {
  if (r.kind === 'requirement_declaration') {
    const lines = (r.declarations || []).map((x) => `<li><code>${esc(r.source?.file)}:${esc(x.line)}</code> · ${esc(String(x.form || '').replaceAll('_', ' '))}<pre class="ot-raw">${esc(x.text)}</pre></li>`).join('');
    return `<div class="ot-gap-record" data-record="${esc(r.evidence_id)}"><h3>Source requirement <small class="mono">${esc(r.role)}</small></h3><ul>${lines || '<li>No declaration line recorded.</li>'}</ul>
      <p class="micro">File SHA-256 <code>${esc(short(r.source?.file_sha256))}</code> · ${esc(r.method)} · ${esc(r.origin)}</p></div>`;
  }
  if (r.kind === 'inventory_name_lookup') {
    const sf = r.scanned_file || {}; const p = r.parse || {}; const inv = r.inventory || {};
    return `<div class="ot-gap-record" data-record="${esc(r.evidence_id)}"><h3>Selected inventory lookup <small class="mono">${esc(r.role)}</small></h3>
      <p>Looked up <code>${esc(r.query?.normalized_name)}</code> (${esc(r.query?.ecosystem)}, ${esc(r.query?.match)}) in <strong>${esc(inv.generator || 'the SBOM')}</strong>: <strong>${fmt(r.matches)} matching component${r.matches === 1 ? '' : 's'}</strong> among ${fmt(p.library_components)} library components${p.complete ? ' (inventory fully classified)' : ' (inventory not fully classified)'}.</p>
      <p>The SBOM ${sf.file_records === 1 ? 'lists' : sf.file_records ? 'records ' + fmt(sf.file_records) + ' entries for' : 'does not list'} <code>${esc(sf.path)}</code>${(sf.recorded_sha256 || []).length ? ' with SHA-256 <code>' + esc(short(sf.recorded_sha256[0])) + '</code>' : ''}.</p>
      <p class="micro">SBOM SHA-256 <code>${esc(short(inv.raw_sha256))}</code> · ${esc(r.method)} · ${esc(r.origin)}</p></div>`;
  }
  if (r.kind === 'source_excerpt' && r.reference_kind === 'model_reference') {   // UIP-13: a model reference in source (a string; not a download, load or execution)
    const m = r.model_reference || {}; const lines = Array.isArray(r.source?.lines) ? r.source.lines.join('–') : '';
    return `<div class="ot-gap-record" data-record="${esc(r.evidence_id)}" data-kind="model_reference"><h3>Model reference in source <small class="mono">${esc(r.role)}</small></h3>
      <p><code>${esc(r.source?.file)}:${esc(lines)}</code> · ${esc(String(m.source_kind || '').replaceAll('_', ' '))} · ${esc(String(m.method || '').replaceAll('-', ' '))} · statically observed, not downloaded or executed</p>
      <pre class="ot-raw">${esc(r.excerpt)}${r.excerpt_truncated ? '\n… (cut)' : ''}</pre><p class="micro">Locator (exact, query and fragment included): <code>${esc(m.locator)}</code></p>
      ${r.role === 'cited' ? `<p class="ot-help">Cited, not compared: ${esc(String(r.reason_code || 'not compared').replaceAll('_', ' '))}.</p>` : ''}
      <p class="micro">File SHA-256 <code>${esc(short(r.source?.file_sha256))}</code> · ${esc(r.method)} · ${esc(r.origin)}</p></div>`;
  }
  if (r.kind === 'aibom_document') {    // UIP-13: what the selected AI-BOM records (a separate evidence record from the source observation)
    const b = r.binding || {}; const p = (r.producer || []).map((x) => `${esc(x.name)} ${esc(x.version)}`).join(', ');
    return `<div class="ot-gap-record" data-record="${esc(r.evidence_id)}" data-kind="aibom_document"><h3>Selected AI-BOM <small class="mono">${esc(r.role)}</small></h3>
      <p>${esc(p || 'producer not recorded')} · CycloneDX ${esc(r.document?.spec_version)} · ${fmt(r.census?.models)} model${r.census?.models === 1 ? '' : 's'} declared${r.status && r.status !== 'ok' ? ' · document not readable by this build' : ''}</p>
      <p class="micro">Acquisition binding: ${esc(b.level || 'none')}${b.revision ? ` · revision <code>${esc(short(b.revision))}</code>` : ''}${(b.conflicts || []).length ? ` · conflicts: ${esc(b.conflicts.join('; '))}` : ''}</p>
      ${r.reason ? `<p class="ot-help">${esc(r.reason)}</p>` : ''}
      <p class="micro">AI-BOM SHA-256 <code>${esc(short(r.document?.raw_sha256))}</code> · ${esc(r.method)} · ${esc(r.origin)}</p></div>`;
  }
  if (r.kind === 'source_excerpt') {   // UIP-12: the observation in source, shown apart from any CBOM record
    const res = r.resolution || {}; const checks = Object.entries(r.checks || {}).map(([k, v]) => `<li><code>${esc(k)}</code>: ${v ? 'yes' : 'no'}</li>`).join('');
    const lines = Array.isArray(r.source?.lines) ? r.source.lines.join('–') : '';
    return `<div class="ot-gap-record" data-record="${esc(r.evidence_id)}"><h3>Source call site <small class="mono">${esc(r.role)}</small></h3>
      <p><code>${esc(r.source?.file)}:${esc(lines)}</code> · ${esc(String(r.operation || '').replaceAll('_', ' '))} · statically observed, not executed</p><pre class="ot-raw">${esc(r.excerpt)}${r.excerpt_truncated ? '\n… (cut)' : ''}</pre>
      <p class="micro">Resolution: ${esc(res.call || 'none')}${res.algorithm_literal ? ` · literal <code>${esc(res.algorithm_literal)}</code>` : ''} · binding ${esc(res.binding_status || 'unknown')}${res.imported_name ? ` · imported name <code>${esc(res.imported_name)}</code>` : ''}${res.local_module_named_hashlib ? ` · local module search: ${esc(String(res.local_module_named_hashlib).replaceAll('_', ' '))}` : ''}</p>
      ${checks ? `<details class="ot-more"><summary>Binding checks</summary><ul>${checks}</ul></details>` : ''}
      ${r.reason ? `<p class="ot-help">${esc(r.relation ? r.relation + ' · ' : '')}${esc(r.reason)}</p>` : ''}
      <p class="micro">File SHA-256 <code>${esc(short(r.source?.file_sha256))}</code> · ${esc(r.method)} · ${esc(r.origin)}</p></div>`;
  }
  if (r.kind === 'cbom_document') {    // UIP-12: what the selected CBOM records (a separate evidence record)
    const c = r.census || {}; const p = (r.producer || []).map((x) => `${esc(x.name)} ${esc(x.version)}`).join(', ');
    return `<div class="ot-gap-record" data-record="${esc(r.evidence_id)}"><h3>Selected CBOM <small class="mono">${esc(r.role)}</small></h3>
      <p>${esc(p || 'producer not recorded')} · CycloneDX ${esc(r.document?.spec_version)} · ${fmt(c.assets)} cryptographic asset${c.assets === 1 ? '' : 's'} among ${fmt(c.components)} components${r.status && r.status !== 'ok' ? ' · document not readable by this build' : ''}</p>
      ${r.reason ? `<p class="ot-help">${esc(r.reason)}</p>` : ''}
      <p class="micro">CBOM SHA-256 <code>${esc(short(r.document?.raw_sha256))}</code> · ${esc(r.method)} · ${esc(r.origin)}</p></div>`;
  }
  return `<div class="ot-gap-record" data-record="${esc(r.evidence_id)}"><h3>${esc(r.kind || 'Record')}</h3><p class="mono">${esc(r.evidence_id)}</p></div>`;
}

// UIP-12: the CBOM-side alias decision and the CBOM records that were seen but not used (both bounded, both from the rule's own finding).
function aliasAndExclusions(c) {
  const a = c.algorithm_alias; const ex = c.excluded_assets || [];
  const alias = a ? `<p><strong>Algorithm spelling:</strong> assertion <code>${esc(a.assertion_value)}</code> · source <code>${esc(a.source_value ?? 'not observed')}</code> · CBOM <code>${esc(a.cbom_value ?? 'no matching record')}</code> · ${a.applied ? 'finite alias mapping applied' : 'no alias applied'}</p>` : '';
  const excluded = ex.length ? `<details class="ot-more"><summary>${fmt(ex.length)} CBOM record${ex.length === 1 ? '' : 's'} seen but not used</summary><ul>${ex.map((x) => `<li><code>${esc(x.name)}</code> · ${esc(bomWords(x.reason_code))}: ${esc(x.detail)}</li>`).join('')}</ul></details>` : '';
  return alias + excluded;
}

// UIP-13: the AI-BOM identity and scan scope behind a model comparison, the models it matched by locator, and the occurrence counts (all bounded, all from the finding).
function modelEvidence(c) {
  if (!c.model_detail && !c.aibom) return '';
  const d = c.model_detail || {}; const n = (v) => fmt(v ?? 0); const a = c.aibom; const sc = a?.scan_scope || {};
  const counts = c.model_detail ? `<p><strong>Occurrences:</strong> ${n(d.occurrences_total)} in source · ${n(d.occurrences_in_scope)} compared · ${n(d.occurrences_outside_scope)} outside the AI-BOM scope · ${n(d.occurrences_gate_failed)} not compared for another reason (see the reason code) · ${n(d.occurrences_cited)} shown${d.reason_code ? ` · reason: <code>${esc(d.reason_code)}</code>` : ''}${d.aibom_model_entities_omitted ? ` · ${n(d.aibom_model_entities_omitted)} AI-BOM model records are listed below but not drawn in the graph` : ''}</p>` : '';
  const scope = a ? `<p><strong>AI-BOM scan scope (as recorded):</strong> revision <code>${esc(short(sc.revision))}</code> · ${sc.file_count == null ? 'file count not recorded' : fmt(sc.file_count) + ' files'} · listing <code>${esc(short(sc.listing_sha256))}</code> · paths ${esc((sc.paths || []).join(', ') || 'none recorded')}${a.completeness ? ` · producer completeness: ${esc(a.completeness)}` : ''}</p><ul class="ot-help">${(a.limits || []).map((x) => `<li>${esc(x)}</li>`).join('')}</ul>` : '';
  const models = (c.matching_models || []).length ? `<details class="ot-more"><summary>${fmt(c.matching_models_total)} AI-BOM model${c.matching_models_total === 1 ? '' : 's'} considered</summary><ul>${c.matching_models.map((m) => `<li><code>${esc(m.name)}</code> · ${esc(bomWords(m.match))}${m.has_hash ? '' : ' · declares no hash'}<br><code>${esc((m.locators || []).join(' '))}</code></li>`).join('')}</ul></details>` : '';
  return counts + scope + models;
}

// The evidence part shared by the legacy inspector and the active BOM inspector: what was compared, why, the separate records, the limits.
// `trigger: false` omits the "why it is a candidate" line where the caller already states it (the shared inspector's second question).
function gapEvidenceBody(c, { trigger = true } = {}) {
  const cc = c.coverage_contract;
  return `<p><strong>BOM checked:</strong> ${c.bom ? `${esc(c.bom.label)} <span class="mono">${esc(c.bom.inventory_id)}</span> · SHA-256 <code>${esc(short(c.bom.sha256))}</code>` : 'none'}</p>
    ${trigger ? `<p><strong>Why it is a candidate:</strong> ${esc(c.trigger || '')}</p>` : ''}
    ${(c.records || []).map(record).join('') || '<p class="ot-help">No separate evidence record is attached to this candidate.</p>'}
    ${aliasAndExclusions(c)}${modelEvidence(c)}
    ${cc && cc.established === false ? '<p class="ot-help">No coverage contract is established that this inventory should represent this declaration form, so this is a coverage gap, not a completeness defect.</p>' : ''}`;
}
function gapEvidence(c, advanced) {
  const lim = (c.not_established || []).map((x) => `<li>${esc(x)}</li>`).join('');
  return `${gapEvidenceBody(c)}
    <details class="ot-more"><summary>Sources &amp; coverage</summary>${lim ? `<p>Not established:</p><ul>${lim}</ul>` : ''}<p>Identity basis: ${esc(c.identity_basis || 'n/a')}</p>${c.bounded_meaning ? `<p>${esc(c.bounded_meaning)}</p>` : ''}${c.next_action ? `<p>Next: ${esc(c.next_action)}</p>` : ''}</details>
    ${advanced ? `<details class="ot-more" open><summary>Technical detail</summary><p>Candidate: <code>${esc(c.candidate_id)}</code></p><p>Assertion: <code>${esc(c.assertion_id || 'none')}</code></p><p>Rule: <code>${esc(c.rule_id || 'none')}</code></p><p>Reason codes: ${esc((c.reason_codes || []).join(', '))}</p></details>` : ''}`;
}
const gapRationale = (c) => esc(c.rationale || (c.state === 'unknown_coverage' ? 'Coverage is unknown: this was not compared against the BOM, and it is not a defect.' : ''));

export function inspector(s) {
  const g = s.gaps || {}; if (!g.selected) return null;
  if (g.detailError) return `<p class="ot-prompt" role="alert">The evidence could not be loaded (${esc(g.detailError)}).</p>`;
  const c = g.detail; if (!c || c.candidate_id !== g.selected) return '<p class="ot-prompt ot-loading" role="status">Loading evidence…</p>';
  return `<div class="ot-gap-inspector" data-candidate="${esc(c.candidate_id)}"><span class="mono">${esc(c.state_label).toUpperCase()} · ${esc(c.category_label).toUpperCase()}</span><h2>${esc(c.title)}</h2>
    <p class="ot-help">${gapRationale(c)}</p>
    ${gapEvidence(c, s.advanced)}</div>`;
}

// UIP-08: the versioned, bound BOM workspace. This renderer consumes only the three
// Workbench v1 payloads; legacy gap and family payloads are kept separate.
const BOM_VIEWS = [['software', 'Software · SBOM'], ['crypto', 'Cryptography · CBOM'], ['ai', 'AI models · AI-BOM'], ['full', 'Full evidence graph'], ['gaps', 'Focused gaps']];

// Presentation-only icons: small outline SVGs, decorative (aria-hidden; the visible text carries the meaning). No icon dependency.
// The shield marks the cryptography FAMILY; it does not imply that anything is verified or protected.
const ICON_PATHS = {
  package: '<path d="m12 3 8 4.5v9L12 21l-8-4.5v-9L12 3Z"/><path d="m4 7.5 8 4.5 8-4.5M12 12v9"/>',
  crypto: '<path d="M12 3 5 6v5.5c0 4.2 2.8 7.6 7 9.5 4.2-1.9 7-5.3 7-9.5V6l-7-3Z"/>',
  model: '<rect x="7" y="7" width="10" height="10" rx="1.5"/><path d="M10 10h4v4h-4zM9 3v4M15 3v4M9 17v4M15 17v4M3 9h4M3 15h4M17 9h4M17 15h4"/>',
  graph: '<circle cx="6" cy="6" r="2.2"/><circle cx="18" cy="8" r="2.2"/><circle cx="12" cy="18" r="2.2"/><path d="m8 7 8 .8M7 8l4 8M17 10l-4 6"/>',
  gaps: '<circle cx="10.5" cy="10.5" r="6"/><path d="m15 15 5.5 5.5M10.5 8v3.2M10.5 13.4v.1"/>',
  other: '<circle cx="12" cy="12" r="8"/><circle cx="12" cy="12" r="1.5"/>',
  warn: '<path d="M12 4 3 19.5h18L12 4Z"/><path d="M12 10v4.5M12 17v.1"/>',
  ok: '<circle cx="12" cy="12" r="8.5"/><path d="m8 12.3 3 3 5-6"/>',
  unavailable: '<circle cx="12" cy="12" r="8.5" stroke-dasharray="3 3"/><path d="M9.7 9.5a2.4 2.4 0 1 1 3.4 2.2c-.7.4-1.1.9-1.1 1.7M12 16.6v.1"/>',
  muted: '<circle cx="12" cy="12" r="8.5" stroke-dasharray="1.5 3"/><path d="M8.5 12h7"/>',
  selected: '<path d="m5 12.5 4.5 4.5L19 7.5"/>',
};
const bomIcon = (name, cls = '') => `<svg class="ot-bom8-icon${cls ? ' ' + cls : ''}" viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false">${ICON_PATHS[name] || ICON_PATHS.other}</svg>`;
const VIEW_ICON = { software: 'package', crypto: 'crypto', ai: 'model', full: 'graph', gaps: 'gaps' };
const FAMILY_ICON = { software: 'package', cryptography: 'crypto', ai_model: 'model', other: 'other' };
const FAMILY_NAME = { software: 'Software', cryptography: 'Cryptography', ai_model: 'AI model', other: 'Other' };
// Status chip: reuses the established candidate-state semantics (STATE_CLASS above); text is the existing label, the icon repeats the tone's shape.
export const bomStateChip = (state) => { const tone = STATE_CLASS[state] || 'muted'; return `<span class="ot-state ot-bom8-chip ${tone}" data-state="${esc(state)}">${bomIcon(tone)}<span>${esc(String(state || '').replaceAll('_', ' '))}</span></span>`; };
const BOM_FILTERS = [['all', 'All'], ['represented', 'Represented'], ['not_represented', 'Not represented'], ['unknown', 'Coverage unknown']];
const bomWords = (value) => String(value || '').replaceAll('_', ' ');
const bomFamily = (view) => ({ software: 'software', crypto: 'cryptography', ai: 'ai_model' })[view];
const bomRow = (item, selected) => { const fam = FAMILY_ICON[item.family] ? item.family : 'other'; return `<button type="button" class="ot-bom8-row${selected ? ' selected' : ''}" data-action="bom-select" data-id="${esc(item.item_id)}" aria-pressed="${selected}"><strong>${bomIcon(FAMILY_ICON[fam], 'ot-bom8-family')}<span class="ot-bom8-name">${esc(item.display.name)}</span><span class="ot-bom8-family-label">${FAMILY_NAME[fam]}</span>${selected ? `<span class="ot-bom8-selmark">${bomIcon('selected')}<span>Selected</span></span>` : ''}</strong><span class="ot-bom8-meta">${bomStateChip(item.state)} <span>${esc(item.location?.path || 'Location not recorded')}</span></span><small>${esc(item.inventory?.generator || 'No bound inventory')} · ${esc(bomWords(item.graph_state))}</small></button>`; };
const bomCount = (n) => fmt(Number(n || 0));

function bomGraph(g, selectedRecord, expanded = false) {
  if (!g) return '<p class="ot-prompt" role="status">Loading recorded graph…</p>';
  if (g.scope.kind === 'group_summary') return '<p class="ot-prompt">Choose a family or open all recorded evidence.</p>';
  const nodes = g.nodes || [], edges = g.edges || [];
  const recordList = `<div class="ot-bom8-records" role="list" aria-label="Complete labels for displayed records">${nodes.map((n) => `<button type="button" role="listitem" class="ot-bom8-record${selectedRecord === n.node_id ? ' selected' : ''}" data-action="bom-record" data-id="${esc(n.node_id)}"><strong>${esc(n.full_label)}</strong><small>${esc(bomWords(n.kind))} · ${esc(bomWords(n.evidence_role || n.role))}</small></button>`).join('') || '<p>No recorded nodes in this scope.</p>'}</div>`;
  const edgeList = `<details class="ot-bom8-edges"><summary>${bomCount(edges.length)} displayed relationships</summary><div>${edges.map((e) => `<button type="button" data-action="bom-edge" data-id="${esc(e.edge_id)}"><strong>${esc(bomWords(e.type))}</strong><small>${esc(e.from)} → ${esc(e.to)}${e.rationale ? ' · ' + esc(e.rationale) : ''}</small></button>`).join('') || '<p>No recorded relationships in this page.</p>'}</div></details>`;
  return `<div class="ot-bom8-graph-head"><span>${bomCount(g.counts.nodes_shown)} of ${bomCount(g.counts.nodes_in_scope)} nodes · ${bomCount(g.counts.edges_shown)} of ${bomCount(g.counts.edges_in_scope)} relationships${g.truncated ? ' · page is partial' : ''}</span><button type="button" class="button small" data-action="bom-fit">Fit graph</button>${expanded ? '' : '<button type="button" class="button small" data-action="bom-expand">Expand graph</button>'}</div>
    ${g.message_code ? '<p class="ot-help" role="status">More evidence is needed; this is a collection task without a rule verdict.</p>' : ''}
    <div class="ot-stage tall ot-bom8-stage" data-keep="cy-bom8-${expanded ? 'popup' : 'inline'}" data-bom-cy="${expanded ? 'popup' : 'inline'}"></div>
    <div class="ot-bom8-graph-lists">${recordList}${edgeList}</div>`;
}

// The ACTIVE workspace's inspector: the shared shell (header, four questions, evidence, collapsed Sources & coverage) fed by fromBom(). The markup built
// here is only what has no row form: the candidate's own loaded evidence records, or the related checks of one exact recorded node/relationship.
function relatedHtml(b) {
  const subject = b.related?.subject?.id === b.selectedRecord ? b.related : null;
  return !subject ? '<p role="status">Looking up related checks…</p>' : subject.resolution === 'multiple' ? `<p>${bomCount(subject.related_total)} related checks</p>${subject.items.map((r) => `<button type="button" class="ot-bom8-related" data-action="bom-related" data-id="${esc(r.item_id)}">${esc(r.display_name)}</button>`).join('')}` : subject.resolution === 'single' ? `<button type="button" class="button small" data-action="bom-related" data-id="${esc(subject.items[0].item_id)}">Open related check</button>` : `<p>${esc(subject.record_detail?.title || 'No related check recorded.')}</p>`;
}
function bomInspector(s) {
  const b = s.bom8, item = bomSelectedItem(b);
  if (!b.selectedRecord && !item) return '<p class="ot-prompt">Select a candidate or recorded item to inspect its source and limits.</p>';
  const model = fromBom(s); if (!model) return '<p class="ot-prompt">Select a candidate or recorded item to inspect its source and limits.</p>';
  if (b.selectedRecord) return renderInspector(model, { advanced: s.advanced, extra: b.graph?.nodes?.some((n) => n.node_id === b.selectedRecord) || b.graph?.edges?.some((e) => e.edge_id === b.selectedRecord) ? relatedHtml(b) : '' });
  const ev = bomEvidence(s, item);   // loading / error / ended-session states stay visible; the loaded detail folds into "Show all evidence"
  return renderInspector(model, { advanced: s.advanced, extra: ev.state, evidenceDetail: ev.detail });
}

// UIP-12-IR-04: the evidence detail of the selected candidate in the ACTIVE workspace. Shown only for the candidate it was loaded for (never another's);
// loading, failure and an ended session are stated, not hidden. Source observations and CBOM records stay separate records (see record()).
function bomEvidence(s, item) {
  const b = s.bom8; const c = b.detail?.candidate;
  if (b.stale) return { state: '', detail: '' };
  return b.detailError ? { state: `<p class="ot-prompt" role="alert">The evidence could not be loaded (${esc(b.detailError)}).</p>`, detail: '' }
    : c && c.candidate_id === item.item_id ? { state: '', detail: `<div class="ot-gap-inspector" data-candidate="${esc(c.candidate_id)}">${gapEvidenceBody(c, { trigger: false })}</div>` }
    : { state: '<p class="ot-prompt ot-loading" role="status">Loading evidence…</p>', detail: '' };
}

// UIP-10-F2: what "no candidates" means depends on the collection state. Zero candidates never implies complete coverage, and no represented count is
// shown because the bound payload carries none (candidates exist only for missing or unknown-coverage declarations).
function bomZeroText(q) {
  const state = (q.capabilities || []).find((x) => x.family === 'software')?.state;
  if (state === 'partial') return 'The comparison produced no candidates, but coverage was partial (see above), so this does not show that every requirement file or declaration was checked.';
  if (state === 'completed_empty') return 'No requirement declarations were found to compare, so the comparison produced no candidates.';
  if (state === 'completed') return 'The comparison produced no candidates. Declarations that match the SBOM are not listed as candidates, so no count of them is shown here.';
  return 'The bound comparison completed with no candidates.';
}

// Coverage text for the BOM connections views. It folds into the evidence strip's collapsed Details (workbench.js), in every view, live and captured.
export function bomDetailsHtml(s) {
  const q = s.bom8?.queue;
  if (!s.analysis) return '';
  // UIP-10-IR-03: a partial collection is disclosed in every BOM view (queue, focused and full evidence graph), whatever the list length or filter.
  const partial = q?.mode === 'discovery_compared' && (q.capabilities || []).some((x) => x.state === 'partial');
  const partialIn = (name) => (q?.capabilities || []).some((x) => x.family === name && x.state === 'partial');
  // UIP-12: a partial cryptography family is disclosed with its own wording (the software text would be wrong for it); both may apply at once.
  const coverage = partial ? `${partialIn('software') || !(partialIn('cryptography') || partialIn('ai_model')) ? '<p class="ot-prompt ot-bom8-coverage" role="status" data-coverage="partial"><strong>Partial coverage.</strong> Requirement files were compared with the SBOM, but not everything in this repository was checked: some matching files were skipped, the search stopped early or a directory could not be read, or declaration files of other formats were found and not compared. These results, and an empty list, do not show that nothing is missing.</p>' : ''}${partialIn('cryptography') ? '<p class="ot-prompt ot-bom8-coverage" role="status" data-coverage="partial" data-family="cryptography"><strong>Partial coverage (cryptography).</strong> Python <code>hashlib</code> call sites were observed in the files that could be read, but not everything was checked or compared: files were skipped, the search stopped early, other source languages exist, or some sites lie outside what the CBOM records. Observed sites are shown as observations only. These results, and an empty list, do not show that no cryptography is used.</p>' : ''}${partialIn('ai_model') ? '<p class="ot-prompt ot-bom8-coverage" role="status" data-coverage="partial" data-family="ai_model"><strong>Partial coverage (AI models).</strong> Static model references were observed in the files that could be read, but not everything was checked or compared: files were skipped, the search stopped early, expressions could not be resolved, other source languages exist, candidates were truncated, or some references cannot be compared for lack of usable AI-BOM binding or scan scope. These results, and an empty list, do not show that no model is used.</p>' : ''}` : '';
  const bound = `<p class="ot-help" data-bom-bound="1">Bound inventory and rule evidence for ${esc(s.analysis.identity.owner)}/${esc(s.analysis.identity.name)} · ${esc(s.analysis.identity.commit.slice(0, 7))}. A candidate is a hypothesis; recorded relationships do not prove runtime use.</p>`;
  return bound + coverage;
}

export function renderBomWorkspace(s) {
  const b = s.bom8, q = b.queue, g = b.graph, family = bomFamily(b.view);
  const counts = q?.counts || {}, items = q?.items || [];
  const activeGraph = b.view === 'full' ? g?.scope?.kind === 'full_view' : g?.scope?.kind === 'focused_candidate' && g.scope.candidate_id === b.selected;
  const status = b.stale ? '<p class="ot-prompt" role="alert">This comparison belongs to an ended session.</p>' : b.error ? `<p class="ot-prompt" role="alert">${esc(b.error)}</p>` : !q ? '<p class="ot-prompt" role="status">Loading bound BOM assessment…</p>' : q.mode !== 'discovery_compared' ? `<p class="ot-prompt" role="status">Not compared. ${esc(q.status_detail?.message || 'No bound discovery assessment is available.')}</p>` : counts.candidates_total === 0 ? `<p class="ot-prompt">${esc(bomZeroText(q))}</p>` : '';
  const capabilities = (q?.capabilities || []).filter((x) => x.family === family);
  const unavailable = family && !items.length && capabilities[0]?.state !== 'completed' ? `<p class="ot-prompt">${esc(BOM_VIEWS.find(([k]) => k === b.view)?.[1] || 'This family')} comparison: ${esc(bomWords(capabilities[0]?.state || 'not run'))}. An inventory alone does not establish a correspondence assessment.</p>` : '';
  // UIP-13: availability of the model comparison is stated in the AI view even when the family is not partial; an unfinished collection is not hidden by it.
  const aiCap = (q?.capabilities || []).find((x) => x.family === 'ai_model');
  const mc = s.analysis?.summary?.gaps?.collection?.models?.coverage;     // collection facts (separate from the comparison state), from the analysis summary
  const mObs = mc?.references?.observed;
  const aiNote = b.view === 'ai' && q?.mode === 'discovery_compared' && aiCap && ['not_run', 'failed', 'unsupported'].includes(aiCap.state) ? `<p class="ot-prompt ot-bom8-coverage" role="status" data-family="ai_model" data-availability="${esc(aiCap.state)}"><strong>Model comparison: ${esc(bomWords(aiCap.state))}.</strong> ${mObs ? 'Static model references that were observed are shown as observations only; nothing was compared with an AI-BOM' + (aiCap.state === 'not_run' ? ' because none was produced' : '') + '.' : 'No static model reference was observed, so nothing could be compared.'} Collection coverage is separate from this state: a stopped or incomplete search is not shown as complete by it.</p>` : '';
  const aiFacts = b.view === 'ai' && q?.mode === 'discovery_compared' && mc ? `<p class="ot-help" data-family="ai_model" data-collection-facts="1"><strong>Model-reference collection:</strong> ${fmt(mObs)} reference${mObs === 1 ? '' : 's'} observed${mc.count_kind === 'at_least' ? ' (at least; the search was incomplete)' : ''} in ${fmt(mc.processed)} of ${fmt(mc.selected)} selected source files · ${fmt(mc.dynamic?.count)} dynamic expression${mc.dynamic?.count === 1 ? '' : 's'} not resolved · collection ${mc.complete ? 'complete for the files in the supported forms' : 'incomplete'}.</p>` : '';
  const cards = b.view === 'full' ? `<div class="ot-bom8-cards">${[['all', 'All recorded evidence'], ['software', 'Software'], ['cryptography', 'Cryptography'], ['ai_model', 'AI models'], ['other', 'Other']].map(([key, label]) => `<button type="button" data-action="bom-group" data-group="${key}" aria-pressed="${b.group === key}"><strong>${label}</strong><small>${key === 'all' ? bomCount(counts.records_total) + ' recorded nodes' : bomCount(counts.family_counts?.[key]) + ' candidates'}</small></button>`).join('')}</div>` : '';
  const controls = `<div class="ot-bom8-controls"><div class="ot-bom8-filters" role="group" aria-label="Candidate status">${BOM_FILTERS.map(([key, label]) => `<button type="button" data-action="bom-filter" data-filter="${key}" aria-pressed="${b.filter === key}">${label} <b>${bomCount(key === 'all' ? counts.candidates_total : counts.filter_group_counts?.[key])}</b></button>`).join('')}</div><label>Search <input type="search" id="ot-bom8-q" data-fk="bom8q" value="${esc(b.q)}" placeholder="Candidate or location" maxlength="80"></label></div>`;
  const page = q?.page;
  const queue = `<section class="ot-bom8-queue" aria-label="Candidate queue"><h3>${b.view === 'gaps' ? 'Focused gaps' : 'Candidate checks'}</h3><p class="ot-help">${bomCount(counts.filtered_total)} matching candidates · ${bomCount(counts.assertions_unique)} distinct assertions in the bound assessment</p>${controls}<div class="ot-bom8-rows" data-scroll-key="bom8queue">${items.map((x) => bomRow(x, b.selected === x.item_id)).join('') || (!q ? '' : q.mode !== 'discovery_compared' ? '<p>Nothing was compared, so there are no candidates to list.</p>' : counts.candidates_total === 0 ? '<p>This assessment has no candidates.</p>' : '<p>No candidates match this filter. This does not establish absence.</p>')}</div><div class="ot-pager"><button type="button" data-action="bom-page" data-dir="-1" ${!page?.offset ? 'disabled' : ''}>Previous</button><span>${page ? `${bomCount(page.offset + (items.length ? 1 : 0))}–${bomCount(page.offset + items.length)} of ${bomCount(counts.filtered_total)}` : ''}</span><button type="button" data-action="bom-page" data-dir="1" ${!page?.has_more ? 'disabled' : ''}>Next</button></div></section>`;
  const full = b.view === 'full';
  const graphControls = full ? `<div class="ot-bom8-controls"><label>Find recorded nodes <input type="search" id="ot-bom8-full-q" data-fk="bom8fullq" value="${esc(b.fullQ || '')}" maxlength="80"></label><button type="button" data-action="bom-full-page" data-dir="-1" ${!b.fullOffset ? 'disabled' : ''}>Previous records</button><button type="button" data-action="bom-full-page" data-dir="1" ${!g?.truncated || (g?.counts?.primary_shown || 0) < 100 ? 'disabled' : ''}>Next records</button></div>` : '';
  const graph = `<section class="ot-bom8-main" aria-label="Recorded BOM graph"><h3>${full ? 'Full evidence graph' : 'Focused recorded graph'}</h3>${cards}${graphControls}${activeGraph ? bomGraph(g, b.selectedRecord) : q && q.mode !== 'discovery_compared' ? '<p class="ot-prompt" role="status">There is no bound comparison graph to show: nothing was compared (see above).</p>' : '<p class="ot-prompt" role="status">Choose a candidate to load its recorded graph.</p>'}</section>`;
  const popup = b.popup === 'graph' ? `<div class="ot-bom8-overlay" role="dialog" aria-modal="true" aria-label="Expanded BOM graph"><div class="ot-bom8-popup"><div class="ot-bom8-popup-head"><strong>Recorded evidence graph</strong><button type="button" data-action="bom-close">Close</button></div>${activeGraph ? bomGraph(g, b.selectedRecord, true) : '<p>Loading…</p>'}</div></div>` : b.popup === 'chooser' ? `<div class="ot-bom8-overlay" role="dialog" aria-modal="true" aria-label="Related checks"><div class="ot-bom8-popup ot-bom8-chooser"><div class="ot-bom8-popup-head"><strong>Related checks for this exact record</strong><button type="button" data-action="bom-close">Close</button></div><label>Search related checks <input type="search" id="ot-bom8-chooser-q" data-fk="bom8chooserq" maxlength="80" value="${esc(b.chooserQ)}"></label><div>${(b.related?.items || []).map((r) => `<button type="button" class="ot-bom8-related" data-action="bom-related" data-id="${esc(r.item_id)}">${esc(r.display_name)} · ${esc(bomWords(r.state))}</button>`).join('') || '<p>No related checks match.</p>'}</div><div class="ot-pager"><button type="button" data-action="bom-chooser-page" data-dir="-1" ${!b.chooserOffset ? 'disabled' : ''}>Previous</button><span>${bomCount(b.related?.related_total)} related checks</span><button type="button" data-action="bom-chooser-page" data-dir="1" ${!b.related?.page?.has_more ? 'disabled' : ''}>Next</button></div></div></div>` : '';
  return `<div class="ot-bom8"><nav class="ot-bom8-tabs" aria-label="BOM views">${BOM_VIEWS.map(([key, label]) => `<button type="button" data-action="bom-view" data-view="${key}" aria-current="${b.view === key ? 'page' : 'false'}">${bomIcon(VIEW_ICON[key])}<span>${label}</span></button>`).join('')}</nav>${status}${aiNote}${aiFacts}${unavailable}<div class="ot-bom8-layout">${queue + graph}<aside class="ot-bom8-inspector${b.drawer ? ' open' : ''}" aria-label="BOM details"><div class="ot-bom8-drawer-head"><h3>Details</h3><button type="button" data-action="bom-drawer" aria-expanded="${b.drawer}">${b.drawer ? 'Close' : 'Open'} details</button></div><div class="ot-bom8-drawer-body">${bomInspector(s)}</div></aside></div>${popup}</div>`;
}
