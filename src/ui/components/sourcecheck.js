// I5C: the source-backed check, shown as three separate blocks. Pure functions of the analysis summary (no DOM, no network),
// so they can be tested with node:test. The source observation never carries the rule's conclusion, and the conclusion never
// repeats the observation: each block is built from its own part of the payload.
import { esc } from '../lib/util.js';

const CONCLUSION = { supported: 'Declaration agrees', unverifiable: 'Could not confirm', inconclusive: 'Could not confirm', contradicted: 'Discrepancy' };
export const conclusionLabel = (state) => CONCLUSION[state] || String(state || '').replaceAll('_', ' ');
const kv = (k, v) => `<div class="ot-kv"><span>${esc(k)}</span><strong class="ot-wrap">${v}</strong></div>`;
const mono = (v) => `<code>${esc(v)}</code>`;

export function sourceObservation(o) {
  const r = o.resolution || {};
  return `<section class="ot-source-block" aria-labelledby="sc-src-h"><span class="mono">OBSERVED IN SOURCE</span><h3 id="sc-src-h">Source observation</h3>
    ${kv('Repository', esc(o.repository))}${kv('Commit', mono(o.commit))}${kv('File', mono(o.path))}${kv('Line', esc(o.line))}
    <pre class="ot-raw" aria-label="Verbatim source line"><span class="ot-lineno">${esc(o.line)}</span>${esc(o.excerpt)}</pre>
    ${kv('File SHA-256', mono(o.file_sha256))}
    <p class="ot-help">Resolved statically to <strong>${esc(r.call)}</strong>: imported from ${mono(r.module)} at line ${esc(r.import_line)} (${mono(r.import_text)}), string literal ${mono(JSON.stringify(r.literal_algorithm))}. ${esc(r.method)}.</p>
    <p class="ot-help">This is what the file says at this commit. It does not show that the code runs.</p></section>`;
}

export function cbomRecord(r) {
  const d = r.document || {}; const m = r.matching_occurrence; const cands = r.candidates || []; const inRange = cands.filter((x) => x.match === 'location_in_range');
  let body;
  if (!d.acquired) body = `<p class="ot-help">No CBOM document was acquired for this analysis (${esc(String(d.outcome || 'not run').replaceAll('_', ' '))}${d.reason ? ': ' + esc(d.reason) : ''}), so there is no record to compare with the source line.</p>`;
  else {
    body = `${kv('Document', esc(d.artifact) + ' · CycloneDX ' + esc(d.spec_version))}${kv('Document SHA-256', mono(d.sha256))}${kv('Generator', esc(d.producer.name + ' ' + d.producer.version))}`;
    body += m ? `${kv('Asset (as recorded)', mono(m.name))}${kv('Occurrence', mono(m.file + ':' + m.line))}${kv('Context', esc(m.context || 'none recorded'))}${kv('bom-ref', mono(m.bom_ref || 'none'))}`
      : inRange.length > 1 ? `<p class="ot-help">${inRange.length} occurrences lie in the observed range, so none is singled out as the match.</p>`
      : `<p class="ot-help">No occurrence is matched to the observed file and line.</p>`;
    if (cands.length) body += `<p class="ot-help">Candidate occurrences${m ? ' (not matched)' : ''}: ${cands.map((x) => mono(x.file + ':' + x.line + (x.name ? ' ' + x.name : ''))).join(', ')}.</p>`;
  }
  return `<section class="ot-source-block" aria-labelledby="sc-cbom-h"><span class="mono">DECLARED IN CBOM</span><h3 id="sc-cbom-h">CBOM record</h3>${body}
    <p class="ot-help">This is what the generator reported, not whether it is right.</p></section>`;
}

export function ruleConclusion(c, assertionId, withAction = true) {
  const a = c.algorithm_alias || {};
  const alias = a.applied ? `<p class="ot-help">Spellings compared: source ${mono(a.source_value)} · CBOM ${mono(a.cbom_value)}. The rule treats these two as the same algorithm (its only alias pair); both values are kept as recorded.</p>` : '';
  return `<section class="ot-source-block" aria-labelledby="sc-rule-h"><span class="mono">${esc(conclusionLabel(c.state).toUpperCase())}</span><h3 id="sc-rule-h">Rule conclusion</h3>
    ${kv('Rule', mono(c.rule_id))}${kv('Reason', esc((c.reason_codes || []).join(', ')))}
    <p class="ot-help">${esc(c.rationale)}</p>${alias}
    <details class="ot-more"><summary>Not established</summary><ul>${(c.not_established || []).map((x) => `<li>${esc(x)}</li>`).join('')}</ul>${c.next_action ? `<p>Next: ${esc(c.next_action)}</p>` : ''}</details>
    ${withAction ? `<p><button type="button" class="button small" data-action="open-check" data-check="${esc(assertionId)}" data-mode="crypto">Inspect in Cryptography →</button></p>` : ''}</section>`;
}

export function renderSourceChecks(summary) {
  const list = (summary && summary.source_checks) || [];
  if (!list.length) return '';
  const items = list.map((c) => {
    if (c.status === 'skipped') return `<div class="ot-source-check"><p class="ot-help">Skipped ${mono(c.file + ':' + c.line)} (${esc(c.reason.replaceAll('_', ' '))}). No observation was recorded and nothing was assessed.</p></div>`;
    return `<div class="ot-source-check">${sourceObservation(c.source_observation)}${cbomRecord(c.cbom_record)}${c.conclusion ? ruleConclusion(c.conclusion, c.assertion_id) : ''}</div>`;
  }).join('');
  return `<div class="ot-section-heading"><h2>Source-backed check</h2></div>
    <p class="ot-help">One declaration read from the repository source, compared with one record of the CBOM. The observation, the record and the conclusion are kept apart.</p>${items}`;
}
