// Live advisory lookup (I5B). Pure string renderers: they take the analysis summary and the lookup view state and
// return HTML, so the three outcomes — match, no match, lookup unavailable — can be tested without a browser.
import { esc, fmt } from '../lib/util.js';

export const STATES = ['match', 'no_match', 'unavailable', 'not_looked_up'];
export const STATE_LABEL = { match: 'Advisory match', no_match: 'No advisory returned', unavailable: 'Lookup unavailable', not_looked_up: 'Not looked up' };
const STATE_CLASS = { match: 'warn', no_match: 'ok', unavailable: 'unavailable', not_looked_up: 'muted' };
const JOIN_LABEL = { both: 'In SBOM and lockfile', sbom_only: 'SBOM only', inventory_only: 'Lockfile only' };
export const NOT_ESTABLISHED = 'Reachability and exploitability are not established. An advisory match says the reported package version falls in a range the advisory database lists as affected; it does not say the vulnerable code is used or can be triggered.';
const REASON = {
  page_limit_reached: 'the page limit was reached before any advisory was seen', malformed_result: 'the advisory source returned a malformed result', network_error: 'the advisory source could not be reached', http_503: 'the advisory source answered with a server error', http_429: 'the advisory source limited requests',
  unparseable_response: 'the advisory source’s answer could not be read', query_rejected: 'the advisory source rejected the query', cancelled: 'the lookup was cancelled',
  wall_cap_reached: 'the lookup time limit was reached', batch_request_cap_reached: 'the lookup request limit was reached', not_attempted: 'the lookup stopped before this version',
  specialist_unavailable: 'the lockfile parser is not available', go_toolchain_missing: 'the lockfile parser could not start (Go toolchain missing)',
  inventory_unavailable: 'the lockfile inventory could not be produced', inventory_failed: 'the lockfile inventory could not be produced',
};
const cap = (x) => x.charAt(0).toUpperCase() + x.slice(1);
export const reasonText = (r) => REASON[r] || (String(r).startsWith('page_failed') ? 'a continuation page of the answer failed or was malformed' : null) || String(r || 'unknown reason').replaceAll('_', ' ');

export const SCOPE_NOTE = 'Complete covers the planned lockfile queries only; it does not mean the SBOM lists every package.';
// RT-01: advisory matches on packages that are in a lockfile but not in the SBOM are shown apart from SBOM-linked results.
export function lockOnlyNote(sum) {
  const lo = sum.lockfile_only || {}; const n = Number.isInteger(lo.match) ? lo.match : 0;
  if (!n) return '';
  return `<p class="ot-lookup-lockonly"><strong>${fmt(n)} lockfile-only package${n === 1 ? '' : 's'} with advisory matches</strong> (${fmt(lo.advisory_groups)} advisory group${lo.advisory_groups === 1 ? '' : 's'}). These come from the lockfile and are <em>not</em> linked to an SBOM component, so they are not in the SBOM-linked headline count. Filter “Advisory match” below to see them.</p>`;
}

export function banner(sum) {
  const c = sum.counts || {};
  if (sum.lookup === 'unavailable') {
    return `<div class="ot-lookup-banner unavailable" role="alert" id="ot-lookup-banner"><strong>Advisory lookup unavailable</strong><p>${esc(cap(reasonText(sum.lookup_reason)))}. No advisory match and no “no match” claim is made for these packages: an unavailable lookup says nothing about whether advisories exist. The scan results above are unaffected.</p></div>`;
  }
  if (sum.lookup === 'partial') {
    return `<div class="ot-lookup-banner partial" role="status" id="ot-lookup-banner"><strong>Partial advisory lookup</strong><p>${fmt(c.answered)} of ${fmt(c.planned_queries)} versions were answered; ${fmt(c.failed)} are shown as “Lookup unavailable”${c.records_failed ? ` and ${fmt(c.records_failed)} advisory record${c.records_failed === 1 ? '' : 's'} could not be fetched` : ''}. ${c.incomplete_answers ? `${fmt(c.incomplete_answers)} match${c.incomplete_answers === 1 ? ' is' : 'es are'} incomplete: the page limit was reached, so more advisories may exist.` : ''} Unanswered versions are not reported as having no advisories.</p>${lockOnlyNote(sum)}</div>`;
  }
  return `<div class="ot-lookup-banner complete" role="status" id="ot-lookup-banner"><strong>Lookup complete</strong><p>${fmt(c.planned_queries)} exact lockfile version${c.planned_queries === 1 ? '' : 's'} sent to OSV; ${fmt(c.answered_with_advisories)} returned at least one advisory. “No advisory returned” means OSV answered with none for that exact version; it is not a statement that the package is safe. ${SCOPE_NOTE}</p>${lockOnlyNote(sum)}</div>`;
}

export function chips(sum, active) {
  const n = sum.states || {};
  const all = `<button type="button" class="ot-chip-button${active ? '' : ' active'}" data-action="lookup-state" data-state="" aria-pressed="${!active}">All <b>${fmt(sum.rows)}</b></button>`;
  return `<div class="ot-lookup-chips" role="group" aria-label="Filter by lookup outcome">${all}${STATES.map((k) => `<button type="button" class="ot-chip-button ${STATE_CLASS[k]}${active === k ? ' active' : ''}" data-action="lookup-state" data-state="${k}" aria-pressed="${active === k}">${esc(STATE_LABEL[k])} <b>${fmt(n[k] || 0)}</b></button>`).join('')}</div>`;
}

export function row(r) {
  const fam = (r.families || []).map((f) => `<button type="button" class="evidence-link" data-action="read-advisory" data-key="${esc(f.key)}" data-pkg="${esc(r.name + ' ' + r.version)}">${esc(f.label)}${f.severity ? ' · ' + esc(f.severity) : ''} ↗</button>`).join(' ');
  const why = r.state === 'unavailable' || r.state === 'not_looked_up' ? `<p class="ot-lookup-why">${esc(r.reason_text || reasonText(r.reason))}</p>` : '';
  const incomplete = r.incomplete ? '<p class="ot-lookup-why">Incomplete: the page limit was reached, so more advisories may exist.</p>' : '';
  const withdrawn = r.withdrawn_only ? '<p class="ot-lookup-why">Only withdrawn advisories were returned.</p>' : '';
  return `<article class="ot-lookup-row state-${r.state}" data-state="${r.state}" data-row="${esc(r.id)}"><div><strong class="ot-pkg-name">${esc(r.name)}</strong> <span class="mono">${esc(r.version || 'no version')}</span>
    <small class="micro"> ${esc(r.ecosystem || '')} · ${esc(JOIN_LABEL[r.join] || r.join)}${r.locations?.length ? ' · ' + esc(r.locations.join(', ')) : ''}</small>${why}${withdrawn}${incomplete}</div>
    <div class="ot-lookup-side"><span class="ot-state ${STATE_CLASS[r.state]}">${esc(STATE_LABEL[r.state])}</span>${fam ? `<p>${fam}</p>` : ''}${r.has_evidence ? `<p><button type="button" class="evidence-link" data-action="lookup-evidence" data-id="${esc(r.id)}">Evidence ↗</button></p>` : ''}</div></article>`;
}

export function panel(s) {
  const sum = s.analysis?.summary?.advisory_lookup; const lk = s.advLookup || {};
  if (!sum) return '';
  const d = lk.data;
  const list = lk.error ? `<p class="ot-prompt" role="alert">The lookup table could not be loaded (${esc(lk.error)}).</p>`
    : !d ? '<p class="ot-prompt" role="status">Loading…</p>'
    : d.items.length ? d.items.map(row).join('')
    : !d.total && !lk.state && !lk.q ? '<p class="ot-prompt" role="status">The lookup produced no rows: no lockfile package versions were looked up for this analysis.</p>'
    : '<p class="ot-prompt" role="status">No package matches this filter.</p>';
  const from = d && d.total ? d.page * d.page_size + 1 : 0; const to = d ? Math.min(d.total, (d.page + 1) * d.page_size) : 0;
  return `<section class="ot-advisories ot-lookup" id="ot-adv-lookup" aria-labelledby="ot-adv-h"><div class="ot-adv-head"><div><h2 id="ot-adv-h">Package advisory lookup</h2>
    <p class="ot-help">Exact lockfile versions looked up in OSV, joined to the SBOM by ecosystem, normalized name and version. <strong>Repository-wide:</strong> these rows cover every lockfile version in this analysis; they are not filtered by, or attributed to, the selected context or package. ${esc(NOT_ESTABLISHED)}</p></div></div>
    ${banner(sum)}${chips(sum, lk.state || null)}
    <div class="ot-search-line"><span class="ot-help">${fmt(sum.join?.both)} in both inventories · ${fmt(sum.join?.sbom_only)} SBOM only · ${fmt(sum.join?.inventory_only)} lockfile only${sum.lockfile_only?.match ? ` (${fmt(sum.lockfile_only.match)} with advisory matches)` : ''}</span><input type="search" id="ot-lookup-q" placeholder="Search package…" aria-label="Search lookup rows" value="${esc(lk.q || '')}"></div>
    <div class="ot-lookup-rows" aria-live="polite">${list}</div>
    <div class="ot-search-line"><span class="ot-help">${d && d.total ? `Showing ${from}–${to} of ${fmt(d.total)}` : ''}</span><span><button type="button" class="button small" data-action="lookup-page" data-dir="-1" ${!d || d.page <= 0 ? 'disabled' : ''}>Previous</button> <button type="button" class="button small" data-action="lookup-page" data-dir="1" ${!d || to >= d.total ? 'disabled' : ''}>Next</button></span></div></section>`;
}

export function evidenceHtml(ev) {
  const e = ev.evidence || {}; const x = e.exchange || {};
  const recs = (e.records || []).map((r) => `<li><code>${esc(r.id)}</code> — ${r.sha256 ? `record sha256 <code>${esc(r.sha256)}</code>` : `record not fetched (${esc(reasonText(r.unavailable))})`}</li>`).join('');
  return `<p><strong>${esc(ev.name)} ${esc(ev.version)}</strong> · ${esc(ev.state_label)}</p>
  <p>${esc(ev.match_basis || 'This row is not in both inventories, so it is not attached to an SBOM component.')}</p>
  <h3>Query sent</h3><pre class="ot-raw">${esc(JSON.stringify(e.query, null, 2))}</pre>
  <h3>Answer received</h3><p class="micro">${esc(e.source || '')} · ${esc(e.queried_at || '')}${e.truncated ? ' · page limit reached: more advisories may exist' : ''}</p>
  <pre class="ot-raw">${esc(JSON.stringify(e.response_slot, null, 2))}</pre>
  <p class="micro">Exchange: HTTP ${esc(x.status)} · request sha256 <code>${esc(x.request_sha256 || '')}</code> · response sha256 <code>${esc(x.response_sha256 || '')}</code> (${esc(x.bytes)} bytes; shared by every version in the same batch).</p>
  <h3>Advisory records</h3>${recs ? `<ul>${recs}</ul>` : '<p>None returned for this exact version.</p>'}
  <h3>Where it comes from</h3><ul>${(ev.sbom || []).map((c) => `<li>SBOM: <code>${esc(c.purl || c.name)}</code></li>`).join('')}${(ev.inventory || []).map((i) => `<li>Lockfile: <code>${esc(i.path)}</code> <code>${esc(i.locator)}</code>${i.direct ? ' (direct dependency)' : ''}</li>`).join('')}</ul>
  <p><strong>Not established:</strong> ${esc(ev.not_established)}</p>`;
}
