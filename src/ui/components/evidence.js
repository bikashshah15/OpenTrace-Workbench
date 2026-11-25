import { esc, fmt } from '../lib/util.js';
import { ARTIFACT_COPY, INFO, LIVE_ARTIFACT_COPY } from '../lib/copy.js';
import { infoButton } from './intake.js';
import { inventoryChecks } from './workbench.js';
import { evidenceStatus } from '../lib/evidence_status.js';

const short = (h) => (h ? h.slice(0, 12) : '');
const WORD = { acquired: 'Completed', failed: 'Failed', unavailable: 'Not run', cancelled: 'Cancelled' };

const ORDER = ['sbom', 'cbom', 'aibom'];
const TITLE = { sbom: 'Software inventory (SBOM)', cbom: 'Cryptography inventory (CBOM)', aibom: 'AI model inventory (AI-BOM)' };
// Decorative only (aria-hidden): the visible word and the accessible name stay "Preview".
const EYE = '<svg class="ot-eye" viewBox="0 0 16 16" width="14" height="14" fill="none" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M1.5 8S4 3.5 8 3.5 14.5 8 14.5 8 12 12.5 8 12.5 1.5 8 1.5 8Z"/><circle cx="8" cy="8" r="2"/></svg>';
const previewBtn = (name, disabled = false) => `<button type="button" class="button small" data-action="preview" data-name="${esc(name)}" ${disabled ? 'disabled' : ''}>${EYE}Preview</button>`;
const downloadLink = (name) => `<a class="button small" href="/api/artifacts/${encodeURIComponent(name)}?disposition=attachment" download="${esc(name)}">Download \u2193</a>`;
const actionsFor = (name, disabled) => `<div class="ot-artifact-actions">${previewBtn(name, disabled)}${downloadLink(name)}</div>`;
// Important inventory statuses only (the strip's own state codes); a plain "available" is not repeated on the card.
const QUIET = new Set(['available', 'available_empty', 'recorded', 'loading']);

// One inventory card: what was reported, an important status, Preview/Download, and everything technical inside one collapsed Details.
function inventoryCard(s, c, art, status) {
  const live = s.analysis.identity.mode === 'live'; const r = c.scan || {};
  const title = TITLE[c.kind] || (LIVE_ARTIFACT_COPY[c.kind] || ARTIFACT_COPY[c.kind] || [c.kind])[0];
  const ok = !live || r.outcome === 'acquired'; const scope = r.scope || {};
  let reported; const details = [];
  if (live) {
    const unit = (r.record_count_unit || '').replaceAll('_', ' ');
    reported = ok
      ? `<p class="ot-live-outcome" data-outcome="acquired"><strong>Scan completed.</strong> ${fmt(r.record_count)} ${esc(unit)} reported${r.record_count === 0 ? ` \u2014 ${esc(r.meaning)}` : ''}.</p>`
      : `<p class="ot-live-outcome ot-session-error" data-outcome="${esc(r.outcome)}" role="alert"><strong>${esc(WORD[r.outcome] || r.outcome)}.</strong> ${esc((r.reason || '').replaceAll('_', ' '))}. No ${esc(c.kind.toUpperCase())} was produced and none is substituted.${r.exit_code != null ? ` Exit code ${esc(r.exit_code)}.` : ''}</p>`;
    details.push(['Scanner', `${esc(r.tool)} ${esc(r.version || 'version unknown')} <small>(pinned ${esc(r.pinned_version)})</small>`], ['Scope', `${esc(scope.basis || '')} \u00b7 ${fmt(scope.file_count)} files \u00b7 listing ${esc(short(scope.listing_sha256))}\u2026`], ['Isolation', `${esc(r.isolation)} (network denied)`]);
    if (ok) details.push(['Artifact', `<span class="mono micro">${esc(c.artifact_name)} \u00b7 ${fmt(art ? art.size : r.size)} bytes \u00b7 sha256 ${esc(r.sha256)}</span>`]);
    else if (r.rejected_sha256) details.push(['Rejected output', `<span class="mono micro">not offered \u00b7 sha256 ${esc(r.rejected_sha256)}</span>`]);
  } else {
    const [, eyebrow, copy] = ARTIFACT_COPY[c.kind] || [c.kind, c.kind, ''];
    reported = `<p>${esc(copy)}</p>`;
    details.push(['Producer', esc(eyebrow)]);
    if (art) details.push(['Artifact', `<span class="mono micro">${esc(art.name)} \u00b7 ${fmt(art.size)} bytes \u00b7 sha256 ${esc(short(art.sha256))}\u2026</span>`]);
  }
  const chip = status && !QUIET.has(status.code) && ok ? `<p class="ot-inv-status" data-status="${esc(status.code)}"><strong>${esc(status.text)}</strong></p>` : '';
  const warn = (r.warnings || []).length ? `<p><strong>Scanner messages (${r.warnings.length})</strong></p>${r.warnings.map((w) => `<p class="micro mono">${esc(w)}</p>`).join('')}` : '';
  const more = `<details class="ot-more"><summary>Details</summary><dl class="ot-kvl">${details.map(([k, v]) => `<dt>${esc(k)}</dt><dd>${v}</dd>`).join('')}</dl>${warn}</details>`;
  return `<article class="ot-small-card" data-inventory="${esc(c.kind)}"${live ? ` data-live-kind="${esc(c.kind)}" data-live-outcome="${esc(r.outcome)}"` : ''}><h3>${esc(title)}</h3>${reported}${chip}${ok ? actionsFor(c.artifact_name, !art) : ''}${more}</article>`;
}
const SUPPORT = {
  'bombridge-result.json': ['Inventory assessment record', 'Recorded inventory information and any checks included in the assessment.'],
  'source-declarations.json': ['Source evidence', 'Repository observations, including dependency declarations, cryptography calls, and AI model references when collected.'],
  'advisory-lookup.json': ['Advisory lookup record', 'The OSV lookup plan and each query\u2019s outcome, without advisory text.'],
};
const link = (tab, label) => `<button type="button" class="evidence-link" data-action="open-tab" data-tab="${tab}">${label}</button>`;
// One short advisory status (always visible, with or without a downloadable record) and the full breakdown in a collapsed Details.
function advisoryStatus(a, live) {
  const L = a.summary.advisory_lookup; const g = a.summary.advisory_groups; const groups = Number.isInteger(g) ? ` \u00b7 ${fmt(g)} advisory group${g === 1 ? '' : 's'} matched` : '';
  if (!live) return `Captured advisory snapshot${groups}`;
  if (!L) return 'Advisory matching not run';
  const word = { complete: 'Lookup complete', partial: 'Partial lookup', unavailable: 'Lookup unavailable', not_run: 'Lookup not run' }[L.lookup] || 'Lookup recorded';
  return word + (L.lookup === 'unavailable' || L.lookup === 'not_run' ? '' : groups);
}
function advisoryDetails(a, live) {
  const L = a.summary.advisory_lookup; const n = L?.states || {};
  const body = !live ? `<p>1775 unique version queries, ${fmt(a.summary.advisory_groups)} advisory groups; captured 2026-11-04. These matches come from the dated OSV snapshot bundled with this service and are separate from the three inventory artifacts above.</p>`
    : !L ? '<p>Advisory lookup is not enabled for this service. The captured Frigate advisory snapshot is never applied to live results.</p>'
    : `<p>Lookup ${esc(String(L.lookup).replaceAll('_', ' '))}: ${fmt(n.match)} advisory match, ${fmt(n.no_match)} no advisory returned, ${fmt(n.unavailable)} lookup unavailable, ${fmt(n.not_looked_up)} not looked up. ${L.lockfile_only?.match ? `${fmt(L.lockfile_only.match)} of the matches are on lockfile-only packages that are not linked to an SBOM component. ` : ''}Lookup completion covers the planned lockfile queries, not SBOM completeness. Matches do not establish reachability or exploitability.</p>`;
  return `<details class="ot-more" id="ot-evidence-lookup"><summary>Details</summary>${body}<p class="ot-help">Rows and per-package evidence are in the Workbench.</p></details>`;
}
const meta = (x) => `<small class="mono micro">${esc(x.name)} \u00b7 ${fmt(x.size)} bytes \u00b7 sha256 ${esc(short(x.sha256))}\u2026</small>`;
function supportRow(a, x, live) {
  const [label, desc] = SUPPORT[x.name] || [x.name, 'A derived output produced by OpenTrace.'];
  const adv = x.name === 'advisory-lookup.json';
  const compared = a.summary.gaps?.status === 'compared';
  const extra = adv ? ''
    : x.name === 'bombridge-result.json' && compared ? `<br><small class="ot-help">${link('bom', 'View comparisons in BOM connections \u2197')}</small>` : '';
  return `<div class="group-record ot-support-row" data-artifact="${esc(x.name)}"><span><strong>${esc(label)}</strong><small class="ot-help"> ${esc(desc)} Derived by OpenTrace, not an original capture.</small>${adv ? advisoryLine(a, live) : ''}${extra}<br>${meta(x)}${adv ? advisoryDetails(a, live) : ''}</span>${actionsFor(x.name, false)}</div>`;
}
const advisoryLine = (a, live) => `<br><small class="ot-help" data-advisory-status="1">${esc(advisoryStatus(a, live))} \u00b7 ${link('dependencies', 'Breakdown in the Workbench \u2197')}</small>`;
// No downloadable lookup record: the status (including unavailable or skipped) is still shown, with no Preview or Download.
function advisoryOnlyRow(a, live) {
  return `<div class="group-record ot-support-row" data-artifact="advisory-status"><span><strong>Advisory lookup</strong>${advisoryLine(a, live)}${advisoryDetails(a, live)}</span></div>`;
}
export function renderEvidence(s) {
  const a = s.analysis; if (!a) return '';
  const live = a.identity.mode === 'live';
  const arts = s.evidence.artifacts; const byName = Object.fromEntries(arts.map((x) => [x.name, x]));
  const st = (evidenceStatus(s, 'bom') || { items: [] }).items;
  const ordered = [...a.summary.cards].sort((x, y) => (ORDER.indexOf(x.kind) + 1 || 9) - (ORDER.indexOf(y.kind) + 1 || 9));
  const cards = ordered.map((c) => inventoryCard(s, c, byName[c.artifact_name], st.find((i) => i.kind === c.kind))).join('');
  const derived = arts.filter((x) => x.kind === 'derived').map((x) => supportRow(a, x, live)).join('');
  const advRow = arts.some((x) => x.name === 'advisory-lookup.json') ? '' : advisoryOnlyRow(a, live);
  const hasChecks = (a.summary.checks || []).length > 0 || (live && (a.summary.source_checks || []).length > 0);
  const recs = s.evidence.records.map((r) => `<div class="group-record"><span><strong>${esc(r.evidence_id)}</strong><small class="ot-help"> ${esc(r.label)} by a displayed check \u00b7 ${esc(r.record.method || '')}</small></span><button type="button" class="evidence-link" data-action="record" data-id="${esc(r.evidence_id)}">Inspect record \u2197</button></div>`).join('');
  return `<div class="ot-intake wide"><div class="eyebrow">${esc(live ? a.identity.name.toUpperCase() : 'FRIGATE')} / ${esc(a.identity.commit.slice(0, 7).toUpperCase())}</div><h1>Artifacts and supporting evidence.</h1>
  <p class="ot-help ot-lead">Start with an inventory. Open the specific source records when you need to understand a finding.</p>
  <div class="ot-section-heading"><h2>Inventories</h2></div><div class="ot-arts">${cards}</div>
  <div class="ot-section-heading"><h2>Supporting evidence</h2></div><div class="ot-records ot-support">${derived}${advRow}</div>
  <p class="ot-note">Preview artifacts on this page, or download a copy. They are temporary and available only for the active session; ending the session deletes them.</p>
  ${hasChecks ? inventoryChecks(s) : ''}
  ${recs ? `<div class="ot-section-heading"><h2>Records behind the findings</h2>${infoButton(INFO.evidence, 'About supporting records')}</div><div class="ot-records">${recs}</div>` : ''}
  </div>`;
}
