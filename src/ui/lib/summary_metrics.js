// UIP-02 §4.1: the four Workbench pills, computed from the ACTIVE analysis only (identity + summary).
// Pure and side-effect free; it changes no definition: component records = summary.components, declared dependency
// edges = summary.edges, advisory groups matched = summary.advisory_groups, BOM inventory checks = summary.inventory_checks
// (assessed, applicable checks — never a candidate or gap row count). Advisory state is read from the analysis's own
// lookup record, never from service configuration. A missing value is null with a reason, never a fabricated zero.
import { reasonText } from '../components/lookup.js';

const NA = 'not available in this analysis';
const SHORT = { not_run: 'not run', unavailable: 'unavailable', partial: 'partial lookup', captured: 'captured' };
const plural = (n, one, many) => `${n} ${n === 1 ? one : many}`;
const count = (v) => (Number.isInteger(v) && v >= 0 ? v : null);

function advisory(identity, sum) {
  const v = count(sum.advisory_groups);
  const L = sum.advisory_lookup || null;
  const scope = identity.mode === 'live' ? 'SBOM-linked package advisory groups with a matching record' : 'Package advisory groups with a matching record';
  const lo = Number.isInteger(L?.lockfile_only?.match) && L.lockfile_only.match > 0 ? L.lockfile_only.match : 0;
  // RT-01: a zero SBOM-linked count must not hide lockfile-only matches; they are counted separately and never added to the headline.
  const loShort = lo ? plural(lo, 'lockfile-only package', 'lockfile-only packages') : null;   // short visible cue; never added to the advisory-group count
  const extra = lo ? `; plus ${lo} lockfile-only package${lo === 1 ? '' : 's'} with advisory matches not linked to an SBOM component (see Package advisory lookup)` : '';
  if (identity.mode === 'live') {
    if (!L || L.lookup === 'not_run') return { value: null, state: 'not_run', scope, reason: 'advisory matching not run' };
    if (L.lookup === 'unavailable') return { value: null, state: 'unavailable', scope, reason: reasonText(L.lookup_reason) };
    if (v === null) return { value: null, state: L.lookup === 'partial' ? 'partial' : 'live_complete', scope, reason: NA };
    if (L.lookup === 'partial') {
      const c = L.counts || {};
      const n = Number.isInteger(c.answered) && Number.isInteger(c.planned_queries) ? `partial lookup — ${c.answered} of ${c.planned_queries} versions answered` : 'partial lookup';
      return { value: v, state: 'partial', scope, reason: n + extra, short: ['partial lookup', loShort].filter(Boolean).join(' \u00b7 ') };
    }
    return { value: v, state: 'live_complete', scope, reason: 'live OSV lookup, SBOM-linked packages only' + extra, short: loShort };
  }
  if (v === null) return { value: null, state: 'captured', scope, reason: NA };
  return { value: v, state: 'captured', scope, reason: 'captured advisory evidence — not a live lookup, and not proof of complete coverage' };
}

// BOM connections review count: the unfiltered candidate total of the active analysis's own comparison (summary.gaps), never the assessed
// inventory-check count. Partial coverage comes from the comparison's own collection states. A missing/skipped/failed comparison is stated, never a zero.
const FAMILIES = ['software', 'cryptography', 'ai_model'];
function bomReview(sum) {
  const g = sum.gaps; const scope = 'Candidate items from the BOM connections comparison (unfiltered total)';
  if (!g) return { value: null, bare: true, state: 'not_run', text: 'BOM comparison not run', scope, reason: 'no BOM comparison exists for this analysis' };
  if (g.status !== 'compared') {
    if (g.code === 'collection_not_run') return { value: null, bare: true, state: 'not_run', text: 'BOM comparison not run', scope, reason: g.message || 'the comparison was not run' };
    return { value: null, bare: true, state: 'unavailable', text: 'BOM comparison unavailable', scope, reason: g.message || 'the comparison could not complete' };
  }
  const n = count(g.totals?.candidates);
  if (n === null) return { value: null, bare: true, state: 'unavailable', text: 'BOM comparison unavailable', scope, reason: NA };
  const c = g.collection || {};
  const partial = FAMILIES.some((f) => c[f]?.state === 'partial');
  const short = partial ? 'Partial coverage' : null;
  const reason = partial ? 'Coverage was partial: this count and an empty list do not show that nothing is missing.' : null;
  if (n === 0) return { value: 0, bare: true, state: 'zero', text: 'No items flagged in the checked scope', scope, reason, short };
  return { value: n, state: 'measured', text: `${n === 1 ? 'item' : 'items'} to review in BOM connections`, scope, reason, short };
}

export function summaryMetrics(analysis) {
  const identity = analysis?.identity || {}; const sum = analysis?.summary || {};
  const plain = (key, label, text, scope, v) => { const value = count(v); return { key, label, text, value, state: value === null ? 'unavailable' : 'measured', scope, reason: value === null ? NA : null, short: value === null ? 'not available' : null }; };
  const adv = advisory(identity, sum);
  return [
    plain('components', 'Component records', 'component records', 'Components reported by the SBOM for this revision', sum.components),
    plain('edges', 'Declared dependency edges', 'declared dependency edges', 'Edges declared in the lockfiles and SBOM', sum.edges),
    { key: 'advisory_groups', label: 'Advisory groups matched', text: 'advisory groups matched', ...adv, short: adv.short !== undefined ? adv.short : (SHORT[adv.state] || null) },
    { key: 'bom_review', label: 'BOM connections', ...bomReview(sum) },
  ];
}
