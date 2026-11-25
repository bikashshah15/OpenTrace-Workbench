// UIP-07: the AI models tab model. Pure (no DOM): filters, text, zones and display rules for `ai_assets/1`.
//
// Layout, viewport, request identity, selection and the pinned-link guard are the accepted UIP-06 functions, imported unchanged
// (`./crypto_graph.js`, contract UIP-07 FD-8): the AI tab uses the same reference geometry (the `ot6-ai` block draws the same root ->
// source-group zones -> 300x90 cards composition as `ot5-crypto`). Nothing here invents a group, asset, connector or text: every drawn
// node is a payload record. Wording never claims that a model is verified, committed, loaded or running.
import { UNLOCATED_LABEL, groupKey, assetKey, ROOT_KEY, requestKey, pageNeeded, resolveSelection, findAsset, findGroup, reviewsOf } from './crypto_graph.js';

export { requestKey, pageNeeded, resolveSelection, findAsset, findGroup, reviewsOf, assetKey, groupKey, ROOT_KEY };
export const DEFAULT_FILTER = 'all';
export const FILTERS = [
  { key: 'all', payload: 'all', label: 'All assets', title: 'Every recorded AI asset' },
  { key: 'models', payload: 'models', label: 'Models', title: 'Model references and inventory-reported models' },
  { key: 'runtimes', payload: 'runtimes', label: 'Runtimes', title: 'Inference runtimes' },
  { key: 'ai_services', payload: 'ai_services', label: 'AI services', title: 'AI services' },
  { key: 'findings', payload: 'findings', label: 'Findings', title: 'Assets with a rule-backed review item' },
];
export const payloadFilter = (key) => (FILTERS.find((f) => f.key === key) || FILTERS[0]).payload;

// The drawing family of an asset: purple models, teal runtimes, cyan services (reference colours).
export const familyOf = (a) => (a.kind === 'runtime' ? 'runtime' : a.kind === 'ai_service' ? 'service' : 'model');
export const KIND_LABEL = { model_artifact: 'Model file', model_reference: 'Model reference', inventory_model: 'Inventory-reported model', runtime: 'Runtime', ai_service: 'AI service' };
export const kindLabel = (k) => KIND_LABEL[k] || 'AI asset';
export const originLabel = (a) => (a.provenance.origin === 'supplemental_observation' ? 'Experimental source observation' : 'From the AI-BOM inventory');
export const statusLabel = (hasReview) => (hasReview ? 'Needs review' : 'Recorded asset');
export const ATTRIBUTE_LABELS = { provider: 'Provider', model_version: 'Model version', license: 'License', dataset_provenance: 'Dataset provenance', artifact_digest: 'Artifact digest', active_configuration: 'Active configuration' };

// Each empty state says why nothing is shown; none says that no AI exists, and zero findings never means "no findings" (they are not assessed).
export function emptyText(page, filterKey, query) {
  const t = page.filter_totals;
  if (filterKey === 'findings' && !query) return 'Model and service security findings are not assessed in this view. This is different from finding none.';
  if (t.all === 0) return page.availability.message;
  if (filterKey === 'ai_services' && !query && !t.ai_services) return 'No AI service was collected: this inventory records none, and the experimental source scan (when it ran) observed no inference-API endpoint literal in its supported forms. This does not show that none exists.';
  if (filterKey === 'runtimes' && !query && !t.runtimes) return 'No runtime was collected: this inventory records none, and the experimental source scan (when it ran) observed no import of a supported runtime module. This does not show that none is used.';
  return 'No assets match this filter in the recorded inventory.';
}
export const captureLabel = (page) => {
  const orig = page.producers.find((p) => p.provenance.origin === 'original_artifact');
  const sup = page.producers.find((p) => p.provenance.origin === 'supplemental_observation');
  const bits = [orig ? `AI-BOM inventory · ${orig.provenance.producer_version || orig.provenance.producer_id}${page.binding.mode === 'captured' ? ' (captured)' : ''}` : 'No AI-BOM inventory recorded'];
  if (sup) bits.push('Experimental source observations');
  return bits.join(' · ');
};
export const countsLine = (page) => {
  const t = page.filter_totals; const pl = (n, w) => `${n} ${w}${n === 1 ? '' : 's'}`;
  return `${pl(t.all, 'AI asset')} · ${pl(t.models, 'model')} · ${pl(t.runtimes, 'runtime')} · ${pl(t.ai_services, 'AI service')}`;
};
export const occurrencesNote = (a) => (a.occurrences_total > a.occurrences.length ? `${a.occurrences.length} of ${a.occurrences_total} occurrences shown; the AI-BOM download lists all of them.` : '');
export const producerStateText = (p) => ({ completed: 'collected', partial: 'collected in part', failed: 'failed', not_run: 'not collected', unsupported: 'not collected (unsupported)' }[p.outcome] || p.outcome);

// ------------------------------------------------------------------------------------------------------------------ zones
// One zone per payload source group that the page's assets reference; assets without a recorded location go to a client-side lane that is
// not a payload group (no id, not selectable as a group).
export function aiZones(page) {
  if (!page) return [];
  const zones = page.source_groups.map((g) => ({ key: groupKey(g), group: g, label: g.label, sub: g.path || g.label, cards: page.assets.filter((a) => a.source_group_ids.includes(g.group_id)) })).filter((z) => z.cards.length);
  const lone = page.assets.filter((a) => a.source_group_ids.length === 0);
  if (lone.length) zones.push({ key: null, group: null, label: UNLOCATED_LABEL, sub: 'Assets whose AI-BOM entry records no repository location', cards: lone });
  return zones;
}
// Alternatives are drawn as alternatives: a dashed labelled connector between two cards on the page, never a concurrency claim.
export function alternativeLinks(page) {
  return (page?.links || []).filter((l) => l.relation === 'conditionally_selects' && page.assets.some((a) => a.asset_id === l.from) && page.assets.some((a) => a.asset_id === l.to));
}

export const AI_ERRORS = {
  stale_generation: 'The session moved on; reopen the analysis.', no_analysis: 'No completed analysis is active.', not_found: 'That source group is not in this analysis.',
  invalid_request: 'The request was refused.', projection_failed: 'The AI assets could not be projected.', response_too_large: 'The response was too large to show.',
};
export const PROJECTION_DETAILS = {
  path_not_representable: 'A recorded repository location cannot be shown exactly, so no partial list is given. The AI-BOM download is unaffected.',
  multiple_inventories: 'More than one AI inventory is recorded for this analysis, so none is chosen.', unmapped_reason: 'The AI inventory ended in a state that has no display reason.',
};
