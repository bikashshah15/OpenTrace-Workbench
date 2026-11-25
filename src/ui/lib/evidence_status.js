// UI-EVIDENCE-STATUS-01: one compact evidence-status model for the Workbench strip. Pure and side-effect free.
// Inventory availability is derived ONLY from validated inventory/producer facts that are already in state:
//   - the analysis summary's inventory cards (kind, state, scan run, record_count, producer, scope);
//   - the validated crypto_assets/1 and ai_assets/1 pages (original_artifact producer outcome, availability.state/reason_code, supplemental producer);
//   - the request status of those pages (loading / error / stale).
// It never uses aggregate graph availability, asset counts shown for a filter, or any unrelated count to decide that a BOM exists.
// A fact that is not established is stated as unknown; nothing here adds a backend field, fetch or guess.
import { liveAiNote, LIVE_LAYER_NOTE } from './copy.js';

export const BOM_NAME = { sbom: 'SBOM', cbom: 'CBOM', aibom: 'AI-BOM' };
const TAB_TITLE = { sbom: 'Repository contexts / Dependencies', cbom: 'Cryptography', aibom: 'AI models' };

// code -> { tone, text(name) }. tone: doc (blue document), neutral (dash / loading), warn (amber).
const STATES = {
  available: { tone: 'doc', text: (n) => `${n} available` },
  available_empty: { tone: 'doc', text: (n) => `${n} available · No assets recorded within its scope` },
  recorded: { tone: 'doc', text: (n) => `${n} recorded · Not validated in this view` },
  partial: { tone: 'warn', text: (n) => `Partial ${n} · Coverage incomplete` },
  none: { tone: 'warn', text: (n) => `No ${n} available` },
  none_source_only: { tone: 'warn', text: (n) => `No ${n} available · Source observations only` },
  not_run: { tone: 'neutral', text: (n) => `${n} step not run` },
  failed: { tone: 'warn', text: (n) => `${n} generation failed` },
  cancelled: { tone: 'warn', text: (n) => `${n} generation cancelled` },
  invalid: { tone: 'warn', text: (n) => `${n} could not be read` },
  unusable: { tone: 'warn', text: (n) => `${n} not usable · Cause not recorded` },
  unsupported: { tone: 'warn', text: (n) => `${n} unavailable · Input unsupported` },
  loading: { tone: 'neutral', text: (n) => `Loading ${n} status…` },
  request_failed: { tone: 'warn', text: (n) => `${n} status unavailable` },
  unknown: { tone: 'warn', text: (n) => `${n} status unavailable` },
};
export const STATE_CODES = Object.keys(STATES);

const wordsOf = (v) => String(v == null ? '' : v).replaceAll('_', ' ');
const isStr = (v) => typeof v === 'string' && v.length > 0;
const producerText = (p) => {
  if (isStr(p)) return p;
  if (Array.isArray(p)) return p.map((x) => (x && typeof x === 'object' ? [x.name, x.version].filter(isStr).join(' ') : isStr(x) ? x : '')).filter(Boolean).join(', ') || null;
  if (p && typeof p === 'object') return [p.name, p.version].filter(isStr).join(' ') || null;
  return null;
};
const scopeText = (v) => {
  if (isStr(v)) return v;
  if (v && typeof v === 'object') {
    const bits = [isStr(v.basis) ? v.basis : null, Number.isInteger(v.file_count) ? `${v.file_count} files` : null].filter(Boolean);
    return bits.length ? bits.join(' · ') : null;
  }
  return null;
};

const cardOf = (s, kind) => {
  const cards = s.analysis?.summary?.cards;
  return Array.isArray(cards) ? cards.find((c) => c && c.kind === kind) || null : null;
};
const isLive = (s) => s.analysis?.identity?.mode === 'live';

// The validated page and its request state belong to the CBOM / AI-BOM tab only.
// A page is requested only while its own tab is showing in the normal view (Advanced keeps the legacy surface), so "loading" is claimed only then.
function pageFacts(s, kind, tab) {
  if (kind === 'cbom') return { page: s.views?.cryptoPage || null, t: s.workbench?.perTab?.crypto || {}, ownsPage: tab === 'crypto' && !s.advanced };
  if (kind === 'aibom') { const t = s.workbench?.perTab?.ai || {}; return { page: s.views?.aiPage || null, t, ownsPage: tab === 'ai' && (!s.advanced || !!t.stale) }; }
  return { page: null, t: {}, ownsPage: false };
}

// Source observations: shown only when a supplemental producer collected something that is present in the page (never inferred from the inventory).
function sourceFacts(page, orig) {
  if (!page) return { code: 'unknown' };
  // a page can list more than one supplemental producer (for example a target-based one that did not run and the source scan that did): any collected one counts
  const sups = (page.producers || []).filter((p) => p?.provenance?.origin === 'supplemental_observation');
  const collected = sups.filter((p) => p.outcome === 'completed' || p.outcome === 'partial' || p.outcome === 'completed_empty');
  const partial = collected.some((p) => p.outcome === 'partial');
  const onPage = (page.assets || []).some((a) => a?.provenance?.origin === 'supplemental_observation');
  if (onPage) return { code: 'displayed', partial };
  // "displayed" rests on current-page evidence only: an empty page under a filter or offset is not evidence of display (and never changes inventory availability)
  if (collected.length) return { code: 'collected_not_on_page' };
  return { code: 'none' };
}

function fromCard(kind, card, live) {
  if (!card) return live && kind === 'aibom' ? { code: 'not_run', basis: 'the live scan recorded no AI-BOM phase' } : { code: 'unknown' };   // a missing card does not establish that no inventory exists
  const scan = card.scan;
  if (scan && typeof scan === 'object') {
    if (scan.outcome === 'acquired') return card.record_count === 0 && kind === 'sbom' ? { code: 'available_empty' } : { code: kind === 'sbom' ? 'available' : 'recorded' };
    if (scan.outcome === 'failed') return { code: 'failed', reason: scan.reason };
    if (scan.outcome === 'cancelled') return { code: 'cancelled', reason: scan.reason };
    if (scan.outcome === 'unavailable') return { code: 'not_run', reason: scan.reason };
    return { code: 'unknown' };
  }
  if (card.state === 'acquired') return card.record_count === 0 && kind === 'sbom' ? { code: 'available_empty' } : { code: kind === 'sbom' ? 'available' : 'recorded' };
  return { code: 'unknown' };
}

// -------------------------------------------------------------------------------------------------------- one inventory
export function inventoryStatus(s, kind, tab) {
  const name = BOM_NAME[kind]; const live = isLive(s); const card = cardOf(s, kind);
  const { page, t, ownsPage } = pageFacts(s, kind, tab);
  const out = { kind, name, code: 'unknown', source: null, details: [], notes: [] };
  const origin = live ? 'Live scan of this commit' : 'Captured evidence (not a live scan)';
  const cardProducer = producerText(card?.producer) || (card?.scan && isStr(card.scan.tool) ? `${card.scan.tool} ${card.scan.version || ''}`.trim() : null);
  const cardScope = scopeText(card?.scan?.scope) || scopeText(card?.scope);
  let producer = cardProducer; let scope = cardScope; let reason = null;
  const reasonCode = card?.scan?.reason || null;

  if (kind === 'sbom' || !ownsPage && !page) {
    const r = fromCard(kind, card, live); out.code = r.code; reason = r.reason || r.basis || null;
  } else if (!page) {
    out.code = t.stale ? 'request_failed' : t.pg?.status === 'error' ? 'request_failed' : 'loading';
  } else {
    const orig = (page.producers || []).find((p) => p?.provenance?.origin === 'original_artifact') || null;
    const av = page.availability || {};
    out.source = sourceFacts(page, orig);
    if (orig) {
      producer = (isStr(orig.provenance?.producer_version) ? orig.provenance.producer_version : orig.provenance?.producer_id) || producer;
      scope = isStr(orig.scope) ? orig.scope : scope;
      const o = orig.outcome;
      if (o === 'completed' || o === 'completed_empty') out.code = o === 'completed_empty' || av.state === 'completed_empty' ? 'available_empty' : 'available';
      else if (o === 'partial') out.code = 'partial';
      else if (o === 'not_run') { out.code = 'not_run'; reason = av.state === 'not_run' ? av.reason_code : null; }   // availability may describe another producer
      else if (o === 'unsupported') { out.code = 'unsupported'; reason = av.state === 'unsupported' ? av.reason_code : null; }
      else if (o === 'failed') {
        // Only the run's own record or the producer's frozen reason establishes the cause; an unexplained failure is stated as such.
        if (card?.scan?.outcome === 'acquired') { out.code = 'invalid'; reason = 'output_invalid'; }
        else if (card?.scan && (card.scan.outcome === 'failed' || card.scan.outcome === 'cancelled')) { out.code = 'failed'; reason = card.scan.reason; }
        else if (av.state === 'failed' && av.reason_code === 'output_invalid') { out.code = 'invalid'; reason = av.reason_code; }
        else if (av.state === 'failed' && isStr(av.reason_code)) { out.code = 'failed'; reason = av.reason_code; }
        else out.code = 'unusable';
      } else out.code = 'unknown';
    } else {
      out.code = out.source.code === 'displayed' ? 'none_source_only' : 'none';
    }
    const cov = orig?.coverage;
    if (cov && (cov.unparsed_total > 0 || cov.files_excluded > 0)) out.notes.push(`Producer coverage: ${cov.files_excluded || 0} excluded, ${cov.unparsed_total || 0} not parsed.`);
  }

  out.tone = STATES[out.code].tone;
  out.text = STATES[out.code].text(name);
  if (producer) out.details.push(['Producer', producer]);
  out.details.push(['Origin', page?.binding?.mode === 'captured' || (!live && !page) ? 'Captured evidence (not a live scan)' : origin]);
  if (reason) out.details.push(['Reason', wordsOf(reason)]);
  if (scope) out.details.push(['Scope', scope]);
  if (card && isStr(card.provenance_status) && card.provenance_status !== 'declared') out.details.push(['Provenance', wordsOf(card.provenance_status)]);
  return out;
}

const SRC_TEXT = {
  displayed: 'Source observations displayed',
  displayed_partial: 'Source observations displayed · Partial',
  collected_not_on_page: 'Source observations collected · None on this page',
  none: 'No source observations displayed',
};
function sourceChip(inv) {
  const f = inv.source; if (!f || f.code === 'unknown') return null;
  const code = f.code === 'displayed' && f.partial ? 'displayed_partial' : f.code;
  return { code, text: SRC_TEXT[code], tone: f.code === 'none' ? 'neutral' : 'doc' };
}

// -------------------------------------------------------------------------------------------------------- the strip
const SCOPE_LINE = {
  contexts: 'Scope: source locations recorded in the SBOM, not a complete repository file tree.',
  dependencies: 'Advisory-query coverage is reported separately.',
  crypto: null,
  ai: null,
  bom: 'Inventory availability does not establish comparison completion or success.',
};
const TAB_KINDS = { contexts: ['sbom'], dependencies: ['sbom'], crypto: ['cbom'], ai: ['aibom'], bom: ['sbom', 'cbom', 'aibom'] };

export function evidenceStatus(s, tab) {
  if (!s || !s.analysis) return null;
  const kinds = TAB_KINDS[tab]; if (!kinds) return null;
  const items = kinds.map((k) => inventoryStatus(s, k, tab));
  const sources = tab === 'bom' ? [] : items.map(sourceChip).filter(Boolean);   // the BOM tab compares inventories; per-BOM source chips would be ambiguous there
  const live = isLive(s);
  const extra = [];
  if (live && tab === 'crypto') extra.push(LIVE_LAYER_NOTE.crypto);                                   // approved live CBOM meaning, moved from the layer note
  if (live && tab === 'ai') extra.push(liveAiNote(s.analysis.summary, s.views?.aiPage));              // approved live AI-banner meanings, moved from the layer note
  const details = items.map((i) => ({ name: i.name, text: i.text, rows: i.details, notes: i.notes }));
  return { tab, items, sources, scope: SCOPE_LINE[tab] || null, extra, details, title: TAB_TITLE[kinds[0]] };
}
